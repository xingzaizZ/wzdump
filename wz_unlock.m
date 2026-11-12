// ============================================================
// wz_unlock.m —— 王者荣耀 iOS 全皮肤解锁（主逻辑）
// ============================================================
// 设计原则：**能不用 il2cpp API 就不用**。
//
// 为什么？
//   il2cpp 的符号在 UnityFramework 里，dlopen 进来的镜像不进全局符号表，
//   dlsym(RTLD_DEFAULT) 查不到。上一版就卡在这 —— 日志显示
//   「il2cpp 符号始终不全，放弃」，等于白注入。
//
//   而 dump 给了我们全部 RVA，UnityFramework 又未加密，
//   所以：**直接 基址 + RVA 算函数地址，patch 掉**，不需要任何 il2cpp API。
//
// 只有 L0（数据注入）需要调用托管方法，那才需要 il2cpp API。
// 所以设计成：
//   L1/L2/L3 只靠 RVA → 一定能成
//   L0 需要 il2cpp API → 拿不到就跳过，不影响 L1~L3
// ============================================================
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>

#include "pac_fix.h"
#include "wzlog.h"
#include "il2cpp_api.h"
#include "il2cpp_call.h"
#include "hook_arm64.h"
#include "thread_freeze.h"
#include "wz_map.h"

static int g_patched = 0;
static int g_failed = 0;
static int g_injected = 0;
static uintptr_t g_base = 0;

// ============================================================
// 基址
// ============================================================
extern const char *_dyld_get_image_name(uint32_t image_index);
extern const struct mach_header *_dyld_get_image_header(uint32_t image_index);
extern uint32_t _dyld_image_count(void);

static uintptr_t wz_unity_base(void) {
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "UnityFramework")) {
            const struct mach_header *h = _dyld_get_image_header(i);
            if (h) return (uintptr_t)h;
        }
    }
    return 0;
}

// ============================================================
// patch 工具
// ============================================================
static void patch_bool(const char *tag, uint32_t rva, int value) {
    if (!g_base) { LOGW("  --   %-46s 无基址\n", tag); return; }

    void *fn = (void *)(g_base + rva);

    // 先检查目标地址可读（防止 RVA 错误导致访问野指针）
    char dis[200] = {0};
    wz_disasm_head(fn, dis, sizeof(dis));

    int rc = wz_patch_return(fn, 0, value);
    if (rc == 0) {
        LOGI("  OK   %-46s @0x%lx -> %d\n", tag, (unsigned long)rva, value);
        g_patched++;
    } else {
        LOGW("  FAIL %-45s @0x%lx rc=%d  原: %s\n", tag, (unsigned long)rva, rc, dis);
        g_failed++;
    }
}

static void patch_int(const char *tag, uint32_t rva, int value) {
    if (!g_base) return;
    void *fn = (void *)(g_base + rva);
    char dis[200] = {0};
    wz_disasm_head(fn, dis, sizeof(dis));

    int rc = wz_patch_return(fn, 1, value);
    if (rc == 0) {
        LOGI("  OK   %-46s @0x%lx -> %d\n", tag, (unsigned long)rva, value);
        g_patched++;
    } else {
        LOGW("  FAIL %-45s @0x%lx rc=%d  原: %s\n", tag, (unsigned long)rva, rc, dis);
        g_failed++;
    }
}

// ============================================================
// L1  判定层：所有皮肤判定返回 true
// ============================================================
// 实证：IsHaveHeroSkin 读 [this+0x358] = heroSkinDic
// 直接返回 true 能兜住 L0 写不进去的情况
static void patch_l1(void) {
    LOGI("[L1] 判定层：皮肤判定返回 true\n");

    // ---- CRoleInfo：真正决定「我有没有这个皮肤」
    patch_bool("CRoleInfo::IsHaveHeroSkin/5", RVA_CRoleInfo_IsHaveHeroSkin_5, 1);
    patch_bool("CRoleInfo::IsHaveHeroSkin/4", RVA_CRoleInfo_IsHaveHeroSkin_4, 1);
    patch_bool("CRoleInfo::IsCanUseSkin/3",   RVA_CRoleInfo_IsCanUseSkin_3,   1);
    patch_bool("CRoleInfo::IsCanUseSkin/2",   RVA_CRoleInfo_IsCanUseSkin_2,   1);

    // ---- 皮肤状态：返回 2 = 「已拥有未穿戴」
    //      HeroSkinState: NormalSkin_Wear=0, LimitSkin_Wear=1,
    //                     NormalSkin_Own=2, LimitSkin_Own=3, Skin_NotOwn=4
    patch_int("CRoleInfo::GetHeroSkinState/2", RVA_CRoleInfo_GetHeroSkinState_2, 2);

    // ---- CSkinInfo：配置 / 商城侧第二道闸
    patch_bool("CSkinInfo::IsHaveHeroSkin/5", RVA_CSkinInfo_IsHaveHeroSkin_5, 1);
    patch_bool("CSkinInfo::IsHaveHeroSkin/4", RVA_CSkinInfo_IsHaveHeroSkin_4, 1);
    patch_bool("CSkinInfo::IsCanBuy/2",       RVA_CSkinInfo_IsCanBuy_2,       1);
    patch_bool("CSkinInfo::IsCanBuy/1",       RVA_CSkinInfo_IsCanBuy_1,       1);
    patch_bool("CSkinInfo::IsCanGet/3",       RVA_CSkinInfo_IsCanGet_3,       1);
    patch_bool("CSkinInfo::IsCanGet/2",       RVA_CSkinInfo_IsCanGet_2,       1);
}

// ============================================================
// L3  无效位层
// ============================================================
// ★★★ 这一层上一版搞反了，是最严重的逻辑错误
//
//   反汇编 CheckSkinMaskBit @0x1f140f0：
//     +32  cbz  x0, 0x1f1413c    ← 查不到记录就跳
//     +52  ldr  w0, [x20, #16]   ← 查到：读 MaskBits
//     +72  b    0x147ac80        ← 尾调用判断
//     +76  mov  w0, #1           ← **没记录 → 返回 1（有效）**
//
//   返回 1 = 皮肤有效，返回 0 = 被封禁。
//   上一版 patch 成恒 0 = 把所有皮肤标记成封禁 = 皮肤全失效 + 可能触发异常处理。
//
//   正确：恒返回 1。
static void patch_l3(void) {
    LOGI("[L3] 无效位层：MaskBits 恒不置位（返回 1 = 有效）\n");

    patch_bool("CSkinInfo::CheckSkinMaskBit/2", RVA_CSkinInfo_CheckSkinMaskBit_2, 1);

    // UpdateSkinMaskBits 返回 void，patch 成直接 ret 即可
    if (g_base) {
        void *fn = (void *)(g_base + RVA_CSkinInfo_UpdateSkinMaskBits_2);
        int rc = wz_patch_return(fn, 0, 0);
        if (rc == 0) {
            LOGI("  OK   %-46s @0x%x -> ret\n", "CSkinInfo::UpdateSkinMaskBits/2",
                 RVA_CSkinInfo_UpdateSkinMaskBits_2);
            g_patched++;
        } else {
            LOGW("  FAIL %-45s @0x%x rc=%d\n", "CSkinInfo::UpdateSkinMaskBits/2",
                 RVA_CSkinInfo_UpdateSkinMaskBits_2, rc);
            g_failed++;
        }
    }
}

// ============================================================
// L0  数据注入：调 OnAddHeroSkin 写进 heroSkinDic
// ============================================================
// 这一层需要 il2cpp API（要拿 CRoleInfo 实例和皮肤清单）。
// 拿不到就跳过，L1/L3 已经能保证皮肤可用。
typedef void *(*GetMasterRoleInfo_t)(const MethodInfo *mi);
typedef void  (*OnAddHeroSkin_t)(void *self, int heroId, int skinId,
                                 const MethodInfo *mi);
typedef void *(*GetAllSkinIDs_t)(const MethodInfo *mi);
typedef int   (*ResolveHeroSkin_t)(int cfgId, int *heroId, int *skinId,
                                   const MethodInfo *mi);

static void try_inject(void) {
    LOGI("[L0] 数据注入：尝试写入 heroSkinDic\n");

    if (!g_il2.domain_get) {
        LOGW("  il2cpp API 不可用，跳过 L0（L1/L3 已生效，皮肤仍可用）\n");
        return;
    }

    Il2CppDomain *dom = g_il2.domain_get();
    if (!dom) { LOGW("  domain 为空，跳过 L0\n"); return; }

    if (g_il2.thread_attach) {
        g_il2.thread_attach(dom);
        LOGI("  已挂到 il2cpp 线程\n");
    }

    // ---- 找 CRoleInfoManager
    Il2CppClass *kMgr = NULL;
    if (g_il2.class_from_name) {
        // 需要先找 image
        size_t n = 0;
        const Il2CppAssembly **asms = g_il2.domain_get_assemblies(dom, &n);
        Il2CppImage *baseImg = NULL;
        for (size_t i = 0; i < n && asms; i++) {
            Il2CppImage *img = g_il2.assembly_get_image((Il2CppAssembly *)asms[i]);
            const char *nm = img ? g_il2.image_get_name(img) : NULL;
            if (nm && strcmp(nm, "Scripts.Base.dll") == 0) { baseImg = img; break; }
        }
        if (baseImg) {
            kMgr = g_il2.class_from_name(baseImg, "Assets.Scripts.GameSystem",
                                         "CRoleInfoManager");
        }
    }

    if (!kMgr) {
        LOGW("  找不到 CRoleInfoManager，跳过 L0\n");
        return;
    }

    MethodInfo *miMaster = NULL;
    if (g_il2.class_get_method_from_name) {
        miMaster = g_il2.class_get_method_from_name(kMgr, "GetMasterRoleInfo", 0);
    }
    if (!miMaster) { LOGW("  找不到 GetMasterRoleInfo，跳过 L0\n"); return; }

    GetMasterRoleInfo_t getMaster =
        (GetMasterRoleInfo_t)wz_callable(miMaster);
    if (!getMaster) { LOGW("  GetMasterRoleInfo 无指针，跳过 L0\n"); return; }

    void *role = getMaster(miMaster);
    LOGI("  CRoleInfo* = %p\n", role);
    if (!role) {
        LOGW("  拿不到主角色（未登录？），跳过 L0\n");
        return;
    }

    // ---- 找 CSkinInfo 和 OnAddHeroSkin
    Il2CppImage *baseImg2 = NULL;
    {
        size_t n = 0;
        const Il2CppAssembly **asms = g_il2.domain_get_assemblies(dom, &n);
        for (size_t i = 0; i < n && asms; i++) {
            Il2CppImage *img = g_il2.assembly_get_image((Il2CppAssembly *)asms[i]);
            const char *nm = img ? g_il2.image_get_name(img) : NULL;
            if (nm && strcmp(nm, "Scripts.Base.dll") == 0) { baseImg2 = img; break; }
        }
    }
    if (!baseImg2) { LOGW("  找不到 Scripts.Base.dll，跳过 L0\n"); return; }

    Il2CppClass *kSkin = g_il2.class_from_name
        ? g_il2.class_from_name(baseImg2, "Assets.Scripts.GameSystem", "CSkinInfo")
        : NULL;
    Il2CppClass *kRole = g_il2.class_from_name
        ? g_il2.class_from_name(baseImg2, "Assets.Scripts.GameSystem", "CRoleInfo")
        : NULL;
    if (!kSkin || !kRole) { LOGW("  找不到 CSkinInfo/CRoleInfo，跳过 L0\n"); return; }

    MethodInfo *miAdd = g_il2.class_get_method_from_name
        ? g_il2.class_get_method_from_name(kRole, "OnAddHeroSkin", 2) : NULL;
    MethodInfo *miAll = g_il2.class_get_method_from_name
        ? g_il2.class_get_method_from_name(kSkin, "GetAllSkinIDs", 0) : NULL;
    MethodInfo *miResolve = g_il2.class_get_method_from_name
        ? g_il2.class_get_method_from_name(kSkin, "ResolveHeroSkin", 3) : NULL;

    if (!miAdd) { LOGW("  找不到 OnAddHeroSkin，跳过 L0\n"); return; }

    OnAddHeroSkin_t addSkin = (OnAddHeroSkin_t)wz_callable(miAdd);
    if (!addSkin) { LOGW("  OnAddHeroSkin 无指针，跳过 L0\n"); return; }

    // ---- 拿全量皮肤清单
    if (!miAll) {
        LOGW("  找不到 GetAllSkinIDs，跳过 L0\n");
        return;
    }
    GetAllSkinIDs_t getAll = (GetAllSkinIDs_t)wz_callable(miAll);
    void *list = getAll ? getAll(miAll) : NULL;
    LOGI("  GetAllSkinIDs() -> %p\n", list);
    if (!list) { LOGW("  皮肤清单为空，跳过 L0\n"); return; }

    // ---- 读 List<uint> 的 size 和 items
    // List<T> 布局：klass(8) + monitor(8) + items(8) + size(4) + version(4)
    int32_t *sizePtr = (int32_t *)((uintptr_t)list + 24);
    void *items = *(void **)((uintptr_t)list + 16);
    int total = *sizePtr;

    LOGI("  皮肤 cfgId 数量 = %d\n", total);
    if (total <= 0 || total > 5000) {
        LOGW("  数量异常（%d），跳过 L0\n", total);
        return;
    }

    // ---- 逐个注入
    ResolveHeroSkin_t resolve = (miResolve) ? (ResolveHeroSkin_t)wz_callable(miResolve) : NULL;

    int ok = 0, bad = 0;
    for (int i = 0; i < total; i++) {
        // 数组元素：Il2CppArray(klass 8 + monitor 8 + bounds 8 + max_length 8) + data
        uint32_t cfgId = *(uint32_t *)((uintptr_t)items + 32 + i * 4);
        if (cfgId == 0) continue;

        int heroId = 0, skinId = 0;
        int got = 0;

        if (resolve) {
            resolve((int)cfgId, &heroId, &skinId, miResolve);
            if (heroId > 0 && heroId < 2000 && skinId >= 0 && skinId < 100) got = 1;
        }
        if (!got) {
            // 兜底：cfgId = heroId * 100 + skinId
            heroId = (int)cfgId / 100;
            skinId = (int)cfgId % 100;
            if (heroId <= 0 || heroId > 2000 || skinId > 99) { bad++; continue; }
        }

        addSkin(role, heroId, skinId, miAdd);
        ok++;
    }

    LOGI("  注入完成：写入 %d 条，跳过 %d 条\n", ok, bad);
    g_injected = ok;
}

// ============================================================
// 自检：直接调用判定函数验证
// ============================================================
typedef int (*IsHave_t)(void *self, int heroId, int skinId,
                        int a, int b, int c, const MethodInfo *mi);

static void self_check(void) {
    LOGI("[自检] 调用判定函数验证\n");

    if (!g_base) return;

    // 没 il2cpp API 就没法拿 CRoleInfo 实例，只能验证 patch 是否写入成功
    // 读回被 patch 的函数头，确认是 movz w0, #1
    uint32_t *p = (uint32_t *)(g_base + RVA_CRoleInfo_IsHaveHeroSkin_5);
    uint32_t insn = p[0];
    LOGI("  IsHaveHeroSkin/5 首指令 = 0x%08x\n", insn);

    // movz w0, #1 的编码是 0x52800020
    if (insn == 0x52800020) {
        LOGI("  ✓ 确认已改为「返回 1」\n");
    } else {
        LOGW("  ✗ 未生效，首指令不是 movz w0,#1\n");
    }

    uint32_t *p2 = (uint32_t *)(g_base + RVA_CSkinInfo_CheckSkinMaskBit_2);
    uint32_t insn2 = p2[0];
    LOGI("  CheckSkinMaskBit/2 首指令 = 0x%08x\n", insn2);
    if (insn2 == 0x52800020) {
        LOGI("  ✓ 确认已改为「返回 1（有效）」\n");
    } else {
        LOGW("  ✗ 未生效\n");
    }
}

// ============================================================
// worker
// ============================================================
static void *wz_worker(void *arg) {
    (void)arg;

    LOGI("=== wzdump 全皮肤解锁启动 ===\n");
    LOGI("  架构 = %s   PAC = %s\n", WZ_ARCH_NAME,
         WZ_HAS_PAC ? "开启" : "关闭");
    wzlog_stage("worker 启动");

    // 1) 找 UnityFramework 基址（轮询最多 120 秒）
    LOGI("=== 等待 UnityFramework 加载 ===\n");
    for (int i = 0; i < 120; i++) {
        g_base = wz_unity_base();
        if (g_base) break;
        sleep(1);
    }
    if (!g_base) {
        LOGE("等 120 秒仍找不到 UnityFramework，放弃\n");
        wzlog_stage("失败：找不到 UnityFramework");
        return NULL;
    }
    LOGI("  UnityFramework 基址 = 0x%lx\n", (unsigned long)g_base);
    wzlog_stage("已拿到基址");

    // 2) 解析 il2cpp 符号（可选，失败不影响 L1/L3）
    LOGI("=== 解析 il2cpp 符号（可选）===\n");
    int ok = 0;
    for (int i = 0; i < 60; i++) {
        if (wz_il2cpp_init_ex(0)) { ok = 1; break; }
        sleep(1);
    }
    if (ok) {
        LOGI("  符号解析成功\n");
        wzlog_stage("符号就绪");
        // 等 assembly 注册完
        int waited = wz_il2cpp_wait_ready(120, 1);
        if (waited < 0) LOGW("  等 120 秒未就绪，L0 会跳过\n");
    } else {
        LOGW("  符号解析失败，跳过 L0（L1/L3 不依赖它，仍会生效）\n");
    }

    // 3) patch（L1 / L3 只靠 RVA，一定能成）
    LOGI("=== 开始 patch ===\n");
    wzlog_stage("开始 patch");

    patch_l1();
    wzlog_stage("L1 完成");

    patch_l3();
    wzlog_stage("L3 完成");

    LOGI("=== patch 结果：成功 %d 处，失败 %d 处 ===\n", g_patched, g_failed);

    // 4) L0 数据注入（可选）
    try_inject();
    wzlog_stage("L0 完成");

    // 5) 自检
    self_check();
    wzlog_stage("全部完成");

    LOGI("=== 完成：patch %d 处，注入 %d 条 ===\n", g_patched, g_injected);
    return NULL;
}

// ============================================================
// 入口
// ============================================================
// 【constructor 里为什么先 sleep】
//
//   dyld 加载 dylib 时执行 constructor，此刻进程处于「镜像加载中」：
//     · malloc zone 可能未就绪
//     · 其它 constructor 可能还没跑（比如 UnityFramework 自己的）
//     · 在这个窗口建线程会和 dyld 的锁竞争
//
//   表现：偶发死锁、新线程在 malloc 里崩、或 dyld 报 image not loaded 直接 SIGKILL。
//
//   所以：先 usleep 让 dyld 收尾，再建线程。
__attribute__((constructor))
static void wz_init(void) {
    // 1) 日志先起（这是唯一能在闪退后还能看到东西的东西）
    if (wzlog_init(NULL) != 0) {
        // 文件打不开就退到 /tmp
        wzlog_init("/tmp");
    }
    wzlog_install_crash_handler();

    LOGI("========================================\n");
    LOGI(" wzdump 全皮肤解锁 dylib 已注入\n");
    LOGI(" pid = %d   arch = %s   PAC = %d\n", getpid(), WZ_ARCH_NAME, WZ_HAS_PAC);
    LOGI(" 日志文件: %s\n", wzlog_path());
    LOGI("========================================\n");

    // 2) 等 dyld 把当前这批 image 收尾
    usleep(200 * 1000);

    // 3) 起 worker（显式给 512KB 栈）
    pthread_t th;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 512 * 1024);

    int rc = pthread_create(&th, &attr, wz_worker, NULL);
    pthread_attr_destroy(&attr);

    if (rc != 0) {
        LOGE("创建 worker 线程失败 rc=%d\n", rc);
    }
}
