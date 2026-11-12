// ============================================================
// il2cpp_dump.m —— 运行时 dump 实现
// ============================================================
// 与 Il2CppDumper 产物对齐，生成五个文件。
//
// 【关键：RVA 怎么算】
//
//   il2cpp_method_get_pointer(mi) 返回的是**运行时实际地址**（已加载 + slide）。
//   我们要的是相对 UnityFramework 基址的 RVA：
//
//     rva = (uintptr_t)ptr - unityframework_base
//
//   这个 rva 就是 dump 文件里那个 0x1ed9690 之类的值。
//   我验证过：用这个公式算出来的 RVA 拿去读二进制，
//   读到的就是真实函数序言（stp/sub sp）。
//
// 【arm64e 注意】
//   method_get_pointer 返回的可能是带 PAC 签名的地址，
//   算 RVA 前必须先 strip，否则减法结果是垃圾。
// ============================================================
#include "il2cpp_dump.h"
#include "il2cpp_api.h"
#include "il2cpp_call.h"
#include "pac_fix.h"
#include "wzlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>

// ---------------------------------------------------------------- 输出缓冲
// 用大缓冲减少 write 次数，但每次写完立即 flush
typedef struct {
    FILE *f;
    char *buf;
    size_t cap;
    size_t len;
} OutBuf;

static int obuf_open(OutBuf *o, const char *path, size_t cap) {
    o->f = fopen(path, "wb");
    if (!o->f) return -1;
    o->buf = (char *)malloc(cap);
    if (!o->buf) { fclose(o->f); o->f = NULL; return -1; }
    o->cap = cap;
    o->len = 0;
    return 0;
}

static void obuf_flush(OutBuf *o) {
    if (!o->f || o->len == 0) return;
    fwrite(o->buf, 1, o->len, o->f);
    fflush(o->f);
    o->len = 0;
}

static void obuf_close(OutBuf *o) {
    if (!o) return;
    obuf_flush(o);
    if (o->f) { fclose(o->f); o->f = NULL; }
    if (o->buf) { free(o->buf); o->buf = NULL; }
}

static void obuf_printf(OutBuf *o, const char *fmt, ...) {
    if (!o->f) return;
    char tmp[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if ((size_t)n >= sizeof(tmp)) n = (int)sizeof(tmp) - 1;

    if (o->len + (size_t)n > o->cap) obuf_flush(o);
    if ((size_t)n > o->cap) {
        // 超长行直接写
        fwrite(tmp, 1, (size_t)n, o->f);
        fflush(o->f);
        return;
    }
    memcpy(o->buf + o->len, tmp, (size_t)n);
    o->len += (size_t)n;
}

// ---------------------------------------------------------------- 基址
static uintptr_t unity_base(void) {
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

// 把运行时指针换算成 RVA
static uint32_t ptr_to_rva(void *p, uintptr_t base) {
    if (!p || !base) return 0;
    uintptr_t raw = wz_pac_raw(p);
    if (raw < base) return 0;
    uintptr_t rva = raw - base;
    if (rva > 0xFFFFFFFFULL) return 0;
    return (uint32_t)rva;
}

// ---------------------------------------------------------------- 字符串安全
// il2cpp 返回的 char* 可能为 NULL，统一兜一下
static const char *S(const char *s) { return s ? s : ""; }

// ---------------------------------------------------------------- 皮肤关键词
// 用于生成 skin.txt：只挑与皮肤/英雄/商城相关的类
static int is_skin_related(const char *cls, const char *ns) {
    static const char *kw[] = {
        "Skin", "skin", "Hero", "hero", "Avatar", "avatar",
        "Mall", "mall", "Shop", "shop", "Item", "item",
        "Role", "role", "Player", "player", "Wear", "wear",
        "Limit", "limit", "Experience", "experience",
        "Mask", "mask", "Trial", "trial", "Train", "train",
        "Valid", "valid", "Own", "own", "Buy", "buy",
        "Get", "get", "Coin", "coin", "Prop", "prop",
        "Collection", "collection", "Quality", "quality",
        NULL
    };
    for (int i = 0; kw[i]; i++) {
        if (strstr(cls, kw[i])) return 1;
        if (ns && strstr(ns, kw[i])) return 1;
    }
    return 0;
}

// ============================================================
// 主流程
// ============================================================
int wz_dump_run(const char *outDir) {
    char dir[1024];
    if (outDir && *outDir) {
        snprintf(dir, sizeof(dir), "%s", outDir);
    } else {
        const char *home = getenv("HOME");
        if (home && *home) snprintf(dir, sizeof(dir), "%s/Documents/wz_dump", home);
        else snprintf(dir, sizeof(dir), "/tmp/wz_dump");
    }
    mkdir(dir, 0755);

    LOGI("=== dump 开始，输出目录 %s ===\n", dir);

    // ---- 前置检查
    if (!wz_il2cpp_init_ex(1)) {
        LOGE("il2cpp API 不完整，无法 dump\n");
        return -1;
    }
    if (!wz_il2cpp_ready()) {
        LOGE("il2cpp 运行时未就绪\n");
        return -2;
    }

    uintptr_t base = unity_base();
    LOGI("UnityFramework 基址 = 0x%lx\n", (unsigned long)base);
    if (!base) {
        LOGE("找不到 UnityFramework\n");
        return -3;
    }

    Il2CppDomain *dom = g_il2.domain_get();
    if (!dom) { LOGE("domain 为空\n"); return -4; }

    if (g_il2.thread_attach) g_il2.thread_attach(dom);

    size_t asmCount = 0;
    const Il2CppAssembly **asms = g_il2.domain_get_assemblies(dom, &asmCount);
    if (!asms || asmCount == 0) { LOGE("assembly 列表为空\n"); return -5; }

    LOGI("assembly 数 = %zu\n", asmCount);

    // ---- 打开输出文件
    char pClasses[1200], pMethods[1200], pFields[1200], pSkin[1200], pSummary[1200];
    snprintf(pClasses, sizeof(pClasses), "%s/classes.txt", dir);
    snprintf(pMethods, sizeof(pMethods), "%s/methods_all.txt", dir);
    snprintf(pFields,  sizeof(pFields),  "%s/fields_all.txt",  dir);
    snprintf(pSkin,    sizeof(pSkin),    "%s/skin.txt",        dir);
    snprintf(pSummary, sizeof(pSummary), "%s/summary.txt",     dir);

    OutBuf oCls, oMth, oFld, oSkin, oSum;
    if (obuf_open(&oCls, pClasses, 1 << 20) != 0) { LOGE("打不开 classes.txt\n"); return -6; }
    if (obuf_open(&oMth, pMethods, 1 << 20) != 0) { obuf_close(&oCls); return -6; }
    if (obuf_open(&oFld, pFields,  1 << 20) != 0) { obuf_close(&oCls); obuf_close(&oMth); return -6; }
    if (obuf_open(&oSkin, pSkin,   1 << 20) != 0) { obuf_close(&oCls); obuf_close(&oMth); obuf_close(&oFld); return -6; }

    // ---- 表头
    obuf_printf(&oCls, "# 全部类  [idx] Namespace.Name : Parent\n\n");
    obuf_printf(&oMth, "# 全部方法  Namespace.Class::Method\n");
    obuf_printf(&oFld, "# 全部字段  Namespace.Class::field @offset\n");
    obuf_printf(&oSkin, "# 皮肤/英雄/拥有/商城相关类完整 dump\n\n");

    // ---- 统计
    size_t totalClasses = 0, totalMethods = 0, totalFields = 0;
    char asmList[16384];
    size_t asmListLen = 0;
    asmList[0] = '\0';

    // ---- 遍历所有 image
    for (size_t ai = 0; ai < asmCount; ai++) {
        if (!asms[ai]) continue;
        Il2CppImage *img = g_il2.assembly_get_image((Il2CppAssembly *)asms[ai]);
        if (!img) continue;

        const char *imgName = S(g_il2.image_get_name(img));
        size_t clsCount = g_il2.image_get_class_count ? g_il2.image_get_class_count(img) : 0;

        LOGI("  [%zu] %-50s %zu 类\n", ai, imgName, clsCount);

        // 记录到 summary
        if (asmListLen + 128 < sizeof(asmList)) {
            asmListLen += (size_t)snprintf(asmList + asmListLen,
                                           sizeof(asmList) - asmListLen,
                                           "  [%zu] %-50s %zu 类\n", ai, imgName, clsCount);
        }

        obuf_printf(&oCls, "\n=== Image %zu: %s  (%zu 类) ===\n", ai, imgName, clsCount);

        // ---- 遍历类
        for (size_t ci = 0; ci < clsCount; ci++) {
            Il2CppClass *k = g_il2.image_get_class(img, ci);
            if (!k) continue;

            const char *cname = S(g_il2.class_get_name(k));
            const char *cns = S(g_il2.class_get_namespace(k));
            uint32_t isize = g_il2.class_instance_size ? g_il2.class_instance_size(k) : 0;

            // 父类
            const char *parent = "";
            if (g_il2.class_get_parent) {
                Il2CppClass *pk = g_il2.class_get_parent(k);
                if (pk) {
                    const char *pn = S(g_il2.class_get_name(pk));
                    const char *pns = S(g_il2.class_get_namespace(pk));
                    static char pbuf[512];
                    if (pns && *pns) snprintf(pbuf, sizeof(pbuf), "%s.%s", pns, pn);
                    else snprintf(pbuf, sizeof(pbuf), "%s", pn);
                    parent = pbuf;
                }
            }

            // 完整名
            char full[1024];
            if (cns && *cns) snprintf(full, sizeof(full), "%s.%s", cns, cname);
            else snprintf(full, sizeof(full), "%s", cname);

            obuf_printf(&oCls, "[%zu] %s : %s\n", ci, full, parent);
            totalClasses++;

            // 是否皮肤相关
            int skinRel = is_skin_related(cname, cns);

            if (skinRel) {
                obuf_printf(&oSkin, "// ========================================================\n");
                obuf_printf(&oSkin, "// %s   instance_size=%u   image=%s\n", full, isize, imgName);
                obuf_printf(&oSkin, "// ========================================================\n");
            }

            // ---- 方法
            if (g_il2.class_get_methods) {
                void *iter = NULL;
                while (1) {
                    MethodInfo *mi = (MethodInfo *)g_il2.class_get_methods(k, &iter);
                    if (!mi) break;

                    const char *mn = S(g_il2.method_get_name(mi));
                    uint32_t pc = g_il2.method_get_param_count
                                      ? g_il2.method_get_param_count(mi) : 0;

                    obuf_printf(&oMth, "%s::%s\n", full, mn);
                    totalMethods++;

                    if (skinRel) {
                        void *ptr = wz_method_pointer(mi);
                        uint32_t rva = ptr_to_rva(ptr, base);
                        obuf_printf(&oSkin, "  method %s(", mn);
                        for (uint32_t pi = 0; pi < pc; pi++) {
                            obuf_printf(&oSkin, "%s?", pi ? ", " : "");
                        }
                        obuf_printf(&oSkin, ")   // RVA 0x%x\n", rva);
                    }
                }
            }

            // ---- 字段
            if (g_il2.class_get_fields) {
                void *fiter = NULL;
                while (1) {
                    FieldInfo *fi = (FieldInfo *)g_il2.class_get_fields(k, &fiter);
                    if (!fi) break;

                    const char *fn = S(g_il2.field_get_name(fi));
                    size_t off = g_il2.field_get_offset ? g_il2.field_get_offset(fi) : 0;

                    obuf_printf(&oFld, "%s::%s @0x%zx\n", full, fn, off);
                    totalFields++;

                    if (skinRel) {
                        obuf_printf(&oSkin, "  field  ? %s   // 0x%zx\n", fn, off);
                    }
                }
            }

            if (skinRel) obuf_printf(&oSkin, "\n");
        }
    }

    // ---- summary
    obuf_printf(&oSum, "wzdump 运行时 dump\n");
    obuf_printf(&oSum, "pid      : %d\n", getpid());
    obuf_printf(&oSum, "输出目录 : %s\n", dir);
    obuf_printf(&oSum, "UnityFramework 基址 : 0x%lx\n", (unsigned long)base);
    obuf_printf(&oSum, "架构     : %s   PAC=%d\n", WZ_ARCH_NAME, WZ_HAS_PAC);
    obuf_printf(&oSum, "\n");
    obuf_printf(&oSum, "Assembly 数: %zu\n", asmCount);
    obuf_printf(&oSum, "%s", asmList);
    obuf_printf(&oSum, "\n总计: 类 %zu, 方法 %zu, 字段 %zu\n", totalClasses, totalMethods, totalFields);
    obuf_printf(&oSum, "\n文件:\n");
    obuf_printf(&oSum, "  classes.txt / methods_all.txt / fields_all.txt / skin.txt\n");

    // ---- 收尾
    obuf_close(&oCls);
    obuf_close(&oMth);
    obuf_close(&oFld);
    obuf_close(&oSkin);
    obuf_close(&oSum);

    LOGI("=== dump 完成：类 %zu，方法 %zu，字段 %zu ===\n",
         totalClasses, totalMethods, totalFields);
    LOGI("  输出: %s\n", dir);

    return 0;
}
