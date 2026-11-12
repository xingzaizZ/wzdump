// ============================================================
// il2cpp_api.m —— 运行时符号解析
// ============================================================
#include "il2cpp_api.h"
#include "pac_fix.h"

#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

WZIl2Cpp g_il2;

// ---------------------------------------------------------------- UnityFramework handle
//
// 这是 iOS 上最容易踩的坑，单独说明：
//
//   il2cpp 的符号全在 UnityFramework.framework/UnityFramework 里。
//   这个 framework 是 app 启动后由主二进制 dlopen 进来的。
//
//   dlopen 进来的镜像**不参与全局符号解析**（除非用 RTLD_GLOBAL 打开，
//   Unity 没用）。所以 dlsym(RTLD_DEFAULT, "il2cpp_domain_get") 返回 NULL。
//
//   必须先拿到它的 handle：
//     dlopen("UnityFramework", RTLD_LAZY | RTLD_NOLOAD)
//   RTLD_NOLOAD 的语义是「如果已加载就返回 handle，没加载就返回 NULL，
//   不会去加载」。这正是我们要的。
static void *g_unity_handle = NULL;
static int g_handle_tried = 0;

static void *wz_unity_handle(void) {
    if (g_unity_handle) return g_unity_handle;
    if (g_handle_tried) return NULL;
    g_handle_tried = 1;

    // 1) 常见短名 / 路径逐个试
    static const char *cands[] = {
        "UnityFramework",
        "@rpath/UnityFramework.framework/UnityFramework",
        "Frameworks/UnityFramework.framework/UnityFramework",
        "/private/var/containers/Bundle/Application/UnityFramework.framework/UnityFramework",
    };
    for (size_t i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
        void *h = dlopen(cands[i], RTLD_LAZY | RTLD_NOLOAD);
        if (h) { g_unity_handle = h; return h; }
    }

    // 2) 兜底：遍历已加载镜像，按名字里含 "UnityFramework" 找
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "UnityFramework") == NULL) continue;
        void *h = dlopen(nm, RTLD_LAZY | RTLD_NOLOAD);
        if (h) { g_unity_handle = h; return h; }
    }
    return NULL;
}

// 允许外部重试（第一次调用时 UnityFramework 可能还没加载）
static void wz_unity_handle_reset(void) {
    g_handle_tried = 0;
}

// ---------------------------------------------------------------- 符号解析
static void *wz_sym(const char *name) {
    if (!name) return NULL;

    // 1) 先查 UnityFramework（真正有符号的地方）
    void *h = wz_unity_handle();
    if (h) {
        void *p = dlsym(h, name);
        if (p) return p;
        char buf[192];
        snprintf(buf, sizeof(buf), "_%s", name);
        p = dlsym(h, buf);
        if (p) return p;
    }

    // 2) 再查全局（少数构建会把符号导到主二进制）
    void *p = dlsym(RTLD_DEFAULT, name);
    if (p) return p;

    // 3) 少数构建带下划线前缀
    char buf[192];
    snprintf(buf, sizeof(buf), "_%s", name);
    return dlsym(RTLD_DEFAULT, buf);
}

// dlsym 返回的裸地址要签成可调用指针（arm64e 上 BLRAAZ 会验签）
#define WZ_BIND_CAST(field, raw) ((__typeof__(g_il2.field))wz_pac_sign(raw))

#define BIND(field, symname, required)                                      \
    do {                                                                    \
        void *raw_ = wz_sym(symname);                                       \
        g_il2.field = WZ_BIND_CAST(field, raw_);                            \
        if (!g_il2.field) {                                                 \
            if (required) {                                                 \
                missing++;                                                  \
                if (verbose) fprintf(stderr, "[wzdump] 缺失必需符号: %s\n", symname); \
            } else if (verbose > 1) {                                       \
                fprintf(stderr, "[wzdump] 缺失可选符号: %s\n", symname);     \
            }                                                               \
        }                                                                   \
    } while (0)

int wz_il2cpp_init_ex(int verbose) {
    int missing = 0;
    memset(&g_il2, 0, sizeof(g_il2));

    // UnityFramework 可能还没加载，每轮重置让它重新找
    wz_unity_handle_reset();

    // ---- 必需（少了任何一项都没法遍历）
    BIND(domain_get,                "il2cpp_domain_get",                1);
    BIND(domain_get_assemblies,     "il2cpp_domain_get_assemblies",     1);
    BIND(assembly_get_image,        "il2cpp_assembly_get_image",        1);
    BIND(image_get_name,            "il2cpp_image_get_name",            1);
    BIND(image_get_class_count,     "il2cpp_image_get_class_count",     1);
    BIND(image_get_class,           "il2cpp_image_get_class",           1);
    BIND(class_get_name,            "il2cpp_class_get_name",            1);
    BIND(class_get_namespace,       "il2cpp_class_get_namespace",       1);
    BIND(class_get_methods,         "il2cpp_class_get_methods",         1);
    BIND(class_get_fields,          "il2cpp_class_get_fields",          1);
    BIND(class_instance_size,       "il2cpp_class_instance_size",       1);
    BIND(method_get_name,           "il2cpp_method_get_name",           1);
    BIND(method_get_param_count,    "il2cpp_method_get_param_count",    1);
    BIND(field_get_name,            "il2cpp_field_get_name",            1);
    BIND(field_get_offset,          "il2cpp_field_get_offset",          1);

    // ---- 强烈建议（少了会退化成慢速遍历或信息不全）
    BIND(class_from_name,           "il2cpp_class_from_name",           0);
    BIND(class_get_parent,          "il2cpp_class_get_parent",          0);
    BIND(class_get_method_from_name,"il2cpp_class_get_method_from_name", 0);
    BIND(class_from_type,           "il2cpp_class_from_type",           0);
    BIND(class_get_type,            "il2cpp_class_get_type",            0);
    BIND(method_get_flags,          "il2cpp_method_get_flags",          0);
    BIND(method_get_token,          "il2cpp_method_get_token",          0);
    BIND(method_get_pointer,        "il2cpp_method_get_pointer",        0);
    BIND(method_get_param,          "il2cpp_method_get_param",          0);
    BIND(method_get_return_type,    "il2cpp_method_get_return_type",    0);
    BIND(field_get_type,            "il2cpp_field_get_type",            0);
    BIND(field_get_flags,           "il2cpp_field_get_flags",           0);
    BIND(type_get_type,             "il2cpp_type_get_type",             0);
    BIND(type_get_name,             "il2cpp_type_get_name",             0);
    BIND(thread_attach,             "il2cpp_thread_attach",             0);
    BIND(object_new,                "il2cpp_object_new",                0);
    BIND(object_unbox,              "il2cpp_object_unbox",              0);
    BIND(object_get_class,          "il2cpp_object_get_class",          0);
    BIND(string_to_utf8,            "il2cpp_string_to_utf8",            0);
    BIND(domain_assembly_open,      "il2cpp_domain_assembly_open",      0);

    if (verbose) {
        fprintf(stderr, "[wzdump] il2cpp API 解析完成，缺失必需 %d 项\n", missing);
    }
    return missing == 0;
}

int wz_il2cpp_init(void) { return wz_il2cpp_init_ex(1); }

int wz_il2cpp_ready(void) {
    if (!g_il2.domain_get) return 0;
    Il2CppDomain *d = g_il2.domain_get();
    if (!d) return 0;
    if (!g_il2.domain_get_assemblies) return 1;
    size_t n = 0;
    const Il2CppAssembly **a = g_il2.domain_get_assemblies(d, &n);
    return (a && n > 0) ? 1 : 0;
}

int wz_il2cpp_wait_ready(int maxSeconds, int verbose) {
    for (int i = 0; i < maxSeconds; i++) {
        if (wz_il2cpp_ready()) {
            if (verbose) fprintf(stderr, "[wzdump] il2cpp 就绪，等待 %d 秒\n", i);
            return i;
        }
        sleep(1);
    }
    if (verbose) fprintf(stderr, "[wzdump] 等 %d 秒仍未就绪\n", maxSeconds);
    return -1;
}

// ---------------------------------------------------------------- 镜像基址
// _dyld_get_image_vmaddr_slide 返回的是 slide，不是基址。
// 真正的基址 = mach_header 的实际地址，直接从 _dyld_get_image_header 取。
uintptr_t wz_unityframework_base(void) {
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "UnityFramework")) {
            const struct mach_header *h = _dyld_get_image_header(i);
            return (uintptr_t)h;
        }
    }
    return 0;
}

// ---------------------------------------------------------------- 方法指针
// 统一剥掉 PAC 返回**裸地址**：
//   · patch 代码段要拿裸地址做 ± 运算和 mprotect
//   · 比较两个函数是否相同时，带签名的值永远不相等
// 调用方要调用时自己 wz_pac_sign() 重新签。
void *wz_method_pointer(MethodInfo *mi) {
    if (!mi) return NULL;
    void *p = NULL;
    if (g_il2.method_get_pointer) {
        p = g_il2.method_get_pointer(mi);
    }
    if (!p) {
        // MethodInfo 第一个字段就是 methodPointer（偏移 0）
        p = *(void **)mi;
    }
    return wz_pac_strip(p);
}

int wz_method_is_static(MethodInfo *mi) {
    if (!mi || !g_il2.method_get_flags) return 0;
    uint32_t iflags = 0;
    uint32_t flags = g_il2.method_get_flags(mi, &iflags);
    return (flags & 0x0010u) ? 1 : 0;
}
