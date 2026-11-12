// ============================================================
// il2cpp_api.h —— 运行时 il2cpp 导出符号解析
// ============================================================
// 与 Il2CppDumper 的根本区别：
//
//   Il2CppDumper 走**静态**路线 —— 读 app 里的
//   global-metadata.dat + libil2cpp.so 的 Mach-O/ELF 符号表，
//   在电脑上离线解析。这条路在 iOS 的加固包上直接废掉：
//     · global-metadata.dat 被加密（腾讯的 libshell 就干这个）
//     · 或者元数据被内嵌进二进制，文件里找不到独立的 metadata
//   静态读出来是一堆密文，解析结果是垃圾。
//
//   本 dumper 走**运行时**路线 —— 注入进进程，用 il2cpp 自己的 C API
//   （il2cpp_domain_get / il2cpp_class_get_methods ...）去遍历。
//   此刻引擎已经把元数据解密、注册进内存了，我们读的就是真数据。
//   好处：
//     · 不用管加密，引擎替我们解了
//     · 拿到的 RVA 是**实际加载后的地址**，直接能用
//     · 顺带能读到运行时才确定的东西（泛型实例化、动态注册的类）
//
// 【iOS 特有的坑：符号不在全局表里】
//
//   il2cpp 的符号在 UnityFramework.framework 里，这是 dlopen 进来的
//   动态库。dlopen 加载的镜像**不进全局符号表**，所以
//   dlsym(RTLD_DEFAULT, "il2cpp_domain_get") 返回 NULL。
//
//   必须先 dlopen("UnityFramework", RTLD_NOLOAD) 拿到 handle，
//   再从 handle 里 dlsym。RTLD_NOLOAD 不加载新镜像，只查已加载的。
// ============================================================
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------- 不透明类型
// 全部用 opaque struct 指针，不用 `typedef void *`。
// 原因：写成 `typedef void *Il2CppImage` 之后再声明 `Il2CppImage *` 就变成
// `void **`，编译不报错但语义全错，运行时会拿到错误地址。
typedef struct Il2CppDomain   Il2CppDomain;
typedef struct Il2CppAssembly Il2CppAssembly;
typedef struct Il2CppImage    Il2CppImage;
typedef struct Il2CppClass    Il2CppClass;
typedef struct Il2CppObject   Il2CppObject;
typedef struct MethodInfo     MethodInfo;
typedef struct FieldInfo      FieldInfo;
typedef struct Il2CppType     Il2CppType;

// ---------------------------------------------------------------- 函数指针表
typedef struct WZIl2Cpp {
    // ---- domain / assembly / image
    Il2CppDomain *(*domain_get)(void);
    const Il2CppAssembly **(*domain_get_assemblies)(Il2CppDomain *, size_t *);
    Il2CppAssembly *(*domain_assembly_open)(Il2CppDomain *, const char *);
    Il2CppImage *(*assembly_get_image)(Il2CppAssembly *);
    const char *(*image_get_name)(Il2CppImage *);
    size_t (*image_get_class_count)(Il2CppImage *);
    Il2CppClass *(*image_get_class)(Il2CppImage *, size_t);

    // ---- class
    const char *(*class_get_name)(Il2CppClass *);
    const char *(*class_get_namespace)(Il2CppClass *);
    Il2CppClass *(*class_from_name)(Il2CppImage *, const char *, const char *);
    Il2CppClass *(*class_get_parent)(Il2CppClass *);
    uint32_t (*class_instance_size)(Il2CppClass *);
    MethodInfo *(*class_get_methods)(Il2CppClass *, void **);
    FieldInfo *(*class_get_fields)(Il2CppClass *, void **);
    Il2CppClass *(*class_from_type)(const Il2CppType *);
    const Il2CppType *(*class_get_type)(Il2CppClass *);

    // ---- method
    const char *(*method_get_name)(MethodInfo *);
    uint32_t (*method_get_param_count)(MethodInfo *);
    MethodInfo *(*class_get_method_from_name)(Il2CppClass *, const char *, int);
    uint32_t (*method_get_flags)(MethodInfo *, uint32_t *);
    uint32_t (*method_get_token)(MethodInfo *);
    void *(*method_get_pointer)(MethodInfo *);
    const Il2CppType *(*method_get_param)(MethodInfo *, uint32_t);
    const Il2CppType *(*method_get_return_type)(MethodInfo *);

    // ---- field
    const char *(*field_get_name)(FieldInfo *);
    size_t (*field_get_offset)(FieldInfo *);
    const Il2CppType *(*field_get_type)(FieldInfo *);
    uint32_t (*field_get_flags)(FieldInfo *);

    // ---- type
    int (*type_get_type)(const Il2CppType *);
    char *(*type_get_name)(const Il2CppType *);

    // ---- thread / object
    void *(*thread_attach)(Il2CppDomain *);
    Il2CppObject *(*object_new)(Il2CppClass *);
    void *(*object_unbox)(Il2CppObject *);
    Il2CppClass *(*object_get_class)(Il2CppObject *);

    // ---- string
    char *(*string_to_utf8)(Il2CppObject *);
} WZIl2Cpp;

extern WZIl2Cpp g_il2;

// 解析全部符号。verbose=0 时不打印缺失项（重试轮询用）。
// 返回 1 = 必需 API 齐全。
int wz_il2cpp_init_ex(int verbose);
int wz_il2cpp_init(void);

// 运行时是否真的可用（domain 非空且 assembly 列表非空）
int wz_il2cpp_ready(void);

// 轮询等待就绪，最多 maxSeconds 秒。返回实际等待秒数，超时返回 -1。
int wz_il2cpp_wait_ready(int maxSeconds, int verbose);

// UnityFramework 的实际加载基址（mach_header 地址），失败返回 0
uintptr_t wz_unityframework_base(void);

#ifdef __cplusplus
}
#endif
