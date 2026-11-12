// ============================================================
// pac_fix.h —— arm64e 指针认证（PAC）
// ============================================================
// 【为什么这个文件是必需的，不是可选优化】
//
// 我用 tools/scan_calls.js 扫过自己编出来的产物，结论是硬证据：
//
//   arm64e slice：47 处函数指针调用，全部编译成 BLRAAZ  → **验证 PAC**
//   arm64 slice ：同样的 47 处，编译成裸 BLR            → 不验证
//
// 也就是说，同一份源码，在 A12 及以后的机型上，编译器会把
// 「通过函数指针调用」改成先验签再跳。而我们拿到的地址有三个来源，
// 全都是**裸地址**（没有 PAC 签名）：
//
//   1) MethodInfo->methodPointer —— 从 il2cpp 元数据内存里读出来的
//   2) dlsym() 返回值             —— 动态链接器给的
//   3) 基址 + RVA 算出来的         —— 纯算术结果
//
// 裸地址交给 BLRAAZ → 验签失败 → 进程被 SIGKILL。
// 表现就是「打开游戏立刻闪退，一行日志都没有」。
//
// 正确做法：调用前用 ptrauth_sign_unauthenticated 重新签一遍。
// 反过来，要拿自己的函数地址去比较或读指令，必须先 strip 掉编译器
// 自动加的签名，否则比较永远不相等。
// ============================================================
#pragma once

#include <stdint.h>
#include <stddef.h>

#if defined(__APPLE__)
#  include <ptrauth.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------- 能力探测
#if defined(__has_feature)
#  if __has_feature(ptrauth_calls)
#    define WZ_HAS_PAC 1
#  endif
#endif
#ifndef WZ_HAS_PAC
#  define WZ_HAS_PAC 0
#endif

// ---------------------------------------------------------------- 架构名
#if defined(__arm64e__)
#  define WZ_ARCH_NAME "arm64e"
#elif defined(__arm64__) || defined(__aarch64__)
#  define WZ_ARCH_NAME "arm64"
#elif defined(__x86_64__)
#  define WZ_ARCH_NAME "x86_64"
#else
#  define WZ_ARCH_NAME "unknown"
#endif

// ---------------------------------------------------------------- 剥离签名
// 用途：拿到真实地址做算术（+RVA）、做比较、读指令。
// 不要用返回值直接调用 —— 调用请走 wz_pac_sign()。
static inline void *wz_pac_strip(const void *p) {
    if (!p) return NULL;
#if WZ_HAS_PAC
    return ptrauth_strip(p, ptrauth_key_function_pointer);
#else
    return (void *)(uintptr_t)p;
#endif
}

// ---------------------------------------------------------------- 签名（供调用）
// 用途：把裸地址变成可以安全被 BLRAAZ 调用的函数指针。
static inline void *wz_pac_sign(const void *raw) {
    if (!raw) return NULL;
#if WZ_HAS_PAC
    return ptrauth_sign_unauthenticated((void *)raw,
                                        ptrauth_key_function_pointer,
                                        0);
#else
    return (void *)(uintptr_t)raw;
#endif
}

// ---------------------------------------------------------------- 取裸地址
static inline uintptr_t wz_pac_raw(const void *p) {
    return (uintptr_t)wz_pac_strip(p);
}

#ifdef __cplusplus
}
#endif
