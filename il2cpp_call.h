// ============================================================
// il2cpp_call.h —— 托管方法安全调用
// ============================================================
// 【IL2CPP 的真实函数签名】
//
//   IL2CPP 把每个 C# 方法编译成一个原生函数，签名固定为：
//
//     RET f(this?, 参数1, ..., 参数N, const MethodInfo *method)
//
//   尾参永远存在，静态方法也有（只是没有 this）。
//
// 【但反汇编告诉我们一个更准确的事实】
//
//   我反汇编了 CRoleInfo::OnAddHeroSkin/2 @0x1ee47d4：
//     +24  mov x22, x2      ← skinId
//     +28  mov x19, x1      ← heroId
//     +32  mov x20, x0      ← this
//     ...  函数体内**没有读 x3**
//
//   说明：对于参数少的函数，编译器可能根本不碰尾参所在的寄存器。
//   那为什么还要传？
//     · IsHaveHeroSkin/5 有 this+5参+尾参 = 7 个，x0~x6
//     · 我们只传 6 个，x6 是垃圾，函数内若用到就崩
//     · 传对了永远安全，传错了看运气 —— 不能靠运气
//
// 【arm64e 的致命问题】
//
//   我用 tools/scan_calls.js 扫自己的产物：
//     arm64e : 47 处函数指针调用 → 全部 BLRAAZ（验证 PAC）
//     arm64  : 同样 47 处        → 裸 BLR（不验证）
//
//   而 il2cpp 元数据里的 methodPointer、dlsym 返回值、RVA 算出来的地址
//   全是**裸地址**。交给 BLRAAZ = 验签失败 = SIGKILL。
//
//   所以：取地址先 strip 做算术，调用前 sign 回来。
// ============================================================
#pragma once

#include <stdint.h>
#include "il2cpp_api.h"
#include "pac_fix.h"

#ifdef __cplusplus
extern "C" {
#endif

// 从 MethodInfo 拿「可直接 CALL」的函数指针（已按架构签好名）
static inline void *wz_callable(MethodInfo *mi) {
    if (!mi) return NULL;
    void *raw = wz_method_pointer(mi);
    if (!raw) return NULL;
    return wz_pac_sign(raw);
}

// 从裸 RVA 拿可调用指针
static inline void *wz_callable_rva(uintptr_t imageBase, uint32_t rva) {
    if (!imageBase) return NULL;
    return wz_pac_sign((void *)(imageBase + rva));
}

// 统一调用宏：自动补尾参
//
//   WZ_CALL(MI, IsHave_t, role, heroId, skinId, 1, 0, 0)
//     ↓
//   ((IsHave_t)wz_pac_sign(wz_method_pointer(MI)))(role, heroId, skinId, 1, 0, 0, MI)
#define WZ_CALL(MI, FNTYPE, ...)                                       \
    ((FNTYPE)wz_pac_sign(wz_method_pointer(MI)))(__VA_ARGS__, (MI))

// 按 RVA 调用（不依赖 MethodInfo，用于 dump 里找不到 MethodInfo 的场景）
#define WZ_CALL_RVA(BASE, RVA, FNTYPE, MI, ...)                        \
    ((FNTYPE)wz_pac_sign((void *)((uintptr_t)(BASE) + (RVA))))(__VA_ARGS__, (MI))

#ifdef __cplusplus
}
#endif
