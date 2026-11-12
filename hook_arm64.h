// ============================================================
// hook_arm64.h —— 代码段改写
// ============================================================
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 让一段内存可写可执行。成功返回 0。
// 降级链：mprotect → vm_protect(带 COPY) → vm_protect(无 COPY)
int wz_make_rwx(void *addr, size_t len);

// 把函数头改成「立即返回常量」。
//   kind: 0 = bool (w0 = value ? 1 : 0)
//         1 = int32 (w0 = value)
//         2 = int64/指针 (x0 = value)
//
// 安全约束：写入前会扫描覆盖范围内是否有 ret。
// 如果函数体短到 ret 落在覆盖区内，说明会踩到相邻函数，直接拒绝（返回 -5）。
// 这就是为什么 CHeroInfo::IsOwnHero/0 会被拒绝 —— 它只有 3 条指令。
int wz_patch_return(void *fn, int kind, int64_t value);

// 同上，但跳过安全检查（已知函数足够长时用）
int wz_patch_return_force(void *fn, int kind, int64_t value);

// 撤销
int wz_unhook(void *fn, const uint8_t *saved, size_t len);

// 调试：把某地址前 4 条指令写进 buf
void wz_disasm_head(void *fn, char *buf, size_t buflen);

// 检查函数头前 16 字节是否含 PC 相对指令（含则不能搬移）
const char *wz_head_hazard(void *fn);

#ifdef __cplusplus
}
#endif
