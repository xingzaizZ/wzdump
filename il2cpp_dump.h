// ============================================================
// il2cpp_dump.h —— 运行时 dump 接口
// ============================================================
// 把 Il2CppDumper 的静态解析改写成**运行时**遍历。
//
// 【为什么要改成运行时】
//
//   Il2CppDumper 原版在电脑上跑：
//     读 global-metadata.dat + libil2cpp.so 的符号表 → 离线解析
//
//   这次的情况：
//     · global-metadata.dat **未加密**（56MB, version 29）→ 静态其实可行
//     · 但静态解析需要 libil2cpp.so 的符号表来算 RVA
//     · iOS 上 il2cpp 代码在 UnityFramework 里，符号是 **stripped 的**
//       （只有导出符号，没有 MethodInfo 表）
//
//   所以：静态能拿类结构，但拿不到准确的函数地址。
//   运行时 dump 能拿到两者 —— 引擎已经把元数据解密并注册好了，
//   而且 il2cpp_class_get_methods 返回的 MethodInfo 里就有真实指针。
//
// 【输出格式】
//   与 Il2CppDumper 的产物对齐，方便直接用：
//     classes.txt      [idx] Namespace.Name : Parent
//     methods_all.txt  Namespace.Class::Method
//     fields_all.txt   Namespace.Class::field @offset
//     skin.txt         皮肤相关类详表（带 RVA）
//     summary.txt      概览
// ============================================================
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 执行 dump。outDir 为 NULL 时用 Documents/wz_dump。
// 返回 0 成功，负数失败。
int wz_dump_run(const char *outDir);

#ifdef __cplusplus
}
#endif
