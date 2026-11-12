// ============================================================
// wzlog.h —— 三路日志（文件 / os_log / stderr）
// ============================================================
// 【为什么必须有这个文件】
//
// 上一版闪退后「没日志」，很可能不是没跑，而是**看不见**。
// iOS 上 fprintf(stderr) 的行为：
//   · 用 Xcode 调试器启动 → stderr 接到控制台，能看到
//   · 从桌面点图标启动   → stderr 写进 /dev/null，什么都看不到
//
// TrollFools 注入后从桌面启动，属于第二种。所以原来的日志系统
// 在真实使用场景下等于不存在。
//
// 修法：三路同时写。
//   1) 文件 —— 最可靠。写到 app 的 Documents 目录，用 Filza 就能看。
//      这是唯一在「已经闪退」之后还能读到的东西。
//   2) os_log —— 系统日志，idevicesyslog / Console.app 能抓。
//      带 subsystem 方便过滤。
//   3) stderr —— 调试器连上时用。
//
// 关键设计：**每次写都立即 flush**。因为闪退会丢缓冲区内容，
// 必须保证崩之前写的东西已经落盘。
// ============================================================
#pragma once

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

// 初始化日志。dir 为 NULL 时自动找 app 的 Documents 目录。
// 返回 0 = 成功，-1 = 文件打不开（此时仍会走 os_log / stderr）。
int wzlog_init(const char *dir);

// 日志文件路径（wzlog_init 之后有效）
const char *wzlog_path(void);

// 关闭并 flush
void wzlog_close(void);

// 写一行。level: 'I' 信息 / 'W' 警告 / 'E' 错误
void wzlog(char level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define LOGI(...) wzlog('I', __VA_ARGS__)
#define LOGW(...) wzlog('W', __VA_ARGS__)
#define LOGE(...) wzlog('E', __VA_ARGS__)

// 崩溃兜底：装信号处理器，崩之前把最后几行刷盘。
// 只做最小动作（write + _exit），不在信号处理里调 malloc。
void wzlog_install_crash_handler(void);

// 手动标记阶段，崩溃日志里能看到最后走到哪
void wzlog_stage(const char *stage);

#ifdef __cplusplus
}
#endif
