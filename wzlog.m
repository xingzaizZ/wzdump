// ============================================================
// wzlog.m —— 三路日志实现
// ============================================================
#include "wzlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>

#if defined(__APPLE__)
#  include <os/log.h>
#endif

// ---------------------------------------------------------------- 状态
static int g_fd = -1;
static char g_path[1024] = {0};
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_stage[128] = "init";

#if defined(__APPLE__)
static os_log_t g_oslog = NULL;
#endif

// ---------------------------------------------------------------- 找 Documents
// app 沙盒里的 Documents 路径形如：
//   /var/mobile/Containers/Data/Application/<UUID>/Documents
// 我们从自己的可执行路径往上找，或者直接读 HOME 环境变量。
static int wz_find_docs(char *out, size_t cap) {
    // 1) HOME 环境变量（最可靠，app 里一定有）
    const char *home = getenv("HOME");
    if (home && *home) {
        snprintf(out, cap, "%s/Documents", home);
        struct stat st;
        if (stat(out, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
        // Documents 不存在就建
        if (mkdir(out, 0755) == 0) return 0;
    }

    // 2) 从可执行路径推：.../Application/<UUID>/xxx.app/xxx
    //    往上两级是 Application/<UUID>，再进 Documents
    char exe[1024] = {0};
    uint32_t sz = sizeof(exe);
    extern int _NSGetExecutablePath(char *buf, uint32_t *bufsize);
    if (_NSGetExecutablePath(exe, &sz) == 0) {
        char *p = strstr(exe, ".app/");
        if (p) {
            *p = '\0';                       // 截到 xxx.app
            char *slash = strrchr(exe, '/'); // xxx.app 前的斜杠
            if (slash) {
                *slash = '\0';               // 截到 Application/<UUID>
                snprintf(out, cap, "%s/Documents", exe);
                struct stat st;
                if (stat(out, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
                if (mkdir(out, 0755) == 0) return 0;
            }
        }
    }

    // 3) 兜底：/tmp（一定能写，但重启会清）
    snprintf(out, cap, "/tmp");
    return -1;
}

int wzlog_init(const char *dir) {
    char base[1024] = {0};

    if (dir && *dir) {
        snprintf(base, sizeof(base), "%s", dir);
    } else {
        if (wz_find_docs(base, sizeof(base)) != 0) {
            // 找不到 Documents 就用 /tmp
            snprintf(base, sizeof(base), "/tmp");
        }
    }

    snprintf(g_path, sizeof(g_path), "%s/wzdump.log", base);

    // O_APPEND 保证多次运行不覆盖；O_CREAT 首次创建
    g_fd = open(g_path, O_WRONLY | O_CREAT | O_APPEND, 0644);

#if defined(__APPLE__)
    g_oslog = os_log_create("com.wzdump.dumper", "dump");
#endif

    if (g_fd < 0) {
        fprintf(stderr, "[wzdump] 日志文件打不开: %s\n", g_path);
        return -1;
    }

    // 写个分隔，区分不同次运行
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tmv;
    time_t sec = tv.tv_sec;
    localtime_r(&sec, &tmv);

    char head[512];
    int n = snprintf(head, sizeof(head),
        "\n========== wzdump 启动 %04d-%02d-%02d %02d:%02d:%02d.%03d  pid=%d ==========\n",
        tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
        tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (int)(tv.tv_usec / 1000),
        getpid());
    if (n > 0) {
        ssize_t w = write(g_fd, head, (size_t)n);
        (void)w;
    }
    fsync(g_fd);

    return 0;
}

const char *wzlog_path(void) { return g_path; }

void wzlog_close(void) {
    pthread_mutex_lock(&g_log_lock);
    if (g_fd >= 0) {
        fsync(g_fd);
        close(g_fd);
        g_fd = -1;
    }
    pthread_mutex_unlock(&g_log_lock);
}

void wzlog_stage(const char *stage) {
    if (!stage) return;
    pthread_mutex_lock(&g_log_lock);
    snprintf(g_stage, sizeof(g_stage), "%s", stage);
    pthread_mutex_unlock(&g_log_lock);
}

// ---------------------------------------------------------------- 写一行
void wzlog(char level, const char *fmt, ...) {
    char body[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof(body)) n = (int)sizeof(body) - 1;

    // 时间戳
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tmv;
    time_t sec = tv.tv_sec;
    localtime_r(&sec, &tmv);

    char line[2400];
    int m = snprintf(line, sizeof(line), "[%02d:%02d:%02d.%03d][%c] %s",
                     tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                     (int)(tv.tv_usec / 1000), level, body);
    if (m < 0) return;
    if ((size_t)m >= sizeof(line)) m = (int)sizeof(line) - 1;
    // 保证结尾有换行
    if (m > 0 && line[m - 1] != '\n') {
        if ((size_t)m + 1 < sizeof(line)) { line[m] = '\n'; line[m + 1] = '\0'; m++; }
    }

    // 1) 文件 —— 立即 write + fsync，保证崩之前已落盘
    pthread_mutex_lock(&g_log_lock);
    if (g_fd >= 0) {
        ssize_t w = write(g_fd, line, (size_t)m);
        (void)w;
        fsync(g_fd);
    }
    pthread_mutex_unlock(&g_log_lock);

#if defined(__APPLE__)
    // 2) os_log —— idevicesyslog / Console.app 能抓
    if (g_oslog) {
        // os_log 要求格式串是常量，这里用 "%{public}s"
        os_log_with_type(g_oslog, OS_LOG_TYPE_DEFAULT, "%{public}s", line);
    }
#endif

    // 3) stderr —— 调试器连上时可见
    fputs(line, stderr);
    fflush(stderr);
}

// ---------------------------------------------------------------- 崩溃兜底
// 信号处理里不能调 malloc / printf，只能用 write + _exit。
// 我们把「最后阶段」记在全局数组里，崩的时候直接 write 出去。
static void wz_crash_handler(int sig) {
    // 用 write 直接写，不经过 stdio 缓冲
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "\n!!! 收到信号 %d，最后阶段: %s !!!\n", sig, g_stage);
    if (n > 0) {
        if (g_fd >= 0) {
            ssize_t w = write(g_fd, buf, (size_t)n);
            (void)w;
        }
        ssize_t w2 = write(2, buf, (size_t)n);
        (void)w2;
    }
    if (g_fd >= 0) {
        fsync(g_fd);
        close(g_fd);
    }
    // 恢复默认处理并重新抛出，让系统生成 .ips
    signal(sig, SIG_DFL);
    raise(sig);
}

void wzlog_install_crash_handler(void) {
    static const int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGABRT, SIGFPE, SIGTRAP };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = wz_crash_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_NODEFER;
        sigaction(sigs[i], &sa, NULL);
    }
}
