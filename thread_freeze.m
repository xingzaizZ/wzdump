// ============================================================
// thread_freeze.m —— 线程冻结实现
// ============================================================
#include "thread_freeze.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/thread_act.h>

#define WZ_MAX_THREADS 1024

static thread_act_array_t g_threads = NULL;
static mach_msg_type_number_t g_count = 0;
static int g_depth = 0;              // 嵌套计数
static thread_t g_self = MACH_PORT_NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

int wz_threads_suspend(void) {
    pthread_mutex_lock(&g_lock);

    // 嵌套调用：只加计数，不重复暂停
    if (g_depth > 0) {
        g_depth++;
        pthread_mutex_unlock(&g_lock);
        return 0;
    }

    g_self = mach_thread_self();

    thread_act_array_t list = NULL;
    mach_msg_type_number_t n = 0;

    if (task_threads(mach_task_self(), &list, &n) != KERN_SUCCESS) {
        fprintf(stderr, "[wzdump][!] task_threads 失败，跳过线程冻结\n");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    if (n > WZ_MAX_THREADS) {
        fprintf(stderr, "[wzdump][!] 线程数 %u 超上限，跳过冻结\n", (unsigned)n);
        vm_deallocate(mach_task_self(), (vm_address_t)list,
                      n * sizeof(thread_t));
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    g_threads = list;
    g_count = n;

    int ok = 0;
    for (mach_msg_type_number_t i = 0; i < n; i++) {
        if (list[i] == g_self) continue;
        if (thread_suspend(list[i]) == KERN_SUCCESS) ok++;
    }

    g_depth = 1;
    pthread_mutex_unlock(&g_lock);
    return ok;
}

int wz_threads_resume(void) {
    pthread_mutex_lock(&g_lock);

    if (g_depth <= 0) {
        pthread_mutex_unlock(&g_lock);
        return 0;
    }

    g_depth--;
    if (g_depth > 0) {
        pthread_mutex_unlock(&g_lock);
        return 0;
    }

    int ok = 0;
    if (g_threads) {
        for (mach_msg_type_number_t i = 0; i < g_count; i++) {
            if (g_threads[i] == g_self) continue;
            if (thread_resume(g_threads[i]) == KERN_SUCCESS) ok++;
        }
        vm_deallocate(mach_task_self(), (vm_address_t)g_threads,
                      g_count * sizeof(thread_t));
        g_threads = NULL;
        g_count = 0;
    }

    pthread_mutex_unlock(&g_lock);
    return ok;
}
