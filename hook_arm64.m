// ============================================================
// hook_arm64.m —— arm64 代码段改写
// ============================================================
// 只做一件事：把函数头改成 movz/movk + ret，让整函数返回指定值。
//
// 为什么不做 inline hook：
//   我们要改的 15 个函数全是「返回 bool」的判定函数，改返回值就够。
//   inline hook 要搬 16 字节到 trampoline，一旦函数头含 adrp/adr/b/bl
//   这些 PC 相对指令，搬走后相对距离就变了，执行必错。
//   返回常量没有这个问题 —— 不搬指令，直接覆盖。
//
// 【arm64e 注意】
//   这里写入的 movz/movk/ret 是纯数据写入，不涉及函数指针调用，
//   所以不需要 PAC 签名。但 mprotect 要能成功。
// ============================================================
#include "hook_arm64.h"
#include "pac_fix.h"
#include "thread_freeze.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>

static inline void *wz_strip(void *p) { return wz_pac_strip(p); }
static inline uint32_t *wz_pc(void *p) { return (uint32_t *)wz_strip(p); }

// ---------------------------------------------------------------- 内存权限
int wz_make_rwx(void *addr, size_t len) {
    void *a = wz_strip(addr);
    uintptr_t psz = (uintptr_t)getpagesize();
    uintptr_t page = (uintptr_t)a & ~(psz - 1);
    size_t span = ((uintptr_t)a + len) - page;

    // 1) 先试 mprotect：越狱环境 __TEXT 常常直接可写
    if (mprotect((void *)page, span, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        return 0;
    }

    // 2) 再走 mach vm_protect
    //    改私有映射的代码页必须带 VM_PROT_COPY（COW 标记），否则内核拒绝
    vm_prot_t tries[] = {
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_WRITE,
    };
    for (size_t i = 0; i < sizeof(tries) / sizeof(tries[0]); i++) {
        if (vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)span,
                       FALSE, tries[i]) == KERN_SUCCESS) {
            return 0;
        }
    }

    fprintf(stderr, "[wzdump] 无法把 %p 改为可写（%zu 字节）\n", a, span);
    return -1;
}

static inline void wz_flush(void *addr, size_t len) {
    sys_icache_invalidate(wz_strip(addr), len);
}

// ---------------------------------------------------------------- 指令编码
#define INSN_MOVZ_W(rd, imm16, lsl) (0x52800000u | (((uint32_t)((lsl) / 16) & 3u) << 21) | (((uint32_t)(imm16) & 0xFFFFu) << 5) | ((uint32_t)(rd) & 0x1Fu))
#define INSN_MOVK_W(rd, imm16, lsl) (0x72800000u | (((uint32_t)((lsl) / 16) & 3u) << 21) | (((uint32_t)(imm16) & 0xFFFFu) << 5) | ((uint32_t)(rd) & 0x1Fu))
#define INSN_MOVZ_X(rd, imm16, lsl) (0xD2800000u | (((uint32_t)((lsl) / 16) & 3u) << 21) | (((uint32_t)(imm16) & 0xFFFFu) << 5) | ((uint32_t)(rd) & 0x1Fu))
#define INSN_MOVK_X(rd, imm16, lsl) (0xF2800000u | (((uint32_t)((lsl) / 16) & 3u) << 21) | (((uint32_t)(imm16) & 0xFFFFu) << 5) | ((uint32_t)(rd) & 0x1Fu))
#define INSN_RET          0xD65F03C0u

static int wz_emit_return(uint32_t *out, int kind, int64_t value) {
    int n = 0;
    if (kind == 0) {
        out[n++] = INSN_MOVZ_W(0, value ? 1 : 0, 0);
    } else if (kind == 1) {
        uint32_t v = (uint32_t)value;
        out[n++] = INSN_MOVZ_W(0, v & 0xFFFFu, 0);
        if (v >> 16) out[n++] = INSN_MOVK_W(0, (v >> 16) & 0xFFFFu, 16);
    } else {
        uint64_t v = (uint64_t)value;
        out[n++] = INSN_MOVZ_X(0, v & 0xFFFFu, 0);
        if ((v >> 16) & 0xFFFFu) out[n++] = INSN_MOVK_X(0, (v >> 16) & 0xFFFFu, 16);
        if ((v >> 32) & 0xFFFFu) out[n++] = INSN_MOVK_X(0, (v >> 32) & 0xFFFFu, 32);
        if ((v >> 48) & 0xFFFFu) out[n++] = INSN_MOVK_X(0, (v >> 48) & 0xFFFFu, 48);
    }
    out[n++] = INSN_RET;
    return n;
}

// ---------------------------------------------------------------- 覆盖区安全
static int wz_is_padding(uint32_t insn) {
    if (insn == 0xD503201Fu) return 1;                  // nop
    if ((insn & 0xFFE0001Fu) == 0xD4200000u) return 1;  // brk #imm
    if (insn == 0x00000000u) return 1;                  // 全零
    return 0;
}

static int wz_is_ret(uint32_t insn) {
    if (insn == 0xD65F03C0u) return 1;                  // ret
    if (insn == 0xD65F0BFFu) return 1;                  // retaa
    if (insn == 0xD65F0FFFu) return 1;                  // retab
    if ((insn & 0xFFFFFC1Fu) == 0xD65F0000u) return 1;   // ret Xn
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) return 1;   // br Xn（尾调用）
    return 0;
}

static int wz_patch_span_safe(uint32_t *p, size_t bytes) {
    size_t words = bytes / 4;
    if (words == 0) return 0;

    for (size_t i = 0; i < words; i++) {
        if (!wz_is_ret(p[i])) continue;
        // ret 在最后一条：覆盖区正好落在函数体内
        if (i + 1 == words) return 0;
        // ret 在中间：后面的字节必须全是填充
        for (size_t j = i + 1; j < words; j++) {
            if (!wz_is_padding(p[j])) return -1;
        }
        return 0;
    }
    return 0;   // 覆盖区内没有 ret，函数更长，安全
}

// ---------------------------------------------------------------- 对外接口
int wz_patch_return_force(void *fn, int kind, int64_t value) {
    if (!fn) return -1;
    uint32_t *p = wz_pc(fn);

    uint32_t seq[8];
    int n = wz_emit_return(seq, kind, value);
    size_t len = (size_t)n * 4;
    if (len > 32) return -1;

    if (wz_make_rwx(p, 32) != 0) return -2;

    // 冻结其它线程：改指令期间主线程若正好跑到这几条，会取到半条指令
    int froze = wz_threads_suspend();
    memcpy(p, seq, len);
    wz_flush(p, len);
    if (froze > 0) wz_threads_resume();
    return 0;
}

int wz_patch_return(void *fn, int kind, int64_t value) {
    if (!fn) return -1;
    uint32_t *p = wz_pc(fn);

    uint32_t seq[8];
    int n = wz_emit_return(seq, kind, value);
    size_t len = (size_t)n * 4;
    if (len > 32) return -1;

    // 覆盖前先确认不会踩到相邻函数
    if (wz_patch_span_safe(p, len) != 0) {
        fprintf(stderr, "[wzdump] 拒绝 patch %p：函数体比 %zu 字节还短，会踩到相邻函数\n",
                fn, len);
        return -5;
    }

    if (wz_make_rwx(p, 32) != 0) return -2;

    int froze = wz_threads_suspend();
    memcpy(p, seq, len);
    wz_flush(p, len);
    if (froze > 0) wz_threads_resume();
    return 0;
}

int wz_unhook(void *fn, const uint8_t *saved, size_t len) {
    if (!fn || !saved || !len) return -1;
    if (wz_make_rwx(fn, len) != 0) return -2;
    int froze = wz_threads_suspend();
    memcpy(fn, saved, len);
    wz_flush(fn, len);
    if (froze > 0) wz_threads_resume();
    return 0;
}

// ---------------------------------------------------------------- 函数头安全
static const char *wz_hazard_of(uint32_t insn) {
    if ((insn & 0x9F000000u) == 0x90000000u) return "adrp";
    if ((insn & 0x9F000000u) == 0x10000000u) return "adr";
    if ((insn & 0x3B000000u) == 0x18000000u) return "ldr-literal";
    if ((insn & 0x7C000000u) == 0x14000000u) return "b/bl";
    if ((insn & 0x7E000000u) == 0x34000000u) return "cbz/cbnz";
    if ((insn & 0x7E000000u) == 0x36000000u) return "tbz/tbnz";
    return NULL;
}

const char *wz_head_hazard(void *fn) {
    if (!fn) return "null";
    uint32_t *p = wz_pc(fn);
    for (int i = 0; i < 4; i++) {
        const char *h = wz_hazard_of(p[i]);
        if (h) return h;
    }
    return NULL;
}

// ---------------------------------------------------------------- 反汇编打印
static const struct { uint32_t mask; uint32_t val; const char *name; } kNames[] = {
    { 0xFFFFFFFFu, 0xD65F03C0u, "ret" },
    { 0xFFFFFFFFu, 0xD503201Fu, "nop" },
    { 0xFFFFFC1Fu, 0xD2800000u, "movz.x" },
    { 0xFFFFFC1Fu, 0x52800000u, "movz.w" },
    { 0xFFFFFC1Fu, 0xF2800000u, "movk.x" },
    { 0xFFFFFC1Fu, 0x72800000u, "movk.w" },
    { 0xFFC00000u, 0xA9000000u, "stp" },
    { 0xFFC00000u, 0xA9800000u, "stp.pre" },
    { 0xFFC00000u, 0xA9400000u, "ldp" },
    { 0xFF800000u, 0x91000000u, "add.imm" },
    { 0xFF800000u, 0xD1000000u, "sub.imm" },
    { 0xFFC00000u, 0xF9400000u, "ldr.x" },
    { 0xFFC00000u, 0xB9400000u, "ldr.w" },
    { 0x9F000000u, 0x90000000u, "adrp" },
};

void wz_disasm_head(void *fn, char *buf, size_t buflen) {
    if (!fn || !buf || buflen < 8) return;
    uint32_t *p = wz_pc(fn);
    size_t off = 0;
    buf[0] = '\0';
    for (int i = 0; i < 4 && off + 24 < buflen; i++) {
        uint32_t insn = p[i];
        const char *nm = "?";
        for (size_t k = 0; k < sizeof(kNames) / sizeof(kNames[0]); k++) {
            if ((insn & kNames[k].mask) == kNames[k].val) { nm = kNames[k].name; break; }
        }
        off += (size_t)snprintf(buf + off, buflen - off, "%08x[%s] ", insn, nm);
    }
}
