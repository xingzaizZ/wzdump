// disasm_fn.js —— 粗粒度反汇编指定 RVA 的函数
// ============================================================
// 不需要完整反汇编器，只要能把前 N 条指令的编码翻译成人能读的形式，
// 用来判断：
//   · 函数返回什么类型（看 w0/x0 怎么写）
//   · 是不是纯读字段直接返回（这种 patch 最安全）
//   · 有没有调用其它函数（BL）
//
// 用法: node tools/disasm_fn.js <rva_hex> [指令条数]
// ============================================================
const fs = require('fs');

const BINARY = 'C:\\Users\\Administrator\\Downloads\\UnityFramework';
const TEXT_VMADDR = 0x4000;
const TEXT_FILEOFF = 16384;

const rva = parseInt(process.argv[2], 16);
const count = parseInt(process.argv[3] || '40', 10);

const fd = fs.openSync(BINARY, 'r');
const fileoff = TEXT_FILEOFF + (rva - TEXT_VMADDR);
const buf = Buffer.alloc(count * 4);
fs.readSync(fd, buf, 0, count * 4, fileoff);
fs.closeSync(fd);

// ---------------------------------------------------------------- 寄存器名
const X = (n) => (n === 31 ? 'sp' : 'x' + n);
const W = (n) => (n === 31 ? 'wzr' : 'w' + n);
const XZR = (n) => (n === 31 ? 'xzr' : 'x' + n);

function sext(v, bits) {
  const m = 1 << (bits - 1);
  return (v ^ m) - m;
}

function dec(w, addr) {
  const u = w >>> 0;
  const M = (mask) => ((u & (mask >>> 0)) >>> 0);
  const rd = u & 0x1f;
  const rn = (u >>> 5) & 0x1f;
  const rt = u & 0x1f;

  // ---- NOP / 系统
  if (u === 0xD503201F) return 'nop';
  if (u === 0xD503237F) return 'pacibsp';
  if (u === 0xD50323BF) return 'autibsp';
  if (u === 0xD503233F) return 'paciasp';
  if (u === 0xD50323FF) return 'autiasp';
  if (u === 0xD65F03C0) return 'ret';
  if (u === 0xD65F0BFF) return 'retaa';
  if (u === 0xD65F0FFF) return 'retab';
  if (u === 0xD503205F) return 'hint #0';

  // ---- BR / BLR
  if (M(0xFFFFFC1F) === 0xD61F0000) return `br ${X(rn)}`;
  if (M(0xFFFFFC1F) === 0xD63F0000) return `blr ${X(rn)}`;
  if (M(0xFFFFFC1F) === 0xD65F0000) return `ret ${X(rn)}`;
  // BLRAAZ / BLRABZ（验证 PAC）
  if (M(0xFFFFFC00) === 0xD63F0800) return `blraaz ${X(rn)}`;
  if (M(0xFFFFFC00) === 0xD63F0C00) return `blrabz ${X(rn)}`;

  // ---- B / BL（直接跳转）
  if ((u >>> 26) === 0b100101) {
    const imm = sext(u & 0x03FFFFFF, 26) * 4;
    return `bl 0x${(addr + imm).toString(16)}`;
  }
  if ((u >>> 26) === 0b000101) {
    const imm = sext(u & 0x03FFFFFF, 26) * 4;
    return `b 0x${(addr + imm).toString(16)}`;
  }

  // ---- 条件分支
  if (M(0xFF000010) === 0x54000000) {
    const imm = sext((u >>> 5) & 0x7FFFF, 19) * 4;
    const cond = u & 0xf;
    const C = ['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv'];
    return `b.${C[cond]} 0x${(addr + imm).toString(16)}`;
  }

  // ---- CBZ / CBNZ
  if (M(0x7E000000) === 0x34000000) {
    const sf = (u >>> 31) & 1;
    const op = (u >>> 24) & 1;
    const imm = sext((u >>> 5) & 0x7FFFF, 19) * 4;
    return `${op ? 'cbnz' : 'cbz'} ${sf ? X(rt) : W(rt)}, 0x${(addr + imm).toString(16)}`;
  }

  // ---- TBZ / TBNZ
  if (M(0x7E000000) === 0x36000000) {
    const op = (u >>> 24) & 1;
    const b5 = (u >>> 31) & 1;
    const b40 = (u >>> 19) & 0x1f;
    const bit = (b5 << 5) | b40;
    const imm = sext((u >>> 5) & 0x3FFF, 14) * 4;
    return `${op ? 'tbnz' : 'tbz'} ${X(rt)}, #${bit}, 0x${(addr + imm).toString(16)}`;
  }

  // ---- ADRP
  if (M(0x9F000000) === 0x90000000) {
    const immlo = (u >>> 29) & 3;
    const immhi = (u >>> 5) & 0x7FFFF;
    const imm = sext((immhi << 2) | immlo, 21) * 4096;
    const page = (addr & ~0xFFF) + imm;
    return `adrp ${X(rd)}, 0x${page.toString(16)}`;
  }
  // ---- ADR
  if (M(0x9F000000) === 0x10000000) {
    const immlo = (u >>> 29) & 3;
    const immhi = (u >>> 5) & 0x7FFFF;
    const imm = sext((immhi << 2) | immlo, 21);
    return `adr ${X(rd)}, 0x${(addr + imm).toString(16)}`;
  }
  // ---- ADD (immediate)
  if (M(0x7F800000) === 0x11000000) {
    const sf = (u >>> 31) & 1;
    const sh = (u >>> 22) & 1;
    const imm = (u >>> 10) & 0xFFF;
    return `add ${sf ? X(rd) : W(rd)}, ${sf ? X(rn) : W(rn)}, #${sh ? imm << 12 : imm}`;
  }
  // ---- SUB (immediate)
  if (M(0x7F800000) === 0x51000000) {
    const sf = (u >>> 31) & 1;
    const sh = (u >>> 22) & 1;
    const imm = (u >>> 10) & 0xFFF;
    return `sub ${sf ? X(rd) : W(rd)}, ${sf ? X(rn) : W(rn)}, #${sh ? imm << 12 : imm}`;
  }
  // ---- CMP (immediate) = SUBS with Rd=31
  if (M(0x7F800000) === 0x71000000 && rd === 31) {
    const sf = (u >>> 31) & 1;
    const imm = (u >>> 10) & 0xFFF;
    return `cmp ${sf ? X(rn) : W(rn)}, #${imm}`;
  }
  // ---- MOVZ / MOVK / MOVN
  if (M(0x7F800000) === 0x52800000) {
    const sf = (u >>> 31) & 1;
    const hw = (u >>> 21) & 3;
    const imm = (u >>> 5) & 0xFFFF;
    return `mov${sf ? '' : ''} ${sf ? X(rd) : W(rd)}, #${imm}${hw ? ', lsl #' + hw * 16 : ''}`;
  }
  if (M(0x7F800000) === 0x72800000) {
    const sf = (u >>> 31) & 1;
    const hw = (u >>> 21) & 3;
    const imm = (u >>> 5) & 0xFFFF;
    return `movk ${sf ? X(rd) : W(rd)}, #${imm}${hw ? ', lsl #' + hw * 16 : ''}`;
  }
  if (M(0x7F800000) === 0x12800000) {
    const sf = (u >>> 31) & 1;
    const imm = (u >>> 5) & 0xFFFF;
    return `movn ${sf ? X(rd) : W(rd)}, #${imm}`;
  }
  // ---- MOV (register) = ORR with Rn=31
  if (M(0xFFE0FFE0) === 0xAA0003E0) {
    const sf = (u >>> 31) & 1;
    return `mov ${sf ? X(rd) : W(rd)}, ${sf ? X((u >>> 16) & 0x1f) : W((u >>> 16) & 0x1f)}`;
  }

  // ---- LDR / STR（各种变体）
  // LDR (immediate, unsigned offset, 64-bit)
  if (M(0xFFC00000) === 0xF9400000) {
    const imm = ((u >>> 10) & 0xFFF) * 8;
    return `ldr ${X(rt)}, [${X(rn)}${imm ? ', #' + imm : ''}]`;
  }
  // LDR (32-bit)
  if (M(0xFFC00000) === 0xB9400000) {
    const imm = ((u >>> 10) & 0xFFF) * 4;
    return `ldr ${W(rt)}, [${X(rn)}${imm ? ', #' + imm : ''}]`;
  }
  // LDRB
  if (M(0xFFC00000) === 0x39400000) {
    return `ldrb ${W(rt)}, [${X(rn)}, #${(u >>> 10) & 0xFFF}]`;
  }
  // LDRH
  if (M(0xFFC00000) === 0x79400000) {
    return `ldrh ${W(rt)}, [${X(rn)}, #${((u >>> 10) & 0xFFF) * 2}]`;
  }
  // STR (64-bit)
  if (M(0xFFC00000) === 0xF9000000) {
    const imm = ((u >>> 10) & 0xFFF) * 8;
    return `str ${X(rt)}, [${X(rn)}${imm ? ', #' + imm : ''}]`;
  }
  // STR (32-bit)
  if (M(0xFFC00000) === 0xB9000000) {
    const imm = ((u >>> 10) & 0xFFF) * 4;
    return `str ${W(rt)}, [${X(rn)}${imm ? ', #' + imm : ''}]`;
  }
  // STRB
  if (M(0xFFC00000) === 0x39000000) {
    return `strb ${W(rt)}, [${X(rn)}, #${(u >>> 10) & 0xFFF}]`;
  }
  // LDR (literal)
  if (M(0x3B000000) === 0x18000000) {
    const sf = (u >>> 31) & 1;
    const imm = sext((u >>> 5) & 0x7FFFF, 19) * 4;
    return `ldr ${sf ? X(rt) : W(rt)}, =0x${(addr + imm).toString(16)}`;
  }
  // LDP (64-bit, signed offset)
  if (M(0xFFC00000) === 0xA9400000) {
    const rt2 = (u >>> 10) & 0x1f;
    const imm = sext((u >>> 15) & 0x7F, 7) * 8;
    return `ldp ${X(rt)}, ${X(rt2)}, [${X(rn)}${imm ? ', #' + imm : ''}]`;
  }
  // STP (pre-index)
  if (M(0xFFC00000) === 0xA9800000) {
    const rt2 = (u >>> 10) & 0x1f;
    const imm = sext((u >>> 15) & 0x7F, 7) * 8;
    return `stp ${X(rt)}, ${X(rt2)}, [${X(rn)}, #${imm}]!`;
  }
  // STP (signed offset)
  if (M(0xFFC00000) === 0xA9000000) {
    const rt2 = (u >>> 10) & 0x1f;
    const imm = sext((u >>> 15) & 0x7F, 7) * 8;
    return `stp ${X(rt)}, ${X(rt2)}, [${X(rn)}${imm ? ', #' + imm : ''}]`;
  }
  // LDP (post-index)
  if (M(0xFFC00000) === 0xA8C00000) {
    const rt2 = (u >>> 10) & 0x1f;
    const imm = sext((u >>> 15) & 0x7F, 7) * 8;
    return `ldp ${X(rt)}, ${X(rt2)}, [${X(rn)}], #${imm}`;
  }
  // AND (immediate)
  if (M(0x7F800000) === 0x12000000) {
    const sf = (u >>> 31) & 1;
    const imm = (u >>> 10) & 0xFFF;
    return `and ${sf ? X(rd) : W(rd)}, ${sf ? X(rn) : W(rn)}, #0x${imm.toString(16)}`;
  }
  // CSEL / CSET 族
  if (M(0xFFE00C00) === 0x1A800000) {
    const cond = (u >>> 12) & 0xf;
    const C = ['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv'];
    return `csel ${W(rd)}, ${W(rn)}, ${W((u >>> 16) & 0x1f)}, ${C[cond]}`;
  }
  // EOR
  if (M(0x7F200000) === 0x4A000000) {
    const sf = (u >>> 31) & 1;
    return `eor ${sf ? X(rd) : W(rd)}, ${sf ? X(rn) : W(rn)}, ${sf ? X((u >>> 16) & 0x1f) : W((u >>> 16) & 0x1f)}`;
  }

  return `??? 0x${u.toString(16).padStart(8, '0')}`;
}

console.log(`RVA 0x${rva.toString(16)}  (file offset ${fileoff})`);
console.log('');
for (let i = 0; i < count; i++) {
  const w = buf.readUInt32LE(i * 4);
  const addr = rva + i * 4;
  const txt = dec(w, addr);
  const raw = w.toString(16).padStart(8, '0');
  console.log(`  +${String(i * 4).padStart(3)}  0x${addr.toString(16).padStart(8)}  ${raw}  ${txt}`);
}
