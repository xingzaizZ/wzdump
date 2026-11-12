// scan_calls.js —— 统计 __text 段控制流指令，判断 PAC 是否必需
// ============================================================
// 这是判断「arm64e 上裸函数指针调用会不会崩」的硬证据工具。
//
// 关键区别：
//   BLR Xn   —— 不验证 PAC，裸地址可以直接调
//   BLRAAZ   —— 验证 PAC，裸地址必崩（SIGKILL）
//
// 用法: node tools/scan_calls.js <dylib>
const fs = require('fs');

function textSection(buf) {
  const ncmds = buf.readUInt32LE(16);
  let p = 32;
  let textOff = 0, textSize = 0;
  for (let j = 0; j < ncmds; j++) {
    const cmd = buf.readUInt32LE(p);
    const cs = buf.readUInt32LE(p + 4);
    if (cmd === 0x19) {
      const nsects = buf.readUInt32LE(p + 64);
      let sp = p + 72;
      for (let k = 0; k < nsects; k++) {
        const sect = buf.toString('ascii', sp, sp + 16).replace(/\0/g, '');
        const sseg = buf.toString('ascii', sp + 16, sp + 32).replace(/\0/g, '');
        if (sseg === '__TEXT' && sect === '__text') {
          textOff = buf.readUInt32LE(sp + 48);
          textSize = Number(buf.readBigUInt64LE(sp + 40));
        }
        sp += 80;
      }
    }
    p += cs;
  }
  return { textOff, textSize };
}

function scan(path) {
  const buf = fs.readFileSync(path);
  const { textOff, textSize } = textSection(buf);
  if (!textSize) { console.log('找不到 __text'); return; }

  const n = { br: 0, blr: 0, bl: 0, b: 0, blraa: 0, blrab: 0, blraaz: 0, blrabz: 0,
              braa: 0, brab: 0, paci: 0, retab: 0 };

  // JS 位运算是有符号 32 位，必须 >>> 0 转无符号
  const U = (x) => x >>> 0;

  for (let i = 0; i < textSize; i += 4) {
    const w = U(buf.readUInt32LE(textOff + i));

    // 先判 BLRAA 族（掩码和 BLR 有重叠）
    if (U(w & 0xFFFFFC00) === 0xD73F0800) { n.blraa++; continue; }
    if (U(w & 0xFFFFFC00) === 0xD73F0C00) { n.blrab++; continue; }
    if (U(w & 0xFFFFFC00) === 0xD63F0800) { n.blraaz++; continue; }
    if (U(w & 0xFFFFFC00) === 0xD63F0C00) { n.blrabz++; continue; }
    if (U(w & 0xFFFFFC00) === 0xD71F0800) { n.braa++; continue; }
    if (U(w & 0xFFFFFC00) === 0xD71F0C00) { n.brab++; continue; }

    // 裸 BR / BLR
    if (U(w & 0xFFFFFC1F) === 0xD61F0000) { n.br++; continue; }
    if (U(w & 0xFFFFFC1F) === 0xD63F0000) { n.blr++; continue; }

    // 直接跳转（用 top-6 位）
    if ((w >>> 26) === 0b100101) { n.bl++; continue; }
    if ((w >>> 26) === 0b000101) { n.b++; continue; }
    if ((w >>> 24) === 0b01010100) { n.b++; continue; }

    if (w === 0xD503233F || w === 0xD503237F) n.paci++;
    if (w === 0xD65F0BFF || w === 0xD65F0FFF) n.retab++;
  }

  console.log(`__text: ${textSize} 字节 / ${textSize / 4} 条指令`);
  console.log(`  BL imm26              : ${n.bl}`);
  console.log(`  B  imm26 / B.cond     : ${n.b}`);
  console.log(`  BLR Xn  (不验 PAC)     : ${n.blr}`);
  console.log(`  BR  Xn  (不验 PAC)     : ${n.br}`);
  console.log(`  BLRAA/BLRAB (验 PAC)  : ${n.blraa} / ${n.blrab}`);
  console.log(`  BLRAAZ/BLRABZ (验 PAC): ${n.blraaz} / ${n.blrabz}`);
  console.log(`  BRAA/BRAB   (验 PAC)  : ${n.braa} / ${n.brab}`);
  console.log(`  PACIASP/PACIBSP       : ${n.paci}`);
  console.log(`  RETAA/RETAB           : ${n.retab}`);
  console.log('');

  const pacCalls = n.blraa + n.blrab + n.blraaz + n.blrabz + n.braa + n.brab;
  if (pacCalls === 0) {
    console.log('  结论：间接调用全走裸 BLR/BR，不验证 PAC。');
    console.log('        → wz_pac_sign() 非必需（但加了也无害）。');
  } else {
    console.log(`  结论：有 ${pacCalls} 处间接调用验证 PAC。`);
    console.log('        → **必须** wz_pac_sign()，否则 SIGKILL。');
  }
}

const target = process.argv[2];
if (!target) { console.log('用法: node tools/scan_calls.js <dylib>'); process.exit(1); }
scan(target);
