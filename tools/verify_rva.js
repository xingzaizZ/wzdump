// verify_rva.js —— 把 skin.txt 里的 RVA 拿到 UnityFramework 二进制里验证
// ============================================================
// 目的：确认 dump 给出的 RVA 真的指向合法函数入口。
//
// 判断依据（arm64 函数序言的典型特征）：
//   函数开头几乎都是这几种指令之一：
//     stp  x29, x30, [sp, #-N]!    0xA9Bxxxxx / 0xA98xxxxx
//     sub  sp, sp, #N              0xD10xxxxx / 0xD11xxxxx
//     stp  xN, xM, [sp, #N]        0xA90xxxxx
//     pacibsp                      0xD503237F
//     ret（极短函数）               0xD65F03C0
//
// 如果读出来的指令不像序言，说明 RVA 错了（版本不匹配 / dumper 算错）。
// ============================================================
const fs = require('fs');

const SKIN_JSON = process.argv[2] || 'skin_chain.json';
const BINARY = process.argv[3] || 'C:\\Users\\Administrator\\Downloads\\UnityFramework';

// UnityFramework 的段信息（前面已解析出来）
const TEXT_VMADDR = 0x4000;
const TEXT_FILEOFF = 16384;

const chain = JSON.parse(fs.readFileSync(SKIN_JSON, 'utf8'));
const fd = fs.openSync(BINARY, 'r');

function readInsn(rva) {
  const fileoff = TEXT_FILEOFF + (rva - TEXT_VMADDR);
  const buf = Buffer.alloc(16);
  fs.readSync(fd, buf, 0, 16, fileoff);
  return buf;
}

function classify(w) {
  // 关键：JS 位运算是**有符号 32 位**，0xA9BE4FF4 这种值会是负数。
  // 所有掩码比较必须两边都 >>> 0 转成无符号，否则永远不相等。
  const u = w >>> 0;
  const m = (mask) => ((u & (mask >>> 0)) >>> 0);

  // stp  (pre-index, 64-bit): 1010 1001 10 imm7 Rt2 Rn Rt
  if (m(0xFFC00000) === 0xA9800000) return 'stp.pre';
  // stp  (signed offset, 64-bit): 1010 1001 00 imm7 ...
  if (m(0xFFC00000) === 0xA9000000) return 'stp';
  // stp  (post-index): 1010 1000 10 ...
  if (m(0xFFC00000) === 0xA8800000) return 'stp.post';
  // stp  向量寄存器变体
  if (m(0xFFC00000) === 0xAD000000) return 'stp.vec';
  if (m(0xFFC00000) === 0xAC800000) return 'stp.vec.pre';
  // sub sp, sp, #imm  : 1101 0001 00 imm12 11111 11111
  if (m(0xFF8003FF) === 0xD10003FF) return 'sub sp';
  // add sp, sp, #imm
  if (m(0xFF8003FF) === 0x910003FF) return 'add sp';
  // mov x29, sp
  if (u === 0x910003FD) return 'mov fp,sp';
  // pacibsp / paciasp
  if (u === 0xD503237F) return 'pacibsp';
  if (u === 0xD503233F) return 'paciasp';
  // ret
  if (u === 0xD65F03C0) return 'ret';
  // nop
  if (u === 0xD503201F) return 'nop';
  // str (single reg store) 也可能出现在开头
  if (m(0xFFC00000) === 0xF9000000) return 'str';
  return null;
}

const KEY_METHODS = [];
for (const [cls, info] of Object.entries(chain)) {
  for (const m of info.methods) {
    KEY_METHODS.push({ cls, name: m.name, pcount: m.pcount, rva: m.rva });
  }
}

// 只验皮肤判定链路的（避免 38720 个全验）
const FILTER = /^(Is|Check|Update|Get).*(Skin|Mask)|^OnAddHeroSkin|^GetMasterRoleInfo|^GetAllSkinIDs|^ResolveHeroSkin/i;
const targets = KEY_METHODS.filter(m => FILTER.test(m.name) && /CRoleInfo|CSkinInfo|CHeroInfo/.test(m.cls));

console.log(`待验证方法: ${targets.length} 个\n`);

let ok = 0, bad = 0;
const badList = [];

for (const m of targets) {
  const buf = readInsn(m.rva);
  const w0 = buf.readUInt32LE(0);
  const w1 = buf.readUInt32LE(4);
  const c0 = classify(w0);
  const c1 = classify(w1);

  const hex = [...buf.slice(0, 12)].map(x => x.toString(16).padStart(2, '0')).join(' ');

  // 判定：第一条或第二条是已知序言就算对
  const good = c0 !== null || c1 !== null;
  if (good) {
    ok++;
  } else {
    bad++;
    badList.push({ ...m, hex, w0: '0x' + (w0 >>> 0).toString(16) });
  }
}

console.log(`✓ 合法函数序言: ${ok} / ${targets.length}`);
console.log(`✗ 不像函数序言: ${bad} / ${targets.length}`);
console.log('');

if (badList.length) {
  console.log('=== 可疑 RVA（前 30 个）===');
  for (const b of badList.slice(0, 30)) {
    console.log(`  0x${b.rva.toString(16).padStart(8)}  ${b.cls}::${b.name}/${b.pcount}`);
    console.log(`      首 12 字节: ${b.hex}`);
    console.log(`      首指令: ${b.w0}`);
  }
  console.log('');
}

// 单独列关键入口的详细情况
console.log('=== 关键入口详细 ===');
const CRITICAL = [
  ['CRoleInfo', 'IsHaveHeroSkin', 5],
  ['CRoleInfo', 'IsHaveHeroSkin', 4],
  ['CRoleInfo', 'IsCanUseSkin', 3],
  ['CRoleInfo', 'IsCanUseSkin', 2],
  ['CRoleInfo', 'OnAddHeroSkin', 2],
  ['CRoleInfo', 'GetHeroSkinState', 2],
  ['CRoleInfoManager', 'GetMasterRoleInfo', 0],
  ['CSkinInfo', 'IsHaveHeroSkin', 5],
  ['CSkinInfo', 'IsHaveHeroSkin', 4],
  ['CSkinInfo', 'IsCanBuy', 2],
  ['CSkinInfo', 'IsCanGet', 3],
  ['CSkinInfo', 'GetAllSkinIDs', 0],
  ['CSkinInfo', 'CheckSkinMaskBit', 2],
  ['CSkinInfo', 'UpdateSkinMaskBits', 2],
  ['CSkinInfo', 'ResolveHeroSkin', 3],
  ['CHeroInfo', 'IsOwnHero', 0],
];

for (const [cls, name, pc] of CRITICAL) {
  const info = chain[cls];
  if (!info) { console.log(`  ${cls}  不在 dump 里`); continue; }
  const m = info.methods.find(x => x.name === name && x.pcount === pc);
  if (!m) { console.log(`  ${cls}::${name}/${pc}  未找到`); continue; }

  const buf = readInsn(m.rva);
  const w0 = buf.readUInt32LE(0);
  const w1 = buf.readUInt32LE(4);
  const c0 = classify(w0), c1 = classify(w1);
  const good = c0 || c1;
  const hex = [...buf.slice(0, 12)].map(x => x.toString(16).padStart(2, '0')).join(' ');
  console.log(`  ${good ? '✓' : '✗'} ${(cls + '::' + name + '/' + pc).padEnd(42)} RVA=0x${m.rva.toString(16).padStart(8)}  [${c0 || c1 || '未知'}]`);
  console.log(`      ${hex}`);
}

fs.closeSync(fd);

console.log('');
console.log('=== 结论 ===');
if (bad === 0) {
  console.log('  ✓ 全部 RVA 合法，可以直接用于 patch');
} else if (bad / targets.length < 0.1) {
  console.log(`  ⚠ ${bad} 个可疑（${(bad / targets.length * 100).toFixed(1)}%），多数合法`);
  console.log('    → 建议：只 patch 验证通过的，可疑的跳过');
} else {
  console.log(`  ✗ ${bad} 个可疑，占比过高`);
  console.log('    → RVA 与二进制不匹配，dump 可能来自不同版本');
}
