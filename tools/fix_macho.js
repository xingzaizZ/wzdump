// fix_macho.js —— 修掉链接器生成的垃圾 LC_ENCRYPTION_INFO_64
// ============================================================
// 【问题】
//
//   clang 链接出来的 dylib 同时带两条加密命令：
//     LC_ENCRYPTION_INFO      (0x2c)  cryptid = 0     ← 正常
//     LC_ENCRYPTION_INFO_64   (0x29)  cryptid = 29    ← 垃圾！
//
//   而 cryptid 的合法值只有 0（未加密）和 1（已加密）。
//   29 是链接器把别的字段错位写进来的。
//
//   dyld 加载时看到 cryptid 既不是 0 也不是 1，直接拒绝加载 →
//   **constructor 一行都不执行 → 闪退且完全没日志**。
//
// 【修法】
//
//   把 LC_ENCRYPTION_INFO_64 的 cryptid 改成 0。
//   或者更彻底：整条命令删掉（改 cmd 为 LC_UUID 之类无害的，或填 0）。
//
//   这里选「改 cryptid = 0」—— 最安全，不动 load command 结构，
//   不改变 sizeofcmds，不破坏代码签名之外的任何东西。
//   （改完必须重新签名，签名会把 load command 区域一起算进 hash）
//
// 用法: node tools/fix_macho.js <dylib> [--dry]
// ============================================================
const fs = require('fs');

const CMD_ENCRYPTION_INFO = 0x2c;
const CMD_ENCRYPTION_INFO_64 = 0x29;
const CMD_NAMES = {
  0x2c: 'LC_ENCRYPTION_INFO',
  0x29: 'LC_ENCRYPTION_INFO_64',
};

function slices(buf) {
  const magic = buf.readUInt32BE(0);
  if (magic !== 0xcafebabe) return [{ off: 0, size: buf.length, label: 'single' }];
  const n = buf.readUInt32BE(4);
  const out = [];
  for (let i = 0; i < n; i++) {
    const p = 8 + i * 20;
    const sub = buf.readUInt32BE(p + 4);
    const off = buf.readUInt32BE(p + 8);
    const size = buf.readUInt32BE(p + 12);
    out.push({ off, size, label: sub === 0x80000002 ? 'arm64e' : 'arm64' });
  }
  return out;
}

function fixSlice(buf, slice, dry) {
  const base = slice.off;
  const ncmds = buf.readUInt32LE(base + 16);
  let p = base + 32;
  let fixed = 0;

  for (let j = 0; j < ncmds; j++) {
    const cmd = buf.readUInt32LE(p);
    const cs = buf.readUInt32LE(p + 4);

    if (cmd === CMD_ENCRYPTION_INFO || cmd === CMD_ENCRYPTION_INFO_64) {
      // LC_ENCRYPTION_INFO:    cmd(4) cmdsize(4) cryptoff(4) cryptsize(4) cryptid(4) = 20
      // LC_ENCRYPTION_INFO_64: cmd(4) cmdsize(4) cryptoff(4) cryptsize(4) cryptid(4) pad(4) = 24
      const cryptidOff = p + 16;
      const cryptid = buf.readUInt32LE(cryptidOff);

      if (cryptid !== 0 && cryptid !== 1) {
        const name = CMD_NAMES[cmd] || ('0x' + cmd.toString(16));
        const cryptoff = buf.readUInt32LE(p + 8);
        const cryptsize = buf.readUInt32LE(p + 12);
        console.log(`  ${slice.label}: ${name} @0x${p.toString(16)}`);
        console.log(`    cryptoff=${cryptoff} cryptsize=${cryptsize} cryptid=${cryptid}  ← 非法值（合法只有 0/1）`);
        if (!dry) {
          buf.writeUInt32LE(0, cryptidOff);
          console.log(`    -> 已改为 cryptid=0`);
        } else {
          console.log(`    -> [dry] 会改为 cryptid=0`);
        }
        fixed++;
      }
    }
    p += cs;
  }
  return fixed;
}

const target = process.argv[2];
const dry = process.argv.includes('--dry');
if (!target) {
  console.log('用法: node tools/fix_macho.js <dylib> [--dry]');
  process.exit(1);
}

const buf = fs.readFileSync(target);
const sl = slices(buf);

console.log(`文件: ${target}  (${buf.length} 字节, ${sl.length} 个 slice)`);
console.log('');

let total = 0;
for (const s of sl) {
  total += fixSlice(buf, s, dry);
}

console.log('');
if (total === 0) {
  console.log('✓ 没有非法 cryptid，无需修改');
} else if (dry) {
  console.log(`发现 ${total} 处非法 cryptid（dry run，未写入）`);
} else {
  fs.writeFileSync(target, buf);
  console.log(`✓ 已修 ${total} 处`);
  console.log('');
  console.log('!! 改完必须重新签名，否则 codesign -v 会失败：');
  console.log(`   codesign --force --sign - --timestamp=none ${target}`);
}
