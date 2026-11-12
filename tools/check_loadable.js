// check_loadable.js —— 检查 dylib 是否会被 dyld 接受
// ============================================================
// 这三项任何一项不过，注入后都是「闪退且完全没日志」：
//
//   1. filetype 必须是 MH_DYLIB(6)
//      如果是 MH_EXECUTE(2) 或 MH_OBJECT(1)，dyld 不会当动态库加载
//
//   2. 所有 LC_ENCRYPTION_INFO* 的 cryptid 必须是 0 或 1
//      链接器 bug 会写出 29 这种垃圾值 → dyld 直接拒绝 →
//      constructor 一行都不执行 → 闪退无日志
//
//   3. 不能有 LC_MAIN(0x80000028) / LC_UNIXTHREAD(0x5)
//      那是可执行文件才有的，出现在 dylib 里会被拒绝
//
// 用法: node tools/check_loadable.js <dylib>
const fs = require('fs');

const path = process.argv[2];
if (!path) {
  console.log('用法: node tools/check_loadable.js <dylib>');
  process.exit(1);
}

const buf = fs.readFileSync(path);

function slices(b) {
  const magic = b.readUInt32BE(0);
  if (magic !== 0xcafebabe) return [{ off: 0, size: b.length, label: 'single' }];
  const n = b.readUInt32BE(4);
  const out = [];
  for (let i = 0; i < n; i++) {
    const p = 8 + i * 20;
    const sub = b.readUInt32BE(p + 4);
    const off = b.readUInt32BE(p + 8);
    const size = b.readUInt32BE(p + 12);
    out.push({ off, size, label: sub === 0x80000002 ? 'arm64e' : 'arm64' });
  }
  return out;
}

const FILE_TYPES = {
  1: 'MH_OBJECT', 2: 'MH_EXECUTE', 3: 'MH_FVMLIB', 4: 'MH_CORE',
  5: 'MH_PRELOAD', 6: 'MH_DYLIB', 7: 'MH_DYLINKER', 8: 'MH_BUNDLE',
  9: 'MH_DYLIB_STUB', 10: 'MH_DSYM', 11: 'MH_KEXT_BUNDLE',
};

const sl = slices(buf);
console.log(`文件: ${path}  (${buf.length} 字节, ${sl.length} 个 slice)`);
console.log('');

let errors = 0;
let warnings = 0;

for (const s of sl) {
  const base = s.off;
  const filetype = buf.readUInt32LE(base + 12);
  const ncmds = buf.readUInt32LE(base + 16);

  console.log(`--- ${s.label} ---`);
  console.log(`  filetype = ${filetype} (${FILE_TYPES[filetype] || '?'})`);

  if (filetype !== 6) {
    console.log(`  ✗ 必须是 MH_DYLIB(6)，否则 dyld 不当动态库加载`);
    errors++;
  } else {
    console.log(`  ✓ MH_DYLIB`);
  }

  let p = base + 32;
  let hasEnc = false;
  let hasMain = false;
  let hasThread = false;

  for (let j = 0; j < ncmds; j++) {
    const cmd = buf.readUInt32LE(p);
    const cs = buf.readUInt32LE(p + 4);

    if (cmd === 0x2c || cmd === 0x29) {
      hasEnc = true;
      const cryptoff = buf.readUInt32LE(p + 8);
      const cryptsize = buf.readUInt32LE(p + 12);
      const cryptid = buf.readUInt32LE(p + 16);
      const name = cmd === 0x2c ? 'LC_ENCRYPTION_INFO' : 'LC_ENCRYPTION_INFO_64';
      if (cryptid !== 0 && cryptid !== 1) {
        console.log(`  ✗ ${name}: cryptid=${cryptid} 非法（合法只有 0/1）`);
        console.log(`      → dyld 会拒绝加载，constructor 不会执行，闪退且无日志`);
        errors++;
      } else {
        console.log(`  ✓ ${name}: cryptid=${cryptid} (cryptoff=${cryptoff} cryptsize=${cryptsize})`);
      }
    }
    if (cmd === 0x80000028 || cmd === 0x28) hasMain = true;
    if (cmd === 0x5) hasThread = true;

    p += cs;
  }

  if (!hasEnc) console.log(`  · 无加密命令（正常）`);

  if (hasMain) {
    console.log(`  ✗ 有 LC_MAIN —— 那是可执行文件的，dylib 不该有`);
    errors++;
  }
  if (hasThread) {
    console.log(`  ✗ 有 LC_UNIXTHREAD —— 同上`);
    errors++;
  }

  // 检查签名
  p = base + 32;
  let csOff = -1, csSz = -1;
  for (let j = 0; j < ncmds; j++) {
    const cmd = buf.readUInt32LE(p);
    const cs = buf.readUInt32LE(p + 4);
    if (cmd === 0x1d) { csOff = buf.readUInt32LE(p + 8); csSz = buf.readUInt32LE(p + 12); }
    p += cs;
  }
  if (csOff < 0) {
    console.log(`  ✗ 没有 LC_CODE_SIGNATURE —— 未签名，越狱机可能拒绝加载`);
    errors++;
  } else {
    const blob = buf.slice(base + csOff, base + csOff + csSz);
    const cnt = blob.readUInt32BE(8);
    let foundCD = false;
    let flagsVal = -1;
    for (let k = 0; k < cnt; k++) {
      const o = blob.readUInt32BE(16 + k * 8);
      const m = blob.readUInt32BE(o);
      if (m === 0xfade0c02) {
        foundCD = true;
        flagsVal = blob.readUInt32BE(o + 12);
      }
    }
    if (!foundCD) {
      console.log(`  ✗ 签名里没有 CodeDirectory`);
      errors++;
    } else if (!(flagsVal & 0x2)) {
      console.log(`  ⚠ CodeDirectory flags=0x${flagsVal.toString(16)}，缺 CS_ADHOC(0x2)`);
      warnings++;
    } else {
      console.log(`  ✓ 签名有效（flags=0x${flagsVal.toString(16)}, ADHOC）`);
    }
  }
  console.log('');
}

console.log('=== 结论 ===');
if (errors === 0) {
  console.log(`  ✓ 可加载${warnings ? `（${warnings} 个警告）` : ''}`);
  process.exit(0);
} else {
  console.log(`  ✗ ${errors} 项不合格，注入后会闪退`);
  console.log(`    修法：node tools/fix_macho.js <dylib> 然后重新 codesign`);
  process.exit(1);
}
