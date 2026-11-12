// analyze_skin.js —— 从 skin.txt 提取皮肤链路完整信息
// ============================================================
// 输出：
//   1. 关键类的完整方法表（名字 + 参数个数 + RVA）
//   2. 关键类的完整字段表（名字 + 偏移）
//   3. 按 RVA 排序，检查是否有重叠（判断 dumper 的 RVA 是否可信）
//   4. 皮肤判定链路的所有候选方法
// ============================================================
const fs = require('fs');

const path = process.argv[2] || 'C:\\Users\\Administrator\\Downloads\\多久\\skin.txt';
const raw = fs.readFileSync(path, 'utf8');
const lines = raw.split('\n');

// ---------------------------------------------------------------- 解析
// 格式：
//   // Namespace.Class   instance_size=N   image=Xxx.dll
//   // ========================================================
//     method Name(? a, ? b)   // RVA 0x1234
//     field  ? name   // 0x10
const classes = [];
let cur = null;

for (let i = 0; i < lines.length; i++) {
  const ln = lines[i];
  const m = ln.match(/^\/\/\s+([\w.<>`+\-]+)\s+instance_size=(\d+)\s+image=(\S+)/);
  if (m) {
    if (cur) classes.push(cur);
    cur = { name: m[1], size: parseInt(m[2], 10), image: m[3], methods: [], fields: [], line: i + 1 };
    continue;
  }
  if (!cur) continue;

  const mm = ln.match(/^\s+method\s+(\S+?)\((.*?)\)\s+\/\/\s+RVA\s+0x([0-9a-fA-F]+)/);
  if (mm) {
    const params = mm[2].trim();
    const pcount = params === '' ? 0 : params.split(',').length;
    cur.methods.push({ name: mm[1], params, pcount, rva: parseInt(mm[3], 16) });
    continue;
  }
  const mf = ln.match(/^\s+field\s+(\S+?)\s+(\S+?)\s+\/\/\s+0x([0-9a-fA-F]+)/);
  if (mf) {
    cur.fields.push({ type: mf[1], name: mf[2], off: parseInt(mf[3], 16) });
    continue;
  }
}
if (cur) classes.push(cur);

console.log(`解析出 ${classes.length} 个类`);

// ---------------------------------------------------------------- 去重
// dumper 可能重复输出同一个类，按 name 去重
const byName = new Map();
for (const c of classes) {
  if (!byName.has(c.name)) byName.set(c.name, c);
}
console.log(`去重后 ${byName.size} 个类`);
console.log('');

// ---------------------------------------------------------------- 关键类
const KEY = [
  'Assets.Scripts.GameSystem.CRoleInfo',
  'Assets.Scripts.GameSystem.CSkinInfo',
  'Assets.Scripts.GameSystem.CHeroInfo',
  'Assets.Scripts.GameSystem.CRoleInfoManager',
];

function short(n) { return n.split('.').pop(); }

for (const key of KEY) {
  const c = byName.get(key);
  if (!c) { console.log(`### ${key}  —— 未找到\n`); continue; }

  console.log(`### ${short(key)}   instance_size=${c.size}   image=${c.image}`);
  console.log(`    方法 ${c.methods.length} 个，字段 ${c.fields.length} 个`);
  console.log('');

  // 皮肤/英雄相关方法
  const kw = /Skin|Hero|Own|Buy|Get|Trial|Train|Valid|Mask|Wear|Experience|Limit/i;
  const rel = c.methods.filter(m => kw.test(m.name));
  console.log(`  --- 相关方法（${rel.length} 个）---`);
  for (const m of rel) {
    const tag = /^Is/.test(m.name) ? 'BOOL? ' : '';
    console.log(`    ${tag}${m.name}/${m.pcount}  RVA=0x${m.rva.toString(16)}  (${m.params || '无参'})`);
  }
  console.log('');

  // 字段
  if (c.fields.length) {
    console.log(`  --- 字段（${c.fields.length} 个）---`);
    for (const f of c.fields) {
      console.log(`    ${f.name}  @0x${f.off.toString(16)}  (${f.type})`);
    }
    console.log('');
  }
}

// ---------------------------------------------------------------- RVA 重叠检查
console.log('=== RVA 合理性检查 ===');
const allMethods = [];
for (const c of byName.values()) {
  for (const m of c.methods) allMethods.push({ cls: short(c.name), ...m });
}
allMethods.sort((a, b) => a.rva - b.rva);
console.log(`  总方法数: ${allMethods.length}`);

let dup = 0, minGap = Infinity, minPair = null;
for (let i = 1; i < allMethods.length; i++) {
  const gap = allMethods[i].rva - allMethods[i - 1].rva;
  if (gap === 0) {
    dup++;
    if (dup <= 5) {
      console.log(`  ⚠ RVA 重复 0x${allMethods[i].rva.toString(16)}: ${allMethods[i-1].cls}::${allMethods[i-1].name} 与 ${allMethods[i].cls}::${allMethods[i].name}`);
    }
  }
  if (gap > 0 && gap < minGap) { minGap = gap; minPair = [allMethods[i - 1], allMethods[i]]; }
}
console.log(`  RVA 重复数: ${dup}`);
console.log(`  最小间隔: ${minGap} 字节  (${minPair ? minPair[0].cls + '::' + minPair[0].name + ' -> ' + minPair[1].cls + '::' + minPair[1].name : 'n/a'})`);
console.log(`  RVA 范围: 0x${allMethods[0].rva.toString(16)} .. 0x${allMethods[allMethods.length-1].rva.toString(16)}`);
console.log('');

// ---------------------------------------------------------------- 皮肤判定链路候选
console.log('=== 皮肤判定链路：所有 Is*Skin* / *Mask* 方法 ===');
const chain = allMethods.filter(m => /^(Is|Check|Update|Get).*(Skin|Mask)/i.test(m.name));
const grouped = new Map();
for (const m of chain) {
  if (!grouped.has(m.cls)) grouped.set(m.cls, []);
  grouped.get(m.cls).push(m);
}
for (const [cls, ms] of [...grouped.entries()].sort((a, b) => b[1].length - a[1].length)) {
  if (!/CRoleInfo|CSkinInfo|CHeroInfo/.test(cls)) continue;
  console.log(`  ${cls}:`);
  for (const m of ms) console.log(`    ${m.name}/${m.pcount}  RVA=0x${m.rva.toString(16)}`);
}
console.log('');

// ---------------------------------------------------------------- 输出 JSON 供后续使用
const out = {};
for (const key of KEY) {
  const c = byName.get(key);
  if (!c) continue;
  out[short(key)] = {
    size: c.size,
    image: c.image,
    methods: c.methods.map(m => ({ name: m.name, pcount: m.pcount, rva: m.rva, params: m.params })),
    fields: c.fields.map(f => ({ name: f.name, off: f.off, type: f.type })),
  };
}
fs.writeFileSync('skin_chain.json', JSON.stringify(out, null, 2));
console.log('已写出 skin_chain.json');
