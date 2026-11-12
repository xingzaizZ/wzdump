// verify_metadata.js —— 验证 global-metadata.dat 是否完整可解析
// ============================================================
// il2cpp metadata (version 29) 格式要点：
//
//   header = 66 个 int32，紧跟 magic(4) + version(4) 之后
//   每个 section 的 "count" 字段**有的是元素数，有的是字节大小**，
//   这一点极易搞错 —— 判断方法：off[i] + count[i] == off[i+1]
//   如果等式成立，说明 count 是字节大小。
//
//   实测本文件：
//     stringOffset(0x29c3f0) + stringCount(11644388) = 0xDB71D4
//     而 header[6] = 14381524 = 0xDB71D4  ✓ 所以 stringCount 是字节数
// ============================================================
const fs = require('fs');

const path = process.argv[2] || 'C:\\Users\\Administrator\\Downloads\\global-metadata.dat';
const buf = fs.readFileSync(path);

const magic = buf.readUInt32LE(0);
const version = buf.readInt32LE(4);

console.log('=== 基本信息 ===');
console.log('  文件大小 :', buf.length, '字节 (', (buf.length / 1048576).toFixed(1), 'MB )');
console.log('  magic    : 0x' + magic.toString(16).toUpperCase(), magic === 0xFAB11BAF ? '✓ 正确' : '✗ 错误');
console.log('  version  :', version, version === 29 ? '✓' : '');
console.log('');

// ---------------------------------------------------------------- header
const H = {};
const NAMES = [
  'stringLiteralOffset', 'stringLiteralCount', 'stringLiteralDataOffset', 'stringLiteralDataCount',
  'stringOffset', 'stringCount', 'eventsOffset', 'eventsCount',
  'propertiesOffset', 'propertiesCount', 'methodsOffset', 'methodsCount',
  'parameterDefaultValuesOffset', 'parameterDefaultValuesCount',
  'fieldDefaultValuesOffset', 'fieldDefaultValuesCount',
  'fieldAndParameterDefaultValueDataOffset', 'fieldAndParameterDefaultValueDataCount',
  'fieldMarshaledSizesOffset', 'fieldMarshaledSizesCount',
  'parametersOffset', 'parametersCount', 'fieldsOffset', 'fieldsCount',
  'genericParametersOffset', 'genericParametersCount',
  'genericParameterConstraintsOffset', 'genericParameterConstraintsCount',
  'genericContainersOffset', 'genericContainersCount',
  'nestedTypesOffset', 'nestedTypesCount', 'interfacesOffset', 'interfacesCount',
  'vtableMethodsOffset', 'vtableMethodsCount', 'interfaceOffsetsOffset', 'interfaceOffsetsCount',
  'typeDefinitionsOffset', 'typeDefinitionsCount', 'imagesOffset', 'imagesCount',
  'assembliesOffset', 'assembliesCount', 'fieldRefsOffset', 'fieldRefsCount',
  'referencedAssembliesOffset', 'referencedAssembliesCount',
  'attributeDataOffset', 'attributeDataCount',
  'attributeDataRangeOffset', 'attributeDataRangeCount',
  'unresolvedVirtualCallParameterTypesOffset', 'unresolvedVirtualCallParameterTypesCount',
  'unresolvedVirtualCallParameterRangesOffset', 'unresolvedVirtualCallParameterRangesCount',
  'windowsRuntimeTypeNamesOffset', 'windowsRuntimeTypeNamesSize',
  'windowsRuntimeStringsOffset', 'windowsRuntimeStringsSize',
  'exportedTypeDefinitionsOffset', 'exportedTypeDefinitionsCount',
];
for (let i = 0; i < NAMES.length; i++) {
  H[NAMES[i]] = buf.readInt32LE(8 + i * 4);
}

console.log('=== header section 范围检查 ===');
const pairs = [
  ['stringLiteral', 'stringLiteralOffset', 'stringLiteralCount'],
  ['stringLiteralData', 'stringLiteralDataOffset', 'stringLiteralDataCount'],
  ['string', 'stringOffset', 'stringCount'],
  ['methods', 'methodsOffset', 'methodsCount'],
  ['parameters', 'parametersOffset', 'parametersCount'],
  ['fields', 'fieldsOffset', 'fieldsCount'],
  ['typeDefinitions', 'typeDefinitionsOffset', 'typeDefinitionsCount'],
  ['images', 'imagesOffset', 'imagesCount'],
  ['assemblies', 'assembliesOffset', 'assembliesCount'],
  ['fieldRefs', 'fieldRefsOffset', 'fieldRefsCount'],
];
let allInRange = true;
for (const [label, offKey, cntKey] of pairs) {
  const off = H[offKey], cnt = H[cntKey];
  const end = off + cnt;
  const ok = off >= 0 && end <= buf.length && cnt >= 0;
  if (!ok) allInRange = false;
  console.log(`  ${label.padEnd(18)} off=0x${off.toString(16).padStart(8)} size/cnt=${String(cnt).padStart(9)}  end=0x${end.toString(16).padStart(8)}  ${ok ? '✓' : '✗'}`);
}
console.log('');

// ---------------------------------------------------------------- 字符串表
function readStr(idx) {
  if (idx < 0 || idx >= H.stringCount) return null;
  let p = H.stringOffset + idx;
  let end = p;
  while (end < buf.length && buf[end] !== 0) end++;
  if (end - p > 512) return null;
  return buf.toString('utf8', p, end);
}

// ---------------------------------------------------------------- 推断元素大小
// images: 已知 115 个（从 summary.txt），count 字段是字节数
const IMG_COUNT = 115;
const IMG_SIZE = Math.round(H.imagesCount / IMG_COUNT);
const ASM_COUNT = 115;
const ASM_SIZE = Math.round(H.assembliesCount / ASM_COUNT);

console.log('=== 推断结构尺寸 ===');
console.log(`  images      : ${H.imagesCount} 字节 / ${IMG_COUNT} 个 = ${IMG_SIZE} 字节每个`);
console.log(`  assemblies  : ${H.assembliesCount} 字节 / ${ASM_COUNT} 个 = ${ASM_SIZE} 字节每个`);
console.log('');

// ---------------------------------------------------------------- 验证 images
console.log('=== 验证 images（应输出 115 个 dll 名）===');
let imgOk = 0;
const imgNames = [];
for (let i = 0; i < IMG_COUNT; i++) {
  const base = H.imagesOffset + i * IMG_SIZE;
  if (base + 8 > buf.length) break;
  const nameIndex = buf.readInt32LE(base);
  const name = readStr(nameIndex);
  if (name && /^[\x20-\x7e]{1,80}$/.test(name)) { imgOk++; imgNames.push(name); }
}
console.log(`  成功读出 ${imgOk} / ${IMG_COUNT} 个 image 名`);
console.log(`  前 5 个: ${imgNames.slice(0, 5).join(', ')}`);
const expect = ['Scripts.System.dll', 'Scripts.Tdr.dll', 'Scripts.Base.dll'];
const hit = expect.filter(e => imgNames.includes(e));
console.log(`  关键 dll 命中: ${hit.length}/3  (${hit.join(', ')})`);
console.log('');

// ---------------------------------------------------------------- 验证 assemblies
console.log('=== 验证 assemblies ===');
let asmOk = 0;
for (let i = 0; i < ASM_COUNT; i++) {
  const base = H.assembliesOffset + i * ASM_SIZE;
  if (base + ASM_SIZE > buf.length) break;
  const imageIndex = buf.readInt32LE(base);
  if (imageIndex >= 0 && imageIndex < IMG_COUNT) asmOk++;
}
console.log(`  有效 imageIndex: ${asmOk} / ${ASM_COUNT}`);
console.log('');

// ---------------------------------------------------------------- 验证 typeDefinitions
console.log('=== 验证 typeDefinitions ===');
const TD_SIZE = Math.round(H.typeDefinitionsCount / 64102);
console.log(`  推断 TD 尺寸: ${H.typeDefinitionsCount} 字节 / 64102 个 = ${TD_SIZE} 字节每个`);
let tdOk = 0;
const tdSamples = [];
for (let i = 0; i < 20; i++) {
  const base = H.typeDefinitionsOffset + i * TD_SIZE;
  if (base + 8 > buf.length) break;
  const nameIndex = buf.readInt32LE(base);
  const nsIndex = buf.readInt32LE(base + 4);
  const name = readStr(nameIndex);
  const ns = readStr(nsIndex);
  if (name !== null && ns !== null) {
    tdOk++;
    if (tdSamples.length < 6) tdSamples.push(`${ns ? ns + '.' : ''}${name}`);
  }
}
console.log(`  前 20 个里有效: ${tdOk}`);
tdSamples.forEach(s => console.log(`    ${s}`));
console.log('');

// ---------------------------------------------------------------- 验证 methods
console.log('=== 验证 methods ===');
const M_SIZE = Math.round(H.methodsCount / 416780);
console.log(`  推断 method 尺寸: ${H.methodsCount} 字节 / 416780 个 = ${M_SIZE} 字节每个`);
let mOk = 0;
const mSamples = [];
for (let i = 0; i < 20; i++) {
  const base = H.methodsOffset + i * M_SIZE;
  if (base + 4 > buf.length) break;
  const nameIndex = buf.readInt32LE(base);
  const name = readStr(nameIndex);
  if (name && /^[A-Za-z_<>][A-Za-z0-9_<>`]{0,60}$/.test(name)) {
    mOk++;
    if (mSamples.length < 6) mSamples.push(name);
  }
}
console.log(`  前 20 个里有效: ${mOk}`);
console.log(`  样本: ${mSamples.join(', ')}`);
console.log('');

// ---------------------------------------------------------------- 找关键类
console.log('=== 搜索关键类型 ===');
const KEY = ['CRoleInfo', 'CSkinInfo', 'CHeroInfo', 'CRoleInfoManager'];
const found = {};
for (let i = 0; i < 64102; i++) {
  const base = H.typeDefinitionsOffset + i * TD_SIZE;
  if (base + 8 > buf.length) break;
  const nameIndex = buf.readInt32LE(base);
  const nsIndex = buf.readInt32LE(base + 4);
  const name = readStr(nameIndex);
  if (!name) continue;
  if (KEY.includes(name)) {
    const ns = readStr(nsIndex) || '';
    found[name] = { index: i, ns };
  }
}
for (const k of KEY) {
  if (found[k]) console.log(`  ✓ ${k}  -> typeDefinitions[${found[k].index}]  ns="${found[k].ns}"`);
  else console.log(`  ✗ ${k}  未找到`);
}
console.log('');

// ---------------------------------------------------------------- 结论
console.log('=== 结论 ===');
const good = allInRange && imgOk === IMG_COUNT && hit.length === 3 && Object.keys(found).length >= 3;
if (good) {
  console.log('  ✓ 元数据完整、未加密、可离线解析');
  console.log('    → 静态路线（Il2CppDumper 那套）完全可行');
  console.log('    → 但函数 RVA 必须从 UnityFramework 二进制里算，不能用静态推测');
} else {
  console.log('  ⚠ 部分验证未通过，见上方明细');
}
