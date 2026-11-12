// check_abi.js —— 防闪退回归检查
// ============================================================
// 盯住这五个历史上真实踩过的坑：
//
//   R1  裸函数指针直接调用（arm64e 上 BLRAAZ 验签必崩）
//   R2  托管方法 typedef 缺 const MethodInfo* 尾参
//   R3  (Some_t)wz_method_pointer(...) 形式的强制转换调用
//   R4  constructor 里 pthread_create / malloc（dyld 阶段不安全）
//   R5  memcpy 改代码段但不冻结线程
//   R6  CheckSkinMaskBit patch 成 0（方向反了，实证返回 1 = 有效）
//
// 用法: node tools/check_abi.js wz_unlock.m il2cpp_api.m hook_arm64.m thread_freeze.m wzlog.m
const fs = require('fs');

function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, ' '))
            .replace(/\/\/[^\n]*/g, m => m.replace(/[^\n]/g, ' '));
}

function checkFile(path) {
  const raw = fs.readFileSync(path, 'utf8');
  const src = stripComments(raw);
  const problems = [];

  const lineOf = (idx) => src.slice(0, idx).split('\n').length;

  // ---- R1/R3：裸 method_pointer 直接调用
  let m;
  const re1 = /\(\s*(\w+_t)\s*\)\s*wz_method_pointer\s*\(/g;
  while ((m = re1.exec(src)) !== null) {
    problems.push({
      line: lineOf(m.index), rule: 'R1/R3',
      msg: `(${m[1]})wz_method_pointer(...) —— 裸地址直接当函数指针调用。` +
           `arm64e 上 BLRAAZ 会验签失败 → SIGKILL。改用 (${m[1]})wz_callable(mi)。`,
    });
  }
  const re2 = /\)\s*\(\s*wz_method_pointer\s*\(/g;
  while ((m = re2.exec(src)) !== null) {
    problems.push({
      line: lineOf(m.index), rule: 'R1',
      msg: '把 wz_method_pointer(...) 的结果直接调用。改用 wz_callable(mi) 或 WZ_CALL。',
    });
  }

  // ---- R2：托管方法 typedef 缺 MethodInfo 尾参
  const re3 = /typedef\s+[\w\s\*]+\(\s*\*\s*(\w+)\s*\)\s*\(([^)]*)\)\s*;/g;
  while ((m = re3.exec(src)) !== null) {
    const name = m[1];
    const params = m[2].trim();
    if (!/_t$/.test(name)) continue;
    const looksManaged = /Skin|Role|Hero|Master|Have|Buy|Get|Add|Cnt|Resolve|IsHave|OnAdd/i.test(name);
    if (!looksManaged) continue;
    if (!/MethodInfo/.test(params)) {
      problems.push({
        line: lineOf(m.index), rule: 'R2',
        msg: `typedef ${name}(${params}) —— 缺 const MethodInfo * 尾参。` +
             `IL2CPP 签名固定为 (this?, 参数..., const MethodInfo*)。`,
      });
    }
  }

  // ---- R4：constructor 里建线程 / 分配
  const ctorIdx = src.indexOf('__attribute__((constructor))');
  if (ctorIdx >= 0) {
    const braceStart = src.indexOf('{', ctorIdx);
    if (braceStart > 0) {
      let depth = 0, i = braceStart, end = -1;
      for (; i < src.length; i++) {
        if (src[i] === '{') depth++;
        else if (src[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
      }
      if (end > 0) {
        const body = src.slice(braceStart, end);
        const pcIdx = body.search(/pthread_create\s*\(/);
        if (pcIdx >= 0) {
          // 检查 pthread_create 之前是否有 usleep/sleep 让 dyld 收尾
          const before = body.slice(0, pcIdx);
          const hasWait = /usleep\s*\(|sleep\s*\(/.test(before);
          if (!hasWait) {
            problems.push({
              line: lineOf(braceStart), rule: 'R4',
              msg: 'constructor 里 pthread_create 之前没有 usleep/sleep —— ' +
                   'dyld 加载阶段建线程会和 dyld 锁竞争，必须先等 dyld 收尾。',
            });
          }
        }
        // malloc 检查只针对 constructor 函数体本身（不含被调函数）
        if (/\bmalloc\s*\(|\bcalloc\s*\(|\brealloc\s*\(/.test(body)) {
          problems.push({
            line: lineOf(braceStart), rule: 'R4',
            msg: 'constructor 里调 malloc —— malloc zone 此时可能未就绪。',
          });
        }
      }
    }
  }

  // ---- R5：改代码段不冻结线程
  if (/memcpy\s*\(\s*p\s*,/.test(src) && !/wz_threads_suspend/.test(src)) {
    problems.push({
      line: 0, rule: 'R5',
      msg: 'memcpy 改写代码段但没有 wz_threads_suspend —— 主线程跑到半条指令会 SIGILL/SIGSEGV。',
    });
  }

  // ---- R6：CheckSkinMaskBit patch 方向
  // 实证：返回 1 = 有效，返回 0 = 被封禁。patch 成 0 是灾难。
  const re6 = /patch_\w+\s*\(\s*"[^"]*CheckSkinMaskBit[^"]*"\s*,\s*[^,]+,\s*(\d+)\s*\)/g;
  while ((m = re6.exec(src)) !== null) {
    const val = parseInt(m[1], 10);
    if (val !== 1) {
      problems.push({
        line: lineOf(m.index), rule: 'R6',
        msg: `CheckSkinMaskBit patch 成 ${val}。实证：返回 1 = 皮肤有效，返回 0 = 被封禁。` +
             `patch 成 0 会让所有皮肤失效。必须 patch 成 1。`,
      });
    }
  }

  return problems;
}

let total = 0;
const files = process.argv.slice(2);
if (files.length === 0) {
  console.log('用法: node tools/check_abi.js <file...>');
  process.exit(1);
}

for (const f of files) {
  let probs;
  try {
    probs = checkFile(f);
  } catch (e) {
    console.log(`FAIL  ${f}: 读取失败 ${e.message}`);
    total++;
    continue;
  }
  if (probs.length === 0) {
    console.log(`OK    ${f}`);
  } else {
    total += probs.length;
    console.log(`FAIL  ${f}  (${probs.length} 处)`);
    for (const p of probs) {
      console.log(`        第 ${p.line} 行 [${p.rule}] ${p.msg}`);
    }
  }
}

console.log('');
if (total === 0) {
  console.log('全部通过：调用约定 / PAC / 线程冻结 / 逻辑方向 均无问题。');
} else {
  console.log(`共 ${total} 处问题。`);
}
process.exit(total === 0 ? 0 : 1);
