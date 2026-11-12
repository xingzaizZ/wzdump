// check_syntax.js —— 轻量 C/ObjC 结构自查
// 不依赖编译器，逐字符扫描：跳过注释、字符串、字符字面量、预处理行，
// 然后检查 {} () [] 配对，并报告第一个失配位置（行号）。
const fs = require('fs');

function scan(src) {
  const stack = [];
  const errors = [];
  let line = 1;
  let i = 0;
  const n = src.length;
  let atLineStart = true;
  let inPreproc = false;

  const push = (ch, ln) => stack.push({ ch, line: ln });
  const pairs = { '}': '{', ')': '(', ']': '[' };

  while (i < n) {
    const c = src[i];

    if (c === '\n') {
      line++; i++; atLineStart = true; inPreproc = false; continue;
    }

    if (atLineStart) {
      let j = i;
      while (j < n && (src[j] === ' ' || src[j] === '\t' || src[j] === '\r')) j++;
      if (j < n && src[j] === '#') inPreproc = true;
      atLineStart = false;
      if (inPreproc) {
        while (i < n && src[i] !== '\n') {
          if (src[i] === '\\' && src[i + 1] === '\n') { i += 2; line++; continue; }
          i++;
        }
        continue;
      }
    }

    if (c === ' ' || c === '\t' || c === '\r') { i++; continue; }

    if (c === '/' && src[i + 1] === '/') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') line++;
        i++;
      }
      i += 2;
      continue;
    }
    if (c === '"') {
      const startLine = line;
      i++;
      while (i < n && src[i] !== '"') {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === '\n') line++;
        i++;
      }
      if (i >= n) errors.push({ msg: '字符串未闭合', line: startLine });
      i++;
      continue;
    }
    if (c === "'") {
      const startLine = line;
      i++;
      while (i < n && src[i] !== "'") {
        if (src[i] === '\\') { i += 2; continue; }
        i++;
      }
      if (i >= n) errors.push({ msg: '字符字面量未闭合', line: startLine });
      i++;
      continue;
    }

    if (c === '{' || c === '(' || c === '[') { push(c, line); i++; continue; }
    if (c === '}' || c === ')' || c === ']') {
      const want = pairs[c];
      const top = stack[stack.length - 1];
      if (!top) {
        errors.push({ msg: `多余的 '${c}'`, line });
      } else if (top.ch !== want) {
        errors.push({ msg: `'${c}' 与第 ${top.line} 行的 '${top.ch}' 不匹配`, line });
        stack.pop();
      } else {
        stack.pop();
      }
      i++;
      continue;
    }

    i++;
  }

  for (const s of stack) errors.push({ msg: `'${s.ch}' 未闭合`, line: s.line });
  return errors;
}

let bad = 0;
const files = process.argv.slice(2);
if (files.length === 0) {
  console.log('用法: node check_syntax.js <file...>');
  process.exit(1);
}

for (const f of files) {
  let src;
  try {
    src = fs.readFileSync(f, 'utf8');
  } catch (e) {
    console.log(`${f}: 读取失败 ${e.message}`);
    bad++;
    continue;
  }
  const errs = scan(src);
  if (errs.length === 0) {
    console.log(`OK    ${f}`);
  } else {
    bad++;
    console.log(`FAIL  ${f}`);
    for (const e of errs.slice(0, 20)) {
      console.log(`        第 ${e.line} 行: ${e.msg}`);
    }
  }
}
process.exit(bad === 0 ? 0 : 1);
