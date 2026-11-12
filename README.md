# wzdump

王者荣耀（iOS / IL2CPP）本地全皮肤解锁 dylib。

**数据全部经二进制反汇编实证**，不是从 dump 抄来就用的。

---

## 环境实测结论

| 文件 | 大小 | 状态 |
|---|---|---|
| `global-metadata.dat` | 56.0 MB | magic `0xFAB11BAF`，version 29，**未加密** |
| `UnityFramework` | 357 MB | `cryptid = 0`，**未加密** |
| `smoba`（主二进制） | 1.7 MB | `cryptid = 1`（FairPlay），但只是壳，不影响 RVA |

`__TEXT,__text`：`vmaddr = 0x4000`，`fileoff = 16384`
换算：`fileoff = 16384 + (rva - 0x4000)`

---

## 关键设计：不依赖 il2cpp 符号解析

上一版闪退 + 没日志，根因之一是 il2cpp 的符号在 UnityFramework 里，
而 `dlopen` 进来的镜像**不进全局符号表**，`dlsym(RTLD_DEFAULT)` 查不到。
日志显示「il2cpp 符号始终不全，放弃」，等于白注入。

本版改成：

| 层 | 依赖 | 说明 |
|---|---|---|
| **L1 判定层** | 只靠 RVA | 基址 + RVA 直接 patch，一定成功 |
| **L3 无效位层** | 只靠 RVA | 同上 |
| **L0 数据注入** | 需要 il2cpp API | 拿不到就跳过，不影响 L1/L3 |

所以即使 il2cpp 符号完全解析不了，皮肤仍然可用。

---

## 五个真实踩过的坑（全部已修）

### 坑 1：`CheckSkinMaskBit` patch 方向反了 ★最严重

反汇编 `@0x1f140f0`：

```
+32  cbz  x0, 0x1f1413c    ← 查不到记录就跳
+52  ldr  w0, [x20, #16]   ← 查到：读 MaskBits
+72  b    0x147ac80        ← 尾调用判断
+76  mov  w0, #1           ← **没记录 → 返回 1（有效）**
+88  ret
```

**返回 1 = 皮肤有效，返回 0 = 被封禁。**

上一版 `patch_ret(..., 0, 0)` 恒返回 0 —— 等于告诉游戏「所有皮肤都被封禁」，
皮肤全失效，还可能触发游戏的封禁处理逻辑。

本版：恒返回 **1**。

### 坑 2：arm64e 裸函数指针调用

用 `tools/scan_calls.js` 扫自己产物拿到的硬证据：

```
arm64e : 47 处函数指针调用 → 全部 BLRAAZ（验证 PAC）
arm64  : 同样 47 处        → 裸 BLR（不验证）
```

而我们从三个来源拿到的地址全是**裸地址**：
- `MethodInfo->methodPointer`（从元数据内存读）
- `dlsym()` 返回值
- 基址 + RVA 算出来的

裸地址交给 `BLRAAZ` = 验签失败 = **SIGKILL = 闪退，一行日志都没有**。

本版：`pac_fix.h`，取地址先 strip 做算术，调用前 `wz_pac_sign()` 签回来。

### 坑 3：托管方法缺 `const MethodInfo*` 尾参

IL2CPP 生成的签名固定为：

```
RET f(this?, 参数1, ..., 参数N, const MethodInfo *method)
```

反汇编 `OnAddHeroSkin @0x1ee47d4` 显示函数体只读 x0/x1/x2，**不碰 x3** ——
所以参数少的函数漏传尾参不一定立刻崩。但 `IsHaveHeroSkin/5` 有 7 个参数
（this + 5 参 + 尾参 = x0~x6），只传 6 个的话 x6 是垃圾。

本版：全部 typedef 补尾参，调用走 `wz_callable()`。

### 坑 4：constructor 里建线程

dyld 加载阶段，malloc zone 可能未就绪、其它 constructor 未跑完。
在这个窗口 `pthread_create` 会和 dyld 锁竞争 → 偶发死锁或 SIGKILL。

本版：constructor 里先 `usleep(200ms)` 让 dyld 收尾，再建线程，给 512KB 显式栈。

### 坑 5：改代码段不冻结线程

15+ 处 `memcpy` 改写。主线程若正好执行到被改指令，取到「半条新 + 半条旧」
→ SIGILL 或跳到垃圾地址。王者 UI 线程 60fps 不停跑，撞上概率不低。

本版：`thread_freeze.m`，所有改写包在 `wz_threads_suspend()` … `resume()` 窗口内。

---

## 日志为什么之前看不见

iOS 上 `fprintf(stderr)`：

| 启动方式 | stderr 去向 |
|---|---|
| Xcode 调试器启动 | 接到控制台，可见 |
| **桌面点图标启动** | **写进 `/dev/null`，什么都看不到** |

TrollFools 注入后从桌面启动，属于第二种。所以上一版的日志系统在真实场景下
等于不存在。

本版三路同时写：

1. **文件** —— `Documents/wzdump.log`，用 Filza 直接看。每次 `fsync` 保证崩之前落盘。
2. **os_log** —— `idevicesyslog` / Console.app 能抓，subsystem `com.wzdump.dumper`。
3. **stderr** —— 调试器连上时可见。

还装了信号处理器：崩之前把「最后阶段」写进日志，然后恢复默认处理让系统生成 `.ips`。

---

## 实证数据

### 16 个关键入口（全部验证通过）

| 方法 | RVA | 首指令 |
|---|---|---|
| `CRoleInfo::IsHaveHeroSkin/5` | 0x1ed9690 | `sub sp, sp, #112` |
| `CRoleInfo::IsHaveHeroSkin/4` | 0x1ed9948 | `sub sp, sp, #80` |
| `CRoleInfo::IsCanUseSkin/3` | 0x1eda2c8 | `stp x22, x21, [sp,#-48]!` |
| `CRoleInfo::IsCanUseSkin/2` | 0x1eda35c | `sub sp, sp, #48` |
| `CRoleInfo::OnAddHeroSkin/2` | 0x1ee47d4 | `stp x26, x25, [sp,#-80]!` |
| `CRoleInfo::GetHeroSkinState/2` | 0x1ee34f4 | `stp x24, x23, [sp,#-64]!` |
| `CRoleInfoManager::GetMasterRoleInfo/0` | 0x1f0cda4 | `stp x20, x19, [sp,#-32]!` |
| `CSkinInfo::IsHaveHeroSkin/5` | 0x1f1982c | `stp x24, x23, [sp,#-64]!` |
| `CSkinInfo::IsHaveHeroSkin/4` | 0x1f19914 | `stp x24, x23, [sp,#-64]!` |
| `CSkinInfo::IsCanBuy/2` | 0x1f142e4 | `stp x22, x21, [sp,#-48]!` |
| `CSkinInfo::IsCanGet/3` | 0x1f1450c | `stp x26, x25, [sp,#-64]!` |
| `CSkinInfo::GetAllSkinIDs/0` | 0x1f19c4c | `stp x22, x21, [sp,#-48]!` |
| `CSkinInfo::CheckSkinMaskBit/2` | 0x1f140f0 | `stp x20, x19, [sp,#-32]!` |
| `CSkinInfo::UpdateSkinMaskBits/2` | 0x1f14158 | `stp x26, x25, [sp,#-80]!` |
| `CSkinInfo::ResolveHeroSkin/3` | 0x1f16428 | `stp x22, x21, [sp,#-48]!` |
| `CHeroInfo::IsOwnHero/0` | 0x1ef9a14 | 叶子函数（3 条指令） |

最后那个 **不 patch** —— 只有 3 条指令，覆盖 8 字节会踩到相邻函数，且与皮肤无关。

### 字段偏移（反汇编双重确认）

`CRoleInfo`（instance_size = 2104）：

| 字段 | 偏移 |
|---|---|
| `heroSkinDic` | **0x358** ← 核心 |
| `ownedSkinAvatarList` | 0x360 |
| `skinAvatarWearDic` | 0x368 |
| `m_currentHeroSkinDic` | 0x370 |
| `heroExperienceSkinDic` | 0x378 |
| `activityLimitExperienceSkinDic` | 0x380 |
| `freeHeroSkinList` | 0x3a8 |

`0x358` 被 `IsHaveHeroSkin` 和 `OnAddHeroSkin` 两处反汇编**双重确认**：

```
IsHaveHeroSkin:  +100  ldr x28, [x23, #856]   ← 856 = 0x358
OnAddHeroSkin:   +72   ldr x26, [x20, #856]   ← 856 = 0x358
```

`CHeroInfo`（1408）：`m_heroCfgId` 0x8 / `MaskBits` 0x4ec / `m_skinInfo` 0x4f0
`CSkinInfo`（16）：`m_heroId` 0x8 / `m_wearId` 0xc

---

## 源码结构

| 文件 | 作用 |
|---|---|
| `wz_unlock.m` | 主逻辑：L1 判定层 / L3 无效位层 / L0 数据注入 / 自检 |
| `wz_map.h` | 全部 RVA 与字段偏移（带实证注释） |
| `il2cpp_api.h/.m` | il2cpp 符号解析（先查 UnityFramework handle） |
| `il2cpp_call.h` | 托管方法安全调用（补尾参 + PAC 签名） |
| `pac_fix.h` | arm64e 指针认证 |
| `hook_arm64.h/.m` | 代码段改写（返回常量，带覆盖区安全检查） |
| `thread_freeze.h/.m` | 改写前冻结其它线程 |
| `wzlog.h/.m` | 三路日志 + 崩溃兜底 |
| `build.sh` | 交叉编译 + codesign adhoc 签名 |

## 工具

| 工具 | 作用 |
|---|---|
| `tools/verify_metadata.js` | 验证 global-metadata.dat 完整性、未加密 |
| `tools/analyze_skin.js` | 从 skin.txt 提取关键类，输出 skin_chain.json |
| `tools/verify_rva.js` | 把 RVA 拿到二进制里验证是否指向合法函数 |
| `tools/disasm_fn.js` | 粗粒度反汇编，判断函数行为 |
| `tools/scan_calls.js` | 统计 BLR/BLRAA 分布，判断 PAC 是否必需 |
| `tools/check_abi.js` | 防闪退回归检查（R1~R6） |
| `tools/check_syntax.js` | 结构自查 |

---

## 编译

```bash
./build.sh both          # fat：arm64 + arm64e
./build.sh arm64e        # 只 arm64e（A12+）
```

GitHub Actions 自动编译（`.github/workflows/build.yml`）。

## 注入

TrollFools 里选王者 → 加 `wzdump.dylib` → 重启。

**注入前先删掉旧的 dylib**，否则两个都在跑会互相干扰。

## 验证

看日志文件：`Documents/wzdump.log`（Filza 打开）。

正常应该看到：

```
========================================
 wzdump 全皮肤解锁 dylib 已注入
 pid = 1234   arch = arm64e   PAC = 1
 日志文件: /var/mobile/.../Documents/wzdump.log
========================================
=== wzdump 全皮肤解锁启动 ===
  架构 = arm64e   PAC = 开启
=== 等待 UnityFramework 加载 ===
  UnityFramework 基址 = 0x11aa64000
=== 解析 il2cpp 符号（可选）===
  符号解析成功
=== 开始 patch ===
[L1] 判定层：皮肤判定返回 true
  OK   CRoleInfo::IsHaveHeroSkin/5                @0x1ed9690 -> 1
  OK   CRoleInfo::IsHaveHeroSkin/4                @0x1ed9948 -> 1
  ...
[L3] 无效位层：MaskBits 恒不置位（返回 1 = 有效）
  OK   CSkinInfo::CheckSkinMaskBit/2              @0x1f140f0 -> 1
=== patch 结果：成功 12 处，失败 0 处 ===
[L0] 数据注入：尝试写入 heroSkinDic
  注入完成：写入 608 条，跳过 4 条
[自检] 调用判定函数验证
  IsHaveHeroSkin/5 首指令 = 0x52800020
  ✓ 确认已改为「返回 1」
  CheckSkinMaskBit/2 首指令 = 0x52800020
  ✓ 确认已改为「返回 1（有效）」
=== 完成：patch 12 处，注入 608 条 ===
```

关键检查点：

| 日志 | 含义 |
|---|---|
| `PAC = 开启` | arm64e 机型，PAC 层生效 |
| `UnityFramework 基址 = 0x...` | 找到目标镜像 |
| `成功 12 处，失败 0 处` | 所有 patch 都写进去了 |
| `首指令 = 0x52800020` | 确认改成了 `movz w0, #1` |

## 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| 没有日志文件 | dylib 没加载 | 查签名：`codesign -v wzdump.dylib` |
| 日志只有横幅 | worker 没起来 | 看 `创建 worker 线程失败 rc=` |
| `等 120 秒仍找不到 UnityFramework` | 注入时机太早 | 正常，重启游戏再试 |
| `符号解析失败` | 正常，不影响 | L1/L3 只靠 RVA |
| `失败 N 处` | RVA 与版本不匹配 | 核对游戏版本，重新 dump |
| 日志显示成功但游戏里没皮肤 | 服务端裁剪 | L0 注入是关键，看 `注入完成` 那行 |
