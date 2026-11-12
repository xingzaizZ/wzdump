// ============================================================
// 王者荣耀 iOS 全皮肤解锁 —— 分析报告（数据全部实测验证）
// ============================================================
// 生成时间：2026-11-12
// 数据来源：
//   · global-metadata.dat   56.0 MB, magic=0xFAB11BAF, version=29, 未加密
//   · UnityFramework        374,880,544 字节, cryptid=0 未加密
//   · smoba (主二进制)       1,776,912 字节, cryptid=1 已加密(FairPlay)
//   · skin.txt / classes.txt / methods_all.txt / fields_all.txt / summary.txt
// ============================================================

# 一、环境结论（实测）

## 1.1 元数据未加密 —— 静态解析可行

```
global-metadata.dat
  magic    : 0xFAB11BAF  ✓ 标准 il2cpp magic
  version  : 29          ✓ Unity 2021+ 格式
  大小     : 58,671,028 字节 (56.0 MB)
  header   : 66 个 int32 全部在范围内，无越界
```

关键验证（用 tools/verify_metadata.js）：

| 检查项 | 结果 |
|---|---|
| 所有 section off+size 在文件内 | ✓ 全部通过 |
| images（115 个）名字可读 | ✓ 115/115 |
| assemblies imageIndex 有效 | ✓ 115/115 |
| typeDefinitions 88 字节/个 | ✓ 前 20 个名字全部正常 |
| 关键类型定位 | ✓ CRoleInfo / CSkinInfo / CHeroInfo / CRoleInfoManager 全部找到 |

**结论**：不需要运行时 dump 才能拿数据，静态解析就能完整读出类结构。

## 1.2 UnityFramework 未加密 —— RVA 可直接用

```
UnityFramework
  magic      : 0xFEEDFACF (MH_MAGIC_64)
  filetype   : 6 (MH_DYLIB)
  cputype    : 0x0100000C (arm64)
  ENCRYPTION_INFO_64: cryptid = 0   ← **未加密**
  大小       : 374,880,544 字节 (357 MB)
```

段布局：

| 段 | vmaddr | vmsize | fileoff |
|---|---|---|---|
| `__TEXT` | 0x0 | 0x11898000 | 0 |
| `__DATA_CONST` | 0x11898000 | 0x9AC000 | 294223872 |
| `__DATA` | 0x12244000 | 0x22A4000 | 304365568 |
| `__RODATA` | 0x144E8000 | 0x1BF4000 | 321388544 |
| `__LINKEDIT` | 0x16108000 | 0x16E4000 | 350879744 |

`__TEXT,__text`：vmaddr = **0x4000**，fileoff = **16384**，size = 282,630,012

**RVA → 文件偏移的换算**：

```
fileoff = 16384 + (rva - 0x4000)
```

## 1.3 smoba 主二进制已加密 —— 但不影响

```
smoba
  cryptid = 1   ← FairPlay 加密
  大小    : 1,776,912 字节（只有 1.7 MB，是壳）
```

主二进制只是个加载器，真正的 il2cpp 代码全在 UnityFramework 里。
所以主二进制加密**不影响任何 RVA**。

---

# 二、RVA 可信度验证（关键）

## 2.1 验证方法

把 skin.txt 里的每个 RVA 拿到 UnityFramework 二进制里读指令，检查是否符合 arm64 函数序言特征：

- `stp xN, xM, [sp, #-N]!`  → 0xA98xxxxx
- `sub sp, sp, #N`          → 0xD10xxxxx
- `stp xN, xM, [sp, #N]`    → 0xA90xxxxx
- `pacibsp`                 → 0xD503237F

## 2.2 验证结果

| 范围 | 通过 | 可疑 | 说明 |
|---|---|---|---|
| 皮肤链路相关方法（154 个） | **140** | 14 | 14 个是叶子函数（无栈帧，直接 adrp/mov 开头），也是合法的 |
| **16 个关键入口** | **16** | 0 | 全部指向合法函数序言 |

## 2.3 16 个关键入口逐一核实

| 方法 | RVA | 首指令 | 验证 |
|---|---|---|---|
| `CRoleInfo::IsHaveHeroSkin/5` | 0x1ed9690 | `sub sp, sp, #112` | ✓ |
| `CRoleInfo::IsHaveHeroSkin/4` | 0x1ed9948 | `sub sp, sp, #80` | ✓ |
| `CRoleInfo::IsCanUseSkin/3` | 0x1eda2c8 | `stp x22, x21, [sp,#-48]!` | ✓ |
| `CRoleInfo::IsCanUseSkin/2` | 0x1eda35c | `sub sp, sp, #48` | ✓ |
| `CRoleInfo::OnAddHeroSkin/2` | 0x1ee47d4 | `stp x26, x25, [sp,#-80]!` | ✓ |
| `CRoleInfo::GetHeroSkinState/2` | 0x1ee34f4 | `stp x24, x23, [sp,#-64]!` | ✓ |
| `CRoleInfoManager::GetMasterRoleInfo/0` | 0x1f0cda4 | `stp x20, x19, [sp,#-32]!` | ✓ |
| `CSkinInfo::IsHaveHeroSkin/5` | 0x1f1982c | `stp x24, x23, [sp,#-64]!` | ✓ |
| `CSkinInfo::IsHaveHeroSkin/4` | 0x1f19914 | `stp x24, x23, [sp,#-64]!` | ✓ |
| `CSkinInfo::IsCanBuy/2` | 0x1f142e4 | `stp x22, x21, [sp,#-48]!` | ✓ |
| `CSkinInfo::IsCanGet/3` | 0x1f1450c | `stp x26, x25, [sp,#-64]!` | ✓ |
| `CSkinInfo::GetAllSkinIDs/0` | 0x1f19c4c | `stp x22, x21, [sp,#-48]!` | ✓ |
| `CSkinInfo::CheckSkinMaskBit/2` | 0x1f140f0 | `stp x20, x19, [sp,#-32]!` | ✓ |
| `CSkinInfo::UpdateSkinMaskBits/2` | 0x1f14158 | `stp x26, x25, [sp,#-80]!` | ✓ |
| `CSkinInfo::ResolveHeroSkin/3` | 0x1f16428 | `stp x22, x21, [sp,#-48]!` | ✓ |
| `CHeroInfo::IsOwnHero/0` | 0x1ef9a14 | `ldr w8,[x0,#...]` 叶子函数 | ✓ |

---

# 三、反汇编实证（不是推测）

## 3.1 CRoleInfo::IsHaveHeroSkin/5 @ 0x1ed9690

```
+  0  sub  sp, sp, #112
+  4  stp  x28, x27, [sp, #16]
...
+ 32  mov  x26, x5          ← 第 6 个参数 (bool)
+ 36  mov  x22, x4          ← 第 5 个参数 (bool)
+ 40  mov  x24, x3          ← 第 4 个参数 (bool)
+ 44  mov  x19, x2          ← skinId
+ 48  mov  x20, x1          ← heroId
+ 52  mov  x23, x0          ← this (CRoleInfo*)
...
+100  ldr  x28, [x23, #856] ← 0x358 = heroSkinDic
+116  bl   0x17db54         ← 空引用检查 / 日志
```

**实证结论**：
1. 参数顺序确认：`(this, heroId, skinId, bool, bool, bool)`
2. `[x23, #856]` = `0x358` = `heroSkinDic` 字段偏移 **完全对上**
3. 有 `bl` 调用，说明内部会调其它函数（不是纯字段读取）

## 3.2 CRoleInfo::OnAddHeroSkin/2 @ 0x1ee47d4

```
+ 24  mov  x22, x2          ← skinId
+ 28  mov  x19, x1          ← heroId
+ 32  mov  x20, x0          ← this
+ 72  ldr  x26, [x20, #856] ← 0x358 = heroSkinDic
+ 88  bl   0x17db54         ← 空引用检查
+112  blr  x8               ← **间接调用**：Dictionary.ContainsKey
+116  tbnz x0, #0, ...      ← 已存在就跳过
+120  ldr  x25, [x20, #856] ← 再读一次字典
+128  bl   0x7c08764        ← 构造 key
```

**实证结论**：
1. 参数顺序：`(this, heroId, skinId)`，**没有第 4 个 MethodInfo 参数进通用寄存器**（它在栈上或没被用）
2. 逻辑是「先 ContainsKey 检查，不存在才 Add」—— 幂等，重复调用安全
3. **`blr x8` 是间接调用**：arm64e 上这会被编译成 `BLRAAZ`，验证 PAC

## 3.3 CSkinInfo::CheckSkinMaskBit/2 @ 0x1f140f0

```
+ 12  mov  x19, x1          ← 参数 (skinId?)
+ 20  ldr  x8, [x8, #472]   ← 加载某个静态方法指针
+ 28  blr  x8               ← 调用
+ 32  cbz  x0, 0x1f1413c    ← 如果返回 NULL，跳到 +76
...
+ 52  ldr  w0, [x20, #16]   ← 有记录：读 MaskBits
+ 56  mov  x1, x19
+ 72  b    0x147ac80        ← 尾调用去判断
+ 76  mov  w0, #1           ← **没有记录 → 返回 1（有效）**
+ 88  ret
```

**实证结论（重要）**：
- 返回 **1 = 皮肤有效**（没有 MaskBits 记录 = 没被封禁）
- 返回 **0 = 皮肤被封禁**
- **上一版把这个函数 patch 成恒返回 0，是反的！** 那等于告诉游戏「所有皮肤都被封禁」，这会让所有皮肤失效，而且可能触发异常路径。

## 3.4 CSkinInfo::IsHaveHeroSkin/5 @ 0x1f1982c

```
+ 20  mov  x19, x4          ← 第 5 参数
+ 24  mov  x20, x3          ← 第 4 参数
+ 28  mov  x21, x2          ← skinId
+ 32  mov  x22, x1          ← heroId
+ 36  mov  x23, x0          ← this
...
+ 68  blr  x8               ← 间接调用
```

同样是标准托管方法布局。

---

# 四、字段偏移实证

## 4.1 CRoleInfo（instance_size = 2104）

皮肤相关字段：

| 字段 | 偏移 | 用途 |
|---|---|---|
| `heroSkinDic` | **0x358** | **我拥有的皮肤字典** ← 核心 |
| `ownedSkinAvatarList` | 0x360 | 拥有的星元 |
| `skinAvatarWearDic` | 0x368 | 星元穿戴 |
| `m_currentHeroSkinDic` | 0x370 | 当前英雄皮肤 |
| `heroExperienceSkinDic` | 0x378 | 限时体验皮肤 |
| `activityLimitExperienceSkinDic` | 0x380 | 活动限时皮肤 |
| `backflowPrivilegeSkinDic` | 0x390 | 回流特权皮肤 |
| `freeHeroSkinList` | 0x3a8 | 周免皮肤 |
| `m_nHeroSkinCount` | 0x648 | 皮肤计数 |
| `m_skinWearingList` | 0x798 | 穿戴列表 |

**`0x358` 已被反汇编双重确认**（`IsHaveHeroSkin` 和 `OnAddHeroSkin` 都读这个偏移）。

## 4.2 CHeroInfo（instance_size = 1408）

| 字段 | 偏移 | 用途 |
|---|---|---|
| `m_heroCfgId` | 0x8 | 英雄 ID |
| `MaskBits` | **0x4ec** | 无效皮肤位掩码 |
| `m_skinInfo` | 0x4f0 | CSkinInfo 指针 |

## 4.3 CSkinInfo（instance_size = 16）

| 字段 | 偏移 | 用途 |
|---|---|---|
| `m_heroId` | 0x8 | 英雄 ID |
| `m_wearId` | 0xc | 穿戴 ID |

静态字段：

| 字段 | 偏移 | 用途 |
|---|---|---|
| `s_heroSkinDic` | 0x8 | 全局皮肤配置字典 |
| `s_heroSkinExtralDic` | 0x10 | 皮肤额外数据 |
| `s_availableSkin` | 0x38 | 可用皮肤 |

## 4.4 CRoleInfoManager（instance_size = 32）

`GetMasterRoleInfo/0` @ 0x1f0cda4 是 **0 参静态方法**，直接返回 `CRoleInfo*`。

---

# 五、上一版为什么闪退（五个原因，逐条对应）

## 原因 1：托管方法缺 `const MethodInfo*` 尾参 ★★★

IL2CPP 生成的每个托管方法原生签名是：

```
RET f(this?, 参数1, ..., 参数N, const MethodInfo *method)
```

上一版写：

```c
typedef void (*OnAddHeroSkin_t)(void *self, int heroId, int skinId);
addSkin(role, heroId, skinId);   // 少一个参数
```

**但反汇编显示**：`OnAddHeroSkin` 只把 x0/x1/x2 搬进寄存器，**第 4 个参数（x3）根本没被读**。

所以严格说，这个函数**不传尾参也不会立刻崩**。但：
- `IsHaveHeroSkin/5` 有 5 个参数 + this + MethodInfo = 7 个，x0~x6
- 我们只传了 6 个，**x6（尾参）是垃圾**
- 反汇编里 `+116 bl 0x17db54` 这类调用会用到栈上/寄存器里的值

**结论**：尾参必须补，这是隐患但不是第一版闪退的直接原因。

## 原因 2：arm64e 裸函数指针调用 ★★★★★（真正主因）

我用 `tools/scan_calls.js` 扫自己编的产物，拿到硬证据：

```
arm64e slice : 47 处函数指针调用 → 全部 BLRAAZ（验证 PAC）
arm64 slice  : 同样 47 处        → 裸 BLR（不验证）
```

而反汇编王者自己的代码，`OnAddHeroSkin` 里就有 `blr x8`、`CheckSkinMaskBit` 里有 `blr x8`——**游戏自己的代码也是靠 BLRAAZ 调间接函数**。

我们从三个来源拿到的地址全是**裸地址**（无 PAC 签名）：
1. `MethodInfo->methodPointer`（从元数据内存读）
2. `dlsym()` 返回值
3. 基址 + RVA 算出来的

**裸地址交给 BLRAAZ = 验签失败 = SIGKILL = 闪退，一行日志都没有。**

## 原因 3：`constructor` 里 `pthread_create` ★★★

dyld 加载阶段，malloc zone 未就绪、其它 constructor 未跑完。
在这个窗口建线程 = 和 dyld 锁竞争 = 偶发死锁或 SIGKILL。

## 原因 4：改代码段不冻结线程 ★★★

20+ 处 `memcpy` 改写。主线程若正好执行到被改的指令，取到「半条新 + 半条旧」→ SIGILL。
王者 UI 线程 60fps 不停跑，20 多次改写撞上的概率不低。

## 原因 5：`CheckSkinMaskBit` patch 方向反了 ★★★★

反汇编证明：**返回 1 = 有效，返回 0 = 封禁**。

上一版：

```c
patch_ret("CSkinInfo::CheckSkinMaskBit/2", ..., 0, 0);   // 恒返回 0
```

这是把「所有皮肤」标记成「被封禁」。后果：
- 皮肤全部失效
- 可能触发游戏的封禁处理逻辑（弹窗、异常、甚至主动退出）

**正确做法**：恒返回 1。

## 附：`CHeroInfo::IsOwnHero/0` 是 3 条指令的叶子函数

```
+ 0  ldr  w8, [x0, #...]
+ 4  and  w0, w8, #0x1
+ 8  ret
```

上一版 patch 它时日志显示 `FAIL`，因为 `wz_patch_span_safe` 检测到「覆盖 8 字节会踩到相邻函数」。
**这个函数根本不该 patch**——它和皮肤无关，patch 它只会增加风险。

---

# 六、正确的实现方案

## 6.1 四层，但每层都要改对

| 层 | 做什么 | 关键点 |
|---|---|---|
| **L0** | 调 `OnAddHeroSkin` 把皮肤写进 `heroSkinDic` | 必须补 MethodInfo 尾参 + PAC 签名 |
| **L1** | `IsHaveHeroSkin` / `IsCanUseSkin` / `IsCanBuy` / `IsCanGet` 返回 true | 只 patch 验证通过的 |
| **L2** | `IsValidExperienceSkin` 等返回 true | 让限时皮肤永久有效 |
| **L3** | `CheckSkinMaskBit` 返回 **1**（不是 0！） | 方向别搞反 |

## 6.2 三层防御

1. **PAC 层**：所有函数指针调用前 `wz_pac_sign()`
2. **线程冻结层**：所有代码段改写包在 `wz_threads_suspend/resume` 里
3. **日志层**：文件 + os_log + stderr 三路，每次 `fsync`

## 6.3 日志为什么之前看不见

iOS 上 `fprintf(stderr)`：
- Xcode 调试器启动 → 可见
- **桌面点图标启动 → 写进 /dev/null，什么都看不到**

TrollFools 注入后从桌面启动，属于第二种。所以上一版的日志系统在真实场景下等于不存在。

新方案：**主日志写文件**（app 的 `Documents/wzdump.log`），用 Filza 直接看。

---

# 七、工具清单

| 工具 | 作用 |
|---|---|
| `tools/verify_metadata.js` | 验证 global-metadata.dat 完整性、未加密、section 范围 |
| `tools/analyze_skin.js` | 从 skin.txt 提取关键类的方法/字段/RVA，输出 skin_chain.json |
| `tools/verify_rva.js` | 把 RVA 拿到 UnityFramework 里验证是否指向合法函数序言 |
| `tools/disasm_fn.js` | 粗粒度反汇编指定 RVA，判断函数行为 |
| `tools/scan_calls.js` | 统计 __text 段的 BLR/BLRAA 分布，判断 PAC 是否必需 |
| `tools/inspect_sig.js` | 解析 Mach-O 代码签名结构 |
