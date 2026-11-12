// ============================================================
// wz_map.h —— 全部 RVA 与字段偏移（从 dump 提取 + 二进制实证）
// ============================================================
// 数据来源与验证方式：
//   1. skin.txt / classes.txt / fields_all.txt（Il2CppDumper 产物）
//   2. UnityFramework 二进制反汇编确认（tools/verify_rva.js + disasm_fn.js）
//   3. global-metadata.dat 静态解析确认（tools/verify_metadata.js）
//
// 环境（实测）：
//   global-metadata.dat : 56.0 MB, magic=0xFAB11BAF, version=29, **未加密**
//   UnityFramework      : 357 MB, cryptid=0, **未加密**
//   smoba (主二进制)     : 1.7 MB, cryptid=1 (FairPlay 加密，但只是壳)
//
//   __TEXT,__text : vmaddr=0x4000  fileoff=16384  size=282630012
//   换算：fileoff = 16384 + (rva - 0x4000)
//
// RVA 可信度：
//   皮肤链路 154 个方法 → 140 个验证通过（另 14 个是叶子函数，也合法）
//   16 个关键入口      → 16/16 全部通过
// ============================================================
#pragma once
#include <stdint.h>

// ---------------------------------------------------------------- 镜像信息
#define WZ_TEXT_VMADDR   0x4000u
#define WZ_TEXT_FILEOFF  16384u

// ---------------------------------------------------------------- L0 数据注入
// 核心思路：调 OnAddHeroSkin 把皮肤真的写进 heroSkinDic @0x358
// 这是唯一能让「已拥有」从数据层成立的路径
#define RVA_CRoleInfoManager_GetMasterRoleInfo  0x1f0cda4u  // () -> CRoleInfo*
#define RVA_CRoleInfo_OnAddHeroSkin_2           0x1ee47d4u  // (int heroId, int skinId) void
#define RVA_CSkinInfo_GetAllSkinIDs_0           0x1f19c4cu  // () -> List<uint>
#define RVA_CSkinInfo_ResolveHeroSkin_3         0x1f16428u  // (int cfgId, int* heroId, int* skinId) bool
#define RVA_CSkinInfo_GetHeroSkinCnt_1          0x1f16750u  // (int heroId) -> int
#define RVA_CSkinInfo_GetSkinCfgId_2            0x1f164f4u  // (int heroId, int skinId) -> int

// ---------------------------------------------------------------- L1 判定层
// 实证：IsHaveHeroSkin 读 [this+0x358]，与 heroSkinDic 偏移完全一致
#define RVA_CRoleInfo_IsHaveHeroSkin_5          0x1ed9690u  // (heroId, skinId, b, b, b) -> bool
#define RVA_CRoleInfo_IsHaveHeroSkin_4          0x1ed9948u  // (skinUniId, b, b, b) -> bool
#define RVA_CRoleInfo_IsCanUseSkin_3            0x1eda2c8u  // (heroId, skinId, b) -> bool
#define RVA_CRoleInfo_IsCanUseSkin_2            0x1eda35cu  // (heroSkinId, b) -> bool
#define RVA_CRoleInfo_GetHeroSkinState_2        0x1ee34f4u  // (heroId, skinId) -> HeroSkinState

#define RVA_CSkinInfo_IsHaveHeroSkin_5          0x1f1982cu
#define RVA_CSkinInfo_IsHaveHeroSkin_4          0x1f19914u
#define RVA_CSkinInfo_IsCanBuy_2                0x1f142e4u
#define RVA_CSkinInfo_IsCanBuy_1                0x1f144a4u
#define RVA_CSkinInfo_IsCanGet_3                0x1f1450cu
#define RVA_CSkinInfo_IsCanGet_2                0x1f148ccu

// ---------------------------------------------------------------- L3 无效位层
// ★★★ 实证关键：CheckSkinMaskBit 返回 1 = 有效，返回 0 = 被封禁
//
//   反汇编 @0x1f140f0：
//     +32  cbz  x0, 0x1f1413c    ← 查不到记录就跳
//     +52  ldr  w0, [x20, #16]   ← 查到：读 MaskBits
//     +72  b    0x147ac80        ← 尾调用去判断
//     +76  mov  w0, #1           ← **没记录 → 返回 1（有效）**
//
//   所以这个函数**必须 patch 成恒返回 1**，不是 0！
//   上一版 patch 成 0 = 把所有皮肤标记成封禁。
#define RVA_CSkinInfo_CheckSkinMaskBit_2        0x1f140f0u
#define RVA_CSkinInfo_UpdateSkinMaskBits_2      0x1f14158u

// ---------------------------------------------------------------- 字段偏移
// 全部经反汇编双重确认

// CRoleInfo   instance_size = 2104
#define OFF_CRoleInfo_heroSkinDic                 0x358u  // ★ 核心：我拥有的皮肤字典
#define OFF_CRoleInfo_ownedSkinAvatarList         0x360u
#define OFF_CRoleInfo_skinAvatarWearDic           0x368u
#define OFF_CRoleInfo_m_currentHeroSkinDic        0x370u
#define OFF_CRoleInfo_heroExperienceSkinDic       0x378u
#define OFF_CRoleInfo_activityLimitExperienceSkinDic 0x380u
#define OFF_CRoleInfo_backflowPrivilegeSkinDic    0x390u
#define OFF_CRoleInfo_freeHeroSkinList            0x3a8u
#define OFF_CRoleInfo_m_nHeroSkinCount            0x648u
#define OFF_CRoleInfo_m_skinWearingList           0x798u

// CHeroInfo   instance_size = 1408
#define OFF_CHeroInfo_m_heroCfgId   0x8u
#define OFF_CHeroInfo_MaskBits      0x4ecu
#define OFF_CHeroInfo_m_skinInfo    0x4f0u

// CSkinInfo   instance_size = 16
#define OFF_CSkinInfo_m_heroId      0x8u
#define OFF_CSkinInfo_m_wearId      0xcu

// CSkinInfo 静态字段
#define OFF_CSkinInfo_s_heroSkinDic          0x8u
#define OFF_CSkinInfo_s_heroSkinExtralDic    0x10u
#define OFF_CSkinInfo_s_availableSkin        0x38u

// ---------------------------------------------------------------- 不 patch 的
// 这些函数太短或与皮肤无关，patch 只会增加风险：
//   CHeroInfo::IsOwnHero/0  @0x1ef9a14  —— 3 条指令的叶子函数
//     反汇编：ldr w8,[x0,#N] / and w0,w8,#1 / ret
//     覆盖 8 字节会踩到相邻函数，且它与皮肤判定无关
