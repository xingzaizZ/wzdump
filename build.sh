#!/usr/bin/env bash
# ============================================================
# build.sh —— 交叉编译 wzdump dylib（iOS arm64 / arm64e）
# ============================================================
# 用法：
#   ./build.sh              # 默认 both（fat：arm64 + arm64e）
#   ./build.sh arm64        # 只要 arm64（A11 及更早）
#   ./build.sh arm64e       # 只要 arm64e（A12 及更新）
#   ./build.sh both --clean # 先清 build 目录
# ============================================================
set -euo pipefail

ARCH_ARG="${1:-both}"
CLEAN="${2:-}"

MIN_IOS="12.0"
OUT="build"
SRCS=(
  wz_unlock.m
  il2cpp_api.m
  hook_arm64.m
  thread_freeze.m
  wzlog.m
)
FRAMEWORKS=(
  -framework Foundation
  -framework CoreFoundation
)

# ---------------------------------------------------------------- 前置检查
if ! command -v xcrun >/dev/null 2>&1; then
  echo "错误：找不到 xcrun，需要在 macOS + Xcode 环境编译" >&2
  exit 1
fi

SDK="$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null || true)"
if [ -z "$SDK" ] || [ ! -d "$SDK" ]; then
  echo "错误：找不到 iPhoneOS SDK" >&2
  exit 1
fi

echo "=== 环境 ==="
echo "  SDK      : $SDK"
echo "  SDK 版本 : $(xcrun --sdk iphoneos --show-sdk-version 2>/dev/null || echo unknown)"
echo "  clang    : $(clang --version | head -1)"
echo "  架构     : $ARCH_ARG"
echo ""

if [ "$CLEAN" = "--clean" ]; then
  echo "==> 清理 $OUT"
  rm -rf "$OUT"
fi
mkdir -p "$OUT"

# ---------------------------------------------------------------- 编译函数
build_arch() {
  local ARCH="$1"
  local TARGET="${ARCH}-apple-ios${MIN_IOS}"

  echo "==> 编译 $ARCH"

  # 关键编译选项：
  #   -fptrauth-calls      : arm64e 上生成指针认证指令。
  #                          不传这个，ptrauth.h 的宏会退化成恒等，
  #                          调用托管方法时 BLRAAZ 验签必失败。
  #   -fptrauth-intrinsics : 允许直接写 ptrauth_sign_unauthenticated
  #   -Wl,-adhoc_codesign  : 让链接器直接产出 adhoc 签名
  local EXTRA=()
  if [ "$ARCH" = "arm64e" ]; then
    EXTRA=(-fptrauth-calls -fptrauth-intrinsics)
  fi

  # 注意：macOS 自带 bash 3.2，set -u 下展开空数组会报 unbound variable
  xcrun -sdk iphoneos clang \
    -arch "$ARCH" \
    -target "$TARGET" \
    -isysroot "$SDK" \
    -miphoneos-version-min="$MIN_IOS" \
    -O2 \
    -g \
    -Wall \
    -Wno-unused-parameter \
    -fvisibility=hidden \
    ${EXTRA[@]+"${EXTRA[@]}"} \
    -I. \
    -dynamiclib \
    -install_name "@executable_path/wzdump.dylib" \
    -Wl,-adhoc_codesign \
    "${FRAMEWORKS[@]}" \
    -o "$OUT/wzdump-$ARCH.dylib" \
    "${SRCS[@]}"

  echo "    -> $OUT/wzdump-$ARCH.dylib  ($(du -h "$OUT/wzdump-$ARCH.dylib" | cut -f1))"
}

# ---------------------------------------------------------------- 主流程
case "$ARCH_ARG" in
  arm64)
    build_arch arm64
    cp "$OUT/wzdump-arm64.dylib" "$OUT/wzdump.dylib"
    ;;
  arm64e)
    build_arch arm64e
    cp "$OUT/wzdump-arm64e.dylib" "$OUT/wzdump.dylib"
    ;;
  both)
    build_arch arm64
    build_arch arm64e
    echo "==> lipo 合并"
    xcrun lipo -create \
      "$OUT/wzdump-arm64.dylib" \
      "$OUT/wzdump-arm64e.dylib" \
      -output "$OUT/wzdump.dylib"
    echo "    -> $OUT/wzdump.dylib  ($(du -h "$OUT/wzdump.dylib" | cut -f1))"
    ;;
  *)
    echo "用法: $0 [arm64|arm64e|both] [--clean]" >&2
    exit 1
    ;;
esac

# ---------------------------------------------------------------- 签名
#
# 为什么用 codesign 而不是 ldid：
#   ldid 对 fat 二进制只签第一个 slice，第二个 slice 没有 LC_CODE_SIGNATURE，
#   dyld 直接拒绝，报 "code object is not signed at all / In architecture: arm64e"。
#   系统 codesign 逐 slice 正确处理，并设好 CS_ADHOC 标志。
echo ""
echo "==> 签名（codesign adhoc）"
codesign --force --sign - --timestamp=none "$OUT/wzdump.dylib"

for a in arm64 arm64e; do
  if [ -f "$OUT/wzdump-$a.dylib" ]; then
    codesign --force --sign - --timestamp=none "$OUT/wzdump-$a.dylib" 2>/dev/null || true
  fi
done
echo "    OK"

# ---------------------------------------------------------------- 签名校验
echo ""
echo "==> 签名校验（不通过则构建失败）"
if ! codesign -v --verbose=2 "$OUT/wzdump.dylib" 2>&1; then
  echo "    !! 签名校验失败"
  exit 1
fi
echo "    签名有效"

echo ""
echo "    CodeDirectory 摘要:"
codesign -d --verbose=4 "$OUT/wzdump.dylib" 2>&1 | \
  grep -E "Identifier|CodeDirectory|CandidateCDHash|Hash|flags|Format" | sed 's/^/      /' || true

# ---------------------------------------------------------------- 产物摘要
echo ""
echo "=== 产物 ==="
ls -lh "$OUT"/*.dylib
echo ""
echo "=== 架构 ==="
xcrun lipo -info "$OUT/wzdump.dylib" 2>/dev/null || true
echo ""
echo "=== 依赖 ==="
xcrun -sdk iphoneos otool -L "$OUT/wzdump.dylib" 2>/dev/null | sed 's/^/  /' || true
echo ""
echo "完成: $OUT/wzdump.dylib"
