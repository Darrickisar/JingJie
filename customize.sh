#!/system/bin/sh
MODDIR=${MODPATH:-${MODDIR:-${0%/*}}}
MODPATH=$MODDIR
export MODDIR MODPATH

: > "$MODDIR/skip_mount" || abort "skip_mount_create_failed"
. "$MODDIR/busybox.sh" || abort "rule_engine_busybox_capability_missing"
for reader in "$MODDIR"/tools/history_reader_arm32 "$MODDIR"/tools/history_reader_arm64 \
  "$MODDIR"/tools/history_reader_x86 "$MODDIR"/tools/history_reader_x86_64; do
  [ -f "$reader" ] && [ ! -L "$reader" ] || abort "history_reader_missing"
  chmod 0755 "$reader" || abort "history_reader_permission_failed"
done

# Keep only the compressed DoH companion this device can run. The module ships
# arm64 and arm32; other architectures acquire the pinned archive on demand.
companion_arch=
case "${ARCH-}" in
  arm64) companion_arch=arm64 ;;
  arm) companion_arch=arm32 ;;
  x64) companion_arch=x86_64 ;;
  x86) companion_arch=x86 ;;
esac
if [ -z "$companion_arch" ] && command -v getprop >/dev/null 2>&1; then
  case "$(getprop ro.product.cpu.abi 2>/dev/null)" in
    arm64*|aarch64) companion_arch=arm64 ;;
    armeabi*|armv7*|armv8l) companion_arch=arm32 ;;
    x86_64) companion_arch=x86_64 ;;
    x86|i686) companion_arch=x86 ;;
  esac
fi
if [ -n "$companion_arch" ]; then
  for archive in "$MODDIR"/companions/jingjie-doh-proxy-*-v1.0.gz; do
    [ -f "$archive" ] && [ ! -L "$archive" ] || continue
    case "$archive" in
      */"jingjie-doh-proxy-$companion_arch-v1.0.gz") continue ;;
    esac
    rm -f "$archive" || true
  done
fi

/system/bin/sh "$MODDIR/update.sh" || true

if command -v ui_print >/dev/null 2>&1; then
  ui_print "- 净界 · 引擎"
  ui_print "- 作者：相貌平平韩老魔"
  ui_print "- 请从官方链接下载，以防恶意脚本"
  ui_print "- 为保障网络环境安全，本工具仅支持过滤非法骚扰、恶意代码等违规信息。请正确合理使用工具功能，勿将合法商业广告纳入屏蔽范围。"
fi

if ! /system/bin/sh "$MODDIR/rule_engine.sh" prepare; then
  /system/bin/sh "$MODDIR/rule_engine.sh" cleanup || true
  abort "rule_engine_prepare_failed"
fi

mkdir -p "$MODDIR/runtime" || abort "initial_refresh_marker_directory_failed"
: > "$MODDIR/runtime/initial-refresh.pending" || abort "initial_refresh_marker_create_failed"

command -v ui_print >/dev/null 2>&1 && ui_print "- 安全基线已准备；首次进入净界并确认使用说明后将自动刷新规则"
