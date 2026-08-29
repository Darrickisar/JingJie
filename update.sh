#!/system/bin/sh
MODDIR=${MODDIR:-${MODPATH:-${0%/*}}}
BB=${BB:-$MODDIR/busybox/busybox}
export MODDIR BB

. "$MODDIR/lib/rules/common.sh"
. "$MODDIR/lib/rules/config.sh"
rules_init_paths "$MODDIR" || exit $?

active_config=${CONFIG_ACTIVE_MODULE:-/data/adb/modules/zhulong_hosts/config}
if [ "$CONFIG_DIR" != "$active_config" ] && [ -f "$active_config/current.prop" ]; then
  if ! config_import_active "$active_config" >/dev/null 2>&1; then
    log_event warn migration_skipped 'current module rule snapshot was not imported' || true
  fi
fi
config_bootstrap
