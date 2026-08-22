#!/system/bin/sh
MODDIR=${MODDIR:-${0%/*}}
[ ! -f "$MODDIR/runtime/uninstalling" ] || exit 0

/system/bin/sh "$MODDIR/rule_engine.sh" mount --boot || exit 0
/system/bin/sh "$MODDIR/doh_manager.sh" boot || true
/system/bin/sh "$MODDIR/lib/rules/app_policy.sh" reconcile || true
if /system/bin/sh "$MODDIR/history_manager.sh" boot-enabled; then
  /system/bin/sh "$MODDIR/process_manager.sh" start history-reconcile || true
fi
if /system/bin/sh "$MODDIR/refresh_manager.sh" boot-enabled; then
  /system/bin/sh "$MODDIR/process_manager.sh" start crond || true
fi
exit 0
