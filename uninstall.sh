#!/system/bin/sh

MODDIR=${MODDIR:-${0%/*}}
export MODDIR
failures=0

mkdir -p "$MODDIR/runtime" || exit 1
if [ ! -f "$MODDIR/runtime/uninstalling" ]; then
  marker="$MODDIR/runtime/uninstalling.tmp.$$"
  {
    printf 'schema_version=1\n'
    printf 'state=uninstalling\n'
    printf 'started_at=%s\n' "$(date +%s 2>/dev/null || printf 0)"
    printf 'pid=%s\n' "$$"
  } > "$marker" || exit 1
  mv -f "$marker" "$MODDIR/runtime/uninstalling" || exit 1
fi

/system/bin/sh "$MODDIR/process_manager.sh" stop operation-worker || failures=1
/system/bin/sh "$MODDIR/doh_manager.sh" cleanup-uninstall || failures=1
/system/bin/sh "$MODDIR/process_manager.sh" stop history-reconcile || failures=1
/system/bin/sh "$MODDIR/history_manager.sh" cleanup-uninstall || failures=1
/system/bin/sh "$MODDIR/process_manager.sh" stop-all || failures=1
/system/bin/sh "$MODDIR/refresh_manager.sh" cleanup-uninstall || failures=1
/system/bin/sh "$MODDIR/lib/rules/app_policy.sh" cleanup || failures=1
/system/bin/sh "$MODDIR/rule_engine.sh" cleanup || failures=1
/system/bin/sh "$MODDIR/firewall_manager.sh" cleanup || failures=1

if [ "$failures" -ne 0 ]; then
  printf '%s\n' 'JingJie cleanup incomplete: owned resources remain or could not be verified' >&2
  exit 1
fi

exit 0
