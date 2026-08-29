#!/system/bin/sh

REFRESH_ROOT=${REFRESH_MANAGER_ROOT:-${0%/*}}
MODDIR=${MODDIR:-$REFRESH_ROOT}
BB=${BB:-$MODDIR/busybox/busybox}
[ -x "$BB" ] || BB=$(command -v busybox 2>/dev/null || printf '%s' "$BB")
SYSTEM_SH=${SYSTEM_SH:-/system/bin/sh}
export MODDIR BB SYSTEM_SH

. "$REFRESH_ROOT/lib/rules/common.sh"
. "$REFRESH_ROOT/lib/rules/operations.sh"

refresh_config_file() {
  printf '%s\n' "$CONFIG_DIR/refresh.conf"
}

refresh_interval_valid() {
  case "$1" in 6|12|24) return 0 ;; *) return 1 ;; esac
}

refresh_config_validate_file() {
  local file=$1
  [ -f "$file" ] && [ ! -L "$file" ] || return 65
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2{bad()}
    $1!~/^(schema_version|auto_refresh_enabled|auto_refresh_interval_hours)$/{bad()}
    seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    $1=="auto_refresh_enabled" && $2!~/^[01]$/{bad()}
    $1=="auto_refresh_interval_hours" && $2!~/^(6|12|24)$/{bad()}
    END{if(NR!=3 || !seen["schema_version"] || !seen["auto_refresh_enabled"] || !seen["auto_refresh_interval_hours"])bad()}
  ' "$file"
}

refresh_config_write() {
  local enabled=$1 hours=$2 file tmp
  { [ "$enabled" = 0 ] || [ "$enabled" = 1 ]; } || return 65
  refresh_interval_valid "$hours" || return 65
  file=$(refresh_config_file)
  tmp="$file.tmp.$$"
  {
    printf 'schema_version=1\n'
    printf 'auto_refresh_enabled=%s\n' "$enabled"
    printf 'auto_refresh_interval_hours=%s\n' "$hours"
  } > "$tmp" || return 74
  refresh_config_validate_file "$tmp" || { rm -f "$tmp"; return 65; }
  chmod 0600 "$tmp" 2>/dev/null || true
  atomic_replace_file "$tmp" "$file"
}

refresh_config_bootstrap() {
  local file
  file=$(refresh_config_file)
  if [ ! -e "$file" ] && [ ! -L "$file" ]; then
    refresh_config_write 0 24 || return
  fi
  refresh_config_validate_file "$file"
}

refresh_config_load() {
  local file
  refresh_config_bootstrap || return
  file=$(refresh_config_file)
  AUTO_REFRESH_ENABLED=$("$BB" awk -F= '$1=="auto_refresh_enabled"{print $2}' "$file") || return 74
  AUTO_REFRESH_INTERVAL_HOURS=$("$BB" awk -F= '$1=="auto_refresh_interval_hours"{print $2}' "$file") || return 74
  export AUTO_REFRESH_ENABLED AUTO_REFRESH_INTERVAL_HOURS
}

refresh_schedule_directory() {
  printf '%s\n' "$RULE_RUNTIME/refresh/crontabs"
}

refresh_schedule_line() {
  local hours=$1 prefix
  case "$hours" in
    6) prefix='0 */6 * * *' ;;
    12) prefix='0 */12 * * *' ;;
    24) prefix='0 0 * * *' ;;
    *) return 65 ;;
  esac
  printf '%s /system/bin/sh %s/refresh_manager.sh tick\n' "$prefix" "$MODDIR"
}

refresh_schedule_write() {
  local hours=$1 directory file tmp expected
  refresh_interval_valid "$hours" || return 65
  directory=$(refresh_schedule_directory)
  [ ! -L "$RULE_RUNTIME/refresh" ] || return 65
  [ ! -L "$directory" ] || return 65
  mkdir -p "$directory" || return 73
  file="$directory/root"
  tmp="$file.tmp.$$"
  expected=$(refresh_schedule_line "$hours") || return
  printf '%s\n' "$expected" > "$tmp" || return 74
  chmod 0600 "$tmp" 2>/dev/null || true
  atomic_replace_file "$tmp" "$file"
}

# 暂停保护期间自动刷新必须彻底停下来：它每 6/12/24 小时就会把所有来源重新下载一遍
# 再重建世代，是暂停后最费电、也最容易把刚删掉的缓存重新造回来的一处。
# 判定方式和 history_active_paused 一致，只读 active.prop，不碰锁。
refresh_active_paused() {
  local file="$RULE_RUNTIME/active.prop" mode
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  mode=$("$BB" awk -F= '$1=="active_mode"{print $2}' "$file" 2>/dev/null || true)
  [ "$mode" = paused ]
}

refresh_schedule_remove() {
  local directory
  directory=$(refresh_schedule_directory)
  [ ! -L "$RULE_RUNTIME/refresh" ] || return 65
  [ ! -L "$directory" ] || return 65
  rm -f "$directory/root" "$directory"/root.tmp.* 2>/dev/null || return 74
  rmdir "$directory" 2>/dev/null || true
  rmdir "$RULE_RUNTIME/refresh" 2>/dev/null || true
}

refresh_status_json() {
  refresh_config_load || return
  if [ "$AUTO_REFRESH_ENABLED" = 1 ]; then
    printf '{"schemaVersion":1,"enabled":true,"intervalHours":%s}\n' "$AUTO_REFRESH_INTERVAL_HOURS"
  else
    printf '{"schemaVersion":1,"enabled":false,"intervalHours":%s}\n' "$AUTO_REFRESH_INTERVAL_HOURS"
  fi
}

refresh_boot_enabled() {
  refresh_config_load || return
  if [ "$AUTO_REFRESH_ENABLED" != 1 ]; then
    refresh_schedule_remove || return
    return 1
  fi
  # 暂停期间开机不起 crond，也不留调度文件；恢复保护时才装回去。
  # 用户的 auto_refresh_enabled 偏好一个字都不动。
  if refresh_active_paused; then
    refresh_schedule_remove || return
    return 1
  fi
  refresh_schedule_write "$AUTO_REFRESH_INTERVAL_HOURS"
}

# 暂停流程调用：撤掉调度并停掉 crond，但保留用户的开关和间隔偏好。
refresh_suspend() {
  local result=0
  refresh_schedule_remove || result=$?
  "$SYSTEM_SH" "$MODDIR/process_manager.sh" stop crond >/dev/null 2>&1 || true
  [ "$result" -eq 0 ] || return "$result"
}

# 恢复流程调用：按用户偏好把调度和 crond 装回去；本来就关着的话什么都不做。
refresh_resume() {
  refresh_config_load || return
  [ "$AUTO_REFRESH_ENABLED" = 1 ] || return 0
  refresh_restore_enabled_state "$AUTO_REFRESH_INTERVAL_HOURS"
}

refresh_restore_enabled_state() {
  local hours=$1
  refresh_config_write 1 "$hours" 2>/dev/null || true
  refresh_schedule_write "$hours" 2>/dev/null || true
  "$SYSTEM_SH" "$MODDIR/process_manager.sh" start crond >/dev/null 2>&1 || true
}

refresh_configure() {
  local enabled=$1 hours=$2 result previous_enabled previous_hours write_result
  { [ "$enabled" = 0 ] || [ "$enabled" = 1 ]; } || return 65
  refresh_interval_valid "$hours" || return 65
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  refresh_config_load || return
  previous_enabled=$AUTO_REFRESH_ENABLED
  previous_hours=$AUTO_REFRESH_INTERVAL_HOURS
  if [ "$enabled" = 0 ]; then
    set +e
    "$SYSTEM_SH" "$MODDIR/process_manager.sh" stop crond
    result=$?
    set -e
    [ "$result" -eq 0 ] || return "$result"
    set +e
    refresh_config_write 0 "$hours"
    write_result=$?
    set -e
    if [ "$write_result" -ne 0 ]; then
      [ "$previous_enabled" != 1 ] || refresh_restore_enabled_state "$previous_hours"
      return "$write_result"
    fi
    if ! refresh_schedule_remove; then
      [ "$previous_enabled" != 1 ] || refresh_restore_enabled_state "$previous_hours"
      return 74
    fi
    return 0
  fi

  if [ "$previous_enabled" = 1 ] && [ "$previous_hours" = "$hours" ]; then
    refresh_schedule_write "$hours" || return
    # 档位没变也要确认 crond 真的还活着。它可能被系统内存回收杀掉，或开机那次没起来；
    # 此时配置和 crontab 都写着“已开启”，但没有任何东西会触发刷新，
    # 而用户能做的恰恰就是再点一次保存。start 是幂等的：已在跑会返回 75，
    # 不会起第二个守护进程；只有确实没在跑时才真的拉起来。
    set +e
    "$SYSTEM_SH" "$MODDIR/process_manager.sh" start crond
    result=$?
    set -e
    { [ "$result" -eq 0 ] || [ "$result" -eq 75 ]; } || return "$result"
    return 0
  fi

  if [ "$previous_enabled" = 1 ] && [ "$previous_hours" != "$hours" ]; then
    set +e
    "$SYSTEM_SH" "$MODDIR/process_manager.sh" stop crond
    result=$?
    set -e
    [ "$result" -eq 0 ] || return "$result"

    if ! refresh_schedule_write "$hours"; then
      refresh_restore_enabled_state "$previous_hours"
      return 74
    fi
    set +e
    refresh_config_write 1 "$hours"
    write_result=$?
    set -e
    if [ "$write_result" -ne 0 ]; then
      refresh_restore_enabled_state "$previous_hours"
      return "$write_result"
    fi
    set +e
    "$SYSTEM_SH" "$MODDIR/process_manager.sh" start crond
    result=$?
    set -e
    if [ "$result" -ne 0 ]; then
      refresh_restore_enabled_state "$previous_hours"
      return "$result"
    fi
    return 0
  fi

  refresh_schedule_write "$hours" || return
  set +e
  refresh_config_write 1 "$hours"
  write_result=$?
  set -e
  if [ "$write_result" -ne 0 ]; then
    if [ "$previous_enabled" = 1 ]; then
      refresh_schedule_write "$previous_hours" 2>/dev/null || true
    else
      refresh_schedule_remove 2>/dev/null || true
    fi
    return "$write_result"
  fi
  set +e
  "$SYSTEM_SH" "$MODDIR/process_manager.sh" start crond
  result=$?
  set -e
  if [ "$result" -ne 0 ]; then
    if [ "$previous_enabled" = 1 ]; then
      refresh_restore_enabled_state "$previous_hours"
    else
      refresh_config_write 0 "$previous_hours" 2>/dev/null || true
      refresh_schedule_remove 2>/dev/null || true
    fi
    return "$result"
  fi
}

refresh_tick() {
  local result
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  refresh_config_load || return
  if [ "$AUTO_REFRESH_ENABLED" != 1 ]; then
    log_event info auto_refresh_skipped disabled || true
    return 0
  fi
  # 纵深防御：调度已经在暂停时撤掉了，这里再挡一层。哪怕有残留的 crontab 被触发，
  # 也不会联网下载、不会重建世代、不会把缓存造回来。
  if refresh_active_paused; then
    log_event info auto_refresh_skipped paused || true
    return 0
  fi
  set +e
  operation_submit refresh
  result=$?
  set -e
  if [ "$result" -eq 0 ]; then
    log_event info auto_refresh_submitted "${OPERATION_ACCEPTED_ID-accepted}" || true
    return 0
  fi
  if [ "$result" -eq 75 ] && [ "${OPERATION_SUBMIT_ERROR-}" = operation_busy ]; then
    log_event info auto_refresh_skipped operation_busy || true
    return 0
  fi
  log_event warn auto_refresh_failed "submit_status_$result" || true
  return "$result"
}

refresh_cleanup_uninstall() {
  [ -f "$RULE_RUNTIME/uninstalling" ] || return 75
  [ ! -L "$RULE_RUNTIME/refresh" ] || return 65
  rm -rf "$RULE_RUNTIME/refresh" || return 74
}

refresh_dispatch() {
  case "${1-}" in
    status) [ "$#" -eq 2 ] && [ "$2" = --json ] || return 64; refresh_status_json ;;
    configure) [ "$#" -eq 3 ] || return 64; refresh_configure "$2" "$3" ;;
    boot-enabled) [ "$#" -eq 1 ] || return 64; refresh_boot_enabled ;;
    suspend) [ "$#" -eq 1 ] || return 64; refresh_suspend ;;
    resume) [ "$#" -eq 1 ] || return 64; refresh_resume ;;
    tick) [ "$#" -eq 1 ] || return 64; refresh_tick ;;
    cleanup-uninstall) [ "$#" -eq 1 ] || return 64; refresh_cleanup_uninstall ;;
    *) return 64 ;;
  esac
}

if [ "${REFRESH_MANAGER_SOURCE_ONLY-0}" != 1 ]; then
  rules_init_paths "$MODDIR" || exit $?
  refresh_dispatch "$@"
fi
