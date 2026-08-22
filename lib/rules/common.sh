#!/system/bin/sh

RULE_MODULE_ID=jingjie_hosts
RULE_LOG_LIMIT=262144

rules_init_paths() {
  MODDIR=$1
  case "$MODDIR" in
    /*) ;;
    *) return 64 ;;
  esac

  CONFIG_DIR="$MODDIR/config"
  CACHE_DIR="$MODDIR/cache"
  RULE_RUNTIME="$MODDIR/runtime"
  RULE_LOG="$RULE_RUNTIME/logs/rule-engine.log"
  RULE_TMP="$RULE_RUNTIME/tmp"
  RULE_LOCKS="$RULE_RUNTIME/locks"
  RULE_GENERATIONS="$RULE_RUNTIME/generations"
  RULE_OPERATIONS="$RULE_RUNTIME/operations"
  export MODDIR CONFIG_DIR CACHE_DIR RULE_RUNTIME RULE_LOG RULE_TMP
  export RULE_LOCKS RULE_GENERATIONS RULE_OPERATIONS

  mkdir -p "$CONFIG_DIR/revisions" "$CACHE_DIR/custom" \
    "$RULE_RUNTIME/logs" "$RULE_TMP" "$RULE_LOCKS" \
    "$RULE_GENERATIONS" "$RULE_OPERATIONS"
}

atomic_replace_file() {
  src=$1
  dst=$2
  [ -f "$src" ] || return 66
  parent=${dst%/*}
  [ "$parent" != "$dst" ] || return 64
  mkdir -p "$parent" || return 73
  mv -f "$src" "$dst" || return 74
}

sha256_file() {
  [ -f "$1" ] || return 66
  "$BB" sha256sum "$1" | "$BB" awk '{print tolower($1)}'
}

sha256_file_stdin() {
  "$BB" sha256sum - | "$BB" awk '{print tolower($1)}'
}

proc_starttime() {
  pid=$1
  case "$pid" in
    ''|*[!0-9]*) return 65 ;;
  esac
  [ -r "/proc/$pid/stat" ] || return 1
  stat_line=$(cat "/proc/$pid/stat") || return 1
  after_comm=${stat_line##*) }
  printf '%s\n' "$after_comm" | "$BB" awk '{print $20}'
}

decimal_uint_in_range() {
  [ "$#" -eq 2 ] || [ "$#" -eq 3 ] || return 1
  local value=$1 maximum=$2 minimum=${3-0} value_length maximum_length minimum_length
  case "$value" in ''|*[!0-9]*) return 1 ;; esac
  case "$maximum" in ''|*[!0-9]*) return 1 ;; esac
  case "$minimum" in ''|*[!0-9]*) return 1 ;; esac
  while [ "${#value}" -gt 1 ] && [ "${value#0}" != "$value" ]; do value=${value#0}; done
  while [ "${#maximum}" -gt 1 ] && [ "${maximum#0}" != "$maximum" ]; do maximum=${maximum#0}; done
  while [ "${#minimum}" -gt 1 ] && [ "${minimum#0}" != "$minimum" ]; do minimum=${minimum#0}; done
  value_length=${#value}
  maximum_length=${#maximum}
  minimum_length=${#minimum}
  [ "$minimum_length" -lt "$maximum_length" ] || {
    [ "$minimum_length" -eq "$maximum_length" ] || return 1
    LC_ALL=C "$BB" awk -v minimum="x$minimum" -v maximum="x$maximum" \
      'BEGIN { exit minimum <= maximum ? 0 : 1 }' || return 1
  }
  [ "$value_length" -ge "$minimum_length" ] && [ "$value_length" -le "$maximum_length" ] || return 1
  if [ "$value_length" -eq "$minimum_length" ]; then
    LC_ALL=C "$BB" awk -v value="x$value" -v minimum="x$minimum" \
      'BEGIN { exit value >= minimum ? 0 : 1 }' || return 1
  fi
  if [ "$value_length" -eq "$maximum_length" ]; then
    LC_ALL=C "$BB" awk -v value="x$value" -v maximum="x$maximum" \
      'BEGIN { exit value <= maximum ? 0 : 1 }' || return 1
  fi
}

lock_name_valid() {
  case "$1" in
    ''|*[!a-z0-9_-]*) return 1 ;;
    *) return 0 ;;
  esac
}

rules_lock_acquire() {
  name=$1
  lock_name_valid "$name" || return 64
  lock_root=${RULE_LOCKS:-${RULE_RUNTIME:?}/locks}
  lock_dir="$lock_root/$name.lock"
  mkdir -p "$lock_root" || return 73
  if mkdir "$lock_dir" 2>/dev/null; then
    start=$(proc_starttime "$$") || {
      rmdir "$lock_dir" 2>/dev/null
      return 70
    }
    printf 'pid=%s\nstarttime=%s\n' "$$" "$start" > "$lock_dir/owner.prop" || {
      rm -rf "$lock_dir"
      return 74
    }
    RULE_HELD_LOCKS="${RULE_HELD_LOCKS-} $name"
    export RULE_HELD_LOCKS
    return 0
  fi

  owner="$lock_dir/owner.prop"
  owner_pid=$("$BB" awk -F= '$1=="pid"{print $2}' "$owner" 2>/dev/null)
  owner_start=$("$BB" awk -F= '$1=="starttime"{print $2}' "$owner" 2>/dev/null)
  live_start=$(proc_starttime "$owner_pid" 2>/dev/null || true)
  if [ -n "$owner_pid" ] && [ -n "$owner_start" ] && [ "$live_start" = "$owner_start" ]; then
    return 75
  fi

  rm -rf "$lock_dir" || return 75
  rules_lock_acquire "$name"
}

rules_lock_release() {
  name=$1
  lock_name_valid "$name" || return 64
  lock_root=${RULE_LOCKS:-${RULE_RUNTIME:?}/locks}
  lock_dir="$lock_root/$name.lock"
  [ -d "$lock_dir" ] || return 0
  owner_pid=$("$BB" awk -F= '$1=="pid"{print $2}' "$lock_dir/owner.prop" 2>/dev/null)
  owner_start=$("$BB" awk -F= '$1=="starttime"{print $2}' "$lock_dir/owner.prop" 2>/dev/null)
  self_start=$(proc_starttime "$$" 2>/dev/null || true)
  [ "$owner_pid" = "$$" ] && [ "$owner_start" = "$self_start" ] || return 76
  rm -rf "$lock_dir" || return 74
  new_held=
  for held in ${RULE_HELD_LOCKS-}; do
    [ "$held" = "$name" ] || new_held="$new_held $held"
  done
  RULE_HELD_LOCKS=$new_held
  export RULE_HELD_LOCKS
}

rules_lock_is_held() {
  case " ${RULE_HELD_LOCKS-} " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

json_escape() {
  "$BB" od -An -v -t u1 | "$BB" awk '
    {
      for (i = 1; i <= NF; i++) {
        b = $i + 0
        if (b == 34) printf "\\\""
        else if (b == 92) printf "\\\\"
        else if (b == 8) printf "\\b"
        else if (b == 9) printf "\\t"
        else if (b == 10) printf "\\n"
        else if (b == 12) printf "\\f"
        else if (b == 13) printf "\\r"
        else if (b < 32) printf "\\u%04x", b
        else printf "%c", b
      }
    }
  '
}

log_event() {
  level=$1
  code=$2
  message=$3
  mkdir -p "${RULE_LOG%/*}" "$RULE_TMP" || return 73
  now=$(date +%s 2>/dev/null || printf '0')
  level_json=$(printf '%s' "$level" | json_escape)
  code_json=$(printf '%s' "$code" | json_escape)
  message_json=$(printf '%s' "$message" | json_escape)
  entry_tmp="$RULE_TMP/log.$$.$now"
  printf '{"time":%s,"level":"%s","code":"%s","message":"%s"}\n' \
    "$now" "$level_json" "$code_json" "$message_json" > "$entry_tmp" || return 74

  current_size=0
  [ ! -f "$RULE_LOG" ] || current_size=$(wc -c < "$RULE_LOG" | tr -d ' ')
  entry_size=$(wc -c < "$entry_tmp" | tr -d ' ')
  if [ $((current_size + entry_size)) -gt "$RULE_LOG_LIMIT" ]; then
    rm -f "$RULE_LOG.2"
    [ ! -f "$RULE_LOG" ] || mv -f "$RULE_LOG" "$RULE_LOG.1" || return 74
  fi
  cat "$entry_tmp" >> "$RULE_LOG" || return 74
  rm -f "$entry_tmp"
}

# 日志档位：off / blocked_error / all。只有选“全部模块事件”时才写明细事件
# （放行计数、命中来源等），其余档位保持安静，避免默认档位写出大量日志。
log_mode_is_all() {
  [ -n "${CONFIG_DIR-}" ] || return 1
  [ -f "$CONFIG_DIR/log-mode.prop" ] || return 1
  while IFS='=' read -r key value || [ -n "$key" ]; do
    [ "$key" = mode ] || continue
    [ "$value" = all ] && return 0
    return 1
  done < "$CONFIG_DIR/log-mode.prop"
  return 1
}

# 只在“全部模块事件”档位落盘的明细日志；其他档位直接成功返回，不影响调用方。
log_verbose_event() {
  log_mode_is_all || return 0
  log_event "$@"
}
