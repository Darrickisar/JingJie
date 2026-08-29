#!/system/bin/sh

# 品牌标识集中在这里，其他脚本一律从这些变量派生，不要再写字面量。
# 改名时只动这一段：模块 id、防火墙链前缀、伴随进程文件名前缀。
# 三者都是纯常量赋值，没有子进程、没有文件读取，因此不增加任何运行开销。
RULE_MODULE_ID=zhulong_hosts
# 拉丁品牌名，用于发布物名称（zip、仓库 URL）。大小写无法从小写 id 推导，
# 所以单独声明；构建器读这一条决定 zip 文件名。
RULE_BRAND_LATIN=ZhuLong
# 自定义链名上限 28 字符，下面最长的 ${RULE_CHAIN_PREFIX}_HISTORY_GUARD 也远低于此。
RULE_CHAIN_PREFIX=ZHULONG
# DoH 链用短前缀：这些名字会进规则文本，短一点便于人工排查。
RULE_DOH_CHAIN_PREFIX=ZLD
# 伴随进程二进制与清单条目的文件名前缀。
RULE_COMPANION_PREFIX=zhulong
RUNTIME_LOG_LIMIT=262144

rules_init_paths() {
  MODDIR=$1
  case "$MODDIR" in
    /*) ;;
    *) return 64 ;;
  esac

  CONFIG_DIR="$MODDIR/config"
  CACHE_DIR="$MODDIR/cache"
  RULE_RUNTIME="$MODDIR/runtime"
  RUNTIME_LOG="$RULE_RUNTIME/logs/runtime.log"
  RULE_TMP="$RULE_RUNTIME/tmp"
  RULE_LOCKS="$RULE_RUNTIME/locks"
  RULE_GENERATIONS="$RULE_RUNTIME/generations"
  RULE_OPERATIONS="$RULE_RUNTIME/operations"
  export MODDIR CONFIG_DIR CACHE_DIR RULE_RUNTIME RUNTIME_LOG RULE_TMP
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

# 把一条已成型的 JSON 行追加到日志文件，超过上限时轮转一代。
log_write_rotating() {
  log_file=$1
  log_limit=$2
  log_line=$3
  mkdir -p "${log_file%/*}" "$RULE_TMP" || return 73
  entry_tmp="$RULE_TMP/log.$$.$(date +%s 2>/dev/null || printf '0')"
  printf '%s\n' "$log_line" > "$entry_tmp" || return 74

  current_size=0
  [ ! -f "$log_file" ] || current_size=$(wc -c < "$log_file" | tr -d ' ')
  entry_size=$(wc -c < "$entry_tmp" | tr -d ' ')
  if [ $((current_size + entry_size)) -gt "$log_limit" ]; then
    rm -f "$log_file.2"
    [ ! -f "$log_file" ] || mv -f "$log_file" "$log_file.1" || { rm -f "$entry_tmp"; return 74; }
  fi
  cat "$entry_tmp" >> "$log_file" || { rm -f "$entry_tmp"; return 74; }
  rm -f "$entry_tmp"
}

# 规则引擎事件。它以前写在单独的 rule-engine.log 里，也就是界面上的「规则日志」；
# 那一栏被取消后这些事件并入运行日志，stage 固定为 engine，全模块只留一份日志文件：
# 少一份要轮转、要占空间、要单独维护上限的文本，也不会再出现两份日志各说一半的情况。
# 同时继承运行日志的开关语义——失败无条件落盘，每步成功的明细跟着开关走。
log_event() {
  [ "$#" -eq 3 ] || return 64
  runtime_log_event "$1" engine "$2" "$3"
}

# 运行日志开关：runtime-log.prop 的 enabled=1。文件缺失时视为开启——
# 这份日志的唯一用途是定位故障，宁可多写也不要在用户真正需要时是空的。
runtime_log_enabled() {
  [ -n "${CONFIG_DIR-}" ] || return 1
  [ -f "$CONFIG_DIR/runtime-log.prop" ] || return 0
  while IFS='=' read -r key value || [ -n "$key" ]; do
    [ "$key" = enabled ] || continue
    [ "$value" = 1 ] && return 0
    return 1
  done < "$CONFIG_DIR/runtime-log.prop"
  return 0
}

# 全模块运行日志。比 log_event 多一个 stage 字段，用来标出失败发生在哪一步。
#
# level=error 无条件写盘，即使开关是关闭的：加密 DNS 曾经只留下一句
# last_error=runtime_failed，没有任何过程记录，整整两天无法定位失败点。
# 开关控制的是每步成功的明细（info/debug），那些才是平时的噪音来源。
runtime_log_event() {
  [ "$#" -eq 4 ] || return 64
  level=$1
  stage=$2
  code=$3
  message=$4
  [ "$level" = error ] || runtime_log_enabled || return 0
  now=$(date +%s 2>/dev/null || printf '0')
  level_json=$(printf '%s' "$level" | json_escape)
  stage_json=$(printf '%s' "$stage" | json_escape)
  code_json=$(printf '%s' "$code" | json_escape)
  message_json=$(printf '%s' "$message" | json_escape)
  log_write_rotating "$RUNTIME_LOG" "$RUNTIME_LOG_LIMIT" \
    "$(printf '{"time":%s,"level":"%s","stage":"%s","code":"%s","message":"%s"}' \
      "$now" "$level_json" "$stage_json" "$code_json" "$message_json")"
}
