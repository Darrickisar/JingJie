#!/system/bin/sh

PROCESS_ROOT=${PROCESS_MANAGER_ROOT:-${0%/*}}
MODDIR=${MODDIR:-$PROCESS_ROOT}
BB=${BB:-$MODDIR/busybox/busybox}
[ -x "$BB" ] || BB=$(command -v busybox 2>/dev/null || printf '%s' "$BB")
SYSTEM_SH=${SYSTEM_SH:-/system/bin/sh}
export MODDIR BB SYSTEM_SH

. "$PROCESS_ROOT/lib/rules/common.sh"
. "$PROCESS_ROOT/lib/rules/operations.sh"
. "$PROCESS_ROOT/lib/rules/doh.sh"

process_role_valid() {
  case "$1" in
    operation-worker|history-reader|history-reconcile|crond|doh-proxy-a|doh-proxy-b) return 0 ;;
    *) return 64 ;;
  esac
}

process_start_role_valid() {
  case "$1" in
    crond|history-reconcile|doh-proxy-a|doh-proxy-b) return 0 ;;
    *) return 64 ;;
  esac
}

process_known_roles() {
  printf '%s\n' operation-worker history-reader history-reconcile crond doh-proxy-a doh-proxy-b
}

process_history_map_token_valid() {
  [ "${#1}" -eq 16 ] || return 1
  case "$1" in *[!0-9a-f]*) return 1 ;; *) return 0 ;; esac
}

process_prop_safe() {
  local value=$1 tab
  tab=$(printf '\t')
  case "$value" in *"$tab"*) return 1 ;; esac
  [ "$(printf '%s' "$value" | "$BB" wc -l | "$BB" tr -d ' ')" -eq 0 ]
}

process_proc_ids() {
  local pid=$1 line after
  line=$(cat "/proc/$pid/stat" 2>/dev/null) || return 1
  after=${line##*) }
  PROCESS_PGID=$(printf '%s\n' "$after" | "$BB" awk '{print $3}')
  PROCESS_SID=$(printf '%s\n' "$after" | "$BB" awk '{print $4}')
  case "$PROCESS_PGID:$PROCESS_SID" in *[!0-9:]*) return 1 ;; esac
  export PROCESS_PGID PROCESS_SID
}

process_identity_capture() {
  local pid=$1
  PROCESS_PID_STARTTIME=$(proc_starttime "$pid" 2>/dev/null) || return 1
  process_proc_ids "$pid" || return 1
  PROCESS_CMD_SHA=$("$BB" sha256sum "/proc/$pid/cmdline" 2>/dev/null | "$BB" awk '{print tolower($1)}') || return 1
  PROCESS_CWD=$("$BB" readlink "/proc/$pid/cwd" 2>/dev/null) || return 1
  PROCESS_EXE=$("$BB" readlink "/proc/$pid/exe" 2>/dev/null) || return 1
  PROCESS_NS=$("$BB" readlink "/proc/$pid/ns/mnt" 2>/dev/null) || return 1
  [ -n "$PROCESS_CMD_SHA" ] && [ -n "$PROCESS_CWD" ] && [ -n "$PROCESS_EXE" ] && [ -n "$PROCESS_NS" ] || return 1
  process_prop_safe "$PROCESS_CWD" && process_prop_safe "$PROCESS_EXE" && process_prop_safe "$PROCESS_NS" || return 1
  export PROCESS_PID_STARTTIME PROCESS_CMD_SHA PROCESS_CWD PROCESS_EXE PROCESS_NS
}

process_record_file() {
  printf '%s\n' "$RULE_RUNTIME/processes.tsv"
}

process_record_find() {
  local role=$1 file
  file=$(process_record_file)
  [ -f "$file" ] || return 1
  "$BB" awk -F '\t' -v wanted="$role" '$3==wanted{line=$0} END{if(line!="")print line; else exit 1}' "$file"
}

process_record_write() {
  local state=$1 token=$2 role=$3 pid=$4 start=$5 pgid=$6 sid=$7 cmd_sha=$8
  shift 8
  local cwd=$1 exe=$2 ns=$3 file tmp
  case "$state" in pending|registered) ;; *) return 65 ;; esac
  operation_token_valid "$token" || return 65
  process_role_valid "$role" || return 64
  file=$(process_record_file)
  tmp="$file.tmp.$$"
  mkdir -p "${file%/*}" || return 73
  if [ -f "$file" ]; then
    "$BB" awk -F '\t' -v wanted="$role" '$3!=wanted{print}' "$file" > "$tmp" || return 74
  else
    : > "$tmp"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$state" "$token" "$role" "$pid" "$start" "$pgid" "$sid" "$cmd_sha" "$cwd" "$exe" "$ns" >> "$tmp" || return 74
  atomic_replace_file "$tmp" "$file"
}

process_record_remove() {
  local role=$1 file tmp
  process_role_valid "$role" || return 64
  file=$(process_record_file)
  [ -f "$file" ] || return 0
  tmp="$file.tmp.$$"
  "$BB" awk -F '\t' -v wanted="$role" '$3!=wanted{print}' "$file" > "$tmp" || return 74
  if [ -s "$tmp" ]; then
    atomic_replace_file "$tmp" "$file"
  else
    rm -f "$tmp" "$file"
  fi
}

process_record_load() {
  local role=$1 line
  process_role_valid "$role" || return 64
  line=$(process_record_find "$role") || return 1
  IFS="$(printf '\t')" read -r PROCESS_STATE PROCESS_TOKEN PROCESS_ROLE PROCESS_PID \
    PROCESS_START PROCESS_RECORDED_PGID PROCESS_RECORDED_SID PROCESS_RECORDED_CMD_SHA \
    PROCESS_RECORDED_CWD PROCESS_RECORDED_EXE PROCESS_RECORDED_NS <<EOF
$line
EOF
  [ "$PROCESS_ROLE" = "$role" ] || return 65
  case "$PROCESS_STATE" in pending|registered) ;; *) return 65 ;; esac
  operation_token_valid "$PROCESS_TOKEN" || return 65
  export PROCESS_STATE PROCESS_TOKEN PROCESS_ROLE PROCESS_PID PROCESS_START
  export PROCESS_RECORDED_PGID PROCESS_RECORDED_SID PROCESS_RECORDED_CMD_SHA
  export PROCESS_RECORDED_CWD PROCESS_RECORDED_EXE PROCESS_RECORDED_NS
}

process_identity_matches_loaded() {
  [ "$PROCESS_STATE" = registered ] || return 1
  process_identity_capture "$PROCESS_PID" || return 1
  [ "$PROCESS_PID_STARTTIME" = "$PROCESS_START" ] &&
    [ "$PROCESS_PGID" = "$PROCESS_RECORDED_PGID" ] &&
    [ "$PROCESS_SID" = "$PROCESS_RECORDED_SID" ] &&
    [ "$PROCESS_CMD_SHA" = "$PROCESS_RECORDED_CMD_SHA" ] &&
    [ "$PROCESS_CWD" = "$PROCESS_RECORDED_CWD" ] &&
    [ "$PROCESS_EXE" = "$PROCESS_RECORDED_EXE" ] &&
    [ "$PROCESS_NS" = "$PROCESS_RECORDED_NS" ]
}

process_background_capable() {
  local applets
  [ -x "$BB" ] || return 69
  applets=$("$BB" --list 2>/dev/null) || return 69
  for applet in nohup setsid sha256sum readlink awk; do
    printf '%s\n' "$applets" | "$BB" grep -x "$applet" >/dev/null 2>&1 || return 69
  done
}

process_architecture() {
  local arch=${PROCESS_ARCH-}
  if [ -z "$arch" ] && command -v getprop >/dev/null 2>&1; then
    arch=$(getprop ro.product.cpu.abi 2>/dev/null || true)
  fi
  [ -n "$arch" ] || arch=$(uname -m 2>/dev/null || true)
  case "$arch" in
    aarch64|arm64|arm64-v8a) printf 'arm64\n' ;;
    armv7l|arm|armeabi-v7a) printf 'arm32\n' ;;
    i686|x86) printf 'x86\n' ;;
    x86_64|x64) printf 'x86_64\n' ;;
    *) return 69 ;;
  esac
}

process_history_reader_binary() {
  local arch path
  arch=$(process_architecture) || return
  path="$MODDIR/tools/history_reader_$arch"
  [ -x "$path" ] && [ -f "$path" ] && [ ! -L "$path" ] || return 69
  printf '%s\n' "$path"
}

process_doh_slot_valid() {
  case "$1" in a|b) return 0 ;; *) return 65 ;; esac
}

process_doh_transition_valid() {
  [ "${#1}" -eq 16 ] || return 65
  case "$1" in *[!0-9a-f]*) return 65 ;; *) return 0 ;; esac
}

process_doh_role_for_slot() {
  process_doh_slot_valid "$1" || return
  printf 'doh-proxy-%s\n' "$1"
}

process_doh_port_for_slot() {
  case "$1" in a) printf '5533\n' ;; b) printf '5534\n' ;; *) return 65 ;; esac
}

process_doh_config_valid() {
  [ "$#" -eq 1 ] || return 64
  [ -f "$1" ] && [ ! -L "$1" ] || return 66
}

process_doh_binary_validate() {
  [ "$#" -eq 0 ] || return 64
  local arch row tab asset url gzip_size gzip_hash binary_size binary_hash machine target mode
  doh_init_paths
  arch=$(process_architecture) || return
  row=$(doh_companion_manifest_row "$arch") || return
  tab=$(printf '\t')
  IFS="$tab" read -r _ asset url gzip_size gzip_hash binary_size binary_hash machine <<EOF
$row
EOF
  target=$DOH_COMPANION_TARGET
  [ -x "$target" ] || return 66
  doh_companion_file_validate "$target" "$binary_size" "$binary_hash" "$machine" || return
  mode=$("$BB" stat -c %a "$target") || return 74
  [ "$mode" = 700 ] || return 65
  printf '%s\n' "$target"
}

process_doh_ready_validate() {
  [ "$#" -eq 3 ] || return 64
  local file=$1 slot=$2 transition=$3 port line
  process_doh_slot_valid "$slot" || return
  process_doh_transition_valid "$transition" || return
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  [ "$(wc -l < "$file" | "$BB" tr -d ' ')" -eq 1 ] || return 65
  port=$(process_doh_port_for_slot "$slot") || return
  IFS= read -r line < "$file" || return 65
  [ "$line" = "READY $transition $port" ] || return 65
}

process_doh_dir() {
  printf '%s\n' "$RULE_RUNTIME/doh/process"
}

process_doh_slot_file() {
  process_doh_slot_valid "$1" || return
  printf '%s/slot-%s.prop\n' "$(process_doh_dir)" "$1"
}

process_doh_ready_file() {
  process_doh_slot_valid "$1" || return
  process_doh_transition_valid "$2" || return
  printf '%s/ready-%s-%s\n' "$(process_doh_dir)" "$1" "$2"
}

process_doh_stop_marker_path() {
  [ "$#" -eq 2 ] || return 64
  process_role_valid "$1" || return
  case "$1" in doh-proxy-a|doh-proxy-b) ;; *) return 64 ;; esac
  process_doh_transition_valid "$2" || return
  printf '%s/stop-%s-%s\n' "$(process_doh_dir)" "$1" "$2"
}

process_doh_generic_stop_marker_path() {
  case "$1" in doh-proxy-a|doh-proxy-b) ;; *) return 64 ;; esac
  printf '%s/stop-%s\n' "$(process_doh_dir)" "$1"
}

process_doh_should_crash() {
  [ "$#" -eq 2 ] || return 64
  local exact generic
  exact=$(process_doh_stop_marker_path "$1" "$2") || return
  generic=$(process_doh_generic_stop_marker_path "$1") || return
  [ ! -e "$exact" ] && [ ! -L "$exact" ] && [ ! -e "$generic" ] && [ ! -L "$generic" ]
}

process_doh_child_record_write() {
  [ "$#" -eq 11 ] || return 64
  local slot=$1 transition=$2 supervisor=$3 pid=$4 start=$5 pgid=$6 sid=$7 sha=$8
  shift 8
  local cwd=$1 exe=$2 ns=$3 file tmp
  process_doh_slot_valid "$slot" || return
  process_doh_transition_valid "$transition" || return
  file=$(process_doh_slot_file "$slot") || return
  tmp="$file.tmp.$$"
  mkdir -p "${file%/*}" || return 73
  {
    printf 'schema_version=1\n'
    printf 'transition_token=%s\n' "$transition"
    printf 'supervisor_pid=%s\n' "$supervisor"
    printf 'child_pid=%s\n' "$pid"
    printf 'child_starttime=%s\n' "$start"
    printf 'child_pgid=%s\n' "$pgid"
    printf 'child_sid=%s\n' "$sid"
    printf 'child_cmd_sha256=%s\n' "$sha"
    printf 'child_cwd=%s\n' "$cwd"
    printf 'child_exe=%s\n' "$exe"
    printf 'child_mnt_ns=%s\n' "$ns"
  } > "$tmp" || { rm -f "$tmp"; return 74; }
  chmod 600 "$tmp" || { rm -f "$tmp"; return 74; }
  atomic_replace_file "$tmp" "$file"
}

process_doh_slot_transition() {
  local file
  file=$(process_doh_slot_file "$1") || return
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  "$BB" awk -F= '$1=="transition_token"{print $2; found=1} END{exit found?0:1}' "$file"
}

process_doh_child_identity_validate() {
  [ "$#" -eq 2 ] || return 64
  local slot=$1 transition=$2 file expected_exe schema token supervisor pid start pgid sid sha cwd exe ns
  file=$(process_doh_slot_file "$slot") || return
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  [ "$(wc -l < "$file" | "$BB" tr -d ' ')" -eq 11 ] || return 65
  schema=$(sed -n '1s/^schema_version=//p' "$file")
  token=$(sed -n '2s/^transition_token=//p' "$file")
  supervisor=$(sed -n '3s/^supervisor_pid=//p' "$file")
  pid=$(sed -n '4s/^child_pid=//p' "$file")
  start=$(sed -n '5s/^child_starttime=//p' "$file")
  pgid=$(sed -n '6s/^child_pgid=//p' "$file")
  sid=$(sed -n '7s/^child_sid=//p' "$file")
  sha=$(sed -n '8s/^child_cmd_sha256=//p' "$file")
  cwd=$(sed -n '9s/^child_cwd=//p' "$file")
  exe=$(sed -n '10s/^child_exe=//p' "$file")
  ns=$(sed -n '11s/^child_mnt_ns=//p' "$file")
  [ "$schema" = 1 ] && [ "$token" = "$transition" ] || return 65
  case "$supervisor:$pid:$start:$pgid:$sid" in *[!0-9:]*) return 65 ;; esac
  process_record_load "$(process_doh_role_for_slot "$slot")" 2>/dev/null || return 69
  [ "$PROCESS_PID" = "$supervisor" ] || return 65
  process_identity_matches_loaded || return 69
  expected_exe=$(process_doh_binary_validate) || return
  [ "$exe" = "$expected_exe" ] || return 65
  process_captured_identity_matches "$pid" "$start" "$pgid" "$sid" "$sha" "$cwd" "$exe" "$ns"
}

process_role_capable() {
  local role=$1 applets
  process_role_valid "$role" || return 64
  process_background_capable || return
  if [ "$role" = history-reader ]; then
    process_history_reader_binary >/dev/null || return
  elif [ "$role" = crond ]; then
    process_crond_schedule_valid || return
    applets=$("$BB" --list 2>/dev/null) || return 69
    printf '%s\n' "$applets" | "$BB" grep -x crond >/dev/null 2>&1 || return 69
  elif [ "$role" = doh-proxy-a ] || [ "$role" = doh-proxy-b ]; then
    process_doh_binary_validate >/dev/null || return
  fi
}

process_crond_schedule_valid() {
  local directory="$RULE_RUNTIME/refresh/crontabs" file line
  file="$directory/root"
  [ -d "$directory" ] && [ ! -L "$directory" ] || return 66
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  [ "$(wc -l < "$file" | "$BB" tr -d ' ')" -eq 1 ] || return 65
  line=$(cat "$file") || return 74
  case "$line" in
    "0 */6 * * * /system/bin/sh $MODDIR/refresh_manager.sh tick"|\
    "0 */12 * * * /system/bin/sh $MODDIR/refresh_manager.sh tick"|\
    "0 0 * * * /system/bin/sh $MODDIR/refresh_manager.sh tick") return 0 ;;
    *) return 65 ;;
  esac
}

process_signal_group() {
  local signal=$1 pgid=$2
  case "$signal" in TERM|KILL) ;; *) return 65 ;; esac
  case "$pgid" in ''|0|*[!0-9]*) return 65 ;; esac
  kill "-$signal" "-$pgid" 2>/dev/null
}

process_captured_identity_matches() {
  local pid=$1 start=$2 pgid=$3 sid=$4 sha=$5 cwd=$6 exe=$7 ns=$8
  process_identity_capture "$pid" || return 1
  [ "$PROCESS_PID_STARTTIME" = "$start" ] && [ "$PROCESS_PGID" = "$pgid" ] && \
    [ "$PROCESS_SID" = "$sid" ] && [ "$PROCESS_CMD_SHA" = "$sha" ] && \
    [ "$PROCESS_CWD" = "$cwd" ] && [ "$PROCESS_EXE" = "$exe" ] && [ "$PROCESS_NS" = "$ns" ]
}

process_stop_captured_identity() {
  local pid=$1 start=$2 pgid=$3 sid=$4 sha=$5 cwd=$6 exe=$7 ns=$8 attempt
  process_captured_identity_matches "$@" || return 0
  process_signal_group TERM "$pgid" 2>/dev/null || true
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    process_captured_identity_matches "$@" || return 0
    attempt=$((attempt + 1)); sleep 0.1
  done
  process_signal_group KILL "$pgid" 2>/dev/null || true
  attempt=0
  while [ "$attempt" -lt 20 ]; do
    process_captured_identity_matches "$@" || return 0
    attempt=$((attempt + 1)); sleep 0.1
  done
  process_captured_identity_matches "$@" && return 76
  return 0
}

process_launcher_ready_validate() {
  local role=$1 token=$2 file="$RULE_RUNTIME/ready/$2" ready_token ready_pid ready_start line
  [ -f "$file" ] || return 1
  [ "$(wc -l < "$file" | "$BB" tr -d ' ')" -eq 3 ] || return 65
  ready_token=$(operation_prop_value "$file" token)
  ready_pid=$(operation_prop_value "$file" pid)
  ready_start=$(operation_prop_value "$file" pid_starttime)
  [ "$ready_token" = "$token" ] && [ "$ready_pid" = "$$" ] || return 65
  [ "$ready_start" = "$(proc_starttime "$$")" ] || return 65
  line=$("$BB" awk -F '\t' -v token="$token" -v pid="$$" -v role="$role" \
    '$1=="registered" && $2==token && $3==role && $4==pid{print; found=1} END{exit found?0:1}' \
    "$RULE_RUNTIME/processes.tsv" 2>/dev/null) || return 65
  [ -n "$line" ]
}

process_launcher_wait_ready() {
  local role=$1 token=$2 attempt=0
  while [ "$attempt" -lt 30 ]; do
    process_launcher_ready_validate "$role" "$token" && {
      rm -f "$RULE_RUNTIME/ready/$token"
      return 0
    }
    [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
    attempt=$((attempt + 1))
    sleep 0.1
  done
  return 69
}

process_history_launcher_exec() {
  local map_token=$1 process_token=$2 binary map history ready request ack
  process_history_map_token_valid "$map_token" || return 65
  operation_token_valid "$process_token" || return 65
  binary=$(process_history_reader_binary) || return
  history="$RULE_RUNTIME/history"
  map="$history/maps/$map_token.tsv"
  [ -f "$map" ] && [ ! -L "$map" ] || return 66
  ready="$history/reader-ready.$process_token.prop"
  request="$history/flush.$process_token.prop"
  ack="$history/flush-ack.$process_token.prop"
  exec "$binary" --group 10007 --token "$map_token" --process-token "$process_token" \
    --map "$map" --events "$history/events.tsv" --ready "$ready" \
    --flush-request "$request" --flush-ack "$ack"
}

process_history_launcher_main() {
  [ "$#" -eq 2 ] || return 64
  local map_token=$1 process_token=$2
  process_history_map_token_valid "$map_token" || return 65
  operation_token_valid "$process_token" || return 65
  rules_init_paths "$MODDIR" || return
  process_launcher_wait_ready history-reader "$process_token" || return
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  process_history_launcher_exec "$map_token" "$process_token"
}

process_launcher_spawn() {
  local role=$1
  case "$role" in
    crond)
      process_crond_schedule_valid || return
      "$BB" crond -f -c "$RULE_RUNTIME/refresh/crontabs" >> "$RULE_LOG" 2>&1 &
      ;;
    history-reconcile)
      "$SYSTEM_SH" "$MODDIR/history_manager.sh" reconcile &
      ;;
    *) return 64 ;;
  esac
  PROCESS_CHILD_PID=$!
  export PROCESS_CHILD_PID
}

process_launcher_main() {
  [ "$#" -eq 2 ] || return 64
  local role=$1 token=$2 result
  process_role_valid "$role" || return 64
  [ "$role" != operation-worker ] || return 64
  operation_token_valid "$token" || return 65
  rules_init_paths "$MODDIR" || return
  process_launcher_wait_ready "$role" "$token" || return
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  process_launcher_spawn "$role" || return
  wait "$PROCESS_CHILD_PID"
  result=$?
  return "$result"
}

process_cmdline_is_doh_supervisor() {
  local pid=$1
  [ -r "/proc/$pid/cmdline" ] || return 1
  "$BB" tr '\000' '\n' < "/proc/$pid/cmdline" 2>/dev/null | "$BB" grep -Fx "$MODDIR/process_manager.sh" >/dev/null 2>&1 &&
    "$BB" tr '\000' '\n' < "/proc/$pid/cmdline" 2>/dev/null | "$BB" grep -Fx __doh_supervisor >/dev/null 2>&1
}

process_doh_supervisor_mark_stop() {
  local exact generic
  exact=$(process_doh_stop_marker_path "$PROCESS_DOH_ROLE" "$PROCESS_DOH_TRANSITION") || return
  generic=$(process_doh_generic_stop_marker_path "$PROCESS_DOH_ROLE") || return
  : > "$exact" 2>/dev/null || true
  : > "$generic" 2>/dev/null || true
  [ -z "${PROCESS_DOH_CHILD_PID-}" ] || kill -TERM "$PROCESS_DOH_CHILD_PID" 2>/dev/null || true
}

process_doh_supervisor_main() {
  [ "$#" -eq 6 ] || return 64
  local slot=$1 transition=$2 config_file=$3 ready_file=$4 process_token=$5 role=$6
  local binary child attempt result=1 reason crash_file exact generic slot_file
  process_doh_slot_valid "$slot" || return
  process_doh_transition_valid "$transition" || return
  [ "$role" = "$(process_doh_role_for_slot "$slot")" ] || return 65
  operation_token_valid "$process_token" || return 65
  rules_init_paths "$MODDIR" || return
  process_doh_config_valid "$config_file" || return
  mkdir -p "$(process_doh_dir)" || return 73
  chmod 700 "$(process_doh_dir)" || return 74
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  binary=$(process_doh_binary_validate) || return
  exact=$(process_doh_stop_marker_path "$role" "$transition") || return
  generic=$(process_doh_generic_stop_marker_path "$role") || return
  rm -f "$exact" "$generic" "$ready_file"

  PROCESS_DOH_ROLE=$role
  PROCESS_DOH_TRANSITION=$transition
  PROCESS_DOH_CHILD_PID=
  export PROCESS_DOH_ROLE PROCESS_DOH_TRANSITION PROCESS_DOH_CHILD_PID
  trap 'process_doh_supervisor_mark_stop' TERM INT

  "$binary" serve --config-fd 3 --ready-fd 4 3<"$config_file" 4>"$ready_file" &
  child=$!
  PROCESS_DOH_CHILD_PID=$child
  export PROCESS_DOH_CHILD_PID
  attempt=0
  while [ "$attempt" -lt 50 ]; do
    if process_identity_capture "$child" && [ "$PROCESS_EXE" = "$binary" ]; then break; fi
    kill -0 "$child" 2>/dev/null || break
    attempt=$((attempt + 1))
    sleep 0.02
  done
  if process_identity_capture "$child" && [ "$PROCESS_EXE" = "$binary" ]; then
    process_doh_child_record_write "$slot" "$transition" "$$" "$child" "$PROCESS_PID_STARTTIME" \
      "$PROCESS_PGID" "$PROCESS_SID" "$PROCESS_CMD_SHA" "$PROCESS_CWD" "$PROCESS_EXE" "$PROCESS_NS" || {
      process_doh_supervisor_mark_stop
    }
  else
    process_doh_supervisor_mark_stop
  fi

  wait "$child"
  result=$?
  trap - TERM INT
  slot_file=$(process_doh_slot_file "$slot") || return 74
  if [ -f "$slot_file" ] && [ ! -L "$slot_file" ] &&
    [ "$(process_doh_slot_transition "$slot" 2>/dev/null || true)" = "$transition" ]; then
    rm -f "$slot_file"
  fi
  if ! process_doh_should_crash "$role" "$transition"; then
    rm -f "$exact" "$generic" "$ready_file"
    return 0
  fi

  [ "$result" -eq 75 ] && reason=upstream_unavailable || reason=companion_exited
  crash_file="$RULE_RUNTIME/doh/crash-$transition.prop"
  {
    printf 'schema_version=1\n'
    printf 'transition_token=%s\n' "$transition"
    printf 'reason=%s\n' "$reason"
  } > "$crash_file.tmp.$$" && chmod 600 "$crash_file.tmp.$$" &&
    atomic_replace_file "$crash_file.tmp.$$" "$crash_file" || rm -f "$crash_file.tmp.$$"
  "$SYSTEM_SH" "$MODDIR/doh_manager.sh" crash "$transition" >/dev/null 2>&1 || true
  rm -f "$ready_file"
  return "$result"
}

process_doh_spawn_supervisor() {
  [ "$#" -eq 6 ] || return 64
  local role=$1 slot=$2 transition=$3 config_file=$4 ready_file=$5 process_token=$6
  PROCESS_MANAGER_INTERNAL=1 "$BB" setsid "$BB" nohup "$SYSTEM_SH" "$MODDIR/process_manager.sh" \
    __doh_supervisor "$slot" "$transition" "$config_file" "$ready_file" "$process_token" "$role" \
    </dev/null >> "$RULE_LOG" 2>&1 &
  PROCESS_DOH_SUPERVISOR_PID=$!
  export PROCESS_DOH_SUPERVISOR_PID
}

process_doh_wait_ready() {
  [ "$#" -eq 4 ] || return 64
  local role=$1 slot=$2 transition=$3 ready_file=$4 attempt=0 result attempts=${PROCESS_DOH_READY_ATTEMPTS:-100}
  decimal_uint_in_range "$attempts" 600 1 || return 65
  while [ "$attempt" -lt "$attempts" ]; do
    process_record_load "$role" 2>/dev/null || return 69
    process_identity_matches_loaded || return 69
    if [ -e "$ready_file" ] || [ -L "$ready_file" ]; then
      process_doh_ready_validate "$ready_file" "$slot" "$transition"
      result=$?
      [ "$result" -eq 0 ] || return "$result"
      process_doh_child_identity_validate "$slot" "$transition" || return 69
      rm -f "$ready_file"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.05
  done
  return 69
}

process_history_ready_file() {
  printf '%s\n' "$RULE_RUNTIME/history/reader-ready.$PROCESS_TOKEN.prop"
}

process_history_reader_ready_validate() {
  local map_token=$1 file map map_sha schema role process_token ready_map ready_sha pid start group expected_exe
  process_history_map_token_valid "$map_token" || return 65
  [ "$PROCESS_STATE" = registered ] && [ "$PROCESS_ROLE" = history-reader ] || return 65
  process_identity_matches_loaded || return 1
  expected_exe=$(process_history_reader_binary) || return
  [ "$PROCESS_RECORDED_EXE" = "$expected_exe" ] || return 65
  file=$(process_history_ready_file)
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  map="$RULE_RUNTIME/history/maps/$map_token.tsv"
  [ -f "$map" ] && [ ! -L "$map" ] || return 66
  map_sha=$(sha256_file "$map") || return
  [ "$(wc -l < "$file" | "$BB" tr -d ' ')" -eq 8 ] || return 65
  IFS='=' read -r key schema < "$file"; [ "$key" = schema_version ] && [ "$schema" = 1 ] || return 65
  role=$(sed -n '2s/^role=//p' "$file"); [ "$role" = history-reader ] || return 65
  process_token=$(sed -n '3s/^process_token=//p' "$file"); [ "$process_token" = "$PROCESS_TOKEN" ] || return 65
  ready_map=$(sed -n '4s/^map_token=//p' "$file"); [ "$ready_map" = "$map_token" ] || return 65
  ready_sha=$(sed -n '5s/^map_sha256=//p' "$file"); [ "$ready_sha" = "$map_sha" ] || return 65
  pid=$(sed -n '6s/^pid=//p' "$file"); [ "$pid" = "$PROCESS_PID" ] || return 65
  start=$(sed -n '7s/^pid_starttime=//p' "$file")
  group=$(sed -n '8s/^nflog_group=//p' "$file")
  [ "$start" = "$PROCESS_START" ] && [ "$group" = 10007 ] || return 65
}

process_history_reader_wait_ready() {
  local map_token=$1 attempt=0
  while [ "$attempt" -le 600 ]; do
    process_record_load history-reader 2>/dev/null || return 69
    process_identity_matches_loaded || return 69
    process_history_reader_ready_validate "$map_token" && return 0
    [ "$attempt" -lt 600 ] || return 69
    attempt=$((attempt + 1))
    sleep 0.1
  done
  return 69
}

process_cmdline_is_launcher() {
  local pid=$1
  "$BB" tr '\000' '\n' < "/proc/$pid/cmdline" 2>/dev/null | "$BB" grep -Fx "$MODDIR/process_manager.sh" >/dev/null 2>&1 &&
    "$BB" tr '\000' '\n' < "/proc/$pid/cmdline" 2>/dev/null | "$BB" grep -Fx __launcher >/dev/null 2>&1
}

process_cmdline_is_history_launcher() {
  local pid=$1
  "$BB" tr '\000' '\n' < "/proc/$pid/cmdline" 2>/dev/null | "$BB" grep -Fx "$MODDIR/process_manager.sh" >/dev/null 2>&1 &&
    "$BB" tr '\000' '\n' < "/proc/$pid/cmdline" 2>/dev/null | "$BB" grep -Fx __history_launcher >/dev/null 2>&1
}

process_cmdline_is_operation_worker() {
  local pid=$1 expected="$MODDIR/operation_worker.sh"
  "$BB" tr '\000' '\n' < "/proc/$pid/cmdline" 2>/dev/null | "$BB" grep -Fx "$expected" >/dev/null 2>&1
}

process_token_allocate() {
  local now counter token
  now=$(date -u +%s 2>/dev/null || date +%s) || return 70
  counter=1
  while :; do
    token="token_${now}_$$_$counter"
    [ ! -e "$RULE_RUNTIME/ready/$token" ] || { counter=$((counter + 1)); continue; }
    printf '%s\n' "$token"
    return 0
  done
}

process_start_managed_locked() {
  local role=$1 token child attempt
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  process_role_valid "$role" || return 64
  [ "$role" != operation-worker ] || return 64
  process_role_capable "$role" || return
  if process_record_load "$role" 2>/dev/null && process_identity_matches_loaded; then
    return 75
  fi
  process_record_remove "$role" || return
  mkdir -p "$RULE_RUNTIME/ready" || return 73
  token=$(process_token_allocate) || return
  process_record_write pending "$token" "$role" 0 0 0 0 - - - - || return
  PROCESS_MANAGER_INTERNAL=1 "$BB" setsid "$BB" nohup "$SYSTEM_SH" "$MODDIR/process_manager.sh" __launcher "$role" "$token" \
    </dev/null >> "$RULE_LOG" 2>&1 &
  child=$!
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if process_cmdline_is_launcher "$child" && process_identity_capture "$child"; then
      break
    fi
    attempt=$((attempt + 1))
    sleep 0.05
  done
  if ! process_cmdline_is_launcher "$child" || ! process_identity_capture "$child"; then
    process_record_remove "$role"
    return 69
  fi
  process_record_write registered "$token" "$role" "$child" "$PROCESS_PID_STARTTIME" \
    "$PROCESS_PGID" "$PROCESS_SID" "$PROCESS_CMD_SHA" "$PROCESS_CWD" "$PROCESS_EXE" "$PROCESS_NS" || {
      process_signal_group TERM "$PROCESS_PGID" 2>/dev/null || true
      process_record_remove "$role"
      return 74
    }
  {
    printf 'token=%s\n' "$token"
    printf 'pid=%s\n' "$child"
    printf 'pid_starttime=%s\n' "$PROCESS_PID_STARTTIME"
  } > "$RULE_RUNTIME/ready/$token.tmp.$$" || {
    process_signal_group TERM "$PROCESS_PGID" 2>/dev/null || true
    process_record_remove "$role"
    return 74
  }
  atomic_replace_file "$RULE_RUNTIME/ready/$token.tmp.$$" "$RULE_RUNTIME/ready/$token"
}

process_start_managed() {
  local role=$1 result
  rules_lock_acquire process || return
  set +e
  process_start_managed_locked "$role"
  result=$?
  set -e
  rules_lock_release process || return
  return "$result"
}

process_start_history_locked() {
  local map_token=$1 token child attempt binary map expected_exe result
  local captured_start captured_pgid captured_sid captured_sha captured_cwd captured_exe captured_ns
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  process_history_map_token_valid "$map_token" || return 65
  process_background_capable || return
  binary=$(process_history_reader_binary) || return
  map="$RULE_RUNTIME/history/maps/$map_token.tsv"
  [ -f "$map" ] && [ ! -L "$map" ] || return 66
  if process_record_load history-reader 2>/dev/null && process_identity_matches_loaded; then return 75; fi
  process_record_remove history-reader || return
  mkdir -p "$RULE_RUNTIME/ready" "$RULE_RUNTIME/history" || return 73
  token=$(process_token_allocate) || return
  rm -f "$RULE_RUNTIME/history/reader-ready.$token.prop" "$RULE_RUNTIME/history/flush.$token.prop" \
    "$RULE_RUNTIME/history/flush-ack.$token.prop"
  process_record_write pending "$token" history-reader 0 0 0 0 - - - - || return
  PROCESS_MANAGER_INTERNAL=1 "$BB" setsid "$BB" nohup "$SYSTEM_SH" "$MODDIR/process_manager.sh" \
    __history_launcher "$map_token" "$token" </dev/null >> "$RULE_LOG" 2>&1 &
  child=$!
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if process_cmdline_is_history_launcher "$child" && process_identity_capture "$child"; then break; fi
    attempt=$((attempt + 1)); sleep 0.05
  done
  if ! process_cmdline_is_history_launcher "$child" || ! process_identity_capture "$child"; then
    process_record_remove history-reader
    return 69
  fi
  captured_start=$PROCESS_PID_STARTTIME; captured_pgid=$PROCESS_PGID; captured_sid=$PROCESS_SID
  captured_sha=$PROCESS_CMD_SHA; captured_cwd=$PROCESS_CWD; captured_exe=$PROCESS_EXE; captured_ns=$PROCESS_NS
  if ! process_record_write registered "$token" history-reader "$child" "$captured_start" \
    "$captured_pgid" "$captured_sid" "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns"; then
    process_stop_captured_identity "$child" "$captured_start" "$captured_pgid" "$captured_sid" \
      "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns" || true
    process_record_remove history-reader
    return 74
  fi
  {
    printf 'token=%s\n' "$token"
    printf 'pid=%s\n' "$child"
    printf 'pid_starttime=%s\n' "$PROCESS_PID_STARTTIME"
  } > "$RULE_RUNTIME/ready/$token.tmp.$$" || {
    process_stop_captured_identity "$child" "$captured_start" "$captured_pgid" "$captured_sid" \
      "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns" || true
    process_record_remove history-reader
    return 74
  }
  if ! atomic_replace_file "$RULE_RUNTIME/ready/$token.tmp.$$" "$RULE_RUNTIME/ready/$token"; then
    process_stop_captured_identity "$child" "$captured_start" "$captured_pgid" "$captured_sid" \
      "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns" || true
    process_record_remove history-reader
    return 74
  fi

  expected_exe=$binary
  attempt=0
  while [ "$attempt" -lt 50 ]; do
    if process_identity_capture "$child" && [ "$PROCESS_EXE" = "$expected_exe" ]; then break; fi
    attempt=$((attempt + 1)); sleep 0.1
  done
  if ! process_identity_capture "$child" || [ "$PROCESS_EXE" != "$expected_exe" ]; then
    if process_identity_capture "$child"; then
      process_stop_captured_identity "$child" "$PROCESS_PID_STARTTIME" "$PROCESS_PGID" "$PROCESS_SID" \
        "$PROCESS_CMD_SHA" "$PROCESS_CWD" "$PROCESS_EXE" "$PROCESS_NS" || true
    else
      process_stop_captured_identity "$child" "$captured_start" "$captured_pgid" "$captured_sid" \
        "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns" || true
    fi
    process_record_remove history-reader
    return 69
  fi
  captured_start=$PROCESS_PID_STARTTIME; captured_pgid=$PROCESS_PGID; captured_sid=$PROCESS_SID
  captured_sha=$PROCESS_CMD_SHA; captured_cwd=$PROCESS_CWD; captured_exe=$PROCESS_EXE; captured_ns=$PROCESS_NS
  if ! process_record_write registered "$token" history-reader "$child" "$captured_start" \
    "$captured_pgid" "$captured_sid" "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns"; then
    process_stop_captured_identity "$child" "$captured_start" "$captured_pgid" "$captured_sid" \
      "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns" || true
    process_record_remove history-reader
    return 74
  fi

  if process_history_reader_wait_ready "$map_token"; then return 0; fi
  set +e
  process_history_flush_stop_locked
  result=$?
  set -e
  [ "$result" -eq 0 ] || [ "$result" -eq 76 ] || true
  return 69
}

process_start_history() {
  local map_token=$1 result
  rules_lock_acquire process || return
  set +e
  process_start_history_locked "$map_token"
  result=$?
  set -e
  rules_lock_release process || return
  return "$result"
}

process_doh_mark_stop() {
  [ "$#" -eq 2 ] || return 64
  local role=$1 transition=$2 exact generic
  mkdir -p "$(process_doh_dir)" || return 73
  generic=$(process_doh_generic_stop_marker_path "$role") || return
  : > "$generic" || return 74
  chmod 600 "$generic" || return 74
  if process_doh_transition_valid "$transition" 2>/dev/null; then
    exact=$(process_doh_stop_marker_path "$role" "$transition") || return
    : > "$exact" || return 74
    chmod 600 "$exact" || return 74
  fi
}

process_start_doh_locked() {
  [ "$#" -eq 3 ] || return 64
  local slot=$1 transition=$2 config_file=$3 role process_token ready_file child attempt result
  local captured_start captured_pgid captured_sid captured_sha captured_cwd captured_exe captured_ns
  process_doh_slot_valid "$slot" || return
  process_doh_transition_valid "$transition" || return
  process_doh_config_valid "$config_file" || return
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  role=$(process_doh_role_for_slot "$slot") || return
  process_background_capable || return
  process_doh_binary_validate >/dev/null || return
  if process_record_load "$role" 2>/dev/null && process_identity_matches_loaded; then return 75; fi
  process_record_remove "$role" || return
  mkdir -p "$(process_doh_dir)" "$RULE_RUNTIME/ready" || return 73
  chmod 700 "$(process_doh_dir)" || return 74
  ready_file=$(process_doh_ready_file "$slot" "$transition") || return
  [ ! -e "$ready_file" ] && [ ! -L "$ready_file" ] || return 76
  process_token=$(process_token_allocate) || return
  process_record_write pending "$process_token" "$role" 0 0 0 0 - - - - || return
  process_doh_spawn_supervisor "$role" "$slot" "$transition" "$config_file" "$ready_file" "$process_token" || {
    result=$?; process_record_remove "$role"; return "$result"
  }
  child=$PROCESS_DOH_SUPERVISOR_PID
  attempt=0
  while [ "$attempt" -lt 60 ]; do
    if process_cmdline_is_doh_supervisor "$child" && process_identity_capture "$child"; then break; fi
    attempt=$((attempt + 1))
    sleep 0.05
  done
  if ! process_cmdline_is_doh_supervisor "$child" || ! process_identity_capture "$child"; then
    process_doh_mark_stop "$role" "$transition" || true
    process_record_remove "$role"
    return 69
  fi
  captured_start=$PROCESS_PID_STARTTIME; captured_pgid=$PROCESS_PGID; captured_sid=$PROCESS_SID
  captured_sha=$PROCESS_CMD_SHA; captured_cwd=$PROCESS_CWD; captured_exe=$PROCESS_EXE; captured_ns=$PROCESS_NS
  if ! process_record_write registered "$process_token" "$role" "$child" "$captured_start" \
    "$captured_pgid" "$captured_sid" "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns"; then
    process_doh_mark_stop "$role" "$transition" || true
    process_stop_captured_identity "$child" "$captured_start" "$captured_pgid" "$captured_sid" \
      "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns" || true
    process_record_remove "$role"
    return 74
  fi
  {
    printf 'token=%s\n' "$process_token"
    printf 'pid=%s\n' "$child"
    printf 'pid_starttime=%s\n' "$captured_start"
  } > "$RULE_RUNTIME/ready/$process_token.tmp.$$" || result=$?
  [ -n "${result-}" ] || atomic_replace_file "$RULE_RUNTIME/ready/$process_token.tmp.$$" "$RULE_RUNTIME/ready/$process_token" || result=$?
  if [ -n "${result-}" ]; then
    process_doh_mark_stop "$role" "$transition" || true
    process_stop_captured_identity "$child" "$captured_start" "$captured_pgid" "$captured_sid" \
      "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns" || true
    process_record_remove "$role"
    rm -f "$RULE_RUNTIME/ready/$process_token.tmp.$$"
    return 74
  fi
  process_doh_wait_ready "$role" "$slot" "$transition" "$ready_file"
  result=$?
  [ "$result" -eq 0 ] && return 0
  process_doh_mark_stop "$role" "$transition" || true
  process_stop_captured_identity "$child" "$captured_start" "$captured_pgid" "$captured_sid" \
    "$captured_sha" "$captured_cwd" "$captured_exe" "$captured_ns" || true
  process_record_remove "$role"
  rm -f "$ready_file" "$RULE_RUNTIME/ready/$process_token"
  return "$result"
}

process_start_doh() {
  [ "$#" -eq 3 ] || return 64
  local slot=$1 result
  case "$slot" in A) slot=a ;; B) slot=b ;; esac
  process_doh_slot_valid "$slot" || return
  rules_lock_acquire process || return
  process_start_doh_locked "$slot" "$2" "$3"
  result=$?
  rules_lock_release process || return
  return "$result"
}

process_stop_doh_locked() {
  [ "$#" -eq 1 ] || return 64
  local slot=$1 role transition=none result file ready
  process_doh_slot_valid "$slot" || return
  role=$(process_doh_role_for_slot "$slot") || return
  if ! process_record_load "$role" 2>/dev/null; then
    rm -f "$(process_doh_slot_file "$slot")" "$(process_doh_generic_stop_marker_path "$role")"
    return 0
  fi
  transition=$(process_doh_slot_transition "$slot" 2>/dev/null || printf 'none')
  process_doh_mark_stop "$role" "$transition" || return
  process_stop_locked "$role"
  result=$?
  [ "$result" -eq 0 ] || return "$result"
  file=$(process_doh_slot_file "$slot") || return
  rm -f "$file" "$(process_doh_generic_stop_marker_path "$role")"
  if process_doh_transition_valid "$transition" 2>/dev/null; then
    rm -f "$(process_doh_stop_marker_path "$role" "$transition")"
    ready=$(process_doh_ready_file "$slot" "$transition") || return
    rm -f "$ready"
  fi
}

process_stop_doh() {
  [ "$#" -eq 1 ] || return 64
  local slot=$1 result
  case "$slot" in A) slot=a ;; B) slot=b ;; esac
  process_doh_slot_valid "$slot" || return
  rules_lock_acquire process || return
  process_stop_doh_locked "$slot"
  result=$?
  rules_lock_release process || return
  return "$result"
}

process_start_operation_locked() {
  local operation_id=$1 token child attempt
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  operation_request_validate_file "$RULE_OPERATIONS/$operation_id/request.prop" "$operation_id" || return
  operation_current_load || return 70
  [ "$CURRENT_OPERATION_ID" = "$operation_id" ] && [ "$CURRENT_OPERATION_STATE" = starting ] || return 76
  process_background_capable || return
  if process_record_load operation-worker 2>/dev/null && process_identity_matches_loaded; then
    return 75
  fi
  process_record_remove operation-worker || return
  mkdir -p "$RULE_RUNTIME/ready" || return 73
  token=$(process_token_allocate) || return
  process_record_write pending "$token" operation-worker 0 0 0 0 - - - - || return
  "$BB" setsid "$BB" nohup "$SYSTEM_SH" "$MODDIR/operation_worker.sh" "$operation_id" "$token" \
    </dev/null >> "$RULE_LOG" 2>&1 &
  child=$!
  attempt=0
  while [ "$attempt" -lt 20 ]; do
    if process_cmdline_is_operation_worker "$child" && process_identity_capture "$child"; then
      break
    fi
    attempt=$((attempt + 1))
    sleep 0.05
  done
  if ! process_cmdline_is_operation_worker "$child" || ! process_identity_capture "$child"; then
    process_record_remove operation-worker
    return 69
  fi
  process_record_write registered "$token" operation-worker "$child" "$PROCESS_PID_STARTTIME" \
    "$PROCESS_PGID" "$PROCESS_SID" "$PROCESS_CMD_SHA" "$PROCESS_CWD" "$PROCESS_EXE" "$PROCESS_NS" || {
      kill -TERM "-$PROCESS_PGID" 2>/dev/null || true
      process_record_remove operation-worker
      return 74
    }
  {
    printf 'token=%s\n' "$token"
    printf 'pid=%s\n' "$child"
    printf 'pid_starttime=%s\n' "$PROCESS_PID_STARTTIME"
  } > "$RULE_RUNTIME/ready/$token.tmp.$$" || return 74
  atomic_replace_file "$RULE_RUNTIME/ready/$token.tmp.$$" "$RULE_RUNTIME/ready/$token"
}

process_start_operation() {
  local operation_id=$1 result
  rules_lock_acquire process || return
  set +e
  process_start_operation_locked "$operation_id"
  result=$?
  set -e
  rules_lock_release process || return
  return "$result"
}

process_stop_locked() {
  local role=$1 attempt
  process_record_load "$role" 2>/dev/null || { process_record_remove "$role"; return 0; }
  if ! process_identity_matches_loaded; then
    process_record_remove "$role"
    return 0
  fi
  process_signal_group TERM "$PROCESS_RECORDED_PGID" 2>/dev/null || true
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    process_identity_matches_loaded || break
    attempt=$((attempt + 1))
    sleep 0.1
  done
  if process_identity_matches_loaded; then
    process_signal_group KILL "$PROCESS_RECORDED_PGID" 2>/dev/null || true
    attempt=0
    while [ "$attempt" -lt 20 ]; do
      process_identity_matches_loaded || break
      attempt=$((attempt + 1))
      sleep 0.1
    done
    process_identity_matches_loaded && return 76
  fi
  process_record_remove "$role"
}

process_history_flush_nonce() {
  printf '%s:%s:%s\n' "$PROCESS_TOKEN" "$$" "$(date +%s 2>/dev/null || printf 0)" | \
    sha256_file_stdin | cut -c1-16
}

process_history_flush_ack_valid() {
  local file=$1 nonce=$2 schema token ack_nonce pid
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  [ "$(wc -l < "$file" | "$BB" tr -d ' ')" -eq 4 ] || return 65
  schema=$(sed -n '1s/^schema_version=//p' "$file")
  token=$(sed -n '2s/^process_token=//p' "$file")
  ack_nonce=$(sed -n '3s/^flush_nonce=//p' "$file")
  pid=$(sed -n '4s/^pid=//p' "$file")
  [ "$schema" = 1 ] && [ "$token" = "$PROCESS_TOKEN" ] && [ "$ack_nonce" = "$nonce" ] && \
    [ "$pid" = "$PROCESS_PID" ] || return 65
}

process_history_flush_stop_locked() {
  local nonce request ack tmp attempt flush_ok=0 request_ready=0 setup_error=0
  process_record_load history-reader 2>/dev/null || { process_record_remove history-reader; return 0; }
  if ! process_identity_matches_loaded; then
    process_record_remove history-reader
    return 0
  fi
  if mkdir -p "$RULE_RUNTIME/history" && nonce=$(process_history_flush_nonce); then
    request="$RULE_RUNTIME/history/flush.$PROCESS_TOKEN.prop"
    ack="$RULE_RUNTIME/history/flush-ack.$PROCESS_TOKEN.prop"
    tmp="$request.tmp.$$"
    rm -f "$ack"
    if {
      printf 'schema_version=1\n'
      printf 'process_token=%s\n' "$PROCESS_TOKEN"
      printf 'flush_nonce=%s\n' "$nonce"
    } > "$tmp" && atomic_replace_file "$tmp" "$request"; then
      request_ready=1
    else
      setup_error=1
      rm -f "$tmp"
    fi
  else
    setup_error=1
  fi
  if [ "$request_ready" -eq 1 ] && process_identity_matches_loaded; then
    kill -USR1 "$PROCESS_PID" 2>/dev/null || true
    attempt=0
    while [ "$attempt" -lt 20 ]; do
      if process_history_flush_ack_valid "$ack" "$nonce" 2>/dev/null; then flush_ok=1; break; fi
      attempt=$((attempt + 1)); sleep 0.1
    done
  fi
  if process_identity_matches_loaded; then
    process_signal_group TERM "$PROCESS_RECORDED_PGID" 2>/dev/null || true
    attempt=0
    while [ "$attempt" -lt 30 ]; do
      process_identity_matches_loaded || break
      attempt=$((attempt + 1)); sleep 0.1
    done
  fi
  if process_identity_matches_loaded; then
    process_signal_group KILL "$PROCESS_RECORDED_PGID" 2>/dev/null || true
    attempt=0
    while [ "$attempt" -lt 20 ]; do
      process_identity_matches_loaded || break
      attempt=$((attempt + 1)); sleep 0.1
    done
  fi
  if process_identity_matches_loaded; then return 76; fi
  process_record_remove history-reader || return
  [ -z "${request-}" ] || rm -f "$request"
  [ -z "${ack-}" ] || rm -f "$ack"
  rm -f "$RULE_RUNTIME/history/reader-ready.$PROCESS_TOKEN.prop"
  [ "$flush_ok" -eq 1 ] && [ "$setup_error" -eq 0 ] || return 76
}

process_history_flush_stop() {
  local result
  rules_lock_acquire process || return
  set +e
  process_history_flush_stop_locked
  result=$?
  set -e
  rules_lock_release process || return
  return "$result"
}

process_stop() {
  local role=$1 result
  process_role_valid "$role" || return 64
  case "$role" in
    doh-proxy-a) process_stop_doh a; return ;;
    doh-proxy-b) process_stop_doh b; return ;;
  esac
  rules_lock_acquire process || return
  set +e
  process_stop_locked "$role"
  result=$?
  set -e
  rules_lock_release process || return
  return "$result"
}

process_stop_all_locked() {
  local role failures=0
  process_stop_doh_locked a || failures=$((failures + 1))
  process_stop_doh_locked b || failures=$((failures + 1))
  process_history_flush_stop_locked || failures=$((failures + 1))
  for role in history-reconcile crond
  do
    process_stop_locked "$role" || failures=$((failures + 1))
  done
  [ "$failures" -eq 0 ] || return 76
}

process_stop_all() {
  local result
  rules_lock_acquire process || return
  set +e
  process_stop_all_locked
  result=$?
  set -e
  rules_lock_release process || return
  return "$result"
}

process_status_json() {
  local role first=1 slot slots= slot_first=1
  printf '{"schemaVersion":1,"processes":['
  while IFS= read -r role; do
    case "$role" in doh-proxy-a|doh-proxy-b) continue ;; esac
    if process_record_load "$role" 2>/dev/null && process_identity_matches_loaded; then
      [ "$first" -eq 1 ] || printf ','
      printf '{"role":"%s","pid":%s,"state":"running"}' "$role" "$PROCESS_PID"
      first=0
    fi
  done <<EOF
$(process_known_roles)
EOF
  for slot in a b; do
    role=$(process_doh_role_for_slot "$slot") || continue
    if process_record_load "$role" 2>/dev/null && process_identity_matches_loaded; then
      [ "$slot_first" -eq 1 ] || slots="$slots,"
      slots="$slots\"$slot\""
      slot_first=0
    fi
  done
  if [ "$slot_first" -eq 0 ]; then
    [ "$first" -eq 1 ] || printf ','
    printf '{"role":"doh-proxy","state":"running","slots":[%s]}' "$slots"
  fi
  printf ']}\n'
}

process_dispatch() {
  case "${1-}" in
    start-operation) [ "$#" -eq 2 ] || return 64; operation_id_valid "$2" || return 65; process_start_operation "$2" ;;
    start) [ "$#" -eq 2 ] || return 64; process_start_role_valid "$2" || return 64; process_start_managed "$2" ;;
    start-doh) [ "$#" -eq 4 ] || return 64; process_start_doh "$2" "$3" "$4" ;;
    stop-doh) [ "$#" -eq 2 ] || return 64; process_stop_doh "$2" ;;
    start-ready)
      [ "$#" -eq 3 ] && [ "$2" = history-reader ] || return 64
      process_history_map_token_valid "$3" || return 65
      process_start_history "$3"
      ;;
    stop)
      [ "$#" -eq 2 ] || return 64
      [ "$2" != history-reader ] || return 64
      process_stop "$2"
      ;;
    flush-stop) [ "$#" -eq 2 ] && [ "$2" = history-reader ] || return 64; process_history_flush_stop ;;
    stop-all) [ "$#" -eq 1 ] || return 64; process_stop_all ;;
    status) [ "$#" -eq 2 ] && [ "$2" = --json ] || return 64; process_status_json ;;
    __launcher)
      [ "$#" -eq 3 ] && [ "${PROCESS_MANAGER_INTERNAL-0}" = 1 ] || return 64
      process_launcher_main "$2" "$3"
      ;;
    __history_launcher)
      [ "$#" -eq 3 ] && [ "${PROCESS_MANAGER_INTERNAL-0}" = 1 ] || return 64
      process_history_launcher_main "$2" "$3"
      ;;
    __doh_supervisor)
      [ "$#" -eq 7 ] && [ "${PROCESS_MANAGER_INTERNAL-0}" = 1 ] || return 64
      process_doh_supervisor_main "$2" "$3" "$4" "$5" "$6" "$7"
      ;;
    *) return 64 ;;
  esac
}

if [ "${PROCESS_MANAGER_SOURCE_ONLY-0}" != 1 ]; then
  rules_init_paths "$MODDIR" || exit $?
  process_dispatch "$@"
fi
