#!/system/bin/sh

mount_manifest_value() {
  local file=$1 key=$2
  [ -f "$file" ] || return 66
  "$BB" awk -F= -v wanted="$key" '$1==wanted{print $2}' "$file"
}

active_validate_v1() {
  local file=${1:-$RULE_RUNTIME/active.prop}
  [ -f "$file" ] || return 66
  "$BB" awk -F= '
    NF != 2 { exit 65 }
    $1 !~ /^(schema_version|active_generation|alternate_generation|alternate_action|applied_sources_revision|config_snapshot_sha256|active_mode|active_hosts_sha256)$/ { exit 65 }
    seen[$1]++ { exit 65 }
    $1=="schema_version" && $2!="1" { exit 65 }
    $1=="active_generation" && $2!~/^g[0-9]+-r[0-9]+-p[0-9]+$/ && $2!~/^g[0-9]+$/ { exit 65 }
    $1=="alternate_generation" && $2!="" && $2!~/^g[0-9]+-r[0-9]+-p[0-9]+$/ && $2!~/^g[0-9]+$/ { exit 65 }
    $1=="alternate_action" && $2!~/^(rollback|redo|none)$/ { exit 65 }
    $1=="applied_sources_revision" && $2!~/^[0-9]+$/ { exit 65 }
    $1=="config_snapshot_sha256" && (length($2)!=64 || $2!~/^[0-9a-f]+$/) { exit 65 }
    $1=="active_mode" && $2!~/^(block_all|preserve_reward|paused)$/ { exit 65 }
    $1=="active_hosts_sha256" && (length($2)!=64 || $2!~/^[0-9a-f]+$/) { exit 65 }
    END { if (NR!=8) exit 65 }
  ' "$file"
}

active_validate_v2() {
  local file=${1:-$RULE_RUNTIME/active.prop}
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    NF != 2 {bad()}
    $1 !~ /^(schema_version|active_generation|alternate_generation|alternate_action|applied_sources_revision|config_snapshot_sha256|active_mode|active_hosts_sha256|active_mount_kind|active_map_token|active_trace_sha256)$/ {bad()}
    seen[$1]++ {bad()}
    $1=="schema_version" && $2!="2" {bad()}
    $1=="active_generation" && $2!~/^g[0-9]+-r[0-9]+-p[0-9]+$/ && $2!~/^g[0-9]+$/ {bad()}
    $1=="alternate_generation" && $2!="" && $2!~/^g[0-9]+-r[0-9]+-p[0-9]+$/ && $2!~/^g[0-9]+$/ {bad()}
    $1=="alternate_action" && $2!~/^(rollback|redo|none)$/ {bad()}
    $1=="applied_sources_revision" && $2!~/^[0-9]+$/ {bad()}
    $1=="config_snapshot_sha256" && (length($2)!=64 || $2!~/^[0-9a-f]+$/) {bad()}
    $1=="active_mode" && $2!~/^(block_all|preserve_reward|paused)$/ {bad()}
    $1=="active_hosts_sha256" && (length($2)!=64 || $2!~/^[0-9a-f]+$/) {bad()}
    $1=="active_mount_kind" && $2!~/^(normal|trace)$/ {bad()}
    END {
      if(NR!=11) bad()
      if(!seen["active_mount_kind"] || !seen["active_map_token"] || !seen["active_trace_sha256"]) bad()
      if(value){}
    }
  ' "$file" || return
  local kind token trace hosts mode
  kind=$($BB awk -F= '$1=="active_mount_kind"{print $2}' "$file")
  token=$($BB awk -F= '$1=="active_map_token"{print $2}' "$file")
  trace=$($BB awk -F= '$1=="active_trace_sha256"{print $2}' "$file")
  hosts=$($BB awk -F= '$1=="active_hosts_sha256"{print $2}' "$file")
  mode=$($BB awk -F= '$1=="active_mode"{print $2}' "$file")
  if [ "$kind" = normal ]; then
    [ -z "$token" ] && [ -z "$trace" ] || return 65
  else
    [ "${#token}" -eq 16 ] || return 65
    case "$token" in *[!0-9a-f]*) return 65 ;; esac
    [ "${#trace}" -eq 64 ] || return 65
    case "$trace" in *[!0-9a-f]*) return 65 ;; esac
    [ "$hosts" = "$trace" ] || return 65
  fi
  if [ "$mode" = paused ]; then
    [ "$kind" = normal ] || return 65
  fi
}

active_validate() {
  local file=${1:-$RULE_RUNTIME/active.prop} schema
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  schema=$($BB awk -F= '$1=="schema_version"{print $2}' "$file")
  case "$schema" in 1) active_validate_v1 "$file" ;; 2) active_validate_v2 "$file" ;; *) return 65 ;; esac
}

active_migrate_v1() {
  local file=${1:-$RULE_RUNTIME/active.prop} schema active alternate action revision config mode hosts tmp
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  schema=$($BB awk -F= '$1=="schema_version"{print $2}' "$file")
  [ "$schema" = 1 ] || { [ "$schema" = 2 ] && active_validate_v2 "$file"; return; }
  active_validate_v1 "$file" || return
  active=$($BB awk -F= '$1=="active_generation"{print $2}' "$file")
  alternate=$($BB awk -F= '$1=="alternate_generation"{print $2}' "$file")
  action=$($BB awk -F= '$1=="alternate_action"{print $2}' "$file")
  revision=$($BB awk -F= '$1=="applied_sources_revision"{print $2}' "$file")
  config=$($BB awk -F= '$1=="config_snapshot_sha256"{print $2}' "$file")
  mode=$($BB awk -F= '$1=="active_mode"{print $2}' "$file")
  hosts=$($BB awk -F= '$1=="active_hosts_sha256"{print $2}' "$file")
  active_write_values "$active" "$alternate" "$action" "$revision" "$config" "$mode" "$hosts"
}

active_value() {
  local key=$1 file=${2:-$RULE_RUNTIME/active.prop}
  active_migrate_v1 "$file" || return
  active_validate "$file" || return
  "$BB" awk -F= -v wanted="$key" '$1==wanted{print $2}' "$file"
}

generation_id_valid() {
  local value=$1 rest epoch tail revision pid
  case "$value" in g*) rest=${value#g} ;; *) return 1 ;; esac
  case "$rest" in
    *-r*-p*)
      epoch=${rest%%-r*}
      tail=${rest#*-r}
      revision=${tail%%-p*}
      pid=${tail#*-p}
      [ "$value" = "g$epoch-r$revision-p$pid" ] || return 1
      case "$epoch:$revision:$pid" in *[!0-9:]*) return 1 ;; esac
      [ -n "$epoch" ] && [ -n "$revision" ] && [ -n "$pid" ]
      ;;
    *)
      case "$rest" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
      ;;
  esac
}

mount_target_valid() {
  case "$1" in /system/etc/hosts|/system/system/etc/hosts) return 0 ;; *) return 1 ;; esac
}

generation_source_validate() {
  local source=$1 generation=$2 kind=$3 expected key actual
  generation_id_valid "$generation" || return 65
  case "$kind" in
    generation_all) key=all_sha256; expected="$RULE_GENERATIONS/$generation/all" ;;
    generation_reward) key=reward_sha256; expected="$RULE_GENERATIONS/$generation/reward" ;;
    generation_recovery) key=recovery_sha256; expected="$RULE_GENERATIONS/$generation/recovery" ;;
    *) return 65 ;;
  esac
  [ "$source" = "$expected" ] && [ -f "$source" ] && [ ! -L "$source" ] || return 65
  [ -f "$RULE_GENERATIONS/$generation/manifest.prop" ] || return 66
  actual=$(sha256_file "$source") || return
  expected=$(mount_manifest_value "$RULE_GENERATIONS/$generation/manifest.prop" "$key") || return
  [ "$actual" = "$expected" ] || return 70
}

trace_source_validate() {
  local source=$1 generation=$2 kind=$3 token=$4 trace_hash=$5 suffix mode manifest expected actual value fields
  generation_id_valid "$generation" || return 65
  [ "${#token}" -eq 16 ] || return 65
  case "$token" in *[!0-9a-f]*) return 65 ;; esac
  [ "${#trace_hash}" -eq 64 ] || return 65
  case "$trace_hash" in *[!0-9a-f]*) return 65 ;; esac
  case "$kind" in trace_all) suffix=all; mode=block_all ;; trace_reward) suffix=reward; mode=preserve_reward ;; *) return 65 ;; esac
  expected="$RULE_RUNTIME/history/traces/$token/$suffix"
  [ "$source" = "$expected" ] && [ -f "$source" ] && [ ! -L "$source" ] || return 65
  [ -d "$RULE_RUNTIME/history" ] && [ ! -L "$RULE_RUNTIME/history" ] || return 65
  [ -d "$RULE_RUNTIME/history/traces" ] && [ ! -L "$RULE_RUNTIME/history/traces" ] || return 65
  [ -d "$RULE_RUNTIME/history/traces/$token" ] && [ ! -L "$RULE_RUNTIME/history/traces/$token" ] || return 65
  [ -f "$RULE_RUNTIME/history/maps/$token.tsv" ] && [ ! -L "$RULE_RUNTIME/history/maps/$token.tsv" ] || return 65
  manifest="$RULE_RUNTIME/history/traces/$token/manifest.prop"
  [ -f "$manifest" ] && [ ! -L "$manifest" ] || return 65
  fields=$($BB awk -F= 'NF!=2{exit 65} $1!~/^(schema_version|map_token|generation_id|mode|source_kind|source_sha256|map_sha256|hosts_sha256|rule_count)$/{exit 65} seen[$1]++{exit 65} END{print NR}' "$manifest") || return 65
  [ "$fields" -eq 9 ] || return 65
  for pair in "schema_version:1" "map_token:$token" "generation_id:$generation" "mode:$mode" "source_kind:$suffix"; do
    value=$($BB awk -F= -v wanted="${pair%%:*}" '$1==wanted{print $2}' "$manifest")
    [ "$value" = "${pair#*:}" ] || return 65
  done
  expected=$($BB awk -F= '$1=="hosts_sha256"{print $2}' "$manifest")
  [ "$expected" = "$trace_hash" ] || return 70
  actual=$(sha256_file "$source") || return
  [ "$actual" = "$expected" ] || return 70
  expected=$($BB awk -F= '$1=="map_sha256"{print $2}' "$manifest")
  actual=$(sha256_file "$RULE_RUNTIME/history/maps/$token.tsv") || return
  [ "$actual" = "$expected" ] || return 70
}

mount_source_tuple_validate() {
  local source=$1 generation=$2 kind=$3 token=${4-} trace_hash=${5-}
  case "$kind" in
    generation_all|generation_reward|generation_recovery)
      case "$token:$trace_hash" in :|-:-) ;; *) return 65 ;; esac
      generation_source_validate "$source" "$generation" "$kind"
      ;;
    trace_all|trace_reward)
      trace_source_validate "$source" "$generation" "$kind" "$token" "$trace_hash"
      ;;
    *) return 65 ;;
  esac
}

detect_system_hosts_target() {
  local candidate
  for candidate in /system/etc/hosts /system/system/etc/hosts; do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then
      SYSTEM_HOSTS_TARGET=$candidate
      export SYSTEM_HOSTS_TARGET
      return 0
    fi
  done
  return 66
}

mount_ns_inode() {
  "$BB" readlink "/proc/$1/ns/mnt"
}

mount_pid_starttime() {
  proc_starttime "$1"
}

mount_find_representative() {
  local ns=$1 recorded_pid=$2 recorded_start=$3 proc_root candidate candidate_ns candidate_start stat_line after_comm
  proc_root=${MOUNT_PROC_ROOT:-/proc}
  case "$ns" in mnt:\[[0-9]*\]) ;; *) return 65 ;; esac
  case "$recorded_pid" in ''|*[!0-9]*) return 65 ;; esac
  case "$recorded_start" in ''|*[!0-9]*) return 65 ;; esac

  candidate_ns=$("$BB" readlink "$proc_root/$recorded_pid/ns/mnt" 2>/dev/null || true)
  stat_line=$(cat "$proc_root/$recorded_pid/stat" 2>/dev/null || true)
  after_comm=${stat_line##*) }
  candidate_start=$(printf '%s\n' "$after_comm" | "$BB" awk '{print $20}' 2>/dev/null || true)
  if [ "$candidate_ns" = "$ns" ] && [ "$candidate_start" = "$recorded_start" ]; then
    printf '%s\n' "$recorded_pid"
    return 0
  fi

  for candidate in "$proc_root"/[0-9]*; do
    [ -d "$candidate" ] || continue
    candidate=${candidate##*/}
    [ "$candidate" != "$recorded_pid" ] || continue
    candidate_ns=$("$BB" readlink "$proc_root/$candidate/ns/mnt" 2>/dev/null || true)
    [ "$candidate_ns" = "$ns" ] || continue
    printf '%s\n' "$candidate"
    return 0
  done
  return 1
}

mount_top_id() {
  local pid=$1 target=$2
  "$BB" awk -v wanted="$target" '$5==wanted{id=$1} END{print id}' "/proc/$pid/mountinfo" 2>/dev/null
}

mount_source_devino() {
  "$BB" stat -c '%d:%i' "$1"
}

mount_target_devino() {
  local pid=$1 target=$2
  "$BB" stat -c '%d:%i' "/proc/$pid/root$target"
}

mount_target_sha() {
  local pid=$1 target=$2
  "$BB" sha256sum "/proc/$pid/root$target" | "$BB" awk '{print tolower($1)}'
}

mount_backend_bind() {
  local pid=$1 source=$2 target=$3
  "$BB" nsenter -t "$pid" -m -- "$BB" mount --bind "$source" "$target"
}

mount_backend_umount() {
  local pid=$1 target=$2
  "$BB" nsenter -t "$pid" -m -- "$BB" umount "$target"
}

mount_compensate_bound() {
  local pid=$1 target=$2 post_id=$3 source_dev=$4 current current_dev
  [ -n "$post_id" ] || return 76
  current=$(mount_top_id "$pid" "$target" 2>/dev/null || true)
  current_dev=$(mount_target_devino "$pid" "$target" 2>/dev/null || true)
  [ "$current" = "$post_id" ] && [ "$current_dev" = "$source_dev" ] || return 76
  mount_backend_umount "$pid" "$target" || return 76
  current=$(mount_top_id "$pid" "$target" 2>/dev/null || true)
  [ "$current" != "$post_id" ] || return 76
  mount_record_remove "$pid" "$target" || return 76
}

mount_record_file() {
  printf '%s\n' "$RULE_RUNTIME/mounts.tsv"
}

mount_record_find() {
  local pid=$1 target=$2 ns file
  ns=$(mount_ns_inode "$pid") || return
  file=$(mount_record_file)
  [ -f "$file" ] || return 1
  "$BB" awk -F '\t' -v ns="$ns" -v target="$target" '$2==ns && $5==target{line=$0} END{if(line!="")print line; else exit 1}' "$file"
}

mount_record_remove() {
  local pid=$1 target=$2 ns file tmp
  ns=$(mount_ns_inode "$pid") || return
  file=$(mount_record_file)
  [ -f "$file" ] || return 0
  tmp="$file.tmp.$$"
  "$BB" awk -F '\t' -v ns="$ns" -v target="$target" '!($2==ns && $5==target){print}' "$file" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$file"
}

mount_record_write() {
  local state=$1 pid=$2 target=$3 source=$4 generation=$5 kind=$6 pre_id=${7-} post_id=${8-} token=${9-} trace_hash=${10-}
  local ns start source_sha source_dev target_dev file tmp inherited_id inherited_dev
  mount_target_valid "$target" || return 65
  mount_source_tuple_validate "$source" "$generation" "$kind" "$token" "$trace_hash" || return
  [ -n "$token" ] || token=-
  [ -n "$trace_hash" ] || trace_hash=-
  ns=$(mount_ns_inode "$pid") || return 70
  start=$(mount_pid_starttime "$pid") || return 70
  source_sha=$(sha256_file "$source") || return
  source_dev=$(mount_source_devino "$source") || return
  target_dev=$(mount_target_devino "$pid" "$target" 2>/dev/null || printf '-')
  inherited_id=-
  inherited_dev=-
  file=$(mount_record_file)
  tmp="$file.tmp.$$"
  mkdir -p "${file%/*}" || return 73
  if [ -f "$file" ]; then
    "$BB" awk -F '\t' -v ns="$ns" -v target="$target" '!($2==ns && $5==target){print}' "$file" > "$tmp" || return 74
  else
    : > "$tmp"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$state" "$ns" "$pid" "$start" "$target" "$kind" "$source" "$generation" "$source_sha" \
    "${pre_id:--}" "${post_id:--}" "$source_dev" "$target_dev" "$inherited_id" "$inherited_dev" "$token" "$trace_hash" >> "$tmp" || return 74
  atomic_replace_file "$tmp" "$file"
}

mount_record_field() {
  local line=$1 field=$2
  printf '%s\n' "$line" | "$BB" awk -F '\t' -v field="$field" '{print $field}'
}

mount_existing_owned() {
  local pid=$1 target=$2 record current post source source_dev current_dev fields generation kind token trace_hash
  record=$(mount_record_find "$pid" "$target" 2>/dev/null || true)
  [ -n "$record" ] || return 1
  [ "$(mount_record_field "$record" 1)" = committed ] || return 1
  fields=$(printf '%s\n' "$record" | "$BB" awk -F '\t' '{print NF}')
  [ "$fields" -eq 15 ] || [ "$fields" -eq 17 ] || return 1
  current=$(mount_top_id "$pid" "$target")
  post=$(mount_record_field "$record" 11)
  source=$(mount_record_field "$record" 7)
  source_dev=$(mount_record_field "$record" 12)
  generation=$(mount_record_field "$record" 8)
  kind=$(mount_record_field "$record" 6)
  if [ "$fields" -eq 17 ]; then token=$(mount_record_field "$record" 16); trace_hash=$(mount_record_field "$record" 17); else token=-; trace_hash=-; fi
  mount_source_tuple_validate "$source" "$generation" "$kind" "$token" "$trace_hash" || return 1
  current_dev=$(mount_target_devino "$pid" "$target" 2>/dev/null || true)
  [ "$current" = "$post" ] && [ "$current_dev" = "$source_dev" ] && [ -f "$source" ]
}

mount_apply() {
  local pid=$1 source=$2 generation=$3 kind=$4 token=${5-} trace_hash=${6-} target pre_id post_id expected actual existing source_dev result
  mount_source_tuple_validate "$source" "$generation" "$kind" "$token" "$trace_hash" || return
  source_dev=$(mount_source_devino "$source") || return
  detect_system_hosts_target || return
  target=$SYSTEM_HOSTS_TARGET
  pre_id=$(mount_top_id "$pid" "$target" 2>/dev/null || true)
  existing=$(mount_record_find "$pid" "$target" 2>/dev/null || true)
  if [ -n "$pre_id" ]; then
    if [ -n "$existing" ] && mount_existing_owned "$pid" "$target"; then
      mount_backend_umount "$pid" "$target" || return 74
      pre_id=$(mount_top_id "$pid" "$target" 2>/dev/null || true)
    else
      return 76
    fi
  fi

  mount_record_write pending "$pid" "$target" "$source" "$generation" "$kind" "$pre_id" '' "$token" "$trace_hash" || return
  if ! mount_backend_bind "$pid" "$source" "$target"; then
    mount_record_remove "$pid" "$target"
    return 74
  fi
  post_id=$(mount_top_id "$pid" "$target" 2>/dev/null || true)
  expected=$(sha256_file "$source") || {
    result=$?
    mount_compensate_bound "$pid" "$target" "$post_id" "$source_dev" || return 76
    return "$result"
  }
  actual=$(mount_target_sha "$pid" "$target" 2>/dev/null || true)
  if [ -z "$post_id" ] || [ "$actual" != "$expected" ]; then
    mount_compensate_bound "$pid" "$target" "$post_id" "$source_dev" || return 76
    return 74
  fi
  mount_record_write committed "$pid" "$target" "$source" "$generation" "$kind" "$pre_id" "$post_id" "$token" "$trace_hash" || {
    result=$?
    mount_compensate_bound "$pid" "$target" "$post_id" "$source_dev" || return 76
    return "$result"
  }
}

mount_pid1() {
  mount_apply 1 "$@"
}

mount_trace_for_mode() {
  local generation=$1 mode=$2 token=$3 manifest suffix
  case "$mode" in block_all) suffix=all; MOUNT_KIND=trace_all ;; preserve_reward) suffix=reward; MOUNT_KIND=trace_reward ;; *) return 65 ;; esac
  MOUNT_SOURCE="$RULE_RUNTIME/history/traces/$token/$suffix"
  manifest="$RULE_RUNTIME/history/traces/$token/manifest.prop"
  [ -f "$manifest" ] || return 66
  MOUNT_TRACE_SHA=$($BB awk -F= '$1=="hosts_sha256"{print $2}' "$manifest")
  trace_source_validate "$MOUNT_SOURCE" "$generation" "$MOUNT_KIND" "$token" "$MOUNT_TRACE_SHA" || return
  MOUNT_MAP_TOKEN=$token
  export MOUNT_SOURCE MOUNT_KIND MOUNT_TRACE_SHA MOUNT_MAP_TOKEN
}

active_tuple_load() {
  ACTIVE_TUPLE_GENERATION=$(active_value active_generation) || return
  ACTIVE_TUPLE_ALTERNATE=$(active_value alternate_generation) || return
  ACTIVE_TUPLE_ACTION=$(active_value alternate_action) || return
  ACTIVE_TUPLE_REVISION=$(active_value applied_sources_revision) || return
  ACTIVE_TUPLE_CONFIG_HASH=$(active_value config_snapshot_sha256) || return
  ACTIVE_TUPLE_MODE=$(active_value active_mode) || return
  ACTIVE_TUPLE_HOSTS_HASH=$(active_value active_hosts_sha256) || return
  ACTIVE_TUPLE_MOUNT_KIND=$(active_value active_mount_kind) || return
  ACTIVE_TUPLE_MAP_TOKEN=$(active_value active_map_token) || return
  ACTIVE_TUPLE_TRACE_HASH=$(active_value active_trace_sha256) || return
  export ACTIVE_TUPLE_GENERATION ACTIVE_TUPLE_ALTERNATE ACTIVE_TUPLE_ACTION ACTIVE_TUPLE_REVISION
  export ACTIVE_TUPLE_CONFIG_HASH ACTIVE_TUPLE_MODE ACTIVE_TUPLE_HOSTS_HASH ACTIVE_TUPLE_MOUNT_KIND
  export ACTIVE_TUPLE_MAP_TOKEN ACTIVE_TUPLE_TRACE_HASH
}

active_tuple_readonly() {
  local file=${1:-$RULE_RUNTIME/active.prop} tuple marker
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  tuple=$($BB awk -F= -v OFS='|' '
    function bad() { exit 65 }
    NF != 2 { bad() }
    $1 !~ /^(schema_version|active_generation|alternate_generation|alternate_action|applied_sources_revision|config_snapshot_sha256|active_mode|active_hosts_sha256|active_mount_kind|active_map_token|active_trace_sha256)$/ { bad() }
    seen[$1]++ { bad() }
    { value[$1]=$2 }
    END {
      schema=value["schema_version"]
      if (schema != "1" && schema != "2") bad()
      if (value["active_generation"] !~ /^g[0-9]+-r[0-9]+-p[0-9]+$/ && value["active_generation"] !~ /^g[0-9]+$/) bad()
      if (value["alternate_generation"] != "" && value["alternate_generation"] !~ /^g[0-9]+-r[0-9]+-p[0-9]+$/ && value["alternate_generation"] !~ /^g[0-9]+$/) bad()
      if (value["alternate_action"] !~ /^(rollback|redo|none)$/) bad()
      if (value["applied_sources_revision"] !~ /^[0-9]+$/) bad()
      if (length(value["config_snapshot_sha256"]) != 64 || value["config_snapshot_sha256"] !~ /^[0-9a-f]+$/) bad()
      if (value["active_mode"] !~ /^(block_all|preserve_reward|paused)$/) bad()
      if (length(value["active_hosts_sha256"]) != 64 || value["active_hosts_sha256"] !~ /^[0-9a-f]+$/) bad()
      if (schema == "1") {
        if (NR != 8 || seen["active_mount_kind"] || seen["active_map_token"] || seen["active_trace_sha256"]) bad()
        kind="normal"
        token=""
        trace=""
      } else {
        if (NR != 11 || !seen["active_mount_kind"] || !seen["active_map_token"] || !seen["active_trace_sha256"]) bad()
        kind=value["active_mount_kind"]
        token=value["active_map_token"]
        trace=value["active_trace_sha256"]
        if (kind !~ /^(normal|trace)$/) bad()
        if (kind == "normal" && (token != "" || trace != "")) bad()
        if (kind == "trace") {
          if (length(token) != 16 || token !~ /^[0-9a-f]+$/) bad()
          if (length(trace) != 64 || trace !~ /^[0-9a-f]+$/) bad()
          if (value["active_hosts_sha256"] != trace) bad()
        }
        if (value["active_mode"] == "paused" && kind != "normal") bad()
      }
      print value["active_generation"], value["alternate_generation"], value["alternate_action"],
        value["applied_sources_revision"], value["config_snapshot_sha256"], value["active_mode"],
        value["active_hosts_sha256"], kind, token, trace, "end"
    }
  ' "$file") || return
  IFS='|' read -r ACTIVE_TUPLE_GENERATION ACTIVE_TUPLE_ALTERNATE ACTIVE_TUPLE_ACTION \
    ACTIVE_TUPLE_REVISION ACTIVE_TUPLE_CONFIG_HASH ACTIVE_TUPLE_MODE ACTIVE_TUPLE_HOSTS_HASH \
    ACTIVE_TUPLE_MOUNT_KIND ACTIVE_TUPLE_MAP_TOKEN ACTIVE_TUPLE_TRACE_HASH marker <<EOF
$tuple
EOF
  [ "$marker" = end ] || return 65
  export ACTIVE_TUPLE_GENERATION ACTIVE_TUPLE_ALTERNATE ACTIVE_TUPLE_ACTION ACTIVE_TUPLE_REVISION
  export ACTIVE_TUPLE_CONFIG_HASH ACTIVE_TUPLE_MODE ACTIVE_TUPLE_HOSTS_HASH ACTIVE_TUPLE_MOUNT_KIND
  export ACTIVE_TUPLE_MAP_TOKEN ACTIVE_TUPLE_TRACE_HASH
}

active_tuple_mount_matches_loaded() {
  local target record fields generation kind source token trace
  detect_system_hosts_target || return
  target=$SYSTEM_HOSTS_TARGET
  mount_existing_owned 1 "$target" || return 76
  record=$(mount_record_find 1 "$target") || return 76
  fields=$(printf '%s\n' "$record" | "$BB" awk -F '\t' '{print NF}')
  generation=$(mount_record_field "$record" 8)
  kind=$(mount_record_field "$record" 6)
  source=$(mount_record_field "$record" 7)
  token=-
  trace=-
  if [ "$fields" -eq 17 ]; then
    token=$(mount_record_field "$record" 16)
    trace=$(mount_record_field "$record" 17)
  fi
  [ "$generation" = "$ACTIVE_TUPLE_GENERATION" ] || return 76
  [ "$(sha256_file "$source")" = "$ACTIVE_TUPLE_HOSTS_HASH" ] || return 76
  case "$ACTIVE_TUPLE_MOUNT_KIND:$ACTIVE_TUPLE_MODE:$kind:$token:$trace" in
    normal:block_all:generation_all:-:-|normal:preserve_reward:generation_reward:-:-|normal:paused:generation_recovery:-:-) ;;
    trace:block_all:trace_all:"$ACTIVE_TUPLE_MAP_TOKEN":"$ACTIVE_TUPLE_TRACE_HASH"|trace:preserve_reward:trace_reward:"$ACTIVE_TUPLE_MAP_TOKEN":"$ACTIVE_TUPLE_TRACE_HASH") ;;
    *) return 76 ;;
  esac
}

active_tuple_mount_loaded() {
  if [ "$ACTIVE_TUPLE_MOUNT_KIND" = trace ]; then
    mount_trace_for_mode "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_MODE" "$ACTIVE_TUPLE_MAP_TOKEN" || return
    mount_pid1 "$MOUNT_SOURCE" "$ACTIVE_TUPLE_GENERATION" "$MOUNT_KIND" \
      "$ACTIVE_TUPLE_MAP_TOKEN" "$ACTIVE_TUPLE_TRACE_HASH"
  else
    mount_generation_for_mode "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_MODE" || return
    mount_pid1 "$MOUNT_SOURCE" "$ACTIVE_TUPLE_GENERATION" "$MOUNT_KIND"
  fi
}

engine_history_mount_trace_locked() {
  local token=$1 result
  active_tuple_load || return
  [ "$ACTIVE_TUPLE_MODE" != paused ] || return 75
  [ "$ACTIVE_TUPLE_MOUNT_KIND" = normal ] || return 76
  mount_trace_for_mode "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_MODE" "$token" || return
  mount_pid1 "$MOUNT_SOURCE" "$ACTIVE_TUPLE_GENERATION" "$MOUNT_KIND" "$token" "$MOUNT_TRACE_SHA" || return
  active_write_values "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_ALTERNATE" "$ACTIVE_TUPLE_ACTION" \
    "$ACTIVE_TUPLE_REVISION" "$ACTIVE_TUPLE_CONFIG_HASH" "$ACTIVE_TUPLE_MODE" "$MOUNT_TRACE_SHA" \
    trace "$token" "$MOUNT_TRACE_SHA"
  result=$?
  if [ "$result" -ne 0 ]; then
    active_tuple_mount_loaded || return 70
    return "$result"
  fi
}

engine_history_mount_normal_locked() {
  local result
  active_tuple_load || return
  [ "$ACTIVE_TUPLE_MODE" != paused ] || return 0
  [ "$ACTIVE_TUPLE_MOUNT_KIND" = trace ] || return 0
  mount_generation_for_mode "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_MODE" || return
  mount_pid1 "$MOUNT_SOURCE" "$ACTIVE_TUPLE_GENERATION" "$MOUNT_KIND" || return
  active_write_values "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_ALTERNATE" "$ACTIVE_TUPLE_ACTION" \
    "$ACTIVE_TUPLE_REVISION" "$ACTIVE_TUPLE_CONFIG_HASH" "$ACTIVE_TUPLE_MODE" "$(sha256_file "$MOUNT_SOURCE")"
  result=$?
  if [ "$result" -ne 0 ]; then
    active_tuple_mount_loaded || return 70
    return "$result"
  fi
}

engine_mount_boot_locked() {
  local result
  active_tuple_load || return
  mount_generation_for_mode "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_MODE" || return
  mount_pid1 "$MOUNT_SOURCE" "$ACTIVE_TUPLE_GENERATION" "$MOUNT_KIND" || return
  active_write_values "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_ALTERNATE" "$ACTIVE_TUPLE_ACTION" \
    "$ACTIVE_TUPLE_REVISION" "$ACTIVE_TUPLE_CONFIG_HASH" "$ACTIVE_TUPLE_MODE" "$(sha256_file "$MOUNT_SOURCE")"
  result=$?
  return "$result"
}

# Switch the effective mount to the generation recovery file without changing
# the user's desired mode.  The active tuple remains untouched until the new
# mount has been verified, and any commit failure is compensated by remounting
# the tuple that was loaded before the operation started.
engine_pause_locked() {
  local result recovery_sha
  active_tuple_load || return
  active_tuple_mount_matches_loaded || return
  [ "$ACTIVE_TUPLE_MODE" = paused ] && return 0
  case "$ACTIVE_TUPLE_MOUNT_KIND" in normal|trace) ;; *) return 76 ;; esac
  mount_generation_for_mode "$ACTIVE_TUPLE_GENERATION" paused || return
  recovery_sha=$(sha256_file "$MOUNT_SOURCE") || return
  mount_pid1 "$MOUNT_SOURCE" "$ACTIVE_TUPLE_GENERATION" "$MOUNT_KIND" || {
    result=$?
    active_tuple_mount_loaded || return 76
    return "$result"
  }
  active_write_values "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_ALTERNATE" "$ACTIVE_TUPLE_ACTION" \
    "$ACTIVE_TUPLE_REVISION" "$ACTIVE_TUPLE_CONFIG_HASH" paused "$recovery_sha"
  result=$?
  if [ "$result" -ne 0 ]; then
    active_tuple_mount_loaded || return 76
    return "$result"
  fi
}

engine_resume_locked() {
  local desired desired_sha result
  active_tuple_load || return
  active_tuple_mount_matches_loaded || return
  [ "$ACTIVE_TUPLE_MODE" = paused ] || return 0
  desired=$(mode_desired) || return
  mount_generation_for_mode "$ACTIVE_TUPLE_GENERATION" "$desired" || return
  desired_sha=$(sha256_file "$MOUNT_SOURCE") || return
  mount_pid1 "$MOUNT_SOURCE" "$ACTIVE_TUPLE_GENERATION" "$MOUNT_KIND" || {
    result=$?
    active_tuple_mount_loaded || return 76
    return "$result"
  }
  active_write_values "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_ALTERNATE" "$ACTIVE_TUPLE_ACTION" \
    "$ACTIVE_TUPLE_REVISION" "$ACTIVE_TUPLE_CONFIG_HASH" "$desired" "$desired_sha"
  result=$?
  if [ "$result" -ne 0 ]; then
    active_tuple_mount_loaded || return 76
    return "$result"
  fi
}

mount_generation_for_mode() {
  local generation=$1 mode=$2
  case "$mode" in
    block_all) MOUNT_SOURCE="$RULE_GENERATIONS/$generation/all"; MOUNT_KIND=generation_all ;;
    preserve_reward) MOUNT_SOURCE="$RULE_GENERATIONS/$generation/reward"; MOUNT_KIND=generation_reward ;;
    recovery|paused) MOUNT_SOURCE="$RULE_GENERATIONS/$generation/recovery"; MOUNT_KIND=generation_recovery ;;
    *) return 65 ;;
  esac
  export MOUNT_SOURCE MOUNT_KIND
}

active_write_values() {
  local active=$1 alternate=$2 action=$3 revision=$4 config_hash=$5 mode=$6 hosts_hash=$7 mount_kind=${8:-normal} map_token=${9-} trace_hash=${10-} tmp
  tmp="$RULE_RUNTIME/active.prop.tmp.$$"
  {
    printf 'schema_version=2\n'
    printf 'active_generation=%s\n' "$active"
    printf 'alternate_generation=%s\n' "$alternate"
    printf 'alternate_action=%s\n' "$action"
    printf 'applied_sources_revision=%s\n' "$revision"
    printf 'config_snapshot_sha256=%s\n' "$config_hash"
    printf 'active_mode=%s\n' "$mode"
    printf 'active_hosts_sha256=%s\n' "$hosts_hash"
    printf 'active_mount_kind=%s\n' "$mount_kind"
    printf 'active_map_token=%s\n' "$map_token"
    printf 'active_trace_sha256=%s\n' "$trace_hash"
  } > "$tmp" || return 74
  active_validate "$tmp" || { rm -f "$tmp"; return 65; }
  atomic_replace_file "$tmp" "$RULE_RUNTIME/active.prop"
}

engine_refresh_from_candidate_mode() {
  local candidate=$1 mode=$2 revision config_hash candidate_source candidate_kind candidate_sha result
  case "$mode" in block_all|preserve_reward|paused) ;; *) return 65 ;; esac
  active_tuple_load || return
  revision=$(mount_manifest_value "$RULE_GENERATIONS/$candidate/manifest.prop" sources_revision) || return
  config_hash=$(mount_manifest_value "$RULE_GENERATIONS/$candidate/manifest.prop" config_snapshot_sha256) || return
  mount_generation_for_mode "$candidate" "$mode" || return
  candidate_source=$MOUNT_SOURCE
  candidate_kind=$MOUNT_KIND
  mount_pid1 "$candidate_source" "$candidate" "$candidate_kind" || {
    result=$?
    active_tuple_mount_loaded || return 76
    return "$result"
  }
  candidate_sha=$(sha256_file "$candidate_source") || {
    result=$?
    active_tuple_mount_loaded || return 76
    return "$result"
  }
  active_write_values "$candidate" "$ACTIVE_TUPLE_GENERATION" rollback "$revision" "$config_hash" "$mode" "$candidate_sha"
  result=$?
  if [ "$result" -ne 0 ]; then
    active_tuple_mount_loaded || return 76
    return "$result"
  fi
}

engine_refresh_from_candidate() {
  local candidate=$1 mode
  mode=$(active_value active_mode) || return
  engine_refresh_from_candidate_mode "$candidate" "$mode"
}

engine_rollback_locked() {
  local alternate action mode revision config_hash source kind sha next_action result
  active_tuple_load || return
  alternate=$ACTIVE_TUPLE_ALTERNATE
  action=$ACTIVE_TUPLE_ACTION
  [ -n "$alternate" ] && { [ "$action" = rollback ] || [ "$action" = redo ]; } || return 65
  mode=$ACTIVE_TUPLE_MODE
  revision=$(mount_manifest_value "$RULE_GENERATIONS/$alternate/manifest.prop" sources_revision) || return
  config_hash=$(mount_manifest_value "$RULE_GENERATIONS/$alternate/manifest.prop" config_snapshot_sha256) || return
  mount_generation_for_mode "$alternate" "$mode" || return
  source=$MOUNT_SOURCE
  kind=$MOUNT_KIND
  mount_pid1 "$source" "$alternate" "$kind" || {
    result=$?
    active_tuple_mount_loaded || return 76
    return "$result"
  }
  sha=$(sha256_file "$source") || {
    result=$?
    active_tuple_mount_loaded || return 76
    return "$result"
  }
  [ "$action" = rollback ] && next_action=redo || next_action=rollback
  active_write_values "$alternate" "$ACTIVE_TUPLE_GENERATION" "$next_action" "$revision" "$config_hash" "$mode" "$sha"
  result=$?
  if [ "$result" -ne 0 ]; then
    active_tuple_mount_loaded || return 76
    return "$result"
  fi
}

engine_mount_namespace_locked() {
  local pid=$1 profile=$2 active mode
  case "$pid" in ''|*[!0-9]*) return 65 ;; esac
  active=$(active_value active_generation) || return
  case "$profile" in preserve_reward) mode=preserve_reward ;; recovery) mode=recovery ;; *) return 65 ;; esac
  mount_generation_for_mode "$active" "$mode" || return
  mount_apply "$pid" "$MOUNT_SOURCE" "$active" "$MOUNT_KIND"
}

mount_record_append_fields() {
  local destination=$1
  shift
  [ "$#" -eq 17 ] || return 64
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >> "$destination"
}

mount_cleanup_all() {
  local file line fields state ns pid start target kind source generation sha pre post source_dev target_dev inherited_id inherited_dev token trace_hash
  local representative current current_dev current_sha failures=0 remaining tmp
  file=$(mount_record_file)
  [ -f "$file" ] || return 0
  remaining="$file.remaining.$$"
  : > "$remaining"
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    fields=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print NF}')
    IFS="$(printf '\t')" read -r state ns pid start target kind source generation sha pre post source_dev target_dev inherited_id inherited_dev token trace_hash <<EOF
$line
EOF
    if [ "$fields" -eq 15 ]; then token=-; trace_hash=-; fi
    if { [ "$fields" -ne 15 ] && [ "$fields" -ne 17 ]; } || ! mount_target_valid "$target" || ! mount_source_tuple_validate "$source" "$generation" "$kind" "$token" "$trace_hash"; then
      mount_record_append_fields "$remaining" "$state" "$ns" "$pid" "$start" "$target" "$kind" "$source" \
        "$generation" "$sha" "$pre" "$post" "$source_dev" "$target_dev" "$inherited_id" "$inherited_dev" "${token:--}" "${trace_hash:--}" || return
      failures=$((failures + 1))
      continue
    fi
    representative=$(mount_find_representative "$ns" "$pid" "$start" 2>/dev/null || true)
    [ -n "$representative" ] || continue
    current=$(mount_top_id "$representative" "$target" 2>/dev/null || true)
    current_dev=$(mount_target_devino "$representative" "$target" 2>/dev/null || true)
    current_sha=$(mount_target_sha "$representative" "$target" 2>/dev/null || true)
    if { [ "$state" = committed ] && [ "$current" = "$post" ] && [ "$current_dev" = "$source_dev" ] && [ "$current_sha" = "$sha" ]; } || \
       { [ "$state" = pending ] && [ "$current" != "$pre" ] && [ "$current_dev" = "$source_dev" ]; }; then
      if ! mount_backend_umount "$representative" "$target"; then
        mount_record_append_fields "$remaining" "$state" "$ns" "$pid" "$start" "$target" "$kind" "$source" \
          "$generation" "$sha" "$pre" "$post" "$source_dev" "$target_dev" "$inherited_id" "$inherited_dev" "$token" "$trace_hash" || return
        failures=$((failures + 1))
      fi
    elif [ -z "$current" ]; then
      :
    else
      mount_record_append_fields "$remaining" "$state" "$ns" "$pid" "$start" "$target" "$kind" "$source" \
        "$generation" "$sha" "$pre" "$post" "$source_dev" "$target_dev" "$inherited_id" "$inherited_dev" "$token" "$trace_hash" || return
      failures=$((failures + 1))
    fi
  done < "$file"
  if [ -s "$remaining" ]; then
    atomic_replace_file "$remaining" "$file"
  else
    rm -f "$remaining" "$file"
  fi
  [ "$failures" -eq 0 ]
}
