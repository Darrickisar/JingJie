#!/system/bin/sh

HISTORY_MANAGER_ROOT=${HISTORY_MANAGER_ROOT:-${0%/*}}
MODDIR=${MODDIR:-$HISTORY_MANAGER_ROOT}
BB=${BB:-$MODDIR/busybox/busybox}
[ -x "$BB" ] || BB=$(command -v busybox 2>/dev/null || printf '%s' "$BB")
export MODDIR BB

. "$HISTORY_MANAGER_ROOT/lib/rules/common.sh"

HISTORY_TRACE_MAX_DOMAINS_DEFAULT=500000
HISTORY_TRACE_MAX_BYTES=33554432
HISTORY_TRACE_RETAIN=4
# 拦截记录的有效期：3 小时。超过就删，不再保留。
# 读取进程在 flush_batch 里做权威删除（有流量才走到，不新增任何定时唤醒），
# 这里是 shell 侧的同一条线：查询时按同一个截止时刻过滤，并顺手删掉整代过期的文件，
# 这样「界面看到的条数」和「文件里留着的行」永远说的是同一件事。
HISTORY_RETENTION_SECONDS=10800

# 保留期的起点。取不到时间就回 0（等于不过滤），宁可多显示也不要把记录全筛没了。
history_retention_cutoff() {
  local now
  now=$(date +%s 2>/dev/null) || { printf '0\n'; return 0; }
  case "$now" in ''|*[!0-9]*) printf '0\n'; return 0 ;; esac
  if [ "$now" -gt "$HISTORY_RETENTION_SECONDS" ]; then
    printf '%s\n' "$((now - HISTORY_RETENTION_SECONDS))"
  else
    printf '0\n'
  fi
}

history_config_file() { printf '%s\n' "$CONFIG_DIR/history.conf"; }
history_root() { printf '%s\n' "$RULE_RUNTIME/history"; }

history_token_valid() {
  [ "${#1}" -eq 16 ] || return 1
  case "$1" in *[!0-9a-f]*) return 1 ;; *) return 0 ;; esac
}

history_generation_valid() {
  printf '%s\n' "$1" | "$BB" awk '
    /^g[0-9]+$/ || /^g[0-9]+-r[0-9]+-p[0-9]+$/ { ok=1 }
    END { exit ok ? 0 : 1 }
  '
}

history_hash_valid() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in *[!0-9a-f]*) return 1 ;; *) return 0 ;; esac
}

history_config_validate() {
  local file=${1:-$(history_config_file)}
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    NF != 2 {bad()}
    $1 !~ /^(schema_version|history_enabled)$/ {bad()}
    seen[$1]++ {bad()}
    $1 == "schema_version" && $2 != "1" {bad()}
    $1 == "history_enabled" && $2 !~ /^[01]$/ {bad()}
    END {if(NR != 2 || !seen["schema_version"] || !seen["history_enabled"]) exit 65}
  ' "$file"
}

history_config_bootstrap() {
  local file tmp
  file=$(history_config_file)
  if [ -e "$file" ] || [ -L "$file" ]; then
    history_config_validate "$file"
    return
  fi
  mkdir -p "$CONFIG_DIR" || return 73
  [ ! -L "$CONFIG_DIR" ] || return 65
  tmp="$file.tmp.$$"
  printf 'schema_version=1\nhistory_enabled=0\n' > "$tmp" || return 74
  atomic_replace_file "$tmp" "$file"
}

history_config_get() {
  local file
  file=$(history_config_file)
  history_config_validate "$file" || return
  "$BB" awk -F= '$1=="history_enabled"{print $2}' "$file"
}

history_config_set_internal_locked() {
  local enabled=$1 file tmp
  rules_lock_is_held history-config || return 75
  [ "$enabled" = 0 ] || [ "$enabled" = 1 ] || return 65
  history_config_bootstrap || return
  file=$(history_config_file)
  tmp="$file.tmp.$$"
  printf 'schema_version=1\nhistory_enabled=%s\n' "$enabled" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$file"
}

history_config_set_internal() {
  local enabled=$1 result
  [ "$#" -eq 1 ] || return 64
  [ "$enabled" = 0 ] || [ "$enabled" = 1 ] || return 65
  rules_lock_acquire history-config || return
  history_config_set_internal_locked "$enabled"
  result=$?
  rules_lock_release history-config || return
  return "$result"
}

history_capability_file() { printf '%s\n' "$RULE_RUNTIME/history-capability.prop"; }
history_enable_error_file() { printf '%s\n' "$RULE_RUNTIME/history-enable-error.prop"; }

history_enable_error_code_valid() {
  case "$1" in
    nflog_unsupported|history_probe_failed|history_rules_unavailable|history_trace_prepare_failed|\
    history_reader_start_failed|history_firewall_install_failed|history_mount_failed|\
    history_state_commit_failed|history_recovery_failed) return 0 ;;
    *) return 1 ;;
  esac
}

history_enable_error_validate() {
  local file=${1:-$(history_enable_error_file)}
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2{bad()}
    $1!~/^(schema_version|code|status)$/{bad()}
    seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    $1=="code" && $2!~/^[a-z0-9_]+$/{bad()}
    $1=="status" && $2!~/^[1-9][0-9]{0,2}$/{bad()}
    END{if(NR!=3 || !seen["schema_version"] || !seen["code"] || !seen["status"])bad()}
  ' "$file" || return 65
  HISTORY_ENABLE_ERROR_CODE=$(history_manifest_get_unique "$file" code) || return 65
  HISTORY_ENABLE_ERROR_STATUS=$(history_manifest_get_unique "$file" status) || return 65
  history_enable_error_code_valid "$HISTORY_ENABLE_ERROR_CODE" || return 65
  decimal_uint_in_range "$HISTORY_ENABLE_ERROR_STATUS" 255 1 || return 65
  export HISTORY_ENABLE_ERROR_CODE HISTORY_ENABLE_ERROR_STATUS
}

history_enable_error_write() {
  local code=$1 status=$2 file tmp
  history_enable_error_code_valid "$code" || return 65
  decimal_uint_in_range "$status" 255 1 || return 65
  file=$(history_enable_error_file)
  tmp="$file.tmp.$$"
  {
    printf 'schema_version=1\n'
    printf 'code=%s\n' "$code"
    printf 'status=%s\n' "$status"
  } > "$tmp" || return 74
  atomic_replace_file "$tmp" "$file"
}

history_enable_error_clear() {
  local file
  file=$(history_enable_error_file)
  rm -f "$file"
}

history_capability_error_valid() {
  [ "${#1}" -ge 1 ] && [ "${#1}" -le 64 ] || return 1
  case "$1" in -) return 0 ;; ''|*[!a-z0-9_]*) return 1 ;; *) return 0 ;; esac
}

history_capability_load() {
  local file=${1:-$(history_capability_file)}
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2{bad()}
    $1!~/^(schema_version|availability|last_error)$/{bad()}
    seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    $1=="availability" && $2!~/^(available|unsupported)$/{bad()}
    $1=="last_error" && $2!~/^(-|[a-z0-9_]+)$/{bad()}
    END{if(NR!=3 || !seen["schema_version"] || !seen["availability"] || !seen["last_error"])bad()}
  ' "$file" || return 65
  HISTORY_CAPABILITY_AVAILABILITY=$(
    "$BB" awk -F= '$1=="availability"{print $2}' "$file"
  ) || return 70
  HISTORY_CAPABILITY_ERROR=$(
    "$BB" awk -F= '$1=="last_error"{print $2}' "$file"
  ) || return 70
  history_capability_error_valid "$HISTORY_CAPABILITY_ERROR" || return 65
  if [ "$HISTORY_CAPABILITY_AVAILABILITY" = available ]; then
    [ "$HISTORY_CAPABILITY_ERROR" = - ] || return 65
  else
    [ "$HISTORY_CAPABILITY_ERROR" != - ] || return 65
  fi
  export HISTORY_CAPABILITY_AVAILABILITY HISTORY_CAPABILITY_ERROR
}

history_capability_write() {
  local availability=$1 error=$2 file tmp
  case "$availability" in available|unsupported) ;; *) return 65 ;; esac
  history_capability_error_valid "$error" || return 65
  if [ "$availability" = available ]; then
    [ "$error" = - ] || return 65
  else
    [ "$error" != - ] || return 65
  fi
  file=$(history_capability_file)
  tmp="$file.tmp.$$"
  {
    printf 'schema_version=1\n'
    printf 'availability=%s\n' "$availability"
    printf 'last_error=%s\n' "$error"
  } > "$tmp" || return 74
  atomic_replace_file "$tmp" "$file"
}

history_manifest_get_unique() {
  local file=$1 key=$2
  "$BB" awk -F= -v wanted="$key" '
    $1==wanted {count++; value=substr($0,index($0,"=")+1)}
    END {if(count!=1) exit 65; print value}
  ' "$file"
}

history_source_copy_validate() {
  local source=$1 generation=$2 mode=$3 copy=$4 kind expected manifest manifest_generation expected_hash actual_hash bytes
  history_generation_valid "$generation" || return 65
  case "$mode" in
    block_all) kind=all ;;
    preserve_reward) kind=reward ;;
    *) return 65 ;;
  esac
  expected="$RULE_GENERATIONS/$generation/$kind"
  [ "$source" = "$expected" ] || return 65
  [ -d "$RULE_GENERATIONS" ] && [ ! -L "$RULE_GENERATIONS" ] || return 65
  [ -d "$RULE_GENERATIONS/$generation" ] && [ ! -L "$RULE_GENERATIONS/$generation" ] || return 65
  [ -f "$source" ] && [ ! -L "$source" ] || return 65
  manifest="$RULE_GENERATIONS/$generation/manifest.prop"
  [ -f "$manifest" ] && [ ! -L "$manifest" ] || return 65
  "$BB" awk -F= '
    index($0,"=")<2 {exit 65}
    {key=substr($0,1,index($0,"=")-1)}
    key !~ /^[a-z0-9_]+$/ || seen[key]++ {exit 65}
  ' "$manifest" || return 65
  manifest_generation=$(history_manifest_get_unique "$manifest" generation_id) || return 65
  [ "$manifest_generation" = "$generation" ] || return 70
  expected_hash=$(history_manifest_get_unique "$manifest" "${kind}_sha256") || return 65
  history_hash_valid "$expected_hash" || return 65
  bytes=$(wc -c < "$source" | tr -d ' ') || return 74
  [ "$bytes" -le "$HISTORY_TRACE_MAX_BYTES" ] || return 65
  cp "$source" "$copy" || return 74
  [ -f "$copy" ] && [ ! -L "$copy" ] || return 74
  actual_hash=$(sha256_file "$copy") || return
  [ "$actual_hash" = "$expected_hash" ] || return 70
  HISTORY_SOURCE_KIND=$kind
  HISTORY_SOURCE_SHA256=$actual_hash
  export HISTORY_SOURCE_KIND HISTORY_SOURCE_SHA256
}

history_hosts_extract_domains() {
  local source=$1 domains=$2 maximum=$3 passthrough=$4
  local records sorted result=0
  [ "$#" -eq 4 ] || return 64
  records="$domains.records"
  sorted="$records.sorted"
  : > "$domains" && : > "$passthrough" || return 74
  "$BB" awk '
    function bad(){exit 65}
    function domain_valid(d, n,a,i){
      if(length(d)<1 || length(d)>253 || d ~ /^[0-9.]+$/ || d ~ /^\./ || d ~ /\.$/ || d ~ /\.\./) return 0
      n=split(d,a,".")
      for(i=1;i<=n;i++)
        if(length(a[i])<1 || length(a[i])>63 || a[i] !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) return 0
      return 1
    }
    NF != 2 {bad()}
    {
      address=$1; domain=$2
      if(address ~ /^127\.(6[4-9]|7[01])\.[0-9]+\.[0-9]+$/) bad()
      if(domain ~ /^[0-9.]+$/) next
      if(domain != tolower(domain) || !domain_valid(domain)) bad()
      if(domain=="localhost") {
        if(address=="127.0.0.1" && !localhost4++) { print domain "\tP\t" address; next }
        if(address=="::1" && !localhost6++) { print domain "\tP\t" address; next }
        bad()
      }
      if(address=="0.0.0.0") {
        print domain "\tB\t" address
      } else {
        print domain "\tP\t" address
      }
    }
  ' "$source" > "$records" || result=$?
  if [ "$result" -eq 0 ]; then
    LC_ALL=C "$BB" sort -t "$(printf '\t')" -k1,1 -k2,2 -k3,3 "$records" > "$sorted" || result=74
  fi
  if [ "$result" -eq 0 ]; then
    "$BB" awk -F '\t' -v domains="$domains" -v passthrough="$passthrough" -v maximum="$maximum" '
      NF!=3 || $2!~/^[BP]$/ {exit 65}
      previous_row==$0 {exit 65}
      previous_domain==$1 && previous_kind!=$2 {exit 65}
      {
        previous_row=$0
        previous_domain=$1
        previous_kind=$2
        if($2=="B") {
          if(last_block!=$1) {
            count++
            if(count>maximum) exit 65
            print $1 > domains
            last_block=$1
          }
        } else print $3 " " $1 > passthrough
      }
    ' "$sorted" || result=$?
  fi
  rm -f "$records" "$sorted"
  return "$result"
}

history_map_build() {
  local domains=$1 map=$2 sorted
  sorted="$map.sorted"
  # 唯一的调用方（history_prepare_trace）传进来的 domains 已经是 history_hosts_extract_domains
  # 按 LC_ALL=C 排过、并且按域名去重过的。已经有序时就不必再排一遍：sort -c 只是 O(n) 扫一趟、
  # 不落临时文件，而对 50 万行重排一遍是开启动作里实打实的一段等待。
  # 顺序仍然由这里保证——sort -c 说没序就照样排，函数的契约不变。
  if LC_ALL=C "$BB" sort -c "$domains" 2>/dev/null; then
    sorted=$domains
  else
    LC_ALL=C "$BB" sort "$domains" > "$sorted" || return 74
  fi
  "$BB" awk '
    {
      ordinal=NR
      second=64+int(ordinal/65536)
      remainder=ordinal%65536
      third=int(remainder/256)
      fourth=remainder%256
      printf "127.%d.%d.%d\t%s\n", second, third, fourth, $0
    }
  ' "$sorted" > "$map" || {
    [ "$sorted" = "$domains" ] || rm -f "$sorted"
    rm -f "$map"
    return 74
  }
  # 走了快路径时 sorted 就是入参本身，不能删。
  [ "$sorted" = "$domains" ] || rm -f "$sorted" || return 74
}

history_trace_hosts_build() {
  local map=$1 passthrough=$2 output=$3
  cat "$passthrough" > "$output" || return 74
  "$BB" awk -F '\t' 'NF!=2{exit 70}{print $1 " " $2}' "$map" >> "$output"
}

history_token_in_use() {
  local token=$1 root ledger
  root=$(history_root)
  ledger="$root/token-ledger.tsv"
  [ ! -e "$root/maps/$token.tsv" ] && [ ! -L "$root/maps/$token.tsv" ] || return 0
  [ ! -e "$root/traces/$token" ] && [ ! -L "$root/traces/$token" ] || return 0
  [ -f "$ledger" ] || return 1
  "$BB" grep -x "$token" "$ledger" >/dev/null 2>&1
}

history_token_new() {
  local token attempts=0
  while [ "$attempts" -lt 32 ]; do
    if [ -n "${HISTORY_TOKEN_SOURCE-}" ]; then
      token=$("$HISTORY_TOKEN_SOURCE" 2>/dev/null) || return 70
    else
      token=$("$BB" od -An -N8 -tx1 /dev/urandom 2>/dev/null | "$BB" tr -d ' \n') || true
      if [ -z "$token" ]; then
        local entropy counter
        counter=0
        [ -f "$(history_root)/token-ledger.tsv" ] && counter=$(wc -l < "$(history_root)/token-ledger.tsv" | tr -d ' ')
        entropy=$(printf '%s:%s:%s:%s' "$$" "$(date +%s 2>/dev/null || printf 0)" "$attempts" "$counter" | sha256_file_stdin) || return 70
        token=${entropy%${entropy#????????????????}}
      fi
    fi
    history_token_valid "$token" || return 70
    if ! history_token_in_use "$token"; then
      printf '%s\n' "$token"
      return 0
    fi
    attempts=$((attempts + 1))
  done
  return 70
}

history_trace_manifest_write() {
  local output=$1 token=$2 generation=$3 mode=$4 kind=$5 source_hash=$6 map=$7 hosts=$8
  local map_hash hosts_hash rule_count
  map_hash=$(sha256_file "$map") || return
  hosts_hash=$(sha256_file "$hosts") || return
  rule_count=$(wc -l < "$map" | tr -d ' ') || return 74
  {
    printf 'schema_version=1\n'
    printf 'map_token=%s\n' "$token"
    printf 'generation_id=%s\n' "$generation"
    printf 'mode=%s\n' "$mode"
    printf 'source_kind=%s\n' "$kind"
    printf 'source_sha256=%s\n' "$source_hash"
    printf 'map_sha256=%s\n' "$map_hash"
    printf 'hosts_sha256=%s\n' "$hosts_hash"
    printf 'rule_count=%s\n' "$rule_count"
  } > "$output"
}

history_trace_manifest_validate() {
  local file=$1 token=$2 value
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    NF != 2 {bad()}
    $1 !~ /^(schema_version|map_token|generation_id|mode|source_kind|source_sha256|map_sha256|hosts_sha256|rule_count)$/ {bad()}
    seen[$1]++ {bad()}
    END {if(NR!=9) bad()}
  ' "$file" || return 65
  value=$(history_manifest_get_unique "$file" schema_version) || return 65
  [ "$value" = 1 ] || return 65
  value=$(history_manifest_get_unique "$file" map_token) || return 65
  [ "$value" = "$token" ] && history_token_valid "$value" || return 65
  value=$(history_manifest_get_unique "$file" generation_id) || return 65
  history_generation_valid "$value" || return 65
  value=$(history_manifest_get_unique "$file" mode) || return 65
  case "$value" in block_all|preserve_reward) ;; *) return 65 ;; esac
  value=$(history_manifest_get_unique "$file" source_kind) || return 65
  case "$value" in all|reward) ;; *) return 65 ;; esac
  for key in source_sha256 map_sha256 hosts_sha256; do
    value=$(history_manifest_get_unique "$file" "$key") || return 65
    history_hash_valid "$value" || return 65
  done
  value=$(history_manifest_get_unique "$file" rule_count) || return 65
  case "$value" in ''|*[!0-9]*) return 65 ;; esac
}

history_trace_validate() {
  local token=$1 root dir manifest kind mode generation generation_dir generation_manifest source expected actual count
  history_token_valid "$token" || return 65
  root=$(history_root)
  dir="$root/traces/$token"
  manifest="$dir/manifest.prop"
  [ -d "$root" ] && [ ! -L "$root" ] || return 66
  [ -d "$root/maps" ] && [ ! -L "$root/maps" ] || return 66
  [ -d "$root/traces" ] && [ ! -L "$root/traces" ] || return 66
  [ -d "$dir" ] && [ ! -L "$dir" ] || return 66
  history_trace_manifest_validate "$manifest" "$token" || return
  kind=$(history_manifest_get_unique "$manifest" source_kind) || return 65
  mode=$(history_manifest_get_unique "$manifest" mode) || return 65
  generation=$(history_manifest_get_unique "$manifest" generation_id) || return 65
  generation_dir="$RULE_GENERATIONS/$generation"
  generation_manifest="$generation_dir/manifest.prop"
  source="$generation_dir/$kind"
  [ -d "$generation_dir" ] && [ ! -L "$generation_dir" ] || return 66
  [ -f "$generation_manifest" ] && [ ! -L "$generation_manifest" ] || return 66
  [ -f "$source" ] && [ ! -L "$source" ] || return 66
  case "$mode:$kind" in block_all:all|preserve_reward:reward) ;; *) return 65 ;; esac
  expected=$(history_manifest_get_unique "$manifest" source_sha256) || return 65
  actual=$(history_manifest_get_unique "$generation_manifest" "${kind}_sha256") || return 65
  history_hash_valid "$actual" || return 65
  [ "$actual" = "$expected" ] || return 70
  actual=$(sha256_file "$source") || return
  [ "$actual" = "$expected" ] || return 70
  [ -f "$dir/$kind" ] && [ ! -L "$dir/$kind" ] || return 66
  [ -f "$root/maps/$token.tsv" ] && [ ! -L "$root/maps/$token.tsv" ] || return 66
  expected=$(history_manifest_get_unique "$manifest" map_sha256) || return 65
  actual=$(sha256_file "$root/maps/$token.tsv") || return
  [ "$actual" = "$expected" ] || return 70
  expected=$(history_manifest_get_unique "$manifest" hosts_sha256) || return 65
  actual=$(sha256_file "$dir/$kind") || return
  [ "$actual" = "$expected" ] || return 70
  count=$(wc -l < "$root/maps/$token.tsv" | tr -d ' ') || return 74
  expected=$(history_manifest_get_unique "$manifest" rule_count) || return 65
  [ "$count" = "$expected" ] || return 70
}

history_trace_pair_validate() {
  local token=$1 map=$2 dir=$3 manifest kind expected actual count
  history_token_valid "$token" || return 70
  manifest="$dir/manifest.prop"
  [ -f "$map" ] && [ ! -L "$map" ] || return 70
  [ -d "$dir" ] && [ ! -L "$dir" ] || return 70
  history_trace_manifest_validate "$manifest" "$token" >/dev/null 2>&1 || return 70
  kind=$(history_manifest_get_unique "$manifest" source_kind) || return 70
  case "$kind" in all|reward) ;; *) return 70 ;; esac
  [ -f "$dir/$kind" ] && [ ! -L "$dir/$kind" ] || return 70
  count=$("$BB" find "$dir" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | "$BB" tr -d ' ') || return 70
  [ "$count" = 2 ] || return 70
  history_query_map_validate "$token" "$map" "$manifest" || return 70
  expected=$(history_manifest_get_unique "$manifest" hosts_sha256) || return 70
  actual=$(sha256_file "$dir/$kind") || return 70
  [ "$actual" = "$expected" ] || return 70
}

history_trace_prune_candidate_validate() {
  local token=$1 root
  root=$(history_root)
  history_trace_pair_validate "$token" "$root/maps/$token.tsv" "$root/traces/$token"
}

history_trace_retire_manifest_write() {
  local output=$1 state=$2 token=$3 map=$4 trace=$5 manifest kind map_hash hosts_hash manifest_hash
  case "$state" in prepared|retired) ;; *) return 65 ;; esac
  manifest="$trace/manifest.prop"
  history_trace_pair_validate "$token" "$map" "$trace" || return 70
  kind=$(history_manifest_get_unique "$manifest" source_kind) || return 70
  map_hash=$(sha256_file "$map") || return 70
  hosts_hash=$(sha256_file "$trace/$kind") || return 70
  manifest_hash=$(sha256_file "$manifest") || return 70
  {
    printf 'schema_version=1\n'
    printf 'state=%s\n' "$state"
    printf 'map_token=%s\n' "$token"
    printf 'source_kind=%s\n' "$kind"
    printf 'map_sha256=%s\n' "$map_hash"
    printf 'hosts_sha256=%s\n' "$hosts_hash"
    printf 'manifest_sha256=%s\n' "$manifest_hash"
  } > "$output" || return 74
}

history_trace_retire_manifest_load() {
  local file=$1 token=$2 value
  [ -f "$file" ] && [ ! -L "$file" ] || return 70
  "$BB" awk -F= '
    function bad(){exit 1}
    NF!=2 || $1!~/^(schema_version|state|map_token|source_kind|map_sha256|hosts_sha256|manifest_sha256)$/ || seen[$1]++ {bad()}
    END{if(NR!=7)bad()}
  ' "$file" || return 70
  value=$(history_manifest_get_unique "$file" schema_version) || return 70
  [ "$value" = 1 ] || return 70
  HISTORY_RETIRE_STATE=$(history_manifest_get_unique "$file" state) || return 70
  case "$HISTORY_RETIRE_STATE" in prepared|retired) ;; *) return 70 ;; esac
  value=$(history_manifest_get_unique "$file" map_token) || return 70
  [ "$value" = "$token" ] && history_token_valid "$value" || return 70
  HISTORY_RETIRE_KIND=$(history_manifest_get_unique "$file" source_kind) || return 70
  case "$HISTORY_RETIRE_KIND" in all|reward) ;; *) return 70 ;; esac
  HISTORY_RETIRE_MAP_SHA=$(history_manifest_get_unique "$file" map_sha256) || return 70
  HISTORY_RETIRE_HOSTS_SHA=$(history_manifest_get_unique "$file" hosts_sha256) || return 70
  HISTORY_RETIRE_MANIFEST_SHA=$(history_manifest_get_unique "$file" manifest_sha256) || return 70
  history_hash_valid "$HISTORY_RETIRE_MAP_SHA" && history_hash_valid "$HISTORY_RETIRE_HOSTS_SHA" && \
    history_hash_valid "$HISTORY_RETIRE_MANIFEST_SHA" || return 70
  export HISTORY_RETIRE_STATE HISTORY_RETIRE_KIND HISTORY_RETIRE_MAP_SHA HISTORY_RETIRE_HOSTS_SHA HISTORY_RETIRE_MANIFEST_SHA
}

history_trace_retired_cleanup() {
  local root=$1 slot=$2 token=$3 marker map trace path name actual entries
  marker="$slot/retire.prop"
  map="$slot/map.tsv"
  trace="$slot/trace"
  history_trace_retire_manifest_load "$marker" "$token" || return 70
  [ "$HISTORY_RETIRE_STATE" = retired ] || return 70
  [ ! -e "$root/maps/$token.tsv" ] && [ ! -L "$root/maps/$token.tsv" ] || return 70
  [ ! -e "$root/traces/$token" ] && [ ! -L "$root/traces/$token" ] || return 70
  for path in "$slot"/*; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    name=${path##*/}
    case "$name" in map.tsv|trace|retire.prop) ;; *) return 70 ;; esac
  done
  if [ -e "$map" ] || [ -L "$map" ]; then
    [ -f "$map" ] && [ ! -L "$map" ] || return 70
    actual=$(sha256_file "$map") || return 70
    [ "$actual" = "$HISTORY_RETIRE_MAP_SHA" ] || return 70
  fi
  if [ -e "$trace" ] || [ -L "$trace" ]; then
    [ -d "$trace" ] && [ ! -L "$trace" ] || return 70
    for path in "$trace"/*; do
      [ -e "$path" ] || [ -L "$path" ] || continue
      name=${path##*/}
      case "$name" in "$HISTORY_RETIRE_KIND"|manifest.prop) ;; *) return 70 ;; esac
      [ -f "$path" ] && [ ! -L "$path" ] || return 70
    done
    if [ -f "$trace/$HISTORY_RETIRE_KIND" ]; then
      actual=$(sha256_file "$trace/$HISTORY_RETIRE_KIND") || return 70
      [ "$actual" = "$HISTORY_RETIRE_HOSTS_SHA" ] || return 70
    fi
    if [ -f "$trace/manifest.prop" ]; then
      actual=$(sha256_file "$trace/manifest.prop") || return 70
      [ "$actual" = "$HISTORY_RETIRE_MANIFEST_SHA" ] || return 70
    fi
  fi
  rm -f "$map" || return 74
  if [ -d "$trace" ]; then
    rm -f "$trace/$HISTORY_RETIRE_KIND" || return 74
    rm -f "$trace/manifest.prop" || return 74
    rmdir "$trace" || return 74
  fi
  rm -f "$marker" || return 74
  rmdir "$slot" || return 74
}

history_trace_prune_recover_locked() {
  local root=$1 retired slot token map trace original_map original_trace marker map_path trace_path entries
  rules_lock_is_held history || return 75
  retired="$root/retired"
  [ -e "$retired" ] || [ -L "$retired" ] || return 0
  [ -d "$retired" ] && [ ! -L "$retired" ] || return 70
  for slot in "$retired"/*; do
    [ -e "$slot" ] || [ -L "$slot" ] || continue
    [ -d "$slot" ] && [ ! -L "$slot" ] || return 70
    token=${slot##*/}
    history_token_valid "$token" || return 70
    "$BB" grep -x "$token" "$root/token-ledger.tsv" >/dev/null 2>&1 || return 70
    marker="$slot/retire.prop"
    map="$slot/map.tsv"
    trace="$slot/trace"
    original_map="$root/maps/$token.tsv"
    original_trace="$root/traces/$token"
    entries=$("$BB" find "$slot" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | "$BB" tr -d ' ') || return 74
    if [ "$entries" = 0 ]; then rmdir "$slot" || return 74; continue; fi
    history_trace_retire_manifest_load "$marker" "$token" || return 70
    if [ "$HISTORY_RETIRE_STATE" = retired ]; then
      history_trace_retired_cleanup "$root" "$slot" "$token" || return
      continue
    fi
    if [ -e "$map" ] || [ -L "$map" ]; then
      [ ! -e "$original_map" ] && [ ! -L "$original_map" ] || return 70
      map_path=$map
    else
      [ -f "$original_map" ] && [ ! -L "$original_map" ] || return 70
      map_path=$original_map
    fi
    if [ -e "$trace" ] || [ -L "$trace" ]; then
      [ ! -e "$original_trace" ] && [ ! -L "$original_trace" ] || return 70
      trace_path=$trace
    else
      [ -d "$original_trace" ] && [ ! -L "$original_trace" ] || return 70
      trace_path=$original_trace
    fi
    history_trace_pair_validate "$token" "$map_path" "$trace_path" || return 70
    [ "$map_path" = "$original_map" ] || mv "$map" "$original_map" || return 74
    [ "$trace_path" = "$original_trace" ] || mv "$trace" "$original_trace" || return 74
    rm -f "$marker" || return 74
    rmdir "$slot" || return 74
  done
  rmdir "$retired" 2>/dev/null || { [ ! -e "$retired" ] && [ ! -L "$retired" ]; } || return 74
}

history_active_trace_token_for_prune() {
  local file="$RULE_RUNTIME/active.prop" mount token
  [ -e "$file" ] || [ -L "$file" ] || return 1
  [ -f "$file" ] && [ ! -L "$file" ] || return 70
  mount=$(history_manifest_get_unique "$file" active_mount_kind) || return 70
  case "$mount" in
    normal) return 1 ;;
    trace)
      token=$(history_manifest_get_unique "$file" active_map_token) || return 70
      history_token_valid "$token" || return 70
      history_trace_validate "$token" >/dev/null 2>&1 || return 70
      printf '%s\n' "$token"
      ;;
    *) return 70 ;;
  esac
}

history_trace_prune_locked() {
  local keep=$1 preserve=${2-} root ledger inventory drop token count=0 remove_count file tmp path name
  local active_token active_result=0 retired slot marker marker_tmp
  rules_lock_is_held history-lifecycle || return 75
  rules_lock_is_held history || return 75
  case "$keep" in ''|*[!0-9]*) return 65 ;; esac
  [ "$keep" -ge 0 ] && [ "$keep" -le "$HISTORY_TRACE_RETAIN" ] || return 65
  [ -z "$preserve" ] || history_token_valid "$preserve" || return 65
  root=$(history_root)
  [ -e "$root" ] || [ -L "$root" ] || return 0
  [ -d "$root" ] && [ ! -L "$root" ] || return 70
  [ -d "$root/maps" ] && [ ! -L "$root/maps" ] || return 70
  [ -d "$root/traces" ] && [ ! -L "$root/traces" ] || return 70
  ledger="$root/token-ledger.tsv"
  [ -f "$ledger" ] && [ ! -L "$ledger" ] || return 70
  "$BB" awk 'length($0)!=16 || $0~/[^0-9a-f]/ || seen[$0]++{exit 1}' "$ledger" || return 70
  history_trace_prune_recover_locked "$root" || return
  active_token=$(history_active_trace_token_for_prune 2>/dev/null) || active_result=$?
  [ "$active_result" -eq 0 ] || [ "$active_result" -eq 1 ] || return 70
  inventory="$RULE_TMP/history-prune.inventory.$$"
  drop="$RULE_TMP/history-prune.drop.$$"
  : > "$inventory" || return 74
  : > "$drop" || { rm -f "$inventory"; return 74; }

  while IFS= read -r token; do
    [ -n "$token" ] || continue
    if [ -e "$root/maps/$token.tsv" ] || [ -L "$root/maps/$token.tsv" ] || \
       [ -e "$root/traces/$token" ] || [ -L "$root/traces/$token" ]; then
      history_trace_prune_candidate_validate "$token" || { rm -f "$inventory" "$drop"; return 70; }
      printf '%s\n' "$token" >> "$inventory" || { rm -f "$inventory" "$drop"; return 74; }
      count=$((count + 1))
    fi
  done < "$ledger"

  for path in "$root/maps"/*; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    name=${path##*/}; token=${name%.tsv}
    [ "$name" = "$token.tsv" ] && history_token_valid "$token" || { rm -f "$inventory" "$drop"; return 70; }
    "$BB" grep -x "$token" "$inventory" >/dev/null 2>&1 || { rm -f "$inventory" "$drop"; return 70; }
  done
  for path in "$root/traces"/*; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    token=${path##*/}
    history_token_valid "$token" || { rm -f "$inventory" "$drop"; return 70; }
    "$BB" grep -x "$token" "$inventory" >/dev/null 2>&1 || { rm -f "$inventory" "$drop"; return 70; }
  done

  remove_count=$((count - keep))
  [ "$remove_count" -gt 0 ] || { rm -f "$inventory" "$drop"; return 0; }
  while IFS= read -r token; do
    [ "$remove_count" -gt 0 ] || break
    [ "$token" = "$preserve" ] && continue
    [ "$token" = "$active_token" ] && continue
    printf '%s\n' "$token" >> "$drop" || { rm -f "$inventory" "$drop"; return 74; }
    remove_count=$((remove_count - 1))
  done < "$inventory"
  [ "$remove_count" -eq 0 ] || { rm -f "$inventory" "$drop"; return 70; }

  for file in "$root/events.tsv.1" "$root/events.tsv"; do
    [ -e "$file" ] || [ -L "$file" ] || continue
    [ -f "$file" ] && [ ! -L "$file" ] || { rm -f "$inventory" "$drop"; return 70; }
    tmp="$file.prune.$$"
    "$BB" awk -F '\t' 'NR==FNR{drop[$1]=1;next}!($2 in drop)' "$drop" "$file" > "$tmp" || {
      rm -f "$inventory" "$drop" "$tmp"
      return 74
    }
    atomic_replace_file "$tmp" "$file" || { rm -f "$inventory" "$drop" "$tmp"; return 74; }
  done

  retired="$root/retired"
  mkdir "$retired" 2>/dev/null || { [ -d "$retired" ] && [ ! -L "$retired" ]; } || { rm -f "$inventory" "$drop"; return 74; }
  while IFS= read -r token; do
    history_trace_prune_candidate_validate "$token" || { rm -f "$inventory" "$drop"; return 70; }
    slot="$retired/$token"
    mkdir "$slot" || { rm -f "$inventory" "$drop"; return 74; }
    marker="$slot/retire.prop"
    marker_tmp="$RULE_TMP/history-retire.$token.prepared.$$"
    history_trace_retire_manifest_write "$marker_tmp" prepared "$token" "$root/maps/$token.tsv" "$root/traces/$token" || {
      rm -f "$marker_tmp"
      rmdir "$slot" 2>/dev/null || true
      rm -f "$inventory" "$drop"
      return 74
    }
    atomic_replace_file "$marker_tmp" "$marker" || {
      rm -f "$marker_tmp"
      rmdir "$slot" 2>/dev/null || true
      rm -f "$inventory" "$drop"
      return 74
    }
    if ! mv "$root/maps/$token.tsv" "$slot/map.tsv"; then
      rm -f "$marker"; rmdir "$slot" 2>/dev/null || true
      rm -f "$inventory" "$drop"
      return 74
    fi
    if ! mv "$root/traces/$token" "$slot/trace"; then
      history_trace_prune_recover_locked "$root" >/dev/null 2>&1 || true
      rm -f "$inventory" "$drop"
      return 74
    fi
    marker_tmp="$RULE_TMP/history-retire.$token.retired.$$"
    history_trace_retire_manifest_write "$marker_tmp" retired "$token" "$slot/map.tsv" "$slot/trace" || {
      rm -f "$marker_tmp"; history_trace_prune_recover_locked "$root" >/dev/null 2>&1 || true
      rm -f "$inventory" "$drop"; return 74
    }
    atomic_replace_file "$marker_tmp" "$marker" || {
      rm -f "$marker_tmp"; history_trace_prune_recover_locked "$root" >/dev/null 2>&1 || true
      rm -f "$inventory" "$drop"; return 74
    }
    history_trace_retired_cleanup "$root" "$slot" "$token" || { rm -f "$inventory" "$drop"; return 74; }
  done < "$drop"
  rmdir "$retired" 2>/dev/null || true
  rm -f "$inventory" "$drop"
}

history_trace_prune() {
  local keep=$1 preserve=${2-} result release_result=0
  rules_lock_is_held history-lifecycle || return 75
  rules_lock_acquire history || return
  set +e
  history_trace_prune_locked "$keep" "$preserve"
  result=$?
  set -e
  rules_lock_release history || release_result=$?
  [ "$result" -ne 0 ] || result=$release_result
  return "$result"
}

history_publish_trace_locked() {
  local stage=$1 token=$2 kind=$3 root=$4 map_target trace_target ledger ledger_tmp map_published=0 trace_published=0 result=0
  rules_lock_is_held history || return 75
  ledger="$root/token-ledger.tsv"
  map_target="$root/maps/$token.tsv"
  trace_target="$root/traces/$token"
  if [ -e "$root" ] || [ -L "$root" ]; then
    [ -d "$root" ] && [ ! -L "$root" ] || return 65
  fi
  mkdir -p "$root/maps" "$root/traces" || return 73
  [ -d "$root/maps" ] && [ ! -L "$root/maps" ] || return 65
  [ -d "$root/traces" ] && [ ! -L "$root/traces" ] || return 65
  [ ! -e "$map_target" ] && [ ! -L "$map_target" ] || return 70
  [ ! -e "$trace_target" ] && [ ! -L "$trace_target" ] || return 70
  if [ -e "$ledger" ] || [ -L "$ledger" ]; then
    [ -f "$ledger" ] && [ ! -L "$ledger" ] || return 65
    "$BB" awk 'length($0)!=16 || $0 ~ /[^0-9a-f]/ || seen[$0]++ {exit 65}' "$ledger" || return 65
  fi
  ledger_tmp="$root/token-ledger.tsv.tmp.$$"
  if [ -f "$ledger" ]; then cat "$ledger" > "$ledger_tmp" || return 74; else : > "$ledger_tmp" || return 74; fi
  printf '%s\n' "$token" >> "$ledger_tmp" || { rm -f "$ledger_tmp"; return 74; }

  mv "$stage/map.tsv" "$map_target" || result=74
  [ "$result" -ne 0 ] || map_published=1
  if [ "$result" -eq 0 ]; then
    mv "$stage/trace" "$trace_target" || result=74
    [ "$result" -ne 0 ] || trace_published=1
  fi
  if [ "$result" -eq 0 ]; then
    atomic_replace_file "$ledger_tmp" "$ledger" || result=$?
  fi
  if [ "$result" -ne 0 ]; then
    rm -f "$ledger_tmp"
    [ "$trace_published" -eq 0 ] || rm -rf "$trace_target"
    [ "$map_published" -eq 0 ] || rm -f "$map_target"
    return "$result"
  fi
}

history_prepare_trace() {
  local source=$1 generation=$2 mode=$3 result=0 maximum temp token root kind
  [ "$#" -eq 3 ] || return 64
  maximum=${HISTORY_TRACE_MAX_DOMAINS:-$HISTORY_TRACE_MAX_DOMAINS_DEFAULT}
  case "$maximum" in ''|*[!0-9]*) return 65 ;; esac
  [ "${#maximum}" -le 6 ] || return 65
  [ "$maximum" -ge 1 ] && [ "$maximum" -le "$HISTORY_TRACE_MAX_DOMAINS_DEFAULT" ] || return 65
  mkdir -p "$RULE_TMP" || return 73
  temp=$(mktemp -d "$RULE_TMP/history-trace.XXXXXX") || return 73
  history_source_copy_validate "$source" "$generation" "$mode" "$temp/source" || result=$?
  if [ "$result" -eq 0 ]; then
    : > "$temp/domains" || result=74
  fi
  if [ "$result" -eq 0 ]; then
    history_hosts_extract_domains "$temp/source" "$temp/domains" "$maximum" "$temp/passthrough" || result=$?
  fi
  if [ "$result" -eq 0 ]; then
    history_map_build "$temp/domains" "$temp/map.tsv" || result=$?
  fi
  if [ "$result" -eq 0 ]; then
    rules_lock_acquire history || result=$?
  fi
  if [ "$result" -eq 0 ]; then
    token=$(history_token_new) || result=$?
  fi
  kind=${HISTORY_SOURCE_KIND-}
  if [ "$result" -eq 0 ]; then
    mkdir "$temp/trace" || result=73
  fi
  if [ "$result" -eq 0 ]; then
    history_trace_hosts_build "$temp/map.tsv" "$temp/passthrough" "$temp/trace/$kind" || result=$?
  fi
  if [ "$result" -eq 0 ]; then
    history_trace_manifest_write "$temp/trace/manifest.prop" "$token" "$generation" "$mode" "$kind" "$HISTORY_SOURCE_SHA256" "$temp/map.tsv" "$temp/trace/$kind" || result=$?
  fi
  if [ "$result" -eq 0 ]; then
    chmod 0444 "$temp/map.tsv" "$temp/trace/$kind" "$temp/trace/manifest.prop" || result=74
    [ "$result" -ne 0 ] || chmod 0555 "$temp/trace" || result=74
  fi
  root=$(history_root)
  if [ "$result" -eq 0 ]; then
    history_publish_trace_locked "$temp" "$token" "$kind" "$root" || result=$?
  fi
  case " ${RULE_HELD_LOCKS-} " in
    *' history '*) rules_lock_release history || [ "$result" -ne 0 ] || result=$? ;;
  esac
  rm -rf "$temp"
  [ "$result" -eq 0 ] || return "$result"
  printf '%s\n' "$token"
}

history_active_paused() {
  local file="$RULE_RUNTIME/active.prop" mode
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  mode=$($BB awk -F= '$1=="active_mode"{print $2}' "$file" 2>/dev/null || true)
  [ "$mode" = paused ]
}

history_boot_enabled() {
  local file
  file=$(history_config_file)
  history_config_validate "$file" >/dev/null 2>&1 || return 1
  [ "$(history_config_get)" = 1 ] || return 1
  ! history_active_paused
}

history_firewall() {
  /system/bin/sh "$MODDIR/firewall_manager.sh" "$@"
}

history_process() {
  /system/bin/sh "$MODDIR/process_manager.sh" "$@"
}

history_mount_normal() {
  /system/bin/sh "$MODDIR/rule_engine.sh" history-mount-normal
}

history_mount_trace() {
  /system/bin/sh "$MODDIR/rule_engine.sh" history-mount-trace "$1"
}

history_active_normal_tuple() {
  local file="$RULE_RUNTIME/active.prop" kind
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  kind=$($BB awk -F= '$1=="active_mount_kind"{print $2}' "$file")
  [ "$kind" = normal ] || return 76
  HISTORY_ACTIVE_GENERATION=$($BB awk -F= '$1=="active_generation"{print $2}' "$file")
  HISTORY_ACTIVE_MODE=$($BB awk -F= '$1=="active_mode"{print $2}' "$file")
  history_generation_valid "$HISTORY_ACTIVE_GENERATION" || return 65
  case "$HISTORY_ACTIVE_MODE" in
    block_all) HISTORY_ACTIVE_SOURCE="$RULE_GENERATIONS/$HISTORY_ACTIVE_GENERATION/all" ;;
    preserve_reward) HISTORY_ACTIVE_SOURCE="$RULE_GENERATIONS/$HISTORY_ACTIVE_GENERATION/reward" ;;
    paused) return 75 ;;
    *) return 65 ;;
  esac
  [ -f "$HISTORY_ACTIVE_SOURCE" ] && [ ! -L "$HISTORY_ACTIVE_SOURCE" ] || return 66
  export HISTORY_ACTIVE_GENERATION HISTORY_ACTIVE_MODE HISTORY_ACTIVE_SOURCE
}

history_enable_compensate() {
  local failures=0
  history_mount_normal || failures=$((failures + 1))
  history_firewall history-uninstall || failures=$((failures + 1))
  history_process flush-stop history-reader || failures=$((failures + 1))
  [ "$failures" -eq 0 ] || return 76
}

history_enable_locked() {
  local force=${1:-0} enabled token result=0 probe_result=0 error_code stage_status=0
  rules_lock_is_held history-lifecycle || return 75
  [ "$force" = 0 ] || [ "$force" = 1 ] || return 65
  history_active_paused && return 75
  history_enable_error_clear || return
  history_config_bootstrap || return
  enabled=$(history_config_get) || return
  [ "$enabled" = 0 ] || [ "$force" = 1 ] || return 0
  history_firewall history-probe || probe_result=$?
  if [ "$probe_result" -ne 0 ]; then
    if [ "$probe_result" -eq 69 ]; then
      history_capability_write unsupported nflog_unsupported || return
      history_enable_error_write nflog_unsupported "$probe_result" >/dev/null 2>&1 || true
    else
      history_enable_error_write history_probe_failed "$probe_result" >/dev/null 2>&1 || true
    fi
    return "$probe_result"
  fi
  history_capability_write available - || {
    result=$?
    history_enable_error_write history_state_commit_failed "$result" >/dev/null 2>&1 || true
    return "$result"
  }
  history_active_normal_tuple || {
    result=$?
    history_enable_error_write history_rules_unavailable "$result" >/dev/null 2>&1 || true
    return "$result"
  }
  history_trace_prune $((HISTORY_TRACE_RETAIN - 1)) '' || {
    result=$?
    history_enable_error_write history_trace_prepare_failed "$result" >/dev/null 2>&1 || true
    return "$result"
  }
  token=$(history_prepare_trace "$HISTORY_ACTIVE_SOURCE" "$HISTORY_ACTIVE_GENERATION" "$HISTORY_ACTIVE_MODE") || {
    result=$?
    history_enable_error_write history_trace_prepare_failed "$result" >/dev/null 2>&1 || true
    return "$result"
  }
  if [ "$result" -eq 0 ]; then
    history_process start-ready history-reader "$token" || {
      stage_status=$?
      result=74
      error_code=history_reader_start_failed
    }
  fi
  if [ "$result" -eq 0 ]; then
    history_firewall history-install "$token" || {
      stage_status=$?
      result=74
      error_code=history_firewall_install_failed
    }
  fi
  if [ "$result" -eq 0 ]; then
    history_mount_trace "$token" || {
      stage_status=$?
      result=74
      error_code=history_mount_failed
    }
  fi
  if [ "$result" -eq 0 ]; then
    history_config_set_internal 1 || {
      result=$?
      stage_status=$result
      error_code=history_state_commit_failed
    }
  fi
  if [ "$result" -ne 0 ]; then
    history_enable_error_write "$error_code" "$stage_status" >/dev/null 2>&1 || true
    if ! history_enable_compensate; then
      history_enable_error_write history_recovery_failed 76 >/dev/null 2>&1 || true
      return 76
    fi
    return "$result"
  fi
  history_enable_error_clear || return
}

history_enable() {
  local result
  history_active_paused && return 75
  rules_lock_acquire history-lifecycle || return
  set +e
  history_enable_locked
  result=$?
  set -e
  rules_lock_release history-lifecycle || return
  return "$result"
}

history_disable_locked() {
  local failures=0
  rules_lock_is_held history-lifecycle || return 75
  history_active_paused && return 75
  history_config_bootstrap || return
  history_mount_normal || failures=$((failures + 1))
  history_firewall history-disable || failures=$((failures + 1))
  history_process flush-stop history-reader || failures=$((failures + 1))
  history_config_set_internal 0 || failures=$((failures + 1))
  [ "$failures" -ne 0 ] || history_enable_error_clear || failures=$((failures + 1))
  [ "$failures" -eq 0 ] || return 76
}

history_disable() {
  local result
  history_active_paused && return 75
  rules_lock_acquire history-lifecycle || return
  set +e
  history_disable_locked
  result=$?
  set -e
  rules_lock_release history-lifecycle || return
  return "$result"
}

history_clear() {
  local result=0 release_result=0 enabled=0 map_token
  history_active_paused && return 75
  rules_lock_acquire history-lifecycle || return
  history_config_bootstrap || result=$?
  if [ "$result" -eq 0 ]; then enabled=$(history_config_get) || result=$?; fi
  if [ "$result" -eq 0 ] && [ "$enabled" = 1 ]; then
    history_firewall history-disable || result=$?
  fi
  if [ "$result" -eq 0 ] && [ "$enabled" = 1 ]; then
    history_process flush-stop history-reader || result=$?
  fi
  if [ "$result" -eq 0 ]; then
    rm -f "$RULE_RUNTIME/history/events.tsv" "$RULE_RUNTIME/history/events.tsv.1" || result=74
  fi
  if [ "$result" -eq 0 ] && [ "$enabled" = 1 ]; then
    map_token=$(history_current_token 2>/dev/null || true)
    history_token_valid "$map_token" || result=70
  fi
  if [ "$result" -eq 0 ] && [ "$enabled" = 1 ]; then
    history_process start-ready history-reader "$map_token" || result=$?
  fi
  if [ "$result" -eq 0 ] && [ "$enabled" = 1 ]; then
    history_firewall history-install "$map_token" || result=$?
    if [ "$result" -ne 0 ]; then
      history_process flush-stop history-reader >/dev/null 2>&1 || true
    fi
  fi
  release_result=0
  rules_lock_release history-lifecycle || release_result=$?
  [ "$result" -ne 0 ] || result=$release_result
  return "$result"
}

history_uninstall_marker_valid() {
  local file="$RULE_RUNTIME/uninstalling"
  [ -f "$file" ] && [ ! -L "$file" ] || return 75
  "$BB" awk -F= '
    function bad(){exit 75}
    NF!=2{bad()}
    $1!~/^(schema_version|state|started_at|pid)$/{bad()}
    seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    $1=="state" && $2!="uninstalling"{bad()}
    ($1=="started_at" || $1=="pid") && $2!~/^[0-9]+$/{bad()}
    END{if(NR!=4 || !seen["schema_version"] || !seen["state"] || !seen["started_at"] || !seen["pid"])bad()}
  ' "$file"
}

history_cleanup_uninstall_locked() {
  local failures=0 reader_stopped=0 normal_restored=0
  rules_lock_is_held history-lifecycle || return 75
  history_uninstall_marker_valid || return
  history_firewall history-disable || failures=$((failures + 1))
  if history_mount_normal; then normal_restored=1; else failures=$((failures + 1)); fi
  history_firewall history-uninstall || failures=$((failures + 1))
  if history_process flush-stop history-reader; then reader_stopped=1; else failures=$((failures + 1)); fi
  if [ "$reader_stopped" -eq 1 ] && [ "$normal_restored" -eq 1 ]; then
    rm -rf "$RULE_RUNTIME/history" || failures=$((failures + 1))
    rm -f "$(history_capability_file)" || failures=$((failures + 1))
    rm -f "$(history_enable_error_file)" || failures=$((failures + 1))
    rm -f "$(history_config_file)" || failures=$((failures + 1))
  fi
  [ "$failures" -eq 0 ] || return 76
}

history_cleanup_uninstall() {
  local result
  rules_init_paths "$MODDIR" || return
  history_uninstall_marker_valid || return
  rules_lock_acquire history-lifecycle || return
  set +e
  history_cleanup_uninstall_locked
  result=$?
  set -e
  rules_lock_release history-lifecycle || return
  return "$result"
}

history_reconcile() {
  local result=0 release_result=0
  if history_active_paused; then
    history_config_bootstrap || return
    rules_lock_acquire history-lifecycle || return
    set +e
    if ! history_firewall history-disable; then
      history_firewall history-uninstall || result=$?
    fi
    [ "$result" -ne 0 ] || history_process flush-stop history-reader || result=$?
    set -e
    release_result=0
    rules_lock_release history-lifecycle || release_result=$?
    [ "$result" -ne 0 ] || result=$release_result
    return "$result"
  fi
  history_boot_enabled || return 0
  rules_lock_acquire history-lifecycle || return
  set +e
  history_mount_normal || result=$?
  if [ "$result" -eq 0 ] && ! history_firewall history-disable; then
    history_firewall history-uninstall || result=$?
  fi
  [ "$result" -ne 0 ] || history_process flush-stop history-reader || result=$?
  [ "$result" -ne 0 ] || history_enable_locked 1 || result=$?
  set -e
  release_result=0
  rules_lock_release history-lifecycle || release_result=$?
  [ "$result" -ne 0 ] || result=$release_result
  return "$result"
}

history_status() {
  local enabled root prepared=0
  history_config_bootstrap || return
  enabled=$(history_config_get) || return
  root=$(history_root)
  if [ -d "$root/traces" ] && [ ! -L "$root/traces" ]; then
    prepared=$("$BB" find "$root/traces" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
  fi
  printf '{"enabled":%s,"preparedCount":%s}\n' "$([ "$enabled" = 1 ] && printf true || printf false)" "$prepared"
}

history_current_token() {
  local token mount file="$RULE_RUNTIME/active.prop"
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  mount=$("$BB" awk -F= '$1=="active_mount_kind"{print $2}' "$file")
  [ "$mount" = trace ] || return 1
  token=$("$BB" awk -F= '$1=="active_map_token"{print $2}' "$file")
  history_token_valid "$token" || return 1
  history_trace_validate "$token" >/dev/null 2>&1 || return 1
  printf '%s\n' "$token"
}

history_runtime_state() {
  local firewall_json process_json active mount token
  HISTORY_RUNTIME_FIREWALL=absent
  HISTORY_RUNTIME_TOKEN=
  HISTORY_RUNTIME_MOUNT=normal
  HISTORY_RUNTIME_MOUNT_TOKEN=
  HISTORY_RUNTIME_PROCESS=stopped
  HISTORY_RUNTIME_LOGGING=0
  HISTORY_RUNTIME_GUARD=0

  firewall_json=$(history_firewall history-status --json 2>/dev/null || true)
  case "$firewall_json" in
    *'"state":"active","mapToken":"'[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'"}'*)
      HISTORY_RUNTIME_FIREWALL=active
      HISTORY_RUNTIME_TOKEN=$(printf '%s\n' "$firewall_json" | "$BB" sed -n 's/.*"mapToken":"\([0-9a-f]\{16\}\)".*/\1/p')
      ;;
    *'"state":"guard","mapToken":"'[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'"}'*)
      HISTORY_RUNTIME_FIREWALL=guard
      HISTORY_RUNTIME_GUARD=1
      HISTORY_RUNTIME_TOKEN=$(printf '%s\n' "$firewall_json" | "$BB" sed -n 's/.*"mapToken":"\([0-9a-f]\{16\}\)".*/\1/p')
      ;;
    *'"state":"incomplete"'*) HISTORY_RUNTIME_FIREWALL=incomplete ;;
    *'"state":"absent"'*) HISTORY_RUNTIME_FIREWALL=absent ;;
  esac

  active="$RULE_RUNTIME/active.prop"
  if [ -f "$active" ] && [ ! -L "$active" ]; then
    mount=$("$BB" awk -F= '$1=="active_mount_kind"{print $2}' "$active")
    token=$("$BB" awk -F= '$1=="active_map_token"{print $2}' "$active")
    case "$mount" in normal) HISTORY_RUNTIME_MOUNT=normal ;; trace) HISTORY_RUNTIME_MOUNT=trace ;; *) HISTORY_RUNTIME_MOUNT=incomplete ;; esac
    history_token_valid "$token" && HISTORY_RUNTIME_MOUNT_TOKEN=$token || HISTORY_RUNTIME_MOUNT_TOKEN=
  else
    HISTORY_RUNTIME_MOUNT=incomplete
  fi

  process_json=$(history_process status --json 2>/dev/null || true)
  case "$process_json" in
    *'"role":"history-reader"'*'"state":"running"'*) HISTORY_RUNTIME_PROCESS=running ;;
  esac
  if [ "$HISTORY_RUNTIME_FIREWALL" = active ] && [ "$HISTORY_RUNTIME_PROCESS" = running ] && \
     [ "$HISTORY_RUNTIME_MOUNT" = trace ] && [ -n "$HISTORY_RUNTIME_TOKEN" ] && \
     [ "$HISTORY_RUNTIME_TOKEN" = "$HISTORY_RUNTIME_MOUNT_TOKEN" ]; then
    HISTORY_RUNTIME_LOGGING=1
  fi
  export HISTORY_RUNTIME_FIREWALL HISTORY_RUNTIME_TOKEN HISTORY_RUNTIME_MOUNT HISTORY_RUNTIME_MOUNT_TOKEN
  export HISTORY_RUNTIME_PROCESS HISTORY_RUNTIME_LOGGING HISTORY_RUNTIME_GUARD
}

# 统计只需要一遍已校验的事件行。拆出来是为了让打包读取复用 history_query_collect
# 已经收集好的那一份：两边各收集一次等于把两个上限 4 MiB 的事件文件白过一遍。
history_event_stats_emit() {
  "$BB" awk -F '\t' '{rows++; count+=$6; dropped+=$7; degraded+=$8} END{printf "%d %d %d %d",rows+0,count+0,dropped+0,degraded+0}' "$1"
}

# $1 给了就当作「收集时顺手算好的统计」直接用，不再自己走一遍事件文件。
# 传的是统计结果而不是事件行：收集会按 token 过滤事件行，拿过滤后的行重算会改掉计数含义。
history_status_json() {
  local collected=${1--} enabled=0 root tmp stats event_rows=0 count=0 dropped=0 degraded=0
  local state=disabled json_token=null availability=unknown error=null file cutoff
  history_config_bootstrap || return
  enabled=$(history_config_get) || return
  root=$(history_root)
  if history_capability_load 2>/dev/null; then
    availability=$HISTORY_CAPABILITY_AVAILABILITY
    [ "$HISTORY_CAPABILITY_ERROR" = - ] || error="\"$HISTORY_CAPABILITY_ERROR\""
  fi
  if history_enable_error_validate 2>/dev/null; then
    error="\"$HISTORY_ENABLE_ERROR_CODE\""
  fi
  if [ "$collected" != - ]; then
    [ -f "$collected" ] && [ ! -L "$collected" ] || return 70
    stats=$(cat "$collected") || return 74
    # 四个十进制数，别的一律不认——统计文件坏了要报错，不能悄悄当 0 显示。
    case "$stats" in
      *[!0-9\ ]*|'') return 74 ;;
    esac
    [ "$(printf '%s\n' "$stats" | "$BB" awk '{print NF}')" = 4 ] || return 74
  else
    tmp="$RULE_TMP/history-status.$$"
    : > "$tmp" || return 74
    # 和 history_query_collect 用同一个截止时刻。少了这个 cutoff，单独读状态会把已经
    # 过期的行也算进拦截次数，而打包读取复用的是收集时按 cutoff 算好的统计——同一个界面
    # 会因为走哪条路而显示两个不同的数字，标题里的条数还会指向列表里根本没有的记录。
    cutoff=$(history_retention_cutoff)
    for file in "$root/events.tsv.1" "$root/events.tsv"; do
      [ -e "$file" ] || [ -L "$file" ] || continue
      [ -f "$file" ] && [ ! -L "$file" ] || { rm -f "$tmp"; return 70; }
      history_event_file_append_valid "$file" "$tmp" "$cutoff" || { rm -f "$tmp"; return 74; }
    done
    stats=$(history_event_stats_emit "$tmp") || { rm -f "$tmp"; return 74; }
    rm -f "$tmp"
  fi
  set -- $stats
  event_rows=$1; count=$2; dropped=$3; degraded=$4

  history_runtime_state || return
  if [ "$enabled" = 1 ]; then
    if history_active_paused; then
      if [ "$HISTORY_RUNTIME_LOGGING" = 0 ] && [ "$HISTORY_RUNTIME_FIREWALL" = absent ] && \
        [ "$HISTORY_RUNTIME_PROCESS" = stopped ] && [ "$HISTORY_RUNTIME_MOUNT" = normal ] && \
        [ "$HISTORY_RUNTIME_GUARD" = 0 ]; then
        state=stopped
      else
        state=incomplete
        [ "$error" != null ] || error='"history_runtime_incomplete"'
      fi
    elif [ "$HISTORY_RUNTIME_LOGGING" = 1 ]; then
      state=active
    elif [ "$HISTORY_RUNTIME_FIREWALL" = active ] && [ "$HISTORY_RUNTIME_MOUNT" = trace ]; then
      state=stopped
      error='"history_reader_stopped"'
    else
      state=incomplete
      error='"history_runtime_incomplete"'
    fi
  fi
  if history_token_valid "$HISTORY_RUNTIME_TOKEN"; then json_token="\"$HISTORY_RUNTIME_TOKEN\""; fi
  printf '{"enabled":%s,"availability":"%s","state":"%s","logging":%s,"guardActive":%s,"mapToken":%s,"eventRowCount":%s,"interceptionCount":%s,"droppedCount":%s,"degradedCount":%s,"lastError":%s}\n' \
    "$([ "$enabled" = 1 ] && printf true || printf false)" "$availability" "$state" \
    "$([ "$HISTORY_RUNTIME_LOGGING" = 1 ] && printf true || printf false)" \
    "$([ "$HISTORY_RUNTIME_GUARD" = 1 ] && printf true || printf false)" "$json_token" \
    "$event_rows" "$count" "$dropped" "$degraded" "$error"
}

# 事件文件的变化签名：每个文件只 stat 取大小和 mtime。
# 刻意不做统计——history_status_json 要把两个事件文件（上限各 4 MiB）过一遍 awk，
# 拿它当轮询源就是按秒烧电。
history_pulse_signature() {
  local root file signature= size mtime
  root=$(history_root)
  for file in "$root/events.tsv.1" "$root/events.tsv"; do
    if [ -f "$file" ] && [ ! -L "$file" ]; then
      size=$("$BB" stat -c %s "$file" 2>/dev/null) || size=0
      mtime=$("$BB" stat -c %Y "$file" 2>/dev/null) || mtime=0
      case "$size:$mtime" in *[!0-9:]*) size=0; mtime=0 ;; esac
    else
      size=0
      mtime=0
    fi
    signature="$signature$size.$mtime-"
  done
  printf '%s\n' "$signature"
}

# 变化探针：只回答「事件文件动过没有」，供界面在日志页可见时轮询。
# 签名没变就什么都不用做；变了界面才去做一次真正的读取。
history_pulse_json() {
  local enabled logging=false signature
  history_config_bootstrap || return
  enabled=$(history_config_get) || return
  signature=$(history_pulse_signature) || return
  # 读取进程是否在跑决定界面还要不要继续轮询：停了就没有新事件可等。
  if [ "$enabled" = 1 ]; then
    history_runtime_state 2>/dev/null || true
    [ "${HISTORY_RUNTIME_LOGGING-0}" = 1 ] && logging=true || logging=false
  fi
  printf '{"enabled":%s,"logging":%s,"signature":"%s"}\n' \
    "$([ "$enabled" = 1 ] && printf true || printf false)" "$logging" "$signature"
}

history_packages_json_from_normalized() {
  local uid=$1 normalized=$2 app_uid
  history_uint_valid "$uid" 4294967294 0 || return 65
  app_uid=$((uid % 100000))
  "$BB" awk -F '\t' -v uid="$app_uid" '
    BEGIN{printf "["}
    $1==uid && count<128 {if(count++)printf ","; printf "\"%s\"",$2}
    END{printf "]"}
  ' "$normalized"
}

history_uint_valid() {
  decimal_uint_in_range "$@"
}

history_domain_filter_valid() {
  printf '%s\n' "$1" | LC_ALL=C "$BB" awk '
    NR!=1 || length($0)<1 || length($0)>253 || $0!=tolower($0) || $0!~/^[a-z0-9._-]+$/ {exit 1}
  '
}

history_packages_normalize() {
  local output=$1 file=${HISTORY_PACKAGES_FILE:-/data/system/packages.list} bytes
  : > "$output" || return 74
  [ -e "$file" ] || [ -L "$file" ] || return 0
  [ -f "$file" ] && [ ! -L "$file" ] || return 70
  bytes=$(wc -c < "$file" | "$BB" tr -d ' ') || return 74
  history_uint_valid "$bytes" 8388608 0 || return 70
  "$BB" awk '
    function package_valid(p,n,a,i){
      if(length(p)<1 || length(p)>255 || p~/^\./ || p~/\.$/ || p~/\.\./) return 0
      n=split(p,a,".")
      for(i=1;i<=n;i++) if(a[i]!~/^[A-Za-z_][A-Za-z0-9_]*$/) return 0
      return 1
    }
    function uid_valid(v){return v~/^[0-9]+$/ && length(v)<=10 && v+0<=4294967294}
    function path_valid(v){return v=="null" || v~/^\/[A-Za-z0-9_.\/-]+$/}
    function seinfo_valid(v){return v~/^[A-Za-z0-9_.:+=-]+$/}
    function gids_valid(v){return v=="none" || v~/^[0-9]+(,[0-9]+)*$/}
    NF<6 || NF>10 || !package_valid($1) || !uid_valid($2) || $3!~/^[01]$/ ||
      !path_valid($4) || !seinfo_valid($5) || !gids_valid($6) {next}
    NF>=7 && $7!~/^[01]$/ {next}
    NF>=8 && $8!~/^[0-9]+$/ {next}
    NF>=9 && $9!~/^[01]$/ {next}
    NF==10 && $10!~/^(@[A-Za-z]+|[A-Za-z_][A-Za-z0-9_.]*)$/ {next}
    {packages[($2+0) SUBSEP $1]=1; rows++; if(rows>100000)exit 70}
    END{if(rows<=100000)for(key in packages){split(key,a,SUBSEP); print a[1] "\t" a[2]}}
  ' "$file" | LC_ALL=C "$BB" sort -t "$(printf '\t')" -k1,1n -k2,2 > "$output.sorted" || {
    rm -f "$output" "$output.sorted"
    return 70
  }
  atomic_replace_file "$output.sorted" "$output" || { rm -f "$output" "$output.sorted"; return 74; }
}

# 事件行的唯一入口：格式校验 + 保留期过滤。两件事放在同一遍 awk 里，
# 免得为了过期过滤再把 4 MiB 过一趟。
history_event_file_append_valid() {
  local file=$1 output=$2 cutoff=${3:-0}
  "$BB" awk -F '\t' -v cutoff="$cutoff" '
    function uint(v,max,min){return v~/^[0-9]+$/ && length(v)<=16 && v+0>=min && v+0<=max}
    function token_valid(v){return length(v)==16 && v~/^[0-9a-f]+$/}
    function octet(v){return v~/^[0-9]+$/ && v+0<=255 && (v=="0" || v!~/^0/)}
    function address_valid(v,n,a){
      n=split(v,a,".")
      return n==4 && a[1]==127 && octet(a[2]) && a[2]+0>=64 && a[2]+0<=71 && octet(a[3]) && octet(a[4])
    }
    NF==8 && uint($1,9007199254740991,0) && $1+0>=cutoff && token_valid($2) && address_valid($3) &&
      uint($4,4294967294,0) && uint($5,65535,1) && uint($6,4294967295,1) &&
      uint($7,4294967295,0) && uint($8,4294967295,0) {print}
  ' "$file" >> "$output"
}

# 映射校验结果的缓存键：映射与清单各自的 inode、大小、mtime。
# 这两份文件都是发布时一次写成、之后只读（换 token 会换路径），所以三元组没变
# 就是同一份字节，不需要为每次查询把 500k 行的映射重新 sha256 一遍。
# 映射一侧的重活（整文件 sha256 + wc + 逐行结构校验）按 500k 行计，而界面每读一次记录
# （轮询命中、换筛选条件、翻页）都要为每个保留世代做一遍。映射建好之后就不再改，
# 所以用 inode.大小.mtime 做键把「已经完整校验过」这件事记下来。
#
# 这个键的分辨率是秒（stat %Y 没有可移植的纳秒字段）。也就是说：同 inode、同大小、
# 且在同一秒内的原地改写不会被这一层看出来。这不降低整体门槛——那种改写需要 root 对
# 运行目录的写权限，而缓存文件本身就在同一棵 root-only 目录里，能那样改映射的人同样能直接
# 伪造缓存。原子替换会换 inode，正常重建又会换清单里的哈希（哈希也在键里），都必然不命中。
history_query_map_stamp() {
  local map=$1 manifest=$2 stamp
  stamp=$("$BB" stat -c '%i.%s.%Y' "$map" "$manifest" 2>/dev/null | "$BB" tr '\n' '-') || return 1
  case "$stamp" in ''|*[!0-9.-]*) return 1 ;; esac
  # 两个文件各一行，缺一行说明 stat 没全拿到，宁可当未命中去做全量校验。
  [ "$("$BB" printf '%s' "$stamp" | "$BB" tr -cd '-' | "$BB" wc -c | "$BB" tr -d ' ')" = 2 ] || return 1
  printf '%s\n' "$stamp"
}

# 放在 history 根里，卸载时的 rm -rf "$RULE_RUNTIME/history" 就顺带清掉了，
# 不用再往 history_cleanup_uninstall_locked 里加一条单独的删除。
history_query_map_cache_file() {
  printf '%s\n' "$(history_root)/map-verified.tsv"
}

# 缓存命中：同 token 同三元组已经完整校验过。缓存文件本身坏了一律当未命中。
history_query_map_cache_hit() {
  local token=$1 stamp=$2 cache
  cache=$(history_query_map_cache_file)
  [ -f "$cache" ] && [ ! -L "$cache" ] || return 1
  "$BB" awk -F '\t' -v token="$token" -v stamp="$stamp" '
    NF==3 && $1=="1" && $2==token && $3==stamp {found=1; exit}
    END{exit found?0:1}
  ' "$cache"
}

history_query_map_cache_store() {
  local token=$1 stamp=$2 cache tmp
  cache=$(history_query_map_cache_file)
  tmp="$cache.$$"
  # 只留当前 token 的一行：换 token 后旧行没有用处，留着只会让缓存无界增长。
  printf '1\t%s\t%s\n' "$token" "$stamp" > "$tmp" || { rm -f "$tmp"; return 0; }
  atomic_replace_file "$tmp" "$cache" 2>/dev/null || rm -f "$tmp"
  return 0
}

history_query_map_validate() {
  local token=$1 map=$2 manifest=$3 manifest_token expected actual count expected_count stamp
  history_token_valid "$token" || return 65
  [ -f "$map" ] && [ ! -L "$map" ] || return 70
  [ -f "$manifest" ] && [ ! -L "$manifest" ] || return 70
  # 清单一侧的校验每次都做：它只有十几行，代价可以忽略，而它是 token 与哈希的来源。
  # 缓存只跳过映射一侧的重活（整文件 sha256 + wc + 逐行结构校验），
  # 那才是每次查询里按 500k 行计的部分。
  history_trace_manifest_validate "$manifest" "$token" >/dev/null 2>&1 || return 70
  manifest_token=$(history_manifest_get_unique "$manifest" map_token) || return 70
  [ "$manifest_token" = "$token" ] || return 70
  expected=$(history_manifest_get_unique "$manifest" map_sha256) || return 70
  if stamp=$(history_query_map_stamp "$map" "$manifest"); then
    # 缓存键里带上清单里记的哈希：清单被换过（哈希变了）就一定不命中。
    stamp="$stamp$expected"
    history_query_map_cache_hit "$token" "$stamp" && return 0
  else
    stamp=
  fi
  actual=$(sha256_file "$map") || return 70
  [ "$actual" = "$expected" ] || return 70
  expected_count=$(history_manifest_get_unique "$manifest" rule_count) || return 70
  count=$(wc -l < "$map" | "$BB" tr -d ' ') || return 70
  [ "$count" = "$expected_count" ] || return 70
  "$BB" awk -F '\t' '
    function valid_domain(d, n,a,i){
      if(length(d)<1 || length(d)>253 || d!=tolower(d) || d~/^[0-9.]+$/ || d~/^\./ || d~/\.$/ || d~/\.\./) return 0
      n=split(d,a,".")
      for(i=1;i<=n;i++) if(length(a[i])<1 || length(a[i])>63 || a[i]!~/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) return 0
      return 1
    }
    function valid_octet(v){return v~/^[0-9]+$/ && v+0<=255 && (v=="0" || v!~/^0/)}
    function valid_address(v,n,a){
      n=split(v,a,".")
      return n==4 && a[1]==127 && valid_octet(a[2]) && a[2]+0>=64 && a[2]+0<=71 && valid_octet(a[3]) && valid_octet(a[4])
    }
    NF!=2 || !valid_address($1) || !valid_domain($2) || addresses[$1]++ || domains[$2]++ {exit 1}
  ' "$map" || return 70
  [ -z "$stamp" ] || history_query_map_cache_store "$token" "$stamp"
}

history_query_collect() {
  local output=$1 root file token tokens token_map manifest valid_tokens cutoff mtime
  root=$(history_root)
  cutoff=$(history_retention_cutoff)
  tokens="$output.tokens"
  valid_tokens="$output.valid-tokens"
  : > "$output" || return 74
  : > "$tokens" || { rm -f "$output"; return 74; }
  : > "$valid_tokens" || { rm -f "$output" "$tokens"; return 74; }
  : > "$output.maps" || { rm -f "$output" "$tokens"; return 74; }
  for file in "$root/events.tsv.1" "$root/events.tsv"; do
    [ -e "$file" ] || [ -L "$file" ] || continue
    [ -f "$file" ] && [ ! -L "$file" ] || { rm -f "$output" "$tokens"; return 70; }
    # 整代过期就直接删掉：行是按时间追加的，mtime 就是这一代里最新一行的时刻，
    # 比它更早的行不可能存在。读取进程停着时（关掉记录之后）也只有这条路径会来清，
    # 所以「超时不保留」不依赖读取进程还活着。
    if [ "$cutoff" -gt 0 ]; then
      mtime=$("$BB" stat -c %Y "$file" 2>/dev/null) || mtime=
      case "$mtime" in ''|*[!0-9]*) mtime= ;; esac
      if [ -n "$mtime" ] && [ "$mtime" -lt "$cutoff" ]; then
        rm -f "$file"
        continue
      fi
    fi
    history_event_file_append_valid "$file" "$output" "$cutoff" || { rm -f "$output" "$tokens" "$output.maps"; return 74; }
  done
  "$BB" awk -F '\t' '{print $2}' "$output" > "$tokens" || { rm -f "$output" "$tokens" "$output.maps"; return 74; }
  LC_ALL=C "$BB" sort -u "$tokens" > "$tokens.sorted" || { rm -f "$output" "$tokens" "$tokens.sorted"; return 74; }
  while IFS= read -r token; do
    [ -n "$token" ] || continue
    token_map="$root/maps/$token.tsv"
    manifest="$root/traces/$token/manifest.prop"
    if [ ! -e "$token_map" ] && [ ! -L "$token_map" ] && \
       [ ! -e "$manifest" ] && [ ! -L "$manifest" ]; then
      continue
    fi
    # 映射或清单还在、但校验不过，说明内容被改过：这是完整性失败，必须整次查询失败，
    # 不能只丢这个 token 的行悄悄往下走——那样篡改就被一屏「记录少了几条」盖过去了。
    # 「世代被裁剪、映射整个没了」是另一回事，上面那个分支已经放过去了。
    history_query_map_validate "$token" "$token_map" "$manifest" || {
      rm -f "$output" "$tokens" "$tokens.sorted" "$valid_tokens" "$output.maps"
      return 70
    }
    printf '%s\n' "$token" >> "$valid_tokens" || {
      rm -f "$output" "$tokens" "$tokens.sorted" "$valid_tokens" "$output.maps"
      return 74
    }
    "$BB" awk -F '\t' -v token="$token" '{print token "\t" $1 "\t" $2}' "$token_map" >> "$output.maps" || {
      rm -f "$output" "$tokens" "$tokens.sorted" "$valid_tokens" "$output.maps"
      return 74
    }
  done < "$tokens.sorted"
  # 统计要在按 token 过滤之前取。过滤会把「映射已被裁剪掉」的事件行丢掉——列表和应用
  # 清单本来就解析不出域名，丢掉是对的；但拦截次数是累计量，之前一直把这些行算在内。
  # 拿过滤后的行去统计会让日志页显示的次数比别处少，那是白改了用户看得见的数字。
  if [ "${HISTORY_COLLECT_STATS-0}" = 1 ]; then
    history_event_stats_emit "$output" > "$output.stats" || {
      rm -f "$output" "$tokens" "$tokens.sorted" "$valid_tokens" "$output.maps" "$output.stats"
      return 74
    }
  fi
  "$BB" awk -F '\t' 'NR==FNR{valid[$1]=1;next} valid[$2]' "$valid_tokens" "$output" > "$output.filtered" || {
    rm -f "$output" "$tokens" "$tokens.sorted" "$valid_tokens" "$output.maps" "$output.filtered"
    return 74
  }
  atomic_replace_file "$output.filtered" "$output" || {
    rm -f "$output" "$tokens" "$tokens.sorted" "$valid_tokens" "$output.maps" "$output.filtered"
    return 74
  }
  rm -f "$tokens" "$tokens.sorted" "$valid_tokens"
}

# 查询参数校验与域名过滤串解码。解出来的过滤串放在 HISTORY_QUERY_FILTER，
# 让单独查询和打包查询共用同一套校验，不用各写一遍。
history_query_prepare() {
  local tmp=$1 cursor=$2 limit=$3 since=$4 uid=$5 port=$6 domain_b64=$7 canonical decoded_bytes
  HISTORY_QUERY_FILTER=
  history_uint_valid "$cursor" 50000 0 || return 65
  history_uint_valid "$limit" 200 1 || return 65
  history_uint_valid "$since" 9223372036854775807 0 || return 65
  [ "$uid" = - ] || history_uint_valid "$uid" 4294967294 0 || return 65
  [ "$port" = - ] || history_uint_valid "$port" 65535 1 || return 65
  [ "$domain_b64" != - ] || return 0
  case "$domain_b64" in ''|*[!A-Za-z0-9+/=]*) return 65 ;; esac
  [ "${#domain_b64}" -le 340 ] || return 65
  [ $(( ${#domain_b64} % 4 )) -eq 0 ] || return 65
  printf '%s' "$domain_b64" | "$BB" base64 -d > "$tmp.domain" 2>/dev/null || { rm -f "$tmp.domain"; return 65; }
  canonical=$("$BB" base64 "$tmp.domain" | "$BB" tr -d '\n') || { rm -f "$tmp.domain"; return 65; }
  [ "$canonical" = "$domain_b64" ] || { rm -f "$tmp.domain"; return 65; }
  decoded_bytes=$(wc -c < "$tmp.domain" | "$BB" tr -d ' ') || { rm -f "$tmp.domain"; return 65; }
  [ "$decoded_bytes" -le 253 ] || { rm -f "$tmp.domain"; return 65; }
  HISTORY_QUERY_FILTER=$(cat "$tmp.domain")
  rm -f "$tmp.domain"
  [ "${#HISTORY_QUERY_FILTER}" -eq "$decoded_bytes" ] || return 65
  history_domain_filter_valid "$HISTORY_QUERY_FILTER" || return 65
}

# 从已经收集好的 $tmp（事件）、$tmp.maps（域名映射）、$tmp.packages（包名）出一页 JSON。
# 不再自己收集，交给调用方决定收集几次——打包读取就靠这个只收集一次。
# $8 给了就把它当事件签名一起写进这一页 JSON（打包读取传 - ，因为它在顶层已经带了一份）。
# 单独查询也要带签名：界面用它当轮询基线，缺了的话「改筛选条件」那条路径读完之后基线仍是旧的，
# 下一轮探针必然比出不同，于是白做一次整包读取。
history_query_emit() {
  local tmp=$1 cursor=$2 limit=$3 since=$4 uid=$5 port=$6 filter=$7 signature=${8--}
  local line epoch domain ev_uid ev_port token count dropped degraded emitted=0 has_more=false next result=0 total
  "$BB" awk -F '\t' -v maps="$tmp.maps" -v since="$since" -v wanted_uid="$uid" -v wanted_port="$port" -v filter="$filter" '
    BEGIN {
      while((getline < maps)>0) domains[$1 SUBSEP $2]=$3
      close(maps)
    }
    {
      domain=domains[$2 SUBSEP $3]
      if(domain=="" || $1+0<since || (wanted_uid!="-" && $4!=wanted_uid) || (wanted_port!="-" && $5!=wanted_port) || (filter!="" && index(domain,filter)==0)) next
      key=$2 SUBSEP $3 SUBSEP $4 SUBSEP $5
      count[key]+=$6; dropped[key]+=$7; degraded[key]+=$8
      if($1+0>=epoch[key]) epoch[key]=$1+0
      token[key]=$2; address[key]=$3; uid[key]=$4; port[key]=$5; resolved[key]=domain
    }
    END {
      for(key in count) printf "%019d\t%.0f\t%s\t%s\t%s\t%s\t%.0f\t%.0f\t%.0f\n", epoch[key], epoch[key], resolved[key], uid[key], port[key], token[key], count[key], dropped[key], degraded[key]
    }
  ' "$tmp" | LC_ALL=C "$BB" sort -t "$(printf '\t')" -k1,1nr -k2,2 -k3,3n -k4,4n > "$tmp.sorted" || result=74
  [ "$result" -eq 0 ] || return "$result"
  # 聚合后的总条数。分页要显示「第几页 / 共几页」，靠 hasMore 只能知道「还有」，
  # 数不出总数；这里已经有排好序的整份结果，多一个 wc -l 就够，不必再过一遍事件文件。
  total=$("$BB" wc -l < "$tmp.sorted" | "$BB" tr -d ' ') || result=74
  case "$total" in ''|*[!0-9]*) total=0 ;; esac
  [ "$result" -eq 0 ] || return "$result"
  printf '{"cursor":%s,"total":%s,"items":[' "$cursor" "$total"
  "$BB" tail -n "+$((cursor + 1))" "$tmp.sorted" > "$tmp.page" || result=74
  while IFS=$(printf '\t') read -r line epoch domain ev_uid ev_port token count dropped degraded; do
    if [ "$emitted" -ge "$limit" ]; then has_more=true; break; fi
    [ "$emitted" -eq 0 ] || printf ','
    printf '{"epoch":%s,"domain":"%s","uid":%s,"packages":%s,"protocol":"tcp","port":%s,"count":%s,"dropped":%s,"degraded":%s}' \
      "$epoch" "$(printf '%s' "$domain" | json_escape)" "$ev_uid" "$(history_packages_json_from_normalized "$ev_uid" "$tmp.packages")" "$ev_port" "$count" "$dropped" "$degraded"
    emitted=$((emitted + 1))
  done < "$tmp.page"
  next=$((cursor + emitted))
  printf '],"nextCursor":%s,"hasMore":%s' "$next" "$has_more"
  [ "$signature" = - ] || printf ',"signature":"%s"' "$signature"
  printf '}\n'
  return "$result"
}

history_query_json() {
  local cursor=$1 limit=$2 since=$3 uid=$4 port=$5 domain_b64=$6 tmp signature result=0
  [ "$#" -eq 6 ] || return 64
  tmp="$RULE_TMP/history-query.$$"
  rm -f "$tmp" "$tmp".*
  history_query_prepare "$tmp" "$cursor" "$limit" "$since" "$uid" "$port" "$domain_b64" || return
  # 与打包读取同理：签名取在读事件文件之前，宁可多读一次也不要漏掉收集期间新到的事件。
  signature=$(history_pulse_signature) || return 74
  history_query_collect "$tmp" || return
  history_packages_normalize "$tmp.packages" || { result=$?; rm -f "$tmp" "$tmp".*; return "$result"; }
  history_query_emit "$tmp" "$cursor" "$limit" "$since" "$uid" "$port" "${HISTORY_QUERY_FILTER-}" "$signature"
  result=$?
  rm -f "$tmp" "$tmp".*
  return "$result"
}

# 同样只出 JSON，收集与包名归一化由调用方负责。
history_apps_emit() {
  local tmp=$1 uid event_count first=1 result=0
  "$BB" awk -F '\t' '{count[$4]+=$6} END{for(uid in count)printf "%s\t%.0f\n",uid,count[uid]}' "$tmp" | \
    LC_ALL=C "$BB" sort -t "$(printf '\t')" -k1,1n | "$BB" head -n 1000 > "$tmp.apps" || return 74
  printf '{"apps":['
  while IFS=$(printf '\t') read -r uid event_count; do
    history_uint_valid "$uid" 4294967294 0 || continue
    history_uint_valid "$event_count" 85899345900000 1 || continue
    [ "$first" = 1 ] || printf ','
    first=0
    printf '{"uid":%s,"packages":%s,"eventCount":%s}' "$uid" "$(history_packages_json_from_normalized "$uid" "$tmp.packages")" "$event_count"
  done < "$tmp.apps"
  printf ']}\n'
  return "$result"
}

history_apps_json() {
  local tmp result=0
  tmp="$RULE_TMP/history-apps.$$"
  rm -f "$tmp" "$tmp".*
  history_query_collect "$tmp" || return
  history_packages_normalize "$tmp.packages" || { result=$?; rm -f "$tmp" "$tmp".*; return "$result"; }
  history_apps_emit "$tmp"
  result=$?
  rm -f "$tmp" "$tmp".*
  return "$result"
}

# 进入日志页要的三份数据（状态、应用清单、一页记录）合并成一次调用。
# 拆开读时 history_query_collect 要走两遍事件文件与映射校验，
# packages.list（上限 8 MiB）也要归一化两遍，还多两次 shell 启动。
# 这里收集一次、归一化一次，三份数据一起出。
history_bundle_json() {
  # 先取 ${6-} 再验个数：直接写 $6 会在 set -u 下于个数检查之前就报错退出。
  local cursor=${1-} limit=${2-} since=${3-} uid=${4-} port=${5-} domain_b64=${6-} tmp status apps page signature result=0
  [ "$#" -eq 6 ] || return 64
  tmp="$RULE_TMP/history-bundle.$$"
  rm -f "$tmp" "$tmp".*
  history_query_prepare "$tmp" "$cursor" "$limit" "$since" "$uid" "$port" "$domain_b64" || return
  # 签名必须在读事件文件之前取。取在后面的话，收集期间（映射校验 + 两遍 awk，忙时可到秒级）
  # 新写进来的事件已经在返回的数据里，却又被算进基线，探针永远比不出变化——那正是
  # 「不动筛选条件就不刷新」的来源。取在前面最多让下一轮多读一次，不会丢事件。
  signature=$(history_pulse_signature) || return 74
  # 先收集，再让状态复用收集时算好的统计。反过来写（状态在前）会让 history_status_json
  # 自己把两个事件文件再过一遍——那正是打包读取要省掉的那一趟。
  # 赋值前缀加在函数调用上，赋值在函数返回后是否还留着按 POSIX 是未定义的，显式收尾。
  HISTORY_COLLECT_STATS=1
  history_query_collect "$tmp" || { result=$?; HISTORY_COLLECT_STATS=0; rm -f "$tmp" "$tmp".*; return "$result"; }
  HISTORY_COLLECT_STATS=0
  status=$(history_status_json "$tmp.stats") || { rm -f "$tmp" "$tmp".*; return 70; }
  history_packages_normalize "$tmp.packages" || { result=$?; rm -f "$tmp" "$tmp".*; return "$result"; }
  apps=$(history_apps_emit "$tmp") || { result=$?; rm -f "$tmp" "$tmp".*; return "$result"; }
  # 签名也要带进嵌套的 history 里：界面用同一个解析路径处理「打包读取」和「单独查询」两种
  # 响应，两边形状必须一样，否则换筛选条件那条路（走单独查询）拿不到基线。
  page=$(history_query_emit "$tmp" "$cursor" "$limit" "$since" "$uid" "$port" "${HISTORY_QUERY_FILTER-}" "$signature")
  result=$?
  rm -f "$tmp" "$tmp".*
  [ "$result" -eq 0 ] || return "$result"
  printf '{"status":%s,"apps":%s,"history":%s,"signature":"%s"}\n' "$status" "$apps" "$page" "$signature"
}

history_main() {
  local command=${1-}
  rules_init_paths "$MODDIR" || return
  case "$command:$#" in
    config-get:1) history_config_bootstrap && history_config_get ;;
    boot-enabled:1) history_boot_enabled ;;
    status:1) history_status ;;
    prepare-trace:4) history_prepare_trace "$2" "$3" "$4" ;;
    enable:1) history_enable ;;
    disable:1) history_disable ;;
    reconcile:1) history_reconcile ;;
    cleanup-uninstall:1) history_cleanup_uninstall ;;
    clear:1) history_clear ;;
    history-status:1) history_status_json ;;
    history-pulse:1) history_pulse_json ;;
    history:6) history_query_json "$2" "$3" "$4" "$5" "$6" - ;;
    history:7) history_query_json "$2" "$3" "$4" "$5" "$6" "$7" ;;
    history-apps:1) history_apps_json ;;
    history-bundle:6) history_bundle_json "$2" "$3" "$4" "$5" "$6" - ;;
    history-bundle:7) history_bundle_json "$2" "$3" "$4" "$5" "$6" "$7" ;;
    *) return 64 ;;
  esac
}

if [ "${HISTORY_MANAGER_SOURCE_ONLY:-0}" != 1 ]; then
  history_main "$@"
fi
