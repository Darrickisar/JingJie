#!/system/bin/sh

operation_id_valid() {
  local value=$1 rest epoch pid counter
  case "$value" in op_*) ;; *) return 1 ;; esac
  rest=${value#op_}
  epoch=${rest%%_*}
  [ "$epoch" != "$rest" ] || return 1
  rest=${rest#*_}
  pid=${rest%%_*}
  [ "$pid" != "$rest" ] || return 1
  counter=${rest#*_}
  case "$epoch:$pid:$counter" in *[!0-9:]*) return 1 ;; esac
  [ -n "$epoch" ] && [ -n "$pid" ] && [ -n "$counter" ] || return 1
  [ "$epoch" != 0 ] && [ "$pid" != 0 ] && [ "$counter" != 0 ]
}

operation_token_valid() {
  local value=$1 rest epoch pid counter
  case "$value" in token_*) ;; *) return 1 ;; esac
  rest=${value#token_}
  epoch=${rest%%_*}; [ "$epoch" != "$rest" ] || return 1
  rest=${rest#*_}
  pid=${rest%%_*}; [ "$pid" != "$rest" ] || return 1
  counter=${rest#*_}
  case "$epoch:$pid:$counter" in *[!0-9:]*) return 1 ;; esac
  [ -n "$epoch" ] && [ -n "$pid" ] && [ -n "$counter" ] &&
    [ "$epoch" != 0 ] && [ "$pid" != 0 ] && [ "$counter" != 0 ]
}

operation_verb_valid() {
  case "$1" in
    refresh|refresh-source|set-auto-refresh|set-builtin|add-source|update-source|set-source|move-source|remove-source|select-mode|pause|resume|set-lists|set-domain-decision|set-overrides|reset-rules|set-notice|set-app-policy|rollback|set-history|clear-history|clear-cache|test-doh|set-doh|disable-doh) return 0 ;;
    *) return 1 ;;
  esac
}

operation_verb_requires_mount_repair() {
  case "$1" in
    refresh|refresh-source|set-builtin|add-source|update-source|set-source|move-source|remove-source|select-mode|pause|resume|set-lists|set-domain-decision|set-overrides|reset-rules|rollback) return 0 ;;
    *) return 1 ;;
  esac
}

operation_mount_repair() {
  local timeout_seconds=${WORKER_REPAIR_TIMEOUT_SECONDS:-30}
  decimal_uint_in_range "$timeout_seconds" 60 1 || return 65
  "$BB" timeout -s TERM -k 5 "$timeout_seconds" "${SYSTEM_SH:-/system/bin/sh}" "$MODDIR/rule_engine.sh" mount --repair
}

operation_expected_argc() {
  case "$1" in
    refresh|pause|resume|rollback|reset-rules) printf '0\n' ;;
    refresh-source|remove-source|select-mode|set-overrides|set-notice) printf '1\n' ;;
    set-auto-refresh|set-builtin|add-source|set-source|move-source|set-lists) printf '2\n' ;;
    update-source) printf '3\n' ;;
    set-app-policy) printf '3\n' ;;
    set-domain-decision) printf '2\n' ;;
    set-history) printf '1\n' ;;
    clear-history|clear-cache) printf '0\n' ;;
    test-doh) printf '1\n' ;;
    set-doh) printf '3\n' ;;
    disable-doh) printf '0\n' ;;
    *) return 64 ;;
  esac
}

operation_source_id_valid() {
  source_registry_id_valid "$1"
}

operation_utf8_valid_file() {
  local file=$1
  "$BB" od -An -v -t u1 "$file" | "$BB" awk '
    function bad(){exit 1}
    {
      for(i=1;i<=NF;i++){
        b=$i+0
        if(remaining>0){
          if(b<128 || b>191)bad()
          if(first && (b<first_min || b>first_max))bad()
          first=0; remaining--; continue
        }
        if(b<=127)continue
        first=1; first_min=128; first_max=191
        if(b>=194 && b<=223){remaining=1; continue}
        if(b==224){remaining=2; first_min=160; continue}
        if((b>=225 && b<=236) || (b>=238 && b<=239)){remaining=2; continue}
        if(b==237){remaining=2; first_max=159; continue}
        if(b==240){remaining=3; first_min=144; continue}
        if(b>=241 && b<=243){remaining=3; continue}
        if(b==244){remaining=3; first_max=143; continue}
        bad()
      }
    }
    END{if(remaining!=0)bad()}
  '
}

operation_source_fields_valid() {
  local name_b64=$1 url_b64=$2 name_file="$RULE_TMP/utf8-name.$$" url_file="$RULE_TMP/utf8-url.$$" result=0
  config_decode_source_fields "$name_b64" "$url_b64" || return 65
  printf '%s' "$name_b64" | "$BB" base64 -d > "$name_file" 2>/dev/null || result=65
  printf '%s' "$url_b64" | "$BB" base64 -d > "$url_file" 2>/dev/null || result=65
  [ "$result" -ne 0 ] || operation_utf8_valid_file "$name_file" || result=65
  [ "$result" -ne 0 ] || operation_utf8_valid_file "$url_file" || result=65
  rm -f "$name_file" "$url_file"
  return "$result"
}

operation_arguments_valid() {
  local verb=$1 expected result
  shift
  operation_verb_valid "$verb" || return 64
  expected=$(operation_expected_argc "$verb") || return
  [ "$#" -eq "$expected" ] || return 64
  case "$verb" in
    refresh|pause|resume|rollback|reset-rules) return 0 ;;
    refresh-source)
      operation_source_id_valid "$1" || return 65
      return 0
      ;;
    set-auto-refresh)
      { [ "$1" = 0 ] || [ "$1" = 1 ]; } && { [ "$2" = 6 ] || [ "$2" = 12 ] || [ "$2" = 24 ]; } || return 65
      return 0
      ;;
    set-builtin)
      { [ "$1" = awa ] || [ "$1" = rule10007 ]; } && { [ "$2" = 0 ] || [ "$2" = 1 ]; }
      ;;
    add-source)
      operation_source_fields_valid "$1" "$2"
      ;;
    update-source)
      operation_source_id_valid "$1" && operation_source_fields_valid "$2" "$3"
      ;;
    set-source)
      operation_source_id_valid "$1" && { [ "$2" = 0 ] || [ "$2" = 1 ]; }
      ;;
    move-source)
      operation_source_id_valid "$1" && { [ "$2" = up ] || [ "$2" = down ]; }
      ;;
    remove-source)
      operation_source_id_valid "$1"
      ;;
    select-mode)
      [ "$1" = block_all ] || [ "$1" = preserve_reward ]
      ;;
    set-lists)
      operation_list_b64_valid "$1" && operation_list_b64_valid "$2"
      ;;
    set-domain-decision)
      operation_domain_decision_fields_valid "$1" "$2"
      ;;
    set-overrides)
      operation_overrides_b64_valid "$1"
      ;;
    set-notice)
      [ "$1" = 0 ] || [ "$1" = 1 ]
      ;;
    set-app-policy)
      operation_app_policy_args_valid "$1" "$2" "$3"
      ;;
    set-history) { [ "$1" = 0 ] || [ "$1" = 1 ]; } || return 65 ;;
    clear-history|clear-cache) return 0 ;;
    test-doh)
      operation_doh_helpers_loaded || return 65
      doh_endpoint_b64_decode "$1" "$RULE_TMP/operation-doh-endpoint.$$"
      result=$?
      rm -f "$RULE_TMP/operation-doh-endpoint.$$"
      return "$result"
      ;;
    set-doh)
      operation_doh_helpers_loaded || return 65
      result=0
      case "$1" in off|global|selected) ;; *) return 65 ;; esac
      doh_endpoint_b64_decode "$2" "$RULE_TMP/operation-doh-endpoint.$$" || { result=$?; rm -f "$RULE_TMP/operation-doh-endpoint.$$"; return "$result"; }
      doh_config_b64_decode "$3" "$RULE_TMP/operation-doh-uids.$$" || { result=$?; rm -f "$RULE_TMP/operation-doh-endpoint.$$" "$RULE_TMP/operation-doh-uids.$$"; return "$result"; }
      if [ "$1" = selected ]; then
        [ -s "$RULE_TMP/operation-doh-uids.$$" ] || result=65
      else
        [ ! -s "$RULE_TMP/operation-doh-uids.$$" ] || result=65
      fi
      rm -f "$RULE_TMP/operation-doh-endpoint.$$" "$RULE_TMP/operation-doh-uids.$$"
      return "$result"
      ;;
    disable-doh) return 0 ;;
    *) return 64 ;;
  esac
}

operation_doh_helpers_loaded() {
  if command -v doh_endpoint_b64_decode >/dev/null 2>&1; then return 0; fi
  [ -n "${RULE_LIB_DIR-}" ] && [ -f "$RULE_LIB_DIR/doh.sh" ] || [ -f "$MODDIR/lib/rules/doh.sh" ] || return 1
  . "${RULE_LIB_DIR:-$MODDIR/lib/rules}/doh.sh"
  doh_init_paths
}

operation_overrides_b64_valid() {
  local encoded=$1 tmp="$RULE_TMP/operation-overrides.$$" result=0
  [ -z "$encoded" ] && return 0
  operation_b64_valid "$encoded" || return 65
  [ "${#encoded}" -le 90000 ] || return 65
  overrides_decode "$encoded" "$tmp" || result=$?
  rm -f "$tmp"
  [ "$result" -eq 0 ]
}

operation_app_policy_args_valid() {
  local mode=$1 uid_b64=$2 ip_b64=$3 uid_file="$RULE_TMP/operation-app-uids.$$" ip_file="$RULE_TMP/operation-app-ips.$$" result=0
  case "$mode" in off|block_selected|allow_resolved) ;; *) return 65 ;; esac
  app_policy_decode_lines "$uid_b64" "$uid_file" uid || result=65
  [ "$result" -ne 0 ] || app_policy_decode_lines "$ip_b64" "$ip_file" ip || result=65
  if [ "$result" -eq 0 ] && [ "$mode" != off ]; then
    app_policy_validate_uid_file "$uid_file" || result=65
  fi
  if [ "$result" -eq 0 ] && [ "$mode" = allow_resolved ]; then
    app_policy_validate_ip_file "$ip_file" || result=65
    [ -s "$ip_file" ] || result=65
  fi
  rm -f "$uid_file" "$ip_file"
  return "$result"
}

operation_b64_valid() {
  local value=$1
  case "$value" in *[!A-Za-z0-9+/=]*) return 1 ;; esac
  [ $(( ${#value} % 4 )) -eq 0 ] || return 1
  printf '%s' "$value" | "$BB" base64 -d >/dev/null 2>&1
}

operation_list_b64_valid() {
  local value=$1 bytes
  [ -z "$value" ] && return 0
  operation_b64_valid "$value" || return 1
  bytes=$(printf '%s' "$value" | "$BB" base64 -d 2>/dev/null | "$BB" wc -c | "$BB" tr -d ' ') || return 1
  [ "$bytes" -le 65536 ]
}

operation_domain_decision_fields_valid() {
  local decision=$1 domain_b64=$2 domain_file="$RULE_TMP/domain-decision.$$" domain validation_result result=0
  [ "$decision" = allow ] || [ "$decision" = block ] || return 65
  [ -n "$domain_b64" ] || return 65
  config_b64_valid "$domain_b64" || return 65
  printf '%s' "$domain_b64" | "$BB" base64 -d > "$domain_file" 2>/dev/null || { rm -f "$domain_file"; return 65; }
  if [ "$result" -eq 0 ]; then
    if domain=$(config_read_canonical_domain_file "$domain_file"); then
      :
    else
      validation_result=$?
      [ "$validation_result" -eq 74 ] && result=74 || result=65
    fi
  fi
  rm -f "$domain_file"
  return "$result"
}

operation_b64_encode() {
  printf '%s' "$1" | "$BB" base64 | "$BB" tr -d '\n'
}

operation_prop_value() {
  local file=$1 wanted=$2
  "$BB" awk -v wanted="$wanted" '
    {
      p=index($0,"=")
      if (p < 2) next
      key=substr($0,1,p-1)
      if (key==wanted) print substr($0,p+1)
    }
  ' "$file"
}

operation_request_validate_file() {
  local file=$1 expected_id=$2
  [ -f "$file" ] || return 66
  operation_id_valid "$expected_id" || return 65
  "$BB" awk '
    function bad(){exit 65}
    {
      p=index($0,"="); if(p<2)bad()
      k=substr($0,1,p-1); v=substr($0,p+1)
      if(k !~ /^(schema_version|operation_id|operation_verb|argc|arg_[123]_(b64|secret))$/)bad()
      if(seen[k]++)bad()
      value[k]=v; total++
    }
    END{
      if(value["schema_version"]!="1")bad()
      if(value["argc"] !~ /^[0-3]$/)bad()
      argc=value["argc"]+0
      if(total != 4+argc)bad()
      for(i=1;i<=3;i++){
        b="arg_" i "_b64"; s="arg_" i "_secret"
        if(i<=argc && ((b in seen)+(s in seen)!=1))bad()
        if(i>argc && ((b in seen)||(s in seen)))bad()
      }
    }
  ' "$file" || return $?
  local id verb argc expected index encoded decoded secret
  id=$(operation_prop_value "$file" operation_id)
  verb=$(operation_prop_value "$file" operation_verb)
  argc=$(operation_prop_value "$file" argc)
  [ "$id" = "$expected_id" ] || return 65
  operation_verb_valid "$verb" || return 65
  expected=$(operation_expected_argc "$verb") || return
  [ "$argc" = "$expected" ] || return 65
  index=1
  while [ "$index" -le "$argc" ]; do
    secret=$(operation_prop_value "$file" "arg_${index}_secret")
    encoded=$(operation_prop_value "$file" "arg_${index}_b64")
    if [ -n "$secret" ]; then
      [ "$secret" = endpoint ] || return 65
      { [ "$verb" = test-doh ] && [ "$index" = 1 ]; } ||
        { [ "$verb" = set-doh ] && [ "$index" = 2 ]; } || return 65
      [ -z "$encoded" ] || return 65
    else
      operation_b64_valid "$encoded" || return 65
      decoded=$(printf '%s' "$encoded" | "$BB" base64 -d 2>/dev/null) || return 65
      [ "$(printf '%s' "$decoded" | "$BB" wc -l | "$BB" tr -d ' ')" -eq 0 ] || return 65
    fi
    index=$((index + 1))
  done
  case "$verb" in
    test-doh) [ -n "$(operation_prop_value "$file" arg_1_secret)" ] || return 65 ;;
    set-doh) [ "$(operation_prop_value "$file" arg_2_secret)" = endpoint ] || return 65 ;;
    *) [ -z "$(operation_prop_value "$file" arg_1_secret)" ] && [ -z "$(operation_prop_value "$file" arg_2_secret)" ] && [ -z "$(operation_prop_value "$file" arg_3_secret)" ] || return 65 ;;
  esac
}

operation_request_load() {
  local operation_id=$1 file index encoded secret secret_file decoded result
  file="$RULE_OPERATIONS/$operation_id/request.prop"
  operation_request_validate_file "$file" "$operation_id" || {
    result=$?
    rm -f "$RULE_OPERATIONS/$operation_id/request.secret"
    return "$result"
  }
  OPERATION_ID=$operation_id
  OPERATION_VERB=$(operation_prop_value "$file" operation_verb)
  OPERATION_ARGC=$(operation_prop_value "$file" argc)
  OPERATION_ARG_1=
  OPERATION_ARG_2=
  OPERATION_ARG_3=
  index=1
  while [ "$index" -le "$OPERATION_ARGC" ]; do
    secret=$(operation_prop_value "$file" "arg_${index}_secret")
    if [ -n "$secret" ]; then
      secret_file="$RULE_OPERATIONS/$operation_id/request.secret"
      if [ ! -f "$secret_file" ] || [ -L "$secret_file" ] ||
        [ "$(stat -c %a "$secret_file" 2>/dev/null)" != 600 ]; then
        rm -f "$secret_file"
        return 65
      fi
      decoded=$(cat "$secret_file") || { rm -f "$secret_file"; return 74; }
      rm -f "$secret_file" || return 74
      operation_doh_helpers_loaded || return 65
      printf '%s' "$decoded" > "$RULE_TMP/operation-doh-secret.$$" || { rm -f "$RULE_TMP/operation-doh-secret.$$"; return 74; }
      doh_endpoint_validate_file "$RULE_TMP/operation-doh-secret.$$" || { result=$?; rm -f "$RULE_TMP/operation-doh-secret.$$"; return "$result"; }
      rm -f "$RULE_TMP/operation-doh-secret.$$"
    else
      encoded=$(operation_prop_value "$file" "arg_${index}_b64")
      decoded=$(printf '%s' "$encoded" | "$BB" base64 -d 2>/dev/null) || return 65
    fi
    case "$index" in
      1) OPERATION_ARG_1=$decoded ;;
      2) OPERATION_ARG_2=$decoded ;;
      3) OPERATION_ARG_3=$decoded ;;
    esac
    index=$((index + 1))
  done
  export OPERATION_ID OPERATION_VERB OPERATION_ARGC
  export OPERATION_ARG_1 OPERATION_ARG_2 OPERATION_ARG_3
}

operation_current_validate_file() {
  local file=$1
  [ -f "$file" ] || return 66
  "$BB" awk '
    function bad(){exit 65}
    {
      p=index($0,"="); if(p<2)bad()
      k=substr($0,1,p-1); v=substr($0,p+1)
      if(k !~ /^(schema_version|operation_id|operation_verb|state|pid|pid_starttime|started_at)$/)bad()
      if(seen[k]++)bad()
      value[k]=v; total++
    }
    END{
      if(total!=7 || value["schema_version"]!="1")bad()
      if(value["state"] !~ /^(starting|running|finished)$/)bad()
      if(value["pid"] !~ /^[0-9]+$/ || value["pid_starttime"] !~ /^[0-9]+$/ || value["started_at"] !~ /^[0-9]+$/)bad()
    }
  ' "$file" || return $?
  local id verb state pid start
  id=$(operation_prop_value "$file" operation_id)
  verb=$(operation_prop_value "$file" operation_verb)
  state=$(operation_prop_value "$file" state)
  pid=$(operation_prop_value "$file" pid)
  start=$(operation_prop_value "$file" pid_starttime)
  operation_id_valid "$id" || return 65
  operation_verb_valid "$verb" || return 65
  case "$state" in
    starting) [ "$pid" = 0 ] && [ "$start" = 0 ] || return 65 ;;
    running) [ "$pid" -gt 0 ] && [ "$start" -gt 0 ] || return 65 ;;
    finished)
      { [ "$pid" = 0 ] && [ "$start" = 0 ]; } ||
        { [ "$pid" -gt 0 ] && [ "$start" -gt 0 ]; } || return 65
      ;;
  esac
}

operation_current_load() {
  local file="$RULE_RUNTIME/current-operation.prop"
  operation_current_validate_file "$file" || return
  CURRENT_OPERATION_ID=$(operation_prop_value "$file" operation_id)
  CURRENT_OPERATION_VERB=$(operation_prop_value "$file" operation_verb)
  CURRENT_OPERATION_STATE=$(operation_prop_value "$file" state)
  CURRENT_OPERATION_PID=$(operation_prop_value "$file" pid)
  CURRENT_OPERATION_PID_STARTTIME=$(operation_prop_value "$file" pid_starttime)
  CURRENT_OPERATION_STARTED_AT=$(operation_prop_value "$file" started_at)
  export CURRENT_OPERATION_ID CURRENT_OPERATION_VERB CURRENT_OPERATION_STATE
  export CURRENT_OPERATION_PID CURRENT_OPERATION_PID_STARTTIME CURRENT_OPERATION_STARTED_AT
}

operation_current_write() {
  local id=$1 verb=$2 state=$3 pid=$4 pid_starttime=$5 started_at=$6
  local tmp="$RULE_RUNTIME/current-operation.prop.tmp.$$"
  operation_id_valid "$id" || return 65
  operation_verb_valid "$verb" || return 65
  case "$state" in starting|running|finished) ;; *) return 65 ;; esac
  case "$pid:$pid_starttime:$started_at" in *[!0-9:]*) return 65 ;; esac
  {
    printf 'schema_version=1\n'
    printf 'operation_id=%s\n' "$id"
    printf 'operation_verb=%s\n' "$verb"
    printf 'state=%s\n' "$state"
    printf 'pid=%s\n' "$pid"
    printf 'pid_starttime=%s\n' "$pid_starttime"
    printf 'started_at=%s\n' "$started_at"
  } > "$tmp" || return 74
  operation_current_validate_file "$tmp" || { rm -f "$tmp"; return 65; }
  atomic_replace_file "$tmp" "$RULE_RUNTIME/current-operation.prop"
}

operation_request_create() {
  local id=$1 verb=$2
  shift 2
  local argc=$# expected tmp final index encoded endpoint_b64 secret_index secret_file endpoint_tmp result
  operation_id_valid "$id" || return 65
  operation_verb_valid "$verb" || return 65
  expected=$(operation_expected_argc "$verb") || return
  [ "$argc" -eq "$expected" ] || return 64
  umask 077
  tmp="$RULE_OPERATIONS/$id.tmp.$$"
  final="$RULE_OPERATIONS/$id"
  [ ! -e "$tmp" ] && [ ! -e "$final" ] || return 76
  mkdir -p "$tmp" || return 73
  case "$verb" in test-doh) secret_index=1 ;; set-doh) secret_index=2 ;; *) secret_index= ;; esac
  if [ -n "$secret_index" ]; then
    endpoint_b64=
    index=1
    for argument in "$@"; do
      [ "$index" -eq "$secret_index" ] && endpoint_b64=$argument
      index=$((index + 1))
    done
    operation_doh_helpers_loaded || { rm -rf "$tmp"; return 65; }
    endpoint_tmp="$RULE_TMP/operation-doh-request-endpoint.$$"
    doh_endpoint_b64_decode "$endpoint_b64" "$endpoint_tmp" || { result=$?; rm -rf "$tmp"; rm -f "$endpoint_tmp"; return "$result"; }
    secret_file="$tmp/request.secret"
    cp "$endpoint_tmp" "$secret_file" || { rm -rf "$tmp"; rm -f "$endpoint_tmp"; return 74; }
    chmod 600 "$secret_file" || { rm -rf "$tmp"; rm -f "$endpoint_tmp"; return 74; }
    rm -f "$endpoint_tmp"
  fi
  {
    printf 'schema_version=1\n'
    printf 'operation_id=%s\n' "$id"
    printf 'operation_verb=%s\n' "$verb"
    printf 'argc=%s\n' "$argc"
    index=1
    for argument in "$@"; do
      if [ "$index" = "$secret_index" ]; then
        printf 'arg_%s_secret=endpoint\n' "$index"
      else
        encoded=$(operation_b64_encode "$argument") || exit 74
        printf 'arg_%s_b64=%s\n' "$index" "$encoded"
      fi
      index=$((index + 1))
    done
  } > "$tmp/request.prop" || { rm -rf "$tmp"; return 74; }
  operation_request_validate_file "$tmp/request.prop" "$id" || { rm -rf "$tmp"; return 65; }
  mv "$tmp" "$final" || { rm -rf "$tmp"; return 74; }
}

operation_history_error_code_valid() {
  case "$1" in
    nflog_unsupported|history_probe_failed|history_rules_unavailable|history_trace_prepare_failed|\
    history_reader_start_failed|history_firewall_install_failed|history_mount_failed|\
    history_state_commit_failed|history_recovery_failed) return 0 ;;
    *) return 1 ;;
  esac
}

operation_error_message() {
  case "$1" in
    engine_failed) printf '%s\n' '规则操作执行失败' ;;
    worker_lost) printf '%s\n' '后台规则任务已中断' ;;
    pause_history_reconcile_failed) printf '%s\n' '暂停保护时无法安全停止拦截历史' ;;
    resume_history_reconcile_failed) printf '%s\n' '恢复保护时无法恢复拦截历史' ;;
    pause_recovery_failed) printf '%s\n' '暂停保护失败且原状态恢复未完成' ;;
    resume_recovery_failed) printf '%s\n' '恢复保护失败且暂停状态恢复未完成' ;;
    pause_refresh_suspend_failed) printf '%s\n' '暂停保护时无法停止自动更新' ;;
    pause_doh_suspend_failed) printf '%s\n' '暂停保护时无法停止加密 DNS' ;;
    pause_app_policy_cleanup_failed) printf '%s\n' '暂停保护时无法移除分应用规则' ;;
    pause_purge_failed) printf '%s\n' '拦截已停止，但缓存和历史世代未清理干净' ;;
    resume_refresh_failed) printf '%s\n' '恢复保护时无法恢复自动更新' ;;
    resume_doh_failed) printf '%s\n' '恢复保护时无法恢复加密 DNS' ;;
    resume_app_policy_failed) printf '%s\n' '恢复保护时无法恢复分应用规则' ;;
    nflog_unsupported) printf '%s\n' '当前内核不支持拦截历史' ;;
    history_probe_failed) printf '%s\n' '拦截历史能力检测失败' ;;
    history_rules_unavailable) printf '%s\n' '当前规则尚未准备好' ;;
    history_trace_prepare_failed) printf '%s\n' '拦截历史映射准备失败' ;;
    history_reader_start_failed) printf '%s\n' '拦截历史读取器启动失败' ;;
    history_firewall_install_failed) printf '%s\n' '拦截历史防火墙规则安装失败' ;;
    history_mount_failed) printf '%s\n' '拦截历史 trace hosts 挂载失败' ;;
    history_state_commit_failed) printf '%s\n' '拦截历史状态保存失败' ;;
    history_recovery_failed) printf '%s\n' '拦截历史启用失败且恢复未完成' ;;
    invalid_endpoint) printf '%s\n' '加密 DNS 地址无效' ;;
    invalid_config) printf '%s\n' '加密 DNS 配置无效' ;;
    package_state_invalid) printf '%s\n' '应用包状态无效' ;;
    test_failed) printf '%s\n' '加密 DNS 检测失败' ;;
    commit_failed) printf '%s\n' '加密 DNS 配置保存失败' ;;
    recovery_failed) printf '%s\n' '加密 DNS 恢复失败' ;;
    runtime_failed) printf '%s\n' '加密 DNS 运行失败' ;;
    bootstrap_unresolved) printf '%s\n' '无法解析加密 DNS 服务器域名' ;;
    firewall_unsupported) printf '%s\n' '当前内核缺少加密 DNS 转发所需的防火墙能力' ;;
    private_dns_active) printf '%s\n' '系统私人 DNS 指定了主机名' ;;
    companion_unavailable) printf '%s\n' '加密 DNS 组件不可用' ;;
    upstream_unavailable) printf '%s\n' '加密 DNS 上游不可用' ;;
    companion_exited) printf '%s\n' '加密 DNS 组件已退出' ;;
    *) return 65 ;;
  esac
}

operation_error_json() {
  local code=$1 message
  message=$(operation_error_message "$code") || return
  printf '{"code":"%s","message":"%s"}' "$code" "$message"
}

operation_history_enable_error_load() {
  local file=${1:-$RULE_RUNTIME/history-enable-error.prop} code status
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2{bad()}
    $1!~/^(schema_version|code|status)$/{bad()}
    seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    $1=="code" && $2!~/^[a-z0-9_]+$/{bad()}
    $1=="status" && $2!~/^[1-9][0-9]*$/{bad()}
    END{if(NR!=3 || !seen["schema_version"] || !seen["code"] || !seen["status"])bad()}
  ' "$file" || return 65
  code=$(operation_prop_value "$file" code) || return 65
  status=$(operation_prop_value "$file" status) || return 65
  operation_history_error_code_valid "$code" || return 65
  case "$status" in ''|*[!0-9]*) return 65 ;; esac
  [ "$status" -ge 1 ] && [ "$status" -le 255 ] || return 65
  OPERATION_HISTORY_ERROR_CODE=$code
  OPERATION_HISTORY_ERROR_STATUS=$status
  export OPERATION_HISTORY_ERROR_CODE OPERATION_HISTORY_ERROR_STATUS
}

operation_result_validate() {
  local id=$1 file="$RULE_OPERATIONS/$1/result.json" line verb result prefix payload finished suffix request_verb error_code expected
  operation_id_valid "$id" || return 65
  [ -f "$file" ] || return 66
  [ "$(wc -l < "$file" | "$BB" tr -d ' ')" -eq 1 ] || return 65
  line=$(cat "$file") || return 74
  verb=$(printf '%s\n' "$line" | "$BB" sed -n 's/.*"operationVerb":"\([a-z-]*\)".*/\1/p')
  result=$(printf '%s\n' "$line" | "$BB" sed -n 's/.*"result":"\([a-z_]*\)".*/\1/p')
  operation_verb_valid "$verb" || return 65
  case "$result" in ok|degraded|failed|rolled_back|critical) ;; *) return 65 ;; esac
  prefix='{"schemaVersion":1,"operationId":"'"$id"'","operationVerb":"'"$verb"'","result":"'"$result"'","finishedAt":'
  [ "${line#"$prefix"}" != "$line" ] || return 65
  payload=${line#"$prefix"}
  finished=${payload%%,*}
  suffix=${payload#*,}
  case "$finished" in ''|*[!0-9]*) return 65 ;; esac
  case "$result" in
    ok|degraded|rolled_back)
      [ "$suffix" = '"error":null}' ] || return 65
      error_code=
      ;;
    failed|critical)
      error_code=$(printf '%s\n' "$suffix" | "$BB" sed -n 's/^"error":{"code":"\([a-z0-9_]*\)","message":".*"}}$/\1/p')
      [ -n "$error_code" ] || return 65
      if [ "$result" = critical ]; then
        case "$error_code" in engine_failed|pause_recovery_failed|resume_recovery_failed) ;; *) return 65 ;; esac
      fi
      expected=$(operation_error_json "$error_code") || return 65
      [ "$suffix" = '"error":'"$expected"'}' ] || return 65
      ;;
  esac
  if [ -f "$RULE_OPERATIONS/$id/request.prop" ]; then
    operation_request_validate_file "$RULE_OPERATIONS/$id/request.prop" "$id" || return 65
    request_verb=$(operation_prop_value "$RULE_OPERATIONS/$id/request.prop" operation_verb)
    [ "$request_verb" = "$verb" ] || return 65
  fi
  OPERATION_RESULT=$result
  OPERATION_RESULT_VERB=$verb
  OPERATION_RESULT_FINISHED_AT=$finished
  OPERATION_RESULT_ERROR_CODE=$error_code
  OPERATION_RESULT_JSON=$line
  export OPERATION_RESULT OPERATION_RESULT_VERB OPERATION_RESULT_FINISHED_AT OPERATION_RESULT_ERROR_CODE OPERATION_RESULT_JSON
}

operation_result_write() {
  local id=$1 verb=$2 result=$3 error_code=${4:-engine_failed} finished tmp error
  operation_id_valid "$id" || return 65
  operation_verb_valid "$verb" || return 65
  case "$result" in
    ok|degraded|rolled_back) error=null ;;
    failed) error=$(operation_error_json "$error_code") || return 65 ;;
    critical)
      case "$error_code" in engine_failed|pause_recovery_failed|resume_recovery_failed) ;; *) return 65 ;; esac
      error=$(operation_error_json "$error_code") || return 65
      ;;
    *) return 65 ;;
  esac
  finished=$(date -u +%s 2>/dev/null || date +%s) || return 70
  tmp="$RULE_OPERATIONS/$id/result.json.tmp.$$"
  printf '{"schemaVersion":1,"operationId":"%s","operationVerb":"%s","result":"%s","finishedAt":%s,"error":%s}\n' \
    "$id" "$verb" "$result" "$finished" "$error" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$RULE_OPERATIONS/$id/result.json"
}

operation_current_worker_is_live() {
  local live_start line
  [ "$CURRENT_OPERATION_STATE" = running ] || return 1
  live_start=$(proc_starttime "$CURRENT_OPERATION_PID" 2>/dev/null || true)
  [ "$live_start" = "$CURRENT_OPERATION_PID_STARTTIME" ] || return 1
  [ -f "$RULE_RUNTIME/processes.tsv" ] || return 1
  line=$("$BB" awk -F '\t' -v pid="$CURRENT_OPERATION_PID" -v start="$CURRENT_OPERATION_PID_STARTTIME" \
    '$1=="registered" && $3=="operation-worker" && $4==pid && $5==start{print; found=1} END{exit found?0:1}' \
    "$RULE_RUNTIME/processes.tsv" 2>/dev/null) || return 1
  [ -n "$line" ] || return 1
  "$BB" tr '\000' '\n' < "/proc/$CURRENT_OPERATION_PID/cmdline" 2>/dev/null | \
    "$BB" grep -Fx "$MODDIR/operation_worker.sh" >/dev/null 2>&1
}

operation_current_recover_dead_locked() {
  local repair_needed=0 repair_result=0
  [ -f "$RULE_RUNTIME/current-operation.prop" ] || return 0
  operation_current_load || return 70
  case "$CURRENT_OPERATION_STATE" in
    finished) return 0 ;;
    starting)
      local now max_starting_age
      now=$(date -u +%s 2>/dev/null || date +%s) || return 70
      max_starting_age=${OPERATION_STARTING_MAX_SECONDS:-30}
      case "$max_starting_age" in ''|*[!0-9]*) return 65 ;; esac
      [ "$now" -ge "$CURRENT_OPERATION_STARTED_AT" ] || return 0
      [ $((now - CURRENT_OPERATION_STARTED_AT)) -gt "$max_starting_age" ] || return 0
      ;;
    running)
      operation_current_worker_is_live && return 0
      repair_needed=1
      ;;
  esac

  if [ "$repair_needed" -eq 1 ] && operation_verb_requires_mount_repair "$CURRENT_OPERATION_VERB"; then
    operation_mount_repair || {
      repair_result=$?
      log_event warn operation_mount_repair_failed "$CURRENT_OPERATION_VERB:$repair_result" || true
    }
  fi

  operation_result_validate "$CURRENT_OPERATION_ID" 2>/dev/null ||
    operation_result_write "$CURRENT_OPERATION_ID" "$CURRENT_OPERATION_VERB" failed worker_lost || return
  operation_current_write "$CURRENT_OPERATION_ID" "$CURRENT_OPERATION_VERB" finished \
    "$CURRENT_OPERATION_PID" "$CURRENT_OPERATION_PID_STARTTIME" "$CURRENT_OPERATION_STARTED_AT" || return
  log_event warn operation_recovered "$CURRENT_OPERATION_ID:worker_not_running" || true
}

operation_current_recover_dead() {
  local result
  rules_lock_acquire submit || return 0
  if operation_current_recover_dead_locked; then
    result=0
  else
    result=$?
  fi
  rules_lock_release submit || return
  return "$result"
}

operation_current_clear_if_starting() {
  local id=$1
  operation_current_load 2>/dev/null || return 0
  if [ "$CURRENT_OPERATION_ID" = "$id" ] && [ "$CURRENT_OPERATION_STATE" = starting ]; then
    rm -f "$RULE_RUNTIME/current-operation.prop"
  fi
}

operation_id_allocate() {
  local now counter candidate
  now=$(date -u +%s 2>/dev/null || date +%s) || return 70
  counter=1
  while :; do
    candidate="op_${now}_$$_$counter"
    [ ! -e "$RULE_OPERATIONS/$candidate" ] || { counter=$((counter + 1)); continue; }
    printf '%s\n' "$candidate"
    return 0
  done
}

operation_submit() {
  local verb=$1 result id now attempt live_start
  shift
  OPERATION_SUBMIT_ERROR=
  rules_lock_acquire submit || { OPERATION_SUBMIT_ERROR=operation_busy; export OPERATION_SUBMIT_ERROR; return 75; }
  if [ -f "$RULE_RUNTIME/uninstalling" ]; then
    OPERATION_SUBMIT_ERROR=uninstalling
    rules_lock_release submit
    export OPERATION_SUBMIT_ERROR
    return 75
  fi
  if [ -f "$RULE_RUNTIME/current-operation.prop" ]; then
    if ! operation_current_load; then
      OPERATION_SUBMIT_ERROR=state_invalid
      rules_lock_release submit
      export OPERATION_SUBMIT_ERROR
      return 70
    fi
    if [ "$CURRENT_OPERATION_STATE" = running ]; then
      live_start=$(proc_starttime "$CURRENT_OPERATION_PID" 2>/dev/null || true)
      if [ "$live_start" != "$CURRENT_OPERATION_PID_STARTTIME" ]; then
        OPERATION_SUBMIT_ERROR=state_invalid
        rules_lock_release submit
        export OPERATION_SUBMIT_ERROR
        return 70
      fi
    fi
    case "$CURRENT_OPERATION_STATE" in starting|running)
      OPERATION_SUBMIT_ERROR=operation_busy
      rules_lock_release submit
      export OPERATION_SUBMIT_ERROR
      return 75
      ;;
    esac
  fi
  id=$(operation_id_allocate) || { result=$?; rules_lock_release submit; return "$result"; }
  operation_request_create "$id" "$verb" "$@" || { result=$?; rules_lock_release submit; return "$result"; }
  now=${id#op_}; now=${now%%_*}
  operation_current_write "$id" "$verb" starting 0 0 "$now" || {
    result=$?; rm -rf "$RULE_OPERATIONS/$id"; rules_lock_release submit; return "$result"
  }
  if ! "$SYSTEM_SH" "$MODDIR/process_manager.sh" start-operation "$id" >>"$RUNTIME_LOG" 2>&1; then
    operation_current_clear_if_starting "$id"
    rm -rf "$RULE_OPERATIONS/$id"
    OPERATION_SUBMIT_ERROR=background_worker_unsupported
    rules_lock_release submit
    export OPERATION_SUBMIT_ERROR
    return 69
  fi
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if operation_current_load 2>/dev/null && [ "$CURRENT_OPERATION_ID" = "$id" ]; then
      if [ "$CURRENT_OPERATION_STATE" = running ]; then
        OPERATION_ACCEPTED_ID=$id
        rules_lock_release submit
        export OPERATION_ACCEPTED_ID
        return 0
      fi
      if [ "$CURRENT_OPERATION_STATE" = finished ] && operation_result_validate "$id"; then
        OPERATION_ACCEPTED_ID=$id
        rules_lock_release submit
        export OPERATION_ACCEPTED_ID
        return 0
      fi
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  "$SYSTEM_SH" "$MODDIR/process_manager.sh" stop operation-worker >/dev/null 2>&1 || true
  operation_current_clear_if_starting "$id"
  rm -rf "$RULE_OPERATIONS/$id"
  OPERATION_SUBMIT_ERROR=worker_start_timeout
  rules_lock_release submit
  export OPERATION_SUBMIT_ERROR
  return 69
}
