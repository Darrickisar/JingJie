#!/system/bin/sh

status_phase_valid() {
  case "$1" in
    idle|validating|downloading|normalizing|merging|generating|mounting|verifying|committing|rolling_back|cleaning) return 0 ;;
    *) return 1 ;;
  esac
}

status_result_valid() {
  case "$1" in ok|degraded|failed|rolled_back|critical) return 0 ;; *) return 1 ;; esac
}

status_serialize_projection() {
  local phase=$1 result=$2 busy=$3
  status_phase_valid "$phase" || return 65
  status_result_valid "$result" || return 65
  [ "$busy" = true ] || [ "$busy" = false ] || return 65
  printf '%s\n' "{\"schemaVersion\":1,\"phase\":\"$phase\",\"result\":\"$result\",\"busy\":$busy,\"operationId\":null,\"operationVerb\":null,\"operationStartedAt\":null,\"initialRefreshPending\":false,\"autoRefresh\":{\"enabled\":false,\"intervalHours\":24},\"desiredSourcesRevision\":null,\"appliedSourcesRevision\":null,\"sourcesOutOfSync\":false,\"manualBlockCount\":0,\"manualAllowCount\":0,\"enhancedWhitelist\":{\"enabled\":false,\"url\":null,\"state\":\"disabled\",\"ruleCount\":0,\"skippedCount\":0,\"updatedAt\":null,\"error\":null},\"desiredMode\":null,\"activeMode\":null,\"activeGeneration\":null,\"alternateGeneration\":null,\"alternateAction\":\"none\",\"ruleCount\":0,\"lastSuccessAt\":null,\"lastFailureAt\":null,\"lastError\":null,\"mountTarget\":null,\"mountedSha256\":null,\"sources\":[]}"
}

status_nullable_string() {
  local escaped
  if [ -n "$1" ]; then
    escaped=$(printf '%s' "$1" | json_escape)
    printf '"%s"' "$escaped"
  else
    printf 'null'
  fi
}

status_manifest_validate() {
  local file=$1
  [ -f "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    {
      if(NF!=2)bad()
      k=$1; v=$2
       if(k !~ /^(schema_version|generation_id|sources_revision|config_snapshot_sha256|base_sha256|recovery_sha256|all_sha256|reward_sha256|all_rule_count|reward_rule_count|source_count|enhanced_whitelist_(enabled|url_sha256|state|rule_count|skipped_count|updated_at|error))$/ && k !~ /^source_[0-9]+_(id|kind|state|updated_at|url_sha256|content_sha256|rule_count|allow_count|skipped_count|error)$/)bad()
      if(seen[k]++)bad()
      value[k]=v; keys++
    }
    END{
      if(value["schema_version"]!="1")bad()
      if(value["generation_id"] !~ /^g[0-9]+(-r[0-9]+-p[0-9]+)?$/)bad()
      if(value["sources_revision"] !~ /^[0-9]+$/)bad()
      for(i in value){if(i ~ /sha256$/ && value[i]!="null" && (length(value[i])!=64 || value[i]!~/^[0-9a-f]+$/))bad()}
      for(k in value){if(k ~ /^(all|reward)_rule_count$/ && value[k]!~/^[0-9]+$/)bad()}
      if(value["source_count"] !~ /^[0-9]+$/ || value["source_count"]>19)bad()
       expected=11+value["source_count"]*10
       enhanced=0
       if("enhanced_whitelist_enabled" in value){
         enhanced=1
         for(k in value) if(k ~ /^enhanced_whitelist_/) enhanced_keys++
         if(enhanced_keys!=7 || value["enhanced_whitelist_enabled"] !~ /^[01]$/ || value["enhanced_whitelist_state"] !~ /^(fresh|stale|error|disabled)$/ || value["enhanced_whitelist_rule_count"] !~ /^[0-9]+$/ || value["enhanced_whitelist_skipped_count"] !~ /^[0-9]+$/ || value["enhanced_whitelist_updated_at"] !~ /^[0-9]+$/ || value["enhanced_whitelist_error"] !~ /^(null|unsupported_format|source_unavailable|download_failed_using_cache)$/)bad()
       }
       if(keys!=expected+enhanced*7)bad()
      for(i=1;i<=value["source_count"];i++){
        p="source_" i "_"
         if(!(p "id" in value) || !(p "kind" in value) || !(p "state" in value) || !(p "updated_at" in value) || !(p "url_sha256" in value) || !(p "content_sha256" in value) || !(p "rule_count" in value) || !(p "allow_count" in value) || !(p "skipped_count" in value) || !(p "error" in value))bad()
        id=value[p "id"]
        if(id!="awa" && id!="rule10007" && id !~ /^custom_[1-9][0-9]*$/)bad()
        if(value[p "kind"]!="builtin" && value[p "kind"]!="custom")bad()
        if((id=="awa" || id=="rule10007") && value[p "kind"]!="builtin")bad()
        if(id ~ /^custom_/ && value[p "kind"]!="custom")bad()
         if(value[p "state"] !~ /^(fresh|stale|disabled|error)$/)bad()
         if(value[p "updated_at"] !~ /^[0-9]+$/)bad()
        if(value[p "rule_count"] !~ /^[0-9]+$/)bad()
        if(value[p "allow_count"] !~ /^[0-9]+$/ || value[p "allow_count"]>value[p "rule_count"])bad()
        if(value[p "skipped_count"] !~ /^[0-9]+$/)bad()
        if(value[p "error"] !~ /^(null|unsupported_format|source_unavailable|download_failed_using_cache)$/)bad()
        if(ids[id]++)bad()
      }
    }
  ' "$file" || return $?
}

status_manifest_meta() {
  local file=$1 wanted=$2
  "$BB" awk -F= -v wanted="$wanted" '
    $1 ~ /^source_[0-9]+_id$/ && $2==wanted {key=$1; sub(/^source_/,"",key); sub(/_id$/,"",key); source_num=key}
    source_num!="" && $1=="source_" source_num "_state" {state=$2}
    source_num!="" && $1=="source_" source_num "_updated_at" {updated=$2}
    source_num!="" && $1=="source_" source_num "_rule_count" {count=$2}
    source_num!="" && $1=="source_" source_num "_skipped_count" {skipped=$2}
    source_num!="" && $1=="source_" source_num "_error" {error=$2}
    source_num!="" && $1=="source_" source_num "_url_sha256" {url_sha=$2}
    END{if(source_num!="")printf "%s\t%s\t%s\t%s\t%s\t%s\n",state,count,skipped,error,url_sha,updated; else exit 1}
  ' "$file"
}

status_diagnostic_meta() {
  local file=$1 wanted=$2 wanted_sha=$3
  [ -f "$file" ] || return 1
  "$BB" awk -F '\t' -v wanted="$wanted" -v wanted_sha="$wanted_sha" '
    function valid_sha(v) {
      return length(v)==64 && v !~ /[^0-9a-f]/
    }
    $1==wanted && $2==wanted_sha {
      if (!valid_sha($2) || $3 !~ /^(fresh|stale|error|disabled)$/ ||
          $4 !~ /^(null|unsupported_format|source_unavailable|download_failed_using_cache)$/) next
      if (NF==7) {
        if ($5 !~ /^[0-9]+$/ || $6 !~ /^[0-9]+$/ || $7 !~ /^[0-9]+$/) next
        count=$5; skipped=$6; updated=$7
      } else {
        if (wanted=="enhanced_whitelist" || NF!=6 || $5 !~ /^[0-9]+$/ || $6 !~ /^[0-9]+$/) next
        count=0; skipped=$5; updated=$6
      }
      if (found++) next
      printf "%s\t%s\t%s\t%s\t%s\n", $3, count, skipped, $4, updated
    }
    END { if (!found) exit 1 }
  ' "$file"
}

status_health_normalize() {
  local state=$1 count=$2 skipped=$3 error=$4 updated=$5
  [ "$error" = null ] && error=
  STATUS_HEALTH_STATE=$state
  STATUS_HEALTH_COUNT=$count
  STATUS_HEALTH_SKIPPED=$skipped
  STATUS_HEALTH_ERROR=$error
  STATUS_HEALTH_UPDATED=$updated
  [ "$STATUS_HEALTH_UPDATED" != 0 ] || STATUS_HEALTH_UPDATED=
  case "$state" in
    fresh) ;;
    stale) STATUS_HEALTH_ERROR=download_failed_using_cache ;;
    error) [ -n "$STATUS_HEALTH_ERROR" ] && [ "$STATUS_HEALTH_ERROR" != null ] || STATUS_HEALTH_ERROR=source_unavailable ;;
    disabled) STATUS_HEALTH_ERROR=; STATUS_HEALTH_UPDATED= ;;
    *) STATUS_HEALTH_STATE=error; STATUS_HEALTH_COUNT=0; STATUS_HEALTH_SKIPPED=0; STATUS_HEALTH_ERROR=source_unavailable; STATUS_HEALTH_UPDATED= ;;
  esac
}

status_source_name_url_valid() {
  local name_b64=$1 url_b64=$2
  if command -v operation_source_fields_valid >/dev/null 2>&1; then
    operation_source_fields_valid "$name_b64" "$url_b64"
  else
    config_decode_source_fields "$name_b64" "$url_b64"
  fi
}

status_enhanced_whitelist_projection() {
  local revision=$1 enabled url url_sha diag state=error count=0 skipped=0 error=source_unavailable updated=
  enabled=$(config_enhanced_whitelist_value "$revision" enabled) || return
  url=$(config_enhanced_whitelist_url "$revision") || return
  if [ "$enabled" = 0 ]; then
    printf '{"enabled":false,"url":%s,"state":"disabled","ruleCount":0,"skippedCount":0,"updatedAt":null,"error":null}' "$(status_nullable_string "$url")"
    return
  fi
  url_sha=$(printf '%s' "$url" | sha256_file_stdin) || return
  if diag=$(status_diagnostic_meta "$RULE_RUNTIME/source-diagnostics.tsv" enhanced_whitelist "$url_sha" 2>/dev/null); then
    IFS="$(printf '\t')" read -r state count skipped error updated <<EOF
$diag
EOF
    status_health_normalize "$state" "$count" "$skipped" "$error" "$updated"
    state=$STATUS_HEALTH_STATE; count=$STATUS_HEALTH_COUNT; skipped=$STATUS_HEALTH_SKIPPED; error=$STATUS_HEALTH_ERROR; updated=$STATUS_HEALTH_UPDATED
  fi
  printf '{"enabled":true,"url":%s,"state":"%s","ruleCount":%s,"skippedCount":%s,"updatedAt":%s,"error":%s}' \
    "$(status_nullable_string "$url")" "$state" "$count" "$skipped" "${updated:-null}" "$(status_nullable_string "$error")"
}

status_sources_projection() {
  local revision=$1 manifest=${2-} generation=${3-} sources id kind enabled order name_b64 url_b64 extra
  local first=true meta diag state count skipped meta_error updated error name url desired_url_sha manifest_url_sha
  local diag_state diag_count diag_skipped diag_error diag_updated
  local manifest_usable diag_file="$RULE_RUNTIME/source-diagnostics.tsv"
  local manifest_updated manifest_generation
  sources="$CONFIG_DIR/revisions/$revision/sources.tsv"
  source_registry_validate_file "$sources" || return
  if [ -n "$manifest" ]; then
    status_manifest_validate "$manifest" || return
    manifest_generation=$(status_prop_value "$manifest" generation_id)
    [ "$manifest_generation" = "$generation" ] || return 70
  fi
  printf '['
  while IFS="$(printf '\t')" read -r id kind enabled order name_b64 url_b64 extra || \
    [ -n "${id}${kind}${enabled}${order}${name_b64}${url_b64}${extra}" ]; do
    [ -n "$id" ] || continue
    [ -z "$extra" ] || return 65
    status_source_name_url_valid "$name_b64" "$url_b64" || return 65
    name=$(printf '%s' "$name_b64" | "$BB" base64 -d 2>/dev/null) || return 65
    url=$(printf '%s' "$url_b64" | "$BB" base64 -d 2>/dev/null) || return 65
    desired_url_sha=$(printf '%s' "$url" | sha256_file_stdin) || return
    state=error; count=0; skipped=0; meta_error=not_applied; updated=
    manifest_usable=false
    if [ "$enabled" = 0 ]; then
      state=disabled; meta_error=
    elif [ -n "$manifest" ] && meta=$(status_manifest_meta "$manifest" "$id" 2>/dev/null); then
      IFS="$(printf '\t')" read -r state count skipped meta_error manifest_url_sha manifest_updated <<EOF
$meta
EOF
      if [ "$manifest_url_sha" = "$desired_url_sha" ]; then
        manifest_usable=true
        status_health_normalize "$state" "$count" "$skipped" "$meta_error" "$manifest_updated"
        state=$STATUS_HEALTH_STATE; count=$STATUS_HEALTH_COUNT; skipped=$STATUS_HEALTH_SKIPPED
        meta_error=$STATUS_HEALTH_ERROR; updated=$STATUS_HEALTH_UPDATED
      else
        state=error; count=0; skipped=0; meta_error=not_applied
      fi
    fi
    if [ "$enabled" = 1 ] && diag=$(status_diagnostic_meta "$diag_file" "$id" "$desired_url_sha" 2>/dev/null); then
      IFS="$(printf '\t')" read -r diag_state diag_count diag_skipped diag_error diag_updated <<EOF
$diag
EOF
      if [ "$manifest_usable" != true ] || [ "$diag_updated" -ge "$manifest_updated" ]; then
        status_health_normalize "$diag_state" "$diag_count" "$diag_skipped" "$diag_error" "$diag_updated"
        state=$STATUS_HEALTH_STATE; count=$STATUS_HEALTH_COUNT; skipped=$STATUS_HEALTH_SKIPPED
        meta_error=$STATUS_HEALTH_ERROR; updated=$STATUS_HEALTH_UPDATED
      fi
    fi
    [ "$first" = true ] || printf ','
    first=false
    [ -n "$meta_error" ] && error=$(status_nullable_string "$meta_error") || error=null
    printf '{"id":"%s","name":"%s","url":"%s","kind":"%s","enabled":%s,"order":%s,"state":"%s","updatedAt":%s,"ruleCount":%s,"skippedCount":%s,"error":%s}' \
      "$id" "$(printf '%s' "$name" | json_escape)" "$(printf '%s' "$url" | json_escape)" "$kind" "$([ "$enabled" = 1 ] && printf true || printf false)" "$order" "$state" "${updated:-null}" "$count" "$skipped" "$error"
  done < "$sources"
  printf ']\n'
}

status_prop_value() {
  local file=$1 key=$2
  "$BB" awk -F= -v wanted="$key" '$1==wanted{print substr($0,index($0,"=")+1)}' "$file" 2>/dev/null
}

status_phase_for_operation() {
  local operation_id=$1 file="$RULE_OPERATIONS/$1/phase.prop" value
  [ -f "$file" ] || { printf 'validating\n'; return; }
  [ "$(wc -l < "$file" | "$BB" tr -d ' ')" -eq 1 ] || { printf 'validating\n'; return; }
  value=$(status_prop_value "$file" phase)
  status_phase_valid "$value" || value=validating
  printf '%s\n' "$value"
}

status_auto_refresh_projection() {
  local file="$CONFIG_DIR/refresh.conf" enabled hours
  if [ ! -e "$file" ] && [ ! -L "$file" ]; then
    printf '{"enabled":false,"intervalHours":24}\n'
    return 0
  fi
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
  ' "$file" || return
  enabled=$("$BB" awk -F= '$1=="auto_refresh_enabled"{print $2}' "$file") || return 74
  hours=$("$BB" awk -F= '$1=="auto_refresh_interval_hours"{print $2}' "$file") || return 74
  if [ "$enabled" = 1 ]; then
    printf '{"enabled":true,"intervalHours":%s}\n' "$hours"
  else
    printf '{"enabled":false,"intervalHours":%s}\n' "$hours"
  fi
}

status_json() {
  local phase=idle result=ok busy=false operation_id= operation_verb= operation_started=
  local desired_revision= applied_revision= desired_mode= active_mode= active_generation=
  local alternate_generation= alternate_action=none rule_count=0 mounted_sha= sources_out=false
  local sources_json='[]' enhanced_json='{"enabled":false,"url":null,"state":"disabled","ruleCount":0,"skippedCount":0,"updatedAt":null,"error":null}' manifest_path manual_block_count=0 manual_allow_count=0
  local last_success= last_failure= last_error=null result_file finished initial_refresh_pending=false auto_refresh_json

  [ -f "$RULE_RUNTIME/initial-refresh.pending" ] && initial_refresh_pending=true
  auto_refresh_json=$(status_auto_refresh_projection 2>/dev/null) || return 70

  if command -v operation_current_recover_dead >/dev/null 2>&1; then
    operation_current_recover_dead || return 70
  fi

  if command -v config_current_revision >/dev/null 2>&1; then
    desired_revision=$(config_current_revision 2>/dev/null || true)
    desired_mode=$(mode_desired 2>/dev/null || true)
  fi
  if [ -f "$RULE_RUNTIME/active.prop" ]; then
    if command -v active_validate >/dev/null 2>&1; then
      active_validate "$RULE_RUNTIME/active.prop" >/dev/null 2>&1 || return 70
    fi
    applied_revision=$(status_prop_value "$RULE_RUNTIME/active.prop" applied_sources_revision)
    active_mode=$(status_prop_value "$RULE_RUNTIME/active.prop" active_mode)
    active_generation=$(status_prop_value "$RULE_RUNTIME/active.prop" active_generation)
    alternate_generation=$(status_prop_value "$RULE_RUNTIME/active.prop" alternate_generation)
    alternate_action=$(status_prop_value "$RULE_RUNTIME/active.prop" alternate_action)
    mounted_sha=$(status_prop_value "$RULE_RUNTIME/active.prop" active_hosts_sha256)
    case "$alternate_action" in rollback|redo|none) ;; *) return 70 ;; esac
    case "$active_mode" in block_all|preserve_reward|paused) ;; *) return 70 ;; esac
    case "$applied_revision" in ''|*[!0-9]*) return 70 ;; esac
    if [ -f "$RULE_GENERATIONS/$active_generation/manifest.prop" ]; then
      case "$active_mode" in
        paused) rule_count=0 ;;
        preserve_reward) rule_count=$(status_prop_value "$RULE_GENERATIONS/$active_generation/manifest.prop" reward_rule_count) ;;
        block_all) rule_count=$(status_prop_value "$RULE_GENERATIONS/$active_generation/manifest.prop" all_rule_count) ;;
      esac
      case "$rule_count" in ''|*[!0-9]*) rule_count=0 ;; esac
    fi
  fi
  [ -z "$desired_revision" ] || [ -z "$applied_revision" ] || [ "$desired_revision" = "$applied_revision" ] || sources_out=true
  if [ -n "$desired_revision" ]; then
    if [ -f "$CONFIG_DIR/revisions/$desired_revision/manual-blocklist.txt" ] && \
      [ -f "$CONFIG_DIR/revisions/$desired_revision/manual-allowlist.txt" ]; then
      manual_block_count=$("$BB" wc -l < "$CONFIG_DIR/revisions/$desired_revision/manual-blocklist.txt" | "$BB" tr -d ' ')
      manual_allow_count=$("$BB" wc -l < "$CONFIG_DIR/revisions/$desired_revision/manual-allowlist.txt" | "$BB" tr -d ' ')
    fi
    manifest_path=
    if [ -n "$active_generation" ] && [ -f "$RULE_GENERATIONS/$active_generation/manifest.prop" ]; then
      manifest_path="$RULE_GENERATIONS/$active_generation/manifest.prop"
    fi
    sources_json=$(status_sources_projection "$desired_revision" "$manifest_path" "$active_generation" 2>/dev/null) || return 70
    enhanced_json=$(status_enhanced_whitelist_projection "$desired_revision" 2>/dev/null) || return 70
  fi

  if [ -f "$RULE_RUNTIME/current-operation.prop" ]; then
    command -v operation_current_load >/dev/null 2>&1 || return 70
    operation_current_load || return 70
    operation_id=$CURRENT_OPERATION_ID
    operation_verb=$CURRENT_OPERATION_VERB
    operation_started=$CURRENT_OPERATION_STARTED_AT
    if [ "$CURRENT_OPERATION_STATE" = starting ] || [ "$CURRENT_OPERATION_STATE" = running ]; then
      busy=true
      phase=$(status_phase_for_operation "$operation_id")
    else
      result_file="$RULE_OPERATIONS/$operation_id/result.json"
      operation_result_validate "$operation_id" || return 70
      [ "$OPERATION_RESULT_VERB" = "$operation_verb" ] || return 70
      result=$OPERATION_RESULT
      finished=$OPERATION_RESULT_FINISHED_AT
      if [ "$result" = ok ] || [ "$result" = degraded ] || [ "$result" = rolled_back ]; then
        last_success=$finished
      else
        last_failure=$finished
        last_error=$(operation_error_json "$OPERATION_RESULT_ERROR_CODE") || return 70
      fi
    fi
  fi

  printf '{"schemaVersion":1,"phase":"%s","result":"%s","busy":%s,' "$phase" "$result" "$busy"
  printf '"operationId":%s,"operationVerb":%s,"operationStartedAt":%s,"initialRefreshPending":%s,"autoRefresh":%s,' \
    "$(status_nullable_string "$operation_id")" "$(status_nullable_string "$operation_verb")" "${operation_started:-null}" "$initial_refresh_pending" "$auto_refresh_json"
  printf '"desiredSourcesRevision":%s,"appliedSourcesRevision":%s,"sourcesOutOfSync":%s,' \
    "${desired_revision:-null}" "${applied_revision:-null}" "$sources_out"
  printf '"manualBlockCount":%s,"manualAllowCount":%s,"enhancedWhitelist":%s,' "$manual_block_count" "$manual_allow_count" "$enhanced_json"
  printf '"desiredMode":%s,"activeMode":%s,"activeGeneration":%s,"alternateGeneration":%s,' \
    "$(status_nullable_string "$desired_mode")" "$(status_nullable_string "$active_mode")" \
    "$(status_nullable_string "$active_generation")" "$(status_nullable_string "$alternate_generation")"
  printf '"alternateAction":"%s","ruleCount":%s,"lastSuccessAt":%s,"lastFailureAt":%s,"lastError":%s,' \
    "$alternate_action" "$rule_count" "${last_success:-null}" "${last_failure:-null}" "$last_error"
  printf '"mountTarget":null,"mountedSha256":%s,"sources":%s}\n' "$(status_nullable_string "$mounted_sha")" "$sources_json"
}
