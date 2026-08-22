#!/system/bin/sh

WORKER_ROOT=${OPERATION_WORKER_ROOT:-${0%/*}}
MODDIR=${MODDIR:-$WORKER_ROOT}
BB=${BB:-$MODDIR/busybox/busybox}
[ -x "$BB" ] || BB=$(command -v busybox 2>/dev/null || printf '%s' "$BB")
SYSTEM_SH=${SYSTEM_SH:-/system/bin/sh}
export MODDIR BB SYSTEM_SH

. "$WORKER_ROOT/lib/rules/common.sh"
. "$WORKER_ROOT/lib/rules/config.sh"
. "$WORKER_ROOT/lib/rules/status.sh"
. "$WORKER_ROOT/lib/rules/doh.sh"
. "$WORKER_ROOT/lib/rules/operations.sh"
DOH_MANAGER_ROOT=$WORKER_ROOT DOH_MANAGER_SOURCE_ONLY=1 . "$WORKER_ROOT/doh_manager.sh"
APP_POLICY_SOURCE_ONLY=1 . "$WORKER_ROOT/lib/rules/app_policy.sh"

WORKER_ENGINE_TIMEOUT_SECONDS=${WORKER_ENGINE_TIMEOUT_SECONDS:-180}
WORKER_REPAIR_TIMEOUT_SECONDS=${WORKER_REPAIR_TIMEOUT_SECONDS:-30}
decimal_uint_in_range "$WORKER_ENGINE_TIMEOUT_SECONDS" 600 1 || exit 64
decimal_uint_in_range "$WORKER_REPAIR_TIMEOUT_SECONDS" 60 1 || exit 64

worker_ready_validate() {
  local token=$1 file="$RULE_RUNTIME/ready/$1" ready_token ready_pid ready_start line
  [ -f "$file" ] || return 1
  [ "$(wc -l < "$file" | "$BB" tr -d ' ')" -eq 3 ] || return 65
  ready_token=$(operation_prop_value "$file" token)
  ready_pid=$(operation_prop_value "$file" pid)
  ready_start=$(operation_prop_value "$file" pid_starttime)
  [ "$ready_token" = "$token" ] && [ "$ready_pid" = "$$" ] || return 65
  [ "$ready_start" = "$(proc_starttime "$$")" ] || return 65
  line=$("$BB" awk -F '\t' -v token="$token" -v pid="$$" -v start="$ready_start" \
    '$1=="registered" && $2==token && $3=="operation-worker" && $4==pid && $5==start{print; found=1} END{exit found?0:1}' \
    "$RULE_RUNTIME/processes.tsv" 2>/dev/null) || return 65
  [ -n "$line" ]
}

worker_wait_ready() {
  local token=$1 attempt=0
  while [ "$attempt" -lt 30 ]; do
    worker_ready_validate "$token" && return 0
    attempt=$((attempt + 1))
    sleep 0.1
  done
  return 69
}

worker_phase_write() {
  local operation_id=$1 phase=$2 tmp="$RULE_OPERATIONS/$1/phase.prop.tmp.$$"
  status_phase_valid "$phase" || return 65
  printf 'phase=%s\n' "$phase" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$RULE_OPERATIONS/$operation_id/phase.prop"
}

worker_exec_engine() {
  "$BB" timeout -s TERM -k 5 "$WORKER_ENGINE_TIMEOUT_SECONDS" "$SYSTEM_SH" "$MODDIR/rule_engine.sh" "$@"
}

worker_effective_mode_paused() {
  local file="$RULE_RUNTIME/active.prop" mode
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  mode=$(status_prop_value "$file" active_mode 2>/dev/null || true)
  [ "$mode" = paused ]
}

worker_pause_transaction() {
  local history_result recovery_result recovery_history_result
  worker_exec_engine pause || return
  worker_exec_history reconcile
  history_result=$?
  [ "$history_result" -ne 0 ] || return 0
  log_event warn history_reconcile_failed "pause:$history_result" || true
  WORKER_TRANSACTION_HANDLED=1
  worker_exec_engine resume
  recovery_result=$?
  worker_exec_history reconcile
  recovery_history_result=$?
  if [ "$recovery_result" -eq 0 ] && [ "$recovery_history_result" -eq 0 ]; then
    WORKER_RESULT_OVERRIDE=failed
    WORKER_ERROR_CODE_OVERRIDE=pause_history_reconcile_failed
  else
    [ "$recovery_history_result" -eq 0 ] ||
      log_event warn history_reconcile_failed "pause-recovery:$recovery_history_result" || true
    WORKER_RESULT_OVERRIDE=critical
    WORKER_ERROR_CODE_OVERRIDE=pause_recovery_failed
  fi
  return "$history_result"
}

worker_resume_transaction() {
  local history_result recovery_result recovery_history_result
  worker_exec_engine resume || return
  worker_exec_history reconcile
  history_result=$?
  [ "$history_result" -ne 0 ] || return 0
  log_event warn history_reconcile_failed "resume:$history_result" || true
  WORKER_TRANSACTION_HANDLED=1
  worker_exec_engine pause
  recovery_result=$?
  worker_exec_history reconcile
  recovery_history_result=$?
  if [ "$recovery_result" -eq 0 ] && [ "$recovery_history_result" -eq 0 ]; then
    WORKER_RESULT_OVERRIDE=failed
    WORKER_ERROR_CODE_OVERRIDE=resume_history_reconcile_failed
  else
    [ "$recovery_history_result" -eq 0 ] ||
      log_event warn history_reconcile_failed "resume-recovery:$recovery_history_result" || true
    WORKER_RESULT_OVERRIDE=critical
    WORKER_ERROR_CODE_OVERRIDE=resume_recovery_failed
  fi
  return "$history_result"
}

worker_run_engine() {
  local result=0 repair_result=0
  WORKER_TRANSACTION_HANDLED=0
  WORKER_RESULT_OVERRIDE=
  WORKER_ERROR_CODE_OVERRIDE=
  case "$OPERATION_VERB" in
    refresh) worker_exec_engine refresh ;;
    refresh-source) worker_exec_engine refresh-source "$OPERATION_ARG_1" ;;
    set-auto-refresh) worker_exec_refresh configure "$OPERATION_ARG_1" "$OPERATION_ARG_2" ;;
    set-builtin) worker_exec_engine set-builtin "$OPERATION_ARG_1" "$OPERATION_ARG_2" ;;
    add-source) worker_exec_engine add-source "$OPERATION_ARG_1" "$OPERATION_ARG_2" ;;
    update-source) worker_exec_engine update-source "$OPERATION_ARG_1" "$OPERATION_ARG_2" "$OPERATION_ARG_3" ;;
    set-source) worker_exec_engine toggle-source "$OPERATION_ARG_1" "$OPERATION_ARG_2" ;;
    move-source) worker_exec_engine move-source "$OPERATION_ARG_1" "$OPERATION_ARG_2" ;;
    remove-source) worker_exec_engine remove-source "$OPERATION_ARG_1" ;;
    set-overrides) worker_exec_engine set-overrides "$OPERATION_ARG_1" ;;
    reset-rules) worker_exec_engine reset-rules ;;
    set-notice) preferences_set_notice "$OPERATION_ARG_1" ;;
    set-log-mode) preferences_set_log_mode "$OPERATION_ARG_1" ;;
    set-app-policy) app_policy_apply "$OPERATION_ARG_1" "$OPERATION_ARG_2" "$OPERATION_ARG_3" ;;
    set-lists) worker_exec_engine set-lists "$OPERATION_ARG_1" "$OPERATION_ARG_2" ;;
    set-enhanced-whitelist) worker_exec_engine set-enhanced-whitelist "$OPERATION_ARG_1" "$OPERATION_ARG_2" "$OPERATION_ARG_3" ;;
    set-domain-decision) worker_exec_engine set-domain-decision "$OPERATION_ARG_1" "$OPERATION_ARG_2" ;;
    select-mode) worker_exec_engine select "$OPERATION_ARG_1" ;;
    pause) worker_pause_transaction ;;
    resume) worker_resume_transaction ;;
    rollback) worker_exec_engine rollback ;;
    set-history) worker_exec_history enable "$OPERATION_ARG_1" ;;
    clear-history) worker_exec_history clear ;;
    clear-cache) worker_exec_engine clear-cache ;;
    test-doh|set-doh|disable-doh) worker_exec_doh ;;
    *) return 64 ;;
  esac
  result=$?
  if [ "$result" -ne 0 ]; then
    [ "$WORKER_TRANSACTION_HANDLED" -eq 0 ] || return "$result"
    if operation_verb_requires_mount_repair "$OPERATION_VERB"; then
      operation_mount_repair || {
        repair_result=$?
        log_event warn operation_mount_repair_failed "$OPERATION_VERB:$repair_result" || true
      }
    fi
    return "$result"
  fi
  case "$OPERATION_VERB" in
    refresh|refresh-source|set-builtin|add-source|update-source|set-source|move-source|remove-source|set-overrides|reset-rules|set-lists|set-enhanced-whitelist|set-domain-decision|select-mode|rollback)
      if ! worker_effective_mode_paused; then
        worker_exec_history reconcile || {
          result=$?
          log_event warn history_reconcile_failed "$OPERATION_VERB:$result" || true
        }
      fi
      ;;
  esac
}

worker_exec_refresh() {
  [ "$#" -eq 3 ] && [ "$1" = configure ] || return 64
  "$SYSTEM_SH" "$MODDIR/refresh_manager.sh" configure "$2" "$3"
}

worker_exec_history() {
  local command=$1
  case "$command" in
    enable)
      [ "$#" -eq 2 ] && { [ "$2" = 0 ] || [ "$2" = 1 ]; } || return 65
      if [ "$2" = 1 ]; then
        "$SYSTEM_SH" "$MODDIR/history_manager.sh" enable
      else
        "$SYSTEM_SH" "$MODDIR/history_manager.sh" disable
      fi
      ;;
    clear) [ "$#" -eq 1 ] || return 64; "$SYSTEM_SH" "$MODDIR/history_manager.sh" clear ;;
    reconcile) [ "$#" -eq 1 ] || return 64; "$SYSTEM_SH" "$MODDIR/history_manager.sh" reconcile ;;
    *) return 64 ;;
  esac
}

worker_exec_doh() {
  case "$OPERATION_VERB" in
    test-doh) doh_manager_test "$OPERATION_ARG_1" ;;
    set-doh) doh_manager_apply "$OPERATION_ARG_1" "$OPERATION_ARG_2" "$OPERATION_ARG_3" ;;
    disable-doh) doh_manager_disable ;;
    *) return 64 ;;
  esac
}

worker_doh_arguments_valid() {
  local endpoint_file uid_file result
  case "$OPERATION_VERB" in
    test-doh)
      endpoint_file="$RULE_TMP/worker-doh-endpoint.$$"
      doh_endpoint_value_write "$OPERATION_ARG_1" "$endpoint_file"
      result=$?
      rm -f "$endpoint_file"
      return "$result"
      ;;
    set-doh)
      doh_mode_valid "$OPERATION_ARG_1" || return 65
      endpoint_file="$RULE_TMP/worker-doh-endpoint.$$"
      uid_file="$RULE_TMP/worker-doh-uids.$$"
      doh_endpoint_value_write "$OPERATION_ARG_2" "$endpoint_file" || { result=$?; rm -f "$endpoint_file"; return "$result"; }
      doh_config_b64_decode "$OPERATION_ARG_3" "$uid_file" || { result=$?; rm -f "$endpoint_file" "$uid_file"; return "$result"; }
      if [ "$OPERATION_ARG_1" = selected ]; then
        [ -s "$uid_file" ] || result=65
      else
        [ ! -s "$uid_file" ] || result=65
      fi
      rm -f "$endpoint_file" "$uid_file"
      return "${result:-0}"
      ;;
    disable-doh) [ "$OPERATION_ARGC" -eq 0 ] || return 64 ;;
    *) return 64 ;;
  esac
}

worker_prune_old_operations() {
  local keep=$1 path id
  for path in "$RULE_OPERATIONS"/op_*; do
    [ -e "$path" ] || continue
    [ -d "$path" ] && [ ! -L "$path" ] || continue
    id=${path##*/}
    operation_id_valid "$id" || continue
    [ "$id" = "$keep" ] || rm -rf "$path"
  done
}

operation_worker_main() {
  [ "$#" -eq 2 ] || return 64
  local operation_id=$1 token=$2 start exit_status result phase error_code=engine_failed
  operation_id_valid "$operation_id" || return 65
  operation_token_valid "$token" || return 65
  rules_init_paths "$MODDIR" || return
  worker_wait_ready "$token" || return
  rm -f "$RULE_RUNTIME/ready/$token"
  operation_request_load "$operation_id" || return
  case "$OPERATION_VERB" in
    test-doh|set-doh|disable-doh) worker_doh_arguments_valid || return 65 ;;
    *)
      case "$OPERATION_ARGC" in
        0) operation_arguments_valid "$OPERATION_VERB" || return 65 ;;
        1) operation_arguments_valid "$OPERATION_VERB" "$OPERATION_ARG_1" || return 65 ;;
        2) operation_arguments_valid "$OPERATION_VERB" "$OPERATION_ARG_1" "$OPERATION_ARG_2" || return 65 ;;
        3) operation_arguments_valid "$OPERATION_VERB" "$OPERATION_ARG_1" "$OPERATION_ARG_2" "$OPERATION_ARG_3" || return 65 ;;
        *) return 65 ;;
      esac
      ;;
  esac
  operation_current_load || return 70
  [ "$CURRENT_OPERATION_ID" = "$operation_id" ] && [ "$CURRENT_OPERATION_STATE" = starting ] || return 76
  start=$(proc_starttime "$$") || return 70
  operation_current_write "$operation_id" "$OPERATION_VERB" running "$$" "$start" "$CURRENT_OPERATION_STARTED_AT" || return
  case "$OPERATION_VERB" in
    rollback) phase=rolling_back ;;
    select-mode|pause|resume) phase=mounting ;;
    clear-history|clear-cache) phase=cleaning ;;
    *) phase=validating ;;
  esac
  worker_phase_write "$operation_id" "$phase" || return
  set +e
  worker_run_engine
  exit_status=$?
  set -e
  if [ "$exit_status" -eq 0 ]; then
    [ "$OPERATION_VERB" = rollback ] && result=rolled_back || result=ok
  else
    result=${WORKER_RESULT_OVERRIDE:-failed}
    error_code=${WORKER_ERROR_CODE_OVERRIDE:-${DOH_ERROR_CODE:-engine_failed}}
    if [ -z "${WORKER_ERROR_CODE_OVERRIDE-}" ] && [ "$OPERATION_VERB" = set-history ] && [ "$OPERATION_ARG_1" = 1 ] && \
      operation_history_enable_error_load "$RULE_RUNTIME/history-enable-error.prop" 2>/dev/null; then
      error_code=$OPERATION_HISTORY_ERROR_CODE
    fi
    log_event warn operation_engine_failed "$OPERATION_VERB:$exit_status" || true
  fi
  unset OPERATION_ARG_1 OPERATION_ARG_2 OPERATION_ARG_3
  operation_result_write "$operation_id" "$OPERATION_VERB" "$result" "$error_code" || return
  operation_current_write "$operation_id" "$OPERATION_VERB" finished "$$" "$start" "$CURRENT_OPERATION_STARTED_AT" || return
  worker_prune_old_operations "$operation_id" || log_event warn operation_prune_failed "$operation_id" || true
  log_event info operation_finished "$operation_id:$result" || true
  return 0
}

if [ "${OPERATION_WORKER_SOURCE_ONLY-0}" != 1 ]; then
  operation_worker_main "$@"
fi
