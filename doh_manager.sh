#!/system/bin/sh

DOH_MANAGER_ROOT=${DOH_MANAGER_ROOT:-${0%/*}}
MODDIR=${MODDIR:-$DOH_MANAGER_ROOT}
BB=${BB:-$MODDIR/busybox/busybox}
[ -x "$BB" ] || BB=$(command -v busybox 2>/dev/null || printf '%s' "$BB")
SYSTEM_SH=${SYSTEM_SH:-/system/bin/sh}
export MODDIR BB SYSTEM_SH

. "$DOH_MANAGER_ROOT/lib/rules/common.sh"
. "$DOH_MANAGER_ROOT/lib/rules/doh.sh"

DOH_PROXY_UID=65534
DOH_PROXY_GID=3003
DOH_PORT_A=5533
DOH_PORT_B=5534

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

process_start_doh() {
  "$SYSTEM_SH" "$MODDIR/process_manager.sh" start-doh "$@"
}

process_stop_doh() {
  "$SYSTEM_SH" "$MODDIR/process_manager.sh" stop-doh "$@"
}

firewall_doh_stage() {
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" doh-stage "$@"
}

firewall_doh_switch() {
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" doh-switch "$@"
}

firewall_doh_rollback() {
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" doh-rollback "$@"
}

firewall_doh_remove_owned() {
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" doh-remove-owned "$@"
}

firewall_doh_detach_owned() {
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" doh-detach-owned "$@"
}

firewall_doh_cleanup_owned() {
  [ "$#" -eq 1 ] || return 64
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" doh-cleanup-owned "$@"
}

firewall_doh_cleanup_recovery() {
  [ "$#" -eq 0 ] || return 64
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" doh-cleanup-recovery
}

doh_manager_set_error() {
  doh_error_valid "$1" || return 65
  DOH_ERROR_CODE=$1
  export DOH_ERROR_CODE
}

# A single exit status cannot say which step produced it: 65 means both "the
# committed triplet disagrees" and "a selected UID belongs to the manager", and
# 69 means both "the device cannot install the redirect rules" and "the server
# name did not resolve". Recording the step lets every distinct cause reach the
# user instead of collapsing into one 加密 DNS 运行失败.
doh_stage_set() {
  DOH_FAILURE_STAGE=$1
  export DOH_FAILURE_STAGE
}

doh_manager_error_for() {
  [ "$#" -eq 3 ] || return 64
  local stage=$1 code=$2 fallback=$3 error=
  case "$stage:$code" in
    endpoint:65|endpoint:66) error=invalid_endpoint ;;
    private_dns:75) error=private_dns_active ;;
    package_state:66|package_state:67) error=package_state_invalid ;;
    bootstrap:69) error=bootstrap_unresolved ;;
    firewall:69) error=firewall_unsupported ;;
    companion:*) error=companion_unavailable ;;
    companion_start:*) error=companion_exited ;;
    probe:*) error=upstream_unavailable ;;
    commit:*) error=commit_failed ;;
  esac
  if [ -z "$error" ]; then
    case "$code" in
      65) error=invalid_config ;;
      66|67) error=package_state_invalid ;;
      75) error=private_dns_active ;;
      *) error=$fallback ;;
    esac
  fi
  doh_error_valid "$error" || error=$fallback
  printf '%s\n' "$error"
}

doh_prop_value() {
  [ "$#" -eq 2 ] || return 64
  [ -f "$1" ] && [ ! -L "$1" ] || return 66
  "$BB" awk -F= -v wanted="$2" '$1==wanted{if(found++)exit 65; print $2} END{if(!found)exit 65}' "$1"
}

doh_transition_token_new() {
  local now token
  now=$(date +%s 2>/dev/null || printf 0)
  token=$(printf '%s:%s:%s\n' "$now" "$$" "${DOH_TOKEN_COUNTER:-0}" | sha256_file_stdin) || return
  DOH_TOKEN_COUNTER=$((${DOH_TOKEN_COUNTER:-0} + 1))
  export DOH_TOKEN_COUNTER
  printf '%s\n' "$token" | "$BB" cut -c1-16
}

doh_slot_port() {
  case "$1" in a) printf '%s\n' "$DOH_PORT_A" ;; b) printf '%s\n' "$DOH_PORT_B" ;; *) return 65 ;; esac
}

doh_slot_firewall() {
  case "$1" in a) printf 'A\n' ;; b) printf 'B\n' ;; *) return 65 ;; esac
}

doh_inactive_slot() {
  case "$1" in a) printf 'b\n' ;; b|null|'') printf 'a\n' ;; *) return 65 ;; esac
}

doh_private_dns_check() {
  local mode
  if [ -n "${DOH_PRIVATE_DNS_MODE+x}" ]; then
    mode=$DOH_PRIVATE_DNS_MODE
  else
    command -v settings >/dev/null 2>&1 || return 70
    mode=$(settings get global private_dns_mode 2>/dev/null) || return 70
  fi
  case "$mode" in
    off|opportunistic|null|'') return 0 ;;
    *) return 75 ;;
  esac
}

doh_proxy_owned_pid() {
  [ "$#" -eq 1 ] || return 64
  local wanted=$1 file pid token exe target=${DOH_COMPANION_TARGET:-$MODDIR/tools/jingjie_doh_proxy}
  for file in "$RULE_RUNTIME/doh/process"/slot-a.prop "$RULE_RUNTIME/doh/process"/slot-b.prop; do
    [ -f "$file" ] && [ ! -L "$file" ] || continue
    pid=$(sed -n '4s/^child_pid=//p' "$file")
    token=$(sed -n '2s/^transition_token=//p' "$file")
    [ "$pid" = "$wanted" ] || continue
    [ "${#token}" -eq 16 ] || continue
    exe=$("$BB" readlink "${DOH_PROC_ROOT:-/proc}/$pid/exe" 2>/dev/null || true)
    [ "$exe" = "$target" ] && return 0
  done
  return 1
}

doh_proxy_uid_available() {
  local packages=${DOH_PACKAGES_LIST:-/data/system/packages.list} proc_root=${DOH_PROC_ROOT:-/proc}
  local path pid uid
  [ -f "$packages" ] && [ ! -L "$packages" ] || return 66
  "$BB" awk '$2==65534{found=1} END{exit found?67:0}' "$packages" || return $?
  [ -d "$proc_root" ] || return 66
  for path in "$proc_root"/[0-9]*; do
    [ -d "$path" ] || continue
    pid=${path##*/}
    uid=$("$BB" awk '$1=="Uid:"{print $2; exit}' "$path/status" 2>/dev/null || true)
    [ "$uid" = "$DOH_PROXY_UID" ] || continue
    doh_proxy_owned_pid "$pid" || return 67
  done
}

doh_endpoint_host() {
  [ "$#" -eq 1 ] || return 64
  local endpoint=$1 authority host
  case "$endpoint" in https://*) ;; *) return 65 ;; esac
  authority=${endpoint#https://}
  authority=${authority%%/*}
  authority=${authority%%\?*}
  case "$authority" in
    \[*\]*) host=${authority#\[}; host=${host%%\]*} ;;
    *:*) host=${authority%:*} ;;
    *) host=$authority ;;
  esac
  [ -n "$host" ] || return 65
  printf '%s\n' "$host"
}

doh_ipv4_candidate_valid() {
  local rest=$1 octet count=0
  while [ -n "$rest" ]; do
    case "$rest" in
      *.*) octet=${rest%%.*}; rest=${rest#*.} ;;
      *) octet=$rest; rest= ;;
    esac
    # A leading zero is rejected here because the companion's own parser
    # (net/netip) rejects it, and one unusable candidate fails the whole config.
    case "$octet" in ''|*[!0-9]*|0?*) return 1 ;; esac
    [ "${#octet}" -le 3 ] && [ "$octet" -le 255 ] || return 1
    count=$((count + 1))
  done
  [ "$count" -eq 4 ]
}

doh_ipv6_candidate_valid() {
  local value=$1 rest group count=0 compressed=0
  case "$value" in *:::*) return 1 ;; esac
  case "$value" in *::*) compressed=1 ;; esac
  case "$value" in :*) case "$value" in ::*) ;; *) return 1 ;; esac ;; esac
  case "$value" in *:) case "$value" in *::) ;; *) return 1 ;; esac ;; esac
  rest=$value
  while [ -n "$rest" ]; do
    case "$rest" in
      *:*) group=${rest%%:*}; rest=${rest#*:} ;;
      *) group=$rest; rest= ;;
    esac
    [ -n "$group" ] || continue
    case "$group" in *[!0-9A-Fa-f]*) return 1 ;; esac
    [ "${#group}" -le 4 ] || return 1
    count=$((count + 1))
  done
  if [ "$compressed" -eq 1 ]; then
    [ "$count" -le 7 ]
  else
    [ "$count" -eq 8 ]
  fi
}

doh_ip_candidate_valid() {
  local value=$1
  case "$value" in
    ''|0.0.0.0|127.*|255.255.255.255|::|::1|ff*|FF*) return 1 ;;
  esac
  # An address is dotted-quad or colon-separated, never both. Rejecting the
  # mixed form is what stops a resolver's own "Address: 8.8.8.8:53" header line
  # from being stored as a bootstrap address the companion then refuses.
  case "$value" in
    *.*:*|*:*.*|.*|*.) return 1 ;;
  esac
  case "$value" in
    *:*) doh_ipv6_candidate_valid "$value" ;;
    *.*) doh_ipv4_candidate_valid "$value" ;;
    *) return 1 ;;
  esac
}

doh_resolve_bootstrap_ips() {
  [ "$#" -eq 2 ] || return 64
  local endpoint=$1 output=$2 host method ip raw="$RULE_TMP/doh-resolve.$$" count=0
  host=$(doh_endpoint_host "$endpoint") || return
  : > "$output" || return 74
  # Every method is tried until one yields a usable address. Choosing a single
  # method by tool presence meant a device where the tool exists but resolves
  # nothing never reached the next one, and DoH could not be enabled at all.
  for method in override literal getent nslookup ping; do
    : > "$raw" || { rm -f "$raw" "$output"; return 74; }
    case "$method" in
      override)
        [ -n "${DOH_BOOTSTRAP_IPS-}" ] || continue
        printf '%s\n' $DOH_BOOTSTRAP_IPS > "$raw" || { rm -f "$raw" "$output"; return 74; }
        ;;
      literal)
        doh_ip_candidate_valid "$host" || continue
        printf '%s\n' "$host" > "$raw" || { rm -f "$raw" "$output"; return 74; }
        ;;
      getent)
        command -v getent >/dev/null 2>&1 || continue
        getent ahosts "$host" 2>/dev/null | "$BB" awk '{print $1}' > "$raw" || true
        ;;
      nslookup)
        "$BB" --list 2>/dev/null | "$BB" grep -x nslookup >/dev/null 2>&1 || continue
        # BusyBox echoes the resolver's own Server:/Address: header before the
        # answer, so only lines after "Name:" describe the host. $NF covers the
        # "Address:" and older "Address 1:" layouts alike, and any run of spaces
        # or tabs between the label and the value -- the previous pattern
        # required exactly one space and silently matched nothing.
        "$BB" nslookup "$host" 2>/dev/null | "$BB" awk '
          /^Name:/{answer=1; next}
          answer && /^Address/{print $NF}
        ' > "$raw" || true
        ;;
      ping)
        command -v ping >/dev/null 2>&1 || continue
        # Android always ships ping and it resolves through bionic like any app,
        # printing the address on its first line even when the host drops the
        # echo request, so it is a usable last resort.
        "$BB" timeout -s TERM -k 1 5 ping -c 1 "$host" 2>/dev/null | "$BB" awk '
          NR==1 && match($0, /\([0-9A-Fa-f.:]+\)/){print substr($0, RSTART + 1, RLENGTH - 2); exit}
        ' > "$raw" || true
        ;;
    esac
    while IFS= read -r ip || [ -n "$ip" ]; do
      doh_ip_candidate_valid "$ip" || continue
      printf '%s\n' "$ip" >> "$output" || { rm -f "$raw" "$output"; return 74; }
      count=$((count + 1))
    done < "$raw"
    [ "$count" -eq 0 ] || break
  done
  rm -f "$raw"
  [ "$count" -gt 0 ] || { rm -f "$output"; return 69; }
  LC_ALL=C "$BB" sort -u "$output" | "$BB" head -n 8 > "$output.sorted" || { rm -f "$output" "$output.sorted"; return 74; }
  atomic_replace_file "$output.sorted" "$output" || { rm -f "$output" "$output.sorted"; return 74; }
  chmod 600 "$output" || { rm -f "$output"; return 74; }
}

doh_config_prepare() {
  [ "$#" -eq 4 ] || return 64
  local endpoint_file=$1 slot=$2 transition=$3 output=$4 endpoint encoded fingerprint port ips ip
  [ -f "$endpoint_file" ] && [ ! -L "$endpoint_file" ] || return 66
  doh_endpoint_validate_file "$endpoint_file" || return
  endpoint=$(cat "$endpoint_file") || return 74
  encoded=$("$BB" base64 "$endpoint_file" | "$BB" tr -d '\n') || return 74
  fingerprint=$(sha256_file "$endpoint_file") || return
  port=$(doh_slot_port "$slot") || return
  ips="$RULE_TMP/doh-bootstrap-$transition.$$"
  doh_resolve_bootstrap_ips "$endpoint" "$ips" || return
  {
    printf 'schema_version=1\n'
    printf 'endpoint_b64=%s\n' "$encoded"
    printf 'endpoint_fingerprint=%s\n' "$fingerprint"
    while IFS= read -r ip || [ -n "$ip" ]; do printf 'bootstrap_ip=%s\n' "$ip"; done < "$ips"
    printf 'listen_port=%s\n' "$port"
    printf 'transition_token=%s\n' "$transition"
    printf 'proxy_uid=%s\n' "$DOH_PROXY_UID"
    printf 'proxy_gid=%s\n' "$DOH_PROXY_GID"
  } > "$output" || { rm -f "$ips" "$output"; return 74; }
  rm -f "$ips"
  chmod 600 "$output" || { rm -f "$output"; return 74; }
}

doh_probe() {
  [ "$#" -eq 1 ] || return 64
  local config_file=$1
  [ -f "$config_file" ] && [ ! -L "$config_file" ] || return 66
  "$DOH_COMPANION_TARGET" probe --config-fd 3 3<"$config_file" >/dev/null 2>&1
}

doh_commit_effective() {
  [ "$#" -eq 3 ] || return 64
  local mode=$1 transition=$2 slot=$3 now coverage
  [ "$mode" = selected ] && coverage=direct_dns_only || coverage=all_dns
  doh_state_update_runtime "$mode" "$mode" "$transition" "$slot" null || return
  now=$(date +%s 2>/dev/null || printf 0)
  doh_runtime_write running active "$coverage" "$transition" "$slot" null "$now"
}

doh_commit_off_error() {
  [ "$#" -eq 1 ] || return 64
  local error=$1 now
  doh_error_valid "$error" || return 65
  doh_state_update_runtime off off null null "$error" || return
  now=$(date +%s 2>/dev/null || printf 0)
  doh_runtime_write stopped absent system_dns null null "$error" "$now"
}

doh_manager_runtime_failure() {
  [ "$#" -eq 1 ] || return 64
  doh_commit_off_error "$1"
}

doh_activation_compensate() {
  [ "$#" -eq 4 ] || return 64
  local slot=$1 transition=$2 firewall_staged=$3 error=$4 result=0 stop_result
  DOH_ACTIVATION_RESTORE_SAFE=0
  [ "$firewall_staged" -eq 0 ] || firewall_doh_rollback "$transition" >/dev/null 2>&1 || result=$?
  process_stop_doh "$slot" >/dev/null 2>&1 || {
    stop_result=$?
    [ "$result" -ne 0 ] || result=$stop_result
  }
  [ "$result" -eq 0 ] || return "$result"
  DOH_ACTIVATION_RESTORE_SAFE=1
}

doh_manager_snapshot_active() {
  [ "$#" -eq 1 ] || return 64
  local recovery=$1 desired effective token slot runtime_companion runtime_firewall runtime_token runtime_slot coverage expected
  DOH_PREVIOUS_ACTIVE=0
  DOH_PREVIOUS_SLOT=null
  DOH_PREVIOUS_TOKEN=null
  DOH_MANAGER_RECOVERY_DIR=
  desired=$(doh_prop_value "$DOH_CONFIG_STATE" desired_mode) || return
  effective=$(doh_prop_value "$DOH_CONFIG_STATE" effective_mode) || return
  [ "$effective" != off ] || return 0
  [ "$desired" = "$effective" ] || return 65
  token=$(doh_prop_value "$DOH_CONFIG_STATE" transition_token) || return
  slot=$(doh_prop_value "$DOH_CONFIG_STATE" active_slot) || return
  runtime_companion=$(doh_prop_value "$DOH_RUNTIME_STATE" companion_state) || return
  runtime_firewall=$(doh_prop_value "$DOH_RUNTIME_STATE" firewall_state) || return
  runtime_token=$(doh_prop_value "$DOH_RUNTIME_STATE" transition_token) || return
  runtime_slot=$(doh_prop_value "$DOH_RUNTIME_STATE" active_slot) || return
  coverage=$(doh_prop_value "$DOH_RUNTIME_STATE" coverage) || return
  [ "$effective" = selected ] && expected=direct_dns_only || expected=all_dns
  [ "$runtime_companion" = running ] && [ "$runtime_firewall" = active ] || return 65
  [ "$runtime_token" = "$token" ] && [ "$runtime_slot" = "$slot" ] && [ "$coverage" = "$expected" ] || return 65
  [ "$token" != null ] && [ "$slot" != null ] || return 65
  [ ! -e "$recovery" ] && [ ! -L "$recovery" ] || return 76
  mkdir -p "$recovery" || return 73
  chmod 700 "$recovery" || return 74
  cp "$DOH_CONFIG_STATE" "$recovery/doh.prop" &&
    cp "$DOH_CONFIG_ENDPOINT" "$recovery/doh-endpoint.txt" &&
    cp "$DOH_CONFIG_UIDS" "$recovery/doh-uids.tsv" &&
    cp "$DOH_RUNTIME_STATE" "$recovery/runtime.prop" || return 74
  chmod 600 "$recovery"/* || return 74
  doh_triplet_validate "$recovery/doh.prop" "$recovery/doh-endpoint.txt" "$recovery/doh-uids.tsv" || return 76
  DOH_PREVIOUS_ACTIVE=1
  DOH_PREVIOUS_SLOT=$slot
  DOH_PREVIOUS_TOKEN=$token
  DOH_MANAGER_RECOVERY_DIR=$recovery
}

doh_manager_restore_active() {
  [ "$#" -eq 1 ] || return 64
  local recovery=$1 runtime_tmp="$DOH_RUNTIME_DIR/.runtime.restore.$$"
  [ -d "$recovery" ] && [ ! -L "$recovery" ] || return 76
  doh_triplet_validate "$recovery/doh.prop" "$recovery/doh-endpoint.txt" "$recovery/doh-uids.tsv" || return 76
  [ -f "$recovery/runtime.prop" ] && [ ! -L "$recovery/runtime.prop" ] || return 76
  doh_publish_file "$recovery/doh-endpoint.txt" "$DOH_CONFIG_ENDPOINT" || return 76
  doh_publish_file "$recovery/doh-uids.tsv" "$DOH_CONFIG_UIDS" || return 76
  doh_publish_file "$recovery/doh.prop" "$DOH_CONFIG_STATE" || return 76
  cp "$recovery/runtime.prop" "$runtime_tmp" || return 76
  chmod 600 "$runtime_tmp" || { rm -f "$runtime_tmp"; return 76; }
  atomic_replace_file "$runtime_tmp" "$DOH_RUNTIME_STATE" || { rm -f "$runtime_tmp"; return 76; }
  doh_triplet_validate "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS" || return 76
  rm -rf "$recovery" || return 76
  DOH_MANAGER_RECOVERY_DIR=
}

doh_manager_activate() {
  [ "$#" -ge 1 ] && [ "$#" -le 2 ] || return 64
  local intent=$1 mode old_slot slot firewall_slot port transition config_file result now uid_stage
  case "$intent" in enable|boot) ;; *) return 64 ;; esac
  DOH_ACTIVATION_COMMITTED=0
  DOH_ACTIVATION_RESTORE_SAFE=1
  DOH_COMPANION_UNAVAILABLE=0
  doh_stage_set config
  mode=$(doh_prop_value "$DOH_CONFIG_STATE" desired_mode) || return
  case "$mode" in global|selected) ;; off) return 0 ;; *) return 65 ;; esac
  doh_triplet_validate "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS" || return
  [ "$mode" != selected ] || doh_validate_uid_ownership "$DOH_CONFIG_UIDS" || return
  doh_stage_set private_dns
  doh_private_dns_check || return
  doh_stage_set package_state
  doh_proxy_uid_available || return
  doh_stage_set companion
  doh_companion_ensure "$intent" || { result=$?; DOH_COMPANION_UNAVAILABLE=1; return "$result"; }
  doh_stage_set config
  if [ "$#" -eq 2 ]; then old_slot=$2; else old_slot=$(doh_prop_value "$DOH_CONFIG_STATE" active_slot) || return; fi
  slot=$(doh_inactive_slot "$old_slot") || return
  firewall_slot=$(doh_slot_firewall "$slot") || return
  port=$(doh_slot_port "$slot") || return
  transition=$(doh_transition_token_new) || return
  config_file="$DOH_RUNTIME_DIR/config-$transition-$slot.prop"
  [ ! -e "$config_file" ] && [ ! -L "$config_file" ] || return 76
  doh_stage_set bootstrap
  doh_config_prepare "$DOH_CONFIG_ENDPOINT" "$slot" "$transition" "$config_file" || return
  doh_stage_set probe
  doh_probe "$config_file"
  result=$?
  if [ "$result" -ne 0 ]; then
    rm -f "$config_file"
    return "$result"
  fi
  now=$(date +%s 2>/dev/null || printf 0)
  doh_runtime_write starting absent system_dns "$transition" "$slot" null "$now" || { rm -f "$config_file"; return 74; }
  doh_stage_set companion_start
  process_start_doh "$slot" "$transition" "$config_file"
  result=$?
  rm -f "$config_file"
  if [ "$result" -ne 0 ]; then
    doh_activation_compensate "$slot" "$transition" 0 companion_exited
    return "$result"
  fi
  doh_stage_set firewall
  # firewall_manager accepts a uid file only from RULE_TMP and refuses every
  # other path with 65 (firewall_doh_uid_file_valid), so the committed CONFIG_DIR
  # copy has to be staged there first. Handing over the config path directly meant
  # staging was rejected on every attempt and encrypted DNS could never turn on.
  # app_policy_apply already stages its uid file the same way.
  uid_stage="$RULE_TMP/doh-stage-uids-$transition.$$"
  rm -f "$uid_stage"
  if ! cp "$DOH_CONFIG_UIDS" "$uid_stage" || ! chmod 600 "$uid_stage"; then
    rm -f "$uid_stage"
    doh_activation_compensate "$slot" "$transition" 0 runtime_failed
    return 74
  fi
  firewall_doh_stage "$mode" "$firewall_slot" "$port" "$transition" "$uid_stage"
  result=$?
  rm -f "$uid_stage"
  if [ "$result" -ne 0 ]; then
    doh_activation_compensate "$slot" "$transition" 0 runtime_failed
    return "$result"
  fi
  now=$(date +%s 2>/dev/null || printf 0)
  doh_runtime_write running staged system_dns "$transition" "$slot" null "$now" || {
    doh_activation_compensate "$slot" "$transition" 1 runtime_failed
    return 74
  }
  firewall_doh_switch "$transition"
  result=$?
  if [ "$result" -ne 0 ]; then
    doh_activation_compensate "$slot" "$transition" 1 runtime_failed
    return "$result"
  fi
  doh_stage_set commit
  doh_commit_effective "$mode" "$transition" "$slot" || {
    result=$?
    doh_activation_compensate "$slot" "$transition" 1 commit_failed
    return "$result"
  }
  DOH_ACTIVATION_COMMITTED=1
  if [ "$old_slot" != null ] && [ "$old_slot" != "$slot" ]; then
    process_stop_doh "$old_slot" || return
  fi
}

doh_fallback_off() {
  local error=${1:-runtime_failed} token result=0
  token=$(doh_prop_value "$DOH_CONFIG_STATE" transition_token 2>/dev/null || printf null)
  if [ "$token" != null ]; then
    firewall_doh_detach_owned "$token" || return
  fi
  process_stop_doh a || return
  process_stop_doh b || return
  [ "$token" = null ] || firewall_doh_cleanup_owned "$token" || return
  doh_commit_off_error "$error"
}

doh_manager_apply() {
  [ "$#" -eq 3 ] || return 64
  local result error=runtime_failed recovery
  DOH_COMPANION_UNAVAILABLE=0
  doh_stage_set config
  rules_lock_acquire doh || return
  doh_bootstrap || { result=$?; rules_lock_release doh; return "$result"; }
  DOH_ACTIVATION_COMMITTED=0
  DOH_ACTIVATION_RESTORE_SAFE=1
  recovery="$DOH_RUNTIME_DIR/apply-recovery"
  doh_manager_snapshot_active "$recovery" || { result=$?; rules_lock_release doh; return "$result"; }
  doh_apply "$1" "$2" "$3"
  result=$?
  if [ "$result" -eq 0 ]; then
    if [ "$1" = off ]; then
      doh_manager_disable_runtime "$DOH_PREVIOUS_TOKEN"
      result=$?
      [ "$result" -ne 0 ] || doh_disable || result=$?
    else
      doh_manager_activate enable "$DOH_PREVIOUS_SLOT"
      result=$?
    fi
  fi
  if [ "$result" -ne 0 ]; then
    error=$(doh_manager_error_for "${DOH_FAILURE_STAGE:-config}" "$result" runtime_failed)
    if [ "${DOH_COMPANION_UNAVAILABLE:-0}" -eq 1 ]; then error=companion_unavailable; fi
    if [ "$DOH_PREVIOUS_ACTIVE" -eq 1 ] && [ "$DOH_ACTIVATION_COMMITTED" -eq 0 ] && [ "$DOH_ACTIVATION_RESTORE_SAFE" -eq 1 ]; then
      doh_manager_restore_active "$recovery" >/dev/null 2>&1 || result=76
    elif [ "$DOH_PREVIOUS_ACTIVE" -eq 0 ]; then
      doh_commit_off_error "$error" >/dev/null 2>&1 || true
    fi
    doh_manager_set_error "$error" || true
  elif [ "$DOH_PREVIOUS_ACTIVE" -eq 1 ]; then
    rm -rf "$recovery" || result=76
  fi
  rules_lock_release doh || return
  return "$result"
}

doh_manager_test() {
  [ "$#" -eq 1 ] || return 64
  local endpoint_tmp config_file transition result error=
  rules_lock_acquire doh || return
  doh_bootstrap || { result=$?; rules_lock_release doh; return "$result"; }
  endpoint_tmp="$RULE_TMP/doh-test-endpoint.$$"
  doh_stage_set endpoint
  doh_endpoint_value_write "$1" "$endpoint_tmp" || result=$?
  [ -n "${result-}" ] || doh_stage_set companion
  [ -n "${result-}" ] || doh_companion_ensure test || { result=$?; error=companion_unavailable; }
  if [ -z "${result-}" ]; then transition=$(doh_transition_token_new) || result=$?; fi
  if [ -z "${result-}" ]; then
    config_file="$DOH_RUNTIME_DIR/test-$transition.prop"
    doh_stage_set bootstrap
    doh_config_prepare "$endpoint_tmp" a "$transition" "$config_file" || result=$?
  fi
  # A probe failure during an explicit test is reported as test_failed, not
  # upstream_unavailable: nothing was switched over, so there is no fallback to
  # tell the user about -- the URL simply did not answer.
  [ -n "${result-}" ] || doh_stage_set test_probe
  [ -n "${result-}" ] || doh_probe "$config_file" || result=$?
  if [ -z "${result-}" ]; then doh_test_endpoint "$1" || result=$?; fi
  rm -f "$endpoint_tmp" "${config_file-}"
  if [ -n "${result-}" ]; then
    if [ -z "$error" ]; then
      error=$(doh_manager_error_for "${DOH_FAILURE_STAGE:-endpoint}" "$result" test_failed)
    fi
    doh_manager_set_error "$error" || true
  else
    result=0
  fi
  rules_lock_release doh || return
  return "$result"
}

doh_manager_disable_runtime() {
  [ "$#" -le 1 ] || return 64
  local token result=0
  if [ "$#" -eq 1 ]; then
    token=$1
  else
    token=$(doh_prop_value "$DOH_CONFIG_STATE" transition_token 2>/dev/null || printf null)
  fi
  if [ "$token" != null ]; then
    [ "${#token}" -eq 16 ] || return 65
    case "$token" in *[!0-9a-f]*) return 65 ;; esac
  fi
  [ "$token" = null ] || firewall_doh_detach_owned "$token" || return
  process_stop_doh a || result=$?
  process_stop_doh b || result=$?
  [ "$token" = null ] || firewall_doh_cleanup_owned "$token" || result=$?
  [ "$result" -eq 0 ] || return "$result"
  doh_commit_disabled
}

doh_commit_disabled() {
  local now
  doh_state_update_runtime off off null null null || return
  now=$(date +%s 2>/dev/null || printf 0)
  doh_runtime_write stopped absent system_dns null null null "$now"
}

doh_manager_disable() {
  local result
  rules_lock_acquire doh || return
  doh_bootstrap || { result=$?; rules_lock_release doh; return "$result"; }
  doh_manager_disable_runtime
  result=$?
  [ "$result" -ne 0 ] || doh_disable || result=$?
  if [ "$result" -ne 0 ]; then doh_manager_set_error recovery_failed || true; fi
  rules_lock_release doh || return
  return "$result"
}

doh_manager_boot() {
  [ "$#" -eq 0 ] || return 64
  local mode result error=runtime_failed
  DOH_COMPANION_UNAVAILABLE=0
  rules_lock_acquire doh || return
  doh_bootstrap || { result=$?; rules_lock_release doh; return "$result"; }
  mode=$(doh_prop_value "$DOH_CONFIG_STATE" desired_mode) || { result=$?; rules_lock_release doh; return "$result"; }
  if [ "$mode" = off ]; then
    rules_lock_release doh || return
    return 0
  fi
  doh_manager_activate boot
  result=$?
  if [ "$result" -ne 0 ]; then
    error=$(doh_manager_error_for "${DOH_FAILURE_STAGE:-config}" "$result" runtime_failed)
    if [ "${DOH_COMPANION_UNAVAILABLE:-0}" -eq 1 ]; then error=companion_unavailable; fi
    doh_fallback_off "$error" >/dev/null 2>&1 || true
  fi
  rules_lock_release doh || return
  return "$result"
}

doh_manager_crash_reason() {
  [ "$#" -eq 1 ] || return 64
  local transition=$1 file="$DOH_RUNTIME_DIR/crash-$1.prop" schema token reason
  [ -f "$file" ] && [ ! -L "$file" ] || { printf 'companion_exited\n'; return 0; }
  [ "$(wc -l < "$file" | "$BB" tr -d ' ')" -eq 3 ] || { rm -f "$file"; printf 'companion_exited\n'; return 0; }
  schema=$(sed -n '1s/^schema_version=//p' "$file")
  token=$(sed -n '2s/^transition_token=//p' "$file")
  reason=$(sed -n '3s/^reason=//p' "$file")
  rm -f "$file"
  [ "$schema" = 1 ] && [ "$token" = "$transition" ] || { printf 'companion_exited\n'; return 0; }
  case "$reason" in upstream_unavailable|companion_exited) printf '%s\n' "$reason" ;; *) printf 'companion_exited\n' ;; esac
}

doh_manager_crash() {
  [ "$#" -eq 1 ] || return 64
  local transition=$1 current effective active peer reason result=0
  case "$transition" in ''|*[!0-9a-f]*) return 65 ;; esac
  [ "${#transition}" -eq 16 ] || return 65
  rules_lock_acquire doh || return
  doh_bootstrap || { result=$?; rules_lock_release doh; return "$result"; }
  current=$(doh_prop_value "$DOH_CONFIG_STATE" transition_token) || result=$?
  effective=$(doh_prop_value "$DOH_CONFIG_STATE" effective_mode) || result=$?
  if [ "$result" -ne 0 ]; then rules_lock_release doh; return "$result"; fi
  if [ "$current" != "$transition" ] || [ "$effective" = off ]; then
    rm -f "$DOH_RUNTIME_DIR/crash-$transition.prop"
    rules_lock_release doh || return
    return 0
  fi
  active=$(doh_prop_value "$DOH_CONFIG_STATE" active_slot) || result=$?
  firewall_doh_detach_owned "$transition"
  result=$?
  if [ "$result" -ne 0 ]; then rules_lock_release doh; return "$result"; fi
  reason=$(doh_manager_crash_reason "$transition") || result=$?
  if [ "$result" -ne 0 ]; then rules_lock_release doh; return "$result"; fi
  if [ "$active" = a ]; then peer=b; else peer=a; fi
  process_stop_doh "$peer"
  result=$?
  if [ "$result" -ne 0 ]; then rules_lock_release doh; return "$result"; fi
  firewall_doh_cleanup_owned "$transition"
  result=$?
  if [ "$result" -ne 0 ]; then rules_lock_release doh; return "$result"; fi
  doh_manager_runtime_failure "$reason"
  result=$?
  rules_lock_release doh || return
  return "$result"
}

doh_manager_cleanup_uninstall() {
  [ "$#" -eq 0 ] || return 64
  local token=null result=0 target recovered=0
  doh_init_paths
  mkdir -p "$RULE_LOCKS" || return 73
  rules_lock_acquire doh || return
  target=${DOH_COMPANION_TARGET:-$MODDIR/tools/jingjie_doh_proxy}
  [ "$target" = "$MODDIR/tools/jingjie_doh_proxy" ] || { rules_lock_release doh; return 76; }
  if doh_triplet_validate "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS" 2>/dev/null; then
    token=$(doh_prop_value "$DOH_CONFIG_STATE" transition_token 2>/dev/null || printf null)
  fi
  if [ "$token" = null ]; then
    firewall_doh_cleanup_recovery
    result=$?
    [ "$result" -eq 0 ] || { rules_lock_release doh; return "$result"; }
    recovered=1
  else
    firewall_doh_detach_owned "$token"
    result=$?
    [ "$result" -eq 0 ] || { rules_lock_release doh; return "$result"; }
  fi
  process_stop_doh a || result=$?
  process_stop_doh b || result=$?
  [ "$result" -eq 0 ] || { rules_lock_release doh; return "$result"; }
  [ "$recovered" -eq 1 ] || firewall_doh_cleanup_owned "$token" || result=$?
  [ "$result" -eq 0 ] || { rules_lock_release doh; return "$result"; }
  rm -f "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS" || result=$?
  rm -f "$target" || result=$?
  rm -rf "$DOH_RUNTIME_DIR" || result=$?
  rules_lock_release doh || return
  return "$result"
}

doh_manager_dispatch() {
  DOH_ERROR_CODE=
  export DOH_ERROR_CODE
  doh_stage_set config
  case "${1-}:$#" in
    test:2) doh_manager_test "$2" ;;
    apply:4) doh_manager_apply "$2" "$3" "$4" ;;
    disable:1) doh_manager_disable ;;
    boot:1) doh_manager_boot ;;
    crash:2) doh_manager_crash "$2" ;;
    cleanup-uninstall:1) doh_manager_cleanup_uninstall ;;
    status-json:1) doh_status_json ;;
    apps-json:4) doh_apps_json "$2" "$3" "$4" ;;
    *) return 64 ;;
  esac
}

if [ "${DOH_MANAGER_SOURCE_ONLY-0}" != 1 ]; then
  rules_init_paths "$MODDIR" || exit $?
  doh_manager_dispatch "$@"
fi
