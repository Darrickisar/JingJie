#!/system/bin/sh

FIREWALL_ROOT=${FIREWALL_ROOT:-${TEST_ROOT:-${0%/*}}}
MODDIR=${MODDIR:-$FIREWALL_ROOT}
BB=${BB:-$MODDIR/busybox/busybox}
[ -x "$BB" ] || BB=$(command -v busybox 2>/dev/null || printf '%s' "$BB")
export MODDIR BB

. "$FIREWALL_ROOT/lib/rules/common.sh"

firewall_manifest() { printf '%s\n' "$RULE_RUNTIME/firewall.tsv"; }
firewall_history_manifest() { printf '%s\n' "$RULE_RUNTIME/history-firewall.tsv"; }
firewall_history_pending_manifest() { printf '%s\n' "$RULE_RUNTIME/history-firewall.pending.tsv"; }
firewall_history_probe_manifest() { printf '%s\n' "$RULE_RUNTIME/history-probe.tsv"; }

HISTORY_CHAIN=JINGJIE_HISTORY_GUARD
HISTORY_TRACE_CIDR=127.64.0.0/13
HISTORY_NFLOG_GROUP=10007

firewall_xt() {
  local family=$1 table=$2
  shift 2
  if [ -n "${FIREWALL_TEST_BACKEND-}" ]; then
    XT_FAMILY=$family "$FIREWALL_TEST_BACKEND" -t "$table" "$@"
    return
  fi
  local command
  [ "$family" = ipv4 ] && command=iptables || command=ip6tables
  command=$(command -v "$command" 2>/dev/null || true)
  [ -n "$command" ] || return 69
  "$command" -t "$table" "$@"
}

firewall_b64() { printf '%s' "$1" | "$BB" base64 | tr -d '\n'; }
firewall_unb64() { printf '%s' "$1" | "$BB" base64 -d; }

firewall_value_valid() {
  case "$1" in ''|*[!A-Za-z0-9._:-]*) return 1 ;; *) return 0 ;; esac
}

firewall_rule_append() {
  local file=$1 rule=$2 encoded
  encoded=$(firewall_b64 "$rule") || return
  printf '%s\n' "$encoded" >> "$file"
}

firewall_history_token_valid() {
  [ "${#1}" -eq 16 ] || return 1
  case "$1" in *[!0-9a-f]*) return 1 ;; *) return 0 ;; esac
}

firewall_history_jump_rule() {
  local chain=${1:-$HISTORY_CHAIN}
  case "$chain" in ''|*[!A-Z0-9_]*) return 65 ;; esac
  printf '%s\n' "-j $chain"
}

firewall_history_jump_rule_legacy() {
  printf '%s\n' "-m comment --comment $RULE_MODULE_ID:history -j $HISTORY_CHAIN"
}

firewall_history_jump_rule_valid() {
  local rule=$1 expected
  expected=$(firewall_history_jump_rule) || return
  [ "$rule" = "$expected" ] && return 0
  expected=$(firewall_history_jump_rule_legacy) || return
  [ "$rule" = "$expected" ]
}

firewall_history_nflog_rule() {
  firewall_history_token_valid "$1" || return 65
  printf '%s\n' "-d $HISTORY_TRACE_CIDR -p tcp --syn -j NFLOG --nflog-group $HISTORY_NFLOG_GROUP --nflog-prefix jjh:$1 --nflog-size 128 --nflog-threshold 1"
}

firewall_history_nflog_rule_legacy() {
  firewall_history_token_valid "$1" || return 65
  printf '%s\n' "-d $HISTORY_TRACE_CIDR -p tcp --syn -m limit --limit 120/second --limit-burst 240 -j NFLOG --nflog-group $HISTORY_NFLOG_GROUP --nflog-prefix jjh:$1 --nflog-size 128 --nflog-threshold 1"
}

firewall_history_nflog_rule_valid() {
  local token=$1 rule=$2 expected
  expected=$(firewall_history_nflog_rule "$token") || return
  [ "$rule" = "$expected" ] && return 0
  expected=$(firewall_history_nflog_rule_legacy "$token") || return
  [ "$rule" = "$expected" ]
}

firewall_history_reject_rule() {
  printf '%s\n' "-d $HISTORY_TRACE_CIDR -j REJECT"
}

firewall_history_manifest_write() {
  local state=$1 token=$2 destination=${3:-$(firewall_history_manifest)} jump_b64=${4-}
  local tmp jump nflog reject actual
  [ "$state" = active ] || [ "$state" = guard ] || return 65
  firewall_history_token_valid "$token" || return 65
  if [ -n "$jump_b64" ]; then
    actual=$(firewall_unb64 "$jump_b64" 2>/dev/null) || return 65
    firewall_history_jump_rule_valid "$actual" || return 65
    jump=$jump_b64
  else
    jump=$(firewall_b64 "$(firewall_history_jump_rule)") || return
  fi
  nflog=$(firewall_b64 "$(firewall_history_nflog_rule "$token")") || return
  reject=$(firewall_b64 "$(firewall_history_reject_rule)") || return
  tmp="$destination.tmp.$$"
  printf 'history-v1\t%s\t%s\t%s\t%s\t%s\n' "$state" "$token" "$jump" "$nflog" "$reject" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$destination"
}

firewall_history_manifest_load() {
  local file=${1:-$(firewall_history_manifest)} line fields expected actual
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  [ "$(wc -l < "$file" | tr -d ' ')" -eq 1 ] || return 65
  line=$(cat "$file") || return 70
  fields=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print NF}')
  [ "$fields" -eq 6 ] || return 65
  IFS="$(printf '\t')" read -r HISTORY_SCHEMA HISTORY_STATE HISTORY_TOKEN \
    HISTORY_JUMP_B64 HISTORY_NFLOG_B64 HISTORY_REJECT_B64 <<EOF
$line
EOF
  [ "$HISTORY_SCHEMA" = history-v1 ] || return 65
  [ "$HISTORY_STATE" = active ] || [ "$HISTORY_STATE" = guard ] || return 65
  firewall_history_token_valid "$HISTORY_TOKEN" || return 65
  actual=$(firewall_unb64 "$HISTORY_JUMP_B64" 2>/dev/null) || return 65
  firewall_history_jump_rule_valid "$actual" || return 65
  actual=$(firewall_unb64 "$HISTORY_NFLOG_B64" 2>/dev/null) || return 65
  firewall_history_nflog_rule_valid "$HISTORY_TOKEN" "$actual" || return 65
  expected=$(firewall_history_reject_rule)
  [ "$(firewall_unb64 "$HISTORY_REJECT_B64" 2>/dev/null)" = "$expected" ] || return 65
  export HISTORY_SCHEMA HISTORY_STATE HISTORY_TOKEN HISTORY_JUMP_B64 HISTORY_NFLOG_B64 HISTORY_REJECT_B64
}

# Re-enabling logging changes the kernel before the guard manifest can be
# committed.  Keep both sides of that transition in a separate, strict
# journal so a restart can either finish the commit or roll back only the
# exact target rule.
firewall_history_pending_manifest_write() {
  local old_state=$1 old_token=$2 target_token=$3 destination=${4:-$(firewall_history_pending_manifest)}
  local old_nflog_b64=${5-} old_jump_b64=${6-} tmp jump old_nflog target_nflog reject actual
  [ "$old_state" = guard ] || return 65
  firewall_history_token_valid "$old_token" || return 65
  firewall_history_token_valid "$target_token" || return 65
  if [ -n "$old_jump_b64" ]; then
    actual=$(firewall_unb64 "$old_jump_b64" 2>/dev/null) || return 65
    firewall_history_jump_rule_valid "$actual" || return 65
    jump=$old_jump_b64
  else
    jump=$(firewall_b64 "$(firewall_history_jump_rule)") || return
  fi
  if [ -n "$old_nflog_b64" ]; then
    old_nflog=$(firewall_unb64 "$old_nflog_b64" 2>/dev/null) || return 65
    firewall_history_nflog_rule_valid "$old_token" "$old_nflog" || return 65
    old_nflog=$old_nflog_b64
  else
    old_nflog=$(firewall_b64 "$(firewall_history_nflog_rule "$old_token")") || return
  fi
  target_nflog=$(firewall_b64 "$(firewall_history_nflog_rule "$target_token")") || return
  reject=$(firewall_b64 "$(firewall_history_reject_rule)") || return
  tmp="$destination.tmp.$$"
  printf 'history-pending-v1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$old_state" "$old_token" "$target_token" "$jump" "$old_nflog" "$target_nflog" "$reject" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$destination"
}

firewall_history_pending_manifest_load() {
  local file=${1:-$(firewall_history_pending_manifest)} line fields expected actual
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  [ "$(wc -l < "$file" | tr -d ' ')" -eq 1 ] || return 65
  line=$(cat "$file") || return 70
  fields=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print NF}')
  [ "$fields" -eq 8 ] || return 65
  IFS="$(printf '\t')" read -r PENDING_SCHEMA PENDING_OLD_STATE PENDING_OLD_TOKEN \
    PENDING_TARGET_TOKEN PENDING_JUMP_B64 PENDING_OLD_NFLOG_B64 \
    PENDING_TARGET_NFLOG_B64 PENDING_REJECT_B64 <<EOF
$line
EOF
  [ "$PENDING_SCHEMA" = history-pending-v1 ] || return 65
  [ "$PENDING_OLD_STATE" = guard ] || return 65
  firewall_history_token_valid "$PENDING_OLD_TOKEN" || return 65
  firewall_history_token_valid "$PENDING_TARGET_TOKEN" || return 65
  actual=$(firewall_unb64 "$PENDING_JUMP_B64" 2>/dev/null) || return 65
  firewall_history_jump_rule_valid "$actual" || return 65
  actual=$(firewall_unb64 "$PENDING_OLD_NFLOG_B64" 2>/dev/null) || return 65
  firewall_history_nflog_rule_valid "$PENDING_OLD_TOKEN" "$actual" || return 65
  actual=$(firewall_unb64 "$PENDING_TARGET_NFLOG_B64" 2>/dev/null) || return 65
  firewall_history_nflog_rule_valid "$PENDING_TARGET_TOKEN" "$actual" || return 65
  expected=$(firewall_history_reject_rule)
  [ "$(firewall_unb64 "$PENDING_REJECT_B64" 2>/dev/null)" = "$expected" ] || return 65
  export PENDING_SCHEMA PENDING_OLD_STATE PENDING_OLD_TOKEN PENDING_TARGET_TOKEN \
    PENDING_JUMP_B64 PENDING_OLD_NFLOG_B64 PENDING_TARGET_NFLOG_B64 PENDING_REJECT_B64
}

firewall_history_pending_target_current() {
  local saved_state=$HISTORY_STATE saved_token=$HISTORY_TOKEN
  local saved_jump=$HISTORY_JUMP_B64 saved_nflog=$HISTORY_NFLOG_B64 saved_reject=$HISTORY_REJECT_B64
  HISTORY_STATE=active
  HISTORY_TOKEN=$PENDING_TARGET_TOKEN
  HISTORY_JUMP_B64=$PENDING_JUMP_B64
  HISTORY_NFLOG_B64=$PENDING_TARGET_NFLOG_B64
  HISTORY_REJECT_B64=$PENDING_REJECT_B64
  firewall_history_current_loaded
  local result=$?
  HISTORY_STATE=$saved_state HISTORY_TOKEN=$saved_token
  HISTORY_JUMP_B64=$saved_jump HISTORY_NFLOG_B64=$saved_nflog HISTORY_REJECT_B64=$saved_reject
  return "$result"
}

firewall_history_pending_target_present() {
  local target
  target=$(firewall_unb64 "$PENDING_TARGET_NFLOG_B64") || return 76
  firewall_chain_exists ipv4 filter "$HISTORY_CHAIN" || return 1
  set -- $target
  firewall_xt ipv4 filter -C "$HISTORY_CHAIN" "$@" >/dev/null 2>&1
}

firewall_history_pending_recover_locked() {
  local pending history jump target had_target=0
  pending=$(firewall_history_pending_manifest)
  [ -e "$pending" ] || { [ ! -L "$pending" ] || return 76; return 0; }
  [ -f "$pending" ] && [ ! -L "$pending" ] || return 76
  firewall_history_pending_manifest_load "$pending" || return 76
  history=$(firewall_history_manifest)

  if [ -f "$history" ]; then
    firewall_history_manifest_load "$history" || return 76
    if [ "$HISTORY_STATE" = active ] && [ "$HISTORY_TOKEN" = "$PENDING_TARGET_TOKEN" ]; then
      [ "$HISTORY_NFLOG_B64" = "$PENDING_TARGET_NFLOG_B64" ] || return 76
      firewall_history_current_loaded || return 76
      rm -f "$pending" || return 76
      return 0
    fi
    [ "$HISTORY_STATE" = guard ] && [ "$HISTORY_TOKEN" = "$PENDING_OLD_TOKEN" ] || return 76
    if firewall_history_pending_target_present; then had_target=1; fi
    if [ "$had_target" -eq 1 ]; then
      # Only remove the target when the entire chain is exactly the pending
      # target plus the owned reject rule and jump.  Foreign/duplicate rules
      # leave the journal intact for a later, safer retry.
      firewall_history_pending_target_current || return 76
      target=$(firewall_unb64 "$PENDING_TARGET_NFLOG_B64") || return 76
      set -- $target
      while firewall_xt ipv4 filter -C "$HISTORY_CHAIN" "$@" >/dev/null 2>&1; do
        firewall_xt ipv4 filter -D "$HISTORY_CHAIN" "$@" || return 76
      done
    fi
    firewall_history_manifest_load "$history" || return 76
    firewall_history_current_loaded || return 76
    rm -f "$pending" || return 76
    return 0
  fi

  # A missing main manifest can only clear the journal when the owned chain
  # and jump are both absent.  Without that proof, do not touch kernel state.
  firewall_chain_exists ipv4 filter "$HISTORY_CHAIN" && return 76
  jump=$(firewall_unb64 "$PENDING_JUMP_B64") || return 76
  set -- $jump
  firewall_xt ipv4 filter -C OUTPUT "$@" >/dev/null 2>&1 && return 76
  rm -f "$pending" || return 76
}

firewall_history_current_loaded() {
  local jump nflog reject actual_count expected_count=1 jump_count
  firewall_chain_exists ipv4 filter "$HISTORY_CHAIN" || return 1
  jump=$(firewall_unb64 "$HISTORY_JUMP_B64") || return 1
  set -- $jump
  firewall_xt ipv4 filter -C OUTPUT "$@" >/dev/null 2>&1 || return 1
  jump_count=$(firewall_history_jump_count_loaded) || return 1
  [ "$jump_count" -eq 1 ] || return 1
  if [ "$HISTORY_STATE" = active ]; then
    nflog=$(firewall_unb64 "$HISTORY_NFLOG_B64") || return 1
    set -- $nflog
    firewall_xt ipv4 filter -C "$HISTORY_CHAIN" "$@" >/dev/null 2>&1 || return 1
    expected_count=2
  fi
  reject=$(firewall_unb64 "$HISTORY_REJECT_B64") || return 1
  set -- $reject
  firewall_xt ipv4 filter -C "$HISTORY_CHAIN" "$@" >/dev/null 2>&1 || return 1
  actual_count=$(firewall_xt ipv4 filter -S "$HISTORY_CHAIN" 2>/dev/null | \
    "$BB" awk -v chain="$HISTORY_CHAIN" '$0=="-N " chain{next} {count++} END{print count+0}') || return 1
  [ "$actual_count" -eq "$expected_count" ]
}

firewall_history_current() {
  firewall_history_manifest_load || return 1
  firewall_history_current_loaded
}

firewall_history_jump_exists_loaded() {
  local jump
  jump=$(firewall_unb64 "$HISTORY_JUMP_B64") || return 1
  set -- $jump
  firewall_xt ipv4 filter -C OUTPUT "$@" >/dev/null 2>&1
}

firewall_history_jump_count_loaded() {
  local expected line count=0
  expected="-A OUTPUT $(firewall_unb64 "$HISTORY_JUMP_B64")" || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    [ "$line" = "$expected" ] && count=$((count + 1))
  done <<EOF
$(firewall_xt ipv4 filter -S OUTPUT 2>/dev/null)
EOF
  printf '%s\n' "$count"
}

firewall_history_kernel_absent_loaded() {
  ! firewall_chain_exists ipv4 filter "$HISTORY_CHAIN" && ! firewall_history_jump_exists_loaded
}

firewall_history_chain_owned_subset_loaded() {
  local actual allowed_nflog allowed_reject line stripped
  firewall_chain_exists ipv4 filter "$HISTORY_CHAIN" || return 0
  actual="$RULE_TMP/history-firewall.subset.$$"
  firewall_xt ipv4 filter -S "$HISTORY_CHAIN" > "$actual" 2>/dev/null || return 76
  allowed_nflog=$(firewall_unb64 "$HISTORY_NFLOG_B64") || { rm -f "$actual"; return 65; }
  allowed_reject=$(firewall_unb64 "$HISTORY_REJECT_B64") || { rm -f "$actual"; return 65; }
  while IFS= read -r line || [ -n "$line" ]; do
    [ "$line" = "-N $HISTORY_CHAIN" ] && continue
    stripped=${line#"-A $HISTORY_CHAIN "}
    [ "$stripped" = "$line" ] && { rm -f "$actual"; return 76; }
    if [ "$stripped" != "$allowed_nflog" ] && [ "$stripped" != "$allowed_reject" ]; then
      case "$stripped" in
        *"-j NFLOG"*"--nflog-group $HISTORY_NFLOG_GROUP"*"--nflog-prefix jjh:$HISTORY_TOKEN"*) ;;
        *) rm -f "$actual"; return 76 ;;
      esac
    fi
  done < "$actual"
  rm -f "$actual"
}

firewall_history_probe_cleanup() {
  local chain=$1 nflog=$2 reject=$3 jump
  jump=$(firewall_history_jump_rule "$chain") || return 76
  set -- $jump
  while firewall_xt ipv4 filter -C OUTPUT "$@" >/dev/null 2>&1; do
    firewall_xt ipv4 filter -D OUTPUT "$@" >/dev/null 2>&1 || return 76
  done
  set -- $nflog; firewall_xt ipv4 filter -D "$chain" "$@" >/dev/null 2>&1 || true
  set -- $reject; firewall_xt ipv4 filter -D "$chain" "$@" >/dev/null 2>&1 || true
  firewall_xt ipv4 filter -X "$chain" >/dev/null 2>&1 || return 76
}

firewall_history_probe_manifest_write() {
  local state=$1 chain=$2 nflog=$3 reject=$4 destination=${5:-$(firewall_history_probe_manifest)} tmp suffix
  [ "$state" = prepared ] || [ "$state" = active ] || return 65
  suffix=${chain#JJ_HP_}
  [ "$suffix" != "$chain" ] || return 65
  case "$suffix" in ''|*[!0-9]*) return 65 ;; esac
  [ "${#chain}" -le 28 ] || return 65
  tmp="$destination.tmp.$$"
  printf 'history-probe-v1\t%s\t%s\t%s\t%s\n' "$state" "$chain" \
    "$(firewall_b64 "$nflog")" "$(firewall_b64 "$reject")" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$destination"
}

firewall_history_probe_manifest_load() {
  local file=${1:-$(firewall_history_probe_manifest)} line fields expected suffix
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  [ "$(wc -l < "$file" | tr -d ' ')" -eq 1 ] || return 65
  line=$(cat "$file") || return 70
  fields=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print NF}')
  [ "$fields" -eq 5 ] || return 65
  IFS="$(printf '\t')" read -r PROBE_SCHEMA PROBE_STATE PROBE_CHAIN PROBE_NFLOG_B64 PROBE_REJECT_B64 <<EOF
$line
EOF
  [ "$PROBE_SCHEMA" = history-probe-v1 ] || return 65
  [ "$PROBE_STATE" = prepared ] || [ "$PROBE_STATE" = active ] || return 65
  suffix=${PROBE_CHAIN#JJ_HP_}
  [ "$suffix" != "$PROBE_CHAIN" ] || return 65
  case "$suffix" in ''|*[!0-9]*) return 65 ;; esac
  [ "${#PROBE_CHAIN}" -le 28 ] || return 65
  expected=$(firewall_history_nflog_rule 0000000000000000) || return
  [ "$(firewall_unb64 "$PROBE_NFLOG_B64" 2>/dev/null)" = "$expected" ] || return 65
  expected=$(firewall_history_reject_rule)
  [ "$(firewall_unb64 "$PROBE_REJECT_B64" 2>/dev/null)" = "$expected" ] || return 65
  export PROBE_SCHEMA PROBE_CHAIN PROBE_NFLOG_B64 PROBE_REJECT_B64
}

firewall_history_probe_recover() {
  local manifest chain nflog reject
  manifest=$(firewall_history_probe_manifest)
  [ -f "$manifest" ] || return 0
  firewall_history_probe_manifest_load "$manifest" || return 76
  chain=$PROBE_CHAIN
  if [ "$PROBE_STATE" = prepared ]; then
    firewall_chain_exists ipv4 filter "$chain" && return 76
    rm -f "$manifest" || return 76
    return 0
  fi
  nflog=$(firewall_unb64 "$PROBE_NFLOG_B64") || return 76
  reject=$(firewall_unb64 "$PROBE_REJECT_B64") || return 76
  if firewall_chain_exists ipv4 filter "$chain"; then
    firewall_history_probe_cleanup "$chain" "$nflog" "$reject" || return 76
  fi
  rm -f "$manifest" || return 76
}

firewall_history_probe_locked() {
  local manifest chain="JJ_HP_$$" jump nflog reject result=0 cleanup_result
  firewall_history_probe_recover || return
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  case "$chain" in *[!A-Z0-9_]*) return 70 ;; esac
  [ "${#chain}" -le 28 ] || return 70
  jump=$(firewall_history_jump_rule "$chain") || return
  nflog=$(firewall_history_nflog_rule 0000000000000000) || return
  reject=$(firewall_history_reject_rule)
  firewall_chain_exists ipv4 filter "$chain" && return 76
  manifest=$(firewall_history_probe_manifest)
  firewall_history_probe_manifest_write prepared "$chain" "$nflog" "$reject" "$manifest" || return
  if ! firewall_xt ipv4 filter -N "$chain"; then
    rm -f "$manifest" || return 76
    return 69
  fi
  if ! firewall_history_probe_manifest_write active "$chain" "$nflog" "$reject" "$manifest"; then
    firewall_history_probe_cleanup "$chain" "$nflog" "$reject" >/dev/null 2>&1 || true
    return 76
  fi
  set -- $nflog
  firewall_xt ipv4 filter -A "$chain" "$@" || result=69
  if [ "$result" -eq 0 ]; then
    set -- $reject
    firewall_xt ipv4 filter -A "$chain" "$@" || result=69
  fi
  if [ "$result" -eq 0 ]; then
    set -- $jump
    firewall_xt ipv4 filter -I OUTPUT 1 "$@" || result=69
  fi
  [ "$result" -ne 0 ] || firewall_xt ipv4 filter -S "$chain" >/dev/null 2>&1 || result=69
  firewall_history_probe_cleanup "$chain" "$nflog" "$reject"
  cleanup_result=$?
  if [ "$cleanup_result" -eq 0 ]; then
    rm -f "$manifest" || cleanup_result=76
  fi
  [ "$cleanup_result" -eq 0 ] || result=$cleanup_result
  return "$result"
}

firewall_history_probe() {
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_history_probe_locked
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_history_remove_exact_loaded() {
  local jump nflog reject
  firewall_history_chain_owned_subset_loaded || return 76
  jump=$(firewall_unb64 "$HISTORY_JUMP_B64") || return 65
  nflog=$(firewall_unb64 "$HISTORY_NFLOG_B64") || return 65
  reject=$(firewall_unb64 "$HISTORY_REJECT_B64") || return 65
  set -- $jump
  while firewall_xt ipv4 filter -C OUTPUT "$@" >/dev/null 2>&1; do
    firewall_xt ipv4 filter -D OUTPUT "$@" || return 74
  done
  firewall_chain_exists ipv4 filter "$HISTORY_CHAIN" || return 0
  if [ "$HISTORY_STATE" = active ]; then
    set -- $nflog
    if firewall_xt ipv4 filter -C "$HISTORY_CHAIN" "$@" >/dev/null 2>&1; then
      firewall_xt ipv4 filter -D "$HISTORY_CHAIN" "$@" || return 74
    fi
  fi
  set -- $reject
  if firewall_xt ipv4 filter -C "$HISTORY_CHAIN" "$@" >/dev/null 2>&1; then
    firewall_xt ipv4 filter -D "$HISTORY_CHAIN" "$@" || return 74
  fi
  firewall_history_chain_owned_subset_loaded || return 76
  firewall_xt ipv4 filter -X "$HISTORY_CHAIN" || return 74
}

firewall_history_install_new_locked() {
  local token=$1 manifest jump nflog reject result=0 created_chain=0 added_nflog=0 added_reject=0 added_jump=0
  manifest=$(firewall_history_manifest)
  firewall_chain_exists ipv4 filter "$HISTORY_CHAIN" && return 76
  firewall_history_manifest_write active "$token" "$manifest" || return
  jump=$(firewall_history_jump_rule)
  nflog=$(firewall_history_nflog_rule "$token") || return
  reject=$(firewall_history_reject_rule)
  if firewall_xt ipv4 filter -N "$HISTORY_CHAIN"; then created_chain=1; else result=76; fi
  if [ "$result" -eq 0 ]; then set -- $nflog; if firewall_xt ipv4 filter -A "$HISTORY_CHAIN" "$@"; then added_nflog=1; else result=74; fi; fi
  if [ "$result" -eq 0 ]; then set -- $reject; if firewall_xt ipv4 filter -A "$HISTORY_CHAIN" "$@"; then added_reject=1; else result=74; fi; fi
  if [ "$result" -eq 0 ]; then set -- $jump; if firewall_xt ipv4 filter -I OUTPUT 1 "$@"; then added_jump=1; else result=74; fi; fi
  if [ "$result" -eq 0 ] && firewall_history_current; then return 0; fi
  [ "$result" -ne 0 ] || result=76
  if [ "$added_jump" -eq 1 ]; then set -- $jump; firewall_xt ipv4 filter -D OUTPUT "$@" >/dev/null 2>&1 || result=76; fi
  if [ "$added_nflog" -eq 1 ]; then set -- $nflog; firewall_xt ipv4 filter -D "$HISTORY_CHAIN" "$@" >/dev/null 2>&1 || result=76; fi
  if [ "$added_reject" -eq 1 ]; then set -- $reject; firewall_xt ipv4 filter -D "$HISTORY_CHAIN" "$@" >/dev/null 2>&1 || result=76; fi
  if [ "$created_chain" -eq 1 ]; then firewall_xt ipv4 filter -X "$HISTORY_CHAIN" >/dev/null 2>&1 || result=76; fi
  if [ "$created_chain" -eq 1 ]; then
    if firewall_history_manifest_load "$manifest" >/dev/null 2>&1 && firewall_history_kernel_absent_loaded; then
      rm -f "$manifest" || result=76
    else
      result=76
    fi
  fi
  return "$result"
}

firewall_history_install_locked() {
  local token=$1 manifest nflog tmp pending
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  firewall_history_token_valid "$token" || return 65
  firewall_history_pending_recover_locked || return
  manifest=$(firewall_history_manifest)
  if [ ! -f "$manifest" ]; then firewall_history_install_new_locked "$token"; return; fi
  firewall_history_manifest_load "$manifest" || return 76
  if ! firewall_history_current_loaded; then
    if firewall_history_kernel_absent_loaded; then
      rm -f "$manifest"
      firewall_history_install_new_locked "$token"
      return
    fi
    return 76
  fi
  if [ "$HISTORY_STATE" = active ]; then [ "$HISTORY_TOKEN" = "$token" ] && return 0; return 76; fi
  nflog=$(firewall_history_nflog_rule "$token") || return
  pending=$(firewall_history_pending_manifest)
  firewall_history_pending_manifest_write guard "$HISTORY_TOKEN" "$token" "$pending" \
    "$HISTORY_NFLOG_B64" "$HISTORY_JUMP_B64" || return
  set -- $nflog
  if ! firewall_xt ipv4 filter -I "$HISTORY_CHAIN" 1 "$@"; then
    if firewall_history_pending_target_present; then
      firewall_history_pending_recover_locked >/dev/null 2>&1 || return 76
    else
      rm -f "$pending" || return 76
    fi
    return 74
  fi
  tmp="$manifest.reenable.$$"
  if ! firewall_history_manifest_write active "$token" "$tmp" "$HISTORY_JUMP_B64"; then
    rm -f "$tmp"
    firewall_history_pending_recover_locked >/dev/null 2>&1 || return 76
    return 74
  fi
  if ! atomic_replace_file "$tmp" "$manifest"; then
    rm -f "$tmp"
    firewall_history_pending_recover_locked >/dev/null 2>&1 || return 76
    return 74
  fi
  rm -f "$pending" || return 76
  firewall_history_current || return 76
}

firewall_history_install() {
  local token=$1 result
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  set +e
  firewall_history_install_locked "$token"
  result=$?
  set -e
  rules_lock_release firewall || return
  return "$result"
}

firewall_history_disable_locked() {
  local manifest nflog old_jump new_jump tmp migrated=0 rollback_failed=0
  firewall_history_pending_recover_locked || return
  manifest=$(firewall_history_manifest)
  [ -f "$manifest" ] || return 0
  firewall_history_manifest_load "$manifest" || return 76
  firewall_history_current_loaded || return 76
  [ "$HISTORY_STATE" = active ] || return 0
  nflog=$(firewall_unb64 "$HISTORY_NFLOG_B64") || return 65
  old_jump=$(firewall_unb64 "$HISTORY_JUMP_B64") || return 65
  new_jump=$(firewall_history_jump_rule) || return
  set -- $nflog
  firewall_xt ipv4 filter -D "$HISTORY_CHAIN" "$@" || return 74
  if [ "$old_jump" != "$new_jump" ]; then
    set -- $new_jump
    if ! firewall_xt ipv4 filter -I OUTPUT 1 "$@"; then
      set -- $nflog
      firewall_xt ipv4 filter -I "$HISTORY_CHAIN" 1 "$@" >/dev/null 2>&1 || return 76
      return 74
    fi
    set -- $old_jump
    if ! firewall_xt ipv4 filter -D OUTPUT "$@"; then
      set -- $new_jump
      firewall_xt ipv4 filter -D OUTPUT "$@" >/dev/null 2>&1 || rollback_failed=1
      set -- $nflog
      firewall_xt ipv4 filter -I "$HISTORY_CHAIN" 1 "$@" >/dev/null 2>&1 || rollback_failed=1
      [ "$rollback_failed" -eq 0 ] || return 76
      return 74
    fi
    migrated=1
  fi
  tmp="$manifest.guard.$$"
  if ! firewall_history_manifest_write guard "$HISTORY_TOKEN" "$tmp"; then
    if [ "$migrated" -eq 1 ]; then
      set -- $old_jump
      firewall_xt ipv4 filter -I OUTPUT 1 "$@" >/dev/null 2>&1 || rollback_failed=1
      if [ "$rollback_failed" -eq 0 ]; then
        set -- $new_jump
        firewall_xt ipv4 filter -D OUTPUT "$@" >/dev/null 2>&1 || rollback_failed=1
      fi
    fi
    set -- $nflog
    firewall_xt ipv4 filter -I "$HISTORY_CHAIN" 1 "$@" >/dev/null 2>&1 || rollback_failed=1
    rm -f "$tmp"
    [ "$rollback_failed" -eq 0 ] || return 76
    return 74
  fi
  if ! atomic_replace_file "$tmp" "$manifest"; then
    if [ "$migrated" -eq 1 ]; then
      set -- $old_jump
      firewall_xt ipv4 filter -I OUTPUT 1 "$@" >/dev/null 2>&1 || rollback_failed=1
      if [ "$rollback_failed" -eq 0 ]; then
        set -- $new_jump
        firewall_xt ipv4 filter -D OUTPUT "$@" >/dev/null 2>&1 || rollback_failed=1
      fi
    fi
    set -- $nflog
    firewall_xt ipv4 filter -I "$HISTORY_CHAIN" 1 "$@" >/dev/null 2>&1 || rollback_failed=1
    rm -f "$tmp"
    [ "$rollback_failed" -eq 0 ] || return 76
    return 74
  fi
  firewall_history_current || return 76
}

firewall_history_disable() {
  local result
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  set +e
  firewall_history_disable_locked
  result=$?
  set -e
  rules_lock_release firewall || return
  return "$result"
}

firewall_history_uninstall_locked() {
  local manifest
  firewall_history_probe_recover || return
  firewall_history_pending_recover_locked || return
  manifest=$(firewall_history_manifest)
  [ -f "$manifest" ] || return 0
  firewall_history_manifest_load "$manifest" || return 76
  if firewall_history_kernel_absent_loaded; then rm -f "$manifest"; return 0; fi
  firewall_history_remove_exact_loaded || return
  rm -f "$manifest"
}

firewall_history_uninstall() {
  local result
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  set +e
  firewall_history_uninstall_locked
  result=$?
  set -e
  rules_lock_release firewall || return
  return "$result"
}

firewall_history_status() {
  rules_init_paths "$MODDIR" || return
  if firewall_history_manifest_load 2>/dev/null && firewall_history_current_loaded; then
    printf '{"ok":true,"data":{"state":"%s","mapToken":"%s"}}\n' "$HISTORY_STATE" "$HISTORY_TOKEN"
  elif [ -f "$(firewall_history_manifest)" ]; then
    printf '{"ok":true,"data":{"state":"incomplete"}}\n'
  else
    printf '{"ok":true,"data":{"state":"absent"}}\n'
  fi
}

firewall_rules_for() {
  local family=$1 table=$2 chain=$3 output=$4 item uid xiaomi_enabled=1
  : > "$output"
  if [ -f "$RULE_RUNTIME/firewall-features.prop" ] && \
     [ "$(cat "$RULE_RUNTIME/firewall-features.prop" 2>/dev/null)" = xiaomi_backup=0 ]; then
    xiaomi_enabled=0
  fi
  if [ "$table:$chain" = filter:JINGJIE_FILTER_OUT ]; then
    while IFS= read -r item || [ -n "$item" ]; do
      case "$item" in ''|'#'*) continue ;; esac
      case "$item:$xiaomi_enabled" in
        a0.app.xiaomi.com:0|api.ad.xiaomi.com:0|globalapi.ad.xiaomi.com:0) continue ;;
      esac
      firewall_value_valid "$item" || return 65
      firewall_rule_append "$output" "-m string --string $item --algo bm --to 65535 -j DROP" || return
    done < "$MODDIR/rules/firewall/output-strings.list"
    if [ "$family" = ipv4 ]; then
      while IFS= read -r item || [ -n "$item" ]; do
        case "$item" in ''|'#'*) continue ;; esac
        case "$item" in *[!0-9.]*|*.*.*.*.*) return 65 ;; esac
        firewall_rule_append "$output" "-d $item -j DROP" || return
      done < "$MODDIR/rules/firewall/output-addresses.list"
    fi
  elif [ "$family:$table:$chain" = ipv4:nat:JINGJIE_NAT_OUT ]; then
    while IFS= read -r item || [ -n "$item" ]; do
      case "$item" in ''|'#'*) continue ;; esac
      case "$item" in *[!A-Za-z0-9._]*) return 65 ;; esac
      uid=$(${FIREWALL_PACKAGES_FILE_CMD:-cat} /data/system/packages.list 2>/dev/null | "$BB" awk -v package="$item" '$1==package{print $2;exit}')
      case "$uid" in ''|*[!0-9]*) continue ;; esac
      firewall_rule_append "$output" "-m owner --uid-owner $uid -p tcp -j DNAT --to-destination 127.0.0.1:8848" || return
    done < "$MODDIR/rules/firewall/nat-packages.list"
  fi
}

firewall_manifest_add() {
  local manifest=$1 family=$2 table=$3 parent=$4 chain=$5 rules=$6 jump count encoded
  jump="-m comment --comment $RULE_MODULE_ID:$chain -j $chain"
  encoded=$(firewall_b64 "$jump") || return
  count=$(wc -l < "$rules" | tr -d ' ')
  {
    printf 'prepared\t%s\t%s\t%s\t%s\t1\t%s\t%s' "$family" "$table" "$parent" "$chain" "$encoded" "$count"
    while IFS= read -r encoded || [ -n "$encoded" ]; do printf '\t%s' "$encoded"; done < "$rules"
    printf '\n'
  } >> "$manifest"
}

firewall_build_manifest() {
  local manifest=$1 family spec table parent chain rules
  : > "$manifest"
  for family in ipv4 ipv6; do
    for spec in 'filter OUTPUT JINGJIE_FILTER_OUT' 'filter FORWARD JINGJIE_FORWARD'; do
      set -- $spec; table=$1; parent=$2; chain=$3
      rules="$RULE_TMP/firewall.$family.$chain.$$"
      firewall_rules_for "$family" "$table" "$chain" "$rules" || return
      firewall_manifest_add "$manifest" "$family" "$table" "$parent" "$chain" "$rules" || return
      rm -f "$rules"
    done
  done
  rules="$RULE_TMP/firewall.ipv4.JINGJIE_NAT_OUT.$$"
  firewall_rules_for ipv4 nat JINGJIE_NAT_OUT "$rules" || return
  firewall_manifest_add "$manifest" ipv4 nat OUTPUT JINGJIE_NAT_OUT "$rules" || return
  rm -f "$rules"
}

firewall_record_validate() {
  local line=$1 state family table parent chain created jump count field_count
  IFS="$(printf '\t')" read -r state family table parent chain created jump count _rest <<EOF
$line
EOF
  [ "$state" = prepared ] || [ "$state" = committed ] || return 65
  [ "$family" = ipv4 ] || [ "$family" = ipv6 ] || return 65
  [ "$table:$parent:$chain" = filter:OUTPUT:JINGJIE_FILTER_OUT ] || \
    [ "$table:$parent:$chain" = filter:FORWARD:JINGJIE_FORWARD ] || \
    [ "$family:$table:$parent:$chain" = ipv4:nat:OUTPUT:JINGJIE_NAT_OUT ] || return 65
  [ "$created" = 1 ] || return 65
  case "$count" in ''|*[!0-9]*) return 65 ;; esac
  firewall_unb64 "$jump" >/dev/null 2>&1 || return 65
  field_count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print NF}')
  [ "$field_count" -eq $((8 + count)) ] || return 65
}

firewall_manifest_valid() {
  local file=${1:-$(firewall_manifest)} line seen=0
  [ -f "$file" ] || return 66
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || return 65
    firewall_record_validate "$line" || return
    seen=$((seen + 1))
  done < "$file"
  [ "$seen" -eq 5 ]
}

firewall_chain_exists() { firewall_xt "$1" "$2" -S "$3" >/dev/null 2>&1; }

firewall_apply_record() {
  local line=$1 family table parent chain created jump count encoded rule index
  IFS="$(printf '\t')" read -r _state family table parent chain created jump count _rest <<EOF
$line
EOF
  firewall_xt "$family" "$table" -N "$chain" || return 76
  index=1
  while [ "$index" -le "$count" ]; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((8 + index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || return 65
    set -- $rule
    firewall_xt "$family" "$table" -A "$chain" "$@" || return 74
    index=$((index + 1))
  done
  jump=$(firewall_unb64 "$jump") || return 65
  set -- $jump
  firewall_xt "$family" "$table" -I "$parent" 1 "$@" || return 74
}

firewall_record_current() {
  local line=$1 family table parent chain jump count actual expected encoded rule index
  IFS="$(printf '\t')" read -r _state family table parent chain _created jump count _rest <<EOF
$line
EOF
  firewall_chain_exists "$family" "$table" "$chain" || return 1
  jump=$(firewall_unb64 "$jump") || return 1
  set -- $jump
  firewall_xt "$family" "$table" -C "$parent" "$@" >/dev/null 2>&1 || return 1
  actual="$RULE_TMP/firewall.actual.$$"
  expected="$RULE_TMP/firewall.expected.$$"
  firewall_xt "$family" "$table" -S "$chain" > "$actual" 2>/dev/null || return 1
  : > "$expected"
  index=1
  while [ "$index" -le "$count" ]; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((8 + index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || return 1
    printf -- '-A %s %s\n' "$chain" "$rule" >> "$expected"
    index=$((index + 1))
  done
  cmp -s "$actual" "$expected"
  local result=$?
  rm -f "$actual" "$expected"
  return "$result"
}

firewall_manifest_current() {
  local line
  firewall_manifest_valid || return 1
  while IFS= read -r line || [ -n "$line" ]; do firewall_record_current "$line" || return 1; done < "$(firewall_manifest)"
}

firewall_reconcile_locked() {
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || return 75
  local manifest tmp line committed
  manifest=$(firewall_manifest)
  if [ -f "$manifest" ]; then
    firewall_manifest_current && return 0
    return 76
  fi
  tmp="$manifest.tmp.$$"
  firewall_build_manifest "$tmp" || { rm -f "$tmp"; return $?; }
  while IFS= read -r line || [ -n "$line" ]; do
    IFS="$(printf '\t')" read -r _state family table _parent chain _rest <<EOF
$line
EOF
    if firewall_chain_exists "$family" "$table" "$chain"; then rm -f "$tmp"; return 76; fi
  done < "$tmp"
  atomic_replace_file "$tmp" "$manifest" || return
  while IFS= read -r line || [ -n "$line" ]; do
    firewall_apply_record "$line" || return
  done < "$manifest"
  committed="$manifest.committed.$$"
  "$BB" awk -F '\t' 'BEGIN{OFS="\t"}{$1="committed";print}' "$manifest" > "$committed" || return 74
  atomic_replace_file "$committed" "$manifest"
}

firewall_reconcile() {
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_reconcile_locked
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_actual_is_prefix() {
  local line=$1 actual=$2 chain count index encoded rule expected actual_line lines
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $8}')
  lines=$(wc -l < "$actual" | tr -d ' ')
  [ "$lines" -le "$count" ] || return 1
  index=1
  while [ "$index" -le "$lines" ]; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((8 + index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || return 1
    expected="-A $chain $rule"
    actual_line=$(sed -n "${index}p" "$actual")
    [ "$actual_line" = "$expected" ] || return 1
    index=$((index + 1))
  done
}

firewall_cleanup_record() {
  local line=$1 family table parent chain jump actual
  IFS="$(printf '\t')" read -r _state family table parent chain _created jump _count _rest <<EOF
$line
EOF
  jump=$(firewall_unb64 "$jump") || return 65
  set -- $jump
  firewall_xt "$family" "$table" -D "$parent" "$@" >/dev/null 2>&1 || true
  firewall_chain_exists "$family" "$table" "$chain" || return 0
  actual="$RULE_TMP/firewall.cleanup.$$"
  firewall_xt "$family" "$table" -S "$chain" > "$actual" 2>/dev/null || return 76
  if ! firewall_actual_is_prefix "$line" "$actual"; then rm -f "$actual"; return 76; fi
  rm -f "$actual"
  firewall_xt "$family" "$table" -F "$chain" || return 74
  firewall_xt "$family" "$table" -X "$chain" || return 74
}

firewall_cleanup_locked() {
  local manifest line remaining failures=0
  firewall_history_probe_recover || return
  firewall_history_pending_recover_locked || return
  manifest=$(firewall_manifest)
  [ -f "$manifest" ] || return 0
  firewall_manifest_valid "$manifest" || return 70
  remaining="$manifest.remaining.$$"
  : > "$remaining"
  while IFS= read -r line || [ -n "$line" ]; do
    if ! firewall_cleanup_record "$line"; then
      printf '%s\n' "$line" >> "$remaining"
      failures=$((failures + 1))
    fi
  done < "$manifest"
  if [ -s "$remaining" ]; then atomic_replace_file "$remaining" "$manifest" || return; else rm -f "$remaining" "$manifest"; fi
  [ "$failures" -eq 0 ] || return 76
}

firewall_cleanup() {
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_cleanup_locked
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_set_feature() {
  local feature=$1 enabled=$2 tmp
  [ "$feature" = xiaomi_backup ] || return 64
  [ "$enabled" = 0 ] || [ "$enabled" = 1 ] || return 64
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || { rules_lock_release firewall; return 75; }
  tmp="$RULE_RUNTIME/firewall-features.prop.tmp.$$"
  printf 'xiaomi_backup=%s\n' "$enabled" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$RULE_RUNTIME/firewall-features.prop" || return
  firewall_cleanup_locked || { local result=$?; rules_lock_release firewall; return "$result"; }
  firewall_reconcile_locked
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_status() {
  rules_init_paths "$MODDIR" || return
  if firewall_manifest_current; then
    printf '{"ok":true,"data":{"state":"committed"}}\n'
  elif [ -f "$(firewall_manifest)" ]; then
    printf '{"ok":true,"data":{"state":"incomplete"}}\n'
  else
    printf '{"ok":true,"data":{"state":"absent"}}\n'
  fi
}

APP_POLICY_CHAIN4=JINGJIE_APP_OUT4
APP_POLICY_CHAIN6=JINGJIE_APP_OUT6

firewall_app_policy_manifest() { printf '%s\n' "$RULE_RUNTIME/app-firewall.tsv"; }
firewall_app_policy_pending_manifest() { printf '%s\n' "$RULE_RUNTIME/app-firewall.pending.tsv"; }

firewall_app_policy_token_valid() {
  [ "${#1}" -eq 16 ] || return 65
  case "$1" in *[!0-9a-f]*) return 65 ;; esac
}

firewall_app_policy_chain_for() {
  local family=$1 token=$2
  firewall_app_policy_token_valid "$token" || return
  case "$family" in
    ipv4) printf 'JJ_AP4_%s\n' "$token" ;;
    ipv6) printf 'JJ_AP6_%s\n' "$token" ;;
    *) return 64 ;;
  esac
}

firewall_app_policy_sha256_valid() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in *[!0-9a-f]*) return 1 ;; *) return 0 ;; esac
}

firewall_app_policy_position_valid() {
  case "$1" in
    [1-9]|[1-9][0-9]*) case "$1" in *[!0-9]*) return 1 ;; esac ;;
    *) return 1 ;;
  esac
}

firewall_app_policy_old_position_valid() {
  [ "$1" = 0 ] || firewall_app_policy_position_valid "$1"
}

firewall_app_policy_record_jump_position() {
  local line=$1 family jump_b64 jump expected raw position
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  jump_b64=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
  jump=$(firewall_unb64 "$jump_b64") || return 65
  expected="-A OUTPUT $jump"
  raw="$RULE_TMP/app-firewall-output-position.$$.$family"
  : > "$raw" || return 74
  if firewall_xt "$family" filter -S OUTPUT > "$raw" 2>/dev/null; then
    :
  else
    rm -f "$raw" || return 74
    return 76
  fi
  if position=$("$BB" awk -v wanted="$expected" '
    $1=="-A" && $2=="OUTPUT" {
      position++
      if ($0==wanted) { count++; found=position }
    }
    END {
      if (count==1) print found
      else exit 1
    }
  ' "$raw"); then
    rm -f "$raw" || return 74
    printf '%s\n' "$position"
  else
    rm -f "$raw" || return 74
    return 76
  fi
}

firewall_app_policy_capture_old_positions() {
  local file=$1 line family position jump_count old4=- old6=- seen4=0 seen6=0
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  if [ -s "$file" ]; then
    firewall_app_policy_manifest_valid "$file" || return
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
      jump_count=$(firewall_app_policy_jump_count "$line") || return
      case "$jump_count" in
        0) position=0 ;;
        1) position=$(firewall_app_policy_record_jump_position "$line") || return ;;
        *) return 76 ;;
      esac
      firewall_app_policy_old_position_valid "$position" || return 76
      case "$family" in
        ipv4) [ "$seen4" -eq 0 ] || return 65; seen4=1; old4=$position ;;
        ipv6) [ "$seen6" -eq 0 ] || return 65; seen6=1; old6=$position ;;
        *) return 65 ;;
      esac
    done < "$file"
  fi
  printf '%s %s\n' "$old4" "$old6"
}

firewall_app_policy_pending_positions_valid() {
  local file=$1 old4=$2 old6=$3 line family seen4=0 seen6=0
  if [ -s "$file" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
      case "$family" in
        ipv4) [ "$seen4" -eq 0 ] || return 65; seen4=1 ;;
        ipv6) [ "$seen6" -eq 0 ] || return 65; seen6=1 ;;
        *) return 65 ;;
      esac
    done < "$file"
  fi
  if [ "$seen4" -eq 1 ]; then
    firewall_app_policy_old_position_valid "$old4" || return 65
  else
    [ "$old4" = - ] || return 65
  fi
  if [ "$seen6" -eq 1 ]; then
    firewall_app_policy_old_position_valid "$old6" || return 65
  else
    [ "$old6" = - ] || return 65
  fi
}

firewall_app_policy_pending_write() {
  local token=$1 mode=$2 old_copy=$3 new_copy=$4 pending tmp old_hash new_hash result positions old4_pos old6_pos
  firewall_app_policy_token_valid "$token" || return
  case "$mode" in off|block_selected|allow_resolved) ;; *) return 65 ;; esac
  [ -f "$old_copy" ] && [ ! -L "$old_copy" ] || return 66
  [ -f "$new_copy" ] && [ ! -L "$new_copy" ] || return 66
  positions=$(firewall_app_policy_capture_old_positions "$old_copy") || return
  old4_pos=${positions%% *}
  old6_pos=${positions#* }
  old_hash=$(sha256_file "$old_copy") || return
  new_hash=$(sha256_file "$new_copy") || return
  firewall_app_policy_sha256_valid "$old_hash" || return 70
  firewall_app_policy_sha256_valid "$new_hash" || return 70
  pending=$(firewall_app_policy_pending_manifest)
  tmp="$pending.tmp.$$"
  printf 'app-pending-v2\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$token" "$mode" "$old_hash" "$new_hash" "$old_copy" "$new_copy" \
    "$old4_pos" "$old6_pos" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$pending" || {
    result=$?
    rm -f "$tmp"
    return "$result"
  }
}

firewall_app_policy_pending_load() {
  local file=${1:-$(firewall_app_policy_pending_manifest)} line fields line_count old_actual new_actual
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  line_count=$(wc -l < "$file" | tr -d ' ') || return 70
  case "$line_count" in ''|*[!0-9]*) return 70 ;; esac
  [ "$line_count" -eq 1 ] || return 76
  line=$(cat "$file") || return 70
  fields=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print NF}') || return 70
  [ "$fields" -eq 9 ] || return 76
  IFS="$(printf '\t')" read -r APP_PENDING_SCHEMA APP_PENDING_TOKEN APP_PENDING_MODE \
    APP_PENDING_OLD_HASH APP_PENDING_NEW_HASH APP_PENDING_OLD_MANIFEST \
    APP_PENDING_NEW_MANIFEST APP_PENDING_OLD4_POS APP_PENDING_OLD6_POS <<EOF
$line
EOF
  [ "$APP_PENDING_SCHEMA" = app-pending-v2 ] || return 76
  firewall_app_policy_token_valid "$APP_PENDING_TOKEN" || return 76
  case "$APP_PENDING_MODE" in off|block_selected|allow_resolved) ;; *) return 76 ;; esac
  firewall_app_policy_sha256_valid "$APP_PENDING_OLD_HASH" || return 76
  firewall_app_policy_sha256_valid "$APP_PENDING_NEW_HASH" || return 76
  case "$APP_PENDING_OLD_MANIFEST:$APP_PENDING_NEW_MANIFEST" in
    "$RULE_RUNTIME/app-firewall-$APP_PENDING_TOKEN.old.tsv:$RULE_RUNTIME/app-firewall-$APP_PENDING_TOKEN.new.tsv") ;;
    *) return 76 ;;
  esac
  [ -f "$APP_PENDING_OLD_MANIFEST" ] && [ ! -L "$APP_PENDING_OLD_MANIFEST" ] || return 66
  [ -f "$APP_PENDING_NEW_MANIFEST" ] && [ ! -L "$APP_PENDING_NEW_MANIFEST" ] || return 66
  old_actual=$(sha256_file "$APP_PENDING_OLD_MANIFEST") || return
  new_actual=$(sha256_file "$APP_PENDING_NEW_MANIFEST") || return
  [ "$old_actual" = "$APP_PENDING_OLD_HASH" ] || return 76
  [ "$new_actual" = "$APP_PENDING_NEW_HASH" ] || return 76
  if [ -s "$APP_PENDING_OLD_MANIFEST" ]; then
    firewall_app_policy_manifest_valid "$APP_PENDING_OLD_MANIFEST" || return 76
  fi
  firewall_app_policy_pending_positions_valid "$APP_PENDING_OLD_MANIFEST" \
    "$APP_PENDING_OLD4_POS" "$APP_PENDING_OLD6_POS" || return 76
  case "$APP_PENDING_MODE" in
    off) [ ! -s "$APP_PENDING_NEW_MANIFEST" ] || return 76 ;;
    *)
      [ -s "$APP_PENDING_NEW_MANIFEST" ] || return 76
      firewall_app_policy_manifest_valid "$APP_PENDING_NEW_MANIFEST" || return 76
      firewall_app_policy_manifest_matches_token "$APP_PENDING_NEW_MANIFEST" "$APP_PENDING_TOKEN" || return 76
      ;;
  esac
  export APP_PENDING_SCHEMA APP_PENDING_TOKEN APP_PENDING_MODE APP_PENDING_OLD_HASH APP_PENDING_NEW_HASH \
    APP_PENDING_OLD_MANIFEST APP_PENDING_NEW_MANIFEST APP_PENDING_OLD4_POS APP_PENDING_OLD6_POS
}

firewall_app_policy_capability() {
  rules_init_paths "$MODDIR" || return
  if [ "${APP_POLICY_FORCE_CAPABILITY-}" = unsupported ]; then
    printf '{"supported":false,"reason":"owner_match_unavailable","families":[]}\n'
    return 0
  fi
  local families= first=true family
  for family in ipv4 ipv6; do
    if [ "${APP_POLICY_FORCE_CAPABILITY-}" = supported ] || \
      firewall_xt "$family" filter -m owner --help >/dev/null 2>&1; then
      [ "$first" = true ] || families="$families,"
      families="$families\"$family\""
      first=false
    fi
  done
  if [ "$first" = true ]; then
    printf '{"supported":false,"reason":"owner_match_unavailable","families":[]}\n'
  else
    printf '{"supported":true,"reason":null,"families":[%s]}\n' "$families"
  fi
}

firewall_app_policy_record_validate() {
  local line=$1 fields schema family chain jump_b64 count token expected_chain jump
  fields=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print NF}') || return 65
  [ "$fields" -ge 6 ] || return 65
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
  jump_b64=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
  count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  schema=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $1}')
  case "$schema" in
    app-v1) case "$family:$chain" in ipv4:$APP_POLICY_CHAIN4|ipv6:$APP_POLICY_CHAIN6) ;; *) return 65 ;; esac ;;
    app-v2)
      token=${chain#JJ_AP?_}
      [ "$token" != "$chain" ] || return 65
      expected_chain=$(firewall_app_policy_chain_for "$family" "$token") || return 65
      [ "$chain" = "$expected_chain" ] || return 65
      ;;
    *) return 65 ;;
  esac
  case "$count" in ''|*[!0-9]*) return 65 ;; esac
  [ "$fields" -eq $((5 + count)) ] || return 65
  jump=$(firewall_unb64 "$jump_b64" 2>/dev/null) || return 65
  [ "$jump" = "-m comment --comment $RULE_MODULE_ID:app-policy -j $chain" ] || return 65
}

firewall_app_policy_manifest_valid() {
  local file=${1:-$(firewall_app_policy_manifest)} line count=0
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    firewall_app_policy_record_validate "$line" || return 65
    count=$((count + 1))
    [ "$count" -le 2 ] || return 65
  done < "$file"
  [ "$count" -ge 1 ]
}

firewall_app_policy_manifest_matches_token() {
  local file=$1 token=$2 line schema family chain expected seen4=0 seen6=0 count=0
  firewall_app_policy_token_valid "$token" || return 65
  firewall_app_policy_manifest_valid "$file" || return
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    schema=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $1}')
    family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
    chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
    [ "$schema" = app-v2 ] || return 65
    expected=$(firewall_app_policy_chain_for "$family" "$token") || return 65
    [ "$chain" = "$expected" ] || return 65
    case "$family" in
      ipv4) [ "$seen4" -eq 0 ] || return 65; seen4=1 ;;
      ipv6) [ "$seen6" -eq 0 ] || return 65; seen6=1 ;;
      *) return 65 ;;
    esac
    count=$((count + 1))
  done < "$file"
  [ "$count" -ge 1 ]
}

firewall_app_policy_manifest_contains_record() {
  local file=$1 line=$2
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  "$BB" grep -F -x "$line" "$file" >/dev/null 2>&1
}

firewall_app_policy_chain_matches_record() {
  local line=$1 family chain count actual raw index encoded rule expected actual_line lines
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
  count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  raw="$RULE_TMP/app-firewall-current-raw.$$"
  actual="$RULE_TMP/app-firewall-current.$$"
  firewall_xt "$family" filter -S "$chain" > "$raw" 2>/dev/null || return 76
  "$BB" awk -v chain="$chain" '$0 != "-N " chain { print }' "$raw" > "$actual" || { rm -f "$raw" "$actual"; return 74; }
  rm -f "$raw"
  lines=$(wc -l < "$actual" | "$BB" tr -d ' ') || { rm -f "$actual"; return 74; }
  [ "$lines" -eq "$count" ] || { rm -f "$actual"; return 76; }
  index=1
  while [ "$index" -le "$count" ]; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((5 + index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || { rm -f "$actual"; return 65; }
    expected="-A $chain $rule"
    actual_line=$("$BB" sed -n "${index}p" "$actual")
    [ "$actual_line" = "$expected" ] || { rm -f "$actual"; return 76; }
    index=$((index + 1))
  done
  rm -f "$actual"
}

firewall_app_policy_chain_subset_indices() {
  local line=$1 family chain count raw actual lines expected_index actual_index=1 encoded rule expected actual_line indices=
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
  count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  raw="$RULE_TMP/app-firewall-prefix-raw.$$"
  actual="$RULE_TMP/app-firewall-prefix.$$"
  firewall_xt "$family" filter -S "$chain" > "$raw" 2>/dev/null || return 76
  "$BB" awk -v chain="$chain" '$0 != "-N " chain { print }' "$raw" > "$actual" || {
    rm -f "$raw" "$actual"
    return 74
  }
  rm -f "$raw"
  lines=$(wc -l < "$actual" | "$BB" tr -d ' ') || { rm -f "$actual"; return 74; }
  [ "$lines" -le "$count" ] || { rm -f "$actual"; return 76; }
  actual_line=$("$BB" sed -n "${actual_index}p" "$actual")
  expected_index=1
  while [ "$expected_index" -le "$count" ] && [ "$actual_index" -le "$lines" ]; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((5 + expected_index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || { rm -f "$actual"; return 65; }
    expected="-A $chain $rule"
    if firewall_rendered_rule_matches "$chain" "$rule" "$actual_line"; then
      indices="$indices $expected_index"
      actual_index=$((actual_index + 1))
      actual_line=$("$BB" sed -n "${actual_index}p" "$actual")
    fi
    expected_index=$((expected_index + 1))
  done
  rm -f "$actual"
  [ "$actual_index" -gt "$lines" ] || return 76
  printf '%s\n' "${indices# }"
}

firewall_app_policy_jump_count() {
  local line=$1 family jump_b64 jump expected raw count
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  jump_b64=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
  jump=$(firewall_unb64 "$jump_b64") || return 65
  expected="-A OUTPUT $jump"
  raw="$RULE_TMP/app-firewall-output-count.$$.$family"
  : > "$raw" || return 74
  if firewall_xt "$family" filter -S OUTPUT > "$raw" 2>/dev/null; then
    :
  else
    rm -f "$raw" || return 74
    return 76
  fi
  if count=$("$BB" awk -v wanted="$expected" '$0==wanted{count++} END{print count+0}' "$raw"); then
    rm -f "$raw" || return 74
    printf '%s\n' "$count"
  else
    rm -f "$raw" || return 74
    return 70
  fi
}

firewall_app_policy_manifest_family_jump_count() {
  local file=$1 wanted_family=$2 line family count total=0
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  case "$wanted_family" in ipv4|ipv6) ;; *) return 64 ;; esac
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
    [ "$family" = "$wanted_family" ] || continue
    count=$(firewall_app_policy_jump_count "$line") || return
    [ "$count" -le 1 ] || return 76
    total=$((total + count))
    [ "$total" -le 1 ] || return 76
  done < "$file"
  printf '%s\n' "$total"
}

firewall_app_policy_record_is_owned_subset() {
  local line=$1 family chain jump_count
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
  jump_count=$(firewall_app_policy_jump_count "$line") || return
  [ "$jump_count" -le 1 ] || return 76
  if ! firewall_chain_exists "$family" filter "$chain"; then
    [ "$jump_count" -eq 0 ] || return 76
    return 0
  fi
  firewall_app_policy_chain_subset_indices "$line" >/dev/null
}

firewall_app_policy_manifest_kernel_current() {
  local file=$1 line count
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  [ -s "$file" ] || return 0
  firewall_app_policy_manifest_valid "$file" || return
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    firewall_app_policy_chain_matches_record "$line" || return 76
    count=$(firewall_app_policy_jump_count "$line") || return
    [ "$count" -eq 1 ] || return 76
  done < "$file"
}

firewall_app_policy_chain_empty() {
  local family=$1 chain=$2 count raw
  raw="$RULE_TMP/app-firewall-chain-empty.$$.$family"
  : > "$raw" || return 74
  if firewall_xt "$family" filter -S "$chain" > "$raw" 2>/dev/null; then
    :
  else
    rm -f "$raw" || return 74
    return 76
  fi
  if count=$("$BB" awk -v chain="$chain" '$0 != "-N " chain { count++ } END { print count+0 }' "$raw"); then
    rm -f "$raw" || return 74
  else
    rm -f "$raw" || return 74
    return 70
  fi
  [ "$count" -eq 0 ]
}

firewall_app_policy_cleanup_locked() {
  local manifest line remaining failures=0
  manifest=$(firewall_app_policy_manifest)
  [ -f "$manifest" ] || return 0
  firewall_app_policy_manifest_valid "$manifest" || return 76
  remaining="$manifest.remaining.$$"
  : > "$remaining" || return 74
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    if ! firewall_app_policy_remove_record_locked "$line"; then
      printf '%s\n' "$line" >> "$remaining" || return 74
      failures=$((failures + 1))
    fi
  done < "$manifest"
  if [ -s "$remaining" ]; then
    atomic_replace_file "$remaining" "$manifest" || return
  else
    rm -f "$remaining" "$manifest" || return 74
  fi
  [ "$failures" -eq 0 ] || return 76
}

firewall_app_policy_cleanup() {
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_app_policy_cleanup_locked
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_app_policy_apply_family_locked() {
  local family=$1 chain=$2 mode=$3 uid_file=$4 ip_file=$5 manifest_tmp=$6 jump rule count=0 uid ip ip_family
  firewall_chain_exists "$family" filter "$chain" && return 76
  firewall_xt "$family" filter -N "$chain" || return 74
  if [ "$mode" = allow_resolved ]; then
    while IFS= read -r uid || [ -n "$uid" ]; do
      [ -n "$uid" ] || continue
      while IFS= read -r ip || [ -n "$ip" ]; do
        [ -n "$ip" ] || continue
        ip_family=$(printf '%s' "$ip" | "$BB" awk '{if(index($0,":")) print "ipv6"; else print "ipv4"}')
        [ "$ip_family" = "$family" ] || continue
        rule="-m owner --uid-owner $uid -d $ip -m comment --comment $RULE_MODULE_ID:app-policy -j RETURN"
        set -- $rule
        firewall_xt "$family" filter -A "$chain" "$@" || return 74
        firewall_rule_append "$manifest_tmp.rules" "$rule" || return
        count=$((count + 1))
      done < "$ip_file"
    done < "$uid_file"
  fi
  while IFS= read -r uid || [ -n "$uid" ]; do
    [ -n "$uid" ] || continue
    rule="-m owner --uid-owner $uid -m comment --comment $RULE_MODULE_ID:app-policy -j REJECT"
    set -- $rule
    firewall_xt "$family" filter -A "$chain" "$@" || return 74
    firewall_rule_append "$manifest_tmp.rules" "$rule" || return
    count=$((count + 1))
  done < "$uid_file"
  jump="-m comment --comment $RULE_MODULE_ID:app-policy -j $chain"
  set -- $jump
  firewall_xt "$family" filter -I OUTPUT 1 "$@" || return 74
  {
    printf 'app-v1\t%s\t%s\t%s\t%s' "$family" "$chain" "$(firewall_b64 "$jump")" "$count"
    while IFS= read -r rule || [ -n "$rule" ]; do printf '\t%s' "$rule"; done < "$manifest_tmp.rules"
    printf '\n'
  } >> "$manifest_tmp" || return 74
  rm -f "$manifest_tmp.rules"
}

firewall_app_policy_build_family_staged() {
  local family=$1 chain=$2 mode=$3 uid_file=$4 ip_file=$5 manifest_tmp=$6 jump rule count=0 uid ip ip_family
  : > "$manifest_tmp.rules" || return 74
  if [ "$mode" = allow_resolved ]; then
    while IFS= read -r uid || [ -n "$uid" ]; do
      [ -n "$uid" ] || continue
      while IFS= read -r ip || [ -n "$ip" ]; do
        [ -n "$ip" ] || continue
        ip_family=$(printf '%s' "$ip" | "$BB" awk '{if(index($0,":")) print "ipv6"; else print "ipv4"}')
        [ "$ip_family" = "$family" ] || continue
        rule="-m owner --uid-owner $uid -d $ip -m comment --comment $RULE_MODULE_ID:app-policy -j RETURN"
        firewall_rule_append "$manifest_tmp.rules" "$rule" || return
        count=$((count + 1))
      done < "$ip_file"
    done < "$uid_file"
  fi
  if [ "$mode" != off ]; then
    while IFS= read -r uid || [ -n "$uid" ]; do
      [ -n "$uid" ] || continue
      rule="-m owner --uid-owner $uid -m comment --comment $RULE_MODULE_ID:app-policy -j REJECT"
      firewall_rule_append "$manifest_tmp.rules" "$rule" || return
      count=$((count + 1))
    done < "$uid_file"
  fi
  jump="-m comment --comment $RULE_MODULE_ID:app-policy -j $chain"
  {
    printf 'app-v2\t%s\t%s\t%s\t%s' "$family" "$chain" "$(firewall_b64 "$jump")" "$count"
    while IFS= read -r rule || [ -n "$rule" ]; do printf '\t%s' "$rule"; done < "$manifest_tmp.rules"
    printf '\n'
  } >> "$manifest_tmp" || return 74
  rm -f "$manifest_tmp.rules"
}

firewall_app_policy_apply_staged_record_locked() {
  local line=$1 owned=$2 family chain jump_b64 jump count index encoded rule result
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
  jump_b64=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
  count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  firewall_chain_exists "$family" filter "$chain" && return 76
  firewall_xt "$family" filter -N "$chain" || return 74
  printf '%s\n' "$line" >> "$owned" || {
    result=74
    if firewall_app_policy_chain_empty "$family" "$chain"; then
      firewall_xt "$family" filter -X "$chain" >/dev/null 2>&1 || result=76
    else
      result=76
    fi
    return "$result"
  }
  index=1
  while [ "$index" -le "$count" ]; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((5 + index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || return 65
    set -- $rule
    firewall_xt "$family" filter -A "$chain" "$@" || return 74
    index=$((index + 1))
  done
  jump=$(firewall_unb64 "$jump_b64") || return 65
  set -- $jump
  firewall_xt "$family" filter -I OUTPUT 1 "$@" || return 74
}

firewall_app_policy_repair_indices_valid() {
  local value=$1 count=$2 old_ifs index previous=0 seen=0
  case "$count" in ''|*[!0-9]*) return 1 ;; esac
  [ "$value" != - ] || return 0
  case "$value" in ''|,*|*,|*,,*) return 1 ;; esac
  old_ifs=$IFS
  IFS=,
  set -- $value
  IFS=$old_ifs
  for index in "$@"; do
    firewall_app_policy_position_valid "$index" || return 1
    [ "$index" -le "$count" ] && [ "$index" -gt "$previous" ] || return 1
    previous=$index
    seen=$((seen + 1))
  done
  [ "$seen" -gt 0 ]
}

firewall_app_policy_repair_indices_contains() {
  case ",$1," in *",$2,"*) return 0 ;; *) return 1 ;; esac
}

firewall_app_policy_repair_journal_decode() {
  local journal=$1 fields record_family record_chain count
  fields=$(printf '%s\n' "$journal" | "$BB" awk -F '\t' '{print NF}') || return 70
  [ "$fields" -eq 7 ] || return 76
  IFS="$(printf '\t')" read -r APP_REPAIR_SCHEMA APP_REPAIR_FAMILY APP_REPAIR_CHAIN \
    APP_REPAIR_JUMP_POSITION APP_REPAIR_CHAIN_PRESENT APP_REPAIR_INDICES \
    APP_REPAIR_RECORD_B64 <<EOF
$journal
EOF
  [ "$APP_REPAIR_SCHEMA" = app-repair-v1 ] || return 76
  case "$APP_REPAIR_FAMILY" in ipv4|ipv6) ;; *) return 76 ;; esac
  case "$APP_REPAIR_CHAIN_PRESENT" in 0|1) ;; *) return 76 ;; esac
  firewall_app_policy_old_position_valid "$APP_REPAIR_JUMP_POSITION" || return 76
  APP_REPAIR_RECORD=$(firewall_unb64 "$APP_REPAIR_RECORD_B64" 2>/dev/null) || return 76
  firewall_app_policy_record_validate "$APP_REPAIR_RECORD" || return 76
  record_family=$(printf '%s\n' "$APP_REPAIR_RECORD" | "$BB" awk -F '\t' '{print $2}')
  record_chain=$(printf '%s\n' "$APP_REPAIR_RECORD" | "$BB" awk -F '\t' '{print $3}')
  count=$(printf '%s\n' "$APP_REPAIR_RECORD" | "$BB" awk -F '\t' '{print $5}')
  [ "$record_family" = "$APP_REPAIR_FAMILY" ] && [ "$record_chain" = "$APP_REPAIR_CHAIN" ] || return 76
  firewall_app_policy_repair_indices_valid "$APP_REPAIR_INDICES" "$count" || return 76
  if [ "$APP_REPAIR_CHAIN_PRESENT" -eq 0 ]; then
    [ "$APP_REPAIR_JUMP_POSITION" -eq 0 ] && [ "$APP_REPAIR_INDICES" = - ] || return 76
  fi
}

firewall_app_policy_repair_journal_line() {
  local line=$1 family chain jump_count jump_position chain_present indices indices_csv record_b64
  firewall_app_policy_record_validate "$line" || return 65
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
  jump_count=$(firewall_app_policy_jump_count "$line") || return
  case "$jump_count" in
    0) jump_position=0 ;;
    1) jump_position=$(firewall_app_policy_record_jump_position "$line") || return ;;
    *) return 76 ;;
  esac
  if firewall_chain_exists "$family" filter "$chain"; then
    chain_present=1
    indices=$(firewall_app_policy_chain_subset_indices "$line") || return
    if [ -n "$indices" ]; then
      indices_csv=$(printf '%s\n' "$indices" | "$BB" tr ' ' ',') || return 70
    else
      indices_csv=-
    fi
  else
    [ "$jump_count" -eq 0 ] || return 76
    chain_present=0
    indices_csv=-
  fi
  record_b64=$(firewall_b64 "$line") || return 70
  printf 'app-repair-v1\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$family" "$chain" "$jump_position" "$chain_present" "$indices_csv" "$record_b64"
}

firewall_app_policy_repair_record_locked() {
  local line=$1 owned=$2 journal family chain jump_position chain_present baseline_indices count index encoded rule jump jump_b64 actual_count
  journal=$(firewall_app_policy_repair_journal_line "$line") || return
  printf '%s\n' "$journal" >> "$owned" || return 74
  firewall_app_policy_repair_journal_decode "$journal" || return
  family=$APP_REPAIR_FAMILY
  chain=$APP_REPAIR_CHAIN
  jump_position=$APP_REPAIR_JUMP_POSITION
  chain_present=$APP_REPAIR_CHAIN_PRESENT
  baseline_indices=$APP_REPAIR_INDICES
  count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  if [ "$chain_present" -eq 0 ]; then
    firewall_xt "$family" filter -N "$chain" || return 74
  fi
  index=1
  while [ "$index" -le "$count" ]; do
    if ! firewall_app_policy_repair_indices_contains "$baseline_indices" "$index"; then
      encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((5 + index)) '{print $n}')
      rule=$(firewall_unb64 "$encoded") || return 65
      set -- $rule
      firewall_xt "$family" filter -I "$chain" "$index" "$@" || return 74
    fi
    index=$((index + 1))
  done
  if [ "$jump_position" -eq 0 ]; then
    jump_b64=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
    jump=$(firewall_unb64 "$jump_b64") || return 65
    set -- $jump
    firewall_xt "$family" filter -I OUTPUT 1 "$@" || return 74
  fi
  firewall_app_policy_chain_matches_record "$line" || return 76
  actual_count=$(firewall_app_policy_jump_count "$line") || return
  [ "$actual_count" -eq 1 ] || return 76
}

firewall_app_policy_restore_repair_journal_locked() {
  local journal=$1 record family chain jump_position chain_present baseline_indices current_indices current_csv old_ifs index actual_position=0 removals= jump_b64 jump count current_position after_indices after_csv
  firewall_app_policy_repair_journal_decode "$journal" || return
  record=$APP_REPAIR_RECORD
  family=$APP_REPAIR_FAMILY
  chain=$APP_REPAIR_CHAIN
  jump_position=$APP_REPAIR_JUMP_POSITION
  chain_present=$APP_REPAIR_CHAIN_PRESENT
  baseline_indices=$APP_REPAIR_INDICES
  if [ "$chain_present" -eq 0 ]; then
    firewall_app_policy_remove_record_locked "$record"
    return
  fi
  firewall_chain_exists "$family" filter "$chain" || return 76
  current_indices=$(firewall_app_policy_chain_subset_indices "$record") || return
  if [ -n "$current_indices" ]; then
    current_csv=$(printf '%s\n' "$current_indices" | "$BB" tr ' ' ',') || return 70
  else
    current_csv=-
  fi
  if [ "$baseline_indices" != - ]; then
    old_ifs=$IFS
    IFS=,
    set -- $baseline_indices
    IFS=$old_ifs
    for index in "$@"; do
      firewall_app_policy_repair_indices_contains "$current_csv" "$index" || return 76
    done
  fi
  jump_b64=$(printf '%s\n' "$record" | "$BB" awk -F '\t' '{print $4}')
  jump=$(firewall_unb64 "$jump_b64") || return 65
  count=$(firewall_app_policy_jump_count "$record") || return
  [ "$count" -le 1 ] || return 76
  if [ "$jump_position" -eq 0 ]; then
    if [ "$count" -eq 1 ]; then
      set -- $jump
      firewall_xt "$family" filter -D OUTPUT "$@" || return 76
    fi
  else
    [ "$count" -eq 1 ] || return 76
    current_position=$(firewall_app_policy_record_jump_position "$record") || return
    [ "$current_position" -eq "$jump_position" ] || return 76
  fi
  for index in $current_indices; do
    actual_position=$((actual_position + 1))
    if ! firewall_app_policy_repair_indices_contains "$baseline_indices" "$index"; then
      removals="$actual_position $removals"
    fi
  done
  for actual_position in $removals; do
    firewall_xt "$family" filter -D "$chain" "$actual_position" || return 76
  done
  after_indices=$(firewall_app_policy_chain_subset_indices "$record") || return
  if [ -n "$after_indices" ]; then
    after_csv=$(printf '%s\n' "$after_indices" | "$BB" tr ' ' ',') || return 70
  else
    after_csv=-
  fi
  [ "$after_csv" = "$baseline_indices" ] || return 76
  count=$(firewall_app_policy_jump_count "$record") || return
  if [ "$jump_position" -eq 0 ]; then
    [ "$count" -eq 0 ] || return 76
  else
    [ "$count" -eq 1 ] || return 76
    current_position=$(firewall_app_policy_record_jump_position "$record") || return
    [ "$current_position" -eq "$jump_position" ] || return 76
  fi
}

firewall_app_policy_remove_record_locked() {
  local line=$1 family chain jump_b64 jump jump_count indices index reverse= encoded rule
  firewall_app_policy_record_validate "$line" || return 65
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
  jump_b64=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
  jump=$(firewall_unb64 "$jump_b64") || return 65
  jump_count=$(firewall_app_policy_jump_count "$line") || return
  [ "$jump_count" -le 1 ] || return 76
  if ! firewall_chain_exists "$family" filter "$chain"; then
    [ "$jump_count" -eq 0 ] || return 76
    return 0
  fi
  indices=$(firewall_app_policy_chain_subset_indices "$line") || return $?
  set -- $jump
  [ "$jump_count" -eq 0 ] || firewall_xt "$family" filter -D OUTPUT "$@" || return 76
  for index in $indices; do reverse="$index $reverse"; done
  for index in $reverse; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((5 + index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || return 65
    set -- $rule
    firewall_xt "$family" filter -D "$chain" "$@" || return 76
  done
  firewall_app_policy_chain_empty "$family" "$chain" || return 76
  firewall_xt "$family" filter -X "$chain" || return 76
}

firewall_app_policy_deactivate_record_locked() {
  local line=$1 family jump_b64 jump count
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  jump_b64=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
  jump=$(firewall_unb64 "$jump_b64") || return 65
  firewall_app_policy_chain_matches_record "$line" || return 76
  count=$(firewall_app_policy_jump_count "$line") || return
  [ "$count" -eq 1 ] || return 76
  set -- $jump
  firewall_xt "$family" filter -D OUTPUT "$@" || return 76
}

firewall_app_policy_restore_record_jump_locked() {
  local line=$1 old_position=$2 new_jump_count=$3 family jump_b64 jump count current_position insert_position
  firewall_app_policy_old_position_valid "$old_position" || return 65
  case "$new_jump_count" in 0|1) ;; *) return 76 ;; esac
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  jump_b64=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
  jump=$(firewall_unb64 "$jump_b64") || return 65
  firewall_app_policy_chain_matches_record "$line" || return 76
  count=$(firewall_app_policy_jump_count "$line") || return
  [ "$count" -le 1 ] || return 76
  if [ "$old_position" -eq 0 ]; then
    [ "$count" -eq 0 ] || return 76
    return 0
  fi
  insert_position=$((old_position + new_jump_count))
  [ "$insert_position" -ge "$old_position" ] || return 76
  set -- $jump
  if [ "$count" -eq 1 ]; then
    current_position=$(firewall_app_policy_record_jump_position "$line") || return
    [ "$current_position" -eq "$insert_position" ] || return 76
    return 0
  fi
  firewall_xt "$family" filter -I OUTPUT "$insert_position" "$@" || return 76
}

firewall_app_policy_retire_chain_locked() {
  firewall_app_policy_remove_record_locked "$1"
}

firewall_app_policy_compensate_owned_locked() {
  local owned=$1 line reverse="$owned.reverse.$$" remaining_reverse="$owned.remaining-reverse.$$" remaining="$owned.remaining.$$" failures=0 tab succeeded
  [ -f "$owned" ] && [ ! -L "$owned" ] || return 66
  tab=$(printf '\t')
  "$BB" awk '{line[NR]=$0} END{for(i=NR;i>=1;i--) print line[i]}' "$owned" > "$reverse" || {
    rm -f "$reverse"
    return 74
  }
  : > "$remaining_reverse" || { rm -f "$reverse"; return 74; }
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    if [ "$failures" -ne 0 ]; then
      printf '%s\n' "$line" >> "$remaining_reverse" || { rm -f "$reverse" "$remaining_reverse"; return 74; }
      continue
    fi
    case "$line" in
      app-repair-v1"$tab"*)
        if firewall_app_policy_restore_repair_journal_locked "$line"; then succeeded=1; else succeeded=0; fi
        ;;
      *)
        if firewall_app_policy_remove_record_locked "$line"; then succeeded=1; else succeeded=0; fi
        ;;
    esac
    if [ "$succeeded" -eq 0 ]; then
      printf '%s\n' "$line" >> "$remaining_reverse" || { rm -f "$reverse" "$remaining_reverse"; return 74; }
      failures=1
    fi
  done < "$reverse"
  rm -f "$reverse" || return 74
  if [ -s "$remaining_reverse" ]; then
    "$BB" awk '{line[NR]=$0} END{for(i=NR;i>=1;i--) print line[i]}' "$remaining_reverse" > "$remaining" || {
      rm -f "$remaining_reverse" "$remaining"
      return 74
    }
    rm -f "$remaining_reverse" || { rm -f "$remaining"; return 74; }
    atomic_replace_file "$remaining" "$owned" || return 76
  else
    rm -f "$remaining_reverse" "$remaining" "$owned" || return 74
  fi
  [ "$failures" -eq 0 ] || return 76
}

firewall_app_policy_terminal_cleanup_locked() {
  local token=$1 pending file suffix
  firewall_app_policy_token_valid "$token" || return
  pending=$(firewall_app_policy_pending_manifest)
  if [ -e "$pending" ] || [ -L "$pending" ]; then
    [ -f "$pending" ] && [ ! -L "$pending" ] || return 76
    rm -f "$pending" || return 74
  fi
  for suffix in old.tsv new.tsv owned.tsv; do
    file="$RULE_RUNTIME/app-firewall-$token.$suffix"
    if [ -e "$file" ] || [ -L "$file" ]; then
      [ -f "$file" ] && [ ! -L "$file" ] || return 76
      rm -f "$file" || return 74
    fi
  done
}

firewall_app_policy_stage_locked() {
  local mode=$1 uid_file=$2 ip_file=$3 token=$4 capability families old_manifest old_copy new_copy tmp owned pending line result=0 cleanup_result=0 original_result family chain
  firewall_app_policy_token_valid "$token" || return
  case "$mode" in off|block_selected|allow_resolved) ;; *) return 65 ;; esac
  case "$uid_file:$ip_file" in "$RULE_TMP"/*:"$RULE_TMP"/*) ;; *) return 65 ;; esac
  [ -f "$uid_file" ] && [ -f "$ip_file" ] || return 66
  pending=$(firewall_app_policy_pending_manifest)
  [ ! -e "$pending" ] && [ ! -L "$pending" ] || return 75
  firewall_app_policy_terminal_cleanup_locked "$token" || return
  capability=$(firewall_app_policy_capability) || return
  printf '%s' "$capability" | "$BB" grep -F '"supported":true' >/dev/null 2>&1 || return 69
  families=$(printf '%s' "$capability" | "$BB" sed -n 's/.*"families":\[\(.*\)\].*/\1/p')
  old_manifest=$(firewall_app_policy_manifest)
  old_copy="$RULE_RUNTIME/app-firewall-$token.old.tsv"
  new_copy="$RULE_RUNTIME/app-firewall-$token.new.tsv"
  tmp="$new_copy.tmp.$$"
  owned="$RULE_RUNTIME/app-firewall-$token.owned.tsv"
  if [ -e "$old_manifest" ] || [ -L "$old_manifest" ]; then
    [ -f "$old_manifest" ] && [ ! -L "$old_manifest" ] || return 76
    firewall_app_policy_manifest_valid "$old_manifest" || return 76
    cp "$old_manifest" "$old_copy" || return 74
  else
    : > "$old_copy" || return 74
  fi
  : > "$tmp" || { rm -f "$old_copy"; return 74; }
  : > "$owned" || { rm -f "$old_copy" "$tmp"; return 74; }
  case "$mode" in off) : ;; *)
    case "$families" in *'"ipv4"'*) chain=$(firewall_app_policy_chain_for ipv4 "$token") || result=$?; [ "$result" -eq 0 ] && firewall_app_policy_build_family_staged ipv4 "$chain" "$mode" "$uid_file" "$ip_file" "$tmp" || result=$? ;; esac
    [ "$result" -eq 0 ] && case "$families" in *'"ipv6"'*) chain=$(firewall_app_policy_chain_for ipv6 "$token") || result=$?; [ "$result" -eq 0 ] && firewall_app_policy_build_family_staged ipv6 "$chain" "$mode" "$uid_file" "$ip_file" "$tmp" || result=$? ;; esac
    ;;
  esac
  if [ "$result" -eq 0 ] && [ "$mode" != off ]; then
    firewall_app_policy_manifest_valid "$tmp" || result=76
    [ "$result" -ne 0 ] || firewall_app_policy_manifest_matches_token "$tmp" "$token" || result=76
  fi
  if [ "$result" -eq 0 ]; then mv "$tmp" "$new_copy" || result=74; else rm -f "$tmp" "$tmp.rules"; fi
  if [ "$result" -ne 0 ]; then
    rm -f "$old_copy" "$new_copy" "$owned"
    return "$result"
  fi
  if ! "$BB" cmp -s "$old_copy" "$new_copy"; then
    firewall_app_policy_manifest_kernel_current "$old_copy" || {
      result=$?
      firewall_app_policy_terminal_cleanup_locked "$token" || return
      return "$result"
    }
  fi
  firewall_app_policy_pending_write "$token" "$mode" "$old_copy" "$new_copy" || result=$?
  if [ "$result" -eq 0 ]; then firewall_app_policy_pending_load "$pending" || result=76; fi
  if [ "$result" -ne 0 ]; then
    original_result=$result
    firewall_app_policy_terminal_cleanup_locked "$token" || cleanup_result=$?
    rm -f "$pending.tmp.$$"
    [ "$cleanup_result" -eq 0 ] || return "$cleanup_result"
    return "$original_result"
  fi
  if [ -s "$old_copy" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      firewall_app_policy_manifest_contains_record "$new_copy" "$line" || continue
      firewall_app_policy_record_is_owned_subset "$line" || { result=76; break; }
    done < "$old_copy"
  fi
  if [ "$result" -ne 0 ]; then
    firewall_app_policy_terminal_cleanup_locked "$token" || return
    return "$result"
  fi
  if [ "$mode" != off ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      if firewall_app_policy_manifest_contains_record "$old_copy" "$line"; then
        firewall_app_policy_repair_record_locked "$line" "$owned" || { result=$?; break; }
      else
        firewall_app_policy_apply_staged_record_locked "$line" "$owned" || { result=$?; break; }
      fi
    done < "$new_copy"
  fi
  if [ "$result" -ne 0 ]; then
    original_result=$result
    firewall_app_policy_compensate_owned_locked "$owned" || cleanup_result=$?
    [ "$cleanup_result" -eq 0 ] || return 76
    firewall_app_policy_terminal_cleanup_locked "$token" || return
    rm -f "$pending.tmp.$$"
    return "$original_result"
  fi
  rm -f "$owned" || return 74
  if [ -f "$old_manifest" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      firewall_app_policy_manifest_contains_record "$new_copy" "$line" && continue
      firewall_app_policy_deactivate_record_locked "$line" || { result=$?; break; }
    done < "$old_manifest"
  fi
  if [ "$result" -ne 0 ]; then
    local original_result=$result rollback_result=0
    firewall_app_policy_rollback_locked "$token" || rollback_result=$?
    [ "$rollback_result" -eq 0 ] || return 76
    return "$original_result"
  fi
}

firewall_app_policy_stage() {
  [ "$#" -eq 4 ] || return 64
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_app_policy_stage_locked "$1" "$2" "$3" "$4"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_app_policy_rollback_locked() {
  local token=$1 line family old_position new_jump_count pending owned load_result result=0 manifest=$(firewall_app_policy_manifest)
  pending=$(firewall_app_policy_pending_manifest)
  [ -e "$pending" ] || { [ ! -L "$pending" ] || return 66; return 65; }
  firewall_app_policy_pending_load "$pending" || {
    load_result=$?
    [ "$load_result" -ne 65 ] || return 76
    return "$load_result"
  }
  [ "$APP_PENDING_TOKEN" = "$token" ] || return 65
  owned="$RULE_RUNTIME/app-firewall-$token.owned.tsv"
  if [ -e "$owned" ] || [ -L "$owned" ]; then
    [ -f "$owned" ] && [ ! -L "$owned" ] || return 76
    firewall_app_policy_compensate_owned_locked "$owned" || return
  fi
  if [ -s "$APP_PENDING_OLD_MANIFEST" ]; then
    "$BB" awk '{line[NR]=$0} END{for(i=NR;i>=1;i--) print line[i]}' "$APP_PENDING_OLD_MANIFEST" | while IFS= read -r line || [ -n "$line" ]; do
      firewall_app_policy_manifest_contains_record "$APP_PENDING_NEW_MANIFEST" "$line" && continue
      family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
      case "$family" in
        ipv4) old_position=$APP_PENDING_OLD4_POS ;;
        ipv6) old_position=$APP_PENDING_OLD6_POS ;;
        *) exit 65 ;;
      esac
      new_jump_count=$(firewall_app_policy_manifest_family_jump_count \
        "$APP_PENDING_NEW_MANIFEST" "$family") || exit $?
      firewall_app_policy_restore_record_jump_locked \
        "$line" "$old_position" "$new_jump_count" || exit $?
    done || result=$?
  fi
  if [ "$result" -eq 0 ] && [ -s "$APP_PENDING_NEW_MANIFEST" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      firewall_app_policy_manifest_contains_record "$APP_PENDING_OLD_MANIFEST" "$line" && continue
      firewall_app_policy_remove_record_locked "$line" || { result=$?; break; }
    done < "$APP_PENDING_NEW_MANIFEST"
  fi
  [ "$result" -eq 0 ] || return "$result"
  firewall_app_policy_terminal_cleanup_locked "$token"
}

firewall_app_policy_rollback() {
  [ "$#" -eq 1 ] || return 64
  firewall_app_policy_token_valid "$1" || return
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_app_policy_rollback_locked "$1"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_app_policy_pending_new_current() {
  local line count
  [ "$APP_PENDING_MODE" != off ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    firewall_app_policy_chain_matches_record "$line" || return 1
    count=$(firewall_app_policy_jump_count "$line") || return 1
    [ "$count" -eq 1 ] || return 1
  done < "$APP_PENDING_NEW_MANIFEST"
}

firewall_app_policy_confirm_locked() {
  local token=$1 line pending load_result result=0 manifest=$(firewall_app_policy_manifest) tmp="$RULE_RUNTIME/app-firewall.confirm.$$"
  pending=$(firewall_app_policy_pending_manifest)
  [ -e "$pending" ] || { [ ! -L "$pending" ] || return 66; return 65; }
  firewall_app_policy_pending_load "$pending" || {
    load_result=$?
    [ "$load_result" -ne 65 ] || return 76
    return "$load_result"
  }
  [ "$APP_PENDING_TOKEN" = "$token" ] || return 65
  firewall_app_policy_pending_new_current || return 76
  cp "$APP_PENDING_NEW_MANIFEST" "$tmp" || return 74
  if [ -s "$APP_PENDING_OLD_MANIFEST" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      firewall_app_policy_manifest_contains_record "$APP_PENDING_NEW_MANIFEST" "$line" && continue
      firewall_app_policy_retire_chain_locked "$line" || { result=$?; break; }
    done < "$APP_PENDING_OLD_MANIFEST"
  fi
  [ "$result" -eq 0 ] || { rm -f "$tmp"; return "$result"; }
  if [ -s "$tmp" ]; then atomic_replace_file "$tmp" "$manifest" || return; else rm -f "$tmp" "$manifest" || return 74; fi
  firewall_app_policy_terminal_cleanup_locked "$token"
}

firewall_app_policy_confirm() {
  [ "$#" -eq 1 ] || return 64
  firewall_app_policy_token_valid "$1" || return
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_app_policy_confirm_locked "$1"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_app_policy_resume_same_manifest_locked() {
  local token=$1 owned line
  owned="$RULE_RUNTIME/app-firewall-$token.owned.tsv"
  if [ -e "$owned" ] || [ -L "$owned" ]; then
    [ -f "$owned" ] && [ ! -L "$owned" ] || return 76
  else
    : > "$owned" || return 74
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    firewall_app_policy_record_is_owned_subset "$line" || return
    firewall_app_policy_repair_record_locked "$line" "$owned" || return
  done < "$APP_PENDING_NEW_MANIFEST"
  firewall_app_policy_pending_new_current || return 76
  firewall_app_policy_confirm_locked "$token"
}

firewall_app_policy_recover_locked() {
  local desired_token=$1 pending token load_result
  firewall_app_policy_token_valid "$desired_token" || return
  pending=$(firewall_app_policy_pending_manifest)
  [ -e "$pending" ] || { [ ! -L "$pending" ] || return 76; return 0; }
  firewall_app_policy_pending_load "$pending" || {
    load_result=$?
    [ "$load_result" -ne 65 ] || return 76
    return "$load_result"
  }
  token=$APP_PENDING_TOKEN
  if [ "$token" = "$desired_token" ]; then
    if firewall_app_policy_pending_new_current; then
      firewall_app_policy_confirm_locked "$token"
    elif [ "$APP_PENDING_OLD_HASH" = "$APP_PENDING_NEW_HASH" ]; then
      firewall_app_policy_resume_same_manifest_locked "$token"
    else
      firewall_app_policy_rollback_locked "$token"
    fi
  else
    firewall_app_policy_rollback_locked "$token"
  fi
}

firewall_app_policy_recover() {
  [ "$#" -eq 1 ] || return 64
  firewall_app_policy_token_valid "$1" || return
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_app_policy_recover_locked "$1"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_app_policy_active_locked() {
  local token=$1 manifest line count
  firewall_app_policy_token_valid "$token" || return
  manifest=$(firewall_app_policy_manifest)
  [ -f "$manifest" ] && [ ! -L "$manifest" ] || return 1
  firewall_app_policy_manifest_matches_token "$manifest" "$token" || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    firewall_app_policy_chain_matches_record "$line" || return 1
    count=$(firewall_app_policy_jump_count "$line") || return 1
    [ "$count" -eq 1 ] || return 1
  done < "$manifest"
}

firewall_app_policy_active() {
  [ "$#" -eq 1 ] || return 64
  firewall_app_policy_token_valid "$1" || return
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_app_policy_active_locked "$1"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_app_policy_ip_family_present() {
  local family=$1 file=$2
  case "$family" in
    ipv4) "$BB" awk 'index($0,":")==0 && NF{found=1} END{exit found?0:1}' "$file" ;;
    ipv6) "$BB" awk 'index($0,":")>0 && NF{found=1} END{exit found?0:1}' "$file" ;;
    *) return 64 ;;
  esac
}

firewall_app_policy_apply() {
  if [ "$#" -eq 4 ]; then
    firewall_app_policy_stage "$1" "$2" "$3" "$4"
    return
  fi
  [ "$#" -eq 3 ] || return 64
  local mode=$1 uid_file=$2 ip_file=$3 capability families manifest tmp result=0
  case "$mode" in block_selected|allow_resolved) ;; *) return 65 ;; esac
  case "$uid_file:$ip_file" in "$RULE_TMP"/*:"$RULE_TMP"/*) ;; *) return 65 ;; esac
  [ -f "$uid_file" ] && [ -f "$ip_file" ] || return 66
  rules_init_paths "$MODDIR" || return
  capability=$(firewall_app_policy_capability) || return
  printf '%s' "$capability" | "$BB" grep -F '"supported":true' >/dev/null 2>&1 || return 69
  families=$(printf '%s' "$capability" | "$BB" sed -n 's/.*"families":\[\(.*\)\].*/\1/p')
  rules_lock_acquire firewall || return
  firewall_app_policy_cleanup_locked || { result=$?; rules_lock_release firewall; return "$result"; }
  manifest=$(firewall_app_policy_manifest)
  tmp="$manifest.tmp.$$"
  : > "$tmp" || { rules_lock_release firewall; return 74; }
  case "$families" in
    *'"ipv4"'*)
      if [ "$mode" != allow_resolved ] || firewall_app_policy_ip_family_present ipv4 "$ip_file"; then
        firewall_app_policy_apply_family_locked ipv4 "$APP_POLICY_CHAIN4" "$mode" "$uid_file" "$ip_file" "$tmp" || result=$?
      fi
      ;;
  esac
  if [ "$result" -eq 0 ]; then
    case "$families" in
      *'"ipv6"'*)
        if [ "$mode" != allow_resolved ] || firewall_app_policy_ip_family_present ipv6 "$ip_file"; then
          firewall_app_policy_apply_family_locked ipv6 "$APP_POLICY_CHAIN6" "$mode" "$uid_file" "$ip_file" "$tmp" || result=$?
        fi
        ;;
    esac
  fi
  if [ "$result" -eq 0 ]; then
    firewall_app_policy_manifest_valid "$tmp" || result=76
  fi
  if [ "$result" -eq 0 ]; then
    atomic_replace_file "$tmp" "$manifest" || result=$?
  else
    rm -f "$tmp" "$tmp.rules"
    for family in ipv4 ipv6; do
      [ "$family" = ipv4 ] && chain=$APP_POLICY_CHAIN4 || chain=$APP_POLICY_CHAIN6
      firewall_xt "$family" filter -D OUTPUT -m comment --comment "$RULE_MODULE_ID:app-policy" -j "$chain" >/dev/null 2>&1 || true
      firewall_xt "$family" filter -F "$chain" >/dev/null 2>&1 || true
      firewall_xt "$family" filter -X "$chain" >/dev/null 2>&1 || true
    done
  fi
  rules_lock_release firewall || return
  return "$result"
}

DOH_CHAIN4=JJD4_OUT
DOH_CHAIN6=JJD6_OUT
DOH_UID_EXEMPT=65534
# Opportunistic Private DNS probes DoT on 853; redirecting it into the local
# proxy makes the probe fail so the resolver falls back to plain 53, which the
# rules below already capture. The module never mutates private_dns_mode.
DOH_DOT_PORT=853
DOH_MIN_APP_ID=10000
DOH_MAX_APP_ID=19999
DOH_MAX_UID=4294967294
# Many Android kernels ship ip6tables without ip6table_nat, so there is nowhere
# to redirect an IPv6 query to. Those kernels still have the filter table, where
# the only honest action is to refuse the plaintext query: the resolver retries
# over IPv4, which is redirected into the companion. Refusing is what stops a
# plaintext IPv6 lookup from leaving the device -- letting it through would be a
# silent bypass of the whole feature.
DOH_REJECT_WITH4=icmp-port-unreachable
DOH_REJECT_WITH6=icmp6-port-unreachable

firewall_doh_dir() { printf '%s\n' "$RULE_RUNTIME/doh"; }
firewall_doh_manifest() { printf '%s\n' "$RULE_RUNTIME/doh/firewall-$1.tsv"; }

firewall_doh_token_valid() {
  [ "${#1}" -eq 16 ] || return 65
  case "$1" in *[!0-9a-f]*) return 65 ;; esac
}

firewall_doh_slot_valid() {
  case "$1" in A|B) return 0 ;; *) return 65 ;; esac
}

firewall_doh_mode_valid() {
  case "$1" in global|selected) return 0 ;; *) return 65 ;; esac
}

firewall_doh_port_valid() {
  decimal_uint_in_range "$1" 65535 1 || return 65
}

# Every DoH record already carries its iptables table in field 3, but each
# handler hardcoded "nat" and the validators asserted it, so the field was dead
# weight. Routing every read and write through one resolver is what lets IPv6
# move to the filter table on kernels without ip6table_nat.
#
# Reading a builtin chain is enough to tell the two apart: a kernel without
# ip6table_nat answers "Table does not exist (do you need to insmod?)" and exits
# non-zero, which is exactly how encrypted DNS failed in the field. If neither
# table answers, stay on nat so the caller reports the missing-xtables failure it
# already knows how to report instead of a confusing filter-table one.
firewall_doh_ipv6_table_probe() {
  if firewall_xt ipv6 nat -S OUTPUT >/dev/null 2>&1; then printf 'nat\n'; return 0; fi
  if firewall_xt ipv6 filter -S OUTPUT >/dev/null 2>&1; then printf 'filter\n'; return 0; fi
  printf 'nat\n'
}

# Resolved once per process and cached: this is consulted at ~50 call sites per
# operation and each probe costs a process spawn. An inherited value is honoured
# only when it names a table this code actually supports.
firewall_doh_table_for() {
  case "$1" in
    ipv4) printf 'nat\n'; return 0 ;;
    ipv6) ;;
    *) return 65 ;;
  esac
  case "${DOH_IPV6_TABLE-}" in
    nat|filter) ;;
    *) DOH_IPV6_TABLE=$(firewall_doh_ipv6_table_probe) ;;
  esac
  export DOH_IPV6_TABLE
  printf '%s\n' "$DOH_IPV6_TABLE"
}

# The action every DNS-carrying rule ends in. The nat table can hand the query to
# the companion; the filter table can only refuse it.
firewall_doh_action_for() {
  local family=$1 port=$2 table
  firewall_doh_port_valid "$port" || return 65
  table=$(firewall_doh_table_for "$family") || return 65
  case "$table:$family" in
    nat:*) printf 'REDIRECT --to-ports %s\n' "$port" ;;
    filter:ipv4) printf 'REJECT --reject-with %s\n' "$DOH_REJECT_WITH4" ;;
    filter:ipv6) printf 'REJECT --reject-with %s\n' "$DOH_REJECT_WITH6" ;;
    *) return 65 ;;
  esac
}

# The four (protocol, port) pairs an owned DoH chain covers, in manifest order.
# The writer and the record validator both read them from here so the rules that
# get installed and the rules that get accepted can never drift apart -- and so
# neither plaintext 53 nor opportunistic DoT on 853 can be dropped from one side
# without failing the other.
firewall_doh_rule_bodies() {
  local family=$1 port=$2 prefix=$3 action
  action=$(firewall_doh_action_for "$family" "$port") || return 65
  printf '%s-p udp --dport 53 -j %s\n' "$prefix" "$action"
  printf '%s-p tcp --dport 53 -j %s\n' "$prefix" "$action"
  printf '%s-p tcp --dport %s -j %s\n' "$prefix" "$DOH_DOT_PORT" "$action"
  printf '%s-p udp --dport %s -j %s\n' "$prefix" "$DOH_DOT_PORT" "$action"
}

# A manifest carries one base64 rule per field, so validation has to pin each
# field to its own generated line. Comparing the joined text instead accepts a
# rehashed record that packs two rules into one field and leaves another empty:
# the same bytes overall, but a rule list the writer never emitted and the
# installer cannot replay.
firewall_doh_rule_line() {
  printf '%s\n' "$1" | "$BB" awk -v n="$2" 'NR==n{print; exit}'
}

# The live-state scans have no record to read the table from, so they resolve it
# the same way the writers do. Wrapping the two call shapes keeps that resolution
# in one place instead of repeating it at ~46 call sites.
firewall_doh_xt() {
  local family=$1 table
  shift
  table=$(firewall_doh_table_for "$family") || return 65
  firewall_xt "$family" "$table" "$@"
}

firewall_doh_chain_exists() {
  local family=$1 chain=$2 table
  table=$(firewall_doh_table_for "$family") || return 65
  firewall_chain_exists "$family" "$table" "$chain"
}

firewall_doh_uid_valid() {
  local uid=$1 appid
  case "$uid" in ''|*[!0-9]*|0[0-9]*) return 65 ;; esac
  decimal_uint_in_range "$uid" "$DOH_MAX_UID" 0 || return 65
  [ "$uid" != "$DOH_UID_EXEMPT" ] || return 65
  appid=$((uid % 100000))
  [ "$appid" -ge "$DOH_MIN_APP_ID" ] && [ "$appid" -le "$DOH_MAX_APP_ID" ] || return 65
}

firewall_doh_family_prefix() {
  case "$1" in
    ipv4) printf '4\n' ;;
    ipv6) printf '6\n' ;;
    *) return 64 ;;
  esac
}

firewall_doh_dispatcher_for() {
  case "$1" in
    ipv4) printf '%s\n' "$DOH_CHAIN4" ;;
    ipv6) printf '%s\n' "$DOH_CHAIN6" ;;
    *) return 64 ;;
  esac
}

firewall_doh_chain_for() {
  local prefix
  firewall_doh_slot_valid "$2" || return
  prefix=$(firewall_doh_family_prefix "$1") || return
  printf 'JJD%s_%s\n' "$prefix" "$2"
}

firewall_doh_output_jump() {
  local dispatcher
  dispatcher=$(firewall_doh_dispatcher_for "$1") || return
  printf '%s\n' "-m comment --comment $RULE_MODULE_ID:doh -j $dispatcher"
}

firewall_render_normalize_known_xtables() {
  printf '%s\n' "$1" | "$BB" sed \
    -e 's/-p udp -m udp /-p udp /g' \
    -e 's/-p tcp -m tcp /-p tcp /g'
}

firewall_rendered_rule_matches() {
  local chain=$1 rule=$2 actual=$3 expected normalized
  expected="-A $chain $rule"
  [ "$actual" = "$expected" ] && return 0
  normalized=$(firewall_render_normalize_known_xtables "$actual") || return 1
  [ "$normalized" = "$expected" ]
}

firewall_doh_uid_file_valid() {
  local file=$1
  case "$file" in "$RULE_TMP"/*) ;; *) return 65 ;; esac
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -v max_uid="$DOH_MAX_UID" -v min_app_id="$DOH_MIN_APP_ID" -v max_app_id="$DOH_MAX_APP_ID" -v exempt="$DOH_UID_EXEMPT" '
    $0 == "" { exit 65 }
    $0 !~ /^[0-9]+$/ { exit 65 }
    $0 ~ /^0[0-9]/ { exit 65 }
    {
      uid = $0 + 0
      appid = uid % 100000
      if (uid > max_uid) exit 65
      if (uid == exempt) exit 65
      if (appid < min_app_id || appid > max_app_id) exit 65
      if (NR > 1 && uid <= previous) exit 65
      previous = uid
    }
  ' "$file" || return 65
}

firewall_doh_selected_uid_file_nonempty() {
  local file=$1 uid
  while IFS= read -r uid || [ -n "$uid" ]; do
    [ -n "$uid" ] || continue
    return 0
  done < "$file"
  return 65
}

firewall_doh_rules_file() {
  local family=$1 mode=$2 port=$3 uid_file=$4 output=$5 uid rule plain result=0
  firewall_doh_mode_valid "$mode" || return
  firewall_doh_port_valid "$port" || return
  firewall_doh_uid_file_valid "$uid_file" || return
  : > "$output" || return 74
  plain="$output.plain"
  rm -f "$plain"
  printf -- '-m owner --uid-owner %s -j RETURN\n' "$DOH_UID_EXEMPT" > "$plain" || return 74
  if [ "$mode" = global ]; then
    firewall_doh_rule_bodies "$family" "$port" '' >> "$plain" || result=65
  else
    firewall_doh_selected_uid_file_nonempty "$uid_file" || result=65
    while IFS= read -r uid || [ -n "$uid" ]; do
      [ -n "$uid" ] || continue
      firewall_doh_uid_valid "$uid" || { result=65; break; }
      firewall_doh_rule_bodies "$family" "$port" "-m owner --uid-owner $uid " >> "$plain" || { result=65; break; }
    done < "$uid_file"
  fi
  [ "$result" -eq 0 ] || { rm -f "$plain"; return "$result"; }
  while IFS= read -r rule || [ -n "$rule" ]; do
    [ -n "$rule" ] || continue
    firewall_rule_append "$output" "$rule" || { rm -f "$plain"; return 74; }
  done < "$plain"
  rm -f "$plain"
}

firewall_doh_slot_record() {
  local family=$1 mode=$2 slot=$3 port=$4 token=$5 uid_file=$6 output=$7 chain dispatcher rules count encoded table
  chain=$(firewall_doh_chain_for "$family" "$slot") || return
  dispatcher=$(firewall_doh_dispatcher_for "$family") || return
  table=$(firewall_doh_table_for "$family") || return
  rules="$RULE_TMP/doh.$family.$slot.rules.$$"
  firewall_doh_rules_file "$family" "$mode" "$port" "$uid_file" "$rules" || { rm -f "$rules"; return $?; }
  count=$(wc -l < "$rules" | tr -d ' ') || { rm -f "$rules"; return 74; }
  {
    printf 'doh-slot-v1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
      "$family" "$table" "$dispatcher" "$chain" "$mode" "$slot" "$port" "$token" "$count"
    while IFS= read -r encoded || [ -n "$encoded" ]; do printf '\t%s' "$encoded"; done < "$rules"
    printf '\n'
  } >> "$output" || { rm -f "$rules"; return 74; }
  rm -f "$rules"
}

firewall_doh_actual_slot_record() {
  local family=$1 slot=$2 token=$3 output=$4 line chain dispatcher mode port predecessor count index encoded table
  line=$(firewall_doh_active_slot_record_line "$family" "$slot") || return
  table=$(firewall_doh_table_for "$family") || return
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  dispatcher=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
  mode=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $6}')
  port=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $8}')
  predecessor=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $9}')
  count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $10}')
  {
    printf 'doh-old-slot-v1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
      "$family" "$table" "$dispatcher" "$chain" "$mode" "$slot" "$port" "$predecessor" "$token" "$count"
    index=1
    while [ "$index" -le "$count" ]; do
      encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((10 + index)) '{print $n}')
      printf '\t%s' "$encoded"
      index=$((index + 1))
    done
    printf '\n'
  } >> "$output" || return 74
}

firewall_doh_dispatch_record() {
  local family=$1 old_slot=$2 new_slot=$3 token=$4 output=$5 dispatcher old_rule=- new_rule table
  dispatcher=$(firewall_doh_dispatcher_for "$family") || return
  table=$(firewall_doh_table_for "$family") || return
  new_rule=$(firewall_b64 "-j $(firewall_doh_chain_for "$family" "$new_slot")") || return
  if [ "$old_slot" != - ]; then
    old_rule=$(firewall_b64 "-j $(firewall_doh_chain_for "$family" "$old_slot")") || return
  fi
  printf 'doh-dispatch-v1\t%s\t%s\tOUTPUT\t%s\t%s\t%s\t%s\n' \
    "$family" "$table" "$dispatcher" "$token" "$old_rule" "$new_rule" >> "$output" || return 74
}

firewall_doh_sha256_valid() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in *[!0-9a-f]*) return 1 ;; *) return 0 ;; esac
}

firewall_doh_manifest_body_hash() {
  local file=$1
  "$BB" awk 'NR>1{print}' "$file" | sha256_file_stdin
}

firewall_doh_record_validate() {
  local line=$1 fields schema family table dispatcher chain mode slot port token count expected index encoded rule uid predecessor slot_line cursor
  fields=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print NF}') || return 65
  schema=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $1}')
  case "$schema" in
    doh-slot-v1)
      [ "$fields" -ge 10 ] || return 65
      family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
      table=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
      dispatcher=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
      chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
      mode=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $6}')
      slot=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $7}')
      port=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $8}')
      token=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $9}')
      count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $10}')
      [ "$table" = "$(firewall_doh_table_for "$family")" ] || return 65
      [ "$dispatcher" = "$(firewall_doh_dispatcher_for "$family")" ] || return 65
      [ "$chain" = "$(firewall_doh_chain_for "$family" "$slot")" ] || return 65
      firewall_doh_mode_valid "$mode" || return
      firewall_doh_port_valid "$port" || return
      firewall_doh_token_valid "$token" || return
      case "$count" in ''|*[!0-9]*) return 65 ;; esac
      [ "$fields" -eq $((10 + count)) ] || return 65
      encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $11}')
      rule=$(firewall_unb64 "$encoded" 2>/dev/null) || return 65
      [ "$rule" = "-m owner --uid-owner $DOH_UID_EXEMPT -j RETURN" ] || return 65
      if [ "$mode" = global ]; then
        [ "$count" -eq 5 ] || return 65
        expected=$(firewall_doh_rule_bodies "$family" "$port" '') || return 65
        cursor=2
        while [ "$cursor" -le 5 ]; do
          encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((10 + cursor)) '{print $n}')
          rule=$(firewall_unb64 "$encoded" 2>/dev/null) || return 65
          [ "$rule" = "$(firewall_doh_rule_line "$expected" $((cursor - 1)))" ] || return 65
          cursor=$((cursor + 1))
        done
      else
        [ "$count" -gt 1 ] || return 65
        [ $(((count - 1) % 4)) -eq 0 ] || return 65
        index=2
        while [ "$index" -le "$count" ]; do
          encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((10 + index)) '{print $n}')
          rule=$(firewall_unb64 "$encoded" 2>/dev/null) || return 65
          uid=${rule#"-m owner --uid-owner "}
          [ "$uid" != "$rule" ] || return 65
          uid=${uid%% *}
          firewall_doh_uid_valid "$uid" || return 65
          expected=$(firewall_doh_rule_bodies "$family" "$port" "-m owner --uid-owner $uid ") || return 65
          cursor=$index
          while [ "$cursor" -le $((index + 3)) ]; do
            encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((10 + cursor)) '{print $n}')
            rule=$(firewall_unb64 "$encoded" 2>/dev/null) || return 65
            [ "$rule" = "$(firewall_doh_rule_line "$expected" $((cursor - index + 1)))" ] || return 65
            cursor=$((cursor + 1))
          done
          index=$((index + 4))
        done
      fi
      ;;
    doh-old-slot-v1)
      [ "$fields" -ge 11 ] || return 65
      family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
      table=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
      dispatcher=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')
      chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
      mode=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $6}')
      slot=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $7}')
      port=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $8}')
      predecessor=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $9}')
      token=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $10}')
      count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $11}')
      [ "$table" = "$(firewall_doh_table_for "$family")" ] || return 65
      [ "$dispatcher" = "$(firewall_doh_dispatcher_for "$family")" ] || return 65
      [ "$chain" = "$(firewall_doh_chain_for "$family" "$slot")" ] || return 65
      firewall_doh_mode_valid "$mode" || return
      firewall_doh_port_valid "$port" || return
      firewall_doh_token_valid "$predecessor" || return
      firewall_doh_token_valid "$token" || return
      case "$count" in ''|*[!0-9]*) return 65 ;; esac
      [ "$fields" -eq $((11 + count)) ] || return 65
      slot_line=$(printf 'doh-slot-v1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
        "$family" "$table" "$dispatcher" "$chain" "$mode" "$slot" "$port" "$predecessor" "$count")
      index=1
      while [ "$index" -le "$count" ]; do
        encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((11 + index)) '{print $n}')
        slot_line="$slot_line	$encoded"
        index=$((index + 1))
      done
      firewall_doh_record_validate "$slot_line" || return 65
      ;;
    doh-dispatch-v1)
      [ "$fields" -eq 8 ] || return 65
      family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
      table=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
      dispatcher=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
      token=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $6}')
      [ "$table" = "$(firewall_doh_table_for "$family")" ] || return 65
      [ "$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $4}')" = OUTPUT ] || return 65
      [ "$dispatcher" = "$(firewall_doh_dispatcher_for "$family")" ] || return 65
      firewall_doh_token_valid "$token" || return
      expected=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $7}')
      [ "$expected" = - ] || firewall_unb64 "$expected" >/dev/null 2>&1 || return 65
      expected=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $8}')
      firewall_unb64 "$expected" >/dev/null 2>&1 || return 65
      ;;
    *) return 65 ;;
  esac
}

firewall_doh_manifest_load() {
  local file=$1 header fields line_count actual_hash line slot_records=0 dispatch_records=0 old_records=0
  local family mode slot port token predecessor old_rule new_rule expected_old expected_new seen4=0 seen6=0 dispatch_seen4=0 dispatch_seen6=0 old_seen4=0 old_seen6=0 old_predecessor=
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  line_count=$(wc -l < "$file" | tr -d ' ') || return 70
  [ "$line_count" -ge 5 ] || return 76
  header=$(sed -n '1p' "$file") || return 70
  fields=$(printf '%s\n' "$header" | "$BB" awk -F '\t' '{print NF}') || return 70
  [ "$fields" -eq 12 ] || return 76
  IFS="$(printf '\t')" read -r DOH_SCHEMA DOH_MODE DOH_SLOT DOH_PORT DOH_TOKEN DOH_STATE \
    DOH_OLD4 DOH_OLD6 DOH_NEW4 DOH_NEW6 DOH_BODY_HASH DOH_UID_HASH <<EOF
$header
EOF
  [ "$DOH_SCHEMA" = doh-v1 ] || return 76
  firewall_doh_mode_valid "$DOH_MODE" || return 76
  firewall_doh_slot_valid "$DOH_SLOT" || return 76
  firewall_doh_port_valid "$DOH_PORT" || return 76
  firewall_doh_token_valid "$DOH_TOKEN" || return 76
  case "$DOH_STATE" in staged|active) ;; *) return 76 ;; esac
  case "$DOH_OLD4:$DOH_OLD6:$DOH_NEW4:$DOH_NEW6" in
    -:-:A:A|-:-:B:B|A:A:B:B|B:B:A:A) ;;
    *) return 76 ;;
  esac
  [ "$DOH_SLOT" = "$DOH_NEW4" ] && [ "$DOH_SLOT" = "$DOH_NEW6" ] || return 76
  firewall_doh_sha256_valid "$DOH_BODY_HASH" || return 76
  firewall_doh_sha256_valid "$DOH_UID_HASH" || return 76
  actual_hash=$(firewall_doh_manifest_body_hash "$file") || return
  [ "$actual_hash" = "$DOH_BODY_HASH" ] || return 76
  "$BB" awk 'NR>1{print}' "$file" | while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || exit 76
    firewall_doh_record_validate "$line" || exit $?
  done || return $?
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      doh-slot-v1*)
        family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
        mode=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $6}')
        slot=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $7}')
        port=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $8}')
        token=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $9}')
        [ "$mode" = "$DOH_MODE" ] && [ "$slot" = "$DOH_SLOT" ] && \
          [ "$port" = "$DOH_PORT" ] && [ "$token" = "$DOH_TOKEN" ] || return 76
        case "$family" in
          ipv4) [ "$seen4" -eq 0 ] || return 76; seen4=1 ;;
          ipv6) [ "$seen6" -eq 0 ] || return 76; seen6=1 ;;
          *) return 76 ;;
        esac
        slot_records=$((slot_records + 1))
        ;;
      doh-old-slot-v1*)
        family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
        mode=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $6}')
        slot=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $7}')
        port=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $8}')
        predecessor=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $9}')
        token=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $10}')
        [ "$token" = "$DOH_TOKEN" ] || return 76
        [ "$predecessor" != "$DOH_TOKEN" ] || return 76
        [ "$DOH_OLD4" != - ] && [ "$DOH_OLD6" != - ] || return 76
        if [ -z "$old_predecessor" ]; then
          old_predecessor=$predecessor
        else
          [ "$predecessor" = "$old_predecessor" ] || return 76
        fi
        case "$family" in
          ipv4) [ "$old_seen4" -eq 0 ] || return 76; old_seen4=1; [ "$slot" = "$DOH_OLD4" ] || return 76 ;;
          ipv6) [ "$old_seen6" -eq 0 ] || return 76; old_seen6=1; [ "$slot" = "$DOH_OLD6" ] || return 76 ;;
          *) return 76 ;;
        esac
        firewall_doh_mode_valid "$mode" || return 76
        firewall_doh_port_valid "$port" || return 76
        old_records=$((old_records + 1))
        ;;
      doh-dispatch-v1*)
        family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
        token=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $6}')
        old_rule=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $7}')
        new_rule=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $8}')
        [ "$token" = "$DOH_TOKEN" ] || return 76
        case "$family" in
          ipv4)
            [ "$dispatch_seen4" -eq 0 ] || return 76; dispatch_seen4=1
            [ "$DOH_OLD4" = - ] && expected_old=- || expected_old=$(firewall_b64 "-j $(firewall_doh_chain_for ipv4 "$DOH_OLD4")")
            expected_new=$(firewall_b64 "-j $(firewall_doh_chain_for ipv4 "$DOH_NEW4")")
            ;;
          ipv6)
            [ "$dispatch_seen6" -eq 0 ] || return 76; dispatch_seen6=1
            [ "$DOH_OLD6" = - ] && expected_old=- || expected_old=$(firewall_b64 "-j $(firewall_doh_chain_for ipv6 "$DOH_OLD6")")
            expected_new=$(firewall_b64 "-j $(firewall_doh_chain_for ipv6 "$DOH_NEW6")")
            ;;
          *) return 76 ;;
        esac
        [ "$old_rule" = "$expected_old" ] && [ "$new_rule" = "$expected_new" ] || return 76
        dispatch_records=$((dispatch_records + 1))
        ;;
    esac
  done <<EOF
$("$BB" awk 'NR>1{print}' "$file")
EOF
  [ "$slot_records" -eq 2 ] && [ "$dispatch_records" -eq 2 ] && \
    [ "$seen4" -eq 1 ] && [ "$seen6" -eq 1 ] && \
    [ "$dispatch_seen4" -eq 1 ] && [ "$dispatch_seen6" -eq 1 ] || return 76
  if [ "$DOH_OLD4" = - ] || [ "$DOH_OLD6" = - ]; then
    [ "$DOH_OLD4" = - ] && [ "$DOH_OLD6" = - ] && [ "$old_records" -eq 0 ] || return 76
  else
    [ "$old_records" -eq 2 ] && [ "$old_seen4" -eq 1 ] && [ "$old_seen6" -eq 1 ] && [ -n "$old_predecessor" ] || return 76
  fi
  export DOH_SCHEMA DOH_MODE DOH_SLOT DOH_PORT DOH_TOKEN DOH_STATE \
    DOH_OLD4 DOH_OLD6 DOH_NEW4 DOH_NEW6 DOH_BODY_HASH DOH_UID_HASH
}

firewall_doh_manifest_write() {
  local mode=$1 slot=$2 port=$3 token=$4 uid_file=$5 old4=$6 old6=$7 body=$8 destination=$9 tmp body_hash uid_hash
  mkdir -p "$(firewall_doh_dir)" || return 73
  body_hash=$(sha256_file "$body") || return
  uid_hash=$(sha256_file "$uid_file") || return
  tmp="$destination.tmp.$$"
  {
    printf 'doh-v1\t%s\t%s\t%s\t%s\tstaged\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$mode" "$slot" "$port" "$token" "$old4" "$old6" "$slot" "$slot" "$body_hash" "$uid_hash"
    cat "$body"
  } > "$tmp" || { rm -f "$tmp"; return 74; }
  atomic_replace_file "$tmp" "$destination" || {
    local result=$?
    rm -f "$tmp"
    return "$result"
  }
}

firewall_doh_output_jump_count() {
  local family=$1 jump expected raw count
  jump=$(firewall_doh_output_jump "$family") || return
  expected="-A OUTPUT $jump"
  raw="$RULE_TMP/doh-output-count.$$.$family"
  firewall_doh_xt "$family" -S OUTPUT > "$raw" 2>/dev/null || return 76
  count=$("$BB" awk -v wanted="$expected" '$0==wanted{count++} END{print count+0}' "$raw") || { rm -f "$raw"; return 70; }
  rm -f "$raw"
  printf '%s\n' "$count"
}

firewall_doh_dispatcher_rule_count() {
  local family=$1 dispatcher raw count
  dispatcher=$(firewall_doh_dispatcher_for "$family") || return
  raw="$RULE_TMP/doh-dispatch-count.$$.$family"
  firewall_doh_xt "$family" -S "$dispatcher" > "$raw" 2>/dev/null || return 1
  count=$("$BB" awk -v chain="$dispatcher" '$0 != "-N " chain { count++ } END{print count+0}' "$raw") || { rm -f "$raw"; return 70; }
  rm -f "$raw"
  printf '%s\n' "$count"
}

firewall_doh_dispatcher_current_slot() {
  local family=$1 dispatcher raw line chain slot count
  dispatcher=$(firewall_doh_dispatcher_for "$family") || return
  if ! firewall_doh_chain_exists "$family" "$dispatcher"; then
    printf -- '-\n'
    return 0
  fi
  raw="$RULE_TMP/doh-dispatch-current.$$.$family"
  firewall_doh_xt "$family" -S "$dispatcher" > "$raw" 2>/dev/null || return 76
  count=$("$BB" awk -v chain="$dispatcher" '$0 != "-N " chain { count++ } END{print count+0}' "$raw") || { rm -f "$raw"; return 70; }
  [ "$count" -le 1 ] || { rm -f "$raw"; return 76; }
  if [ "$count" -eq 0 ]; then
    rm -f "$raw"
    printf -- '-\n'
    return 0
  fi
  line=$("$BB" awk -v chain="$dispatcher" '$0 != "-N " chain { print; exit }' "$raw") || { rm -f "$raw"; return 70; }
  rm -f "$raw"
  case "$line" in
    "-A $dispatcher -j JJD4_A"|"-A $dispatcher -j JJD6_A") slot=A ;;
    "-A $dispatcher -j JJD4_B"|"-A $dispatcher -j JJD6_B") slot=B ;;
    *) return 76 ;;
  esac
  chain=$(firewall_doh_chain_for "$family" "$slot") || return
  [ "$line" = "-A $dispatcher -j $chain" ] || return 76
  printf '%s\n' "$slot"
}

firewall_doh_stage_old_slot() {
  local family=$1 count slot
  count=$(firewall_doh_output_jump_count "$family") || return
  [ "$count" -le 1 ] || return 76
  slot=$(firewall_doh_dispatcher_current_slot "$family") || return
  if [ "$slot" = - ]; then
    local dispatcher
    dispatcher=$(firewall_doh_dispatcher_for "$family") || return
    firewall_doh_chain_exists "$family" "$dispatcher" && return 76
  fi
  if [ "$slot" = - ]; then
    [ "$count" -eq 0 ] || return 76
  fi
  printf '%s\n' "$slot"
}

firewall_doh_active_slot_record_line() {
  local family=$1 slot=$2 dir file manifest_slot line
  dir=$(firewall_doh_dir)
  [ -d "$dir" ] || return 1
  for file in "$dir"/firewall-*.tsv; do
    [ -e "$file" ] || continue
    firewall_doh_manifest_load "$file" || continue
    [ "$DOH_STATE" = active ] || continue
    case "$family" in
      ipv4) manifest_slot=$DOH_NEW4 ;;
      ipv6) manifest_slot=$DOH_NEW6 ;;
      *) return 64 ;;
    esac
    [ "$manifest_slot" = "$slot" ] || continue
    line=$(firewall_doh_manifest_new_slot_record "$file" "$family") || return
    firewall_doh_chain_matches_record "$line" || return 76
    printf '%s\n' "$line"
    return 0
  done
  return 1
}

firewall_doh_active_slot_owned() {
  firewall_doh_active_slot_record_line "$1" "$2" >/dev/null
}

firewall_doh_chain_subset_indices() {
  local line=$1 schema family chain count raw actual lines expected_index actual_index=1 encoded rule expected actual_line indices=
  schema=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $1}')
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  case "$schema" in
    doh-slot-v1) count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $10}'); offset=10 ;;
    doh-old-slot-v1) count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $11}'); offset=11 ;;
    *) return 65 ;;
  esac
  raw="$RULE_TMP/doh-chain-raw.$$.$family"
  actual="$RULE_TMP/doh-chain-actual.$$.$family"
  firewall_doh_xt "$family" -S "$chain" > "$raw" 2>/dev/null || return 76
  "$BB" awk -v chain="$chain" '$0 != "-N " chain { print }' "$raw" > "$actual" || { rm -f "$raw" "$actual"; return 74; }
  rm -f "$raw"
  lines=$(wc -l < "$actual" | tr -d ' ') || { rm -f "$actual"; return 74; }
  [ "$lines" -le "$count" ] || { rm -f "$actual"; return 76; }
  actual_line=$(sed -n "${actual_index}p" "$actual")
  expected_index=1
  while [ "$expected_index" -le "$count" ] && [ "$actual_index" -le "$lines" ]; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((offset + expected_index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || { rm -f "$actual"; return 65; }
    if firewall_rendered_rule_matches "$chain" "$rule" "$actual_line"; then
      indices="$indices $expected_index"
      actual_index=$((actual_index + 1))
      actual_line=$(sed -n "${actual_index}p" "$actual")
    fi
    expected_index=$((expected_index + 1))
  done
  rm -f "$actual"
  [ "$actual_index" -gt "$lines" ] || return 76
  printf '%s\n' "${indices# }"
}

firewall_doh_chain_matches_record() {
  local line=$1 schema count indices actual_count=0
  schema=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $1}')
  case "$schema" in
    doh-slot-v1) count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $10}') ;;
    doh-old-slot-v1) count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $11}') ;;
    *) return 65 ;;
  esac
  indices=$(firewall_doh_chain_subset_indices "$line") || return
  for _idx in $indices; do actual_count=$((actual_count + 1)); done
  [ "$actual_count" -eq "$count" ]
}

firewall_doh_chain_empty() {
  local family=$1 chain=$2 raw count
  raw="$RULE_TMP/doh-empty.$$.$family"
  firewall_doh_xt "$family" -S "$chain" > "$raw" 2>/dev/null || return 76
  count=$("$BB" awk -v chain="$chain" '$0 != "-N " chain { count++ } END{print count+0}' "$raw") || { rm -f "$raw"; return 70; }
  rm -f "$raw"
  [ "$count" -eq 0 ]
}

firewall_doh_apply_slot_record_locked() {
  local line=$1 family chain count index encoded rule table
  firewall_doh_record_validate "$line" || return 65
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  table=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $10}')
  firewall_chain_exists "$family" "$table" "$chain" && return 76
  firewall_xt "$family" "$table" -N "$chain" || return 74
  index=1
  while [ "$index" -le "$count" ]; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((10 + index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || return 65
    set -- $rule
    firewall_xt "$family" "$table" -A "$chain" "$@" || return 74
    index=$((index + 1))
  done
  firewall_doh_chain_matches_record "$line" || return 76
}

firewall_doh_rebuild_old_slot_record_locked() {
  local line=$1 family chain count index encoded rule table
  firewall_doh_record_validate "$line" || return 65
  [ "$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $1}')" = doh-old-slot-v1 ] || return 65
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  table=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $11}')
  if firewall_chain_exists "$family" "$table" "$chain"; then
    firewall_doh_chain_matches_record "$line" || return 76
    return 0
  fi
  firewall_xt "$family" "$table" -N "$chain" || return 76
  index=1
  while [ "$index" -le "$count" ]; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((11 + index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || return 65
    set -- $rule
    firewall_xt "$family" "$table" -A "$chain" "$@" || return 76
    index=$((index + 1))
  done
  firewall_doh_chain_matches_record "$line" || return 76
}

firewall_doh_rebuild_old_slots_from_manifest() {
  local manifest=$1 line
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in doh-old-slot-v1*) firewall_doh_rebuild_old_slot_record_locked "$line" || return ;; esac
  done < "$manifest"
}

firewall_doh_remove_slot_record_locked() {
  local line=$1 schema family chain count offset indices index reverse= encoded rule table
  firewall_doh_record_validate "$line" || return 65
  schema=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $1}')
  family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
  table=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $3}')
  chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
  if ! firewall_chain_exists "$family" "$table" "$chain"; then return 0; fi
  case "$schema" in
    doh-slot-v1) count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $10}'); offset=10 ;;
    doh-old-slot-v1) count=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $11}'); offset=11 ;;
    *) return 65 ;;
  esac
  indices=$(firewall_doh_chain_subset_indices "$line") || return
  for index in $indices; do reverse="$index $reverse"; done
  for index in $reverse; do
    encoded=$(printf '%s\n' "$line" | "$BB" awk -F '\t' -v n=$((offset + index)) '{print $n}')
    rule=$(firewall_unb64 "$encoded") || return 65
    set -- $rule
    firewall_xt "$family" "$table" -D "$chain" "$@" || return 76
  done
  firewall_doh_chain_empty "$family" "$chain" || return 76
  firewall_xt "$family" "$table" -X "$chain" || return 76
}

firewall_doh_cleanup_new_slots_from_body() {
  local body=$1 line result=0
  [ -f "$body" ] || return 0
  "$BB" awk '{line[NR]=$0} END{for(i=NR;i>=1;i--) print line[i]}' "$body" | while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in doh-slot-v1*) firewall_doh_remove_slot_record_locked "$line" || exit $? ;; esac
  done || result=$?
  return "$result"
}

firewall_doh_probe_family_locked() {
  local family=$1 chain=$2 actual filtered result=0 count line rule index action
  # Probe the action this family will actually install. Probing REDIRECT on a
  # filter-table family would fail for the wrong reason and report the kernel as
  # incapable when it can enforce encrypted DNS perfectly well.
  action=$(firewall_doh_action_for "$family" 1053) || return 69
  firewall_doh_chain_exists "$family" "$chain" && return 76
  firewall_doh_xt "$family" -N "$chain" || return 69
  firewall_doh_xt "$family" -A "$chain" -m owner --uid-owner "$DOH_UID_EXEMPT" -j RETURN || result=69
  [ "$result" -ne 0 ] || firewall_doh_xt "$family" -A "$chain" -p udp --dport 53 -j $action || result=69
  [ "$result" -ne 0 ] || firewall_doh_xt "$family" -A "$chain" -p tcp --dport 53 -j $action || result=69
  if [ "$result" -eq 0 ]; then
    actual=$(firewall_doh_xt "$family" -S "$chain" 2>/dev/null) || result=69
    [ "$result" -ne 0 ] || filtered=$(printf '%s\n' "$actual" | "$BB" awk -v chain="$chain" '$0 != "-N " chain { print }') || result=69
    if [ "$result" -eq 0 ]; then
      count=$(printf '%s\n' "$filtered" | "$BB" awk 'NF{count++} END{print count+0}') || result=69
      [ "$result" -ne 0 ] || [ "$count" -eq 3 ] || result=69
    fi
    if [ "$result" -eq 0 ]; then
      index=1
      while [ "$index" -le 3 ]; do
        line=$(printf '%s\n' "$filtered" | sed -n "${index}p")
        case "$index" in
          1) rule="-m owner --uid-owner $DOH_UID_EXEMPT -j RETURN" ;;
          2) rule="-p udp --dport 53 -j $action" ;;
          3) rule="-p tcp --dport 53 -j $action" ;;
        esac
        firewall_rendered_rule_matches "$chain" "$rule" "$line" || { result=69; break; }
        index=$((index + 1))
      done
    fi
  fi
  firewall_doh_xt "$family" -D "$chain" -p tcp --dport 53 -j $action >/dev/null 2>&1 || true
  firewall_doh_xt "$family" -D "$chain" -p udp --dport 53 -j $action >/dev/null 2>&1 || true
  firewall_doh_xt "$family" -D "$chain" -m owner --uid-owner "$DOH_UID_EXEMPT" -j RETURN >/dev/null 2>&1 || true
  firewall_doh_xt "$family" -X "$chain" >/dev/null 2>&1 || return 76
  return "$result"
}

firewall_doh_capability_locked() {
  local chain4="JJ_DOH_CAP4_$$" chain6="JJ_DOH_CAP6_$$" result4 result6 reason table6
  firewall_doh_probe_family_locked ipv4 "$chain4"; result4=$?
  case "$result4" in
    0) ;;
    69)
      if [ -n "${XT_FAIL_OWNER-}" ]; then printf 'unsupported owner_match_unavailable\n'; else printf 'unsupported redirect_unavailable\n'; fi
      return 0
      ;;
    *) printf 'unsupported probe_cleanup_failed\n'; return 0 ;;
  esac
  table6=$(firewall_doh_table_for ipv6) || table6=nat
  firewall_doh_probe_family_locked ipv6 "$chain6"; result6=$?
  case "$result6" in
    0) printf 'supported -\n' ;;
    69)
      # A filter-table IPv6 that cannot even refuse is a different failure from a
      # nat-table IPv6 that cannot redirect, and the user needs to be told which.
      if [ "$table6" = filter ]; then reason=ipv6_reject_unavailable; else reason=ipv6_probe_failed; fi
      if [ -n "${XT_FAIL_OWNER-}" ]; then reason=owner_match_unavailable; fi
      if [ -n "${XT_FAIL_REDIRECT-}" ] && [ "$table6" = nat ]; then reason=redirect_unavailable; fi
      printf 'unsupported %s\n' "$reason"
      ;;
    *) printf 'unsupported probe_cleanup_failed\n' ;;
  esac
}

firewall_doh_capability_json() {
  local capability state reason result table6 ipv6_mode
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  capability=$(firewall_doh_capability_locked)
  result=$?
  table6=$(firewall_doh_table_for ipv6) || table6=nat
  rules_lock_release firewall || return
  [ "$result" -eq 0 ] || return "$result"
  state=${capability%% *}
  reason=${capability#* }
  if [ "$state" = supported ]; then
    # "blocked" is not a lesser form of support: plaintext IPv6 DNS is refused so
    # the resolver falls back to the IPv4 path, which is encrypted. The UI needs
    # the distinction to explain what the kernel is actually doing.
    [ "$table6" = filter ] && ipv6_mode=blocked || ipv6_mode=encrypted
    printf '{"supported":true,"reason":null,"families":["ipv4","ipv6"],"modes":["global","selected"],"ipv6Mode":"%s"}\n' "$ipv6_mode"
  else
    printf '{"supported":false,"reason":"%s","families":[],"modes":[]}\n' "$reason"
  fi
}

firewall_doh_stage_locked() {
  local mode=$1 slot=$2 port=$3 token=$4 uid_file=$5 manifest body old4 old6 capability cap_state line result=0 cleanup_result
  firewall_doh_mode_valid "$mode" || return
  firewall_doh_slot_valid "$slot" || return
  firewall_doh_port_valid "$port" || return
  firewall_doh_token_valid "$token" || return
  firewall_doh_uid_file_valid "$uid_file" || return
  [ "$mode" != selected ] || firewall_doh_selected_uid_file_nonempty "$uid_file" || return
  mkdir -p "$(firewall_doh_dir)" || return 73
  manifest=$(firewall_doh_manifest "$token")
  [ ! -e "$manifest" ] && [ ! -L "$manifest" ] || return 76
  capability=$(firewall_doh_capability_locked)
  cap_state=${capability%% *}
  [ "$cap_state" = supported ] || return 69
  old4=$(firewall_doh_stage_old_slot ipv4) || return
  old6=$(firewall_doh_stage_old_slot ipv6) || return
  [ "$old4" = "$old6" ] || return 76
  [ "$old4" != "$slot" ] || return 76
  if [ "$old4" != - ]; then
    firewall_doh_active_slot_owned ipv4 "$old4" || return 76
    firewall_doh_active_slot_owned ipv6 "$old6" || return 76
  fi
  body="$RULE_TMP/doh-firewall-$token.body.$$"
  : > "$body" || return 74
  if [ "$old4" != - ]; then
    firewall_doh_actual_slot_record ipv4 "$old4" "$token" "$body" || { rm -f "$body"; return $?; }
    firewall_doh_actual_slot_record ipv6 "$old6" "$token" "$body" || { rm -f "$body"; return $?; }
  fi
  firewall_doh_slot_record ipv4 "$mode" "$slot" "$port" "$token" "$uid_file" "$body" || { rm -f "$body"; return $?; }
  firewall_doh_dispatch_record ipv4 "$old4" "$slot" "$token" "$body" || { rm -f "$body"; return $?; }
  firewall_doh_slot_record ipv6 "$mode" "$slot" "$port" "$token" "$uid_file" "$body" || { rm -f "$body"; return $?; }
  firewall_doh_dispatch_record ipv6 "$old6" "$slot" "$token" "$body" || { rm -f "$body"; return $?; }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in doh-slot-v1*) firewall_doh_apply_slot_record_locked "$line" || { result=$?; break; } ;; esac
  done < "$body"
  if [ "$result" -ne 0 ]; then
    firewall_doh_cleanup_new_slots_from_body "$body" || cleanup_result=$?
    rm -f "$body"
    [ "${cleanup_result:-0}" -eq 0 ] || return 76
    return "$result"
  fi
  firewall_doh_manifest_write "$mode" "$slot" "$port" "$token" "$uid_file" "$old4" "$old6" "$body" "$manifest" || {
    result=$?
    firewall_doh_cleanup_new_slots_from_body "$body" || cleanup_result=$?
    rm -f "$body"
    [ "${cleanup_result:-0}" -eq 0 ] || return 76
    return "$result"
  }
  rm -f "$body"
}

firewall_doh_stage() {
  [ "$#" -eq 5 ] || return 64
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_doh_stage_locked "$1" "$2" "$3" "$4" "$5"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_doh_manifest_new_slot_record() {
  local file=$1 family=$2 line
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in doh-slot-v1*)
      [ "$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')" = "$family" ] || continue
      printf '%s\n' "$line"
      return 0
      ;;
    esac
  done < "$file"
  return 76
}

firewall_doh_ensure_output_jump() {
  local family=$1 count jump
  count=$(firewall_doh_output_jump_count "$family") || return
  [ "$count" -le 1 ] || return 76
  [ "$count" -eq 1 ] && return 0
  jump=$(firewall_doh_output_jump "$family") || return
  set -- $jump
  firewall_doh_xt "$family" -I OUTPUT 1 "$@" || return 76
}

firewall_doh_remove_output_jumps() {
  local family=$1 count jump
  jump=$(firewall_doh_output_jump "$family") || return
  set -- $jump
  while firewall_doh_xt "$family" -C OUTPUT "$@" >/dev/null 2>&1; do
    firewall_doh_xt "$family" -D OUTPUT "$@" || return 76
  done
  count=$(firewall_doh_output_jump_count "$family") || return
  [ "$count" -eq 0 ] || return 76
}

firewall_doh_switch_family() {
  local family=$1 old_slot=$2 new_slot=$3 dispatcher old_chain new_chain current count
  dispatcher=$(firewall_doh_dispatcher_for "$family") || return
  new_chain=$(firewall_doh_chain_for "$family" "$new_slot") || return
  if ! firewall_doh_chain_exists "$family" "$dispatcher"; then
    firewall_doh_xt "$family" -N "$dispatcher" || return 76
    case "$family" in
      ipv4) DOH_SWITCH_CREATED4=1 ;;
      ipv6) DOH_SWITCH_CREATED6=1 ;;
    esac
  elif [ "$old_slot" = - ]; then
    current=$(firewall_doh_dispatcher_current_slot "$family") || return
    [ "$current" = "$new_slot" ] || return 76
  fi
  current=$(firewall_doh_dispatcher_current_slot "$family") || return
  count=$(firewall_doh_dispatcher_rule_count "$family" "$dispatcher" 2>/dev/null || printf '0')
  [ "$count" -le 1 ] || return 76
  if [ "$current" = "$new_slot" ]; then
    firewall_doh_ensure_output_jump "$family"
    return
  fi
  if [ "$current" = - ]; then
    firewall_doh_xt "$family" -A "$dispatcher" -j "$new_chain" || return 76
  else
    [ "$old_slot" = - ] || [ "$current" = "$old_slot" ] || return 76
    firewall_doh_xt "$family" -R "$dispatcher" 1 -j "$new_chain" || return 76
  fi
  firewall_doh_ensure_output_jump "$family" || return
}

firewall_doh_restore_family() {
  local family=$1 old_slot=$2 new_slot=$3 created=${4:-1} dispatcher old_chain new_chain current
  dispatcher=$(firewall_doh_dispatcher_for "$family") || return
  new_chain=$(firewall_doh_chain_for "$family" "$new_slot") || return
  firewall_doh_chain_exists "$family" "$dispatcher" || return 0
  current=$(firewall_doh_dispatcher_current_slot "$family") || return
  if [ "$old_slot" = - ] && [ "$current" = - ]; then
    [ "$created" -eq 1 ] || return 0
    firewall_doh_remove_output_jumps "$family" || return
    firewall_doh_chain_empty "$family" "$dispatcher" || return 76
    firewall_doh_xt "$family" -X "$dispatcher" || return 76
    return 0
  fi
  [ "$current" = "$new_slot" ] || return 0
  if [ "$old_slot" = - ]; then
    firewall_doh_remove_output_jumps "$family" || return
    firewall_doh_xt "$family" -D "$dispatcher" -j "$new_chain" >/dev/null 2>&1 || true
    firewall_doh_chain_empty "$family" "$dispatcher" || return 76
    firewall_doh_xt "$family" -X "$dispatcher" || return 76
  else
    old_chain=$(firewall_doh_chain_for "$family" "$old_slot") || return
    firewall_doh_xt "$family" -R "$dispatcher" 1 -j "$old_chain" || return 76
  fi
}

firewall_doh_mark_manifest_state() {
  local file=$1 state=$2 tmp
  case "$state" in staged|active) ;; *) return 65 ;; esac
  tmp="$file.state.$$"
  "$BB" awk -F '\t' -v state="$state" 'BEGIN{OFS="\t"} NR==1{$6=state} {print}' "$file" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$file"
}

firewall_doh_manifest_predecessor_token() {
  local manifest=$1 line predecessor=
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      doh-old-slot-v1*)
        predecessor=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $9}') || return 70
        firewall_doh_token_valid "$predecessor" || return 76
        printf '%s\n' "$predecessor"
        return 0
        ;;
    esac
  done < "$manifest"
  printf -- '-\n'
}

firewall_doh_cleanup_stale_manifests_locked() {
  local current_token=$1 predecessor_token=$2 dir file loaded_token
  dir=$(firewall_doh_dir)
  [ -d "$dir" ] || return 0
  for file in "$dir"/firewall-*.tsv; do
    [ -e "$file" ] || continue
    [ -f "$file" ] && [ ! -L "$file" ] || continue
    firewall_doh_manifest_load "$file" || continue
    loaded_token=$DOH_TOKEN
    [ "$loaded_token" = "$current_token" ] && continue
    [ "$predecessor_token" != - ] && [ "$loaded_token" = "$predecessor_token" ] && continue
    rm -f "$file" || return 74
  done
}

firewall_doh_compensate_switch_failure_locked() {
  local manifest=$1 cleanup_new=${2:-yes} restore_result=0 cleanup_result=0
  firewall_doh_rebuild_old_slots_from_manifest "$manifest" || restore_result=$?
  [ "$restore_result" -eq 0 ] || return 76
  firewall_doh_restore_family ipv6 "$DOH_OLD6" "$DOH_NEW6" "${DOH_SWITCH_CREATED6:-0}" || restore_result=$?
  firewall_doh_restore_family ipv4 "$DOH_OLD4" "$DOH_NEW4" "${DOH_SWITCH_CREATED4:-0}" || restore_result=$?
  [ "$restore_result" -eq 0 ] || return 76
  [ "$cleanup_new" = yes ] || return 0
  firewall_doh_cleanup_new_slots_from_body "$manifest" || cleanup_result=$?
  [ "$cleanup_result" -eq 0 ] || return 76
}

firewall_doh_compensate_published_switch_failure_locked() {
  local manifest=$1 result=$2
  firewall_doh_manifest_load "$manifest" || return 76
  firewall_doh_compensate_switch_failure_locked "$manifest" yes || return 76
  rm -f "$manifest" || return 76
  return "$result"
}

firewall_doh_switch_locked() {
  local token=$1 manifest line result=0 predecessor=-
  DOH_SWITCH_CREATED4=0
  DOH_SWITCH_CREATED6=0
  firewall_doh_token_valid "$token" || return
  manifest=$(firewall_doh_manifest "$token")
  firewall_doh_manifest_load "$manifest" || return 76
  predecessor=$(firewall_doh_manifest_predecessor_token "$manifest") || return
  line=$(firewall_doh_manifest_new_slot_record "$manifest" ipv4) || return
  firewall_doh_chain_matches_record "$line" || return 76
  line=$(firewall_doh_manifest_new_slot_record "$manifest" ipv6) || return
  firewall_doh_chain_matches_record "$line" || return 76
  firewall_doh_switch_family ipv4 "$DOH_OLD4" "$DOH_NEW4" || result=$?
  if [ "$result" -ne 0 ]; then
    firewall_doh_compensate_switch_failure_locked "$manifest" yes || return 76
    return "$result"
  fi
  firewall_doh_switch_family ipv6 "$DOH_OLD6" "$DOH_NEW6" || result=$?
  if [ "$result" -ne 0 ]; then
    firewall_doh_compensate_switch_failure_locked "$manifest" yes || return 76
    return "$result"
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in doh-old-slot-v1*) firewall_doh_remove_slot_record_locked "$line" || { result=$?; break; } ;; esac
  done < "$manifest"
  if [ "$result" -ne 0 ]; then
    firewall_doh_compensate_switch_failure_locked "$manifest" yes || return 76
    return "$result"
  fi
  firewall_doh_mark_manifest_state "$manifest" active || {
    result=$?
    firewall_doh_compensate_switch_failure_locked "$manifest" yes || return 76
    rm -f "$manifest" || return 76
    return "$result"
  }
  line=$(firewall_doh_manifest_new_slot_record "$manifest" ipv4) || result=$?
  [ "$result" -ne 0 ] || firewall_doh_chain_matches_record "$line" || result=$?
  if [ "$result" -ne 0 ]; then
    firewall_doh_compensate_published_switch_failure_locked "$manifest" "$result"
    return
  fi
  line=$(firewall_doh_manifest_new_slot_record "$manifest" ipv6) || result=$?
  [ "$result" -ne 0 ] || firewall_doh_chain_matches_record "$line" || result=$?
  if [ "$result" -ne 0 ]; then
    firewall_doh_compensate_published_switch_failure_locked "$manifest" "$result"
    return
  fi
  firewall_doh_cleanup_stale_manifests_locked "$token" "$predecessor" || {
    result=$?
    firewall_doh_compensate_published_switch_failure_locked "$manifest" "$result"
    return
  }
}

firewall_doh_switch() {
  [ "$#" -eq 1 ] || return 64
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_doh_switch_locked "$1"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_doh_rollback_locked() {
  local token=$1 manifest line result=0 restore_result=0
  firewall_doh_token_valid "$token" || return
  manifest=$(firewall_doh_manifest "$token")
  firewall_doh_manifest_load "$manifest" || return 76
  firewall_doh_rebuild_old_slots_from_manifest "$manifest" || return
  firewall_doh_restore_family ipv4 "$DOH_OLD4" "$DOH_NEW4" || return
  firewall_doh_restore_family ipv6 "$DOH_OLD6" "$DOH_NEW6" || result=$?
  if [ "$result" -ne 0 ]; then
    firewall_doh_switch_family ipv4 "$DOH_OLD4" "$DOH_NEW4" || restore_result=$?
    [ "$restore_result" -eq 0 ] || return 76
    return 76
  fi
  "$BB" awk '{line[NR]=$0} END{for(i=NR;i>=1;i--) print line[i]}' "$manifest" | while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in doh-slot-v1*) firewall_doh_remove_slot_record_locked "$line" || exit $? ;; esac
  done || return $?
  rm -f "$manifest" || return 74
}

firewall_doh_rollback() {
  [ "$#" -eq 1 ] || return 64
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_doh_rollback_locked "$1"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_doh_remove_dispatcher() {
  local family=$1 dispatcher current chain
  dispatcher=$(firewall_doh_dispatcher_for "$family") || return
  firewall_doh_remove_output_jumps "$family" || return
  firewall_doh_chain_exists "$family" "$dispatcher" || return 0
  current=$(firewall_doh_dispatcher_current_slot "$family") || return
  if [ "$current" != - ]; then
    chain=$(firewall_doh_chain_for "$family" "$current") || return
    firewall_doh_xt "$family" -D "$dispatcher" -j "$chain" || return 76
  fi
  firewall_doh_chain_empty "$family" "$dispatcher" || return 76
  firewall_doh_xt "$family" -X "$dispatcher" || return 76
  case "$family" in
    ipv4) DOH_REMOVE_TOUCHED4=1 ;;
    ipv6) DOH_REMOVE_TOUCHED6=1 ;;
  esac
}

firewall_doh_restore_active_family() {
  local manifest=$1 family=$2 touched=$3 line dispatcher chain slot current count
  case "$touched" in 0|1) ;; *) return 64 ;; esac
  case "$family" in
    ipv4|ipv6) ;;
    *) return 64 ;;
  esac
  line=$(firewall_doh_manifest_new_slot_record "$manifest" "$family") || return
  firewall_doh_chain_matches_record "$line" || return 76
  dispatcher=$(firewall_doh_dispatcher_for "$family") || return
  slot=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $7}') || return
  chain=$(firewall_doh_chain_for "$family" "$slot") || return
  if ! firewall_doh_chain_exists "$family" "$dispatcher"; then
    [ "$touched" -eq 1 ] || return 76
    firewall_doh_xt "$family" -N "$dispatcher" || return 76
    current=-
  else
    current=$(firewall_doh_dispatcher_current_slot "$family") || return
  fi
  case "$current" in
    -)
      [ "$touched" -eq 1 ] || return 76
      count=$(firewall_doh_dispatcher_rule_count "$family" "$dispatcher") || return 76
      [ "$count" -eq 0 ] || return 76
      firewall_doh_xt "$family" -A "$dispatcher" -j "$chain" || return 76
      ;;
    "$slot") ;;
    *) return 76 ;;
  esac
  firewall_doh_ensure_output_jump "$family"
}

firewall_doh_dispatchers_absent() {
  local family dispatcher count
  for family in ipv4 ipv6; do
    count=$(firewall_doh_output_jump_count "$family") || return
    [ "$count" -eq 0 ] || return 76
    dispatcher=$(firewall_doh_dispatcher_for "$family") || return
    firewall_doh_chain_exists "$family" "$dispatcher" && return 76
  done
  return 0
}

firewall_doh_remove_owned_recovery_locked() {
  local manifest=$1 line family chain result=0
  firewall_doh_dispatchers_absent || return 76
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      doh-slot-v1*|doh-old-slot-v1*)
        family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
        chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
        if firewall_doh_chain_exists "$family" "$chain"; then
          firewall_doh_chain_subset_indices "$line" >/dev/null || { result=$?; break; }
        fi
        ;;
    esac
  done < "$manifest"
  [ "$result" -eq 0 ] || return "$result"
  "$BB" awk '{line[NR]=$0} END{for(i=NR;i>=1;i--) print line[i]}' "$manifest" | while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in doh-slot-v1*|doh-old-slot-v1*) firewall_doh_remove_slot_record_locked "$line" || exit $? ;; esac
  done || result=$?
  [ "$result" -eq 0 ] || return "$result"
}

firewall_doh_preflight_remove_family() {
  local manifest=$1 family=$2 expected_slot count current line
  count=$(firewall_doh_output_jump_count "$family") || return
  [ "$count" -eq 1 ] || return 76
  case "$family" in
    ipv4) expected_slot=$DOH_NEW4 ;;
    ipv6) expected_slot=$DOH_NEW6 ;;
    *) return 64 ;;
  esac
  current=$(firewall_doh_dispatcher_current_slot "$family") || return
  [ "$current" = "$expected_slot" ] || return 76
  count=$(firewall_doh_dispatcher_rule_count "$family") || return 76
  [ "$count" -eq 1 ] || return 76
  line=$(firewall_doh_manifest_new_slot_record "$manifest" "$family") || return
  firewall_doh_chain_matches_record "$line" || return 76
}

# Detach is allowed to be retried after a previous, successful detach.  The
# normal remove path intentionally requires a live OUTPUT jump, but detach is
# the first half of a two-step shutdown and must also accept an already-empty
# dispatcher (while still rejecting foreign or ambiguous rules).
firewall_doh_preflight_detach_family() {
  local manifest=$1 family=$2 expected_slot count current dispatcher line
  count=$(firewall_doh_output_jump_count "$family") || return
  [ "$count" -le 1 ] || return 76
  case "$family" in
    ipv4) expected_slot=$DOH_NEW4 ;;
    ipv6) expected_slot=$DOH_NEW6 ;;
    *) return 64 ;;
  esac
  dispatcher=$(firewall_doh_dispatcher_for "$family") || return
  if ! firewall_doh_chain_exists "$family" "$dispatcher"; then
    [ "$count" -eq 0 ] || return 76
    return 0
  fi
  current=$(firewall_doh_dispatcher_current_slot "$family") || return
  case "$current" in
    -)
      count=$(firewall_doh_dispatcher_rule_count "$family") || return 76
      [ "$count" -eq 0 ] || return 76
      firewall_doh_chain_empty "$family" "$dispatcher" || return 76
      ;;
    "$expected_slot")
      count=$(firewall_doh_dispatcher_rule_count "$family") || return 76
      [ "$count" -eq 1 ] || return 76
      line=$(firewall_doh_manifest_new_slot_record "$manifest" "$family") || return
      firewall_doh_chain_matches_record "$line" || return 76
      ;;
    *) return 76 ;;
  esac
}

firewall_doh_preflight_manifest_chains() {
  local manifest=$1 line family chain
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      doh-slot-v1*|doh-old-slot-v1*)
        family=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $2}')
        chain=$(printf '%s\n' "$line" | "$BB" awk -F '\t' '{print $5}')
        if firewall_doh_chain_exists "$family" "$chain"; then
          firewall_doh_chain_subset_indices "$line" >/dev/null || return 76
        fi
        ;;
    esac
  done < "$manifest"
}

firewall_doh_remove_owned_locked() {
  local token=$1 manifest line result=0
  DOH_REMOVE_TOUCHED4=0
  DOH_REMOVE_TOUCHED6=0
  firewall_doh_token_valid "$token" || return
  manifest=$(firewall_doh_manifest "$token")
  [ -e "$manifest" ] || { [ ! -L "$manifest" ] || return 76; return 0; }
  firewall_doh_manifest_load "$manifest" || return 76
  [ "$DOH_STATE" = active ] || return 76
  if firewall_doh_dispatchers_absent; then
    firewall_doh_remove_owned_recovery_locked "$manifest" || return
    rm -f "$manifest" || return 74
    return 0
  fi
  firewall_doh_preflight_remove_family "$manifest" ipv4 || return
  firewall_doh_preflight_remove_family "$manifest" ipv6 || return
  firewall_doh_preflight_manifest_chains "$manifest" || return
  DOH_REMOVE_TOUCHED4=1
  firewall_doh_remove_dispatcher ipv4 || {
    result=$?
    firewall_doh_restore_active_family "$manifest" ipv4 "$DOH_REMOVE_TOUCHED4" || return 76
    firewall_doh_restore_active_family "$manifest" ipv6 "$DOH_REMOVE_TOUCHED6" || return 76
    return "$result"
  }
  DOH_REMOVE_TOUCHED6=1
  firewall_doh_remove_dispatcher ipv6 || {
    result=$?
    firewall_doh_restore_active_family "$manifest" ipv6 "$DOH_REMOVE_TOUCHED6" || return 76
    firewall_doh_restore_active_family "$manifest" ipv4 "$DOH_REMOVE_TOUCHED4" || return 76
    return "$result"
  }
  "$BB" awk '{line[NR]=$0} END{for(i=NR;i>=1;i--) print line[i]}' "$manifest" | while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in doh-slot-v1*|doh-old-slot-v1*) firewall_doh_remove_slot_record_locked "$line" || exit $? ;; esac
  done || result=$?
  [ "$result" -eq 0 ] || return "$result"
  rm -f "$manifest" || return 74
}

firewall_doh_remove_owned() {
  [ "$#" -eq 1 ] || return 64
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_doh_remove_owned_locked "$1"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

# Detach only the module-owned OUTPUT -> dispatcher routing. Slot and
# dispatcher chains remain intact until the companion processes have stopped.
firewall_doh_detach_dispatcher_locked() {
  local manifest=$1 family=$2 dispatcher expected_slot current count chain
  dispatcher=$(firewall_doh_dispatcher_for "$family") || return
  count=$(firewall_doh_output_jump_count "$family") || return
  [ "$count" -le 1 ] || return 76
  if [ "$count" -eq 1 ]; then
    case "$family" in ipv4) DOH_DETACH_TOUCHED4=1 ;; ipv6) DOH_DETACH_TOUCHED6=1 ;; esac
    firewall_doh_remove_output_jumps "$family" || return
  fi
  firewall_doh_chain_exists "$family" "$dispatcher" || return 0
  case "$family" in ipv4) expected_slot=$DOH_NEW4 ;; ipv6) expected_slot=$DOH_NEW6 ;; *) return 64 ;; esac
  current=$(firewall_doh_dispatcher_current_slot "$family") || return
  if [ "$current" = - ]; then
    count=$(firewall_doh_dispatcher_rule_count "$family" "$dispatcher") || return 76
    [ "$count" -eq 0 ] || return 76
    firewall_doh_chain_empty "$family" "$dispatcher" || return 76
    return 0
  fi
  [ "$current" = "$expected_slot" ] || return 76
  chain=$(firewall_doh_chain_for "$family" "$current") || return
  case "$family" in ipv4) DOH_DETACH_TOUCHED4=1 ;; ipv6) DOH_DETACH_TOUCHED6=1 ;; esac
  firewall_doh_xt "$family" -D "$dispatcher" -j "$chain" || return 76
  count=$(firewall_doh_dispatcher_rule_count "$family" "$dispatcher") || return 76
  [ "$count" -eq 0 ] || return 76
  firewall_doh_chain_empty "$family" "$dispatcher" || return 76
}

firewall_doh_detach_owned_locked() {
  local token=$1 manifest result=0
  DOH_DETACH_TOUCHED4=0
  DOH_DETACH_TOUCHED6=0
  firewall_doh_token_valid "$token" || return
  manifest=$(firewall_doh_manifest "$token")
  [ -e "$manifest" ] || { [ ! -L "$manifest" ] || return 76; return 0; }
  firewall_doh_manifest_load "$manifest" || return 76
  [ "$DOH_STATE" = active ] || return 76
  firewall_doh_preflight_detach_family "$manifest" ipv4 || return
  firewall_doh_preflight_detach_family "$manifest" ipv6 || return
  firewall_doh_preflight_manifest_chains "$manifest" || return
  firewall_doh_detach_dispatcher_locked "$manifest" ipv4 || {
    result=$?
    if [ "$DOH_DETACH_TOUCHED4" -eq 1 ]; then
      firewall_doh_restore_active_family "$manifest" ipv4 "$DOH_DETACH_TOUCHED4" || return 76
    fi
    return "$result"
  }
  firewall_doh_detach_dispatcher_locked "$manifest" ipv6 || {
    result=$?
    if [ "$DOH_DETACH_TOUCHED6" -eq 1 ]; then
      firewall_doh_restore_active_family "$manifest" ipv6 "$DOH_DETACH_TOUCHED6" || return 76
    fi
    if [ "$DOH_DETACH_TOUCHED4" -eq 1 ]; then
      firewall_doh_restore_active_family "$manifest" ipv4 "$DOH_DETACH_TOUCHED4" || return 76
    fi
    return "$result"
  }
  [ "$(firewall_doh_output_jump_count ipv4)" -eq 0 ] && [ "$(firewall_doh_output_jump_count ipv6)" -eq 0 ] || return 76
}

firewall_doh_detach_owned() {
  [ "$#" -eq 1 ] || return 64
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_doh_detach_owned_locked "$1"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_doh_cleanup_owned_locked() {
  local token=$1 manifest line family dispatcher count result=0
  firewall_doh_token_valid "$token" || return
  manifest=$(firewall_doh_manifest "$token")
  [ -e "$manifest" ] || { [ ! -L "$manifest" ] || return 76; return 0; }
  firewall_doh_manifest_load "$manifest" || return 76
  [ "$DOH_STATE" = active ] || return 76
  for family in ipv4 ipv6; do
    count=$(firewall_doh_output_jump_count "$family") || return
    [ "$count" -eq 0 ] || return 76
    dispatcher=$(firewall_doh_dispatcher_for "$family") || return
    if firewall_doh_chain_exists "$family" "$dispatcher"; then
      count=$(firewall_doh_dispatcher_rule_count "$family" "$dispatcher") || return 76
      [ "$count" -eq 0 ] || return 76
      firewall_doh_chain_empty "$family" "$dispatcher" || return 76
    fi
  done
  firewall_doh_preflight_manifest_chains "$manifest" || return 76
  "$BB" awk '{line[NR]=$0} END{for(i=NR;i>=1;i--) print line[i]}' "$manifest" | while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in doh-slot-v1*|doh-old-slot-v1*) firewall_doh_remove_slot_record_locked "$line" || exit $? ;; esac
  done || result=$?
  [ "$result" -eq 0 ] || return "$result"
  for family in ipv4 ipv6; do
    dispatcher=$(firewall_doh_dispatcher_for "$family") || return
    firewall_doh_chain_exists "$family" "$dispatcher" || continue
    firewall_doh_xt "$family" -X "$dispatcher" || return 76
  done
  rm -f "$manifest" || return 74
}

firewall_doh_cleanup_owned() {
  [ "$#" -eq 1 ] || return 64
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_doh_cleanup_owned_locked "$1"
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_doh_known_chains_absent() {
  local family slot chain
  for family in ipv4 ipv6; do
    chain=$(firewall_doh_dispatcher_for "$family") || return
    firewall_doh_chain_exists "$family" "$chain" && return 76
    for slot in A B; do
      chain=$(firewall_doh_chain_for "$family" "$slot") || return
      firewall_doh_chain_exists "$family" "$chain" && return 76
    done
  done
  return 0
}

firewall_doh_cleanup_recovery_locked() {
  local dir file expected tokens manifest_count=0 active_count=0 active_token= result=0
  local slot4 slot6 count4 count6 rule4 rule6 token
  dir=$(firewall_doh_dir)
  slot4=$(firewall_doh_dispatcher_current_slot ipv4) || return 76
  slot6=$(firewall_doh_dispatcher_current_slot ipv6) || return 76
  count4=$(firewall_doh_output_jump_count ipv4) || return 76
  count6=$(firewall_doh_output_jump_count ipv6) || return 76
  [ "$count4" -le 1 ] && [ "$count6" -le 1 ] || return 76

  tokens="$RULE_TMP/doh-recovery-tokens.$$"
  : > "$tokens" || return 73
  if [ -d "$dir" ]; then
    for file in "$dir"/firewall-*.tsv; do
      [ -e "$file" ] || [ -L "$file" ] || continue
      if [ ! -f "$file" ] || [ -L "$file" ] || ! firewall_doh_manifest_load "$file" || [ "$DOH_STATE" != active ]; then
        rm -f "$tokens"
        return 76
      fi
      expected=$(firewall_doh_manifest "$DOH_TOKEN") || { rm -f "$tokens"; return 76; }
      [ "$file" = "$expected" ] || { rm -f "$tokens"; return 76; }
      firewall_doh_preflight_manifest_chains "$file" || { rm -f "$tokens"; return 76; }
      printf '%s\n' "$DOH_TOKEN" >> "$tokens" || { rm -f "$tokens"; return 73; }
      manifest_count=$((manifest_count + 1))
      if [ "$count4" -eq 1 ] && [ "$count6" -eq 1 ] && [ "$DOH_NEW4" = "$slot4" ] && [ "$DOH_NEW6" = "$slot6" ]; then
        rule4=$(firewall_doh_manifest_new_slot_record "$file" ipv4) || { rm -f "$tokens"; return 76; }
        rule6=$(firewall_doh_manifest_new_slot_record "$file" ipv6) || { rm -f "$tokens"; return 76; }
        if firewall_doh_chain_matches_record "$rule4" && firewall_doh_chain_matches_record "$rule6"; then
          active_count=$((active_count + 1))
          active_token=$DOH_TOKEN
        fi
      fi
    done
  fi

  if [ "$manifest_count" -eq 0 ]; then
    rm -f "$tokens"
    [ "$count4" -eq 0 ] && [ "$count6" -eq 0 ] && [ "$slot4" = - ] && [ "$slot6" = - ] || return 76
    firewall_doh_known_chains_absent
    return $?
  fi

  if [ "$count4" -eq 1 ] && [ "$count6" -eq 1 ] && [ "$slot4" = "$slot6" ] && [ "$slot4" != - ]; then
    [ "$active_count" -eq 1 ] || { rm -f "$tokens"; return 76; }
    firewall_doh_detach_owned_locked "$active_token" || { result=$?; rm -f "$tokens"; return "$result"; }
  elif [ "$count4" -eq 0 ] && [ "$count6" -eq 0 ] && [ "$slot4" = - ] && [ "$slot6" = - ]; then
    :
  else
    rm -f "$tokens"
    return 76
  fi

  while IFS= read -r token || [ -n "$token" ]; do
    firewall_doh_cleanup_owned_locked "$token" || { result=$?; break; }
  done < "$tokens"
  rm -f "$tokens"
  [ "$result" -eq 0 ] || return "$result"
  firewall_doh_known_chains_absent
}

firewall_doh_cleanup_recovery() {
  [ "$#" -eq 0 ] || return 64
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_doh_cleanup_recovery_locked
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_doh_status_json_locked() {
  local dir file state=absent token= mode= coverage=null found=0 slot4 slot6 count4 count6 line
  dir=$(firewall_doh_dir)
  [ -d "$dir" ] || { printf '{"ok":true,"data":{"state":"absent"}}\n'; return 0; }
  slot4=$(firewall_doh_dispatcher_current_slot ipv4 2>/dev/null || printf 'incomplete')
  slot6=$(firewall_doh_dispatcher_current_slot ipv6 2>/dev/null || printf 'incomplete')
  count4=$(firewall_doh_output_jump_count ipv4 2>/dev/null || printf '0')
  count6=$(firewall_doh_output_jump_count ipv6 2>/dev/null || printf '0')
  if [ "$slot4" = incomplete ] || [ "$slot6" = incomplete ] || [ "$count4" -gt 1 ] || [ "$count6" -gt 1 ]; then
    printf '{"ok":true,"data":{"state":"incomplete"}}\n'
    return 0
  fi
  if [ "$slot4" = - ] && [ "$slot6" = - ] && [ "$count4" -eq 0 ] && [ "$count6" -eq 0 ]; then
    printf '{"ok":true,"data":{"state":"absent"}}\n'
    return 0
  fi
  [ "$slot4" = "$slot6" ] && [ "$count4" -eq 1 ] && [ "$count6" -eq 1 ] || {
    printf '{"ok":true,"data":{"state":"incomplete"}}\n'
    return 0
  }
  for file in "$dir"/firewall-*.tsv; do
    [ -e "$file" ] || continue
    firewall_doh_manifest_load "$file" || continue
    [ "$DOH_STATE" = active ] || continue
    [ "$DOH_NEW4" = "$slot4" ] && [ "$DOH_NEW6" = "$slot6" ] || continue
    line=$(firewall_doh_manifest_new_slot_record "$file" ipv4) || continue
    firewall_doh_chain_matches_record "$line" || continue
    line=$(firewall_doh_manifest_new_slot_record "$file" ipv6) || continue
    firewall_doh_chain_matches_record "$line" || continue
    token=$DOH_TOKEN
    mode=$DOH_MODE
    found=1
    break
  done
  [ "$found" -eq 1 ] || { printf '{"ok":true,"data":{"state":"incomplete"}}\n'; return 0; }
  [ "$mode" = selected ] && coverage=direct_dns_only || coverage=all_dns
  printf '{"ok":true,"data":{"state":"active","mode":"%s","slot":"%s","token":"%s","coverage":"%s"}}\n' \
    "$mode" "$slot4" "$token" "$coverage"
}

firewall_doh_status_json() {
  rules_init_paths "$MODDIR" || return
  rules_lock_acquire firewall || return
  firewall_doh_status_json_locked
  local result=$?
  rules_lock_release firewall || return
  return "$result"
}

firewall_dispatch() {
  case "${1-}:$#" in
    reconcile:1) firewall_reconcile ;;
    cleanup:1) firewall_cleanup ;;
    status:2) [ "$2" = --json ] || return 64; firewall_status ;;
    set-feature:3) firewall_set_feature "$2" "$3" ;;
    history-probe:1) firewall_history_probe ;;
    history-install:2) firewall_history_install "$2" ;;
    history-disable:1) firewall_history_disable ;;
    history-uninstall:1) firewall_history_uninstall ;;
    history-status:2) [ "$2" = --json ] || return 64; firewall_history_status ;;
    app-policy-capability:2) [ "$2" = --json ] || return 64; firewall_app_policy_capability ;;
    app-policy-apply:4) firewall_app_policy_apply "$2" "$3" "$4" ;;
    app-policy-apply:5) firewall_app_policy_apply "$2" "$3" "$4" "$5" ;;
    app-policy-confirm:2) firewall_app_policy_confirm "$2" ;;
    app-policy-rollback:2) firewall_app_policy_rollback "$2" ;;
    app-policy-recover:2) firewall_app_policy_recover "$2" ;;
    app-policy-active:2) firewall_app_policy_active "$2" ;;
    app-policy-cleanup:1) firewall_app_policy_cleanup ;;
    doh-capability:2) [ "$2" = --json ] || return 64; firewall_doh_capability_json ;;
    doh-status:2) [ "$2" = --json ] || return 64; firewall_doh_status_json ;;
    doh-stage:6) firewall_doh_stage "$2" "$3" "$4" "$5" "$6" ;;
    doh-switch:2) firewall_doh_switch "$2" ;;
    doh-rollback:2) firewall_doh_rollback "$2" ;;
    doh-remove-owned:2) firewall_doh_remove_owned "$2" ;;
    doh-detach-owned:2) firewall_doh_detach_owned "$2" ;;
    doh-cleanup-owned:2) firewall_doh_cleanup_owned "$2" ;;
    doh-cleanup-recovery:1) firewall_doh_cleanup_recovery ;;
    *) return 64 ;;
  esac
}

if [ "${FIREWALL_SOURCE_ONLY-0}" != 1 ]; then
  firewall_dispatch "$@"
fi
