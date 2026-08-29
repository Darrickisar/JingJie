#!/system/bin/sh

APP_POLICY_MAX_UIDS=256
APP_POLICY_MAX_IPS=2048
APP_POLICY_MAX_ANDROID_UID=4294967294
APP_POLICY_MIN_APP_ID=10000
APP_POLICY_MAX_APP_ID=19999

app_policy_state_file() { printf '%s\n' "$CONFIG_DIR/app-policy.prop"; }
app_policy_uid_file() { printf '%s\n' "$CONFIG_DIR/app-policy-uids.tsv"; }
app_policy_ip_file() { printf '%s\n' "$CONFIG_DIR/app-policy-ips.tsv"; }
app_policy_pointer_file() { printf '%s\n' "$CONFIG_DIR/app-policy-current.prop"; }
app_policy_revisions_dir() { printf '%s\n' "$CONFIG_DIR/app-policy-revisions"; }
app_policy_revision_dir() { printf '%s\n' "$(app_policy_revisions_dir)/$1"; }
app_policy_revision_state_file() { printf '%s\n' "$(app_policy_revision_dir "$1")/state.prop"; }
app_policy_revision_uid_file() { printf '%s\n' "$(app_policy_revision_dir "$1")/uids.tsv"; }
app_policy_revision_ip_file() { printf '%s\n' "$(app_policy_revision_dir "$1")/ips.tsv"; }

app_policy_revision_valid() {
  case "$1" in ''|0|*[!0-9]*) return 1 ;; esac
}

app_policy_pointer_validate() {
  local file=${1:-$(app_policy_pointer_file)}
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2{bad()}
    $1!~/^(schema_version|revision)$/{bad()}
    seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    $1=="revision" && $2!~/^[1-9][0-9]*$/{bad()}
    END{if(NR!=2 || !seen["schema_version"] || !seen["revision"])bad()}
  ' "$file" || return 65
  APP_POLICY_CURRENT_REVISION=$("$BB" awk -F= '$1=="revision"{print $2}' "$file") || return 65
  export APP_POLICY_CURRENT_REVISION
}

app_policy_snapshot_manifest_write() {
  local dir=$1 tmp="$1/manifest.prop.tmp.$$" state_hash uid_hash ip_hash
  state_hash=$(sha256_file "$dir/state.prop") || return
  uid_hash=$(sha256_file "$dir/uids.tsv") || return
  ip_hash=$(sha256_file "$dir/ips.tsv") || return
  printf 'schema_version=2\nstate_sha256=%s\nuids_sha256=%s\nips_sha256=%s\n' \
    "$state_hash" "$uid_hash" "$ip_hash" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$dir/manifest.prop"
}

app_policy_snapshot_manifest_validate() {
  local file=$1 state_hash uid_hash ip_hash
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2{bad()}
    $1!~/^(schema_version|state_sha256|uids_sha256|ips_sha256)$/{bad()}
    seen[$1]++{bad()}
    $1=="schema_version" && $2!="2"{bad()}
    $1~/sha256$/ && $2!~/^[0-9a-f]{64}$/{bad()}
    END{if(NR!=4 || !seen["schema_version"] || !seen["state_sha256"] || !seen["uids_sha256"] || !seen["ips_sha256"])bad()}
  ' "$file" || return 65
  state_hash=$("$BB" awk -F= '$1=="state_sha256"{print $2}' "$file")
  uid_hash=$("$BB" awk -F= '$1=="uids_sha256"{print $2}' "$file")
  ip_hash=$("$BB" awk -F= '$1=="ips_sha256"{print $2}' "$file")
  [ "$state_hash" = "$(sha256_file "${file%/*}/state.prop")" ] || return 70
  [ "$uid_hash" = "$(sha256_file "${file%/*}/uids.tsv")" ] || return 70
  [ "$ip_hash" = "$(sha256_file "${file%/*}/ips.tsv")" ] || return 70
}

app_policy_payload_validate() {
  local state=$1 uids=$2 ips=$3 enabled mode
  app_policy_validate_state_file "$state" || return
  [ -f "$uids" ] && [ ! -L "$uids" ] || return 66
  [ -f "$ips" ] && [ ! -L "$ips" ] || return 66
  enabled=$("$BB" awk -F= '$1=="enabled"{print $2}' "$state")
  mode=$("$BB" awk -F= '$1=="mode"{print $2}' "$state")
  if [ "$enabled" = 1 ]; then
    app_policy_validate_uid_file "$uids" || return
  else
    [ ! -s "$uids" ] || return 65
  fi
  [ "$mode" != allow_resolved ] || { app_policy_validate_ip_file "$ips" || return; [ -s "$ips" ] || return 65; }
}

app_policy_snapshot_dir_validate() {
  local dir=$1
  [ -d "$dir" ] && [ ! -L "$dir" ] || return 66
  app_policy_payload_validate "$dir/state.prop" "$dir/uids.tsv" "$dir/ips.tsv" || return
  app_policy_snapshot_manifest_validate "$dir/manifest.prop"
}

app_policy_snapshot_validate() {
  local revision=$1
  app_policy_revision_valid "$revision" || return 65
  app_policy_snapshot_dir_validate "$(app_policy_revision_dir "$revision")"
}

app_policy_snapshot_publish() {
  local tmp=$1 final=$2
  [ -d "$tmp" ] && [ ! -L "$tmp" ] || return 66
  [ ! -e "$final" ] && [ ! -L "$final" ] || return 76
  mv "$tmp" "$final" || return 74
}

app_policy_pointer_publish() {
  atomic_replace_file "$1" "$2"
}

app_policy_snapshot_create() {
  local revision=$1 state_src=$2 uid_src=$3 ip_src=$4 tmp result
  tmp="$(app_policy_revision_dir "$revision").tmp.$$"
  [ ! -e "$tmp" ] || rm -rf "$tmp"
  mkdir -p "$tmp" || return 73
  cp "$state_src" "$tmp/state.prop" || { rm -rf "$tmp"; return 74; }
  cp "$uid_src" "$tmp/uids.tsv" || { rm -rf "$tmp"; return 74; }
  cp "$ip_src" "$tmp/ips.tsv" || { rm -rf "$tmp"; return 74; }
  app_policy_snapshot_manifest_write "$tmp" || {
    result=$?
    rm -rf "$tmp"
    return "$result"
  }
  app_policy_snapshot_dir_validate "$tmp" || {
    local result=$?
    rm -rf "$tmp"
    return "$result"
  }
  app_policy_snapshot_publish "$tmp" "$(app_policy_revision_dir "$revision")" || {
    local result=$?
    rm -rf "$tmp"
    return "$result"
  }
}

app_policy_next_revision() {
  local current=${1:-0} next
  case "$current" in ''|*[!0-9]*) return 65 ;; esac
  next=$((current + 1))
  while [ -e "$(app_policy_revision_dir "$next")" ] || [ -L "$(app_policy_revision_dir "$next")" ]; do
    next=$((next + 1))
  done
  printf '%s\n' "$next"
}

app_policy_revision_token() {
  local revision=$1
  app_policy_revision_valid "$revision" || return 65
  printf 'app-policy:%s' "$revision" | sha256_file_stdin | "$BB" cut -c1-16
}

app_policy_snapshot_load_current() {
  app_policy_pointer_validate || return
  app_policy_snapshot_validate "$APP_POLICY_CURRENT_REVISION" || return
  APP_POLICY_CURRENT_STATE=$(app_policy_revision_state_file "$APP_POLICY_CURRENT_REVISION")
  APP_POLICY_CURRENT_UIDS=$(app_policy_revision_uid_file "$APP_POLICY_CURRENT_REVISION")
  APP_POLICY_CURRENT_IPS=$(app_policy_revision_ip_file "$APP_POLICY_CURRENT_REVISION")
  export APP_POLICY_CURRENT_STATE APP_POLICY_CURRENT_UIDS APP_POLICY_CURRENT_IPS
}

app_policy_project_snapshot() {
  local revision=$1 state_tmp="$RULE_TMP/app-policy-project-state.$$" uid_tmp="$RULE_TMP/app-policy-project-uids.$$" ip_tmp="$RULE_TMP/app-policy-project-ips.$$" result=0
  cp "$(app_policy_revision_state_file "$revision")" "$state_tmp" || return 74
  cp "$(app_policy_revision_uid_file "$revision")" "$uid_tmp" || { rm -f "$state_tmp"; return 74; }
  cp "$(app_policy_revision_ip_file "$revision")" "$ip_tmp" || { rm -f "$state_tmp" "$uid_tmp"; return 74; }
  if [ "$result" -eq 0 ]; then atomic_replace_file "$uid_tmp" "$(app_policy_uid_file)" || result=$?; fi
  if [ "$result" -eq 0 ]; then atomic_replace_file "$ip_tmp" "$(app_policy_ip_file)" || result=$?; fi
  if [ "$result" -eq 0 ]; then atomic_replace_file "$state_tmp" "$(app_policy_state_file)" || result=$?; fi
  rm -f "$state_tmp" "$uid_tmp" "$ip_tmp"
  return "$result"
}

app_policy_validate_uid_file() {
  local file=$1 count=0 uid canonical app_id previous=
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  while IFS= read -r uid || [ -n "$uid" ]; do
    [ -n "$uid" ] || return 65
    decimal_uint_in_range "$uid" "$APP_POLICY_MAX_ANDROID_UID" "$APP_POLICY_MIN_APP_ID" || return 65
    canonical=$uid
    while [ "${#canonical}" -gt 1 ] && [ "${canonical#0}" != "$canonical" ]; do canonical=${canonical#0}; done
    [ "$canonical" = "$uid" ] || return 65
    app_id=$((uid % 100000))
    [ "$app_id" -ge "$APP_POLICY_MIN_APP_ID" ] && [ "$app_id" -le "$APP_POLICY_MAX_APP_ID" ] || return 65
    [ "$uid" != "$previous" ] || return 65
    previous=$uid
    count=$((count + 1))
    [ "$count" -le "$APP_POLICY_MAX_UIDS" ] || return 65
  done < "$file"
  [ "$count" -gt 0 ] || return 65
  LC_ALL=C "$BB" sort -n "$file" | "$BB" cmp -s - "$file" || return 65
}

app_policy_validate_ip_file() {
  local file=$1 count=0 ip previous=
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  while IFS= read -r ip || [ -n "$ip" ]; do
    [ -n "$ip" ] || continue
    overrides_ip_family "$ip" >/dev/null || return 65
    [ "$ip" != "$previous" ] || return 65
    previous=$ip
    count=$((count + 1))
    [ "$count" -le "$APP_POLICY_MAX_IPS" ] || return 65
  done < "$file"
  LC_ALL=C "$BB" sort "$file" | "$BB" cmp -s - "$file" || return 65
}

app_policy_decode_lines() {
  [ "$#" -eq 3 ] || return 64
  local encoded=$1 output=$2 type=$3 raw="$RULE_TMP/app-policy-raw.$$"
  [ -n "$encoded" ] || { : > "$output"; return 0; }
  config_b64_valid "$encoded" || return 65
  printf '%s' "$encoded" | "$BB" base64 -d > "$raw" 2>/dev/null || return 65
  case "$type" in
    uid)
      local count=0 uid canonical app_id sorted
      : > "$output" || { rm -f "$raw"; return 74; }
      while IFS= read -r uid || [ -n "$uid" ]; do
        [ -n "$uid" ] || { rm -f "$raw" "$output"; return 65; }
        decimal_uint_in_range "$uid" "$APP_POLICY_MAX_ANDROID_UID" "$APP_POLICY_MIN_APP_ID" || {
          rm -f "$raw" "$output"
          return 65
        }
        canonical=$uid
        while [ "${#canonical}" -gt 1 ] && [ "${canonical#0}" != "$canonical" ]; do canonical=${canonical#0}; done
        app_id=$((canonical % 100000))
        [ "$app_id" -ge "$APP_POLICY_MIN_APP_ID" ] && [ "$app_id" -le "$APP_POLICY_MAX_APP_ID" ] || {
          rm -f "$raw" "$output"
          return 65
        }
        count=$((count + 1))
        [ "$count" -le "$APP_POLICY_MAX_UIDS" ] || { rm -f "$raw" "$output"; return 65; }
        printf '%s\n' "$canonical" >> "$output" || { rm -f "$raw" "$output"; return 74; }
      done < "$raw" || { rm -f "$raw" "$output"; return 65; }
      sorted="$output.sorted.$$"
      LC_ALL=C "$BB" sort -n -u "$output" > "$sorted" || { rm -f "$raw" "$output" "$sorted"; return 65; }
      mv -f "$sorted" "$output" || { rm -f "$raw" "$output" "$sorted"; return 74; }
      ;;
    ip) "$BB" awk 'NF==1{print tolower($1)} NF!=1{exit 65}' "$raw" | LC_ALL=C "$BB" sort -u > "$output" ;;
    *) rm -f "$raw"; return 64 ;;
  esac || { rm -f "$raw" "$output"; return 65; }
  rm -f "$raw"
}

app_policy_validate_uid_ownership() {
  local uid_file=$1 packages=${APP_POLICY_PACKAGES_LIST:-/data/system/packages.list}
  [ -f "$packages" ] && [ ! -L "$packages" ] || return 66
  "$BB" awk '
    BEGIN { status=0 }
    FNR==NR {
      if ($0 !~ /^[0-9]+$/ || $0 ~ /^0[0-9]/) { status=65; next }
      uid=$0+0
      if (uid < 10000 || uid > 4294967294) { status=65; next }
      selected_appid[uid % 100000]=1
      next
    }
    {
      if (NF < 2 || $1 !~ /^[A-Za-z0-9_.-]+$/ || $2 !~ /^[0-9]+$/ || $2 ~ /^0[0-9]/) { status=65; next }
      uid=$2+0
      if (uid < 0 || uid > 4294967294) { status=65; next }
      appid=uid % 100000
      mapped_appid[appid]=1
      if ($1 ~ /^(me\.weishu\.kernelsu|com\.rifsxd\.ksunext|me\.bmax\.apatch)$/) manager_appid[appid]=1
    }
    END {
      if (status != 0) exit status
      for (appid in selected_appid) if (!(appid in mapped_appid)) exit 67
      for (appid in selected_appid) if (appid in manager_appid) exit 65
      exit 0
    }
  ' "$uid_file" "$packages"
}

app_policy_validate_state_file() {
  local file=$1
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2{bad()}
    $1!~/^(schema_version|enabled|mode|updated_at)$/{bad()}
    seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    $1=="enabled" && $2!~/^[01]$/{bad()}
    $1=="mode" && $2!~/^(off|block_selected|allow_resolved)$/{bad()}
    $1=="updated_at" && $2!~/^[0-9]+$/{bad()}
    END{if(NR!=4 || !seen["schema_version"] || !seen["enabled"] || !seen["mode"] || !seen["updated_at"])bad()}
  ' "$file"
}

app_policy_bootstrap_locked() {
  local state uids ips pointer tmp tmp_state tmp_uid tmp_ip next result
  rules_lock_is_held app-policy || return 75
  mkdir -p "$CONFIG_DIR" "$(app_policy_revisions_dir)" || return 73
  state=$(app_policy_state_file); uids=$(app_policy_uid_file); ips=$(app_policy_ip_file); pointer=$(app_policy_pointer_file)
  if [ -f "$pointer" ] || [ -L "$pointer" ]; then
    app_policy_snapshot_load_current || return
    return 0
  fi
  [ ! -L "$pointer" ] || return 65
  if [ -f "$state" ] || [ -L "$state" ] || [ -f "$uids" ] || [ -L "$uids" ] || [ -f "$ips" ] || [ -L "$ips" ]; then
    [ -f "$state" ] && [ ! -L "$state" ] || return 65
    [ -f "$uids" ] && [ ! -L "$uids" ] || return 65
    [ -f "$ips" ] && [ ! -L "$ips" ] || return 65
    tmp_state="$RULE_TMP/app-policy-bootstrap-state.$$"; tmp_uid="$RULE_TMP/app-policy-bootstrap-uids.$$"; tmp_ip="$RULE_TMP/app-policy-bootstrap-ips.$$"
    cp "$state" "$tmp_state" && cp "$uids" "$tmp_uid" && cp "$ips" "$tmp_ip" || { rm -f "$tmp_state" "$tmp_uid" "$tmp_ip"; return 74; }
  else
    tmp_state="$RULE_TMP/app-policy-bootstrap-state.$$"; tmp_uid="$RULE_TMP/app-policy-bootstrap-uids.$$"; tmp_ip="$RULE_TMP/app-policy-bootstrap-ips.$$"
    printf 'schema_version=1\nenabled=0\nmode=off\nupdated_at=0\n' > "$tmp_state" || return 74
    : > "$tmp_uid" || { rm -f "$tmp_state"; return 74; }
    : > "$tmp_ip" || { rm -f "$tmp_state" "$tmp_uid"; return 74; }
  fi
  app_policy_payload_validate "$tmp_state" "$tmp_uid" "$tmp_ip" || {
    result=$?
    rm -f "$tmp_state" "$tmp_uid" "$tmp_ip"
    return "$result"
  }
  next=$(app_policy_next_revision 0) || {
    result=$?
    rm -f "$tmp_state" "$tmp_uid" "$tmp_ip"
    return "$result"
  }
  app_policy_snapshot_create "$next" "$tmp_state" "$tmp_uid" "$tmp_ip" || {
    result=$?
    rm -f "$tmp_state" "$tmp_uid" "$tmp_ip"
    return "$result"
  }
  rm -f "$tmp_state" "$tmp_uid" "$tmp_ip"
  tmp="$pointer.tmp.$$"
  printf 'schema_version=1\nrevision=%s\n' "$next" > "$tmp" || return 74
  app_policy_pointer_publish "$tmp" "$pointer" || {
    result=$?
    rm -f "$tmp"
    return "$result"
  }
  app_policy_snapshot_load_current || return
  app_policy_project_snapshot "$next" || return
}

app_policy_bootstrap() {
  local result release_result=0
  if rules_lock_is_held app-policy; then
    app_policy_bootstrap_locked
    return
  fi
  rules_lock_acquire app-policy || return
  app_policy_bootstrap_locked
  result=$?
  rules_lock_release app-policy || release_result=$?
  [ "$result" -ne 0 ] && return "$result"
  return "$release_result"
}

app_policy_capability_json() {
  local data result
  set +e
  data=$("$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-capability --json 2>/dev/null)
  result=$?
  set -e
  if [ "$result" -eq 0 ] && [ -n "$data" ]; then
    printf '%s\n' "$data"
  else
    printf '{"supported":false,"reason":"owner_match_unavailable","families":[]}\n'
  fi
}

app_policy_read_json() {
  local state uids ips enabled mode updated first=true value pointer
  pointer=$(app_policy_pointer_file)
  if [ -f "$pointer" ] || [ -L "$pointer" ]; then
    app_policy_snapshot_load_current || return
    state=$APP_POLICY_CURRENT_STATE; uids=$APP_POLICY_CURRENT_UIDS; ips=$APP_POLICY_CURRENT_IPS
  else
    state=$(app_policy_state_file); uids=$(app_policy_uid_file); ips=$(app_policy_ip_file)
    app_policy_payload_validate "$state" "$uids" "$ips" || return
  fi
  enabled=$("$BB" awk -F= '$1=="enabled"{print $2}' "$state") || return
  mode=$("$BB" awk -F= '$1=="mode"{print $2}' "$state") || return
  updated=$("$BB" awk -F= '$1=="updated_at"{print $2}' "$state") || return
  printf '{"enabled":%s,"mode":"%s","updatedAt":%s,"uids":[' "$([ "$enabled" = 1 ] && printf true || printf false)" "$mode" "$updated"
  while IFS= read -r value || [ -n "$value" ]; do
    [ -n "$value" ] || continue
    [ "$first" = true ] || printf ','
    first=false
    printf '%s' "$value"
  done < "$uids"
  printf '],"allowIps":['
  first=true
  while IFS= read -r value || [ -n "$value" ]; do
    [ -n "$value" ] || continue
    [ "$first" = true ] || printf ','
    first=false
    printf '"%s"' "$(printf '%s' "$value" | json_escape)"
  done < "$ips"
  printf ']}\n'
}

app_policy_reconcile_validation_failure() {
  local validation_status=$1 cleanup_status
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-cleanup >/dev/null 2>&1
  cleanup_status=$?
  [ "$cleanup_status" -eq 0 ] && return "$validation_status"
  return "$cleanup_status"
}

app_policy_apply() {
  [ "$#" -eq 3 ] || return 64
  local mode=$1 uid_b64=$2 ip_b64=$3 state_tmp uid_tmp ip_tmp enabled now result rollback_result=0 current next token pointer pointer_tmp staged=0 firewall_mode
  case "$mode" in off|block_selected|allow_resolved) ;; *) return 65 ;; esac
  rules_lock_acquire app-policy || return
  app_policy_bootstrap_locked || { result=$?; rules_lock_release app-policy; return "$result"; }
  app_policy_snapshot_load_current || { result=$?; rules_lock_release app-policy; return "$result"; }
  current=$APP_POLICY_CURRENT_REVISION
  uid_tmp="$RULE_TMP/app-policy-uids.$$"; ip_tmp="$RULE_TMP/app-policy-ips.$$"
  app_policy_decode_lines "$uid_b64" "$uid_tmp" uid || { result=$?; rules_lock_release app-policy; return "$result"; }
  app_policy_decode_lines "$ip_b64" "$ip_tmp" ip || {
    result=$?
    rm -f "$uid_tmp"
    rules_lock_release app-policy
    return "$result"
  }
  if [ "$mode" != off ]; then
    app_policy_validate_uid_file "$uid_tmp" || { rm -f "$uid_tmp" "$ip_tmp"; rules_lock_release app-policy; return 65; }
    app_policy_validate_uid_ownership "$uid_tmp" || { rm -f "$uid_tmp" "$ip_tmp"; rules_lock_release app-policy; return 65; }
  fi
  if [ "$mode" = allow_resolved ]; then
    app_policy_validate_ip_file "$ip_tmp" || { rm -f "$uid_tmp" "$ip_tmp"; rules_lock_release app-policy; return 65; }
    [ -s "$ip_tmp" ] || { rm -f "$uid_tmp" "$ip_tmp"; rules_lock_release app-policy; return 65; }
  fi
  [ "$mode" = off ] && enabled=0 || enabled=1
  now=$(date +%s 2>/dev/null || printf 0)
  state_tmp="$RULE_TMP/app-policy-state.$$"
  printf 'schema_version=1\nenabled=%s\nmode=%s\nupdated_at=%s\n' "$enabled" "$mode" "$now" > "$state_tmp" || {
    rm -f "$uid_tmp" "$ip_tmp"
    rules_lock_release app-policy
    return 74
  }
  next=$(app_policy_next_revision "$current") || {
    result=$?
    rm -f "$uid_tmp" "$ip_tmp" "$state_tmp"
    rules_lock_release app-policy
    return "$result"
  }
  app_policy_snapshot_create "$next" "$state_tmp" "$uid_tmp" "$ip_tmp" || {
    result=$?
    rm -f "$state_tmp" "$uid_tmp" "$ip_tmp"
    rules_lock_release app-policy
    return "$result"
  }
  token=$(app_policy_revision_token "$next") || {
    result=$?
    rm -f "$state_tmp" "$uid_tmp" "$ip_tmp"
    rules_lock_release app-policy
    return "$result"
  }
  # 暂停保护期间用户改分应用策略：快照照实记下用户选的 mode，但内核里一条规则都不装。
  # staged 路径对 off 是明确的空操作（firewall_manager.sh:1826），也就是用户自己
  # 关掉分应用时走的同一条路，不是绕过校验。恢复保护时 reconcile 会照快照里的
  # 真 mode 把规则装回来。
  firewall_mode=$mode
  if app_policy_active_paused; then firewall_mode=off; fi
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-apply "$firewall_mode" "$uid_tmp" "$ip_tmp" "$token" || {
    result=$?
    "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-rollback "$token" >/dev/null 2>&1 || rollback_result=$?
    rm -f "$state_tmp" "$uid_tmp" "$ip_tmp"
    rules_lock_release app-policy
    case "$rollback_result" in 0|65) ;; *) return 76 ;; esac
    return "$result"
  }
  staged=1
  pointer=$(app_policy_pointer_file); pointer_tmp="$pointer.tmp.$$"
  printf 'schema_version=1\nrevision=%s\n' "$next" > "$pointer_tmp" || result=74
  if [ "${result:-0}" -eq 0 ]; then app_policy_pointer_publish "$pointer_tmp" "$pointer" || result=$?; fi
  if [ "${result:-0}" -ne 0 ]; then
    rm -f "$pointer_tmp" "$state_tmp" "$uid_tmp" "$ip_tmp"
    [ "$staged" -eq 0 ] || \
      "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-rollback "$token" >/dev/null 2>&1 || rollback_result=$?
    rules_lock_release app-policy
    [ "$rollback_result" -eq 0 ] || return 76
    return "$result"
  fi
  rm -f "$state_tmp" "$uid_tmp" "$ip_tmp"
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-confirm "$token" || {
    result=$?
    rules_lock_release app-policy
    return "$result"
  }
  app_policy_project_snapshot "$next" || { result=$?; rules_lock_release app-policy; return "$result"; }
  rules_lock_release app-policy
}

# 暂停保护期间不装分应用规则。只读 active.prop，不碰锁。
app_policy_active_paused() {
  local file="$RULE_RUNTIME/active.prop" mode
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  mode=$("$BB" awk -F= '$1=="active_mode"{print $2}' "$file" 2>/dev/null || true)
  [ "$mode" = paused ]
}

app_policy_reconcile_locked() {
  local state enabled mode uids ips uid_tmp ip_tmp result token revision
  rules_lock_is_held app-policy || return 75
  app_policy_bootstrap_locked || return
  app_policy_snapshot_load_current || return
  revision=$APP_POLICY_CURRENT_REVISION
  token=$(app_policy_revision_token "$revision") || return
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-recover "$token" || return
  # 暂停保护期间分应用规则不能留在内核里。recover 必须先跑完：cleanup 是照清单删的，
  # 清单和现实不一致时只有 recover 能把清单修回来，否则这次清理只是半拉子。
  # 这里不投影快照——用户的 enabled 偏好要原样留着，恢复时 reconcile 会照它装回来。
  if app_policy_active_paused; then
    "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-cleanup || return
    return 0
  fi
  state=$APP_POLICY_CURRENT_STATE
  enabled=$("$BB" awk -F= '$1=="enabled"{print $2}' "$state") || return
  if [ "$enabled" != 1 ]; then
    "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-cleanup || return
    app_policy_project_snapshot "$revision"
    return
  fi
  mode=$("$BB" awk -F= '$1=="mode"{print $2}' "$state") || return
  uids=$APP_POLICY_CURRENT_UIDS; ips=$APP_POLICY_CURRENT_IPS
  app_policy_validate_uid_file "$uids" || {
    app_policy_reconcile_validation_failure 65
    return $?
  }
  app_policy_validate_uid_ownership "$uids" || {
    app_policy_reconcile_validation_failure 65
    return $?
  }
  [ "$mode" != allow_resolved ] || app_policy_validate_ip_file "$ips" || {
    app_policy_reconcile_validation_failure 65
    return $?
  }
  if "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-active "$token"; then
    app_policy_project_snapshot "$revision"
    return
  else
    result=$?
  fi
  [ "$result" -eq 1 ] || return "$result"
  uid_tmp="$RULE_TMP/app-policy-reconcile-uids.$$"
  ip_tmp="$RULE_TMP/app-policy-reconcile-ips.$$"
  cp "$uids" "$uid_tmp" || return 74
  cp "$ips" "$ip_tmp" || { rm -f "$uid_tmp"; return 74; }
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-apply "$mode" "$uid_tmp" "$ip_tmp" "$token" || {
    result=$?
    rm -f "$uid_tmp" "$ip_tmp"
    return "$result"
  }
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-confirm "$token" || {
    result=$?
    rm -f "$uid_tmp" "$ip_tmp"
    return "$result"
  }
  rm -f "$uid_tmp" "$ip_tmp"
  app_policy_project_snapshot "$revision"
}

app_policy_reconcile() {
  local result release_result=0
  rules_lock_acquire app-policy || return
  app_policy_reconcile_locked
  result=$?
  rules_lock_release app-policy || release_result=$?
  [ "$result" -ne 0 ] && return "$result"
  return "$release_result"
}

app_policy_cleanup() {
  local result release_result=0
  rules_lock_acquire app-policy || return
  "$SYSTEM_SH" "$MODDIR/firewall_manager.sh" app-policy-cleanup
  result=$?
  rules_lock_release app-policy || release_result=$?
  [ "$result" -ne 0 ] && return "$result"
  return "$release_result"
}

app_policy_dispatch() {
  case "${1-}:$#" in
    capability:1) app_policy_capability_json ;;
    read:1) app_policy_read_json ;;
    apply:4) app_policy_apply "$2" "$3" "$4" ;;
    reconcile:1) app_policy_reconcile ;;
    cleanup:1) app_policy_cleanup ;;
    *) return 64 ;;
  esac
}

if [ "${APP_POLICY_SOURCE_ONLY-0}" != 1 ]; then
  APP_POLICY_ROOT=${APP_POLICY_ROOT:-${TEST_ROOT:-${0%/*}/../..}}
  MODDIR=${MODDIR:-$APP_POLICY_ROOT}
  BB=${BB:-$MODDIR/busybox/busybox}
  [ -x "$BB" ] || BB=$(command -v busybox 2>/dev/null || printf '%s' "$BB")
  SYSTEM_SH=${SYSTEM_SH:-/system/bin/sh}
  RULE_LIB_DIR=${RULE_LIB_DIR:-$MODDIR/lib/rules}
  export MODDIR BB SYSTEM_SH RULE_LIB_DIR
  . "$RULE_LIB_DIR/common.sh"
  . "$RULE_LIB_DIR/config.sh"
  rules_init_paths "$MODDIR" || exit $?
  app_policy_dispatch "$@"
fi
