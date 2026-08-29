#!/system/bin/sh

diagnostics_hosts_protection() {
  local active_file="$RULE_RUNTIME/active.prop" target record fields state generation kind source
  local expected_kind expected_source expected_sha actual_sha

  if [ ! -e "$active_file" ] && [ ! -L "$active_file" ]; then
    printf 'inactive\n'
    return 0
  fi
  [ -f "$active_file" ] && [ ! -L "$active_file" ] || {
    printf 'unknown\n'
    return 0
  }
  active_tuple_readonly "$active_file" >/dev/null 2>&1 || {
    printf 'unknown\n'
    return 0
  }

  case "${ACTIVE_TUPLE_MOUNT_KIND:-normal}:${ACTIVE_TUPLE_MODE}" in
    normal:block_all|:block_all)
      expected_kind=generation_all
      expected_source="$RULE_GENERATIONS/$ACTIVE_TUPLE_GENERATION/all"
      ;;
    normal:preserve_reward|:preserve_reward)
      expected_kind=generation_reward
      expected_source="$RULE_GENERATIONS/$ACTIVE_TUPLE_GENERATION/reward"
      ;;
    normal:paused|:paused)
      expected_kind=generation_recovery
      expected_source="$RULE_GENERATIONS/$ACTIVE_TUPLE_GENERATION/recovery"
      ;;
    trace:block_all)
      expected_kind=trace_all
      expected_source="$RULE_RUNTIME/history/traces/$ACTIVE_TUPLE_MAP_TOKEN/all"
      ;;
    trace:preserve_reward)
      expected_kind=trace_reward
      expected_source="$RULE_RUNTIME/history/traces/$ACTIVE_TUPLE_MAP_TOKEN/reward"
      ;;
    *)
      printf 'unknown\n'
      return 0
      ;;
  esac

  detect_system_hosts_target >/dev/null 2>&1 || {
    printf 'unknown\n'
    return 0
  }
  target=$SYSTEM_HOSTS_TARGET
  record=$(mount_record_find 1 "$target" 2>/dev/null) || {
    printf 'inactive\n'
    return 0
  }
  fields=$(printf '%s\n' "$record" | "$BB" awk -F '\t' '{print NF}' 2>/dev/null) || {
    printf 'unknown\n'
    return 0
  }
  case "$fields" in 15|17) ;; *) printf 'unknown\n'; return 0 ;; esac

  state=$(mount_record_field "$record" 1)
  generation=$(mount_record_field "$record" 8)
  kind=$(mount_record_field "$record" 6)
  source=$(mount_record_field "$record" 7)
  expected_sha=${ACTIVE_TUPLE_HOSTS_HASH-}
  if [ "$state" != committed ]; then
    printf 'inactive\n'
    return 0
  fi
  if [ "$generation" != "$ACTIVE_TUPLE_GENERATION" ] || [ "$kind" != "$expected_kind" ] ||
    [ "$source" != "$expected_source" ] || [ "$(mount_record_field "$record" 9)" != "$expected_sha" ]; then
    printf 'mismatch\n'
    return 0
  fi
  mount_existing_owned 1 "$target" >/dev/null 2>&1 || {
    printf 'mismatch\n'
    return 0
  }
  actual_sha=$(mount_target_sha 1 "$target" 2>/dev/null) || {
    printf 'unknown\n'
    return 0
  }
  if [ -n "$expected_sha" ] && [ "$actual_sha" = "$expected_sha" ]; then
    printf 'verified\n'
  else
    printf 'mismatch\n'
  fi
}

diagnostics_private_dns() {
  local mode
  if ! mode=$(settings get global private_dns_mode 2>/dev/null); then
    printf 'unknown\n'
    return 0
  fi
  mode=$(printf '%s' "$mode" | "$BB" tr -d '\r\n') || {
    printf 'unknown\n'
    return 0
  }
  # settings get 对不存在的键会打印字面量 null，不是空串。漏掉 null 的话，
  # 从没动过「私人 DNS」的设备会被判成 active，环境检查就报一条假警告。
  # doh_manager.sh 的 doh_private_dns_check 一直是把 null 当关闭的，这里跟它保持一致。
  case "$mode" in
    ''|null|off|opportunistic) printf 'off\n' ;;
    *) printf 'active\n' ;;
  esac
}

diagnostics_json() {
  local hosts_protection private_dns
  hosts_protection=$(diagnostics_hosts_protection 2>/dev/null) || hosts_protection=unknown
  private_dns=$(diagnostics_private_dns 2>/dev/null) || private_dns=unknown
  case "$hosts_protection" in verified|inactive|mismatch|unknown) ;; *) hosts_protection=unknown ;; esac
  case "$private_dns" in off|active|unknown) ;; *) private_dns=unknown ;; esac
  printf '{"hostsProtection":"%s","privateDns":"%s","appLocalEncryptedDns":"informational"}\n' \
    "$hosts_protection" "$private_dns"
}
