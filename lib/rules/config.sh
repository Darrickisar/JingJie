#!/system/bin/sh

LIST_MAX_BYTES=65536
LIST_MAX_DOMAINS=4096

. "${RULE_LIB_DIR:-$MODDIR/lib/rules}/source_registry.sh"
. "${RULE_LIB_DIR:-$MODDIR/lib/rules}/overrides.sh"
. "${RULE_LIB_DIR:-$MODDIR/lib/rules}/preferences.sh"

config_validate_rules_file() {
  local file=$1
  [ -f "$file" ] || return 66
  "$BB" awk -F= '
    function bad() { exit 65 }
    NF != 2 { bad() }
    $1 !~ /^(schema_version|sources_revision|next_custom_id)$/ { bad() }
    seen[$1]++ { bad() }
    $1 == "schema_version" && $2 != "2" { bad() }
    $1 == "sources_revision" && $2 !~ /^[0-9]+$/ { bad() }
    $1 == "next_custom_id" && $2 !~ /^[1-9][0-9]*$/ { bad() }
    END {
      if (NR != 3 || !seen["schema_version"] || !seen["sources_revision"] ||
          !seen["next_custom_id"]) exit 65
    }
  ' "$file"
}

config_validate_v1_rules_file() {
  local file=$1
  [ -f "$file" ] || return 66
  "$BB" awk -F= '
    function bad() { exit 65 }
    NF != 2 { bad() }
    $1 !~ /^(schema_version|sources_revision|awa_enabled|fcm_enabled|rule10007_enabled|next_custom_id)$/ { bad() }
    seen[$1]++ { bad() }
    $1 == "schema_version" && $2 != "1" { bad() }
    $1 == "sources_revision" && $2 !~ /^[0-9]+$/ { bad() }
    ($1 == "awa_enabled" || $1 == "fcm_enabled" || $1 == "rule10007_enabled") && $2 !~ /^[01]$/ { bad() }
    $1 == "next_custom_id" && $2 !~ /^[1-9][0-9]*$/ { bad() }
    END {
      if (NR != 6 || !seen["schema_version"] || !seen["sources_revision"] ||
          !seen["awa_enabled"] || !seen["fcm_enabled"] || !seen["rule10007_enabled"] ||
          !seen["next_custom_id"]) exit 65
    }
  ' "$file"
}

config_b64_valid() {
  local value=$1 canonical
  case "$value" in
    ''|*[!A-Za-z0-9+/=]*) return 1 ;;
  esac
  [ $(( ${#value} % 4 )) -eq 0 ] || return 1
  canonical=$(printf '%s' "$value" | "$BB" base64 -d 2>/dev/null | "$BB" base64 | "$BB" tr -d '\n') || return 1
  [ "$canonical" = "$value" ]
}

config_dump_bytes() {
  local file=$1 dump=$2
  rm -f "$dump" || return 74
  "$BB" od -An -v -t u1 "$file" > "$dump" 2>/dev/null || {
    rm -f "$dump"
    return 74
  }
}

config_utf8_valid_file() {
  local file=$1 dump="$RULE_TMP/config-byte-dump.$$" result=0
  config_dump_bytes "$file" "$dump" || return $?
  "$BB" awk '
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
  ' "$dump" || result=$?
  rm -f "$dump" || [ "$result" -ne 0 ] || result=74
  return "$result"
}

config_url_forbidden_bytes() {
  local file=$1 dump="$RULE_TMP/config-byte-dump.$$" result=1
  config_dump_bytes "$file" "$dump" || return $?
  "$BB" awk '
    { for(i=1;i<=NF;i++) if(($i>=9 && $i<=13) || $i==32 || $i==96) found=1 }
    END{exit found ? 0 : 1}
  ' "$dump" && result=0 || result=$?
  rm -f "$dump" || [ "$result" -ne 0 ] || result=74
  return "$result"
}

config_validate_custom_file() {
  local file=$1
  [ -f "$file" ] || return 66
  local count=0 id enabled name_b64 url_b64 extra
  while IFS="$(printf '\t')" read -r id enabled name_b64 url_b64 extra || [ -n "${id}${enabled}${name_b64}${url_b64}${extra}" ]; do
    [ -n "$id" ] || continue
    [ -z "$extra" ] || return 65
    case "$id" in custom_[1-9]*[!0-9]*|custom_|*[!a-z0-9_]*) return 65 ;; esac
    case "$id" in custom_[1-9]* ) ;; *) return 65 ;; esac
    [ "$enabled" = 0 ] || [ "$enabled" = 1 ] || return 65
    config_b64_valid "$name_b64" || return 65
    config_b64_valid "$url_b64" || return 65
    "$BB" awk -F '\t' -v wanted="$id" '$1==wanted{n++} END{exit n==1?0:1}' "$file" || return 65
    count=$((count + 1))
    [ "$count" -le 16 ] || return 65
  done < "$file"
}

snapshot_sha256() {
  local dir=$1 tmp
  config_validate_rules_file "$dir/rules.conf" || return
  source_registry_validate_file "$dir/sources.tsv" || return
  overrides_validate_file "$dir/overrides.tsv" || return
  [ -f "$dir/manual-blocklist.txt" ] && [ -f "$dir/manual-allowlist.txt" ] || return 66
  config_validate_domain_list_file "$dir/manual-blocklist.txt" || return
  config_validate_domain_list_file "$dir/manual-allowlist.txt" || return
  tmp="$RULE_TMP/snapshot.$$"
  {
    printf '%s\n' rules.conf
    cat "$dir/rules.conf"
    printf '%s\n' sources.tsv
    cat "$dir/sources.tsv"
    printf '%s\n' overrides.tsv
    cat "$dir/overrides.tsv"
    printf '%s\n' manual-blocklist.txt
    cat "$dir/manual-blocklist.txt"
    printf '%s\n' manual-allowlist.txt
    cat "$dir/manual-allowlist.txt"
  } > "$tmp" || return 74
  sha256_file "$tmp"
  rm -f "$tmp"
}

# 旧版（schema 2）快照里还带着白名单订阅的两个文件，升级时要按原样重算校验值。
config_v2_snapshot_sha256() {
  local dir=$1 tmp
  config_validate_rules_file "$dir/rules.conf" || return
  source_registry_validate_file "$dir/sources.tsv" || return
  overrides_validate_file "$dir/overrides.tsv" || return
  [ -f "$dir/manual-blocklist.txt" ] && [ -f "$dir/manual-allowlist.txt" ] || return 66
  [ -f "$dir/enhanced-whitelist.conf" ] || return 66
  config_validate_domain_list_file "$dir/manual-blocklist.txt" || return
  config_validate_domain_list_file "$dir/manual-allowlist.txt" || return
  config_validate_domain_list_file "$dir/enhanced-whitelist-manual.txt" || return
  tmp="$RULE_TMP/snapshot-v2.$$"
  {
    printf '%s\n' rules.conf
    cat "$dir/rules.conf"
    printf '%s\n' sources.tsv
    cat "$dir/sources.tsv"
    printf '%s\n' overrides.tsv
    cat "$dir/overrides.tsv"
    printf '%s\n' manual-blocklist.txt
    cat "$dir/manual-blocklist.txt"
    printf '%s\n' manual-allowlist.txt
    cat "$dir/manual-allowlist.txt"
    printf '%s\n' enhanced-whitelist.conf
    cat "$dir/enhanced-whitelist.conf"
    printf '%s\n' enhanced-whitelist-manual.txt
    cat "$dir/enhanced-whitelist-manual.txt"
  } > "$tmp" || return 74
  sha256_file "$tmp"
  rm -f "$tmp"
}

config_v1_snapshot_sha256() {
  local dir=$1 tmp
  config_validate_v1_rules_file "$dir/rules.conf" || return
  config_validate_custom_file "$dir/custom-sources.tsv" || return
  [ -f "$dir/manual-blocklist.txt" ] && [ -f "$dir/manual-allowlist.txt" ] || return 66
  config_validate_domain_list_file "$dir/manual-blocklist.txt" || return
  config_validate_domain_list_file "$dir/manual-allowlist.txt" || return
  [ -f "$dir/enhanced-whitelist.conf" ] || return 66
  config_validate_domain_list_file "$dir/enhanced-whitelist-manual.txt" || return
  tmp="$RULE_TMP/snapshot-v1.$$"
  {
    printf '%s\n' rules.conf
    cat "$dir/rules.conf"
    printf '%s\n' custom-sources.tsv
    cat "$dir/custom-sources.tsv"
    printf '%s\n' manual-blocklist.txt
    cat "$dir/manual-blocklist.txt"
    printf '%s\n' manual-allowlist.txt
    cat "$dir/manual-allowlist.txt"
    printf '%s\n' enhanced-whitelist.conf
    cat "$dir/enhanced-whitelist.conf"
    printf '%s\n' enhanced-whitelist-manual.txt
    cat "$dir/enhanced-whitelist-manual.txt"
  } > "$tmp" || return 74
  sha256_file "$tmp"
  rm -f "$tmp"
}

config_snapshot_hash() {
  local rev=$1
  case "$rev" in ''|*[!0-9]*) return 65 ;; esac
  snapshot_sha256 "$CONFIG_DIR/revisions/$rev"
}

config_domain_list_valid() {
  case "$1" in
    ''|*[!a-z0-9.-]*) return 1 ;;
  esac
  case "$1" in
    .*|*.|*..*) return 1 ;;
  esac
  printf '%s\n' "$1" | "$BB" awk '
    length($0)>253 || $0 ~ /^[0-9.]+$/ {exit 1}
    {
      n=split($0,a,".");
      for(i=1;i<=n;i++) if(length(a[i])>63 || a[i] !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) exit 1
    }
  '
}

config_read_canonical_domain_file() {
  local file=$1 dump="$RULE_TMP/config-domain-byte-dump.$$" bytes result=0 domain
  [ -f "$file" ] || return 66
  bytes=$(wc -c < "$file" | tr -d ' ') || return 74
  [ "$bytes" -ge 1 ] && [ "$bytes" -le 253 ] || return 65
  config_dump_bytes "$file" "$dump" || return $?
  "$BB" awk '
    {
      for (i=1; i<=NF; i++) {
        b=$i+0
        if (b != 45 && b != 46 && (b < 48 || b > 57) && (b < 97 || b > 122)) bad=1
      }
    }
    END { exit bad ? 65 : 0 }
  ' "$dump" || result=$?
  rm -f "$dump" || [ "$result" -ne 0 ] || result=74
  [ "$result" -eq 0 ] || return "$result"
  domain=$(cat "$file") || return 74
  config_domain_list_valid "$domain" || return 65
  printf '%s\n' "$domain"
}

config_validate_domain_list_file() {
  local file=$1 bytes line normalized tmp count
  [ -f "$file" ] || return 66
  bytes=$(wc -c < "$file" | tr -d ' ')
  [ "$bytes" -le "$LIST_MAX_BYTES" ] || return 65
  tmp="$RULE_TMP/domain-list.$$"
  : > "$tmp" || return 74
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | "$BB" tr -d '\r') || { rm -f "$tmp"; return 74; }
    [ -n "$line" ] || continue
    case "$line" in \#*) continue ;; esac
    normalized=$(printf '%s' "$line" | "$BB" tr 'A-Z' 'a-z') || { rm -f "$tmp"; return 74; }
    config_domain_list_valid "$normalized" || { rm -f "$tmp"; return 65; }
    printf '%s\n' "$normalized" >> "$tmp" || { rm -f "$tmp"; return 74; }
  done < "$file"
  LC_ALL=C "$BB" sort -u "$tmp" -o "$tmp" || { rm -f "$tmp"; return 74; }
  count=$(wc -l < "$tmp" | tr -d ' ')
  [ "$count" -le "$LIST_MAX_DOMAINS" ] || { rm -f "$tmp"; return 65; }
  if ! "$BB" cmp -s "$tmp" "$file" 2>/dev/null; then
    # Validation accepts comments and mixed case, but stored revisions must be canonical.
    rm -f "$tmp"
    return 65
  fi
  rm -f "$tmp"
}

config_decode_domain_list() {
  local encoded=$1 output=$2 raw="$RULE_TMP/list-raw.$$" tmp="$RULE_TMP/list.$$" bytes line normalized count
  if [ -z "$encoded" ]; then
    : > "$output"
    return 0
  fi
  config_b64_valid "$encoded" || return 65
  printf '%s' "$encoded" | "$BB" base64 -d > "$raw" 2>/dev/null || return 65
  bytes=$(wc -c < "$raw" | tr -d ' ')
  [ "$bytes" -le "$LIST_MAX_BYTES" ] || { rm -f "$raw"; return 65; }
  : > "$tmp" || { rm -f "$raw"; return 74; }
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | "$BB" tr -d '\r') || { rm -f "$raw" "$tmp"; return 74; }
    [ -n "$line" ] || continue
    case "$line" in \#*) continue ;; esac
    normalized=$(printf '%s' "$line" | "$BB" tr 'A-Z' 'a-z') || { rm -f "$raw" "$tmp"; return 74; }
    config_domain_list_valid "$normalized" || { rm -f "$raw" "$tmp"; return 65; }
    printf '%s\n' "$normalized" >> "$tmp" || { rm -f "$raw" "$tmp"; return 74; }
  done < "$raw"
  LC_ALL=C "$BB" sort -u "$tmp" -o "$tmp" || { rm -f "$raw" "$tmp"; return 74; }
  count=$(wc -l < "$tmp" | tr -d ' ')
  [ "$count" -le "$LIST_MAX_DOMAINS" ] || { rm -f "$raw" "$tmp"; return 65; }
  mv "$tmp" "$output" || { rm -f "$raw" "$tmp"; return 74; }
  rm -f "$raw" "$tmp"
}

config_lists_json() {
  local revision=$1 block allow first=true line block_count allow_count
  case "$revision" in ''|*[!0-9]*) return 65 ;; esac
  block="$CONFIG_DIR/revisions/$revision/manual-blocklist.txt"
  allow="$CONFIG_DIR/revisions/$revision/manual-allowlist.txt"
  config_validate_domain_list_file "$block" || return
  config_validate_domain_list_file "$allow" || return
  block_count=$(wc -l < "$block" | tr -d ' ')
  allow_count=$(wc -l < "$allow" | tr -d ' ')
  printf '{"revision":%s,"blockCount":%s,"allowCount":%s,"block":[' "$revision" "$block_count" "$allow_count"
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    [ "$first" = true ] || printf ','
    first=false
    printf '"%s"' "$(printf '%s' "$line" | json_escape)"
  done < "$block"
  first=true
  printf '],"allow":['
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    [ "$first" = true ] || printf ','
    first=false
    printf '"%s"' "$(printf '%s' "$line" | json_escape)"
  done < "$allow"
  printf ']}\n'
}

config_fold_legacy_enhanced_manual() {
  local allowlist=$1 enhanced_manual=$2 merged="$RULE_TMP/folded-allow.$$" result
  config_validate_domain_list_file "$allowlist" || return
  config_validate_domain_list_file "$enhanced_manual" || return
  cat "$allowlist" "$enhanced_manual" | LC_ALL=C "$BB" sort -u > "$merged" || { rm -f "$merged"; return 74; }
  config_validate_domain_list_file "$merged" || {
    result=$?
    rm -f "$merged"
    return "$result"
  }
  mv "$merged" "$allowlist" || { rm -f "$merged"; return 74; }
  : > "$enhanced_manual" || return 74
}

config_validate_pointer() {
  local file=${1:-$CONFIG_DIR/current.prop}
  [ -f "$file" ] || return 66
  "$BB" awk -F= '
    NF != 2 { exit 65 }
    $1 !~ /^(sources_revision|snapshot_sha256)$/ { exit 65 }
    seen[$1]++ { exit 65 }
    $1 == "sources_revision" && $2 !~ /^[0-9]+$/ { exit 65 }
    $1 == "snapshot_sha256" && $2 !~ /^[0-9a-f]{64}$/ { exit 65 }
    END { if (NR != 2 || !seen["sources_revision"] || !seen["snapshot_sha256"]) exit 65 }
  ' "$file"
}

pointer_value() {
  local key=$1 file=${2:-$CONFIG_DIR/current.prop}
  "$BB" awk -F= -v wanted="$key" '$1==wanted{print $2}' "$file"
}

config_current_revision() {
  config_validate_pointer || return
  local rev expected actual
  rev=$(pointer_value sources_revision) || return
  expected=$(pointer_value snapshot_sha256) || return
  actual=$(config_snapshot_hash "$rev") || return
  [ "$expected" = "$actual" ] || return 70
  printf '%s\n' "$rev"
}

strict_config_value() {
  local rev=$1 key=$2 file="$CONFIG_DIR/revisions/$1/rules.conf"
  config_validate_rules_file "$file" || return
  case "$key" in schema_version|sources_revision|next_custom_id) ;; *) return 64 ;; esac
  "$BB" awk -F= -v wanted="$key" '$1==wanted{print $2}' "$file"
}

custom_source_count() {
  local rev=$1 file="$CONFIG_DIR/revisions/$1/sources.tsv"
  source_registry_validate_file "$file" || return
  "$BB" awk -F '\t' '$2=="custom"{n++} END{print n+0}' "$file"
}

custom_source_id_at() {
  local rev=$1 position=$2 file="$CONFIG_DIR/revisions/$1/sources.tsv"
  source_registry_validate_file "$file" || return
  "$BB" awk -F '\t' -v wanted="$position" '$2=="custom" && ++n==wanted{print $1}' "$file"
}

config_commit_dir() {
  local rev=$1 tmp="$CONFIG_DIR/revisions/$1.tmp" final="$CONFIG_DIR/revisions/$1" hash pointer_tmp result
  [ -d "$tmp" ] || return 66
  [ ! -e "$final" ] || return 76
  hash=$(snapshot_sha256 "$tmp") || return
  mv "$tmp" "$final" || return 74
  pointer_tmp="$CONFIG_DIR/current.prop.tmp.$$"
  printf 'sources_revision=%s\nsnapshot_sha256=%s\n' "$rev" "$hash" > "$pointer_tmp" || {
    rm -f "$pointer_tmp"
    rm -rf "$final"
    return 74
  }
  atomic_replace_file "$pointer_tmp" "$CONFIG_DIR/current.prop" || {
    result=$?
    rm -f "$pointer_tmp"
    rm -rf "$final"
    return "$result"
  }
}

config_write_default_mode() {
  local desired=block_all tmp="$CONFIG_DIR/mode.prop.tmp.$$"
  printf 'desired_mode=%s\n' "$desired" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$CONFIG_DIR/mode.prop"
}

config_migrate_current_registry() {
  config_validate_pointer || return
  local old_rev expected actual new_rev tmp result old_dir next_id awa_enabled rule10007_enabled
  local id enabled name_b64 url_b64 extra order=2
  old_rev=$(pointer_value sources_revision) || return
  expected=$(pointer_value snapshot_sha256) || return
  old_dir="$CONFIG_DIR/revisions/$old_rev"
  actual=$(config_v1_snapshot_sha256 "$old_dir") || return
  [ "$expected" = "$actual" ] || return 70
  new_rev=$((old_rev + 1))
  while [ -e "$CONFIG_DIR/revisions/$new_rev" ] || [ -e "$CONFIG_DIR/revisions/$new_rev.tmp" ]; do
    new_rev=$((new_rev + 1))
  done
  tmp="$CONFIG_DIR/revisions/$new_rev.tmp"
  mkdir -p "$tmp" || return 73
  next_id=$("$BB" awk -F= '$1=="next_custom_id"{print $2}' "$old_dir/rules.conf") || { rm -rf "$tmp"; return 74; }
  awa_enabled=$("$BB" awk -F= '$1=="awa_enabled"{print $2}' "$old_dir/rules.conf") || { rm -rf "$tmp"; return 74; }
  rule10007_enabled=$("$BB" awk -F= '$1=="rule10007_enabled"{print $2}' "$old_dir/rules.conf") || { rm -rf "$tmp"; return 74; }
  printf 'schema_version=2\nsources_revision=%s\nnext_custom_id=%s\n' "$new_rev" "$next_id" > "$tmp/rules.conf" || { rm -rf "$tmp"; return 74; }
  source_registry_seed "$tmp/sources.tsv" || { rm -rf "$tmp"; return $?; }
  : > "$tmp/overrides.tsv" || { rm -rf "$tmp"; return 74; }
  "$BB" awk -F '\t' -v OFS='\t' -v awa="$awa_enabled" -v r10007="$rule10007_enabled" \
    '$1=="awa"{$3=awa} $1=="rule10007"{$3=r10007} {print}' "$tmp/sources.tsv" > "$tmp/sources.new" || { rm -rf "$tmp"; return 74; }
  mv "$tmp/sources.new" "$tmp/sources.tsv" || { rm -rf "$tmp"; return 74; }
  while IFS="$(printf '\t')" read -r id enabled name_b64 url_b64 extra || [ -n "${id}${enabled}${name_b64}${url_b64}${extra}" ]; do
    [ -n "$id" ] || continue
    [ -z "$extra" ] || { rm -rf "$tmp"; return 65; }
    printf '%s\tcustom\t%s\t%s\t%s\t%s\n' "$id" "$enabled" "$order" "$name_b64" "$url_b64" >> "$tmp/sources.tsv" || { rm -rf "$tmp"; return 74; }
    order=$((order + 1))
  done < "$old_dir/custom-sources.tsv"
  source_registry_validate_file "$tmp/sources.tsv" || { rm -rf "$tmp"; return 65; }
  cp "$old_dir/manual-blocklist.txt" "$tmp/manual-blocklist.txt" || { rm -rf "$tmp"; return 74; }
  cp "$old_dir/manual-allowlist.txt" "$tmp/manual-allowlist.txt" || { rm -rf "$tmp"; return 74; }
  config_fold_legacy_allowlist "$old_dir" "$tmp/manual-allowlist.txt" || {
    result=$?
    rm -rf "$tmp"
    return "$result"
  }
  config_commit_dir "$new_rev" || {
    result=$?
    rm -rf "$tmp"
    return "$result"
  }
}

# 老快照里的“白名单订阅”手动条目要合并进普通白名单，功能下线后一条都不能丢。
config_fold_legacy_allowlist() {
  local old_dir=$1 allowlist=$2 legacy="$1/enhanced-whitelist-manual.txt" staged result
  [ -f "$legacy" ] || return 0
  staged="$RULE_TMP/legacy-allow.$$"
  cp "$legacy" "$staged" || return 74
  config_fold_legacy_enhanced_manual "$allowlist" "$staged" || {
    result=$?
    rm -f "$staged"
    return "$result"
  }
  rm -f "$staged"
}

# schema 2 的快照带着白名单订阅文件，这里原地升级成不含订阅的新版快照。
config_migrate_v2_registry() {
  config_validate_pointer || return
  local old_rev expected actual new_rev tmp old_dir result file
  old_rev=$(pointer_value sources_revision) || return
  expected=$(pointer_value snapshot_sha256) || return
  old_dir="$CONFIG_DIR/revisions/$old_rev"
  actual=$(config_v2_snapshot_sha256 "$old_dir") || return
  [ "$expected" = "$actual" ] || return 70
  new_rev=$((old_rev + 1))
  while [ -e "$CONFIG_DIR/revisions/$new_rev" ] || [ -e "$CONFIG_DIR/revisions/$new_rev.tmp" ]; do
    new_rev=$((new_rev + 1))
  done
  tmp="$CONFIG_DIR/revisions/$new_rev.tmp"
  rm -rf "$tmp"
  mkdir -p "$tmp" || return 73
  for file in rules.conf sources.tsv overrides.tsv manual-blocklist.txt manual-allowlist.txt; do
    cp "$old_dir/$file" "$tmp/$file" || { rm -rf "$tmp"; return 74; }
  done
  config_fold_legacy_allowlist "$old_dir" "$tmp/manual-allowlist.txt" || {
    result=$?
    rm -rf "$tmp"
    return "$result"
  }
  config_replace_rule_value "$tmp/rules.conf" sources_revision "$new_rev" || {
    result=$?
    rm -rf "$tmp"
    return "$result"
  }
  config_commit_dir "$new_rev" || {
    result=$?
    rm -rf "$tmp"
    return "$result"
  }
}

# 规则日志已经取消。旧版本留下的档位偏好和 rule-engine.log 不会再有任何读者，
# 升级后放着只是白占空间，所以在引导时一次性删掉：每次开机四条 rm，不进任何热路径。
config_prune_removed_features() {
  rm -f "$CONFIG_DIR/log-mode.prop" 2>/dev/null || true
  rm -f "$RULE_RUNTIME/logs/rule-engine.log" 2>/dev/null || true
  rm -f "$RULE_RUNTIME/logs/rule-engine.log.1" 2>/dev/null || true
  rm -f "$RULE_RUNTIME/logs/rule-engine.log.2" 2>/dev/null || true
}

config_bootstrap() {
  local revision tmp
  rules_init_paths "$MODDIR" || return
  config_prune_removed_features
  preferences_bootstrap || return
  if [ -f "$CONFIG_DIR/current.prop" ]; then
    if config_current_revision >/dev/null 2>&1; then
      revision=$(pointer_value sources_revision)
      config_prune_custom_cache "$revision" || return
      return 0
    fi
    config_migrate_current_registry 2>/dev/null || config_migrate_v2_registry || return
    revision=$(config_current_revision) || return
    config_prune_custom_cache "$revision" || return
    return
  fi
  tmp="$CONFIG_DIR/revisions/0.tmp"
  rm -rf "$tmp"
  mkdir -p "$tmp" || return 73
  printf '%s\n' \
    'schema_version=2' \
    'sources_revision=0' \
    'next_custom_id=1' > "$tmp/rules.conf" || return 74
  source_registry_seed "$tmp/sources.tsv" || return
  : > "$tmp/overrides.tsv" || return 74
  : > "$tmp/manual-blocklist.txt"
  : > "$tmp/manual-allowlist.txt"
  config_commit_dir 0 || return
  [ -f "$CONFIG_DIR/mode.prop" ] || config_write_default_mode
  config_prune_custom_cache 0 || return
}

config_mode_value() {
  local file=$1
  [ -f "$file" ] || return 66
  "$BB" awk -F= '
    NF != 2 || $1 != "desired_mode" || seen++ { exit 65 }
    $2 != "block_all" && $2 != "preserve_reward" { exit 65 }
    { value=$2 }
    END { if (NR != 1) exit 65; print value }
  ' "$file"
}

mode_desired() {
  config_mode_value "$CONFIG_DIR/mode.prop"
}

mode_set_locked() {
  rules_lock_is_held rules || return 75
  local mode=$1 tmp="$CONFIG_DIR/mode.prop.tmp.$$"
  [ "$mode" = block_all ] || [ "$mode" = preserve_reward ] || return 65
  printf 'desired_mode=%s\n' "$mode" > "$tmp" || return 74
  atomic_replace_file "$tmp" "$CONFIG_DIR/mode.prop"
}

config_decode_source_fields() {
  local name_b64=$1 url_b64=$2 name_file="$RULE_TMP/name.$$" url_file="$RULE_TMP/url.$$"
  config_b64_valid "$name_b64" || return 65
  config_b64_valid "$url_b64" || return 65
  printf '%s' "$name_b64" | "$BB" base64 -d > "$name_file" 2>/dev/null || return 65
  printf '%s' "$url_b64" | "$BB" base64 -d > "$url_file" 2>/dev/null || return 65
  local name_bytes url_bytes
  name_bytes=$(wc -c < "$name_file" | tr -d ' ')
  url_bytes=$(wc -c < "$url_file" | tr -d ' ')
  [ "$name_bytes" -ge 1 ] && [ "$name_bytes" -le 320 ] || return 65
  [ "$url_bytes" -ge 9 ] && [ "$url_bytes" -le 2048 ] || return 65
  LC_ALL=C grep '[[:cntrl:]]' "$name_file" >/dev/null 2>&1 && return 65
  LC_ALL=C grep '[[:space:]`]' "$url_file" >/dev/null 2>&1 && return 65
  local url
  url=$(cat "$url_file")
  case "$url" in https://*) ;; *) return 65 ;; esac
  rm -f "$name_file" "$url_file"
}

config_clone_next() {
  local old_rev=$1 new_rev=$2 tmp="$CONFIG_DIR/revisions/$2.tmp"
  rm -rf "$tmp"
  mkdir -p "$tmp" || return 73
  cp "$CONFIG_DIR/revisions/$old_rev/rules.conf" "$tmp/rules.conf" || return 74
  cp "$CONFIG_DIR/revisions/$old_rev/sources.tsv" "$tmp/sources.tsv" || return 74
  if [ -f "$CONFIG_DIR/revisions/$old_rev/overrides.tsv" ]; then
    cp "$CONFIG_DIR/revisions/$old_rev/overrides.tsv" "$tmp/overrides.tsv" || return 74
  else
    : > "$tmp/overrides.tsv" || return 74
  fi
  if [ -f "$CONFIG_DIR/revisions/$old_rev/manual-blocklist.txt" ]; then
    cp "$CONFIG_DIR/revisions/$old_rev/manual-blocklist.txt" "$tmp/manual-blocklist.txt" || return 74
  else
    : > "$tmp/manual-blocklist.txt"
  fi
  if [ -f "$CONFIG_DIR/revisions/$old_rev/manual-allowlist.txt" ]; then
    cp "$CONFIG_DIR/revisions/$old_rev/manual-allowlist.txt" "$tmp/manual-allowlist.txt" || return 74
  else
    : > "$tmp/manual-allowlist.txt"
  fi
  "$BB" awk -F= -v rev="$new_rev" 'BEGIN{OFS="="} $1=="sources_revision"{$2=rev} {print}' \
    "$tmp/rules.conf" > "$tmp/rules.new" || return 74
  mv "$tmp/rules.new" "$tmp/rules.conf" || return 74
}

config_replace_rule_value() {
  local file=$1 key=$2 value=$3
  "$BB" awk -F= -v wanted="$key" -v replacement="$value" 'BEGIN{OFS="="} $1==wanted{$2=replacement} {print}' \
    "$file" > "$file.new" || return 74
  mv "$file.new" "$file"
}

config_custom_cache_hash() {
  printf '%s' "$1" | "$BB" sha256sum - | "$BB" awk '{print tolower($1)}'
}

config_prune_custom_cache() {
  local revision=${1-} sources cache_root allowed allowed_hash dir id file base url extra kind enabled order name_b64 url_b64
  [ -n "${CACHE_DIR-}" ] || return 0
  if [ -z "$revision" ]; then
    revision=$(config_current_revision) || return
  fi
  case "$revision" in ''|*[!0-9]*) return 65 ;; esac
  rm -rf "$CACHE_DIR/enhanced-whitelist" || return 74
  cache_root="$CACHE_DIR/custom"
  [ -d "$cache_root" ] || return 0
  sources="$CONFIG_DIR/revisions/$revision/sources.tsv"
  source_registry_validate_file "$sources" || return

  allowed="$RULE_TMP/custom-cache-allow.$$"
  : > "$allowed" || return 74
  while IFS="$(printf '\t')" read -r id kind enabled order name_b64 url_b64 extra || \
    [ -n "${id}${kind}${enabled}${order}${name_b64}${url_b64}${extra}" ]; do
    [ -n "$id" ] || continue
    [ -z "$extra" ] || { rm -f "$allowed"; return 65; }
    [ "$kind" = custom ] || continue
    url=$(printf '%s' "$url_b64" | "$BB" base64 -d 2>/dev/null) || {
      rm -f "$allowed"
      return 65
    }
    printf '%s\t%s\n' "$id" "$(config_custom_cache_hash "$url")" >> "$allowed" || {
      rm -f "$allowed"
      return 74
    }
  done < "$sources"

  for dir in "$cache_root"/custom_*; do
    [ -e "$dir" ] || [ -L "$dir" ] || continue
    id=${dir##*/}
    case "$id" in
      custom_[1-9]*)
        case "${id#custom_}" in *[!0-9]*) continue ;; esac
        ;;
      *) continue ;;
    esac
    allowed_hash=$("$BB" awk -F '\t' -v wanted="$id" '$1==wanted{print $2; found=1} END{if(!found) exit 1}' "$allowed" 2>/dev/null || true)
    if [ -z "$allowed_hash" ]; then
      rm -rf "$dir" || { rm -f "$allowed"; return 74; }
      continue
    fi
    for file in "$dir"/*; do
      [ -e "$file" ] || [ -L "$file" ] || continue
      base=${file##*/}
      # 归一化缓存（.norm 系列）是当前缓存的加速副本，跟着它一起留下。
      case "$base" in
        "$allowed_hash.hosts"|"$allowed_hash.hosts.norm"|"$allowed_hash.hosts.norm.allow"|"$allowed_hash.hosts.norm.meta")
          continue
          ;;
      esac
      rm -rf "$file" || {
        rm -f "$allowed"
        return 74
      }
    done
  done
  rm -f "$allowed"
}

# 清理缓存：只删掉已停用来源留下的缓存副本。
# 启用中的来源必须保留缓存，否则断网时就没有兜底副本可用。
# 成功时向 stdout 输出被清理的条目数，供调用方写日志。
config_clear_disabled_cache() {
  local revision=${1-} sources cleared=0 id kind enabled order name_b64 url_b64 extra
  [ -n "${CACHE_DIR-}" ] || { printf '0\n'; return 0; }
  if [ -z "$revision" ]; then
    revision=$(config_current_revision) || return
  fi
  case "$revision" in ''|*[!0-9]*) return 65 ;; esac
  sources="$CONFIG_DIR/revisions/$revision/sources.tsv"
  source_registry_validate_file "$sources" || return
  while IFS="$(printf '\t')" read -r id kind enabled order name_b64 url_b64 extra || \
    [ -n "${id}${kind}${enabled}${order}${name_b64}${url_b64}${extra}" ]; do
    [ -n "$id" ] || continue
    [ -z "$extra" ] || return 65
    [ "$enabled" = 0 ] || continue
    source_registry_remove_cache "$id" || return
    cleared=$((cleared + 1))
  done < "$sources"
  printf '%s\n' "$cleared"
}

config_mutate_locked() {
  rules_lock_is_held rules || return 75
  local verb=${1-} old_rev new_rev tmp rules sources overrides_file blocklist allowlist result removed_id=
  old_rev=$(config_current_revision) || return
  new_rev=$((old_rev + 1))
  config_clone_next "$old_rev" "$new_rev" || return
  tmp="$CONFIG_DIR/revisions/$new_rev.tmp"
  rules="$tmp/rules.conf"
  sources="$tmp/sources.tsv"
  overrides_file="$tmp/overrides.tsv"
  blocklist="$tmp/manual-blocklist.txt"
  allowlist="$tmp/manual-allowlist.txt"

  case "$verb:$#" in
    reset-rules:1)
      printf 'schema_version=2\nsources_revision=%s\nnext_custom_id=1\n' "$new_rev" > "$rules" || { rm -rf "$tmp"; return 74; }
      source_registry_seed "$sources" || { rm -rf "$tmp"; return 65; }
      : > "$overrides_file" || { rm -rf "$tmp"; return 74; }
      : > "$blocklist" || { rm -rf "$tmp"; return 74; }
      : > "$allowlist" || { rm -rf "$tmp"; return 74; }
      ;;
    set-builtin:3)
      local builtin=$2 enabled=$3
      [ "$builtin" = awa ] || [ "$builtin" = rule10007 ] || { rm -rf "$tmp"; return 65; }
      [ "$enabled" = 0 ] || [ "$enabled" = 1 ] || { rm -rf "$tmp"; return 65; }
      source_registry_exists "$sources" "$builtin" || { rm -rf "$tmp"; return 65; }
      "$BB" awk -F '\t' -v OFS='\t' -v wanted="$builtin" -v value="$enabled" \
        '$1==wanted{$3=value} {print}' "$sources" > "$sources.new" || { rm -rf "$tmp"; return 74; }
      mv "$sources.new" "$sources" || { rm -rf "$tmp"; return 74; }
      ;;
    add-source:3)
      local name_b64=$2 url_b64=$3 count next id kind=custom order decoded_url builtin_url
      config_decode_source_fields "$name_b64" "$url_b64" || { rm -rf "$tmp"; return 65; }
      count=$(custom_source_count "$old_rev") || return
      decoded_url=$(printf '%s' "$url_b64" | "$BB" base64 -d 2>/dev/null) || { rm -rf "$tmp"; return 65; }
      for id in awa rule10007; do
        builtin_url=$(source_registry_builtin_url "$id") || { rm -rf "$tmp"; return 65; }
        if [ "$decoded_url" = "$builtin_url" ] && ! source_registry_exists "$sources" "$id"; then
          kind=builtin
          break
        fi
      done
      if [ "$kind" = custom ]; then
        [ "$count" -lt "$SOURCE_REGISTRY_MAX_CUSTOM" ] || { rm -rf "$tmp"; return 65; }
        next=$(strict_config_value "$old_rev" next_custom_id) || {
          result=$?
          rm -rf "$tmp"
          return "$result"
        }
        id="custom_$next"
        config_replace_rule_value "$rules" next_custom_id $((next + 1)) || {
          result=$?
          rm -rf "$tmp"
          return "$result"
        }
      fi
      order=$(source_registry_next_order "$sources") || {
        result=$?
        rm -rf "$tmp"
        return "$result"
      }
      printf '%s\t%s\t1\t%s\t%s\t%s\n' "$id" "$kind" "$order" "$name_b64" "$url_b64" >> "$sources" || { rm -rf "$tmp"; return 74; }
      ;;
    update-source:4)
      local id=$2 name_b64=$3 url_b64=$4
      source_registry_exists "$sources" "$id" || { rm -rf "$tmp"; return 65; }
      config_decode_source_fields "$name_b64" "$url_b64" || { rm -rf "$tmp"; return 65; }
      "$BB" awk -F '\t' -v OFS='\t' -v wanted="$id" -v name="$name_b64" -v url="$url_b64" \
        '$1==wanted{$5=name;$6=url} {print}' "$sources" > "$sources.new" || { rm -rf "$tmp"; return 74; }
      mv "$sources.new" "$sources" || { rm -rf "$tmp"; return 74; }
      ;;
    toggle-source:3)
      local id=$2 enabled=$3
      [ "$enabled" = 0 ] || [ "$enabled" = 1 ] || { rm -rf "$tmp"; return 65; }
      source_registry_exists "$sources" "$id" || { rm -rf "$tmp"; return 65; }
      "$BB" awk -F '\t' -v OFS='\t' -v wanted="$id" -v value="$enabled" '$1==wanted{$3=value} {print}' \
        "$sources" > "$sources.new" || { rm -rf "$tmp"; return 74; }
      mv "$sources.new" "$sources" || { rm -rf "$tmp"; return 74; }
      ;;
    move-source:3)
      local id=$2 direction=$3
      source_registry_exists "$sources" "$id" || { rm -rf "$tmp"; return 65; }
      [ "$direction" = up ] || [ "$direction" = down ] || { rm -rf "$tmp"; return 65; }
      LC_ALL=C "$BB" sort -t "$(printf '\t')" -k4,4n "$sources" | \
      "$BB" awk -F '\t' -v OFS='\t' -v wanted="$id" -v direction="$direction" '
        { line[NR]=$0; if ($1==wanted) pos=NR }
        END {
          target=(direction=="up" ? pos-1 : pos+1)
          if (target >= 1 && target <= NR) { temp=line[pos]; line[pos]=line[target]; line[target]=temp }
          for(i=1;i<=NR;i++){split(line[i],field,"\t");field[4]=i-1;out=field[1];for(j=2;j<=6;j++)out=out OFS field[j];print out}
        }
      ' > "$sources.new" || { rm -rf "$tmp"; return 74; }
      mv "$sources.new" "$sources" || { rm -rf "$tmp"; return 74; }
      ;;
    remove-source:2)
      local id=$2
      source_registry_exists "$sources" "$id" || { rm -rf "$tmp"; return 65; }
      "$BB" awk -F '\t' -v wanted="$id" '$1!=wanted{print}' "$sources" > "$sources.new" || return 74
      mv "$sources.new" "$sources" || { rm -rf "$tmp"; return 74; }
      source_registry_normalize_orders "$sources" || { rm -rf "$tmp"; return 65; }
      removed_id=$id
      ;;
    set-overrides:2)
      overrides_decode "$2" "$overrides_file" || { rm -rf "$tmp"; return 65; }
      ;;
    set-lists:3)
      config_decode_domain_list "$2" "$blocklist" || { rm -rf "$tmp"; return 65; }
      config_decode_domain_list "$3" "$allowlist" || { rm -rf "$tmp"; return 65; }
      ;;
    set-domain-decision:3)
      local decision=$2 domain_b64=$3 domain_file="$RULE_TMP/domain-decision-config.$$" domain result
      [ "$decision" = allow ] || [ "$decision" = block ] || { rm -rf "$tmp"; return 65; }
      config_b64_valid "$domain_b64" || { rm -rf "$tmp"; return 65; }
      printf '%s' "$domain_b64" | "$BB" base64 -d > "$domain_file" 2>/dev/null || { rm -f "$domain_file"; rm -rf "$tmp"; return 65; }
      domain=$(config_read_canonical_domain_file "$domain_file") || {
        result=$?
        rm -f "$domain_file"
        rm -rf "$tmp"
        return "$result"
      }
      rm -f "$domain_file"
      "$BB" awk -v domain="$domain" '$0 != domain' "$blocklist" > "$blocklist.new" || { rm -rf "$tmp"; return 74; }
      "$BB" awk -v domain="$domain" '$0 != domain' "$allowlist" > "$allowlist.new" || { rm -rf "$tmp"; return 74; }
      if [ "$decision" = allow ]; then
        printf '%s\n' "$domain" >> "$allowlist.new" || { rm -rf "$tmp"; return 74; }
      else
        printf '%s\n' "$domain" >> "$blocklist.new" || { rm -rf "$tmp"; return 74; }
      fi
      LC_ALL=C "$BB" sort -u "$blocklist.new" -o "$blocklist.new" || { rm -rf "$tmp"; return 74; }
      LC_ALL=C "$BB" sort -u "$allowlist.new" -o "$allowlist.new" || { rm -rf "$tmp"; return 74; }
      config_validate_domain_list_file "$blocklist.new" || { rm -rf "$tmp"; return 65; }
      config_validate_domain_list_file "$allowlist.new" || { rm -rf "$tmp"; return 65; }
      mv "$blocklist.new" "$blocklist" || { rm -rf "$tmp"; return 74; }
      mv "$allowlist.new" "$allowlist" || { rm -rf "$tmp"; return 74; }
      ;;
    *) rm -rf "$tmp"; return 64 ;;
  esac

  source_registry_validate_file "$sources" || { rm -rf "$tmp"; return 65; }
  config_commit_dir "$new_rev" || { result=$?; rm -rf "$tmp"; return "$result"; }
  if [ "$verb" = reset-rules ]; then
    mode_set_locked block_all || return
  fi
  [ -z "$removed_id" ] || source_registry_remove_cache "$removed_id" || return
  config_prune_custom_cache "$new_rev" || return
  # 来源一旦被停用就立刻清掉它的缓存副本，不用再等用户手动点“清理缓存”。
  config_clear_disabled_cache "$new_rev" >/dev/null || return
}

config_import_file_size_le() {
  local file=$1 maximum=$2 bytes
  bytes=$(wc -c < "$file" | "$BB" tr -d ' ') || return 74
  case "$bytes" in ''|*[!0-9]*) return 74 ;; esac
  [ "$bytes" -le "$maximum" ] 2>/dev/null || return 65
}

config_import_validate_notice_file() {
  [ -f "$1" ] && [ ! -L "$1" ] || return 66
  config_import_file_size_le "$1" 64 || return
  preferences_validate_notice_file "$1"
}

config_import_validate_history_file() {
  local file=$1
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  config_import_file_size_le "$file" 128 || return
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2 || $1!~/^(schema_version|history_enabled)$/ || seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    $1=="history_enabled" && $2!~/^[01]$/{bad()}
    END{if(NR!=2 || !seen["schema_version"] || !seen["history_enabled"])bad()}
  ' "$file"
}

config_import_validate_refresh_file() {
  local file=$1
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  config_import_file_size_le "$file" 256 || return
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2 || $1!~/^(schema_version|auto_refresh_enabled|auto_refresh_interval_hours)$/ || seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    $1=="auto_refresh_enabled" && $2!~/^[01]$/{bad()}
    $1=="auto_refresh_interval_hours" && $2!~/^(6|12|24)$/{bad()}
    END{if(NR!=3 || !seen["schema_version"] || !seen["auto_refresh_enabled"] || !seen["auto_refresh_interval_hours"])bad()}
  ' "$file"
}

config_import_validate_app_state_file() {
  local file=$1
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  config_import_file_size_le "$file" 256 || return
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2 || $1!~/^(schema_version|enabled|mode|updated_at)$/ || seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    $1=="enabled" && $2!~/^[01]$/{bad()}
    $1=="mode" && $2!~/^(off|block_selected|allow_resolved)$/{bad()}
    $1=="updated_at" && $2!~/^[0-9]+$/{bad()}
    END{if(NR!=4 || !seen["schema_version"] || !seen["enabled"] || !seen["mode"] || !seen["updated_at"])bad()}
  ' "$file"
}

config_import_validate_app_uid_file() {
  local file=$1 count=0 uid previous=
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  config_import_file_size_le "$file" 4096 || return
  while IFS= read -r uid || [ -n "$uid" ]; do
    [ -n "$uid" ] || continue
    decimal_uint_in_range "$uid" 4294967294 10000 || return 65
    [ "$uid" != "$previous" ] || return 65
    previous=$uid
    count=$((count + 1))
    [ "$count" -le 256 ] || return 65
  done < "$file"
  [ "$count" -eq 0 ] || LC_ALL=C "$BB" sort -n "$file" | "$BB" cmp -s - "$file" || return 65
}

config_import_validate_app_ip_file() {
  local file=$1 count=0 ip previous=
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  config_import_file_size_le "$file" 131072 || return
  while IFS= read -r ip || [ -n "$ip" ]; do
    [ -n "$ip" ] || continue
    overrides_ip_family "$ip" >/dev/null || return 65
    [ "$ip" != "$previous" ] || return 65
    previous=$ip
    count=$((count + 1))
    [ "$count" -le 2048 ] || return 65
  done < "$file"
  [ "$count" -eq 0 ] || LC_ALL=C "$BB" sort "$file" | "$BB" cmp -s - "$file" || return 65
}

config_import_validate_app_policy_dir() {
  local dir=$1 state="$1/app-policy.prop" uids="$1/app-policy-uids.tsv" ips="$1/app-policy-ips.tsv" enabled mode
  config_import_validate_app_state_file "$state" || return
  config_import_validate_app_uid_file "$uids" || return
  config_import_validate_app_ip_file "$ips" || return
  enabled=$("$BB" awk -F= '$1=="enabled"{print $2}' "$state") || return 74
  mode=$("$BB" awk -F= '$1=="mode"{print $2}' "$state") || return 74
  case "$enabled:$mode" in
    0:off) ;;
    1:block_selected) [ -s "$uids" ] || return 65 ;;
    1:allow_resolved) [ -s "$uids" ] && [ -s "$ips" ] || return 65 ;;
    *) return 65 ;;
  esac
}

config_import_stage_valid_file() {
  local old_dir=$1 stage=$2 name=$3 validator=$4 source="$1/$3" target="$2/$3"
  [ -e "$source" ] || [ -L "$source" ] || return 0
  "$validator" "$source" >/dev/null 2>&1 || return 0
  "$BB" cp -P "$source" "$target" || return 74
  "$validator" "$target" >/dev/null 2>&1 || { rm -f "$target"; return 0; }
  chmod 0600 "$target" 2>/dev/null || true
}

config_import_stage_app_policy() {
  local old_dir=$1 stage=$2 file present=0
  for file in app-policy.prop app-policy-uids.tsv app-policy-ips.tsv; do
    [ ! -e "$old_dir/$file" ] && [ ! -L "$old_dir/$file" ] || present=$((present + 1))
  done
  [ "$present" -eq 0 ] && return 0
  [ "$present" -eq 3 ] || return 0
  config_import_validate_app_policy_dir "$old_dir" >/dev/null 2>&1 || return 0
  for file in app-policy.prop app-policy-uids.tsv app-policy-ips.tsv; do
    "$BB" cp -P "$old_dir/$file" "$stage/$file" || {
      rm -f "$stage/app-policy.prop" "$stage/app-policy-uids.tsv" "$stage/app-policy-ips.tsv"
      return 74
    }
  done
  config_import_validate_app_policy_dir "$stage" >/dev/null 2>&1 || {
    rm -f "$stage/app-policy.prop" "$stage/app-policy-uids.tsv" "$stage/app-policy-ips.tsv"
    return 0
  }
  chmod 0600 "$stage/app-policy.prop" "$stage/app-policy-uids.tsv" "$stage/app-policy-ips.tsv" 2>/dev/null || true
}

config_import_active() {
  [ "$#" -eq 1 ] || return 64
  local old_dir=$1 active_dir=${CONFIG_ACTIVE_MODULE:-/data/adb/modules/zhulong_hosts/config}
  local rev expected actual embedded old_snapshot format tmp final meta_tmp pointer_tmp mode mode_tmp result source_file
  local migrated_file cleanup_file installed_files=
  [ "$old_dir" = "$active_dir" ] || return 64
  [ -d "$old_dir" ] && [ ! -L "$old_dir" ] || return 66
  [ "$CONFIG_DIR" != "$old_dir" ] || return 64
  [ ! -e "$CONFIG_DIR/current.prop" ] || return 76
  for migrated_file in mode.prop notice.prop history.conf refresh.conf \
    app-policy.prop app-policy-uids.tsv app-policy-ips.tsv; do
    [ ! -e "$CONFIG_DIR/$migrated_file" ] && [ ! -L "$CONFIG_DIR/$migrated_file" ] || return 76
  done
  [ -f "$old_dir/current.prop" ] && [ ! -L "$old_dir/current.prop" ] || return 66
  [ -f "$old_dir/mode.prop" ] && [ ! -L "$old_dir/mode.prop" ] || return 66
  config_validate_pointer "$old_dir/current.prop" || return
  rev=$(pointer_value sources_revision "$old_dir/current.prop") || return 74
  expected=$(pointer_value snapshot_sha256 "$old_dir/current.prop") || return 74
  case "$rev" in ''|*[!0-9]*) return 65 ;; esac
  [ "${#rev}" -le 9 ] || return 65
  old_snapshot="$old_dir/revisions/$rev"
  [ -d "$old_snapshot" ] && [ ! -L "$old_snapshot" ] || return 66

  if [ -f "$old_snapshot/custom-sources.tsv" ]; then
    format=v1
    actual=$(config_v1_snapshot_sha256 "$old_snapshot" 2>/dev/null) || return 65
  elif [ -f "$old_snapshot/enhanced-whitelist.conf" ]; then
    format=v2
    actual=$(config_v2_snapshot_sha256 "$old_snapshot" 2>/dev/null) || return 65
  else
    format=v3
    actual=$(snapshot_sha256 "$old_snapshot" 2>/dev/null) || return 65
  fi
  [ "$expected" = "$actual" ] || return 70
  embedded=$("$BB" awk -F= '$1=="sources_revision"{print $2}' "$old_snapshot/rules.conf") || return 74
  [ "$embedded" = "$rev" ] || return 70
  mode=$(config_mode_value "$old_dir/mode.prop") || return

  tmp="$CONFIG_DIR/revisions/$rev.import.$$"
  final="$CONFIG_DIR/revisions/$rev"
  meta_tmp="$CONFIG_DIR/import-meta.$$"
  [ ! -e "$tmp" ] && [ ! -L "$tmp" ] && [ ! -e "$final" ] && [ ! -L "$final" ] || return 76
  [ ! -e "$meta_tmp" ] && [ ! -L "$meta_tmp" ] || return 76
  mkdir -p "$tmp" "$meta_tmp" || return 73
  config_import_stage_valid_file "$old_dir" "$meta_tmp" notice.prop config_import_validate_notice_file || {
    result=$?; rm -rf "$tmp" "$meta_tmp"; return "$result"
  }
  config_import_stage_valid_file "$old_dir" "$meta_tmp" history.conf config_import_validate_history_file || {
    result=$?; rm -rf "$tmp" "$meta_tmp"; return "$result"
  }
  config_import_stage_valid_file "$old_dir" "$meta_tmp" refresh.conf config_import_validate_refresh_file || {
    result=$?; rm -rf "$tmp" "$meta_tmp"; return "$result"
  }
  config_import_stage_app_policy "$old_dir" "$meta_tmp" || {
    result=$?; rm -rf "$tmp" "$meta_tmp"; return "$result"
  }
  case "$format" in
    v3)
      set -- rules.conf sources.tsv overrides.tsv manual-blocklist.txt manual-allowlist.txt
      ;;
    v2)
      set -- rules.conf sources.tsv overrides.tsv manual-blocklist.txt manual-allowlist.txt \
        enhanced-whitelist.conf enhanced-whitelist-manual.txt
      ;;
    *)
      set -- rules.conf custom-sources.tsv manual-blocklist.txt manual-allowlist.txt \
        enhanced-whitelist.conf enhanced-whitelist-manual.txt
      ;;
  esac
  for source_file do
    [ -f "$old_snapshot/$source_file" ] && [ ! -L "$old_snapshot/$source_file" ] || {
      rm -rf "$tmp" "$meta_tmp"
      return 66
    }
    cp "$old_snapshot/$source_file" "$tmp/$source_file" || {
      rm -rf "$tmp" "$meta_tmp"
      return 74
    }
  done
  mv "$tmp" "$final" || { rm -rf "$tmp" "$meta_tmp"; return 74; }

  mode_tmp="$CONFIG_DIR/mode.prop.tmp.$$"
  printf 'desired_mode=%s\n' "$mode" > "$mode_tmp" || {
    rm -f "$mode_tmp"
    rm -rf "$final" "$meta_tmp"
    return 74
  }
  atomic_replace_file "$mode_tmp" "$CONFIG_DIR/mode.prop" || {
    result=$?
    rm -f "$mode_tmp" "$CONFIG_DIR/mode.prop"
    rm -rf "$final" "$meta_tmp"
    return "$result"
  }
  for migrated_file in notice.prop history.conf refresh.conf \
    app-policy.prop app-policy-uids.tsv app-policy-ips.tsv; do
    [ -f "$meta_tmp/$migrated_file" ] && [ ! -L "$meta_tmp/$migrated_file" ] || continue
    atomic_replace_file "$meta_tmp/$migrated_file" "$CONFIG_DIR/$migrated_file" || {
      result=$?
      for cleanup_file in $installed_files; do rm -f "$CONFIG_DIR/$cleanup_file"; done
      rm -f "$CONFIG_DIR/mode.prop"
      rm -rf "$final" "$meta_tmp"
      return "$result"
    }
    installed_files="$installed_files $migrated_file"
  done

  pointer_tmp="$CONFIG_DIR/current.prop.tmp.$$"
  printf 'sources_revision=%s\nsnapshot_sha256=%s\n' "$rev" "$expected" > "$pointer_tmp" || {
    for cleanup_file in $installed_files; do rm -f "$CONFIG_DIR/$cleanup_file"; done
    rm -f "$CONFIG_DIR/mode.prop" "$pointer_tmp"
    rm -rf "$final" "$meta_tmp"
    return 74
  }
  atomic_replace_file "$pointer_tmp" "$CONFIG_DIR/current.prop" || {
    result=$?
    for cleanup_file in $installed_files; do rm -f "$CONFIG_DIR/$cleanup_file"; done
    rm -f "$CONFIG_DIR/mode.prop" "$pointer_tmp" "$CONFIG_DIR/current.prop"
    rm -rf "$final" "$meta_tmp"
    return "$result"
  }
  rmdir "$meta_tmp" 2>/dev/null || true
}
