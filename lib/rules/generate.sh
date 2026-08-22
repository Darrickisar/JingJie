#!/system/bin/sh

GEN_MAX_DOMAINS_DEFAULT=500000
GEN_MAX_BYTES_DEFAULT=33554432

manifest_value() {
  local file=$1 key=$2
  "$BB" awk -F= -v wanted="$key" '$1==wanted{print $2}' "$file"
}

generation_rows_to_hosts() {
  local rows=$1 output=$2
  {
    printf '127.0.0.1 localhost\n'
    printf '::1 localhost\n'
    "$BB" awk -F '\t' 'NF==2{print $2 " " $1}' "$rows"
  } > "$output"
}

generation_domain_count() {
  "$BB" awk -F '\t' 'NF && !seen[$1]++{n++} END{print n+0}' "$1"
}

generation_cleanup_outputs() {
  local work=$1
  rm -f "$work/all" "$work/reward" "$work/recovery" "$work/manifest.prop"
}

build_generation() {
  local work=$1 rev=$2 rules_dir tmp base_norm recovery_norm records merged reward_domains whitelist_domains remote_allow_domains manual_blocklist manual_allowlist result
  local all_rows reward_rows all_filtered reward_filtered overrides_file all_overridden reward_overridden all_count reward_count max_domains max_bytes
  case "$rev" in ''|*[!0-9]*) return 65 ;; esac
  rules_dir=${RULES_DIR:-$MODDIR/rules}
  [ -f "$rules_dir/base.hosts" ] && [ -f "$rules_dir/recovery.hosts" ] || return 66
  [ -f "$work/sources.tsv" ] || return 66
  mkdir -p "$work" || return 73
  generation_cleanup_outputs "$work"
  tmp="$work/.generation.$$"
  rm -rf "$tmp"
  mkdir -p "$tmp" || return 73
  base_norm="$tmp/base.tsv"
  recovery_norm="$tmp/recovery.tsv"
  normalize_hosts "$rules_dir/base.hosts" "$base_norm" || { rm -rf "$tmp"; return 65; }
  normalize_hosts "$rules_dir/recovery.hosts" "$recovery_norm" || { rm -rf "$tmp"; return 65; }

  records="$tmp/records.tsv"
  "$BB" awk -F '\t' 'NF==2{print "0\t" $1 "\t" $2}' "$base_norm" > "$records"
  remote_allow_domains="$tmp/remote-allow-domains.tsv"
  : > "$remote_allow_domains"
  manual_blocklist="$CONFIG_DIR/revisions/$rev/manual-blocklist.txt"
  manual_allowlist="$CONFIG_DIR/revisions/$rev/manual-allowlist.txt"
  if [ -f "$manual_blocklist" ] && [ -f "$manual_allowlist" ]; then
    "$BB" awk 'NF{print "999999\t" $1 "\t0.0.0.0"}' "$manual_blocklist" >> "$records" || { rm -rf "$tmp"; return 74; }
  fi
  # 把每个启用来源的归一化规则按优先级并入候选集；来源自带的例外规则进入最终放行名单。
  local priority id kind enabled state updated count sha url_sha path allow_count skipped_count allow_path source_error extra
  while IFS="$(printf '\t')" read -r priority id kind enabled state updated count sha url_sha path allow_count skipped_count allow_path source_error extra || \
    [ -n "${priority}${id}${kind}${enabled}${state}${updated}${count}${sha}${url_sha}${path}${allow_count}${skipped_count}${allow_path}${source_error}${extra}" ]; do
    [ -n "$id" ] || continue
    [ -z "$extra" ] || { rm -rf "$tmp"; return 65; }
    case "$priority" in ''|*[!0-9]*) rm -rf "$tmp"; return 65 ;; esac
    case "$count:$allow_count:$skipped_count" in *[!0-9:]*) rm -rf "$tmp"; return 65 ;; esac
    [ "$enabled" = 1 ] || continue
    [ "$state" = fresh ] || [ "$state" = stale ] || continue
    case "$path" in "$work/normalized/"*.tsv) ;; *) rm -rf "$tmp"; return 65 ;; esac
    [ -f "$path" ] || { rm -rf "$tmp"; return 66; }
    "$BB" awk -F '\t' -v p="$priority" 'NF==2{print p "\t" $1 "\t" $2}' "$path" >> "$records"
    if [ "$allow_count" -gt 0 ]; then
      case "$allow_path" in "$work/normalized/"*.tsv.allow) ;; *) rm -rf "$tmp"; return 65 ;; esac
      [ -f "$allow_path" ] || { rm -rf "$tmp"; return 66; }
      cat "$allow_path" >> "$remote_allow_domains" || { rm -rf "$tmp"; return 74; }
    fi
  done < "$work/sources.tsv"
  merged="$tmp/merged.tsv"
  LC_ALL=C "$BB" sort -t "$(printf '\t')" -k2,2 -k1,1nr -k3,3 "$records" | \
    "$BB" awk -F '\t' '
      $2 != current { current=$2; chosen=$1 }
      $1 == chosen { print $2 "\t" $3 }
    ' | LC_ALL=C "$BB" sort -u > "$merged" || { rm -rf "$tmp"; return 74; }

  reward_domains="$tmp/reward-domains.tsv"
  whitelist_domains="$tmp/whitelist-domains.tsv"
  normalize_hosts "$MODDIR/广告奖励.prop" "$tmp/reward-records.tsv" || { rm -rf "$tmp"; return 65; }
  if [ -f "$manual_allowlist" ]; then
    cp "$manual_allowlist" "$tmp/whitelist-records.tsv" || { rm -rf "$tmp"; return 74; }
  else
    : > "$tmp/whitelist-records.tsv"
  fi
  "$BB" awk -F '\t' '!seen[$1]++{print $1}' "$tmp/reward-records.tsv" > "$reward_domains"
  {
    "$BB" awk -F '\t' '!seen[$1]++{print $1}' "$tmp/whitelist-records.tsv"
    cat "$remote_allow_domains"
  } | LC_ALL=C "$BB" sort -u > "$whitelist_domains"

  all_rows="$tmp/all-rows.tsv"
  reward_rows="$tmp/reward-rows.tsv"
  "$BB" awk -F '\t' 'FILENAME==ARGV[1]{blocked[$1]=1; next} !($1 in blocked){print}' \
    "$reward_domains" "$merged" > "$reward_rows"
  cp "$reward_rows" "$all_rows" || { rm -rf "$tmp"; return 74; }
  "$BB" awk 'NF{print $1 "\t0.0.0.0"}' "$reward_domains" >> "$all_rows"
  LC_ALL=C "$BB" sort -u "$all_rows" -o "$all_rows"

  all_filtered="$tmp/all-filtered.tsv"
  reward_filtered="$tmp/reward-filtered.tsv"
  "$BB" awk -F '\t' 'FILENAME==ARGV[1]{allowed[$1]=1; next} !($1 in allowed){print}' \
    "$whitelist_domains" "$all_rows" > "$all_filtered"
  "$BB" awk -F '\t' 'FILENAME==ARGV[1]{allowed[$1]=1; next} !($1 in allowed){print}' \
    "$whitelist_domains" "$reward_rows" > "$reward_filtered"

  overrides_file="$CONFIG_DIR/revisions/$rev/overrides.tsv"
  all_overridden="$tmp/all-overridden.tsv"
  reward_overridden="$tmp/reward-overridden.tsv"
  overrides_apply "$all_filtered" "$overrides_file" "$all_overridden" || { rm -rf "$tmp"; return 65; }
  overrides_apply "$reward_filtered" "$overrides_file" "$reward_overridden" || { rm -rf "$tmp"; return 65; }
  all_filtered=$all_overridden
  reward_filtered=$reward_overridden

  max_domains=${GEN_MAX_DOMAINS:-$GEN_MAX_DOMAINS_DEFAULT}
  max_bytes=${GEN_MAX_BYTES:-$GEN_MAX_BYTES_DEFAULT}
  all_count=$(generation_domain_count "$all_filtered")
  reward_count=$(generation_domain_count "$reward_filtered")
  if [ "$all_count" -gt "$max_domains" ] || [ "$reward_count" -gt "$max_domains" ]; then
    rm -rf "$tmp"
    return 65
  fi
  # 「全部模块事件」档位下把这一代的放行/拦截明细写进规则日志，
  # 用户才能核对白名单、来源例外和奖励广告例外到底放行了什么。
  if command -v log_verbose_event >/dev/null 2>&1; then
    local allow_total manual_allow_count remote_allow_count reward_exception_count
    allow_total=$("$BB" awk 'NF{count++} END{print count+0}' "$whitelist_domains" 2>/dev/null) || allow_total=0
    manual_allow_count=$("$BB" awk 'NF{count++} END{print count+0}' "$tmp/whitelist-records.tsv" 2>/dev/null) || manual_allow_count=0
    remote_allow_count=$("$BB" awk 'NF{count++} END{print count+0}' "$remote_allow_domains" 2>/dev/null) || remote_allow_count=0
    reward_exception_count=$("$BB" awk 'NF{count++} END{print count+0}' "$reward_domains" 2>/dev/null) || reward_exception_count=0
    log_verbose_event info generation_allowed \
      "放行 $allow_total 个域名：白名单 $manual_allow_count、来源例外 $remote_allow_count；奖励广告例外 $reward_exception_count" || true
    log_verbose_event info generation_blocked \
      "拦截 $all_count 个域名（保留奖励广告模式 $reward_count 个）" || true
  fi

  generation_rows_to_hosts "$all_filtered" "$tmp/all"
  generation_rows_to_hosts "$reward_filtered" "$tmp/reward"
  generation_rows_to_hosts "$recovery_norm" "$tmp/recovery"
  for output in all reward recovery; do
    bytes=$(wc -c < "$tmp/$output" | tr -d ' ')
    [ "$bytes" -le "$max_bytes" ] || { rm -rf "$tmp"; return 65; }
  done

  local generation_id config_hash base_hash recovery_hash all_hash reward_hash source_count manifest index
  generation_id="g$(date +%s)-r$rev-p$$"
  config_hash=${CONFIG_SNAPSHOT_SHA256:-}
  if [ -z "$config_hash" ] && command -v config_snapshot_hash >/dev/null 2>&1; then
    config_hash=$(config_snapshot_hash "$rev" 2>/dev/null || true)
  fi
  [ -n "$config_hash" ] || config_hash=0000000000000000000000000000000000000000000000000000000000000000
  base_hash=$(sha256_file "$rules_dir/base.hosts")
  recovery_hash=$(sha256_file "$tmp/recovery")
  all_hash=$(sha256_file "$tmp/all")
  reward_hash=$(sha256_file "$tmp/reward")
  source_count=$("$BB" awk 'NF{n++} END{print n+0}' "$work/sources.tsv")
  manifest="$tmp/manifest.prop"
  {
    printf 'schema_version=1\n'
    printf 'generation_id=%s\n' "$generation_id"
    printf 'sources_revision=%s\n' "$rev"
    printf 'config_snapshot_sha256=%s\n' "$config_hash"
    printf 'base_sha256=%s\n' "$base_hash"
    printf 'recovery_sha256=%s\n' "$recovery_hash"
    printf 'all_sha256=%s\n' "$all_hash"
    printf 'reward_sha256=%s\n' "$reward_hash"
    printf 'all_rule_count=%s\n' "$all_count"
    printf 'reward_rule_count=%s\n' "$reward_count"
    printf 'source_count=%s\n' "$source_count"
  } > "$manifest" || { rm -rf "$tmp"; return 74; }

  index=0
  while IFS="$(printf '\t')" read -r priority id kind enabled state updated count sha url_sha path allow_count skipped_count allow_path source_error extra || \
    [ -n "${priority}${id}${kind}${enabled}${state}${updated}${count}${sha}${url_sha}${path}${allow_count}${skipped_count}${allow_path}${source_error}${extra}" ]; do
    [ -n "$id" ] || continue
    index=$((index + 1))
    {
      printf 'source_%s_id=%s\n' "$index" "$id"
      printf 'source_%s_kind=%s\n' "$index" "$kind"
      printf 'source_%s_state=%s\n' "$index" "$state"
      printf 'source_%s_updated_at=%s\n' "$index" "$updated"
      printf 'source_%s_url_sha256=%s\n' "$index" "$url_sha"
      printf 'source_%s_content_sha256=%s\n' "$index" "$sha"
      printf 'source_%s_rule_count=%s\n' "$index" "$count"
      printf 'source_%s_allow_count=%s\n' "$index" "$allow_count"
      printf 'source_%s_skipped_count=%s\n' "$index" "$skipped_count"
      printf 'source_%s_error=%s\n' "$index" "$source_error"
    } >> "$manifest" || { rm -rf "$tmp"; return 74; }
  done < "$work/sources.tsv"

  for output in all reward recovery manifest.prop; do
    mv "$tmp/$output" "$work/$output" || { generation_cleanup_outputs "$work"; rm -rf "$tmp"; return 74; }
  done
  rm -rf "$tmp"
}
