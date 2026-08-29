#!/system/bin/sh

GEN_MAX_DOMAINS_DEFAULT=500000
GEN_MAX_BYTES_DEFAULT=33554432
# 合并缓存的格式版本。改了指纹口径或合并算法就加一，旧缓存自动失效。
GEN_MERGE_CACHE_VERSION=1

generation_merge_cache_dir() {
  printf '%s\n' "${CACHE_DIR:-$MODDIR/cache}/merge"
}

# 合并结果只由「基线 + 各启用来源的优先级与归一化内容 + 归一化脚本本身」决定。
# 黑白名单、例外、奖励广告全都在合并之后才参与，所以存名单前后拿到的是同一个指纹。
# contrib 里的 path 带着 job.$$ 的进程号，每次都不一样，指纹只取前三列。
generation_merge_fingerprint() {
  local contrib=$1 base_sha=$2 lib_dir norm_sha norm_custom_sha
  lib_dir=${RULE_LIB_DIR:-$MODDIR/lib/rules}
  norm_sha=$(sha256_file "$lib_dir/normalize.awk") || return 66
  norm_custom_sha=$(sha256_file "$lib_dir/normalize-custom.awk") || return 66
  {
    printf 'version=%s\nbase=%s\nnormalize=%s\nnormalize_custom=%s\n' \
      "$GEN_MERGE_CACHE_VERSION" "$base_sha" "$norm_sha" "$norm_custom_sha"
    "$BB" awk -F '\t' '{print $1 "\t" $2 "\t" $3}' "$contrib" | LC_ALL=C "$BB" sort
  } | sha256_file_stdin
}

generation_merge_cache_load() {
  local fingerprint=$1 dest=$2 dir meta rows version stored_fp stored_sha extra
  dir=$(generation_merge_cache_dir)
  meta="$dir/$fingerprint.prop"
  [ -f "$meta" ] && [ ! -L "$meta" ] || return 1
  [ -f "$dir/$fingerprint.tsv" ] && [ ! -L "$dir/$fingerprint.tsv" ] || return 1
  IFS="$(printf '\t')" read -r version stored_fp stored_sha rows extra < "$meta" || return 1
  [ -z "$extra" ] || return 1
  [ "$version" = "$GEN_MERGE_CACHE_VERSION" ] || return 1
  [ "$stored_fp" = "$fingerprint" ] || return 1
  case "$rows" in ''|*[!0-9]*) return 1 ;; esac
  # 摘要现算现比：缓存被截断或改写过就当它不存在，回去重新合并一次。
  [ "$stored_sha" = "$(sha256_file "$dir/$fingerprint.tsv")" ] || return 1
  cp "$dir/$fingerprint.tsv" "$dest" || return 1
}

# 缓存只是加速手段，写不进去不该让这一代失败，所以全程不往外报错。
# 先落内容再落元数据：元数据缺失或对不上只会让下一次miss，不会读到半份内容。
generation_merge_cache_store() {
  local fingerprint=$1 merged=$2 dir rows sha entry
  dir=$(generation_merge_cache_dir)
  mkdir -p "$dir" 2>/dev/null || return 0
  rows=$("$BB" awk 'END{print NR+0}' "$merged" 2>/dev/null) || return 0
  sha=$(sha256_file "$merged" 2>/dev/null) || return 0
  rm -f "$dir/$fingerprint.prop"
  cp "$merged" "$dir/$fingerprint.tsv.new" 2>/dev/null || {
    rm -f "$dir/$fingerprint.tsv.new"
    return 0
  }
  mv -f "$dir/$fingerprint.tsv.new" "$dir/$fingerprint.tsv" 2>/dev/null || {
    rm -f "$dir/$fingerprint.tsv.new"
    return 0
  }
  printf '%s\t%s\t%s\t%s\n' "$GEN_MERGE_CACHE_VERSION" "$fingerprint" "$sha" "$rows" \
    > "$dir/$fingerprint.prop.new" 2>/dev/null || {
    rm -f "$dir/$fingerprint.prop.new"
    return 0
  }
  mv -f "$dir/$fingerprint.prop.new" "$dir/$fingerprint.prop" 2>/dev/null || {
    rm -f "$dir/$fingerprint.prop.new"
    return 0
  }
  # 只留当前这一份：来源换了内容，旧指纹再也不会命中，留着白占空间。
  for entry in "$dir"/*; do
    [ -e "$entry" ] || continue
    case "${entry##*/}" in "$fingerprint.tsv"|"$fingerprint.prop") continue ;; esac
    rm -f "$entry"
  done
  return 0
}

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

# 只用于已按域名排序的行（overrides_apply 结尾就是 sort -k1,1 -k2,2 -u）。
# 排好序时相邻比较就够，不必为十几万个域名建一张哈希表——那是这一步的峰值内存，
# 而手机上内存压力正是 crond 和读取进程被杀的原因。
generation_domain_count() {
  "$BB" awk -F '\t' 'NF && $1!=prev{n++; prev=$1} END{print n+0}' "$1"
}

# 例外表为空时 overrides_apply 的输出就等于输入，可它照样要把十几万行流一遍再整份排序，
# 「存名单」「改来源」这类操作每次都白跑两遍。绝大多数用户一条例外都没设，这一段最划算。
# 注意：文件不存在不算空——那是配置损坏，仍旧交给 overrides_apply 去报错。
generation_overrides_absent() {
  local file=$1
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  "$BB" awk 'NF{found=1; exit} END{exit found?1:0}' "$file"
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
  # 基线的归一化挪到合并那一段里去了：命中合并缓存时它的结果没人再用，白跑一趟。
  normalize_hosts "$rules_dir/recovery.hosts" "$recovery_norm" || { rm -rf "$tmp"; return 65; }

  records="$tmp/records.tsv"
  remote_allow_domains="$tmp/remote-allow-domains.tsv"
  : > "$remote_allow_domains"
  manual_blocklist="$CONFIG_DIR/revisions/$rev/manual-blocklist.txt"
  manual_allowlist="$CONFIG_DIR/revisions/$rev/manual-allowlist.txt"
  # 把每个启用来源的归一化规则按优先级并入候选集；来源自带的例外规则进入最终放行名单。
  # 停用某个来源只是让它这一代不参与合并，缓存与配置都留着，重新启用后下一代就会恢复。
  local priority id kind enabled state updated count sha url_sha path allow_count skipped_count allow_path source_error extra
  local source_row_count=0 enabled_source_count=0 contrib="$tmp/contrib.tsv"
  : > "$contrib"
  while IFS="$(printf '\t')" read -r priority id kind enabled state updated count sha url_sha path allow_count skipped_count allow_path source_error extra || \
    [ -n "${priority}${id}${kind}${enabled}${state}${updated}${count}${sha}${url_sha}${path}${allow_count}${skipped_count}${allow_path}${source_error}${extra}" ]; do
    [ -n "$id" ] || continue
    [ -z "$extra" ] || { rm -rf "$tmp"; return 65; }
    case "$priority" in ''|*[!0-9]*) rm -rf "$tmp"; return 65 ;; esac
    case "$count:$allow_count:$skipped_count" in *[!0-9:]*) rm -rf "$tmp"; return 65 ;; esac
    source_row_count=$((source_row_count + 1))
    [ "$enabled" = 1 ] || continue
    enabled_source_count=$((enabled_source_count + 1))
    [ "$state" = fresh ] || [ "$state" = stale ] || continue
    case "$path" in "$work/normalized/"*.tsv) ;; *) rm -rf "$tmp"; return 65 ;; esac
    [ -f "$path" ] || { rm -rf "$tmp"; return 66; }
    printf '%s\t%s\t%s\t%s\n' "$priority" "$id" "$sha" "$path" >> "$contrib" || { rm -rf "$tmp"; return 74; }
    if [ "$allow_count" -gt 0 ]; then
      case "$allow_path" in "$work/normalized/"*.tsv.allow) ;; *) rm -rf "$tmp"; return 65 ;; esac
      [ -f "$allow_path" ] || { rm -rf "$tmp"; return 66; }
      cat "$allow_path" >> "$remote_allow_domains" || { rm -rf "$tmp"; return 74; }
    fi
  done < "$work/sources.tsv"

  # 合并这一步要把十几万到几十万条规则排两遍，是整条流水线里最贵的一段，也是
  # 手机上「存个名单要等很久、还烫手」的来源。但它只取决于基线和各启用来源的内容：
  # 存黑白名单、改例外、点历史里的放行/拦截都不会改变它。所以按指纹缓存合并结果，
  # 这类操作直接复用，只跑后面那段便宜的过滤与落盘。
  local merge_base_sha merge_fingerprint merge_cached=0
  merged="$tmp/merged.tsv"
  merge_base_sha=$(sha256_file "$rules_dir/base.hosts") || { rm -rf "$tmp"; return 66; }
  merge_fingerprint=$(generation_merge_fingerprint "$contrib" "$merge_base_sha") || merge_fingerprint=
  if [ -n "$merge_fingerprint" ] && generation_merge_cache_load "$merge_fingerprint" "$merged"; then
    merge_cached=1
  else
    normalize_hosts "$rules_dir/base.hosts" "$base_norm" || { rm -rf "$tmp"; return 65; }
    "$BB" awk -F '\t' 'NF==2{print "0\t" $1 "\t" $2}' "$base_norm" > "$records"
    while IFS="$(printf '\t')" read -r priority id sha path || [ -n "${priority}${id}${sha}${path}" ]; do
      [ -n "$path" ] || continue
      "$BB" awk -F '\t' -v p="$priority" 'NF==2{print p "\t" $1 "\t" $2}' "$path" >> "$records" || { rm -rf "$tmp"; return 74; }
    done < "$contrib"
    LC_ALL=C "$BB" sort -t "$(printf '\t')" -k2,2 -k1,1nr -k3,3 "$records" | \
      "$BB" awk -F '\t' '
        $2 != current { current=$2; chosen=$1 }
        $1 == chosen { print $2 "\t" $3 }
      ' | LC_ALL=C "$BB" sort -u > "$merged" || { rm -rf "$tmp"; return 74; }
    [ -z "$merge_fingerprint" ] || generation_merge_cache_store "$merge_fingerprint" "$merged"
  fi

  # 手工黑名单以前是以 999999 优先级并进合并前的候选集的。它的优先级高于任何来源、
  # 地址恒为 0.0.0.0，所以「合并后把这些域名的行换成 0.0.0.0」与原来完全等价——
  # 而这样一来名单就不再是合并的输入，改名单才能命中上面的缓存。
  # 位置必须留在奖励广告拆分之前，否则会改变「手工拦截 + 奖励例外」这一组的既有行为。
  if [ -f "$manual_blocklist" ] && [ -f "$manual_allowlist" ]; then
    "$BB" awk -F '\t' '
      FILENAME==ARGV[1] { if (NF && $1 != "") blocked[$1]=1; next }
      !($1 in blocked) { print }
    ' "$manual_blocklist" "$merged" > "$merged.blocked" || { rm -rf "$tmp"; return 74; }
    # 追加的手工黑名单行破坏了合并结果的有序性，而后面的域名计数靠相邻比较、跳过例外表
    # 也要求输入有序。两边各自有序，用 sort -m 归并即可，不必为几十条新增再整份排一遍。
    "$BB" awk 'NF && !seen[$1]++{print $1 "\t0.0.0.0"}' "$manual_blocklist" \
      | LC_ALL=C "$BB" sort -u > "$merged.added" || { rm -rf "$tmp"; return 74; }
    LC_ALL=C "$BB" sort -m -u "$merged.blocked" "$merged.added" > "$merged" || { rm -rf "$tmp"; return 74; }
    rm -f "$merged.blocked" "$merged.added"
  fi

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
  # 直接管进 sort，省掉一次十几万行的整份复制。
  {
    cat "$reward_rows"
    "$BB" awk 'NF{print $1 "\t0.0.0.0"}' "$reward_domains"
  } | LC_ALL=C "$BB" sort -u > "$all_rows" || { rm -rf "$tmp"; return 74; }

  all_filtered="$tmp/all-filtered.tsv"
  reward_filtered="$tmp/reward-filtered.tsv"
  "$BB" awk -F '\t' 'FILENAME==ARGV[1]{allowed[$1]=1; next} !($1 in allowed){print}' \
    "$whitelist_domains" "$all_rows" > "$all_filtered"
  "$BB" awk -F '\t' 'FILENAME==ARGV[1]{allowed[$1]=1; next} !($1 in allowed){print}' \
    "$whitelist_domains" "$reward_rows" > "$reward_filtered"

  overrides_file="$CONFIG_DIR/revisions/$rev/overrides.tsv"
  all_overridden="$tmp/all-overridden.tsv"
  reward_overridden="$tmp/reward-overridden.tsv"
  # 没有任何例外时结果与输入逐字节相同（两份输入到这里都已经是 sort -u 的产物），
  # 直接沿用，省掉两趟十几万行的流式过滤加整份排序。
  if generation_overrides_absent "$overrides_file"; then
    all_overridden=$all_filtered
    reward_overridden=$reward_filtered
  else
    overrides_apply "$all_filtered" "$overrides_file" "$all_overridden" || { rm -rf "$tmp"; return 65; }
    overrides_apply "$reward_filtered" "$overrides_file" "$reward_overridden" || { rm -rf "$tmp"; return 65; }
  fi
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
