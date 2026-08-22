#!/system/bin/sh

SOURCE_MAX_BYTES=16777216
SOURCE_MAX_DOMAINS=500000
SOURCE_CONNECT_TIMEOUT=10
SOURCE_TIMEOUT=15
SOURCE_CURL_TIMEOUT=7
SOURCE_ATTEMPTS=2
SOURCE_REFRESH_TIMEOUT=480

builtin_source_url() {
  source_registry_builtin_url "$1"
}

source_force_block_addresses() {
  local file=$1 tmp="$1.block.$$"
  [ -f "$file" ] || return 66
  "$BB" awk -F '\t' 'NF==2{print $1 "\t0.0.0.0"}' "$file" | LC_ALL=C "$BB" sort -u > "$tmp" || {
    rm -f "$tmp"
    return 74
  }
  [ -s "$tmp" ] || { rm -f "$tmp"; return 65; }
  atomic_replace_file "$tmp" "$file"
}

source_cache_path() {
  local id=$1 url=$2 hash suffix
  case "$id" in
    awa) SOURCE_CACHE_PATH="$CACHE_DIR/awa.hosts" ;;
    rule10007) SOURCE_CACHE_PATH="$CACHE_DIR/rule10007.hosts" ;;
    enhanced_whitelist)
      hash=$(printf '%s' "$url" | sha256_file_stdin)
      SOURCE_CACHE_PATH="$CACHE_DIR/enhanced-whitelist/$hash.hosts"
      ;;
    custom_[1-9]*)
      suffix=${id#custom_}
      case "$suffix" in *[!0-9]*) return 65 ;; esac
      hash=$(printf '%s' "$url" | sha256_file_stdin)
      SOURCE_CACHE_PATH="$CACHE_DIR/custom/$id/$hash.hosts"
      ;;
    *) return 65 ;;
  esac
  export SOURCE_CACHE_PATH
}

source_cache_path_prepare() {
  [ "$#" -eq 1 ] || return 64
  local cache=$1 parent relative current component old_ifs
  case "$cache" in "$CACHE_DIR"/*) ;; *) return 65 ;; esac
  [ -d "$CACHE_DIR" ] && [ ! -L "$CACHE_DIR" ] || return 65
  parent=${cache%/*}
  if [ "$parent" != "$CACHE_DIR" ]; then
    relative=${parent#"$CACHE_DIR"/}
    [ "$relative" != "$parent" ] || return 65
    current=$CACHE_DIR
    old_ifs=$IFS
    IFS=/
    set -- $relative
    IFS=$old_ifs
    for component in "$@"; do
      [ -n "$component" ] || return 65
      current="$current/$component"
      if [ -e "$current" ] || [ -L "$current" ]; then
        [ -d "$current" ] && [ ! -L "$current" ] || return 65
      else
        mkdir "$current" || return 73
      fi
    done
  fi
  if [ -e "$cache" ] || [ -L "$cache" ]; then
    [ -f "$cache" ] && [ ! -L "$cache" ] || return 65
  fi
}

# Keep refresh diagnostics independent from generation commits.  Only the
# public, bounded source states and errors are projected into this file.
source_diagnostics_write() {
  local source_file=$1 tmp="$RULE_RUNTIME/source-diagnostics.tsv.tmp.$$"
  local priority id kind enabled state updated count sha url_sha path allow_count skipped_count allow_path source_error extra
  [ -f "$source_file" ] || return 66
  mkdir -p "$RULE_RUNTIME" || return 73
  : > "$tmp" || return 74
  while IFS="$(printf '\t')" read -r priority id kind enabled state updated count sha url_sha path allow_count skipped_count allow_path source_error extra || \
    [ -n "${priority}${id}${kind}${enabled}${state}${updated}${count}${sha}${url_sha}${path}${allow_count}${skipped_count}${allow_path}${source_error}${extra}" ]; do
    [ -n "$id" ] || continue
    [ -z "$extra" ] || { rm -f "$tmp"; return 65; }
    case "$id" in awa|rule10007|enhanced_whitelist|custom_[1-9]*) ;; *) rm -f "$tmp"; return 65 ;; esac
    case "$state" in fresh|stale|error|disabled) ;; *) rm -f "$tmp"; return 65 ;; esac
    case "$source_error" in ''|null|unsupported_format|source_unavailable|download_failed_using_cache) ;; *) rm -f "$tmp"; return 65 ;; esac
    if [ "$url_sha" != null ]; then
      [ "${#url_sha}" -eq 64 ] || { rm -f "$tmp"; return 65; }
      case "$url_sha" in *[!0-9a-f]*) rm -f "$tmp"; return 65 ;; esac
    fi
    case "$count:$skipped_count" in *[!0-9:]*) rm -f "$tmp"; return 65 ;; esac
    case "$updated" in ''|*[!0-9]*) rm -f "$tmp"; return 65 ;; esac
    [ "$source_error" = null ] && source_error=
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$id" "$url_sha" "$state" "${source_error:-null}" "$count" "$skipped_count" "$updated" >> "$tmp" || {
      rm -f "$tmp"
      return 74
    }
  done < "$source_file"
  if [ -n "${SOURCE_ENHANCED_DIAGNOSTIC_FILE-}" ] && [ -f "$SOURCE_ENHANCED_DIAGNOSTIC_FILE" ]; then
    id=enhanced_whitelist
    url_sha=$("$BB" awk -F= '$1=="url_sha256"{print $2}' "$SOURCE_ENHANCED_DIAGNOSTIC_FILE") || { rm -f "$tmp"; return 65; }
    state=$("$BB" awk -F= '$1=="state"{print $2}' "$SOURCE_ENHANCED_DIAGNOSTIC_FILE") || { rm -f "$tmp"; return 65; }
    source_error=$("$BB" awk -F= '$1=="error"{print $2}' "$SOURCE_ENHANCED_DIAGNOSTIC_FILE") || { rm -f "$tmp"; return 65; }
    count=$("$BB" awk -F= '$1=="rule_count"{print $2}' "$SOURCE_ENHANCED_DIAGNOSTIC_FILE") || { rm -f "$tmp"; return 65; }
    skipped_count=$("$BB" awk -F= '$1=="skipped_count"{print $2}' "$SOURCE_ENHANCED_DIAGNOSTIC_FILE") || { rm -f "$tmp"; return 65; }
    updated=$("$BB" awk -F= '$1=="updated_at"{print $2}' "$SOURCE_ENHANCED_DIAGNOSTIC_FILE") || { rm -f "$tmp"; return 65; }
    case "$state" in fresh|stale|error|disabled) ;; *) rm -f "$tmp"; return 65 ;; esac
    case "$source_error" in null|unsupported_format|source_unavailable|download_failed_using_cache) ;; *) rm -f "$tmp"; return 65 ;; esac
    case "$url_sha" in null|[0-9a-f][0-9a-f]*) ;; *) rm -f "$tmp"; return 65 ;; esac
    case "$count:$skipped_count:$updated" in *[!0-9:]*) rm -f "$tmp"; return 65 ;; esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$url_sha" "$state" "$source_error" "$count" "$skipped_count" "$updated" >> "$tmp" || {
      rm -f "$tmp"
      return 74
    }
  fi
  atomic_replace_file "$tmp" "$RULE_RUNTIME/source-diagnostics.tsv"
}

source_previous_updated_at() {
  [ "$#" -eq 2 ] || return 64
  local id=$1 url_sha=$2 diagnostics="$RULE_RUNTIME/source-diagnostics.tsv"
  [ -f "$diagnostics" ] && [ ! -L "$diagnostics" ] || return 1
  "$BB" awk -F '\t' -v wanted="$id" -v wanted_sha="$url_sha" '
    $1 == wanted && $2 == wanted_sha && NF == 7 && $7 ~ /^[0-9]+$/ {
      if (found++) bad=1
      updated=$7
    }
    END {
      if (bad || !found) exit 1
      print updated
    }
  ' "$diagnostics"
}

source_previous_cache_health() {
  [ "$#" -eq 2 ] || return 64
  local id=$1 url_sha=$2 diagnostics="$RULE_RUNTIME/source-diagnostics.tsv"
  [ -f "$diagnostics" ] && [ ! -L "$diagnostics" ] || return 1
  "$BB" awk -F '\t' -v wanted="$id" -v wanted_sha="$url_sha" '
    $1 == wanted && $2 == wanted_sha && NF == 7 &&
      (($3 == "fresh" && $4 == "null") ||
       ($3 == "stale" && $4 == "download_failed_using_cache")) {
      if (found++) bad=1
      state=$3
      error=$4
    }
    END {
      if (bad || !found) exit 1
      print state "\t" error
    }
  ' "$diagnostics"
}

source_refresh_updated_at() {
  [ "$#" -eq 3 ] || return 64
  local target_id=$1 id=$2 url_sha=$3 updated
  if [ -n "$target_id" ] && [ "$id" != "$target_id" ]; then
    updated=$(source_previous_updated_at "$id" "$url_sha" 2>/dev/null) || updated=0
    printf '%s\n' "$updated"
  else
    date +%s
  fi
}

normalize_hosts() {
  local input=$1 output=$2 tmp count
  [ -f "$input" ] || return 66
  mkdir -p "${output%/*}" || return 73
  tmp="${output}.tmp.$$"
  "$BB" awk -f "${RULE_LIB_DIR:-$MODDIR/lib/rules}/normalize.awk" "$input" | \
    LC_ALL=C "$BB" sort -t "$(printf '\t')" -k1,1 -k2,2 > "$tmp" || {
      rm -f "$tmp"
      return 65
    }
  count=$("$BB" awk -F '\t' '!seen[$1]++{n++} END{print n+0}' "$tmp")
  [ "$count" -le "$SOURCE_MAX_DOMAINS" ] || {
    rm -f "$tmp"
    return 65
  }
  atomic_replace_file "$tmp" "$output"
  NORMALIZED_RULE_COUNT=$count
  export NORMALIZED_RULE_COUNT
}

normalize_custom_source() {
  local input=$1 block_output=$2 allow_output=$3 tagged block_tmp allow_tmp supported unique_supported
  [ -f "$input" ] || return 66
  mkdir -p "${block_output%/*}" "${allow_output%/*}" || return 73
  tagged="$RULE_TMP/custom-normalized.$$.tsv"
  block_tmp="${block_output}.tmp.$$"
  allow_tmp="${allow_output}.tmp.$$"
  rm -f "$tagged" "$block_tmp" "$allow_tmp"

  "$BB" awk -f "${RULE_LIB_DIR:-$MODDIR/lib/rules}/normalize-custom.awk" "$input" > "$tagged" || {
    rm -f "$tagged" "$block_tmp" "$allow_tmp"
    return 65
  }
  "$BB" awk -F '\t' '$1=="B" && NF==3{print $2 "\t" $3}' "$tagged" | \
    LC_ALL=C "$BB" sort -u > "$block_tmp" || {
      rm -f "$tagged" "$block_tmp" "$allow_tmp"
      return 74
    }
  "$BB" awk -F '\t' '$1=="A" && NF==2{print $2}' "$tagged" | \
    LC_ALL=C "$BB" sort -u > "$allow_tmp" || {
      rm -f "$tagged" "$block_tmp" "$allow_tmp"
      return 74
    }

  CUSTOM_BLOCK_COUNT=$("$BB" awk 'NF{n++} END{print n+0}' "$block_tmp")
  CUSTOM_ALLOW_COUNT=$("$BB" awk 'NF{n++} END{print n+0}' "$allow_tmp")
  CUSTOM_SKIPPED_COUNT=$("$BB" awk -F '\t' '$1=="S"{n++} END{print n+0}' "$tagged")
  supported=$((CUSTOM_BLOCK_COUNT + CUSTOM_ALLOW_COUNT))
  unique_supported=$("$BB" awk -F '\t' '
    FNR == NR { if (NF) domains[$1]=1; next }
    NF { domains[$1]=1 }
    END { for (domain in domains) count++; print count+0 }
  ' "$block_tmp" "$allow_tmp") || {
    rm -f "$tagged" "$block_tmp" "$allow_tmp"
    return 74
  }
  rm -f "$tagged"
  if [ "$supported" -eq 0 ] || [ "$unique_supported" -gt "$SOURCE_MAX_DOMAINS" ]; then
    rm -f "$block_tmp" "$allow_tmp" "$block_output" "$allow_output"
    return 65
  fi

  atomic_replace_file "$block_tmp" "$block_output" || return
  atomic_replace_file "$allow_tmp" "$allow_output" || return
  CUSTOM_RULE_COUNT=$unique_supported
  export CUSTOM_BLOCK_COUNT CUSTOM_ALLOW_COUNT CUSTOM_RULE_COUNT CUSTOM_SKIPPED_COUNT
}

normalize_enhanced_whitelist_source() {
  local input output block allow tmp
  input=$1
  output=$2
  block="$RULE_TMP/enhanced-block.$$.tsv"
  allow="$RULE_TMP/enhanced-allow.$$.txt"
  tmp="$output.tmp.$$"
  normalize_custom_source "$input" "$block" "$allow" || return
  {
    "$BB" awk -F '\t' 'NF==2{print $1}' "$block"
    cat "$allow"
  } | LC_ALL=C "$BB" sort -u > "$tmp" || { rm -f "$block" "$allow" "$tmp"; return 74; }
  [ -s "$tmp" ] || { rm -f "$block" "$allow" "$tmp"; return 65; }
  atomic_replace_file "$tmp" "$output" || { rm -f "$block" "$allow"; return; }
  ENHANCED_WHITELIST_RULE_COUNT=$CUSTOM_RULE_COUNT
  ENHANCED_WHITELIST_SKIPPED_COUNT=$CUSTOM_SKIPPED_COUNT
  export ENHANCED_WHITELIST_RULE_COUNT ENHANCED_WHITELIST_SKIPPED_COUNT
  rm -f "$block" "$allow"
}

validate_non_zip_source() {
  local file=$1 magic
  [ -f "$file" ] || return 66
  magic=$("$BB" od -An -N4 -tx1 "$file" | "$BB" tr -d ' \n') || return 65
  case "$magic" in
    504b0304|504b0506|504b0708) return 65 ;;
  esac
}

validate_download() {
  local file=$1 normalized=$2
  [ -f "$file" ] || return 66
  local bytes
  bytes=$(wc -c < "$file" | tr -d ' ')
  [ "$bytes" -gt 0 ] && [ "$bytes" -le "$SOURCE_MAX_BYTES" ] || return 65
  validate_non_zip_source "$file" || return 65
  if "$BB" head -c 256 "$file" | LC_ALL=C grep -Eiq '^[[:space:]]*<(html|!doctype|xml)'; then
    return 65
  fi
  normalize_hosts "$file" "$normalized" || return 65
  [ -s "$normalized" ] || return 65
  VALIDATE_RULE_COUNT=$NORMALIZED_RULE_COUNT
  export VALIDATE_RULE_COUNT
}

validate_custom_download() {
  local file=$1 normalized=$2 bytes
  [ -f "$file" ] || return 66
  bytes=$(wc -c < "$file" | tr -d ' ')
  [ "$bytes" -gt 0 ] && [ "$bytes" -le "$SOURCE_MAX_BYTES" ] || return 65
  validate_non_zip_source "$file" || return 65
  if "$BB" head -c 256 "$file" | LC_ALL=C grep -Eiq '^[[:space:]]*<(html|!doctype|xml)'; then
    return 65
  fi
  normalize_custom_source "$file" "$normalized" "${normalized}.allow" || return 65
  VALIDATE_RULE_COUNT=$CUSTOM_RULE_COUNT
  VALIDATE_ALLOW_COUNT=$CUSTOM_ALLOW_COUNT
  VALIDATE_SKIPPED_COUNT=$CUSTOM_SKIPPED_COUNT
  VALIDATE_ALLOW_PATH="${normalized}.allow"
  export VALIDATE_RULE_COUNT VALIDATE_ALLOW_COUNT VALIDATE_SKIPPED_COUNT VALIDATE_ALLOW_PATH
}

validate_enhanced_whitelist_download() {
  local file=$1 normalized=$2 bytes
  [ -f "$file" ] || return 66
  bytes=$(wc -c < "$file" | tr -d ' ')
  [ "$bytes" -gt 0 ] && [ "$bytes" -le "$SOURCE_MAX_BYTES" ] || return 65
  validate_non_zip_source "$file" || return 65
  if "$BB" head -c 256 "$file" | LC_ALL=C grep -Eiq '^[[:space:]]*<(html|!doctype|xml)'; then
    return 65
  fi
  normalize_enhanced_whitelist_source "$file" "$normalized" || return 65
  VALIDATE_RULE_COUNT=$ENHANCED_WHITELIST_RULE_COUNT
  VALIDATE_ALLOW_COUNT=0
  VALIDATE_SKIPPED_COUNT=$ENHANCED_WHITELIST_SKIPPED_COUNT
  VALIDATE_ALLOW_PATH=-
  export VALIDATE_RULE_COUNT VALIDATE_ALLOW_COUNT VALIDATE_SKIPPED_COUNT VALIDATE_ALLOW_PATH
}

validate_source_download() {
  case "$1" in
    enhanced_whitelist) validate_enhanced_whitelist_download "$2" "$3" ;;
    custom_[1-9]*) validate_custom_download "$2" "$3" ;;
    *)
      validate_download "$2" "$3" || return
      VALIDATE_ALLOW_COUNT=0
      VALIDATE_SKIPPED_COUNT=0
      VALIDATE_ALLOW_PATH=-
      export VALIDATE_ALLOW_COUNT VALIDATE_SKIPPED_COUNT VALIDATE_ALLOW_PATH
      ;;
  esac
}

source_run_fetcher() {
  [ "$#" -eq 2 ] || return 64
  local url=$1 output=$2 curl_bin app_process dex result diagnostics= now deadline remaining curl_timeout refresh_deadline
  local connect_ms read_ms error_file android_category
  [ "${RULE_FETCH_OFFLINE-0}" != 1 ] || return 69
  case "$url" in https://*) ;; *) return 65 ;; esac
  SOURCE_FETCH_DIAGNOSTIC=
  export SOURCE_FETCH_DIAGNOSTIC
  if [ "${RULE_TEST_MODE-}" = 1 ]; then
    [ -n "${RULE_CURL_BIN-}" ] || return 69
    if [ -x "$RULE_CURL_BIN" ]; then
      "$RULE_CURL_BIN" -o "$output" "$url"
    else
      "$BB" ash "$RULE_CURL_BIN" -o "$output" "$url"
    fi
    return
  fi

  case "$SOURCE_TIMEOUT:$SOURCE_CURL_TIMEOUT:$SOURCE_CONNECT_TIMEOUT" in
    *[!0-9:]*) SOURCE_FETCH_DIAGNOSTIC=invalid_timeout; export SOURCE_FETCH_DIAGNOSTIC; return 69 ;;
  esac
  [ "$SOURCE_TIMEOUT" -ge 1 ] && [ "$SOURCE_TIMEOUT" -le 120 ] && \
    [ "$SOURCE_CURL_TIMEOUT" -ge 1 ] && [ "$SOURCE_CURL_TIMEOUT" -le "$SOURCE_TIMEOUT" ] && \
    [ "$SOURCE_CONNECT_TIMEOUT" -ge 1 ] && [ "$SOURCE_CONNECT_TIMEOUT" -le 60 ] || {
      SOURCE_FETCH_DIAGNOSTIC=invalid_timeout
      export SOURCE_FETCH_DIAGNOSTIC
      return 69
    }
  now=$(date +%s 2>/dev/null) || {
    SOURCE_FETCH_DIAGNOSTIC=clock_error
    export SOURCE_FETCH_DIAGNOSTIC
    return 69
  }
  deadline=$((now + SOURCE_TIMEOUT))
  if [ -n "${SOURCE_REFRESH_DEADLINE-}" ]; then
    refresh_deadline=$SOURCE_REFRESH_DEADLINE
    case "$refresh_deadline" in *[!0-9]*) refresh_deadline=0 ;; esac
    [ "$refresh_deadline" -lt "$deadline" ] && deadline=$refresh_deadline
  fi
  remaining=$((deadline - now))
  if [ "$remaining" -le 0 ]; then
    SOURCE_FETCH_DIAGNOSTIC=deadline
    export SOURCE_FETCH_DIAGNOSTIC
    rm -f "$output" "$output.part"
    return 69
  fi
  rm -f "$output" "$output.part"

  if [ -n "${RULE_CURL_BIN-}" ] && [ -x "$RULE_CURL_BIN" ]; then
    curl_bin=$RULE_CURL_BIN
  elif [ -x /system/bin/curl ]; then
    curl_bin=/system/bin/curl
  else
    curl_bin=
  fi
  if [ -n "$curl_bin" ]; then
    curl_timeout=$SOURCE_CURL_TIMEOUT
    [ "$remaining" -lt "$curl_timeout" ] && curl_timeout=$remaining
    "$BB" timeout -s TERM -k 1 "$curl_timeout" "$curl_bin" --fail --silent --show-error \
      --proto '=https' --proto-redir '=https' --max-redirs 3 \
      --connect-timeout "$SOURCE_CONNECT_TIMEOUT" --max-time "$curl_timeout" \
      --max-filesize "$SOURCE_MAX_BYTES" -o "$output" "$url" && return 0
    result=$?
    diagnostics="curl_$result"
    rm -f "$output" "$output.part"
  fi

  now=$(date +%s 2>/dev/null) || now=$deadline
  remaining=$((deadline - now))
  if [ "$remaining" -le 0 ]; then
    [ -n "$diagnostics" ] && diagnostics="$diagnostics,"
    SOURCE_FETCH_DIAGNOSTIC="${diagnostics}deadline"
    export SOURCE_FETCH_DIAGNOSTIC
    return 69
  fi

  app_process=${RULE_APP_PROCESS_BIN:-/system/bin/app_process}
  dex="$MODDIR/tools/rule_fetcher.dex"
  if [ -x "$app_process" ] && [ -f "$dex" ]; then
    connect_ms=$((SOURCE_CONNECT_TIMEOUT * 1000))
    [ "$connect_ms" -gt $((remaining * 1000)) ] && connect_ms=$((remaining * 1000))
    read_ms=$((remaining * 1000))
    error_file="$RULE_TMP/fetcher-error.$$.txt"
    rm -f "$error_file"
    CLASSPATH="$dex" "$BB" timeout -s TERM -k 1 "$remaining" \
      "$app_process" /system/bin --nice-name=jingjie-fetcher com.jingjie.RuleFetcher \
      "$url" "$output" "$SOURCE_MAX_BYTES" "$connect_ms" "$read_ms" \
      > /dev/null 2> "$error_file" && {
        rm -f "$error_file" "$output.part"
        return 0
      }
    result=$?
    android_category=$(
      "$BB" sed -n 's/^fetch_error:\(argument\|protocol\|redirect\|http\|too_large\|empty\|io\|tls\|timeout\|network\)$/\1/p' \
        "$error_file" 2>/dev/null | "$BB" head -n 1
    )
    rm -f "$error_file" "$output" "$output.part"
    if [ -z "$android_category" ]; then
      case "$result" in 124|137|143) android_category=timeout ;; *) android_category=runtime ;; esac
    fi
    [ -n "$diagnostics" ] && diagnostics="$diagnostics,"
    diagnostics="${diagnostics}android_$android_category"
  else
    [ -n "$diagnostics" ] && diagnostics="$diagnostics,"
    diagnostics="${diagnostics}android_unavailable"
  fi
  SOURCE_FETCH_DIAGNOSTIC=${diagnostics:-downloader_unavailable}
  export SOURCE_FETCH_DIAGNOSTIC
  return 69
}

fetch_source() {
  local id=$1 url=$2 raw_dest=$3 normalized_dest=$4
  case "$url" in https://*) ;; *) FETCH_ERROR=invalid_protocol; return 65 ;; esac
  [ "$#" -eq 4 ] || return 64
  source_cache_path "$id" "$url" || return
  local cache="$SOURCE_CACHE_PATH" cache_tmp attempt raw_tmp normalized_tmp format_failed=0
  source_cache_path_prepare "$cache" || return
  mkdir -p "${raw_dest%/*}" "${normalized_dest%/*}" || return 73
  FETCH_STATE=error
  FETCH_ERROR=download_failed
  attempt=1
  while [ "$attempt" -le "$SOURCE_ATTEMPTS" ]; do
    raw_tmp="$RULE_TMP/fetch.$$.${attempt}.raw"
    rm -f "$raw_tmp" "$normalized_dest"
    if source_run_fetcher "$url" "$raw_tmp" 2>/dev/null; then
      if validate_source_download "$id" "$raw_tmp" "$normalized_dest"; then
        atomic_replace_file "$raw_tmp" "$raw_dest" || return 74
        source_cache_path_prepare "$cache" || return
        cache_tmp="$cache.tmp.$$"
        [ ! -e "$cache_tmp" ] && [ ! -L "$cache_tmp" ] || return 65
        cp "$raw_dest" "$cache_tmp" || return 74
        atomic_replace_file "$cache_tmp" "$cache" || return 74
        FETCH_STATE=fresh
        FETCH_ERROR=
        FETCH_SHA=$(sha256_file "$cache")
        FETCH_RULE_COUNT=$VALIDATE_RULE_COUNT
        FETCH_ALLOW_COUNT=$VALIDATE_ALLOW_COUNT
        FETCH_SKIPPED_COUNT=$VALIDATE_SKIPPED_COUNT
        FETCH_ALLOW_PATH=$VALIDATE_ALLOW_PATH
        export FETCH_STATE FETCH_ERROR FETCH_SHA FETCH_RULE_COUNT
        export FETCH_ALLOW_COUNT FETCH_SKIPPED_COUNT FETCH_ALLOW_PATH
        return 0
      fi
      format_failed=1
    fi
    attempt=$((attempt + 1))
  done

  source_cache_path_prepare "$cache" || return
  if [ -f "$cache" ] && [ ! -L "$cache" ] && validate_source_download "$id" "$cache" "$normalized_dest"; then
    cp "$cache" "$raw_dest" || return 74
    FETCH_STATE=stale
    FETCH_ERROR=download_failed_using_cache
    FETCH_SHA=$(sha256_file "$cache")
    FETCH_RULE_COUNT=$VALIDATE_RULE_COUNT
    FETCH_ALLOW_COUNT=$VALIDATE_ALLOW_COUNT
    FETCH_SKIPPED_COUNT=$VALIDATE_SKIPPED_COUNT
    FETCH_ALLOW_PATH=$VALIDATE_ALLOW_PATH
    export FETCH_STATE FETCH_ERROR FETCH_SHA FETCH_RULE_COUNT
    export FETCH_ALLOW_COUNT FETCH_SKIPPED_COUNT FETCH_ALLOW_PATH
    return 0
  fi
  FETCH_STATE=error
  if [ "$format_failed" -eq 1 ]; then
    FETCH_ERROR=unsupported_format
  else
    FETCH_ERROR=source_unavailable
  fi
  FETCH_ALLOW_COUNT=0
  FETCH_SKIPPED_COUNT=0
  FETCH_ALLOW_PATH=-
  export FETCH_STATE FETCH_ERROR
  export FETCH_ALLOW_COUNT FETCH_SKIPPED_COUNT FETCH_ALLOW_PATH
  [ "$FETCH_ERROR" != source_unavailable ] || \
    log_event warn source_download_failed "$id:${SOURCE_FETCH_DIAGNOSTIC:-unknown}" || true
  return 69
}

load_source_cache() {
  [ "$#" -eq 4 ] || return 64
  local id=$1 url=$2 raw_dest=$3 normalized_dest=$4 cache
  case "$url" in https://*) ;; *) return 65 ;; esac
  source_cache_path "$id" "$url" || return
  cache=$SOURCE_CACHE_PATH
  source_cache_path_prepare "$cache" || return
  mkdir -p "${raw_dest%/*}" "${normalized_dest%/*}" || return 73
  rm -f "$raw_dest" "$normalized_dest" "${normalized_dest}.allow"
  FETCH_STATE=error
  FETCH_ERROR=source_unavailable
  FETCH_RULE_COUNT=0
  FETCH_ALLOW_COUNT=0
  FETCH_SKIPPED_COUNT=0
  FETCH_ALLOW_PATH=-
  export FETCH_STATE FETCH_ERROR FETCH_RULE_COUNT FETCH_ALLOW_COUNT FETCH_SKIPPED_COUNT FETCH_ALLOW_PATH
  [ -f "$cache" ] && [ ! -L "$cache" ] || return 69
  if ! validate_source_download "$id" "$cache" "$normalized_dest"; then
    rm -f "$normalized_dest" "${normalized_dest}.allow"
    return 69
  fi
  cp "$cache" "$raw_dest" || return 74
  FETCH_STATE=fresh
  FETCH_ERROR=
  FETCH_SHA=$(sha256_file "$cache") || return
  FETCH_RULE_COUNT=$VALIDATE_RULE_COUNT
  FETCH_ALLOW_COUNT=$VALIDATE_ALLOW_COUNT
  FETCH_SKIPPED_COUNT=$VALIDATE_SKIPPED_COUNT
  FETCH_ALLOW_PATH=$VALIDATE_ALLOW_PATH
  export FETCH_STATE FETCH_ERROR FETCH_SHA FETCH_RULE_COUNT
  export FETCH_ALLOW_COUNT FETCH_SKIPPED_COUNT FETCH_ALLOW_PATH
}

source_refresh_target_validate() {
  [ "$#" -eq 2 ] || return 64
  local revision=$1 target=$2 enabled sources
  [ -n "$target" ] || return 0
  case "$target" in
    enhanced_whitelist)
      enabled=$(config_enhanced_whitelist_value "$revision" enabled) || return
      [ "$enabled" = 1 ] && [ -n "$(config_enhanced_whitelist_url "$revision")" ] || return 65
      ;;
    *)
      source_registry_id_valid "$target" || return 65
      sources="$CONFIG_DIR/revisions/$revision/sources.tsv"
      source_registry_validate_file "$sources" || return
      "$BB" awk -F '\t' -v wanted="$target" '$1==wanted && $3==1{found=1} END{exit found?0:1}' "$sources" || return 65
      ;;
  esac
}

source_fetch_or_load_cache() {
  [ "$#" -eq 5 ] || return 64
  local target_id=$1 id=$2 url=$3 raw_dest=$4 normalized_dest=$5 url_sha previous_health previous_state previous_error tab
  if [ -z "$target_id" ] || [ "$id" = "$target_id" ]; then
    fetch_source "$id" "$url" "$raw_dest" "$normalized_dest"
  else
    load_source_cache "$id" "$url" "$raw_dest" "$normalized_dest" || return
    url_sha=$(printf '%s' "$url" | sha256_file_stdin) || return
    if previous_health=$(source_previous_cache_health "$id" "$url_sha" 2>/dev/null); then
      tab=$(printf '\t')
      previous_state=${previous_health%%"$tab"*}
      previous_error=${previous_health#*"$tab"}
      [ "$previous_error" != null ] || previous_error=
      FETCH_STATE=$previous_state
      FETCH_ERROR=$previous_error
      export FETCH_STATE FETCH_ERROR
    fi
  fi
}

fetch_enabled_sources() {
  local workdir=$1 target_id=${2-} current sources id kind enabled order name_b64 url_b64 extra url priority normalized raw state failures=0 url_sha source_error
  local refresh_now updated_at SOURCE_REFRESH_DEADLINE
  case "$SOURCE_REFRESH_TIMEOUT" in ''|*[!0-9]*) return 65 ;; esac
  [ "$SOURCE_REFRESH_TIMEOUT" -ge 1 ] && [ "$SOURCE_REFRESH_TIMEOUT" -le 540 ] || return 65
  refresh_now=$(date +%s 2>/dev/null) || return 70
  SOURCE_REFRESH_DEADLINE=$((refresh_now + SOURCE_REFRESH_TIMEOUT))
  export SOURCE_REFRESH_DEADLINE
  mkdir -p "$workdir/normalized" || return 73
  current=${FETCH_CONFIG_REVISION:-$(config_current_revision)}
  source_refresh_target_validate "$current" "$target_id" || return
  sources="$CONFIG_DIR/revisions/$current/sources.tsv"
  source_registry_validate_file "$sources" || return
  : > "$workdir/sources.tsv"

  while IFS="$(printf '\t')" read -r id kind enabled order name_b64 url_b64 extra || \
    [ -n "${id}${kind}${enabled}${order}${name_b64}${url_b64}${extra}" ]; do
    [ -n "$id" ] || continue
    [ -z "$extra" ] || return 65
    url=$(printf '%s' "$url_b64" | "$BB" base64 -d 2>/dev/null) || return 65
    priority=$((10 + order * 10))
    if [ "$enabled" = 0 ]; then
      url_sha=$(printf '%s' "$url" | sha256_file_stdin) || return
      printf '%s\t%s\t%s\t0\tdisabled\t%s\t0\tnull\t%s\t-\t0\t0\t-\tnull\n' \
        "$priority" "$id" "$kind" "$(date +%s)" "$url_sha" >> "$workdir/sources.tsv"
      continue
    fi
    raw="$workdir/$id.raw"
    normalized="$workdir/normalized/$id.tsv"
    if [ "$id" = awa ] && [ -n "${RULE_AWA_PRIMARY_URL-}" ]; then
      url=$RULE_AWA_PRIMARY_URL
    elif [ "$id" = rule10007 ] && [ -n "${RULE_10007_PRIMARY_URL-}" ]; then
      url=$RULE_10007_PRIMARY_URL
    fi
    url_sha=$(printf '%s' "$url" | sha256_file_stdin) || return
    if source_fetch_or_load_cache "$target_id" "$id" "$url" "$raw" "$normalized"; then
      state=$FETCH_STATE
      case "$id" in awa|rule10007) source_force_block_addresses "$normalized" || return ;; esac
      [ -n "$FETCH_ERROR" ] && source_error=$FETCH_ERROR || source_error=null
      updated_at=$(source_refresh_updated_at "$target_id" "$id" "$url_sha") || return
      printf '%s\t%s\t%s\t1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$priority" "$id" "$kind" "$state" "$updated_at" "$FETCH_RULE_COUNT" "$FETCH_SHA" "$url_sha" "$normalized" \
        "$FETCH_ALLOW_COUNT" "$FETCH_SKIPPED_COUNT" "$FETCH_ALLOW_PATH" "$source_error" >> "$workdir/sources.tsv"
    else
      state=$FETCH_STATE
      updated_at=$(source_refresh_updated_at "$target_id" "$id" "$url_sha") || return
      printf '%s\t%s\t%s\t1\t%s\t%s\t0\tnull\t%s\t-\t0\t%s\t-\t%s\n' \
        "$priority" "$id" "$kind" "$state" "$updated_at" "$url_sha" "$FETCH_SKIPPED_COUNT" "$FETCH_ERROR" >> "$workdir/sources.tsv"
      failures=$((failures + 1))
    fi
  done < "$sources"
  enhanced_meta="$workdir/enhanced-whitelist.prop"
  enhanced_enabled=$(config_enhanced_whitelist_value "$current" enabled) || return
  enhanced_url=$(config_enhanced_whitelist_url "$current") || return
  if [ -n "$enhanced_url" ]; then
    enhanced_url_sha=$(printf '%s' "$enhanced_url" | sha256_file_stdin) || return
  else
    enhanced_url_sha=null
  fi
  if [ "$enhanced_enabled" = 0 ]; then
    {
      printf 'enabled=0\n'
      printf 'url_sha256=%s\n' "$enhanced_url_sha"
      printf 'state=disabled\nupdated_at=0\nrule_count=0\nskipped_count=0\nerror=null\n'
    } > "$enhanced_meta" || return 74
  else
    enhanced_raw="$workdir/enhanced-whitelist.raw"
    enhanced_domains="$workdir/enhanced-whitelist-domains.txt"
    if source_fetch_or_load_cache "$target_id" enhanced_whitelist "$enhanced_url" "$enhanced_raw" "$enhanced_domains"; then
      [ -n "$FETCH_ERROR" ] && source_error=$FETCH_ERROR || source_error=null
      updated_at=$(source_refresh_updated_at "$target_id" enhanced_whitelist "$enhanced_url_sha") || return
      {
        printf 'enabled=1\n'
        printf 'url_sha256=%s\n' "$enhanced_url_sha"
        printf 'state=%s\nupdated_at=%s\nrule_count=%s\nskipped_count=%s\nerror=%s\n' \
          "$FETCH_STATE" "$updated_at" "$FETCH_RULE_COUNT" "$FETCH_SKIPPED_COUNT" "$source_error"
      } > "$enhanced_meta" || return 74
    else
      updated_at=$(source_refresh_updated_at "$target_id" enhanced_whitelist "$enhanced_url_sha") || return
      {
        printf 'enabled=1\n'
        printf 'url_sha256=%s\n' "$enhanced_url_sha"
        printf 'state=%s\nupdated_at=%s\nrule_count=0\nskipped_count=%s\nerror=%s\n' \
          "$FETCH_STATE" "$updated_at" "$FETCH_SKIPPED_COUNT" "$FETCH_ERROR"
      } > "$enhanced_meta" || return 74
      failures=$((failures + 1))
    fi
  fi
  SOURCE_ENHANCED_DIAGNOSTIC_FILE="$enhanced_meta"
  export SOURCE_ENHANCED_DIAGNOSTIC_FILE
  source_diagnostics_write "$workdir/sources.tsv" || return 74
  unset SOURCE_ENHANCED_DIAGNOSTIC_FILE
  [ "$failures" -eq 0 ] || return 69
}
