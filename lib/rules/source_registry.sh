#!/system/bin/sh

SOURCE_REGISTRY_MAX_CUSTOM=16
SOURCE_REGISTRY_MAX_TOTAL=18

source_registry_builtin_url() {
  case "$1" in
    awa) printf '%s\n' 'https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-hosts.txt' ;;
    rule10007) printf '%s\n' 'https://lingeringsound.github.io/10007/all' ;;
    *) return 65 ;;
  esac
}

source_registry_builtin_name() {
  case "$1" in
    awa) printf '%s\n' '秋风规则' ;;
    rule10007) printf '%s\n' '10007规则' ;;
    *) return 65 ;;
  esac
}

source_registry_id_valid() {
  local id=$1 suffix
  case "$id" in
    awa|rule10007) return 0 ;;
    custom_*)
      suffix=${id#custom_}
      case "$suffix" in ''|0|*[!0-9]*) return 1 ;; esac
      [ "${#id}" -le 64 ]
      ;;
    *) return 1 ;;
  esac
}

source_registry_validate_file() {
  [ "$#" -eq 1 ] || return 64
  local file=$1 id kind enabled order name_b64 url_b64 extra count=0 custom_count=0 scan_result
  local name_file="$RULE_TMP/source-name.$$" url_file="$RULE_TMP/source-url.$$" name_bytes url_bytes url
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  while IFS="$(printf '\t')" read -r id kind enabled order name_b64 url_b64 extra || \
    [ -n "${id}${kind}${enabled}${order}${name_b64}${url_b64}${extra}" ]; do
    [ -n "$id" ] || continue
    [ -z "$extra" ] || return 65
    source_registry_id_valid "$id" || return 65
    case "$id:$kind" in awa:builtin|rule10007:builtin|custom_[1-9]*:custom) ;; *) return 65 ;; esac
    [ "$enabled" = 0 ] || [ "$enabled" = 1 ] || return 65
    case "$order" in ''|*[!0-9]*) return 65 ;; esac
    [ "${#order}" -le 4 ] || return 65
    config_b64_valid "$name_b64" || return 65
    config_b64_valid "$url_b64" || return 65
    printf '%s' "$name_b64" | "$BB" base64 -d > "$name_file" 2>/dev/null || return 65
    printf '%s' "$url_b64" | "$BB" base64 -d > "$url_file" 2>/dev/null || { rm -f "$name_file"; return 65; }
    name_bytes=$(wc -c < "$name_file" | "$BB" tr -d ' ') || { rm -f "$name_file" "$url_file"; return 74; }
    url_bytes=$(wc -c < "$url_file" | "$BB" tr -d ' ') || { rm -f "$name_file" "$url_file"; return 74; }
    [ "$name_bytes" -ge 1 ] && [ "$name_bytes" -le 320 ] || { rm -f "$name_file" "$url_file"; return 65; }
    [ "$url_bytes" -ge 9 ] && [ "$url_bytes" -le 2048 ] || { rm -f "$name_file" "$url_file"; return 65; }
    if config_utf8_valid_file "$name_file" && config_utf8_valid_file "$url_file"; then
      :
    else
      scan_result=$?
      rm -f "$name_file" "$url_file"
      [ "$scan_result" -eq 1 ] && return 65
      return "$scan_result"
    fi
    if config_url_forbidden_bytes "$url_file"; then
      rm -f "$name_file" "$url_file"
      return 65
    else
      scan_result=$?
      [ "$scan_result" -eq 1 ] || { rm -f "$name_file" "$url_file"; return "$scan_result"; }
    fi
    url=$(cat "$url_file") || { rm -f "$name_file" "$url_file"; return 74; }
    rm -f "$name_file" "$url_file"
    case "$url" in https://*) ;; *) return 65 ;; esac
    "$BB" awk -F '\t' -v wanted="$id" '$1==wanted{n++} END{exit n==1?0:1}' "$file" || return 65
    "$BB" awk -F '\t' -v wanted="$order" '$4==wanted{n++} END{exit n==1?0:1}' "$file" || return 65
    count=$((count + 1))
    [ "$kind" != custom ] || custom_count=$((custom_count + 1))
    [ "$count" -le "$SOURCE_REGISTRY_MAX_TOTAL" ] || return 65
    [ "$custom_count" -le "$SOURCE_REGISTRY_MAX_CUSTOM" ] || return 65
  done < "$file"
  return 0
}

source_registry_seed() {
  [ "$#" -eq 1 ] || return 64
  local output=$1 id name url name_b64 url_b64 order=0
  : > "$output" || return 74
  for id in awa rule10007; do
    name=$(source_registry_builtin_name "$id") || return
    url=$(source_registry_builtin_url "$id") || return
    name_b64=$(printf '%s' "$name" | "$BB" base64 | "$BB" tr -d '\n') || return 74
    url_b64=$(printf '%s' "$url" | "$BB" base64 | "$BB" tr -d '\n') || return 74
    printf '%s\tbuiltin\t1\t%s\t%s\t%s\n' "$id" "$order" "$name_b64" "$url_b64" >> "$output" || return 74
    order=$((order + 1))
  done
  source_registry_validate_file "$output"
}

source_registry_exists() {
  [ "$#" -eq 2 ] || return 64
  local file=$1 id=$2
  source_registry_id_valid "$id" || return 65
  "$BB" awk -F '\t' -v wanted="$id" '$1==wanted{found=1} END{exit found?0:1}' "$file"
}

source_registry_next_order() {
  [ "$#" -eq 1 ] || return 64
  "$BB" awk -F '\t' 'NF{if($4>=max)max=$4+1} END{print max+0}' "$1"
}

source_registry_normalize_orders() {
  [ "$#" -eq 1 ] || return 64
  local file=$1 tmp="$1.orders.$$"
  LC_ALL=C "$BB" sort -t "$(printf '\t')" -k4,4n "$file" | \
    "$BB" awk -F '\t' 'BEGIN{OFS="\t"} NF==6{$4=order++; print}' > "$tmp" || { rm -f "$tmp"; return 74; }
  source_registry_validate_file "$tmp" || { rm -f "$tmp"; return 65; }
  mv "$tmp" "$file" || { rm -f "$tmp"; return 74; }
}

source_registry_template_json() {
  [ "$#" -eq 1 ] || return 64
  local current=$1 first=true id name url present
  [ -f "$current" ] || return 66
  printf '['
  for id in awa rule10007; do
    name=$(source_registry_builtin_name "$id") || return
    url=$(source_registry_builtin_url "$id") || return
    if source_registry_exists "$current" "$id"; then present=true; else present=false; fi
    [ "$first" = true ] || printf ','
    first=false
    printf '{"id":"%s","name":"%s","url":"%s","present":%s}' \
      "$id" "$(printf '%s' "$name" | json_escape)" "$(printf '%s' "$url" | json_escape)" "$present"
  done
  printf ']\n'
}

source_registry_remove_cache() {
  [ "$#" -eq 1 ] || return 64
  local id=$1
  source_registry_id_valid "$id" || return 65
  case "$id" in
    awa|rule10007) rm -f "$CACHE_DIR/$id.hosts" ;;
    custom_*) rm -rf "$CACHE_DIR/custom/$id" ;;
  esac
}
