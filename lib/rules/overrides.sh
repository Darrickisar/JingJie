#!/system/bin/sh

OVERRIDES_MAX_ROWS=1024
OVERRIDES_MAX_BYTES=65536

overrides_domain_protected() {
  case "$1" in
    localhost|localhost.localdomain|local|broadcasthost|ip6-localhost|ip6-loopback|ip6-allnodes|ip6-allrouters|*.localhost) return 0 ;;
    *) return 1 ;;
  esac
}

overrides_ipv4_valid() {
  printf '%s\n' "$1" | "$BB" awk -F. '
    NF!=4{exit 1}
    {for(i=1;i<=4;i++) if($i!~/^[0-9]+$/ || $i+0>255 || ($i!="0" && $i~/^0/)) exit 1}
  '
}

overrides_ipv6_valid() {
  printf '%s\n' "$1" | "$BB" awk '
    function bad(){exit 1}
    $0!~/^[0-9a-f:]+$/ || $0!~/:/ {bad()}
    index($0,":::") {bad()}
    {
      compact=index($0,"::")>0
      rest=$0; occurrences=0
      while((p=index(rest,"::"))>0){occurrences++;rest=substr(rest,p+2)}
      if(occurrences>1)bad()
      n=split($0,a,":")
      present=0
      for(i=1;i<=n;i++){
        if(a[i]=="")continue
        if(length(a[i])>4 || a[i]!~/^[0-9a-f]+$/)bad()
        present++
      }
      if(compact){if(present>=8)bad()}else if(present!=8)bad()
    }
  '
}

overrides_ip_family() {
  if overrides_ipv4_valid "$1"; then
    printf '4\n'
  elif overrides_ipv6_valid "$1"; then
    printf '6\n'
  else
    return 65
  fi
}

overrides_validate_file() {
  [ "$#" -eq 1 ] || return 64
  local file=$1 bytes rows domain ip extra family key seen_file="$RULE_TMP/override-seen.$$"
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  bytes=$(wc -c < "$file" | "$BB" tr -d ' ') || return 74
  [ "$bytes" -le "$OVERRIDES_MAX_BYTES" ] || return 65
  : > "$seen_file" || return 74
  rows=0
  while IFS="$(printf '\t')" read -r domain ip extra || [ -n "${domain}${ip}${extra}" ]; do
    [ -n "$domain$ip" ] || continue
    [ -n "$domain" ] && [ -n "$ip" ] && [ -z "$extra" ] || { rm -f "$seen_file"; return 65; }
    [ "$domain" = "$(printf '%s' "$domain" | "$BB" tr 'A-Z' 'a-z')" ] || { rm -f "$seen_file"; return 65; }
    config_domain_list_valid "$domain" || { rm -f "$seen_file"; return 65; }
    overrides_domain_protected "$domain" && { rm -f "$seen_file"; return 65; }
    family=$(overrides_ip_family "$ip") || { rm -f "$seen_file"; return 65; }
    key="$domain:$family"
    "$BB" grep -Fx "$key" "$seen_file" >/dev/null 2>&1 && { rm -f "$seen_file"; return 65; }
    printf '%s\n' "$key" >> "$seen_file" || { rm -f "$seen_file"; return 74; }
    rows=$((rows + 1))
    [ "$rows" -le "$OVERRIDES_MAX_ROWS" ] || { rm -f "$seen_file"; return 65; }
  done < "$file"
  rm -f "$seen_file"
  if [ "$rows" -gt 0 ]; then
    LC_ALL=C "$BB" sort -t "$(printf '\t')" -k1,1 -k2,2 "$file" | "$BB" cmp -s - "$file" || return 65
  fi
}

overrides_decode() {
  [ "$#" -eq 2 ] || return 64
  local encoded=$1 output=$2 raw="$RULE_TMP/overrides-raw.$$" canonical="$RULE_TMP/overrides-canonical.$$"
  if [ -z "$encoded" ]; then
    : > "$output" || return 74
    return 0
  fi
  config_b64_valid "$encoded" || return 65
  printf '%s' "$encoded" | "$BB" base64 -d > "$raw" 2>/dev/null || return 65
  "$BB" awk -F '\t' 'NF==2{print tolower($1) "\t" tolower($2)} NF!=2{exit 65}' "$raw" | \
    LC_ALL=C "$BB" sort -t "$(printf '\t')" -k1,1 -k2,2 -u > "$canonical" || { rm -f "$raw" "$canonical"; return 65; }
  rm -f "$raw"
  overrides_validate_file "$canonical" || { rm -f "$canonical"; return 65; }
  mv "$canonical" "$output" || { rm -f "$canonical"; return 74; }
}

overrides_apply() {
  [ "$#" -eq 3 ] || return 64
  local source=$1 overrides=$2 output=$3 domains tmp
  domains="$RULE_TMP/override-domains.$$"
  tmp="$output.tmp.$$"
  [ -f "$source" ] || return 66
  overrides_validate_file "$overrides" || return
  "$BB" awk -F '\t' 'NF==2{print $1}' "$overrides" | LC_ALL=C "$BB" sort -u > "$domains" || return 74
  "$BB" awk -F '\t' 'FILENAME==ARGV[1]{override[$1]=1;next} NF==2 && !override[$1]{print $1 "\t" $2}' \
    "$domains" "$source" > "$tmp" || { rm -f "$domains" "$tmp"; return 74; }
  cat "$overrides" >> "$tmp" || { rm -f "$domains" "$tmp"; return 74; }
  LC_ALL=C "$BB" sort -t "$(printf '\t')" -k1,1 -k2,2 -u "$tmp" -o "$tmp" || { rm -f "$domains" "$tmp"; return 74; }
  rm -f "$domains"
  atomic_replace_file "$tmp" "$output"
}

overrides_json() {
  [ "$#" -eq 1 ] || return 64
  local file=$1 first=true domain ip
  overrides_validate_file "$file" || return
  printf '{"items":['
  while IFS="$(printf '\t')" read -r domain ip || [ -n "$domain$ip" ]; do
    [ -n "$domain" ] || continue
    [ "$first" = true ] || printf ','
    first=false
    printf '{"domain":"%s","address":"%s"}' "$(printf '%s' "$domain" | json_escape)" "$(printf '%s' "$ip" | json_escape)"
  done < "$file"
  printf ']}\n'
}
