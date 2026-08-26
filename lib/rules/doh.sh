#!/system/bin/sh

DOH_MAX_ENDPOINT_BYTES=2048
DOH_MAX_UIDS=256
DOH_MAX_APPS=100
DOH_MIN_APP_ID=10000
DOH_MAX_APP_ID=19999
DOH_MAX_UID=4294967294
DOH_COMPANION_MAX_GZIP_BYTES=16777216
DOH_COMPANION_MAX_BINARY_BYTES=33554432

doh_init_paths() {
  DOH_CONFIG_STATE="$CONFIG_DIR/doh.prop"
  DOH_CONFIG_ENDPOINT="$CONFIG_DIR/doh-endpoint.txt"
  DOH_CONFIG_UIDS="$CONFIG_DIR/doh-uids.tsv"
  DOH_RUNTIME_DIR="$RULE_RUNTIME/doh"
  DOH_RUNTIME_STATE="$DOH_RUNTIME_DIR/runtime.prop"
  DOH_LAST_TEST="$DOH_RUNTIME_DIR/last-test.prop"
  DOH_TX_DIR="$DOH_RUNTIME_DIR/config-transaction"
  DOH_TX_PREVIOUS="$DOH_TX_DIR/previous"
  DOH_TX_STAGED="$DOH_TX_DIR/staged"
  DOH_TX_MARKER="$DOH_TX_DIR/phase.prop"
  DOH_COMPANION_MANIFEST=${DOH_COMPANION_MANIFEST:-$MODDIR/assets/doh-companions.tsv}
  DOH_COMPANION_TARGET=${DOH_COMPANION_TARGET:-$MODDIR/tools/jingjie_doh_proxy}
  DOH_COMPANION_BUNDLE_DIR=${DOH_COMPANION_BUNDLE_DIR:-$MODDIR/companions}
  export DOH_CONFIG_STATE DOH_CONFIG_ENDPOINT DOH_CONFIG_UIDS DOH_RUNTIME_DIR
  export DOH_RUNTIME_STATE DOH_LAST_TEST DOH_TX_DIR DOH_TX_PREVIOUS DOH_TX_STAGED DOH_TX_MARKER
}

doh_companion_elf_validate() {
  [ "$#" -eq 2 ] || return 64
  local file=$1 machine=$2 bytes
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  bytes=$("$BB" od -An -N 20 -t u1 "$file") || return 74
  set -- $bytes
  [ "$#" -ge 20 ] || return 65
  [ "$1" = 127 ] && [ "$2" = 69 ] && [ "$3" = 76 ] && [ "$4" = 70 ] && [ "$6" = 1 ] || return 65
  [ $(( ${19} + 256 * ${20} )) -eq "$machine" ] || return 65
}

doh_companion_file_integrity_validate() {
  [ "$#" -eq 3 ] || return 64
  local file=$1 expected_size=$2 expected_hash=$3 actual_size actual_hash
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  actual_size=$(wc -c < "$file" | "$BB" tr -d ' ') || return 74
  [ "$actual_size" = "$expected_size" ] || return 65
  actual_hash=$(sha256_file "$file") || return
  [ "$actual_hash" = "$expected_hash" ] || return 65
}

doh_companion_file_validate() {
  [ "$#" -eq 4 ] || return 64
  local file=$1 expected_size=$2 expected_hash=$3 machine=$4
  doh_companion_file_integrity_validate "$file" "$expected_size" "$expected_hash" || return
  doh_companion_elf_validate "$file" "$machine"
}

doh_companion_manifest_row() {
  [ "$#" -eq 1 ] || return 64
  local arch=$1 manifest=${DOH_COMPANION_MANIFEST:-$MODDIR/assets/doh-companions.tsv}
  [ -f "$manifest" ] && [ ! -L "$manifest" ] || return 66
  "$BB" awk -F '\t' -v wanted="$arch" '
    NR == 1 { if ($0 != "arch\tasset\turl\tgzip_size\tgzip_sha256\tbinary_size\tbinary_sha256\telf_machine") exit 65; next }
    NF != 8 { exit 65 }
    $1 == wanted { if (found++) exit 65; print }
    END { if (NR != 5 || !found) exit 65 }
  ' "$manifest"
}

doh_companion_fetch_android() {
  [ "$#" -eq 3 ] || return 64
  local url=$1 output=$2 maximum=$3 app_process dex staged
  app_process=${RULE_APP_PROCESS_BIN:-/system/bin/app_process}
  dex=${RULE_FETCHER_DEX:-$MODDIR/tools/rule_fetcher.dex}
  [ -x "$app_process" ] && [ -f "$dex" ] && [ ! -L "$dex" ] || return 69
  [ "$maximum" -ge 1 ] && [ "$maximum" -le 16777216 ] || return 65
  staged="$output.fetch"
  rm -f "$staged" "$staged.part"
  CLASSPATH="$dex" "$BB" timeout -s TERM -k 1 120 \
    "$app_process" /system/bin --nice-name=jingjie-fetcher com.jingjie.RuleFetcher \
    "$url" "$staged" "$maximum" 10000 30000 >/dev/null 2>&1 || {
      rm -f "$staged" "$staged.part"
      return 74
    }
  [ -f "$staged" ] && [ ! -L "$staged" ] || { rm -f "$staged" "$staged.part"; return 74; }
  "$BB" cat "$staged" > "$output" || { rm -f "$staged" "$staged.part"; return 74; }
  rm -f "$staged" "$staged.part"
}

doh_companion_bundled_copy() {
  [ "$#" -eq 3 ] || return 64
  local asset=$1 output=$2 maximum=$3 bundled actual_size
  bundled=${DOH_COMPANION_BUNDLE_DIR:-$MODDIR/companions}/$asset
  [ -f "$bundled" ] && [ ! -L "$bundled" ] || return 66
  [ -f "$output" ] && [ ! -L "$output" ] || return 66
  actual_size=$(wc -c < "$bundled" | "$BB" tr -d ' ') || return 74
  [ "$actual_size" -le "$maximum" ] || return 65
  "$BB" cat "$bundled" > "$output" || return 74
}

doh_companion_download() {
  [ "$#" -eq 3 ] || return 64
  local url=$1 output=$2 maximum=$3 actual_size limit result=69
  limit=$((maximum + 1))
  case "$url" in https://github.com/Darrickisar/JingJie/releases/download/v1.0/*) ;; *) return 65 ;; esac
  [ -f "$output" ] && [ ! -L "$output" ] || return 66
  if command -v curl >/dev/null 2>&1; then
    if (set -o pipefail; curl --fail --location --proto '=https' --connect-timeout 10 --max-time 30 --output - "$url" | "$BB" head -c "$limit" > "$output"); then
      result=0
    else
      result=74
    fi
  fi
  if [ "$result" -ne 0 ] && command -v wget >/dev/null 2>&1; then
    if (set -o pipefail; wget --https-only --timeout=10 --tries=1 -O - "$url" | "$BB" head -c "$limit" > "$output"); then
      result=0
    else
      result=74
    fi
  fi
  if [ "$result" -ne 0 ] && [ -f "$output" ] && [ ! -L "$output" ]; then
    : > "$output" || { rm -f "$output"; return 74; }
    if doh_companion_fetch_android "$url" "$output" "$maximum"; then
      result=0
    else
      result=$?
    fi
  fi
  [ "$result" -eq 0 ] || { rm -f "$output"; return "$result"; }
  [ -f "$output" ] && [ ! -L "$output" ] || return 65
  actual_size=$(wc -c < "$output" | "$BB" tr -d ' ') || { rm -f "$output"; return 74; }
  [ "$actual_size" -le "$maximum" ] || { rm -f "$output"; return 65; }
}

doh_companion_ensure() {
  [ "$#" -eq 1 ] || return 64
  local intent=$1 arch row tab asset url gzip_size gzip_hash binary_size binary_hash machine download binary target result mode
  case "$intent" in enable|test|boot) ;; *) return 64 ;; esac
  doh_init_paths
  arch=$(process_architecture) || return
  case "$arch" in arm64|arm32|x86|x86_64) ;; *) return 69 ;; esac
  row=$(doh_companion_manifest_row "$arch") || return
  tab=$(printf '\t')
  IFS="$tab" read -r _ asset url gzip_size gzip_hash binary_size binary_hash machine <<EOF
$row
EOF
  case "$asset" in "jingjie-doh-proxy-$arch-v1.0.gz") ;; *) return 65 ;; esac
  case "$url" in "https://github.com/Darrickisar/JingJie/releases/download/v1.0/$asset") ;; *) return 65 ;; esac
  case "$gzip_size:$binary_size:$machine" in *[!0-9:]*|:*|*::*) return 65 ;; esac
  case "$gzip_hash:$binary_hash" in *[!0-9a-f:]*|????????????????????????????????????????????????????????????????:????????????????????????????????????????????????????????????????) ;; *) return 65 ;; esac
  [ "$gzip_size" -le "$DOH_COMPANION_MAX_GZIP_BYTES" ] && [ "$binary_size" -le "$DOH_COMPANION_MAX_BINARY_BYTES" ] || return 65
  case "$machine" in 183|40|3|62) ;; *) return 65 ;; esac
  target=$DOH_COMPANION_TARGET
  if [ -L "$target" ]; then
    rm -f "$target" || return 74
    return 65
  fi
  if doh_companion_file_validate "$target" "$binary_size" "$binary_hash" "$machine" >/dev/null 2>&1; then
    chmod 700 "$target" || { rm -f "$target"; return 74; }
    mode=$("$BB" stat -c %a "$target") || { rm -f "$target"; return 74; }
    [ "$mode" = 700 ] || { rm -f "$target"; return 74; }
    return 0
  fi
  rm -f "$target" || return 74
  mkdir -p "$DOH_RUNTIME_DIR" "$MODDIR/tools" || return 73
  chmod 700 "$DOH_RUNTIME_DIR" || return 74
  download=$("$BB" mktemp "$DOH_RUNTIME_DIR/download.XXXXXX") || return 74
  [ -f "$download" ] && [ ! -L "$download" ] || { rm -f "$download"; return 65; }
  if ! doh_companion_bundled_copy "$asset" "$download" "$gzip_size"; then
    if [ "$intent" = boot ]; then
      rm -f "$download"
      return 65
    fi
    doh_companion_download "$url" "$download" "$gzip_size" || { result=$?; rm -f "$download"; return "$result"; }
  fi
  doh_companion_file_integrity_validate "$download" "$gzip_size" "$gzip_hash" || { rm -f "$download"; return 65; }
  binary=$("$BB" mktemp "$MODDIR/tools/.jingjie_doh_proxy.XXXXXX") || { rm -f "$download"; return 74; }
  [ -f "$binary" ] && [ ! -L "$binary" ] || { rm -f "$download" "$binary"; return 65; }
  "$BB" gzip -dc "$download" > "$binary" 2>/dev/null || { rm -f "$download" "$binary"; return 65; }
  rm -f "$download"
  doh_companion_file_validate "$binary" "$binary_size" "$binary_hash" "$machine" || { rm -f "$binary"; return 65; }
  chmod 700 "$binary" || { rm -f "$binary"; return 74; }
  atomic_replace_file "$binary" "$target" || { result=$?; rm -f "$binary"; rm -f "$target"; return "$result"; }
  doh_companion_file_validate "$target" "$binary_size" "$binary_hash" "$machine" || { rm -f "$target"; return 65; }
}

doh_error_valid() {
  case "$1" in
    invalid_endpoint|invalid_config|package_state_invalid|test_failed|commit_failed|recovery_failed|runtime_failed|private_dns_active|companion_unavailable|upstream_unavailable|companion_exited|bootstrap_unresolved|firewall_unsupported) return 0 ;;
    *) return 1 ;;
  esac
}

doh_mode_valid() {
  case "$1" in off|global|selected) return 0 ;; *) return 1 ;; esac
}

doh_utf8_valid_file() {
  "$BB" od -An -v -t u1 "$1" | "$BB" awk '
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
  '
}

doh_b64_decode_file() {
  [ "$#" -eq 3 ] || return 64
  local encoded=$1 output=$2 allow_empty=$3 canonical tmp="$RULE_TMP/doh-b64.$$"
  case "$encoded" in *[!A-Za-z0-9+/=]*) return 65 ;; esac
  [ $(( ${#encoded} % 4 )) -eq 0 ] || return 65
  [ -n "$encoded" ] || {
    [ "$allow_empty" = 1 ] || return 65
    : > "$output" || return 74
    return 0
  }
  printf '%s' "$encoded" | "$BB" base64 -d > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 65; }
  canonical=$("$BB" base64 "$tmp" | "$BB" tr -d '\n') || { rm -f "$tmp"; return 74; }
  [ "$canonical" = "$encoded" ] || { rm -f "$tmp"; return 65; }
  mv -f "$tmp" "$output" || { rm -f "$tmp"; return 74; }
}

doh_endpoint_validate_file() {
  [ "$#" -eq 1 ] || return 64
  local file=$1 bytes
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  bytes=$(wc -c < "$file" | "$BB" tr -d ' ') || return 74
  [ "$bytes" -ge 1 ] && [ "$bytes" -le "$DOH_MAX_ENDPOINT_BYTES" ] || return 65
  doh_utf8_valid_file "$file" || return 65
  # BusyBox awk rejects the portable-looking control-byte range used here
  # previously. URI input cannot contain any ASCII control or space byte.
  "$BB" od -An -v -t u1 "$file" | "$BB" awk '
    { for (i = 1; i <= NF; i++) if (($i + 0) <= 32 || ($i + 0) == 127) exit 65 }
  ' || return 65
  "$BB" awk '
    function bad(){exit 65}
    NR!=1{bad()}
    {
      if($0 !~ /^https:\/\// || index($0,"#"))bad()
      rest=substr($0,9); authority=rest
      sub(/[\/?].*$/, "", authority)
      if(authority=="" || index(authority,"@"))bad()
      if(substr(authority,1,1)=="[") {
        close_bracket=index(authority,"]")
        if(close_bracket<3)bad()
        tail=substr(authority,close_bracket+1)
        if(tail!="" && tail !~ /^:[0-9]+$/)bad()
        host=substr(authority,1,close_bracket)
      } else {
        host=tolower(authority)
        if(index(host,":")>0) {
          if(host ~ /:[^0-9][^\/]*$/ || host ~ /:$/)bad()
          sub(/:[0-9]+$/, "", host)
        }
      }
      if(host=="" || host=="localhost" || host=="localhost.")bad()
    }
    END{if(NR!=1)bad()}
  ' "$file"
}

doh_endpoint_b64_decode() {
  [ "$#" -eq 2 ] || return 64
  local encoded=$1 output=$2 result
  doh_b64_decode_file "$encoded" "$output" 0 || return
  doh_endpoint_validate_file "$output" || { result=$?; rm -f "$output"; return "$result"; }
}

doh_endpoint_value_write() {
  [ "$#" -eq 2 ] || return 64
  local endpoint=$1 output=$2
  printf '%s' "$endpoint" > "$output" || return 74
  chmod 600 "$output" || { rm -f "$output"; return 74; }
  doh_endpoint_validate_file "$output"
}

doh_config_b64_decode() {
  [ "$#" -eq 2 ] || return 64
  local encoded=$1 output=$2 raw="$RULE_TMP/doh-config-raw.$$" result
  doh_b64_decode_file "$encoded" "$raw" 0 || return
  "$BB" awk -v max_uid="$DOH_MAX_UID" -v max_count="$DOH_MAX_UIDS" '
    function bad(){exit 65}
    NR==1{if($0!="ack=doh-v1")bad(); next}
    {
      if($0!~/^uid=[0-9]+$/)bad()
      uid=substr($0,5)
      if(uid~/^0[0-9]/ || length(uid)>10)bad()
      numeric=uid+0
      if(numeric<0 || numeric>max_uid || numeric==65534)bad()
      appid=numeric%100000
      if(appid<10000 || appid>19999)bad()
      if(count>0 && numeric<=previous)bad()
      previous=numeric; count++
      if(count>max_count)bad()
      print uid
    }
    END{if(NR<1)bad()}
  ' "$raw" > "$output"
  result=$?
  rm -f "$raw"
  [ "$result" -eq 0 ] || { rm -f "$output"; return 65; }
  chmod 600 "$output" || { rm -f "$output"; return 74; }
}

doh_query_b64_decode() {
  [ "$#" -eq 2 ] || return 64
  local encoded=$1 output=$2 bytes result
  doh_b64_decode_file "$encoded" "$output" 1 || return
  bytes=$(wc -c < "$output" | "$BB" tr -d ' ') || { rm -f "$output"; return 74; }
  [ "$bytes" -le 128 ] || { rm -f "$output"; return 65; }
  LC_ALL=C "$BB" awk 'NR>1{exit 65} $0!~/^[A-Za-z0-9_.-]*$/{exit 65}' "$output"
  result=$?
  [ "$result" -eq 0 ] || { rm -f "$output"; return 65; }
}

doh_uid_file_validate() {
  [ "$#" -eq 1 ] || return 64
  local file=$1 count=0 uid previous= appid
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  while IFS= read -r uid || [ -n "$uid" ]; do
    case "$uid" in ''|*[!0-9]*|0[0-9]*) return 65 ;; esac
    decimal_uint_in_range "$uid" "$DOH_MAX_UID" 0 || return 65
    [ "$uid" != 65534 ] || return 65
    appid=$((uid % 100000))
    [ "$appid" -ge "$DOH_MIN_APP_ID" ] && [ "$appid" -le "$DOH_MAX_APP_ID" ] || return 65
    [ -z "$previous" ] || [ "$uid" -gt "$previous" ] || return 65
    previous=$uid
    count=$((count + 1))
    [ "$count" -le "$DOH_MAX_UIDS" ] || return 65
  done < "$file"
}

doh_packages_regular() {
  local packages=${DOH_PACKAGES_LIST:-/data/system/packages.list}
  [ -f "$packages" ] && [ ! -L "$packages" ] || return 66
}

doh_validate_uid_ownership() {
  [ "$#" -eq 1 ] || return 64
  local uid_file=$1 packages=${DOH_PACKAGES_LIST:-/data/system/packages.list}
  doh_packages_regular || return
  "$BB" awk '
    function bad(code){status=code; exit}
    FNR==NR {
      if($0!~/^[0-9]+$/)bad(65)
      selected_uid[$0]=1; selected_appid[($0+0)%100000]=1; next
    }
    {
      if(NF<2 || $1!~/^[A-Za-z0-9_.-]+$/ || $2!~/^[0-9]+$/ || $2~/^0[0-9]/)bad(65)
      uid=$2+0
      if(uid<0 || uid>4294967294)bad(65)
      known_uid[$2]=1
      if($1~/^(me\.weishu\.kernelsu|com\.rifsxd\.ksunext|me\.bmax\.apatch)$/)manager_appid[uid%100000]=1
    }
    END {
      if(status)exit status
      for(uid in selected_uid)if(!(uid in known_uid))exit 67
      for(appid in selected_appid)if(appid in manager_appid)exit 65
    }
  ' "$uid_file" "$packages"
}

doh_state_validate_file() {
  [ "$#" -eq 1 ] || return 64
  local file=$1
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    function bad(){exit 65}
    NF!=2{bad()}
    $1!~/^(schema_version|desired_mode|effective_mode|endpoint_sha256|uids_sha256|endpoint_fingerprint|transition_token|active_slot|updated_at|last_error)$/{bad()}
    seen[$1]++{bad()}
    $1=="schema_version" && $2!="1"{bad()}
    ($1=="desired_mode" || $1=="effective_mode") && $2!~/^(off|global|selected)$/{bad()}
    ($1=="endpoint_sha256" || $1=="uids_sha256") && $2!~/^[0-9a-f]{64}$/{bad()}
    $1=="endpoint_fingerprint" && $2!="null" && $2!~/^[0-9a-f]{12}$/{bad()}
    $1=="transition_token" && $2!="null" && $2!~/^[0-9a-f]{16}$/{bad()}
    $1=="active_slot" && $2!="null" && $2!~/^[ab]$/{bad()}
    $1=="updated_at" && $2!~/^[0-9]+$/{bad()}
    $1=="last_error" && $2!~/^(null|invalid_endpoint|invalid_config|package_state_invalid|test_failed|commit_failed|recovery_failed|runtime_failed|private_dns_active|companion_unavailable|upstream_unavailable|companion_exited|bootstrap_unresolved|firewall_unsupported)$/{bad()}
    END{if(NR!=10)bad()}
  ' "$file"
}

doh_triplet_validate() {
  [ "$#" -eq 3 ] || return 64
  local state=$1 endpoint=$2 uids=$3 expected actual fingerprint bytes
  doh_state_validate_file "$state" || return
  [ -f "$endpoint" ] && [ ! -L "$endpoint" ] || return 66
  doh_uid_file_validate "$uids" || return
  expected=$("$BB" awk -F= '$1=="endpoint_sha256"{print $2}' "$state") || return 74
  actual=$(sha256_file "$endpoint") || return
  [ "$expected" = "$actual" ] || return 65
  expected=$("$BB" awk -F= '$1=="uids_sha256"{print $2}' "$state") || return 74
  actual=$(sha256_file "$uids") || return
  [ "$expected" = "$actual" ] || return 65
  bytes=$(wc -c < "$endpoint" | "$BB" tr -d ' ') || return 74
  fingerprint=$("$BB" awk -F= '$1=="endpoint_fingerprint"{print $2}' "$state") || return 74
  if [ "$bytes" -eq 0 ]; then
    [ "$fingerprint" = null ] || return 65
  else
    doh_endpoint_validate_file "$endpoint" || return
    actual=$(sha256_file "$endpoint") || return
    [ "$fingerprint" = "$(printf '%s' "$actual" | "$BB" cut -c53-64)" ] || return 65
  fi
}

doh_state_write() {
  [ "$#" -eq 6 ] || return 64
  local mode=$1 endpoint=$2 uids=$3 error=$4 updated=$5 output=$6 endpoint_hash uids_hash fingerprint
  doh_mode_valid "$mode" || return 65
  [ "$error" = null ] || doh_error_valid "$error" || return 65
  endpoint_hash=$(sha256_file "$endpoint") || return
  uids_hash=$(sha256_file "$uids") || return
  [ -s "$endpoint" ] && fingerprint=$(printf '%s' "$endpoint_hash" | "$BB" cut -c53-64) || fingerprint=null
  {
    printf 'schema_version=1\n'
    printf 'desired_mode=%s\n' "$mode"
    printf 'effective_mode=off\n'
    printf 'endpoint_sha256=%s\n' "$endpoint_hash"
    printf 'uids_sha256=%s\n' "$uids_hash"
    printf 'endpoint_fingerprint=%s\n' "$fingerprint"
    printf 'transition_token=null\n'
    printf 'active_slot=null\n'
    printf 'updated_at=%s\n' "$updated"
    printf 'last_error=%s\n' "$error"
  } > "$output" || return 74
  chmod 600 "$output" || return 74
  doh_triplet_validate "$output" "$endpoint" "$uids"
}

doh_phase_write() {
  [ "$#" -eq 1 ] || return 64
  case "$1" in prepared|endpoint_published|uids_published|state_published) ;; *) return 65 ;; esac
  local tmp="$DOH_TX_DIR/phase.prop.tmp.$$"
  printf 'schema_version=1\nphase=%s\n' "$1" > "$tmp" || return 74
  chmod 600 "$tmp" || { rm -f "$tmp"; return 74; }
  mv -f "$tmp" "$DOH_TX_MARKER" || { rm -f "$tmp"; return 74; }
}

doh_publish_file() {
  [ "$#" -eq 2 ] || return 64
  local source target tmp
  source=$1
  target=$2
  tmp="$CONFIG_DIR/.${target##*/}.tmp.$$"
  cp "$source" "$tmp" || return 74
  chmod 600 "$tmp" || { rm -f "$tmp"; return 74; }
  atomic_replace_file "$tmp" "$target" || { local result=$?; rm -f "$tmp"; return "$result"; }
}

doh_transaction_cleanup() {
  rm -f "$DOH_TX_MARKER"
  rm -rf "$DOH_TX_PREVIOUS" "$DOH_TX_STAGED"
}

doh_transaction_restore() {
  doh_triplet_validate "$DOH_TX_PREVIOUS/doh.prop" "$DOH_TX_PREVIOUS/doh-endpoint.txt" "$DOH_TX_PREVIOUS/doh-uids.tsv" || return 76
  doh_publish_file "$DOH_TX_PREVIOUS/doh-endpoint.txt" "$DOH_CONFIG_ENDPOINT" || return 76
  doh_publish_file "$DOH_TX_PREVIOUS/doh-uids.tsv" "$DOH_CONFIG_UIDS" || return 76
  doh_publish_file "$DOH_TX_PREVIOUS/doh.prop" "$DOH_CONFIG_STATE" || return 76
  doh_triplet_validate "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS" || return 76
  doh_transaction_cleanup
}

doh_commit_triplet() {
  [ "$#" -eq 3 ] || return 64
  local state=$1 endpoint=$2 uids=$3 result
  doh_triplet_validate "$state" "$endpoint" "$uids" || return
  doh_triplet_validate "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS" || return
  doh_transaction_cleanup
  mkdir -p "$DOH_TX_PREVIOUS" "$DOH_TX_STAGED" || return 73
  chmod 700 "$DOH_TX_PREVIOUS" "$DOH_TX_STAGED" || return 74
  cp "$DOH_CONFIG_STATE" "$DOH_TX_PREVIOUS/doh.prop" &&
    cp "$DOH_CONFIG_ENDPOINT" "$DOH_TX_PREVIOUS/doh-endpoint.txt" &&
    cp "$DOH_CONFIG_UIDS" "$DOH_TX_PREVIOUS/doh-uids.tsv" || { doh_transaction_cleanup; return 74; }
  cp "$state" "$DOH_TX_STAGED/doh.prop" && cp "$endpoint" "$DOH_TX_STAGED/doh-endpoint.txt" &&
    cp "$uids" "$DOH_TX_STAGED/doh-uids.tsv" || { doh_transaction_cleanup; return 74; }
  chmod 600 "$DOH_TX_PREVIOUS"/* "$DOH_TX_STAGED"/* || { doh_transaction_cleanup; return 74; }
  doh_triplet_validate "$DOH_TX_STAGED/doh.prop" "$DOH_TX_STAGED/doh-endpoint.txt" "$DOH_TX_STAGED/doh-uids.tsv" || { doh_transaction_cleanup; return 65; }
  doh_phase_write prepared || { doh_transaction_cleanup; return 74; }
  doh_publish_file "$DOH_TX_STAGED/doh-endpoint.txt" "$DOH_CONFIG_ENDPOINT" || result=$?
  [ -n "${result-}" ] || doh_phase_write endpoint_published || result=$?
  [ -n "${result-}" ] || doh_publish_file "$DOH_TX_STAGED/doh-uids.tsv" "$DOH_CONFIG_UIDS" || result=$?
  [ -n "${result-}" ] || doh_phase_write uids_published || result=$?
  [ -n "${result-}" ] || doh_publish_file "$DOH_TX_STAGED/doh.prop" "$DOH_CONFIG_STATE" || result=$?
  [ -n "${result-}" ] || doh_phase_write state_published || result=$?
  if [ -n "${result-}" ]; then
    doh_transaction_restore || return 76
    return "$result"
  fi
  doh_triplet_validate "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS" || { doh_transaction_restore; return 76; }
  doh_transaction_cleanup
}

doh_runtime_defaults() {
  [ -e "$DOH_RUNTIME_STATE" ] || {
    printf 'schema_version=1\ncompanion_state=stopped\nfirewall_state=absent\ncoverage=system_dns\ntransition_token=null\nactive_slot=null\nupdated_at=0\nlast_error=null\n' > "$DOH_RUNTIME_STATE" || return 74
  }
  [ -e "$DOH_LAST_TEST" ] || {
    printf 'schema_version=1\nresult=none\nendpoint_fingerprint=null\nupdated_at=0\nerror=null\n' > "$DOH_LAST_TEST" || return 74
  }
  [ -f "$DOH_RUNTIME_STATE" ] && [ ! -L "$DOH_RUNTIME_STATE" ] || return 65
  [ -f "$DOH_LAST_TEST" ] && [ ! -L "$DOH_LAST_TEST" ] || return 65
  # Migrate the pre-Task-5 seven-line runtime record without touching any
  # effective routing state; later validation is strict and fail-closed.
  if [ "$(wc -l < "$DOH_RUNTIME_STATE" | "$BB" tr -d ' ')" -eq 7 ] &&
    "$BB" awk -F= '$1=="schema_version"||$1=="companion_state"||$1=="firewall_state"||$1=="coverage"||$1=="transition_token"||$1=="updated_at"||$1=="last_error"{seen[$1]++} END{exit (seen["schema_version"]==1&&seen["companion_state"]==1&&seen["firewall_state"]==1&&seen["coverage"]==1&&seen["transition_token"]==1&&seen["updated_at"]==1&&seen["last_error"]==1)?0:1}' "$DOH_RUNTIME_STATE"; then
    tmp="$DOH_RUNTIME_STATE.migrate.$$"
    "$BB" awk '1; $1=="transition_token=null"{print "active_slot=null"}' "$DOH_RUNTIME_STATE" > "$tmp" || { rm -f "$tmp"; return 74; }
    chmod 600 "$tmp" || { rm -f "$tmp"; return 74; }
    atomic_replace_file "$tmp" "$DOH_RUNTIME_STATE" || { rm -f "$tmp"; return 74; }
  fi
  [ "$(wc -l < "$DOH_RUNTIME_STATE" | "$BB" tr -d ' ')" -eq 8 ] || return 65
  "$BB" awk -F= '
    function bad(){exit 1}
    NF!=2{bad()}
    $1!~/^(schema_version|companion_state|firewall_state|coverage|transition_token|active_slot|updated_at|last_error)$/{bad()}
    seen[$1]++{bad()}
    $1=="schema_version"&&$2!="1"{bad()}
    $1=="companion_state"&&$2!~/^(stopped|starting|running)$/{bad()}
    $1=="firewall_state"&&$2!~/^(absent|staged|active|incomplete)$/{bad()}
    $1=="coverage"&&$2!~/^(system_dns|all_dns|direct_dns_only)$/{bad()}
    $1=="transition_token"&&$2!="null"&&$2!~/^[0-9a-f]{16}$/{bad()}
    $1=="active_slot"&&$2!~/^(null|a|b)$/{bad()}
    $1=="updated_at"&&$2!~/^[0-9]+$/{bad()}
    $1=="last_error"&&$2!~/^(null|invalid_endpoint|invalid_config|package_state_invalid|test_failed|commit_failed|recovery_failed|runtime_failed|private_dns_active|companion_unavailable|upstream_unavailable|companion_exited|bootstrap_unresolved|firewall_unsupported)$/{bad()}
    END{if(NR!=8)bad()}
  ' "$DOH_RUNTIME_STATE" || return 65
  chmod 600 "$DOH_RUNTIME_STATE" "$DOH_LAST_TEST" || return 74
}

doh_runtime_write() {
  [ "$#" -eq 7 ] || return 64
  local companion=$1 firewall=$2 coverage=$3 transition=$4 slot=$5 error=$6 updated=$7 tmp
  case "$companion" in stopped|starting|running) ;; *) return 65 ;; esac
  case "$firewall" in absent|staged|active|incomplete) ;; *) return 65 ;; esac
  case "$coverage" in system_dns|all_dns|direct_dns_only) ;; *) return 65 ;; esac
  [ "$transition" = null ] || { [ "${#transition}" -eq 16 ] && case "$transition" in *[!0-9a-f]*) false ;; *) true ;; esac; } || return 65
  case "$slot" in null|a|b) ;; *) return 65 ;; esac
  [ "$error" = null ] || doh_error_valid "$error" || return 65
  decimal_uint_in_range "$updated" 9999999999999999999 0 || return 65
  mkdir -p "$DOH_RUNTIME_DIR" || return 73
  tmp="$DOH_RUNTIME_STATE.tmp.$$"
  {
    printf 'schema_version=1\n'
    printf 'companion_state=%s\n' "$companion"
    printf 'firewall_state=%s\n' "$firewall"
    printf 'coverage=%s\n' "$coverage"
    printf 'transition_token=%s\n' "$transition"
    printf 'active_slot=%s\n' "$slot"
    printf 'updated_at=%s\n' "$updated"
    printf 'last_error=%s\n' "$error"
  } > "$tmp" || { rm -f "$tmp"; return 74; }
  chmod 600 "$tmp" || { rm -f "$tmp"; return 74; }
  atomic_replace_file "$tmp" "$DOH_RUNTIME_STATE"
}

doh_state_update_runtime() {
  [ "$#" -eq 5 ] || return 64
  local desired=$1 effective=$2 transition=$3 slot=$4 error=$5 endpoint_hash uids_hash fingerprint now tmp
  doh_mode_valid "$desired" || return 65
  doh_mode_valid "$effective" || return 65
  [ "$transition" = null ] || { [ "${#transition}" -eq 16 ] && case "$transition" in *[!0-9a-f]*) false ;; *) true ;; esac; } || return 65
  case "$slot" in null|a|b) ;; *) return 65 ;; esac
  [ "$error" = null ] || doh_error_valid "$error" || return 65
  [ "$effective" = off ] && { [ "$transition" = null ] && [ "$slot" = null ]; } || {
    [ "$desired" = "$effective" ] && [ "$transition" != null ] && [ "$slot" != null ]
  } || return 65
  doh_triplet_validate "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS" || return
  endpoint_hash=$(sha256_file "$DOH_CONFIG_ENDPOINT") || return
  uids_hash=$(sha256_file "$DOH_CONFIG_UIDS") || return
  fingerprint=$("$BB" awk -F= '$1=="endpoint_fingerprint"{print $2}' "$DOH_CONFIG_STATE") || return 74
  now=$(date +%s 2>/dev/null || printf 0)
  tmp="$CONFIG_DIR/.doh.prop.runtime.$$"
  {
    printf 'schema_version=1\n'
    printf 'desired_mode=%s\n' "$desired"
    printf 'effective_mode=%s\n' "$effective"
    printf 'endpoint_sha256=%s\n' "$endpoint_hash"
    printf 'uids_sha256=%s\n' "$uids_hash"
    printf 'endpoint_fingerprint=%s\n' "$fingerprint"
    printf 'transition_token=%s\n' "$transition"
    printf 'active_slot=%s\n' "$slot"
    printf 'updated_at=%s\n' "$now"
    printf 'last_error=%s\n' "$error"
  } > "$tmp" || { rm -f "$tmp"; return 74; }
  chmod 600 "$tmp" || { rm -f "$tmp"; return 74; }
  doh_triplet_validate "$tmp" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS" || { rm -f "$tmp"; return 65; }
  atomic_replace_file "$tmp" "$DOH_CONFIG_STATE" || { local result=$?; rm -f "$tmp"; return "$result"; }
  doh_triplet_validate "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS"
}

doh_bootstrap() {
  local state_tmp endpoint_tmp uids_tmp result
  umask 077
  doh_init_paths
  mkdir -p "$DOH_RUNTIME_DIR" "$DOH_TX_DIR" || return 73
  chmod 700 "$DOH_RUNTIME_DIR" "$DOH_TX_DIR" || return 74
  doh_runtime_defaults || return
  if [ -e "$DOH_TX_MARKER" ] || [ -L "$DOH_TX_MARKER" ]; then
    [ -f "$DOH_TX_MARKER" ] && [ ! -L "$DOH_TX_MARKER" ] || return 65
    doh_transaction_restore || return
  fi
  # 检查配置文件是否存在且有效
  if [ -e "$DOH_CONFIG_STATE" ] || [ -L "$DOH_CONFIG_STATE" ] || [ -e "$DOH_CONFIG_ENDPOINT" ] || [ -L "$DOH_CONFIG_ENDPOINT" ] || [ -e "$DOH_CONFIG_UIDS" ] || [ -L "$DOH_CONFIG_UIDS" ]; then
    # 如果配置文件存在，尝试验证
    if doh_triplet_validate "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS" 2>/dev/null; then
      # 验证成功，直接返回
      return 0
    fi
    # 验证失败，清理损坏的配置文件，继续创建新的默认配置
    rm -f "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS"
  fi
  # 创建默认的 off 状态配置
  state_tmp="$RULE_TMP/doh-bootstrap-state.$$"
  endpoint_tmp="$RULE_TMP/doh-bootstrap-endpoint.$$"
  uids_tmp="$RULE_TMP/doh-bootstrap-uids.$$"
  : > "$endpoint_tmp" && : > "$uids_tmp" || { rm -f "$state_tmp" "$endpoint_tmp" "$uids_tmp"; return 74; }
  chmod 600 "$endpoint_tmp" "$uids_tmp" || { rm -f "$state_tmp" "$endpoint_tmp" "$uids_tmp"; return 74; }
  doh_state_write off "$endpoint_tmp" "$uids_tmp" null 0 "$state_tmp" || { result=$?; rm -f "$state_tmp" "$endpoint_tmp" "$uids_tmp"; return "$result"; }
  doh_publish_file "$endpoint_tmp" "$DOH_CONFIG_ENDPOINT" || result=$?
  [ -n "${result-}" ] || doh_publish_file "$uids_tmp" "$DOH_CONFIG_UIDS" || result=$?
  [ -n "${result-}" ] || doh_publish_file "$state_tmp" "$DOH_CONFIG_STATE" || result=$?
  rm -f "$state_tmp" "$endpoint_tmp" "$uids_tmp"
  [ -z "${result-}" ] || return "$result"
  doh_triplet_validate "$DOH_CONFIG_STATE" "$DOH_CONFIG_ENDPOINT" "$DOH_CONFIG_UIDS"
}

doh_status_json() {
  local desired effective fingerprint count error error_json endpoint_configured companion firewall coverage endpoint endpoint_json
  doh_bootstrap || return
  desired=$("$BB" awk -F= '$1=="desired_mode"{print $2}' "$DOH_CONFIG_STATE") || return 74
  effective=$("$BB" awk -F= '$1=="effective_mode"{print $2}' "$DOH_CONFIG_STATE") || return 74
  fingerprint=$("$BB" awk -F= '$1=="endpoint_fingerprint"{print $2}' "$DOH_CONFIG_STATE") || return 74
  error=$("$BB" awk -F= '$1=="last_error"{print $2}' "$DOH_CONFIG_STATE") || return 74
  count=$(wc -l < "$DOH_CONFIG_UIDS" | "$BB" tr -d ' ') || return 74
  companion=$("$BB" awk -F= '$1=="companion_state"{print $2}' "$DOH_RUNTIME_STATE" 2>/dev/null || true)
  firewall=$("$BB" awk -F= '$1=="firewall_state"{print $2}' "$DOH_RUNTIME_STATE" 2>/dev/null || true)
  coverage=$("$BB" awk -F= '$1=="coverage"{print $2}' "$DOH_RUNTIME_STATE" 2>/dev/null || true)
  case "$companion" in stopped|starting|running) ;; *) companion=stopped ;; esac
  case "$firewall" in absent|staged|active|incomplete) ;; *) firewall=absent ;; esac
  case "$coverage" in system_dns|all_dns|direct_dns_only) ;; *) coverage=system_dns ;; esac
  [ -s "$DOH_CONFIG_ENDPOINT" ] && endpoint_configured=true || endpoint_configured=false
  [ "$fingerprint" = null ] && fingerprint=null || fingerprint='"'"$fingerprint"'"'
  [ "$error" = null ] && error_json=null || error_json='"'"$error"'"'
  # The endpoint is returned so the WebUI can prefill its input instead of making
  # the address be retyped on every re-enable. Only a committed, still-valid
  # endpoint is echoed; anything unparseable is reported as absent rather than
  # emitted raw. Callers must keep treating this as user-supplied data.
  endpoint_json=null
  if [ -s "$DOH_CONFIG_ENDPOINT" ] && doh_endpoint_validate_file "$DOH_CONFIG_ENDPOINT" 2>/dev/null; then
    endpoint=$(cat "$DOH_CONFIG_ENDPOINT") || return 74
    endpoint_json='"'"$(printf '%s' "$endpoint" | json_escape)"'"'
  fi
  printf '{"supported":true,"modes":["off","global","selected"],"desiredMode":"%s","effectiveMode":"%s","endpointConfigured":%s,"endpointFingerprint":%s,"endpoint":%s,"selectedUidCount":%s,"companionState":"%s","firewallState":"%s","coverage":"%s","lastError":%s}\n' \
    "$desired" "$effective" "$endpoint_configured" "$fingerprint" "$endpoint_json" "$count" "$companion" "$firewall" "$coverage" "$error_json"
}

doh_apply() {
  [ "$#" -eq 3 ] || return 64
  local mode=$1 endpoint=$2 config=$3 endpoint_tmp="$RULE_TMP/doh-apply-endpoint.$$" uids_tmp="$RULE_TMP/doh-apply-uids.$$" state_tmp="$RULE_TMP/doh-apply-state.$$" now result
  doh_mode_valid "$mode" || return 65
  doh_bootstrap || return
  doh_endpoint_value_write "$endpoint" "$endpoint_tmp" || { result=$?; rm -f "$endpoint_tmp"; return "$result"; }
  doh_config_b64_decode "$config" "$uids_tmp" || { result=$?; rm -f "$endpoint_tmp" "$uids_tmp"; return "$result"; }
  if [ "$mode" = selected ]; then
    [ -s "$uids_tmp" ] || { rm -f "$endpoint_tmp" "$uids_tmp"; return 65; }
    doh_validate_uid_ownership "$uids_tmp" || { result=$?; rm -f "$endpoint_tmp" "$uids_tmp"; return "$result"; }
  else
    [ ! -s "$uids_tmp" ] || { rm -f "$endpoint_tmp" "$uids_tmp"; return 65; }
  fi
  now=$(date +%s 2>/dev/null || printf 0)
  doh_state_write "$mode" "$endpoint_tmp" "$uids_tmp" null "$now" "$state_tmp" || { result=$?; rm -f "$endpoint_tmp" "$uids_tmp" "$state_tmp"; return "$result"; }
  doh_commit_triplet "$state_tmp" "$endpoint_tmp" "$uids_tmp"
  result=$?
  rm -f "$endpoint_tmp" "$uids_tmp" "$state_tmp"
  return "$result"
}

doh_disable() {
  [ "$#" -eq 0 ] || return 64
  local state_tmp endpoint_tmp uids_tmp now result
  doh_bootstrap || return
  state_tmp="$RULE_TMP/doh-disable-state.$$"
  endpoint_tmp="$RULE_TMP/doh-disable-endpoint.$$"
  uids_tmp="$RULE_TMP/doh-disable-uids.$$"
  # Turning encrypted DNS off used to blank the endpoint, which meant the address
  # had to be retyped on every re-enable. Carry the committed endpoint forward
  # instead: desired_mode=off already stops every runtime path from using it, and
  # doh_state_write recomputes the hash and fingerprint from whatever it is given,
  # so the triplet stays internally consistent either way. The uid list is still
  # cleared -- an off state has no selected apps, and a stale list would fail the
  # "global mode must have an empty uid file" check on the next enable.
  if [ -s "$DOH_CONFIG_ENDPOINT" ] && doh_endpoint_validate_file "$DOH_CONFIG_ENDPOINT" 2>/dev/null; then
    cp "$DOH_CONFIG_ENDPOINT" "$endpoint_tmp" || { rm -f "$endpoint_tmp"; return 74; }
  else
    : > "$endpoint_tmp" || { rm -f "$endpoint_tmp"; return 74; }
  fi
  : > "$uids_tmp" || { rm -f "$endpoint_tmp" "$uids_tmp"; return 74; }
  chmod 600 "$endpoint_tmp" "$uids_tmp" || { rm -f "$endpoint_tmp" "$uids_tmp"; return 74; }
  now=$(date +%s 2>/dev/null || printf 0)
  doh_state_write off "$endpoint_tmp" "$uids_tmp" null "$now" "$state_tmp" || {
    result=$?
    rm -f "$state_tmp" "$endpoint_tmp" "$uids_tmp"
    return "$result"
  }
  doh_commit_triplet "$state_tmp" "$endpoint_tmp" "$uids_tmp"
  result=$?
  rm -f "$state_tmp" "$endpoint_tmp" "$uids_tmp"
  return "$result"
}

doh_test_endpoint() {
  [ "$#" -eq 1 ] || return 64
  local endpoint=$1 endpoint_tmp="$RULE_TMP/doh-test-endpoint.$$" state_tmp="$DOH_RUNTIME_DIR/last-test.prop.tmp.$$" hash fingerprint now result
  doh_bootstrap || return
  doh_endpoint_value_write "$endpoint" "$endpoint_tmp" || { result=$?; rm -f "$endpoint_tmp"; return "$result"; }
  hash=$(sha256_file "$endpoint_tmp") || { rm -f "$endpoint_tmp"; return 74; }
  fingerprint=$(printf '%s' "$hash" | "$BB" cut -c53-64)
  now=$(date +%s 2>/dev/null || printf 0)
  printf 'schema_version=1\nresult=ok\nendpoint_fingerprint=%s\nupdated_at=%s\nerror=null\n' "$fingerprint" "$now" > "$state_tmp" || { rm -f "$endpoint_tmp" "$state_tmp"; return 74; }
  chmod 600 "$state_tmp" || { rm -f "$endpoint_tmp" "$state_tmp"; return 74; }
  atomic_replace_file "$state_tmp" "$DOH_LAST_TEST" || { result=$?; rm -f "$endpoint_tmp" "$state_tmp"; return "$result"; }
  rm -f "$endpoint_tmp"
}

doh_apps_json() {
  [ "$#" -eq 3 ] || return 64
  local query_b64=$1 cursor=$2 limit=$3 packages=${DOH_PACKAGES_LIST:-/data/system/packages.list}
  local query_file="$RULE_TMP/doh-query.$$" rows="$RULE_TMP/doh-app-rows.$$" sorted="$RULE_TMP/doh-app-sorted.$$" query result
  decimal_uint_in_range "$cursor" "$DOH_MAX_UID" 0 || return 65
  decimal_uint_in_range "$limit" "$DOH_MAX_APPS" 1 || return 65
  doh_query_b64_decode "$query_b64" "$query_file" || return
  query=$(cat "$query_file") || { rm -f "$query_file"; return 74; }
  doh_packages_regular || { result=$?; rm -f "$query_file"; return "$result"; }
  "$BB" awk -v query="$query" '
    function bad(){exit 65}
    {
      if(NF<2 || $1!~/^[A-Za-z0-9_.-]+$/ || $2!~/^[0-9]+$/ || $2~/^0[0-9]/)bad()
      uid=$2+0
      if(uid<0 || uid>4294967294)bad()
      appid=uid%100000
      key=uid SUBSEP $1
      if(seen[key]++)bad()
      pkg[NR]=$1; fulluid[NR]=$2; app[NR]=appid
      if($1~/^(me\.weishu\.kernelsu|com\.rifsxd\.ksunext|me\.bmax\.apatch)$/)manager[appid]=1
    }
    END{
      for(i=1;i<=NR;i++)if(app[i]>=10000 && app[i]<=19999 && fulluid[i]!=65534 && !(app[i] in manager) && (query=="" || index(pkg[i],query)>0))
        print fulluid[i] "\t" pkg[i]
    }
  ' "$packages" > "$rows"
  result=$?
  rm -f "$query_file"
  [ "$result" -eq 0 ] || { rm -f "$rows"; return 65; }
  LC_ALL=C "$BB" sort -t "$(printf '\t')" -k1,1n -k2,2 "$rows" > "$sorted" || { rm -f "$rows" "$sorted"; return 74; }
  "$BB" awk -F '\t' -v cursor="$cursor" -v limit="$limit" '
    function emit_group( shared, i){
      if(group_uid=="" || group_uid+0<=cursor+0)return
      group_count++
      if(group_count>limit){more=1; return}
      if(output_count++)printf ","
      shared=(package_count>1?"true":"false")
      printf "{\"uid\":%s,\"packages\":[",group_uid
      for(i=1;i<=package_count;i++){if(i>1)printf ","; printf "\"%s\"",packages[i]}
      printf "],\"shared\":%s}",shared
      last_cursor=group_uid
    }
    BEGIN{printf "{\"apps\":["}
    {
      if(group_uid!="" && $1!=group_uid){emit_group(); delete packages; package_count=0}
      group_uid=$1; packages[++package_count]=$2
    }
    END{
      emit_group()
      printf "],\"nextCursor\":"
      if(more)printf "%s",last_cursor; else printf "null"
      printf "}\n"
    }
  ' "$sorted"
  result=$?
  rm -f "$rows" "$sorted"
  return "$result"
}
