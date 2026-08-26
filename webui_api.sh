#!/system/bin/sh

API_ROOT=${WEBUI_API_ROOT:-${0%/*}}
MODDIR=${MODDIR:-$API_ROOT}
BB=${BB:-$MODDIR/busybox/busybox}
[ -x "$BB" ] || BB=$(command -v busybox 2>/dev/null || printf '%s' "$BB")
SYSTEM_SH=${SYSTEM_SH:-/system/bin/sh}
export MODDIR BB SYSTEM_SH

. "$API_ROOT/lib/rules/common.sh"
. "$API_ROOT/lib/rules/config.sh"
. "$API_ROOT/lib/rules/sources.sh"
. "$API_ROOT/lib/rules/generate.sh"
. "$API_ROOT/lib/rules/mount.sh"
. "$API_ROOT/lib/rules/diagnostics.sh"
. "$API_ROOT/lib/rules/status.sh"
. "$API_ROOT/lib/rules/doh.sh"
. "$API_ROOT/lib/rules/operations.sh"
APP_POLICY_SOURCE_ONLY=1 . "$API_ROOT/lib/rules/app_policy.sh"

api_error() {
  local code=$1 message=$2 code_json message_json
  code_json=$(printf '%s' "$code" | json_escape)
  message_json=$(printf '%s' "$message" | json_escape)
  printf '{"ok":false,"error":{"code":"%s","message":"%s"}}\n' "$code_json" "$message_json"
}

api_ok_data() {
  printf '{"ok":true,"data":%s}\n' "$1"
}

api_uint_valid() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [ "${#1}" -le 18 ] || return 1
  return 0
}

api_history_uint_valid() {
  decimal_uint_in_range "$@"
}

api_history_domain_arg_valid() {
  local encoded=$1 tmp canonical bytes domain result=0
  [ "$encoded" != - ] || return 0
  case "$encoded" in ''|*[!A-Za-z0-9+/=]*) return 1 ;; esac
  [ "${#encoded}" -le 340 ] || return 1
  [ $(( ${#encoded} % 4 )) -eq 0 ] || return 1
  tmp="$RULE_TMP/api-history-domain.$$"
  rm -f "$tmp"
  printf '%s' "$encoded" | "$BB" base64 -d > "$tmp" 2>/dev/null || result=1
  if [ "$result" -eq 0 ]; then
    canonical=$("$BB" base64 "$tmp" | "$BB" tr -d '\n') || result=1
    [ "$canonical" = "$encoded" ] || result=1
  fi
  if [ "$result" -eq 0 ]; then
    bytes=$(wc -c < "$tmp" | "$BB" tr -d ' ') || result=1
    [ "$bytes" -le 253 ] 2>/dev/null || result=1
  fi
  if [ "$result" -eq 0 ]; then
    domain=$(cat "$tmp") || result=1
    [ "${#domain}" -eq "$bytes" ] || result=1
  fi
  rm -f "$tmp"
  [ "$result" -eq 0 ] || return 1
  printf '%s\n' "$domain" | LC_ALL=C "$BB" awk '
    NR!=1 || length($0)<1 || length($0)>253 || $0!=tolower($0) || $0!~/^[a-z0-9._-]+$/ {exit 1}
  '
}

api_history_args_valid() {
  [ "$#" -eq 6 ] || return 1
  api_history_uint_valid "$1" 50000 0 || return 1
  api_history_uint_valid "$2" 200 1 || return 1
  api_history_uint_valid "$3" 9223372036854775807 0 || return 1
  [ "$4" = - ] || api_history_uint_valid "$4" 4294967294 0 || return 1
  [ "$5" = - ] || api_history_uint_valid "$5" 65535 1 || return 1
  api_history_domain_arg_valid "$6"
}

# 按游标分页读取任意日志文件；规则日志与运行日志共用。
api_log_file_data() {
  local file=$1 cursor=$2 max=$3 size start text next
  api_uint_valid "$cursor" && api_uint_valid "$max" || return 65
  [ "$max" -ge 1024 ] 2>/dev/null && [ "$max" -le 32768 ] 2>/dev/null || return 65
  if [ ! -f "$file" ]; then
    printf '{"cursor":0,"nextCursor":0,"text":""}\n'
    return 0
  fi
  size=$("$BB" wc -c < "$file" | "$BB" tr -d ' ') || return 74
  [ "$cursor" -le "$size" ] 2>/dev/null || cursor=$size
  start=$((cursor + 1))
  text=$("$BB" tail -c "+$start" "$file" | "$BB" head -c "$max" | json_escape) || return 74
  next=$((cursor + max))
  [ "$next" -le "$size" ] || next=$size
  printf '{"cursor":%s,"nextCursor":%s,"text":"%s"}\n' "$cursor" "$next" "$text"
}

api_logs_data() {
  api_log_file_data "$RULE_LOG" "$1" "$2"
}

api_runtime_logs_data() {
  api_log_file_data "$RUNTIME_LOG" "$1" "$2"
}

# 只清运行日志本体与它的轮转代，不碰规则日志。
api_runtime_logs_clear() {
  rm -f "$RUNTIME_LOG" "$RUNTIME_LOG.1" "$RUNTIME_LOG.2" || return 74
  printf '{"cleared":true}\n'
}

# 导出目录白名单，与相册那套同源。测试可以覆写。
RUNTIME_LOG_EXPORT_ROOTS=${RUNTIME_LOG_EXPORT_ROOTS:-"/sdcard/Download /storage/emulated/0/Download /sdcard /storage/emulated/0"}

# 把运行日志（含轮转代，按时间从旧到新）导出成一个纯文本文件。
#
# 目的地由这里自己挑，WebUI 一个参数都不传：路径不经过前端，就没有可注入的面。
api_runtime_logs_export() {
  local root dest name tmp bytes
  [ -f "$RUNTIME_LOG" ] || [ -f "$RUNTIME_LOG.1" ] || [ -f "$RUNTIME_LOG.2" ] || return 66
  name="jingjie-runtime-log-$(date +%Y%m%d-%H%M%S 2>/dev/null || printf 'export').txt"
  dest=
  for root in $RUNTIME_LOG_EXPORT_ROOTS; do
    [ -d "$root" ] || continue
    tmp="$root/.jingjie-write-test.$$"
    if : > "$tmp" 2>/dev/null; then
      rm -f "$tmp"
      dest="$root/$name"
      break
    fi
    rm -f "$tmp" 2>/dev/null || true
  done
  [ -n "$dest" ] || return 73
  # 轮转代是越旧编号越大，所以 .2 -> .1 -> 当前，导出后按时间顺序可读。
  {
    [ ! -f "$RUNTIME_LOG.2" ] || cat "$RUNTIME_LOG.2"
    [ ! -f "$RUNTIME_LOG.1" ] || cat "$RUNTIME_LOG.1"
    [ ! -f "$RUNTIME_LOG" ] || cat "$RUNTIME_LOG"
  } > "$dest" 2>/dev/null || { rm -f "$dest"; return 74; }
  bytes=$("$BB" wc -c < "$dest" | "$BB" tr -d ' ') || { rm -f "$dest"; return 74; }
  printf '{"path":"%s","bytes":%s}\n' "$(printf '%s' "$dest" | json_escape)" "$bytes"
}

api_appearance_file() {
  printf '%s\n' "$CONFIG_DIR/ui-theme"
}

api_appearance_valid_file() {
  local file=$1
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    NF!=2 {exit 65}
    $1=="surface" {if(seen_surface++ || $2!~/^(classic|liquid)$/) exit 65; next}
    $1=="scheme" {if(seen_scheme++ || $2!~/^(light|dark|system)$/) exit 65; next}
    $1=="glass" {if(seen_glass++ || $2!~/^(soft|standard|strong)$/) exit 65; next}
    $1=="motion" {if(seen_motion++ || $2!~/^(auto|off)$/) exit 65; next}
    $1=="background" {if(seen_background++ || $2!~/^[01]$/) exit 65; next}
    $1=="background_revision" {if(seen_revision++ || $2!~/^[0-9]{1,9}$/) exit 65; next}
    {exit 65}
    END{
      if(NR!=6 || !seen_surface || !seen_scheme || !seen_glass || !seen_motion) exit 65
      if(!seen_background || !seen_revision) exit 65
    }
  ' "$file"
}

api_appearance_field() {
  "$BB" awk -F= -v key="$2" '$1==key{print $2}' "$1"
}

api_appearance_load() {
  local file
  APPEARANCE_SURFACE=classic
  APPEARANCE_SCHEME=system
  APPEARANCE_GLASS=soft
  APPEARANCE_MOTION=auto
  APPEARANCE_BACKGROUND=0
  APPEARANCE_REVISION=0
  file=$(api_appearance_file)
  api_appearance_valid_file "$file" 2>/dev/null || return 0
  APPEARANCE_SURFACE=$(api_appearance_field "$file" surface) || return 74
  APPEARANCE_SCHEME=$(api_appearance_field "$file" scheme) || return 74
  APPEARANCE_GLASS=$(api_appearance_field "$file" glass) || return 74
  APPEARANCE_MOTION=$(api_appearance_field "$file" motion) || return 74
  APPEARANCE_BACKGROUND=$(api_appearance_field "$file" background) || return 74
  APPEARANCE_REVISION=$(api_appearance_field "$file" background_revision) || return 74
}

api_appearance_store() {
  local surface=$1 scheme=$2 glass=$3 motion=$4 background=$5 revision=$6 file tmp
  case "$surface" in classic|liquid) ;; *) return 65 ;; esac
  case "$scheme" in light|dark|system) ;; *) return 65 ;; esac
  case "$glass" in soft|standard|strong) ;; *) return 65 ;; esac
  case "$motion" in auto|off) ;; *) return 65 ;; esac
  case "$background" in 0|1) ;; *) return 65 ;; esac
  case "$revision" in ''|*[!0-9]*) return 65 ;; esac
  [ "${#revision}" -le 9 ] || return 65
  mkdir -p "$CONFIG_DIR" "$RULE_TMP" || return 73
  file=$(api_appearance_file)
  tmp="$RULE_TMP/ui-theme.$$"
  rm -f "$tmp"
  {
    printf 'surface=%s\n' "$surface"
    printf 'scheme=%s\n' "$scheme"
    printf 'glass=%s\n' "$glass"
    printf 'motion=%s\n' "$motion"
    printf 'background=%s\n' "$background"
    printf 'background_revision=%s\n' "$revision"
  } > "$tmp" || return 74
  api_appearance_valid_file "$tmp" || { rm -f "$tmp"; return 65; }
  atomic_replace_file "$tmp" "$file" || { rm -f "$tmp"; return 74; }
}

api_appearance_json() {
  api_appearance_load || return
  printf '{"surface":"%s","scheme":"%s","glass":"%s","motion":"%s","background":{"enabled":%s,"revision":%s}}\n' \
    "$APPEARANCE_SURFACE" "$APPEARANCE_SCHEME" "$APPEARANCE_GLASS" "$APPEARANCE_MOTION" \
    "$([ "$APPEARANCE_BACKGROUND" = 1 ] && printf true || printf false)" "$APPEARANCE_REVISION"
}

api_background_json() {
  printf '{"enabled":%s,"revision":%s}\n' \
    "$([ "$1" = 1 ] && printf true || printf false)" "$2"
}

api_appearance_write() {
  local surface=$1 scheme=$2 glass=$3 motion=$4
  api_appearance_load || return
  api_appearance_store "$surface" "$scheme" "$glass" "$motion" \
    "$APPEARANCE_BACKGROUND" "$APPEARANCE_REVISION" || return
  api_appearance_load || return
  api_appearance_json
}

api_background_dir() {
  printf '%s\n' "$MODDIR/webroot/user"
}

api_background_upload_file() {
  printf '%s\n' "$RULE_TMP/background-upload.jpg"
}

# 相册根目录白名单。测试可以通过环境变量覆写，WebUI 只能传路径参数。
BACKGROUND_ROOTS=${BACKGROUND_ROOTS:-"/sdcard /storage/emulated/0 /storage/self/primary"}

api_background_decode_path() {
  local encoded=$1 tmp path bytes
  case "$encoded" in ''|*[!A-Za-z0-9+/=]*) return 65 ;; esac
  [ "${#encoded}" -le 5464 ] || return 65
  [ $(( ${#encoded} % 4 )) -eq 0 ] || return 65
  mkdir -p "$RULE_TMP" || return 73
  tmp="$RULE_TMP/background-path.$$"
  rm -f "$tmp"
  printf '%s' "$encoded" | "$BB" base64 -d > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 65; }
  bytes=$("$BB" wc -c < "$tmp" | "$BB" tr -d ' ') || { rm -f "$tmp"; return 74; }
  [ "$bytes" -ge 1 ] && [ "$bytes" -le 4096 ] || { rm -f "$tmp"; return 65; }
  # busybox awk 会把 [\000-\037] 里的 NUL 当成字符串结尾，字符组永远解析失败，
  # 于是任何合法路径都会被判成非法。改用工程里通用的 grep 控制字符检查。
  LC_ALL=C "$BB" grep -q '[[:cntrl:]]' "$tmp" && { rm -f "$tmp"; return 65; }
  path=$(cat "$tmp") || { rm -f "$tmp"; return 74; }
  rm -f "$tmp"
  [ "${#path}" -eq "$bytes" ] || return 65
  case "$path" in *../*|*/..|..) return 65 ;; esac
  api_background_path_allowed "$path" || return 65
  printf '%s\n' "$path"
}

api_background_path_allowed() {
  local path=$1 root
  for root in $BACKGROUND_ROOTS; do
    [ "$path" = "$root" ] && return 0
    case "$path" in "$root"/*) return 0 ;; esac
  done
  return 65
}

api_background_image_extension() {
  local head_hex
  head_hex=$("$BB" head -c 12 "$1" | "$BB" od -An -tx1 | "$BB" tr -d ' \n') || return 74
  case "$head_hex" in
    ffd8ff*) printf 'jpg\n' ;;
    89504e47*) printf 'png\n' ;;
    52494646????????57454250*) printf 'webp\n' ;;
    *) return 65 ;;
  esac
}

api_background_list() {
  local path=$1 listing name full bytes count=0 truncated=false first=true
  [ -d "$path" ] || return 66
  mkdir -p "$RULE_TMP" || return 73
  listing="$RULE_TMP/background-list.$$"
  rm -f "$listing"
  "$BB" ls -A -- "$path" 2>/dev/null | LC_ALL=C "$BB" sort > "$listing" || : > "$listing"

  printf '{"path":"%s","parent":' "$(printf '%s' "$path" | json_escape)"
  if [ "${path%/*}" != "$path" ] && api_background_path_allowed "${path%/*}"; then
    printf '"%s"' "$(printf '%s' "${path%/*}" | json_escape)"
  else
    printf 'null'
  fi

  printf ',"dirs":['
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    full="$path/$name"
    [ -d "$full" ] || continue
    [ ! -L "$full" ] || continue
    [ "$count" -lt 300 ] || { truncated=true; break; }
    count=$((count + 1))
    if [ "$first" = true ]; then first=false; else printf ','; fi
    printf '{"name":"%s"}' "$(printf '%s' "$name" | json_escape)"
  done < "$listing"

  printf '],"files":['
  first=true
  count=0
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    full="$path/$name"
    [ -f "$full" ] || continue
    [ ! -L "$full" ] || continue
    case "$name" in
      *.jpg|*.JPG|*.jpeg|*.JPEG|*.png|*.PNG|*.webp|*.WEBP) ;;
      *) continue ;;
    esac
    [ "$count" -lt 300 ] || { truncated=true; break; }
    bytes=$("$BB" wc -c < "$full" 2>/dev/null | "$BB" tr -d ' ') || continue
    count=$((count + 1))
    if [ "$first" = true ]; then first=false; else printf ','; fi
    printf '{"name":"%s","bytes":%s}' "$(printf '%s' "$name" | json_escape)" "$bytes"
  done < "$listing"

  rm -f "$listing"
  printf '],"truncated":%s}\n' "$truncated"
}

api_background_stage() {
  local path=$1 dir target bytes ext
  [ -f "$path" ] || return 66
  [ ! -L "$path" ] || return 65
  bytes=$("$BB" wc -c < "$path" | "$BB" tr -d ' ') || return 74
  [ "$bytes" -ge 64 ] 2>/dev/null || return 65
  [ "$bytes" -le 8388608 ] 2>/dev/null || return 65
  ext=$(api_background_image_extension "$path") || return 65
  dir=$(api_background_dir)
  mkdir -p "$dir" || return 73
  api_background_unstage >/dev/null 2>&1 || true
  target="$dir/staged.$ext"
  "$BB" cp -f -- "$path" "$target" || return 74
  chmod 0644 "$target" 2>/dev/null || true
  chmod 0755 "$dir" 2>/dev/null || true
  printf '{"file":"staged.%s","bytes":%s}\n' "$ext" "$bytes"
}

api_background_unstage() {
  local dir
  dir=$(api_background_dir)
  rm -f "$dir/staged.jpg" "$dir/staged.png" "$dir/staged.webp"
  printf '{"staged":false}\n'
}

api_background_put() {
  local slot=$1 payload=$2 tmp bytes
  case "$slot" in first|next) ;; *) return 65 ;; esac
  case "$payload" in ''|*[!A-Za-z0-9+/=]*) return 65 ;; esac
  [ "${#payload}" -le 8192 ] || return 65
  [ $(( ${#payload} % 4 )) -eq 0 ] || return 65
  mkdir -p "$RULE_TMP" || return 73
  tmp=$(api_background_upload_file)
  [ "$slot" != first ] || rm -f "$tmp"
  [ "$slot" = first ] || [ -f "$tmp" ] || return 66
  printf '%s' "$payload" | "$BB" base64 -d >> "$tmp" 2>/dev/null || { rm -f "$tmp"; return 65; }
  bytes=$("$BB" wc -c < "$tmp" | "$BB" tr -d ' ') || { rm -f "$tmp"; return 74; }
  [ "$bytes" -le 4194304 ] 2>/dev/null || { rm -f "$tmp"; return 65; }
  printf '{"received":%s}\n' "$bytes"
}

api_background_is_jpeg() {
  local head_hex
  head_hex=$("$BB" head -c 3 "$1" | "$BB" od -An -tx1 | "$BB" tr -d ' \n') || return 74
  [ "$head_hex" = ffd8ff ] || return 65
}

api_background_commit() {
  local tmp dir target bytes revision
  tmp=$(api_background_upload_file)
  [ -f "$tmp" ] || return 66
  bytes=$("$BB" wc -c < "$tmp" | "$BB" tr -d ' ') || { rm -f "$tmp"; return 74; }
  [ "$bytes" -ge 64 ] 2>/dev/null || { rm -f "$tmp"; return 65; }
  api_background_is_jpeg "$tmp" || { rm -f "$tmp"; return 65; }
  api_appearance_load || { rm -f "$tmp"; return 74; }
  dir=$(api_background_dir)
  mkdir -p "$dir" || { rm -f "$tmp"; return 73; }
  target="$dir/background.jpg"
  atomic_replace_file "$tmp" "$target" || { rm -f "$tmp"; return 74; }
  chmod 0644 "$target" 2>/dev/null || true
  chmod 0755 "$dir" 2>/dev/null || true
  api_background_unstage >/dev/null 2>&1 || true
  revision=$((APPEARANCE_REVISION + 1))
  [ "$revision" -le 999999999 ] 2>/dev/null || revision=1
  api_appearance_store "$APPEARANCE_SURFACE" "$APPEARANCE_SCHEME" "$APPEARANCE_GLASS" \
    "$APPEARANCE_MOTION" 1 "$revision" || return
  api_background_json 1 "$revision"
}

api_background_clear() {
  local dir
  api_appearance_load || return
  dir=$(api_background_dir)
  rm -f "$dir/background.jpg" "$(api_background_upload_file)"
  api_background_unstage >/dev/null 2>&1 || true
  api_appearance_store "$APPEARANCE_SURFACE" "$APPEARANCE_SCHEME" "$APPEARANCE_GLASS" \
    "$APPEARANCE_MOTION" 0 0 || return
  api_background_json 0 0
}

api_background_enabled() {
  local value=$1
  case "$value" in 0|1) ;; *) return 65 ;; esac
  api_appearance_load || return
  api_appearance_store "$APPEARANCE_SURFACE" "$APPEARANCE_SCHEME" "$APPEARANCE_GLASS" \
    "$APPEARANCE_MOTION" "$value" "$APPEARANCE_REVISION" || return
  api_background_json "$value" "$APPEARANCE_REVISION"
}

api_submit_error() {
  case "${OPERATION_SUBMIT_ERROR-}" in
    operation_busy) api_error operation_busy '已有操作正在执行' ;;
    uninstalling) api_error uninstalling '模块正在卸载' ;;
    state_invalid) api_error state_invalid '运行状态损坏' ;;
    background_worker_unsupported) api_error background_worker_unsupported '当前环境不支持后台任务' ;;
    worker_start_timeout) api_error worker_start_timeout '后台任务启动超时' ;;
    *) api_error operation_failed '无法创建后台操作' ;;
  esac
}

api_write_verb_known() {
  operation_verb_valid "$1"
}

api_dispatch() {
  local verb=${1-} data result revision generation manifest history_cursor history_limit history_since history_uid history_port history_domain background_path bundle_lists bundle_templates bundle_overrides
  case "$verb" in
    status)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(status_json 2>/dev/null) || { api_error state_invalid '运行状态损坏'; return 0; }
      api_ok_data "$data"
      ;;
    diagnostics)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(diagnostics_json 2>/dev/null) || { api_error state_invalid '运行状态损坏'; return 0; }
      api_ok_data "$data"
      ;;
    doh-status)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(doh_status_json 2>/dev/null) || { api_error state_invalid '运行状态损坏'; return 0; }
      api_ok_data "$data"
      ;;
    doh-apps)
      [ "$#" -eq 4 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(doh_apps_json "$2" "$3" "$4" 2>/dev/null) || { api_error invalid_argument '参数无效'; return 0; }
      api_ok_data "$data"
      ;;
    logs)
      [ "$#" -eq 3 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_logs_data "$2" "$3" 2>/dev/null) || { api_error invalid_argument '参数无效'; return 0; }
      api_ok_data "$data"
      ;;
    runtime-logs)
      [ "$#" -eq 3 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_runtime_logs_data "$2" "$3" 2>/dev/null) || { api_error invalid_argument '参数无效'; return 0; }
      api_ok_data "$data"
      ;;
    clear-runtime-logs)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_runtime_logs_clear 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    export-runtime-logs)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_runtime_logs_export 2>/dev/null) || { api_error state_invalid '运行日志导出失败'; return 0; }
      api_ok_data "$data"
      ;;
    lists)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      config_bootstrap >/dev/null 2>&1 || { api_error state_invalid 'state invalid'; return 0; }
      revision=$(config_current_revision 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      data=$(config_lists_json "$revision" 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    sources)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      config_bootstrap >/dev/null 2>&1 || { api_error state_invalid 'state invalid'; return 0; }
      revision=$(config_current_revision 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      generation=$(active_value active_generation 2>/dev/null || true)
      manifest=
      [ -z "$generation" ] || manifest="$RULE_GENERATIONS/$generation/manifest.prop"
      [ -f "$manifest" ] || manifest=
      data=$(status_sources_projection "$revision" "$manifest" "$generation" 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    templates)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      config_bootstrap >/dev/null 2>&1 || { api_error state_invalid 'state invalid'; return 0; }
      revision=$(config_current_revision 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      data=$(source_registry_template_json "$CONFIG_DIR/revisions/$revision/sources.tsv" 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    overrides)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      config_bootstrap >/dev/null 2>&1 || { api_error state_invalid 'state invalid'; return 0; }
      revision=$(config_current_revision 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      data=$(overrides_json "$CONFIG_DIR/revisions/$revision/overrides.tsv" 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    # 进入规则页需要的三份只读数据合并为一次调用，避免三次 shell 启动与三次 config_bootstrap。
    rules-bundle)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      config_bootstrap >/dev/null 2>&1 || { api_error state_invalid 'state invalid'; return 0; }
      revision=$(config_current_revision 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      bundle_lists=$(config_lists_json "$revision" 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      bundle_templates=$(source_registry_template_json "$CONFIG_DIR/revisions/$revision/sources.tsv" 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      bundle_overrides=$(overrides_json "$CONFIG_DIR/revisions/$revision/overrides.tsv" 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "{\"lists\":$bundle_lists,\"templates\":$bundle_templates,\"overrides\":$bundle_overrides}"
      ;;
    notice-status)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(preferences_notice_json 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    ui-theme)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_appearance_json 2>/dev/null) || { api_error state_invalid '界面偏好不可用'; return 0; }
      api_ok_data "$data"
      ;;
    set-ui-theme)
      [ "$#" -eq 5 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_appearance_write "$2" "$3" "$4" "$5" 2>/dev/null) || { api_error invalid_argument '参数无效'; return 0; }
      api_ok_data "$data"
      ;;
    set-background-enabled)
      [ "$#" -eq 2 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_background_enabled "$2" 2>/dev/null) || { api_error invalid_argument '参数无效'; return 0; }
      api_ok_data "$data"
      ;;
    set-background-put)
      [ "$#" -eq 3 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_background_put "$2" "$3" 2>/dev/null) || { api_error invalid_argument '参数无效'; return 0; }
      api_ok_data "$data"
      ;;
    set-background-commit)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_background_commit 2>/dev/null) || { api_error invalid_argument '背景图片无效'; return 0; }
      api_ok_data "$data"
      ;;
    set-background-clear)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_background_clear 2>/dev/null) || { api_error state_invalid '界面偏好不可用'; return 0; }
      api_ok_data "$data"
      ;;
    background-list)
      [ "$#" -eq 2 ] || { api_error invalid_argument '参数无效'; return 0; }
      background_path=$(api_background_decode_path "$2" 2>/dev/null) || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_background_list "$background_path" 2>/dev/null) || { api_error not_found '目录不可读'; return 0; }
      api_ok_data "$data"
      ;;
    background-stage)
      [ "$#" -eq 2 ] || { api_error invalid_argument '参数无效'; return 0; }
      background_path=$(api_background_decode_path "$2" 2>/dev/null) || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_background_stage "$background_path" 2>/dev/null) || { api_error invalid_argument '图片不可用'; return 0; }
      api_ok_data "$data"
      ;;
    background-unstage)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(api_background_unstage 2>/dev/null) || { api_error state_invalid '界面偏好不可用'; return 0; }
      api_ok_data "$data"
      ;;
    log-mode)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(preferences_log_mode_json 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    runtime-log-mode)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(preferences_runtime_log_json 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    set-runtime-log-mode)
      [ "$#" -eq 2 ] || { api_error invalid_argument '参数无效'; return 0; }
      preferences_set_runtime_log "$2" 2>/dev/null || { api_error invalid_argument '参数无效'; return 0; }
      data=$(preferences_runtime_log_json 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    app-capability)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(app_policy_capability_json 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    app-policy)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$(app_policy_read_json 2>/dev/null) || { api_error state_invalid 'state invalid'; return 0; }
      api_ok_data "$data"
      ;;
    history-status)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$("$SYSTEM_SH" "$MODDIR/history_manager.sh" history-status 2>/dev/null) || { api_error state_invalid '历史状态不可用'; return 0; }
      api_ok_data "$data"
      ;;
    history)
      case "$#" in
        4) set -- "$@" - - - ;;
        5) set -- "$@" - - ;;
        6) set -- "$@" - ;;
        7) ;;
        *) api_error invalid_argument '参数无效'; return 0 ;;
      esac
      history_cursor=$2
      history_limit=$3
      history_since=$4
      history_uid=$5
      history_port=$6
      history_domain=$7
      [ "$history_uid" != none ] || history_uid=-
      [ "$history_port" != none ] || history_port=-
      [ "$history_domain" != none ] || history_domain=-
      api_history_args_valid "$history_cursor" "$history_limit" "$history_since" \
        "$history_uid" "$history_port" "$history_domain" || {
        api_error invalid_argument '参数无效'
        return 0
      }
      set +e
      data=$("$SYSTEM_SH" "$MODDIR/history_manager.sh" history "$history_cursor" "$history_limit" \
        "$history_since" "$history_uid" "$history_port" "$history_domain" 2>/dev/null)
      result=$?
      set -e
      case "$result" in
        0) api_ok_data "$data" ;;
        *) api_error history_unavailable '拦截历史数据暂不可用' ;;
      esac
      ;;
    history-apps)
      [ "$#" -eq 1 ] || { api_error invalid_argument '参数无效'; return 0; }
      data=$("$SYSTEM_SH" "$MODDIR/history_manager.sh" history-apps 2>/dev/null) || { api_error state_invalid '历史应用不可用'; return 0; }
      api_ok_data "$data"
      ;;
    *)
      if ! api_write_verb_known "$verb"; then
        api_error invalid_verb '不支持的操作'
        return 0
      fi
      shift
      operation_arguments_valid "$verb" "$@" >/dev/null 2>&1 || {
        api_error invalid_argument '参数无效'
        return 0
      }
      set +e
      operation_submit "$verb" "$@"
      result=$?
      set -e
      if [ "$result" -eq 0 ]; then
        api_ok_data '{"accepted":true,"operationId":"'"$OPERATION_ACCEPTED_ID"'"}'
      else
        api_submit_error
      fi
      ;;
  esac
}

rules_init_paths "$MODDIR" >/dev/null 2>&1 || {
  api_error initialization_failed '模块运行目录不可用'
  exit 0
}
api_dispatch "$@"
