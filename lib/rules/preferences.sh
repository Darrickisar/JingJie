#!/system/bin/sh

preferences_notice_file() {
  printf '%s\n' "$CONFIG_DIR/notice.prop"
}

preferences_runtime_log_file() {
  printf '%s\n' "$CONFIG_DIR/runtime-log.prop"
}

preferences_validate_notice_file() {
  local file=$1
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    NF!=2 || $1!="acknowledged" || seen++ || $2!~/^[01]$/ {exit 65}
    END{if(NR!=1)exit 65}
  ' "$file"
}

preferences_validate_runtime_log_file() {
  local file=$1
  [ -f "$file" ] && [ ! -L "$file" ] || return 66
  "$BB" awk -F= '
    NF!=2 || $1!="enabled" || seen++ || $2!~/^[01]$/ {exit 65}
    END{if(NR!=1)exit 65}
  ' "$file"
}

preferences_bootstrap() {
  local notice runtime_log tmp
  mkdir -p "$CONFIG_DIR" || return 73
  notice=$(preferences_notice_file)
  runtime_log=$(preferences_runtime_log_file)
  if [ ! -e "$notice" ] && [ ! -L "$notice" ]; then
    tmp="$notice.tmp.$$"
    printf 'acknowledged=0\n' > "$tmp" || return 74
    atomic_replace_file "$tmp" "$notice" || return
  else
    preferences_validate_notice_file "$notice" || return
  fi
  # 默认开启：这份日志存在的意义就是出问题时能查，默认关掉等于没做。
  if [ ! -e "$runtime_log" ] && [ ! -L "$runtime_log" ]; then
    tmp="$runtime_log.tmp.$$"
    printf 'enabled=1\n' > "$tmp" || return 74
    atomic_replace_file "$tmp" "$runtime_log" || return
  else
    preferences_validate_runtime_log_file "$runtime_log" || return
  fi
}

preferences_notice_value() {
  local file
  preferences_bootstrap || return
  file=$(preferences_notice_file)
  "$BB" awk -F= '$1=="acknowledged"{print $2}' "$file"
}

preferences_notice_json() {
  local value
  value=$(preferences_notice_value) || return
  if [ "$value" = 1 ]; then
    printf '{"acknowledged":true}\n'
  else
    printf '{"acknowledged":false}\n'
  fi
}

preferences_set_notice() {
  [ "$#" -eq 1 ] || return 64
  local value=$1 file tmp
  [ "$value" = 0 ] || [ "$value" = 1 ] || return 65
  preferences_bootstrap || return
  file=$(preferences_notice_file)
  tmp="$file.tmp.$$"
  printf 'acknowledged=%s\n' "$value" > "$tmp" || return 74
  preferences_validate_notice_file "$tmp" || { rm -f "$tmp"; return 65; }
  atomic_replace_file "$tmp" "$file"
}

preferences_runtime_log_value() {
  local file
  preferences_bootstrap || return
  file=$(preferences_runtime_log_file)
  "$BB" awk -F= '$1=="enabled"{print $2}' "$file"
}

preferences_runtime_log_json() {
  local value
  value=$(preferences_runtime_log_value) || return
  if [ "$value" = 1 ]; then
    printf '{"enabled":true}\n'
  else
    printf '{"enabled":false}\n'
  fi
}

preferences_set_runtime_log() {
  [ "$#" -eq 1 ] || return 64
  local value=$1 file tmp
  [ "$value" = 0 ] || [ "$value" = 1 ] || return 65
  preferences_bootstrap || return
  file=$(preferences_runtime_log_file)
  tmp="$file.tmp.$$"
  printf 'enabled=%s\n' "$value" > "$tmp" || return 74
  preferences_validate_runtime_log_file "$tmp" || { rm -f "$tmp"; return 65; }
  atomic_replace_file "$tmp" "$file"
}
