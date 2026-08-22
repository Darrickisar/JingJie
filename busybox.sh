#!/system/bin/sh

busybox_candidate_has_applets() {
  candidate=$1
  [ -x "$candidate" ] || return 1
  applets=$($candidate --list 2>/dev/null) || return 1
  for applet in ash awk base64 nohup setsid nsenter sha256sum stat timeout od; do
    printf '%s\n' "$applets" | grep -x "$applet" >/dev/null 2>&1 || return 1
  done
}

busybox_setup() {
  module_dir=${MODPATH:-${MODDIR:-}}
  [ -n "$module_dir" ] || return 64
  busybox_dir="$module_dir/busybox"

  selected=
  for candidate in \
    "$busybox_dir/busybox" \
    /data/adb/ksu/bin/busybox \
    /data/adb/ap/bin/busybox \
    /data/adb/magisk/busybox
  do
    if busybox_candidate_has_applets "$candidate"; then
      selected=$candidate
      break
    fi
  done

  if [ -z "$selected" ]; then
    message='rule_engine_busybox_capability_missing'
    if command -v abort >/dev/null 2>&1; then
      abort "$message"
    fi
    printf '%s\n' "$message" >&2
    return 69
  fi

  mkdir -p "$busybox_dir" || return 73
  if [ "$selected" != "$busybox_dir/busybox" ]; then
    ln -sf "$selected" "$busybox_dir/busybox" || return 74
  fi
  "$selected" --install -s "$busybox_dir" >/dev/null 2>&1 || return 74
  BB="$busybox_dir/busybox"
  export BB
}

busybox_setup
