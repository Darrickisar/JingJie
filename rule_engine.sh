#!/system/bin/sh

ENGINE_ROOT=${RULE_ENGINE_ROOT:-${TEST_ROOT:-${0%/*}}}
MODDIR=${MODDIR:-$ENGINE_ROOT}
BB=${BB:-$MODDIR/busybox/busybox}
[ -x "$BB" ] || BB=$(command -v busybox 2>/dev/null || printf '%s' "$BB")
export MODDIR BB

. "$ENGINE_ROOT/lib/rules/common.sh"
. "$ENGINE_ROOT/lib/rules/config.sh"
. "$ENGINE_ROOT/lib/rules/status.sh"
. "$ENGINE_ROOT/lib/rules/sources.sh"
. "$ENGINE_ROOT/lib/rules/generate.sh"
. "$ENGINE_ROOT/lib/rules/mount.sh"
. "$ENGINE_ROOT/lib/rules/operations.sh"

engine_install_generation_from_work() {
  local work=$1 generation destination tmp output
  generation=$(manifest_value "$work/manifest.prop" generation_id) || return
  generation_id_valid "$generation" || return 65
  destination="$RULE_GENERATIONS/$generation"
  tmp="$destination.tmp"
  [ ! -e "$destination" ] && [ ! -e "$tmp" ] || return 76
  mkdir -p "$tmp" || return 73
  for output in all reward recovery manifest.prop; do
    cp "$work/$output" "$tmp/$output" || { rm -rf "$tmp"; return 74; }
  done
  mv "$tmp" "$destination" || return 74
  INSTALLED_GENERATION=$generation
  export INSTALLED_GENERATION
}

engine_prepare_locked() {
  config_bootstrap || return
  [ -f "$RULE_RUNTIME/active.prop" ] && return 0
  local rev work generation mode sha config_hash fetch_result
  rev=$(config_current_revision) || return
  work="$RULE_TMP/bootstrap.$$"
  rm -rf "$work"
  mkdir -p "$work/normalized" || return 73
  fetch_result=0
  fetch_enabled_sources "$work" || fetch_result=$?
  if [ "$fetch_result" -ne 0 ]; then
    [ -f "$work/sources.tsv" ] || : > "$work/sources.tsv"
    log_event warn bootstrap_sources_degraded 'online defaults unavailable; committed baseline and available caches'
  fi
  build_generation "$work" "$rev" || return
  engine_install_generation_from_work "$work" || return
  generation=$INSTALLED_GENERATION
  mode=$(mode_desired) || return
  mount_generation_for_mode "$generation" "$mode" || return
  sha=$(sha256_file "$MOUNT_SOURCE") || return
  config_hash=$(config_snapshot_hash "$rev") || return
  active_write_values "$generation" '' none "$rev" "$config_hash" "$mode" "$sha"
}

engine_bootstrap_locked() {
  engine_prepare_locked || return
  engine_mount_active
}

engine_refresh_locked() {
  local target=${1-} rev work generation result
  rev=$(config_current_revision) || return
  work="$RULE_TMP/job.$$"
  rm -rf "$work"
  mkdir -p "$work" || return 73
  if ! fetch_enabled_sources "$work" "$target"; then
    rm -rf "$work"
    return 69
  fi
  build_generation "$work" "$rev" || { result=$?; rm -rf "$work"; return "$result"; }
  engine_install_generation_from_work "$work" || { result=$?; rm -rf "$work"; return "$result"; }
  generation=$INSTALLED_GENERATION
  if [ -f "$RULE_RUNTIME/active.prop" ]; then
    engine_refresh_from_candidate "$generation" || {
      result=$?
      rm -rf "$RULE_GENERATIONS/$generation" "$work"
      return "$result"
    }
  else
    local mode source kind sha config_hash
    mode=$(mode_desired) || return
    mount_generation_for_mode "$generation" "$mode" || return
    source=$MOUNT_SOURCE; kind=$MOUNT_KIND
    mount_pid1 "$source" "$generation" "$kind" || return
    sha=$(sha256_file "$source")
    config_hash=$(config_snapshot_hash "$rev")
    active_write_values "$generation" '' none "$rev" "$config_hash" "$mode" "$sha" || return
  fi
  rm -f "$RULE_RUNTIME/initial-refresh.pending"
  rm -rf "$work"
}

engine_refresh_degraded_locked() {
  local rev work generation result effective_mode active_mode
  rev=$(config_current_revision) || return
  work="$RULE_TMP/reset.$$"
  rm -rf "$work"
  mkdir -p "$work" || return 73
  fetch_enabled_sources "$work" || log_event warn reset_sources_degraded 'using baseline and available caches' || true
  [ -f "$work/sources.tsv" ] || : > "$work/sources.tsv"
  build_generation "$work" "$rev" || { result=$?; rm -rf "$work"; return "$result"; }
  engine_install_generation_from_work "$work" || { result=$?; rm -rf "$work"; return "$result"; }
  generation=$INSTALLED_GENERATION
  if [ -f "$RULE_RUNTIME/active.prop" ]; then
    # Reset explicitly leaves the paused state and applies the newly selected
    # block_all preference. Other refresh paths preserve a paused active tuple.
    active_mode=$(active_value active_mode 2>/dev/null || true)
    effective_mode=$(mode_desired 2>/dev/null || printf 'block_all')
    if [ "$active_mode" = paused ]; then
      engine_refresh_from_candidate_mode "$generation" "$effective_mode" || {
        result=$?
        rm -rf "$RULE_GENERATIONS/$generation" "$work"
        return "$result"
      }
      rm -f "$RULE_RUNTIME/initial-refresh.pending"
      rm -rf "$work"
      return 0
    fi
    engine_refresh_from_candidate "$generation" || {
      result=$?
      rm -rf "$RULE_GENERATIONS/$generation" "$work"
      return "$result"
    }
  else
    local mode source kind sha config_hash
    mode=$(mode_desired) || return
    mount_generation_for_mode "$generation" "$mode" || return
    source=$MOUNT_SOURCE; kind=$MOUNT_KIND
    mount_pid1 "$source" "$generation" "$kind" || return
    sha=$(sha256_file "$source") || return
    config_hash=$(config_snapshot_hash "$rev") || return
    active_write_values "$generation" '' none "$rev" "$config_hash" "$mode" "$sha" || return
  fi
  rm -f "$RULE_RUNTIME/initial-refresh.pending"
  rm -rf "$work"
}

# 恢复保护时从零重建。暂停把缓存和世代都删了，所以这一步必须联网下载；
# 下载失败就沿用 degraded 的兜底：内置基线加手工名单照样能建出一版，
# 用户至少能拿回一个在拦的状态，而不是卡在暂停里出不来。
#
# 和 engine_refresh_degraded_locked 的差别只有一处：写活动元组时不留回滚指针。
# 旧世代已经被清成只剩 recovery 的残桩，不能当回滚目标。
engine_resume_rebuild_locked() {
  local mode=$1 rev work generation result
  rev=$(config_current_revision) || return
  work="$RULE_TMP/resume.$$"
  rm -rf "$work"
  mkdir -p "$work" || return 73
  fetch_enabled_sources "$work" || log_event warn resume_sources_degraded '联网失败，改用内置基线与可用缓存' || true
  [ -f "$work/sources.tsv" ] || : > "$work/sources.tsv"
  build_generation "$work" "$rev" || { result=$?; rm -rf "$work"; return "$result"; }
  engine_install_generation_from_work "$work" || { result=$?; rm -rf "$work"; return "$result"; }
  generation=$INSTALLED_GENERATION
  engine_refresh_from_candidate_mode_no_alternate "$generation" "$mode" || {
    result=$?
    rm -rf "$RULE_GENERATIONS/$generation" "$work"
    return "$result"
  }
  rm -f "$RULE_RUNTIME/initial-refresh.pending"
  rm -rf "$work"
}

engine_with_rules_lock() {
  rules_lock_acquire rules || return
  if [ -f "$RULE_RUNTIME/uninstalling" ] && [ "$1" != cleanup ]; then
    rules_lock_release rules
    return 75
  fi
  local command=$1
  shift
  set +e
  "$command" "$@"
  local result=$?
  set -e
  rules_lock_release rules || return
  return "$result"
}

engine_bootstrap() {
  rules_init_paths "$MODDIR" || return
  engine_with_rules_lock engine_bootstrap_locked
}

engine_prepare() {
  rules_init_paths "$MODDIR" || return
  RULE_FETCH_OFFLINE=1 engine_with_rules_lock engine_prepare_locked
}

# 暂停保护期间一切「会重新造出缓存和世代」的动作都要挡住。
# 直接读 active.prop，文件不在（还没初始化过）就当没暂停。
engine_active_paused() {
  local file="$RULE_RUNTIME/active.prop" mode
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  mode=$("$BB" awk -F= '$1=="active_mode"{print $2}' "$file" 2>/dev/null || true)
  [ "$mode" = paused ]
}

engine_refresh_locked_unless_paused() {
  # 刷新就是「下载全部来源再重建世代」，暂停期间这正是最不该发生的事。
  # 75 是既有的「当前状态不允许」码，webui 会照常把它翻成一句话。
  engine_active_paused && return 75
  engine_refresh_locked "$@"
}

engine_refresh() {
  rules_init_paths "$MODDIR" || return
  engine_with_rules_lock engine_refresh_locked_unless_paused
}

engine_refresh_source() {
  local target=$1
  rules_init_paths "$MODDIR" || return
  engine_with_rules_lock engine_refresh_locked_unless_paused "$target"
}

engine_mutate_and_apply() {
  local verb=$1
  shift
  rules_lock_acquire rules || return
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || { rules_lock_release rules; return 75; }
  set +e
  config_mutate_locked "$verb" "$@"
  local result=$?
  if [ "$result" -eq 0 ] && engine_active_paused; then
    # 暂停期间改配置只推进配置修订，不重建。否则用户一存黑白名单，
    # 刚删掉的世代和缓存就又长回来了——「停用后什么都不许再跑」就白说了。
    # status 会因为 desired != applied 报出「配置待应用」，恢复保护时按最新修订重建。
    # 顺带的好处：暂停期间存名单几乎瞬间完成。
    log_event info mutation_deferred_paused "$verb" || true
  elif [ "$result" -eq 0 ]; then
    # 改配置不等于内容过期：先用已校验的来源缓存重建规则，缓存缺失才会去下载。
    # 这样启停来源、存黑白名单、改例外这类按钮不必再等一轮联网。
    # 内容刷新仍由「立即刷新」、单源刷新和自动刷新负责。
    RULE_FETCH_CACHE_FIRST=1
    export RULE_FETCH_CACHE_FIRST
    if [ "$verb" = reset-rules ]; then
      engine_refresh_degraded_locked
    else
      engine_refresh_locked
    fi
    result=$?
    RULE_FETCH_CACHE_FIRST=0
    export RULE_FETCH_CACHE_FIRST
  fi
  set -e
  rules_lock_release rules || return
  return "$result"
}

engine_select() {
  local mode=$1 result source sha
  rules_lock_acquire rules || return
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || { rules_lock_release rules; return 75; }
  active_tuple_load || { result=$?; rules_lock_release rules; return "$result"; }
  mode_set_locked "$mode" || { result=$?; rules_lock_release rules; return "$result"; }
  if [ "$ACTIVE_TUPLE_MODE" = paused ]; then
    rules_lock_release rules || return
    return 0
  fi
  mount_generation_for_mode "$ACTIVE_TUPLE_GENERATION" "$mode" || {
    result=$?; rules_lock_release rules; return "$result"
  }
  source=$MOUNT_SOURCE
  mount_pid1 "$source" "$ACTIVE_TUPLE_GENERATION" "$MOUNT_KIND" || {
    result=$?
    active_tuple_mount_loaded || result=76
    rules_lock_release rules || return
    return "$result"
  }
  sha=$(sha256_file "$source") || {
    result=$?
    active_tuple_mount_loaded || result=76
    rules_lock_release rules || return
    return "$result"
  }
  active_write_values "$ACTIVE_TUPLE_GENERATION" "$ACTIVE_TUPLE_ALTERNATE" "$ACTIVE_TUPLE_ACTION" \
    "$ACTIVE_TUPLE_REVISION" "$ACTIVE_TUPLE_CONFIG_HASH" "$mode" "$sha"
  result=$?
  if [ "$result" -ne 0 ]; then
    active_tuple_mount_loaded || result=76
  fi
  rules_lock_release rules || return
  return "$result"
}

engine_pause() {
  rules_init_paths "$MODDIR" || return
  engine_with_rules_lock engine_pause_locked
}

engine_resume() {
  rules_init_paths "$MODDIR" || return
  engine_with_rules_lock engine_resume_locked
}

engine_rollback() {
  rules_lock_acquire rules || return
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || { rules_lock_release rules; return 75; }
  set +e
  engine_rollback_locked
  local result=$?
  set -e
  rules_lock_release rules || return
  return "$result"
}

engine_mount_active() {
  local generation mode
  generation=$(active_value active_generation) || return
  mode=$(active_value active_mode) || return
  mount_generation_for_mode "$generation" "$mode" || return
  mount_pid1 "$MOUNT_SOURCE" "$generation" "$MOUNT_KIND"
}

engine_mount_boot() { engine_with_rules_lock engine_mount_boot_locked; }
engine_mount_repair() { engine_with_rules_lock engine_mount_active; }

engine_mount_namespace() {
  local pid=$1 profile=$2
  rules_lock_acquire rules || return
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || { rules_lock_release rules; return 75; }
  set +e
  engine_mount_namespace_locked "$pid" "$profile"
  local result=$?
  set -e
  rules_lock_release rules
  return "$result"
}

engine_history_mount_trace() {
  local token=$1 result
  rules_lock_acquire rules || return
  [ ! -f "$RULE_RUNTIME/uninstalling" ] || { rules_lock_release rules; return 75; }
  set +e
  engine_history_mount_trace_locked "$token"
  result=$?
  set -e
  rules_lock_release rules || return
  return "$result"
}

engine_history_mount_normal() {
  local result
  rules_lock_acquire rules || return
  set +e
  engine_history_mount_normal_locked
  result=$?
  set -e
  rules_lock_release rules || return
  return "$result"
}

engine_cleanup() {
  rules_lock_acquire rules || return
  set +e
  mount_cleanup_all
  local result=$?
  set -e
  rm -rf "$RULE_TMP"/* "$RULE_LOCKS/submit.lock" 2>/dev/null || true
  rules_lock_release rules
  return "$result"
}

# 用户停用某个来源后，它的缓存还留在磁盘上（只有删除来源才会顺手清掉）。
# 这个命令把这些用不上的缓存删掉，启用中的来源一个不动。
engine_clear_cache_locked() {
  local revision cleared
  config_bootstrap || return
  revision=$(config_current_revision) || return
  cleared=$(config_clear_disabled_cache "$revision") || return
  log_event info cache_cleared "已清理 $cleared 份停用来源缓存"
}

engine_clear_cache() {
  rules_init_paths "$MODDIR" || return
  engine_with_rules_lock engine_clear_cache_locked
}

# 暂停保护后把磁盘上一切能重建的东西删干净：所有来源缓存、所有历史世代，
# 只留下当前世代里那份 recovery（正挂载着的那个文件）和它的 manifest。
#
# 为什么必须留一份：engine_pause_locked 挂的就是 $active/recovery，全删会把
# 正在挂载的文件删掉。留下 recovery + manifest.prop 这一对不需要改任何挂载校验——
# generation_source_validate 只校验被请求那一种文件和它在 manifest 里的哈希，
# active_tuple_readonly 也只要求 paused 对应 kind=normal。
#
# 只在已经暂停、且挂载确实是当前世代 recovery 的前提下动手；任何一条不成立就
# 什么都不删。删除不可回滚，所以放在暂停流程的最后一步。
engine_purge_locked() {
  local generation entry removed_generations=0 removed_cache=0 base
  active_tuple_load || return
  [ "$ACTIVE_TUPLE_MODE" = paused ] || return 75
  [ "$ACTIVE_TUPLE_MOUNT_KIND" = normal ] || return 76
  active_tuple_mount_matches_loaded || return 76
  generation=$ACTIVE_TUPLE_GENERATION
  [ -f "$RULE_GENERATIONS/$generation/recovery" ] || return 66

  # 其它世代整个删掉，构建中断留下的 *.tmp 一起收。
  for entry in "$RULE_GENERATIONS"/*; do
    [ -e "$entry" ] || continue
    base=${entry##*/}
    [ "$base" != "$generation" ] || continue
    rm -rf "$entry" || return 74
    removed_generations=$((removed_generations + 1))
  done

  # 当前世代只留 recovery 和 manifest：all/reward 加起来是几兆到几十兆，
  # 暂停期间没有任何一处会读它们（status 的 paused 分支直接给 0 条，
  # history_active_normal_tuple 的 paused 分支返回 75）。
  rm -f "$RULE_GENERATIONS/$generation/all" "$RULE_GENERATIONS/$generation/reward" || return 74

  removed_cache=$(engine_purge_cache) || return

  rm -rf "$RULE_TMP"/* 2>/dev/null || true

  # 回滚指针不能指向已经删掉的世代：engine_rollback_locked 会去读
  # $alternate/manifest.prop，删了之后那一步会以一个含义不明的错误码失败。
  # awk 校验允许 alternate_generation 为空、alternate_action=none。
  active_write_values "$generation" '' none "$ACTIVE_TUPLE_REVISION" \
    "$ACTIVE_TUPLE_CONFIG_HASH" paused "$ACTIVE_TUPLE_HOSTS_HASH" || return

  log_event info purged "已删除 $removed_generations 个历史世代、$removed_cache 份来源缓存"
}

# 删掉全部来源缓存：原始、归一化、自定义、合并。逐条走 source_registry_remove_cache，
# 避免手写通配打偏；已登记之外的残留（改过 id、构建中断）由末尾的兜底收掉。
engine_purge_cache() {
  local revision sources id kind enabled order name_b64 url_b64 extra cleared=0
  [ -n "${CACHE_DIR-}" ] || { printf '0\n'; return 0; }
  revision=$(config_current_revision) || return
  sources="$CONFIG_DIR/revisions/$revision/sources.tsv"
  if [ -f "$sources" ] && [ ! -L "$sources" ]; then
    while IFS="$(printf '\t')" read -r id kind enabled order name_b64 url_b64 extra || \
      [ -n "${id}${kind}${enabled}${order}${name_b64}${url_b64}${extra}" ]; do
      [ -n "$id" ] || continue
      source_registry_remove_cache "$id" || return
      cleared=$((cleared + 1))
    done < "$sources"
  fi
  rm -rf "$(generation_merge_cache_dir)" 2>/dev/null || true
  rm -f "$CACHE_DIR"/*.hosts "$CACHE_DIR"/*.hosts.norm \
    "$CACHE_DIR"/*.hosts.norm.allow "$CACHE_DIR"/*.hosts.norm.meta 2>/dev/null || true
  rm -rf "$CACHE_DIR"/custom/* 2>/dev/null || true
  printf '%s\n' "$cleared"
}

engine_purge() {
  rules_init_paths "$MODDIR" || return
  engine_with_rules_lock engine_purge_locked
}

engine_validate_mutation_argv() {
  case "$1:$#" in
    set-builtin:3) { [ "$2" = awa ] || [ "$2" = rule10007 ]; } && { [ "$3" = 0 ] || [ "$3" = 1 ]; } ;;
    add-source:3) return 0 ;;
    update-source:4) return 0 ;;
    toggle-source:3) [ "$3" = 0 ] || [ "$3" = 1 ] ;;
    move-source:3) [ "$3" = up ] || [ "$3" = down ] ;;
    remove-source:2) return 0 ;;
    set-overrides:2) operation_overrides_b64_valid "$2" ;;
    reset-rules:1) return 0 ;;
    set-lists:3) return 0 ;;
    set-domain-decision:3) operation_domain_decision_fields_valid "$2" "$3" ;;
    *) return 64 ;;
  esac
}

engine_dispatch() {
  local cmd=${1-}
  case "$cmd" in
    prepare) [ "$#" -eq 1 ] || return 64; engine_prepare ;;
    bootstrap) [ "$#" -eq 1 ] || return 64; engine_bootstrap ;;
    refresh) [ "$#" -eq 1 ] || return 64; engine_refresh ;;
    refresh-source)
      [ "$#" -eq 2 ] || return 64
      operation_source_id_valid "$2" || return 65
      engine_refresh_source "$2"
      ;;
    mount)
      case "$#:${2-}" in
        2:--boot) engine_mount_boot ;;
        2:--repair) engine_mount_repair ;;
        4:--namespace) engine_mount_namespace "$3" "$4" ;;
        *) return 64 ;;
      esac
      ;;
    status) [ "$#" -eq 2 ] && [ "$2" = --json ] || return 64; status_json ;;
    history-mount-trace) [ "$#" -eq 2 ] || return 64; engine_history_mount_trace "$2" ;;
    history-mount-normal) [ "$#" -eq 1 ] || return 64; engine_history_mount_normal ;;
    set-builtin|add-source|update-source|toggle-source|move-source|remove-source|set-overrides|reset-rules|set-lists|set-domain-decision)
      engine_validate_mutation_argv "$@" || return 64
      engine_mutate_and_apply "$@"
      ;;
    select) [ "$#" -eq 2 ] || return 64; [ "$2" = block_all ] || [ "$2" = preserve_reward ] || return 64; engine_select "$2" ;;
    pause) [ "$#" -eq 1 ] || return 64; engine_pause ;;
    resume) [ "$#" -eq 1 ] || return 64; engine_resume ;;
    rollback) [ "$#" -eq 1 ] || return 64; engine_rollback ;;
    clear-cache) [ "$#" -eq 1 ] || return 64; engine_clear_cache ;;
    purge) [ "$#" -eq 1 ] || return 64; engine_purge ;;
    cleanup) [ "$#" -eq 1 ] || return 64; engine_cleanup ;;
    *) return 64 ;;
  esac
}

if [ "${RULE_ENGINE_SOURCE_ONLY-0}" != 1 ]; then
  rules_init_paths "$MODDIR" || exit $?
  engine_dispatch "$@"
fi
