import {
  encodeBase64Bytes,
  encodeBase64Utf8,
  execApi,
  pollBackoffMs,
  pollOperation,
  submitMutation,
} from './api.js';

const PHASE_LABELS = {
  idle: '空闲',
  validating: '校验配置',
  downloading: '下载规则',
  normalizing: '规范化',
  merging: '合并规则',
  generating: '生成规则',
  mounting: '挂载规则',
  verifying: '验证挂载',
  committing: '提交状态',
  rolling_back: '回滚挂载',
  cleaning: '清理中',
};

const SOURCE_STATES = {
  fresh: { label: '正常', icon: 'circle-check', tone: 'success' },
  stale: { label: '使用缓存', icon: 'history', tone: 'warning' },
  disabled: { label: '已停用', icon: 'circle-pause', tone: 'neutral' },
  error: { label: '错误', icon: 'circle-alert', tone: 'danger' },
};

const SOURCE_ERRORS = {
  unsupported_format: '不支持此文件格式，请使用可直接下载的 Raw 规则文本',
  not_applied: '尚未应用：最近一次刷新未提交',
  source_unavailable: '来源暂不可用',
  download_failed_using_cache: '下载失败，已使用缓存',
};

const HISTORY_ERRORS = {
  engine_failed: '后台任务执行失败',
  worker_lost: '后台任务已中断',
  nflog_unsupported: '当前内核不支持拦截日志',
  history_probe_failed: '拦截日志能力检测失败',
  history_rules_unavailable: '当前规则尚未准备好',
  history_trace_prepare_failed: '拦截日志映射准备失败',
  history_reader_start_failed: '拦截日志读取器启动失败',
  history_firewall_install_failed: '拦截日志防火墙规则安装失败',
  history_mount_failed: '拦截日志 trace hosts 挂载失败',
  history_state_commit_failed: '拦截日志状态保存失败',
  history_recovery_failed: '拦截日志启用失败且恢复未完成',
  history_reader_stopped: '拦截日志读取器已停止',
  history_runtime_incomplete: '拦截日志运行状态不完整',
};

const DOH_ERRORS = {
  invalid_endpoint: 'DoH URL 无效，请检查地址格式',
  invalid_config: '加密 DNS 配置无效',
  package_state_invalid: '应用包状态无效，请重新选择应用',
  test_failed: 'DoH URL 检测未通过，该地址当前不可用',
  commit_failed: '加密 DNS 配置保存失败',
  recovery_failed: '加密 DNS 恢复失败',
  runtime_failed: '加密 DNS 运行失败',
  bootstrap_unresolved: '无法解析 DoH 服务器域名，请确认当前网络可以正常解析域名后重试',
  firewall_unsupported: '当前内核缺少加密 DNS 转发所需的防火墙能力（owner 匹配或 DNS 重定向），普通 hosts 保护不受影响',
  private_dns_active: '系统“私人 DNS”指定了主机名，请先改为“自动”或“关闭”，再启用加密 DNS',
  companion_unavailable: '加密 DNS 组件不可用，请检查网络后重试',
  upstream_unavailable: 'DoH 上游不可用，已回退到系统 DNS',
  companion_exited: '加密 DNS 组件已退出，已回退到系统 DNS',
};

// 后端返回的是机器码（owner_match_unavailable 之类），直接塞进界面用户看不懂。
// 和 DOH_ERRORS 一样在这里翻成人话，认不出来的码退回通用说明。
const APP_POLICY_REASONS = {
  owner_match_unavailable: '当前内核的防火墙缺少 owner 匹配能力，无法按应用区分流量；普通 hosts 保护不受影响。',
  redirect_unavailable: '当前内核缺少 DNS 重定向能力；普通 hosts 保护不受影响。',
  probe_cleanup_failed: '能力探测后的清理未完成，未改动任何防火墙规则；重启后可再试。',
};

function appPolicyReasonMessage(value, fallback = '缺少 owner match 或安全的 IPv4/IPv6 规则能力；普通 hosts 保护不受影响。') {
  const code = typeof value === 'string' ? value.trim() : '';
  if (!code) return fallback;
  if (APP_POLICY_REASONS[code]) return APP_POLICY_REASONS[code];
  // 没收录的码不要原样显示，但也别丢掉：附在通用说明后面便于反馈。
  return /^[a-z0-9_]+$/.test(code) ? `${fallback}（${code}）` : code;
}

const VERB_LABELS = {
  'set-lists': '保存黑白名单',
  'set-domain-decision': '更新域名名单',
  refresh: '刷新规则',
  pause: '暂停保护',
  resume: '恢复保护',
  'refresh-source': '刷新单个来源',
  'set-auto-refresh': '保存自动刷新',
  'set-builtin': '切换内置来源',
  'add-source': '添加来源',
  'update-source': '编辑来源',
  'set-source': '切换来源',
  'move-source': '调整顺序',
  'remove-source': '删除来源',
  'select-mode': '切换模式',
  rollback: '切换历史版本',
  'set-history': '开启拦截日志',
  'clear-history': '清空拦截日志',
  'clear-cache': '清理缓存',
  'set-notice': '保存提示偏好',
  'set-app-policy': '保存应用策略',
  'test-doh': '检测 DoH URL',
  'set-doh': '启用加密 DNS',
  'disable-doh': '关闭加密 DNS',
};

const countFormatter = new Intl.NumberFormat('zh-CN');
const timeFormatter = new Intl.DateTimeFormat('zh-CN', {
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  hour12: false,
});
const LIST_READ_MAX_ATTEMPTS = 3;
const PANEL_SETTLE_MS = 140;
const LIST_VALIDATE_DEBOUNCE_MS = 180;
const PANEL_PREWARM_MS = 220;
// 预热要强制整棵子树同步布局，撞在用户点页签那一帧上就是一次能看见的卡顿；
// 主线程明显没闲下来时先让路，隔这么久再试。
const PANEL_PREWARM_DEFER_MS = 260;
const PANEL_PREWARM_MAX_DEFERRALS = 24;
// 入场动画跑完之前，底栏的折射层每帧都要重算背景，这段窗口里把它摘掉。
const PANEL_SWITCH_SETTLE_MS = 260;
const HISTORY_RENDER_CHUNK = 25;
// 一页的条数。开着日志跑一阵子之后，聚合后的记录能有几千条；一次全挂进 DOM，
// 从日志底栏切到别的底栏时浏览器要把这几千个节点连同它们的样式与折射层一起销毁，
// 那一下就是用户看到的卡顿。分页之后列表里永远只有这一页，切换代价与记录总量无关。
const HISTORY_PAGE_SIZE = 50;
// 探针间隔。DoH 那边是 5s，但它等的是一次用户刚触发的状态翻转；
// 拦截日志是长时间挂着看，放到 6s 并配合「签名不变就不读取」，空闲代价接近于零。
const HISTORY_PULSE_INTERVAL_MS = 6000;
// 开着日志但后端还没报「记录中」时的探针间隔。分开一个更长的值，是因为这种状态
// 既要能自己恢复（不能像以前那样干脆不挂探针，那样界面就永远停在开启那一刻），
// 又不该按 6 秒去问——它多半是刚开启还没收敛，或读取进程真的停了，等得起。
const HISTORY_PULSE_SETTLING_INTERVAL_MS = 12000;
// 刚开启后的收敛窗口：按 800ms 追问状态，等后端把 NFLOG 规则装好、读取进程起来。
// 探针只 stat 事件文件 + 查一次运行状态，比整包读取便宜得多。
// 只等 4 轮（约 3.2 秒）。以前等 15 轮，最坏要把用户按在按钮上等满 12 秒，
// 而那之后无非是做同一次读取——等不到收敛也没有别的补救。现在等不到就直接读，
// 剩下的交给探针在后台纠（logging 为假时它按 12 秒一轮，见 scheduleHistoryPulse），
// 用户看到的是「点完很快出界面」，记录随后自己补上，代价没有增加。
const HISTORY_SETTLE_INTERVAL_MS = 800;
const HISTORY_SETTLE_ATTEMPTS = 4;
const SURFACE_MODES = ['classic', 'liquid'];
const SCHEME_MODES = ['light', 'dark', 'system'];
const GLASS_LEVELS = ['soft', 'standard', 'strong'];
const MOTION_MODES = ['auto', 'off'];
const SURFACE_LABELS = { classic: '经典主题', liquid: '液态主题' };
const SCHEME_LABELS = { light: '亮色', dark: '暗色', system: '跟随系统' };
const GLASS_LABELS = { soft: '轻透', standard: '标准', strong: '浓郁' };
const BACKGROUND_MAX_EDGE = 1440;
const BACKGROUND_MAX_BYTES = 262_144;
const BACKGROUND_CHUNK_BYTES = 6_144;
const BACKGROUND_QUALITIES = [0.78, 0.68, 0.58, 0.48, 0.38];
const BACKGROUND_SOURCE = './user/background.jpg';
const BACKGROUND_GALLERY_ROOT = '/sdcard';
const BACKGROUND_MAX_PIXELS = 40_000_000;
// 自定义背景仍在开发中：模块侧的读写与图片浏览器已经就绪并有测试覆盖，
// 但在真机管理器上还无法稳定读取 webroot 里的图片，所以界面入口暂时关闭。
const BACKGROUND_FEATURE_READY = false;

const elements = {
  app: document.querySelector('#app'),
  headerStatus: document.querySelector('#header-status'),
  headerStatusText: document.querySelector('#header-status-text'),
  statusRail: document.querySelector('#status-rail'),
  overviewStatus: document.querySelector('#overview-status'),
  overviewDetail: document.querySelector('#overview-detail'),
  overviewWorkspace: document.querySelector('#overview-workspace'),
  ruleImpact: document.querySelector('#rule-impact'),
  ruleImpactHint: document.querySelector('#rule-impact-hint'),
  ruleCount: document.querySelector('#rule-count'),
  networkImpact: document.querySelector('#network-impact'),
  lastSuccess: document.querySelector('#last-success'),
  clearCacheButton: document.querySelector('#clear-cache-button'),
  refreshButton: document.querySelector('#refresh-button'),
  pauseProtectionButton: document.querySelector('#pause-protection-button'),
  resumeProtectionButton: document.querySelector('#resume-protection-button'),
  rollbackButton: document.querySelector('#rollback-button'),
  autoRefreshEnabled: document.querySelector('#auto-refresh-enabled'),
  autoRefreshInterval: document.querySelector('#auto-refresh-interval'),
  autoRefreshSummary: document.querySelector('#auto-refresh-summary'),
  modeControl: document.querySelector('#mode-control'),
  modeSyncNote: document.querySelector('#mode-sync-note'),
  overviewSources: document.querySelector('#overview-sources'),
  builtinSources: document.querySelector('#builtin-sources'),
  customSources: document.querySelector('#custom-sources'),
  builtinSourcesToggle: document.querySelector('#builtin-sources-toggle'),
  customSourcesToggle: document.querySelector('#custom-sources-toggle'),
  builtinSourcesContent: document.querySelector('#builtin-sources-content'),
  customSourcesContent: document.querySelector('#custom-sources-content'),
  builtinRecovery: document.querySelector('#builtin-recovery'),
  addSourceButton: document.querySelector('#add-source-button'),
  manualBlocklist: document.querySelector('#manual-blocklist'),
  manualAllowlist: document.querySelector('#manual-allowlist'),
  blockListCount: document.querySelector('#block-list-count'),
  allowListCount: document.querySelector('#allow-list-count'),
  blockListError: document.querySelector('#block-list-error'),
  allowListError: document.querySelector('#allow-list-error'),
  listSyncNote: document.querySelector('#list-sync-note'),
  saveListsButton: document.querySelector('#save-lists-button'),
  domainOverrides: document.querySelector('#domain-overrides'),
  overrideCount: document.querySelector('#override-count'),
  overrideError: document.querySelector('#override-error'),
  overrideSyncNote: document.querySelector('#override-sync-note'),
  saveOverridesButton: document.querySelector('#save-overrides-button'),
  historyView: document.querySelector('#history-view'),
  historyEnabled: document.querySelector('#history-enabled'),
  historyDetails: document.querySelector('#history-details'),
  historyStatusRail: document.querySelector('#history-status-rail'),
  historyStatusTitle: document.querySelector('#history-status-title'),
  historyStateChip: document.querySelector('#history-state-chip'),
  historyStatusDetail: document.querySelector('#history-status-detail'),
  historyCapability: document.querySelector('#history-capability'),
  historyCountSummary: document.querySelector('#history-count-summary'),
  historyAppFilter: document.querySelector('#history-app-filter'),
  historyDomainFilter: document.querySelector('#history-domain-filter'),
  historyPortFilter: document.querySelector('#history-port-filter'),
  historyTimeFilter: document.querySelector('#history-time-filter'),
  clearHistoryButton: document.querySelector('#clear-history-button'),
  historyList: document.querySelector('#history-list'),
  historyPager: document.querySelector('#history-pager'),
  historyPrevPage: document.querySelector('#history-prev-page'),
  historyNextPage: document.querySelector('#history-next-page'),
  historyPageStatus: document.querySelector('#history-page-status'),
  historyRefreshHint: document.querySelector('#history-refresh-hint'),
  runtimeLogView: document.querySelector('#runtime-log-view'),
  runtimeLogOutput: document.querySelector('#runtime-log-output'),
  reloadRuntimeLogsButton: document.querySelector('#reload-runtime-logs-button'),
  loadMoreRuntimeLogs: document.querySelector('#load-more-runtime-logs'),
  runtimeLogEnabled: document.querySelector('#runtime-log-enabled'),
  clearRuntimeLogsButton: document.querySelector('#clear-runtime-logs-button'),
  exportRuntimeLogsButton: document.querySelector('#export-runtime-logs-button'),
  runtimeLogExportNote: document.querySelector('#runtime-log-export-note'),
  clearHistoryDialog: document.querySelector('#clear-history-dialog'),
  clearHistoryForm: document.querySelector('#clear-history-form'),
  noticeDialog: document.querySelector('#notice-dialog'),
  noticeCancelButton: document.querySelector('#notice-cancel-button'),
  noticeConfirmButton: document.querySelector('#notice-confirm-button'),
  noticeConfirmPermanentButton: document.querySelector('#notice-confirm-permanent-button'),
  noticeReadonly: document.querySelector('#notice-readonly'),
  noticeReopenButton: document.querySelector('#notice-reopen-button'),
  appPolicyCard: document.querySelector('#app-policy-card'),
  appPolicyStatus: document.querySelector('#app-policy-status'),
  appPolicyDetail: document.querySelector('#app-policy-detail'),
  appPolicyControls: document.querySelector('#app-policy-controls'),
  appPolicyMode: document.querySelector('#app-policy-mode'),
  appPolicyUids: document.querySelector('#app-policy-uids'),
  appPolicyIps: document.querySelector('#app-policy-ips'),
  appPolicySave: document.querySelector('#app-policy-save'),
  dohSection: document.querySelector('#doh-section'),
  dohStatus: document.querySelector('#doh-status'),
  dohMode: document.querySelector('#doh-mode'),
  dohEndpoint: document.querySelector('#doh-endpoint'),
  dohTest: document.querySelector('#doh-test'),
  dohTestResult: document.querySelector('#doh-test-result'),
  dohSelectedRegion: document.querySelector('#doh-selected-region'),
  dohAppSearch: document.querySelector('#doh-app-search'),
  dohAppList: document.querySelector('#doh-app-list'),
  dohLoadMoreApps: document.querySelector('#doh-load-more-apps'),
  dohUids: document.querySelector('#doh-uids'),
  dohApply: document.querySelector('#doh-apply'),
  dohDisable: document.querySelector('#doh-disable'),
  dohConfirmDialog: document.querySelector('#doh-confirm-dialog'),
  dohConfirmForm: document.querySelector('#doh-confirm-form'),
  dohConfirmEnable: document.querySelector('#doh-confirm-enable'),
  resetRulesButton: document.querySelector('#reset-rules-button'),
  resetRulesDialog: document.querySelector('#reset-rules-dialog'),
  resetRulesForm: document.querySelector('#reset-rules-form'),
  diagnosticsButton: document.querySelector('#diagnostics-button'),
  diagnosticsResult: document.querySelector('#diagnostics-result'),
  creditsDialog: document.querySelector('#credits-dialog'),
  aboutCreditsButton: document.querySelector('#about-credits-button'),
  surfaceMode: document.querySelector('#surface-mode'),
  schemeMode: document.querySelector('#scheme-mode'),
  glassStrength: document.querySelector('#glass-strength'),
  glassStrengthHint: document.querySelector('#glass-strength-hint'),
  motionEnabled: document.querySelector('#motion-enabled'),
  appearanceNote: document.querySelector('#appearance-note'),
  backgroundEnabled: document.querySelector('#background-enabled'),
  backgroundFields: document.querySelector('#background-fields'),
  backgroundPreview: document.querySelector('#background-preview'),
  backgroundPreviewHint: document.querySelector('#background-preview-hint'),
  backgroundPick: document.querySelector('#background-pick'),
  backgroundRemove: document.querySelector('#background-remove'),
  backgroundNote: document.querySelector('#background-note'),
  backgroundPickerDialog: document.querySelector('#background-picker-dialog'),
  backgroundPickerList: document.querySelector('#background-picker-list'),
  backgroundPickerPath: document.querySelector('#background-picker-path'),
  backgroundPickerUp: document.querySelector('#background-picker-up'),
  sourceDialog: document.querySelector('#source-dialog'),
  sourceForm: document.querySelector('#source-form'),
  sourceDialogTitle: document.querySelector('#source-dialog-title'),
  sourceId: document.querySelector('#source-id'),
  sourceName: document.querySelector('#source-name'),
  sourceUrl: document.querySelector('#source-url'),
  sourceNameError: document.querySelector('#source-name-error'),
  sourceUrlError: document.querySelector('#source-url-error'),
  deleteDialog: document.querySelector('#delete-dialog'),
  deleteForm: document.querySelector('#delete-form'),
  deleteSourceName: document.querySelector('#delete-source-name'),
  deleteSourceId: document.querySelector('#delete-source-id'),
  rollbackDialog: document.querySelector('#rollback-dialog'),
  rollbackForm: document.querySelector('#rollback-form'),
  rollbackDialogTitle: document.querySelector('#rollback-dialog-title'),
  rollbackDialogCopy: document.querySelector('#rollback-dialog-copy'),
  confirmRollbackButton: document.querySelector('#confirm-rollback-button'),
  pauseDialog: document.querySelector('#pause-dialog'),
  pauseForm: document.querySelector('#pause-form'),
  announcer: document.querySelector('#announcer'),
};

const lifecycle = new AbortController();
const timers = new Set();
const tabScrollOffsets = new Map();
const debounceTimers = new Map();
const warmedPanels = new Set();
// 预热优先级：元素数从多到少，重的面板先热。
const PANEL_PREWARM_ORDER = ['panel-settings', 'panel-sources', 'panel-logs', 'panel-overview', 'panel-apps'];
let prewarmIdleHandle = null;
let prewarmDeferrals = 0;
let lastTabSwitchAt = 0;
let switchStateTimer = null;
let initialized = false;
let disposed = false;
let currentStatus = null;
let canonicalBeforeMutation = null;
let unknownSubmission = null;
let renderedSourcesKey = '';
let latestSources = [];
let sourcePanelRendered = false;
let headerPresentationKey = '';
let noticeTimer = null;
let listsLoaded = false;
let listsLoading = false;
let listsLoadPromise = null;
let listsRevision = null;
let historyStatus = null;
let historyApps = [];
let historyAppsFingerprintCache = null;
let historyLoaded = false;
let historyLoading = false;
// 当前页码（从 0 数）与后端给出的聚合后总条数。页码兼作「用户翻过页没有」的判据：
// 只有它大于 0 才说明用户离开了第一页，实时刷新这才需要让路。
let historyPage = 0;
let historyTotal = 0;
let historyPanelActive = false;
let historyQuerySerial = 0;
let historyDomainTimer = null;
let historyDomainApplied = '';
let historyDomainComposing = false;
let historyRenderToken = 0;
let historyReloadQueued = false;
// 读回来发现当前页已经越界（过期删除让总数缩了）时要夹回的页码，由 finally 统一排。
let historyClampPage = null;
let historyAllowCacheText = null;
let historyAllowCacheSet = new Set();
let historyActionsDisabled = null;
let historyPulseTimer = null;
let historyPulseSignature = null;
// 翻过页期间探到的新签名。翻页时不方便直接刷新（会把用户从第三页拽回第一页），
// 但也不能丢掉这个事实，否则翻过一次页就等于关掉了实时更新。
let historyPendingSignature = null;
let runtimeLogCursor = '0';
let runtimeLogsLoaded = false;
let runtimeLogsLoading = false;
let runtimeLogHasContent = false;
let runtimeLogModeLoaded = false;
let managementUnlocked = false;
let initialRefreshScheduled = false;
let backendWatch = null;
let noticeLoaded = false;
let appPolicyLoaded = false;
let appPolicyLoading = false;
let appsPanelActive = false;
let dohLoaded = false;
// 用户一旦改过地址框，状态刷新就不再回填，否则 5 秒一次的轮询会把正在输入的
// 内容覆盖掉（轮询期间输入框会被短暂禁用，焦点也会因此丢失）。
let dohEndpointDirty = false;
let dohLoading = false;
let dohStatus = null;
let dohAppsLoading = false;
let dohAppsLoaded = false;
let dohAppsCursor = '0';
let dohAppsHasMore = false;
let dohAppSearchTimer = null;
let dohRefreshTimer = null;
let pendingDohConfig = null;
let builtinRecoveryLoaded = false;
let builtinRecoveryLoading = false;
let overridesLoaded = false;
let overridesLoading = false;
let diagnosticsLoading = false;
let appearance = {
  surface: 'classic',
  scheme: 'system',
  glass: 'soft',
  motion: 'auto',
  background: { enabled: false, revision: 0 },
};
let appearanceSaving = false;
let appearanceSavePending = false;
let backgroundBusy = false;
let pickerPath = BACKGROUND_GALLERY_ROOT;
let pickerParent = null;
let pickerLoading = false;

function refreshIcons(root = document) {
  const pending = [...root.querySelectorAll('i[data-lucide]')];
  if (pending.length === 0) return;
  pending.forEach((icon) => {
    const name = icon.getAttribute('data-lucide') || 'circle-info';
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('data-lucide', name);
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    svg.classList.add('app-icon');
    if (icon.className) svg.setAttribute('class', `${icon.className} app-icon`);
    use.setAttribute('href', `./icons.svg#${name}`);
    svg.append(use);
    icon.replaceWith(svg);
  });
}

function schedule(callback, delay) {
  const timer = globalThis.setTimeout(() => {
    timers.delete(timer);
    callback();
  }, delay);
  timers.add(timer);
  return timer;
}

// 同一个 key 只保留最后一次回调，避开逐键同步校验的阻塞。
function debounce(key, callback, delay) {
  const existing = debounceTimers.get(key);
  if (existing !== undefined) {
    globalThis.clearTimeout(existing);
    timers.delete(existing);
  }
  debounceTimers.set(key, schedule(() => {
    debounceTimers.delete(key);
    callback();
  }, delay));
}

function monotonicNow() {
  return globalThis.performance?.now?.() ?? Date.now();
}

function elapsedSince(stamp) {
  return stamp === 0 ? Number.POSITIVE_INFINITY : monotonicNow() - stamp;
}

// 入场动画期间给 :root 挂个开关，好让样式表把那几帧真正贵的活儿摘掉。
//
// 这个开关本身不便宜：改 :root 上的属性会让整棵树的样式失效，实测一次切换要多花
// 约 8ms 的样式重算。所以只在它真能省回来的那一种组合下才挂——液态材质的「浓郁」
// 档位，那里有一层 SVG 位移滤镜（feDisplacementMap），每帧重算整块背景，
// 比全树失效贵得多。其余组合（经典材质、轻透/标准玻璃）下挂了纯亏，
// 因为它们没有折射层可摘，只剩光斑停帧那点收益。
function panelSwitchNeedsGuard() {
  const root = document.documentElement;
  return root.dataset.surface === 'liquid' && root.dataset.glass === 'strong';
}

function markPanelSwitch() {
  lastTabSwitchAt = monotonicNow();
  const root = document.documentElement;
  if (!panelSwitchNeedsGuard()) {
    // 上一次切换可能留着这个属性（比如刚从浓郁档切到标准档），清掉再返回。
    if (root.dataset.switching) delete root.dataset.switching;
    return;
  }
  root.dataset.switching = 'true';
  if (switchStateTimer !== null) {
    globalThis.clearTimeout(switchStateTimer);
    timers.delete(switchStateTimer);
  }
  switchStateTimer = schedule(() => {
    switchStateTimer = null;
    delete root.dataset.switching;
  }, PANEL_SWITCH_SETTLE_MS);
}

function afterFirstPaint(callback) {
  globalThis.requestAnimationFrame(() => {
    schedule(() => {
      if (!disposed) callback();
    }, 0);
  });
}

function sleep(delay) {
  return new Promise((resolve, reject) => {
    if (lifecycle.signal.aborted) {
      const error = new Error('Aborted');
      error.name = 'AbortError';
      reject(error);
      return;
    }
    const timer = schedule(() => {
      lifecycle.signal.removeEventListener('abort', onAbort);
      resolve();
    }, delay);
    const onAbort = () => {
      globalThis.clearTimeout(timer);
      timers.delete(timer);
      lifecycle.signal.removeEventListener('abort', onAbort);
      const error = new Error('Aborted');
      error.name = 'AbortError';
      reject(error);
    };
    lifecycle.signal.addEventListener('abort', onAbort, { once: true });
  });
}

// 让出一个任务，把多次大段 DOM 写入拆到不同帧；pagehide 清理 timer 后该 promise 不再兑现。
function nextTask() {
  return new Promise((resolve) => {
    schedule(resolve, 0);
  });
}

function afterPanelPaint(tab, callback) {
  globalThis.requestAnimationFrame(() => {
    schedule(() => {
      if (!disposed && tab.getAttribute('aria-selected') === 'true') callback();
    }, 0);
  });
}

// 连点页签时，只有真正停留下来的页签才会付出读取与渲染的代价。
// 首次进入某页要渲染整段列表，这笔活儿必须等入场动画跑完再做，
// 固定延时总会砸在动画的最后几帧上；关掉动画时又该立刻开工，所以直接等动画自己收尾。
function afterPanelSettled(tab, callback) {
  const run = () => {
    if (disposed || tab.getAttribute('aria-selected') !== 'true') return;
    callback();
  };
  globalThis.requestAnimationFrame(() => {
    if (disposed) return;
    const panel = document.querySelector(`#${tab.getAttribute('aria-controls')}`);
    const animations = panel?.getAnimations?.() ?? [];
    if (animations.length === 0) {
      schedule(run, PANEL_SETTLE_MS);
      return;
    }
    let settled = false;
    const settle = () => {
      if (settled) return;
      settled = true;
      schedule(run, 0);
    };
    // 动画被打断时 finished 会 reject，两条路都当作收尾。
    Promise.all(animations.map((animation) => animation.finished)).then(settle, settle);
    // 兜底：拿不到 finished 时不能把首次加载卡死。
    schedule(settle, PANEL_SETTLE_MS + PANEL_PREWARM_MS);
  });
}

// 入场动画一结束就摘掉 data-motion-direction，让 will-change 失效、合成层释放。
// 动画被打断时 finished 会 reject，两条路都要摘；拿不到 finished 时用兜底延时。
function releaseMotionHint(panel) {
  const drop = () => {
    if (disposed) return;
    delete panel.dataset.motionDirection;
  };
  globalThis.requestAnimationFrame(() => {
    if (disposed) return;
    const animations = panel.getAnimations?.() ?? [];
    if (animations.length === 0) {
      drop();
      return;
    }
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      drop();
    };
    Promise.all(animations.map((animation) => animation.finished)).then(finish, finish);
    schedule(finish, PANEL_SWITCH_SETTLE_MS);
  });
}

function animateInsertedItems(insertedItems) {
  if (globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
  const items = [...insertedItems].slice(0, 12);
  items.forEach((item, index) => {
    item.classList.add('is-entering');
    item.style.setProperty('--item-enter-delay', `${index * 12}ms`);
  });
  schedule(() => {
    items.forEach((item) => {
      item.classList.remove('is-entering');
      item.style.removeProperty('--item-enter-delay');
    });
  }, 360);
}

function formatTime(seconds) {
  if (!Number.isFinite(seconds)) return '—';
  return timeFormatter.format(new Date(seconds * 1000));
}

function formatCount(value) {
  return Number.isFinite(value) ? countFormatter.format(value) : '—';
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function errorMessage(value, fallback = '') {
  const code = typeof value === 'string' ? value : value?.code;
  if (HISTORY_ERRORS[code]) return HISTORY_ERRORS[code];
  if (DOH_ERRORS[code]) return DOH_ERRORS[code];
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && typeof value.message === 'string') return value.message;
  return fallback;
}

function historyErrorMessage(value, fallback = '拦截日志状态异常') {
  const code = typeof value === 'string' ? value : value?.code;
  return HISTORY_ERRORS[code] || fallback;
}

function displaySourceName(source) {
  if (source.id === 'awa') return '秋风规则';
  if (source.id === 'rule10007') return '10007规则';
  return source.name || source.id;
}

function statusPresentation(status) {
  if (status.activeMode === 'paused') {
    return {
      header: '已暂停',
      headerIcon: 'circle-pause',
      headerTone: 'warning',
      title: '已暂停',
      detail: '规则过滤、自动刷新、加密 DNS 与分应用规则都已停止，恢复后重新下载并按当前模式装回',
      icon: 'circle-pause',
      tone: 'warning',
    };
  }

  const effective = Boolean(status.activeGeneration)
    && status.result !== 'critical'
    && status.result !== 'failed'
    && !status.sourcesOutOfSync;
  const header = effective ? '已生效' : '未生效';
  const headerIcon = effective ? 'shield-check' : 'shield-x';
  const headerTone = effective ? 'success' : 'danger';

  if (status.busy) {
    return {
      header,
      headerIcon,
      headerTone,
      title: '应用中',
      detail: PHASE_LABELS[status.phase] || '正在应用规则配置',
      tone: 'warning',
    };
  }
  if (status.result === 'critical') {
    return {
      header,
      headerIcon,
      headerTone,
      title: '严重错误',
      detail: errorMessage(status.lastError, '规则挂载与回滚均未通过验证'),
      icon: 'octagon-alert',
      tone: 'danger',
    };
  }
  if (status.result === 'rolled_back') {
    return {
      header,
      headerIcon,
      headerTone,
      title: '已回滚',
      detail: errorMessage(status.lastError, '已恢复到上一份通过验证的规则'),
      icon: 'rotate-ccw',
      tone: 'warning',
    };
  }
  if (status.sourcesOutOfSync) {
    return {
      header,
      headerIcon,
      headerTone,
      title: '配置尚未生效',
      detail: errorMessage(status.lastError, '期望来源与当前活动规则不一致'),
      icon: 'triangle-alert',
      tone: 'warning',
    };
  }
  if (status.result === 'degraded' || status.sources?.some((source) => source.state === 'stale')) {
    return {
      header,
      headerIcon,
      headerTone,
      title: '使用缓存',
      detail: '部分在线来源不可用，当前规则由最近一次有效缓存生成',
      icon: 'history',
      tone: 'warning',
    };
  }
  if (status.result === 'failed') {
    return {
      header,
      headerIcon,
      headerTone,
      title: '配置尚未生效',
      detail: errorMessage(status.lastError, '最近一次操作失败，当前活动规则保持不变'),
      icon: 'circle-x',
      tone: 'danger',
    };
  }
  return {
    header,
    headerIcon,
    headerTone,
    title: '规则保护已生效',
    detail: '活动规则已挂载并通过校验',
    icon: 'shield-check',
    tone: 'success',
  };
}

function iconMarkup(name, className = '') {
  const classes = className ? `${className} app-icon` : 'app-icon';
  return `<svg class="${classes}" data-lucide="${name}" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><use href="./icons.svg#${name}"></use></svg>`;
}

function setHeaderPresentation(presentation) {
  const nextKey = `${presentation.headerTone}|${presentation.headerIcon}`;
  setClass(elements.headerStatus, `header-status status-tone-${presentation.headerTone}`);
  if (headerPresentationKey !== nextKey) {
    elements.headerStatus.innerHTML = `
      ${iconMarkup(presentation.headerIcon)}
      <span id="header-status-text"></span>
    `;
    elements.headerStatusText = elements.headerStatus.querySelector('#header-status-text');
    headerPresentationKey = nextKey;
  }
  setText(elements.headerStatusText, presentation.header);
  setData(elements.statusRail, 'tone', presentation.tone);
  setText(elements.overviewStatus, presentation.title);
  setText(elements.overviewDetail, presentation.detail);
}

let writesSweepKey = null;

// guardDisabled 是「这个按钮此刻在业务上没意义」，和「全局不可写」是两个独立条件，
// 真正的 disabled 是两者取或。凡是设了前者的地方都要顺手把结果写回去，不能指望后面
// 那次兜底扫描替自己收尾——扫描现在只在全局条件变化时才跑。
function applyGuard(control, guard) {
  if (!control) return;
  setData(control, 'guardDisabled', String(guard));
  setFlag(control, 'disabled',
    !initialized || !managementUnlocked || Boolean(currentStatus?.busy) || guard);
}

function setWritesDisabled(disabled) {
  const unavailable = disabled || !managementUnlocked;
  // 这次全文档扫描是兜底：每个产出 .write-action 的地方（sourceCard 的模板、
  // patchSourceCards、renderDohApps、恢复按钮）都在创建那一刻就按同一个条件设过
  // disabled，所以只有条件本身变了才需要重扫。操作进行中轮询会按 120/200/320/480ms
  // 反复调到这里，条件却一直是 true——照旧扫的话，就是每轮把整页近百个按钮连同
  // 视口外的卡片子树一起标脏，用户此刻正在滑动，那些子树被滑进视口时要重算样式。
  if (writesSweepKey !== unavailable) {
    writesSweepKey = unavailable;
    document.querySelectorAll('.write-action').forEach((control) => {
      control.disabled = unavailable || control.dataset.guardDisabled === 'true';
    });
  }
  setFlag(elements.modeControl, 'disabled', unavailable);
  setFlag(elements.autoRefreshInterval, 'disabled', unavailable);
  setFlag(elements.manualBlocklist, 'disabled', unavailable || listsLoading);
  setFlag(elements.manualAllowlist, 'disabled', unavailable || listsLoading);
  setFlag(elements.appPolicyMode, 'disabled', unavailable || appPolicyLoading);
  setFlag(elements.appPolicyUids, 'disabled', unavailable || appPolicyLoading);
  setFlag(elements.appPolicyIps, 'disabled', unavailable || appPolicyLoading);
  setFlag(elements.domainOverrides, 'disabled', unavailable || overridesLoading);
  setFlag(elements.diagnosticsButton, 'disabled',
    !initialized || Boolean(currentStatus?.busy) || diagnosticsLoading);
  syncDohControls(unavailable);
  syncHistoryControls();
}

function sourceState(source) {
  return SOURCE_STATES[source.state] || SOURCE_STATES.error;
}

function sourceError(source) {
  const message = typeof source.error === 'string'
    ? (SOURCE_ERRORS[source.error] || SOURCE_ERRORS.source_unavailable)
    : '';
  if (source.skippedCount > 0 && source.error !== 'unsupported_format') {
    const skipped = `已跳过 ${formatCount(source.skippedCount)} 条不兼容规则`;
    return message ? `${message} · ${skipped}` : skipped;
  }
  return message;
}

function sourceStateMarkup(source) {
  const state = sourceState(source);
  return `
    <span class="state-chip state-chip-${state.tone}">
      ${iconMarkup(state.icon)}
      <span>${state.label}</span>
    </span>
  `;
}

let renderedOverviewKey = '';

// 首页健康列表。操作进行中状态会在 fresh/refreshing 之间来回跳，每次轮询都走到这里；
// 以前每次都 innerHTML 重建全部行，等于在整个加载/保存/刷新期间反复拆建 DOM，
// 这是首页和规则页掉帧的主要来源。骨架（有哪些来源、什么顺序、叫什么名字）没变时
// 只改文字和徽标。
function renderOverviewSources(sources) {
  if (sources.length === 0) {
    elements.overviewSources.innerHTML = '<p class="empty-state">没有可用的规则来源</p>';
    renderedOverviewKey = '';
    return;
  }
  const key = sources.map((source) => `${source.id}${displaySourceName(source)}`).join('');
  const rows = elements.overviewSources.children;
  if (key === renderedOverviewKey && rows.length === sources.length) {
    sources.forEach((source, index) => {
      const row = rows[index];
      setText(row.querySelector('.health-name span'),
        source.enabled ? `${formatCount(source.ruleCount)} 条` : '未参与合并');
      patchStateChip(row.querySelector('.state-chip'), sourceState(source));
    });
    return;
  }
  renderedOverviewKey = key;
  elements.overviewSources.innerHTML = sources.map((source) => `
    <div class="health-row">
      <div class="health-name">
        <strong>${escapeText(displaySourceName(source))}</strong>
        <span>${source.enabled ? `${formatCount(source.ruleCount)} 条` : '未参与合并'}</span>
      </div>
      ${sourceStateMarkup(source)}
    </div>
  `).join('');
}

// 徽标就地更新。图标是 <svg data-lucide><use href="./icons.svg#name">，
// 类名、文字和 use 的 href 三处都要跟着状态改，否则会出现「文字变了图标没变」。
// 图标就地换名。data-lucide 和 use 的 href 两处都要改，否则会出现「文字变了图标没变」。
// 名字没变就一个字都不写——不要换节点：换节点等于拆一次装一次，还要重新解析 use 引用。
function patchIcon(icon, name) {
  if (!icon || icon.getAttribute('data-lucide') === name) return;
  icon.setAttribute('data-lucide', name);
  icon.querySelector('use')?.setAttribute('href', `./icons.svg#${name}`);
}

function patchStateChip(chip, state) {
  if (!chip) return;
  setClass(chip, `state-chip state-chip-${state.tone}`);
  setText(chip.querySelector('span'), state.label);
  patchIcon(chip.querySelector('svg[data-lucide]'), state.icon);
}

function escapeText(value) {
  return escapeAttribute(value);
}

function escapeAttribute(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[character]);
}

function sourceCard(source, sourceIndex, sourceCount) {
  const name = displaySourceName(source);
  const sourceErrorText = sourceError(source);
  const isCustom = source.kind === 'custom';
  const disabled = !initialized || !managementUnlocked || Boolean(currentStatus?.busy);
  const meta = source.enabled
    ? `${formatCount(source.ruleCount)} 条 · ${formatTime(source.updatedAt)}`
    : '已停用：规则不参与合并，缓存已清理';
  const url = source.url
    ? `<span class="source-url" title="${escapeAttribute(source.url)}">${escapeText(source.url)}</span>`
    : '';
  const orderActions = sourceCount > 1
    ? `
      <button class="icon-button source-command write-action" type="button" data-action="move" data-id="${escapeAttribute(source.id)}" data-direction="up" data-guard-disabled="${sourceIndex === 0}" aria-label="上移 ${escapeAttribute(name)}" title="上移" ${sourceIndex === 0 || disabled ? 'disabled' : ''}>
        ${iconMarkup('arrow-up')}
      </button>
      <button class="icon-button source-command write-action" type="button" data-action="move" data-id="${escapeAttribute(source.id)}" data-direction="down" data-guard-disabled="${sourceIndex === sourceCount - 1}" aria-label="下移 ${escapeAttribute(name)}" title="下移" ${sourceIndex === sourceCount - 1 || disabled ? 'disabled' : ''}>
        ${iconMarkup('arrow-down')}
      </button>
    `
    : '';
  // 暂停期间刷新是被后端挡掉的（会下载全部来源并重建世代，正是暂停要停的事），
  // 按钮跟着锁住，不要让用户点了才收到一句拒绝。
  const refreshBlocked = !source.enabled || currentStatus?.activeMode === 'paused';
  const refreshDisabled = disabled || refreshBlocked;
  const refreshAction = `
    <button class="icon-button source-command source-refresh write-action" type="button" data-action="refresh" data-id="${escapeAttribute(source.id)}" data-guard-disabled="${refreshBlocked}" aria-label="刷新 ${escapeAttribute(name)}" title="${currentStatus?.activeMode === 'paused' ? '保护已暂停，恢复后才能刷新' : '刷新此来源'}" ${refreshDisabled ? 'disabled' : ''}>
      ${iconMarkup('refresh-cw')}
    </button>
  `;
  const sourceActions = `
      ${orderActions}
      ${isCustom ? `
      <button class="icon-button source-command write-action" type="button" data-action="edit" data-id="${escapeAttribute(source.id)}" aria-label="编辑 ${escapeAttribute(name)}" title="编辑" ${disabled ? 'disabled' : ''}>
        ${iconMarkup('pencil')}
      </button>` : ''}
      <button class="icon-button source-command write-action" type="button" data-action="delete" data-id="${escapeAttribute(source.id)}" aria-label="删除 ${escapeAttribute(name)}" title="删除" ${disabled ? 'disabled' : ''}>
        ${iconMarkup('trash-2')}
      </button>
    `;

  return `
    <article class="source-card source-card-${escapeAttribute(source.kind)} source-card-${escapeAttribute(source.state)}" data-source-id="${escapeAttribute(source.id)}">
      <div class="source-main">
        <div class="source-title-line">
          <h4>${escapeText(name)}</h4>
          ${sourceStateMarkup(source)}
        </div>
        <p class="source-meta">${escapeText(meta)}</p>
        ${url}
        ${sourceErrorText ? `<p class="source-error">${escapeText(sourceErrorText)}</p>` : ''}
      </div>
      <div class="source-controls">
        <label class="switch-label" title="${source.enabled ? '停用' : '启用'} ${escapeAttribute(name)}">
          <span class="visually-hidden">${source.enabled ? '停用' : '启用'} ${escapeText(name)}</span>
          <input class="source-switch write-action" type="checkbox" role="switch" aria-label="${escapeAttribute(name)}" data-action="toggle" data-id="${escapeAttribute(source.id)}" ${source.enabled ? 'checked' : ''} ${disabled ? 'disabled' : ''}>
          <span class="source-toggle" aria-hidden="true">
            <span class="source-toggle-box"></span>
            <span class="source-toggle-label source-toggle-on">已启用</span>
            <span class="source-toggle-label source-toggle-off">已停用</span>
          </span>
        </label>
        <div class="source-actions">${refreshAction}${sourceActions}</div>
      </div>
    </article>
  `;
}

// 卡片骨架（有哪些来源、什么顺序、名字和地址）在一次操作里是不变的，
// 变的只有状态徽标、条数摘要、报错和启停。这个键只覆盖骨架部分。
function sourceStructureKey(sources) {
  return sources.map((source) => [
    source.id,
    source.kind,
    source.url ?? '',
    displaySourceName(source),
  ].join('\u001f')).join('\u001e');
}

// 下面四个都是「值没变就一个字都不写」。这一层不能省：浏览器在这里不会替我们比对。
//
// textContent 赋值是无条件把子节点全换成一个新文本节点，文字一模一样也算一次真实改动。
// class、data-* 以及 hidden/disabled 这类反射属性同理——写回相同的值照样落一次属性
// 改动，而属性改动会触发样式失效并沿子树走一遍，比换个文本节点更贵。
//
// 为什么值得较真：这些节点所在的容器挂着 content-visibility: auto，改动本身在视口外
// 很便宜，但它把整棵子树标脏了，等用户滑到那里时，样式和布局就全压在那一帧上。操作
// 进行中轮询按 120/200/320/480/650ms 一轮轮打过来，每轮脏一遍，于是「操作进行中
// 滑动界面」必掉帧——这正是用户反馈的现象。
//
// checked 不在其中：它是 checkedness，写它不产生属性改动，照常赋值即可。
function setText(node, value) {
  if (node && node.textContent !== value) node.textContent = value;
}

function setClass(node, value) {
  if (node && node.className !== value) node.className = value;
}

function setData(node, key, value) {
  if (node && node.dataset[key] !== value) node.dataset[key] = value;
}

// hidden / disabled 这类布尔反射属性。读属性很便宜，也不会强制布局。
function setFlag(node, prop, value) {
  if (node && node[prop] !== value) node[prop] = value;
}

// aria-* 之类没有反射属性可读的，比对 getAttribute。setAttribute 写回相同的值同样算
// 一次属性改动，MutationObserver 照样记一条。
function setAttr(node, name, value) {
  if (node && node.getAttribute(name) !== value) node.setAttribute(name, value);
}

// 名单类 textarea 的 value。这几个框能装到 4,096 行、64KB，写一次就要把整块文本重新排版
// ——保存名单时这是全页最贵的一次布局。而保存路径上这一步几乎总是在写「一模一样的内容」：
// 先把规范化后的文本写回框里，紧接着 loadLists 重读，后端返回的又是同一份文本再写一遍。
// 用户此刻手指还在屏幕上，那次重排就落在滑动的帧上。
//
// 顺带还修掉一个手感问题：写 value 会把光标弹到末尾并清掉选区，跳过同值写入就不会动它。
function setValue(node, value) {
  if (node && node.value !== value) node.value = value;
}

// 只把易变字段写回已有卡片。骨架不动，所以不拆 DOM、不重放入场动画，
// 也不会把用户刚点的那个开关连同焦点一起销毁重建。
function patchSourceCards(sources) {
  const disabled = !initialized || !managementUnlocked || Boolean(currentStatus?.busy);
  const directory = elements.builtinSources.closest('.source-directory');
  sources.forEach((source, index) => {
    const card = directory.querySelector(`.source-card[data-source-id="${cssEscapeId(source.id)}"]`);
    if (!card) return;
    const name = displaySourceName(source);
    setClass(card, `source-card source-card-${source.kind} source-card-${source.state}`);

    patchStateChip(card.querySelector('.state-chip'), sourceState(source));

    setText(card.querySelector('.source-meta'), source.enabled
      ? `${formatCount(source.ruleCount)} 条 · ${formatTime(source.updatedAt)}`
      : '已停用：规则不参与合并，缓存已清理');

    // 报错行是「有就显示」，出现和消失都要处理，否则旧错误会一直挂着。
    const errorText = sourceError(source);
    let errorNode = card.querySelector('.source-error');
    if (errorText && !errorNode) {
      errorNode = document.createElement('p');
      errorNode.className = 'source-error';
      card.querySelector('.source-main')?.append(errorNode);
    }
    if (errorNode) {
      if (errorText) setText(errorNode, errorText);
      else errorNode.remove();
    }

    const toggle = card.querySelector('[data-action="toggle"]');
    if (toggle) {
      // 不要覆盖用户刚拨过、正在等后端确认的那一下：只有值真的不同才写。
      if (toggle.checked !== Boolean(source.enabled)) toggle.checked = Boolean(source.enabled);
      setFlag(toggle, 'disabled', disabled);
      const action = `${source.enabled ? '停用' : '启用'} ${name}`;
      const label = toggle.closest('.switch-label');
      if (label && label.title !== action) label.title = action;
      setText(label?.querySelector('.visually-hidden'), action);
    }

    const refresh = card.querySelector('[data-action="refresh"]');
    if (refresh) {
      const blocked = !source.enabled || currentStatus?.activeMode === 'paused';
      setData(refresh, 'guardDisabled', String(blocked));
      setFlag(refresh, 'disabled', disabled || blocked);
      const title = currentStatus?.activeMode === 'paused'
        ? '保护已暂停，恢复后才能刷新'
        : '刷新此来源';
      if (refresh.title !== title) refresh.title = title;
    }
    card.querySelectorAll('[data-action="move"]').forEach((button) => {
      const first = button.dataset.direction === 'up' && index === 0;
      const last = button.dataset.direction === 'down' && index === sources.length - 1;
      setData(button, 'guardDisabled', String(first || last));
      setFlag(button, 'disabled', disabled || first || last);
    });
    card.querySelectorAll('[data-action="edit"],[data-action="delete"]').forEach((button) => {
      setFlag(button, 'disabled', disabled);
    });
  });
}

function cssEscapeId(value) {
  const text = String(value ?? '');
  return typeof CSS?.escape === 'function' ? CSS.escape(text) : text.replace(/["\\]/g, '\\$&');
}

let renderedSourceStructureKey = '';

// 纯次序变化的快路径。接手的前提是「这批卡片已经在页面上，只是排错了」，所以要先核对
// 到能确定重建不会带来任何新内容为止：数量、id 集合，以及卡片上显示的名字和地址。
// 名字和地址必须比——patchSourceCards 不写 <h4>，改名要是走了这条路，卡片上的名字
// 就永远停在旧值上。对不上就返回 false，交回给整表重建。
function reorderSourceCards(builtins, custom) {
  // 一条来源都没有时下面每一项校验都会「恰好通过」，但那种状态要写的是占位文案，
  // 不是挪位置，必须交回重建。
  if (builtins.length === 0 && custom.length === 0) return false;
  const groups = [[elements.builtinSources, builtins], [elements.customSources, custom]];
  const plans = [];
  for (const [container, list] of groups) {
    // 容器里要么全是卡片，要么只有一个 .empty-state 占位。拿 children 和卡片数一起比，
    // 就把「有占位符」的情况一并挡在外面，后面的下标才等得上 children 的下标。
    const cards = [...container.querySelectorAll('.source-card')];
    if (cards.length !== list.length || container.children.length !== list.length) return false;
    const byId = new Map(cards.map((card) => [card.dataset.sourceId, card]));
    for (const source of list) {
      const card = byId.get(source.id);
      if (!card) return false;
      if (card.querySelector('.source-title-line h4')?.textContent !== displaySourceName(source)) return false;
      if ((card.querySelector('.source-url')?.textContent ?? '') !== (source.url ?? '')) return false;
    }
    plans.push([container, list, byId]);
  }
  for (const [container, list, byId] of plans) {
    list.forEach((source, index) => {
      const card = byId.get(source.id);
      // 只在位置真的不对时才动这一个节点。上移一次实际只需要挪一个卡片，逐个 append
      // 会把整列都重新插一遍，白白多出一列样式失效——正在滑动时这点差别是看得见的。
      if (container.children[index] !== card) {
        container.insertBefore(card, container.children[index] ?? null);
      }
    });
  }
  return true;
}

function renderSourceManagement(sources) {
  const structureKey = sourceStructureKey(sources);
  // 操作进行中会按轮询节奏反复调到这里（来源状态在 fresh/refreshing 之间来回跳）。
  // 以前每次都 innerHTML 重建全部卡片并重放入场动画，那就是「切换来源很慢」的手感来源，
  // 顺带还会把用户刚点的开关销毁重建、焦点丢掉。骨架没变就只改易变字段。
  if (structureKey === renderedSourceStructureKey
    && elements.builtinSources.querySelector('.source-card, .empty-state')) {
    patchSourceCards(sources);
    // 这一条是轮询路径上真正的热点分支，走 applyGuard 顺手把 guardDisabled 一起对齐，
    // 值没变就一个字都不写。
    applyGuard(elements.addSourceButton,
      sources.filter((source) => source.kind === 'custom').length >= 16);
    return;
  }
  const builtins = sources.filter((source) => source.kind !== 'custom');
  const custom = sources.filter((source) => source.kind === 'custom');

  // 调整顺序时来源集合没变，只是次序变了。这种情况下把已有卡片挪位置就够了：
  // append 一个已在文档里的节点是移动而不是新建，所以不拆 DOM、不重建图标、
  // 不重放入场动画，用户刚点的那个按钮也不会连焦点一起被销毁——这正是
  // 「调整顺序掉帧」的来源。
  if (renderedSourceStructureKey && reorderSourceCards(builtins, custom)) {
    renderedSourceStructureKey = structureKey;
    patchSourceCards(sources);
    applyGuard(elements.addSourceButton, custom.length >= 16);
    return;
  }

  renderedSourceStructureKey = structureKey;
  // indexOf 在 map 里是 O(n²)，这里先算一次位置表。
  const positions = new Map(sources.map((source, index) => [source.id, index]));
  elements.builtinSources.innerHTML = builtins.length
    ? builtins.map((source) => sourceCard(source, positions.get(source.id), sources.length)).join('')
    : '<p class="empty-state">内置来源已删除，可使用下方恢复操作添加</p>';
  elements.customSources.innerHTML = custom.length
    ? custom.map((source) => sourceCard(source, positions.get(source.id), sources.length)).join('')
    : '<p class="empty-state">尚未添加自定义规则</p>';
  animateInsertedItems(elements.builtinSources.closest('.source-directory').querySelectorAll('.source-card'));
  applyGuard(elements.addSourceButton, custom.length >= 16);
}

function renderAutoRefresh(value) {
  const interval = [6, 12, 24].includes(Number(value?.intervalHours))
    ? Number(value.intervalHours)
    : 24;
  const enabled = Boolean(value?.enabled);
  elements.autoRefreshEnabled.checked = enabled;
  setAttr(elements.autoRefreshEnabled, 'aria-expanded', String(enabled));
  setFlag(elements.autoRefreshInterval, 'hidden', !enabled);
  document.querySelectorAll('input[name="auto-refresh-interval"]').forEach((input) => {
    input.checked = Number(input.value) === interval;
  });
  setText(elements.autoRefreshSummary, enabled
    ? `每 ${interval} 小时自动更新`
    : '自动更新已关闭');
}

// 变更检测只看界面真正会显示的字段。以前是 JSON.stringify(sources)，把整份来源
// （含界面根本不读的字段）序列化一遍，而这是轮询路径——每次操作轮询都要付一次，
// 而且任何无关字段变动都会触发一次整表重建。
function sourcesDigest(sources) {
  let digest = '';
  for (const source of sources) {
    digest += `${source.id}${source.kind}${source.url ?? ''}`
      + `${displaySourceName(source)}${source.enabled ? 1 : 0}${source.state}`
      + `${source.ruleCount ?? ''}${source.updatedAt ?? ''}`
      + `${source.error ?? ''}${source.skippedCount ?? 0}`;
  }
  return digest;
}

function renderSources(sources) {
  latestSources = sources;
  const key = sourcesDigest(sources);
  if (key === renderedSourcesKey) return;
  renderedSourcesKey = key;
  renderOverviewSources(sources);
  if (sourcePanelRendered) renderSourceManagement(sources);
}

function ensureSourcePanelRendered() {
  if (sourcePanelRendered) return;
  sourcePanelRendered = true;
  renderSourceManagement(latestSources);
  refreshIcons(elements.builtinSources.closest('.source-directory'));
}

// 单个域名的合法性判断。之所以单独拿出来：覆写校验要对每一行都判一次域名，
// 以前它是整个调 canonicalList，于是每行都白白付一次 Set、sort 和 TextEncoder，
// 1024 行覆写就是 1024 次——保存时的卡顿主要来自这里。
function domainIsInvalid(domain) {
  if (domain.length > 253 || /^[0-9.]+$/.test(domain) || !/^[a-z0-9.-]+$/.test(domain)) return true;
  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) return true;
  return domain.split('.').some((label) => label.length > 63
    || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
}

// 只数 UTF-8 字节数，不为了取长度而先编码出一整个 Uint8Array。名单上限是 64 KiB，
// 原来的写法每次保存都要额外分配这么大一块，纯粹是丢给 GC 的垃圾。
function utf8ByteLength(text) {
  let bytes = 0;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < text.length) {
      const next = text.charCodeAt(index + 1);
      // 合法代理对算 4 字节并跳过低位；孤立的高位代理按替换字符的 3 字节算。
      if (next >= 0xdc00 && next <= 0xdfff) { bytes += 4; index += 1; } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

// canonicalList / canonicalOverrides 要 split、逐行 trim+转小写、逐行跑一遍格式校验，再去重
// 排序——名单填到几千行时，这是保存那一帧上最重的一段纯计算。而输入时的防抖校验刚刚已经
// 拿同样的内容算过一遍了：用户总是停手打字之后才去点保存，两次的输入几乎必然一模一样。
//
// 于是按输入框记住「上一次的原文 + 算出来的结果」，原文没变就直接复用，把这一段整个从点击
// 那一帧上拿掉。每个框只对应一个规范化函数，所以只记原文就够。WeakMap 保证条目数就等于框
// 的个数，不会随编辑次数增长。
const canonicalCache = new WeakMap();

function canonicalFor(node, compute) {
  const raw = node.value;
  const cached = canonicalCache.get(node);
  if (cached && cached.raw === raw) return cached.result;
  const result = compute(raw);
  canonicalCache.set(node, { raw, result });
  return result;
}

function canonicalList(value) {
  const lines = String(value ?? '').split(/\r?\n/)
    .map((line) => line.trim().toLowerCase())
    .filter((line) => line && !line.startsWith('#'));
  const invalid = lines.find(domainIsInvalid);
  if (invalid) return { error: `域名格式无效：${invalid}` };
  const unique = [...new Set(lines)].sort();
  if (unique.length > 4096) return { error: '单个名单最多 4,096 个域名' };
  const text = unique.length ? `${unique.join('\n')}\n` : '';
  if (utf8ByteLength(text) > 65536) return { error: '单个名单不能超过 65,536 字节' };
  return { text, count: unique.length };
}

function ipv4Valid(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^(?:0|[1-9][0-9]{0,2})$/.test(part)
    && Number(part) <= 255);
}

function ipv6Valid(value) {
  if (!/^[0-9a-f:]+$/.test(value) || !value.includes(':') || value.includes(':::')) return false;
  if ((value.match(/::/g) || []).length > 1) return false;
  const compact = value.includes('::');
  const groups = value.split(':').filter(Boolean);
  if (groups.some((group) => group.length > 4 || !/^[0-9a-f]+$/.test(group))) return false;
  return compact ? groups.length < 8 : groups.length === 8;
}

function canonicalOverrides(value) {
  const protectedNames = new Set([
    'localhost', 'localhost.localdomain', 'local', 'broadcasthost',
    'ip6-localhost', 'ip6-loopback', 'ip6-allnodes', 'ip6-allrouters',
  ]);
  const rows = [];
  const seen = new Set();
  for (const rawLine of String(value ?? '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const fields = line.split(/\s+/);
    if (fields.length !== 2) return { error: `覆写格式无效：${line}` };
    const domain = fields[0].toLowerCase();
    const address = fields[1].toLowerCase();
    if (domainIsInvalid(domain) || protectedNames.has(domain) || domain.endsWith('.localhost')) {
      return { error: `覆写域名无效或受保护：${domain}` };
    }
    const family = ipv4Valid(address) ? '4' : ipv6Valid(address) ? '6' : '';
    if (!family) return { error: `IP 地址无效：${address}` };
    const key = `${domain}:${family}`;
    if (seen.has(key)) return { error: `同一域名的 IPv${family} 覆写只能有一条：${domain}` };
    seen.add(key);
    rows.push([domain, address]);
  }
  if (rows.length > 1024) return { error: '最多保存 1,024 条覆写' };
  rows.sort((left, right) => left[0].localeCompare(right[0]) || left[1].localeCompare(right[1]));
  const text = rows.length ? `${rows.map((row) => row.join('\t')).join('\n')}\n` : '';
  if (utf8ByteLength(text) > 65536) return { error: '覆写内容不能超过 65,536 字节' };
  return { rows, text, count: rows.length };
}

async function loadBuiltinRecovery({ force = false, read = null } = {}) {
  if (builtinRecoveryLoading || (builtinRecoveryLoaded && !force)) return;
  builtinRecoveryLoading = true;
  try {
    const templates = read ? await read() : await execApi('templates');
    const missing = Array.isArray(templates)
      ? templates.filter((template) => !template.present)
      : [];
    const recoveryDisabled = !managementUnlocked || Boolean(currentStatus?.busy);
    elements.builtinRecovery.hidden = missing.length === 0;
    elements.builtinRecovery.innerHTML = missing.map((template) => `
      <div class="builtin-recovery-row">
        <span>可恢复 ${escapeText(template.name)}</span>
        <button class="icon-button builtin-recovery-action write-action" type="button" data-recovery-id="${escapeAttribute(template.id)}" data-recovery-name="${escapeAttribute(template.name)}" data-recovery-url="${escapeAttribute(template.url)}" aria-label="恢复 ${escapeAttribute(template.name)}" title="恢复 ${escapeAttribute(template.name)}" ${recoveryDisabled ? 'disabled' : ''}>
          ${iconMarkup('rotate-ccw')}
        </button>
      </div>
    `).join('');
    refreshIcons(elements.builtinRecovery);
    builtinRecoveryLoaded = true;
  } catch (error) {
    elements.builtinRecovery.hidden = false;
    elements.builtinRecovery.innerHTML = `<p class="empty-state">恢复信息读取失败：${escapeText(error?.message || '未知错误')}</p>`;
  } finally {
    builtinRecoveryLoading = false;
  }
}

// 进入规则页原本会并发发起 lists / templates / overrides 三次调用，
// 而每次调用都要重新 source 整套规则库并各跑一遍 config_bootstrap。
// 这里合并为一次 rules-bundle 读取，并把三份数据的落地拆到不同任务，
// 避开大文本域赋值与来源卡渲染挤在同一帧。
function loadRulesBundle() {
  const wantLists = !listsLoaded && !listsLoading;
  const wantOverrides = !overridesLoaded && !overridesLoading;
  const wantTemplates = !builtinRecoveryLoaded && !builtinRecoveryLoading;
  if (!wantLists && !wantOverrides && !wantTemplates) return;
  const bundle = execApi('rules-bundle');
  bundle.catch(() => {});
  const readPart = (key, deferred) => async () => {
    const data = await bundle;
    if (deferred) await nextTask();
    return data?.[key];
  };
  if (wantLists) loadLists({ read: readPart('lists', false) });
  if (wantOverrides) loadOverrides({ read: readPart('overrides', true) });
  if (wantTemplates) loadBuiltinRecovery({ read: readPart('templates', true) });
}

async function loadOverrides({ force = false, read = null } = {}) {
  if (overridesLoading || (overridesLoaded && !force)) return;
  overridesLoading = true;
  elements.overrideSyncNote.textContent = '正在读取';
  try {
    const data = read ? await read() : await execApi('overrides');
    const items = Array.isArray(data?.items) ? data.items : [];
    // 先把整段文本拼好再写一次。原来是先写一遍、再 `+= '\n'` 补一个换行，那是两次完整的
    // value 写入——第二次还要先把整块文本读回来——等于把最贵的那次重排做了两遍。
    const text = items.map((item) => `${item.domain}\t${item.address}`).join('\n');
    setValue(elements.domainOverrides, items.length ? `${text}\n` : text);
    setText(elements.overrideCount, `${items.length} 条`);
    setText(elements.overrideError, '');
    setText(elements.overrideSyncNote, '');
    overridesLoaded = true;
  } catch (error) {
    elements.overrideSyncNote.textContent = '读取失败';
    showNotice(`覆写读取失败：${error?.message || '未知错误'}`, { persistent: true, tone: 'danger' });
  } finally {
    overridesLoading = false;
    setWritesDisabled(Boolean(currentStatus?.busy));
  }
}

async function saveOverrides() {
  const result = canonicalFor(elements.domainOverrides, canonicalOverrides);
  setText(elements.overrideError, result.error || '');
  if (result.error) return;
  setValue(elements.domainOverrides, result.text);
  setText(elements.overrideCount, `${result.count} 条`);
  await runMutation('set-overrides', [encodeBase64Utf8(result.text)]);
  overridesLoaded = false;
  await loadOverrides({ force: true });
}

function renderListCounts(blockCount, allowCount) {
  setText(elements.blockListCount, `${formatCount(blockCount)} 条`);
  setText(elements.allowListCount, `${formatCount(allowCount)} 条`);
}

function renderListErrors(blockError = '', allowError = '') {
  setText(elements.blockListError, blockError);
  setText(elements.allowListError, allowError);
  elements.manualBlocklist.toggleAttribute('aria-invalid', Boolean(blockError));
  elements.manualAllowlist.toggleAttribute('aria-invalid', Boolean(allowError));
}

// 后端返回的名单数组按 canonicalList 的形状拼成文本：非空时带结尾换行，空名单就是空串。
function listText(items) {
  if (!Array.isArray(items) || items.length === 0) return '';
  return `${items.join('\n')}\n`;
}

function loadLists({ force = false, read = null } = {}) {
  if (disposed || (!force && listsLoaded)) return Promise.resolve();
  if (listsLoading) return listsLoadPromise ?? Promise.resolve();
  listsLoading = true;
  elements.manualBlocklist.disabled = true;
  elements.manualAllowlist.disabled = true;
  elements.saveListsButton.disabled = true;
  elements.listSyncNote.textContent = '正在读取';
  listsLoadPromise = (async () => {
    try {
      for (let attempt = 0; attempt < LIST_READ_MAX_ATTEMPTS; attempt += 1) {
        // 预取只用于第一次；版本落后时的重读仍然单独读 lists。
        const data = attempt === 0 && read ? await read() : await execApi('lists');
        if (!Number.isInteger(data?.revision)) {
          throw new Error('名单响应缺少有效版本号');
        }
        if (Number.isInteger(currentStatus?.desiredSourcesRevision)
          && data.revision < currentStatus.desiredSourcesRevision) {
          if (attempt === LIST_READ_MAX_ATTEMPTS - 1) {
            throw new Error('名单配置仍在同步，请稍后重试');
          }
          elements.listSyncNote.textContent = '配置已更新，正在重读';
          continue;
        }
        // 保存后紧接着就会重读一次，返回的和框里现有的内容一字不差，跳过这次重排。
        // 结尾那个换行必须跟 canonicalList 保持一致：保存时写进框里的文本是带换行的，
        // 这里要是按 join('\n') 拼成不带的，两份就差一个字符，跳过判定永远不成立，
        // 两个框每次保存都要把整块文本重排两遍。canonicalList 会滤掉空行，末尾这个
        // 换行对所有读取方都是透明的，loadOverrides 一直也是这么写的。
        setValue(elements.manualBlocklist, listText(data?.block));
        setValue(elements.manualAllowlist, listText(data?.allow));
        listsRevision = data.revision;
        listsLoaded = true;
        renderListCounts(data?.blockCount ?? 0, data?.allowCount ?? 0);
        renderListErrors();
        elements.listSyncNote.textContent = '';
        return;
      }
    } catch (error) {
      elements.listSyncNote.textContent = '读取失败';
      showNotice(error?.message || '黑白名单读取失败', { persistent: true, tone: 'danger' });
    } finally {
      listsLoading = false;
      listsLoadPromise = null;
      const disabled = !initialized || !managementUnlocked || Boolean(currentStatus?.busy);
      elements.manualBlocklist.disabled = disabled;
      elements.manualAllowlist.disabled = disabled;
      elements.saveListsButton.disabled = disabled;
    }
  })();
  return listsLoadPromise;
}

async function saveLists() {
  if (!initialized || !managementUnlocked || currentStatus?.busy) return;
  const block = canonicalFor(elements.manualBlocklist, canonicalList);
  const allow = canonicalFor(elements.manualAllowlist, canonicalList);
  renderListErrors(block.error || '', allow.error || '');
  if (block.error || allow.error) return;
  // 用户填的内容本来就规范时（粘贴一份已经排好的名单、或者只是又点了一次保存），
  // 规范化的结果和框里的一字不差，这次重排整块文本的开销就可以整个省掉。
  setValue(elements.manualBlocklist, block.text);
  setValue(elements.manualAllowlist, allow.text);
  renderListCounts(block.count, allow.count);
  await runMutation('set-lists', [encodeBase64Utf8(block.text), encodeBase64Utf8(allow.text)]);
}

function renderStatus(status) {
  if (!status || typeof status !== 'object') return;
  currentStatus = status;
  initialized = true;
  setAttr(elements.app, 'aria-busy', String(Boolean(status.busy)));
  setHeaderPresentation(dohHeaderPresentation(statusPresentation(status)));
  setText(elements.ruleCount, formatCount(status.ruleCount));
  renderListCounts(status.manualBlockCount ?? 0, status.manualAllowCount ?? 0);
  renderAutoRefresh(status.autoRefresh);
  if (listsLoaded && listsRevision !== status.desiredSourcesRevision && !status.busy) {
    listsLoaded = false;
    loadLists({ force: true });
  }
  const sources = Array.isArray(status.sources) ? status.sources : [];
  const enabledSources = sources.filter((source) => source.enabled);
  const loadedSources = enabledSources.filter((source) => source.state === 'fresh' || source.state === 'stale');
  const onlineRuleTotal = loadedSources.reduce((total, source) => (
    total + (Number.isFinite(source.ruleCount) ? source.ruleCount : 0)
  ), 0);
  const noOnlineRules = sources.length > 0 && onlineRuleTotal === 0;
  const allSourcesDisabled = sources.length > 0 && enabledSources.length === 0;
  const retainedPreviousGeneration = Boolean(status.activeGeneration)
    && (status.sourcesOutOfSync || status.result === 'failed' || status.result === 'critical');
  const impactCopy = elements.ruleCount.closest('#rule-impact-copy');
  const paused = status.activeMode === 'paused';
  // 第一行永远是「规则总数」，本地规则等细节放在第二行小字里。
  // 这句话由「前缀 + 活的 ruleCount 节点 + 后缀」三段拼成，措辞只有三种。原来每轮都
  // 先清空再 append 一遍：清空会把 ruleCount 从文档里摘下来，append 又插回去，等于
  // 每轮拆装一次首页最显眼的那行字，一定要重排。措辞没变时一个字都不用动。
  const impactPrefix = paused ? '已暂停，当前挂载 '
    : retainedPreviousGeneration ? '当前保留上一版 '
    : '当前已经累积 ';
  if (impactCopy && impactCopy.firstChild?.nodeValue !== impactPrefix) {
    impactCopy.textContent = '';
    impactCopy.append(impactPrefix, elements.ruleCount, ' 条 hosts 规则');
  }
  if (elements.ruleImpactHint) {
    const localCopy = `本地规则 ${formatCount(status.ruleCount)} 条`;
    setText(elements.ruleImpactHint, paused
      ? '缓存与历史版本已清空，恢复保护时重新下载规则'
      : allSourcesDisabled
      ? `${localCopy} · 已停用全部来源：来源规则不生效，手工黑名单仍然拦截`
      : noOnlineRules
      ? `${localCopy} · 在线来源未加载，只剩内置名单与手工规则生效`
      : onlineRuleTotal > 0
      ? `在线来源合计 ${formatCount(onlineRuleTotal)} 条 · 超过 50,000 条会轻微影响网络`
      : '超过 50,000 条会轻微影响网络');
  }
  const hasRuleCount = Number.isFinite(status.ruleCount);
  const hasLightImpact = hasRuleCount && status.ruleCount <= 50_000;
  if (paused) {
    setText(elements.networkImpact, '保护已暂停');
    setData(elements.ruleImpact, 'tone', 'notice');
  } else if (!hasRuleCount) {
    setText(elements.networkImpact, '等待读取');
    setData(elements.ruleImpact, 'tone', 'neutral');
  } else if (noOnlineRules) {
    setText(elements.networkImpact, '仅本地保护');
    setData(elements.ruleImpact, 'tone', 'notice');
  } else {
    setText(elements.networkImpact, hasLightImpact ? '网络基本无影响' : '可能轻微影响网络');
    setData(elements.ruleImpact, 'tone', hasLightImpact ? 'calm' : 'notice');
  }
  setText(elements.lastSuccess, formatTime(status.lastSuccessAt));

  const mode = status.desiredMode || status.activeMode;
  document.querySelectorAll('input[name="mode"]').forEach((input) => {
    input.checked = input.value === mode;
  });
  setText(elements.modeSyncNote, paused
    ? '恢复后继续使用当前模式'
    // 模式偏好确实保留，这句不用改；规则内容会重新下载，那句在上面的规则总数提示里。
    : status.desiredMode !== status.activeMode ? '模式等待应用' : '');

  setFlag(elements.pauseProtectionButton, 'hidden', paused || !status.activeGeneration);
  setFlag(elements.resumeProtectionButton, 'hidden', !paused);
  applyGuard(elements.pauseProtectionButton, !status.activeGeneration);

  // 暂停期间「立即刷新」会被后端拒掉：它要下载全部来源再重建世代，正是暂停停掉的事。
  applyGuard(elements.refreshButton, paused);
  const refreshTitle = paused ? '保护已暂停，恢复后才能刷新' : '';
  if (elements.refreshButton.title !== refreshTitle) elements.refreshButton.title = refreshTitle;

  // 缓存只有在来源被停用之后才会变成没人用的死文件：启用中的来源要留着缓存断网兜底，
  // 删除来源时缓存已经顺手清掉了。所以没有停用来源就没有可清的东西，直接锁住按钮。
  const disabledSourceCount = sources.length - enabledSources.length;
  applyGuard(elements.clearCacheButton, disabledSourceCount === 0);
  const clearCacheTitle = disabledSourceCount > 0
    ? `清理 ${formatCount(disabledSourceCount)} 个已停用来源留下的缓存文件`
    : '没有已停用的来源，暂时没有可清理的缓存';
  if (elements.clearCacheButton.title !== clearCacheTitle) {
    elements.clearCacheButton.title = clearCacheTitle;
  }

  const rollbackVisible = status.alternateAction === 'rollback' || status.alternateAction === 'redo';
  setFlag(elements.rollbackButton, 'hidden', !rollbackVisible);
  if (rollbackVisible) {
    const iconName = status.alternateAction === 'redo' ? 'rotate-cw' : 'rotate-ccw';
    setText(elements.rollbackButton.querySelector('span'),
      status.alternateAction === 'redo' ? '恢复新版' : '回滚上一版');
    // 图标就地改 data-lucide 和 use 的 href，和 patchStateChip 同一个路子。
    //
    // 原来是换成一个占位 <i data-lucide data-icon-name>，等下面 refreshIcons 再变回 svg。
    // 但 refreshIcons 只搬 data-lucide，不带 data-icon-name，于是变回来的 svg 上永远读不到
    // 这个值，判断就永远成立——回滚按钮显示期间，每一轮轮询都要拆一次、装一次。
    patchIcon(elements.rollbackButton.querySelector('.rollback-icon'), iconName);
  }

  renderSources(sources);
  setWritesDisabled(Boolean(status.busy));
  if (historyStatus) renderHistoryStatus(historyStatus);
  refreshIcons(elements.headerStatus);
  refreshIcons(elements.overviewSources);
  refreshIcons(elements.rollbackButton);
}

function renderBridgeFailure(error) {
  initialized = false;
  currentStatus = null;
  setHeaderPresentation({
    header: '未生效',
    headerIcon: 'shield-x',
    headerTone: 'danger',
    title: '无法连接规则服务',
    detail: error?.message || '请从支持模块 WebUI 的管理器中打开此页面',
    icon: 'unplug',
    tone: 'danger',
  });
  elements.app.setAttribute('aria-busy', 'false');
  setWritesDisabled(true);
  elements.diagnosticsButton.disabled = true;
  renderDohUnavailable(error);
  refreshIcons(elements.headerStatus);
}

function clearNotice() {
  if (noticeTimer !== null) {
    globalThis.clearTimeout(noticeTimer);
    timers.delete(noticeTimer);
    noticeTimer = null;
  }
  elements.announcer.replaceChildren();
}

function showNotice(message, { persistent = false, progress = false, tone = 'neutral' } = {}) {
  clearNotice();
  const notice = document.createElement('div');
  notice.className = `toast-message toast-${tone}`;
  if (progress) {
    const indicator = document.createElement('span');
    indicator.className = 'toast-progress-indicator';
    indicator.setAttribute('aria-hidden', 'true');
    notice.append(indicator);
  }
  const copy = document.createElement('span');
  copy.textContent = message;
  notice.append(copy);
  elements.announcer.append(notice);
  if (!persistent) {
    noticeTimer = schedule(() => {
      elements.announcer.replaceChildren();
      noticeTimer = null;
    }, 4000);
  }
}

function unlockManagement({ remembered = false, permanently = false } = {}) {
  managementUnlocked = true;
  elements.noticeReadonly.hidden = true;
  if (elements.noticeDialog.open) elements.noticeDialog.close();
  setWritesDisabled(Boolean(currentStatus?.busy));
  syncHistoryControls();
  if (builtinRecoveryLoaded) loadBuiltinRecovery({ force: true });
  if (runInitialRefreshIfPending()) return;
  if (permanently) {
    showNotice('已确认，后续进入不再提醒', { tone: 'success' });
  } else if (remembered) {
    clearNotice();
  }
}

function runInitialRefreshIfPending() {
  if (initialRefreshScheduled
    || !initialized
    || !managementUnlocked
    || !currentStatus?.initialRefreshPending
    || disposed) {
    return false;
  }
  initialRefreshScheduled = true;
  void startInitialRefresh();
  return true;
}

// 首次进入时后台可能正在跑安装后的首刷。这时既不能直接下发 refresh（runMutation 会因
// busy 原地返回），也不能干等——没有任何轮询会把规则总量刷出来。先跟着后台轮询让状态
// 实时更新，等它空闲后再看首刷标记是否还在，还在才补一次 refresh。
async function startInitialRefresh() {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (currentStatus?.busy) {
      try {
        await watchBackendUntilIdle();
      } catch {
        return;
      }
    }
    if (disposed || !managementUnlocked || !currentStatus?.initialRefreshPending) return;
    const outcome = await runMutation('refresh');
    if (outcome?.errorCode !== 'operation_busy') return;
    // 后台已经在跑安装后的首刷。重新读一次真实状态，跟着它轮询到空闲，
    // 再看首刷标记是否还在，还在才补下发一次。
    try {
      renderStatus(await execApi('status'));
    } catch {
      return;
    }
  }
}

function keepReadonly() {
  managementUnlocked = false;
  if (elements.noticeDialog.open) elements.noticeDialog.close();
  elements.noticeReadonly.hidden = false;
  setWritesDisabled(true);
  syncHistoryControls();
  // 只读态也要显示真实进度，否则后台忙时规则总量会一直停在占位符上。
  if (currentStatus?.busy) void watchBackendUntilIdle().catch(() => {});
}

async function loadNoticeGate(noticeOutcome = null) {
  managementUnlocked = false;
  setWritesDisabled(true);
  try {
    if (noticeOutcome?.state === 'rejected') throw noticeOutcome.reason;
    const preference = noticeOutcome?.state === 'fulfilled'
      ? noticeOutcome.value
      : await execApi('notice-status');
    noticeLoaded = true;
    if (preference?.acknowledged === true) {
      unlockManagement({ remembered: true });
      return;
    }
  } catch (error) {
    noticeLoaded = true;
    showNotice(`提示偏好读取失败：${error?.message || '未知错误'}`, {
      persistent: true,
      tone: 'danger',
    });
  }
  if (!elements.noticeDialog.open) elements.noticeDialog.showModal();
}

async function acknowledgeNoticePermanently() {
  elements.noticeConfirmPermanentButton.disabled = true;
  elements.noticeCancelButton.disabled = true;
  elements.noticeConfirmButton.disabled = true;
  try {
    const result = await submitMutation('set-notice', ['1']);
    if (result.state === 'result_unknown') {
      throw new Error('保存结果未知，下次进入仍会提醒');
    }
    const status = await pollOperation(
      result.operationId,
      (nextStatus) => renderStatus(nextStatus),
      lifecycle.signal,
    );
    renderStatus(status);
    if (status.result === 'failed' || status.result === 'critical') {
      throw new Error('提示偏好保存失败，下次进入仍会提醒');
    }
    unlockManagement({ remembered: true, permanently: true });
  } catch (error) {
    if (!isAbort(error)) {
      unlockManagement();
      showNotice(error?.message || '提示偏好保存失败，下次进入仍会提醒', {
        persistent: true,
        tone: 'danger',
      });
    }
  } finally {
    elements.noticeConfirmPermanentButton.disabled = false;
    elements.noticeCancelButton.disabled = false;
    elements.noticeConfirmButton.disabled = false;
  }
}

function nextPaint() {
  return new Promise((resolve) => {
    globalThis.requestAnimationFrame(() => schedule(resolve, 0));
  });
}

function optimisticMutationStatus(verb, args) {
  const optimistic = {
    ...currentStatus,
    busy: true,
    operationVerb: verb,
    phase: verb === 'rollback' ? 'rolling_back' : 'validating',
  };
  if (verb === 'select-mode') optimistic.desiredMode = args[0];
  if (verb === 'pause') {
    optimistic.activeMode = 'paused';
    optimistic.ruleCount = 0;
  }
  if (verb === 'resume') optimistic.activeMode = optimistic.desiredMode || 'block_all';
  if (verb === 'set-auto-refresh') {
    optimistic.autoRefresh = {
      enabled: args[0] === '1',
      intervalHours: Number(args[1]),
    };
  }
  if (verb === 'set-builtin' || verb === 'set-source') {
    const sources = Array.isArray(currentStatus.sources) ? currentStatus.sources : [];
    optimistic.sources = sources.map((source) => source.id === args[0]
      ? { ...source, enabled: args[1] === '1' }
      : source);
  }
  return optimistic;
}

// 加密 DNS 与应用联网策略都不改规则来源，所以不能拿 sourcesOutOfSync 判定它们失败，
// 否则来源恰好不同步时一次成功的应用也会被报成失败（clear-cache 早先已单独豁免过）。
const SOURCE_NEUTRAL_VERBS = new Set(['set-doh', 'disable-doh', 'set-app-policy']);

function showMutationResult(verb, status) {
  const label = VERB_LABELS[verb] || '操作';
  const sourceNeutral = SOURCE_NEUTRAL_VERBS.has(verb);
  const failed = status.result === 'critical' || status.result === 'failed'
    || (!sourceNeutral && status.sourcesOutOfSync);
  if (failed) {
    // 失败时把后台给出的具体原因带出来，否则用户只看到“未完成”，无从下手。
    const reason = sourceNeutral ? errorMessage(status.lastError, '') : '';
    showNotice(
      reason ? `${label}未完成：${reason}` : `${label}未完成，当前规则保持不变`,
      { persistent: true, tone: 'danger' },
    );
  } else if (status.result === 'degraded') {
    showNotice(`${label}完成，部分来源使用缓存`, { tone: 'warning' });
  } else {
    showNotice(`${label}完成`, { tone: 'success' });
  }
}

function isAbort(error) {
  return disposed || error?.name === 'AbortError' || error?.code === 'page_hidden';
}

function dohErrorMessage(value, fallback = '加密 DNS 状态异常') {
  const code = typeof value === 'string' ? value : value?.code;
  if (DOH_ERRORS[code]) return DOH_ERRORS[code];
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && typeof value.message === 'string') return value.message;
  return fallback;
}

// 运行态取值必须与 lib/rules/doh.sh 的 doh_runtime_write 保持一致：
// companionState 为 stopped|starting|running，firewallState 为 absent|staged|active|incomplete。
// 只有伴随进程在跑且规则已切换完成，才算真正生效。
function dohVerifiedActive(status = dohStatus) {
  return ['global', 'selected'].includes(status?.effectiveMode)
    && status?.companionState === 'running'
    && status?.firewallState === 'active';
}

function selectedDohSupported(status = dohStatus) {
  return status?.supported !== false && Array.isArray(status?.modes) && status.modes.includes('selected');
}

function selectedDohMode() {
  return document.querySelector('input[name="doh-mode"]:checked')?.value || 'off';
}

// 加密 DNS 生效时在头部和首页详情后面各加一段后缀。
//
// 这里改成「先把后缀拼进 presentation，再整句写一次」，而不是原来的「先写主句，再回头读
// 出来接一段」。原来那种写法每轮轮询都必然改两次 DOM：renderStatus 先把不带后缀的主句
// 写回去，紧接着这里读到没有后缀又追加一次。两次的值都和上一次不同，setText 的比对根本
// 挡不住。现在最终值一轮和一轮一样，就一个字都不用写。
function dohHeaderPresentation(presentation) {
  if (!dohVerifiedActive()) return presentation;
  return {
    ...presentation,
    header: `${presentation.header} · DoH`,
    detail: presentation.detail ? `${presentation.detail}；加密 DNS 已启用` : '加密 DNS 已启用',
  };
}

// 加密 DNS 状态单独刷新时（它有自己 5 秒一次的轮询）也要把头部重算一遍，否则刚启用完
// 头部要等到下一次状态轮询才带上后缀。
function applyDohHeaderPresentation() {
  if (!currentStatus) return;
  setHeaderPresentation(dohHeaderPresentation(statusPresentation(currentStatus)));
}

function stopDohRefresh() {
  if (dohRefreshTimer !== null) {
    globalThis.clearTimeout(dohRefreshTimer);
    timers.delete(dohRefreshTimer);
    dohRefreshTimer = null;
  }
}

function scheduleDohRefresh() {
  stopDohRefresh();
  if (!appsPanelActive || document.hidden || !dohVerifiedActive()) return;
  dohRefreshTimer = schedule(async () => {
    dohRefreshTimer = null;
    await loadDohStatus({ force: true, refresh: true });
  }, 5000);
}

function renderDohStatus(status = {}) {
  dohStatus = status;
  const active = dohVerifiedActive(status);
  const supported = status.supported !== false;
  const selectedSupported = selectedDohSupported(status);
  const renderMode = active ? status.effectiveMode : 'off';
  document.querySelectorAll('input[name="doh-mode"]').forEach((input) => {
    input.checked = input.value === renderMode;
    setData(input, 'guardDisabled', String(input.value === 'selected' && !selectedSupported));
  });
  setFlag(elements.dohSelectedRegion, 'hidden', renderMode !== 'selected');
  setFlag(elements.dohAppList, 'hidden', renderMode !== 'selected');

  // 后端会回传已提交的地址，用它回填输入框，避免每次重新启用都要重输。
  if (typeof status.endpoint === 'string' && status.endpoint
    && !dohEndpointDirty
    && elements.dohEndpoint.value !== status.endpoint) {
    elements.dohEndpoint.value = status.endpoint;
  }

  const selectedUnsupported = supported && !selectedSupported;
  const selectedUnsupportedCopy = selectedUnsupported ? ' · 当前设备不支持所选应用模式' : '';
  // 加密 DNS 生效时这一段自己也有 5 秒一次的轮询，措辞一直不变，同样一个字都不该写。
  if (!supported) {
    setText(elements.dohStatus, '当前设备不支持加密 DNS');
  } else if (active) {
    const modeCopy = status.effectiveMode === 'selected' ? '所选应用' : '全设备';
    setText(elements.dohStatus, `加密 DNS 已启用 · ${modeCopy}${selectedUnsupportedCopy}`);
  } else if (status.desiredMode && status.desiredMode !== 'off' && status.lastError) {
    setText(elements.dohStatus, `已回退到关闭 · ${dohErrorMessage(status.lastError)}${selectedUnsupportedCopy}`);
  } else {
    setText(elements.dohStatus, `加密 DNS 关闭${selectedUnsupportedCopy}`);
  }
  setClass(elements.dohStatus, active
    ? 'state-chip state-chip-success'
    : status.lastError ? 'state-chip state-chip-warning' : 'state-chip');
  syncDohControls();
  applyDohHeaderPresentation();
  if (renderMode === 'selected' && !dohAppsLoaded && !dohAppsLoading) {
    loadDohApps({ reset: true });
  }
  scheduleDohRefresh();
}

function renderDohUnavailable(error) {
  dohStatus = null;
  dohLoaded = false;
  stopDohRefresh();
  elements.dohStatus.textContent = error?.message || '加密 DNS 状态不可用';
  elements.dohStatus.className = 'state-chip state-chip-danger';
  syncDohControls(true);
}

function syncDohControls(disabled = !initialized || !managementUnlocked || Boolean(currentStatus?.busy)) {
  if (!elements.dohSection) return;
  const unavailable = disabled || dohLoading;
  const selected = selectedDohMode() === 'selected';
  const selectedSupported = selectedDohSupported();
  // 这里十几个开关全走 setFlag：setWritesDisabled 每轮轮询都会调到这个函数，而操作
  // 进行中这些值一轮都不会变。hidden 尤其要紧，它落在 .doh-section 这种挂了
  // content-visibility 的容器里，写一次就把整棵子树标脏。
  setFlag(elements.dohMode, 'disabled', unavailable);
  document.querySelectorAll('input[name="doh-mode"]').forEach((input) => {
    setFlag(input, 'disabled', unavailable || (input.value === 'selected' && !selectedSupported));
  });
  setFlag(elements.dohSelectedRegion, 'hidden', !selected);
  setFlag(elements.dohAppList, 'hidden', !selected);
  setFlag(elements.dohEndpoint, 'disabled', unavailable);
  setFlag(elements.dohTest, 'disabled', unavailable);
  setFlag(elements.dohApply, 'disabled', unavailable);
  setFlag(elements.dohDisable, 'disabled', unavailable || !dohVerifiedActive());
  setFlag(elements.dohAppSearch, 'disabled', unavailable || !selected || dohAppsLoading);
  setFlag(elements.dohUids, 'disabled', unavailable || !selected);
  setFlag(elements.dohLoadMoreApps, 'disabled', unavailable || dohAppsLoading);
}

async function loadDohStatus({ force = false, refresh = false } = {}) {
  if (dohLoading || (dohLoaded && !force)) return;
  dohLoading = true;
  if (!refresh) elements.dohStatus.textContent = '正在读取加密 DNS 状态…';
  syncDohControls(true);
  try {
    const data = await execApi('doh-status');
    if (disposed || !appsPanelActive) return;
    dohLoaded = true;
    renderDohStatus(data || {});
  } catch (error) {
    if (!isAbort(error)) renderDohUnavailable(error);
  } finally {
    dohLoading = false;
    syncDohControls(Boolean(currentStatus?.busy));
  }
}

function renderDohApps(apps, { reset = false } = {}) {
  if (reset) elements.dohAppList.replaceChildren();
  const normalized = Array.isArray(apps) ? apps : [];
  if (normalized.length > 0) {
    const fragment = document.createDocumentFragment();
    normalized.forEach((app) => {
      const uid = Number(app.uid);
      const packages = Array.isArray(app.packages) ? app.packages : [];
      const label = document.createElement('label');
      label.className = 'doh-app-row';
      const checkbox = document.createElement('input');
      checkbox.className = 'write-action';
      checkbox.type = 'checkbox';
      checkbox.value = String(uid);
      checkbox.disabled = !managementUnlocked || Boolean(currentStatus?.busy);
      const copy = document.createElement('span');
      copy.className = 'doh-app-copy';
      const title = document.createElement('strong');
      title.textContent = packages[0] || app.label || `UID ${uid}`;
      const detail = document.createElement('span');
      detail.textContent = packages.length > 0 ? packages.join(' · ') : `UID ${uid}`;
      copy.append(title, detail);
      label.append(checkbox, copy);
      if (packages.length > 1) {
        const warning = document.createElement('em');
        warning.textContent = '共享 UID，所有同 UID 包都会受影响';
        label.append(warning);
      }
      fragment.append(label);
    });
    elements.dohAppList.append(fragment);
  }
  if (!elements.dohAppList.querySelector('.doh-app-row')) {
    elements.dohAppList.innerHTML = '<p class="empty-state">没有匹配的应用</p>';
  }
  refreshIcons(elements.dohAppList);
}

async function loadDohApps({ reset = false } = {}) {
  if (dohAppsLoading || selectedDohMode() !== 'selected' || !appsPanelActive || disposed) return;
  const query = elements.dohAppSearch.value.trim();
  if (query && !/^[A-Za-z0-9_.-]{1,128}$/.test(query)) {
    elements.dohAppList.innerHTML = '<p class="empty-state">搜索内容只能包含包名、UID、点、下划线或连字符</p>';
    return;
  }
  dohAppsLoading = true;
  if (reset) {
    dohAppsCursor = '0';
    dohAppsHasMore = false;
    dohAppsLoaded = false;
    elements.dohAppList.hidden = false;
    elements.dohAppList.innerHTML = '<p class="empty-state">正在读取应用列表…</p>';
  }
  syncDohControls();
  try {
    const data = await execApi('doh-apps', [
      query ? encodeBase64Utf8(query) : '',
      reset ? '0' : dohAppsCursor,
      '50',
    ]);
    if (selectedDohMode() !== 'selected' || disposed || !appsPanelActive) return;
    const apps = Array.isArray(data?.apps) ? data.apps : [];
    dohAppsCursor = data?.nextCursor === null || data?.nextCursor === undefined
      ? dohAppsCursor
      : String(data.nextCursor);
    dohAppsHasMore = Boolean(data?.hasMore);
    dohAppsLoaded = true;
    renderDohApps(apps, { reset });
    elements.dohLoadMoreApps.hidden = !dohAppsHasMore;
  } catch (error) {
    if (!isAbort(error)) {
      elements.dohAppList.innerHTML = `<p class="empty-state">读取应用列表失败：${escapeText(error?.message || '未知错误')}</p>`;
    }
  } finally {
    dohAppsLoading = false;
    syncDohControls();
  }
}

function validateDohEndpoint(value) {
  const endpoint = String(value ?? '');
  const httpsScheme = 'https:' + '//';
  if (!endpoint) return { error: '请输入 DoH URL' };
  if (!endpoint.startsWith(httpsScheme) || /[\u0000-\u0020\u007f#]/.test(endpoint)) {
    return { error: 'DoH URL 必须是 HTTPS，且不能包含空白或片段' };
  }
  try {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) {
      return { error: 'DoH URL 必须是有效 HTTPS 地址' };
    }
  } catch {
    return { error: 'DoH URL 格式无效' };
  }
  return { value: endpoint };
}

function validateDohUidNumber(uid) {
  const appId = uid % 100000;
  return Number.isSafeInteger(uid)
    && uid <= 4_294_967_294
    && uid !== 65534
    && appId >= 10000
    && appId <= 19999;
}

function canonicalDohAdvancedUids(value) {
  const rows = String(value ?? '').split(/\r?\n/).filter((row) => row.length > 0);
  const values = [];
  for (const row of rows) {
    if (row !== row.trim() || !/^[0-9]+$/.test(row) || (row.length > 1 && row.startsWith('0'))) {
      return { error: 'UID 必须为严格十进制数字，每行一个且不能带空格' };
    }
    const uid = Number(row);
    if (!validateDohUidNumber(uid)) {
      return { error: 'UID 必须是 Android 应用 UID，且不能是受保护、管理器或伴随进程 UID' };
    }
    values.push(uid);
  }
  return { values };
}

function selectedDohUids() {
  const checked = [...elements.dohAppList.querySelectorAll('input[type="checkbox"]:checked')]
    .map((input) => Number(input.value))
    .filter(validateDohUidNumber);
  const advanced = canonicalDohAdvancedUids(elements.dohUids.value);
  if (advanced.error) return advanced;
  const values = [...new Set([...checked, ...advanced.values])].sort((left, right) => left - right);
  if (values.length > 256) return { error: '最多选择 256 个 UID' };
  return { values };
}

function dohConfigText(mode) {
  if (mode === 'global') return { text: 'ack=doh-v1' };
  const uids = selectedDohUids();
  if (uids.error) return uids;
  if (uids.values.length === 0) return { error: '所选应用模式至少选择一个应用 UID' };
  return { text: ['ack=doh-v1', ...uids.values.map((uid) => `uid=${uid}`)].join('\n') };
}

async function testDohEndpoint() {
  if (!managementUnlocked || currentStatus?.busy || dohLoading) return;
  const endpoint = validateDohEndpoint(elements.dohEndpoint.value);
  if (endpoint.error) {
    elements.dohTestResult.textContent = endpoint.error;
    showNotice(endpoint.error, { persistent: true, tone: 'danger' });
    return;
  }
  // 检测会真的下发一次后台操作（首次还要下载伴随组件），必须等它跑完并以它的
  // 结论为准；交给 runMutation 复用统一的进度条与轮询，结果在 test-doh 分支落地。
  elements.dohTestResult.textContent = '正在检测…';
  const outcome = await runMutation('test-doh', [encodeBase64Utf8(endpoint.value)]);
  if (elements.dohTestResult.textContent === '正在检测…') {
    // 没走到 runMutation 的结果分支（后台忙、页面隐藏或已中止），别把占位文案留在界面上。
    elements.dohTestResult.textContent = outcome?.errorCode ? '检测未开始，后台有其他操作正在执行' : '';
  }
}

function openDohConfirmation() {
  const mode = selectedDohMode();
  if (mode === 'off') {
    if (dohVerifiedActive() || (dohStatus?.desiredMode && dohStatus.desiredMode !== 'off')) {
      disableDoh();
      return;
    }
    showNotice('请输入 DoH URL', { persistent: true, tone: 'danger' });
    return;
  }
  if (!['global', 'selected'].includes(mode)) {
    showNotice('请输入 DoH URL', { persistent: true, tone: 'danger' });
    return;
  }
  if (mode === 'selected' && !selectedDohSupported()) {
    showNotice('当前设备不支持所选应用模式', { persistent: true, tone: 'danger' });
    return;
  }
  const endpoint = validateDohEndpoint(elements.dohEndpoint.value);
  if (endpoint.error) {
    showNotice(endpoint.error, { persistent: true, tone: 'danger' });
    return;
  }
  const config = dohConfigText(mode);
  if (config.error) {
    showNotice(config.error, { persistent: true, tone: 'danger' });
    return;
  }
  pendingDohConfig = { mode, endpoint: endpoint.value, config: config.text };
  if (!elements.dohConfirmDialog.open) elements.dohConfirmDialog.showModal();
}

async function confirmDohEnable() {
  const config = pendingDohConfig;
  pendingDohConfig = null;
  closeDialog(elements.dohConfirmDialog);
  if (!config) return;
  await runMutation('set-doh', [
    config.mode,
    encodeBase64Utf8(config.endpoint),
    encodeBase64Utf8(config.config),
  ]);
  // 已提交，之后的回填就是这个地址本身，可以重新接受回填。
  dohEndpointDirty = false;
  dohLoaded = false;
  await loadDohStatus({ force: true });
}

async function disableDoh() {
  if (!managementUnlocked || currentStatus?.busy) return;
  await runMutation('disable-doh');
  // 地址保留在后端，loadDohStatus 会回填，这里不再清空输入框。
  dohEndpointDirty = false;
  elements.dohUids.value = '';
  dohLoaded = false;
  await loadDohStatus({ force: true });
}

// 后台忙时只允许一个轮询者，多个调用方共享同一个 promise，避免重复读状态。
function watchBackendUntilIdle() {
  if (!backendWatch) {
    backendWatch = (async () => {
      try {
        // 每轮都是一次 status，也就是在手机上重新拉起一个 shell。这里跟的是别人发起的
        // 后台任务（安装后首刷、只读态下另一处的操作），时长完全不由本页控制，固定
        // 650ms 会让开销随任务时长一直线性长上去。用和 pollOperation 同一条退让曲线：
        // 头几轮照旧密，进度条该跳还是跳；真拖长了就自己降到两秒一次。
        for (let attempt = 0; !disposed && currentStatus?.busy; attempt += 1) {
          await sleep(pollBackoffMs(attempt));
          const status = await execApi('status');
          renderStatus(status);
        }
      } finally {
        backendWatch = null;
      }
    })();
  }
  return backendWatch;
}

async function reconcileUnknown() {
  showNotice('结果未知，正在核对模块状态', { persistent: true, tone: 'warning' });
  // 这个循环没有次数上限，只要后台一直报忙就一直读下去。固定 650ms 时，后台真卡住
  // 就是每秒一个半 shell 一直烧到用户关掉页面——本文件里最费电的一处。同样退让到
  // 两秒一次；核对的是「有没有变空闲」，晚一秒知道不影响任何结论。
  for (let attempt = 0; !disposed; attempt += 1) {
    const status = await execApi('status');
    renderStatus(status);
    if (!status.busy) {
      showNotice('结果未知，请核对当前配置', { persistent: true, tone: 'warning' });
      return;
    }
    await sleep(pollBackoffMs(attempt));
  }
}

function canonicalUidList(value) {
  const values = String(value ?? '')
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
  if (values.some((item) => !/^[0-9]{1,10}$/.test(item))) {
    return { error: 'UID 必须为每行一个正整数' };
  }
  const numbers = [...new Set(values.map(Number))].sort((left, right) => left - right);
  if (numbers.some((item) => !Number.isSafeInteger(item) || item < 10_000 || item > 4_294_967_294)) {
    return { error: '仅允许普通应用 UID（10000 及以上）' };
  }
  if (numbers.length > 256) return { error: '最多选择 256 个 UID' };
  return { values: numbers, text: numbers.join('\n') };
}

async function loadAppPolicy({ force = false } = {}) {
  if (appPolicyLoading || (appPolicyLoaded && !force)) return;
  appPolicyLoading = true;
  elements.appPolicyStatus.textContent = '正在读取设备能力…';
  elements.appPolicyDetail.textContent = '不会启动 VPN、代理或常驻网络进程。';
  elements.appPolicyControls.hidden = true;
  try {
    const [capability, policy] = await Promise.all([
      execApi('app-capability'),
      execApi('app-policy'),
    ]);
    const supported = capability?.supported === true || capability?.available === true
      || capability?.capability === 'supported';
    if (!supported) {
      elements.appPolicyStatus.textContent = '当前设备不支持静态应用策略';
      elements.appPolicyDetail.textContent = appPolicyReasonMessage(capability?.reason);
      appPolicyLoaded = true;
      return;
    }
    const families = Array.isArray(capability?.families) ? capability.families.join(' / ') : 'IPv4';
    setText(elements.appPolicyStatus, policy?.enabled ? '应用联网策略已启用' : '应用联网策略');
    setText(elements.appPolicyDetail, `支持 ${families}；共享 UID、VPN/TUN、应用自带 DoH 可能影响策略效果。`);
    setValue(elements.appPolicyMode, policy?.enabled ? (policy?.mode || 'block_selected') : 'off');
    // 保存后会重读一次，返回的和框里现有的通常一字不差；这两个框同样能装很多行。
    setValue(elements.appPolicyUids, Array.isArray(policy?.uids) ? policy.uids.join('\n') : '');
    setValue(elements.appPolicyIps, Array.isArray(policy?.allowIps) ? policy.allowIps.join('\n') : '');
    setFlag(elements.appPolicyControls, 'hidden', false);
    appPolicyLoaded = true;
  } catch (error) {
    elements.appPolicyStatus.textContent = '应用策略状态不可用';
    elements.appPolicyDetail.textContent = error?.message || '能力读取失败；未修改任何防火墙规则。';
  } finally {
    appPolicyLoading = false;
    setWritesDisabled(Boolean(currentStatus?.busy));
  }
}

async function saveAppPolicy() {
  if (!managementUnlocked || currentStatus?.busy || appPolicyLoading) return;
  const mode = elements.appPolicyMode.value;
  if (!['off', 'block_selected', 'allow_resolved'].includes(mode)) return;
  const uids = canonicalUidList(elements.appPolicyUids.value);
  if (uids.error) {
    showNotice(uids.error, { persistent: true, tone: 'danger' });
    return;
  }
  if (mode !== 'off' && uids.values.length === 0) {
    showNotice('启用应用策略前至少填写一个应用 UID', { persistent: true, tone: 'danger' });
    return;
  }
  const ips = String(elements.appPolicyIps.value ?? '')
    .split(/\r?\n/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (ips.some((item) => !ipv4Valid(item) && !ipv6Valid(item))) {
    showNotice('允许地址快照中包含无效 IP', { persistent: true, tone: 'danger' });
    return;
  }
  const ipText = [...new Set(ips)].sort().join('\n');
  if (mode === 'allow_resolved' && !ipText) {
    showNotice('仅允许解析地址模式必须至少填写一个 IP', { persistent: true, tone: 'danger' });
    return;
  }
  await runMutation('set-app-policy', [
    mode,
    encodeBase64Utf8(uids.text),
    ipText ? encodeBase64Utf8(ipText) : '',
  ]);
  appPolicyLoaded = false;
  await loadAppPolicy({ force: true });
}

async function runMutation(verb, args = []) {
  if (!initialized || !managementUnlocked || currentStatus?.busy || disposed) return null;
  let mutationOutcome = null;
  const progressStartedAt = globalThis.performance.now();
  const preserveProgressFeedback = async () => {
    const remaining = 120 - (globalThis.performance.now() - progressStartedAt);
    if (remaining > 0) await sleep(remaining);
  };
  unknownSubmission = null;
  canonicalBeforeMutation = currentStatus;
  const optimistic = optimisticMutationStatus(verb, args);
  currentStatus = optimistic;
  const mutationLabel = verb === 'set-history'
    ? (args[0] === '1' ? '开启拦截日志' : '关闭拦截日志')
    : VERB_LABELS[verb] || '处理操作';
  showNotice(`正在${mutationLabel}，请稍候`, {
    persistent: true,
    progress: true,
    tone: 'progress',
  });
  elements.app.setAttribute('aria-busy', 'true');
  setWritesDisabled(true);

  try {
    await nextPaint();
    if (disposed) return;
    const result = await submitMutation(verb, args);
    if (result.state === 'result_unknown') {
      unknownSubmission = result;
      await preserveProgressFeedback();
      await reconcileUnknown();
      return;
    }
    const finalStatus = await pollOperation(
      result.operationId,
      (status) => renderStatus(status),
      lifecycle.signal,
    );
    renderStatus(finalStatus);
    await preserveProgressFeedback();
    if (verb === 'set-history') {
      if (finalStatus.result === 'failed' || finalStatus.result === 'critical') {
        let latestHistoryStatus = null;
        try {
          latestHistoryStatus = await loadHistoryStatus();
        } catch {
          latestHistoryStatus = null;
        }
        const reason = historyErrorMessage(
          latestHistoryStatus?.lastError || finalStatus.lastError,
          '模块未返回具体失败原因',
        );
        showNotice(`${mutationLabel}未成功：${reason}`, { persistent: true, tone: 'danger' });
      } else {
        showNotice(`${mutationLabel}完成`, { tone: 'success' });
        historyPulseSignature = null;
        historyLoaded = false;
        // 开启后后端还要装 NFLOG 规则并起读取进程，history-status 会滞后一两拍。
        // 先用探针等它收敛，再做唯一一次整包读取。以前是反过来的：先整包读一次，
        // 再每 400ms 整包重读，最多五次——那五次里前几次读到的必然是「刚起来、事件数 0」，
        // 每次却都要把两个事件文件过一遍 awk、把每个保留 token 的映射（最多 50 万行）
        // 重新 sha256、再把 packages.list 归一化一遍。开启按钮之所以点下去等很久，
        // 相当一部分就花在这些注定读不到东西的整包读取上。
        // 探针只 stat 两个事件文件 + 查一次运行状态，代价小得多。窗口是 4 × 800ms ≈ 3.2 秒，
        // 等不到就直接读，别把用户按在按钮上（见 HISTORY_SETTLE_ATTEMPTS）。
        if (args?.[0] === '1') {
          await settleHistoryAfterEnable();
        }
        // 收敛没等到也照样往下读：探针会继续在后台纠状态（见 scheduleHistoryPulse），
        // 没必要把用户按在「开启中」上等满整个窗口。
        historyLoaded = false;
        await loadHistory({ reset: true });
      }
    } else if (verb === 'test-doh') {
      // 检测只探测 URL，不改任何规则，所以只看这次操作自己的结论。
      if (finalStatus.result === 'failed' || finalStatus.result === 'critical') {
        const reason = dohErrorMessage(finalStatus.lastError, '该地址当前不可用');
        elements.dohTestResult.textContent = `检测未通过：${reason}`;
        showNotice(`${mutationLabel}未通过：${reason}`, { persistent: true, tone: 'danger' });
      } else {
        elements.dohTestResult.textContent = '检测通过';
        showNotice(`${mutationLabel}通过`, { tone: 'success' });
      }
    } else if (verb === 'clear-cache') {
      // 清理缓存不动规则，所以这里不看 sourcesOutOfSync，只看这次操作自己的结果。
      if (finalStatus.result === 'failed' || finalStatus.result === 'critical') {
        showNotice('清理缓存未完成', { persistent: true, tone: 'danger' });
      } else {
        showNotice('已清理停用来源的缓存', { tone: 'success' });
      }
    } else if (verb === 'clear-history') {
      if (finalStatus.result === 'failed' || finalStatus.result === 'critical') {
        showNotice('清空拦截日志未完成', { persistent: true, tone: 'danger' });
      } else {
        showNotice('拦截日志已清空', { tone: 'success' });
        historyLoaded = false;
        historyPage = 0;
        historyTotal = 0;
        await loadHistory({ reset: true });
      }
    } else {
      showMutationResult(verb, finalStatus);
    }
    if ((verb === 'set-lists' || verb === 'set-domain-decision')
      && finalStatus.result !== 'failed' && finalStatus.result !== 'critical') {
      listsLoaded = false;
      await loadLists({ force: true });
    }
    // 让调用方能区分“提交失败”和“提交成功但后台判失败”，拦截日志靠它决定回不回滚徽标。
    mutationOutcome = { errorCode: null, result: finalStatus.result ?? null };
  } catch (error) {
    if (isAbort(error)) return null;
    await preserveProgressFeedback();
    if (canonicalBeforeMutation) {
      renderedSourcesKey = '';
      renderStatus(canonicalBeforeMutation);
    }
    showNotice(error?.message || '操作未完成', { persistent: true, tone: 'danger' });
    // 让调用方能识别“后台已有操作”这种可以等待重试的失败。
    return { errorCode: error?.code ?? null, result: null };
  } finally {
    canonicalBeforeMutation = null;
  }
  return mutationOutcome;
}

function normalizeAppearance(value) {
  const background = value?.background;
  const revision = Number(background?.revision);
  return {
    surface: SURFACE_MODES.includes(value?.surface) ? value.surface : 'classic',
    scheme: SCHEME_MODES.includes(value?.scheme) ? value.scheme : 'system',
    glass: GLASS_LEVELS.includes(value?.glass) ? value.glass : 'soft',
    motion: MOTION_MODES.includes(value?.motion) ? value.motion : 'auto',
    background: {
      enabled: Boolean(background?.enabled),
      revision: Number.isInteger(revision) && revision >= 0 ? revision : 0,
    },
  };
}

function appearanceSummary(extra = '') {
  const parts = [SURFACE_LABELS[appearance.surface], SCHEME_LABELS[appearance.scheme]];
  if (appearance.surface === 'liquid') parts.push(GLASS_LABELS[appearance.glass]);
  if (BACKGROUND_FEATURE_READY && appearance.background.enabled) parts.push('自定义背景');
  parts.push(appearance.motion === 'off' ? '动画已关闭' : '动画已开启');
  const summary = `当前外观：${parts.join(' · ')}`;
  return extra ? `${summary}（${extra}）` : summary;
}

function setAppearanceNote(extra = '') {
  if (elements.appearanceNote) elements.appearanceNote.textContent = appearanceSummary(extra);
}

function setBackgroundNote(message) {
  if (elements.backgroundNote) elements.backgroundNote.textContent = message;
}

function backgroundImageValue() {
  if (!BACKGROUND_FEATURE_READY) return '';
  if (!appearance.background.enabled || appearance.background.revision <= 0) return '';
  return `url("${BACKGROUND_SOURCE}?v=${appearance.background.revision}")`;
}

function probeBackgroundImage(image) {
  const probe = new Image();
  probe.addEventListener('load', () => {
    if (disposed || backgroundImageValue() !== image) return;
    setBackgroundNote('背景图片已生效。');
  }, { once: true });
  probe.addEventListener('error', () => {
    if (disposed || backgroundImageValue() !== image) return;
    setBackgroundNote('图片已保存，但当前管理器无法读取它，界面会继续使用纯色背景。');
  }, { once: true });
  probe.src = image.slice(5, -2);
}

function applyBackgroundLayer() {
  const root = document.documentElement;
  const enabled = BACKGROUND_FEATURE_READY && appearance.background.enabled;
  const image = backgroundImageValue();
  const hasImage = image.length > 0;
  root.dataset.background = enabled ? 'on' : 'off';
  if (hasImage) root.style.setProperty('--custom-background', image);
  else root.style.removeProperty('--custom-background');
  if (elements.backgroundFields) elements.backgroundFields.hidden = !enabled;
  if (elements.backgroundEnabled) {
    elements.backgroundEnabled.checked = enabled;
    elements.backgroundEnabled.setAttribute('aria-expanded', String(enabled));
  }
  if (elements.backgroundPreview) elements.backgroundPreview.dataset.state = hasImage ? 'ready' : 'empty';
  if (elements.backgroundPreviewHint) {
    elements.backgroundPreviewHint.textContent = hasImage ? '' : '尚未选择背景图片';
  }
  if (elements.backgroundRemove) elements.backgroundRemove.hidden = !hasImage;
  if (hasImage) probeBackgroundImage(image);
}

function applyAppearance({ note = '' } = {}) {
  const root = document.documentElement;
  root.dataset.surface = appearance.surface;
  root.dataset.scheme = appearance.scheme;
  root.dataset.glass = appearance.glass;
  root.dataset.motion = appearance.motion;

  const liquid = appearance.surface === 'liquid';
  if (elements.surfaceMode) {
    elements.surfaceMode.querySelectorAll('input[name="surface-mode"]').forEach((input) => {
      input.checked = input.value === appearance.surface;
    });
  }
  if (elements.schemeMode) {
    elements.schemeMode.querySelectorAll('input[name="scheme-mode"]').forEach((input) => {
      input.checked = input.value === appearance.scheme;
    });
  }
  if (elements.glassStrength) {
    elements.glassStrength.disabled = !liquid;
    elements.glassStrength.querySelectorAll('input[name="glass-strength"]').forEach((input) => {
      input.checked = input.value === appearance.glass;
    });
  }
  if (elements.glassStrengthHint) {
    elements.glassStrengthHint.textContent = liquid
      ? '轻透最流畅；标准与浓郁的玻璃层更明显，也更耗电。'
      : '切换到液态主题后生效。';
  }
  if (elements.motionEnabled) elements.motionEnabled.checked = appearance.motion !== 'off';
  applyBackgroundLayer();
  setAppearanceNote(note);
}

async function persistAppearance() {
  if (appearanceSaving) {
    appearanceSavePending = true;
    return;
  }
  appearanceSaving = true;
  try {
    do {
      appearanceSavePending = false;
      const snapshot = { ...appearance };
      await execApi('set-ui-theme', [snapshot.surface, snapshot.scheme, snapshot.glass, snapshot.motion]);
      if (disposed) return;
    } while (appearanceSavePending);
    setAppearanceNote();
  } catch (error) {
    if (!isAbort(error) && !disposed) setAppearanceNote('本次会话已生效，但未能写入模块配置');
  } finally {
    appearanceSaving = false;
    appearanceSavePending = false;
  }
}

async function loadAppearance() {
  try {
    const data = await execApi('ui-theme');
    if (disposed) return;
    appearance = normalizeAppearance(data);
    applyAppearance();
  } catch (error) {
    if (isAbort(error) || disposed) return;
    appearance = normalizeAppearance(null);
    applyAppearance({ note: '未能读取模块中的外观偏好，本次使用默认外观' });
  }
}

function setupAppearance() {
  applyAppearance();
  if (elements.surfaceMode) {
    elements.surfaceMode.addEventListener('change', (event) => {
      const value = event.target?.value;
      if (!SURFACE_MODES.includes(value) || value === appearance.surface) return;
      appearance = { ...appearance, surface: value };
      applyAppearance();
      persistAppearance();
    });
  }
  if (elements.schemeMode) {
    elements.schemeMode.addEventListener('change', (event) => {
      const value = event.target?.value;
      if (!SCHEME_MODES.includes(value) || value === appearance.scheme) return;
      appearance = { ...appearance, scheme: value };
      applyAppearance();
      persistAppearance();
    });
  }
  if (elements.glassStrength) {
    elements.glassStrength.addEventListener('change', (event) => {
      const value = event.target?.value;
      if (!GLASS_LEVELS.includes(value) || value === appearance.glass) return;
      appearance = { ...appearance, glass: value };
      applyAppearance();
      persistAppearance();
    });
  }
  if (elements.motionEnabled) {
    elements.motionEnabled.addEventListener('change', () => {
      const motion = elements.motionEnabled.checked ? 'auto' : 'off';
      if (motion === appearance.motion) return;
      appearance = { ...appearance, motion };
      applyAppearance();
      persistAppearance();
    });
  }
  setupBackground();
}

function setBackgroundControlsBusy(busy) {
  backgroundBusy = busy;
  if (elements.backgroundPick) elements.backgroundPick.disabled = busy;
  if (elements.backgroundRemove) elements.backgroundRemove.disabled = busy;
  if (elements.backgroundEnabled) elements.backgroundEnabled.disabled = busy;
}

function setupBackground() {
  if (elements.backgroundEnabled) {
    elements.backgroundEnabled.addEventListener('change', () => {
      if (!BACKGROUND_FEATURE_READY) {
        elements.backgroundEnabled.checked = false;
        applyBackgroundLayer();
        showNotice('此功能正在开发中', { tone: 'warning' });
        return;
      }
      toggleBackground(elements.backgroundEnabled.checked);
    });
  }
  if (elements.backgroundPick) {
    elements.backgroundPick.addEventListener('click', () => openBackgroundPicker());
  }
  if (elements.backgroundRemove) {
    elements.backgroundRemove.addEventListener('click', () => clearBackgroundImage());
  }
  if (elements.backgroundPickerUp) {
    elements.backgroundPickerUp.addEventListener('click', () => {
      if (pickerParent) loadBackgroundGallery(pickerParent);
    });
  }
  if (elements.backgroundPickerList) {
    elements.backgroundPickerList.addEventListener('click', (event) => {
      const entry = event.target.closest('[data-picker-kind]');
      if (!entry || pickerLoading) return;
      const name = entry.dataset.pickerName || '';
      if (entry.dataset.pickerKind === 'dir') loadBackgroundGallery(`${pickerPath}/${name}`);
      else useBackgroundImage(`${pickerPath}/${name}`);
    });
  }
}

function renderBackgroundGallery(data) {
  const dirs = Array.isArray(data?.dirs) ? data.dirs : [];
  const files = Array.isArray(data?.files) ? data.files : [];
  const rows = [
    ...dirs.map((item) => `
      <button class="picker-entry picker-entry-dir" type="button" data-picker-kind="dir" data-picker-name="${escapeAttribute(item.name)}">
        ${iconMarkup('folder')}
        <span class="picker-entry-name">${escapeText(item.name)}</span>
        <span class="picker-entry-size">目录</span>
      </button>`),
    ...files.map((item) => `
      <button class="picker-entry picker-entry-file" type="button" data-picker-kind="file" data-picker-name="${escapeAttribute(item.name)}">
        ${iconMarkup('image')}
        <span class="picker-entry-name">${escapeText(item.name)}</span>
        <span class="picker-entry-size">${formatBytes(item.bytes)}</span>
      </button>`),
  ];
  elements.backgroundPickerList.innerHTML = rows.length > 0
    ? rows.join('')
    : '<p class="empty-state">这个目录里没有可用图片</p>';
  if (elements.backgroundPickerPath) elements.backgroundPickerPath.textContent = pickerPath;
  if (elements.backgroundPickerUp) elements.backgroundPickerUp.disabled = !pickerParent;
}

async function loadBackgroundGallery(path) {
  if (pickerLoading) return;
  pickerLoading = true;
  elements.backgroundPickerList.setAttribute('aria-busy', 'true');
  elements.backgroundPickerList.innerHTML = '<p class="empty-state">正在读取目录…</p>';
  try {
    const data = await execApi('background-list', [encodeBase64Utf8(path)]);
    if (disposed) return;
    pickerPath = typeof data?.path === 'string' ? data.path : path;
    pickerParent = typeof data?.parent === 'string' ? data.parent : null;
    renderBackgroundGallery(data);
  } catch (error) {
    if (isAbort(error) || disposed) return;
    elements.backgroundPickerList.innerHTML = `<p class="empty-state">${escapeText(error?.message || '无法读取这个目录')}</p>`;
  } finally {
    pickerLoading = false;
    elements.backgroundPickerList.setAttribute('aria-busy', 'false');
  }
}

function openBackgroundPicker() {
  if (backgroundBusy) return;
  if (!elements.backgroundPickerDialog.open) elements.backgroundPickerDialog.showModal();
  loadBackgroundGallery(pickerPath || BACKGROUND_GALLERY_ROOT);
}

async function toggleBackground(enabled) {
  if (backgroundBusy) return;
  const previous = appearance.background;
  appearance = { ...appearance, background: { ...previous, enabled } };
  applyAppearance();
  if (enabled && appearance.background.revision <= 0) {
    setBackgroundNote('选择一张设备里的图片后即可作为界面背景。');
  }
  setBackgroundControlsBusy(true);
  try {
    const data = await execApi('set-background-enabled', [enabled ? '1' : '0']);
    if (disposed) return;
    appearance = normalizeAppearance({ ...appearance, background: data });
    applyAppearance();
  } catch (error) {
    if (isAbort(error) || disposed) return;
    appearance = { ...appearance, background: previous };
    applyAppearance();
    setBackgroundNote('未能保存自定义背景开关，请稍后重试。');
  } finally {
    setBackgroundControlsBusy(false);
  }
}

function loadBackgroundImageElement(url) {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.addEventListener('load', () => resolve(image), { once: true });
    image.addEventListener('error', () => reject(new Error('无法解码这张图片')), { once: true });
    image.src = url;
  });
}

async function encodeBackgroundImage(url) {
  const image = await loadBackgroundImageElement(url);
  const sourceWidth = image.naturalWidth || 0;
  const sourceHeight = image.naturalHeight || 0;
  if (sourceWidth < 1 || sourceHeight < 1) throw new Error('无法解码这张图片');
  if (sourceWidth * sourceHeight > BACKGROUND_MAX_PIXELS) throw new Error('图片分辨率过高，请选择更小的图片');
  const scale = Math.min(1, BACKGROUND_MAX_EDGE / Math.max(sourceWidth, sourceHeight));
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(sourceWidth * scale));
  canvas.height = Math.max(1, Math.round(sourceHeight * scale));
  const context = canvas.getContext('2d');
  if (!context) throw new Error('无法处理这张图片');
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  for (const quality of BACKGROUND_QUALITIES) {
    const blob = await new Promise((resolve) => { canvas.toBlob(resolve, 'image/jpeg', quality); });
    if (!blob) break;
    if (blob.size <= BACKGROUND_MAX_BYTES) return blob;
  }
  return null;
}

async function useBackgroundImage(path) {
  if (backgroundBusy) return;
  closeDialog(elements.backgroundPickerDialog);
  setBackgroundControlsBusy(true);
  let notified = false;
  showNotice('正在处理背景图片', { persistent: true, progress: true });
  try {
    const staged = await execApi('background-stage', [encodeBase64Utf8(path)]);
    if (disposed) return;
    const blob = await encodeBackgroundImage(`./user/${staged.file}?t=${Date.now()}`);
    if (disposed) return;
    if (!blob) {
      showNotice('图片过大，请选择更小的图片', { tone: 'warning' });
      notified = true;
      setBackgroundNote('压缩后仍超过 256 KB，请换一张图片。');
      return;
    }
    const bytes = new Uint8Array(await blob.arrayBuffer());
    for (let offset = 0; offset < bytes.length; offset += BACKGROUND_CHUNK_BYTES) {
      const slot = offset === 0 ? 'first' : 'next';
      const chunk = bytes.subarray(offset, offset + BACKGROUND_CHUNK_BYTES);
      await execApi('set-background-put', [slot, encodeBase64Bytes(chunk)]);
      if (disposed) return;
    }
    const data = await execApi('set-background-commit');
    if (disposed) return;
    appearance = normalizeAppearance({ ...appearance, background: data });
    applyAppearance();
    showNotice('背景图片已保存', { tone: 'success' });
    notified = true;
  } catch (error) {
    if (isAbort(error) || disposed) return;
    showNotice(error?.message || '保存背景图片失败', { tone: 'danger' });
    notified = true;
    setBackgroundNote('保存失败，界面继续使用当前背景。');
  } finally {
    if (!notified && !disposed) clearNotice();
    setBackgroundControlsBusy(false);
    if (!disposed) execApi('background-unstage').catch(() => {});
  }
}

async function clearBackgroundImage() {
  if (backgroundBusy) return;
  setBackgroundControlsBusy(true);
  try {
    const data = await execApi('set-background-clear');
    if (disposed) return;
    appearance = normalizeAppearance({ ...appearance, background: data });
    applyAppearance();
    setBackgroundNote('已移除背景图片。');
  } catch (error) {
    if (isAbort(error) || disposed) return;
    setBackgroundNote('未能移除背景图片，请稍后重试。');
  } finally {
    setBackgroundControlsBusy(false);
  }
}

function gotoWorkspaceTarget(button) {
  const tabId = button.dataset.gotoTab;
  const targetId = button.dataset.gotoTarget;
  const tab = tabId ? document.querySelector(`#${tabId}`) : null;
  if (tab) selectTab(tab);
  if (!targetId) return;
  afterFirstPaint(() => {
    const target = document.querySelector(`#${targetId}`);
    if (!target) return;
    target.scrollIntoView({ block: 'start', behavior: 'auto' });
    const focusable = target.querySelector(
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])',
    );
    if (focusable) focusable.focus({ preventScroll: true });
  });
}

// 隐藏面板首次展开时要一次性完成整棵子树的样式解析、外部图标引用实例化和字体整形，
// 这笔开销原本全压在切页那一帧上。改为开机后在空闲片段里逐个面板离屏预热，
// 切页时只剩下已经缓存好的样式与布局。
function prewarmPanel(panel, width) {
  panel.style.width = `${width}px`;
  panel.dataset.prewarm = 'true';
  panel.hidden = false;
  void panel.offsetHeight;
  // 打上 data-warm，隐藏态就从 display:none 换成 content-visibility:hidden，
  // 刚算好的样式与布局会被缓存下来，下次切过去只需解锁而不是从零重建。
  panel.dataset.warm = 'true';
  panel.hidden = true;
  delete panel.dataset.prewarm;
  panel.style.width = '';
}

// 忙的时候把这一轮整个推后，而不是硬着头皮预热。推后不记账，也不占名额。
function deferPanelPrewarm() {
  if (disposed) return;
  prewarmDeferrals += 1;
  if (prewarmDeferrals > PANEL_PREWARM_MAX_DEFERRALS) return;
  schedule(schedulePanelPrewarm, PANEL_PREWARM_DEFER_MS);
}

function schedulePanelPrewarm() {
  if (disposed || prewarmIdleHandle !== null) return;
  const run = (deadline) => {
    prewarmIdleHandle = null;
    if (disposed) return;
    // requestIdleCallback 带 timeout 时会在超时那一刻硬插进来，哪怕主线程正忙。
    // 预热那一次强制布局要是落在用户点页签的同一帧里，就是他抱怨的切页卡顿，
    // 所以超时唤醒和刚切过页签这两种情况都先让路。
    if (deadline?.didTimeout === true || elapsedSince(lastTabSwitchAt) < PANEL_SWITCH_SETTLE_MS) {
      deferPanelPrewarm();
      return;
    }
    const pending = [...document.querySelectorAll('.tab-panel[hidden]')]
      .filter((item) => !warmedPanels.has(item.id));
    // 按体量从重到轻预热：整轮要一两秒才走完，这段窗口里用户随时可能点标签，
    // 谁最后热起来谁就最可能让用户自己付那笔首次布局。设置页最重，排第一。
    const panel = PANEL_PREWARM_ORDER.map((id) => pending.find((item) => item.id === id))
      .find(Boolean) ?? pending[0];
    if (!panel) return;
    const width = document.querySelector('.tab-panel:not([hidden])')?.getBoundingClientRect().width ?? 0;
    // 量不到宽度就别记账。记了又没真预热，面板会一直停在 display:none，
    // 首次切过去那笔整棵子树的布局最后还是原样压在用户那一帧上。
    if (width <= 0) {
      deferPanelPrewarm();
      return;
    }
    warmedPanels.add(panel.id);
    prewarmDeferrals = 0;
    prewarmPanel(panel, width);
    schedulePanelPrewarm();
  };
  // 优先用空闲帧，避免和开机首屏渲染抢主线程；不支持时退回定时器错峰。
  const idle = globalThis.requestIdleCallback;
  if (typeof idle === 'function') prewarmIdleHandle = idle.call(globalThis, run, { timeout: 1_500 });
  else schedule(run, PANEL_PREWARM_MS);
}

// 五个面板共用文档滚动，所以切页时手动代管滚动位置，让每页各自记住自己的位置。
function rememberTabScroll(tabId, offset) {
  if (!tabId) return;
  tabScrollOffsets.set(tabId, offset);
}

// scrollTo 必须先夹取滚动范围，所以会把此刻所有待结算的布局强制算完。放在面板
// 增删之后调用，等于每次切换都在点击回调里同步重排整篇文档——面板越高越贵。
//
// 拆成两段来躲开这笔开销：
//   · 目标位置是顶部（切换里的绝大多数）：在任何写入之前就滚，那时布局还是干净的，
//     scrollTo 无需结算任何东西；而且 0 永远落在合法范围内，不存在夹取问题。
//   · 目标位置非 0（切回一个你之前滚过的页）：只能等新面板显示后再滚，否则文档
//     高度还是旧面板的，目标位置会被夹回去。这种情况少，且宁可慢也不能滚错。
function restoreTabScrollBeforeSwap(tabId, currentOffset) {
  const target = tabScrollOffsets.get(tabId) ?? 0;
  if (target !== 0) return false;
  if (currentOffset !== 0) globalThis.scrollTo({ top: 0, left: 0, behavior: 'auto' });
  return true;
}

function restoreTabScrollAfterSwap(tabId, currentOffset) {
  const target = tabScrollOffsets.get(tabId) ?? 0;
  if (target === currentOffset) return;
  globalThis.scrollTo({ top: target, left: 0, behavior: 'auto' });
}

function selectTab(tab) {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const nextIndex = tabs.indexOf(tab);
  const previousIndex = tabs.findIndex((item) => item.getAttribute('aria-selected') === 'true');
  if (nextIndex < 0 || nextIndex === previousIndex) return;
  const direction = nextIndex > previousIndex ? 'forward' : 'backward';
  const previousTab = tabs[previousIndex];
  // 先读滚动位置，此刻还没有任何写入，这次读取不会触发强制布局。
  const currentOffset = globalThis.scrollY || 0;
  rememberTabScroll(previousTab?.id, currentOffset);
  // 趁布局还干净把「回到顶部」这一档滚完；剩下的少数情况留到面板换完再滚。
  const scrolled = restoreTabScrollBeforeSwap(tab.id, currentOffset);
  // 切换窗口要在昂贵的写入之前就打开，玻璃折射滤镜和光斑动画才不会陪着这一帧跑。
  markPanelSwitch();

  // 只改真正换了状态的一进一出：整排五个页签一起写，每次切换要白挨九次属性变更。
  if (previousTab) {
    previousTab.classList.remove('is-active');
    previousTab.setAttribute('aria-selected', 'false');
    previousTab.tabIndex = -1;
    const previousPanel = document.querySelector(`#${previousTab.getAttribute('aria-controls')}`);
    if (previousPanel) {
      // 刚看过的面板已经布好版了，标上 data-warm 让隐藏态保住这份渲染状态，
      // 下次切回来只需解锁。首屏的概览页不走预热，全靠这里兜住。
      previousPanel.dataset.warm = 'true';
      previousPanel.hidden = true;
      // 方向留在隐藏面板上会盖过预热时的 animation: none。
      delete previousPanel.dataset.motionDirection;
    }
  }
  tab.classList.add('is-active');
  tab.setAttribute('aria-selected', 'true');
  tab.tabIndex = 0;
  const panel = document.querySelector(`#${tab.getAttribute('aria-controls')}`);
  panel.dataset.motionDirection = direction;
  warmedPanels.add(panel.id);
  panel.hidden = false;
  // data-motion-direction 挂着 will-change: transform, opacity。样式表明确写了它
  // 只该在动画那两百多毫秒里存在，否则「每个面板长期占一层纹理，在 WebView 上
  // 反而更卡」——但原来它只在面板被隐藏时才删（见上面的 previousPanel 分支），
  // 当前可见的那一页会一直挂着，等于常驻一层和面板等高的合成纹理。面板越高纹理
  // 越大，所以规则页与日志页切走时最容易卡。动画收尾就摘掉。
  releaseMotionHint(panel);

  const tabBar = tab.closest('[role="tablist"]');
  tabBar.dataset.activeIndex = String(nextIndex);
  tabBar.style.setProperty('--active-tab-offset', `${nextIndex * 100}%`);
  if (!scrolled) restoreTabScrollAfterSwap(tab.id, currentOffset);

  historyPanelActive = tab.id === 'tab-logs';
  appsPanelActive = tab.id === 'tab-apps';
  if (!appsPanelActive) stopDohRefresh();
  if (!historyPanelActive) {
    historyPulseSignature = null;
    stopHistoryPulse();
  }
  if (historyPanelActive && !historyLoaded && !historyLoading) {
    afterPanelSettled(tab, () => loadHistory({ reset: true }));
  } else if (historyPanelActive) {
    // 列表已经加载过时不会再走 loadHistory，探针得在这里自己续上。
    afterPanelSettled(tab, () => scheduleHistoryPulse());
  }
  if (historyPanelActive && !runtimeLogModeLoaded) {
    afterPanelSettled(tab, () => loadRuntimeLogMode());
  }
  if (tab.id === 'tab-sources') {
    afterPanelSettled(tab, () => {
      ensureSourcePanelRendered();
      // 来源卡渲染与规则数据读取分帧。
      afterPanelPaint(tab, () => loadRulesBundle());
    });
  }
  if (tab.id === 'tab-apps') {
    afterPanelSettled(tab, () => {
      if (!dohLoaded && !dohLoading) loadDohStatus();
      else scheduleDohRefresh();
      if (!appPolicyLoaded && !appPolicyLoading) loadAppPolicy();
    });
  }
}

function setupTabs() {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const tabBar = tabs[0]?.closest('[role="tablist"]');
  if (tabBar) {
    tabBar.dataset.activeIndex = '0';
    tabBar.style.setProperty('--active-tab-offset', '0%');
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', (event) => {
      let targetIndex = index;
      if (event.key === 'ArrowRight') targetIndex = (index + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') targetIndex = (index - 1 + tabs.length) % tabs.length;
      else if (event.key === 'Home') targetIndex = 0;
      else if (event.key === 'End') targetIndex = tabs.length - 1;
      else return;
      event.preventDefault();
      selectTab(tabs[targetIndex]);
      tabs[targetIndex].focus();
    });
  });
}

function toggleCollapsible(toggle, { force } = {}) {
  const content = document.querySelector(`#${toggle.getAttribute('aria-controls')}`);
  if (!content) return;
  const expanded = typeof force === 'boolean'
    ? force
    : toggle.getAttribute('aria-expanded') !== 'true';
  const label = toggle.dataset.collapseLabel || '此区块';
  const action = expanded ? '收起' : '展开';
  content.hidden = !expanded;
  toggle.setAttribute('aria-expanded', String(expanded));
  toggle.setAttribute('aria-label', `${action}${label}`);
  toggle.title = `${action}${label}`;
}

function setupCollapsibles() {
  document.querySelectorAll('.section-toggle').forEach((toggle) => {
    toggle.addEventListener('click', () => toggleCollapsible(toggle));
  });
}

function closeDialog(dialog) {
  if (dialog.open) dialog.close();
}

function openSourceDialog(source = null) {
  elements.sourceForm.reset();
  elements.sourceNameError.textContent = '';
  elements.sourceUrlError.textContent = '';
  elements.sourceId.value = source?.id || '';
  elements.sourceName.value = source?.name || '';
  elements.sourceUrl.value = source?.url || '';
  elements.sourceDialogTitle.textContent = source ? '编辑自定义规则' : '添加自定义规则';
  elements.sourceDialog.showModal();
  elements.sourceName.focus();
}

function validateSourceForm() {
  const name = elements.sourceName.value.trim();
  const url = elements.sourceUrl.value.trim();
  let valid = true;
  elements.sourceNameError.textContent = '';
  elements.sourceUrlError.textContent = '';

  if ([...name].length < 1 || [...name].length > 80) {
    elements.sourceNameError.textContent = '名称需为 1 至 80 个字符';
    valid = false;
  }

  let parsedUrl = null;
  try {
    parsedUrl = new URL(url);
  } catch {
    valid = false;
  }
  const urlBytes = new TextEncoder().encode(url).length;
  if (!parsedUrl || parsedUrl.protocol !== 'https:' || !parsedUrl.hostname) {
    elements.sourceUrlError.textContent = '请输入有效的规则链接';
    valid = false;
  } else if (urlBytes > 2048 || /[\s\x00-\x1f\x7f`]/.test(url)) {
    elements.sourceUrlError.textContent = '链接包含空白、控制字符或长度超限';
    valid = false;
  }

  return valid ? { name, url } : null;
}

async function handleSourceCommand(event) {
  const control = event.target.closest('[data-action]');
  if (!control || control.disabled || currentStatus?.busy) return;
  const source = currentStatus?.sources?.find((item) => item.id === control.dataset.id);
  if (!source) return;

  if (control.dataset.action === 'toggle') {
    await runMutation('set-source', [source.id, source.enabled ? '0' : '1']);
  } else if (control.dataset.action === 'move') {
    await runMutation('move-source', [source.id, control.dataset.direction]);
  } else if (control.dataset.action === 'edit') {
    openSourceDialog(source);
  } else if (control.dataset.action === 'delete') {
    elements.deleteSourceId.value = source.id;
    elements.deleteSourceName.textContent = displaySourceName(source);
    elements.deleteDialog.showModal();
  } else if (control.dataset.action === 'refresh' && source.enabled) {
    await runMutation('refresh-source', [source.id]);
  }
}

async function loadRuntimeLogs({ reset = false } = {}) {
  if (runtimeLogsLoading || disposed) return;
  runtimeLogsLoading = true;
  elements.runtimeLogView.setAttribute('aria-busy', 'true');
  elements.reloadRuntimeLogsButton.disabled = true;
  elements.loadMoreRuntimeLogs.disabled = true;
  if (reset) {
    runtimeLogCursor = '0';
    runtimeLogsLoaded = false;
    runtimeLogHasContent = false;
    elements.runtimeLogOutput.textContent = '正在载入运行日志…';
  }

  try {
    const data = await execApi('runtime-logs', [runtimeLogCursor, '32768']);
    const text = typeof data?.text === 'string' ? data.text : '';
    if (runtimeLogsLoaded && !reset) {
      if (text) {
        elements.runtimeLogOutput.append(
          document.createTextNode(`${runtimeLogHasContent ? '\n' : ''}${text}`),
        );
        runtimeLogHasContent = true;
      }
    } else {
      elements.runtimeLogOutput.textContent = text || '当前没有运行日志';
      runtimeLogHasContent = Boolean(text);
    }
    runtimeLogsLoaded = true;
    const previousCursor = runtimeLogCursor;
    const nextCursor = data?.nextCursor === null || data?.nextCursor === undefined
      ? '0'
      : String(data.nextCursor);
    runtimeLogCursor = nextCursor;
    const hasMore = Boolean(text) && nextCursor !== previousCursor;
    elements.loadMoreRuntimeLogs.hidden = !hasMore;
    elements.reloadRuntimeLogsButton.querySelector('span').textContent = '重新载入运行日志';
  } catch (error) {
    if (!isAbort(error)) {
      elements.runtimeLogOutput.textContent = `读取运行日志失败：${error?.message || '未知错误'}`;
    }
  } finally {
    runtimeLogsLoading = false;
    elements.runtimeLogView.setAttribute('aria-busy', 'false');
    elements.reloadRuntimeLogsButton.disabled = false;
    elements.loadMoreRuntimeLogs.disabled = false;
  }
}

async function loadRuntimeLogMode() {
  if (runtimeLogModeLoaded || disposed) return;
  try {
    const data = await execApi('runtime-log-mode');
    elements.runtimeLogEnabled.checked = data?.enabled === true;
    elements.runtimeLogEnabled.disabled = false;
    elements.clearRuntimeLogsButton.disabled = false;
    // 导出是只读动作，不受管理解锁的写保护约束。
    elements.exportRuntimeLogsButton.disabled = false;
    runtimeLogModeLoaded = true;
  } catch (error) {
    if (!isAbort(error)) {
      showNotice(`读取运行日志开关失败：${error?.message || '未知错误'}`, { tone: 'danger' });
    }
  }
}

async function setRuntimeLogMode(enabled) {
  if (disposed) return;
  elements.runtimeLogEnabled.disabled = true;
  try {
    const data = await execApi('set-runtime-log-mode', [enabled ? '1' : '0']);
    elements.runtimeLogEnabled.checked = data?.enabled === true;
    showNotice(enabled ? '运行日志已记录全过程' : '运行日志仅记录失败', { tone: 'success' });
  } catch (error) {
    if (!isAbort(error)) {
      elements.runtimeLogEnabled.checked = !enabled;
      showNotice(`切换运行日志失败：${error?.message || '未知错误'}`, { tone: 'danger' });
    }
  } finally {
    elements.runtimeLogEnabled.disabled = false;
  }
}

// WebView 里由页面自己发起的下载不可靠，所以导出走后端：目的地由 shell 自己挑，
// 前端一个参数都不传，然后把落盘路径显示出来。
async function exportRuntimeLogs() {
  if (disposed) return;
  elements.exportRuntimeLogsButton.disabled = true;
  try {
    const data = await execApi('export-runtime-logs');
    const path = typeof data?.path === 'string' ? data.path : '';
    if (path) {
      const size = Number.isFinite(Number(data?.bytes)) ? Number(data.bytes) : null;
      elements.runtimeLogExportNote.textContent = size === null
        ? `已导出到 ${path}`
        : `已导出到 ${path}（${formatBytes(size)}）`;
      elements.runtimeLogExportNote.hidden = false;
      showNotice('运行日志已导出', { tone: 'success' });
    } else {
      showNotice('运行日志导出未返回路径', { tone: 'warning' });
    }
  } catch (error) {
    if (!isAbort(error)) {
      elements.runtimeLogExportNote.hidden = true;
      showNotice(`导出运行日志失败：${error?.message || '未知错误'}`, { tone: 'danger' });
    }
  } finally {
    elements.exportRuntimeLogsButton.disabled = false;
  }
}

async function clearRuntimeLogs() {
  if (disposed) return;
  elements.clearRuntimeLogsButton.disabled = true;
  try {
    await execApi('clear-runtime-logs');
    runtimeLogCursor = '0';
    runtimeLogsLoaded = false;
    runtimeLogHasContent = false;
    elements.runtimeLogOutput.textContent = '当前没有运行日志';
    elements.loadMoreRuntimeLogs.hidden = true;
    showNotice('运行日志已清空', { tone: 'success' });
  } catch (error) {
    if (!isAbort(error)) {
      showNotice(`清空运行日志失败：${error?.message || '未知错误'}`, { tone: 'danger' });
    }
  } finally {
    elements.clearRuntimeLogsButton.disabled = false;
  }
}

function historyStatusLabel(status) {
  if (currentStatus?.activeMode === 'paused') return { title: '保护已暂停', chip: '暂停期间不记录', tone: 'warning' };
  if (status?.availability === 'unsupported') return { title: '当前内核不支持拦截日志', chip: '不可用', tone: 'danger' };
  if (!status?.enabled) return { title: '拦截日志未启用', chip: '默认关闭', tone: 'neutral' };
  if (status.logging) return { title: '正在记录拦截日志', chip: '记录中', tone: 'success' };
  return { title: '拦截保护仍在运行', chip: '记录器未连接', tone: 'warning' };
}

function syncHistoryControls() {
  const unavailable = !initialized || !managementUnlocked || historyLoading || !historyStatus || Boolean(currentStatus?.busy)
    || currentStatus?.activeMode === 'paused' || historyStatus?.availability === 'unsupported';
  const actionsDisabled = !initialized || !managementUnlocked || !historyStatus || Boolean(currentStatus?.busy)
    || currentStatus?.activeMode === 'paused' || historyStatus?.availability === 'unsupported';
  const enabled = Boolean(historyStatus?.enabled);
  if (elements.historyEnabled) {
    // checked 是 checkedness，不是反射属性，写回同样的值不产生改动，照常赋值。
    elements.historyEnabled.checked = enabled;
    setFlag(elements.historyEnabled, 'disabled', unavailable);
  }
  [
    elements.historyAppFilter,
    elements.historyDomainFilter,
    elements.historyPortFilter,
    elements.historyTimeFilter,
    elements.clearHistoryButton,
  ].forEach((control) => {
    setFlag(control, 'disabled', unavailable || !enabled);
  });
  elements.historyList?.toggleAttribute('inert', historyLoading);
  if (historyActionsDisabled !== actionsDisabled) {
    historyActionsDisabled = actionsDisabled;
    elements.historyList?.querySelectorAll('[data-history-decision]').forEach((control) => {
      control.disabled = actionsDisabled;
    });
  }
  renderHistoryPager();
}

function renderHistoryStatus(status = {}) {
  historyStatus = status;
  const presentation = historyStatusLabel(status);
  setText(elements.historyStatusTitle, presentation.title);
  setText(elements.historyStateChip, presentation.chip);
  setData(elements.historyStatusRail, 'tone', presentation.tone);
  const enabled = Boolean(status.enabled);
  setAttr(elements.historyEnabled, 'aria-expanded', String(enabled));
  setFlag(elements.historyDetails, 'hidden', !enabled);
  setText(elements.historyStatusDetail, currentStatus?.activeMode === 'paused'
    ? '暂停期间不会写入或修改拦截日志；恢复保护后继续使用原有偏好。'
    : status.availability === 'unsupported'
    ? '当前设备未提供 NFLOG 能力，普通 hosts 规则仍然正常工作。'
    : status.logging
      ? '仅记录被拒绝的 TCP 连接起始请求；放行的连接抓不到。记录只保留最近 3 小时，更早的会自动删除。关闭后不再产生新的历史。'
      : '开启后仅记录被拒绝的 TCP 连接起始请求，会增加少量耗电；放行的连接抓不到。记录只保留最近 3 小时，更早的会自动删除。');
  // 能力状态和报错先在字符串里拼完再写一次。原来是先写主体、再用 += 追加，那是两次
  // DOM 改动，中间还夹一次 textContent 读取。
  let capability = status.availability === 'unsupported'
    ? '能力状态：不可用'
    : status.availability === 'available' ? '能力状态：可用' : '能力状态：待检测';
  if (status.lastError) {
    const errorDetail = historyErrorMessage(status.lastError);
    if (errorDetail !== presentation.title) capability += ` · ${errorDetail}`;
  }
  setText(elements.historyCapability, capability);
  setText(elements.historyCountSummary,
    `${formatCount(status.interceptionCount ?? 0)} 次连接 · ${formatCount(status.eventRowCount ?? 0)} 条事件`);
  syncHistoryControls();
  refreshIcons(elements.historyStatusRail);
  // 开启即实时：只看 enabled。以前这里要求 logging 也为真才挂探针，把
  // scheduleHistoryPulse 内部刚放宽的判断又在调用方这一层堵回去了——logging 要靠
  // shell 去问 iptables 和读取进程状态，任一次问失败就是 false，于是探针不挂、
  // 签名基线还被清成 null，再没有任何东西会去重读一次，列表就永远停在开启那一刻的
  // 空状态；用户只能靠改筛选条件（走的是不刷新状态的那条读取路径）才看得到记录。
  // 那正是「开启后默认不显示、选了时间才显示」的直接来源。
  // 现在开着就挂探针，logging 为假时由 scheduleHistoryPulse 自己换成更长的间隔，
  // 让探针把状态纠回来；只有真的关掉了才清基线、收探针。
  if (enabled) scheduleHistoryPulse();
  else {
    historyPulseSignature = null;
    stopHistoryPulse();
  }
}

// 应用清单是从已拦截的数据里汇总出来的，绝大多数刷新拿回的是和上一次一模一样的一份。
// 名单没变就别重建 <select>：这里最多挂 1000 个 <option>，每次都拆光重插等于在
// 用户可能正在拖动列表的那一帧里做上千次 DOM 写入。
function historyAppsFingerprint(apps) {
  return apps.map((app) => `${app.uid}:${(Array.isArray(app.packages) ? app.packages : []).join(',')}`).join('|');
}

function renderHistoryApps(apps = []) {
  const normalizedApps = Array.isArray(apps) ? apps : [];
  const fingerprint = historyAppsFingerprint(normalizedApps);
  if (fingerprint === historyAppsFingerprintCache && elements.historyAppFilter.options.length > 0) {
    historyApps = normalizedApps;
    return false;
  }
  historyAppsFingerprintCache = fingerprint;
  historyApps = normalizedApps;
  const current = elements.historyAppFilter.value;
  const fragment = document.createDocumentFragment();
  fragment.append(new Option('全部应用', '-'));
  historyApps.forEach((app) => {
    const packages = Array.isArray(app.packages) ? app.packages : [];
    const label = packages[0] || `UID ${app.uid}`;
    const suffix = packages.length > 1 ? ` +${packages.length - 1}` : '';
    fragment.append(new Option(`${label}${suffix}`, String(app.uid)));
  });
  // 一次性换掉：逐个 append 到活的 <select> 上会让每次插入都动一遍它的选项索引。
  elements.historyAppFilter.replaceChildren(fragment);
  const selected = [...elements.historyAppFilter.options].some((option) => option.value === current)
    ? current
    : '-';
  elements.historyAppFilter.value = selected;
  return selected !== current;
}

function historyQueryArgs(page = historyPage) {
  const seconds = Number(elements.historyTimeFilter.value || 0);
  const since = seconds > 0 ? Math.max(0, Math.floor(Date.now() / 1000) - seconds) : 0;
  const domain = elements.historyDomainFilter.value.trim().toLowerCase();
  return [
    // 后端的游标就是聚合排序后的行偏移，页码乘以页长即可，不必自己记游标。
    String(Math.max(0, page) * HISTORY_PAGE_SIZE),
    String(HISTORY_PAGE_SIZE),
    String(since),
    elements.historyAppFilter.value || '-',
    elements.historyPortFilter.value || '-',
    domain ? encodeBase64Utf8(domain) : '-',
  ];
}

function historyAllowSet() {
  const value = elements.manualAllowlist.value;
  if (value === historyAllowCacheText) return historyAllowCacheSet;
  historyAllowCacheText = value;
  // 走同一份按框缓存的结果：拦截日志渲染时白名单往往刚刚被校验过，不必再算一遍。
  const allow = canonicalFor(elements.manualAllowlist, canonicalList);
  historyAllowCacheSet = allow.error || !allow.text
    ? new Set()
    : new Set(allow.text.trimEnd().split('\n'));
  return historyAllowCacheSet;
}

function historyDecisionForDomain(domain, allowSet) {
  const normalized = String(domain || '').toLowerCase();
  return allowSet.has(normalized) ? 'allow' : 'block';
}

// 徽标说的是这个域名当前的名单状态，不是这一条记录的结果：历史里只可能有被拦下来的连接。
// 首次渲染和后来的就地改写都从这里取文案，免得两处各写一份、改一处忘一处。
function historyDecisionPresentation(decision) {
  if (decision === 'allow') {
    return { label: '已放行', hint: '已在白名单：后续连接放行，不会再写进拦截日志' };
  }
  if (decision === 'block') {
    return { label: '已拦截', hint: '不在白名单：按当前规则继续拦截' };
  }
  return { label: '未设置', hint: '尚未加入任何名单' };
}

// 加入名单只改这个域名的“当前名单状态”，历史记录本身一条都没变，
// 所以不用重查后端再整段重建，直接把同域名的行就地改掉。
function patchHistoryRowDecision(domain, decision) {
  const normalized = String(domain || '').toLowerCase();
  if (!normalized || !elements.historyList) return;
  const { label, hint } = historyDecisionPresentation(decision);
  // 用 dataset 比对而不是拼 attribute selector：域名里的字符不用再考虑选择器转义。
  elements.historyList.querySelectorAll('.history-row').forEach((row) => {
    if (row.dataset.domain !== normalized) return;
    row.dataset.decision = decision;
    const badge = row.querySelector('.history-decision');
    if (!badge) return;
    badge.className = `history-decision history-decision-${decision}`;
    badge.title = hint;
    badge.textContent = label;
  });
}

function historyItemMarkup(item, allowSet) {
  const packages = Array.isArray(item.packages) ? item.packages : [];
  const app = packages[0] || `UID ${item.uid}`;
  const packageSuffix = packages.length > 1 ? ` +${packages.length - 1}` : '';
  const domain = String(item.domain || '').toLowerCase();
  const decision = item.decision === 'allow' || item.decision === 'block'
    ? item.decision
    : historyDecisionForDomain(domain, allowSet);
  const { label: decisionLabel, hint: decisionHint } = historyDecisionPresentation(decision);
  const warning = Number(item.dropped || item.degraded) > 0
    ? `<span class="history-event-warning">${item.dropped ? `丢弃 ${formatCount(item.dropped)}` : ''}${item.dropped && item.degraded ? ' · ' : ''}${item.degraded ? `降级 ${formatCount(item.degraded)}` : ''}</span>`
    : '';
  return `
    <article class="history-row" data-domain="${escapeAttribute(domain)}" data-decision="${decision}">
      <div class="history-row-main">
        <strong>${escapeText(item.domain || '未知域名')}</strong>
        <span>${escapeText(app)}${escapeText(packageSuffix)} · ${escapeText(item.protocol || 'tcp').toUpperCase()} ${formatCount(item.port)}</span>
      </div>
      <div class="history-row-meta">
        <time datetime="${escapeAttribute(new Date(Number(item.epoch) * 1000).toISOString())}">${escapeText(formatTime(Number(item.epoch)))}</time>
        <b>${formatCount(item.count)} 次</b>
        <span class="history-decision history-decision-${decision}" title="${escapeAttribute(decisionHint)}">${decisionLabel}</span>
        ${warning}
      </div>
      <div class="history-row-actions" role="group" aria-label="${escapeAttribute(domain)} 名单操作">
        <button class="icon-button history-action-allow" type="button" data-history-decision="allow" aria-label="放行 ${escapeAttribute(domain)}" title="加入白名单">${iconMarkup('circle-check')}</button>
        <button class="icon-button history-action-block" type="button" data-history-decision="block" aria-label="拦截 ${escapeAttribute(domain)}" title="加入黑名单">${iconMarkup('ban')}</button>
      </div>
    </article>
  `;
}

function appendHistoryChunk(items, allowSet, { animate = false } = {}) {
  if (items.length === 0) return;
  const markup = items.map((item) => historyItemMarkup(item, allowSet)).join('');
  const fragment = document.createRange().createContextualFragment(markup);
  const insertedRows = fragment.querySelectorAll('.history-row');
  fragment.querySelectorAll('[data-history-decision]').forEach((control) => {
    control.disabled = Boolean(historyActionsDisabled);
  });
  elements.historyList.append(fragment);
  if (animate) animateInsertedItems(insertedRows);
}

function renderHistoryItems(items, { reset = false } = {}) {
  const normalized = Array.isArray(items) ? items : [];
  const token = ++historyRenderToken;
  if (reset) elements.historyList.replaceChildren();
  if (normalized.length > 0) {
    const allowSet = historyAllowSet();
    // 首屏一批同步插入，其余按帧分批，避免一次插入上百行把主线程堵死。
    appendHistoryChunk(normalized.slice(0, HISTORY_RENDER_CHUNK), allowSet, { animate: true });
    const pump = (offset) => {
      globalThis.requestAnimationFrame(() => {
        if (disposed || token !== historyRenderToken) return;
        appendHistoryChunk(normalized.slice(offset, offset + HISTORY_RENDER_CHUNK), allowSet);
        const next = offset + HISTORY_RENDER_CHUNK;
        if (next < normalized.length) pump(next);
      });
    };
    if (normalized.length > HISTORY_RENDER_CHUNK) pump(HISTORY_RENDER_CHUNK);
  }
  const hasRows = elements.historyList.querySelector('.history-row');
  if (!hasRows) {
    elements.historyList.innerHTML = '<p class="empty-state">当前没有拦截记录</p>';
  }
  renderHistoryPager();
}

function historyPageCount() {
  return Math.max(1, Math.ceil(historyTotal / HISTORY_PAGE_SIZE));
}

// 翻页条。只有超过一页才显示——记录不多时多一条空按钮栏纯属噪音。
function renderHistoryPager() {
  if (!elements.historyPager) return;
  const pages = historyPageCount();
  const multi = historyTotal > HISTORY_PAGE_SIZE;
  setFlag(elements.historyPager, 'hidden', !multi || !historyStatus?.enabled);
  setText(elements.historyPageStatus,
    `第 ${historyPage + 1} / ${pages} 页 · 共 ${formatCount(historyTotal)} 条`);
  setFlag(elements.historyPrevPage, 'disabled', historyLoading || historyPage <= 0);
  setFlag(elements.historyNextPage, 'disabled', historyLoading || historyPage + 1 >= pages);
}

// 翻到某一页。页码越界（比如过期删除后总数变少）就夹回有效范围。
function goToHistoryPage(page) {
  if (historyLoading) return;
  const target = Math.min(Math.max(0, page), historyPageCount() - 1);
  if (target === historyPage) return;
  loadHistory({ page: target, refreshMetadata: false });
}

// 开启后用探针等后端把 NFLOG 规则装好、读取进程起来。只 stat + 查运行状态，
// 不做整包读取，所以可以等得久一点。等到了（或等超了）都返回，由调用方去做那一次读取。
async function settleHistoryAfterEnable() {
  for (let attempt = 0; attempt < HISTORY_SETTLE_ATTEMPTS; attempt += 1) {
    if (disposed || !historyPanelActive) return;
    await sleep(HISTORY_SETTLE_INTERVAL_MS);
    if (disposed || !historyPanelActive) return;
    let pulse = null;
    try {
      pulse = await execApi('history-pulse');
    } catch {
      // 探针失败不必打扰用户：真正的错误会在随后那次整包读取里报出来。
      return;
    }
    // 关掉了（用户又点了一次，或后端回滚了）就不用再等。
    if (!pulse?.enabled) return;
    if (pulse.logging) return;
  }
}

// 翻页期间探到新记录时给一个可点的提示，而不是默默不刷新。
function renderHistoryPendingHint() {
  if (!elements.historyRefreshHint) return;
  elements.historyRefreshHint.hidden = historyPendingSignature === null;
}

function clearHistoryPendingHint() {
  historyPendingSignature = null;
  renderHistoryPendingHint();
}

async function loadHistoryStatus() {
  const data = await execApi('history-status');
  renderHistoryStatus(data || {});
  return data;
}

function stopHistoryPulse() {
  if (historyPulseTimer !== null) {
    globalThis.clearTimeout(historyPulseTimer);
    timers.delete(historyPulseTimer);
    historyPulseTimer = null;
  }
}

// 开着拦截日志时记录就该自己冒出来，不该逼用户去动筛选条件。但也不能常驻轮询：
// 只在日志页真的可见、且读取进程确实在跑时才探一下，离开页签或息屏立刻停。
// 探针只 stat 事件文件（见 history_pulse_json），空闲时的代价就是每轮一次 stat，
// 签名没变一次读取都不发；真有新事件才走一次完整读取。
function scheduleHistoryPulse() {
  stopHistoryPulse();
  if (disposed || !historyPanelActive || document.hidden) return;
  // 只看 enabled，不再要求 logging。以前要求 logging 为真才挂探针，而 logging 是
  // 「防火墙规则在位 + 读取进程在跑 + trace 挂载 + token 对齐」四个条件同时成立才为真，
  // 其中前两个要靠 shell 去问 iptables 和进程状态——任一次问失败（比如 xtables 锁被占）
  // 就会得到 false。那时探针不挂、也没有别的东西会再去读一次状态，列表就永远停在
  // 开启那一刻的空状态，用户只能靠动筛选条件（走的是另一条不刷新状态的读取路径）
  // 才能看到记录。现在开着就挂探针，由探针自己把状态纠回来；logging 为假时用更长的间隔。
  if (!historyStatus?.enabled) return;
  if (currentStatus?.activeMode === 'paused') return;
  const interval = historyStatus?.logging ? HISTORY_PULSE_INTERVAL_MS : HISTORY_PULSE_SETTLING_INTERVAL_MS;
  historyPulseTimer = schedule(async () => {
    historyPulseTimer = null;
    await runHistoryPulse();
    scheduleHistoryPulse();
  }, interval);
}

async function runHistoryPulse() {
  if (disposed || !historyPanelActive || document.hidden || historyLoading) return;
  if (currentStatus?.busy) return;
  let pulse = null;
  try {
    pulse = await execApi('history-pulse');
  } catch {
    // 探针失败不该打扰用户：下一轮再试，真正的错误会在用户主动读取时报出来。
    return;
  }
  if (disposed || !historyPanelActive) return;
  // 关掉了就收手：这是用户的意思，没有新事件可等。
  if (!pulse?.enabled) {
    historyPulseSignature = null;
    stopHistoryPulse();
    if (!historyLoading) await loadHistory({ reset: true });
    return;
  }
  // 界面显示的 logging 与后端不一致时读一次，把状态栏纠回来（顺带重排探针间隔）。
  // 以前这里是「logging 为假就停掉探针 + 整包重读一次」：停探针让界面失去自愈能力，
  // 而那一次整包重读在读取进程真停了的情况下每 6 秒来一遍，纯烧电。
  const loggingChanged = pulse.logging !== Boolean(historyStatus?.logging);
  const signature = typeof pulse.signature === 'string' ? pulse.signature : null;
  // 签名变了就一定要读，不管 logging 报的是什么。logging 要靠 shell 去问 iptables
  // 和进程状态，任一次问失败就会得到 false；而事件文件确实长大了是硬事实——
  // 读取进程明明在写，界面却因为 logging 为假而不去读，正是「不动筛选条件就看不到记录」。
  const changed = signature !== null && signature !== historyPulseSignature;
  if (loggingChanged && !changed) {
    if (!historyLoading) await loadHistory({ reset: true });
    return;
  }
  // 基线由上一次真正的读取写入（history-bundle 和 history 都会带回签名），所以比出不同
  // 就是「读完之后又有新事件」，不需要为首次探针留特例。
  if (!changed) return;
  // 正在用输入法打域名时不要动列表：重建上百行会把主线程占住，表现成输入卡顿。
  // 打完（compositionend 会触发一次读取）自然跟上。
  if (historyDomainComposing) return;
  // 翻过页就不能直接拽回第一页——用户正在看第三页。但也不能像以前那样当作
  // 「此后永不刷新」：那是「记录不完整」的一个直接来源，用户翻过一次页之后
  // 新拦截的连接再也不会自己出现。这里记下有新记录，并在状态栏提示，
  // 等他回到第一页、改筛选条件或点了提示就补上。
  if (historyPage > 0) {
    historyPendingSignature = signature;
    renderHistoryPendingHint();
    return;
  }
  // 域名筛选不再阻止刷新：筛选串是带给后端的查询参数，重读会照样按它过滤，
  // 结果仍然是「符合当前筛选的最新记录」，没有把用户的筛选弄丢的问题。
  // 这一轮走打包读取：拦截计数和应用清单都要跟着新事件走，二者都在 history-bundle 里。
  // 打包读取只比单读贵两遍 awk（统计与应用汇总），而且都在已经收集好的临时文件上跑——
  // 事件文件本身一趟不多走。清单没变时 renderHistoryApps 还会跳过整段 <select> 重建。
  await loadHistory({ reset: true });
}

function diagnosticValueLabel(kind, value) {
  const labels = {
    hostsProtection: {
      verified: '已校验',
      inactive: '未生效',
      mismatch: '状态不一致',
      unknown: '无法确认',
    },
    privateDns: {
      off: '未启用',
      active: '已启用，可能绕过 hosts 规则',
      unknown: '无法确认',
    },
    appLocalEncryptedDns: {
      informational: '应用自带 DoH 或 VPN 可能绕过 hosts 规则',
    },
  };
  return labels[kind]?.[value] || '无法确认';
}

function renderDiagnostics(data = {}) {
  const rows = [
    ['hostsProtection', 'hosts 保护'],
    ['privateDns', 'Private DNS'],
    ['appLocalEncryptedDns', '应用本地加密 DNS'],
  ];
  const fragment = document.createDocumentFragment();
  rows.forEach(([kind, label]) => {
    const row = document.createElement('div');
    row.className = 'diagnostics-row';
    const name = document.createElement('span');
    name.textContent = label;
    const value = document.createElement('strong');
    value.textContent = diagnosticValueLabel(kind, data[kind]);
    row.append(name, value);
    fragment.append(row);
  });
  elements.diagnosticsResult.replaceChildren(fragment);
}

async function loadDiagnostics() {
  if (!initialized || currentStatus?.busy || diagnosticsLoading || disposed) return;
  diagnosticsLoading = true;
  elements.diagnosticsButton.disabled = true;
  elements.diagnosticsResult.hidden = false;
  elements.diagnosticsResult.setAttribute('aria-busy', 'true');
  elements.diagnosticsResult.textContent = '正在检查当前环境…';
  try {
    const data = await execApi('diagnostics');
    if (!disposed) renderDiagnostics(data);
  } catch (error) {
    if (!isAbort(error)) elements.diagnosticsResult.textContent = `环境检查失败：${error?.message || '未知错误'}`;
  } finally {
    diagnosticsLoading = false;
    elements.diagnosticsResult.setAttribute('aria-busy', 'false');
    elements.diagnosticsButton.disabled = !initialized || Boolean(currentStatus?.busy);
  }
}

// page 给了就读那一页；不给则按 reset 决定读第一页还是留在当前页。
// 每次读取都整页换掉列表，所以 DOM 里始终只有 HISTORY_PAGE_SIZE 行。
async function loadHistory({ reset = false, refreshMetadata = reset, page = null } = {}) {
  if (!historyPanelActive || disposed) return;
  if (historyLoading) {
    if (reset) {
      historyQuerySerial += 1;
      historyReloadQueued = true;
    }
    return;
  }
  historyLoading = true;
  const serial = ++historyQuerySerial;
  const targetPage = page !== null ? Math.max(0, page) : reset ? 0 : historyPage;
  historyPage = targetPage;
  if (targetPage === 0) {
    // 回到第一页就等于把「有新记录」这件事消化掉了，提示该收。
    clearHistoryPendingHint();
  }
  if (reset || page !== null) {
    // 列表里已经有行时不要先拆空再重建。搜索域名是一边打字一边触发的，
    // 每次都「拆掉上百行 → 插入占位 → 拆掉占位 → 再插回上百行」，
    // 四趟 DOM 里有两趟纯属白跑，主线程被占住就成了输入法卡顿。
    // 保留旧行只标忙碌，等新数据到了由 renderHistoryItems 一次换掉。
    if (elements.historyList.querySelector('.history-row')) {
      elements.historyList.setAttribute('aria-busy', 'true');
    } else {
      elements.historyList.innerHTML = '<p class="empty-state">正在读取拦截日志…</p>';
    }
  }
  syncHistoryControls();
  try {
    // 需要刷新元数据时（进入页签、开关历史后）三份数据一次取回：状态 + 应用清单 + 首页记录。
    // 分开读要走三次 shell，而后端为此把事件收集和 packages.list 归一化各做两遍。
    let apps = null;
    let initialData = null;
    if (refreshMetadata) {
      const bundle = await execApi('history-bundle', historyQueryArgs(targetPage));
      if (serial !== historyQuerySerial || disposed || !historyPanelActive) return;
      // 状态一到就先渲染，不要等名单：名单只影响下面那批行的名单徽标，
      // 让开关和能力状态跟着一次慢的名单读取一起卡住是没必要的。
      // 先记基线再渲染状态：renderHistoryStatus 会挂探针，探针拿到的必须是这一页
      // 数据对应的签名，否则第一轮就会白读一次。
      if (typeof bundle?.signature === 'string') historyPulseSignature = bundle.signature;
      renderHistoryStatus(bundle?.status || {});
      apps = bundle?.apps;
      initialData = bundle?.history;
    } else {
      if (!historyStatus) await loadHistoryStatus();
      if (serial !== historyQuerySerial || disposed || !historyPanelActive) return;
    }
    if (!historyStatus?.enabled) {
      historyPage = 0;
      historyTotal = 0;
      // 不要在这里把 historyLoaded 置为已加载：开启动作刚提交时后端可能还没翻转状态，
      // latch 住之后重新进入页签也不会重试，用户就只能靠改筛选条件才能看到记录。
      historyLoaded = false;
      elements.historyList.innerHTML = '<p class="empty-state">开启拦截日志后显示记录</p>';
      renderHistoryPager();
      return;
    }
    if (refreshMetadata) {
      // 名单只在真要渲染行时才需要（决定名单徽标），历史没开就不用白读一次。
      if (!listsLoaded) await loadLists();
      if (serial !== historyQuerySerial || disposed || !historyPanelActive) return;
    } else {
      initialData = await execApi('history', historyQueryArgs(targetPage));
      if (serial !== historyQuerySerial || disposed || !historyPanelActive) return;
    }
    let data = initialData;
    let appFilterReset = refreshMetadata && renderHistoryApps(apps?.apps);
    const initialItems = Array.isArray(data?.items) ? data.items : [];
    // An app can disappear between the cached app list and a later search.
    // Revalidate only this rare empty-result case so normal searches stay to one history read.
    if (!refreshMetadata && initialItems.length === 0 && elements.historyAppFilter.value !== '-') {
      const latestApps = await execApi('history-apps');
      if (serial !== historyQuerySerial || disposed || !historyPanelActive) return;
      appFilterReset = renderHistoryApps(latestApps?.apps);
    }
    if (appFilterReset) {
      historyPage = 0;
      data = await execApi('history', historyQueryArgs(0));
      if (serial !== historyQuerySerial || disposed || !historyPanelActive) return;
    }
    const items = Array.isArray(data?.items) ? data.items : [];
    // 单读路径（改筛选条件、翻页）也带回签名，把轮询基线一起更新。不更新的话，
    // 下一轮探针会拿这一页之前的旧基线去比，必然比出不同，白做一次整包读取。
    // 只在第一页更新：翻页读的是同一份数据的后续页，基线不该跟着往后走。
    if (historyPage === 0 && typeof data?.signature === 'string') historyPulseSignature = data.signature;
    // total 是后端聚合排序后的总条数。老后端没有这个字段时退回按 hasMore 估一个下界，
    // 至少还能翻到下一页，不会因为算出「共 1 页」把后面的记录全藏起来。
    const reportedTotal = Number(data?.total);
    historyTotal = Number.isInteger(reportedTotal) && reportedTotal >= 0
      ? reportedTotal
      : historyPage * HISTORY_PAGE_SIZE + items.length + (data?.hasMore ? 1 : 0);
    // 过期删除或筛选变化让总数缩了，当前页可能已经越界（表现成空列表）。夹回最后一页重读一次。
    // 直接在这里递归会在外层 finally 之前重入，historyReloadQueued 的归属就乱了。
    // 记下要夹回的页码，交给 finally 统一排一次。
    const lastPage = historyPageCount() - 1;
    if (items.length === 0 && historyPage > lastPage) {
      historyClampPage = Math.max(0, lastPage);
    }
    historyLoaded = true;
    // 每页都整页换掉，列表里始终只有这一页。
    renderHistoryItems(items, { reset: true });
  } catch (error) {
    if (!isAbort(error) && serial === historyQuerySerial && historyPanelActive) {
      if (reset) {
        elements.historyList.innerHTML = `<p class="empty-state">读取拦截日志失败：${escapeText(error?.message || '未知错误')}</p>`;
      }
      showNotice(`读取拦截日志失败：${error?.message || '未知错误'}`, { persistent: true, tone: 'danger' });
    }
  } finally {
    historyLoading = false;
    elements.historyList.removeAttribute('aria-busy');
    syncHistoryControls();
    const reloadQueued = historyReloadQueued;
    historyReloadQueued = false;
    const clampPage = historyClampPage;
    historyClampPage = null;
    if (reloadQueued && historyPanelActive && !disposed) {
      schedule(() => loadHistory({ reset: true }), 0);
    } else if (clampPage !== null && historyPanelActive && !disposed) {
      schedule(() => loadHistory({ page: clampPage, refreshMetadata: false }), 0);
    }
  }
}

function setupInteractions() {
  elements.noticeCancelButton.addEventListener('click', keepReadonly);
  elements.noticeConfirmButton.addEventListener('click', () => unlockManagement());
  elements.noticeConfirmPermanentButton.addEventListener('click', acknowledgeNoticePermanently);
  elements.noticeDialog.addEventListener('cancel', (event) => {
    event.preventDefault();
    keepReadonly();
  });
  elements.noticeReopenButton.addEventListener('click', () => {
    elements.noticeReadonly.hidden = true;
    if (!elements.noticeDialog.open) elements.noticeDialog.showModal();
  });
  elements.aboutCreditsButton.addEventListener('click', () => {
    if (!elements.creditsDialog.open) elements.creditsDialog.showModal();
  });
  document.querySelectorAll('[data-goto-tab]').forEach((button) => {
    button.addEventListener('click', () => gotoWorkspaceTarget(button));
  });
  document.querySelectorAll('input[name="doh-mode"]').forEach((input) => {
    input.addEventListener('change', () => {
      syncDohControls();
      if (input.checked && input.value === 'selected') loadDohApps({ reset: true });
    });
  });
  elements.dohEndpoint.addEventListener('input', () => {
    dohEndpointDirty = true;
  });
  elements.dohTest.addEventListener('click', testDohEndpoint);
  elements.dohApply.addEventListener('click', openDohConfirmation);
  elements.dohDisable.addEventListener('click', disableDoh);
  elements.dohConfirmForm.addEventListener('submit', (event) => {
    event.preventDefault();
    confirmDohEnable();
  });
  elements.dohAppSearch.addEventListener('input', () => {
    if (dohAppSearchTimer !== null) {
      globalThis.clearTimeout(dohAppSearchTimer);
      timers.delete(dohAppSearchTimer);
    }
    dohAppSearchTimer = schedule(() => {
      dohAppSearchTimer = null;
      loadDohApps({ reset: true });
    }, 180);
  });
  elements.dohLoadMoreApps.addEventListener('click', () => loadDohApps());
  elements.appPolicySave.addEventListener('click', saveAppPolicy);
  elements.saveOverridesButton.addEventListener('click', saveOverrides);
  elements.domainOverrides.addEventListener('input', () => {
    debounce('overrides-validate', () => {
      const result = canonicalFor(elements.domainOverrides, canonicalOverrides);
      setText(elements.overrideError, result.error || '');
      setText(elements.overrideCount, `${result.count ?? 0} 条`);
    }, LIST_VALIDATE_DEBOUNCE_MS);
  });
  elements.builtinRecovery.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-recovery-id]');
    if (!button || button.disabled || currentStatus?.busy) return;
    await runMutation('add-source', [
      encodeBase64Utf8(button.dataset.recoveryName),
      encodeBase64Utf8(button.dataset.recoveryUrl),
    ]);
    builtinRecoveryLoaded = false;
    await loadBuiltinRecovery({ force: true });
  });
  elements.resetRulesButton.addEventListener('click', () => elements.resetRulesDialog.showModal());
  elements.resetRulesForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    closeDialog(elements.resetRulesDialog);
    await runMutation('reset-rules');
    listsLoaded = false;
    builtinRecoveryLoaded = false;
    overridesLoaded = false;
  });
  elements.clearCacheButton.addEventListener('click', () => runMutation('clear-cache'));
  elements.refreshButton.addEventListener('click', () => runMutation('refresh'));
  elements.pauseProtectionButton.addEventListener('click', () => elements.pauseDialog.showModal());
  elements.resumeProtectionButton.addEventListener('click', () => runMutation('resume'));
  elements.pauseForm.addEventListener('submit', (event) => {
    event.preventDefault();
    closeDialog(elements.pauseDialog);
    runMutation('pause');
  });
  elements.diagnosticsButton.addEventListener('click', loadDiagnostics);
  elements.autoRefreshEnabled.addEventListener('change', () => {
    const interval = document.querySelector('input[name="auto-refresh-interval"]:checked')?.value || '24';
    if (elements.autoRefreshEnabled.checked !== Boolean(currentStatus?.autoRefresh?.enabled)) {
      runMutation('set-auto-refresh', [elements.autoRefreshEnabled.checked ? '1' : '0', interval]);
    }
  });
  document.querySelectorAll('input[name="auto-refresh-interval"]').forEach((input) => {
    input.addEventListener('change', () => {
      if (input.checked && Number(input.value) !== Number(currentStatus?.autoRefresh?.intervalHours)) {
        runMutation('set-auto-refresh', [currentStatus?.autoRefresh?.enabled ? '1' : '0', input.value]);
      }
    });
  });
  elements.rollbackButton.addEventListener('click', () => {
    const redo = currentStatus?.alternateAction === 'redo';
    elements.rollbackDialogTitle.textContent = redo ? '恢复规则版本' : '回滚规则版本';
    elements.rollbackDialogCopy.textContent = redo
      ? '将恢复到回滚前的已验证规则版本。'
      : '将切换到上一份已验证的规则版本。';
    elements.confirmRollbackButton.textContent = redo ? '确认恢复' : '确认回滚';
    elements.rollbackDialog.showModal();
  });

  document.querySelectorAll('input[name="mode"]').forEach((input) => {
    input.addEventListener('change', () => {
      if (input.checked && input.value !== currentStatus?.desiredMode) {
        runMutation('select-mode', [input.value]);
      }
    });
  });

  elements.addSourceButton.addEventListener('click', () => openSourceDialog());
  elements.saveListsButton.addEventListener('click', saveLists);
  for (const input of [elements.manualBlocklist, elements.manualAllowlist]) {
    input.addEventListener('input', () => {
      debounce('manual-lists-validate', () => {
        // 结果连同原文一起记下来，点保存时不用再算一遍。
        const block = canonicalFor(elements.manualBlocklist, canonicalList);
        const allow = canonicalFor(elements.manualAllowlist, canonicalList);
        renderListCounts(block.count ?? 0, allow.count ?? 0);
        renderListErrors(block.error || '', allow.error || '');
      }, LIST_VALIDATE_DEBOUNCE_MS);
    });
  }
  elements.builtinSources.addEventListener('click', handleSourceCommand);
  elements.builtinSources.addEventListener('change', handleSourceCommand);
  elements.customSources.addEventListener('click', handleSourceCommand);
  elements.customSources.addEventListener('change', handleSourceCommand);
  setupCollapsibles();

  elements.sourceForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const value = validateSourceForm();
    if (!value) return;
    const id = elements.sourceId.value;
    closeDialog(elements.sourceDialog);
    const encoded = [encodeBase64Utf8(value.name), encodeBase64Utf8(value.url)];
    if (id) runMutation('update-source', [id, ...encoded]);
    else runMutation('add-source', encoded);
  });

  elements.deleteForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const id = elements.deleteSourceId.value;
    closeDialog(elements.deleteDialog);
    if (!id) return;
    await runMutation('remove-source', [id]);
    builtinRecoveryLoaded = false;
    await loadBuiltinRecovery({ force: true });
  });

  elements.rollbackForm.addEventListener('submit', (event) => {
    event.preventDefault();
    closeDialog(elements.rollbackDialog);
    runMutation('rollback');
  });

  document.querySelectorAll('[data-close-dialog]').forEach((button) => {
    button.addEventListener('click', () => closeDialog(button.closest('dialog')));
  });

  elements.historyEnabled.addEventListener('change', () => {
    if (elements.historyEnabled.checked !== Boolean(historyStatus?.enabled)) {
      runMutation('set-history', [elements.historyEnabled.checked ? '1' : '0']);
    }
  });
  elements.historyList.addEventListener('click', async (event) => {
    const action = event.target.closest('[data-history-decision]');
    if (!action || action.disabled || historyLoading || currentStatus?.busy || currentStatus?.activeMode === 'paused') return;
    const row = action.closest('.history-row');
    const domain = row?.dataset.domain;
    if (!domain) return;
    const decision = action.dataset.historyDecision;
    const previousDecision = row.dataset.decision;
    // 先把徽标改过去，用户点完立刻看到结果；失败再翻回原样。
    patchHistoryRowDecision(domain, decision);
    row.setAttribute('aria-busy', 'true');
    row.querySelectorAll('[data-history-decision]').forEach((button) => { button.disabled = true; });
    try {
      const outcome = await runMutation('set-domain-decision', [decision, encodeBase64Utf8(domain)]);
      // 历史记录是既成事实的连接日志，加名单不会改动其中任何一条，变的只是
      // 「这个域名现在在哪个名单里」。所以成功后不再整段重查重建，
      // 上面那次就地改写就是最终结果；失败才回滚徽标。
      const rejected = Boolean(outcome?.errorCode)
        || outcome?.result === 'failed' || outcome?.result === 'critical';
      if (rejected) patchHistoryRowDecision(domain, previousDecision);
    } catch (error) {
      patchHistoryRowDecision(domain, previousDecision);
      throw error;
    } finally {
      if (row.isConnected) {
        row.removeAttribute('aria-busy');
        row.querySelectorAll('[data-history-decision]').forEach((button) => {
          button.disabled = Boolean(currentStatus?.busy) || currentStatus?.activeMode === 'paused';
        });
      }
    }
  });
  const resetHistoryQuery = () => {
    historyLoaded = false;
    // 换了筛选条件，原来的第几页没有意义了，回第一页。
    loadHistory({ reset: true, refreshMetadata: false, page: 0 });
  };
  elements.historyAppFilter.addEventListener('change', resetHistoryQuery);
  elements.historyPortFilter.addEventListener('change', resetHistoryQuery);
  elements.historyTimeFilter.addEventListener('change', resetHistoryQuery);
  // 输入法组词期间每敲一下拼音都会派发 input，而此刻输入框里是还没定字的
  // 候选串，拿去查历史必然查不到东西，白跑一趟整段列表的重建，
  // 主线程被这笔活儿占住的表现就是输入法卡住。组词中一律不查，定字后再查一次。
  const applyHistoryDomainQuery = () => {
    if (historyDomainComposing) return;
    const query = elements.historyDomainFilter.value.trim().toLowerCase();
    if (query === historyDomainApplied) return;
    historyDomainApplied = query;
    resetHistoryQuery();
  };
  const scheduleHistoryDomainQuery = () => {
    if (historyDomainTimer !== null) {
      globalThis.clearTimeout(historyDomainTimer);
      timers.delete(historyDomainTimer);
    }
    historyDomainTimer = schedule(() => {
      historyDomainTimer = null;
      applyHistoryDomainQuery();
    }, 280);
  };
  elements.historyDomainFilter.addEventListener('compositionstart', () => {
    historyDomainComposing = true;
  });
  elements.historyDomainFilter.addEventListener('compositionend', () => {
    historyDomainComposing = false;
    scheduleHistoryDomainQuery();
  });
  elements.historyDomainFilter.addEventListener('input', (event) => {
    // Safari/部分 WebView 不派发 compositionstart，但 isComposing 一直是可信的。
    if (event.isComposing === true) {
      historyDomainComposing = true;
      return;
    }
    scheduleHistoryDomainQuery();
  });
  elements.historyPrevPage?.addEventListener('click', () => goToHistoryPage(historyPage - 1));
  elements.historyNextPage?.addEventListener('click', () => goToHistoryPage(historyPage + 1));
  elements.historyRefreshHint?.addEventListener('click', () => {
    historyLoaded = false;
    loadHistory({ reset: true });
  });
  elements.reloadRuntimeLogsButton.addEventListener('click', () => loadRuntimeLogs({ reset: true }));
  elements.loadMoreRuntimeLogs.addEventListener('click', () => loadRuntimeLogs());
  elements.runtimeLogEnabled.addEventListener('change', (event) => {
    setRuntimeLogMode(event.target.checked);
  });
  elements.clearRuntimeLogsButton.addEventListener('click', () => clearRuntimeLogs());
  elements.exportRuntimeLogsButton.addEventListener('click', () => exportRuntimeLogs());
  elements.clearHistoryButton.addEventListener('click', () => elements.clearHistoryDialog.showModal());
  elements.clearHistoryForm.addEventListener('submit', (event) => {
    event.preventDefault();
    closeDialog(elements.clearHistoryDialog);
    runMutation('clear-history');
  });
}

async function start() {
  setupTabs();
  setupAppearance();
  setupInteractions();
  afterFirstPaint(() => {
    elements.overviewWorkspace.hidden = false;
    afterFirstPaint(() => refreshIcons());
  });
  const statusPromise = execApi('status');
  const appearancePromise = loadAppearance();
  // 等外观落地后再预热，避免用马上要被替换的主题去缓存样式。
  void appearancePromise.then(
    () => { if (!disposed) schedulePanelPrewarm(); },
    () => {},
  );
  const noticePreferencePromise = execApi('notice-status').then(
    (value) => ({ state: 'fulfilled', value }),
    (reason) => ({ state: 'rejected', reason }),
  );
  try {
    const status = await statusPromise;
    if (disposed) return;
    renderStatus(status);
    if (status.busy) await watchBackendUntilIdle();
    await loadNoticeGate(await noticePreferencePromise);
  } catch (error) {
    if (!isAbort(error)) renderBridgeFailure(error);
  } finally {
    await appearancePromise;
  }
}

globalThis.addEventListener('pagehide', () => {
  disposed = true;
  lifecycle.abort();
  historyPanelActive = false;
  appsPanelActive = false;
  historyQuerySerial += 1;
  if (historyDomainTimer !== null) globalThis.clearTimeout(historyDomainTimer);
  if (dohAppSearchTimer !== null) globalThis.clearTimeout(dohAppSearchTimer);
  stopDohRefresh();
  stopHistoryPulse();
  if (prewarmIdleHandle !== null && typeof globalThis.cancelIdleCallback === 'function') {
    globalThis.cancelIdleCallback(prewarmIdleHandle);
    prewarmIdleHandle = null;
  }
  for (const timer of timers) globalThis.clearTimeout(timer);
  timers.clear();
  debounceTimers.clear();
}, { once: true });

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    stopDohRefresh();
    stopHistoryPulse();
  } else {
    scheduleDohRefresh();
    scheduleHistoryPulse();
  }
});

start();
