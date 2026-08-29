import { BridgeError, execBridge } from './bridge.js';

const API_SCRIPT = "/system/bin/sh '/data/adb/modules/zhulong_hosts/webui_api.sh'";
const DEFAULT_TIMEOUT_MS = 10_000;
// 稳定期的轮询间隔，也是 pollOperation 的上限：调用方传更小的值仍然按小的走。
const DEFAULT_POLL_MS = 2_000;
// 大多数操作一两秒内就结束，前几轮用更短的间隔让按钮更快恢复；
// 之后一路退让到 DEFAULT_POLL_MS，长任务才不会被刷成高频轮询。
// 每一轮都是一次 status 调用，也就是在手机上重新拉起一个 shell：
// 从前四轮之后就固定 650ms，一次十几秒的保存要拉起三四十个 shell，
// 这笔开销随操作时长线性增长，正是「点一下按钮就更费电」里看不见的那一半。
// 继续退让不影响短操作的手感——前四轮的节奏一个字都没改。
const POLL_RAMP_MS = [120, 200, 320, 480, 650, 900, 1200, 1600];
const SOURCE_ID = /^(?:awa|rule10007|custom_(?!0+$)[0-9]{1,57})$/;
const OPERATION_ID = /^op_[A-Za-z0-9_-]+$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const CURSOR = /^[0-9]{1,18}$/;

// 第 attempt 轮（从 0 起）该等多久。app.js 里跟随后台的那两个轮询循环共用这条曲线，
// 免得同一个「每轮一次 status」的代价在三处各定一套节奏。
export function pollBackoffMs(attempt) {
  const index = Number.isInteger(attempt) && attempt > 0 ? attempt : 0;
  return index < POLL_RAMP_MS.length ? POLL_RAMP_MS[index] : DEFAULT_POLL_MS;
}

export class ApiError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    Object.assign(this, details);
  }
}

function invalid(message) {
  throw new ApiError('invalid_argument', message);
}

function isBase64(value) {
  return typeof value === 'string' && value.length > 0 && BASE64.test(value);
}

function decodeCanonicalBase64Utf8(value, label) {
  if (!isBase64(value)) invalid(`invalid Base64 ${label}`);
  let bytes;
  let decoded;
  try {
    bytes = Uint8Array.from(globalThis.atob(value), (char) => char.charCodeAt(0));
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    invalid(`invalid Base64 ${label}`);
  }
  if (encodeBase64Utf8(decoded) !== value) invalid(`invalid Base64 ${label}`);
  return { bytes, decoded };
}

function validateDohEndpoint(value) {
  const { bytes, decoded } = decodeCanonicalBase64Utf8(value, 'endpoint');
  if (bytes.length > 2048) invalid('endpoint is too large');
  const httpsPrefix = 'https:' + '//';
  if (!decoded.startsWith(httpsPrefix) || /[\u0000-\u0020\u007f#]/.test(decoded)) {
    invalid('invalid DoH endpoint');
  }
  let url;
  try { url = new URL(decoded); } catch { invalid('invalid DoH endpoint'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password
    || url.hostname === 'localhost' || url.hostname === 'localhost.') {
    invalid('invalid DoH endpoint');
  }
}

function validateDohConfig(value) {
  const { decoded } = decodeCanonicalBase64Utf8(value, 'DoH config');
  const rows = decoded.split('\n');
  if (rows[rows.length - 1] === '') rows.pop();
  if (rows[0] !== 'ack=doh-v1' || rows.some((row) => row.length === 0)) invalid('invalid DoH config');
  if (rows.length - 1 > 256) invalid('invalid DoH config');
  let prior = -1;
  for (const row of rows.slice(1)) {
    const match = /^uid=([0-9]+)$/.exec(row);
    if (!match || (match[1].length > 1 && match[1][0] === '0')) invalid('invalid DoH config');
    const uid = Number(match[1]);
    const appId = uid % 100000;
    if (!Number.isSafeInteger(uid) || uid > 4294967294 || uid === 65534
      || appId < 10000 || appId > 19999 || uid <= prior) invalid('invalid DoH config');
    prior = uid;
  }
}

function validateArgs(verb, args) {
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
    invalid('API arguments must be strings');
  }

  const count = (length) => {
    if (args.length !== length) invalid(`invalid argument count for ${verb}`);
  };
  const sourceId = (value) => {
    if (!SOURCE_ID.test(value)) invalid('invalid source id');
  };
  const refreshSourceId = (value) => {
    if (!SOURCE_ID.test(value)) {
      invalid('invalid source id');
    }
  };
  const boolean = (value) => {
    if (value !== '0' && value !== '1') invalid('invalid boolean');
  };
  const encoded = (value) => {
    if (!isBase64(value)) invalid('invalid Base64 value');
  };
  const listEncoded = (value) => {
    if (value !== '' && !isBase64(value)) invalid('invalid Base64 list');
    if (value.length > 90_000) invalid('list payload is too large');
  };

  switch (verb) {
    case 'status':
    case 'diagnostics':
    case 'lists':
    case 'sources':
    case 'templates':
    case 'overrides':
    case 'rules-bundle':
    case 'notice-status':
    case 'runtime-log-mode':
    case 'clear-runtime-logs':
    case 'export-runtime-logs':
    case 'ui-theme':
    case 'app-capability':
    case 'app-policy':
    case 'history-status':
    case 'history-pulse':
    case 'history-apps':
    case 'refresh':
    case 'pause':
    case 'resume':
    case 'rollback':
    case 'reset-rules':
    case 'doh-status':
    case 'disable-doh':
    case 'set-background-commit':
    case 'set-background-clear':
    case 'background-unstage':
      count(0);
      break;
    case 'set-ui-theme':
      count(4);
      if (!['classic', 'liquid'].includes(args[0])) invalid('invalid interface surface');
      if (!['light', 'dark', 'system'].includes(args[1])) invalid('invalid interface scheme');
      if (!['soft', 'standard', 'strong'].includes(args[2])) invalid('invalid glass level');
      if (!['auto', 'off'].includes(args[3])) invalid('invalid motion preference');
      break;
    case 'set-background-enabled':
      count(1);
      boolean(args[0]);
      break;
    case 'set-background-put':
      count(2);
      if (args[0] !== 'first' && args[0] !== 'next') invalid('invalid background chunk slot');
      if (!isBase64(args[1]) || args[1].length > 8_192) invalid('invalid background chunk');
      break;
    case 'background-list':
    case 'background-stage': {
      count(1);
      const { decoded } = decodeCanonicalBase64Utf8(args[0], 'gallery path');
      if (decoded.length > 4_096) invalid('gallery path is too long');
      if (!decoded.startsWith('/')) invalid('invalid gallery path');
      if (/[\u0000-\u001f]/u.test(decoded)) invalid('invalid gallery path');
      if (decoded.includes('/../') || decoded.endsWith('/..')) invalid('invalid gallery path');
      break;
    }
    case 'doh-apps': {
      count(3);
      const query = args[0] === ''
        ? ''
        : decodeCanonicalBase64Utf8(args[0], 'query').decoded;
      if (new TextEncoder().encode(query).length > 128 || !/^[A-Za-z0-9_.-]*$/.test(query)) invalid('invalid DoH app query');
      if (!CURSOR.test(args[1]) || Number(args[1]) > 4294967294) invalid('invalid DoH app cursor');
      if (!CURSOR.test(args[2]) || Number(args[2]) < 1 || Number(args[2]) > 100) invalid('invalid DoH app page size');
      break;
    }
    case 'test-doh':
      count(1);
      validateDohEndpoint(args[0]);
      break;
    case 'set-doh':
      count(3);
      if (!['off', 'global', 'selected'].includes(args[0])) invalid('invalid DoH mode');
      validateDohEndpoint(args[1]);
      validateDohConfig(args[2]);
      break;
    case 'set-history':
      count(1);
      boolean(args[0]);
      break;
    case 'refresh-source':
      count(1);
      refreshSourceId(args[0]);
      break;
    case 'set-auto-refresh':
      count(2);
      boolean(args[0]);
      if (!['6', '12', '24'].includes(args[1])) invalid('invalid refresh interval');
      break;
    case 'clear-history':
    case 'clear-cache':
      count(0);
      break;
    // history-bundle 的参数形状和 history 完全一致，共用同一套校验。
    case 'history-bundle':
    case 'history': {
      count(6);
      if (!CURSOR.test(args[0]) || Number(args[0]) > 50000) invalid('invalid history cursor');
      const limit = Number(args[1]);
      if (!Number.isInteger(limit) || limit < 1 || limit > 200) invalid('invalid history page size');
      if (!CURSOR.test(args[2])) invalid('invalid history timestamp');
      if (args[3] !== '-' && (!CURSOR.test(args[3]) || Number(args[3]) > 4294967294)) invalid('invalid history uid');
      if (args[4] !== '-' && (!CURSOR.test(args[4]) || Number(args[4]) < 1 || Number(args[4]) > 65535)) invalid('invalid history port');
      if (args[5] !== '-') {
        encoded(args[5]);
        let domain;
        try { domain = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(globalThis.atob(args[5]), (char) => char.charCodeAt(0))); } catch { invalid('invalid domain filter'); }
        if (!/^[a-z0-9._-]{1,253}$/.test(domain)) invalid('invalid domain filter');
      }
      break;
    }
    case 'set-builtin':
      count(2);
      if (args[0] !== 'awa' && args[0] !== 'rule10007') invalid('invalid built-in source');
      boolean(args[1]);
      break;
    case 'add-source':
      count(2);
      encoded(args[0]);
      encoded(args[1]);
      break;
    case 'update-source':
      count(3);
      sourceId(args[0]);
      encoded(args[1]);
      encoded(args[2]);
      break;
    case 'set-source':
      count(2);
      sourceId(args[0]);
      boolean(args[1]);
      break;
    case 'move-source':
      count(2);
      sourceId(args[0]);
      if (args[1] !== 'up' && args[1] !== 'down') invalid('invalid move direction');
      break;
    case 'remove-source':
      count(1);
      sourceId(args[0]);
      break;
    case 'select-mode':
      count(1);
      if (args[0] !== 'block_all' && args[0] !== 'preserve_reward') invalid('invalid mode');
      break;
    case 'set-lists':
      count(2);
      listEncoded(args[0]);
      listEncoded(args[1]);
      break;
    case 'set-domain-decision':
      count(2);
      if (args[0] !== 'allow' && args[0] !== 'block') invalid('invalid domain decision');
      encoded(args[1]);
      let domain;
      try {
        domain = new TextDecoder('utf-8', { fatal: true }).decode(
          Uint8Array.from(globalThis.atob(args[1]), (char) => char.charCodeAt(0)),
        );
      } catch { invalid('invalid domain'); }
      if (domain.length > 253 || /^[0-9.]+$/.test(domain)
        || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(domain)) {
        invalid('invalid domain');
      }
      break;
    case 'set-overrides':
      count(1);
      listEncoded(args[0]);
      break;
    case 'set-notice':
      count(1);
      boolean(args[0]);
      break;
    case 'set-app-policy':
      count(3);
      if (!['off', 'block_selected', 'allow_resolved'].includes(args[0])) invalid('invalid app policy mode');
      listEncoded(args[1]);
      listEncoded(args[2]);
      break;
    case 'runtime-logs': {
      count(2);
      if (!CURSOR.test(args[0])) invalid('invalid log cursor');
      const maxBytes = Number(args[1]);
      if (!Number.isInteger(maxBytes) || maxBytes < 1024 || maxBytes > 32768) {
        invalid('invalid log page size');
      }
      break;
    }
    case 'set-runtime-log-mode':
      count(1);
      boolean(args[0]);
      break;
    default:
      invalid('unsupported API verb');
  }
}

function parseResponse(stdout) {
  if (stdout.trim().length === 0) {
    throw new ApiError('empty_response', 'API 返回了空响应');
  }
  let response;
  try {
    response = JSON.parse(stdout);
  } catch (cause) {
    throw new ApiError('invalid_json', 'API 返回了 invalid JSON', { cause });
  }
  if (!response || typeof response !== 'object' || typeof response.ok !== 'boolean') {
    throw new ApiError('invalid_response', 'API 响应结构无效');
  }
  if (!response.ok) {
    const code = typeof response.error?.code === 'string' ? response.error.code : 'api_error';
    const message = typeof response.error?.message === 'string'
      ? response.error.message
      : '规则服务返回错误';
    throw new ApiError(code, message);
  }
  if (!Object.hasOwn(response, 'data')) {
    throw new ApiError('invalid_response', 'API 响应缺少 data');
  }
  return response.data;
}

export function encodeBase64Utf8(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary);
}

export function encodeBase64Bytes(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary);
}

export async function execApi(verb, args = [], { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  validateArgs(verb, args);
  const shellArgs = args.map((arg, index) => {
    // 尾部的可选筛选位用 none 占位，避免裸 '-' 被 shell 当成选项。
    const positional = verb === 'history' || verb === 'history-bundle';
    const value = positional && index >= 3 && arg === '-' ? 'none' : arg;
    return value === '' ? "''" : value;
  });
  const command = [API_SCRIPT, verb, ...shellArgs].join(' ');
  const { stdout } = await execBridge(command, { timeoutMs });
  const data = parseResponse(stdout);
  return data;
}

export async function submitMutation(verb, args = [], { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  try {
    const data = await execApi(verb, args, { timeoutMs });
    if (!data || data.accepted !== true || !OPERATION_ID.test(data.operationId)) {
      throw new ApiError('invalid_response', 'API 未返回有效的 operation ID');
    }
    return { state: 'accepted', operationId: data.operationId };
  } catch (error) {
    if (error instanceof BridgeError && error.code === 'bridge_timeout') {
      return { state: 'result_unknown' };
    }
    throw error;
  }
}

function abortError() {
  if (typeof DOMException === 'function') return new DOMException('Aborted', 'AbortError');
  const error = new Error('Aborted');
  error.name = 'AbortError';
  return error;
}

function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError());
      return;
    }
    const timer = globalThis.setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      globalThis.clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      reject(abortError());
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

export async function pollOperation(operationId, onStatus, signal, {
  pollMs = DEFAULT_POLL_MS,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!OPERATION_ID.test(operationId)) invalid('invalid operation id');
  if (typeof onStatus !== 'function') invalid('onStatus must be a function');

  let attempt = 0;
  while (true) {
    if (signal?.aborted) throw abortError();
    const status = await execApi('status', [], { timeoutMs });
    if (signal?.aborted) throw abortError();
    onStatus(status);

    if (!status.busy) {
      if (status.operationId !== operationId) {
        throw new ApiError('operation_mismatch', '最近完成的操作与本次提交不一致');
      }
      return status;
    }
    const ramped = pollBackoffMs(attempt);
    attempt += 1;
    await delay(Math.min(ramped, pollMs), signal);
  }
}
