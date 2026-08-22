const CALLBACK_PREFIX = '__jingjie_cb_';
const DEFAULT_TIMEOUT_MS = 10_000;
const FIXED_MODULE_DIR = '/data/adb/modules/jingjie_hosts';

let callbackSequence = 0;

export class BridgeError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'BridgeError';
    this.code = code;
    Object.assign(this, details);
  }
}

function callbackName() {
  callbackSequence += 1;
  const stamp = Date.now().toString(36);
  const sequence = callbackSequence.toString(36);
  const random = Math.random().toString(36).slice(2, 10) || '0';
  return `${CALLBACK_PREFIX}${stamp}_${sequence}_${random}`;
}

function getHostAndBridge() {
  const host = globalThis.window;
  if (!host) return { host: null, ksu: null };
  const ksu = globalThis.window.ksu;
  return { host, ksu };
}

export function readModuleInfoDiagnostic() {
  const { ksu } = getHostAndBridge();
  if (!ksu || typeof ksu.moduleInfo !== 'function') {
    return { available: false, moduleDir: null };
  }

  try {
    const raw = ksu.moduleInfo();
    const info = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (!info || typeof info !== 'object' || typeof info.moduleDir !== 'string') {
      return { available: true, moduleDir: null };
    }
    const normalized = info.moduleDir.replace(/\/+$/, '');
    return {
      available: true,
      moduleDir: normalized === FIXED_MODULE_DIR ? FIXED_MODULE_DIR : null,
    };
  } catch {
    return { available: false, moduleDir: null };
  }
}

export function execBridge(command, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const { host, ksu } = getHostAndBridge();
    if (!host || !ksu || typeof ksu.exec !== 'function') {
      reject(new BridgeError('bridge_unavailable', 'KernelSU、KernelSU Next 或 APatch 连接桥不可用'));
      return;
    }
    if (typeof command !== 'string' || command.length === 0) {
      reject(new BridgeError('bridge_protocol', '连接桥命令无效'));
      return;
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      reject(new BridgeError('bridge_protocol', '连接桥超时时间无效'));
      return;
    }

    const name = callbackName();
    let active = true;
    let timer = null;

    const cleanup = () => {
      if (timer !== null) globalThis.clearTimeout(timer);
      if (host[name]) delete host[name];
      if (typeof host.removeEventListener === 'function') {
        host.removeEventListener('pagehide', onPageHide);
      }
    };

    const finish = (error, value) => {
      if (!active) return;
      active = false;
      cleanup();
      if (error) reject(error);
      else resolve(value);
    };

    const onPageHide = () => {
      finish(new BridgeError('page_hidden', '页面已关闭'));
    };

    host[name] = (errno, stdout, stderr) => {
      if (!active) return;
      if (!Number.isInteger(errno) || typeof stdout !== 'string' || typeof stderr !== 'string') {
      finish(new BridgeError('bridge_protocol', '连接桥返回了无效数据'));
        return;
      }
      if (errno !== 0) {
        finish(new BridgeError('command_failed', stderr || `命令退出码 ${errno}`, {
          errno,
          stdout,
          stderr,
        }));
        return;
      }
      finish(null, { stdout, stderr });
    };

    if (typeof host.addEventListener === 'function') {
      host.addEventListener('pagehide', onPageHide);
    }
    timer = globalThis.setTimeout(() => {
      finish(new BridgeError('bridge_timeout', '连接桥调用超时'));
    }, timeoutMs);

    try {
      ksu.exec(command, '{}', name);
    } catch (cause) {
      finish(new BridgeError('bridge_exception', '连接桥调用异常', { cause }));
    }
  });
}
