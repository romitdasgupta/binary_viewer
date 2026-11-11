/**
 * BinaryStudio analysis engine worker (module worker).
 *
 * Runs CPython (Pyodide) with the BinaryStudio backend and answers API requests from the page
 * through the same transport-agnostic router the Python server uses (backend/api.py). Created by
 * static/wasm/transport.js; never loaded directly. Everything it fetches comes from this origin.
 *
 * Page -> worker
 *   {type: 'init', pyodide: {module, indexURL}, bundle: {url, sha256, size}, prefetch: [{url, size}],
 *    overrides: {...}}                                   once, first message
 *   {type: 'request', id, method, route, query, headers, body: ArrayBuffer | null}
 *       the page sends one request at a time and waits for its response (it owns the queue)
 * Worker -> page
 *   {type: 'progress', loaded, total, stage}             quiet start-up progress (bytes are decoded sizes)
 *   {type: 'ready', timings, stats, version, heap}         heap: WebAssembly memory size in bytes
 *   {type: 'init-failed', message}
 *   {type: 'response', id, status, headers, body: ArrayBuffer, recycle?, fatal?}
 *       body is transferred, never copied twice. recycle: a MemoryError was handled; replace this
 *       worker (a WebAssembly heap never shrinks). fatal: the interpreter is unusable; replace it.
 *
 * No eval / new Function here. Python source is executed by the interpreter (runPython), which the
 * page's CSP does not govern; WebAssembly compilation needs 'wasm-unsafe-eval' and nothing more.
 */

let pyodide = null;
let glue = null;
let fatal = false;

const post = (msg, transfer) => self.postMessage(msg, transfer || []);
const now = () => performance.now();

function jsonError(status, code, message) {
  const body = new TextEncoder().encode(JSON.stringify({ error: message, code }));
  return { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }, body: body.buffer };
}

/** Fetch `url` fully, reporting progress; returns an ArrayBuffer. */
async function fetchWithProgress(url, onBytes) {
  const res = await fetch(url, { credentials: 'same-origin' });
  if (!res.ok) throw new Error(`${new URL(url).pathname} answered HTTP ${res.status}`);
  if (!res.body || !res.body.getReader) {
    const buf = await res.arrayBuffer();
    onBytes(buf.byteLength);
    return buf;
  }
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.byteLength;
    onBytes(value.byteLength);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out.buffer;
}

/** Warm the HTTP cache for the runtime files with byte-level progress, without keeping them. */
async function prefetch(list, onBytes) {
  await Promise.all(list.map(async ({ url }) => {
    const res = await fetch(url, { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`${new URL(url).pathname} answered HTTP ${res.status}`);
    if (!res.body || !res.body.getReader) {
      onBytes((await res.arrayBuffer()).byteLength);
      return;
    }
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      onBytes(value.byteLength);
    }
  }));
}

async function sha256Hex(buf) {
  if (!self.crypto || !self.crypto.subtle) return null; // not a secure context; integrity check skipped
  const digest = await self.crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function init(msg) {
  const t0 = now();
  const timings = {};
  const total = (msg.prefetch || []).reduce((n, f) => n + (f.size || 0), 0) + (msg.bundle.size || 0);
  let loaded = 0;
  let lastSent = 0;
  const progress = (stage, force) => {
    const t = now();
    if (!force && t - lastSent < 100) return;
    lastSent = t;
    post({ type: 'progress', loaded: Math.min(loaded, total), total, stage });
  };
  const onBytes = (n) => {
    loaded += n;
    progress('download', false);
  };
  progress('download', true);

  // 1. Runtime files and the engine bundle, in parallel. The runtime files only warm the cache
  //    (Pyodide fetches them itself right after); the bundle is kept.
  const [, bundle] = await Promise.all([
    prefetch(msg.prefetch || [], onBytes),
    fetchWithProgress(msg.bundle.url, onBytes),
  ]);
  timings.download = Math.round(now() - t0);
  if (msg.bundle.sha256) {
    const got = await sha256Hex(bundle);
    if (got && got !== msg.bundle.sha256) throw new Error('The engine bundle failed its integrity check. Reload the page.');
  }

  // 2. The interpreter.
  progress('runtime', true);
  const t1 = now();
  const { loadPyodide } = await import(msg.pyodide.module);
  pyodide = await loadPyodide({
    indexURL: msg.pyodide.indexURL,
    // Never fall back to a CDN for packages: none are used, and none may be fetched from elsewhere.
    packageBaseUrl: msg.pyodide.indexURL,
    lockFileURL: msg.pyodide.indexURL + 'pyodide-lock.json',
    fullStdLib: false,
    stdout: (line) => console.log('[engine]', line),
    stderr: (line) => console.warn('[engine]', line),
  });
  timings.runtime = Math.round(now() - t1);

  // 3. The backend: unpack the bundle into the in-memory filesystem and build the router.
  progress('engine', true);
  const t2 = now();
  pyodide.unpackArchive(bundle, 'zip', { extractDir: '/app' });
  pyodide.runPython('import sys\nif "/app" not in sys.path:\n    sys.path.insert(0, "/app")');
  glue = pyodide.pyimport('bs_wasm_glue');
  glue.init(JSON.stringify(msg.overrides || {}), '/app');
  timings.engine = Math.round(now() - t2);
  timings.total = Math.round(now() - t0);
  let stats = {};
  try {
    stats = JSON.parse(glue.stats());
  } catch {
    stats = {};
  }
  post({ type: 'ready', timings, stats, version: pyodide.version, heap: heapBytes() });
}

/** Size of the WebAssembly heap (it only ever grows), for diagnostics; null if not exposed. */
function heapBytes() {
  try {
    const mod = pyodide && pyodide._module;
    return mod && mod.HEAPU8 ? mod.HEAPU8.byteLength : null;
  } catch {
    return null;
  }
}

function serve(msg) {
  if (fatal || !glue) {
    const e = jsonError(503, 'internal', 'The analysis engine is not available.');
    post({ type: 'response', id: msg.id, ...e }, [e.body]);
    return;
  }
  let result = null;
  let bodyProxy = null;
  try {
    // undefined, not null: Pyodide maps JS null to jsnull, undefined to None.
    const body = msg.body ? new Uint8Array(msg.body) : undefined;
    result = glue.handle(msg.method, msg.route, JSON.stringify(msg.query || {}), JSON.stringify(msg.headers || {}), body);
    const status = result.get(0);
    const headers = JSON.parse(result.get(1));
    bodyProxy = result.get(2);
    let out;
    const view = bodyProxy.getBuffer('u8');
    try {
      out = view.data.slice().buffer; // the one copy out of the WebAssembly heap
    } finally {
      view.release();
    }
    const recycle = Boolean(glue.should_recycle());
    post({ type: 'response', id: msg.id, status, headers, body: out, recycle, heap: heapBytes() }, [out]);
  } catch (err) {
    // A Python exception cannot get here (the router never raises). This is the interpreter itself
    // failing (out of WebAssembly memory, stack exhaustion) or a JS allocation failure.
    const message = String((err && err.message) || err).slice(0, 300);
    const oom = /memory|allocation|RangeError/i.test(message) || (err && err.name === 'RangeError');
    const e = oom
      ? jsonError(507, 'out_of_memory', 'This file needs more memory than this browser tab can give the analysis engine. The engine has been restarted. Try a smaller file, or run BinaryStudio locally for very large binaries.')
      : jsonError(500, 'internal', 'The analysis engine failed while handling this request and has been restarted.');
    fatal = true;
    post({ type: 'response', id: msg.id, ...e, fatal: message }, [e.body]);
  } finally {
    try {
      if (bodyProxy) bodyProxy.destroy();
      if (result) result.destroy();
    } catch {
      /* the interpreter may already be gone */
    }
  }
}

self.onmessage = (event) => {
  const msg = event.data || {};
  if (msg.type === 'init') {
    init(msg).catch((err) => {
      fatal = true;
      post({ type: 'init-failed', message: String((err && err.message) || err).slice(0, 300) });
    });
  } else if (msg.type === 'request') {
    serve(msg);
  }
};
