/**
 * BinaryStudio static build: the in-browser transport.
 *
 * Loaded only in the static build (tools/build_static.py injects it into dist/index.html as the
 * first feature script). It installs BS.api.setTransport(...) so every API request the core and
 * the feature files make is answered by the Python engine running in a Web Worker
 * (engine-worker.js) instead of a server. Nothing leaves the browser.
 *
 *  - /api/config and /api/presets are answered at once from the build manifest, so the shell
 *    boots and is usable before the engine has loaded. Every other route goes to the worker,
 *    generically: new endpoints registered in backend/api.py work without changes here.
 *  - Requests made before the engine is ready wait in a queue; they never fail for that reason.
 *  - One request at a time is in the worker (Python is single threaded anyway). The queue lives
 *    here, so an aborted request that has not started never reaches the engine, and a request
 *    that kills the engine is known exactly.
 *  - Large bodies are copied once and transferred; responses are transferred back.
 *  - If the worker dies (out of memory, interpreter failure, watchdog), the request in flight
 *    gets a contract-shaped error, the worker is restarted, queued requests continue, and the
 *    user is told in one plain sentence. Documents opened earlier come back through the core's
 *    410 doc_expired re-upload path.
 *  - A long analysis can be stopped (status-bar button, or "Stop the running analysis" in the
 *    command palette): the worker is terminated and restarted. The page never blocks.
 *
 * The build replaces the manifest placeholder below with JSON. No eval / new Function.
 */
(() => {
  'use strict';

  const MANIFEST = /*@@BS_WASM_MANIFEST@@*/ null;
  const BS = window.BinaryStudio;
  if (!BS || !BS.api || typeof BS.api.setTransport !== 'function' || !MANIFEST) return;

  const abs = (p) => new URL(p, document.baseURI).href;
  const enc = new TextEncoder();
  const BUSY_NOTICE_MS = 1200;           // show "Working… Stop" only for requests slower than this
  const MAX_INIT_FAILURES = 3;           // consecutive start-up failures before giving up
  const HARD_TIMEOUT_MS = Math.max(30, Number(MANIFEST.hardTimeoutSeconds) || 150) * 1000;
  const OPEN_ROUTES = /^\/api\/(upload|parse)$/; // failures of these are shown by the core
  const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };

  const jsonResponse = (status, payload) => ({ status, headers: Object.assign({}, JSON_HEADERS), body: enc.encode(JSON.stringify(payload)) });
  const errorResponse = (status, code, message) => jsonResponse(status, { error: message, code });
  const abortError = () => new DOMException('The request was aborted.', 'AbortError');

  // Static answers (the same payloads the router gives in wasm mode, computed at build time).
  const STATIC_ROUTES = {
    '/api/config': () => jsonResponse(200, MANIFEST.config),
    '/api/presets': () => jsonResponse(200, { presets: MANIFEST.presets }),
  };

  // =========================================================================
  // Engine: worker lifecycle, queue, watchdog
  // =========================================================================
  const engine = {
    worker: null,
    state: 'idle',         // idle | loading | ready | restarting | failed
    queue: [],
    inflight: null,
    seq: 0,
    initFailures: 0,
    failure: '',
    progress: { loaded: 0, total: 0, stage: '' },
    timings: { scriptStart: performance.now(), workerStart: null, ready: null, firstReady: null, restarts: 0, lastInit: null },
    version: null,
    stats: null,
    heapBytes: null,
  };

  function startWorker() {
    engine.state = engine.timings.firstReady === null ? 'loading' : 'restarting';
    engine.progress = { loaded: 0, total: 0, stage: 'download' };
    engine.timings.workerStart = performance.now();
    let worker;
    try {
      worker = new Worker(abs(MANIFEST.worker), { type: 'module', name: 'binarystudio-engine' });
    } catch (err) {
      initFailed(`This browser cannot start the analysis engine (${String((err && err.message) || err)}).`, true);
      return;
    }
    engine.worker = worker;
    worker.onmessage = (ev) => onWorkerMessage(worker, ev.data || {});
    worker.onerror = (ev) => {
      if (worker !== engine.worker) return;
      ev.preventDefault();
      const msg = ev.message || 'the engine script failed to load';
      if (engine.state === 'ready') crash(`The analysis engine stopped unexpectedly (${msg}).`);
      else initFailed(`The analysis engine could not start (${msg}).`);
    };
    worker.onmessageerror = () => {
      if (worker === engine.worker) crash('The analysis engine sent a message the page could not read.');
    };
    worker.postMessage({
      type: 'init',
      pyodide: { module: abs(MANIFEST.pyodide.module), indexURL: abs(MANIFEST.pyodide.indexURL) },
      bundle: { url: abs(MANIFEST.bundle.url), sha256: MANIFEST.bundle.sha256, size: MANIFEST.bundle.size },
      prefetch: (MANIFEST.prefetch || []).map((f) => ({ url: abs(f.url), size: f.size })),
      overrides: MANIFEST.overrides || {},
    });
    render();
  }

  function stopWorker() {
    const w = engine.worker;
    engine.worker = null;
    if (w) {
      w.onmessage = null;
      w.onerror = null;
      w.onmessageerror = null;
      try {
        w.terminate();
      } catch {
        /* already gone */
      }
    }
  }

  function onWorkerMessage(worker, msg) {
    if (worker !== engine.worker) return; // a terminated worker's last words
    switch (msg.type) {
      case 'progress':
        engine.progress = { loaded: msg.loaded || 0, total: msg.total || 0, stage: msg.stage || '' };
        render();
        break;
      case 'ready': {
        const t = performance.now();
        engine.state = 'ready';
        engine.initFailures = 0;
        engine.version = msg.version || null;
        engine.stats = msg.stats || null;
        engine.heapBytes = typeof msg.heap === 'number' ? msg.heap : null;
        engine.timings.ready = t;
        engine.timings.lastInit = Object.assign({ wall: Math.round(t - engine.timings.workerStart) }, msg.timings || {});
        if (engine.timings.firstReady === null) {
          engine.timings.firstReady = t;
          registerServiceWorker();
        }
        render();
        pump();
        break;
      }
      case 'init-failed':
        initFailed(`The analysis engine could not start: ${msg.message || 'unknown error'}.`);
        break;
      case 'response':
        onResponse(msg);
        break;
      default:
        break;
    }
  }

  function onResponse(msg) {
    const job = engine.inflight;
    if (typeof msg.heap === 'number') engine.heapBytes = Math.max(engine.heapBytes || 0, msg.heap);
    const replace = msg.fatal ? 'fatal' : msg.recycle ? 'memory' : null;
    // Stop the queue before answering, so nothing is handed to a worker that is about to go.
    if (replace) engine.state = 'restarting';
    if (job && job.id === msg.id) {
      finish(job, { status: msg.status, headers: msg.headers || {}, body: msg.body ? new Uint8Array(msg.body) : new Uint8Array(0) });
    }
    // The core reports a failed open itself; say something only for other requests.
    if (msg.status === 507 && !(job && OPEN_ROUTES.test(job.route))) {
      BS.ui.toast('The analysis engine ran out of memory and was restarted. Files you had open reopen automatically.', 'warn');
    }
    // A MemoryError was handled cleanly, but the WebAssembly heap never shrinks: start fresh.
    if (replace) restart(replace === 'fatal' && msg.status !== 507 ? 'fatal' : 'memory');
  }

  function finish(job, res) {
    if (engine.inflight === job) engine.inflight = null;
    clearTimeout(job.busyTimer);
    clearTimeout(job.hardTimer);
    if (job.signal && job.onAbort) job.signal.removeEventListener('abort', job.onAbort);
    if (!job.settled) {
      job.settled = true;
      job.resolve(res);
    }
    render();
    pump();
  }

  function pump() {
    if (engine.state !== 'ready' || engine.inflight || !engine.worker) return;
    const job = engine.queue.shift();
    if (!job) return;
    engine.inflight = job;
    job.started = performance.now();
    job.busyTimer = setTimeout(render, BUSY_NOTICE_MS);
    job.hardTimer = setTimeout(() => {
      if (engine.inflight !== job) return;
      engine.state = 'restarting'; // hold the queue: nothing more goes to this worker
      finish(job, errorResponse(422, 'timeout', 'The analysis engine stopped responding on this request and was restarted. The file may be malformed or too large for this browser.'));
      restart('watchdog');
    }, HARD_TIMEOUT_MS);
    const transfer = job.body ? [job.body] : [];
    try {
      engine.worker.postMessage({ type: 'request', id: job.id, method: job.method, route: job.route, query: job.query, headers: job.headers, body: job.body }, transfer);
    } catch (err) {
      finish(job, errorResponse(500, 'internal', `The request could not be handed to the analysis engine (${String((err && err.message) || err)}).`));
      return;
    }
    job.body = null; // transferred
    render();
  }

  /** The engine died while handling the request in flight. */
  function crash(reason) {
    engine.state = 'restarting';
    const job = engine.inflight;
    if (job) finish(job, errorResponse(500, 'internal', `${reason} It has been restarted; files you had open reopen automatically.`));
    restart('crash');
  }

  /** Terminate and start again. The request in flight (if any) must already be answered. */
  function restart(why) {
    engine.state = 'restarting'; // hold the queue: nothing more goes to the worker being replaced
    const job = engine.inflight;
    if (job) {
      const message = why === 'memory' || why === 'fatal'
        ? 'The analysis engine had to be restarted while handling this request.'
        : 'The analysis engine was restarted while handling this request.';
      finish(job, errorResponse(500, 'internal', message));
    }
    stopWorker();
    engine.timings.restarts += 1;
    if (why === 'fatal' || why === 'crash') {
      BS.ui.toast('The analysis engine stopped and has been restarted. Files you had open reopen automatically.', 'warn');
    } else if (why === 'watchdog') {
      BS.ui.toast('The analysis engine stopped responding and has been restarted.', 'warn');
    }
    startWorker();
  }

  function initFailed(message, permanent) {
    stopWorker();
    engine.initFailures += 1;
    if (!permanent && engine.initFailures < MAX_INIT_FAILURES) {
      setTimeout(startWorker, 500 * engine.initFailures);
      return;
    }
    engine.state = 'failed';
    engine.failure = message;
    const pending = engine.queue.splice(0);
    if (engine.inflight) pending.unshift(engine.inflight);
    engine.inflight = null;
    pending.forEach((job) => finish(job, errorResponse(503, 'internal', `${message} Reload the page to try again.`)));
    BS.ui.toast(`${message} Reload the page to try again.`, 'error');
    render();
  }

  /** User-initiated: stop whatever the engine is doing. */
  function cancel() {
    const job = engine.inflight;
    if (!job) return false;
    engine.state = 'restarting';
    finish(job, errorResponse(499, 'cancelled', 'Stopped. The analysis engine was restarted; files you had open reopen automatically.'));
    engine.timings.restarts += 1;
    stopWorker();
    startWorker();
    if (!OPEN_ROUTES.test(job.route)) BS.ui.toast('Analysis stopped.', 'info');
    return true;
  }

  // =========================================================================
  // The transport installed into the core
  // =========================================================================
  function transport({ method, route, query, body, headers, signal }) {
    const m = String(method || 'GET').toUpperCase();
    if (m === 'GET' && Object.prototype.hasOwnProperty.call(STATIC_ROUTES, route)) {
      return Promise.resolve(STATIC_ROUTES[route]());
    }
    if (signal && signal.aborted) return Promise.reject(abortError());
    if (engine.state === 'failed') {
      return Promise.resolve(errorResponse(503, 'internal', `${engine.failure} Reload the page to try again.`));
    }
    let buffer = null;
    if (body && body.byteLength) {
      // One copy: the caller may keep its bytes (the core does, to re-upload after a restart),
      // so they cannot be transferred themselves. The copy is transferred, never cloned again.
      buffer = body.slice().buffer;
    }
    const lowered = {};
    Object.entries(headers || {}).forEach(([k, v]) => {
      lowered[String(k).toLowerCase()] = String(v);
    });
    return new Promise((resolve, reject) => {
      const job = {
        id: ++engine.seq, method: m, route, query: Object.assign({}, query), headers: lowered, body: buffer,
        resolve, signal, settled: false, started: 0, busyTimer: 0, hardTimer: 0, onAbort: null,
      };
      if (signal) {
        job.onAbort = () => {
          const i = engine.queue.indexOf(job);
          if (i >= 0) engine.queue.splice(i, 1);
          // A request already in the engine runs to completion (it cannot be interrupted without
          // restarting the engine); its answer is simply dropped.
          if (!job.settled) {
            job.settled = true;
            reject(abortError());
          }
        };
        signal.addEventListener('abort', job.onAbort, { once: true });
      }
      engine.queue.push(job);
      pump();
      render();
    });
  }

  BS.api.setTransport(transport);

  // =========================================================================
  // Quiet status in the status bar
  // =========================================================================
  let chip = null;
  let label = null;
  let stopBtn = null;

  function ensureChip() {
    if (chip) return chip;
    const right = document.querySelector('.status-right');
    if (!right) return null;
    chip = document.createElement('span');
    chip.className = 'status-item engine-status';
    chip.id = 'engine-status';
    chip.setAttribute('role', 'status');
    chip.setAttribute('aria-live', 'polite');
    label = document.createElement('span');
    label.className = 'engine-status-label';
    stopBtn = document.createElement('button');
    stopBtn.type = 'button';
    stopBtn.className = 'engine-stop';
    stopBtn.textContent = 'Stop';
    stopBtn.title = 'Stop the running analysis (restarts the engine)';
    stopBtn.hidden = true;
    stopBtn.addEventListener('click', cancel);
    chip.append(label, stopBtn);
    const mode = document.getElementById('status-mode');
    right.insertBefore(chip, mode || null);
    return chip;
  }

  function longRunning() {
    const job = engine.inflight;
    return Boolean(job && performance.now() - job.started >= BUSY_NOTICE_MS - 5);
  }

  function render() {
    if (!ensureChip()) return;
    let text = '';
    let title = '';
    let kind = '';
    const p = engine.progress;
    if (engine.state === 'loading' || engine.state === 'restarting') {
      const pct = p.total ? Math.min(99, Math.floor((100 * p.loaded) / p.total)) : 0;
      const verb = engine.state === 'restarting' ? 'Engine restarting' : 'Engine loading';
      text = p.stage === 'download' && p.total ? `${verb} ${pct}%` : `${verb}…`;
      title = `Loading the analysis engine (Python in WebAssembly, ${BS.util.formatBytes(p.total || MANIFEST.runtimeBytes || 0)}) into this tab. It is cached after the first visit. Requests wait until it is ready.`;
      kind = 'loading';
    } else if (engine.state === 'failed') {
      text = 'Engine unavailable';
      title = engine.failure;
      kind = 'error';
    } else if (engine.state === 'ready' && longRunning()) {
      text = engine.queue.length ? `Working… (${engine.queue.length} waiting)` : 'Working…';
      title = 'The analysis engine is busy with a long request. Stop restarts it.';
      kind = 'busy';
    }
    chip.dataset.state = kind;
    label.textContent = text;
    chip.title = title;
    chip.hidden = !text;
    stopBtn.hidden = kind !== 'busy';
  }

  // =========================================================================
  // Commands, offline support, introspection
  // =========================================================================
  BS.registerCommand({
    id: 'engine.stop',
    title: 'Stop the running analysis',
    hint: 'Restarts the in-browser engine',
    keywords: 'cancel abort engine wasm',
    section: 'Engine',
    when: () => longRunning(),
    run: () => cancel(),
  });
  BS.registerCommand({
    id: 'engine.restart',
    title: 'Restart the analysis engine',
    hint: 'Frees its memory; open files reopen automatically',
    keywords: 'engine wasm memory reset',
    section: 'Engine',
    run: () => {
      if (engine.inflight) cancel();
      else restart('user');
    },
  });

  function registerServiceWorker() {
    if (!MANIFEST.serviceWorker || !('serviceWorker' in navigator) || !window.isSecureContext) return;
    // Registered only after the engine is up, so it never competes with the first load.
    navigator.serviceWorker.register(abs(MANIFEST.serviceWorker), { scope: './' }).catch((err) => {
      console.warn('[BinaryStudio] offline support unavailable:', err && err.message);
    });
  }

  window.BinaryStudioEngine = Object.freeze({
    get state() { return engine.state; },
    get queued() { return engine.queue.length; },
    get busy() { return Boolean(engine.inflight); },
    get version() { return engine.version; },
    get stats() { return engine.stats; },
    get heapBytes() { return engine.heapBytes; },  // high-water mark of this worker's WebAssembly memory
    timings: () => JSON.parse(JSON.stringify(engine.timings)),
    build: () => ({ transport: (document.querySelector('script[src*="transport."]') || {}).src || null, pyodide: MANIFEST.pyodide.version, bundle: MANIFEST.bundle.sha256 }),
    cancel,
    restart: () => restart('user'),
  });

  // Start loading at once: the shell renders meanwhile from the static config.
  startWorker();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', render, { once: true });
})();
