/**
 * BinaryStudio — core shell: state, API client, tree, inspector views, hex pane, palette.
 * Mach-O (thin / universal), ELF32/64, PE32/PE32+. Vanilla ES2020, no build step, no dependencies.
 *
 * This file is the core. Features (Learn, Labs, the WASM build, ads) live in separate files under
 * static/js/ loaded by <script defer> after this one, and talk to the core ONLY through the
 * extension API below. Everything else in this IIFE is private and may change.
 *
 * =====================================================================================================
 * EXTENSION API — window.BinaryStudio (alias window.BS)
 * =====================================================================================================
 * The object exists as soon as this script has executed. The core boots on DOMContentLoaded, i.e.
 * after every deferred feature script has run, so a feature script may call registerView /
 * registerCommand / api.setTransport at its top level and they take effect before the first request.
 *
 * BS.version                  string
 * BS.config                   the /api/config payload, or null until it has loaded (always set before
 *                             'ready'). If the server has no /api/config (v1 backend) a local-mode
 *                             default is assumed and BS.config.assumed === true.
 * BS.state                    live core state (read it, do not replace it). Stable fields:
 *                               doc, docId, activeSliceIndex, cursorOffset, selectedNodeId, viewParams,
 *                               structSpan, fieldSpan ({abs_offset,size,label} | null), theme ('light'|'dark'),
 *                               learnMode (bool), hexDock, hexAddrMode, decoderEndian, presets.
 *                             docId is null when no document is open or the backend predates doc ids.
 * BS.getActiveSlice()         the active slice object of BS.state.doc, or null.
 *
 * --- HTTP / RPC ---------------------------------------------------------------------------------------
 * BS.api.get(route, params?, opts?)         -> Promise<json>
 * BS.api.post(route, body?, params?, opts?) -> Promise<json>
 * BS.api.getBytes(route, params?, opts?)    -> Promise<Uint8Array>
 *     route   starts with '/', e.g. '/api/hex'.
 *     params  plain object -> query string. While a document is open, `doc` and `slice_index` are
 *             added automatically (except for /api/config, /api/presets, /api/upload, /api/parse).
 *             Pass your own value to override either one, or null to omit it.
 *     body    plain object / array (sent as JSON) | Uint8Array | ArrayBuffer | Blob (sent as
 *             application/octet-stream). `doc` is NOT injected into a JSON body; put it there yourself
 *             if the endpoint wants it (e.g. /api/patch): {doc: BS.state.docId, ...}.
 *     opts    {signal?: AbortSignal, headers?: object}
 *     Errors  rejects with BS.ApiError {status, code, message}. code is the server's machine code
 *             (bad_request, not_found, doc_expired, too_large, rate_limited, forbidden, parse_failed,
 *             timeout, internal) or 'network' (status 0) / 'bad_response'. An aborted request rejects
 *             with the usual AbortError DOMException instead.
 *     410 doc_expired is handled for you: if the expired id is the open document (or one still in
 *             the back/forward cache) and the core can re-create it (it holds the uploaded bytes, or
 *             the doc is a preset / path), it re-uploads, swaps the id (in the query and in a JSON
 *             body's top-level `doc`), retries once and emits 'doc:renewed'. Otherwise the ApiError
 *             propagates and 'doc:expired' is emitted. Bytes are held for the open document, and
 *             for up to two previous ones only if they are 16 MiB or smaller.
 * BS.api.setTransport(fn | null)
 *     fn({method, route, query, body, headers, signal}) -> Promise<{status, headers, body}>
 *     query: object of strings; request body: Uint8Array | null; request headers: object;
 *     response headers: object with lower-cased keys; response body: Uint8Array (ArrayBuffer and
 *     string are also accepted). null restores the default fetch transport. Used by the WASM build.
 * BS.api.baseUrl              default document.baseURI; routes are resolved relative to it.
 * BS.ApiError                 class (extends Error).
 *
 * --- Events -------------------------------------------------------------------------------------------
 * BS.on(event, fn) -> unsubscribe fn      BS.off(event, fn)      BS.emit(event, detail)
 *   'ready'            {config}            core initialised; config + presets loaded. Sticky: a
 *                                          listener added later is called on the next microtask.
 *   'doc:loaded'       {doc, docId}        a document became active (also when returning to one via
 *                                          back/forward). Hex decorations are cleared just before.
 *   'doc:closed'       {}                  no document is open any more.
 *   'doc:renewed'      {oldId, docId}      the server dropped the doc and it was re-uploaded.
 *   'doc:expired'      {docId}             the server dropped the doc and it could not be re-created.
 *   'slice:changed'    {index, slice}
 *   'cursor:changed'   {absOffset}
 *   'selection:changed' {span}             fieldSpan changed ({abs_offset,size,label} | null).
 *   'node:selected'    {id}                a tree node / view was opened.
 *   'view:rendered'    {id, bodyEl}        inspector content for node `id` is in the DOM (fires again
 *                                          when a built-in view re-renders after async data arrives).
 *   'theme:changed'    {theme}             'light' | 'dark' (resolved, never 'system').
 *   'learnmode:changed' {on}
 *   A listener that throws is logged and does not affect other listeners or the core.
 *
 * --- Views --------------------------------------------------------------------------------------------
 * BS.registerView({id, title, badge?, icon?, group?, order?, requiresDoc?, subtitle?, render, dispose?})
 *     -> {unregister(), update(partial)}
 *   Adds a node to the left tree under `group` and an inspector view. Groups render in this order:
 *   'Analysis' (the built-in structure nodes; extra views are appended), 'Learn', 'Labs', any other
 *   name in registration order, 'Help' last. Empty groups are not shown.
 *     id           unique string; use a prefix ('learn.', 'labs.'). It is the node id used by
 *                  BS.nav, history and deep links (#view=<id>).
 *     title        tree label and inspector title.     subtitle  optional inspector subtitle.
 *     badge        optional short text shown right-aligned in the tree row (e.g. a count).
 *     icon         optional 2-3 letter tag shown before the label (default: initials of the title).
 *     order        sort key inside the group (default 1000; lower first; ties by title).
 *     requiresDoc  true -> the node exists only while a document is open (default false).
 *     render(bodyEl, ctx)   fill bodyEl (an empty, scrollable flex column). May return a Promise.
 *                  ctx = {id, params, doc, docId, slice, sliceIndex, bodyEl, setSubtitle(text)}.
 *                  Called again when the active slice or document changes while the view is open,
 *                  and on BS.nav.openView for the same id (params may differ).
 *     dispose()    called before the view is replaced or re-rendered. Release timers/listeners here.
 *   A throwing render shows an error card in the inspector; it never breaks the shell.
 *
 * --- Commands -----------------------------------------------------------------------------------------
 * BS.registerCommand({id, title, hint?, keywords?, shortcut?, section?, when?, run}) -> {unregister()}
 *   Appears in the Cmd/Ctrl+K palette. A query starting with '>' shows commands only; otherwise
 *   matching commands are listed after views and before search hits.
 *     shortcut   'Mod+K', 'Shift+C', 'Alt+C', 'G', '?', '['  (Mod = Cmd on macOS, Ctrl elsewhere),
 *                or an array of those. Bare-key shortcuts never fire while focus is in an input,
 *                textarea, select or contenteditable, nor while a dialog is open.
 *     section    heading used in the keyboard reference (default 'Commands').
 *     when()     optional predicate; false hides the command and disables its shortcut.
 *     run()      may return a Promise; a rejection is reported as a toast.
 * BS.commands.run(id)         run a command by id (respects when()). -> Promise<boolean>
 * BS.commands.list(opts?)     [{id, title, hint, shortcut, section}] currently enabled; {all: true} also
 *                             includes commands whose when() is false right now.
 *
 * --- Navigation ---------------------------------------------------------------------------------------
 * BS.nav.openView(id, params?)        select a tree node / registered view. params is a flat object of
 *                                     strings/numbers; it is stored in history and in the URL hash
 *                                     (#view=<id>&p.<key>=<value>) and comes back as ctx.params (strings).
 * BS.nav.selectNode(id)               same as openView without params. Both return false if no such node.
 * BS.nav.jumpToOffset(absOffset, size?, label?)   move the cursor, highlight [absOffset, +size), scroll
 *                                     the hex view there and record a history entry.
 * BS.nav.jumpToVmaddr(vmaddr)         number | bigint | '0x…' string -> Promise<boolean> (false if unmapped).
 * BS.nav.back() / BS.nav.forward()
 * BS.nav.permalink()                  URL of the current view. Uploaded documents are never encoded
 *                                     (their ids are capabilities); such links restore the view only.
 *
 * --- Documents ----------------------------------------------------------------------------------------
 * BS.loadDocument(doc, opts?)         adopt a Document returned by the API (must carry doc_id on a v2
 *                                     server). opts: {keepView?: bool — stay on the current view and
 *                                     cursor instead of going to Overview; bytes?: Uint8Array and
 *                                     filename?: string — lets the core re-upload after doc_expired;
 *                                     replace?: bool — the document takes the place of the active one
 *                                     (a patched copy of it): no history entry is added, history entries
 *                                     of the replaced document now point at this one, with keepView the
 *                                     hex scroll position and selection also stay, and a replaced document
 *                                     that was itself adopted through loadDocument is forgotten}.
 *                                     Passing the very object of a document that is still in the
 *                                     back/forward cache re-activates it with its original source.
 * BS.loadBytes(filename, uint8array)  upload + open -> Promise<doc | null> (null: rejected or failed;
 *                                     the user has been told why).
 * BS.openPreset(id)                   open a sample by preset id -> Promise<doc | null>.
 * BS.closeDocument()
 *
 * --- Hex pane -----------------------------------------------------------------------------------------
 * BS.hex.getBytes(absOffset, length)  -> Promise<Uint8Array> (clamped to the file; max 4 MiB per call).
 * BS.hex.setDecorations(key, list)    list: [{abs_offset, size, className, title?}] — an extra highlight
 *                                     layer. className: space-separated CSS classes ([A-Za-z0-9_-] only)
 *                                     added to each covered byte cell (style them in your own CSS,
 *                                     e.g. `.hex-byte.labs-patched`). Empty list or null removes the layer.
 *                                     All layers are cleared when another document becomes active.
 * BS.hex.onByteActivate(fn)           fn({absOffset, byte, event}) on double-click / Enter on a byte.
 *                                     event is the second `click` (detail === 2) or the `keydown`.
 *                                     byte is null if not loaded yet. Returns an unsubscribe fn.
 * BS.hex.refresh()                    drop cached bytes and redraw (after the bytes changed server-side).
 *
 * --- UI -----------------------------------------------------------------------------------------------
 * BS.ui.toast(message, kind?)         kind: 'info' | 'ok' | 'warn' | 'error'. Plain text only.
 * BS.ui.modal({title, bodyEl | text, onClose?, className?}) -> {close(), el, bodyEl}
 *                                     Focus is trapped and restored; Escape / backdrop click closes.
 *                                     bodyEl: a DOM node you built; text: a plain string shown as a
 *                                     paragraph. There is no markup option.
 * BS.ui.status(text, mode?)           status-bar text. mode: 'ready' | 'loading' | 'error'.
 * BS.ui.addToolbarButton({id, label, title?, pressed?, onClick}) -> {el, setPressed(bool), setLabel(text), remove()}
 *                                     adds a quiet text button to the toolbar's extension area
 *                                     (#toolbar-ext, left of Search). `pressed` given -> a toggle (aria-pressed).
 * BS.ui.slot(name)                    -> {el, show(heightPx), hide()} | null. One optional container
 *                                     exists: 'footer', a full-width strip under the status bar. It is
 *                                     display:none until show(); show() reserves a fixed height so later
 *                                     content cannot shift the layout. Reserved at boot when
 *                                     config.ads.enabled && config.ads.slots.footer ({height}).
 * BS.ui.copy(text, label?)            copy to clipboard with a confirmation toast -> Promise<boolean>.
 * BS.learn.isOn() / set(bool) / toggle()   "Learn mode". Off (default) hides every element with class
 *                                     `learn-only`; on adds class `learn-on` to <html>. Persisted.
 *
 * --- Utilities ----------------------------------------------------------------------------------------
 * BS.util.hex(n, pad?)        0x-prefixed lower-case hex; strings starting 0x pass through.
 * BS.util.formatBytes(n)      '1.2 KB'
 * BS.util.escapeHtml(v)       -> string safe as HTML text and inside a quoted attribute (& < > " ' `).
 * BS.util.escapeAttr(v)       -> same, plus whitespace/= normalised for attribute values.
 * BS.util.html`...`           tagged template: every ${value} is HTML-escaped unless it is itself the
 *                             result of BS.util.html / BS.util.raw; arrays are concatenated. Assign the
 *                             result to innerHTML (it stringifies). Always quote attributes: a="${v}".
 * BS.util.raw(str)            mark a string you have already escaped as markup.
 * BS.util.debounce(fn, ms)
 * BS.storage.get(key, fallback) / BS.storage.set(key, value) / BS.storage.remove(key)
 *                             JSON values in localStorage under the 'binarystudio:' namespace; never throws.
 *
 * --- Security rules for feature code ------------------------------------------------------------------
 * Every string that came out of a binary (symbol, section, segment and library names, strings, paths,
 * PDB paths, entitlements, filenames) and every server error message is attacker-controlled.
 * Build DOM with textContent / createElement, or with BS.util.html. No inline event handlers, no
 * inline <script>, no eval / new Function, no javascript: URLs, no inline style="" attributes (the
 * page is served with script-src 'self' and should also work under style-src 'self'; set dynamic
 * styles through element.style). No requests to other origins.
 */

(() => {
  'use strict';

  const VERSION = '2.0.0';
  const HEX_ROW_HEIGHT = 21;
  const HEX_BYTES_PER_ROW = 16;
  const HEX_CHUNK_SIZE = 4096; // 256 rows per cached chunk
  const HEX_MAX_CHUNKS = 1024; // ~4 MiB of cached bytes
  const HEX_MAX_SCROLL_PX = 8000000; // above this the hex scrollbar is scaled (browsers cap element height)
  const VIRT_ROW_HEIGHT = 24;
  const BUSY_DELAY_MS = 150; // loading indicators appear only if work takes longer than this
  const INACTIVE_BYTES_LIMIT = 16 * 1024 * 1024; // uploads larger than this are not kept in memory once another document is open
  const NARROW_DOCK_PX = 1100; // below this width the hex pane always docks at the bottom
  const DRAWER_PX = 760; // below this width the tree becomes a drawer
  const IS_MAC = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '');

  // =========================================================================
  // Namespaced Storage (never throws)
  // =========================================================================
  const STORAGE_PREFIX = 'binarystudio:';
  const storage = {
    get(key, fallback) {
      try {
        const raw = window.localStorage.getItem(STORAGE_PREFIX + key);
        return raw === null ? fallback : JSON.parse(raw);
      } catch {
        return fallback;
      }
    },
    set(key, value) {
      try {
        window.localStorage.setItem(STORAGE_PREFIX + key, JSON.stringify(value));
        return true;
      } catch {
        return false;
      }
    },
    remove(key) {
      try {
        window.localStorage.removeItem(STORAGE_PREFIX + key);
      } catch {
        /* ignore */
      }
    },
  };

  const oneOf = (value, allowed, fallback) => (allowed.includes(value) ? value : fallback);
  const numIn = (value, min, max, fallback) => {
    const n = Number(value);
    return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
  };

  // =========================================================================
  // Application State Store
  // =========================================================================
  const state = {
    presets: [],
    doc: null,
    docId: null,       // opaque v2 doc id ('preset:…', 'u_…', 'p_…', 'path:…'); null on a v1 backend
    legacyPath: null,  // v1 backend only: the `path=` value that addresses the active file
    docSource: null,   // {kind: 'preset'|'path'|'upload'|'derived', presetId?, path?, filename?}
    docKey: null,      // key of the active record in the document cache
    activeSliceIndex: 0,

    // Tree Navigator
    treeNodesMap: new Map(), // id -> node descriptor (positional / built-in / registered ids only)
    treeNodeAliases: new Map(), // name-derived alias ('seg_<segname>', 'sect_<seg>_<sect>', 'header_0') -> node
    treeRootNodes: [],       // built-in "Analysis" nodes
    treeGroups: [],          // [{id, nodes}] in display order
    treeVisible: [],         // flattened visible rows, for keyboard navigation
    treeFocusIndex: -1,
    expandedNodeIds: new Set(['load_commands', 'segments']),
    collapsedGroups: new Set(storage.get('tree.collapsed', [])),
    selectedNodeId: null,
    viewParams: {},
    treeFilter: '',

    // Memory Map Ribbon
    memmapScale: oneOf(storage.get('memmap.scale'), ['sqrt', 'linear'], 'sqrt'),

    // Synchronized Selection & Spans (all coordinates in abs_offset)
    cursorOffset: 0,
    selAnchor: 0,
    structSpan: null, // { abs_offset, size, label }
    fieldSpan: null,  // { abs_offset, size, label }

    // Hex Viewer Cache & Modes
    hexDock: oneOf(storage.get('layout.dock'), ['right', 'bottom'], 'right'),
    hexAddrMode: oneOf(storage.get('hex.addrMode'), ['file', 'vm'], 'file'),
    hexChunks: new Map(), // chunkStartOffset -> Uint8Array
    hexPendingChunks: new Map(), // chunkStartOffset -> Promise
    hexDecorations: new Map(), // key -> [{abs_offset, size, className, title}]
    decoderEndian: oneOf(storage.get('hex.endian'), ['little', 'big'], 'little'),
    lastDecodeData: null,

    // Inspector Sub-View States
    symSearch: '',
    lcSearch: '',
    fnSearch: '',
    symScope: 'all', // 'all' | 'ext' | 'local' | 'undef'
    symDemangle: storage.get('sym.demangle', true) !== false,
    strSearch: '',
    strSourceFilter: 'all',
    csSubTab: 'summary', // 'summary' | 'entitlements' | 'slots' | 'fields'
    dyldSubTab: 'fixups', // 'fixups' | 'imports' | 'exports' | 'binds'
    disasmCache: new Map(), // key -> response
    activeDisasmSection: '',
    activeDisasmVmaddr: '',

    // Back / Forward Navigation History
    history: [],
    historyIndex: -1,
    suppressHistory: false,

    // Cmd+K Palette
    cmdkOpen: false,
    cmdkScope: 'all',
    cmdkResults: [],
    cmdkActiveIdx: 0,

    // Preferences
    themePref: oneOf(storage.get('theme'), ['system', 'light', 'dark'], 'system'),
    theme: 'dark',
    learnMode: storage.get('learn.on', false) === true,

    // Local mode: a path from a URL waiting for the user's go-ahead ({path, restore} | null).
    pendingPath: null,
  };

  let config = null;      // /api/config payload
  let docGeneration = 0;  // bumped whenever the active document changes; guards async results
  let renderToken = 0;    // bumped on every inspector render; guards async view content

  // =========================================================================
  // Theme (applied immediately so the first paint is already correct)
  // =========================================================================
  // Kept at module scope: a MediaQueryList that is garbage-collected silently drops its listeners.
  const schemeQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;

  function resolveTheme(pref) {
    if (pref === 'light' || pref === 'dark') return pref;
    // Ask afresh: a long-lived MediaQueryList can report a stale `matches` in a throttled tab.
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function applyTheme(pref, persist) {
    state.themePref = oneOf(pref, ['system', 'light', 'dark'], 'system');
    const theme = resolveTheme(state.themePref);
    const root = document.documentElement;
    if (state.themePref === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', state.themePref);
    root.style.colorScheme = theme;
    if (persist) storage.set('theme', state.themePref);
    const changed = theme !== state.theme;
    state.theme = theme;
    const btn = document.getElementById('btn-theme');
    if (btn) {
      const next = theme === 'dark' ? 'light' : 'dark';
      btn.title = `Switch to ${next} theme (T)`;
      btn.setAttribute('aria-label', `Switch to ${next} theme`);
    }
    if (changed) bus.emit('theme:changed', { theme });
  }

  // =========================================================================
  // Event Bus
  // =========================================================================
  const bus = (() => {
    const map = new Map();
    const sticky = new Map(); // event -> last detail, for one-shot lifecycle events
    return {
      on(event, fn) {
        if (typeof fn !== 'function') return () => {};
        if (!map.has(event)) map.set(event, new Set());
        map.get(event).add(fn);
        if (sticky.has(event)) {
          const detail = sticky.get(event);
          Promise.resolve().then(() => {
            if (map.get(event)?.has(fn)) safeCall(fn, detail, event);
          });
        }
        return () => bus.off(event, fn);
      },
      off(event, fn) {
        map.get(event)?.delete(fn);
      },
      emit(event, detail) {
        if (event === 'ready') sticky.set(event, detail);
        const set = map.get(event);
        if (!set) return;
        [...set].forEach((fn) => safeCall(fn, detail, event));
      },
    };
  })();

  function safeCall(fn, detail, label) {
    try {
      const r = fn(detail);
      if (r && typeof r.then === 'function') r.catch((err) => console.error(`[BinaryStudio] async listener for "${label}" failed:`, err));
    } catch (err) {
      console.error(`[BinaryStudio] listener for "${label}" failed:`, err);
    }
  }

  applyTheme(state.themePref, false);
  if (state.learnMode) document.documentElement.classList.add('learn-on');

  // =========================================================================
  // Utility Formatters
  // =========================================================================
  function hex(num, pad = 0) {
    if (num === null || num === undefined || Number.isNaN(num)) return '—';
    if (typeof num === 'string') {
      return num.startsWith('0x') || num.startsWith('0X') ? num.toLowerCase() : num;
    }
    if (typeof num === 'bigint') return (num < 0n ? '-0x' : '0x') + (num < 0n ? -num : num).toString(16).padStart(pad, '0');
    const n = Number(num);
    if (!Number.isFinite(n)) return '—';
    if (n < 0) return '-0x' + Math.abs(n).toString(16).padStart(pad, '0');
    return '0x' + n.toString(16).padStart(pad, '0');
  }

  function hexNoPrefix(num, pad = 8) {
    if (num === null || num === undefined || Number.isNaN(Number(num))) return '0'.repeat(pad);
    return Math.max(0, Number(num)).toString(16).toUpperCase().padStart(pad, '0');
  }

  function formatBytes(bytes) {
    if (bytes === null || bytes === undefined) return '0 B';
    const n = Number(bytes);
    if (!Number.isFinite(n)) return '—';
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  /** Finite number or fallback — for values that feed arithmetic, data-* numbers and styles. */
  function num(v, fallback = 0) {
    const n = typeof v === 'number' ? v : Number(v);
    return Number.isFinite(n) ? n : fallback;
  }

  function str(v, fallback = '') {
    return v === null || v === undefined ? fallback : String(v);
  }

  /** Reduce a value to a single safe CSS class token. */
  function tok(v) {
    return str(v).replace(/[^A-Za-z0-9_-]/g, '');
  }

  function plural(n, one, many) {
    return `${n} ${n === 1 ? one : many || one + 's'}`;
  }

  function truncate(text, max = 80) {
    const s = str(text);
    return s.length > max ? s.slice(0, max - 1) + '…' : s;
  }

  function debounce(fn, ms) {
    let t = null;
    const wrapped = function (...args) {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), ms);
    };
    wrapped.cancel = () => clearTimeout(t);
    return wrapped;
  }

  // -------------------------------------------------------------------------
  // HTML escaping. All markup in this file is built with the html`` tag, which
  // escapes every interpolated value; nothing derived from a binary or from the
  // server is ever concatenated into markup by hand.
  // -------------------------------------------------------------------------
  const ESCAPE_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };

  function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[&<>"'`]/g, (ch) => ESCAPE_MAP[ch]);
  }

  function escapeAttr(value) {
    return escapeHtml(value).replace(/[\u0000-\u001f\u007f=]/g, (ch) => `&#${ch.charCodeAt(0)};`);
  }

  class SafeHtml {
    constructor(markup) {
      this.markup = markup;
    }
    toString() {
      return this.markup;
    }
  }

  function htmlValue(v) {
    if (v === null || v === undefined || v === false || v === true) return '';
    if (v instanceof SafeHtml) return v.markup;
    if (Array.isArray(v)) return v.map(htmlValue).join('');
    return escapeHtml(v);
  }

  function html(strings, ...values) {
    let out = strings[0];
    for (let i = 0; i < values.length; i++) out += htmlValue(values[i]) + strings[i + 1];
    return new SafeHtml(out);
  }

  function raw(markup) {
    return new SafeHtml(str(markup));
  }

  /** Join SafeHtml / plain values with a separator, escaping the plain ones. */
  function joinHtml(items, sep = ' ') {
    return new SafeHtml(items.map(htmlValue).join(escapeHtml(sep)));
  }

  /**
   * Apply dynamic sizes that used to be inline style attributes (blocked under style-src 'self').
   * data-w / data-h are percentages, data-indent is a pixel padding-left.
   */
  function hydrateStyles(root) {
    if (!root) return;
    root.querySelectorAll('[data-w]').forEach((el) => {
      el.style.width = `${numIn(el.dataset.w, 0, 100, 0)}%`;
    });
    root.querySelectorAll('[data-h]').forEach((el) => {
      el.style.height = `${numIn(el.dataset.h, 0, 100, 0)}%`;
    });
    root.querySelectorAll('[data-indent]').forEach((el) => {
      el.style.paddingLeft = `${numIn(el.dataset.indent, 0, 400, 0)}px`;
    });
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function parseBigIntHex(val) {
    if (val === null || val === undefined) return 0n;
    if (typeof val === 'bigint') return val;
    if (typeof val === 'number') return Number.isFinite(val) ? BigInt(Math.trunc(val)) : 0n;
    const s = String(val).trim();
    if (!s) return 0n;
    try {
      return BigInt(s);
    } catch {
      return 0n;
    }
  }

  /** Parse user-typed offsets: 0x…, plain decimal, or bare hex containing a-f. */
  function parseOffsetInput(rawText) {
    const s = str(rawText).trim().replace(/_/g, '');
    if (!s) return null;
    let n;
    if (/^0x[0-9a-f]+$/i.test(s)) n = parseInt(s, 16);
    else if (/^[0-9]+$/.test(s)) n = parseInt(s, 10);
    else if (/^[0-9a-f]+h?$/i.test(s)) n = parseInt(s, 16);
    else return null;
    return Number.isSafeInteger(n) && n >= 0 ? n : null;
  }

  function protClass(protStr) {
    if (!protStr) return 'nil';
    const p = String(protStr).toLowerCase();
    if (p.includes('w') && p.includes('x')) return 'rwx';
    if (p.includes('x')) return 'rx';
    if (p.includes('w')) return 'rw';
    if (p.includes('r')) return 'ro';
    return 'nil';
  }

  function getActiveSlice() {
    if (!state.doc || !Array.isArray(state.doc.slices) || state.doc.slices.length === 0) {
      return null;
    }
    return state.doc.slices[state.activeSliceIndex] || state.doc.slices[0];
  }

  function fileSize() {
    return num(state.doc?.file_info?.file_size, 0);
  }

  function sliceFormat(slice) {
    const f = str(slice?.format).toUpperCase();
    if (f === 'ELF') return 'ELF';
    if (f === 'PE') return 'PE';
    return 'MACHO';
  }

  // =========================================================================
  // Status Bar, Busy Indicator, Toasts, Clipboard
  // =========================================================================
  function setStatus(text, mode = 'ready') {
    const dot = document.getElementById('status-dot');
    const txt = document.getElementById('status-text');
    if (txt) txt.textContent = str(text);
    if (dot) {
      dot.className = 'status-indicator';
      if (mode === 'loading') dot.classList.add('loading');
      if (mode === 'error') dot.classList.add('error');
    }
  }

  /** Show a loading state only if the work outlives BUSY_DELAY_MS, so fast responses never flicker. */
  const busy = (() => {
    let active = 0;
    return {
      start(text) {
        let shown = false;
        const timer = setTimeout(() => {
          shown = true;
          active++;
          setStatus(text, 'loading');
          document.getElementById('busy-bar')?.classList.add('active');
        }, BUSY_DELAY_MS);
        let finished = false;
        return (finalText, mode) => {
          if (finished) return;
          finished = true;
          clearTimeout(timer);
          if (shown) active = Math.max(0, active - 1);
          if (active === 0) document.getElementById('busy-bar')?.classList.remove('active');
          if (finalText !== undefined) setStatus(finalText, mode || 'ready');
          else if (shown && active === 0) setStatus('Ready', 'ready');
        };
      },
    };
  })();

  function toast(message, kind = 'info') {
    const region = document.getElementById('toast-region');
    if (!region) return;
    const k = oneOf(kind, ['info', 'ok', 'warn', 'error'], 'info');
    const node = el('div', `toast toast-${k}`);
    node.setAttribute('role', k === 'error' || k === 'warn' ? 'alert' : 'status');
    node.appendChild(el('span', 'toast-text', truncate(message, 400)));
    const close = el('button', 'toast-close', '×');
    close.type = 'button';
    close.setAttribute('aria-label', 'Dismiss');
    node.appendChild(close);
    const remove = () => node.remove();
    close.addEventListener('click', remove);
    region.appendChild(node);
    while (region.children.length > 4) region.firstElementChild.remove();
    setTimeout(remove, k === 'error' ? 9000 : k === 'warn' ? 7000 : 3200);
  }

  async function copyText(text, label) {
    const value = str(text);
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
        ok = true;
      }
    } catch {
      ok = false;
    }
    if (!ok) {
      // Fallback for non-secure origins.
      const ta = el('textarea', 'sr-only');
      ta.value = value;
      ta.setAttribute('readonly', '');
      document.body.appendChild(ta);
      const prev = document.activeElement;
      ta.select();
      try {
        ok = document.execCommand('copy');
      } catch {
        ok = false;
      }
      ta.remove();
      if (prev && prev.focus) prev.focus({ preventScroll: true });
    }
    if (ok) toast(`Copied ${truncate(label || value, 64)}`, 'ok');
    else toast('Could not copy: the browser blocked clipboard access.', 'warn');
    return ok;
  }

  // =========================================================================
  // Layer Stack (Escape always closes the topmost one) and Modal Dialogs
  // =========================================================================
  const layers = [];

  function pushLayer(layer) {
    layers.push(layer);
    return layer;
  }

  function removeLayer(layer) {
    const i = layers.indexOf(layer);
    if (i >= 0) layers.splice(i, 1);
  }

  function closeTopLayer() {
    const top = layers[layers.length - 1];
    if (!top) return false;
    top.close();
    return true;
  }

  const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  function focusableIn(container) {
    return [...container.querySelectorAll(FOCUSABLE)].filter((n) => n.offsetParent !== null || n === document.activeElement);
  }

  function trapTab(e, container) {
    if (e.key !== 'Tab') return;
    const items = focusableIn(container);
    if (!items.length) {
      e.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && (document.activeElement === first || !container.contains(document.activeElement))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  let modalSeq = 0;
  function openModal(opts = {}) {
    const root = document.getElementById('modal-root') || document.body;
    const prevFocus = document.activeElement;
    const titleId = `modal-title-${++modalSeq}`;
    const backdrop = el('div', 'modal-backdrop');
    const dialog = el('div', 'modal-dialog');
    str(opts.className).split(/\s+/).map(tok).filter(Boolean).forEach((c) => dialog.classList.add(c));
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    dialog.setAttribute('aria-labelledby', titleId);
    dialog.tabIndex = -1;

    const header = el('div', 'modal-header');
    const h = el('h2', 'modal-title', opts.title || '');
    h.id = titleId;
    const closeBtn = el('button', 'btn-icon-only modal-close', '×');
    closeBtn.type = 'button';
    closeBtn.setAttribute('aria-label', 'Close');
    header.append(h, closeBtn);

    const body = el('div', 'modal-body');
    // Content is a DOM node or plain text; there is deliberately no markup option.
    if (opts.bodyEl instanceof Node) body.appendChild(opts.bodyEl);
    else if (opts.text !== undefined && opts.text !== null) body.appendChild(el('p', 'modal-text', String(opts.text)));

    dialog.append(header, body);
    backdrop.appendChild(dialog);

    let closed = false;
    const layer = { kind: 'modal', close };
    function close() {
      if (closed) return;
      closed = true;
      removeLayer(layer);
      backdrop.remove();
      try {
        if (typeof opts.onClose === 'function') opts.onClose();
      } catch (err) {
        console.error('[BinaryStudio] modal onClose failed:', err);
      }
      if (prevFocus && document.contains(prevFocus) && prevFocus.focus) prevFocus.focus({ preventScroll: true });
    }

    closeBtn.addEventListener('click', close);
    backdrop.addEventListener('mousedown', (e) => {
      if (e.target === backdrop) close();
    });
    dialog.addEventListener('keydown', (e) => trapTab(e, dialog));

    pushLayer(layer);
    root.appendChild(backdrop);
    const first = focusableIn(body)[0];
    (first || dialog).focus({ preventScroll: true });
    return { close, el: dialog, bodyEl: body };
  }

  // =========================================================================
  // Toolbar Extension Area and the Optional Layout Slot
  // =========================================================================
  function addToolbarButton(spec = {}) {
    const host = document.getElementById('toolbar-ext');
    const btn = el('button', 'btn-toolbar btn-quiet', spec.label || '');
    btn.type = 'button';
    if (spec.id) btn.id = `tb-${tok(spec.id)}`;
    if (spec.title) btn.title = String(spec.title);
    const isToggle = typeof spec.pressed === 'boolean';
    if (isToggle) btn.setAttribute('aria-pressed', String(spec.pressed));
    btn.addEventListener('click', (e) => {
      if (typeof spec.onClick === 'function') safeCall(() => spec.onClick(e), undefined, `toolbar:${spec.id || spec.label}`);
    });
    if (host) host.appendChild(btn);
    return {
      el: btn,
      setPressed(on) {
        btn.setAttribute('aria-pressed', String(Boolean(on)));
      },
      setLabel(text) {
        btn.textContent = str(text);
      },
      remove() {
        btn.remove();
      },
    };
  }

  function getSlot(name) {
    if (name !== 'footer') return null;
    const node = document.getElementById('ext-slot-footer');
    if (!node) return null;
    return {
      el: node,
      show(heightPx) {
        node.style.height = `${numIn(heightPx, 0, 250, 90)}px`;
        node.hidden = false;
        scheduleLayoutRefresh();
      },
      hide() {
        node.hidden = true;
        node.style.height = '';
        scheduleLayoutRefresh();
      },
    };
  }

  // =========================================================================
  // API Client: pluggable transport, doc-id handling, doc_expired recovery
  // =========================================================================
  class ApiError extends Error {
    constructor(status, code, message) {
      super(message || code || `HTTP ${status}`);
      this.name = 'ApiError';
      this.status = status;
      this.code = code;
    }
  }

  const STATUS_CODES = { 400: 'bad_request', 403: 'forbidden', 404: 'not_found', 408: 'timeout', 410: 'doc_expired', 413: 'too_large', 422: 'parse_failed', 429: 'rate_limited', 504: 'timeout' };
  const DOCLESS_ROUTES = /^\/api\/(config|presets|upload|parse)$/;
  const textDecoder = new TextDecoder('utf-8');
  const textEncoder = new TextEncoder();

  function isPlainObject(v) {
    return v !== null && typeof v === 'object' && (Object.getPrototypeOf(v) === Object.prototype || Array.isArray(v));
  }

  async function encodeBody(body) {
    if (body === null || body === undefined) return { bytes: null, type: null };
    if (body instanceof Uint8Array) return { bytes: body, type: 'application/octet-stream' };
    if (body instanceof ArrayBuffer) return { bytes: new Uint8Array(body), type: 'application/octet-stream' };
    if (ArrayBuffer.isView(body)) return { bytes: new Uint8Array(body.buffer, body.byteOffset, body.byteLength), type: 'application/octet-stream' };
    if (typeof Blob !== 'undefined' && body instanceof Blob) return { bytes: new Uint8Array(await body.arrayBuffer()), type: 'application/octet-stream' };
    if (typeof body === 'string') return { bytes: textEncoder.encode(body), type: 'text/plain; charset=utf-8' };
    return { bytes: textEncoder.encode(JSON.stringify(body)), type: 'application/json' };
  }

  function responseBytes(body) {
    if (body instanceof Uint8Array) return body;
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (typeof body === 'string') return textEncoder.encode(body);
    return new Uint8Array(0);
  }

  function parseJsonBytes(bytes) {
    try {
      return JSON.parse(textDecoder.decode(bytes));
    } catch {
      return undefined;
    }
  }

  const api = {
    baseUrl: null,
    _transport: null,

    setTransport(fn) {
      api._transport = typeof fn === 'function' ? fn : null;
    },

    async _fetchTransport({ method, route, query, body, headers, signal }) {
      const url = new URL(route.replace(/^\/+/, ''), api.baseUrl || document.baseURI);
      url.hash = '';
      url.search = '';
      Object.entries(query || {}).forEach(([k, v]) => url.searchParams.set(k, v));
      const res = await fetch(url, { method, headers, body: body || undefined, signal, credentials: 'same-origin', cache: 'no-store' });
      const outHeaders = Object.create(null);
      res.headers.forEach((v, k) => {
        outHeaders[k.toLowerCase()] = v;
      });
      return { status: res.status, headers: outHeaders, body: new Uint8Array(await res.arrayBuffer()) };
    },

    /** Query for a request: caller params on top of the automatic doc + slice_index. */
    _query(route, params) {
      const q = Object.create(null);
      if (state.doc && !DOCLESS_ROUTES.test(route)) {
        if (state.docId) q.doc = state.docId;
        else if (state.legacyPath) q.path = state.legacyPath;
        q.slice_index = String(state.activeSliceIndex);
      }
      Object.entries(params || {}).forEach(([k, v]) => {
        if (v === null || v === undefined) delete q[k];
        else q[k] = String(v);
      });
      if (params && params.doc !== undefined && params.doc !== null && params.path === undefined) delete q.path;
      return q;
    },

    async _send(req) {
      let res;
      try {
        res = await (api._transport || api._fetchTransport)(req);
      } catch (err) {
        if (err && err.name === 'AbortError') throw err;
        if (err instanceof ApiError) throw err;
        throw new ApiError(0, 'network', 'Could not reach the analysis engine. Check that the server is running and try again.');
      }
      if (!res || typeof res.status !== 'number') throw new ApiError(0, 'bad_response', 'The transport returned no response.');
      return { status: res.status, headers: res.headers || {}, body: responseBytes(res.body) };
    },

    _error(res) {
      const data = parseJsonBytes(res.body);
      const code = (data && typeof data.code === 'string' && data.code) || STATUS_CODES[res.status] || (res.status >= 500 ? 'internal' : 'bad_request');
      const message = (data && typeof data.error === 'string' && data.error) || `Request failed (HTTP ${res.status}).`;
      return new ApiError(res.status, code, message);
    },

    async _request(method, route, params, body, opts = {}) {
      if (typeof route !== 'string' || route[0] !== '/') throw new TypeError('BS.api: route must start with "/"');
      let query = api._query(route, params);
      const encoded = await encodeBody(body);
      const baseHeaders = Object.assign({}, opts.headers);
      if (encoded.type && !baseHeaders['Content-Type']) baseHeaders['Content-Type'] = encoded.type;
      // Document ids are bearer capabilities: send them as headers, never in the URL, so they
      // do not end up in proxy or access logs. `query` keeps the logical view for recovery.
      const wire = (q) => {
        const wq = Object.assign(Object.create(null), q);
        const headers = Object.assign({}, baseHeaders);
        const move = (key, name) => {
          if (typeof wq[key] === 'string' && wq[key]) {
            headers[name] = encodeURIComponent(wq[key]);
            delete wq[key];
          }
        };
        move('doc', 'X-BS-Doc');
        if (route === '/api/labs/compare') {
          move('a', 'X-BS-Doc-A');
          move('b', 'X-BS-Doc-B');
        }
        return { query: wq, headers };
      };
      let res = await api._send(Object.assign({ method, route, body: encoded.bytes, signal: opts.signal }, wire(query)));

      if (res.status === 410 && api._error(res).code === 'doc_expired') {
        const bodyDoc = isPlainObject(body) && !Array.isArray(body) && typeof body.doc === 'string' ? body.doc : null;
        const expired = query.doc || bodyDoc;
        const fresh = await recoverDocument(expired);
        if (fresh) {
          if (query.doc === expired) query = Object.assign({}, query, { doc: fresh });
          let retryBytes = encoded.bytes;
          if (bodyDoc === expired) retryBytes = (await encodeBody(Object.assign({}, body, { doc: fresh }))).bytes;
          res = await api._send(Object.assign({ method, route, body: retryBytes, signal: opts.signal }, wire(query)));
        }
      }
      if (res.status >= 400 || res.status < 200) throw api._error(res);
      return res;
    },

    _json(res) {
      if (!res.body.length) return null;
      const data = parseJsonBytes(res.body);
      if (data === undefined) throw new ApiError(res.status, 'bad_response', 'The server sent a response that is not valid JSON.');
      return data;
    },

    async get(route, params, opts) {
      return api._json(await api._request('GET', route, params, null, opts));
    },

    async post(route, body, params, opts) {
      return api._json(await api._request('POST', route, params, body, opts));
    },

    async getBytes(route, params, opts) {
      return (await api._request('GET', route, params, null, opts)).body;
    },
  };

  /** Plain-language description of a failure: what happened and what to do. */
  function describeError(err) {
    const code = err instanceof ApiError ? err.code : 'internal';
    const message = str(err && err.message, 'Unknown error.');
    const limit = config?.limits?.max_upload_bytes;
    switch (code) {
      case 'network':
        return { what: 'The analysis engine is not reachable.', next: 'Check that the server is still running, then try again.' };
      case 'too_large':
        return { what: limit ? `The file is larger than the ${formatBytes(limit)} this server accepts.` : 'The file is larger than this server accepts.', next: config?.mode === 'public' ? 'Run BinaryStudio locally to analyse larger files.' : 'Raise the upload limit or use a smaller file.' };
      case 'rate_limited':
        return { what: 'The server is limiting requests from this connection.', next: 'Wait a minute, then try again.' };
      case 'parse_failed':
        return { what: 'The file could not be parsed as Mach-O, ELF or PE.', next: 'Check that it is an executable, object file or library in one of those formats.', detail: message };
      case 'forbidden':
        return { what: 'This server does not allow that operation.', next: '', detail: message };
      case 'not_found':
        return { what: 'The file was not found.', next: 'Check the path or pick a sample.', detail: message };
      case 'doc_expired':
        return { what: 'The server no longer holds this file.', next: 'Open it again to continue.' };
      case 'timeout':
        return { what: 'Analysis took too long and was stopped.', next: 'The file may be malformed. Try a smaller or different file.', detail: message };
      case 'out_of_memory': // in-browser engine (static build) only
        return { what: 'This file needs more memory than this browser tab can give the analysis engine.', next: 'Try a smaller file, or run BinaryStudio locally for very large binaries.' };
      case 'cancelled': // in-browser engine: the user stopped a long analysis
        return { what: 'Analysis stopped.', next: 'Open the file again to retry.' };
      default:
        return { what: 'The request failed.', next: 'Try again. If it keeps failing, reload the page.', detail: message };
    }
  }

  // =========================================================================
  // Fast Client-Side Offset <-> VM Address Lookup (Fallback + Live Hex Col)
  // =========================================================================
  function absOffsetToVmAddr(absOffset, slice) {
    if (!slice || !Array.isArray(slice.segments)) return null;
    const sliceOff = absOffset - num(slice.slice_base_offset);
    if (sliceOff < 0) return null;
    for (const seg of slice.segments) {
      if (seg.segname === '__PAGEZERO' && num(seg.filesize) === 0) continue;
      const foff = num(seg.fileoff);
      const fsize = num(seg.filesize);
      if (sliceOff >= foff && sliceOff < foff + fsize) {
        const vmBase = parseBigIntHex(seg.vmaddr ?? seg.vmaddr_int);
        const vm = vmBase + BigInt(sliceOff - foff);
        return '0x' + vm.toString(16);
      }
    }
    return null;
  }

  // =========================================================================
  // Extension Registries: Views and Commands
  // =========================================================================
  const GROUP_ORDER = ['Analysis', 'Learn', 'Labs'];
  const LAST_GROUP = 'Help';
  const BUILTIN_NODE_IDS = new Set([
    'start', 'overview', 'semantic_intel', 'loader_lifecycle', 'rosetta_stone', 'fat_header', 'mach_header', 'header_0',
    'load_commands', 'segments', 'disassembly', 'dyld_info', 'symtab', 'dysymtab', 'strings', 'function_starts',
    'objc_metadata', 'code_signature', 'security_audit', 'hex',
  ]);
  const extViews = new Map(); // id -> view
  let booted = false;
  let treeRefreshQueued = false;

  function refreshTreeSoon() {
    if (!booted || treeRefreshQueued) return;
    treeRefreshQueued = true;
    Promise.resolve().then(() => {
      treeRefreshQueued = false;
      buildStructureTree();
      if (state.selectedNodeId && !hasNode(state.selectedNodeId)) {
        selectTreeNode(state.doc ? 'overview' : 'start', { scrollHex: false, recordHistory: false });
      } else {
        renderStructureTree();
      }
    });
  }

  function initials(title) {
    const words = str(title).replace(/[^A-Za-z0-9 ]/g, ' ').trim().split(/\s+/).filter(Boolean);
    if (!words.length) return '·';
    if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
    return words.slice(0, 3).map((w) => w[0]).join('').toUpperCase();
  }

  function registerView(spec) {
    if (!spec || typeof spec.id !== 'string' || !spec.id) throw new TypeError('registerView: id is required');
    if (typeof spec.render !== 'function') throw new TypeError(`registerView(${spec.id}): render(bodyEl, ctx) is required`);
    if (extViews.has(spec.id) || BUILTIN_NODE_IDS.has(spec.id) || /^(lc|seg|sect|field|slice)_/.test(spec.id)) {
      throw new Error(`registerView: id "${spec.id}" is already in use or reserved`);
    }
    const view = {
      id: spec.id,
      title: str(spec.title, spec.id),
      subtitle: str(spec.subtitle),
      badge: spec.badge === undefined || spec.badge === null ? '' : str(spec.badge),
      icon: spec.icon ? str(spec.icon).slice(0, 3) : '',
      group: str(spec.group, 'Analysis') || 'Analysis',
      order: num(spec.order, 1000),
      requiresDoc: spec.requiresDoc === true,
      render: spec.render,
      dispose: typeof spec.dispose === 'function' ? spec.dispose : null,
    };
    extViews.set(view.id, view);
    refreshTreeSoon();
    return {
      unregister() {
        if (extViews.get(view.id) !== view) return;
        if (activeExt && activeExt.view === view) disposeActiveExtView();
        extViews.delete(view.id);
        refreshTreeSoon();
      },
      update(partial = {}) {
        ['title', 'subtitle', 'badge', 'icon', 'group'].forEach((k) => {
          if (partial[k] !== undefined) view[k] = str(partial[k]);
        });
        if (partial.order !== undefined) view.order = num(partial.order, view.order);
        if (partial.requiresDoc !== undefined) view.requiresDoc = partial.requiresDoc === true;
        refreshTreeSoon();
      },
    };
  }

  const commands = new Map(); // id -> command

  function parseShortcut(text) {
    const s = str(text).trim();
    if (!s) return null;
    const parts = s === '+' ? ['+'] : s.split('+').map((p) => p.trim());
    if (s.length > 1 && s.endsWith('+')) parts.splice(-2, 2, '+');
    const keyRaw = parts.pop();
    const mods = parts.map((p) => p.toLowerCase());
    return {
      mod: mods.includes('mod') || mods.includes('cmd') || mods.includes('ctrl'),
      alt: mods.includes('alt') || mods.includes('option'),
      shift: mods.includes('shift'),
      keyRaw,
      key: keyRaw.toLowerCase(),
    };
  }

  function formatShortcut(sc) {
    if (!sc) return '';
    const key = sc.keyRaw.length === 1 ? sc.keyRaw.toUpperCase() : sc.keyRaw;
    if (IS_MAC) return `${sc.mod ? '⌘' : ''}${sc.alt ? '⌥' : ''}${sc.shift ? '⇧' : ''}${key}`;
    return `${sc.mod ? 'Ctrl+' : ''}${sc.alt ? 'Alt+' : ''}${sc.shift ? 'Shift+' : ''}${key}`;
  }

  function shortcutMatches(sc, e) {
    if (sc.mod !== (e.metaKey || e.ctrlKey)) return false;
    if (sc.alt !== e.altKey) return false;
    if (/^[a-z]$/.test(sc.key)) {
      // Letters: prefer the produced character (layout-aware); fall back to the physical key when
      // a modifier turns it into something else (e.g. Option+C on macOS).
      const produced = e.key && e.key.length === 1 ? e.key.toLowerCase() : '';
      const physical = e.code && e.code.startsWith('Key') ? e.code.slice(3).toLowerCase() : '';
      const pressed = /^[a-z]$/.test(produced) ? produced : physical;
      return pressed === sc.key && sc.shift === e.shiftKey;
    }
    if (sc.key.length === 1) return e.key === sc.keyRaw; // symbols such as ? / [ ] already imply Shift
    return str(e.key).toLowerCase() === sc.key && sc.shift === e.shiftKey;
  }

  function registerCommand(spec) {
    if (!spec || typeof spec.id !== 'string' || !spec.id) throw new TypeError('registerCommand: id is required');
    if (typeof spec.run !== 'function') throw new TypeError(`registerCommand(${spec.id}): run() is required`);
    if (commands.has(spec.id)) throw new Error(`registerCommand: id "${spec.id}" is already registered`);
    const shortcuts = (Array.isArray(spec.shortcut) ? spec.shortcut : [spec.shortcut]).map(parseShortcut).filter(Boolean);
    const keywords = Array.isArray(spec.keywords) ? spec.keywords.join(' ') : str(spec.keywords);
    const cmd = {
      id: spec.id,
      title: str(spec.title, spec.id),
      hint: str(spec.hint),
      section: str(spec.section, 'Commands') || 'Commands',
      haystack: `${str(spec.title, spec.id)} ${keywords} ${str(spec.hint)}`.toLowerCase(),
      shortcuts,
      shortcutLabel: shortcuts.map(formatShortcut).join('  '),
      when: typeof spec.when === 'function' ? spec.when : null,
      run: spec.run,
    };
    commands.set(cmd.id, cmd);
    return {
      unregister() {
        if (commands.get(cmd.id) === cmd) commands.delete(cmd.id);
      },
    };
  }

  function commandEnabled(cmd) {
    if (!cmd.when) return true;
    try {
      return Boolean(cmd.when());
    } catch (err) {
      console.error(`[BinaryStudio] when() of command "${cmd.id}" failed:`, err);
      return false;
    }
  }

  async function runCommand(cmdOrId) {
    const cmd = typeof cmdOrId === 'string' ? commands.get(cmdOrId) : cmdOrId;
    if (!cmd || !commandEnabled(cmd)) return false;
    try {
      await cmd.run();
      return true;
    } catch (err) {
      console.error(`[BinaryStudio] command "${cmd.id}" failed:`, err);
      toast(`${cmd.title} failed: ${str(err && err.message, 'unknown error')}`, 'error');
      return false;
    }
  }

  function listCommands(opts) {
    const all = Boolean(opts && opts.all);
    return [...commands.values()].filter((c) => all || commandEnabled(c)).map((c) => ({ id: c.id, title: c.title, hint: c.hint, shortcut: c.shortcutLabel, section: c.section }));
  }

  // =========================================================================
  // Runtime Configuration (/api/config) and Samples (/api/presets)
  // =========================================================================
  const plainObject = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

  function normaliseAds(raw) {
    const a = plainObject(raw);
    return {
      enabled: a.enabled === true,
      provider: typeof a.provider === 'string' ? a.provider : null,
      slots: plainObject(a.slots),
      options: plainObject(a.options),
    };
  }

  function normaliseConfig(rawConfig, assumed) {
    const c = rawConfig && typeof rawConfig === 'object' ? rawConfig : {};
    const mode = oneOf(c.mode, ['local', 'public', 'wasm'], 'local');
    const f = c.features && typeof c.features === 'object' ? c.features : null;
    const limits = c.limits && typeof c.limits === 'object' ? c.limits : {};
    return {
      app: str(c.app, 'BinaryStudio'),
      version: str(c.version, VERSION),
      mode,
      assumed: Boolean(assumed),
      features: {
        // A server that publishes a config must opt in to path loading explicitly.
        path_load: f ? f.path_load === true : assumed,
        host_presets: f ? f.host_presets === true : assumed,
        upload: f ? f.upload !== false : true,
        external_tools: f ? f.external_tools === true : assumed,
        patch: f ? f.patch === true : false,
        download: f ? f.download === true : false,
      },
      limits: {
        max_upload_bytes: numIn(limits.max_upload_bytes, 1, Number.MAX_SAFE_INTEGER, 256 * 1024 * 1024),
        max_patch_bytes: numIn(limits.max_patch_bytes, 0, Number.MAX_SAFE_INTEGER, 65536),
      },
      // Copied field by field: a server object is never spread over one whose fields pick behaviour.
      ads: normaliseAds(c.ads),
      links: plainObject(c.links),
      initial_doc: typeof c.initial_doc === 'string' ? c.initial_doc : null,
    };
  }

  async function loadConfig() {
    try {
      return normaliseConfig(await api.get('/api/config'), false);
    } catch (err) {
      // A v1 backend has no /api/config: it is single-user and local by construction.
      if (err instanceof ApiError && err.status === 404) return normaliseConfig({}, true);
      throw err;
    }
  }

  async function loadPresets() {
    try {
      const data = await api.get('/api/presets');
      const list = Array.isArray(data?.presets) ? data.presets : [];
      return list.filter((p) => p && typeof p.id === 'string' && p.exists !== false && (typeof p.doc === 'string' || typeof p.path === 'string'));
    } catch (err) {
      console.warn('[BinaryStudio] samples unavailable:', err);
      return [];
    }
  }

  function isLoopbackHost() {
    const host = window.location.hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1' || host === '' || host.endsWith('.localhost');
  }

  /** One truthful sentence about where a file goes in this mode. */
  function privacyLine() {
    if (!config) return '';
    if (config.mode === 'wasm') return 'Analysis runs inside this browser tab. Files you open are not uploaded.';
    if (config.mode === 'public') return 'Files you open are uploaded to this server for analysis. They are held in memory only and are not stored.';
    if (isLoopbackHost()) return 'Analysis runs on this machine. Files you open stay on it.';
    return `Files you open are sent to the BinaryStudio server at ${window.location.host} for analysis.`;
  }

  function safeLink(href) {
    // Only same-origin paths or http(s) URLs; never javascript: or data:.
    const s = str(href).trim();
    if (!s) return null;
    try {
      const u = new URL(s, document.baseURI);
      return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
    } catch {
      return null;
    }
  }

  function applyConfig() {
    const root = document.documentElement;
    root.dataset.mode = config.mode;

    const chip = document.getElementById('status-mode');
    if (chip) {
      chip.textContent = config.mode === 'wasm' ? 'In browser' : config.mode === 'public' ? 'Hosted' : 'Local';
      chip.title = privacyLine();
      chip.hidden = false;
    }

    const linksEl = document.getElementById('status-links');
    if (linksEl) {
      linksEl.replaceChildren();
      if (config.mode !== 'local') {
        [['privacy', 'Privacy'], ['terms', 'Terms'], ['about', 'About'], ['source', 'Source']].forEach(([key, label]) => {
          const href = safeLink(config.links[key]);
          if (!href) return;
          const a = el('a', 'status-link', label);
          a.href = href;
          a.rel = 'noopener';
          linksEl.appendChild(a);
        });
      }
    }

    // The hidden file input exists only when uploads are allowed.
    const existing = document.getElementById('file-upload-input');
    if (config.features.upload && !existing) {
      const input = el('input', 'sr-only');
      input.type = 'file';
      input.id = 'file-upload-input';
      input.tabIndex = -1;
      input.setAttribute('aria-hidden', 'true');
      input.addEventListener('change', () => {
        const file = input.files && input.files[0];
        input.value = '';
        if (file) openFile(file);
      });
      document.body.appendChild(input);
    } else if (!config.features.upload && existing) {
      existing.remove();
    }

    const dropTitle = document.getElementById('dropzone-sub');
    if (dropTitle) dropTitle.textContent = `Mach-O, ELF or PE, up to ${formatBytes(config.limits.max_upload_bytes)}`;

    // Reserve the optional layout slot up front so nothing shifts when its content arrives.
    const footerSlot = config.ads.enabled && config.ads.slots && config.ads.slots.footer;
    if (footerSlot) getSlot('footer')?.show(num(footerSlot.height, 90));
    // The ad renderer (static/js/ads.js, same origin) is fetched only for this explicit opt-in, so a
    // configuration without ads makes no request for it at all.
    if (footerSlot && !document.getElementById('bs-ads-script')) {
      const s = document.createElement('script');
      s.id = 'bs-ads-script';
      s.src = 'static/js/ads.js';
      s.async = true;
      document.head.appendChild(s);
    }
  }

  // =========================================================================
  // Opening Documents
  // =========================================================================
  const docCache = new Map(); // docKey -> record, most recently used last (max 3 kept for back/forward)
  const renewedIds = new Map(); // expired doc id -> replacement id
  let docKeySeq = 0;
  let loadSeq = 0;

  function makeRecord(doc, source, extras = {}) {
    const fi = doc.file_info || {};
    const docId = typeof doc.doc_id === 'string' && doc.doc_id ? doc.doc_id : null;
    const src = Object.assign({}, source);
    if (src.kind === 'path' && typeof fi.path === 'string' && fi.path) src.path = fi.path;
    return {
      key: `d${++docKeySeq}`,
      doc,
      docId,
      legacyPath: docId ? null : str(fi.path) || null,
      source: src,
      bytes: extras.bytes instanceof Uint8Array ? extras.bytes : null,
      filename: str(extras.filename || fi.filename || src.filename || 'binary'),
      recovering: null,
      expiredNotified: false,
    };
  }

  /** The doc reference that may appear in a URL: presets always, paths in local mode, uploads never. */
  function recordRef(record) {
    if (!record) return null;
    if (record.source.kind === 'preset' && record.source.presetId) return `preset:${record.source.presetId}`;
    if (record.source.kind === 'path' && record.source.path && config && config.mode === 'local' && config.features.path_load) return `path:${record.source.path}`;
    return null;
  }

  function findRecordByRef(ref) {
    for (const record of docCache.values()) if (recordRef(record) === ref) return record;
    return null;
  }

  function validateDocument(doc) {
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.slices) || doc.slices.length === 0) {
      throw new ApiError(200, 'parse_failed', 'The analysis returned no architecture slices.');
    }
    if (!doc.file_info || typeof doc.file_info !== 'object') doc.file_info = {};
  }

  async function openWith(label, source, fetchDoc, restore, extras) {
    const seq = ++loadSeq;
    const done = busy.start(`Opening ${truncate(label, 60)}…`);
    try {
      const doc = await fetchDoc();
      if (seq !== loadSeq) {
        done();
        return null;
      }
      validateDocument(doc);
      done('Ready');
      activateRecord(makeRecord(doc, source, extras), restore || {});
      return doc;
    } catch (err) {
      if (seq !== loadSeq) {
        done();
        return null;
      }
      done(`Could not open ${truncate(label, 60)}`, 'error');
      showLoadError(label, err);
      return null;
    }
  }

  function openPresetById(id, restore) {
    const p = state.presets.find((x) => x.id === id);
    if (!p) {
      showLoadError(id, new ApiError(404, 'not_found', `There is no sample named "${id}" on this server.`));
      return Promise.resolve(null);
    }
    const fetchDoc = () => (typeof p.doc === 'string' ? api.get('/api/parse', { doc: p.doc }) : api.get('/api/parse', { path: p.path }));
    return openWith(str(p.label, p.id), { kind: 'preset', presetId: p.id }, fetchDoc, restore);
  }

  /**
   * Local mode only. Paths the user chose to open in this browser: typed into the Open panel,
   * confirmed in the "Open …?" prompt, the server's own --file, or resumed from a session that was
   * itself confirmed. A path that arrives any other way (a #doc=path: link, ?file=) is never read
   * until the user says so: it is shown as a prompt on the start view instead.
   */
  const confirmedPathRefs = new Set();

  /** Open a server path. Callers are explicit user actions, or openRef() after its check. */
  function openPath(path, restore) {
    const p = str(path).trim();
    if (!p) return Promise.resolve(null);
    if (!config.features.path_load) {
      showLoadError(p, new ApiError(403, 'forbidden', 'Opening files by server path is disabled here.'));
      return Promise.resolve(null);
    }
    confirmedPathRefs.add(`path:${p}`);
    state.pendingPath = null;
    return openWith(p, { kind: 'path', path: p }, () => api.get('/api/parse', { path: p }), restore).then((doc) => {
      const resolved = doc && doc.file_info && typeof doc.file_info.path === 'string' ? doc.file_info.path : '';
      if (resolved) confirmedPathRefs.add(`path:${resolved}`);
      return doc;
    });
  }

  /** A path that came from a URL: ask on the start view (quietly, inline) before reading it. */
  function askToOpenPath(path, restore) {
    const p = str(path).trim();
    if (!p || !config.features.path_load) return;
    state.pendingPath = { path: p.slice(0, 4096), restore: restore || {} };
    state.lastLoadError = null;
    if (state.doc) closeDocument(false);
    else showStartView(false);
  }

  function checkUploadAllowed(name, size) {
    if (!config.features.upload) {
      return new ApiError(403, 'forbidden', 'This server does not accept uploads.');
    }
    if (size === 0) return new ApiError(400, 'bad_request', `${name} is empty.`);
    const limit = config.limits.max_upload_bytes;
    if (size > limit) {
      return new ApiError(413, 'too_large', `${name} is ${formatBytes(size)}. The limit here is ${formatBytes(limit)}.`);
    }
    return null;
  }

  function openBytes(filename, bytes, restore) {
    const name = str(filename, 'binary') || 'binary';
    const data = bytes instanceof Uint8Array ? bytes : bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : null;
    if (!data) {
      showLoadError(name, new ApiError(400, 'bad_request', 'No bytes to open.'));
      return Promise.resolve(null);
    }
    const refusal = checkUploadAllowed(name, data.length);
    if (refusal) {
      showLoadError(name, refusal);
      return Promise.resolve(null);
    }
    const fetchDoc = () => api.post('/api/upload', data, null, { headers: { 'X-Filename': encodeURIComponent(name) } });
    return openWith(name, { kind: 'upload', filename: name }, fetchDoc, restore, { bytes: data, filename: name });
  }

  async function openFile(file) {
    if (!file) return null;
    // Reject oversized files before reading or uploading a single byte.
    const refusal = checkUploadAllowed(str(file.name, 'binary'), num(file.size));
    if (refusal) {
      showLoadError(file.name, refusal);
      return null;
    }
    let buf;
    try {
      buf = new Uint8Array(await file.arrayBuffer());
    } catch {
      showLoadError(file.name, new ApiError(0, 'bad_request', 'The browser could not read this file.'));
      return null;
    }
    return openBytes(file.name, buf);
  }

  function showLoadError(label, err) {
    const info = describeError(err);
    const isLocalRefusal = err instanceof ApiError && (err.code === 'too_large' || err.code === 'bad_request' || err.code === 'forbidden' || err.code === 'not_found') && err.message;
    const what = isLocalRefusal ? err.message : info.what;
    setStatus(`Could not open ${truncate(label, 60)}`, 'error');
    if (state.doc) {
      state.lastLoadError = null;
      toast(`Could not open ${truncate(label, 60)}. ${what} ${info.next}`.trim(), 'error');
    } else {
      state.lastLoadError = { label: str(label), what, next: info.next, detail: isLocalRefusal ? '' : str(info.detail) };
      showStartView(false);
    }
  }

  /**
   * The server answered 410 doc_expired for `expiredId`. Re-create the document if we can
   * (uploaded bytes still in memory, or a preset / path) and return its new id; otherwise null.
   */
  function recoverDocument(expiredId) {
    if (!expiredId) return Promise.resolve(null);
    if (renewedIds.has(expiredId)) return Promise.resolve(renewedIds.get(expiredId));
    let record = null;
    for (const r of docCache.values()) if (r.docId === expiredId) record = r;
    if (!record) return Promise.resolve(null);
    if (record.recovering) return record.recovering;

    record.recovering = (async () => {
      try {
        let res;
        if (record.bytes) {
          res = await api._send({ method: 'POST', route: '/api/upload', query: {}, body: record.bytes, headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': encodeURIComponent(record.filename) } });
        } else if (record.source.kind === 'preset' || record.source.kind === 'path') {
          const preset = record.source.kind === 'preset' ? state.presets.find((p) => p.id === record.source.presetId) : null;
          const query = preset && preset.doc ? { doc: preset.doc } : { path: preset ? preset.path : record.source.path };
          res = await api._send({ method: 'GET', route: '/api/parse', query, body: null, headers: {} });
        } else {
          return null;
        }
        if (res.status !== 200) return null;
        const fresh = parseJsonBytes(res.body);
        const freshId = fresh && typeof fresh.doc_id === 'string' ? fresh.doc_id : null;
        if (!freshId) return null;
        renewedIds.set(expiredId, freshId);
        record.docId = freshId;
        if (state.docKey === record.key) state.docId = freshId;
        bus.emit('doc:renewed', { oldId: expiredId, docId: freshId });
        return freshId;
      } catch {
        return null;
      } finally {
        record.recovering = null;
      }
    })().then((id) => {
      if (!id && !record.expiredNotified) {
        record.expiredNotified = true;
        toast(`The server no longer holds ${truncate(record.filename, 60)}. Open the file again to continue.`, 'warn');
        bus.emit('doc:expired', { docId: expiredId });
      }
      return id;
    });
    return record.recovering;
  }

  // =========================================================================
  // Document Initialization & Slice Switching
  // =========================================================================
  function defaultSliceIndex(doc) {
    // Prefer an arm64 slice in a universal binary.
    if (Array.isArray(doc.slices) && doc.slices.length > 1) {
      const armIdx = doc.slices.findIndex((s) => /arm64/i.test(str(s.arch_name)));
      if (armIdx >= 0) return armIdx;
    }
    return 0;
  }

  /** Make `record` the active document. restore: {slice?, view?, params?, off?}. */
  function activateRecord(record, restore = {}, recordHistory = true) {
    state.pendingPath = null;
    docCache.delete(record.key);
    docCache.set(record.key, record);
    while (docCache.size > 3) docCache.delete(docCache.keys().next().value);
    // Memory: a document that is no longer on screen gives up its bytes if they are large. Going
    // back to it still works while the server holds it; only its doc_expired recovery is lost.
    docCache.forEach((other) => {
      if (other !== record && other.bytes && other.bytes.length > INACTIVE_BYTES_LIMIT) other.bytes = null;
    });

    docGeneration++;
    state.doc = record.doc;
    state.docId = record.docId;
    state.legacyPath = record.legacyPath;
    state.docSource = record.source;
    state.docKey = record.key;
    state.lastLoadError = null;
    state.hexChunks.clear();
    state.hexPendingChunks.clear();
    state.hexDecorations.clear();
    state.disasmCache.clear();
    state.symSearch = '';
    state.lcSearch = '';
    state.fnSearch = '';
    state.symScope = 'all';
    state.strSearch = '';
    state.strSourceFilter = 'all';
    state.csSubTab = 'summary';
    state.dyldSubTab = 'fixups';

    const slices = record.doc.slices;
    const wantedSlice = Number.isInteger(restore.slice) && restore.slice >= 0 && restore.slice < slices.length ? restore.slice : defaultSliceIndex(record.doc);

    document.body.classList.remove('no-doc');
    updateDocChrome();
    renderSliceSelector();
    registerDocCommands();

    const wasSuppressed = state.suppressHistory;
    state.suppressHistory = true;
    activateSlice(wantedSlice, { view: restore.view, params: restore.params, off: restore.off, emit: false });
    state.suppressHistory = wasSuppressed;
    if (recordHistory && !restore.noHistory && !state.suppressHistory) pushHistory(currentEntry());

    scheduleLayoutRefresh();
    bus.emit('doc:loaded', { doc: state.doc, docId: state.docId });
    bus.emit('slice:changed', { index: state.activeSliceIndex, slice: getActiveSlice() });
  }

  function loadDocument(doc, opts = {}) {
    validateDocument(doc);
    const restore = opts.keepView && state.doc
      ? { slice: state.activeSliceIndex, view: state.selectedNodeId, params: state.viewParams, off: state.cursorOffset }
      : {};
    const filename = str(opts.filename || doc.file_info.filename || 'binary');
    loadSeq++; // supersede any in-flight open
    // The very object of a document that is still cached re-activates its record, source and all.
    let record = null;
    docCache.forEach((r) => {
      if (r.doc === doc) record = r;
    });
    if (!record) record = makeRecord(doc, { kind: 'derived', filename }, { bytes: opts.bytes, filename });
    const prev = docCache.get(state.docKey);
    if (!opts.replace || !prev || prev === record) {
      activateRecord(record, restore);
      return doc;
    }
    // opts.replace: the document takes the place of the active one (e.g. a patched copy of it).
    const hexTop = hexView.topRow;
    const anchor = state.selAnchor;
    const span = state.fieldSpan;
    activateRecord(record, Object.assign(restore, { noHistory: true }));
    state.history.forEach((entry) => {
      if (entry.docKey === prev.key) Object.assign(entry, { docKey: record.key, ref: recordRef(record) });
    });
    if (prev.source.kind === 'derived') docCache.delete(prev.key);
    if (opts.keepView) {
      const last = Math.max(0, fileSize() - 1);
      state.selAnchor = Math.min(anchor, last);
      if (span && span.abs_offset <= last) setFieldSpan(span);
      updateSelectionReadout();
      hexSetTopRow(hexTop);
    }
    const current = state.history[state.historyIndex];
    if (current) {
      Object.assign(current, currentEntry());
      writeLocation(current, 'replace');
      saveSession(current);
    }
    return doc;
  }

  function closeDocument(recordHistory = true) {
    loadSeq++;
    docGeneration++;
    state.doc = null;
    state.docId = null;
    state.legacyPath = null;
    state.docSource = null;
    state.docKey = null;
    state.hexChunks.clear();
    state.hexPendingChunks.clear();
    state.hexDecorations.clear();
    state.disasmCache.clear();
    state.structSpan = null;
    state.fieldSpan = null;
    state.cursorOffset = 0;
    document.body.classList.add('no-doc');
    updateDocChrome();
    renderSliceSelector();
    registerDocCommands();
    renderMemoryMapRibbon();
    showStartView(recordHistory);
    bus.emit('doc:closed', {});
  }

  function showStartView(recordHistory) {
    buildStructureTree();
    selectTreeNode('start', { scrollHex: false, recordHistory });
  }

  /** Everything outside the panes that names the open document. */
  function updateDocChrome() {
    const fi = state.doc?.file_info || {};
    const name = state.doc ? str(fi.filename || fi.path || 'binary') : '';
    const openLabel = document.getElementById('btn-open-label');
    if (openLabel) openLabel.textContent = state.doc ? name : 'Open…';
    const openBtn = document.getElementById('btn-open');
    if (openBtn) openBtn.title = state.doc ? `${name} — open another binary (O)` : 'Open a binary (O)';

    const fileEl = document.getElementById('status-file');
    const hashEl = document.getElementById('status-hash');
    if (fileEl) {
      fileEl.textContent = state.doc ? `${name} · ${formatBytes(fi.file_size || 0)}` : 'No file open';
      fileEl.title = state.doc ? str(fi.path || name) : '';
    }
    if (hashEl) {
      const sha = str(fi.sha256);
      hashEl.hidden = !state.doc || !sha;
      hashEl.textContent = sha ? `sha256 ${sha.slice(0, 12)}…` : '';
      hashEl.title = sha ? `SHA-256 ${sha}${fi.md5 ? `\nMD5 ${fi.md5}` : ''}\nClick to copy the SHA-256` : '';
      hashEl.dataset.copy = sha;
    }
    document.title = state.doc ? `${name} — BinaryStudio` : 'BinaryStudio';
    if (!state.doc) {
      const tag = document.getElementById('doc-format-tag');
      if (tag) tag.textContent = '';
      const arch = document.getElementById('status-arch');
      if (arch) arch.textContent = '';
      const span = document.getElementById('status-span');
      if (span) span.textContent = '';
    }
  }

  function renderSliceSelector() {
    const sel = document.getElementById('slice-select');
    const wrap = document.getElementById('slice-switcher');
    if (!sel || !wrap) return;
    const slices = state.doc?.slices || [];
    wrap.hidden = slices.length < 2;
    sel.innerHTML = html`${slices.map((s, idx) => html`<option value="${idx}">${s.arch_name} · ${formatBytes(s.slice_size)}</option>`)}`;
    sel.value = String(state.activeSliceIndex);
  }

  function activateSlice(sliceIdx, opts = {}) {
    const slices = (state.doc && state.doc.slices) || [];
    if (!slices.length) return;
    const prevNodeId = state.selectedNodeId;
    state.activeSliceIndex = Math.max(0, Math.min(num(sliceIdx), slices.length - 1));
    const slice = getActiveSlice();

    const baseOff = num(slice.slice_base_offset);
    state.cursorOffset = baseOff;
    state.selAnchor = baseOff;
    state.structSpan = { abs_offset: baseOff, size: num(slice.header?.region?.size, 32), label: 'header' };
    state.fieldSpan = null;
    state.activeDisasmSection = '';
    state.activeDisasmVmaddr = '';

    const sel = document.getElementById('slice-select');
    if (sel) sel.value = String(state.activeSliceIndex);
    const tag = document.getElementById('doc-format-tag');
    if (tag) tag.textContent = `${str(slice.format_display || slice.overview?.filetype_name || slice.format)} · ${str(slice.arch_name)}`;
    const arch = document.getElementById('status-arch');
    if (arch) arch.textContent = `${str(slice.arch_name)} · ${str(slice.format_display || slice.overview?.filetype_name || 'Mach-O')}`;

    buildStructureTree();
    renderMemoryMapRibbon();
    initHexViewport();

    let target = 'overview';
    if (opts.view && hasNode(opts.view)) target = opts.view;
    else if (opts.keepView && prevNodeId && hasNode(prevNodeId)) target = prevNodeId;
    selectTreeNode(target, { scrollHex: true, recordHistory: opts.recordHistory !== false, params: opts.params });
    if (Number.isFinite(opts.off)) setCursorAndHighlight(opts.off, null, { scrollHex: true });
    if (opts.emit !== false) bus.emit('slice:changed', { index: state.activeSliceIndex, slice });
  }

  // =========================================================================
  // Open Panel: the no-document start view and the Open dialog share it
  // =========================================================================
  function buildOpenPanel(context, onPick) {
    const feats = config.features;
    const panel = el('div', 'open-panel');
    const picked = () => {
      if (typeof onPick === 'function') onPick();
    };

    const pending = context === 'start' && !state.doc && feats.path_load ? state.pendingPath : null;
    if (pending) {
      // A link asked for a file on this machine. Nothing is read until the user says so.
      const ask = el('div', 'open-confirm');
      ask.setAttribute('role', 'group');
      ask.setAttribute('aria-label', 'Open a file named by a link');
      const text = el('span', 'open-confirm-text', 'Open ');
      text.appendChild(el('code', 'open-confirm-path', truncate(pending.path, 300)));
      text.appendChild(document.createTextNode('? It is a file on this machine that was named in a link, not opened from here.'));
      const yes = el('button', 'btn', 'Open');
      yes.type = 'button';
      yes.id = 'open-confirm-yes';
      yes.addEventListener('click', () => {
        const p = state.pendingPath;
        if (!p) return;
        picked();
        // Opened now by the user, so it becomes a normal history entry.
        openPath(p.path, Object.assign({}, p.restore, { noHistory: false }));
      });
      const no = el('button', 'btn btn-quiet', 'Dismiss');
      no.type = 'button';
      no.addEventListener('click', () => {
        const p = state.pendingPath;
        state.pendingPath = null;
        const sess = storage.get('session', null);
        if (p && sess && sess.doc === `path:${p.path}`) storage.remove('session');
        ask.remove();
        document.getElementById('path-input')?.focus();
      });
      ask.append(text, yes, no);
      panel.appendChild(ask);
    }

    const err = context === 'start' ? state.lastLoadError : null;
    if (err) {
      const alert = el('div', 'open-alert');
      alert.setAttribute('role', 'alert');
      alert.appendChild(el('strong', '', `Could not open ${truncate(err.label, 80)}`));
      alert.appendChild(el('span', '', ` ${err.what} ${err.next}`.trimEnd()));
      if (err.detail) alert.appendChild(el('code', 'open-alert-detail', truncate(err.detail, 300)));
      panel.appendChild(alert);
    }

    if (feats.upload) {
      const row = el('div', 'open-row');
      const browse = el('button', 'btn btn-accent', 'Choose file…');
      browse.type = 'button';
      browse.addEventListener('click', () => {
        picked();
        document.getElementById('file-upload-input')?.click();
      });
      row.append(browse, el('span', 'open-hint', 'or drop a file anywhere in this window'));
      panel.appendChild(row);
    }

    if (feats.path_load) {
      // Only exists when the server allows reading its own filesystem (local mode).
      const form = el('form', 'open-path-form');
      form.autocomplete = 'off';
      const label = el('label', 'open-label', 'Path on this machine');
      const input = el('input', 'path-input');
      input.type = 'text';
      input.id = context === 'start' ? 'path-input' : 'path-input-dialog';
      input.name = 'path';
      input.placeholder = '/path/to/binary';
      input.spellcheck = false;
      input.autocapitalize = 'off';
      label.htmlFor = input.id;
      const go = el('button', 'btn', 'Open');
      go.type = 'submit';
      const line = el('div', 'open-path-line');
      line.append(input, go);
      form.append(label, line);
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const value = input.value.trim();
        if (!value) return;
        picked();
        openPath(value);
      });
      panel.appendChild(form);
    }

    const formats = 'Mach-O (thin or universal), ELF32/64 and PE32/PE32+';
    const note = feats.upload
      ? `${formats}, up to ${formatBytes(config.limits.max_upload_bytes)}. Nothing you open is ever executed.`
      : `${formats}. Nothing you open is ever executed.`;
    panel.appendChild(el('p', 'open-note', note));

    const privacy = el('p', 'open-note privacy-line', privacyLine());
    const privacyHref = config.mode !== 'local' ? safeLink(config.links.privacy) : null;
    if (privacyHref) {
      const a = el('a', 'status-link', 'Privacy');
      a.href = privacyHref;
      a.rel = 'noopener';
      privacy.append(' ', a);
    }
    panel.appendChild(privacy);

    if (state.presets.length) {
      panel.appendChild(el('h2', 'open-heading', 'Samples'));
      const list = el('ul', 'sample-list');
      state.presets.forEach((p) => {
        const li = el('li');
        const btn = el('button', 'sample-row');
        btn.type = 'button';
        btn.append(el('span', 'sample-name', str(p.label, p.id)), el('span', 'sample-desc', str(p.description)));
        btn.addEventListener('click', () => {
          picked();
          openPresetById(p.id);
        });
        li.appendChild(btn);
        list.appendChild(li);
      });
      panel.appendChild(list);
    } else if (!feats.upload && !feats.path_load) {
      panel.appendChild(el('p', 'open-note', 'This server offers no samples and does not accept files.'));
    }

    // Mount point: document-independent views in the "Learn" group are offered from the start view.
    const learnViews = [...extViews.values()].filter((v) => v.group === 'Learn' && !v.requiresDoc).sort((a, b) => a.order - b.order || a.title.localeCompare(b.title));
    if (learnViews.length) {
      panel.appendChild(el('h2', 'open-heading', 'Learn'));
      const list = el('ul', 'sample-list');
      learnViews.forEach((v) => {
        const li = el('li');
        const btn = el('button', 'sample-row');
        btn.type = 'button';
        btn.append(el('span', 'sample-name', v.title), el('span', 'sample-desc', v.subtitle));
        btn.addEventListener('click', () => {
          picked();
          selectTreeNode(v.id, { scrollHex: false });
        });
        li.appendChild(btn);
        list.appendChild(li);
      });
      panel.appendChild(list);
    }
    return panel;
  }

  let openDialog = null;
  function showOpenDialog() {
    if (!config) return;
    if (!state.doc && state.selectedNodeId === 'start') {
      const first = document.querySelector('#inspector-body .open-panel button, #inspector-body .open-panel input');
      if (first) first.focus();
      return;
    }
    if (openDialog) return;
    const body = buildOpenPanel('dialog', () => openDialog && openDialog.close());
    openDialog = openModal({
      title: 'Open a binary',
      bodyEl: body,
      className: 'open-dialog',
      onClose: () => {
        openDialog = null;
      },
    });
  }

  function renderStartInspector(bodyEl) {
    const wrap = el('div', 'start-view');
    if (config) wrap.appendChild(buildOpenPanel('start'));
    bodyEl.replaceChildren(wrap);
  }

  // =========================================================================
  // Left Sidebar: Build & Render Hierarchical Structure Tree
  // =========================================================================
  function buildStructureTree() {
    state.treeNodesMap.clear();
    state.treeNodeAliases.clear();
    state.treeRootNodes = [];
    const learnNodes = [];

    const reg = (node) => {
      state.treeNodesMap.set(node.id, node);
      return node;
    };
    // Name aliases live in their own map and are consulted only when no real id matches (see
    // findNode), so a segment or section whose name looks like a number or a built-in id can never
    // take over another node. Aliases shaped like a positional id are not registered at all, and
    // the first node with a given name keeps the alias.
    const alias = (key, node) => {
      if (/^(seg_\d+|sect_\d+_\d+|lc_\d+)$/.test(key) || state.treeNodeAliases.has(key)) return;
      state.treeNodeAliases.set(key, node);
    };

    const slice = state.doc ? getActiveSlice() : null;
    if (!slice) {
      reg({ id: 'start', label: 'Open a binary', type: 'start', hidden: true });
    } else {
      const fi = state.doc.file_info || {};
      const fmt = sliceFormat(slice);
      const isElf = fmt === 'ELF';
      const isPe = fmt === 'PE';
      const headerRegion = slice.header?.region || { abs_offset: num(slice.slice_base_offset), size: 32 };

      // 1. Overview
      state.treeRootNodes.push(
        reg({
          id: 'overview',
          label: 'Overview',
          icon: 'OV',
          badge: str(slice.format_display || slice.overview?.filetype_name),
          region: headerRegion,
          type: 'overview',
          subtitle: str(slice.overview?.filetype_desc),
        })
      );

      // 1B. Entropy, capabilities, provenance
      const sem = slice.semantic_layers || {};
      const entVal = num(sem.entropy_analysis?.overall_entropy, NaN);
      state.treeRootNodes.push(
        reg({
          id: 'semantic_intel',
          label: 'Entropy & capabilities',
          icon: 'EN',
          badge: Number.isFinite(entVal) ? `${entVal.toFixed(1)} b/B` : '',
          region: headerRegion,
          type: 'semantic_intel',
          subtitle: `${str(sem.entropy_analysis?.overall_classification, 'Entropy')} · ${plural((sem.capabilities?.categories || []).length, 'capability', 'capabilities')} · ${str(sem.provenance?.compiler_family, 'unknown toolchain')}`,
        })
      );

      // 1C / 1D. Built-in learning views live in the "Learn" group.
      const ped = slice.pedagogy || {};
      const stageCount = (ped.loader_lifecycle?.stages || []).length;
      learnNodes.push(
        reg({
          id: 'loader_lifecycle',
          label: 'Loader lifecycle',
          icon: 'LD',
          badge: stageCount ? String(stageCount) : '',
          region: headerRegion,
          type: 'loader_lifecycle',
          subtitle: str(ped.loader_lifecycle?.loader_name, 'How the OS turns this file into a process'),
        })
      );
      // The "Format comparison & tours" node was superseded by static/js/learn.js (views learn.compare
      // and learn.tours, served from /api/learn/*). renderRosettaAndToursInspector is now unreachable
      // (an old #view=rosetta_stone link falls back to Overview) and can be removed by the core.

      // 2. Universal Fat Header (if Fat binary)
      if (fi.is_fat && fi.fat_header) {
        state.treeRootNodes.push(
          reg({
            id: 'fat_header',
            label: 'Fat header',
            icon: 'FAT',
            badge: plural(num(fi.fat_header.nfat_arch, (fi.fat_header.slices_summary || []).length), 'arch', 'archs'),
            region: fi.fat_header.region || { abs_offset: 0, size: 48 },
            type: 'fields',
            fields: fi.fat_header.fields || [],
            subtitle: `${str(fi.fat_header.magic_name, 'FAT_MAGIC')} (${str(fi.fat_header.magic, '0xcafebabe')})`,
          })
        );
      }

      // 3. Primary File Header (Mach-O Header / ELF Ehdr / PE DOS+NT Header)
      if (slice.header) {
        const hdrLabel = isElf
          ? (slice.header.is_64bit ? 'ELF64 header' : 'ELF32 header')
          : isPe
          ? (slice.header.is_64bit ? 'PE32+ headers' : 'PE32 headers')
          : (slice.header.is_64bit ? 'Mach-O header (64-bit)' : 'Mach-O header (32-bit)');
        const hdrNode = reg({
          id: 'mach_header',
          label: hdrLabel,
          icon: 'HDR',
          sub: hex(slice.header.region?.abs_offset ?? slice.slice_base_offset),
          region: slice.header.region,
          type: 'fields',
          fields: slice.header.fields || [],
          subtitle: [slice.header.magic_name, slice.header.cputype_name, slice.header.filetype_name].filter(Boolean).join(' · '),
        });
        alias('header_0', hdrNode);
        state.treeRootNodes.push(hdrNode);
      }

      // 4. Load Commands / Program Headers / PE Headers & Data Directories (#0..#N)
      const lcs = slice.load_commands || [];
      const lcChildren = lcs.map((lc) =>
        reg({
          id: `lc_${lc.index}`,
          parentId: 'load_commands',
          label: `#${lc.index} ${str(lc.cmd_name)}`,
          icon: isElf ? 'PH' : isPe ? 'DIR' : 'LC',
          sub: lc.summary ? str(lc.summary).split(' ')[0] : hex(lc.region?.abs_offset),
          region: lc.region,
          type: 'load_command',
          lc,
          fields: lc.fields || [],
          subtitle: str(lc.summary) || `${str(lc.cmd_name)} (${num(lc.cmdsize)} bytes)`,
        })
      );

      state.treeRootNodes.push(
        reg({
          id: 'load_commands',
          label: isElf ? 'Program headers & notes' : isPe ? 'Headers & data directories' : 'Load commands',
          icon: 'CMD',
          badge: String(lcs.length),
          region: lcs.length
            ? {
                abs_offset: num(lcs[0].region?.abs_offset, num(slice.slice_base_offset) + 32),
                size: num(slice.header?.sizeofcmds, 512),
              }
            : slice.header?.region,
          type: 'load_commands_summary',
          children: lcChildren,
        })
      );

      // 5. Segments & Sections
      const segs = slice.segments || [];
      const segChildren = segs.map((seg, sIdx) => {
        const sectChildren = (seg.sections || []).map((sect, secIdx) => {
          const sectNode = reg({
            id: `sect_${sIdx}_${secIdx}`,
            parentId: `seg_${sIdx}`,
            label: str(sect.sectname, `section ${secIdx}`),
            icon: sect.is_executable ? 'ASM' : 'SEC',
            iconClass: sect.is_executable ? 'tag-code' : '',
            prot: sect.prot || seg.initprot,
            sub: formatBytes(sect.size),
            region: sect.region || { abs_offset: sect.abs_offset, size: sect.size, vmaddr: sect.vmaddr },
            headerRegion: sect.header_region,
            type: 'section',
            segment: seg,
            section: sect,
            fields: sect.fields || [],
            subtitle: `${str(seg.segname)},${str(sect.sectname)} · ${str(sect.section_type, 'regular')}`,
          });
          alias(`sect_${str(sect.segname)}_${str(sect.sectname)}`, sectNode);
          return sectNode;
        });

        const segNode = reg({
          id: `seg_${sIdx}`,
          parentId: 'segments',
          label: str(seg.segname) || `segment ${sIdx}`,
          icon: 'SEG',
          prot: seg.initprot,
          badge: sectChildren.length ? String(sectChildren.length) : null,
          region: seg.region || { abs_offset: seg.abs_offset, size: seg.filesize, vmaddr: seg.vmaddr },
          headerRegion: seg.header_region,
          type: 'segment',
          segment: seg,
          fields: seg.fields || [],
          subtitle: `VM ${str(seg.vmaddr)} (${formatBytes(seg.vmsize_int)}) · file ${hex(seg.abs_offset)} (${formatBytes(seg.filesize)}) · ${str(seg.initprot)}/${str(seg.maxprot)}`,
          children: sectChildren,
        });
        alias(`seg_${str(seg.segname)}`, segNode);
        return segNode;
      });

      state.treeRootNodes.push(
        reg({
          id: 'segments',
          label: 'Segments & sections',
          icon: 'MAP',
          badge: String(segs.length),
          region: segs[0]?.region || slice.header?.region,
          type: 'segments_summary',
          children: segChildren,
        })
      );

      // 6. Disassembly View
      state.treeRootNodes.push(
        reg({
          id: 'disassembly',
          label: 'Disassembly',
          icon: 'ASM',
          iconClass: 'tag-code',
          badge: str(slice.arch_name),
          region: slice.entry_point?.abs_offset
            ? { abs_offset: slice.entry_point.abs_offset, size: 64, vmaddr: slice.entry_point.vmaddr }
            : slice.header?.region,
          type: 'disassembly',
        })
      );

      // 7. Dyld Info / ELF Dynamic Linking / PE Imports, Exports & BaseReloc
      const dyld = slice.dyld_info || {};
      const fixupCount =
        (dyld.chained_fixups?.fixups?.length || 0) +
        (dyld.exports?.length || 0) +
        (dyld.binds?.length || 0) +
        (dyld.rebases?.length || 0);
      state.treeRootNodes.push(
        reg({
          id: 'dyld_info',
          label: isElf ? 'Dynamic linking' : isPe ? 'Imports, exports & relocations' : 'Fixups & exports',
          icon: 'FIX',
          badge: String(fixupCount),
          region: dyld.chained_fixups?.region || slice.header?.region,
          type: 'dyld_info',
        })
      );

      // 8. Symbol Table (LC_SYMTAB / .dynsym+.symtab / PE Imports+Exports)
      const syms = slice.symbols || [];
      state.treeRootNodes.push(
        reg({
          id: 'symtab',
          label: 'Symbols',
          icon: 'SYM',
          badge: String(syms.length),
          region: syms[0] ? { abs_offset: syms[0].abs_offset, size: syms.length * num(syms[0].size, 16) } : slice.header?.region,
          type: 'symtab',
        })
      );

      // 9. Dynamic Symbol Table (LC_DYSYMTAB / PLT / IAT Thunks)
      const dysym = slice.dysymtab || {};
      state.treeRootNodes.push(
        reg({
          id: 'dysymtab',
          label: isElf ? 'PLT / GOT slots' : isPe ? 'IAT thunks' : 'Indirect symbols',
          icon: 'DYS',
          badge: String((dysym.indirect_symbols || []).length),
          region: slice.header?.region,
          type: 'dysymtab',
        })
      );

      // 10. Strings Table & C-String Literals
      const strs = slice.strings || [];
      state.treeRootNodes.push(
        reg({
          id: 'strings',
          label: 'Strings',
          icon: 'STR',
          badge: String(strs.length),
          region: strs[0] ? { abs_offset: strs[0].abs_offset, size: strs[0].length } : slice.header?.region,
          type: 'strings',
        })
      );

      // 11. Function Starts & Entry Point / Thread State
      const fnStarts = slice.function_starts || [];
      state.treeRootNodes.push(
        reg({
          id: 'function_starts',
          label: 'Entry point & functions',
          icon: 'FN',
          badge: String(fnStarts.length || (slice.entry_point ? 1 : 0)),
          region: slice.entry_point?.abs_offset
            ? { abs_offset: slice.entry_point.abs_offset, size: 16, vmaddr: slice.entry_point.vmaddr }
            : slice.header?.region,
          type: 'function_starts',
        })
      );

      // 12. Objective-C Metadata / Fileset Entries (if present)
      const objc = slice.objc_metadata || {};
      const objcTotal = (objc.classes?.length || 0) + (objc.selectors?.length || 0) + (objc.protocols?.length || 0) + (slice.fileset_entries?.length || 0);
      if (objcTotal > 0 || objc.present) {
        state.treeRootNodes.push(
          reg({
            id: 'objc_metadata',
            label: 'Objective-C & filesets',
            icon: 'OBJ',
            badge: String(objcTotal),
            region: slice.header?.region,
            type: 'objc_metadata',
          })
        );
      }

      // 13. Code Signature & Entitlements / Authenticode / ELF Build-ID
      const cs = slice.code_signature_detail || {};
      const noteCount = (slice.elf_metadata?.notes || []).length;
      state.treeRootNodes.push(
        reg({
          id: 'code_signature',
          label: isPe ? 'Authenticode' : isElf ? 'Notes & build ID' : 'Code signature',
          icon: 'SIG',
          // Mach-O: page hashes checked against the CodeDirectory. PE: the certificate table holds this
          // file's Authenticode hash. Neither says the signature or its chain was evaluated. ELF has no
          // embedded signature; the node lists its notes.
          badge: cs.present
            ? (isPe ? (cs.code_directory?.cdhash_verified ? 'hash matches' : 'present') : (cs.code_directory?.cdhash_verified ? 'verified' : 'signed'))
            : isElf && noteCount ? String(noteCount) : 'none',
          region: cs.superblob_region || slice.header?.region,
          type: 'code_signature',
        })
      );

      // 14. Security & Hardening Audit
      const sec = slice.security_posture || {};
      const warnCount = (sec.checks || []).filter((c) => c.status === 'WARN' || c.status === 'FAIL').length;
      state.treeRootNodes.push(
        reg({
          id: 'security_audit',
          label: 'Hardening',
          icon: 'SEC',
          iconClass: warnCount > 0 ? 'tag-warn' : '',
          badge: warnCount > 0 ? `${warnCount} to review` : 'ok',
          region: slice.header?.region,
          type: 'security_audit',
        })
      );
    }

    // Assemble groups: built-in nodes first, then registered views.
    const groups = new Map();
    groups.set('Analysis', [...state.treeRootNodes]);
    groups.set('Learn', learnNodes);
    [...extViews.values()]
      .filter((v) => !v.requiresDoc || state.doc)
      .sort((a, b) => a.order - b.order || a.title.localeCompare(b.title))
      .forEach((v) => {
        const node = reg({ id: v.id, label: v.title, icon: v.icon || initials(v.title), badge: v.badge, type: 'ext', view: v, subtitle: v.subtitle });
        if (!groups.has(v.group)) groups.set(v.group, []);
        groups.get(v.group).push(node);
      });

    const names = [...groups.keys()];
    const ordered = [
      ...GROUP_ORDER.filter((g) => groups.has(g)),
      ...names.filter((g) => !GROUP_ORDER.includes(g) && g !== LAST_GROUP),
      ...(groups.has(LAST_GROUP) ? [LAST_GROUP] : []),
    ];
    state.treeGroups = ordered.map((id) => ({ id, nodes: groups.get(id) })).filter((g) => g.nodes.length > 0);
    const tagGroup = (node, groupId) => {
      node.groupId = groupId;
      (node.children || []).forEach((child) => tagGroup(child, groupId));
    };
    state.treeGroups.forEach((g) => g.nodes.forEach((n) => tagGroup(n, g.id)));
  }

  function renderStructureTree() {
    const container = document.getElementById('structure-tree');
    if (!container) return;
    const filter = state.treeFilter.trim().toLowerCase();
    const focusKey = state.treeVisible[state.treeFocusIndex]?.key;

    const matchesNode = (node) => {
      if (!filter) return true;
      if (str(node.label).toLowerCase().includes(filter)) return true;
      if (node.subtitle && str(node.subtitle).toLowerCase().includes(filter)) return true;
      if (node.sub && str(node.sub).toLowerCase().includes(filter)) return true;
      if (Array.isArray(node.children)) {
        return node.children.some(matchesNode);
      }
      return false;
    };

    const rows = [];
    const visible = [];
    const renderNode = (node, depth, parentRow) => {
      if (!matchesNode(node)) return;
      const hasChildren = Array.isArray(node.children) && node.children.length > 0;
      const isExpanded = filter ? true : state.expandedNodeIds.has(node.id);
      const isSelected = state.selectedNodeId === node.id;
      const rowIndex = visible.length;
      visible.push({ key: `n:${node.id}`, kind: 'node', id: node.id, hasChildren, expanded: hasChildren && isExpanded, parentRow });

      rows.push(html`
        <div class="tree-node-row ${isSelected ? 'selected' : ''}" id="tree-row-${rowIndex}" data-row="${rowIndex}" data-node-id="${node.id}" data-indent="${8 + depth * 14}"
             role="treeitem" aria-level="${depth + 2}" aria-selected="${isSelected ? 'true' : 'false'}" ${hasChildren ? raw(`aria-expanded="${isExpanded ? 'true' : 'false'}"`) : ''}>
          <span class="tree-twisty ${hasChildren ? (isExpanded ? 'expanded' : '') : 'leaf'}" data-twisty-id="${node.id}" aria-hidden="true"></span>
          <span class="tree-icon ${tok(node.iconClass)}" aria-hidden="true">${node.icon || '·'}</span>
          <span class="tree-label" title="${node.subtitle || node.label}">${node.label}</span>
          ${node.prot ? html`<span class="prot-pill ${protClass(node.prot)}">${str(node.prot).toUpperCase()}</span>` : ''}
          ${node.sub && !node.badge ? html`<span class="tree-sub">${node.sub}</span>` : ''}
          ${node.badge ? html`<span class="tree-badge">${node.badge}</span>` : ''}
        </div>
      `);

      if (hasChildren && isExpanded) {
        node.children.forEach((child) => renderNode(child, depth + 1, rowIndex));
      }
    };

    state.treeGroups.forEach((group) => {
      const nodes = group.nodes.filter(matchesNode);
      if (!nodes.length) return;
      const collapsed = !filter && state.collapsedGroups.has(group.id);
      const rowIndex = visible.length;
      visible.push({ key: `g:${group.id}`, kind: 'group', id: group.id, hasChildren: true, expanded: !collapsed, parentRow: -1 });
      rows.push(html`
        <div class="tree-group-row" id="tree-row-${rowIndex}" data-row="${rowIndex}" data-group-id="${group.id}" role="treeitem" aria-level="1" aria-expanded="${collapsed ? 'false' : 'true'}">
          <span class="tree-twisty ${collapsed ? '' : 'expanded'}" aria-hidden="true"></span>
          <span class="tree-group-label">${group.id}</span>
        </div>
      `);
      if (!collapsed) nodes.forEach((n) => renderNode(n, 0, rowIndex));
    });

    if (!rows.length) {
      rows.push(html`<div class="tree-empty">${filter ? 'No matching nodes.' : 'Open a binary to see its structure.'}</div>`);
    }

    container.innerHTML = html`${rows}`;
    hydrateStyles(container);
    state.treeVisible = visible;
    const keep = focusKey ? visible.findIndex((r) => r.key === focusKey) : -1;
    state.treeFocusIndex = keep;
    paintTreeFocus(false);
  }

  function paintTreeFocus(scroll) {
    const container = document.getElementById('structure-tree');
    if (!container) return;
    container.querySelectorAll('.kbd-focus').forEach((n) => n.classList.remove('kbd-focus'));
    const row = state.treeFocusIndex >= 0 ? document.getElementById(`tree-row-${state.treeFocusIndex}`) : null;
    if (row && document.activeElement === container) {
      row.classList.add('kbd-focus');
      container.setAttribute('aria-activedescendant', row.id);
      if (scroll) row.scrollIntoView({ block: 'nearest' });
    } else {
      container.removeAttribute('aria-activedescendant');
    }
  }

  function toggleTreeGroup(groupId) {
    if (state.collapsedGroups.has(groupId)) state.collapsedGroups.delete(groupId);
    else state.collapsedGroups.add(groupId);
    storage.set('tree.collapsed', [...state.collapsedGroups]);
    renderStructureTree();
  }

  /**
   * Open a tree node (built-in or registered view).
   * opts: {scrollHex = true, recordHistory = true, params}
   */
  /** The node for an id: real ids (positional, built-in, registered views) first, then name aliases. */
  function findNode(id) {
    if (typeof id !== 'string' || !id) return null;
    return state.treeNodesMap.get(id) || state.treeNodeAliases.get(id) || null;
  }

  function hasNode(id) {
    return findNode(id) !== null;
  }

  function selectTreeNode(nodeId, options) {
    const opts = Object.assign({ scrollHex: true, recordHistory: true }, options);
    const node = findNode(nodeId);
    if (!node) return false;
    const canonicalId = node.id;

    // Reveal: expand every ancestor and the group that holds the node.
    let parent = node.parentId ? state.treeNodesMap.get(node.parentId) : null;
    while (parent) {
      state.expandedNodeIds.add(parent.id);
      parent = parent.parentId ? state.treeNodesMap.get(parent.parentId) : null;
    }
    if (node.groupId && state.collapsedGroups.has(node.groupId)) {
      state.collapsedGroups.delete(node.groupId);
      storage.set('tree.collapsed', [...state.collapsedGroups]);
    }

    state.selectedNodeId = canonicalId;
    state.viewParams = flattenParams(opts.params);
    renderStructureTree();

    if (state.doc && node.region && typeof node.region.abs_offset === 'number') {
      state.structSpan = {
        abs_offset: node.region.abs_offset,
        size: Math.max(1, num(node.region.size, 16)),
        label: node.label,
      };
      setFieldSpan(null);
      if (opts.scrollHex) {
        setCursorAndHighlight(node.region.abs_offset, null, { scrollHex: true });
      }
    }

    if (opts.recordHistory && !state.suppressHistory) {
      pushHistory(currentEntry());
    } else {
      syncLocationSoon();
    }

    renderCenterInspector(node);
    renderMemoryMapRibbon();
    document.getElementById('workspace-main')?.classList.remove('sidebar-open');
    bus.emit('node:selected', { id: canonicalId });
    return true;
  }

  function flattenParams(params) {
    const out = Object.create(null); // keys come from URLs: no prototype to shadow or reach
    if (params && typeof params === 'object') {
      Object.entries(params).forEach(([k, v]) => {
        if (v === null || v === undefined) return;
        if (/^[A-Za-z0-9_.-]{1,40}$/.test(k)) out[k] = String(v);
      });
    }
    return out;
  }

  // =========================================================================
  // Top Dual Visual Memory Map Ribbon (File Layout vs Virtual Memory Layout)
  // =========================================================================
  function segProtClass(seg) {
    const p = str(seg.initprot);
    if (p.includes('w') && p.includes('x')) return 'prot-rwx';
    if (p.includes('x')) return 'prot-rx';
    if (p.includes('w')) return 'prot-rw';
    return 'prot-ro';
  }

  function renderMemoryMapRibbon() {
    const fileTrack = document.getElementById('memmap-file-track');
    const vmTrack = document.getElementById('memmap-vm-track');
    if (!fileTrack || !vmTrack) return;

    const slice = getActiveSlice();
    if (!slice || !state.doc) {
      fileTrack.replaceChildren();
      vmTrack.replaceChildren();
      updateMemoryMapPlayhead();
      return;
    }

    const scaleFn = (size) => {
      const s = Math.max(1, num(size, 1));
      return state.memmapScale === 'sqrt' ? Math.sqrt(s) : s;
    };

    const segs = slice.segments || [];

    // 1. Build File Track Blocks
    const fileBlocks = [];
    // Header + load commands block at the start of the slice
    const hdrSize = num(slice.header?.region?.size, 32) + num(slice.header?.sizeofcmds);
    if (hdrSize > 0) {
      fileBlocks.push({
        id: 'mach_header',
        label: 'Headers',
        abs_offset: num(slice.slice_base_offset),
        size: hdrSize,
        vmaddr: slice.segments?.[0]?.vmaddr || '0x0',
        protClass: 'prot-hdr',
        protLabel: 'header',
      });
    }

    segs.forEach((seg, idx) => {
      if (num(seg.filesize) <= 0) return;
      fileBlocks.push({
        id: `seg_${idx}`,
        label: str(seg.segname),
        abs_offset: num(seg.abs_offset),
        size: num(seg.filesize),
        vmaddr: seg.vmaddr,
        vmsize: seg.vmsize_int,
        protClass: segProtClass(seg),
        protLabel: `${str(seg.initprot)}/${str(seg.maxprot)}`,
      });
    });

    if (slice.code_signature_detail?.present && slice.code_signature_detail.superblob_region) {
      const csReg = slice.code_signature_detail.superblob_region;
      fileBlocks.push({
        id: 'code_signature',
        label: 'Signature',
        abs_offset: num(csReg.abs_offset),
        size: num(csReg.size),
        vmaddr: null,
        protClass: 'prot-cs',
        protLabel: 'signature',
      });
    }

    const totalFileWeight = fileBlocks.reduce((acc, b) => acc + scaleFn(b.size), 0) || 1;
    fileTrack.innerHTML = html`${fileBlocks.map((b) => html`
      <div class="memmap-block ${b.protClass} ${state.selectedNodeId === b.id ? 'active-block' : ''}"
           data-w="${((scaleFn(b.size) / totalFileWeight) * 100).toFixed(3)}"
           data-node-id="${b.id}" data-abs-offset="${b.abs_offset}" data-size="${b.size}"
           data-tt-title="${b.label} — file"
           data-tt-file="${hex(b.abs_offset)} – ${hex(b.abs_offset + b.size)} (${formatBytes(b.size)})"
           data-tt-vm="${b.vmaddr ? b.vmaddr : 'not mapped'}"
           data-tt-prot="${b.protLabel}">${b.label}</div>
    `)}`;

    // 2. Build Virtual Memory Track Blocks
    const vmBlocks = segs
      .map((seg, idx) => ({ seg, idx }))
      .filter(({ seg }) => num(seg.vmsize_int) > 0)
      .map(({ seg, idx }) => {
        const isPageZero = seg.segname === '__PAGEZERO';
        // Cap __PAGEZERO's visual weight so the other segments remain visible
        const rawVmSize = isPageZero ? Math.min(num(seg.vmsize_int), state.memmapScale === 'linear' ? 65536 : 256 * 1024) : num(seg.vmsize_int);
        return {
          id: `seg_${idx}`,
          label: str(seg.segname),
          abs_offset: num(seg.abs_offset),
          size: num(seg.filesize),
          vmaddr: seg.vmaddr,
          vmsize: num(seg.vmsize_int),
          weight: scaleFn(rawVmSize),
          protClass: isPageZero ? 'prot-pagezero' : segProtClass(seg),
          protLabel: `${str(seg.initprot)}/${str(seg.maxprot)}`,
        };
      });

    const totalVmWeight = vmBlocks.reduce((acc, b) => acc + b.weight, 0) || 1;
    vmTrack.innerHTML = html`${vmBlocks.map((b) => html`
      <div class="memmap-block ${b.protClass} ${state.selectedNodeId === b.id ? 'active-block' : ''}"
           data-w="${((b.weight / totalVmWeight) * 100).toFixed(3)}"
           data-node-id="${b.id}" data-abs-offset="${b.abs_offset}" data-size="${b.size}" data-vmsize="${b.vmsize}"
           data-tt-title="${b.label} — virtual memory"
           data-tt-file="${b.size > 0 ? `${hex(b.abs_offset)} (${formatBytes(b.size)})` : 'no file bytes (zero-fill)'}"
           data-tt-vm="${str(b.vmaddr)} (${formatBytes(b.vmsize)})"
           data-tt-prot="${b.protLabel}">${b.label}</div>
    `)}`;

    hydrateStyles(fileTrack);
    hydrateStyles(vmTrack);
    updateMemoryMapPlayhead();
  }

  /** Place each track's playhead inside the block that actually contains the cursor. */
  function updateMemoryMapPlayhead() {
    const container = document.getElementById('memmap-tracks-container');
    if (!container) return;
    const containerRect = container.getBoundingClientRect();
    const place = (playheadId, trackId, extentAttr) => {
      const ph = document.getElementById(playheadId);
      const track = document.getElementById(trackId);
      if (!ph || !track) return;
      let left = null;
      if (state.doc) {
        for (const block of track.children) {
          const start = num(block.dataset.absOffset, -1);
          const size = num(block.dataset.size);
          if (size <= 0 || state.cursorOffset < start || state.cursorOffset >= start + size) continue;
          const extent = Math.max(size, num(block.dataset[extentAttr], size));
          const rect = block.getBoundingClientRect();
          if (rect.width > 0) left = rect.left - containerRect.left + ((state.cursorOffset - start) / extent) * rect.width;
          break;
        }
      }
      if (left === null) {
        ph.hidden = true;
      } else {
        ph.style.left = `${left}px`;
        ph.hidden = false;
      }
    };
    place('memmap-playhead-file', 'memmap-file-track', 'size');
    place('memmap-playhead-vm', 'memmap-vm-track', 'vmsize');
  }

  // =========================================================================
  // Center Context-Sensitive Inspector Renderer
  // =========================================================================
  let activeExt = null; // {view} — the registered view currently mounted in the inspector

  function disposeActiveExtView() {
    if (!activeExt) return;
    const view = activeExt.view;
    activeExt = null;
    if (view.dispose) {
      try {
        view.dispose();
      } catch (err) {
        console.error(`[BinaryStudio] dispose() of view "${view.id}" failed:`, err);
      }
    }
  }

  // Small markup helpers shared by the views. Every interpolation is escaped by html``.
  const jumpChip = (off, size, label) => html`<button type="button" class="jump-chip" data-jump-offset="${num(off)}" data-jump-size="${Math.max(1, num(size, 16))}">${label}</button>`;
  const disasmChip = (vm, label) => (vm ? html`<button type="button" class="jump-chip" data-disasm-vm="${vm}">${label}</button>` : '');
  const nodeChip = (id, label) => html`<button type="button" class="jump-chip" data-select-node="${id}">${label}</button>`;
  const emptyRow = (cols, text) => html`<tr class="empty-row"><td colspan="${cols}">${text}</td></tr>`;
  const flagPills = (list) => (list || []).map((f) => html`<span class="bitflag-pill" title="${f}">${f}</span>`);
  const kpi = (label, value, sub, tone) => html`
    <div class="kpi-card">
      <span class="kpi-label">${label}</span>
      <span class="kpi-value ${tok(tone)}" title="${value}">${value}</span>
      <span class="kpi-sub">${sub}</span>
    </div>`;
  /** A cell whose value can be copied with Alt/Option-click. */
  const cp = (cls, value, shown) => html`<td class="${cls}" data-copy="${str(value)}" title="${str(value)}">${shown === undefined ? value : shown}</td>`;

  function errorCard(title, detail) {
    const card = el('div', 'panel-card error-card');
    card.setAttribute('role', 'alert');
    card.appendChild(el('div', 'panel-card-header', title));
    if (detail) card.appendChild(el('pre', 'xml-code-block', truncate(detail, 2000)));
    const wrap = el('div', 'overview-container');
    wrap.appendChild(card);
    return wrap;
  }

  function renderCenterInspector(node) {
    const titleEl = document.getElementById('inspector-title');
    const subEl = document.getElementById('inspector-subtitle');
    const pillsEl = document.getElementById('inspector-meta-pills');
    const bodyEl = document.getElementById('inspector-body');
    if (!bodyEl || !node) return;
    const token = ++renderToken;
    disposeActiveExtView();

    titleEl.textContent = str(node.label);
    subEl.textContent = str(node.subtitle);
    subEl.title = str(node.subtitle);

    // Offset / address / size pills. Each one copies its value when clicked.
    const reg = node.type === 'ext' || node.type === 'start' ? null : node.region;
    if (reg && typeof reg.abs_offset === 'number') {
      pillsEl.innerHTML = html`
        <button type="button" class="meta-pill" data-copy="${hex(reg.abs_offset)}" title="Copy file offset">File <strong>${hex(reg.abs_offset, 6)}</strong></button>
        ${reg.vmaddr ? html`<button type="button" class="meta-pill" data-copy="${reg.vmaddr}" title="Copy virtual address">VM <strong>${reg.vmaddr}</strong></button>` : ''}
        ${reg.size ? html`<button type="button" class="meta-pill" data-copy="${num(reg.size)}" title="Copy size in bytes">Size <strong>${formatBytes(reg.size)} (${hex(reg.size)})</strong></button>` : ''}
        ${jumpChip(reg.abs_offset, reg.size || 16, 'Show in hex')}
      `;
    } else {
      pillsEl.replaceChildren();
    }

    bodyEl.className = `inspector-body view-${tok(node.type)}`;
    bodyEl.scrollTop = 0;

    try {
      // Route to specialized view renderer
      switch (node.type) {
        case 'start':
          renderStartInspector(bodyEl);
          break;
        case 'ext':
          renderExtView(bodyEl, node, token);
          break;
        case 'overview':
          renderOverviewInspector(bodyEl);
          break;
        case 'semantic_intel':
          renderSemanticIntelInspector(bodyEl);
          break;
        case 'loader_lifecycle':
          renderLoaderLifecycleInspector(bodyEl);
          break;
        case 'rosetta_stone':
          renderRosettaAndToursInspector(bodyEl);
          break;
        case 'fields':
        case 'load_command':
        case 'segment':
        case 'section':
          renderStructInspector(bodyEl, node);
          break;
        case 'load_commands_summary':
          renderLoadCommandsSummaryInspector(bodyEl);
          break;
        case 'segments_summary':
          renderSegmentsSummaryInspector(bodyEl);
          break;
        case 'disassembly':
          renderDisassemblyInspector(bodyEl, token);
          break;
        case 'dyld_info':
          renderDyldInspector(bodyEl);
          break;
        case 'symtab':
          renderSymbolTableInspector(bodyEl);
          break;
        case 'dysymtab':
          renderDysymtabInspector(bodyEl);
          break;
        case 'strings':
          renderStringsInspector(bodyEl);
          break;
        case 'function_starts':
          renderFunctionStartsInspector(bodyEl);
          break;
        case 'objc_metadata':
          renderObjcInspector(bodyEl);
          break;
        case 'code_signature':
          renderCodeSignatureInspector(bodyEl);
          break;
        case 'security_audit':
          renderSecurityAuditInspector(bodyEl);
          break;
        default:
          renderOverviewInspector(bodyEl);
      }
    } catch (err) {
      // A malformed document must never take the shell down with it.
      console.error(`[BinaryStudio] view "${node.id}" failed to render:`, err);
      bodyEl.replaceChildren(errorCard('This view could not be rendered from the analysis data.', str(err && err.message)));
    }
    afterRender(bodyEl, node.id);
  }

  /** Re-render the open view in place (sub-tab or filter change). */
  function refreshInspector() {
    const node = state.treeNodesMap.get(state.selectedNodeId);
    if (!node) return;
    const bodyEl = document.getElementById('inspector-body');
    const top = bodyEl ? bodyEl.scrollTop : 0;
    renderCenterInspector(node);
    if (bodyEl) bodyEl.scrollTop = top;
  }

  function afterRender(bodyEl, id) {
    hydrateStyles(bodyEl);
    // Roving tabindex: Tab reaches the first row of each table, arrow keys move between rows.
    bodyEl.querySelectorAll('table').forEach((table) => {
      table.querySelectorAll('tr.struct-row, tr.disasm-row').forEach((row, i) => {
        row.tabIndex = i === 0 ? 0 : -1;
      });
    });
    bodyEl.querySelectorAll('.kv-row[data-jump-offset]').forEach((row) => {
      row.tabIndex = 0;
      row.setAttribute('role', 'button');
    });
    bus.emit('view:rendered', { id, bodyEl });
  }

  function renderExtView(bodyEl, node, token) {
    const view = node.view;
    bodyEl.replaceChildren();
    const subEl = document.getElementById('inspector-subtitle');
    const ctx = {
      id: view.id,
      params: Object.assign({}, state.viewParams),
      doc: state.doc,
      docId: state.docId,
      slice: getActiveSlice(),
      sliceIndex: state.activeSliceIndex,
      bodyEl,
      setSubtitle(text) {
        if (token === renderToken && subEl) {
          subEl.textContent = str(text);
          subEl.title = str(text);
        }
      },
    };
    activeExt = { view };
    const fail = (err) => {
      console.error(`[BinaryStudio] view "${view.id}" failed to render:`, err);
      if (token !== renderToken) return;
      bodyEl.replaceChildren(errorCard(`${view.title} could not be shown.`, str(err && err.message)));
    };
    try {
      const result = view.render(bodyEl, ctx);
      if (result && typeof result.then === 'function') {
        result.then(() => {
          if (token === renderToken) afterRender(bodyEl, view.id);
        }, fail);
      }
    } catch (err) {
      fail(err);
    }
  }

  // -------------------------------------------------------------------------
  // View 1: Overview
  // -------------------------------------------------------------------------
  function renderOverviewInspector(bodyEl) {
    const fi = state.doc?.file_info || {};
    const slice = getActiveSlice();
    if (!slice) return;
    const fmt = sliceFormat(slice);
    const ov = slice.overview || {};
    const sec = slice.security_posture || {};
    const cs = sec.code_signature || {};
    const dylibs = slice.dylibs || [];
    const rpaths = slice.rpaths || [];
    const fatSlices = fi.is_fat && Array.isArray(fi.fat_header?.slices_summary) ? fi.fat_header.slices_summary : null;

    const cmdNoun = fmt === 'ELF' ? 'program headers' : fmt === 'PE' ? 'headers & directories' : 'load commands';
    const idLabel = fmt === 'ELF' ? 'Build ID' : fmt === 'PE' ? 'Debug GUID' : 'UUID';
    // `pie_applicable === false`: MH_PIE means nothing for this Mach-O file type (dylib, bundle, object, ...).
    const pieLabel = sec.pie_applicable === false ? 'PIE n/a' : sec.pie ? 'PIE' : 'no PIE';
    const hardening = [pieLabel, fmt === 'MACHO' && sec.pac_enabled ? 'PAC' : '', sec.has_rwx_segments ? 'RWX segment' : 'W^X'].filter(Boolean).join(' · ');
    const signed = fmt === 'ELF' ? 'n/a' : cs.present ? (cs.cdhash_verified ? (fmt === 'PE' ? 'hash matches' : 'verified') : 'present') : 'none';
    const sigRowLabel = fmt === 'PE' ? 'Authenticode' : 'Signature';

    bodyEl.innerHTML = html`
      <div class="overview-container">
        <div class="kpi-cards-grid">
          ${kpi('Type', str(ov.filetype_name || slice.header?.filetype_name, '—'), `${str(ov.arch_display || slice.arch_name)} · ${str(ov.endianness)}`, 'accent')}
          <div class="kpi-card">
            <span class="kpi-label">Entry point · ${str(ov.entry_point_type, 'none')}</span>
            <span class="kpi-value" data-copy="${str(ov.entry_point_vmaddr)}">${str(ov.entry_point_vmaddr, '—')}</span>
            <span class="kpi-sub">file ${hex(ov.entry_point_abs_offset)} ${disasmChip(ov.entry_point_vmaddr, 'Disassemble')}</span>
          </div>
          ${kpi('Platform', str(ov.platform, '—'), fmt === 'MACHO' ? `min OS ${str(ov.minos, '—')} · SDK ${str(ov.sdk, '—')}` : [ov.minos, ov.sdk].filter(Boolean).join(' · '))}
          ${kpi('Structure', `${num(ov.ncmds)} ${cmdNoun}`, `${num(ov.segments_count)} segments · ${num(ov.sections_count)} sections · ${num(ov.symbols_count)} symbols · ${num(ov.strings_count)} strings`)}
          <div class="kpi-card">
            <span class="kpi-label">Hardening</span>
            <span class="kpi-value ${sec.has_rwx_segments ? 'bad' : 'ok'}">${hardening}</span>
            <span class="kpi-sub">stack canary ${sec.stack_canary ? 'yes' : 'no'} · signature ${signed} ${nodeChip('security_audit', 'Details')}</span>
          </div>
        </div>

        ${fatSlices ? html`
          <div class="panel-card">
            <div class="panel-card-header"><span>Architecture slices (${fatSlices.length})</span>${nodeChip('fat_header', 'Fat header')}</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>#</th><th>Architecture</th><th>CPU type / subtype</th><th>Offset</th><th>Size</th><th>Alignment</th><th></th></tr></thead>
                <tbody>
                  ${fatSlices.map((s, idx) => html`
                    <tr class="struct-row ${idx === state.activeSliceIndex ? 'active-field-row' : ''}" data-switch-slice="${idx}">
                      <td>${idx}</td>
                      <td class="col-name">${s.arch_name}</td>
                      <td>${s.cputype_name} / ${s.cpusubtype_name}</td>
                      ${cp('col-offset', hex(s.offset), hex(s.offset, 6))}
                      <td>${formatBytes(s.size)} (${hex(s.size)})</td>
                      <td>2^${num(s.align)} (${formatBytes(s.align_bytes)})</td>
                      <td>${idx === state.activeSliceIndex ? 'active' : html`<button type="button" class="jump-chip" data-switch-slice="${idx}">Switch</button>`}</td>
                    </tr>
                  `)}
                </tbody>
              </table>
            </div>
          </div>
        ` : ''}

        <div class="overview-two-col">
          <div class="panel-card">
            <div class="panel-card-header"><span>Identity</span>${nodeChip('mach_header', 'Header')}</div>
            <div class="kv-list">
              <div class="kv-row"><span class="kv-key">File</span><span class="kv-val" data-copy="${str(fi.path || fi.filename)}">${str(fi.path || fi.filename)}</span></div>
              <div class="kv-row"><span class="kv-key">Size</span><span class="kv-val">${formatBytes(fi.file_size)}${fi.is_fat ? ` · slice ${formatBytes(slice.slice_size)} at ${hex(slice.slice_base_offset)}` : ''}</span></div>
              <div class="kv-row"><span class="kv-key">${idLabel}</span><span class="kv-val" data-copy="${str(ov.uuid)}">${str(ov.uuid, 'none')}</span></div>
              <div class="kv-row"><span class="kv-key">SHA-256</span><span class="kv-val" data-copy="${str(fi.sha256)}">${str(fi.sha256, '—')}</span></div>
              <div class="kv-row"><span class="kv-key">MD5</span><span class="kv-val" data-copy="${str(fi.md5)}">${str(fi.md5, '—')}</span></div>
              <div class="kv-row"><span class="kv-key">Header flags ${str(slice.header?.flags_hex)}</span><span class="kv-val flag-list">${(slice.header?.flags_decoded || []).length ? flagPills(slice.header.flags_decoded) : 'none'}</span></div>
              ${fmt === 'ELF'
                ? html`<div class="kv-row"><span class="kv-key">Signature</span><span class="kv-val">not applicable: ELF has no embedded signature format</span></div>`
                : html`<div class="kv-row"><span class="kv-key">${sigRowLabel}</span><span class="kv-val" data-copy="${str(cs.cdhash)}">${str(cs.identifier, cs.present ? 'present' : 'none')}${cs.cdhash ? ` (${fmt === 'PE' ? 'image hash ' : ''}${str(cs.cdhash).slice(0, 20)}…)` : ''}</span></div>`}
            </div>
          </div>

          <div class="panel-card">
            <div class="panel-card-header"><span>Linked libraries (${dylibs.length})${rpaths.length ? ` · run paths (${rpaths.length})` : ''}</span>${nodeChip('load_commands', cmdNoun)}</div>
            <div class="kv-list">
              ${dylibs.length === 0 && rpaths.length === 0 ? html`<div class="kv-row"><span class="kv-key">No dynamic library dependencies.</span></div>` : ''}
              ${dylibs.map((d) => html`
                <div class="kv-row row-clickable" data-jump-offset="${num(d.abs_offset)}" data-jump-size="${num(d.size, 16)}">
                  <span class="kv-key lib-name" data-copy="${str(d.name)}" title="${str(d.name)}">${d.name}</span>
                  <span class="kv-val">${d.current_version ? `${d.current_version} · ` : ''}${d.cmd_name}</span>
                </div>
              `)}
              ${rpaths.map((r) => html`
                <div class="kv-row row-clickable" data-jump-offset="${num(r.abs_offset)}" data-jump-size="${num(r.size, 16)}">
                  <span class="kv-key">run path</span>
                  <span class="kv-val" data-copy="${str(r.path)}">${r.path}</span>
                </div>
              `)}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 2: Structure Field Table View (Headers, Load Commands, Segments, Sections)
  // -------------------------------------------------------------------------
  function structFieldsTable(fields) {
    return html`
      <div class="struct-table-wrap">
        <table class="struct-table">
          <thead>
            <tr><th>File offset</th><th class="col-slice">Slice offset</th><th class="col-rawbytes">Bytes</th><th class="col-type">Type</th><th>Field</th><th>Value</th><th>Meaning</th></tr>
          </thead>
          <tbody>
            ${fields.length === 0 ? emptyRow(7, 'No fields decoded for this structure.') : ''}
            ${fields.map((f, idx) => {
              const flags = Array.isArray(f.bit_flags) ? f.bit_flags.filter((bf) => bf && bf.set !== false) : [];
              let jump = '';
              if (typeof f.target_offset === 'number' && f.target_offset > 0) jump = jumpChip(f.target_offset, 16, `Go to ${hex(f.target_offset)}`);
              else if (f.target_vmaddr) jump = disasmChip(f.target_vmaddr, `Go to ${f.target_vmaddr}`);
              const ped = f.pedagogy;
              return html`
                <tr class="struct-row" data-field-idx="${idx}" data-abs-offset="${num(f.abs_offset)}" data-field-size="${num(f.size, 1)}" data-field-name="${str(f.name)}">
                  ${cp('col-offset', hex(f.abs_offset), hex(f.abs_offset, 6))}
                  <td class="col-offset col-slice">+${hex(f.slice_offset, 4)}</td>
                  ${cp('col-bytes col-rawbytes', str(f.raw_hex), str(f.raw_hex))}
                  <td class="col-type">${f.type} · ${num(f.size)} B</td>
                  ${cp('col-name', str(f.name), str(f.name))}
                  ${cp('col-val', str(f.value), str(f.value))}
                  <td class="col-desc">
                    <strong>${str(f.interpreted)}</strong>
                    ${f.description ? html`<span class="t-dim"> — ${f.description}</span>` : ''}
                    ${jump}
                    ${flags.length ? html`<div class="bitflags-inline">${flags.map((bf) => html`<span class="bitflag-pill" title="mask ${str(bf.mask)}">${bf.name} (${str(bf.mask)})</span>`)}</div>` : ''}
                    ${ped ? html`
                      <div class="pedagogy-inline-box learn-only">
                        <div><strong>Why it matters</strong> ${str(ped.why_it_matters)}</div>
                        <div><strong>Loader behaviour</strong> ${str(ped.loader_behavior)}</div>
                        <div><strong>If modified</strong> ${str(ped.what_if_modified)}</div>
                        <div><strong>In other formats</strong> ${str(ped.cross_format_peer)}</div>
                      </div>
                    ` : ''}
                  </td>
                </tr>
              `;
            })}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderStructInspector(bodyEl, node) {
    const fields = node.fields || [];
    let top = '';
    const extra = [];

    // Section: where its data lives, and a shortcut to disassembly if it holds code.
    if (node.type === 'section' && node.section) {
      const s = node.section;
      const key = `${str(s.segname)},${str(s.sectname)}`;
      top = html`
        <div class="explorer-toolbar">
          <div class="toolbar-facts">
            <span class="prot-pill ${protClass(s.prot)}">${str(s.prot, 'r--').toUpperCase()}</span>
            <span>data at <strong class="mono" data-copy="${hex(s.abs_offset)}">${hex(s.abs_offset, 6)}</strong></span>
            <span>VM <strong class="mono" data-copy="${str(s.vmaddr)}">${str(s.vmaddr)}</strong></span>
            <span>${formatBytes(s.size)}</span>
          </div>
          <div class="toolbar-actions">
            ${jumpChip(s.abs_offset, Math.min(num(s.size, 64) || 64, 256), 'Show data in hex')}
            ${s.is_executable ? html`<button type="button" class="jump-chip" data-disasm-section="${key}" data-disasm-vm="${str(s.vmaddr)}">Disassemble</button>` : ''}
          </div>
        </div>
      `;
    }

    // Segment: its sections.
    if (node.type === 'segment' && node.segment && Array.isArray(node.segment.sections) && node.segment.sections.length > 0) {
      const sIdx = num(node.segment.index);
      extra.push(html`
        <div class="pad">
          <div class="panel-card">
            <div class="panel-card-header">Sections in ${str(node.segment.segname)} (${node.segment.sections.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>#</th><th>Section</th><th>VM address</th><th>File offset</th><th>Size</th><th>Type and attributes</th><th></th></tr></thead>
                <tbody>
                  ${node.segment.sections.map((sec, idx) => html`
                    <tr class="struct-row" data-select-node="sect_${sIdx}_${idx}">
                      <td>${idx}</td>
                      ${cp('col-name', `${str(sec.segname)},${str(sec.sectname)}`)}
                      ${cp('col-val', str(sec.vmaddr))}
                      ${cp('col-offset', hex(sec.abs_offset), hex(sec.abs_offset, 6))}
                      <td>${formatBytes(sec.size)} (${hex(sec.size)})</td>
                      <td>${str(sec.section_type)} ${flagPills(sec.attributes_decoded)}</td>
                      <td class="col-actions">
                        ${sec.is_executable ? html`<button type="button" class="jump-chip" data-disasm-section="${str(sec.segname)},${str(sec.sectname)}" data-disasm-vm="${str(sec.vmaddr)}">Disassemble</button>` : ''}
                      </td>
                    </tr>
                  `)}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      `);
    }

    // Thread-state load command: initial register values.
    const registers = node.type === 'load_command' ? node.lc?.details?.registers : null;
    if (registers && typeof registers === 'object' && Object.keys(registers).length > 0) {
      extra.push(html`
        <div class="pad">
          <div class="panel-card">
            <div class="panel-card-header">Initial register state · ${str(node.lc.details.flavor_name)}</div>
            <div class="reg-grid">
              ${Object.entries(registers).map(([name, value]) => html`<div class="dec-cell"><span class="dec-k">${str(name).toUpperCase()}</span><span class="dec-v" data-copy="${str(value)}">${str(value)}</span></div>`)}
            </div>
          </div>
        </div>
      `);
    }

    bodyEl.innerHTML = html`${top}${structFieldsTable(fields)}${extra}`;
  }

  function renderLoadCommandsSummaryInspector(bodyEl) {
    const slice = getActiveSlice();
    const lcs = slice?.load_commands || [];
    // Virtualised like Symbols and Strings: a file may carry thousands of commands.
    bodyEl.innerHTML = html`
      <div class="explorer-toolbar">
        <div class="explorer-filter-group">
          <input id="lc-search-input" type="search" class="explorer-search-input" placeholder="Filter by command, summary or offset" aria-label="Filter load commands" value="${state.lcSearch}" spellcheck="false" autocomplete="off" />
        </div>
        <span class="toolbar-facts" id="lc-count"></span>
      </div>
      <div class="virt-table-header">
        <span class="vcol-idx">#</span><span class="vcol-off">File offset</span><span class="vcol-sect vcol-cmd">Command</span>
        <span class="vcol-vm">ID</span><span class="vcol-type">Size</span><span class="vcol-name">Summary</span>
      </div>
      <div id="lc-virt-viewport" class="virt-viewport" aria-label="Load commands">
        <div id="lc-virt-phantom" class="virt-phantom"></div>
        <div id="lc-virt-rows" class="virt-rows-container"></div>
      </div>
    `;
    const filterLcs = () => {
      const q = state.lcSearch.trim().toLowerCase();
      if (!q) return lcs;
      return lcs.filter((lc) => [lc.cmd_name, lc.cmd_hex, lc.summary, hex(lc.region?.abs_offset), String(num(lc.index))].some((v) => v && String(v).toLowerCase().includes(q)));
    };
    let filtered = filterLcs();
    const countEl = document.getElementById('lc-count');
    const showCount = () => {
      countEl.textContent = filtered.length === lcs.length ? plural(lcs.length, 'command', 'commands') : `${filtered.length} of ${lcs.length}`;
    };
    const list = createVirtualList({
      viewport: document.getElementById('lc-virt-viewport'),
      phantom: document.getElementById('lc-virt-phantom'),
      rowsEl: document.getElementById('lc-virt-rows'),
      count: () => filtered.length,
      emptyText: () => (lcs.length ? 'No load commands match this filter.' : 'This binary has none.'),
      renderRow: (i, isActive) => {
        const lc = filtered[i];
        return html`
          <div class="virt-row ${isActive ? 'selected' : ''}" data-vi="${i}" data-select-node="lc_${num(lc.index)}">
            <span class="vcol-idx">${num(lc.index)}</span>
            <span class="vcol-off" data-copy="${hex(lc.region?.abs_offset)}">${hex(lc.region?.abs_offset, 6)}</span>
            <span class="vcol-sect vcol-cmd" data-copy="${str(lc.cmd_name)}" title="${str(lc.cmd_name)}">${str(lc.cmd_name)}</span>
            <span class="vcol-vm">${str(lc.cmd_hex)}</span>
            <span class="vcol-type">${num(lc.cmdsize)} B</span>
            <span class="vcol-name" title="${str(lc.summary)}">${str(lc.summary)}</span>
          </div>
        `;
      },
    });
    showCount();
    list.render();
    document.getElementById('lc-search-input').addEventListener('input', (e) => {
      state.lcSearch = e.target.value;
      filtered = filterLcs();
      showCount();
      list.reset();
    });
  }

  function renderSegmentsSummaryInspector(bodyEl) {
    const slice = getActiveSlice();
    const segs = slice?.segments || [];
    bodyEl.innerHTML = html`
      <div class="struct-table-wrap">
        <table class="struct-table">
          <thead><tr><th>#</th><th>Segment</th><th>VM address</th><th>VM size</th><th>File offset</th><th>File size</th><th>Protection (initial / max)</th><th>Sections</th></tr></thead>
          <tbody>
            ${segs.length === 0 ? emptyRow(8, 'This binary has no segments.') : ''}
            ${segs.map((seg, idx) => html`
              <tr class="struct-row" data-select-node="seg_${idx}">
                <td>${idx}</td>
                ${cp('col-name', str(seg.segname))}
                ${cp('col-val', str(seg.vmaddr))}
                <td>${formatBytes(seg.vmsize_int)} (${str(seg.vmsize)})</td>
                ${cp('col-offset', hex(seg.abs_offset), hex(seg.abs_offset, 6))}
                <td>${formatBytes(seg.filesize)}</td>
                <td><span class="prot-pill ${protClass(seg.initprot)}">${str(seg.initprot).toUpperCase()} / ${str(seg.maxprot).toUpperCase()}</span></td>
                <td>${(seg.sections || []).length}</td>
              </tr>
            `)}
          </tbody>
        </table>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // Virtualised list shared by Symbols and Strings: only visible rows are in
  // the DOM. Arrow keys / PageUp / PageDown / Home / End move the active row,
  // Enter activates it (same as a click).
  // -------------------------------------------------------------------------
  function createVirtualList({ viewport, phantom, rowsEl, count, renderRow, emptyText }) {
    let active = -1;
    viewport.tabIndex = 0;

    const render = () => {
      const n = count();
      phantom.style.height = `${n * VIRT_ROW_HEIGHT}px`;
      if (n === 0) {
        rowsEl.style.transform = 'none';
        rowsEl.innerHTML = html`<div class="virt-empty">${emptyText()}</div>`;
        return;
      }
      const scrollTop = viewport.scrollTop;
      const viewHeight = viewport.clientHeight || 500;
      const startIdx = Math.max(0, Math.floor(scrollTop / VIRT_ROW_HEIGHT) - 8);
      const endIdx = Math.min(n, Math.ceil((scrollTop + viewHeight) / VIRT_ROW_HEIGHT) + 8);
      rowsEl.style.transform = `translateY(${startIdx * VIRT_ROW_HEIGHT}px)`;
      const out = [];
      for (let i = startIdx; i < endIdx; i++) out.push(renderRow(i, i === active));
      rowsEl.innerHTML = html`${out}`;
    };

    const setActive = (index, reveal) => {
      const n = count();
      if (n === 0) return;
      active = Math.max(0, Math.min(n - 1, index));
      if (reveal) {
        const top = active * VIRT_ROW_HEIGHT;
        const viewHeight = viewport.clientHeight || 500;
        if (top < viewport.scrollTop) viewport.scrollTop = top;
        else if (top + VIRT_ROW_HEIGHT > viewport.scrollTop + viewHeight) viewport.scrollTop = top + VIRT_ROW_HEIGHT - viewHeight;
      }
      render();
    };

    viewport.addEventListener('scroll', render, { passive: true });
    rowsEl.addEventListener('click', (e) => {
      const row = e.target.closest('[data-vi]');
      if (!row) return;
      active = num(row.dataset.vi, -1);
      rowsEl.querySelectorAll('.virt-row.selected').forEach((n) => n.classList.remove('selected'));
      row.classList.add('selected');
    });
    viewport.addEventListener('keydown', (e) => {
      const page = Math.max(1, Math.floor((viewport.clientHeight || 500) / VIRT_ROW_HEIGHT) - 1);
      let next = null;
      if (e.key === 'ArrowDown') next = active + 1;
      else if (e.key === 'ArrowUp') next = active - 1;
      else if (e.key === 'PageDown') next = active + page;
      else if (e.key === 'PageUp') next = active - page;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = count() - 1;
      else if (e.key === 'Enter' && active >= 0) {
        e.preventDefault();
        rowsEl.querySelector(`[data-vi="${active}"]`)?.click();
        return;
      }
      if (next === null) return;
      e.preventDefault();
      setActive(next, true);
    });

    return {
      render,
      reset() {
        active = -1;
        viewport.scrollTop = 0;
        render();
      },
    };
  }

  // -------------------------------------------------------------------------
  // View 3: Symbols (virtualised) & Indirect Symbols
  // -------------------------------------------------------------------------
  function renderSymbolTableInspector(bodyEl) {
    const slice = getActiveSlice();
    const allSyms = slice?.symbols || [];
    const scopes = [['all', `All (${allSyms.length})`], ['ext', 'Defined external'], ['local', 'Local'], ['undef', 'Undefined']];

    bodyEl.innerHTML = html`
      <div class="explorer-toolbar">
        <div class="explorer-filter-group">
          <input id="sym-search-input" type="search" class="explorer-search-input" placeholder="Filter by name, section, library or address" aria-label="Filter symbols" value="${state.symSearch}" spellcheck="false" autocomplete="off" />
          <div class="filter-pills-group" id="sym-scope-pills" role="group" aria-label="Symbol scope">
            ${scopes.map(([id, label]) => html`<button type="button" class="filter-pill-btn ${state.symScope === id ? 'active' : ''}" aria-pressed="${state.symScope === id ? 'true' : 'false'}" data-sym-scope="${id}">${label}</button>`)}
          </div>
        </div>
        <button type="button" id="btn-toggle-demangle" class="filter-pill-btn ${state.symDemangle ? 'active' : ''}" aria-pressed="${state.symDemangle ? 'true' : 'false'}" title="Show demangled C++ / Swift names where available">Demangle</button>
      </div>
      <div class="virt-table-header">
        <span class="vcol-idx">#</span><span class="vcol-off">Entry</span><span class="vcol-vm">Address</span><span class="vcol-type">Kind</span>
        <span class="vcol-sect">Section</span><span class="vcol-lib">Library</span><span class="vcol-name">Name</span>
      </div>
      <div id="sym-virt-viewport" class="virt-viewport" aria-label="Symbols">
        <div id="sym-virt-phantom" class="virt-phantom"></div>
        <div id="sym-virt-rows" class="virt-rows-container"></div>
      </div>
    `;

    const filterSymbols = () => {
      const q = state.symSearch.trim().toLowerCase();
      return allSyms.filter((s) => {
        if (state.symScope === 'ext' && (!s.is_external || s.type_name === 'UNDF')) return false;
        if (state.symScope === 'local' && (s.is_external || s.type_name === 'UNDF')) return false;
        if (state.symScope === 'undef' && s.type_name !== 'UNDF') return false;
        if (!q) return true;
        return [s.name, s.demangled, s.section_name, s.library_name, s.n_value].some((v) => v && String(v).toLowerCase().includes(q));
      });
    };

    let filtered = filterSymbols();
    const list = createVirtualList({
      viewport: document.getElementById('sym-virt-viewport'),
      phantom: document.getElementById('sym-virt-phantom'),
      rowsEl: document.getElementById('sym-virt-rows'),
      count: () => filtered.length,
      emptyText: () => (allSyms.length ? 'No symbols match this filter.' : 'This binary has no symbol table.'),
      renderRow: (i, isActive) => {
        const s = filtered[i];
        const dispName = state.symDemangle && s.demangled ? s.demangled : s.name;
        const kindCls = s.type_name === 'UNDF' ? 'rw' : s.is_external ? 'rx' : 'ro';
        return html`
          <div class="virt-row ${isActive ? 'selected' : ''}" data-vi="${i}" data-sym-idx="${num(s.index)}" data-abs-offset="${num(s.target_abs_offset || s.abs_offset)}" data-field-size="16" data-field-name="${str(dispName)}">
            <span class="vcol-idx">${num(s.index)}</span>
            <span class="vcol-off" data-copy="${hex(s.abs_offset)}">${hex(s.abs_offset, 6)}</span>
            <span class="vcol-vm" data-copy="${str(s.n_value)}">${str(s.n_value)}</span>
            <span class="vcol-type"><span class="prot-pill ${kindCls}">${str(s.type_name)} ${s.is_external ? 'ext' : 'loc'}</span></span>
            <span class="vcol-sect" title="${str(s.section_name)}">${str(s.section_name) || '—'}</span>
            <span class="vcol-lib" title="${str(s.library_name)}">${str(s.library_name) || '—'}</span>
            <span class="vcol-name" data-copy="${str(dispName)}" title="${str(s.name)}">${str(dispName)}</span>
          </div>
        `;
      },
    });
    list.render();

    document.getElementById('sym-search-input').addEventListener('input', (e) => {
      state.symSearch = e.target.value;
      filtered = filterSymbols();
      list.reset();
    });
    document.getElementById('sym-scope-pills').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-sym-scope]');
      if (!btn) return;
      state.symScope = btn.dataset.symScope;
      refreshInspector();
    });
    document.getElementById('btn-toggle-demangle').addEventListener('click', (e) => {
      state.symDemangle = !state.symDemangle;
      storage.set('sym.demangle', state.symDemangle);
      e.currentTarget.classList.toggle('active', state.symDemangle);
      e.currentTarget.setAttribute('aria-pressed', String(state.symDemangle));
      list.render();
    });
  }

  function renderDysymtabInspector(bodyEl) {
    const slice = getActiveSlice();
    const dysym = slice?.dysymtab || {};
    const indirects = dysym.indirect_symbols || [];

    bodyEl.innerHTML = html`
      <div class="overview-container">
        <div class="kpi-cards-grid">
          ${kpi('Local symbols', num(dysym.nlocalsym), `from index ${num(dysym.ilocalsym)}`)}
          ${kpi('Defined external', num(dysym.nextdefsym), `from index ${num(dysym.iextdefsym)}`)}
          ${kpi('Undefined', num(dysym.nundefsym), `from index ${num(dysym.iundefsym)}`)}
          ${kpi('Indirect entries', indirects.length, 'stub and pointer slots')}
        </div>
        <div class="panel-card">
          <div class="panel-card-header">Indirect symbol slots (${indirects.length})</div>
          <div class="struct-table-wrap">
            <table class="struct-table">
              <thead><tr><th>#</th><th>Section</th><th>Slot address</th><th>Symbol index</th><th>Symbol</th><th></th></tr></thead>
              <tbody>
                ${indirects.length === 0 ? emptyRow(6, 'No indirect symbol entries.') : ''}
                ${indirects.map((ind) => html`
                  <tr class="struct-row" data-disasm-vm="${str(ind.slot_vmaddr)}">
                    <td>${num(ind.index)}</td>
                    <td class="col-name">${str(ind.section, '—')}</td>
                    ${cp('col-val', str(ind.slot_vmaddr), str(ind.slot_vmaddr, '—'))}
                    <td>${num(ind.symtab_index)}</td>
                    ${cp('col-name', str(ind.symbol_name))}
                    <td class="col-actions">${disasmChip(ind.slot_vmaddr, 'Disassemble')}</td>
                  </tr>
                `)}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 4: Strings (virtualised)
  // -------------------------------------------------------------------------
  function renderStringsInspector(bodyEl) {
    const slice = getActiveSlice();
    const allStrings = slice?.strings || [];
    const sources = [...new Set(allStrings.map((s) => s.source).filter(Boolean).map(String))];
    if (state.strSourceFilter !== 'all' && !sources.includes(state.strSourceFilter)) state.strSourceFilter = 'all';
    // A binary can name thousands of sections; past a handful, a select scales where pills do not.
    const sourcePicker = sources.length <= 6
      ? html`<div class="filter-pills-group" id="str-source-pills" role="group" aria-label="String source">
          ${['all', ...sources].map((src) => html`<button type="button" class="filter-pill-btn ${state.strSourceFilter === src ? 'active' : ''}" aria-pressed="${state.strSourceFilter === src ? 'true' : 'false'}" data-str-source="${src}" title="${src}">${src === 'all' ? `All (${allStrings.length})` : src}</button>`)}
        </div>`
      : html`<select id="str-source-select" class="explorer-select" aria-label="String source">
          <option value="all">All sources (${allStrings.length})</option>
          ${sources.map((src) => html`<option value="${src}">${truncate(src, 60)}</option>`)}
        </select>`;

    bodyEl.innerHTML = html`
      <div class="explorer-toolbar">
        <div class="explorer-filter-group">
          <input id="str-search-input" type="search" class="explorer-search-input" placeholder="Filter by content, source or address" aria-label="Filter strings" value="${state.strSearch}" spellcheck="false" autocomplete="off" />
          ${sourcePicker}
        </div>
      </div>
      <div class="virt-table-header">
        <span class="vcol-idx">#</span><span class="vcol-off">File offset</span><span class="vcol-vm">Address</span>
        <span class="vcol-sect">Source</span><span class="vcol-idx">Length</span><span class="vcol-name">String</span>
      </div>
      <div id="str-virt-viewport" class="virt-viewport" aria-label="Strings">
        <div id="str-virt-phantom" class="virt-phantom"></div>
        <div id="str-virt-rows" class="virt-rows-container"></div>
      </div>
    `;

    const filterStrings = () => {
      const q = state.strSearch.trim().toLowerCase();
      return allStrings.filter((s) => {
        if (state.strSourceFilter !== 'all' && String(s.source) !== state.strSourceFilter) return false;
        if (!q) return true;
        return [s.value, s.source, s.vmaddr].some((v) => v && String(v).toLowerCase().includes(q));
      });
    };

    let filtered = filterStrings();
    const list = createVirtualList({
      viewport: document.getElementById('str-virt-viewport'),
      phantom: document.getElementById('str-virt-phantom'),
      rowsEl: document.getElementById('str-virt-rows'),
      count: () => filtered.length,
      emptyText: () => (allStrings.length ? 'No strings match this filter.' : 'No strings were found in this binary.'),
      renderRow: (i, isActive) => {
        const s = filtered[i];
        return html`
          <div class="virt-row ${isActive ? 'selected' : ''}" data-vi="${i}" data-abs-offset="${num(s.abs_offset)}" data-field-size="${Math.max(1, num(s.length, 1))}" data-field-name="string at ${hex(s.abs_offset)}">
            <span class="vcol-idx">${num(s.index)}</span>
            <span class="vcol-off" data-copy="${hex(s.abs_offset)}">${hex(s.abs_offset, 6)}</span>
            <span class="vcol-vm" data-copy="${str(s.vmaddr)}">${str(s.vmaddr) || '—'}</span>
            <span class="vcol-sect" title="${str(s.source)}">${str(s.source) || '—'}</span>
            <span class="vcol-idx">${num(s.length)}</span>
            <span class="vcol-name vcol-string" data-copy="${str(s.value)}" title="${truncate(s.value, 600)}">${truncate(s.value, 600)}</span>
          </div>
        `;
      },
    });
    list.render();

    document.getElementById('str-search-input').addEventListener('input', (e) => {
      state.strSearch = e.target.value;
      filtered = filterStrings();
      list.reset();
    });
    document.getElementById('str-source-pills')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-str-source]');
      if (!btn) return;
      state.strSourceFilter = btn.dataset.strSource;
      refreshInspector();
    });
    const select = document.getElementById('str-source-select');
    if (select) {
      select.value = state.strSourceFilter;
      select.addEventListener('change', () => {
        state.strSourceFilter = select.value;
        filtered = filterStrings();
        list.reset();
      });
    }
  }

  // -------------------------------------------------------------------------
  // View 5: Disassembly (`/api/disassemble`)
  // -------------------------------------------------------------------------
  function mnemonicClass(m) {
    const low = str(m).toLowerCase();
    if (low.startsWith('ret')) return 'mnem-ret';
    if (low.startsWith('pac') || low.startsWith('aut') || low.startsWith('xpaci')) return 'mnem-pac';
    if (low.startsWith('b') || low.startsWith('cbz') || low.startsWith('cbnz') || low.startsWith('tbz') || low.startsWith('tbnz') || low.startsWith('call') || low.startsWith('j')) return 'mnem-branch';
    if (low.startsWith('ldr') || low.startsWith('str') || low.startsWith('ldp') || low.startsWith('stp') || low.startsWith('mov')) return 'mnem-mem';
    return 'mnem-alu';
  }

  async function renderDisassemblyInspector(bodyEl, token) {
    const slice = getActiveSlice();
    if (!slice) return;
    const generation = docGeneration;

    // Collect executable sections
    const execSections = [];
    (slice.segments || []).forEach((seg) => {
      (seg.sections || []).forEach((sec) => {
        const name = str(sec.sectname);
        if (sec.is_executable || name === '__text' || name.includes('stub') || name.includes('code')) {
          execSections.push({ key: `${str(seg.segname)},${name}`, vmaddr: str(sec.vmaddr), size: sec.size });
        }
      });
    });

    if (!state.activeDisasmSection && !state.activeDisasmVmaddr && execSections.length > 0) {
      state.activeDisasmSection = execSections[0].key;
    }

    const target = state.activeDisasmVmaddr || state.activeDisasmSection || 'entry point';
    const picker = execSections.length === 0
      ? html`<span class="t-dim">No executable sections; decoding from the entry point.</span>`
      : execSections.length <= 6
      ? html`<div class="filter-pills-group" id="disasm-sect-pills" role="group" aria-label="Executable section">
          ${execSections.map((es) => html`<button type="button" class="filter-pill-btn ${state.activeDisasmSection === es.key ? 'active' : ''}" aria-pressed="${state.activeDisasmSection === es.key ? 'true' : 'false'}" data-disasm-sec-btn="${es.key}" title="${es.key}">${es.key} · ${formatBytes(es.size)}</button>`)}
        </div>`
      : html`<select id="disasm-sect-select" class="explorer-select" aria-label="Executable section">
          <option value="">Section…</option>
          ${execSections.map((es) => html`<option value="${es.key}">${truncate(es.key, 60)} · ${formatBytes(es.size)}</option>`)}
        </select>`;

    bodyEl.innerHTML = html`
      <div class="explorer-toolbar">
        <div class="explorer-filter-group">${picker}</div>
        <form id="disasm-addr-form" class="inline-form">
          <input id="disasm-addr-input" type="text" class="explorer-search-input addr-input" placeholder="VM address, e.g. 0x100003f60" aria-label="Disassemble at VM address" value="${state.activeDisasmVmaddr}" spellcheck="false" autocomplete="off" />
          <button type="submit" class="btn-conv-action">Disassemble</button>
        </form>
      </div>
      <div id="disasm-results-wrap" class="struct-table-wrap fill-scroll" aria-live="polite"></div>
    `;

    document.getElementById('disasm-sect-pills')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-disasm-sec-btn]');
      if (!btn) return;
      state.activeDisasmSection = btn.dataset.disasmSecBtn;
      state.activeDisasmVmaddr = '';
      refreshInspector();
    });
    const select = document.getElementById('disasm-sect-select');
    if (select) {
      select.value = state.activeDisasmSection;
      select.addEventListener('change', () => {
        if (!select.value) return;
        state.activeDisasmSection = select.value;
        state.activeDisasmVmaddr = '';
        refreshInspector();
      });
    }
    document.getElementById('disasm-addr-form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = document.getElementById('disasm-addr-input').value.trim();
      if (val) {
        state.activeDisasmVmaddr = val;
        state.activeDisasmSection = '';
        refreshInspector();
      }
    });

    // Fetch disassembly
    const params = { count: 350 };
    if (state.activeDisasmVmaddr) params.vmaddr = state.activeDisasmVmaddr;
    else if (state.activeDisasmSection) params.section = state.activeDisasmSection;
    const cacheKey = `${state.activeSliceIndex}|${params.vmaddr || ''}|${params.section || ''}`;

    const wrap = document.getElementById('disasm-results-wrap');
    let data = state.disasmCache.get(cacheKey);
    let failure = null;
    if (!data) {
      // Only say "Disassembling…" if the answer is slow; a fast one replaces the pane directly.
      const slow = setTimeout(() => {
        if (token === renderToken && wrap.isConnected) wrap.innerHTML = html`<div class="empty-note">Disassembling ${target}…</div>`;
      }, BUSY_DELAY_MS);
      try {
        data = await api.get('/api/disassemble', params);
        if (generation === docGeneration && data && Array.isArray(data.instructions)) state.disasmCache.set(cacheKey, data);
      } catch (err) {
        failure = err;
      } finally {
        clearTimeout(slow);
      }
    }
    if (token !== renderToken || generation !== docGeneration || !wrap.isConnected) return;

    if (failure) {
      const info = describeError(failure);
      wrap.innerHTML = html`<div class="empty-note" role="alert">Disassembly failed. ${info.what} ${info.next}</div>`;
      return;
    }
    const insns = Array.isArray(data?.instructions) ? data.instructions : [];
    if (!insns.length) {
      // `unsupported_reason`: this architecture has no decoder (only x86, x86-64 and AArch64 do).
      wrap.innerHTML = data?.unsupported_reason
        ? html`<div class="empty-note">${str(data.unsupported_reason)}</div>`
        : html`<div class="empty-note">Nothing decoded at ${target}. The address may be unmapped, or outside any section that has bytes in the file.</div>`;
      return;
    }

    const rows = [];
    insns.forEach((insn) => {
      if (insn.symbol_label) {
        rows.push(html`<tr><td colspan="6" class="disasm-sym-banner" data-copy="${str(insn.symbol_label)}">${str(insn.symbol_label)}:</td></tr>`);
      }
      rows.push(html`
        <tr class="disasm-row" data-abs-offset="${num(insn.abs_offset)}" data-field-size="${num(insn.size, 4) || 4}" data-field-name="${str(insn.mnemonic)} ${str(insn.operands)}">
          ${cp('col-offset col-foff', hex(insn.abs_offset), hex(insn.abs_offset, 6))}
          ${cp('col-addr', str(insn.vmaddr))}
          ${cp('col-bytes col-rawbytes', str(insn.raw_hex))}
          <td class="${mnemonicClass(insn.mnemonic)}">${str(insn.mnemonic)}</td>
          <td class="col-operands">${str(insn.operands)} ${disasmChip(insn.branch_target_vmaddr, str(insn.branch_target_vmaddr))}</td>
          <td class="disasm-comment" title="${str(insn.comment)}">${insn.comment ? `; ${insn.comment}` : ''}</td>
        </tr>
      `);
    });

    wrap.innerHTML = html`
      <table class="disasm-table">
        <thead><tr><th class="col-foff">File offset</th><th>Address</th><th class="col-rawbytes">Bytes</th><th>Mnemonic</th><th>Operands</th><th>Comment</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `;
    afterRender(bodyEl, 'disassembly');
  }

  // -------------------------------------------------------------------------
  // View 6: Fixups, Imports, Exports, Binds
  // -------------------------------------------------------------------------
  function renderDyldInspector(bodyEl) {
    const slice = getActiveSlice();
    const dyld = slice?.dyld_info || {};
    const cf = dyld.chained_fixups || {};
    const fixups = cf.fixups || [];
    const imports = cf.imports || [];
    // ELF records the providing library only for versioned symbols (.gnu.version_r).
    const isElfSlice = sliceFormat(slice) === 'ELF';
    const exportsList = dyld.exports || [];
    const binds = dyld.binds || [];
    const rebaseCount = (dyld.rebases || []).length;
    const tabs = [['fixups', `Fixups (${fixups.length})`], ['imports', `Imports (${imports.length})`], ['exports', `Exports (${exportsList.length})`], ['binds', `Binds and rebases (${binds.length + rebaseCount})`]];

    let table;
    if (state.dyldSubTab === 'imports') {
      table = html`
        <table class="struct-table">
          <thead><tr><th>#</th><th>Symbol</th><th>Library ordinal</th><th>${isElfSlice ? 'Library (from symbol versioning)' : 'Library'}</th><th>Weak</th></tr></thead>
          <tbody>
            ${imports.length === 0 ? emptyRow(5, 'No import table.') : ''}
            ${imports.map((imp) => html`
              <tr class="struct-row">
                <td>${num(imp.index)}</td>
                ${cp('col-name', str(imp.name))}
                <td>${imp.lib_ordinal ? num(imp.lib_ordinal) : '—'}</td>
                ${cp('col-lib', str(imp.lib_name), imp.lib_name
                  ? `${str(imp.lib_name)}${imp.version ? ` (${str(imp.version)})` : ''}`
                  : (isElfSlice ? 'not recorded in the file' : '—'))}
                <td>${imp.weak_import ? html`<span class="prot-pill rw">weak</span>` : 'no'}</td>
              </tr>
            `)}
          </tbody>
        </table>`;
    } else if (state.dyldSubTab === 'exports') {
      table = html`
        <table class="struct-table">
          <thead><tr><th>Symbol</th><th>Address</th><th>Slice offset</th><th>Flags</th><th></th></tr></thead>
          <tbody>
            ${exportsList.length === 0 ? emptyRow(5, 'No exported symbols.') : ''}
            ${exportsList.map((ex) => html`
              <tr class="struct-row" data-disasm-vm="${str(ex.vmaddr)}">
                ${cp('col-name', str(ex.name))}
                ${cp('col-val', str(ex.vmaddr))}
                <td class="col-offset">+${hex(ex.offset, 4)}</td>
                <td>${(ex.flags_decoded || []).length ? flagPills(ex.flags_decoded) : hex(ex.flags)}</td>
                <td class="col-actions">${disasmChip(ex.vmaddr, 'Disassemble')}</td>
              </tr>
            `)}
          </tbody>
        </table>`;
    } else if (state.dyldSubTab === 'binds') {
      table = html`
        <table class="struct-table">
          <thead><tr><th>Type</th><th>Segment</th><th>Address</th><th>Symbol</th><th>Library</th></tr></thead>
          <tbody>
            ${binds.length === 0 ? emptyRow(5, rebaseCount ? `${rebaseCount} rebase entries and no binds.` : 'No bind or rebase opcodes. Binaries built with chained fixups have none.') : ''}
            ${binds.map((b) => html`
              <tr class="struct-row">
                <td><span class="prot-pill rx">${str(b.type, 'BIND')}</span></td>
                <td>${str(b.segment, '—')}</td>
                ${cp('col-val', str(b.vmaddr), str(b.vmaddr, '—'))}
                ${cp('col-name', str(b.symbol), str(b.symbol, '—'))}
                <td class="col-lib" title="${str(b.library)}">${str(b.library, '—')}</td>
              </tr>
            `)}
          </tbody>
        </table>`;
    } else {
      table = html`
        <table class="struct-table">
          <thead><tr><th>File offset</th><th>Address</th><th>Type</th><th>Target</th><th>Pointer authentication</th></tr></thead>
          <tbody>
            ${fixups.length === 0 ? emptyRow(5, 'No fixups recorded.') : ''}
            ${fixups.map((fx) => html`
              <tr class="struct-row" data-abs-offset="${num(fx.abs_offset)}" data-field-size="8" data-field-name="fixup ${str(fx.type)}">
                ${cp('col-offset', hex(fx.abs_offset), hex(fx.abs_offset, 6))}
                ${cp('col-val', str(fx.vmaddr))}
                <td><span class="prot-pill ${str(fx.type).includes('AUTH') ? 'rx' : 'rw'}">${str(fx.type)}</span></td>
                ${cp('col-name', str(fx.symbol || fx.target || `ordinal ${num(fx.ordinal)}`))}
                <td>${fx.pac_key ? `key ${fx.pac_key} · diversity ${num(fx.diversity)}${fx.addr_div ? ' · address-diversified' : ''}` : '—'}</td>
              </tr>
            `)}
          </tbody>
        </table>`;
    }

    bodyEl.innerHTML = html`
      <div class="subtabs-bar" id="dyld-subtabs" role="tablist">
        ${tabs.map(([id, label]) => html`<button type="button" role="tab" aria-selected="${state.dyldSubTab === id ? 'true' : 'false'}" class="subtab-btn ${state.dyldSubTab === id ? 'active' : ''}" data-dyld-tab="${id}">${label}</button>`)}
      </div>
      <div id="dyld-tab-content" class="struct-table-wrap fill-scroll">${table}</div>
    `;

    document.getElementById('dyld-subtabs')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-dyld-tab]');
      if (!btn) return;
      state.dyldSubTab = btn.dataset.dyldTab;
      refreshInspector();
    });
  }

  // -------------------------------------------------------------------------
  // View 7: Entry Point, Thread State & Function Starts
  // -------------------------------------------------------------------------
  function renderFunctionStartsInspector(bodyEl) {
    const slice = getActiveSlice();
    const ep = slice?.entry_point || {};
    const fns = slice?.function_starts || [];
    const regs = ep.registers && typeof ep.registers === 'object' ? ep.registers : {};

    bodyEl.innerHTML = html`
      <div class="overview-container fs-head">
        <div class="panel-card">
          <div class="panel-card-header"><span>Entry point</span>${disasmChip(ep.vmaddr, 'Disassemble')}</div>
          <div class="kv-list">
            <div class="kv-row"><span class="kv-key">Declared by</span><span class="kv-val">${str(ep.type, 'none')}</span></div>
            <div class="kv-row"><span class="kv-key">Address</span><span class="kv-val" data-copy="${str(ep.vmaddr)}">${str(ep.vmaddr, '—')}</span></div>
            <div class="kv-row"><span class="kv-key">File offset</span><span class="kv-val" data-copy="${hex(ep.abs_offset)}">${hex(ep.abs_offset)} (slice +${hex(ep.entryoff)})</span></div>
          </div>
        </div>

        ${Object.keys(regs).length > 0 ? html`
          <div class="panel-card">
            <div class="panel-card-header">Initial register state · ${str(ep.thread_flavor)}</div>
            <div class="reg-grid">
              ${Object.entries(regs).map(([k, v]) => html`<div class="dec-cell"><span class="dec-k">${str(k).toUpperCase()}</span><span class="dec-v" data-copy="${str(v)}">${str(v)}</span></div>`)}
            </div>
          </div>
        ` : ''}

      </div>
      <div class="explorer-toolbar">
        <div class="explorer-filter-group">
          <input id="fs-search-input" type="search" class="explorer-search-input" placeholder="Filter by address, offset or symbol" aria-label="Filter function starts" value="${state.fnSearch}" spellcheck="false" autocomplete="off" />
        </div>
        <span class="toolbar-facts" id="fs-count"></span>
      </div>
      <div class="virt-table-header">
        <span class="vcol-idx">#</span><span class="vcol-off">File offset</span><span class="vcol-type">Slice offset</span>
        <span class="vcol-vm">Address</span><span class="vcol-name">Symbol</span><span class="vcol-act"></span>
      </div>
      <div id="fs-virt-viewport" class="virt-viewport" aria-label="Function starts">
        <div id="fs-virt-phantom" class="virt-phantom"></div>
        <div id="fs-virt-rows" class="virt-rows-container"></div>
      </div>
    `;
    // Virtualised: a large binary records tens of thousands of function starts.
    const filterFns = () => {
      const q = state.fnSearch.trim().toLowerCase();
      if (!q) return fns;
      return fns.filter((fn) => [fn.name, fn.vmaddr, hex(fn.abs_offset), hex(fn.slice_offset)].some((v) => v && String(v).toLowerCase().includes(q)));
    };
    let filtered = filterFns();
    const countEl = document.getElementById('fs-count');
    const showCount = () => {
      countEl.textContent = filtered.length === fns.length ? `Function starts (${fns.length})` : `Function starts: ${filtered.length} of ${fns.length}`;
    };
    const list = createVirtualList({
      viewport: document.getElementById('fs-virt-viewport'),
      phantom: document.getElementById('fs-virt-phantom'),
      rowsEl: document.getElementById('fs-virt-rows'),
      count: () => filtered.length,
      emptyText: () => (fns.length ? 'No function starts match this filter.' : 'This binary records no function start table.'),
      renderRow: (i, isActive) => {
        const fn = filtered[i];
        const name = str(fn.name) || `sub_${str(fn.vmaddr).replace(/^0x/, '')}`;
        return html`
          <div class="virt-row ${isActive ? 'selected' : ''}" data-vi="${i}" data-abs-offset="${num(fn.abs_offset)}" data-field-size="4" data-field-name="${str(fn.name, 'function')}">
            <span class="vcol-idx">${num(fn.index)}</span>
            <span class="vcol-off" data-copy="${hex(fn.abs_offset)}">${hex(fn.abs_offset, 6)}</span>
            <span class="vcol-type">+${hex(fn.slice_offset, 4)}</span>
            <span class="vcol-vm" data-copy="${str(fn.vmaddr)}">${str(fn.vmaddr)}</span>
            <span class="vcol-name" data-copy="${name}" title="${name}">${name}</span>
            <span class="vcol-act">${disasmChip(fn.vmaddr, 'Disassemble')}</span>
          </div>
        `;
      },
    });
    showCount();
    list.render();
    document.getElementById('fs-search-input').addEventListener('input', (e) => {
      state.fnSearch = e.target.value;
      filtered = filterFns();
      showCount();
      list.reset();
    });
  }

  // -------------------------------------------------------------------------
  // View 8: Objective-C Metadata & Fileset Entries
  // -------------------------------------------------------------------------
  function renderObjcInspector(bodyEl) {
    const slice = getActiveSlice();
    const objc = slice?.objc_metadata || {};
    const classes = objc.classes || [];
    const selectors = objc.selectors || [];
    const filesets = slice?.fileset_entries || [];
    const nameOf = (x) => (x && typeof x === 'object' ? str(x.name) : str(x));
    const whereOf = (x) => (x && typeof x === 'object' ? str(x.vmaddr) || hex(x.abs_offset) : '—');
    const offOf = (x) => (x && typeof x === 'object' ? num(x.abs_offset) : 0);
    const nameTable = (title, items, heading, emptyText) => html`
      <div class="panel-card">
        <div class="panel-card-header">${title} (${items.length})</div>
        <div class="struct-table-wrap">
          <table class="struct-table">
            <thead><tr><th>${heading}</th><th>Location</th></tr></thead>
            <tbody>
              ${items.length === 0 ? emptyRow(2, emptyText) : ''}
              ${items.map((c) => html`
                <tr class="struct-row" data-abs-offset="${offOf(c)}" data-field-size="8" data-field-name="${nameOf(c)}">
                  ${cp('col-name', nameOf(c))}
                  <td class="col-val">${whereOf(c)}</td>
                </tr>
              `)}
            </tbody>
          </table>
        </div>
      </div>`;

    bodyEl.innerHTML = html`
      <div class="overview-container">
        ${filesets.length > 0 ? html`
          <div class="panel-card">
            <div class="panel-card-header">Fileset entries (${filesets.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Entry ID</th><th>Address</th><th>File offset</th></tr></thead>
                <tbody>
                  ${filesets.map((fe) => html`
                    <tr class="struct-row" data-abs-offset="${num(fe.abs_offset)}" data-field-size="32" data-field-name="${str(fe.entry_id)}">
                      ${cp('col-name', str(fe.entry_id))}
                      ${cp('col-val', str(fe.vmaddr))}
                      ${cp('col-offset', hex(fe.abs_offset), hex(fe.abs_offset, 6))}
                    </tr>
                  `)}
                </tbody>
              </table>
            </div>
          </div>
        ` : ''}
        <div class="overview-two-col">
          ${nameTable('Classes', classes, 'Class', 'No Objective-C classes.')}
          ${nameTable('Selectors', selectors, 'Selector', 'No Objective-C selectors.')}
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 9: Code Signature / Authenticode / ELF Notes
  // -------------------------------------------------------------------------
  function renderCodeSignatureInspector(bodyEl) {
    const slice = getActiveSlice();
    const fmt = sliceFormat(slice);
    const cs = slice?.code_signature_detail || {};
    if (!cs.present) {
      const elfNotes = slice?.elf_metadata?.notes || [];
      if (fmt === 'ELF' && elfNotes.length > 0) {
        bodyEl.innerHTML = html`
          <div class="overview-container">
            <div class="panel-card">
              <div class="panel-card-header">ELF notes (${elfNotes.length})</div>
              <div class="struct-table-wrap">
                <table class="struct-table">
                  <thead><tr><th>File offset</th><th>Owner</th><th>Type</th><th>Description</th></tr></thead>
                  <tbody>
                    ${elfNotes.map((n) => html`
                      <tr class="struct-row" data-abs-offset="${num(n.abs_offset)}" data-field-size="${num(n.size, 16)}" data-field-name="${str(n.type_name)}">
                        ${cp('col-offset', hex(n.abs_offset), hex(n.abs_offset, 6))}
                        <td class="col-name">${str(n.name)}</td>
                        <td class="col-val">${str(n.type_name)}</td>
                        <td class="col-desc" data-copy="${str(n.description)}">${str(n.description)}</td>
                      </tr>
                    `)}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        `;
        return;
      }
      const what = fmt === 'PE' ? 'an Authenticode certificate table' : fmt === 'ELF' ? 'notes or an embedded signature' : 'an embedded code signature (LC_CODE_SIGNATURE)';
      bodyEl.innerHTML = html`<div class="overview-container"><div class="panel-card"><div class="panel-card-header">Not signed</div><div class="empty-note">This slice does not contain ${what}.</div></div></div>`;
      return;
    }

    const cd = cs.code_directory || {};
    const blobs = cs.blobs || [];
    const entEntries = cs.entitlements_entries || [];
    const certs = cs.cms_signature?.certificates || [];
    const specialSlots = cd.special_slots || [];
    const codeSlots = cd.code_slots_preview || [];
    // Entitlements and hash slots belong to Mach-O code signatures; a PE certificate table has neither.
    const tabs = fmt === 'PE'
      ? [['summary', 'Summary'], ['fields', 'Fields']]
      : [['summary', 'Summary'], ['entitlements', `Entitlements (${entEntries.length})`], ['slots', `Hash slots (${specialSlots.length + codeSlots.length})`], ['fields', 'Fields']];
    if (!tabs.some(([id]) => id === state.csSubTab)) state.csSubTab = 'summary';

    let content;
    if (state.csSubTab === 'entitlements') {
      content = html`
        <div class="overview-container">
          <div class="panel-card">
            <div class="panel-card-header">Entitlements (${entEntries.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Key</th><th>Value</th><th>Risk</th><th>Note</th></tr></thead>
                <tbody>
                  ${entEntries.length === 0 ? emptyRow(4, 'No embedded entitlements.') : ''}
                  ${entEntries.map((e) => html`
                    <tr class="struct-row">
                      ${cp('col-name', str(e.key))}
                      ${cp('col-val', JSON.stringify(e.value) ?? '')}
                      <td><span class="sec-status-pill sec-${e.risk === 'HIGH' ? 'WARN' : 'INFO'}">${str(e.risk, 'INFO')}</span></td>
                      <td class="col-desc">${str(e.reason)}</td>
                    </tr>
                  `)}
                </tbody>
              </table>
            </div>
          </div>
          <div class="panel-card">
            <div class="panel-card-header">Entitlements plist (XML, as embedded)</div>
            <div class="pad"><pre class="xml-code-block">${str(cs.entitlements_xml) || 'No XML entitlements blob.'}</pre></div>
          </div>
        </div>`;
    } else if (state.csSubTab === 'slots') {
      content = html`
        <div class="overview-container">
          <div class="panel-card">
            <div class="panel-card-header">Special slots (Info.plist, requirements, resources, entitlements)</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Slot</th><th>Covers</th><th>Hash</th><th>Status</th></tr></thead>
                <tbody>
                  ${specialSlots.length === 0 ? emptyRow(4, 'No special slots.') : ''}
                  ${specialSlots.map((s) => html`
                    <tr class="struct-row">
                      <td class="col-val">${num(s.slot)}</td>
                      <td class="col-name">${str(s.name)}</td>
                      ${cp('col-bytes col-hash', str(s.hash), str(s.hash, '—'))}
                      <td><span class="sec-status-pill sec-${s.present ? 'PASS' : 'INFO'}">${s.present ? (s.verified !== false ? 'verified' : 'present') : 'empty'}</span></td>
                    </tr>
                  `)}
                </tbody>
              </table>
            </div>
          </div>
          <div class="panel-card">
            <div class="panel-card-header">Code page hashes (${num(cd.n_code_slots, codeSlots.length)} pages; showing ${codeSlots.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Page</th><th>File offset</th><th>Recorded hash</th><th>Hash of file bytes</th><th>Result</th></tr></thead>
                <tbody>
                  ${codeSlots.length === 0 ? emptyRow(5, 'No code page hashes.') : ''}
                  ${codeSlots.map((p) => html`
                    <tr class="struct-row" data-abs-offset="${num(p.file_offset)}" data-field-size="${num(cd.page_size, 4096) || 4096}" data-field-name="code page ${num(p.page_index)}">
                      <td>${num(p.page_index)}</td>
                      ${cp('col-offset', hex(p.file_offset), hex(p.file_offset, 6))}
                      ${cp('col-bytes', str(p.expected_hash))}
                      ${cp('col-bytes', str(p.actual_hash || p.expected_hash))}
                      <td><span class="sec-status-pill sec-${p.verified !== false ? 'PASS' : 'FAIL'}">${p.verified !== false ? 'match' : 'mismatch'}</span></td>
                    </tr>
                  `)}
                </tbody>
              </table>
            </div>
          </div>
        </div>`;
    } else if (state.csSubTab === 'fields') {
      content = structFieldsTable([...(cs.fields || []), ...(cd.fields || [])]);
    } else {
      content = html`
        <div class="overview-container">
          <div class="kpi-cards-grid">
            ${kpi('Identifier', str(cd.identifier, '—'), cd.team_id ? `team ${cd.team_id}` : 'no team ID', 'accent')}
            ${fmt === 'PE'
              ? kpi('Authenticode image hash', cd.cdhash_verified ? 'found in the signature' : 'not found in the signature', `${str(cd.cdhash).slice(0, 24)}${cd.cdhash ? '…' : ''} · signature and chain not evaluated`, cd.cdhash_verified ? 'ok' : 'warn')
              : kpi('CDHash', cd.cdhash_verified ? 'verified' : 'present, not verified', `${str(cd.cdhash).slice(0, 24)}${cd.cdhash ? '…' : ''}`, cd.cdhash_verified ? 'ok' : 'warn')}
            ${kpi(`Flags ${str(cd.flags)}`, (cd.flags_decoded || []).join(' | ') || 'none', `${str(cd.hash_type, 'hash')} · ${num(cd.page_size, 4096)} B pages`)}
            ${kpi('Blobs', num(cs.blob_count, blobs.length), `${formatBytes(cs.length)} at ${hex(cs.superblob_region?.abs_offset)}`)}
          </div>
          <div class="overview-two-col">
            <div class="panel-card">
              <div class="panel-card-header">Signature blobs (${blobs.length})</div>
              <div class="struct-table-wrap">
                <table class="struct-table">
                  <thead><tr><th>#</th><th>Slot</th><th>Magic</th><th>File offset</th><th>Size</th></tr></thead>
                  <tbody>
                    ${blobs.length === 0 ? emptyRow(5, 'No blobs.') : ''}
                    ${blobs.map((b) => html`
                      <tr class="struct-row" data-abs-offset="${num(b.abs_offset)}" data-field-size="${Math.min(num(b.size, 64) || 64, 512)}" data-field-name="${str(b.type_name)}">
                        <td>${num(b.index)}</td>
                        <td class="col-name">${str(b.type_name)}</td>
                        <td class="col-val">${str(b.magic_name)} (${str(b.magic)})</td>
                        ${cp('col-offset', hex(b.abs_offset), hex(b.abs_offset, 6))}
                        <td>${formatBytes(b.size)}</td>
                      </tr>
                    `)}
                  </tbody>
                </table>
              </div>
            </div>
            <div class="panel-card">
              <div class="panel-card-header">Signer</div>
              <div class="kv-list">
                <div class="kv-row"><span class="kv-key">Signing</span><span class="kv-val">${fmt === 'PE' ? 'PKCS#7 SignedData (signature and certificate chain not evaluated)' : cs.cms_signature?.is_adhoc ? 'ad hoc (hashes only, no certificate)' : 'CMS signature'}</span></div>
                <div class="kv-row"><span class="kv-key">${fmt === 'PE' ? 'Image hash' : 'CDHash'}</span><span class="kv-val" data-copy="${str(cd.cdhash_full || cd.cdhash)}">${str(cd.cdhash_full || cd.cdhash, '—')}</span></div>
                ${certs.map((c, idx) => html`
                  <div class="kv-row">
                    <span class="kv-key">Certificate ${idx + 1}</span>
                    <span class="kv-val">${typeof c === 'string' ? c : `${str(c?.subject_cn)}${c?.issuer_cn || c?.org ? ` (issuer ${str(c.issuer_cn || c.org)})` : ''}`}</span>
                  </div>
                `)}
              </div>
            </div>
          </div>
        </div>`;
    }

    bodyEl.innerHTML = html`
      <div class="subtabs-bar" id="cs-subtabs" role="tablist">
        ${tabs.map(([id, label]) => html`<button type="button" role="tab" aria-selected="${state.csSubTab === id ? 'true' : 'false'}" class="subtab-btn ${state.csSubTab === id ? 'active' : ''}" data-cs-tab="${id}">${label}</button>`)}
      </div>
      <div id="cs-tab-body" class="fill-scroll">${content}</div>
    `;

    document.getElementById('cs-subtabs')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-cs-tab]');
      if (!btn) return;
      state.csSubTab = btn.dataset.csTab;
      refreshInspector();
    });
  }

  // -------------------------------------------------------------------------
  // View 10: Hardening
  // -------------------------------------------------------------------------
  function renderSecurityAuditInspector(bodyEl) {
    const slice = getActiveSlice();
    const fmt = sliceFormat(slice);
    const sec = slice?.security_posture || {};
    const checks = sec.checks || [];

    bodyEl.innerHTML = html`
      <div class="overview-container">
        <div class="kpi-cards-grid">
          ${sec.pie_applicable === false
            ? kpi('PIE / ASLR', 'not applicable', 'MH_PIE is a flag of main executables', '')
            : kpi('PIE / ASLR', sec.pie ? 'enabled' : 'disabled', 'position-independent image', sec.pie ? 'ok' : 'warn')}
          ${kpi('Stack canary', sec.stack_canary ? 'referenced' : 'not found', 'detected from stack-check symbol references', sec.stack_canary ? 'ok' : '')}
          ${fmt === 'MACHO' ? kpi('Pointer authentication', sec.pac_enabled ? 'arm64e' : 'not used', 'signed return addresses and pointers', sec.pac_enabled ? 'ok' : '') : ''}
          ${kpi('W^X', sec.has_rwx_segments ? 'RWX segment present' : 'no writable + executable segment', 'from segment protections', sec.has_rwx_segments ? 'bad' : 'ok')}
        </div>
        <div class="panel-card">
          <div class="panel-card-header">Checks (${checks.length})</div>
          ${checks.length === 0 ? html`<div class="empty-note">No checks were produced for this slice.</div>` : ''}
          <div class="security-grid">
            ${checks.map((chk) => html`
              <div class="sec-check-card">
                <div class="sec-check-top">
                  <span class="sec-check-title">${str(chk.title)}</span>
                  <span class="sec-status-pill sec-${oneOf(str(chk.status), ['PASS', 'WARN', 'FAIL', 'INFO'], 'INFO')}">${str(chk.status)}</span>
                </div>
                <div class="sec-check-val">${str(chk.value)}</div>
                <div class="sec-check-detail">${str(chk.detail)}</div>
              </div>
            `)}
          </div>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 11: Entropy, Capabilities, Provenance
  // -------------------------------------------------------------------------
  function entropyClass(h) {
    if (h < 1.0) return 'ent-sparse';
    if (h < 4.5) return 'ent-structured';
    if (h < 6.5) return 'ent-code';
    if (h < 7.2) return 'ent-dense';
    return 'ent-packed';
  }

  function renderSemanticIntelInspector(bodyEl) {
    const slice = getActiveSlice();
    if (!slice) return;
    const sem = slice.semantic_layers || {};
    const ent = sem.entropy_analysis || {};
    const caps = sem.capabilities || {};
    const prov = sem.provenance || {};
    const anom = sem.anomalies || {};
    const dist = ent.byte_class_distribution || {};
    const windows = ent.sliding_windows || [];
    const secMetrics = ent.section_metrics || [];
    const capCats = caps.categories || [];
    // Areas whose only evidence is an API name that appears as a string: weaker, shown apart.
    const weakCats = caps.weak_categories || [];
    const strIntel = caps.string_intelligence || {};
    const findings = anom.findings || [];
    const rich = sliceFormat(slice) === 'PE' && slice.pe_metadata?.rich_header?.present ? slice.pe_metadata.rich_header : null;
    const overall = num(ent.overall_entropy);
    const pct = (v) => numIn(v, 0, 100, 0);

    bodyEl.innerHTML = html`
      <div class="overview-container">
        <div class="kpi-cards-grid">
          ${kpi('Shannon entropy', `${overall.toFixed(2)} of 8 bits/byte`, `${str(ent.overall_classification, '—')} · highest window ${num(ent.max_window_entropy).toFixed(2)}`, overall >= 7.2 ? 'bad' : 'accent')}
          ${kpi('Toolchain', str(prov.compiler_family, 'unknown'), (prov.source_languages || []).join(', '))}
          ${kpi('Capabilities', plural(capCats.length, 'area'), `${num(caps.total_matched_indicators)} imported or defined API names${num(caps.total_weak_indicators) ? ` · ${num(caps.total_weak_indicators)} named only in strings` : ''}`)}
          ${kpi('Anomalies', plural(findings.length, 'finding'), `symbols: ${str(prov.strip_level, 'unknown')}`, num(anom.high_severity_count) > 0 ? 'bad' : '')}
        </div>

        <div class="panel-card">
          <div class="panel-card-header"><span>Entropy across the slice (${windows.length} windows)</span><span class="header-note">${str(ent.packing_assessment)}</span></div>
          <div class="entropy-sparkline-wrap">
            <div class="entropy-sparkline-bars">
              ${windows.map((w) => html`<button type="button" class="entropy-bar ${entropyClass(num(w.entropy))}" data-h="${Math.max(6, Math.round((num(w.entropy) / 8) * 100))}" data-jump-offset="${num(w.abs_offset)}" data-jump-size="${num(w.size, 16)}" title="${hex(w.abs_offset, 6)} · ${formatBytes(w.size)} · ${num(w.entropy).toFixed(2)} bits/byte" aria-label="Window at ${hex(w.abs_offset)}, entropy ${num(w.entropy).toFixed(2)}"></button>`)}
            </div>
            <div class="entropy-axis">
              <span>${hex(slice.slice_base_offset, 6)}</span>
              <span class="entropy-legend">
                <span><i class="legend-swatch ent-sparse"></i>sparse &lt;1</span>
                <span><i class="legend-swatch ent-structured"></i>structured 1–4.5</span>
                <span><i class="legend-swatch ent-code"></i>code 4.5–6.5</span>
                <span><i class="legend-swatch ent-dense"></i>dense 6.5–7.2</span>
                <span><i class="legend-swatch ent-packed"></i>compressed or encrypted &gt;7.2</span>
              </span>
              <span>${hex(num(slice.slice_base_offset) + num(slice.slice_size), 6)}</span>
            </div>
            <div class="byte-class-caption">Bytes: null ${pct(dist.null_pct)}% · printable ASCII ${pct(dist.ascii_pct)}% · control ${pct(dist.control_pct)}% · high bit set ${pct(dist.high_pct)}%</div>
            <div class="byte-class-stacked-bar" aria-hidden="true">
              <div class="bc-null" data-w="${pct(dist.null_pct)}"></div><div class="bc-ascii" data-w="${pct(dist.ascii_pct)}"></div><div class="bc-ctrl" data-w="${pct(dist.control_pct)}"></div><div class="bc-high" data-w="${pct(dist.high_pct)}"></div>
            </div>
          </div>
        </div>

        <div class="panel-card">
          <div class="panel-card-header">Capabilities, from imported and defined API names (${capCats.length})</div>
          ${capCats.length === 0 ? html`<div class="empty-note">No imported or defined symbol is one of the API names this view looks for.</div>` : ''}
          <div class="capability-grid">
            ${capCats.map((cat) => html`
              <div class="cap-card">
                <div class="sec-check-top">
                  <span class="sec-check-title">${str(cat.title)}</span>
                  <span class="sec-status-pill sec-${cat.risk === 'HIGH' ? 'WARN' : 'INFO'}">${str(cat.risk)} · ${num(cat.match_count)}</span>
                </div>
                <div class="sec-check-detail">${str(cat.description)}</div>
                <div class="cap-evidence-list">
                  ${(cat.evidence || []).map((ev) => html`<button type="button" class="jump-chip" data-jump-offset="${num(ev.abs_offset)}" data-jump-size="16" title="${str(ev.kind)}: ${str(ev.value)}">${truncate(ev.indicator, 80)}</button>`)}
                </div>
                ${(cat.weak_evidence || []).length ? html`
                  <div class="sec-check-detail">Also named in strings (weaker evidence):</div>
                  <div class="cap-evidence-list">
                    ${cat.weak_evidence.map((ev) => html`<button type="button" class="jump-chip" data-jump-offset="${num(ev.abs_offset)}" data-jump-size="${Math.max(1, str(ev.value).length)}" title="string: ${str(ev.value)}">${truncate(ev.indicator, 80)}</button>`)}
                  </div>` : ''}
              </div>
            `)}
          </div>
        </div>

        ${weakCats.length ? html`
        <div class="panel-card">
          <div class="panel-card-header"><span>Named only in strings (${weakCats.length})</span><span class="header-note">weaker evidence: the API name appears as text, not as an import</span></div>
          <div class="capability-grid">
            ${weakCats.map((cat) => html`
              <div class="cap-card">
                <div class="sec-check-top">
                  <span class="sec-check-title">${str(cat.title)}</span>
                  <span class="sec-status-pill sec-INFO">strings only · ${num(cat.weak_count)}</span>
                </div>
                <div class="sec-check-detail">A string in the file is exactly one of these API names. That is how a name passed to dlsym or GetProcAddress looks, and also how ordinary text can look; no import refers to it.</div>
                <div class="cap-evidence-list">
                  ${(cat.weak_evidence || []).map((ev) => html`<button type="button" class="jump-chip" data-jump-offset="${num(ev.abs_offset)}" data-jump-size="${Math.max(1, str(ev.value).length)}" title="string: ${str(ev.value)}">${truncate(ev.indicator, 80)}</button>`)}
                </div>
              </div>
            `)}
          </div>
        </div>` : ''}

        <div class="overview-two-col">
          <div class="panel-card">
            <div class="panel-card-header">Entropy by section (${secMetrics.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Section</th><th>Size</th><th>Entropy</th><th>Looks like</th><th>ASCII / null</th></tr></thead>
                <tbody>
                  ${secMetrics.length === 0 ? emptyRow(5, 'No sections with file bytes.') : ''}
                  ${secMetrics.map((m) => html`
                    <tr class="struct-row" data-abs-offset="${num(m.abs_offset)}" data-field-size="${Math.min(num(m.size, 64) || 64, 256)}" data-field-name="${str(m.name)}">
                      ${cp('col-name', str(m.name))}
                      <td>${formatBytes(m.size)}</td>
                      <td class="col-val ${num(m.entropy) >= 7.2 ? 't-danger' : ''}">${num(m.entropy).toFixed(2)}</td>
                      <td>${str(m.classification)}</td>
                      <td>${pct(m.byte_classes?.ascii_pct)}% / ${pct(m.byte_classes?.null_pct)}%</td>
                    </tr>
                  `)}
                </tbody>
              </table>
            </div>
          </div>

          <div class="panel-card">
            <div class="panel-card-header">Provenance and anomalies</div>
            <div class="kv-list">
              <div class="kv-row"><span class="kv-key">Compiler / linker</span><span class="kv-val">${str(prov.compiler_family, '—')}${(prov.linker_info || []).length ? ` (${prov.linker_info.join(', ')})` : ''}</span></div>
              <div class="kv-row"><span class="kv-key">ABI</span><span class="kv-val">${str(prov.abi, '—')}</span></div>
              <div class="kv-row"><span class="kv-key">Debug artefacts</span><span class="kv-val" data-copy="${(prov.debug_artifacts || []).join('\n')}">${(prov.debug_artifacts || []).join(' | ') || 'none'}</span></div>
              <div class="kv-row"><span class="kv-key">In strings</span><span class="kv-val">${plural((strIntel.urls || []).length, 'URL')}, ${plural((strIntel.file_paths || []).length, 'path')}, ${plural((strIntel.registry_keys || []).length, 'registry key')}</span></div>
              ${findings.map((f) => html`
                <div class="kv-row row-clickable finding-row" data-jump-offset="${num(f.abs_offset)}" data-jump-size="32">
                  <span class="kv-key"><span class="sec-status-pill sec-${f.severity === 'WARN' ? 'WARN' : 'INFO'}">${str(f.severity)}</span> ${str(f.title)}</span>
                  <span class="kv-val finding-detail">${str(f.detail)}</span>
                </div>
              `)}
            </div>
          </div>
        </div>

        ${rich ? html`
          <div class="panel-card">
            <div class="panel-card-header"><span>Rich header · XOR key ${str(rich.xor_key)}</span>${jumpChip(rich.abs_offset, rich.size, 'Show in hex')}</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Product ID</th><th>Tool</th><th>Build</th><th>Objects</th></tr></thead>
                <tbody>
                  ${(rich.entries || []).map((r) => html`
                    <tr class="struct-row" data-abs-offset="${num(rich.abs_offset)}" data-field-size="${num(rich.size, 16)}" data-field-name="Rich header">
                      <td class="col-val">${hex(r.prod_id, 4)}</td>
                      <td class="col-name">${str(r.product_name)}</td>
                      <td>${num(r.build_num)}</td>
                      <td>${num(r.use_count)}</td>
                    </tr>
                  `)}
                </tbody>
              </table>
            </div>
          </div>
        ` : ''}
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 12 (Learn group): Loader Lifecycle
  // -------------------------------------------------------------------------
  function renderLoaderLifecycleInspector(bodyEl) {
    const slice = getActiveSlice();
    if (!slice) return;
    const lc = slice.pedagogy?.loader_lifecycle || {};
    const stages = lc.stages || [];

    bodyEl.innerHTML = html`
      <div class="overview-container">
        <div class="panel-card">
          <div class="panel-card-header"><span>From file to process · ${str(lc.os_family)}</span><span class="header-note mono">${str(lc.loader_name)}</span></div>
          <p class="panel-intro">The steps the kernel and the dynamic linker take to turn this ${str(slice.format_display || slice.format)} file into a running process. Each step links to the bytes it reads.</p>
          ${stages.length === 0 ? html`<div class="empty-note">No lifecycle description is available for this slice.</div>` : ''}
          <div class="lifecycle-stepper">
            ${stages.map((st) => html`
              <div class="lifecycle-stage-card">
                <div class="stage-head">
                  <span class="stage-title"><span class="stage-num-badge">${num(st.stage)}</span>${str(st.title).replace(/^\d+\.\s*/, '')}</span>
                  ${jumpChip(st.abs_offset, st.size || 32, 'Show bytes')}
                </div>
                <div class="stage-actor">${str(st.actor)}</div>
                <div class="stage-summary">${str(st.summary)}</div>
                <div class="stage-evidence">
                  <div><strong>In this binary</strong> ${str(st.binary_state)}</div>
                  <div><strong>If it is wrong</strong> ${str(st.failure_mode)}</div>
                </div>
              </div>
            `)}
          </div>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 13 (Learn group): Format Comparison & Guided Tours
  // -------------------------------------------------------------------------
  function renderRosettaAndToursInspector(bodyEl) {
    const slice = getActiveSlice();
    if (!slice) return;
    const ped = slice.pedagogy || {};
    const rows = ped.rosetta_stone || [];
    const tours = ped.guided_tours || [];
    const fmt = sliceFormat(slice);
    const on = (f) => (fmt === f ? 'cell-active' : '');

    bodyEl.innerHTML = html`
      <div class="overview-container">
        <div class="panel-card">
          <div class="panel-card-header">Guided tours (${tours.length})</div>
          ${tours.length === 0 ? html`<div class="empty-note">No tours are available for this slice.</div>` : ''}
          <div class="lifecycle-stepper">
            ${tours.map((tour) => html`
              <div class="tour-card">
                <div class="stage-head">
                  <span class="stage-title">${str(tour.title)}</span>
                  <span class="tour-meta">${str(tour.level)} · ${str(tour.estimated_time)}</span>
                </div>
                <div class="t-dim">${str(tour.description)}</div>
                ${(tour.steps || []).map((st) => html`
                  <div class="tour-step">
                    <div class="stage-head">
                      <strong>Step ${num(st.step_number)}. ${str(st.title)}</strong>
                      <button type="button" class="jump-chip" data-select-node="${str(st.target_node_id, 'overview')}" data-jump-offset="${num(st.abs_offset)}" data-jump-size="${num(st.size, 32) || 32}">Show</button>
                    </div>
                    <div class="tour-narrative">${str(st.narrative)}</div>
                    ${st.challenge ? html`
                      <div class="quiz">
                        <div class="quiz-q">${str(st.challenge.question)}</div>
                        ${(st.challenge.options || []).map((opt, oIdx) => html`
                          <button type="button" class="quiz-option-btn" data-quiz-correct="${oIdx === st.challenge.correct_index ? '1' : '0'}" data-quiz-exp="${str(st.challenge.explanation)}">${str(opt)}</button>
                        `)}
                        <div class="quiz-feedback" role="status" hidden></div>
                      </div>
                    ` : ''}
                  </div>
                `)}
              </div>
            `)}
          </div>
        </div>

        <div class="panel-card">
          <div class="panel-card-header">The same idea in Mach-O, ELF and PE</div>
          <div class="struct-table-wrap">
            <table class="struct-table rosetta-table">
              <thead><tr><th>Concept</th><th class="${on('MACHO')}">Mach-O</th><th class="${on('ELF')}">ELF</th><th class="${on('PE')}">PE</th><th>Why it exists</th></tr></thead>
              <tbody>
                ${rows.length === 0 ? emptyRow(5, 'No comparison data.') : ''}
                ${rows.map((r) => html`
                  <tr class="struct-row" data-abs-offset="${num(r.active_offset)}" data-field-size="32" data-field-name="${str(r.concept)}">
                    <td class="col-name">${str(r.concept).replace(/^\d+\.\s*/, '')}</td>
                    <td class="col-desc ${on('MACHO')}">${str(r.macho)}</td>
                    <td class="col-desc ${on('ELF')}">${str(r.elf)}</td>
                    <td class="col-desc ${on('PE')}">${str(r.pe)}</td>
                    <td class="col-desc">${str(r.pedagogical_note)} <button type="button" class="jump-chip" data-select-node="${str(r.active_target_node, 'overview')}" data-jump-offset="${num(r.active_offset)}" data-jump-size="32">Show in this binary</button></td>
                  </tr>
                `)}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  // =========================================================================
  // Synchronized Virtualized Hex & ASCII Pane + Chunk Fetcher
  // =========================================================================
  // topRow is the (fractional) index of the first visible row. For files whose full height would
  // exceed what browsers can lay out, the scrollbar is scaled and the wheel is handled explicitly
  // so that scrolling still moves by rows, not by megabytes.
  const hexView = { topRow: 0, scaled: false };
  const byteActivateListeners = new Set();

  function hexTotalRows() {
    return Math.ceil(fileSize() / HEX_BYTES_PER_ROW);
  }

  function hexViewRows(viewport) {
    return Math.max(1, Math.floor((viewport.clientHeight || 380) / HEX_ROW_HEIGHT));
  }

  function hexMaxTopRow(viewport) {
    return Math.max(0, hexTotalRows() - hexViewRows(viewport));
  }

  function hexScaledScrollTop(viewport) {
    const maxTop = hexMaxTopRow(viewport);
    const maxScroll = Math.max(1, HEX_MAX_SCROLL_PX - viewport.clientHeight);
    return maxTop > 0 ? (hexView.topRow / maxTop) * maxScroll : 0;
  }

  function initHexViewport() {
    const phantom = document.getElementById('hex-phantom');
    const viewport = document.getElementById('hex-viewport');
    if (!phantom || !viewport) return;
    const fullHeight = hexTotalRows() * HEX_ROW_HEIGHT;
    hexView.scaled = fullHeight > HEX_MAX_SCROLL_PX;
    phantom.style.height = `${hexView.scaled ? HEX_MAX_SCROLL_PX : fullHeight}px`;
    hexView.topRow = 0;
    viewport.scrollTop = 0;
    applyHexModeLabels();
    renderHexViewport();
  }

  function hexSetTopRow(row) {
    const viewport = document.getElementById('hex-viewport');
    if (!viewport) return;
    hexView.topRow = Math.max(0, Math.min(hexMaxTopRow(viewport), row));
    viewport.scrollTop = hexView.scaled ? hexScaledScrollTop(viewport) : hexView.topRow * HEX_ROW_HEIGHT;
    renderHexViewport();
  }

  function onHexScroll() {
    const viewport = document.getElementById('hex-viewport');
    if (!viewport) return;
    if (!hexView.scaled) {
      hexView.topRow = viewport.scrollTop / HEX_ROW_HEIGHT;
    } else if (Math.abs(viewport.scrollTop - hexScaledScrollTop(viewport)) > 1.5) {
      // The user dragged the scrollbar; a programmatic scroll already has an exact topRow.
      const maxScroll = Math.max(1, HEX_MAX_SCROLL_PX - viewport.clientHeight);
      hexView.topRow = (viewport.scrollTop / maxScroll) * hexMaxTopRow(viewport);
    }
    renderHexViewport();
  }

  function decodeHexResponse(data) {
    if (data && typeof data.hex_bytes === 'string') {
      const clean = data.hex_bytes.replace(/[^0-9a-fA-F]/g, '');
      const bytes = new Uint8Array(clean.length >> 1);
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
      return bytes;
    }
    if (data && Array.isArray(data.rows)) {
      const bytes = new Uint8Array(data.rows.length * 16);
      let k = 0;
      data.rows.forEach((r) => {
        (r.hex_array || []).forEach((hb) => {
          bytes[k++] = parseInt(hb, 16) & 0xff;
        });
      });
      return bytes.subarray(0, k);
    }
    return null;
  }

  /** Load one cached chunk; resolves to its bytes (or null on failure). */
  function ensureHexChunk(chunkOffset) {
    if (state.hexChunks.has(chunkOffset)) return Promise.resolve(state.hexChunks.get(chunkOffset));
    if (state.hexPendingChunks.has(chunkOffset)) return state.hexPendingChunks.get(chunkOffset);
    const generation = docGeneration;
    const job = (async () => {
      try {
        const bytes = decodeHexResponse(await api.get('/api/hex', { offset: chunkOffset, length: HEX_CHUNK_SIZE }));
        if (generation !== docGeneration || !bytes) return null; // a different document is open now
        state.hexChunks.set(chunkOffset, bytes);
        while (state.hexChunks.size > HEX_MAX_CHUNKS) state.hexChunks.delete(state.hexChunks.keys().next().value);
        renderHexViewport();
        return bytes;
      } catch (err) {
        if (!(err instanceof ApiError)) console.warn('[BinaryStudio] hex chunk failed:', err);
        return null;
      } finally {
        if (generation === docGeneration) state.hexPendingChunks.delete(chunkOffset);
      }
    })();
    state.hexPendingChunks.set(chunkOffset, job);
    return job;
  }

  function getByteAtOffset(absOffset) {
    const chunkStart = Math.floor(absOffset / HEX_CHUNK_SIZE) * HEX_CHUNK_SIZE;
    const chunk = state.hexChunks.get(chunkStart);
    if (!chunk) {
      ensureHexChunk(chunkStart);
      return null;
    }
    const idx = absOffset - chunkStart;
    return idx >= 0 && idx < chunk.length ? chunk[idx] : null;
  }

  /** BS.hex.getBytes */
  async function hexGetBytes(absOffset, length) {
    if (!state.doc) throw new Error('No document is open.');
    const size = fileSize();
    const start = Math.max(0, Math.min(size, Math.trunc(num(absOffset))));
    const len = Math.max(0, Math.min(4 * 1024 * 1024, size - start, Math.trunc(num(length))));
    const out = new Uint8Array(len);
    if (!len) return out;
    const generation = docGeneration;
    const stale = () => new Error('The document changed while its bytes were being read.');

    if (len <= 2 * HEX_CHUNK_SIZE) {
      const first = Math.floor(start / HEX_CHUNK_SIZE) * HEX_CHUNK_SIZE;
      const offsets = [];
      for (let c = first; c < start + len; c += HEX_CHUNK_SIZE) offsets.push(c);
      const chunks = await Promise.all(offsets.map(ensureHexChunk));
      if (generation !== docGeneration) throw stale();
      chunks.forEach((chunk, i) => {
        if (!chunk) throw new ApiError(0, 'bad_response', `Could not read bytes at ${hex(offsets[i])}.`);
        const from = Math.max(start, offsets[i]);
        const to = Math.min(start + len, offsets[i] + chunk.length);
        if (to > from) out.set(chunk.subarray(from - offsets[i], to - offsets[i]), from - start);
      });
      return out;
    }

    const PIECE = 32768;
    for (let pos = start; pos < start + len; pos += PIECE) {
      const want = Math.min(PIECE, start + len - pos);
      const bytes = decodeHexResponse(await api.get('/api/hex', { offset: pos, length: want }));
      if (generation !== docGeneration) throw stale();
      if (!bytes || bytes.length < want) throw new ApiError(0, 'bad_response', `Could not read bytes at ${hex(pos)}.`);
      out.set(bytes.subarray(0, want), pos - start);
    }
    return out;
  }

  /** BS.hex.setDecorations */
  function setHexDecorations(key, list) {
    const k = str(key);
    if (!k) return;
    const clean = (Array.isArray(list) ? list : [])
      .map((d) => ({
        abs_offset: Math.trunc(num(d && d.abs_offset, -1)),
        size: Math.max(1, Math.trunc(num(d && d.size, 1))),
        className: str(d && d.className).split(/\s+/).map(tok).filter(Boolean).join(' '),
        title: str(d && d.title),
      }))
      .filter((d) => d.abs_offset >= 0);
    if (clean.length) state.hexDecorations.set(k, clean);
    else state.hexDecorations.delete(k);
    renderHexViewport();
  }

  function renderHexViewport() {
    const viewport = document.getElementById('hex-viewport');
    const rowsContainer = document.getElementById('hex-rows-container');
    if (!viewport || !rowsContainer) return;
    if (!state.doc) {
      rowsContainer.replaceChildren();
      return;
    }

    const size = fileSize();
    const totalRows = hexTotalRows();
    const viewHeight = viewport.clientHeight || 380;
    let firstRow;
    let lastRow;
    let translate;
    if (hexView.scaled) {
      firstRow = Math.floor(hexView.topRow);
      lastRow = Math.min(totalRows, firstRow + hexViewRows(viewport) + 3);
      translate = viewport.scrollTop - (hexView.topRow - firstRow) * HEX_ROW_HEIGHT;
    } else {
      const scrollTop = viewport.scrollTop;
      firstRow = Math.max(0, Math.floor(scrollTop / HEX_ROW_HEIGHT) - 6);
      lastRow = Math.min(totalRows, Math.ceil((scrollTop + viewHeight) / HEX_ROW_HEIGHT) + 6);
      translate = firstRow * HEX_ROW_HEIGHT;
    }
    rowsContainer.style.transform = `translateY(${translate}px)`;

    const slice = getActiveSlice();
    const sSpan = state.structSpan;
    const fSpan = state.fieldSpan;

    // Extension highlight layers that intersect the visible window.
    const winStart = firstRow * HEX_BYTES_PER_ROW;
    const winEnd = lastRow * HEX_BYTES_PER_ROW;
    const decos = [];
    state.hexDecorations.forEach((list) => {
      for (const d of list) if (d.abs_offset < winEnd && d.abs_offset + d.size > winStart) decos.push(d);
    });

    // Built by concatenation for speed. Every dynamic piece is a number, a fixed class name, a
    // sanitised decoration class, or passes through escapeHtml / escapeAttr.
    const parts = [];
    for (let r = firstRow; r < lastRow; r++) {
      const rowOffset = r * HEX_BYTES_PER_ROW;
      let addrLabel = hexNoPrefix(rowOffset, 8);
      let addrCls = 'hex-row-addr';
      if (state.hexAddrMode === 'vm') {
        const vm = absOffsetToVmAddr(rowOffset, slice);
        if (vm) addrLabel = vm.replace(/^0x/i, '').toUpperCase().padStart(9, '0');
        else {
          addrLabel = 'unmapped';
          addrCls += ' addr-unmapped';
        }
      }

      let bytesHtml = '';
      let asciiHtml = '';
      for (let b = 0; b < HEX_BYTES_PER_ROW; b++) {
        const off = rowOffset + b;
        if (off >= size) {
          bytesHtml += `<span class="hex-byte hex-pad${b === 8 ? ' byte-gap' : ''}"></span>`;
          asciiHtml += '<span class="ascii-char"></span>';
          continue;
        }

        const val = getByteAtOffset(off);
        const hexStr = val === null ? '··' : (val < 16 ? '0' : '') + val.toString(16).toUpperCase();
        const isPrintable = val !== null && val >= 0x20 && val <= 0x7e;
        const asciiChar = val === null ? '·' : isPrintable ? escapeHtml(String.fromCharCode(val)) : '.';

        const inStruct = sSpan && off >= sSpan.abs_offset && off < sSpan.abs_offset + sSpan.size;
        const inField = fSpan && off >= fSpan.abs_offset && off < fSpan.abs_offset + fSpan.size;
        const isCursor = off === state.cursorOffset;

        let cls = 'hex-byte';
        if (b === 8) cls += ' byte-gap';
        if (val === 0) cls += ' byte-zero';
        if (val === null) cls += ' byte-pending';
        if (inStruct) cls += ' in-struct-span';
        if (inField) cls += ' in-field-span';
        let title = '';
        for (const d of decos) {
          if (off >= d.abs_offset && off < d.abs_offset + d.size) {
            if (d.className) cls += ' ' + d.className;
            if (d.title) title = d.title;
          }
        }
        if (isCursor) cls += ' cursor-byte';

        let asciiCls = 'ascii-char';
        if (!isPrintable) asciiCls += ' ascii-nonprint';
        if (inField) asciiCls += ' in-field-span';
        if (isCursor) asciiCls += ' cursor-byte';

        bytesHtml += `<span class="${cls}" data-byte-offset="${off}"${title ? ` title="${escapeAttr(title)}"` : ''}>${hexStr}</span>`;
        asciiHtml += `<span class="${asciiCls}" data-byte-offset="${off}">${asciiChar}</span>`;
      }

      parts.push(`<div class="hex-row"><span class="${addrCls}">${addrLabel}</span><span class="hex-row-bytes">${bytesHtml}</span><span class="hex-row-ascii">${asciiHtml}</span></div>`);
    }

    rowsContainer.innerHTML = parts.join('');
  }

  function scrollHexToOffset(absOffset) {
    const viewport = document.getElementById('hex-viewport');
    if (!viewport || !state.doc) return;
    const rowIdx = Math.floor(absOffset / HEX_BYTES_PER_ROW);
    const rows = hexViewRows(viewport);
    if (rowIdx < hexView.topRow + 1 || rowIdx > hexView.topRow + rows - 2) {
      hexSetTopRow(rowIdx - Math.floor(rows / 3));
    } else {
      renderHexViewport();
    }
  }

  function setFieldSpan(span) {
    const prev = state.fieldSpan;
    state.fieldSpan = span
      ? { abs_offset: Math.max(0, Math.trunc(num(span.abs_offset))), size: Math.max(1, Math.trunc(num(span.size, 1))), label: str(span.label) }
      : null;
    const same = prev && state.fieldSpan && prev.abs_offset === state.fieldSpan.abs_offset && prev.size === state.fieldSpan.size && prev.label === state.fieldSpan.label;
    if (!same && (prev || state.fieldSpan)) bus.emit('selection:changed', { span: state.fieldSpan });
  }

  function updateSelectionReadout() {
    const span = state.fieldSpan;
    const pill = document.getElementById('hex-selection-pill');
    const status = document.getElementById('status-span');
    if (!state.doc) {
      if (pill) pill.textContent = '';
      if (status) status.textContent = '';
      return;
    }
    if (pill) {
      pill.textContent = span ? `${truncate(span.label || 'selection', 28)} ${hex(span.abs_offset, 6)} +${span.size}` : `cursor ${hex(state.cursorOffset, 6)}`;
      pill.dataset.copy = hex(span ? span.abs_offset : state.cursorOffset);
      pill.title = span ? `${span.label || 'Selection'}: ${hex(span.abs_offset)} – ${hex(span.abs_offset + span.size)} (${span.size} bytes). Click to copy the offset.` : 'Click to copy the cursor offset';
    }
    if (status) {
      status.textContent = span ? `${truncate(span.label || 'selection', 40)} @ ${hex(span.abs_offset)} · ${plural(span.size, 'byte')}` : `cursor ${hex(state.cursorOffset)}`;
    }
  }

  /**
   * Move the byte cursor. fieldSpan (optional) becomes the highlighted range.
   * opts: {scrollHex = true, recordHistory = false, keepAnchor = false}
   */
  function setCursorAndHighlight(absOffset, fieldSpan = null, options) {
    const opts = Object.assign({ scrollHex: true, recordHistory: false, keepAnchor: false }, options);
    if (!state.doc) return;
    const maxOff = Math.max(0, fileSize() - 1);
    const clamped = Math.max(0, Math.min(Math.trunc(num(absOffset)), maxOff));
    const moved = clamped !== state.cursorOffset;

    state.cursorOffset = clamped;
    if (!opts.keepAnchor) state.selAnchor = clamped;
    if (fieldSpan) setFieldSpan(fieldSpan);
    updateSelectionReadout();

    if (opts.scrollHex) {
      scrollHexToOffset(clamped);
    } else {
      renderHexViewport();
    }

    updateMemoryMapPlayhead();
    fetchLiveByteDecode(clamped);
    updateConverterFromOffset(clamped);

    if (opts.recordHistory && !state.suppressHistory) pushHistory(currentEntry());
    else syncLocationSoon();
    if (moved) bus.emit('cursor:changed', { absOffset: clamped });
  }

  function applyHexModeLabels() {
    const vm = state.hexAddrMode === 'vm';
    const modeLabel = document.getElementById('hex-addr-mode-label');
    if (modeLabel) modeLabel.textContent = vm ? 'VM address' : 'file offset';
    const colTitle = document.getElementById('hex-col-offset-title');
    if (colTitle) colTitle.textContent = vm ? 'Address' : 'Offset';
    const endian = document.getElementById('decoder-endian-label');
    if (endian) endian.textContent = state.decoderEndian;
    const scale = document.getElementById('memmap-scale-label');
    if (scale) scale.textContent = state.memmapScale === 'sqrt' ? 'sqrt' : 'linear';
  }

  function toggleHexAddrMode() {
    state.hexAddrMode = state.hexAddrMode === 'file' ? 'vm' : 'file';
    storage.set('hex.addrMode', state.hexAddrMode);
    applyHexModeLabels();
    renderHexViewport();
  }

  function toggleDecoderEndian() {
    state.decoderEndian = state.decoderEndian === 'little' ? 'big' : 'little';
    storage.set('hex.endian', state.decoderEndian);
    applyHexModeLabels();
    if (state.doc) fetchLiveByteDecode(state.cursorOffset);
  }

  function toggleMemmapScale() {
    state.memmapScale = state.memmapScale === 'sqrt' ? 'linear' : 'sqrt';
    storage.set('memmap.scale', state.memmapScale);
    applyHexModeLabels();
    renderMemoryMapRibbon();
  }

  function bytesToHex(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) out += (i ? ' ' : '') + (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return out;
  }

  /** Copy the highlighted range (or the byte under the cursor) as hex text. */
  async function copySelectionHex() {
    if (!state.doc) return;
    const span = state.fieldSpan || { abs_offset: state.cursorOffset, size: 1 };
    const LIMIT = 65536;
    const size = Math.min(span.size, LIMIT);
    try {
      const bytes = await hexGetBytes(span.abs_offset, size);
      await copyText(bytesToHex(bytes), `${plural(bytes.length, 'byte')} from ${hex(span.abs_offset)}`);
      if (span.size > LIMIT) toast(`Only the first ${formatBytes(LIMIT)} of the ${formatBytes(span.size)} selection were copied.`, 'warn');
    } catch (err) {
      toast(`Could not read the selected bytes. ${describeError(err).what}`, 'error');
    }
  }

  function activateByte(absOffset, event) {
    const detail = { absOffset, byte: getByteAtOffset(absOffset), event };
    byteActivateListeners.forEach((fn) => safeCall(fn, detail, 'hex:activate'));
  }

  // =========================================================================
  // Live Byte Inspector / Data Decoder Card (`/api/decode`)
  // =========================================================================
  let decodeAbortController = null;
  let decodeTimer = null;

  function fetchLiveByteDecode(absOffset) {
    // Debounced so that holding an arrow key does not send one request per repeat.
    clearTimeout(decodeTimer);
    decodeTimer = setTimeout(async () => {
      if (decodeAbortController) decodeAbortController.abort();
      if (!state.doc) return;
      decodeAbortController = new AbortController();
      const generation = docGeneration;
      try {
        const data = await api.get('/api/decode', { offset: absOffset, endian: state.decoderEndian }, { signal: decodeAbortController.signal });
        if (generation !== docGeneration) return;
        state.lastDecodeData = data;
        renderByteDecoderCard(data);
      } catch (err) {
        if (err.name !== 'AbortError' && !(err instanceof ApiError)) console.warn('[BinaryStudio] decode failed:', err);
      }
    }, 35);
  }

  function renderByteDecoderCard(data) {
    if (!data) return;
    const p = data.primitives || {};
    const show = (id, text, copyValue) => {
      const node = document.getElementById(id);
      if (!node) return;
      node.textContent = text;
      node.title = text;
      node.dataset.copy = copyValue === undefined ? text : str(copyValue);
    };
    const v = (x) => (x === null || x === undefined ? '—' : String(x));

    show('dec-u8', `${v(p.uint8)} / ${v(p.int8)}`, v(p.uint8));
    show('dec-u16', `${v(p.uint16)} / ${v(p.int16)}`, v(p.uint16));
    show('dec-u32', `${v(p.uint32)} (${v(p.hex32)})`, v(p.hex32));
    show('dec-u64', v(p.uint64));
    show('dec-uleb', p.uleb128 ? `${v(p.uleb128.value)} (${num(p.uleb128.byte_length)} B)` : '—', p.uleb128 ? v(p.uleb128.value) : '');
    show('dec-sleb', p.sleb128 ? `${v(p.sleb128.value)} (${num(p.sleb128.byte_length)} B)` : '—', p.sleb128 ? v(p.sleb128.value) : '');
    const f32 = p.float32 === null || p.float32 === undefined ? '—' : Number(p.float32).toPrecision(6);
    const f64 = p.float64 === null || p.float64 === undefined ? '—' : Number(p.float64).toPrecision(6);
    show('dec-float', `${f32} / ${f64}`, f32);
    // `insn_arch` says which decoder applies to this slice ("arm64" | "x86"); null means the
    // architecture is not disassembled, and then no instruction is shown for these bytes.
    const insnPreview = p.insn_arch === 'arm64' ? p.arm64_insn : p.insn_arch === 'x86' ? p.x86_insn : null;
    show('dec-insn', p.insn_arch === null && p.insn_note
      ? str(p.insn_note)
      : str(insnPreview && insnPreview !== 'N/A' ? insnPreview : p.cstring_preview) || '—');

    // Field explanation: only visible in Learn mode (class learn-only).
    const pedBox = document.getElementById('decoder-pedagogy-box');
    if (pedBox) {
      const fp = data.field_pedagogy;
      if (fp) {
        pedBox.innerHTML = html`<strong>${str(fp.field_name)}</strong> ${str(fp.why_it_matters)} <span class="t-dim">In other formats: ${str(fp.cross_format_peer)}</span>`;
        pedBox.hidden = false;
      } else {
        pedBox.hidden = true;
        pedBox.replaceChildren();
      }
    }

    const crumbsEl = document.getElementById('decoder-breadcrumbs');
    const crumbs = Array.isArray(data.breadcrumbs) ? data.breadcrumbs : [];
    if (crumbs.length === 0) {
      crumbsEl.innerHTML = html`<span class="crumb-empty">${hex(data.abs_offset, 6)} is outside every parsed structure</span>`;
    } else {
      crumbsEl.innerHTML = html`${crumbs.map((c, i) => html`
        ${i > 0 ? html`<span class="crumb-sep" aria-hidden="true">›</span>` : ''}
        <button type="button" class="crumb-pill" data-crumb-offset="${num(c.abs_offset)}" data-crumb-size="${num(c.size, 16)}" data-crumb-id="${str(c.id)}" title="${str(c.label)} · ${hex(c.abs_offset)} · ${plural(num(c.size), 'byte')}">${truncate(c.label, 48)}</button>
      `)}`;
    }
  }

  // =========================================================================
  // Real-Time Address / Offset Converter Bar (`/api/translate`)
  // =========================================================================
  let translateTimeout = null;
  let translateAbort = null;

  async function runTranslateQuery(query, mode = 'auto') {
    if (!state.doc || query === '' || query === null || query === undefined) return null;
    if (translateAbort) translateAbort.abort();
    translateAbort = new AbortController();
    const generation = docGeneration;
    try {
      const data = await api.get('/api/translate', { query: String(query), mode }, { signal: translateAbort.signal });
      if (generation !== docGeneration) return null;
      renderConverterResult(data);
      return data;
    } catch (err) {
      if (err.name !== 'AbortError' && !(err instanceof ApiError)) console.warn('[BinaryStudio] translate failed:', err);
      return null;
    }
  }

  function updateConverterFromOffset(absOffset) {
    clearTimeout(translateTimeout);
    translateTimeout = setTimeout(() => {
      runTranslateQuery(hex(absOffset), 'abs_offset');
    }, 45);
  }

  function renderConverterResult(data) {
    if (!data) return;
    const absIn = document.getElementById('conv-abs-input');
    const sliceIn = document.getElementById('conv-slice-input');
    const vmIn = document.getElementById('conv-vm-input');
    const rvaIn = document.getElementById('conv-rva-input');
    if (!absIn || !sliceIn || !vmIn || !rvaIn) return;

    if (document.activeElement !== absIn) absIn.value = typeof data.abs_offset === 'number' ? hex(data.abs_offset, 6) : '';
    if (document.activeElement !== sliceIn) sliceIn.value = typeof data.slice_offset === 'number' ? hex(data.slice_offset, 6) : '';
    if (document.activeElement !== vmIn) vmIn.value = str(data.vmaddr);
    vmIn.placeholder = data.vmaddr ? '' : 'not mapped';
    rvaIn.value = data.rva ? str(data.rva) : '';

    const statusBadge = document.getElementById('conv-status-badge');
    const segPill = document.getElementById('conv-seg-pill');
    const symPill = document.getElementById('conv-sym-pill');

    const status = str(data.status || (data.mapped ? 'MAPPED' : 'UNMAPPED'));
    statusBadge.textContent = status === 'MAPPED' ? 'mapped' : status === 'UNMAPPED_ZEROFILL' ? 'zero-fill' : 'not mapped';
    statusBadge.title = status === 'UNMAPPED_ZEROFILL' ? 'Inside a segment in memory, but beyond the bytes stored in the file' : '';
    statusBadge.className = `res-status-badge ${data.mapped ? 'status-mapped' : 'status-unmapped'}`;

    if (data.segment) {
      const secStr = data.section ? `,${str(data.section.sectname)}` : '';
      segPill.textContent = `${str(data.segment.segname)}${secStr} ${str(data.segment.initprot, '---')}`;
    } else {
      segPill.textContent = 'not in a segment';
    }

    let symText = '';
    if (data.nearest_symbol) symText = str(data.nearest_symbol.display || data.nearest_symbol.name);
    symPill.textContent = symText;
    symPill.title = symText ? `${symText}\nClick to copy` : '';
    symPill.dataset.copy = symText;
    symPill.hidden = !symText;
  }

  // =========================================================================
  // Command Palette: search (`/api/search`), views and commands
  // =========================================================================
  const cmdkLayer = { kind: 'palette', close: () => closeCmdkModal() };
  let cmdkPrevFocus = null;
  let cmdkTimer = null;
  let cmdkSeq = 0;
  let cmdkNote = '';

  function openCmdkModal(prefill) {
    const modal = document.getElementById('cmdk-modal');
    const input = document.getElementById('cmdk-input');
    if (!modal || !input) return;
    if (!state.cmdkOpen) {
      state.cmdkOpen = true;
      cmdkPrevFocus = document.activeElement;
      modal.hidden = false;
      pushLayer(cmdkLayer);
    }
    if (typeof prefill === 'string') input.value = prefill;
    input.focus();
    if (typeof prefill === 'string') input.setSelectionRange(input.value.length, input.value.length);
    else input.select();
    runCmdkSearch(input.value);
  }

  function closeCmdkModal() {
    if (!state.cmdkOpen) return;
    state.cmdkOpen = false;
    cmdkSeq++;
    clearTimeout(cmdkTimer);
    removeLayer(cmdkLayer);
    const modal = document.getElementById('cmdk-modal');
    if (modal.contains(document.activeElement)) document.activeElement.blur();
    modal.hidden = true;
    const prev = cmdkPrevFocus;
    cmdkPrevFocus = null;
    if (prev && prev !== document.body && document.contains(prev) && prev.focus) prev.focus({ preventScroll: true });
  }

  /** Views and commands that match locally; no request needed. */
  function localPaletteItems(query, commandsOnly) {
    const needle = query.toLowerCase();
    const score = (title, haystack) => {
      if (!needle) return 1;
      const t = title.toLowerCase();
      if (t.startsWith(needle)) return 3;
      if (t.includes(needle)) return 2;
      return haystack.includes(needle) ? 1 : 0;
    };
    const views = [];
    if (!commandsOnly) {
      state.treeGroups.forEach((group) => {
        group.nodes.forEach((node) => {
          const s = score(str(node.label), `${str(node.subtitle)} ${group.id}`.toLowerCase());
          if (s > 0) views.push({ kind: 'view', score: s, title: str(node.label), subtitle: `${group.id} view`, node_id: node.id });
        });
      });
    }
    const cmds = [];
    commands.forEach((cmd) => {
      if (!commandEnabled(cmd)) return;
      const s = score(cmd.title, cmd.haystack);
      if (s > 0) cmds.push({ kind: 'command', score: s, title: cmd.title, subtitle: cmd.hint, cmd, shortcut: cmd.shortcutLabel });
    });
    const byScore = (a, b) => b.score - a.score;
    views.sort(byScore);
    cmds.sort(byScore);
    return { views, cmds };
  }

  /**
   * One /api/search row as a palette item. The row is server data: it is copied field by field from
   * a whitelist with checked types, and `kind` is always 'result', so a row can only ever move the
   * cursor or open a tree node, never pick another code path (a command, a view action).
   */
  function searchHit(r) {
    if (!r || typeof r !== 'object') return null;
    const text = (v, max) => (typeof v === 'string' ? v.slice(0, max) : typeof v === 'number' && Number.isFinite(v) ? String(v) : '');
    const offset = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : null);
    const title = text(r.title, 400);
    if (!title) return null;
    return {
      kind: 'result',
      title,
      subtitle: text(r.subtitle, 400),
      category: text(r.category, 40),
      node_id: typeof r.node_id === 'string' && r.node_id.length <= 300 ? r.node_id : null,
      abs_offset: offset(r.abs_offset),
      size: offset(r.size),
      vmaddr: typeof r.vmaddr === 'string' && /^(0x)?[0-9a-f]{1,16}$/i.test(r.vmaddr) ? r.vmaddr : null,
    };
  }

  function runCmdkSearch(rawQuery) {
    clearTimeout(cmdkTimer);
    const seq = ++cmdkSeq;
    const rawText = str(rawQuery).trim();
    const commandsOnly = rawText.startsWith('>') || state.cmdkScope === 'commands';
    const q = rawText.replace(/^>\s*/, '');
    const scoped = state.cmdkScope !== 'all' && state.cmdkScope !== 'commands';
    const local = scoped && !commandsOnly ? { views: [], cmds: [] } : localPaletteItems(q, commandsOnly);
    cmdkNote = '';

    const publish = (hits) => {
      const views = q && !commandsOnly ? local.views.slice(0, 5) : local.views.slice(0, commandsOnly ? 0 : 8);
      const cmds = q && !commandsOnly ? local.cmds.slice(0, 5) : local.cmds;
      state.cmdkResults = [...views, ...cmds, ...hits];
      state.cmdkActiveIdx = 0;
      renderCmdkResults();
    };

    if (commandsOnly || !q || !state.doc) {
      if (q && !commandsOnly && !state.doc) cmdkNote = 'Open a binary to search its symbols, strings and bytes.';
      publish([]);
      return;
    }

    publish([]);
    cmdkTimer = setTimeout(async () => {
      try {
        const data = await api.get('/api/search', { q, scope: state.cmdkScope });
        if (seq !== cmdkSeq) return;
        const hits = (Array.isArray(data?.results) ? data.results.slice(0, 200) : []).map(searchHit).filter(Boolean);
        publish(hits);
      } catch (err) {
        if (seq !== cmdkSeq) return;
        cmdkNote = `Search failed. ${describeError(err).what}`;
        publish([]);
      }
    }, 70);
  }

  function renderCmdkResults() {
    const container = document.getElementById('cmdk-results');
    const input = document.getElementById('cmdk-input');
    if (!container) return;
    if (!state.cmdkResults.length) {
      container.innerHTML = html`<div class="cmdk-empty">${cmdkNote || 'No matches.'}</div>`;
      input?.removeAttribute('aria-activedescendant');
      return;
    }

    const tag = (item) => {
      if (item.kind === 'command') return 'cmd';
      if (item.kind === 'view') return 'view';
      const c = str(item.category).toLowerCase();
      if (c.includes('sym')) return 'sym';
      if (c.includes('str')) return 'str';
      if (c.includes('hex')) return 'hex';
      if (c.includes('addr')) return 'addr';
      return 'struct';
    };
    const right = (item) => {
      if (item.kind === 'command') return item.shortcut ? html`<kbd>${item.shortcut}</kbd>` : '';
      if (item.kind === 'view') return '';
      return item.vmaddr ? str(item.vmaddr) : hex(item.abs_offset, 6);
    };

    container.innerHTML = html`${state.cmdkResults.map((item, idx) => html`
      <div class="cmdk-item ${idx === state.cmdkActiveIdx ? 'active' : ''}" id="cmdk-item-${idx}" role="option" aria-selected="${idx === state.cmdkActiveIdx ? 'true' : 'false'}" data-cmdk-idx="${idx}">
        <div class="cmdk-item-left">
          <span class="cmdk-tag">${tag(item)}</span>
          <div class="cmdk-item-text">
            <div class="cmdk-item-title">${truncate(item.title, 200)}</div>
            ${item.subtitle ? html`<div class="cmdk-item-sub">${truncate(item.subtitle, 200)}</div>` : ''}
          </div>
        </div>
        <div class="cmdk-item-right">${right(item)}</div>
      </div>
    `)}${cmdkNote ? html`<div class="cmdk-empty">${cmdkNote}</div>` : ''}`;
    input?.setAttribute('aria-activedescendant', `cmdk-item-${state.cmdkActiveIdx}`);
  }

  function moveCmdkActive(delta) {
    const n = state.cmdkResults.length;
    if (!n) return;
    state.cmdkActiveIdx = Math.max(0, Math.min(n - 1, state.cmdkActiveIdx + delta));
    renderCmdkResults();
    document.getElementById(`cmdk-item-${state.cmdkActiveIdx}`)?.scrollIntoView({ block: 'nearest' });
  }

  function executeCmdkSelection(idx) {
    const item = state.cmdkResults[idx];
    if (!item) return;
    closeCmdkModal();

    if (item.kind === 'command') {
      runCommand(item.cmd);
      return;
    }
    if (item.kind === 'view') {
      selectTreeNode(item.node_id, { scrollHex: true });
      return;
    }
    const known = Boolean(item.node_id) && hasNode(item.node_id);
    if (typeof item.abs_offset === 'number') {
      if (known) selectTreeNode(item.node_id, { scrollHex: false, recordHistory: false });
      setCursorAndHighlight(
        item.abs_offset,
        { abs_offset: item.abs_offset, size: num(item.size, 8) || 8, label: str(item.title) },
        { scrollHex: true, recordHistory: true }
      );
    } else if (known) {
      selectTreeNode(item.node_id, { scrollHex: true });
    }
  }

  // =========================================================================
  // Back / Forward History, URL Hash (deep links), Session Resume
  // =========================================================================
  // Every in-app history entry is also a browser history entry, so the browser's back/forward
  // buttons and the in-app ones walk the same list. The hash holds: doc (presets, and paths in
  // local mode — never an upload id), slice, view, p.<key> view params, off (cursor).
  const SESSION_ID = Math.random().toString(36).slice(2) + Date.now().toString(36);

  function currentEntry() {
    return {
      docKey: state.docKey,
      ref: recordRef(docCache.get(state.docKey)),
      sliceIndex: state.activeSliceIndex,
      nodeId: state.selectedNodeId,
      params: Object.assign({}, state.viewParams),
      cursorOffset: state.cursorOffset,
    };
  }

  function sameEntry(a, b) {
    return a.docKey === b.docKey && a.sliceIndex === b.sliceIndex && a.nodeId === b.nodeId && a.cursorOffset === b.cursorOffset && JSON.stringify(a.params) === JSON.stringify(b.params);
  }

  function entryHash(entry) {
    const parts = [];
    const enc = (v) => encodeURIComponent(v).replace(/%3A/gi, ':').replace(/%2F/gi, '/');
    const view = extViews.get(entry.nodeId);
    const docless = view && !view.requiresDoc;
    if (entry.docKey && entry.ref) {
      parts.push(`doc=${enc(entry.ref)}`);
      const record = docCache.get(entry.docKey);
      if (!record || record.doc.slices.length > 1) parts.push(`slice=${entry.sliceIndex}`);
      if (entry.nodeId && entry.nodeId !== 'overview') parts.push(`view=${enc(entry.nodeId)}`);
    } else if (docless) {
      parts.push(`view=${enc(entry.nodeId)}`);
    }
    if (parts.length && (view || entry.ref)) {
      Object.entries(entry.params || {}).forEach(([k, v]) => parts.push(`p.${k}=${enc(v)}`));
    }
    if (entry.docKey && entry.ref && entry.cursorOffset > 0) parts.push(`off=${hex(entry.cursorOffset)}`);
    return parts.length ? `#${parts.join('&')}` : '';
  }

  function writeLocation(entry, how) {
    const url = window.location.pathname + window.location.search + entryHash(entry);
    const st = { bs: SESSION_ID, idx: state.historyIndex };
    try {
      if (how === 'push') window.history.pushState(st, '', url);
      else window.history.replaceState(st, '', url);
    } catch {
      /* history API unavailable (e.g. sandboxed frame): in-app history still works */
    }
  }

  function saveSession(entry) {
    // The session names a preset, or (local mode) a path the user opened deliberately; never an
    // upload. `confirmed` lets a later visit resume that path without asking again.
    if (entry.docKey && entry.ref) storage.set('session', { doc: entry.ref, slice: entry.sliceIndex, view: entry.nodeId, off: entry.cursorOffset, confirmed: entry.ref.startsWith('path:') ? confirmedPathRefs.has(entry.ref) : undefined });
    else if (!entry.docKey || !entry.ref) storage.remove('session');
  }

  function pushHistory(entry) {
    const top = state.history[state.historyIndex];
    if (top && sameEntry(top, entry)) return;
    const first = state.historyIndex < 0;
    state.history = state.history.slice(0, state.historyIndex + 1);
    state.history.push(entry);
    state.historyIndex = state.history.length - 1;
    writeLocation(entry, first ? 'replace' : 'push');
    saveSession(entry);
    updateHistoryButtons();
  }

  /** Fold the current cursor / view into the current history entry and the URL (no new entry). */
  const syncLocationSoon = debounce(() => {
    if (state.historyIndex < 0 || state.suppressHistory) return;
    const entry = state.history[state.historyIndex];
    if (!entry) return;
    Object.assign(entry, currentEntry());
    writeLocation(entry, 'replace');
    saveSession(entry);
  }, 250);

  /** Restart the in-app history at whatever is on screen now. */
  function anchorHistory() {
    state.history = [currentEntry()];
    state.historyIndex = 0;
    writeLocation(state.history[0], 'replace');
    saveSession(state.history[0]);
    updateHistoryButtons();
  }

  function openRef(ref, restore) {
    if (typeof ref !== 'string') return Promise.resolve(null);
    if (ref.startsWith('preset:')) return openPresetById(ref.slice(7), restore);
    if (ref.startsWith('path:') && config.features.path_load) {
      if (confirmedPathRefs.has(ref)) return openPath(ref.slice(5), restore);
      askToOpenPath(ref.slice(5), restore);
    }
    return Promise.resolve(null);
  }

  async function applyEntry(entry) {
    const restore = { slice: entry.sliceIndex, view: entry.nodeId, params: entry.params, off: entry.cursorOffset, noHistory: true };
    if (entry.docKey && entry.docKey !== state.docKey) {
      const record = docCache.get(entry.docKey) || (entry.ref ? findRecordByRef(entry.ref) : null);
      if (record) {
        activateRecord(record, restore, false);
        entry.docKey = record.key;
      } else if (entry.ref) {
        await openRef(entry.ref, restore);
        if (state.docKey) entry.docKey = state.docKey;
      } else {
        toast('That file is no longer loaded. Open it again to return to it.', 'warn');
      }
      updateHistoryButtons();
      return;
    }
    state.suppressHistory = true;
    try {
      if (!entry.docKey) {
        if (state.doc) closeDocument(false);
        else showStartView(false);
        if (entry.nodeId && entry.nodeId !== 'start') selectTreeNode(entry.nodeId, { scrollHex: false, recordHistory: false, params: entry.params });
      } else if (entry.sliceIndex !== state.activeSliceIndex) {
        activateSlice(entry.sliceIndex, { view: entry.nodeId, params: entry.params, off: entry.cursorOffset, recordHistory: false });
      } else {
        selectTreeNode(entry.nodeId, { scrollHex: false, recordHistory: false, params: entry.params });
        setCursorAndHighlight(entry.cursorOffset, null, { scrollHex: true });
      }
    } finally {
      state.suppressHistory = false;
      updateHistoryButtons();
    }
  }

  function navigateHistory(delta) {
    const targetIdx = state.historyIndex + delta;
    if (targetIdx < 0 || targetIdx >= state.history.length) return;
    const st = window.history.state;
    if (st && st.bs === SESSION_ID && st.idx === state.historyIndex) {
      window.history.go(delta); // popstate applies the entry
      return;
    }
    state.historyIndex = targetIdx;
    applyEntry(state.history[targetIdx]);
  }

  function updateHistoryButtons() {
    const back = document.getElementById('btn-nav-back');
    const fwd = document.getElementById('btn-nav-fwd');
    if (back) back.disabled = state.historyIndex <= 0;
    if (fwd) fwd.disabled = state.historyIndex >= state.history.length - 1;
  }

  function parseLocationHash() {
    const out = { ref: null, slice: null, view: null, off: null, params: Object.create(null) };
    const h = window.location.hash.replace(/^#/, '');
    if (!h) return out;
    h.split('&').forEach((pair) => {
      const i = pair.indexOf('=');
      if (i < 0) return;
      const k = pair.slice(0, i);
      let v;
      try {
        v = decodeURIComponent(pair.slice(i + 1));
      } catch {
        return;
      }
      if (k === 'doc') out.ref = v;
      else if (k === 'slice') {
        if (/^\d{1,4}$/.test(v)) out.slice = parseInt(v, 10);
      } else if (k === 'view') out.view = v;
      else if (k === 'off') out.off = parseOffsetInput(v);
      else if (k.startsWith('p.')) out.params[k.slice(2)] = v;
    });
    out.params = flattenParams(out.params);
    return out;
  }

  /** A doc reference from a URL is honoured only for presets and (local mode) paths. */
  function refAllowed(ref) {
    if (typeof ref !== 'string') return false;
    if (/^preset:[A-Za-z0-9_.-]{1,80}$/.test(ref)) return true;
    return ref.startsWith('path:') && ref.length > 5 && config.mode === 'local' && config.features.path_load;
  }

  /** Bring the app to the state described by the URL hash (page load, hand-edited hash, foreign history entry). */
  async function restoreFromLocation() {
    const t = parseLocationHash();
    const restore = { slice: t.slice, view: t.view, params: t.params, off: t.off === null ? undefined : t.off, noHistory: true };
    if (refAllowed(t.ref)) {
      const current = docCache.get(state.docKey);
      if (current && recordRef(current) === t.ref) {
        state.suppressHistory = true;
        try {
          const slice = Number.isInteger(t.slice) && t.slice < state.doc.slices.length ? t.slice : state.activeSliceIndex;
          if (slice !== state.activeSliceIndex) activateSlice(slice, { view: t.view, params: t.params, off: restore.off, recordHistory: false });
          else {
            selectTreeNode(t.view && hasNode(t.view) ? t.view : 'overview', { scrollHex: restore.off === undefined, recordHistory: false, params: t.params });
            if (restore.off !== undefined) setCursorAndHighlight(restore.off, null, { scrollHex: true });
          }
        } finally {
          state.suppressHistory = false;
        }
      } else {
        const cached = findRecordByRef(t.ref);
        if (cached) activateRecord(cached, restore, false);
        else await openRef(t.ref, restore);
      }
    } else if (state.doc && t.view && hasNode(t.view)) {
      selectTreeNode(t.view, { scrollHex: true, recordHistory: false, params: t.params });
    } else {
      if (state.doc) closeDocument(false);
      else showStartView(false);
      const view = t.view ? extViews.get(t.view) : null;
      if (view && !view.requiresDoc) selectTreeNode(t.view, { scrollHex: false, recordHistory: false, params: t.params });
    }
    anchorHistory();
  }

  function permalink() {
    return window.location.origin + window.location.pathname + window.location.search + entryHash(currentEntry());
  }

  // =========================================================================
  // Layout: dock side, pane sizes, Learn mode
  // =========================================================================
  const layout = {
    sidebar: numIn(storage.get('layout.sidebarWidth'), 180, 600, 280),
    hexWidth: numIn(storage.get('layout.hexWidth'), 360, 1400, 520),
    hexHeight: numIn(storage.get('layout.hexHeight'), 140, 1000, 300),
  };

  function effectiveDock() {
    return window.innerWidth < NARROW_DOCK_PX ? 'bottom' : state.hexDock;
  }

  function applyLayout() {
    const root = document.documentElement;
    root.style.setProperty('--sidebar-width', `${layout.sidebar}px`);
    root.style.setProperty('--hex-pane-width', `${layout.hexWidth}px`);
    root.style.setProperty('--hex-pane-height', `${layout.hexHeight}px`);
    const main = document.getElementById('workspace-main');
    const dock = effectiveDock();
    if (main) {
      main.classList.toggle('dock-right', dock === 'right');
      main.classList.toggle('dock-bottom', dock === 'bottom');
    }
    document.getElementById('resizer-hex')?.setAttribute('aria-orientation', dock === 'right' ? 'vertical' : 'horizontal');
    const btn = document.getElementById('btn-toggle-dock');
    if (btn) {
      const next = dock === 'right' ? 'bottom' : 'right';
      btn.title = `Dock the hex pane at the ${next} (D)`;
      btn.setAttribute('aria-label', `Dock the hex pane at the ${next}`);
      btn.dataset.dock = dock;
    }
  }

  let layoutRefreshQueued = false;
  function scheduleLayoutRefresh() {
    if (layoutRefreshQueued) return;
    layoutRefreshQueued = true;
    requestAnimationFrame(() => {
      layoutRefreshQueued = false;
      applyLayout();
      const viewport = document.getElementById('hex-viewport');
      if (viewport && state.doc) hexView.topRow = Math.min(hexView.topRow, hexMaxTopRow(viewport));
      renderHexViewport();
      updateMemoryMapPlayhead();
    });
  }

  function toggleHexDock() {
    if (window.innerWidth < NARROW_DOCK_PX) {
      toast('In a window this narrow the hex pane stays at the bottom.', 'info');
      return;
    }
    state.hexDock = state.hexDock === 'right' ? 'bottom' : 'right';
    storage.set('layout.dock', state.hexDock);
    scheduleLayoutRefresh();
  }

  function setLearnMode(on) {
    const next = Boolean(on);
    if (next === state.learnMode) return;
    state.learnMode = next;
    document.documentElement.classList.toggle('learn-on', next);
    storage.set('learn.on', next);
    bus.emit('learnmode:changed', { on: next });
  }

  function initPaneResizers() {
    const main = document.getElementById('workspace-main');
    const resLeft = document.getElementById('resizer-left');
    const resHex = document.getElementById('resizer-hex');
    if (!main || !resLeft || !resHex) return;

    const setSidebar = (px) => {
      layout.sidebar = Math.round(Math.max(180, Math.min(480, window.innerWidth * 0.45, px)));
    };
    const setHexWidth = (px) => {
      layout.hexWidth = Math.round(Math.max(360, Math.min(window.innerWidth - layout.sidebar - 320, px)));
    };
    const setHexHeight = (px) => {
      layout.hexHeight = Math.round(Math.max(140, Math.min(main.clientHeight - 160, px)));
    };
    const persist = () => {
      storage.set('layout.sidebarWidth', layout.sidebar);
      storage.set('layout.hexWidth', layout.hexWidth);
      storage.set('layout.hexHeight', layout.hexHeight);
    };

    const drag = (handle, onMove) => {
      handle.addEventListener('pointerdown', (e) => {
        if (e.button !== undefined && e.button !== 0) return;
        e.preventDefault();
        handle.setPointerCapture(e.pointerId);
        handle.classList.add('dragging');
        const move = (ev) => {
          onMove(ev, main.getBoundingClientRect());
          applyLayout();
          renderHexViewport();
          updateMemoryMapPlayhead();
        };
        const end = () => {
          handle.classList.remove('dragging');
          handle.removeEventListener('pointermove', move);
          handle.removeEventListener('pointerup', end);
          handle.removeEventListener('pointercancel', end);
          persist();
          scheduleLayoutRefresh();
        };
        handle.addEventListener('pointermove', move);
        handle.addEventListener('pointerup', end);
        handle.addEventListener('pointercancel', end);
      });
    };

    drag(resLeft, (e, rect) => setSidebar(e.clientX - rect.left));
    drag(resHex, (e, rect) => {
      if (effectiveDock() === 'right') setHexWidth(rect.right - e.clientX);
      else setHexHeight(rect.bottom - e.clientY);
    });

    // Keyboard resizing: arrow keys on a focused separator.
    const keyResize = (handle, onStep) => {
      handle.addEventListener('keydown', (e) => {
        const step = e.shiftKey ? 64 : 16;
        let delta = 0;
        if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') delta = -step;
        else if (e.key === 'ArrowRight' || e.key === 'ArrowDown') delta = step;
        else return;
        e.preventDefault();
        onStep(delta);
        persist();
        scheduleLayoutRefresh();
      });
    };
    keyResize(resLeft, (d) => setSidebar(layout.sidebar + d));
    keyResize(resHex, (d) => {
      if (effectiveDock() === 'right') setHexWidth(layout.hexWidth - d);
      else setHexHeight(layout.hexHeight - d);
    });

    resLeft.addEventListener('dblclick', () => {
      setSidebar(280);
      persist();
      scheduleLayoutRefresh();
    });
    resHex.addEventListener('dblclick', () => {
      setHexWidth(520);
      setHexHeight(300);
      persist();
      scheduleLayoutRefresh();
    });
  }

  // =========================================================================
  // Event Listeners & Delegation Setup
  // =========================================================================
  function isTypingTarget(node) {
    if (!node || node.nodeType !== 1) return false;
    if (node.isContentEditable) return true;
    const tag = node.tagName;
    if (tag === 'TEXTAREA' || tag === 'SELECT') return true;
    if (tag === 'INPUT') return !['checkbox', 'radio', 'button', 'submit', 'range', 'file'].includes(node.type);
    return false;
  }

  function jumpFromDataset(node, recordHistory) {
    const off = num(node.dataset.jumpOffset, NaN);
    if (!Number.isFinite(off)) return;
    const size = num(node.dataset.jumpSize, 16) || 16;
    setCursorAndHighlight(off, { abs_offset: off, size, label: str(node.dataset.jumpLabel, 'range') }, { scrollHex: true, recordHistory });
  }

  function openDisassemblyAt(vmaddr, section) {
    state.activeDisasmSection = str(section);
    state.activeDisasmVmaddr = str(vmaddr);
    selectTreeNode('disassembly', { scrollHex: false });
  }

  function initEventListeners() {
    const on = (id, type, fn, opts) => document.getElementById(id)?.addEventListener(type, fn, opts);

    // 1. Open (dialog), drag-and-drop
    on('btn-open', 'click', showOpenDialog);

    const dropOverlay = document.getElementById('dropzone-overlay');
    const hasFiles = (e) => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
    const canUpload = () => Boolean(config && config.features.upload);
    let dragDepth = 0;
    window.addEventListener('dragenter', (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      if (!canUpload()) return;
      dragDepth++;
      dropOverlay.hidden = false;
    });
    window.addEventListener('dragover', (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault(); // without this the browser would navigate to the dropped file
      e.dataTransfer.dropEffect = canUpload() ? 'copy' : 'none';
    });
    window.addEventListener('dragleave', (e) => {
      if (!hasFiles(e)) return;
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) dropOverlay.hidden = true;
    });
    window.addEventListener('drop', (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      dragDepth = 0;
      dropOverlay.hidden = true;
      if (!canUpload()) return;
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) {
        if (openDialog) openDialog.close();
        openFile(file);
      }
    });

    // 2. Slice selector, history, toolbar buttons
    on('slice-select', 'change', (e) => activateSlice(Number(e.target.value), { keepView: true }));
    on('btn-nav-back', 'click', () => navigateHistory(-1));
    on('btn-nav-fwd', 'click', () => navigateHistory(1));
    on('btn-open-cmdk', 'click', () => openCmdkModal());
    on('btn-theme', 'click', () => runCommand('core.theme'));
    on('btn-toggle-dock', 'click', toggleHexDock);
    on('btn-help', 'click', () => runCommand('core.shortcuts'));
    on('btn-toggle-sidebar', 'click', () => {
      const main = document.getElementById('workspace-main');
      const open = main.classList.toggle('sidebar-open');
      if (open) document.getElementById('structure-tree')?.focus();
    });
    on('status-mode', 'click', () => toast(privacyLine(), 'info'));

    // 3. Memory map: scale toggle, hover tooltip, click-to-select
    on('btn-memmap-scale', 'click', toggleMemmapScale);
    const tracksContainer = document.getElementById('memmap-tracks-container');
    const tooltip = document.getElementById('global-tooltip');
    tracksContainer.addEventListener('mousemove', (e) => {
      const block = e.target.closest('.memmap-block');
      if (!block) {
        tooltip.hidden = true;
        return;
      }
      tooltip.innerHTML = html`
        <div class="tt-title">${block.dataset.ttTitle}</div>
        <div class="tt-row"><span>File</span><strong>${block.dataset.ttFile}</strong></div>
        <div class="tt-row"><span>VM</span><strong>${block.dataset.ttVm}</strong></div>
        <div class="tt-row"><span>Protection</span><strong>${block.dataset.ttProt}</strong></div>
      `;
      tooltip.hidden = false;
      const w = tooltip.offsetWidth || 300;
      tooltip.style.left = `${Math.max(4, Math.min(window.innerWidth - w - 8, e.clientX + 12))}px`;
      tooltip.style.top = `${e.clientY + 16}px`;
    });
    tracksContainer.addEventListener('mouseleave', () => {
      tooltip.hidden = true;
    });
    tracksContainer.addEventListener('click', (e) => {
      const block = e.target.closest('.memmap-block');
      if (!block) return;
      const nodeId = block.dataset.nodeId;
      if (nodeId && hasNode(nodeId)) selectTreeNode(nodeId, { scrollHex: true });
    });

    // 4. Address / offset converter
    const liveTranslate = debounce((value, mode) => runTranslateQuery(value, mode), 120);
    const convJump = () => {
      const off = parseOffsetInput(document.getElementById('conv-abs-input').value);
      if (off === null) {
        toast('That address has no bytes in the file, so there is nothing to show in hex.', 'info');
        return;
      }
      setCursorAndHighlight(off, { abs_offset: off, size: 8, label: 'translated' }, { scrollHex: true, recordHistory: true });
      document.getElementById('hex-viewport')?.focus({ preventScroll: true });
    };
    [['conv-abs-input', 'abs_offset'], ['conv-slice-input', 'slice_offset'], ['conv-vm-input', 'vmaddr']].forEach(([id, mode]) => {
      on(id, 'input', (e) => liveTranslate(e.target.value.trim(), mode));
      on(id, 'keydown', async (e) => {
        if (e.key !== 'Enter') return;
        e.preventDefault();
        liveTranslate.cancel();
        await runTranslateQuery(e.target.value.trim(), mode);
        convJump();
      });
    });
    on('btn-conv-jump-hex', 'click', convJump);
    on('btn-conv-disasm', 'click', () => {
      const vm = document.getElementById('conv-vm-input').value.trim();
      if (/^0x[0-9a-f]+$/i.test(vm)) openDisassemblyAt(vm, '');
      else toast('Enter a VM address first, for example 0x100003f60.', 'info');
    });

    // 5. Tree: filter, mouse, keyboard
    const treeFilterIn = document.getElementById('tree-filter-input');
    const treeClearBtn = document.getElementById('btn-tree-clear');
    treeFilterIn.addEventListener('input', (e) => {
      state.treeFilter = e.target.value;
      treeClearBtn.hidden = !state.treeFilter;
      renderStructureTree();
    });
    treeFilterIn.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown' || e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('structure-tree').focus();
      }
    });
    treeClearBtn.addEventListener('click', () => {
      state.treeFilter = '';
      treeFilterIn.value = '';
      treeClearBtn.hidden = true;
      renderStructureTree();
      treeFilterIn.focus();
    });

    const tree = document.getElementById('structure-tree');
    const toggleNode = (id) => {
      if (state.expandedNodeIds.has(id)) state.expandedNodeIds.delete(id);
      else state.expandedNodeIds.add(id);
      renderStructureTree();
    };
    tree.addEventListener('click', (e) => {
      const groupRow = e.target.closest('[data-group-id]');
      if (groupRow) {
        state.treeFocusIndex = num(groupRow.dataset.row, -1);
        toggleTreeGroup(groupRow.dataset.groupId);
        return;
      }
      const row = e.target.closest('[data-node-id]');
      if (!row) return;
      state.treeFocusIndex = num(row.dataset.row, -1);
      const twisty = e.target.closest('[data-twisty-id]');
      if (twisty && !twisty.classList.contains('leaf')) {
        toggleNode(twisty.dataset.twistyId);
        return;
      }
      const id = row.dataset.nodeId;
      const node = state.treeNodesMap.get(id);
      if (node && Array.isArray(node.children) && node.children.length > 0) state.expandedNodeIds.add(id);
      selectTreeNode(id, { scrollHex: true });
    });
    tree.addEventListener('focus', () => {
      if (state.treeFocusIndex < 0) {
        const sel = state.treeVisible.findIndex((r) => r.kind === 'node' && r.id === state.selectedNodeId);
        state.treeFocusIndex = sel >= 0 ? sel : state.treeVisible.length ? 0 : -1;
      }
      paintTreeFocus(true);
    });
    tree.addEventListener('blur', () => paintTreeFocus(false));
    tree.addEventListener('keydown', (e) => {
      const rows = state.treeVisible;
      if (!rows.length || e.metaKey || e.ctrlKey || e.altKey) return;
      const idx = Math.max(0, state.treeFocusIndex);
      const row = rows[idx];
      const move = (to) => {
        state.treeFocusIndex = Math.max(0, Math.min(rows.length - 1, to));
        paintTreeFocus(true);
      };
      const setExpanded = (want) => {
        if (row.kind === 'group') {
          if (row.expanded !== want) toggleTreeGroup(row.id);
        } else if (row.hasChildren && row.expanded !== want) {
          toggleNode(row.id);
        }
        paintTreeFocus(true);
      };
      switch (e.key) {
        case 'ArrowDown': move(idx + 1); break;
        case 'ArrowUp': move(idx - 1); break;
        case 'Home': move(0); break;
        case 'End': move(rows.length - 1); break;
        case 'ArrowRight':
          if (row.hasChildren && !row.expanded) setExpanded(true);
          else if (row.hasChildren) move(idx + 1);
          break;
        case 'ArrowLeft':
          if (row.hasChildren && row.expanded) setExpanded(false);
          else if (row.parentRow >= 0) move(row.parentRow);
          break;
        case 'Enter':
        case ' ':
          if (row.kind === 'group') toggleTreeGroup(row.id);
          else {
            if (row.hasChildren) state.expandedNodeIds.add(row.id);
            selectTreeNode(row.id, { scrollHex: true });
          }
          paintTreeFocus(true);
          break;
        default:
          return;
      }
      e.preventDefault();
    });

    // 6. Copy affordances. Alt/Option-click copies any value that carries data-copy; a few
    //    non-navigating controls (pills, decoder values, hash) copy on a plain click.
    document.addEventListener('click', (e) => {
      const target = e.target.nodeType === 1 ? e.target : e.target.parentElement;
      if (!target) return;
      const plain = target.closest('.meta-pill[data-copy], .copy-click[data-copy]');
      const any = e.altKey ? target.closest('[data-copy]') : null;
      const node = any || plain;
      if (!node || !node.dataset.copy) return;
      e.preventDefault();
      e.stopPropagation();
      copyText(node.dataset.copy);
    }, true);

    // 7. Inspector: delegated clicks (fields, chips, slice switches, disassembly links, quiz)
    const inspector = document.getElementById('center-inspector');
    inspector.addEventListener('click', (e) => {
      const quizBtn = e.target.closest('.quiz-option-btn');
      if (quizBtn) {
        const isCorrect = quizBtn.dataset.quizCorrect === '1';
        const parent = quizBtn.parentElement;
        parent.querySelectorAll('.quiz-option-btn').forEach((b) => b.classList.remove('correct', 'wrong'));
        quizBtn.classList.add(isCorrect ? 'correct' : 'wrong');
        const fb = parent.querySelector('.quiz-feedback');
        if (fb) {
          fb.hidden = false;
          fb.classList.toggle('ok', isCorrect);
          fb.classList.toggle('bad', !isCorrect);
          fb.textContent = isCorrect ? str(quizBtn.dataset.quizExp).replace(/^Correct!\s*/i, 'Correct. ') : 'Not that one. Try another.';
        }
        return;
      }

      const sliceBtn = e.target.closest('[data-switch-slice]');
      if (sliceBtn) {
        activateSlice(num(sliceBtn.dataset.switchSlice), { keepView: true });
        return;
      }

      const selNodeBtn = e.target.closest('[data-select-node]');
      if (selNodeBtn) {
        const hasJump = selNodeBtn.dataset.jumpOffset !== undefined;
        if (selectTreeNode(selNodeBtn.dataset.selectNode, { scrollHex: !hasJump }) && hasJump) jumpFromDataset(selNodeBtn, false);
        return;
      }

      const disasmBtn = e.target.closest('[data-disasm-vm], [data-disasm-section]');
      if (disasmBtn) {
        if (disasmBtn.dataset.disasmVm || disasmBtn.dataset.disasmSection) openDisassemblyAt(disasmBtn.dataset.disasmVm, disasmBtn.dataset.disasmSection);
        return;
      }

      const jumpChipEl = e.target.closest('[data-jump-offset]');
      if (jumpChipEl) {
        jumpFromDataset(jumpChipEl, true);
        return;
      }

      // Field / instruction / symbol / string row: highlight its bytes.
      const fieldRow = e.target.closest('[data-abs-offset]');
      if (fieldRow && inspector.contains(fieldRow)) {
        inspector.querySelectorAll('.active-field-row, .disasm-row.selected').forEach((n) => n.classList.remove('active-field-row', 'selected'));
        if (!fieldRow.classList.contains('virt-row')) fieldRow.classList.add(fieldRow.classList.contains('disasm-row') ? 'selected' : 'active-field-row');
        const off = num(fieldRow.dataset.absOffset);
        const size = num(fieldRow.dataset.fieldSize, 4) || 4;
        setCursorAndHighlight(off, { abs_offset: off, size, label: str(fieldRow.dataset.fieldName, 'field') }, { scrollHex: true });
      }
    });

    // Rows are focusable: arrows move between rows of a table, Enter / Space activates.
    inspector.addEventListener('keydown', (e) => {
      const target = e.target;
      if (!target || !target.matches) return;
      if (target.matches('tr.struct-row, tr.disasm-row')) {
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          let next = target;
          do {
            next = e.key === 'ArrowDown' ? next.nextElementSibling : next.previousElementSibling;
          } while (next && !next.matches('tr.struct-row, tr.disasm-row'));
          if (next) {
            e.preventDefault();
            target.tabIndex = -1;
            next.tabIndex = 0;
            next.focus();
          }
        } else if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          target.click();
        }
      } else if (target.matches('.kv-row[role="button"]') && (e.key === 'Enter' || e.key === ' ')) {
        e.preventDefault();
        target.click();
      }
    });

    // 8. Hex viewport: scroll, wheel, mouse, keyboard
    const hexViewport = document.getElementById('hex-viewport');
    hexViewport.addEventListener('scroll', onHexScroll, { passive: true });
    hexViewport.addEventListener('wheel', (e) => {
      if (!hexView.scaled || e.ctrlKey) return;
      e.preventDefault();
      const dy = e.deltaMode === 1 ? e.deltaY * HEX_ROW_HEIGHT : e.deltaMode === 2 ? e.deltaY * hexViewport.clientHeight : e.deltaY;
      hexSetTopRow(hexView.topRow + dy / HEX_ROW_HEIGHT);
    }, { passive: false });

    const selectTo = (off) => {
      const lo = Math.min(state.selAnchor, off);
      const hi = Math.max(state.selAnchor, off);
      return { abs_offset: lo, size: hi - lo + 1, label: 'selection' };
    };
    hexViewport.addEventListener('click', (e) => {
      const byteEl = e.target.closest('[data-byte-offset]');
      if (!byteEl) return;
      const off = num(byteEl.dataset.byteOffset);
      if (e.shiftKey) setCursorAndHighlight(off, selectTo(off), { scrollHex: false, keepAnchor: true });
      else setCursorAndHighlight(off, null, { scrollHex: false });
      // Double-click: the first click redraws the rows, so the browser never fires `dblclick`
      // (its two clicks hit different nodes). The click count is reliable.
      if (e.detail === 2 && !e.shiftKey) activateByte(off, e);
    });
    hexViewport.addEventListener('keydown', (e) => {
      if (!state.doc || e.altKey) return;
      const cur = state.cursorOffset;
      const last = Math.max(0, fileSize() - 1);
      const page = Math.max(1, hexViewRows(hexViewport) - 1) * HEX_BYTES_PER_ROW;
      const mod = e.metaKey || e.ctrlKey;
      let next = null;
      switch (e.key) {
        case 'ArrowLeft': next = cur - 1; break;
        case 'ArrowRight': next = cur + 1; break;
        case 'ArrowUp': next = cur - HEX_BYTES_PER_ROW; break;
        case 'ArrowDown': next = cur + HEX_BYTES_PER_ROW; break;
        case 'PageUp': next = cur - page; break;
        case 'PageDown': next = cur + page; break;
        case 'Home': next = mod ? 0 : cur - (cur % HEX_BYTES_PER_ROW); break;
        case 'End': next = mod ? last : cur - (cur % HEX_BYTES_PER_ROW) + HEX_BYTES_PER_ROW - 1; break;
        case 'Enter':
          e.preventDefault();
          activateByte(cur, e);
          return;
        default:
          return;
      }
      if (mod && e.key !== 'Home' && e.key !== 'End') return;
      e.preventDefault();
      next = Math.max(0, Math.min(last, next));
      if (e.shiftKey) setCursorAndHighlight(next, selectTo(next), { scrollHex: true, keepAnchor: true });
      else setCursorAndHighlight(next, null, { scrollHex: true });
    });

    on('btn-hex-addr-mode', 'click', toggleHexAddrMode);
    on('hex-goto-form', 'submit', (e) => {
      e.preventDefault();
      const input = document.getElementById('hex-goto-input');
      const val = parseOffsetInput(input.value);
      if (val === null) {
        toast('Enter a file offset such as 0x1f40 or 8000.', 'info');
        return;
      }
      if (val >= fileSize()) {
        toast(`${hex(val)} is past the end of the file (${hex(fileSize())}).`, 'info');
        return;
      }
      setCursorAndHighlight(val, { abs_offset: val, size: 1, label: 'go to' }, { scrollHex: true, recordHistory: true });
      hexViewport.focus({ preventScroll: true });
    });
    on('btn-decoder-endian', 'click', toggleDecoderEndian);
    on('decoder-breadcrumbs', 'click', (e) => {
      const crumb = e.target.closest('[data-crumb-offset]');
      if (!crumb) return;
      const off = num(crumb.dataset.crumbOffset);
      const size = num(crumb.dataset.crumbSize, 16) || 16;
      const id = crumb.dataset.crumbId;
      if (id && hasNode(id)) selectTreeNode(id, { scrollHex: false, recordHistory: false });
      setCursorAndHighlight(off, { abs_offset: off, size, label: crumb.textContent.trim() }, { scrollHex: true, recordHistory: true });
    });

    // 9. Command palette
    const cmdkModal = document.getElementById('cmdk-modal');
    const cmdkInput = document.getElementById('cmdk-input');
    cmdkModal.addEventListener('mousedown', (e) => {
      if (e.target === cmdkModal) closeCmdkModal();
    });
    cmdkModal.addEventListener('keydown', (e) => trapTab(e, cmdkModal));
    cmdkInput.addEventListener('input', (e) => runCmdkSearch(e.target.value));
    cmdkInput.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') moveCmdkActive(1);
      else if (e.key === 'ArrowUp') moveCmdkActive(-1);
      else if (e.key === 'PageDown') moveCmdkActive(8);
      else if (e.key === 'PageUp') moveCmdkActive(-8);
      else if (e.key === 'Enter') executeCmdkSelection(state.cmdkActiveIdx);
      else return;
      e.preventDefault();
    });
    on('cmdk-scopes', 'click', (e) => {
      const btn = e.target.closest('[data-scope]');
      if (!btn) return;
      state.cmdkScope = btn.dataset.scope;
      document.querySelectorAll('.cmdk-scope-btn').forEach((b) => {
        b.classList.toggle('active', b === btn);
        b.setAttribute('aria-pressed', String(b === btn));
      });
      cmdkInput.focus();
      runCmdkSearch(cmdkInput.value);
    });
    on('cmdk-results', 'click', (e) => {
      const item = e.target.closest('[data-cmdk-idx]');
      if (item) executeCmdkSelection(num(item.dataset.cmdkIdx));
    });

    // 10. Global keyboard: Escape closes the topmost layer; command shortcuts.
    window.addEventListener('keydown', (e) => {
      if (e.defaultPrevented || e.isComposing) return;
      if (e.key === 'Escape') {
        if (closeTopLayer()) {
          e.preventDefault();
          return;
        }
        const main = document.getElementById('workspace-main');
        // Whenever Escape did something here it is consumed, so the browser's own Escape
        // behaviour ("stop loading") does not also run.
        if (main.classList.contains('sidebar-open')) {
          e.preventDefault();
          main.classList.remove('sidebar-open');
          return;
        }
        if (isTypingTarget(document.activeElement)) {
          e.preventDefault();
          document.activeElement.blur();
          return;
        }
        if (state.doc && state.fieldSpan) {
          e.preventDefault();
          setFieldSpan(null);
          updateSelectionReadout();
          renderHexViewport();
        }
        return;
      }
      if (e.repeat) return;
      const typing = isTypingTarget(e.target);
      const layered = layers.length > 0;
      for (const cmd of commands.values()) {
        for (const sc of cmd.shortcuts) {
          if (!shortcutMatches(sc, e)) continue;
          if ((typing || layered) && !sc.mod) continue; // bare keys never fire while typing or in a dialog
          if (layered && cmd.id !== 'core.palette') continue;
          if (!commandEnabled(cmd)) continue;
          e.preventDefault();
          runCommand(cmd);
          return;
        }
      }
    });

    // 11. Browser history, window size, system theme
    window.addEventListener('popstate', (e) => {
      if (!booted) return;
      const st = e.state;
      if (st && st.bs === SESSION_ID && state.history[st.idx]) {
        state.historyIndex = st.idx;
        applyEntry(state.history[st.idx]);
      } else {
        restoreFromLocation();
      }
    });
    window.addEventListener('resize', scheduleLayoutRefresh);
    if (schemeQuery) {
      const onScheme = () => {
        if (state.themePref === 'system') applyTheme('system', false);
      };
      if (schemeQuery.addEventListener) schemeQuery.addEventListener('change', onScheme);
      else if (schemeQuery.addListener) schemeQuery.addListener(onScheme);
      // The change event can be missed while the tab is in the background; re-check on return.
      document.addEventListener('visibilitychange', onScheme);
      window.addEventListener('focus', onScheme);
    }
  }

  // =========================================================================
  // Public Extension API (documented at the top of this file)
  // =========================================================================
  const BS = {
    version: VERSION,
    get config() {
      return config;
    },
    state,
    getActiveSlice,
    api: {
      get: (route, params, opts) => api.get(route, params, opts),
      post: (route, body, params, opts) => api.post(route, body, params, opts),
      getBytes: (route, params, opts) => api.getBytes(route, params, opts),
      setTransport: (fn) => api.setTransport(fn),
      get baseUrl() {
        return api.baseUrl || document.baseURI;
      },
      set baseUrl(value) {
        api.baseUrl = value ? String(value) : null;
      },
    },
    ApiError,
    on: bus.on,
    off: bus.off,
    emit: bus.emit,
    registerView,
    registerCommand,
    commands: {
      run: (id) => runCommand(String(id)),
      list: listCommands,
    },
    nav: {
      openView: (id, params) => selectTreeNode(String(id), { scrollHex: false, params }),
      selectNode: (id) => selectTreeNode(String(id), { scrollHex: true }),
      jumpToOffset(absOffset, size, label) {
        if (!state.doc) return;
        const off = Math.trunc(num(absOffset));
        const span = size ? { abs_offset: off, size: Math.max(1, Math.trunc(num(size, 1))), label: str(label, 'range') } : null;
        setCursorAndHighlight(off, span, { scrollHex: true, recordHistory: true });
      },
      async jumpToVmaddr(vmaddr) {
        if (!state.doc) return false;
        const query = typeof vmaddr === 'string' ? vmaddr : hex(vmaddr);
        let data;
        try {
          data = await api.get('/api/translate', { query, mode: 'vmaddr' });
        } catch {
          return false;
        }
        if (!data || typeof data.abs_offset !== 'number') return false;
        renderConverterResult(data);
        setCursorAndHighlight(data.abs_offset, { abs_offset: data.abs_offset, size: 8, label: query }, { scrollHex: true, recordHistory: true });
        return true;
      },
      back: () => navigateHistory(-1),
      forward: () => navigateHistory(1),
      permalink,
    },
    loadDocument,
    loadBytes: (filename, bytes) => openBytes(filename, bytes),
    openPreset: (id) => openPresetById(String(id)),
    closeDocument: () => closeDocument(true),
    hex: {
      getBytes: hexGetBytes,
      setDecorations: setHexDecorations,
      onByteActivate(fn) {
        if (typeof fn !== 'function') return () => {};
        byteActivateListeners.add(fn);
        return () => byteActivateListeners.delete(fn);
      },
      refresh() {
        state.hexChunks.clear();
        state.hexPendingChunks.clear();
        renderHexViewport();
        if (state.doc) fetchLiveByteDecode(state.cursorOffset);
      },
    },
    ui: {
      toast,
      modal: openModal,
      status: setStatus,
      addToolbarButton,
      slot: getSlot,
      copy: copyText,
    },
    learn: {
      isOn: () => state.learnMode,
      set: setLearnMode,
      toggle: () => setLearnMode(!state.learnMode),
    },
    util: { hex, formatBytes, escapeHtml, escapeAttr, html, raw, debounce },
    storage,
  };
  window.BinaryStudio = BS;
  window.BS = BS;

  // =========================================================================
  // Core commands and the keyboard reference view.
  // Deliberately registered through the public API only (BS.*), exactly as a
  // feature file under static/js/ would do it, so the seam is exercised on every load.
  // =========================================================================
  (function registerCoreExtensions() {
    const hasDoc = () => Boolean(BS.state.doc);
    const focusEl = (id, select) => {
      const node = document.getElementById(id);
      if (!node) return;
      node.focus();
      if (select && node.select) node.select();
    };
    const cmd = (section, id, title, shortcut, run, extra) => BS.registerCommand(Object.assign({ id, title, shortcut, section, run }, extra));

    cmd('General', 'core.palette', 'Search and commands', ['Mod+K', '/'], () => (state.cmdkOpen ? closeCmdkModal() : openCmdkModal()), { hint: 'Symbols, strings, structures, bytes, views, commands', keywords: 'find palette omni' });
    cmd('General', 'core.commands', 'Show all commands', 'Mod+Shift+P', () => openCmdkModal('> '), { keywords: 'palette actions' });
    cmd('General', 'core.open', 'Open a binary…', ['O', 'Mod+O'], showOpenDialog, { keywords: 'file upload sample load browse' });
    cmd('General', 'core.close', 'Close the document', null, () => BS.closeDocument(), { when: hasDoc });
    cmd('General', 'core.shortcuts', 'Keyboard shortcuts', '?', () => BS.nav.openView('help.shortcuts'), { keywords: 'help keys reference' });
    cmd('General', 'core.theme', 'Toggle light / dark theme', 'T', () => applyTheme(BS.state.theme === 'dark' ? 'light' : 'dark', true), { keywords: 'appearance colour color' });
    cmd('General', 'core.theme.system', 'Use the system theme', null, () => applyTheme('system', true), { keywords: 'appearance auto' });
    cmd('General', 'core.learn', 'Toggle Learn mode', 'L', () => BS.learn.toggle(), { hint: 'Show or hide inline explanations', keywords: 'explain teach pedagogy' });
    cmd('General', 'core.permalink', 'Copy link to this view', 'P', () => BS.ui.copy(BS.nav.permalink(), 'link to this view'), { hint: 'Samples and local paths only; uploads are never put in a link', keywords: 'share url deep link' });

    cmd('Navigation', 'core.back', 'Back', '[', () => BS.nav.back(), { when: () => BS.state.historyIndex > 0 });
    cmd('Navigation', 'core.forward', 'Forward', ']', () => BS.nav.forward(), { when: () => BS.state.historyIndex < BS.state.history.length - 1 });
    cmd('Navigation', 'core.focus.tree', 'Focus the structure tree', '1', () => focusEl('structure-tree'));
    cmd('Navigation', 'core.focus.inspector', 'Focus the inspector', '2', () => {
      const body = document.getElementById('inspector-body');
      const first = body && body.querySelector('[tabindex="0"], input, button, select');
      (first || document.getElementById('inspector-title'))?.focus();
    });
    cmd('Navigation', 'core.focus.hex', 'Focus the hex view', '3', () => focusEl('hex-viewport'), { when: hasDoc });
    cmd('Navigation', 'core.filter', 'Filter the structure tree', 'F', () => focusEl('tree-filter-input', true));
    cmd('Navigation', 'core.translate', 'Translate an address', 'G', () => focusEl('conv-vm-input', true), { when: hasDoc, hint: 'File offset, slice offset and VM address', keywords: 'convert vmaddr rva' });
    cmd('Navigation', 'core.goto', 'Go to file offset…', 'Shift+G', () => focusEl('hex-goto-input', true), { when: hasDoc, keywords: 'jump seek' });
    cmd('Navigation', 'core.disasm.cursor', 'Disassemble at cursor', 'A', async () => {
      const vm = absOffsetToVmAddr(BS.state.cursorOffset, BS.getActiveSlice());
      if (vm) openDisassemblyAt(vm, '');
      else BS.ui.toast('The cursor is not inside a mapped segment, so it has no address to disassemble at.', 'info');
    }, { when: hasDoc, keywords: 'assembly code instructions' });

    cmd('Hex view', 'core.copy.hex', 'Copy selection as hex', 'C', copySelectionHex, { when: hasDoc, hint: 'The highlighted range, or the byte under the cursor' });
    cmd('Hex view', 'core.copy.offset', 'Copy cursor file offset', 'Shift+C', () => BS.ui.copy(BS.util.hex(BS.state.cursorOffset)), { when: hasDoc });
    cmd('Hex view', 'core.copy.vmaddr', 'Copy cursor VM address', 'Alt+C', () => {
      const vm = absOffsetToVmAddr(BS.state.cursorOffset, BS.getActiveSlice());
      if (vm) BS.ui.copy(vm);
      else BS.ui.toast('The cursor is not inside a mapped segment.', 'info');
    }, { when: hasDoc });
    cmd('Hex view', 'core.hex.addrmode', 'Toggle offset column: file offset / VM address', 'H', toggleHexAddrMode, { when: hasDoc });
    cmd('Hex view', 'core.hex.endian', 'Toggle decoder endianness', 'E', toggleDecoderEndian, { when: hasDoc, keywords: 'little big byte order' });
    cmd('Hex view', 'core.hex.dock', 'Toggle hex pane dock: right / bottom', 'D', toggleHexDock, { when: hasDoc, keywords: 'layout split' });
    cmd('Hex view', 'core.memmap.scale', 'Toggle memory map scale: sqrt / linear', 'M', toggleMemmapScale, { when: hasDoc });

    // The keyboard reference is an ordinary registered view.
    const STATIC_KEYS = [
      ['Everywhere', [
        ['Esc', 'Close the topmost dialog or palette; leave a text field; clear the selection'],
        ['Tab / Shift+Tab', 'Move between controls and panes'],
        [`${IS_MAC ? '⌥' : 'Alt+'}click`, 'Copy the value under the pointer (offsets, addresses, names, hashes)'],
        ['Browser Back / Forward', 'Same history as [ and ]'],
      ]],
      ['Structure tree', [
        ['↑ ↓ Home End', 'Move'],
        ['→ ←', 'Expand / collapse, or step into / out of a node'],
        ['Enter or Space', 'Open the focused node'],
      ]],
      ['Hex view', [
        ['← → ↑ ↓', 'Move the cursor by a byte / a row'],
        ['PageUp PageDown', 'Move by a screen'],
        ['Home End', 'Start / end of the row; with Ctrl or ⌘, of the file'],
        ['Shift + movement, Shift+click', 'Extend the selection'],
        ['Enter, double-click', 'Activate the byte (used by Labs)'],
      ]],
      ['Tables', [
        ['↑ ↓', 'Move between rows (PageUp / PageDown / Home / End in Symbols and Strings)'],
        ['Enter', 'Show the row’s bytes in the hex view'],
      ]],
      ['Search palette', [
        ['>', 'Commands only'],
        ['@  "  #', 'Symbols, strings, structures'],
        ['0x…  or hex bytes', 'Jump to an address, or find a byte sequence (e.g. cf fa ed fe)'],
      ]],
    ];

    BS.registerView({
      id: 'help.shortcuts',
      title: 'Keyboard shortcuts',
      icon: '?',
      group: 'Help',
      order: 10,
      requiresDoc: false,
      render(bodyEl) {
        const { html: h } = BS.util;
        const sections = new Map();
        BS.commands.list({ all: true }).forEach((c) => {
          if (!c.shortcut) return;
          if (!sections.has(c.section)) sections.set(c.section, []);
          sections.get(c.section).push([c.shortcut, c.title]);
        });
        const all = [...sections.entries(), ...STATIC_KEYS];
        bodyEl.innerHTML = h`
          <div class="overview-container shortcuts-view">
            <p class="panel-intro">Single-key shortcuts work when focus is not in a text field. Every command is also in the palette: press ${formatShortcut(parseShortcut('Mod+K'))} and type <kbd>&gt;</kbd>.</p>
            <div class="shortcut-grid">
              ${all.map(([name, rows]) => h`
                <div class="panel-card">
                  <div class="panel-card-header">${name}</div>
                  <dl class="shortcut-list">
                    ${rows.map(([keys, what]) => h`<div class="shortcut-row"><dt><kbd>${keys}</kbd></dt><dd>${what}</dd></div>`)}
                  </dl>
                </div>
              `)}
            </div>
          </div>
        `;
      },
    });
  })();

  // Commands that depend on what is loaded: one per sample, one per slice.
  let presetCommandHandles = [];
  let docCommandHandles = [];

  function registerPresetCommands() {
    presetCommandHandles.forEach((h) => h.unregister());
    presetCommandHandles = state.presets.map((p) =>
      BS.registerCommand({ id: `core.sample.${p.id}`, title: `Open sample: ${str(p.label, p.id)}`, hint: str(p.description), section: 'Samples', run: () => BS.openPreset(p.id) })
    );
  }

  function registerDocCommands() {
    docCommandHandles.forEach((h) => h.unregister());
    const slices = state.doc?.slices || [];
    docCommandHandles = slices.length < 2 ? [] : slices.map((s, idx) =>
      BS.registerCommand({ id: `core.slice.${idx}`, title: `Switch to slice: ${str(s.arch_name)}`, section: 'Slices', when: () => state.activeSliceIndex !== idx, run: () => activateSlice(idx, { keepView: true }) })
    );
  }

  // =========================================================================
  // Application Bootstrap
  // =========================================================================
  function showBootError(err) {
    const bodyEl = document.getElementById('inspector-body');
    const info = describeError(err);
    document.getElementById('inspector-title').textContent = 'BinaryStudio could not start';
    const card = errorCard(info.what, [info.next, info.detail].filter(Boolean).join('\n'));
    const retry = el('button', 'btn btn-accent', 'Try again');
    retry.type = 'button';
    retry.addEventListener('click', () => window.location.reload());
    const pad = el('div', 'pad');
    pad.appendChild(retry);
    card.firstElementChild.appendChild(pad);
    bodyEl.replaceChildren(card);
  }

  async function bootstrap() {
    initEventListeners();
    initPaneResizers();
    applyLayout();
    applyHexModeLabels();
    applyTheme(state.themePref, false);

    // "Learn mode" toggle — the mount point later Learn features build on (BS.learn, .learn-only).
    const learnBtn = BS.ui.addToolbarButton({
      id: 'learn',
      label: 'Learn',
      title: 'Learn mode: show explanations next to fields and bytes (L)',
      pressed: BS.learn.isOn(),
      onClick: () => BS.learn.toggle(),
    });
    BS.on('learnmode:changed', ({ on }) => learnBtn.setPressed(on));

    const done = busy.start('Starting…');
    try {
      config = await loadConfig();
    } catch (err) {
      done('Not connected', 'error');
      showBootError(err);
      return;
    }
    applyConfig();
    state.presets = await loadPresets();
    registerPresetCommands();
    done('Ready');
    booted = true;
    bus.emit('ready', { config });

    // Where to start: an explicit link, then ?file= (local), then the last session, else the start view.
    const target = parseLocationHash();
    const session = storage.get('session', null);
    // A path the user opened deliberately in this browser may be resumed (also on reload, when the
    // hash still names it); any other path from a URL waits for confirmation.
    if (session && typeof session.doc === 'string' && session.doc.startsWith('path:') && session.confirmed === true) confirmedPathRefs.add(session.doc);
    if (target.ref || target.view) {
      await restoreFromLocation();
      return;
    }
    const fileParam = new URLSearchParams(window.location.search).get('file');
    const restore = { noHistory: true };
    if (fileParam && config.features.path_load) {
      // ?file= comes from a link: ask first (see confirmedPathRefs).
      askToOpenPath(fileParam, restore);
    } else if (config.initial_doc && refAllowed(config.initial_doc)) {
      if (config.initial_doc.startsWith('path:')) confirmedPathRefs.add(config.initial_doc); // the server's own --file
      await openRef(config.initial_doc, restore);
    } else if (session && refAllowed(session.doc) && (!session.doc.startsWith('preset:') || state.presets.some((p) => `preset:${p.id}` === session.doc))) {
      await openRef(session.doc, { slice: session.slice, view: session.view, off: Number.isFinite(session.off) ? session.off : undefined, noHistory: true });
    }
    if (!state.doc && state.selectedNodeId !== 'start') showStartView(false);
    anchorHistory();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }
})();
