/**
 * BinaryStudio Labs — patch and observe, guided experiments, the minimal-ELF builder, compare.
 *
 * Presentation and interaction only. Every decision about bytes or Documents is made by the
 * backend (backend/labs_patch.py): this file sends edits, and draws what comes back.
 *
 * Model: a patch session belongs to one root document. It is a list of byte patches
 * [{offset, hex, label}] against that root. Every change sends the whole list to POST /api/patch,
 * which answers with a derived document and a structural diff of root -> derived; the derived
 * document then takes the root's place on screen (BS.loadDocument with replace). Undo and redo are
 * earlier and later versions of the list. The root document is never modified.
 *
 * Views (tree group "Labs"): labs.patch, labs.experiments, labs.build, labs.compare.
 * Nothing here executes a binary, on the server or in the browser.
 */
(() => {
  'use strict';

  const BS = window.BinaryStudio;
  if (!BS) return;
  const { html, hex: hx, formatBytes } = BS.util;

  const VIEW_PATCH = 'labs.patch';
  const VIEW_EXPERIMENTS = 'labs.experiments';
  const VIEW_BUILD = 'labs.build';
  const VIEW_COMPARE = 'labs.compare';
  const PATCHSET_FORMAT = 'binarystudio-patchset';
  const NO_DOC = { doc: null, slice_index: null }; // keeps BS.api from adding the open document to a query

  // ===========================================================================
  // Small helpers
  // ===========================================================================
  const str = (v, fallback = '') => (v === null || v === undefined || v === '' ? fallback : String(v));
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many || `${one}s`}`;
  const spaced = (hexText) => str(hexText).replace(/(..)(?=.)/g, '$1 ');
  const clip = (text, max) => (str(text).length > max ? `${str(text).slice(0, max - 1)}…` : str(text));

  function canPatch() {
    return Boolean(BS.config && BS.config.features && BS.config.features.patch && BS.state.doc && BS.state.docId);
  }

  function errorText(err) {
    if (err instanceof BS.ApiError) return str(err.message, 'The request failed.');
    return str(err && err.message, 'Something went wrong.');
  }

  function saveBlob(bytes, filename, type) {
    const url = URL.createObjectURL(new Blob([bytes], { type: type || 'application/octet-stream' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.className = 'labs-offscreen';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 15000);
  }

  function hexToBytes(text) {
    const clean = str(text).replace(/[^0-9a-fA-F]/g, '');
    const out = new Uint8Array(clean.length >> 1);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }

  // ---- shapes of server responses and imported files ---------------------------------------
  // Server data and imported files never pick a class name, a loop bound or a code path directly:
  // each is checked once where it arrives (below) and anything unexpected becomes an inline message.
  const isOff = (v, max) => Number.isSafeInteger(v) && v >= 0 && (max === undefined || v <= max);
  const isHexText = (v, maxChars) => typeof v === 'string' && v.length % 2 === 0 && v.length <= maxChars && /^[0-9a-f]*$/.test(v);
  const UNEXPECTED = 'The server sent an unexpected response.';
  const BUILD_GROUPS = new Set(['ehdr', 'phdr0', 'phdr1', 'phdr2', 'phdr3', 'payload']);
  const groupClass = (g) => `labs-g-${BUILD_GROUPS.has(g) ? g : 'other'}`;
  const noteClass = (level) => `labs-bnote-${level === 'warn' ? 'warn' : 'info'}`;
  const BUILD_MAX_BYTES = 64 * 1024;   // the builder makes files of a few hundred bytes
  const BUILD_SHOW_BYTES = 4096;       // at most this many byte cells are drawn
  const PATCH_ROWS_SHOWN = 500;        // the patch table lists at most this many rows
  const IMPORT_MAX_PATCHES = 4096;
  const IMPORT_LABEL_MAX = 120;

  /** /api/labs/build -> normalised result, or {error}. */
  function checkBuildResponse(r) {
    const txt = (v, max) => (typeof v === 'string' ? v.slice(0, max || 2000) : v === null || v === undefined ? '' : null);
    if (!r || typeof r !== 'object' || !isHexText(r.hex, BUILD_MAX_BYTES * 2)) return { error: UNEXPECTED };
    const size = r.hex.length / 2;
    const regions = Array.isArray(r.regions) && r.regions.length <= 1024 ? r.regions : null;
    const groups = Array.isArray(r.groups) && r.groups.length <= 32 ? r.groups : null;
    const notes = Array.isArray(r.notes) && r.notes.length <= 64 ? r.notes : null;
    if (!regions || !groups || !notes) return { error: UNEXPECTED };
    const out = {
      hex: r.hex, size, sha256: txt(r.sha256, 64), filename: txt(r.filename, 200),
      verify: r.verify && typeof r.verify === 'object' ? r.verify : {},
      regions: [], groups: [], notes: [],
    };
    if (out.sha256 === null || out.filename === null) return { error: UNEXPECTED };
    for (const g of regions) {
      if (!g || typeof g !== 'object' || !isOff(g.offset, size) || !isOff(g.size, size - g.offset)) return { error: UNEXPECTED };
      const region = { offset: g.offset, size: g.size, group: txt(g.group, 40), name: txt(g.name, 120), value: txt(g.value, 200), meaning: txt(g.meaning), hex: txt(g.hex, 2 * size) };
      if (Object.values(region).includes(null)) return { error: UNEXPECTED };
      out.regions.push(region);
    }
    for (const g of groups) {
      if (!g || typeof g !== 'object') return { error: UNEXPECTED };
      const group = { id: txt(g.id, 40), label: txt(g.label, 120), offset: txt(String(g.offset), 40), size: txt(String(g.size), 40) };
      if (Object.values(group).includes(null)) return { error: UNEXPECTED };
      out.groups.push(group);
    }
    for (const n of notes) {
      if (!n || typeof n !== 'object' || txt(n.text) === null) return { error: UNEXPECTED };
      out.notes.push({ level: n.level === 'warn' ? 'warn' : 'info', text: txt(n.text) });
    }
    return out;
  }

  /** Bound every array in a server diff before it is drawn (each section is a plain table). */
  function capArrays(v, depth = 0) {
    if (Array.isArray(v)) return v.slice(0, 1000).map((x) => capArrays(x, depth + 1));
    if (v && typeof v === 'object' && depth < 12) {
      const out = {};
      Object.keys(v).forEach((k) => { out[k] = capArrays(v[k], depth + 1); });
      return out;
    }
    return v;
  }

  /** /api/patch -> true if the answer has the shape the session relies on. */
  function checkPatchResponse(res) {
    if (!res || typeof res !== 'object' || !Array.isArray(res.patches) || res.patches.length > IMPORT_MAX_PATCHES) return false;
    if (!res.patches.every((p) => p && isOff(p.offset) && isHexText(p.hex, 1 << 22))) return false;
    if (!res.identical && (typeof res.doc_id !== 'string' || !res.document || typeof res.document !== 'object' || !Array.isArray(res.document.slices))) return false;
    if (res.diff !== null && res.diff !== undefined) {
      if (typeof res.diff !== 'object') return false;
      const ranges = res.diff.bytes && res.diff.bytes.ranges;
      if (ranges !== undefined && (!Array.isArray(ranges) || !ranges.every((r) => r && isOff(r.offset) && isOff(r.size)))) return false;
    }
    return true;
  }

  /**
   * A patch-set file -> {patches, target} or {error}. Rejects the whole file unless every entry is
   * well formed: at most IMPORT_MAX_PATCHES entries, total bytes within the server's limit, every
   * `hex` an even-length hex string, offsets inside the open file, labels short strings. Unknown
   * keys are dropped.
   */
  function checkPatchSet(data, fileSize) {
    if (!data || typeof data !== 'object' || data.format !== PATCHSET_FORMAT || !Array.isArray(data.patches)) {
      return { error: 'That file is not a BinaryStudio patch list.' };
    }
    const list = data.patches;
    if (!list.length) return { error: 'The patch list is empty.' };
    if (list.length > IMPORT_MAX_PATCHES) return { error: `The patch list has ${list.length} entries; at most ${IMPORT_MAX_PATCHES} can be imported.` };
    const limit = Number(BS.config && BS.config.limits && BS.config.limits.max_patch_bytes) || 0;
    const patches = [];
    let total = 0;
    for (let i = 0; i < list.length; i++) {
      const p = list[i];
      const where = `Entry ${i + 1}`;
      if (!p || typeof p !== 'object' || Array.isArray(p)) return { error: `${where} is not an object with an offset and hex bytes.` };
      const hexText = typeof p.hex === 'string' ? p.hex.replace(/\s+/g, '').toLowerCase() : null;
      if (hexText === null || !hexText.length || !isHexText(hexText, 2 * Math.max(limit, 1))) return { error: `${where}: "hex" must be an even number of hex digits.` };
      const n = hexText.length / 2;
      if (!isOff(p.offset) || p.offset + n > fileSize) return { error: `${where}: the offset is not inside the open file (${formatBytes(fileSize)}).` };
      if (p.label !== undefined && p.label !== null && (typeof p.label !== 'string' || p.label.length > IMPORT_LABEL_MAX)) return { error: `${where}: "label" must be text of at most ${IMPORT_LABEL_MAX} characters.` };
      total += n;
      if (limit && total > limit) return { error: `The patch list changes ${formatBytes(total)} or more; at most ${formatBytes(limit)} are allowed here.` };
      patches.push({ offset: p.offset, hex: hexText, label: typeof p.label === 'string' ? p.label : '' });
    }
    const t = data.target && typeof data.target === 'object' ? data.target : null;
    const target = t ? {
      filename: typeof t.filename === 'string' ? t.filename.slice(0, 200) : '',
      sha256: typeof t.sha256 === 'string' && /^[0-9a-f]{64}$/i.test(t.sha256) ? t.sha256.toLowerCase() : '',
    } : null;
    return { patches, target };
  }

  const jump = (offset, size, label, text) => html`<button type="button" class="jump-chip" data-labs-jump="${Number(offset)}" data-labs-size="${Math.max(1, Number(size) || 1)}" data-labs-label="${str(label, 'range')}">${text === undefined ? hx(offset, 6) : text}</button>`;
  const nodeLink = (id, text) => html`<button type="button" class="jump-chip" data-labs-node="${id}">${text}</button>`;
  const act = (name, text, extra = {}) => html`<button type="button" class="${extra.cls || 'jump-chip'}" data-labs-act="${name}" data-labs-arg="${str(extra.arg)}" title="${str(extra.title)}" ${extra.disabled ? html`disabled` : ''} ${extra.pressed === undefined ? '' : html`aria-pressed="${String(Boolean(extra.pressed))}"`}>${text}</button>`;

  // Compare view state (declared early: a patch session points the view at its before/after pair).
  const compare = { a: null, b: null, auto: false, diff: null, error: '', key: '', recent: new Map(), seq: 0 };

  // ===========================================================================
  // Patch session
  // ===========================================================================
  /** @type {null | {rootId:string, rootDoc:object, patches:Array, undo:Array, redo:Array, currentId:(string|null), currentDoc:(object|null), diff:(object|null), viewing:string}} */
  let S = null;
  /** An imported list waiting for the user to confirm it (made for another file, or for an unnamed one). */
  let pendingImport = null;
  let syncing = null;      // the in-flight /api/patch round trip, if any
  let syncDirty = false;   // the list changed while a round trip was in flight
  let deferTimer = null;   // a round trip scheduled for when the typing pauses
  const TYPING_PAUSE_MS = 160;
  const echoBytes = new Map(); // offset -> value: bytes typed but not yet part of the document on screen
  const edit = { on: false, nibble: null, hint: '' };

  function startSession() {
    if (S || !canPatch()) return S;
    S = { rootId: BS.state.docId, rootDoc: BS.state.doc, patches: [], undo: [], redo: [], currentId: null, currentDoc: null, diff: null, viewing: 'original', sliceBase: activeSliceBase(), good: [], goodUndo: 0, unsent: false };
    S.good = S.patches;
    return S;
  }

  function activeSliceBase() {
    const slice = BS.getActiveSlice();
    return slice ? Number(slice.slice_base_offset) || 0 : 0;
  }

  /** Show a version of the session's document in place, staying on the slice the user chose. */
  let swapping = false;
  function showDoc(doc) {
    swapping = true;
    try {
      BS.loadDocument(doc, { keepView: true, replace: true });
      // A patch can make a slice of a universal file disappear and reappear; slices are
      // identified by where they start in the file, not by their position in the list.
      const want = S ? S.sliceBase : null;
      const index = (doc.slices || []).findIndex((sl) => Number(sl.slice_base_offset) === want);
      if (index >= 0 && index !== BS.state.activeSliceIndex) BS.commands.run(`core.slice.${index}`);
    } finally {
      swapping = false;
    }
  }

  function patchedBytes() {
    return S ? S.patches.reduce((n, p) => n + (p.hex.length >> 1), 0) : 0;
  }

  /** The document higher-level edits are resolved against: the patched copy if there is one. */
  function opDoc() {
    return S && S.currentId ? S.currentId : BS.state.docId;
  }

  function viewingOriginalWithPatches() {
    return Boolean(S && S.patches.length && S.currentId && S.viewing === 'original' && !syncing && !deferTimer);
  }

  function refuseWhileOriginal() {
    if (!viewingOriginalWithPatches()) return false;
    BS.ui.toast('This is the original. Switch to the patched copy (V) to keep editing it.', 'info');
    return true;
  }

  /** Replace the patch list and bring the screen in line with it. */
  function setPatches(next, opts = {}) {
    if (!startSession()) return Promise.resolve(false);
    if (opts.history !== false) {
      S.undo.push(S.patches);
      if (S.undo.length > 500) S.undo.shift();
      S.redo = [];
    }
    S.patches = next;
    if (opts.defer) {
      // Typing: several keystrokes become one round trip. The typed bytes are already on
      // screen (see echo); the analysis follows a moment after the last key.
      clearTimeout(deferTimer);
      deferTimer = setTimeout(sync, TYPING_PAUSE_MS);
      paintBar();
      return Promise.resolve(true);
    }
    echoBytes.clear();
    return sync();
  }

  function sync() {
    clearTimeout(deferTimer);
    deferTimer = null;
    if (syncing) {
      syncDirty = true;
      return syncing;
    }
    syncing = (async () => {
      let ok = true;
      do {
        syncDirty = false;
        ok = await syncOnce();
      } while (syncDirty && ok && S);
      return ok;
    })().finally(() => {
      syncing = null;
      paintBar();
    });
    paintBar();
    return syncing;
  }

  async function syncOnce() {
    const session = S;
    const sent = session.patches;
    try {
      if (!sent.length) {
        session.currentId = null;
        session.currentDoc = null;
        session.diff = null;
        if (BS.state.doc !== session.rootDoc) showDoc(session.rootDoc);
        else afterDocChange();
        // The superseded copy is left to expire: it is small, counts against this client's
        // share of the cache only, and the next patch names the copy it replaces.
        applied(session, sent);
        BS.ui.status('All patches reverted', 'ready');
        return true;
      }
      const res = await BS.api.post('/api/patch', {
        doc: session.rootId,
        patches: sent.map((p) => ({ offset: p.offset, hex: p.hex, label: p.label })),
        replace: session.currentId || undefined,
      }, NO_DOC);
      if (S !== session) return false; // another document was opened meanwhile
      if (!checkPatchResponse(res)) throw new BS.ApiError(200, 'bad_response', UNEXPECTED);
      if (res.diff) res.diff = capArrays(res.diff);
      // The server's list is the normalised one (and carries the bytes each patch replaced).
      if (session.patches === sent) session.patches = res.patches.map((p) => ({ offset: p.offset, hex: p.hex, label: str(p.label), before: str(p.before) }));
      applied(session, sent);
      if (res.identical) {
        session.currentId = null;
        session.currentDoc = null;
        session.diff = res.diff;
        if (BS.state.doc !== session.rootDoc) showDoc(session.rootDoc);
        else afterDocChange();
        BS.ui.status('The patches leave the file unchanged', 'ready');
        return true;
      }
      if (!session.currentId) compare.auto = true; // a new before/after pair: Compare starts on it
      session.currentId = res.doc_id;
      session.currentDoc = res.document;
      session.diff = res.diff;
      showDoc(res.document);
      if (res.diff && res.diff.parse && res.diff.parse.ok === false) {
        BS.ui.toast('The patched file no longer parses. Patch & observe says what broke; Undo (U) restores it.', 'warn');
        if (BS.state.selectedNodeId !== VIEW_PATCH) BS.nav.openView(VIEW_PATCH);
      }
      BS.ui.status(statusLine(res.diff), 'ready');
      return true;
    } catch (err) {
      if (S !== session) return false;
      echoBytes.clear();
      const transient = err instanceof BS.ApiError && ['rate_limited', 'busy', 'network', 'timeout'].includes(err.code);
      if (transient) {
        // Nothing is wrong with the edit; the server could not take it just now. Keep the list.
        session.unsent = true;
        BS.ui.toast(`Not applied yet. ${errorText(err)} Your patches are kept; use Retry in the hex pane.`, 'warn');
      } else {
        // The server refused this list (out of range, over the limit): go back to the last one it accepted.
        session.patches = session.good;
        session.undo.length = Math.min(session.undo.length, session.goodUndo);
        session.redo = [];
        BS.ui.toast(`Patch not applied. ${errorText(err)}`, 'error');
      }
      BS.ui.status('Patch not applied', 'error');
      BS.hex.refresh();
      rerenderOpenView();
      return false;
    }
  }

  function applied(session, sent) {
    session.good = session.patches;
    session.goodUndo = session.undo.length;
    session.unsent = false;
    // Typed bytes that this round trip carried are now real; later ones stay echoed.
    const carried = new Map();
    sent.forEach((p) => {
      for (let i = 0; i < p.hex.length >> 1; i++) carried.set(p.offset + i, parseInt(p.hex.substr(i * 2, 2), 16));
    });
    echoBytes.forEach((value, offset) => {
      if (carried.get(offset) === value || !session.patches.length) echoBytes.delete(offset);
    });
  }

  function statusLine(diff) {
    if (!diff || !diff.summary) return 'Patched';
    const s = diff.summary;
    const parts = [plural(s.bytes || 0, 'byte')];
    if (s.fields) parts.push(plural(s.fields, 'field'));
    if (s.security) parts.push(plural(s.security, 'hardening check'));
    if (s.anomalies) parts.push(plural(s.anomalies, 'anomaly', 'anomalies'));
    if (s.integrity) parts.push('integrity');
    return `Patched: ${parts.join(' · ')} changed`;
  }

  function undo() {
    if (!S || !S.undo.length) return;
    S.redo.push(S.patches);
    S.patches = S.undo.pop();
    echoBytes.clear();
    sync();
  }

  function redo() {
    if (!S || !S.redo.length) return;
    S.undo.push(S.patches);
    S.patches = S.redo.pop();
    echoBytes.clear();
    sync();
  }

  function revertAll() {
    if (S && S.patches.length) setPatches([]);
  }

  function revertOne(index) {
    if (!S || !S.patches[index]) return;
    setPatches(S.patches.filter((_, i) => i !== index));
  }

  /** Append byte patches. Bytes typed one after another extend the previous patch. */
  function addPatches(list, opts = {}) {
    if (!startSession() || !list.length) return Promise.resolve(false);
    let next = S.patches.slice();
    list.forEach((p) => {
      const last = next[next.length - 1];
      if (opts.typed && last && !last.label) {
        const end = last.offset + (last.hex.length >> 1);
        const size = p.hex.length >> 1;
        if (p.offset === end) {
          next[next.length - 1] = Object.assign({}, last, { hex: last.hex + p.hex, before: '' });
          return;
        }
        if (p.offset >= last.offset && p.offset + size <= end) {
          const at = (p.offset - last.offset) * 2;
          next[next.length - 1] = Object.assign({}, last, { hex: last.hex.slice(0, at) + p.hex + last.hex.slice(at + p.hex.length), before: '' });
          return;
        }
      }
      next.push({ offset: p.offset, hex: p.hex, label: str(p.label) });
    });
    return setPatches(next, { defer: Boolean(opts.typed) });
  }

  /** Turn a higher-level edit into byte patches on the server, then apply them. */
  async function resolveAndApply(op) {
    if (!canPatch() || refuseWhileOriginal()) return false;
    try {
      if (deferTimer) sync();
      if (syncing) await syncing;
      const res = await BS.api.post('/api/labs/resolve', { doc: opDoc(), slice_index: BS.state.activeSliceIndex, op }, NO_DOC);
      if (res.ok === false) {
        BS.ui.toast(str(res.error, 'That edit cannot be made.'), 'warn');
        return false;
      }
      if (!res.patches.length) {
        BS.ui.toast('Nothing to change: the bytes already have that value.', 'info');
        return false;
      }
      return await addPatches(res.patches);
    } catch (err) {
      BS.ui.toast(errorText(err), 'error');
      return false;
    }
  }

  // ===========================================================================
  // Keeping up with the core
  // ===========================================================================
  function afterDocChange() {
    paintDecorations();
    paintBar();
    rerenderOpenView();
  }

  BS.on('doc:loaded', ({ docId }) => {
    if (S && docId && docId === S.currentId) S.viewing = 'patched';
    else if (S && docId && docId === S.rootId) S.viewing = 'original';
    else {
      S = null;
      pendingImport = null;
      echoBytes.clear();
      clearTimeout(deferTimer);
      deferTimer = null;
      setEdit(false, true);
    }
    edit.nibble = null;
    fieldIndex = null;
    paintDecorations();
    paintBar();
  });
  BS.on('doc:closed', () => {
    S = null;
    pendingImport = null;
    setEdit(false, true);
    paintBar();
  });
  BS.on('doc:renewed', ({ oldId, docId }) => {
    if (S && S.rootId === oldId) S.rootId = docId;
  });
  BS.on('slice:changed', () => {
    if (S && !swapping) S.sliceBase = activeSliceBase();
    fieldIndex = null;
  });
  BS.on('doc:expired', ({ docId }) => {
    // The server dropped the patched copy; the list is all that is needed to make it again.
    if (S && docId === S.currentId && S.patches.length) {
      S.currentId = null;
      sync();
    }
  });
  BS.on('cursor:changed', () => {
    if (edit.nibble !== null || edit.hint) {
      edit.nibble = null;
      paintBar();
    }
  });

  function paintDecorations() {
    if (!BS.state.doc) return;
    const ranges = S && S.diff && S.diff.bytes && Array.isArray(S.diff.bytes.ranges) && S.patches.length ? S.diff.bytes.ranges : [];
    const original = S && S.viewing === 'original';
    BS.hex.setDecorations('labs-patch', ranges.map((r) => ({
      abs_offset: r.offset,
      size: r.size,
      className: original ? 'labs-patched-orig' : 'labs-patched',
      title: original ? `Patched in the modified copy: ${r.before} -> ${r.after}` : `Patched. Was: ${r.before}`,
    })));
  }

  // ===========================================================================
  // Hex pane: edit mode, typing, paste, fill; the patch bar
  // ===========================================================================
  let bar = null;
  const hexViewport = () => document.getElementById('hex-viewport');

  function ensureBar() {
    if (bar) return bar;
    const pane = document.getElementById('hex-pane');
    const toolbar = pane && pane.querySelector('.hex-toolbar');
    if (!toolbar) return null;
    bar = document.createElement('div');
    bar.className = 'labs-bar';
    bar.id = 'labs-bar';
    bar.hidden = true;
    bar.setAttribute('role', 'toolbar');
    bar.setAttribute('aria-label', 'Patches');
    toolbar.after(bar);
    bar.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && fillOpen) {
        e.preventDefault();
        e.stopPropagation();
        fillOpen = false;
        paintBar();
        hexViewport()?.focus({ preventScroll: true });
      }
    });
    bar.addEventListener('submit', (e) => {
      e.preventDefault();
      const input = bar.querySelector('.labs-fill-input');
      const span = BS.state.fieldSpan || { abs_offset: BS.state.cursorOffset, size: 1 };
      const value = input ? input.value.trim().replace(/^0x/i, '') : '';
      if (!/^[0-9a-fA-F]{1,2}$/.test(value)) {
        BS.ui.toast('Enter one byte as two hex digits, for example 00 or ff.', 'info');
        return;
      }
      fillOpen = false;
      resolveAndApply({ kind: 'fill', offset: span.abs_offset, size: span.size, byte: `0x${value}` }).then(() => hexViewport()?.focus({ preventScroll: true }));
    });
    return bar;
  }

  let fillOpen = false;

  function paintBar() {
    const el = ensureBar();
    if (!el) return;
    const count = S ? S.patches.length : 0;
    const show = Boolean(BS.state.doc) && (edit.on || fillOpen || count > 0 || Boolean(S && (S.undo.length || S.redo.length)));
    el.hidden = !show;
    document.getElementById('hex-pane')?.classList.toggle('labs-editing', edit.on && show);
    if (!show) return;
    const original = S && S.viewing === 'original' && count > 0;
    let state = '';
    if (syncing || deferTimer) state = 'applying…';
    else if (S && S.unsent) state = 'not applied yet';
    else if (edit.nibble !== null) state = `${hx(BS.state.cursorOffset)}: ${edit.nibble.toUpperCase()}_`;
    else if (edit.hint) state = edit.hint;
    else if (edit.on) state = 'type hex digits';
    const span = BS.state.fieldSpan;
    el.innerHTML = html`
      ${act('toggle-edit', 'Edit', { cls: 'labs-bar-btn', pressed: edit.on, title: 'Overwrite bytes at the cursor by typing hex digits (I, or Enter in the hex view). Esc stops.' })}
      <span class="labs-bar-state" aria-live="polite">${state}</span>
      ${fillOpen ? html`<form class="labs-fill-form"><label>fill ${span ? plural(span.size, 'byte') : '1 byte'} with <input class="labs-fill-input" type="text" size="3" maxlength="4" placeholder="00" spellcheck="false" autocomplete="off" aria-label="Fill value, two hex digits" /></label></form>` : ''}
      <span class="labs-bar-spacer"></span>
      ${count ? act('open-patch', `${plural(count, 'patch', 'patches')} · ${plural(patchedBytes(), 'byte')}`, { cls: 'labs-bar-btn labs-bar-count', title: 'Show the patch list and what changed' }) : ''}
      ${S && S.unsent && !syncing ? act('retry', 'Retry', { cls: 'labs-bar-btn', title: 'Send the patch list to the server again' }) : ''}
      ${act('undo', 'Undo', { cls: 'labs-bar-btn', disabled: !S || !S.undo.length, title: 'Undo the last change to the patch list (U)' })}
      ${act('redo', 'Redo', { cls: 'labs-bar-btn', disabled: !S || !S.redo.length, title: 'Redo (Shift+U)' })}
      ${count ? act('toggle-original', original ? 'Original' : 'Patched', { cls: 'labs-bar-btn', pressed: original, title: 'Switch between the original and the patched copy (V)' }) : ''}
      ${count ? act('revert-all', 'Revert', { cls: 'labs-bar-btn', title: 'Remove every patch (undoable)' }) : ''}
    `;
    if (fillOpen) el.querySelector('.labs-fill-input')?.focus();
    else restoreFocus(el);
    const badge = count ? String(count) : '';
    if (patchViewHandle && badge !== lastBadge) {
      lastBadge = badge;
      patchViewHandle.update({ badge });
    }
  }
  let patchViewHandle = null;
  let lastBadge = '';

  // Buttons are redrawn after every action; put the focus back on the one that was used.
  let lastAct = null;
  function restoreFocus(root) {
    if (!lastAct || Date.now() - lastAct.at > 4000 || !root) return;
    const active = document.activeElement;
    if (active && active !== document.body && document.body.contains(active)) return;
    const again = Array.from(root.querySelectorAll('[data-labs-act]')).find((b) => b.dataset.labsAct === lastAct.act && str(b.dataset.labsArg) === lastAct.arg && !b.disabled && lastAct.inBar === Boolean(b.closest('#labs-bar')));
    if (again) again.focus({ preventScroll: true });
  }

  function setEdit(on, quiet) {
    const next = Boolean(on) && canPatch();
    if (on && !next && !quiet) BS.ui.toast(BS.state.doc ? 'Patching is not available on this server.' : 'Open a binary first.', 'info');
    if (next && refuseWhileOriginal()) return;
    edit.on = next;
    edit.nibble = null;
    edit.hint = '';
    fillOpen = false;
    paintBar();
    if (next) hexViewport()?.focus({ preventScroll: true });
  }

  BS.hex.onByteActivate(({ event }) => {
    if (!canPatch()) return;
    // Enter toggles; a double-click only ever turns editing on (it is also how one picks another byte).
    if (event && event.type === 'keydown') setEdit(!edit.on);
    else if (!edit.on) setEdit(true);
  });

  /** Draw typed bytes over the cells the core rendered, until the patched document arrives. */
  function echo() {
    if (!echoBytes.size) return;
    const root = document.getElementById('hex-rows-container');
    if (!root) return;
    echoBytes.forEach((value, offset) => {
      root.querySelectorAll(`[data-byte-offset="${offset}"]`).forEach((cell) => {
        if (cell.classList.contains('hex-byte')) {
          cell.textContent = value.toString(16).toUpperCase().padStart(2, '0');
          cell.classList.add('labs-patched', 'labs-pending');
          cell.classList.remove('byte-zero');
        } else cell.textContent = value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : '.';
      });
    });
  }

  function moveCursor(key) {
    // The core's own handler moves the cursor (no history entry, selection kept consistent).
    hexViewport()?.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true }));
  }

  function showNibble() {
    const cell = document.querySelector('#hex-rows-container .hex-byte.cursor-byte');
    if (cell && edit.nibble !== null) cell.textContent = `${edit.nibble.toUpperCase()}_`;
  }

  function onHexKeydown(e) {
    if (!edit.on || !e.isTrusted || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      if (edit.nibble !== null) {
        edit.nibble = null;
        BS.hex.refresh();
        paintBar();
      } else setEdit(false);
      return;
    }
    if (e.key === 'Backspace') {
      e.preventDefault();
      e.stopPropagation();
      if (edit.nibble !== null) {
        edit.nibble = null;
        BS.hex.refresh();
        paintBar();
      } else moveCursor('ArrowLeft');
      return;
    }
    if (e.key.length !== 1 || !/[0-9a-fA-F]/.test(e.key)) {
      if (edit.nibble !== null && e.key.length === 1) {
        edit.nibble = null;
        BS.hex.refresh();
        paintBar();
      }
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    if (refuseWhileOriginal()) return;
    edit.hint = '';
    if (edit.nibble === null) {
      // A selection is typed over from its first byte.
      const span = BS.state.fieldSpan;
      if (span && span.size > 1 && BS.state.cursorOffset !== span.abs_offset && span.label === 'selection') BS.nav.jumpToOffset(span.abs_offset);
      edit.nibble = e.key.toLowerCase();
      showNibble();
      paintBar();
      return;
    }
    const value = edit.nibble + e.key.toLowerCase();
    const offset = BS.state.cursorOffset;
    edit.nibble = null;
    echoBytes.set(offset, parseInt(value, 16));
    addPatches([{ offset, hex: value, label: '' }], { typed: true });
    moveCursor('ArrowRight');
    echo();
  }

  function onPaste(e) {
    if (!edit.on || document.activeElement !== hexViewport()) return;
    const text = (e.clipboardData && e.clipboardData.getData('text')) || '';
    const digits = text.replace(/0x/gi, '').replace(/[\s,;:_-]/g, '');
    e.preventDefault();
    if (!digits || digits.length % 2 || /[^0-9a-fA-F]/.test(digits)) {
      BS.ui.toast('The clipboard does not hold hex bytes (expected text such as "de ad be ef").', 'info');
      return;
    }
    if (refuseWhileOriginal()) return;
    const limit = BS.config.limits.max_patch_bytes;
    if (digits.length / 2 > limit) {
      BS.ui.toast(`That is ${formatBytes(digits.length / 2)}; one patch set may change at most ${formatBytes(limit)}.`, 'warn');
      return;
    }
    addPatches([{ offset: BS.state.cursorOffset, hex: digits.toLowerCase(), label: `paste ${plural(digits.length / 2, 'byte')}` }]);
  }

  // ===========================================================================
  // Structure tables: edit a decoded value, toggle a flag
  // ===========================================================================
  let fieldIndex = null; // Map "offset:size:name" -> field, for the active document
  let editorState = null; // {offset, size, name, focusFlag} — reopened after the view re-renders
  let refocusRow = null;

  function buildFieldIndex() {
    const map = new Map();
    const add = (fields) => {
      if (!Array.isArray(fields)) return;
      fields.forEach((f) => {
        if (f && typeof f === 'object' && typeof f.abs_offset === 'number') {
          const key = `${f.abs_offset}:${f.size}:${f.name}`;
          if (!map.has(key)) map.set(key, f);
        }
      });
    };
    const skip = new Set(['symbols', 'strings', 'intervals', 'memory_map', 'semantic_layers', 'pedagogy', 'function_starts']);
    const walk = (node, depth) => {
      if (!node || typeof node !== 'object' || depth > 6) return;
      if (Array.isArray(node)) {
        node.forEach((child) => walk(child, depth + 1));
        return;
      }
      Object.keys(node).forEach((key) => {
        if (key === 'fields') add(node[key]);
        else if (!skip.has(key) && node[key] && typeof node[key] === 'object') walk(node[key], depth + 1);
      });
    };
    const doc = BS.state.doc;
    if (doc) {
      walk(doc.file_info && doc.file_info.fat_header, 0);
      walk(BS.getActiveSlice(), 0);
    }
    return map;
  }

  function lookupField(offset, size, name) {
    if (!fieldIndex) fieldIndex = buildFieldIndex();
    return fieldIndex.get(`${offset}:${size}:${name}`) || null;
  }

  function fieldInitialValue(field) {
    if (typeof field.raw_value === 'number' && Number.isFinite(field.raw_value) && Number.isSafeInteger(field.raw_value)) return hx(field.raw_value);
    if (typeof field.raw_value === 'string' && /^[\x20-\x7e]*$/.test(field.raw_value)) return field.raw_value;
    // Integers beyond 2^53 lose precision as JSON numbers; offer the raw bytes instead.
    return `hex:${str(field.raw_hex).replace(/[^0-9a-fA-F ]/g, '').trim()}`;
  }

  function closeFieldEditor(keepState) {
    document.querySelectorAll('tr.labs-fe-row').forEach((row) => row.remove());
    if (!keepState) editorState = null;
  }

  function openFieldEditor(row, focusFlag) {
    if (!canPatch() || refuseWhileOriginal()) return;
    const offset = Number(row.dataset.absOffset);
    const size = Number(row.dataset.fieldSize);
    const name = str(row.dataset.fieldName);
    const field = lookupField(offset, size, name);
    if (!field) {
      BS.ui.toast('This row is not a decoded field of the file, so it cannot be edited here. Edit its bytes in the hex view.', 'info');
      return;
    }
    closeFieldEditor();
    editorState = { offset, size, name, focusFlag: focusFlag || null };
    const flags = Array.isArray(field.bit_flags) ? field.bit_flags.filter((f) => f && f.name && f.mask) : [];
    const tr = document.createElement('tr');
    tr.className = 'labs-fe-row';
    const td = document.createElement('td');
    td.colSpan = row.children.length;
    td.innerHTML = html`
      <form class="labs-fe" data-offset="${offset}" data-size="${size}" data-name="${name}">
        <label class="labs-fe-label"><span>${name}</span>
          <input class="labs-fe-input" type="text" value="${fieldInitialValue(field)}" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="New value for ${name}" />
        </label>
        <button type="submit" class="jump-chip">Apply</button>
        <button type="button" class="jump-chip" data-labs-act="fe-cancel">Cancel</button>
        <span class="labs-fe-hint">${size} ${size === 1 ? 'byte' : 'bytes'} at ${hx(offset)} · decimal, 0x hex, or hex: followed by raw bytes · Enter applies, Esc cancels</span>
        ${flags.length ? html`<div class="labs-fe-flags" role="group" aria-label="Flag bits of ${name}">
          ${flags.map((f) => html`<button type="button" class="labs-flag" data-labs-act="fe-flag" data-labs-arg="${f.name}" aria-pressed="${String(Boolean(f.set))}" title="${str(f.desc || f.description)} (mask ${str(f.mask)})">${f.name}</button>`)}
        </div>` : ''}
      </form>`;
    tr.appendChild(td);
    row.after(tr);
    const wanted = focusFlag ? Array.from(td.querySelectorAll('.labs-flag')).find((b) => b.dataset.labsArg === focusFlag) : null;
    const input = td.querySelector('.labs-fe-input');
    if (wanted) wanted.focus();
    else {
      input.focus();
      input.select();
    }
  }

  function findFieldRow(root, offset, name) {
    return Array.from(root.querySelectorAll('tr.labs-editable')).find((r) => Number(r.dataset.absOffset) === offset && r.dataset.fieldName === name) || null;
  }

  BS.on('view:rendered', ({ bodyEl }) => {
    if (!bodyEl || !BS.state.doc) return;
    fieldIndex = null;
    const rows = bodyEl.querySelectorAll('tr.struct-row[data-abs-offset][data-field-name][data-field-idx]');
    if (!rows.length || !(BS.config && BS.config.features && BS.config.features.patch)) return;
    rows.forEach((row) => {
      row.classList.add('labs-editable');
      const cell = row.querySelector('td.col-val');
      if (cell) cell.title = `${cell.title}\nDouble-click or F2 to edit`;
    });
    if (editorState) {
      const row = findFieldRow(bodyEl, editorState.offset, editorState.name);
      if (row && editorState.focusFlag) openFieldEditor(row, editorState.focusFlag);
      else editorState = null;
    }
    if (refocusRow) {
      const row = findFieldRow(bodyEl, refocusRow.offset, refocusRow.name);
      refocusRow = null;
      if (row && !editorState) {
        bodyEl.querySelectorAll('tr.struct-row[tabindex="0"]').forEach((r) => { r.tabIndex = -1; });
        row.tabIndex = 0;
        row.focus({ preventScroll: true });
        row.scrollIntoView({ block: 'nearest' });
      }
    }
  });

  document.addEventListener('dblclick', (e) => {
    const cell = e.target.closest && e.target.closest('tr.labs-editable > td.col-val');
    if (cell) {
      e.preventDefault();
      openFieldEditor(cell.parentElement);
    }
  });

  document.addEventListener('keydown', (e) => {
    const target = e.target;
    if (!target || !target.matches) return;
    if (e.key === 'F2' && target.matches('tr.labs-editable')) {
      e.preventDefault();
      openFieldEditor(target);
      return;
    }
    const form = target.closest('.labs-fe');
    if (form && e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      const row = form.closest('tr').previousElementSibling;
      closeFieldEditor();
      if (row) row.focus();
    }
  }, true);

  document.addEventListener('submit', (e) => {
    const form = e.target.closest && e.target.closest('.labs-fe');
    if (!form) return;
    e.preventDefault();
    const offset = Number(form.dataset.offset);
    const size = Number(form.dataset.size);
    const name = form.dataset.name;
    const value = form.querySelector('.labs-fe-input').value.trim();
    editorState = null;
    refocusRow = { offset, name };
    resolveAndApply({ kind: 'field', offset, size, name, value }).then((ok) => {
      if (!ok) refocusRow = null;
    });
  });

  // ===========================================================================
  // Rendering a diff (shared by Patch & observe and Compare)
  // ===========================================================================
  const PROP_LABELS = {
    segname: 'name', vmaddr: 'VM address', vmsize: 'VM size', fileoff: 'file offset', filesize: 'file size', initprot: 'protection',
    maxprot: 'max protection', nsects: 'sections', flags_decoded: 'flags', sectname: 'name', size: 'size', abs_offset: 'file offset',
    section_type: 'type', attributes_decoded: 'attributes', prot: 'protection', is_executable: 'executable', cmd_name: 'type',
    cmdsize: 'size', summary: 'summary', file_size: 'file size', format_display: 'format', is_fat: 'universal',
  };
  const propLabel = (p) => PROP_LABELS[p] || str(p).replace(/_/g, ' ');

  function showValue(v) {
    if (v === null || v === undefined || v === '') return '—';
    if (v === true) return 'yes';
    if (v === false) return 'no';
    if (Array.isArray(v)) return v.length ? v.join(' | ') : 'none';
    return String(v);
  }

  const beforeAfter = (b, a) => html`<span class="labs-was">${clip(showValue(b), 160)}</span><span class="labs-arrow" aria-hidden="true">→</span><span class="labs-now">${clip(showValue(a), 160)}</span>`;

  function recordSection(title, noun, data) {
    if (!data || !data.total) return '';
    return html`
      <div class="panel-card">
        <div class="panel-card-header"><span>${title} (${data.total})</span></div>
        <div class="struct-table-wrap"><table class="struct-table labs-table">
          <thead><tr><th>${noun}</th><th>Property</th><th>Before → after</th></tr></thead>
          <tbody>
            ${data.changed.map((rec) => rec.changes.map((c, i) => html`<tr>
              <td class="col-name">${i === 0 ? (rec.node ? nodeLink(rec.node, rec.label) : rec.label) : ''}</td>
              <td>${propLabel(c.prop)}</td><td class="labs-ba">${beforeAfter(c.before, c.after)}</td></tr>`))}
            ${data.removed.map((rec) => html`<tr><td class="col-name">${rec.label}</td><td>no longer present</td><td class="labs-ba"><span class="labs-was">present</span><span class="labs-arrow" aria-hidden="true">→</span><span class="labs-now">gone</span></td></tr>`)}
            ${data.added.map((rec) => html`<tr><td class="col-name">${rec.node ? nodeLink(rec.node, rec.label) : rec.label}</td><td>new</td><td class="labs-ba"><span class="labs-was">absent</span><span class="labs-arrow" aria-hidden="true">→</span><span class="labs-now">present</span></td></tr>`)}
          </tbody>
        </table></div>
        ${data.truncated ? html`<div class="labs-more">${data.truncated} more not shown.</div>` : ''}
      </div>`;
  }

  function fieldsSection(fields, total, mode) {
    if (!fields || !fields.length) return '';
    return html`
      <div class="panel-card">
        <div class="panel-card-header"><span>Decoded fields (${total || fields.length})</span></div>
        <div class="struct-table-wrap"><table class="struct-table labs-table">
          <thead><tr><th>Structure</th><th>Field</th><th>Offset</th><th>Before</th><th>After</th></tr></thead>
          <tbody>
            ${fields.map((f) => html`<tr>
              <td>${f.node ? nodeLink(f.node, f.struct) : f.struct}</td>
              <td class="col-name">${f.name}${f.kind === 'meaning' ? html` <span class="t-dim" title="Its bytes are unchanged; it decodes differently because something it depends on changed">(same bytes)</span>` : ''}</td>
              <td class="col-offset">${typeof f.abs_offset === 'number' ? jump(f.abs_offset, f.size, f.name) : ''}</td>
              <td><span class="labs-raw">${mode === 'compare' ? '' : f.before.raw_hex}</span> <strong>${clip(f.before.interpreted || f.before.value, 90)}</strong></td>
              <td><span class="labs-raw">${mode === 'compare' ? '' : f.after.raw_hex}</span> <strong>${f.undecoded ? html`<span class="t-dim">${f.after.value || 'not decoded any more'}</span>` : clip(f.after.interpreted || f.after.value, 90)}</strong>
                ${(f.flags_set || []).map((x) => html`<span class="labs-flag-delta labs-flag-on" title="mask ${str(x.mask)}">+ ${x.name}</span>`)}
                ${(f.flags_cleared || []).map((x) => html`<span class="labs-flag-delta labs-flag-off" title="mask ${str(x.mask)}">− ${x.name}</span>`)}
              </td></tr>`)}
          </tbody>
        </table></div>
        ${total > fields.length ? html`<div class="labs-more">${total - fields.length} more changed fields not shown.</div>` : ''}
      </div>`;
  }

  function securitySection(list) {
    if (!list || !list.length) return '';
    const side = (c) => (c ? html`<span class="sec-status-pill sec-${/^(PASS|WARN|FAIL|INFO)$/.test(str(c.status)) ? c.status : 'INFO'}">${str(c.status)}</span> ${str(c.value)}` : html`<span class="t-dim">not reported</span>`);
    return html`
      <div class="panel-card">
        <div class="panel-card-header"><span>Hardening audit (${list.length})</span>${BS.state.doc ? nodeLink('security_audit', 'Open the audit') : ''}</div>
        <div class="struct-table-wrap"><table class="struct-table labs-table">
          <thead><tr><th>Check</th><th>Before</th><th>After</th></tr></thead>
          <tbody>${list.map((c) => html`<tr><td class="col-name">${str(c.title, c.id)}</td><td>${side(c.before)}</td><td>${side(c.after)}${c.after && c.after.detail ? html`<div class="t-dim labs-detail">${c.after.detail}</div>` : ''}</td></tr>`)}</tbody>
        </table></div>
        <div class="labs-more">The audit reads the file's headers. It reports what the file claims, which is not always what a loader does with it.</div>
      </div>`;
  }

  function entrySection(entry) {
    if (!entry) return '';
    const side = (e) => (e ? html`<strong class="mono">${e.vmaddr}</strong> ${e.mapped ? html`in ${str(e.segment)}${e.section ? html`, ${e.section}` : ''} <span class="prot-pill ${e.executable ? (str(e.prot).includes('w') ? 'rwx' : 'rx') : 'rw'}">${str(e.prot).toUpperCase()}</span>` : html`<span class="t-dim">not in any mapped segment</span>`}` : html`<span class="t-dim">none</span>`);
    return html`
      <div class="panel-card">
        <div class="panel-card-header"><span>Entry point</span>${BS.state.doc ? nodeLink('disassembly', 'Disassembly') : ''}</div>
        <div class="kv-list">
          <div class="kv-row"><span class="kv-key">Before</span><span class="kv-val">${side(entry.before)}</span></div>
          <div class="kv-row"><span class="kv-key">After</span><span class="kv-val">${side(entry.after)}</span></div>
        </div>
      </div>`;
  }

  function findingsSection(title, data, render) {
    if (!data || (!data.added.length && !data.removed.length)) return '';
    return html`
      <div class="panel-card">
        <div class="panel-card-header"><span>${title}</span></div>
        <div class="kv-list">
          ${data.added.map((f) => html`<div class="kv-row"><span class="kv-key labs-tag-new">new</span><span class="kv-val labs-wrap">${render(f)}</span></div>`)}
          ${data.removed.map((f) => html`<div class="kv-row"><span class="kv-key labs-tag-gone">gone</span><span class="kv-val labs-wrap">${render(f)}</span></div>`)}
        </div>
      </div>`;
  }

  function scalarSection(title, changes) {
    if (!changes || !changes.length) return '';
    return html`
      <div class="panel-card">
        <div class="panel-card-header"><span>${title} (${changes.length})</span></div>
        <div class="kv-list">${changes.map((c) => html`<div class="kv-row"><span class="kv-key">${propLabel(c.prop)}</span><span class="kv-val labs-ba labs-wrap">${beforeAfter(c.before, c.after)}</span></div>`)}</div>
      </div>`;
  }

  function namesSection(title, data, withChanged) {
    if (!data) return '';
    const n = (data.added_count || 0) + (data.removed_count || 0) + (data.changed_count || 0);
    if (!n) return '';
    const more = (shown, total) => (total > shown.length ? html` <span class="t-dim">and ${total - shown.length} more</span>` : '');
    return html`
      <div class="panel-card">
        <div class="panel-card-header"><span>${title}: ${data.before_count} → ${data.after_count}</span></div>
        <div class="kv-list">
          ${data.added_count ? html`<div class="kv-row"><span class="kv-key labs-tag-new">added (${data.added_count})</span><span class="kv-val labs-wrap mono">${data.added.map((x) => clip(x, 60)).join(', ')}${more(data.added, data.added_count)}</span></div>` : ''}
          ${data.removed_count ? html`<div class="kv-row"><span class="kv-key labs-tag-gone">removed (${data.removed_count})</span><span class="kv-val labs-wrap mono">${data.removed.map((x) => clip(x, 60)).join(', ')}${more(data.removed, data.removed_count)}</span></div>` : ''}
          ${withChanged && data.changed_count ? data.changed.map((c) => html`<div class="kv-row"><span class="kv-key mono">${clip(c.name, 40)}</span><span class="kv-val labs-ba labs-wrap">${beforeAfter(c.before, c.after)}</span></div>`) : ''}
        </div>
      </div>`;
  }

  function integritySection(items) {
    if (!items || !items.length) return '';
    const yes = (v) => (v === true ? html`<span class="sec-status-pill sec-PASS">matches</span>` : v === false ? html`<span class="sec-status-pill sec-FAIL">does not match</span>` : html`<span class="t-dim">—</span>`);
    return html`
      <div class="panel-card">
        <div class="panel-card-header"><span>Checksums and signature hashes</span>${BS.state.doc ? nodeLink('code_signature', 'Signature view') : ''}</div>
        ${items.map((item) => {
          if (item.kind === 'pe_checksum') {
            const b = item.before || {};
            const a = item.after || {};
            return html`<div class="struct-table-wrap"><table class="struct-table labs-table">
              <thead><tr><th>PE integrity</th><th>Before</th><th>After</th></tr></thead>
              <tbody>
                <tr><td class="col-name">CheckSum stored in the header ${typeof a.checksum_offset === 'number' ? jump(a.checksum_offset, 4, 'CheckSum') : ''}</td><td class="mono">${str(b.checksum_stored, '—')}</td><td class="mono">${str(a.checksum_stored, '—')}</td></tr>
                <tr><td class="col-name">Checksum computed from the file</td><td class="mono">${str(b.checksum_computed, '—')} ${yes(b.checksum_ok)}</td><td class="mono">${str(a.checksum_computed, '—')} ${yes(a.checksum_ok)}</td></tr>
                ${b.signed || a.signed ? html`<tr><td class="col-name">Authenticode image hash (SHA-256)</td><td class="mono labs-hash">${str(b.image_hash_sha256, '—')}</td><td class="mono labs-hash">${str(a.image_hash_sha256, '—')}</td></tr>
                <tr><td class="col-name">That hash is present in the signature</td><td>${b.signed ? (b.embedded_hash_matches ? yes(true) : html`<span class="t-dim">not found in the signature blob</span>`) : '—'}</td><td>${a.signed ? (a.embedded_hash_matches ? yes(true) : b.embedded_hash_matches ? yes(false) : html`<span class="t-dim">not found in the signature blob</span>`) : '—'}</td></tr>` : ''}
              </tbody></table></div>`;
          }
          if (item.kind === 'macho_pages') {
            if (item.summary) {
              return html`<div class="labs-more">${item.side === 'before' ? 'First' : 'Second'} file, ${item.slice}: ${item.summary.failing_count} of ${item.summary.checked} code pages do not match the CodeDirectory (pages ${item.summary.failing.join(', ')}${item.summary.failing_count > item.summary.failing.length ? ', …' : ''}).</div>`;
            }
            return html`<div class="struct-table-wrap"><table class="struct-table labs-table">
              <thead><tr><th>Code page (${item.slice})</th><th>File range</th><th>Before</th><th>After</th><th>Hash in CodeDirectory / hash of the page now</th></tr></thead>
              <tbody>${item.pages.map((p) => html`<tr>
                <td class="col-name">page ${p.page}</td><td>${jump(p.file_offset, p.size, `code page ${p.page}`, `${hx(p.file_offset)} +${hx(p.size)}`)}</td>
                <td>${yes(p.before_ok)}</td><td>${yes(p.after_ok)}</td>
                <td class="mono labs-hash">${p.expected}<br />${p.actual}</td></tr>`)}</tbody></table></div>
              ${item.page_count > item.pages.length ? html`<div class="labs-more">${item.page_count - item.pages.length} more pages changed.</div>` : ''}`;
          }
          if (item.kind === 'macho_signature_lost') {
            return html`<div class="labs-more">${item.slice}: the code signature can no longer be located, so no page can be checked against it.</div>`;
          }
          return '';
        })}
      </div>`;
  }

  function signatureSection(list) {
    if (!list || !list.length) return '';
    return html`
      <div class="panel-card">
        <div class="panel-card-header"><span>Signature as decoded (${list.length})</span></div>
        <div class="kv-list">${list.map((c) => html`<div class="kv-row"><span class="kv-key">${propLabel(c.prop)}</span><span class="kv-val labs-ba labs-wrap">${beforeAfter(c.before, c.after)}</span></div>`)}</div>
      </div>`;
  }

  function consequencesSection(notes) {
    if (!notes || !notes.length) return '';
    return html`
      <div class="panel-card labs-notes">
        <div class="panel-card-header"><span>What this means for a real loader</span></div>
        ${notes.map((n) => html`<div class="labs-note">
          <div class="labs-note-title">${n.title}</div>
          <p>${n.text}</p>
          <div class="labs-note-foot"><span class="t-dim">Basis: ${n.basis}. Stated from documentation and source, not by running the file.</span>
            ${(n.refs || []).map((r) => (typeof r.abs_offset === 'number' ? jump(r.abs_offset, r.size || 1, r.label, clip(r.label, 48)) : ''))}</div>
        </div>`)}
      </div>`;
  }

  function parseSection(diff) {
    const p = diff.parse || {};
    if (p.ok !== false) return '';
    const c = p.culprit;
    return html`
      <div class="panel-card labs-broken" role="alert">
        <div class="panel-card-header"><span>The patched file no longer parses</span>${act('undo', 'Undo', { title: 'Undo the last change (U)' })}</div>
        <div class="kv-list">
          <div class="kv-row"><span class="kv-key">Parser said</span><span class="kv-val labs-wrap">${str(p.error)}</span></div>
          ${c && typeof c.patch_index === 'number' ? html`<div class="kv-row"><span class="kv-key">${c.isolated ? 'First patch that breaks it' : 'Patch'}</span><span class="kv-val labs-wrap">#${c.patch_index + 1}${c.label ? html` (${c.label})` : ''} at ${jump(c.offset, c.size, 'patch')}</span></div>` : ''}
          ${c && c.structures && c.structures.length ? html`<div class="kv-row"><span class="kv-key">Structure it changed</span><span class="kv-val labs-wrap">${c.structures.map((s) => html`<span class="labs-culprit">${s.label} <span class="t-dim">(was ${clip(s.was, 40)})</span> ${jump(s.abs_offset, s.size, s.label)}</span>`)}</span></div>` : html`<div class="kv-row"><span class="kv-key">Structure it changed</span><span class="kv-val">The changed bytes are not inside a decoded header field.</span></div>`}
          <div class="kv-row"><span class="kv-key">Still available</span><span class="kv-val labs-wrap">The hex view and byte decoder show the patched bytes. Structure views are empty until the file parses again.</span></div>
        </div>
      </div>`;
  }

  function bytesSection(bytes) {
    if (!bytes || !bytes.ranges || !bytes.ranges.length) return '';
    return html`
      <div class="panel-card">
        <div class="panel-card-header"><span>Bytes (${plural(bytes.changed, 'byte')} in ${plural(bytes.ranges.length + (bytes.truncated || 0), 'run')})</span></div>
        <div class="struct-table-wrap"><table class="struct-table labs-table">
          <thead><tr><th>Offset</th><th>Length</th><th>Before</th><th>After</th><th>Inside</th></tr></thead>
          <tbody>${bytes.ranges.map((r) => html`<tr><td class="col-offset">${jump(r.offset, r.size, 'changed bytes')}</td><td>${r.size}</td><td class="col-bytes labs-was">${r.before}</td><td class="col-bytes labs-now">${r.after}</td><td>${r.node ? nodeLink(r.node, clip(r.where, 60)) : clip(r.where, 60)}</td></tr>`)}</tbody>
        </table></div>
        ${bytes.truncated ? html`<div class="labs-more">${bytes.truncated} more runs not shown.</div>` : ''}
      </div>`;
  }

  function summaryChips(diff) {
    const s = diff.summary || {};
    const chips = [];
    const add = (n, one, many) => { if (n) chips.push(plural(n, one, many)); };
    add(s.bytes, 'byte');
    add(s.fields, 'field');
    add(s.security, 'hardening check');
    add(s.segments, 'segment');
    add(s.sections, 'section');
    add(s.commands, 'header entry', 'header entries');
    add(s.entry, 'entry point change');
    add(s.integrity, 'integrity result');
    add(s.signature, 'signature property', 'signature properties');
    add(s.anomalies, 'anomaly', 'anomalies');
    add(s.warnings, 'parser warning');
    add(s.symbols, 'symbol');
    add(s.libraries, 'library', 'libraries');
    add(s.strings, 'string');
    if (!chips.length) return html`<div class="labs-chips"><span class="labs-chip">no structural difference</span></div>`;
    return html`<div class="labs-chips" aria-label="Summary of differences">${chips.map((c) => html`<span class="labs-chip">${c}</span>`)}</div>`;
  }

  function sliceSections(part, mode) {
    return html`
      ${securitySection(part.security)}
      ${fieldsSection(part.fields, part.fields_total, mode)}
      ${entrySection(part.entry)}
      ${recordSection('Segments', 'Segment', part.segments)}
      ${recordSection('Sections', 'Section', part.sections)}
      ${recordSection('Header entries', 'Entry', part.commands)}
      ${signatureSection(part.signature)}
      ${findingsSection('Anomalies', part.anomalies, (f) => html`<strong>${str(f.title)}</strong> <span class="t-dim">${str(f.detail)}</span>`)}
      ${findingsSection('Parser warnings', part.warnings, (f) => html`${str(f.message)}`)}
      ${scalarSection('Overview', part.overview)}
      ${scalarSection('Format metadata', part.metadata)}
      ${namesSection('Symbols', part.symbols, true)}
      ${namesSection('Linked libraries', part.libraries)}
      ${namesSection('Run paths', part.rpaths)}
      ${namesSection('Strings', part.strings)}`;
  }

  function diffMarkup(diff) {
    const mode = diff.mode;
    const slices = (diff.slices || []).filter((p) => p.status !== 'same');
    const multi = (diff.slices || []).length > 1;
    return html`
      ${parseSection(diff)}
      ${summaryChips(diff)}
      ${consequencesSection(diff.consequences)}
      ${integritySection(diff.integrity)}
      ${scalarSection('File', diff.file)}
      ${fieldsSection(diff.file_fields, (diff.file_fields || []).length, mode)}
      ${findingsSection('Container warnings', diff.file_warnings, (f) => html`${str(f.message)}`)}
      ${slices.map((part) => html`
        ${multi || mode === 'compare' || part.status !== 'changed' ? html`<h2 class="labs-slice-head">${part.label}${part.status === 'removed' ? ' · no longer a parseable slice' : part.status === 'added' ? ' · only in the second file' : part.status === 'unparsed' ? ' · not parsed' : ''}</h2>` : ''}
        ${part.status === 'added' ? '' : sliceSections(part, mode)}`)}
      ${mode === 'patch' || (diff.bytes && diff.bytes.comparable) ? bytesSection(diff.bytes) : html`<div class="labs-more">${diff.bytes && diff.bytes.why_not === 'large' ? 'The files are too large to be compared byte by byte here; the structural comparison above is complete.' : 'The two files differ in size, so they are not compared byte by byte.'}</div>`}`;
  }

  // ===========================================================================
  // View: Patch & observe
  // ===========================================================================
  const mounted = {}; // view id -> {bodyEl, ctx}
  // The inspector body is shared by every view. A render that awaits must check, when it
  // resumes, that it is still the one on screen; `live` changes whenever that stops being true.
  let live = 0;
  const current = (token) => () => token === live;

  function rerenderOpenView() {
    const id = BS.state.selectedNodeId;
    const m = mounted[id];
    if (!m || !document.body.contains(m.bodyEl)) return;
    const done = VIEWS[id](m.bodyEl, m.ctx, current(++live));
    if (done && typeof done.then === 'function') done.then(() => restoreFocus(m.bodyEl));
    else restoreFocus(m.bodyEl);
  }

  function renderPatchView(bodyEl) {
    const limit = BS.config.limits.max_patch_bytes;
    if (!canPatch()) {
      bodyEl.innerHTML = html`<div class="overview-container"><div class="panel-card"><div class="panel-card-header"><span>Patching is not available</span></div><div class="labs-prose"><p>${BS.state.doc ? 'This server has patching turned off.' : 'Open a binary first.'}</p></div></div></div>`;
      return;
    }
    const count = S ? S.patches.length : 0;
    const original = S && S.viewing === 'original' && count > 0;
    const toolbar = html`
      <div class="explorer-toolbar labs-toolbar">
        <div class="toolbar-facts">
          <span><strong>${plural(count, 'patch', 'patches')}</strong> · ${plural(patchedBytes(), 'byte')} of ${formatBytes(limit)} allowed</span>
          ${original ? html`<span class="labs-pill-warn">showing the original</span>` : ''}
        </div>
        <div class="toolbar-actions">
          ${act('toggle-edit', 'Edit bytes', { pressed: edit.on, title: 'Type hex digits over the bytes at the hex cursor (I)' })}
          ${act('fill', 'Fill selection…', { title: 'Fill the selected bytes with one value' })}
          ${act('undo', 'Undo', { disabled: !S || !S.undo.length, title: 'U' })}
          ${act('redo', 'Redo', { disabled: !S || !S.redo.length, title: 'Shift+U' })}
          ${act('toggle-original', original ? 'Show patched' : 'Show original', { disabled: !count, title: 'V' })}
          ${act('download', 'Download patched file', { disabled: !count })}
          ${act('export', 'Export patches', { disabled: !count, title: 'Save the patch list as a small JSON file' })}
          ${act('import', 'Import patches…', { title: 'Apply a patch list saved earlier' })}
          ${act('revert-all', 'Revert all', { disabled: !count, title: 'Remove every patch (undoable)' })}
        </div>
      </div>`;

    const list = count ? html`
      <div class="panel-card">
        <div class="panel-card-header"><span>Patches, in the order they are applied</span></div>
        <div class="struct-table-wrap"><table class="struct-table labs-table">
          <thead><tr><th>#</th><th>Offset</th><th>Bytes</th><th>Was</th><th>Now</th><th>What</th><th></th></tr></thead>
          <tbody>${S.patches.slice(0, PATCH_ROWS_SHOWN).map((p, i) => html`<tr>
            <td>${i + 1}</td><td class="col-offset">${jump(p.offset, p.hex.length >> 1, p.label || 'patch')}</td><td>${p.hex.length >> 1}</td>
            <td class="col-bytes labs-was">${clip(spaced(p.before), 48)}</td><td class="col-bytes labs-now">${clip(spaced(p.hex), 48)}</td>
            <td>${str(p.label, 'typed in the hex view')}</td>
            <td class="col-actions">${act('revert-one', 'Revert', { arg: i, title: 'Remove this patch (undoable)' })}</td></tr>`)}</tbody>
        </table></div>
        ${count > PATCH_ROWS_SHOWN ? html`<div class="labs-more">Showing the first ${PATCH_ROWS_SHOWN} of ${count} patches. Export the list to see all of them.</div>` : ''}
      </div>` : '';

    const intro = count ? '' : html`
      <div class="panel-card">
        <div class="panel-card-header"><span>Change bytes, see what it does</span></div>
        <div class="labs-prose">
          <p>Edits are made to a copy; the file you opened is never changed, and nothing is ever run. After each edit the copy is analysed again and this page shows exactly what is different: decoded fields, segment permissions, the hardening audit, signature hashes, and what a real loader would make of it.</p>
          <ul class="labs-ways">
            <li><strong>In the hex view:</strong> press <kbd>Enter</kbd> on a byte (or <kbd>I</kbd>), then type hex digits. Paste hex text to write several bytes. ${act('toggle-edit', 'Start editing')}</li>
            <li><strong>In a structure table:</strong> double-click a value, or press <kbd>F2</kbd> on a row, to set a field or toggle its flag bits. ${nodeLink('mach_header', 'Open the header')}</li>
            <li><strong>From a recipe:</strong> ${nodeLink(VIEW_EXPERIMENTS, 'Experiments')} apply a known change and say what to look at.</li>
          </ul>
          <p class="t-dim"><kbd>U</kbd> undoes, <kbd>Shift</kbd>+<kbd>U</kbd> redoes, <kbd>V</kbd> switches between the original and the patched copy. A patch set may change up to ${formatBytes(limit)} and never changes the size of the file.</p>
        </div>
      </div>`;

    const diff = S && S.diff && count ? diffMarkup(S.diff) : '';
    bodyEl.innerHTML = html`${toolbar}<div class="overview-container labs-view">${pendingImportMarkup()}${intro}${list}${diff}</div><input type="file" class="labs-offscreen" id="labs-import-input" accept=".json,application/json" tabindex="-1" aria-hidden="true" />`;
  }

  function exportPatches() {
    if (!S || !S.patches.length) return;
    const info = S.rootDoc.file_info || {};
    const payload = {
      format: PATCHSET_FORMAT,
      version: 1,
      target: { filename: str(info.filename), size: info.file_size, sha256: str(info.sha256) },
      patches: S.patches.map((p) => ({ offset: p.offset, hex: p.hex, label: p.label || '' })),
    };
    saveBlob(new TextEncoder().encode(`${JSON.stringify(payload, null, 2)}\n`), `${str(info.filename, 'binary')}.patches.json`, 'application/json');
  }

  async function importPatches(file) {
    if (!file || !canPatch()) return;
    if (file.size > 4 * 1024 * 1024) {
      BS.ui.toast('That file is too large to be a patch list.', 'warn');
      return;
    }
    let data;
    try {
      data = JSON.parse(await file.text());
    } catch {
      BS.ui.toast('That file is not JSON.', 'warn');
      return;
    }
    if (!canPatch()) return;
    startSession();
    const info = S.rootDoc.file_info || {};
    const checked = checkPatchSet(data, Number(info.file_size) || 0);
    if (checked.error) {
      BS.ui.toast(`Not imported. ${checked.error}`, 'warn');
      return;
    }
    const root = str(info.sha256).toLowerCase();
    const t = checked.target;
    const reason = !t || !t.sha256 ? 'unnamed' : root && t.sha256 !== root ? 'other' : '';
    if (!reason) {
      applyImported(checked.patches);
      return;
    }
    // Ask before applying, inline in the patch view: a list made for another file writes the same
    // offsets of this one, which is rarely what was meant.
    pendingImport = { rootId: S.rootId, patches: checked.patches, filename: t ? t.filename : '', reason };
    if (BS.state.selectedNodeId !== VIEW_PATCH) BS.nav.openView(VIEW_PATCH);
    else rerenderOpenView();
    document.querySelector('[data-labs-act="import-apply"]')?.focus();
  }

  async function applyImported(patches) {
    pendingImport = null;
    const ok = await setPatches(patches);
    if (ok) BS.ui.toast(`${plural(patches.length, 'patch', 'patches')} applied.`, 'ok');
    else rerenderOpenView();
    const active = document.activeElement;
    if (!active || active === document.body) document.querySelector('#inspector-body [data-labs-act="import"]')?.focus({ preventScroll: true });
  }

  function pendingImportMarkup() {
    const p = pendingImport;
    if (!p || !S || p.rootId !== S.rootId) return '';
    const one = p.patches.length === 1;
    const what = p.reason === 'other'
      ? html`${one ? 'This patch was' : `These ${p.patches.length} patches were`} made for ${p.filename ? html`<strong>${clip(p.filename, 60)}</strong>` : 'another file'}, which is not the open file (its SHA-256 differs). Applied here, ${one ? 'it writes the same offset' : 'they write the same offsets'} of this file.`
      : html`This list of ${plural(p.patches.length, 'patch', 'patches')} does not say which file it was made for, so it cannot be checked against the open file.`;
    return html`<div class="panel-card labs-import-confirm" role="group" aria-label="Imported patches">
        <div class="labs-prose"><p>${what}</p>
          <p class="labs-exp-actions">${act('import-apply', 'Apply anyway', { cls: 'btn' })} ${act('import-cancel', 'Discard', { cls: 'btn' })}</p></div>
      </div>`;
  }

  async function downloadPatched() {
    if (!S || !S.patches.length) return;
    if (deferTimer || S.unsent) sync();
    if (syncing) await syncing;
    if (!S || !S.currentId) return;
    try {
      const bytes = await BS.api.getBytes('/api/download', { doc: S.currentId, slice_index: null });
      saveBlob(bytes, str((S.currentDoc.file_info || {}).filename, 'patched.bin'));
    } catch (err) {
      BS.ui.toast(`Download failed. ${errorText(err)}`, 'error');
    }
  }

  function toggleOriginal() {
    if (!S || !S.patches.length || !S.currentDoc || syncing || deferTimer) return;
    edit.nibble = null;
    if (S.viewing === 'patched') {
      setEdit(false, true);
      showDoc(S.rootDoc);
    } else showDoc(S.currentDoc);
    rerenderOpenView();
  }

  // ===========================================================================
  // View: Experiments
  // ===========================================================================
  const expUi = { open: new Set(), data: null, forDoc: null, loading: false };

  function appliedExperimentPatches(exp) {
    if (!S) return [];
    const prefix = `${exp.title} · `;
    return S.patches.map((p, i) => (str(p.label).startsWith(prefix) ? i : -1)).filter((i) => i >= 0);
  }

  function experimentCard(exp, haveDoc) {
    const applied = appliedExperimentPatches(exp);
    const original = viewingOriginalWithPatches();
    const sample = (BS.state.presets || []).find((p) => p.id === exp.sample);
    const status = applied.length ? 'applied' : exp.applicable ? '' : haveDoc ? 'not applicable here' : '';
    return html`
      <details class="labs-exp" data-exp="${exp.id}" ${expUi.open.has(exp.id) ? html`open` : ''}>
        <summary><span class="labs-exp-title">${exp.title}</span><span class="labs-exp-fmt">${exp.format_name}</span>${status ? html`<span class="labs-exp-status ${applied.length ? 'labs-on' : ''}">${status}</span>` : ''}</summary>
        <div class="labs-exp-body">
          <p>${exp.setup}</p>
          ${exp.changes.length ? html`
            <div class="labs-exp-h">The change</div>
            <div class="struct-table-wrap"><table class="struct-table labs-table">
              <thead><tr><th>Where</th><th>Offset</th><th>Bytes before</th><th>Bytes after</th><th>Meaning</th></tr></thead>
              <tbody>${exp.changes.map((c) => html`<tr><td>${str(c.struct)}${c.field ? html` · <span class="col-name">${c.field}</span>` : ''}</td><td class="col-offset">${jump(c.offset, c.size, c.label)}</td><td class="col-bytes labs-was">${spaced(c.before_hex)}</td><td class="col-bytes labs-now">${spaced(c.hex)}</td><td>${c.flag ? html`${c.flag_set ? 'set' : 'clear'} ${c.flag} (${c.mask})` : c.before_value ? html`${c.before_value} → ${c.after_value}` : ''}</td></tr>`)}</tbody>
            </table></div>
            <div class="labs-exp-actions">
              ${act('exp-apply', 'Apply it', { cls: 'btn btn-accent', arg: exp.id, disabled: original })}
              ${act('exp-hand', 'Do it by hand', { cls: 'btn', arg: exp.id, disabled: original, title: 'Go to the bytes in the hex view with editing on; type the new bytes yourself' })}
            </div>` : ''}
          ${applied.length ? html`<div class="labs-exp-actions"><span class="labs-pill-ok">Applied.</span> ${nodeLink(VIEW_PATCH, 'See what changed')} ${act('exp-revert', 'Revert this experiment', { arg: exp.id })}</div>` : ''}
          ${!exp.applicable && !applied.length ? html`<div class="labs-exp-actions"><span class="t-dim">${exp.reason}</span> ${sample ? act('exp-sample', `Open the sample: ${str(sample.label, sample.id)}`, { arg: exp.id }) : ''}</div>` : ''}
          <div class="labs-exp-h">What to look at afterwards</div>
          <div class="labs-exp-look">${exp.look.map((l) => (haveDoc ? nodeLink(l.node, l.label) : html`<span class="labs-chip">${l.label}</span>`))}</div>
          <div class="labs-exp-h">What a real loader does with the result</div>
          ${exp.loader.map((n) => html`<p>${n.text}</p><p class="t-dim labs-basis">Basis: ${n.basis}. Stated from documentation and source; BinaryStudio never runs the file.</p>`)}
        </div>
      </details>`;
  }

  async function renderExperimentsView(bodyEl, ctx, isCurrent) {
    const docKey = BS.state.docId ? `${BS.state.docId}#${BS.state.activeSliceIndex}` : 'none';
    if (ctx && ctx.params && ctx.params.exp) expUi.open.add(String(ctx.params.exp));
    if (!expUi.data || expUi.forDoc !== docKey) {
      if (!expUi.data) bodyEl.innerHTML = html`<div class="overview-container"><div class="labs-more">Loading experiments…</div></div>`;
      try {
        const data = await BS.api.get('/api/labs/experiments', BS.state.docId ? {} : NO_DOC);
        if (!data || !Array.isArray(data.experiments) || data.experiments.length > 500
          || !data.experiments.every((e) => e && typeof e === 'object' && Array.isArray(e.changes) && Array.isArray(e.look) && Array.isArray(e.loader))) {
          throw new Error(UNEXPECTED);
        }
        expUi.data = data;
        expUi.forDoc = docKey;
        if (!isCurrent()) return;
      } catch (err) {
        if (!isCurrent()) return;
        bodyEl.innerHTML = html`<div class="overview-container"><div class="panel-card"><div class="panel-card-header"><span>Experiments could not be loaded</span></div><div class="labs-prose"><p>${errorText(err)}</p></div></div></div>`;
        return;
      }
    }
    const data = expUi.data;
    const haveDoc = Boolean(BS.state.doc);
    const here = data.experiments.filter((e) => e.format === data.format);
    const others = data.experiments.filter((e) => e.format !== data.format);
    const groups = {};
    others.forEach((e) => { (groups[e.format_name] = groups[e.format_name] || []).push(e); });
    bodyEl.innerHTML = html`
      <div class="overview-container labs-view">
        <div class="labs-prose labs-lead"><p>Each experiment changes a few bytes of a copy of the open file and then shows the difference. You can let it make the change or make it yourself in the hex view. Nothing is executed.</p>
          ${data.caveat ? html`<p class="labs-pill-warn">${data.caveat}</p>` : ''}
          ${viewingOriginalWithPatches() ? html`<p class="labs-pill-warn">You are looking at the original. Switch to the patched copy (V) to apply more.</p>` : ''}</div>
        ${here.length ? html`<h2 class="labs-slice-head">For this file (${here[0].format_name}${BS.state.doc && BS.state.doc.slices.length > 1 ? html`, ${str(BS.getActiveSlice().arch_name)} slice` : ''})</h2>${here.map((e) => experimentCard(e, haveDoc))}` : ''}
        ${Object.keys(groups).map((name) => html`<h2 class="labs-slice-head">${name}</h2>${groups[name].map((e) => experimentCard(e, haveDoc))}`)}
      </div>`;
  }

  function findExperiment(id) {
    return expUi.data ? expUi.data.experiments.find((e) => e.id === id) : null;
  }

  async function applyExperiment(id) {
    expUi.open.add(id);
    const ok = await resolveAndApply({ kind: 'experiment', id });
    if (ok) {
      expUi.data = null; // the catalogue is resolved against the document, which just changed
      BS.nav.openView(VIEW_PATCH);
    }
  }

  function experimentByHand(id) {
    const exp = findExperiment(id);
    if (!exp || !exp.changes.length) return;
    const c = exp.changes[0];
    setEdit(true);
    if (!edit.on) return;
    BS.nav.jumpToOffset(c.offset, c.size, c.label);
    edit.hint = `type ${spaced(c.hex)} here${exp.changes.length > 1 ? `, then ${exp.changes.slice(1).map((x) => `${spaced(x.hex)} at ${hx(x.offset)}`).join(', ')}` : ''}`;
    paintBar();
    hexViewport()?.focus({ preventScroll: true });
  }

  async function openExperimentSample(id) {
    const exp = findExperiment(id);
    if (!exp) return;
    expUi.open.add(id);
    const doc = await BS.openPreset(exp.sample);
    if (doc) BS.nav.openView(VIEW_EXPERIMENTS, { exp: id });
  }

  // ===========================================================================
  // View: Build a binary
  // ===========================================================================
  const build = { options: null, form: null, result: null, prevHex: '', timer: null, seq: 0 };

  function buildFormMarkup() {
    const o = build.options;
    const f = build.form;
    const arch = o.arches.find((a) => a.id === f.arch) || o.arches[0];
    const flag = (ch) => html`<label class="labs-check"><input type="checkbox" data-build="flag-${ch}" ${f.flags.includes(ch) ? html`checked` : ''} /> ${ch.toUpperCase()}</label>`;
    return html`
      <form class="labs-build-form" id="labs-build-form" autocomplete="off">
        <label><span>Architecture</span><select data-build="arch">${o.arches.map((a) => html`<option value="${a.id}" ${a.id === f.arch ? html`selected` : ''}>${a.label}</option>`)}</select></label>
        <label><span>File type</span><select data-build="type">${o.types.map((t) => html`<option value="${t.id}" ${t.id === f.type ? html`selected` : ''}>${t.label}</option>`)}</select></label>
        <label><span>Base address (p_vaddr)</span><input type="text" data-build="base" value="${f.base}" spellcheck="false" /></label>
        <label><span>Entry address (e_entry)</span><input type="text" data-build="entry" value="${f.entry}" placeholder="start of the payload" spellcheck="false" /></label>
        <fieldset><legend>Segment permissions (p_flags)</legend>${flag('r')}${flag('w')}${flag('x')}</fieldset>
        <label><span>Payload</span><select data-build="payload">${arch.payloads.map((p) => html`<option value="${p.id}" ${p.id === f.payload ? html`selected` : ''}>${p.label} (${p.bytes} bytes)</option>`)}</select></label>
        <fieldset><legend>Stack</legend>
          <label class="labs-check"><input type="checkbox" data-build="gnu_stack" ${f.gnu_stack ? html`checked` : ''} /> add PT_GNU_STACK</label>
          <label class="labs-check"><input type="checkbox" data-build="stack_exec" ${f.stack_exec ? html`checked` : ''} ${f.gnu_stack ? '' : html`disabled`} /> executable</label>
        </fieldset>
      </form>`;
  }

  function buildResultMarkup() {
    const r = build.result;
    if (!r) return html`<div class="labs-more">Building…</div>`;
    if (r.error) return html`<div class="panel-card labs-broken"><div class="panel-card-header"><span>Not built</span></div><div class="labs-prose"><p>${r.error}</p></div></div>`;
    const prev = build.prevHex;
    const bytes = [];
    // Regions were checked to lie inside the bytes received; draw at most BUILD_SHOW_BYTES cells.
    r.regions.forEach((region, idx) => {
      for (let i = 0; i < region.size && bytes.length < BUILD_SHOW_BYTES; i++) {
        const off = region.offset + i;
        const b = r.hex.substr(off * 2, 2);
        const changed = prev && prev.length === r.hex.length ? prev.substr(off * 2, 2) !== b : Boolean(prev) && prev.substr(off * 2, 2) !== b;
        bytes.push(html`<span class="labs-b ${groupClass(region.group)}${changed ? ' labs-b-changed' : ''}${off % 16 === 8 ? ' labs-b-gap' : ''}" data-region="${idx}" title="${hx(off)} ${region.name}">${b}</span>`);
      }
    });
    const shownNote = bytes.length < r.size ? html`<div class="labs-b-info">Showing the first ${bytes.length} of ${r.size} bytes.</div>` : '';
    const rows = [];
    for (let off = 0; off < bytes.length; off += 16) {
      rows.push(html`<div class="labs-b-row"><span class="labs-b-addr">${off.toString(16).padStart(4, '0')}</span>${bytes.slice(off, off + 16)}</div>`);
    }
    const v = r.verify || {};
    return html`
      <div class="labs-build-actions">
        ${act('build-open', 'Open in the viewer', { cls: 'btn btn-accent', title: 'Analyse the built file like any other binary' })}
        ${act('build-download', `Download ${r.filename}`, { cls: 'btn' })}
        <span class="t-dim">${r.size} bytes · sha256 ${r.sha256.slice(0, 16)}…</span>
      </div>
      <div class="labs-notes-list">${r.notes.map((n) => html`<p class="labs-bnote ${noteClass(n.level)}">${n.text}</p>`)}</div>
      <div class="panel-card">
        <div class="panel-card-header"><span>Every byte of the file</span></div>
        <div class="labs-legend" aria-hidden="true">${r.groups.map((g) => html`<span class="labs-b ${groupClass(g.id)} labs-legend-swatch">${g.label}</span>`)}</div>
        <div class="labs-bytes" id="labs-bytes" tabindex="0" aria-label="Hex dump of the built file. Fields are listed in the table below.">${rows}</div>${shownNote}
        <div class="labs-b-info" id="labs-b-info" aria-live="off">Point at a byte, or move through the table, to see which field it belongs to.${prev && prev !== r.hex ? ' Bytes that changed with your last edit are outlined.' : ''}</div>
      </div>
      <div class="panel-card">
        <div class="panel-card-header"><span>Fields</span><span class="t-dim">${v.ok ? `Read back by BinaryStudio's parser: ${str(v.format)} · ${str(v.type)} · ${str(v.machine)} · entry ${str(v.entry)} · ${(v.segments || []).map((s) => `${s.vmaddr} ${s.prot}`).join(', ')}` : `The parser rejects this file: ${str(v.error)}`}</span></div>
        <div class="struct-table-wrap"><table class="struct-table labs-table" id="labs-build-table">
          <thead><tr><th>Offset</th><th>Bytes</th><th>Field</th><th>Value</th><th>Meaning</th></tr></thead>
          <tbody>${r.groups.map((g) => html`
            <tr class="labs-group-row"><td colspan="5">${g.label} · offset ${g.offset}, ${g.size} bytes</td></tr>
            ${r.regions.map((region, idx) => (region.group === g.id ? html`<tr class="labs-region-row" data-region="${idx}" tabindex="-1">
              <td class="col-offset">${hx(region.offset, 4)}</td><td class="col-bytes">${spaced(region.hex)}</td><td class="col-name">${region.name}</td><td class="col-val">${region.value}</td><td>${region.meaning}</td></tr>` : ''))}`)}</tbody>
        </table></div>
      </div>`;
  }

  function highlightRegion(root, idx) {
    root.querySelectorAll('.labs-hot').forEach((n) => n.classList.remove('labs-hot'));
    if (idx === null || !build.result || !build.result.regions) return;
    root.querySelectorAll(`[data-region="${idx}"]`).forEach((n) => n.classList.add('labs-hot'));
    const region = build.result.regions[idx];
    const info = root.querySelector('#labs-b-info');
    if (info && region) info.textContent = `${hx(region.offset, 4)} · ${region.name} = ${region.value} · ${region.meaning}`;
  }

  async function runBuild(bodyEl) {
    const seq = ++build.seq;
    const f = build.form;
    BS.storage.set('labs.build.form', f);
    let result;
    try {
      result = await BS.api.post('/api/labs/build', { format: 'elf64', arch: f.arch, type: f.type, base: f.base, entry: f.entry, flags: f.flags, payload: f.payload, gnu_stack: f.gnu_stack, stack_exec: f.stack_exec }, NO_DOC);
    } catch (err) {
      result = { error: errorText(err) };
    }
    if (seq !== build.seq) return;
    if (!result.error) result = checkBuildResponse(result);
    build.prevHex = build.result && build.result.hex ? build.result.hex : '';
    build.result = result;
    const out = bodyEl.querySelector('#labs-build-out');
    if (out) out.innerHTML = buildResultMarkup();
  }

  function readBuildForm(bodyEl) {
    const get = (name) => bodyEl.querySelector(`[data-build="${name}"]`);
    const f = build.form;
    const prevArch = f.arch;
    const prevType = f.type;
    f.arch = get('arch').value;
    f.type = get('type').value;
    f.base = get('base').value.trim();
    f.entry = get('entry').value.trim();
    f.flags = ['r', 'w', 'x'].filter((ch) => get(`flag-${ch}`).checked).join('');
    f.payload = get('payload').value;
    f.gnu_stack = get('gnu_stack').checked;
    f.stack_exec = f.gnu_stack && get('stack_exec').checked;
    let redraw = false;
    if (f.arch !== prevArch) {
      const arch = build.options.arches.find((a) => a.id === f.arch);
      if (arch && !arch.payloads.some((p) => p.id === f.payload)) f.payload = arch.payloads[0].id;
      redraw = true;
    }
    if (f.type !== prevType) {
      // The conventional base differs: 0 for a file the loader may place anywhere.
      if (f.type === 'dyn' && /^0x0*400000$/i.test(f.base)) f.base = '0x0';
      if (f.type === 'exec' && /^(0x)?0+$/i.test(f.base)) f.base = '0x400000';
      redraw = true;
    }
    return redraw;
  }

  async function renderBuildView(bodyEl, _ctx, isCurrent) {
    if (!build.options) {
      bodyEl.innerHTML = html`<div class="overview-container"><div class="labs-more">Loading…</div></div>`;
      try {
        const options = await BS.api.get('/api/labs/build/options', NO_DOC);
        const named = (list, more) => Array.isArray(list) && list.length > 0 && list.length <= 32 && list.every((x) => x && typeof x.id === 'string' && typeof x.label === 'string' && (!more || more(x)));
        if (!options || !named(options.types) || !named(options.arches, (a) => named(a.payloads)) || !options.defaults || typeof options.defaults !== 'object') throw new Error(UNEXPECTED);
        build.options = build.options || options;
        if (!isCurrent()) return;
      } catch (err) {
        if (!isCurrent()) return;
        bodyEl.innerHTML = html`<div class="overview-container"><div class="panel-card"><div class="panel-card-header"><span>The builder could not be loaded</span></div><div class="labs-prose"><p>${errorText(err)}</p></div></div></div>`;
        return;
      }
    }
    if (!build.form) {
      const saved = BS.storage.get('labs.build.form', null);
      // Only the known form keys are taken from the server's defaults and from storage.
      const pick = (o) => (o && typeof o === 'object' ? o : {});
      const d = pick(build.options.defaults);
      const v = pick(saved);
      const take = (k) => (Object.prototype.hasOwnProperty.call(v, k) ? v[k] : d[k]);
      build.form = {};
      ['arch', 'type', 'base', 'entry', 'flags', 'payload'].forEach((k) => { build.form[k] = str(typeof take(k) === 'string' ? take(k) : ''); });
      build.form.gnu_stack = take('gnu_stack') === true;
      build.form.stack_exec = take('stack_exec') === true;
    }
    bodyEl.innerHTML = html`
      <div class="overview-container labs-view">
        <div class="labs-prose labs-lead"><p>A complete ELF64 executable is an ELF header, one program header and some machine code: under 200 bytes. Change the form and watch which bytes move. The payloads are fixed, pre-assembled snippets shown as bytes with their disassembly; BinaryStudio never runs them.</p></div>
        <div class="panel-card"><div class="panel-card-header"><span>Minimal ELF64 for Linux</span></div><div id="labs-build-form-wrap">${buildFormMarkup()}</div></div>
        <div id="labs-build-out">${buildResultMarkup()}</div>
      </div>`;
    const wrap = bodyEl.querySelector('#labs-build-form-wrap');
    const changed = (immediate) => {
      const focused = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.build : null;
      if (readBuildForm(bodyEl)) {
        wrap.innerHTML = buildFormMarkup();
        if (focused) wrap.querySelector(`[data-build="${focused}"]`)?.focus();
      }
      clearTimeout(build.timer);
      build.timer = setTimeout(() => runBuild(bodyEl), immediate ? 0 : 180);
    };
    wrap.addEventListener('change', () => changed(true));
    wrap.addEventListener('input', (e) => {
      if (e.target.matches('input[type="text"]')) changed(false);
    });
    wrap.addEventListener('submit', (e) => e.preventDefault());
    const out = bodyEl.querySelector('#labs-build-out');
    const regionOf = (e) => {
      const node = e.target.closest('[data-region]');
      return node ? Number(node.dataset.region) : null;
    };
    out.addEventListener('mouseover', (e) => {
      const idx = regionOf(e);
      if (idx !== null) highlightRegion(out, idx);
    });
    out.addEventListener('focusin', (e) => {
      const idx = regionOf(e);
      if (idx !== null) highlightRegion(out, idx);
    });
    out.addEventListener('click', (e) => {
      const idx = regionOf(e);
      if (idx === null) return;
      highlightRegion(out, idx);
      const row = out.querySelector(`tr.labs-region-row[data-region="${idx}"]`);
      if (row && !e.target.closest('tr')) row.scrollIntoView({ block: 'nearest' });
    });
    out.addEventListener('keydown', (e) => {
      // Arrow keys walk the field table; the matching bytes light up.
      const row = e.target.closest && e.target.closest('tr.labs-region-row');
      const rows = Array.from(out.querySelectorAll('tr.labs-region-row'));
      if (!rows.length) return;
      let next = null;
      if (e.target.id === 'labs-bytes' && (e.key === 'ArrowDown' || e.key === 'Enter')) next = rows[0];
      else if (row && e.key === 'ArrowDown') next = rows[rows.indexOf(row) + 1];
      else if (row && e.key === 'ArrowUp') next = rows[rows.indexOf(row) - 1];
      if (next) {
        e.preventDefault();
        next.focus();
      }
    });
    runBuild(bodyEl);
  }

  // ===========================================================================
  // View: Compare
  // ===========================================================================


  BS.on('doc:loaded', ({ doc, docId }) => {
    if (!docId || (S && (docId === S.currentId))) return; // patched copies are offered as "patched copy"
    const info = doc.file_info || {};
    compare.recent.delete(docId);
    compare.recent.set(docId, { id: docId, label: `${str(info.filename, 'binary')} · ${str(info.format_display || info.format)}` });
    while (compare.recent.size > 8) compare.recent.delete(compare.recent.keys().next().value);
  });
  BS.on('doc:renewed', ({ oldId, docId }) => {
    const item = compare.recent.get(oldId);
    if (item) {
      compare.recent.delete(oldId);
      compare.recent.set(docId, Object.assign(item, { id: docId }));
    }
    if (compare.a === oldId) compare.a = docId;
    if (compare.b === oldId) compare.b = docId;
  });

  function compareOptions() {
    const options = [];
    const seen = new Set();
    const add = (id, label) => {
      if (id && !seen.has(id)) {
        seen.add(id);
        options.push({ id, label });
      }
    };
    if (S && S.patches.length && S.currentId) {
      add(S.rootId, `Original · ${str((S.rootDoc.file_info || {}).filename)}`);
      add(S.currentId, `Patched copy · ${str((S.currentDoc.file_info || {}).filename)}`);
    } else if (BS.state.docId) add(BS.state.docId, `Open document · ${str((BS.state.doc.file_info || {}).filename)}`);
    Array.from(compare.recent.values()).reverse().forEach((r) => add(r.id, `Opened earlier · ${r.label}`));
    (BS.state.presets || []).filter((p) => p.exists !== false && p.doc).forEach((p) => add(p.doc, `Sample · ${str(p.label, p.id)}`));
    return options;
  }

  async function runCompare(bodyEl) {
    const seq = ++compare.seq;
    const key = `${compare.a}|${compare.b}`;
    if (!compare.a || !compare.b) {
      compare.diff = null;
      compare.error = '';
      compare.key = key;
    } else if (compare.a === compare.b) {
      compare.diff = null;
      compare.error = 'Choose two different documents.';
      compare.key = key;
    } else if (compare.key !== key) {
      try {
        const res = await BS.api.get('/api/labs/compare', { a: compare.a, b: compare.b, doc: null, slice_index: null });
        if (seq !== compare.seq) return;
        compare.diff = res.diff;
        compare.error = '';
      } catch (err) {
        if (seq !== compare.seq) return;
        compare.diff = null;
        compare.error = errorText(err);
      }
      compare.key = key;
    }
    const out = bodyEl.querySelector('#labs-compare-out');
    if (out) out.innerHTML = compareResultMarkup();
  }

  function compareResultMarkup() {
    if (compare.error) return html`<div class="panel-card"><div class="panel-card-header"><span>Nothing to compare</span></div><div class="labs-prose"><p>${compare.error}</p></div></div>`;
    const d = compare.diff;
    if (!d) return html`<div class="labs-more">Choose a second document: a sample, a file opened earlier in this tab, or another file.</div>`;
    const side = (s) => html`<strong>${str(s.filename)}</strong> · ${str(s.format)} · ${formatBytes(s.size)} · ${(s.slices || []).join(', ')}${s.parsed ? '' : ' · unparsed'}<br /><span class="mono t-dim">sha256 ${str(s.sha256).slice(0, 32)}…</span>`;
    return html`
      <div class="panel-card">
        <div class="kv-list">
          <div class="kv-row"><span class="kv-key">First (before)</span><span class="kv-val labs-wrap">${side(d.before)}</span></div>
          <div class="kv-row"><span class="kv-key">Second (after)</span><span class="kv-val labs-wrap">${side(d.after)}</span></div>
        </div>
      </div>
      ${d.identical ? html`<div class="labs-more">The two documents hold the same bytes.</div>` : ''}
      ${diffMarkup(d)}`;
  }

  function renderCompareView(bodyEl, ctx) {
    const options = compareOptions();
    const has = (id) => options.some((o) => o.id === id);
    if (ctx && ctx.params && ctx.params.b && has(ctx.params.b)) compare.b = ctx.params.b;
    if (S && S.patches.length && S.currentId && (!has(compare.a) || !has(compare.b) || compare.auto)) {
      compare.a = S.rootId;
      compare.b = S.currentId;
      compare.auto = true;
    } else {
      if (!has(compare.a)) compare.a = BS.state.docId || (options[0] && options[0].id) || null;
      if (!has(compare.b) || compare.auto) compare.b = null;
      compare.auto = false;
    }
    const select = (which, value) => html`<label><span>${which === 'a' ? 'First (before)' : 'Second (after)'}</span><select data-compare="${which}">${value ? '' : html`<option value="" selected>Choose a document…</option>`}${options.map((o) => html`<option value="${o.id}" ${o.id === value ? html`selected` : ''}>${clip(o.label, 70)}</option>`)}</select></label>`;
    bodyEl.innerHTML = html`
      <div class="overview-container labs-view">
        <div class="panel-card"><div class="panel-card-header"><span>Compare two documents structurally</span></div>
          <form class="labs-compare-form" id="labs-compare-form">
            ${select('a', compare.a)}
            ${act('compare-swap', 'Swap', { title: 'Swap first and second' })}
            ${select('b', compare.b)}
            ${BS.config.features.upload ? act('compare-upload', 'Add a file…', { title: 'Upload another file to compare with; the open document stays open' }) : ''}
            <input type="file" class="labs-offscreen" id="labs-compare-input" tabindex="-1" aria-hidden="true" />
          </form>
          <div class="labs-more">Structures are paired by name (segments, sections, header entries, symbols) and by architecture for universal files. Uploaded files are compared on the server like any open document and are not kept longer.</div>
        </div>
        <div id="labs-compare-out">${compare.key === `${compare.a}|${compare.b}` ? compareResultMarkup() : html`<div class="labs-more">Comparing…</div>`}</div>
      </div>`;
    bodyEl.querySelector('#labs-compare-form').addEventListener('change', (e) => {
      const which = e.target.dataset.compare;
      if (which) {
        compare[which] = e.target.value || null;
        compare.auto = false;
        runCompare(bodyEl);
      }
      if (e.target.id === 'labs-compare-input' && e.target.files && e.target.files[0]) uploadForCompare(e.target.files[0]);
    });
    runCompare(bodyEl);
  }

  async function uploadForCompare(file) {
    const limit = BS.config.limits.max_upload_bytes;
    if (file.size > limit) {
      BS.ui.toast(`${clip(file.name, 40)} is ${formatBytes(file.size)}; the limit here is ${formatBytes(limit)}.`, 'warn');
      return;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const doc = await BS.api.post('/api/upload', bytes, NO_DOC, { headers: { 'X-Filename': encodeURIComponent(file.name) } });
      const info = doc.file_info || {};
      compare.recent.set(doc.doc_id, { id: doc.doc_id, label: `${str(info.filename, 'binary')} · ${str(info.format_display || info.format)}` });
      compare.b = doc.doc_id;
      compare.auto = false;
      rerenderOpenView();
    } catch (err) {
      BS.ui.toast(`Could not add ${clip(file.name, 40)}. ${errorText(err)}`, 'error');
    }
  }

  // ===========================================================================
  // Actions (delegated), commands, registration
  // ===========================================================================
  const ACTIONS = {
    'toggle-edit': () => setEdit(!edit.on),
    'open-patch': () => BS.nav.openView(VIEW_PATCH),
    undo,
    redo,
    'toggle-original': toggleOriginal,
    retry: () => sync(),
    download: downloadPatched,
    'revert-all': revertAll,
    'revert-one': (arg) => revertOne(Number(arg)),
    export: exportPatches,
    import: () => document.getElementById('labs-import-input')?.click(),
    'import-apply': () => {
      if (pendingImport && S && pendingImport.rootId === S.rootId) applyImported(pendingImport.patches);
    },
    'import-cancel': () => {
      pendingImport = null;
      rerenderOpenView();
      document.querySelector('[data-labs-act="import"]')?.focus();
    },
    fill: () => {
      if (!canPatch() || refuseWhileOriginal()) return;
      fillOpen = true;
      paintBar();
    },
    'fe-cancel': (_arg, btn) => {
      const row = btn.closest('tr').previousElementSibling;
      closeFieldEditor();
      if (row) row.focus();
    },
    'fe-flag': (arg, btn) => {
      const form = btn.closest('.labs-fe');
      const offset = Number(form.dataset.offset);
      const size = Number(form.dataset.size);
      const name = form.dataset.name;
      editorState = { offset, size, name, focusFlag: arg };
      resolveAndApply({ kind: 'flag', offset, size, name, flag: arg, set: btn.getAttribute('aria-pressed') !== 'true' }).then((ok) => {
        if (!ok) editorState = null;
      });
    },
    'exp-apply': (arg) => applyExperiment(arg),
    'exp-hand': (arg) => experimentByHand(arg),
    'exp-sample': (arg) => openExperimentSample(arg),
    'exp-revert': (arg) => {
      const exp = findExperiment(arg);
      const drop = exp ? new Set(appliedExperimentPatches(exp)) : new Set();
      if (drop.size) {
        expUi.data = null;
        setPatches(S.patches.filter((_, i) => !drop.has(i)));
      }
    },
    'build-open': async () => {
      const r = build.result;
      if (r && r.hex) await BS.loadBytes(r.filename, hexToBytes(r.hex));
    },
    'build-download': () => {
      const r = build.result;
      if (r && r.hex) saveBlob(hexToBytes(r.hex), r.filename);
    },
    'compare-swap': () => {
      [compare.a, compare.b] = [compare.b, compare.a];
      compare.auto = false;
      rerenderOpenView();
    },
    'compare-upload': () => document.getElementById('labs-compare-input')?.click(),
  };

  document.addEventListener('click', (e) => {
    const target = e.target.closest ? e.target.closest('[data-labs-act], [data-labs-jump], [data-labs-node]') : null;
    if (!target) return;
    if (target.dataset.labsAct) {
      const fn = ACTIONS[target.dataset.labsAct];
      if (fn && !target.disabled) {
        e.preventDefault();
        lastAct = { act: target.dataset.labsAct, arg: str(target.dataset.labsArg), at: Date.now(), inBar: Boolean(target.closest('#labs-bar')) };
        fn(target.dataset.labsArg, target);
      }
    } else if (target.dataset.labsJump !== undefined) {
      e.preventDefault();
      if (BS.state.doc) BS.nav.jumpToOffset(Number(target.dataset.labsJump), Number(target.dataset.labsSize) || 1, target.dataset.labsLabel);
    } else if (target.dataset.labsNode) {
      e.preventDefault();
      if (!BS.nav.selectNode(target.dataset.labsNode)) BS.ui.toast('That view is not available for this document.', 'info');
    }
  });

  document.addEventListener('change', (e) => {
    if (e.target.id === 'labs-import-input' && e.target.files && e.target.files[0]) {
      importPatches(e.target.files[0]);
      e.target.value = '';
    }
  });

  document.addEventListener('toggle', (e) => {
    const card = e.target;
    if (card && card.classList && card.classList.contains('labs-exp')) {
      if (card.open) expUi.open.add(card.dataset.exp);
      else expUi.open.delete(card.dataset.exp);
    }
  }, true);

  document.addEventListener('paste', onPaste);

  const VIEWS = {
    [VIEW_PATCH]: renderPatchView,
    [VIEW_EXPERIMENTS]: renderExperimentsView,
    [VIEW_BUILD]: renderBuildView,
    [VIEW_COMPARE]: renderCompareView,
  };

  function view(id, title, order, requiresDoc, subtitle, icon) {
    return BS.registerView({
      id, title, group: 'Labs', order, requiresDoc, subtitle, icon,
      render(bodyEl, ctx) {
        mounted[id] = { bodyEl, ctx };
        const done = VIEWS[id](bodyEl, ctx, current(++live));
        if (done && typeof done.then === 'function') return done.then(() => restoreFocus(bodyEl));
        restoreFocus(bodyEl);
        return done;
      },
      dispose() {
        live++;
        delete mounted[id];
        if (id === VIEW_BUILD) clearTimeout(build.timer);
      },
    });
  }
  patchViewHandle = view(VIEW_PATCH, 'Patch & observe', 10, true, 'Edit bytes of a copy and see what changes', 'PAT');
  view(VIEW_EXPERIMENTS, 'Experiments', 20, false, 'Guided changes and what real loaders do with them', 'EXP');
  view(VIEW_BUILD, 'Build a binary', 30, false, 'A minimal ELF64, byte by byte', 'NEW');
  view(VIEW_COMPARE, 'Compare', 40, false, 'Two documents side by side, structurally', 'CMP');

  const typing = () => {
    const a = document.activeElement;
    return Boolean(a && (a.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)));
  };
  const hasDoc = () => Boolean(BS.state.doc);
  const cmd = (id, title, shortcut, run, when, hint, keywords) => BS.registerCommand({ id, title, shortcut, run, when, hint, keywords, section: 'Labs' });
  cmd('labs.patch.edit', 'Edit bytes in the hex view', 'I', () => setEdit(!edit.on), canPatch, 'Type hex digits over the bytes at the cursor; Esc stops', 'patch overwrite modify write hex');
  cmd('labs.patch.undo', 'Undo patch', ['U', 'Mod+Z'], undo, () => Boolean(S && S.undo.length) && !typing(), '', 'revert');
  cmd('labs.patch.redo', 'Redo patch', ['Shift+U', 'Mod+Shift+Z'], redo, () => Boolean(S && S.redo.length) && !typing());
  cmd('labs.patch.toggle', 'Switch between original and patched copy', 'V', toggleOriginal, () => Boolean(S && S.patches.length && S.currentDoc), '', 'before after compare peek');
  cmd('labs.patch.fill', 'Fill the selection with a byte…', null, () => ACTIONS.fill(), canPatch, 'Uses the highlighted range in the hex view', 'nop zero overwrite');
  cmd('labs.patch.revert', 'Revert all patches', null, revertAll, () => Boolean(S && S.patches.length));
  cmd('labs.patch.download', 'Download the patched file', null, downloadPatched, () => Boolean(S && S.currentId));
  cmd('labs.patch.export', 'Export the patch list (JSON)', null, exportPatches, () => Boolean(S && S.patches.length));
  cmd('labs.patch.open', 'Labs: Patch & observe', null, () => BS.nav.openView(VIEW_PATCH), hasDoc, 'The patch list and what changed', 'diff changes');
  cmd('labs.experiments.open', 'Labs: Experiments', null, () => BS.nav.openView(VIEW_EXPERIMENTS), null, 'Guided changes: W^X, executable stack, PIE, RELRO, signatures…', 'guided lab try');
  cmd('labs.build.open', 'Labs: Build a minimal ELF', null, () => BS.nav.openView(VIEW_BUILD), null, 'Construct a tiny executable from a form', 'create new elf builder');
  cmd('labs.compare.open', 'Labs: Compare two documents', null, () => BS.nav.openView(VIEW_COMPARE), null, 'Structural diff of two files', 'diff before after');

  BS.on('ready', () => {
    const viewport = hexViewport();
    if (viewport) viewport.addEventListener('keydown', onHexKeydown, true);
    const rows = document.getElementById('hex-rows-container');
    if (rows) new MutationObserver(echo).observe(rows, { childList: true });
    paintBar();
  });
})();
