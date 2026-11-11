/**
 * BinaryStudio — Learn: curriculum, glossary, tours, field reference, and the Learn-mode
 * affordances inside the analysis views (term help, instruction help, idiom labels).
 *
 * All content is data served by /api/learn/* (see backend/learn_content.py for the format).
 * This file only renders it and talks to the core through window.BinaryStudio.
 *
 * Views (group "Learn"):  learn.home (learning path; ?c=<concept id> opens a concept),
 *   learn.tours, learn.glossary (?t=<term id>, ?q=<filter>), learn.compare, learn.fields.
 * Storage:  'learn.progress'  {concepts: {id: timestamp}, tours: {id: {step, solved, done}}, last}
 *
 * Security: every string is escaped on the way into the DOM. Rich text is tokenised first and
 * each piece escaped (rich()); document-derived values only ever pass through BS.util.html,
 * rich() or textContent. No inline styles or handlers.
 */
(() => {
  'use strict';

  const BS = window.BinaryStudio;
  if (!BS || typeof BS.registerView !== 'function') return;
  const { html: h, raw, escapeHtml: esc } = BS.util;

  const VIEW_HOME = 'learn.home';
  const VIEW_TOURS = 'learn.tours';
  const VIEW_GLOSSARY = 'learn.glossary';
  const VIEW_COMPARE = 'learn.compare';
  const VIEW_FIELDS = 'learn.fields';
  const FORMATS = [['macho', 'Mach-O'], ['elf', 'ELF'], ['pe', 'PE']];
  const FORMAT_NAME = { macho: 'Mach-O', elf: 'ELF', pe: 'PE' };
  const LEVELS = { 1: 'First contact', 2: 'Working knowledge', 3: 'Advanced' };
  const PROGRESS_KEY = 'learn.progress';
  // Server values never become class names directly: levels map through this allow-list.
  const levelNum = (v) => (v === 1 || v === 2 || v === 3 ? v : 0);
  const levelName = (v) => (levelNum(v) ? LEVELS[v] : '');
  // Bounds on server-supplied content (a malformed or hostile response cannot hang the tab).
  const MAX_TERMS = 2000;
  const MAX_TERM_KEYS = 6000;

  // ===========================================================================
  // Content loading (each resource is fetched once)
  // ===========================================================================
  const cache = new Map();
  function load(key, route, params) {
    if (!cache.has(key)) {
      const req = BS.api.get(route, Object.assign({ doc: null, slice_index: null }, params)).catch((err) => {
        cache.delete(key);
        throw err;
      });
      cache.set(key, req);
    }
    return cache.get(key);
  }

  let I = null; // index: {modules, concepts, tours, counts, byId: Map, tourById: Map}
  let G = null; // glossary: {terms, byId: Map, re: RegExp, strings: Map}
  let X = null; // instructions: {mnemonics, conditions, idioms}

  function getIndex() {
    return load('index', '/api/learn/index').then((data) => {
      if (!I) {
        // Server data: each list is checked once here (entries need a string id; tours a list of
        // formats), bounded in length, and copied field by field into the index the views use.
        const d = data && typeof data === 'object' ? data : {};
        const list = (v, ok) => (Array.isArray(v) ? v.slice(0, 2000) : []).filter((x) => x && typeof x === 'object' && typeof x.id === 'string' && x.id && (!ok || ok(x)));
        const modules = list(d.modules);
        const concepts = list(d.concepts);
        const tours = list(d.tours, (t) => Array.isArray(t.formats) && t.formats.every((f) => typeof f === 'string'));
        I = {
          modules, concepts, tours, counts: d.counts && typeof d.counts === 'object' ? d.counts : {},
          byId: new Map(concepts.map((c) => [c.id, c])),
          tourById: new Map(tours.map((t) => [t.id, t])),
        };
      }
      return I;
    });
  }

  const reEscape = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  function getGlossary() {
    return load('glossary', '/api/learn/glossary').then((data) => {
      if (!G) {
        // Server data: keep only well-formed terms, and only non-empty string match keys, so the
        // decoration regex never has an empty alternative (which would match everywhere).
        const terms = (Array.isArray(data && data.terms) ? data.terms : [])
          .filter((t) => t && typeof t === 'object' && typeof t.id === 'string' && t.id && typeof t.term === 'string')
          .slice(0, MAX_TERMS);
        const strings = new Map();
        terms.forEach((t) => (Array.isArray(t.match) ? t.match.slice(0, 32) : []).forEach((m) => {
          if (typeof m === 'string' && m.trim().length >= 2 && m.length <= 80 && !strings.has(m) && strings.size < MAX_TERM_KEYS) strings.set(m, t.id);
        }));
        const keys = [...strings.keys()].sort((a, b) => b.length - a.length);
        G = {
          terms,
          byId: new Map(terms.map((t) => [t.id, t])),
          strings,
          re: keys.length ? new RegExp(keys.map(reEscape).join('|'), 'g') : null,
        };
      }
      return G;
    });
  }

  // ---- idiom patterns ------------------------------------------------------------------------
  // /api/learn/instructions ships idiom steps as mnemonic lists and simple patterns (see
  // backend/learn/instructions.py, IDIOMS), never as regular expressions: nothing received over
  // the wire is compiled. A pattern is literal text plus `*` at either end and the tokens below;
  // every token takes the longest run it can and never backtracks, so a match costs at most
  // len(pattern) x len(text), and annotate() also stops after a fixed amount of work.
  const PAT_CLASSES = new Set(['{n}', '{hex}', '{imm}', '{w}', '{w=}']);
  const IDIOM_CAPS = { idioms: 100, steps: 8, names: 16, alts: 8, pattern: 120, gap: 16, text: 512, work: 3000000 };
  const isDigit = (c) => c >= '0' && c <= '9';
  const isHex = (c) => isDigit(c) || (c >= 'a' && c <= 'f');
  const isWord = (c) => isDigit(c) || (c >= 'a' && c <= 'z') || c === '_';

  /** Same as instructions.py normalise(): lower case, single spaces, no space after a comma. */
  const normaliseInsnText = (v) => str(v).toLowerCase().split(/\s+/).filter(Boolean).join(' ').split(', ').join(',').slice(0, IDIOM_CAPS.text);

  /** {anywhere, prefix, tokens} or null (same grammar as instructions.py parse_pattern()). */
  function parsePattern(p) {
    if (typeof p !== 'string' || !p || p.length > IDIOM_CAPS.pattern || p !== p.toLowerCase()) return null;
    const anywhere = p.startsWith('*');
    let body = anywhere ? p.slice(1) : p;
    const prefix = body.endsWith('*');
    if (prefix) body = body.slice(0, -1);
    const tokens = [];
    for (let i = 0; i < body.length;) {
      if (body[i] === '{') {
        const j = body.indexOf('}', i);
        const tok = j < 0 ? '' : body.slice(i, j + 1);
        if (!PAT_CLASSES.has(tok)) return null;
        tokens.push(tok);
        i = j + 1;
      } else if (body[i] === '*' || body[i] === '}') {
        return null;
      } else {
        tokens.push(body[i]);
        i += 1;
      }
    }
    return { anywhere, prefix, tokens };
  }

  let idiomWork = 0; // token comparisons left for the current annotate() call

  /** End position if the tokens match text at pos, else -1. */
  function matchFrom(tokens, text, pos) {
    let word = null;
    const end = text.length;
    for (const tok of tokens) {
      idiomWork -= 1;
      if (tok.length === 1) {
        if (pos < end && text[pos] === tok) {
          pos += 1;
          continue;
        }
        return -1;
      }
      if (tok === '{w=}') {
        if (word === null || !text.startsWith(word, pos)) return -1;
        pos += word.length;
        continue;
      }
      const start = pos;
      if ((tok === '{hex}' || tok === '{imm}') && text.startsWith('0x', pos) && pos + 2 < end && isHex(text[pos + 2])) {
        pos += 2;
        while (pos < end && isHex(text[pos])) pos += 1;
      } else {
        const ok = tok === '{hex}' ? isHex : tok === '{w}' ? isWord : isDigit;
        while (pos < end && ok(text[pos])) pos += 1;
        if (pos === start) return -1;
      }
      idiomWork -= pos - start;
      if (tok === '{w}') word = text.slice(start, pos);
    }
    return pos;
  }

  function patternMatches(pat, text) {
    const last = pat.anywhere ? text.length : 0;
    for (let start = 0; start <= last && idiomWork > 0; start++) {
      const stop = matchFrom(pat.tokens, text, start);
      if (stop >= 0 && (pat.prefix || stop === text.length)) return true;
    }
    return false;
  }

  /** One idiom from the wire, validated; null drops it. */
  function validIdiom(raw) {
    if (!raw || typeof raw !== 'object') return null;
    if (typeof raw.id !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(raw.id)) return null;
    if (raw.arch !== 'x86' && raw.arch !== 'arm64') return null;
    if (!Array.isArray(raw.steps) || !raw.steps.length || raw.steps.length > IDIOM_CAPS.steps) return null;
    const alts = (list) => {
      if (list === undefined) return undefined;
      if (!Array.isArray(list) || !list.length || list.length > IDIOM_CAPS.alts) return null;
      const out = list.map(parsePattern);
      return out.every(Boolean) ? out : null;
    };
    const steps = [];
    for (const st of raw.steps) {
      if (!st || typeof st !== 'object' || !Array.isArray(st.mn) || !st.mn.length || st.mn.length > IDIOM_CAPS.names) return null;
      if (!st.mn.every((m) => typeof m === 'string' && m.length > 0 && m.length <= 32)) return null;
      const gap = st.gap === undefined ? 0 : st.gap;
      if (!Number.isInteger(gap) || gap < 0 || gap > IDIOM_CAPS.gap) return null;
      const ops = alts(st.ops);
      const txt = alts(st.txt);
      if (ops === null || txt === null) return null;
      steps.push({ mn: new Set(st.mn), ops, txt, opt: st.opt === true, gap });
    }
    return {
      id: raw.id, arch: raw.arch, steps,
      title: str(typeof raw.title === 'string' ? raw.title : '').slice(0, 200),
      text: typeof raw.text === 'string' ? raw.text.slice(0, 2000) : '',
      concept: typeof raw.concept === 'string' ? raw.concept : '',
    };
  }

  const plainTable = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

  function getInstructions() {
    return load('instructions', '/api/learn/instructions').then((data) => {
      if (!X) {
        const d = plainTable(data);
        const list = Array.isArray(d.idioms) ? d.idioms.slice(0, IDIOM_CAPS.idioms) : [];
        const idioms = list.map(validIdiom).filter(Boolean);
        if (idioms.length < list.length) console.warn(`[BinaryStudio] learn: ignored ${list.length - idioms.length} malformed idiom(s)`);
        X = {
          mnemonics: plainTable(d.mnemonics), families: plainTable(d.families), prefixes: plainTable(d.prefixes),
          conditions: plainTable(d.conditions), idioms, byId: new Map(idioms.map((i) => [i.id, i])),
        };
      }
      return X;
    });
  }

  const getBase = () => Promise.all([getIndex(), getGlossary()]);

  // ===========================================================================
  // Small helpers
  // ===========================================================================
  const str = (v, fallback = '') => (v === null || v === undefined || v === '' ? fallback : String(v));

  function docFormat() {
    const slice = BS.getActiveSlice();
    const fmt = slice ? str(slice.format).toLowerCase() : '';
    return FORMAT_NAME[fmt] ? fmt : '';
  }

  function presetLabel(id) {
    const hit = (BS.state.presets || []).find((p) => p && p.id === id);
    return hit ? str(hit.label, id) : str(id);
  }

  function errorNote(err) {
    return h`<div class="empty-note" role="alert">The learning content could not be loaded. ${str(err && err.message)}</div>`;
  }

  // ---- rich text ------------------------------------------------------------
  const RICH = /`([^`]*)`|\[\[([^\]|]+)(?:\|([^\]]*))?\]\]|\*([^*\s][^*]*)\*/g;

  function linkStr(target, shown) {
    if (target.startsWith('concept:')) {
      const id = target.slice(8);
      const hit = I && I.byId.get(id);
      return `<button type="button" class="learn-link" data-learn-concept="${esc(id)}">${esc(shown || (hit ? hit.title : id))}</button>`;
    }
    const term = G && G.byId.get(target);
    return `<button type="button" class="learn-link learn-link-term" data-learn-term="${esc(target)}" title="${esc(term ? term.short : '')}">${esc(shown || (term ? term.term : target))}</button>`;
  }

  /** Rich text -> escaped markup string. Tokenise first, escape every piece. */
  function richStr(text) {
    const s = str(text);
    let out = '';
    let last = 0;
    for (const m of s.matchAll(RICH)) {
      out += esc(s.slice(last, m.index));
      if (m[1] !== undefined) out += `<code>${esc(m[1])}</code>`;
      else if (m[2] !== undefined) out += linkStr(m[2], m[3]);
      else out += `<em>${esc(m[4])}</em>`;
      last = m.index + m[0].length;
    }
    return out + esc(s.slice(last));
  }
  const rich = (text) => raw(richStr(text));

  function blocks(list) {
    return raw((Array.isArray(list) ? list : []).map((b) => {
      if (typeof b === 'string') return `<p>${richStr(b)}</p>`;
      if (!b || typeof b !== 'object') return '';
      if (b.type === 'list') {
        const tag = b.ordered ? 'ol' : 'ul';
        return `<${tag}>${(b.items || []).map((i) => `<li>${richStr(i)}</li>`).join('')}</${tag}>`;
      }
      if (b.type === 'code') {
        return `<figure class="learn-code"><pre>${esc(str(b.text))}</pre>${b.caption ? `<figcaption>${esc(b.caption)}</figcaption>` : ''}</figure>`;
      }
      if (b.type === 'table') {
        const head = (b.head || []).map((c) => `<th scope="col">${richStr(c)}</th>`).join('');
        const rows = (b.rows || []).map((r) => `<tr>${(r || []).map((c, i) => (i === 0 ? `<th scope="row">${richStr(c)}</th>` : `<td>${richStr(c)}</td>`)).join('')}</tr>`).join('');
        return `<div class="learn-table-wrap"><table class="learn-table"><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div>`;
      }
      if (b.type === 'note') return `<p class="learn-note">${richStr(b.text)}</p>`;
      return '';
    }).join(''));
  }

  // ---- progress ---------------------------------------------------------------
  const plainObj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
  function readProgress() {
    const p = plainObj(BS.storage.get(PROGRESS_KEY, null));
    return { concepts: plainObj(p.concepts), tours: plainObj(p.tours), last: typeof p.last === 'string' ? p.last : null };
  }
  let progress = readProgress();
  let homeHandle = null;
  function saveProgress() {
    BS.storage.set(PROGRESS_KEY, progress);
    updateBadge();
  }
  function updateBadge() {
    if (!homeHandle || !I) return;
    const read = I.concepts.filter((c) => progress.concepts[c.id]).length;
    homeHandle.update({ badge: read ? `${read}/${I.concepts.length}` : '' });
  }

  // ---- driving the core ---------------------------------------------------------
  let selfNav = 0; // > 0 while this file is moving the cursor or selecting nodes itself
  function driving(fn) {
    selfNav += 1;
    try {
      return fn();
    } finally {
      setTimeout(() => {
        selfNav = Math.max(0, selfNav - 1);
      }, 300);
    }
  }

  function markRow(absOffset) {
    setTimeout(() => {
      const body = document.getElementById('inspector-body');
      if (!body) return;
      const row = [...body.querySelectorAll('tr.struct-row[data-abs-offset]')].find((r) => Number(r.dataset.absOffset) === absOffset);
      if (!row) return;
      body.querySelectorAll('.active-field-row').forEach((n) => n.classList.remove('active-field-row'));
      row.classList.add('active-field-row');
      row.scrollIntoView({ block: 'nearest' });
    }, 30);
  }

  /** Highlight a byte range in the hex view without leaving the current view. */
  function showBytes(t) {
    if (!BS.state.doc || !t || typeof t.abs_offset !== 'number') return;
    driving(() => BS.nav.jumpToOffset(t.abs_offset, t.size || 1, str(t.label, 'range')));
  }

  /** Select the tree node of a resolved target and highlight its bytes. */
  function openTarget(t) {
    if (!BS.state.doc || !t) return;
    driving(() => {
      if (t.disasm && typeof t.abs_offset === 'number') {
        BS.nav.jumpToOffset(t.abs_offset, t.size || 4, str(t.label, 'entry point'));
        BS.commands.run('core.disasm.cursor');
        return;
      }
      if (t.node_id) BS.nav.selectNode(t.node_id);
      if (typeof t.abs_offset === 'number') {
        BS.nav.jumpToOffset(t.abs_offset, t.size || 1, str(t.label, 'range'));
        markRow(t.abs_offset);
      }
    });
  }

  async function openSampleThen(presetId, after) {
    const doc = await BS.openPreset(presetId);
    if (doc && typeof after === 'function') after();
  }

  // ===========================================================================
  // Views
  // ===========================================================================
  let renderSeq = 0;
  const targets = new Map(); // key -> resolved target, for the buttons of the view on screen
  const disposeView = () => {
    renderSeq += 1;
    targets.clear();
  };
  const loadingNote = (text) => h`<div class="learn-view"><div class="empty-note">${text}</div></div>`;

  const learnHint = () => h`Learn mode (<kbd>L</kbd>) adds explanations to fields, terms and instructions in the analysis views. It is ${BS.learn.isOn() ? 'on' : 'off'}.
    <button type="button" class="learn-link" data-learn-act="toggle-learn">${BS.learn.isOn() ? 'Turn it off' : 'Turn it on'}</button>`;

  // ---- Learning path and concept reader ------------------------------------------
  async function renderHome(bodyEl, ctx) {
    const seq = ++renderSeq;
    targets.clear();
    if (!I || !G) bodyEl.innerHTML = loadingNote('Loading…');
    try {
      await getBase();
    } catch (err) {
      if (seq === renderSeq) bodyEl.innerHTML = errorNote(err);
      return;
    }
    if (seq !== renderSeq) return;
    updateBadge();
    const conceptId = str(ctx.params && ctx.params.c);
    if (conceptId && I.byId.has(conceptId)) {
      await renderConcept(bodyEl, ctx, conceptId, seq);
      return;
    }
    ctx.setSubtitle('From bytes to running processes');
    const readCount = I.concepts.filter((c) => progress.concepts[c.id]).length;
    const last = progress.last && I.byId.get(progress.last);
    const firstUnread = I.concepts.find((c) => !progress.concepts[c.id]);
    const resume = last && !progress.concepts[last.id] ? last : firstUnread;
    const fmt = docFormat();
    const suggested = I.tours.filter((t) => !fmt || t.formats.includes(fmt)).slice(0, 3);

    bodyEl.innerHTML = h`
      <div class="learn-view">
        <header class="learn-hero">
          <p class="learn-lead">A path from bytes to running processes in ${I.concepts.length} concepts. Each one explains an idea, shows how Mach-O, ELF and PE express it, and points at the bytes in the open file.</p>
          <div class="learn-hero-actions">
            ${resume ? h`<button type="button" class="learn-btn learn-btn-primary" data-learn-concept="${resume.id}">${readCount ? 'Continue' : 'Start'}: ${resume.title}</button>` : ''}
            <button type="button" class="learn-btn" data-learn-view="${VIEW_TOURS}">Tours</button>
            <button type="button" class="learn-btn" data-learn-view="${VIEW_GLOSSARY}">Glossary</button>
            <span class="learn-meta">${readCount} of ${I.concepts.length} read</span>
          </div>
          <p class="learn-hint">${learnHint()}</p>
        </header>
        ${I.modules.map((m, mi) => {
          const items = I.concepts.filter((c) => c.module === m.id);
          return h`
            <section class="learn-module" aria-labelledby="learn-mod-${m.id}">
              <h2 id="learn-mod-${m.id}" class="learn-module-title"><span class="learn-module-num">${mi + 1}</span>${m.title}</h2>
              <p class="learn-module-summary">${m.summary}</p>
              <ol class="learn-concept-list">
                ${items.map((c) => h`
                  <li>
                    <button type="button" class="learn-concept-row" data-learn-concept="${c.id}">
                      <span class="learn-dot ${progress.concepts[c.id] ? 'is-read' : ''}" aria-hidden="true"></span>
                      <span class="learn-concept-main">
                        <span class="learn-concept-title">${c.title}${progress.concepts[c.id] ? h`<span class="learn-sr"> (read)</span>` : ''}</span>
                        <span class="learn-concept-summary">${c.summary}</span>
                      </span>
                      <span class="learn-level learn-level-${levelNum(c.level)}">${levelName(c.level)}</span>
                    </button>
                  </li>`)}
              </ol>
            </section>`;
        })}
        <section class="learn-module" aria-labelledby="learn-home-tours">
          <h2 id="learn-home-tours" class="learn-module-title">Tours</h2>
          <p class="learn-module-summary">A tour walks through the open file step by step and asks you to find things in it.</p>
          <ul class="learn-chip-list">
            ${suggested.map((t) => h`<li><button type="button" class="learn-btn" data-learn-view="${VIEW_TOURS}" data-learn-param-t="${t.id}">${t.title}</button></li>`)}
            <li><button type="button" class="learn-link" data-learn-view="${VIEW_TOURS}">All ${I.tours.length} tours</button></li>
          </ul>
        </section>
      </div>`;
  }

  /** Fill the action cells of the "See it in this file" rows (the rows exist already: no layout shift). */
  function fillSee(list, actions) {
    const hasDoc = Boolean(BS.state.doc);
    actions.forEach((a) => {
      const row = list.querySelector(`[data-see="${CSS.escape(a.id)}"]`);
      const cell = row && row.querySelector('.learn-see-actions');
      if (!cell) return;
      if (a.available) {
        targets.set(a.id, a);
        const hasBytes = typeof a.abs_offset === 'number';
        cell.innerHTML = h`
          ${hasBytes && !a.disasm ? h`<button type="button" class="learn-btn learn-btn-small" data-learn-bytes="${a.id}">Show bytes</button>` : ''}
          <button type="button" class="learn-btn learn-btn-small" data-learn-open="${a.id}">${a.disasm ? 'Disassemble' : 'Open'}</button>`;
        return;
      }
      row.classList.add('is-missing');
      const samples = Array.isArray(a.samples) ? a.samples : [];
      cell.innerHTML = h`
        <span class="learn-see-reason">${hasDoc ? str(a.reason) : ''}</span>
        ${samples.slice(0, 3).map((s) => h`<button type="button" class="learn-btn learn-btn-small" data-learn-sample="${s}">Open ${presetLabel(s)}</button>`)}`;
    });
  }

  async function renderConcept(bodyEl, ctx, conceptId, seq) {
    let c;
    try {
      c = await load(`concept:${conceptId}`, '/api/learn/concept', { id: conceptId });
    } catch (err) {
      if (seq === renderSeq) bodyEl.innerHTML = errorNote(err);
      return;
    }
    if (seq !== renderSeq) return;
    progress.last = c.id;
    BS.storage.set(PROGRESS_KEY, progress);

    const module = I.modules.find((m) => m.id === c.module) || { title: '' };
    const fmt = docFormat();
    const prev = I.concepts[c.order - 2];
    const next = I.concepts[c.order];
    const tours = I.tours.filter((t) => (t.concepts || []).includes(c.id));
    const isRead = Boolean(progress.concepts[c.id]);
    ctx.setSubtitle(`${module.title} · ${c.order} of ${I.concepts.length}`);

    bodyEl.innerHTML = h`
      <article class="learn-view learn-article" data-concept="${c.id}">
        <nav class="learn-crumbs" aria-label="Position in the curriculum">
          <button type="button" class="learn-link" data-learn-view="${VIEW_HOME}">Learning path</button>
          <span aria-hidden="true">›</span><span>${module.title}</span>
          <span class="learn-level learn-level-${levelNum(c.level)}">${levelName(c.level)}</span>
        </nav>
        <h2 class="learn-title" tabindex="-1">${c.title}</h2>
        <p class="learn-summary">${c.summary}</p>
        <div class="learn-prose">${blocks(c.body)}</div>

        <section aria-labelledby="learn-h-formats">
          <h3 id="learn-h-formats">In each format</h3>
          <div class="learn-format-grid">
            ${FORMATS.map(([id, name]) => h`
              <div class="learn-format ${fmt === id ? 'is-active' : ''}">
                <h4>${name}${fmt === id ? h`<span class="learn-tag">this file</span>` : ''}</h4>
                <div class="learn-prose">${blocks((c.formats || {})[id])}</div>
              </div>`)}
          </div>
          ${c.differences ? h`<p class="learn-diff"><strong>Why they differ.</strong> ${rich(c.differences)}</p>` : ''}
        </section>

        <section aria-labelledby="learn-h-see">
          <h3 id="learn-h-see">See it in this file</h3>
          ${BS.state.doc ? '' : h`<p class="learn-quiet">No file is open. Open one of the samples below, or any file of your own, and these become links to its bytes.</p>`}
          <ul class="learn-see-list" id="learn-see-list">
            ${(c.see || []).map((a) => h`<li class="learn-see-item" data-see="${a.id}"><span class="learn-see-label">${a.label}</span><span class="learn-see-actions"></span></li>`)}
          </ul>
        </section>

        ${(c.misconceptions || []).length ? h`
          <section aria-labelledby="learn-h-wrong">
            <h3 id="learn-h-wrong">Common misconceptions</h3>
            <dl class="learn-wrong">
              ${c.misconceptions.map((m) => h`<div><dt>${m.claim}</dt><dd>${rich(m.reality)}</dd></div>`)}
            </dl>
          </section>` : ''}

        ${tours.length ? h`
          <section aria-labelledby="learn-h-tours">
            <h3 id="learn-h-tours">Practise</h3>
            <ul class="learn-chip-list">
              ${tours.map((t) => h`<li><button type="button" class="learn-btn" data-learn-view="${VIEW_TOURS}" data-learn-param-t="${t.id}">Tour: ${t.title}</button></li>`)}
            </ul>
          </section>` : ''}

        <section aria-labelledby="learn-h-next">
          <h3 id="learn-h-next">Read next</h3>
          <ul class="learn-chip-list">
            ${(c.next || []).filter((id) => I.byId.has(id)).map((id) => h`<li><button type="button" class="learn-btn" data-learn-concept="${id}" data-learn-mark="${c.id}">${I.byId.get(id).title}</button></li>`)}
          </ul>
        </section>

        <footer class="learn-foot">
          <div class="learn-foot-nav">
            ${prev ? h`<button type="button" class="learn-link" data-learn-concept="${prev.id}">← ${prev.title}</button>` : h`<span></span>`}
            <button type="button" class="learn-btn learn-btn-small" data-learn-read="${c.id}" aria-pressed="${isRead ? 'true' : 'false'}">${isRead ? 'Read' : 'Mark as read'}</button>
            ${next ? h`<button type="button" class="learn-link" data-learn-concept="${next.id}" data-learn-mark="${c.id}">${next.title} →</button>` : h`<span></span>`}
          </div>
          ${(c.sources || []).length ? h`<p class="learn-sources">Checked against: ${c.sources.join('; ')}.</p>` : ''}
        </footer>
      </article>`;
    bodyEl.scrollTop = 0;

    let actions = [];
    try {
      const params = { scope: `concept:${c.id}` };
      if (!BS.state.doc) Object.assign(params, { doc: null, slice_index: null });
      actions = (await BS.api.get('/api/learn/resolve', params)).actions || [];
    } catch (err) {
      actions = null;
    }
    if (seq !== renderSeq) return;
    const list = bodyEl.querySelector('#learn-see-list');
    if (!list) return;
    if (actions === null) list.insertAdjacentHTML('afterend', h`<p class="learn-quiet" role="status">These could not be located in the open file.</p>`);
    else fillSee(list, actions);
    list.dataset.resolved = '1';
  }

  // ---- Tours list -------------------------------------------------------------------
  async function renderTours(bodyEl, ctx) {
    const seq = ++renderSeq;
    targets.clear();
    if (!I || !G) bodyEl.innerHTML = loadingNote('Loading…');
    try {
      await getBase();
    } catch (err) {
      if (seq === renderSeq) bodyEl.innerHTML = errorNote(err);
      return;
    }
    if (seq !== renderSeq) return;
    const fmt = docFormat();
    const focus = str(ctx.params && ctx.params.t);
    ctx.setSubtitle(fmt ? `For the open ${FORMAT_NAME[fmt]} file` : 'Open a file or a sample to start one');

    const card = (t) => {
      const saved = plainObj(progress.tours[t.id]);
      const applies = fmt && t.formats.includes(fmt);
      const running = tour.active && tour.active.id === t.id;
      let status = '';
      if (saved.done) status = 'Completed';
      else if (saved.step) status = 'In progress';
      const sampleFormats = fmt ? (applies ? [] : t.formats) : t.formats;
      return h`
        <li class="learn-tour-card ${focus === t.id ? 'is-focus' : ''}" id="learn-tour-${t.id}">
          <div class="learn-tour-card-head">
            <span class="learn-tour-card-title">${t.title}</span>
            <span class="learn-meta">${t.formats.map((f) => FORMAT_NAME[f]).join(' · ')} · about ${t.minutes} min · ${t.tasks} ${t.tasks === 1 ? 'task' : 'tasks'}</span>
          </div>
          <p class="learn-tour-card-summary">${t.summary}</p>
          <div class="learn-tour-card-actions">
            ${applies ? h`<button type="button" class="learn-btn learn-btn-primary" data-learn-tour="${t.id}">${running ? 'Show' : saved.step && !saved.done ? 'Resume' : saved.done ? 'Run again' : 'Start'}</button>` : ''}
            ${applies && saved.step && !saved.done ? h`<button type="button" class="learn-btn" data-learn-tour="${t.id}" data-learn-restart="1">Start over</button>` : ''}
            ${sampleFormats.map((f) => h`<button type="button" class="learn-btn" data-learn-sample="${t.samples[f]}" data-learn-then-tour="${t.id}">Open the ${FORMAT_NAME[f]} sample and start</button>`)}
            ${fmt && !applies ? h`<span class="learn-see-reason">Not for ${FORMAT_NAME[fmt]} files.</span>` : ''}
            ${status ? h`<span class="learn-status">${status}</span>` : ''}
          </div>
        </li>`;
    };

    bodyEl.innerHTML = h`
      <div class="learn-view">
        <p class="learn-lead">A tour walks through the open file. Each step selects a structure or highlights bytes, and most ask you to find or work out something in the file itself. Answers are checked against the file that is open.</p>
        ${[1, 2, 3].map((level) => {
          const items = I.tours.filter((t) => t.level === level);
          if (!items.length) return '';
          return h`
            <section class="learn-module" aria-labelledby="learn-tours-${level}">
              <h2 id="learn-tours-${level}" class="learn-module-title">${LEVELS[level]}</h2>
              <ul class="learn-tour-list">${items.map(card)}</ul>
            </section>`;
        })}
      </div>`;
    if (focus) {
      const node = bodyEl.querySelector(`#learn-tour-${CSS.escape(focus)}`);
      if (node) node.scrollIntoView({ block: 'nearest' });
    }
  }

  // ---- Glossary ---------------------------------------------------------------------
  let glossaryFilter = '';
  async function renderGlossary(bodyEl, ctx) {
    const seq = ++renderSeq;
    targets.clear();
    if (!I || !G) bodyEl.innerHTML = loadingNote('Loading…');
    try {
      await getBase();
    } catch (err) {
      if (seq === renderSeq) bodyEl.innerHTML = errorNote(err);
      return;
    }
    if (seq !== renderSeq) return;
    const focus = str(ctx.params && ctx.params.t);
    if (ctx.params && typeof ctx.params.q === 'string') glossaryFilter = ctx.params.q;
    if (focus) glossaryFilter = '';
    const sorted = [...G.terms].sort((a, b) => a.term.localeCompare(b.term, 'en', { sensitivity: 'base' }));
    ctx.setSubtitle(`${sorted.length} terms`);

    bodyEl.innerHTML = h`
      <div class="learn-view learn-glossary">
        <div class="learn-toolbar">
          <input id="learn-gloss-q" type="search" class="explorer-search-input learn-search" placeholder="Filter terms" aria-label="Filter glossary terms" value="${glossaryFilter}" spellcheck="false" autocomplete="off" />
          <span class="learn-meta" id="learn-gloss-count" role="status"></span>
        </div>
        <dl class="learn-terms">
          ${sorted.map((t) => {
            const concept = I.byId.get(t.concept);
            return h`
              <div class="learn-term-entry ${focus === t.id ? 'is-focus' : ''}" id="learn-term-${t.id}" data-hay="${[t.term, ...(t.aka || []), t.short].join(' ').toLowerCase()}">
                <dt>${t.term}${(t.aka || []).length ? h`<span class="learn-aka">${t.aka.join(', ')}</span>` : ''}</dt>
                <dd>
                  ${t.short}
                  <span class="learn-term-links">
                    ${(t.see || []).filter((id) => G.byId.has(id)).map((id) => h`<button type="button" class="learn-link learn-link-term" data-learn-term="${id}">${G.byId.get(id).term}</button>`)}
                    ${concept ? h`<button type="button" class="learn-link" data-learn-concept="${concept.id}">Background: ${concept.title}</button>` : ''}
                  </span>
                </dd>
              </div>`;
          })}
        </dl>
        <div class="empty-note" id="learn-gloss-empty" hidden>No term matches this filter.</div>
      </div>`;

    const input = bodyEl.querySelector('#learn-gloss-q');
    const count = bodyEl.querySelector('#learn-gloss-count');
    const empty = bodyEl.querySelector('#learn-gloss-empty');
    const entries = [...bodyEl.querySelectorAll('.learn-term-entry')];
    const apply = () => {
      const q = glossaryFilter.trim().toLowerCase();
      let shown = 0;
      entries.forEach((node) => {
        const ok = !q || node.dataset.hay.includes(q);
        node.hidden = !ok;
        if (ok) shown += 1;
      });
      count.textContent = q ? `${shown} of ${entries.length}` : `${entries.length} terms`;
      empty.hidden = shown > 0;
    };
    input.addEventListener('input', () => {
      glossaryFilter = input.value;
      apply();
    });
    apply();
    if (focus) {
      const node = bodyEl.querySelector(`#learn-term-${CSS.escape(focus)}`);
      if (node) node.scrollIntoView({ block: 'center' });
    }
  }

  // ---- Format comparison ----------------------------------------------------------------
  async function renderCompare(bodyEl, ctx) {
    const seq = ++renderSeq;
    targets.clear();
    if (!I || !G) bodyEl.innerHTML = loadingNote('Loading…');
    let rows;
    try {
      await getBase();
      rows = (await load('compare', '/api/learn/compare')).rows || [];
    } catch (err) {
      if (seq === renderSeq) bodyEl.innerHTML = errorNote(err);
      return;
    }
    if (seq !== renderSeq) return;
    const fmt = docFormat();
    ctx.setSubtitle('The same idea in Mach-O, ELF and PE');
    const on = (f) => (fmt === f ? 'is-active' : '');
    bodyEl.innerHTML = h`
      <div class="learn-view learn-wide">
        <p class="learn-lead">Each row is one job that every executable format has to do, and the structure each format uses for it.${fmt ? ` The column for the open file is marked.` : ''}</p>
        <div class="learn-table-wrap">
          <table class="learn-table learn-compare">
            <thead><tr><th scope="col">Idea</th><th scope="col" class="${on('macho')}">Mach-O</th><th scope="col" class="${on('elf')}">ELF</th><th scope="col" class="${on('pe')}">PE</th><th scope="col">Why it exists</th></tr></thead>
            <tbody>
              ${rows.map((r) => h`
                <tr>
                  <th scope="row">
                    <button type="button" class="learn-link" data-learn-concept="${r.concept}">${r.title}</button>
                    <span class="learn-compare-go" data-compare-row="compare.${r.id}"></span>
                  </th>
                  <td class="${on('macho')}">${rich(r.macho)}</td>
                  <td class="${on('elf')}">${rich(r.elf)}</td>
                  <td class="${on('pe')}">${rich(r.pe)}</td>
                  <td>${rich(r.why)}</td>
                </tr>`)}
            </tbody>
          </table>
        </div>
      </div>`;
    if (!BS.state.doc) return;
    let actions = [];
    try {
      actions = (await BS.api.get('/api/learn/resolve', { scope: 'compare' })).actions || [];
    } catch {
      return;
    }
    if (seq !== renderSeq) return;
    actions.filter((a) => a.available).forEach((a) => {
      const slot = bodyEl.querySelector(`[data-compare-row="${CSS.escape(a.id)}"]`);
      if (!slot) return;
      targets.set(a.id, a);
      slot.innerHTML = h`<button type="button" class="learn-btn learn-btn-small" data-learn-open="${a.id}">Show in this file</button>`;
    });
  }

  // ---- Field reference ----------------------------------------------------------------------
  let fieldsFormat = '';
  let fieldsFilter = '';
  async function renderFields(bodyEl, ctx) {
    const seq = ++renderSeq;
    targets.clear();
    if (!I || !G) bodyEl.innerHTML = loadingNote('Loading…');
    let data;
    try {
      await getBase();
      data = await load('fields', '/api/learn/fields');
    } catch (err) {
      if (seq === renderSeq) bodyEl.innerHTML = errorNote(err);
      return;
    }
    if (seq !== renderSeq) return;
    const wanted = str(ctx.params && ctx.params.f);
    if (FORMAT_NAME[wanted]) fieldsFormat = wanted;
    if (!fieldsFormat) fieldsFormat = docFormat() || 'macho';
    const structs = (data && Array.isArray(data.structs) ? data.structs.slice(0, 500) : []).filter((s) => s && typeof s === 'object' && s.format === fieldsFormat);
    const total = structs.reduce((n, s) => n + s.fields.length, 0);
    ctx.setSubtitle(`${FORMAT_NAME[fieldsFormat]} · ${total} fields`);

    bodyEl.innerHTML = h`
      <div class="learn-view learn-wide">
        <div class="learn-toolbar">
          <div class="filter-pills-group" role="group" aria-label="Format">
            ${FORMATS.map(([id, name]) => h`<button type="button" class="filter-pill-btn ${fieldsFormat === id ? 'active' : ''}" aria-pressed="${fieldsFormat === id ? 'true' : 'false'}" data-learn-fields-format="${id}">${name}</button>`)}
          </div>
          <input id="learn-fields-q" type="search" class="explorer-search-input learn-search" placeholder="Filter fields" aria-label="Filter fields" value="${fieldsFilter}" spellcheck="false" autocomplete="off" />
        </div>
        <p class="learn-quiet">For each field: what it holds, who reads it and when, what happens if it is wrong, and its counterpart in the other formats. The same text appears next to the field in the inspector when Learn mode is on.</p>
        ${structs.map((s) => h`
          <section class="learn-struct" data-struct="${s.id}">
            <h3 class="learn-struct-title">${s.title}</h3>
            <div class="learn-table-wrap">
              <table class="learn-table learn-fields-table">
                <thead><tr><th scope="col">Field</th><th scope="col">Meaning</th><th scope="col">Read by</th><th scope="col">If it is wrong</th><th scope="col">In other formats</th></tr></thead>
                <tbody>
                  ${s.fields.map((f) => h`
                    <tr data-hay="${[f.field, f.meaning, f.reader, f.if_wrong, f.peers].join(' ').toLowerCase()}">
                      <th scope="row" class="learn-field-name">${f.field.replace('@', ' in ')}</th>
                      <td>${f.meaning}</td><td>${f.reader}</td><td>${f.if_wrong}</td><td>${f.peers}</td>
                    </tr>`)}
                </tbody>
              </table>
            </div>
          </section>`)}
        <div class="empty-note" id="learn-fields-empty" hidden>No field matches this filter.</div>
      </div>`;

    const input = bodyEl.querySelector('#learn-fields-q');
    const empty = bodyEl.querySelector('#learn-fields-empty');
    const apply = () => {
      const q = fieldsFilter.trim().toLowerCase();
      let shown = 0;
      bodyEl.querySelectorAll('.learn-struct').forEach((section) => {
        let any = 0;
        section.querySelectorAll('tbody tr').forEach((row) => {
          const ok = !q || row.dataset.hay.includes(q);
          row.hidden = !ok;
          if (ok) any += 1;
        });
        section.hidden = any === 0;
        shown += any;
      });
      empty.hidden = shown > 0;
    };
    input.addEventListener('input', () => {
      fieldsFilter = input.value;
      apply();
    });
    apply();
  }

  homeHandle = BS.registerView({ id: VIEW_HOME, title: 'Learning path', icon: 'LP', group: 'Learn', order: 10, requiresDoc: false, subtitle: 'A curriculum from bytes to running processes', render: renderHome, dispose: disposeView });
  BS.registerView({ id: VIEW_TOURS, title: 'Tours', icon: 'TR', group: 'Learn', order: 20, requiresDoc: false, subtitle: 'Guided walks through the open file, with tasks', render: renderTours, dispose: disposeView });
  BS.registerView({ id: VIEW_GLOSSARY, title: 'Glossary', icon: 'AZ', group: 'Learn', order: 30, requiresDoc: false, subtitle: 'Every term used in the tool and the curriculum', render: renderGlossary, dispose: disposeView });
  BS.registerView({ id: VIEW_COMPARE, title: 'Format comparison', icon: 'CMP', group: 'Learn', order: 40, requiresDoc: false, subtitle: 'Mach-O, ELF and PE side by side', render: renderCompare, dispose: disposeView });
  BS.registerView({ id: VIEW_FIELDS, title: 'Field reference', icon: 'REF', group: 'Learn', order: 50, requiresDoc: false, subtitle: 'What every header field means', render: renderFields, dispose: disposeView });

  const openConcept = (id) => BS.nav.openView(VIEW_HOME, { c: id });
  const openTerm = (id) => BS.nav.openView(VIEW_GLOSSARY, { t: id });

  // ===========================================================================
  // Tour runner: a panel docked under the inspector
  // ===========================================================================
  const tour = { active: null, index: 0, solved: {}, el: null, minimised: false, feedback: null };

  function ensurePanel() {
    if (tour.el) return tour.el;
    const host = document.getElementById('center-inspector');
    const el = document.createElement('section');
    el.id = 'learn-tour-panel';
    el.className = `learn-tour-panel${host ? '' : ' is-floating'}`;
    el.setAttribute('role', 'region');
    el.setAttribute('aria-label', 'Guided tour');
    el.hidden = true;
    (host || document.body).appendChild(el);
    el.addEventListener('click', onTourClick);
    el.addEventListener('submit', (e) => {
      e.preventDefault();
      const input = el.querySelector('.learn-task-input');
      if (input) checkValue(input.value);
    });
    tour.el = el;
    return el;
  }

  const currentStep = () => (tour.active ? tour.active.steps[tour.index] : null);
  const currentTask = () => {
    const step = currentStep();
    return step && step.task ? step.task : null;
  };
  const taskKey = (task) => `${currentStep().id}:${task.id}`;
  const isSolved = (task) => Boolean(task && tour.solved[taskKey(task)]);

  function saveTour(done) {
    if (!tour.active) return;
    const step = currentStep();
    const prev = plainObj(progress.tours[tour.active.id]);
    progress.tours[tour.active.id] = { step: step ? step.id : '', solved: tour.solved, done: Boolean(done || prev.done) };
    saveProgress();
  }

  function taskControls(task) {
    if (task.kind === 'bytes') {
      return h`<div class="learn-task-controls"><button type="button" class="learn-btn learn-btn-small" data-tour-act="check">Check the cursor</button></div>`;
    }
    if (task.kind === 'node') {
      const options = Array.isArray(task.options) ? task.options : [];
      return options.length ? h`<div class="learn-task-controls learn-task-options" role="group" aria-label="Segments">
        ${options.map((o) => h`<button type="button" class="learn-btn learn-btn-small learn-mono" data-tour-node="${o.node_id}">${o.label}</button>`)}
      </div>` : '';
    }
    if (task.kind === 'value') {
      return h`<form class="learn-task-controls learn-task-form">
        <input type="text" class="explorer-search-input learn-task-input" aria-label="Your answer (decimal or 0x hexadecimal)" placeholder="0x… or decimal" spellcheck="false" autocomplete="off" autocapitalize="off" />
        <button type="submit" class="learn-btn learn-btn-small">Check</button>
      </form>`;
    }
    if (task.kind === 'choice') {
      return h`<div class="learn-task-controls learn-task-options" role="group" aria-label="Answers">
        ${(task.options || []).map((o, i) => h`<button type="button" class="learn-btn learn-btn-small" data-tour-choice="${i}">${o}</button>`)}
      </div>`;
    }
    return '';
  }

  function renderPanel(focusTitle) {
    const el = ensurePanel();
    const t = tour.active;
    if (!t) {
      el.hidden = true;
      el.replaceChildren();
      return;
    }
    const step = currentStep();
    const task = step.task;
    const last = tour.index === t.steps.length - 1;
    const solved = isSolved(task);
    const fb = tour.feedback;
    el.hidden = false;
    el.classList.toggle('is-min', tour.minimised);
    el.innerHTML = h`
      <div class="learn-tour-head">
        <span class="learn-tour-kicker">Tour</span>
        <strong class="learn-tour-name">${t.title}</strong>
        <span class="learn-meta">Step ${tour.index + 1} of ${t.steps.length}</span>
        <span class="learn-tour-spacer"></span>
        <button type="button" class="learn-btn learn-btn-small" data-tour-act="min" aria-expanded="${tour.minimised ? 'false' : 'true'}">${tour.minimised ? 'Expand' : 'Collapse'}</button>
        <button type="button" class="learn-btn learn-btn-small" data-tour-act="close">End tour</button>
      </div>
      <div class="learn-tour-body" ${tour.minimised ? raw('hidden') : ''}>
        <h3 class="learn-tour-step-title" tabindex="-1">${step.title}</h3>
        <div class="learn-prose"><p>${rich(step.text)}</p></div>
        ${task ? h`
          <div class="learn-task ${solved ? 'is-solved' : ''}">
            <div class="learn-task-label">${solved ? 'Done' : 'Try it'}</div>
            <p class="learn-task-prompt">${rich(task.prompt)}</p>
            ${solved ? '' : taskControls(task)}
            <div class="learn-task-feedback ${fb ? `is-${fb.kind}` : ''}" role="status">${fb ? rich(fb.text) : ''}</div>
            ${solved ? '' : h`<button type="button" class="learn-link" data-tour-act="reveal">Show the answer</button>`}
          </div>` : ''}
      </div>
      <div class="learn-tour-foot" ${tour.minimised ? raw('hidden') : ''}>
        <button type="button" class="learn-btn" data-tour-act="back" ${tour.index === 0 ? raw('disabled') : ''}>Back</button>
        ${step.show ? h`<button type="button" class="learn-btn" data-tour-act="show">Show</button>` : ''}
        <button type="button" class="learn-btn learn-btn-primary" data-tour-act="next">${last ? 'Finish' : 'Next'}</button>
        <span class="learn-tour-keys" aria-hidden="true"><kbd>,</kbd> back <kbd>.</kbd> next</span>
      </div>`;
    if (focusTitle) {
      const title = el.querySelector('.learn-tour-step-title');
      if (title) title.focus({ preventScroll: true });
    }
  }

  function setFeedback(kind, text) {
    tour.feedback = { kind, text };
    renderPanel(false);
  }

  function showStep(enter, focusTitle) {
    tour.feedback = null;
    const step = currentStep();
    if (!step) return;
    const task = step.task;
    if (isSolved(task)) tour.feedback = { kind: 'ok', text: `Correct. ${task.explain}` };
    saveTour(false);
    renderPanel(focusTitle);
    if (enter && step.show && !task) openTarget(step.show);
  }

  function solve() {
    const task = currentTask();
    if (!task) return;
    tour.solved[taskKey(task)] = 1;
    tour.feedback = { kind: 'ok', text: `Correct. ${task.explain}` };
    saveTour(false);
    renderPanel(false);
  }

  function parseNumber(text) {
    const s = String(text).trim().replace(/[_\s,]/g, '').toLowerCase();
    try {
      if (/^0x[0-9a-f]+$/.test(s)) return BigInt(s);
      if (/^[0-9]+$/.test(s)) return BigInt(s);
      if (/^[0-9a-f]+h$/.test(s)) return BigInt(`0x${s.slice(0, -1)}`);
      if (/^[0-9a-f]+$/.test(s)) return BigInt(`0x${s}`);
    } catch {
      return null;
    }
    return null;
  }

  function checkValue(text) {
    const task = currentTask();
    if (!task || task.kind !== 'value') return;
    const given = parseNumber(text);
    if (given === null) {
      setFeedback('bad', 'Type a number: decimal, or hexadecimal with the prefix `0x`.');
      return;
    }
    let expect;
    try {
      expect = BigInt(task.expect_text);
    } catch {
      expect = BigInt(Math.trunc(Number(task.expect) || 0));
    }
    if (given === expect) solve();
    else setFeedback('bad', 'Not that value. Check which bytes belong to the field and the order they are read in, then try again.');
  }

  const inRanges = (task, off) => (task.ranges || []).some((r) => off >= r.abs_offset && off < r.abs_offset + Math.max(1, r.size));

  function reveal() {
    const step = currentStep();
    const task = currentTask();
    if (!task) return;
    if (task.kind === 'bytes' && task.ranges && task.ranges[0]) {
      openTarget({ node_id: task.node_id, abs_offset: task.ranges[0].abs_offset, size: task.ranges[0].size, label: 'answer' });
    } else if (task.kind === 'node' && task.node_ids && task.node_ids[0]) {
      driving(() => BS.nav.selectNode(task.node_ids[0]));
    } else if (task.kind === 'value' && task.show && task.show.node_id) {
      openTarget(task.show);
    } else if (step.show) {
      openTarget(step.show);
    }
    setFeedback('shown', task.explain || 'Shown in the tool.');
  }

  function endTour(message) {
    if (!tour.active) return;
    tour.active = null;
    tour.feedback = null;
    renderPanel(false);
    if (message) BS.ui.toast(message, 'info');
    if (BS.state.selectedNodeId === VIEW_TOURS) BS.nav.openView(VIEW_TOURS);
  }

  function nextStep() {
    if (!tour.active) return;
    if (tour.index >= tour.active.steps.length - 1) {
      const title = tour.active.title;
      saveTour(true);
      endTour(`Tour finished: ${title}.`);
      return;
    }
    tour.index += 1;
    showStep(true, true);
  }

  function prevStep() {
    if (!tour.active || tour.index === 0) return;
    tour.index -= 1;
    showStep(true, true);
  }

  function onTourClick(e) {
    const target = e.target.closest('[data-tour-act], [data-tour-choice], [data-tour-node]');
    if (!target || !tour.active) return;
    const task = currentTask();
    if (target.dataset.tourChoice !== undefined && task && task.kind === 'choice') {
      if (Number(target.dataset.tourChoice) === task.correct) solve();
      else setFeedback('bad', 'Not that one. Look at the field again and try another answer.');
      return;
    }
    if (target.dataset.tourNode !== undefined && task && task.kind === 'node') {
      if ((task.node_ids || []).includes(target.dataset.tourNode)) solve();
      else setFeedback('bad', 'Not that one. Compare the address with where each segment starts and how large it is.');
      return;
    }
    const act = target.dataset.tourAct;
    if (act === 'next') nextStep();
    else if (act === 'back') prevStep();
    else if (act === 'close') {
      saveTour(false);
      endTour('');
    } else if (act === 'min') {
      tour.minimised = !tour.minimised;
      renderPanel(false);
    } else if (act === 'show') {
      const step = currentStep();
      if (step && step.show) openTarget(step.show);
    } else if (act === 'reveal') reveal();
    else if (act === 'check' && task && task.kind === 'bytes') {
      if (inRanges(task, BS.state.cursorOffset)) solve();
      else setFeedback('bad', `The cursor is at ${BS.util.hex(BS.state.cursorOffset)}, which is not it. Find the field in the inspector, or use the Translate bar.`);
    }
  }

  async function fetchTour(id) {
    return BS.api.get('/api/learn/tour', { id });
  }

  async function startTour(id, opts = {}) {
    if (!BS.state.doc) {
      BS.ui.toast('A tour walks through an open file. Open a file or a sample first.', 'info');
      BS.nav.openView(VIEW_TOURS, { t: id });
      return;
    }
    if (tour.active && tour.active.id === id && !opts.restart) {
      tour.minimised = false;
      renderPanel(true);
      return;
    }
    let built;
    try {
      await getBase();
      built = await fetchTour(id);
    } catch (err) {
      BS.ui.toast(`The tour could not be started. ${str(err && err.message)}`, 'error');
      return;
    }
    if (!built || !built.available || !(built.steps || []).length) {
      BS.ui.toast(str(built && built.reason, 'This tour does not apply to the open file.'), 'info');
      BS.nav.openView(VIEW_TOURS, { t: id });
      return;
    }
    const saved = plainObj(progress.tours[id]);
    const fresh = opts.restart || saved.done;
    const at = built.steps.findIndex((s) => s.id === saved.step);
    tour.active = built;
    tour.index = fresh || at < 0 ? 0 : at;
    tour.solved = fresh ? {} : Object.assign({}, plainObj(saved.solved));
    tour.minimised = false;
    if (fresh) progress.tours[id] = { step: '', solved: {}, done: false };
    showStep(true, true);
    if (BS.state.selectedNodeId === VIEW_TOURS) BS.nav.openView(VIEW_TOURS, { t: id });
  }

  // The steps and expected answers belong to one document: rebuild when it changes.
  let rebuildQueued = false;
  function rebuildTour() {
    if (!tour.active || rebuildQueued) return;
    rebuildQueued = true;
    setTimeout(async () => {
      rebuildQueued = false;
      if (!tour.active) return;
      const id = tour.active.id;
      const stepId = currentStep() ? currentStep().id : '';
      if (!BS.state.doc) {
        endTour('');
        return;
      }
      let built = null;
      try {
        built = await fetchTour(id);
      } catch {
        built = null;
      }
      if (!tour.active || tour.active.id !== id) return;
      if (!built || !built.available || !(built.steps || []).length) {
        endTour(`The tour ended: ${str(built && built.reason, 'it does not apply to this file')}`);
        return;
      }
      const at = built.steps.findIndex((s) => s.id === stepId);
      tour.active = built;
      tour.index = at < 0 ? 0 : at;
      tour.solved = {};
      showStep(false, false);
    }, 0);
  }

  BS.on('doc:loaded', rebuildTour);
  BS.on('slice:changed', rebuildTour);
  BS.on('doc:closed', () => endTour(''));
  BS.on('cursor:changed', ({ absOffset }) => {
    if (selfNav || !tour.active) return;
    const task = currentTask();
    if (task && task.kind === 'bytes' && !isSolved(task) && inRanges(task, absOffset)) solve();
  });
  BS.on('node:selected', ({ id }) => {
    if (selfNav || !tour.active) return;
    const task = currentTask();
    if (!task || task.kind !== 'node' || isSolved(task)) return;
    if ((task.node_ids || []).includes(id)) solve();
    else if ((task.options || []).some((o) => o.node_id === id)) setFeedback('bad', 'Not that one. Compare the address with where each segment starts and how large it is.');
  });
  BS.hex.onByteActivate(({ absOffset }) => {
    if (!tour.active) return;
    const task = currentTask();
    if (!task || task.kind !== 'bytes' || isSolved(task)) return;
    if (inRanges(task, absOffset)) solve();
    else setFeedback('bad', `Offset ${BS.util.hex(absOffset)} is not it. Find the field in the inspector, or use the Translate bar.`);
  });

  // A click on the byte the cursor is already on moves nothing, so the core emits no cursor event
  // for it. Capture phase: the core redraws the hex rows in its own click handler.
  document.addEventListener('click', (e) => {
    if (!tour.active || e.shiftKey || !e.target.closest) return;
    const byteEl = e.target.closest('#hex-viewport [data-byte-offset]');
    const task = byteEl ? currentTask() : null;
    if (task && task.kind === 'bytes' && !isSolved(task) && inRanges(task, Number(byteEl.dataset.byteOffset))) solve();
  }, true);

  // ===========================================================================
  // Learn mode inside the analysis views
  // ===========================================================================
  // ---- popover (terms and instructions) ---------------------------------------------
  const pop = { el: null, anchor: null, pinned: false, showTimer: 0, hideTimer: 0 };

  function ensurePopover() {
    if (pop.el) return pop.el;
    const el = document.createElement('div');
    el.id = 'learn-popover';
    el.className = 'learn-popover';
    el.setAttribute('role', 'note');
    el.hidden = true;
    document.body.appendChild(el);
    el.addEventListener('mouseenter', () => clearTimeout(pop.hideTimer));
    el.addEventListener('mouseleave', () => {
      if (!pop.pinned) scheduleHide();
    });
    pop.el = el;
    return el;
  }

  function hideNow() {
    if (pop.el) pop.el.hidden = true;
    pop.anchor = null;
    pop.pinned = false;
  }
  function hidePopover() {
    clearTimeout(pop.showTimer);
    clearTimeout(pop.hideTimer);
    hideNow();
  }
  // A delayed hide must not cancel a show that was scheduled after it (moving from one term to the next).
  function scheduleHide() {
    clearTimeout(pop.hideTimer);
    pop.hideTimer = setTimeout(hideNow, 220);
  }

  function popoverContent(anchor) {
    if (anchor.dataset.learnTip && G) {
      const t = G.byId.get(anchor.dataset.learnTip);
      if (!t) return null;
      const concept = I && I.byId.get(t.concept);
      return h`
        <div class="learn-pop-title">${t.term}</div>
        <p>${t.short}</p>
        <div class="learn-pop-links">
          <button type="button" class="learn-link" data-learn-term="${t.id}">Glossary</button>
          ${concept ? h`<button type="button" class="learn-link" data-learn-concept="${concept.id}">Background: ${concept.title}</button>` : ''}
        </div>`;
    }
    if (anchor.dataset.learnInsn && X) {
      const arch = anchor.dataset.learnArch;
      const info = lookupMnemonic(arch, anchor.dataset.learnInsn);
      if (!info) return null;
      const concept = I && I.byId.get(info.concept);
      return h`
        <div class="learn-pop-title"><code>${anchor.dataset.learnInsn}</code> ${info.title}</div>
        <p>${rich(info.text)}</p>
        <div class="learn-pop-links">
          ${concept ? h`<button type="button" class="learn-link" data-learn-concept="${concept.id}">Background: ${concept.title}</button>` : ''}
        </div>`;
    }
    return null;
  }

  function showPopover(anchor, pinned) {
    if (!BS.learn.isOn() || !anchor || !anchor.isConnected) return;
    const content = popoverContent(anchor);
    if (!content) return;
    const el = ensurePopover();
    clearTimeout(pop.hideTimer);
    el.innerHTML = content;
    el.hidden = false;
    pop.anchor = anchor;
    pop.pinned = Boolean(pinned);
    const rect = anchor.getBoundingClientRect();
    const width = el.offsetWidth;
    const height = el.offsetHeight;
    let left = Math.min(rect.left, window.innerWidth - width - 8);
    left = Math.max(8, left);
    let top = rect.bottom + 6;
    if (top + height > window.innerHeight - 8) top = Math.max(8, rect.top - height - 6);
    el.style.left = `${Math.round(left)}px`;
    el.style.top = `${Math.round(top)}px`;
  }

  const tipAnchor = (node) => (node && node.closest ? node.closest('.learn-term, .learn-insn') : null);

  document.addEventListener('mouseover', (e) => {
    if (!BS.learn.isOn()) return;
    const anchor = tipAnchor(e.target);
    if (!anchor) return;
    if (anchor === pop.anchor) {
      clearTimeout(pop.hideTimer);
      return;
    }
    clearTimeout(pop.showTimer);
    pop.showTimer = setTimeout(() => showPopover(anchor, false), 280);
  });
  document.addEventListener('mouseout', (e) => {
    const anchor = tipAnchor(e.target);
    if (!anchor) return;
    clearTimeout(pop.showTimer);
    if (!pop.pinned) scheduleHide();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && pop.el && !pop.el.hidden) {
      e.preventDefault();
      e.stopPropagation();
      hidePopover();
    }
  }, true);
  document.addEventListener('scroll', () => {
    if (pop.el && !pop.el.hidden) hidePopover();
  }, true);

  // ---- glossary terms in the core's views ---------------------------------------------
  const TERM_SKIP = 'button, a, input, textarea, select, pre, script, style, kbd, .learn-view, .learn-term, .learn-idiom-row, .pedagogy-inline-box, .virt-viewport, .virt-table-header, .disasm-table, .xml-code-block, .open-panel';
  const WORD = /[A-Za-z0-9_$@]/;
  const TERM_BUDGET = 300;
  const PER_TERM = 2;

  function decorateTerms(root) {
    if (!G || !G.re || !root) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const value = node.nodeValue;
        if (!value || value.length < 2 || !/\S/.test(value)) return NodeFilter.FILTER_REJECT;
        const parent = node.parentElement;
        if (!parent || parent.closest(TERM_SKIP)) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    const nodes = [];
    while (nodes.length < 5000 && walker.nextNode()) nodes.push(walker.currentNode);
    const seen = new Map();
    let budget = TERM_BUDGET;
    for (const node of nodes) {
      if (budget <= 0) break;
      const text = node.nodeValue;
      G.re.lastIndex = 0;
      let match;
      let last = 0;
      let frag = null;
      while (budget > 0 && (match = G.re.exec(text))) {
        if (!match[0]) {
          // Never loop on an empty match (the keys are non-empty, but stay safe regardless).
          G.re.lastIndex += 1;
          continue;
        }
        const start = match.index;
        const end = start + match[0].length;
        const before = start > 0 ? text[start - 1] : '';
        const after = end < text.length ? text[end] : '';
        if ((before && WORD.test(before)) || (after && WORD.test(after))) continue;
        const id = G.strings.get(match[0]);
        const count = seen.get(id) || 0;
        if (!id || count >= PER_TERM) continue;
        seen.set(id, count + 1);
        frag = frag || document.createDocumentFragment();
        if (start > last) frag.appendChild(document.createTextNode(text.slice(last, start)));
        const span = document.createElement('span');
        span.className = 'learn-term';
        span.dataset.learnTip = id;
        span.textContent = match[0];
        frag.appendChild(span);
        last = end;
        budget -= 1;
      }
      if (frag) {
        if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
        node.parentNode.replaceChild(frag, node);
      }
    }
  }

  function undecorate(root) {
    if (!root) return;
    root.querySelectorAll('.learn-term').forEach((span) => {
      const parent = span.parentNode;
      if (!parent || span.closest('.learn-view')) return;
      parent.replaceChild(document.createTextNode(span.textContent), span);
      parent.normalize();
    });
    root.querySelectorAll('.learn-more, .learn-idiom-row').forEach((n) => n.remove());
    root.querySelectorAll('.learn-insn').forEach((cell) => {
      cell.classList.remove('learn-insn');
      delete cell.dataset.learnInsn;
      delete cell.dataset.learnArch;
    });
    root.querySelectorAll('.learn-idiom-in').forEach((row) => row.classList.remove('learn-idiom-in', 'learn-idiom-first', 'learn-idiom-last'));
    root.querySelectorAll('[data-learn-applied]').forEach((n) => n.removeAttribute('data-learn-applied'));
  }

  // ---- "Background" links in the field explanations -----------------------------------------
  let fieldIndex = null;
  function buildFieldIndex() {
    const map = new Map();
    const add = (fields) => (Array.isArray(fields) ? fields : []).forEach((f) => {
      if (f && f.pedagogy && f.pedagogy.concept) map.set(`${f.abs_offset}:${f.name}`, f.pedagogy.concept);
    });
    const doc = BS.state.doc;
    const slice = BS.getActiveSlice();
    if (doc && slice) {
      add(slice.header && slice.header.fields);
      add(doc.file_info && doc.file_info.fat_header && doc.file_info.fat_header.fields);
      (slice.load_commands || []).forEach((lc) => add(lc.fields));
      (slice.segments || []).forEach((seg) => {
        add(seg.fields);
        (seg.sections || []).forEach((sect) => add(sect.fields));
      });
      const cs = slice.code_signature_detail || {};
      add(cs.fields);
      add(cs.code_directory && cs.code_directory.fields);
    }
    return map;
  }
  const dropFieldIndex = () => {
    fieldIndex = null;
  };
  BS.on('doc:loaded', dropFieldIndex);
  BS.on('slice:changed', dropFieldIndex);
  BS.on('doc:closed', dropFieldIndex);

  function decorateFieldBoxes(root) {
    if (!I || !root) return;
    const boxes = root.querySelectorAll('.pedagogy-inline-box');
    if (!boxes.length) return;
    fieldIndex = fieldIndex || buildFieldIndex();
    boxes.forEach((box) => {
      if (box.querySelector('.learn-more')) return;
      const row = box.closest('tr[data-field-name]');
      if (!row) return;
      const concept = I.byId.get(fieldIndex.get(`${row.dataset.absOffset}:${row.dataset.fieldName}`));
      if (!concept) return;
      const wrap = document.createElement('div');
      wrap.className = 'learn-more';
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'learn-link';
      btn.dataset.learnConcept = concept.id;
      btn.textContent = `Background: ${concept.title}`;
      wrap.appendChild(btn);
      box.appendChild(wrap);
    });
  }

  // ---- instructions and idioms in the disassembly view ----------------------------------------
  function archFamily(name) {
    const n = str(name).toLowerCase();
    if (n.startsWith('arm64') || n.startsWith('aarch64')) return 'arm64';
    if (n.startsWith('x86') || n === 'i386' || n === 'amd64' || n === 'i686') return 'x86';
    return '';
  }

  /** Same rules as backend/learn/instructions.py lookup(): families, x86 prefixes, b.<cond>. */
  function lookupMnemonic(arch, mnemonic) {
    const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
    const table = plainTable(X && own(X.mnemonics, arch) ? X.mnemonics[arch] : null);
    let name = str(mnemonic).trim().toLowerCase().split(/\s+/).join(' ');
    let prefix = null;
    const prefixes = plainTable(X && own(X.prefixes, arch) ? X.prefixes[arch] : null);
    if (name.includes(' ')) {
      const head = name.slice(0, name.indexOf(' '));
      if (own(prefixes, head)) {
        prefix = prefixes[head];
        name = name.slice(head.length + 1);
      }
    }
    let entry = null;
    if (own(table, name)) {
      entry = plainTable(table[name]);
      if (entry.family) {
        const family = typeof entry.family === 'string' && own(X.families, entry.family) ? plainTable(X.families[entry.family]) : null;
        entry = family ? { title: entry.title, text: family.text, concept: family.concept } : null;
      }
    } else if (arch === 'arm64' && name.startsWith('b.') && own(table, 'b.cond')) {
      const conds = plainTable(own(X.conditions, 'arm64') ? X.conditions.arm64 : null);
      const cond = own(conds, name.slice(2)) && typeof conds[name.slice(2)] === 'string' ? conds[name.slice(2)] : '';
      entry = Object.assign({}, table['b.cond'], cond ? { title: `Branch if ${cond}` } : {});
    } else if (arch === 'x86' && name === 'callq') {
      entry = own(table, 'call') ? plainTable(table.call) : null;
    }
    if (entry && prefix) prefix = plainTable(prefix);
    if (entry && prefix) entry = { title: `${entry.title} (${prefix.title})`, text: `${prefix.text} ${entry.text}`, concept: entry.concept };
    return entry;
  }

  // row: {mn, ops, txt} already normalised (see decorateDisasm).
  const stepMatches = (row, step) => step.mn.has(row.mn) && (!step.ops || step.ops.some((p) => patternMatches(p, row.ops))) && (!step.txt || step.txt.some((p) => patternMatches(p, row.txt)));

  /** Same algorithm as backend/learn/instructions.py match_at(). */
  function matchAt(rows, index, idiom) {
    let pos = index;
    let first = true;
    for (const step of idiom.steps) {
      const limit = pos + (first ? 0 : step.gap);
      let found = -1;
      for (let k = pos; k <= limit && k < rows.length; k++) {
        if (stepMatches(rows[k], step)) {
          found = k;
          break;
        }
      }
      if (found >= 0) {
        pos = found + 1;
        first = false;
      } else if (!(step.opt && !first)) {
        return 0;
      }
    }
    return pos - index;
  }

  function annotate(rows, arch) {
    const out = [];
    const idioms = X.idioms.filter((i) => i.arch === arch);
    let busyUntil = 0;
    idiomWork = IDIOM_CAPS.work;
    for (let index = 0; index < rows.length && idiomWork > 0; index++) {
      if (index < busyUntil) continue;
      for (const idiom of idioms) {
        let span = matchAt(rows, index, idiom);
        if (!span) continue;
        if (idiom.id.endsWith('-pad')) {
          let end = index + span;
          while (end < rows.length && idiomWork > 0 && stepMatches(rows[end], idiom.steps[0])) end++;
          span = end - index;
        }
        busyUntil = index + span;
        out.push({ index, span, id: idiom.id });
        break;
      }
    }
    return out;
  }

  function decorateDisasm(root) {
    const table = root && root.querySelector('table.disasm-table');
    const slice = BS.getActiveSlice();
    const arch = slice ? archFamily(slice.arch_name) : '';
    if (!table || !X || !arch || table.dataset.learnApplied) return;
    table.dataset.learnApplied = '1';
    const trs = [...table.querySelectorAll('tr.disasm-row')];
    const rows = trs.map((tr) => {
      const cells = tr.cells;
      const opCell = cells[4];
      const opText = opCell && opCell.firstChild && opCell.firstChild.nodeType === 3 ? opCell.firstChild.nodeValue : opCell ? opCell.textContent : '';
      const mnemonic = str(cells[3] && cells[3].textContent).trim();
      const operands = str(opText).trim();
      const comment = str(cells[5] && cells[5].textContent).replace(/^;\s*/, '').trim();
      return {
        mnemonic,
        mn: mnemonic.toLowerCase().split(/\s+/).filter(Boolean).join(' '),
        ops: normaliseInsnText(operands),
        txt: normaliseInsnText(`${operands} ; ${comment}`),
      };
    });
    trs.forEach((tr, i) => {
      const cell = tr.cells[3];
      if (!cell || !lookupMnemonic(arch, rows[i].mnemonic)) return;
      cell.classList.add('learn-insn');
      cell.dataset.learnInsn = rows[i].mnemonic;
      cell.dataset.learnArch = arch;
    });
    annotate(rows, arch).forEach((a) => {
      const idiom = X.byId.get(a.id);
      const first = trs[a.index];
      if (!idiom || !first) return;
      const tr = document.createElement('tr');
      tr.className = 'learn-idiom-row learn-only';
      const td = document.createElement('td');
      td.colSpan = 6;
      const concept = I && I.byId.get(idiom.concept);
      td.innerHTML = h`<span class="learn-idiom-title">${idiom.title}</span><span class="learn-idiom-text">${rich(idiom.text)}</span>${concept ? h` <button type="button" class="learn-link" data-learn-concept="${concept.id}">Background</button>` : ''}`;
      tr.appendChild(td);
      first.parentNode.insertBefore(tr, first);
      for (let k = a.index; k < a.index + a.span && k < trs.length; k++) {
        trs[k].classList.add('learn-idiom-in');
        if (k === a.index) trs[k].classList.add('learn-idiom-first');
        if (k === a.index + a.span - 1) trs[k].classList.add('learn-idiom-last');
      }
    });
  }

  function applyLearnMode(id, bodyEl) {
    if (!bodyEl || !BS.learn.isOn()) return;
    getBase().then(() => {
      if (!BS.learn.isOn() || !bodyEl.isConnected) return;
      if (!bodyEl.querySelector('.learn-view')) decorateTerms(bodyEl);
      decorateFieldBoxes(bodyEl);
      if (bodyEl.querySelector('table.disasm-table')) {
        getInstructions().then(() => {
          if (BS.learn.isOn() && bodyEl.isConnected) decorateDisasm(bodyEl);
        }).catch(() => {});
      }
    }).catch(() => {});
  }

  BS.on('view:rendered', ({ id, bodyEl }) => applyLearnMode(id, bodyEl));
  BS.on('learnmode:changed', ({ on }) => {
    const body = document.getElementById('inspector-body');
    hidePopover();
    if (on) applyLearnMode(BS.state.selectedNodeId, body);
    else undecorate(body);
    const hint = body && body.querySelector('.learn-hint');
    if (hint) hint.innerHTML = learnHint();
  });

  /** Keyboard path to the same help: the focused instruction, or the terms of the open view. */
  function explainSelection() {
    const active = document.activeElement;
    const row = active && active.closest ? active.closest('tr.disasm-row') : null;
    const insn = row ? row.querySelector('.learn-insn') : document.querySelector('#inspector-body tr.disasm-row.selected .learn-insn');
    if (insn) {
      showPopover(insn, true);
      return;
    }
    const body = document.getElementById('inspector-body');
    const ids = [...new Set([...(body ? body.querySelectorAll('.learn-term') : [])].map((n) => n.dataset.learnTip))].filter((id) => G && G.byId.has(id));
    if (!ids.length) {
      BS.ui.toast('This view shows no glossary terms. The glossary lists them all.', 'info');
      return;
    }
    const wrap = document.createElement('div');
    wrap.className = 'learn-view learn-modal-terms';
    wrap.innerHTML = h`<dl class="learn-terms">${ids.map((id) => {
      const t = G.byId.get(id);
      return h`<div class="learn-term-entry"><dt>${t.term}</dt><dd>${t.short} <span class="learn-term-links"><button type="button" class="learn-link" data-learn-term="${t.id}">Glossary</button></span></dd></div>`;
    })}</dl>`;
    const modal = BS.ui.modal({ title: 'Terms in this view', bodyEl: wrap, className: 'learn-modal' });
    wrap.addEventListener('click', (e) => {
      if (e.target.closest('[data-learn-term], [data-learn-concept]')) setTimeout(() => modal.close(), 0);
    });
  }

  // ===========================================================================
  // Clicks on anything this file rendered
  // ===========================================================================
  document.addEventListener('click', (e) => {
    const target = e.target.nodeType === 1 ? e.target : e.target.parentElement;
    if (!target) return;

    const tip = target.closest('.learn-term, .learn-insn');
    if (tip && BS.learn.isOn()) {
      showPopover(tip, true);
      return;
    }
    if (pop.el && !pop.el.hidden && !target.closest('#learn-popover')) hidePopover();

    const node = target.closest('[data-learn-concept], [data-learn-term], [data-learn-view], [data-learn-bytes], [data-learn-open], [data-learn-sample], [data-learn-tour], [data-learn-read], [data-learn-act], [data-learn-fields-format]');
    if (!node) return;
    const d = node.dataset;
    if (node.closest('#learn-popover')) hidePopover();

    if (d.learnConcept) {
      if (d.learnMark && !progress.concepts[d.learnMark]) {
        progress.concepts[d.learnMark] = Date.now();
        saveProgress();
      }
      openConcept(d.learnConcept);
    } else if (d.learnTerm) {
      openTerm(d.learnTerm);
    } else if (d.learnView) {
      BS.nav.openView(d.learnView, d.learnParamT ? { t: d.learnParamT } : undefined);
    } else if (d.learnBytes) {
      showBytes(targets.get(d.learnBytes));
    } else if (d.learnOpen) {
      openTarget(targets.get(d.learnOpen));
    } else if (d.learnSample) {
      const article = node.closest('[data-concept]');
      const thenTour = d.learnThenTour;
      const back = article ? article.dataset.concept : '';
      openSampleThen(d.learnSample, () => {
        if (thenTour) startTour(thenTour);
        else if (back) openConcept(back);
      });
    } else if (d.learnTour) {
      startTour(d.learnTour, { restart: d.learnRestart === '1' });
    } else if (d.learnRead) {
      if (progress.concepts[d.learnRead]) delete progress.concepts[d.learnRead];
      else progress.concepts[d.learnRead] = Date.now();
      saveProgress();
      const on = Boolean(progress.concepts[d.learnRead]);
      node.setAttribute('aria-pressed', on ? 'true' : 'false');
      node.textContent = on ? 'Read' : 'Mark as read';
    } else if (d.learnAct === 'toggle-learn') {
      BS.learn.toggle();
    } else if (d.learnFieldsFormat) {
      fieldsFormat = d.learnFieldsFormat;
      BS.nav.openView(VIEW_FIELDS, { f: fieldsFormat });
    }
  });

  // ===========================================================================
  // Commands
  // ===========================================================================
  const tourActive = () => Boolean(tour.active);
  const cmd = (id, title, shortcut, run, extra) => BS.registerCommand(Object.assign({ id, title, shortcut, run, section: 'Learn' }, extra));

  cmd('learn.open', 'Learn: learning path', 'Shift+L', () => BS.nav.openView(VIEW_HOME), { hint: 'The curriculum, from bytes to running processes', keywords: 'curriculum course teach concepts tutorial' });
  cmd('learn.tours', 'Learn: tours', null, () => BS.nav.openView(VIEW_TOURS), { hint: 'Guided walks through the open file', keywords: 'guided tutorial exercise practice' });
  cmd('learn.glossary', 'Learn: glossary', 'Shift+K', () => BS.nav.openView(VIEW_GLOSSARY), { hint: 'Look up a term', keywords: 'dictionary terms definitions meaning' });
  cmd('learn.compare', 'Learn: format comparison', null, () => BS.nav.openView(VIEW_COMPARE), { keywords: 'mach-o elf pe side by side rosetta' });
  cmd('learn.fields', 'Learn: field reference', null, () => BS.nav.openView(VIEW_FIELDS), { keywords: 'header struct fields meaning reference' });
  cmd('learn.explain', 'Explain the selected instruction or the terms in this view', 'X', () => getBase().then(() => getInstructions()).then(explainSelection), { when: () => BS.learn.isOn(), hint: 'Learn mode', keywords: 'help what is glossary mnemonic' });
  cmd('learn.tour.next', 'Tour: next step', '.', nextStep, { when: tourActive });
  cmd('learn.tour.back', 'Tour: previous step', ',', prevStep, { when: tourActive });
  cmd('learn.tour.focus', 'Tour: focus the tour panel', '4', () => {
    tour.minimised = false;
    renderPanel(true);
  }, { when: tourActive });
  cmd('learn.tour.end', 'Tour: end the tour', null, () => {
    saveTour(false);
    endTour('');
  }, { when: tourActive });
  cmd('learn.reset', 'Learn: reset progress…', null, () => {
    const wrap = document.createElement('div');
    wrap.className = 'learn-view learn-confirm';
    wrap.innerHTML = h`<p>This forgets which concepts you have read and where you are in each tour. It is stored only in this browser.</p>
      <div class="learn-hero-actions"><button type="button" class="learn-btn learn-btn-primary" data-confirm="yes">Reset progress</button><button type="button" class="learn-btn" data-confirm="no">Cancel</button></div>`;
    const modal = BS.ui.modal({ title: 'Reset learning progress', bodyEl: wrap, className: 'learn-modal' });
    wrap.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-confirm]');
      if (!btn) return;
      if (btn.dataset.confirm === 'yes') {
        if (tour.active) endTour('');
        BS.storage.remove(PROGRESS_KEY);
        progress = readProgress();
        updateBadge();
        BS.ui.toast('Learning progress was reset.', 'ok');
        const open = BS.state.selectedNodeId;
        if (open === VIEW_HOME || open === VIEW_TOURS) BS.nav.openView(open);
      }
      modal.close();
    });
  }, { keywords: 'clear forget history' });

  // Terms, concepts and tours are searchable from the palette. They appear only once something
  // has been typed, so the unfiltered command list stays short.
  const paletteQuery = () => {
    const input = document.getElementById('cmdk-input');
    return input ? input.value.replace(/^>\s*/, '').trim() : '';
  };
  const whenSearching = () => paletteQuery().length >= 2;

  function registerContentCommands() {
    G.terms.forEach((t) => {
      BS.registerCommand({ id: `learn.term.${t.id}`, title: `${t.term} (glossary)`, hint: t.short, keywords: [t.id, ...(t.aka || [])].join(' '), section: 'Glossary', when: whenSearching, run: () => openTerm(t.id) });
    });
    I.concepts.forEach((c) => {
      BS.registerCommand({ id: `learn.concept.${c.id}`, title: `Learn: ${c.title}`, hint: c.summary, keywords: c.id.replace(/-/g, ' '), section: 'Learn', when: whenSearching, run: () => openConcept(c.id) });
    });
    I.tours.forEach((t) => {
      BS.registerCommand({ id: `learn.tour.start.${t.id}`, title: `Tour: ${t.title}`, hint: t.summary, keywords: 'guided walk exercise', section: 'Learn', when: whenSearching, run: () => startTour(t.id) });
    });
  }

  BS.on('ready', () => {
    // Fetched once, shortly after start-up, so that the palette can search the glossary.
    setTimeout(() => {
      getBase().then(() => {
        updateBadge();
        registerContentCommands();
        if (BS.learn.isOn()) applyLearnMode(BS.state.selectedNodeId, document.getElementById('inspector-body'));
      }).catch(() => {});
    }, 300);
  });

  // For tests and for other feature files.
  BS.learnContent = { startTour, openConcept, openTerm, state: tour };
})();
