/**
 * BinaryStudio — High-Density Multi-Format Binary, Disassembly & Firmware Inspector
 * Supports Apple Mach-O (32/64 & Universal Fat), Linux ELF32/64, and Windows PE32/PE32+
 * Frontend Architecture & Interactive State Engine (Vanilla ES6+)
 */

(() => {
  'use strict';

  const HEX_ROW_HEIGHT = 21;
  const HEX_BYTES_PER_ROW = 16;
  const HEX_CHUNK_SIZE = 4096; // 256 rows per cached chunk
  const VIRT_ROW_HEIGHT = 24;

  // =========================================================================
  // Application State Store
  // =========================================================================
  const state = {
    presets: [],
    doc: null,
    activeSliceIndex: 0,

    // Tree Navigator
    treeNodesMap: new Map(), // id -> node descriptor
    treeRootNodes: [],
    expandedNodeIds: new Set(['load_commands', 'segments', 'dyld_info', 'code_signature']),
    selectedNodeId: 'overview',
    treeFilter: '',

    // Memory Map Ribbon
    memmapScale: 'sqrt', // 'sqrt' | 'linear'

    // Synchronized Selection & Spans (all coordinates in abs_offset)
    cursorOffset: 0,
    structSpan: null, // { abs_offset, size, label }
    fieldSpan: null,  // { abs_offset, size, label }

    // Hex Viewer Cache & Modes
    hexDock: 'right',    // 'right' | 'bottom'
    hexAddrMode: 'file', // 'file' | 'vm'
    hexChunks: new Map(), // chunkStartOffset -> Uint8Array
    hexPendingChunks: new Set(),
    decoderEndian: 'little', // 'little' | 'big'
    lastDecodeData: null,

    // Inspector Sub-View States
    symSearch: '',
    symScope: 'all', // 'all' | 'ext' | 'local' | 'undef'
    symDemangle: true,
    strSearch: '',
    strSourceFilter: 'all',
    csSubTab: 'summary', // 'summary' | 'entitlements' | 'slots' | 'fields'
    dyldSubTab: 'fixups', // 'fixups' | 'imports' | 'exports' | 'binds'
    disasmCache: new Map(), // key -> instructions[]
    activeDisasmSection: '',
    activeDisasmVmaddr: '',

    // Back / Forward Navigation History
    history: [],
    historyIndex: -1,
    suppressHistory: false,

    // Cmd+K Omni-Search
    cmdkOpen: false,
    cmdkScope: 'all',
    cmdkResults: [],
    cmdkActiveIdx: 0,
  };

  // =========================================================================
  // Utility Formatters
  // =========================================================================
  function hex(num, pad = 0) {
    if (num === null || num === undefined || Number.isNaN(num)) return '—';
    if (typeof num === 'string') {
      return num.startsWith('0x') || num.startsWith('0X') ? num.toLowerCase() : num;
    }
    const n = Number(num);
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
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function parseBigIntHex(val) {
    if (val === null || val === undefined) return 0n;
    if (typeof val === 'bigint') return val;
    if (typeof val === 'number') return BigInt(Math.trunc(val));
    const s = String(val).trim();
    if (!s) return 0n;
    try {
      return BigInt(s);
    } catch {
      return 0n;
    }
  }

  function protClass(protStr) {
    if (!protStr) return 'nil';
    const p = protStr.toLowerCase();
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

  function setStatus(text, mode = 'ready') {
    const dot = document.getElementById('status-dot');
    const txt = document.getElementById('status-text');
    if (txt) txt.textContent = text;
    if (dot) {
      dot.className = 'status-indicator';
      if (mode === 'loading') dot.classList.add('loading');
      if (mode === 'error') dot.classList.add('error');
    }
  }

  // =========================================================================
  // Fast Client-Side Offset <-> VM Address Lookup (Fallback + Live Hex Col)
  // =========================================================================
  function absOffsetToVmAddr(absOffset, slice) {
    if (!slice || !Array.isArray(slice.segments)) return null;
    const sliceOff = absOffset - (slice.slice_base_offset || 0);
    if (sliceOff < 0) return null;
    for (const seg of slice.segments) {
      if (seg.segname === '__PAGEZERO' && (seg.filesize || 0) === 0) continue;
      const foff = Number(seg.fileoff || 0);
      const fsize = Number(seg.filesize || 0);
      if (sliceOff >= foff && sliceOff < foff + fsize) {
        const vmBase = parseBigIntHex(seg.vmaddr ?? seg.vmaddr_int);
        const vm = vmBase + BigInt(sliceOff - foff);
        return '0x' + vm.toString(16);
      }
    }
    return null;
  }

  // =========================================================================
  // API Client Methods
  // =========================================================================
  async function fetchPresets() {
    try {
      const res = await fetch('/api/presets');
      if (!res.ok) return;
      const data = await res.json();
      if (Array.isArray(data.presets) && data.presets.length > 0) {
        state.presets = data.presets;
        renderPresetsBar();
      }
    } catch (err) {
      console.warn('Presets fetch notice:', err);
    }
  }

  function renderPresetsBar() {
    const bar = document.getElementById('presets-bar');
    if (!bar || !state.presets.length) return;
    const dotColors = ['dot-purple', 'dot-amber', 'dot-cyan', 'dot-emerald'];
    let html = '<span class="toolbar-label">Presets:</span>';
    state.presets.forEach((p, idx) => {
      const dot = dotColors[idx % dotColors.length];
      const active = state.doc && state.doc.file_info && state.doc.file_info.path === p.path ? 'active' : '';
      html += `
        <button class="preset-pill ${active}" data-preset-path="${escapeHtml(p.path)}" title="${escapeHtml(p.description || p.path)}">
          <span class="preset-dot ${dot}"></span>${escapeHtml(p.label)}
        </button>
      `;
    });
    bar.innerHTML = html;
  }

  async function loadBinaryByPath(filePath) {
    if (!filePath) return;
    setStatus(`Parsing ${filePath}…`, 'loading');
    const pathInput = document.getElementById('path-input');
    if (pathInput) pathInput.value = filePath;

    try {
      const res = await fetch('/api/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: filePath }),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      applyLoadedDocument(data);
      setStatus('Ready', 'ready');
    } catch (err) {
      setStatus(`Error: ${err.message}`, 'error');
      renderLoadError(filePath, err.message);
    }
  }

  async function uploadBinaryFile(file) {
    if (!file) return;
    setStatus(`Uploading & parsing ${file.name} (${formatBytes(file.size)})…`, 'loading');
    try {
      const arrayBuf = await file.arrayBuffer();
      const res = await fetch('/api/upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Filename': encodeURIComponent(file.name),
        },
        body: arrayBuf,
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      applyLoadedDocument(data);
      setStatus(`Loaded ${file.name}`, 'ready');
    } catch (err) {
      setStatus(`Upload failed: ${err.message}`, 'error');
    }
  }

  function renderLoadError(filePath, msg) {
    const body = document.getElementById('inspector-body');
    if (!body) return;
    body.innerHTML = `
      <div class="overview-container">
        <div class="panel-card" style="border-color: var(--danger-border);">
          <div class="panel-card-header" style="color: var(--danger-fg);">Failed to Parse Binary</div>
          <div style="padding: 16px; display: flex; flex-direction: column; gap: 10px;">
            <div>Could not load <code style="color: var(--rx-fg);">${escapeHtml(filePath)}</code>:</div>
            <pre class="xml-code-block" style="color: var(--danger-fg);">${escapeHtml(msg)}</pre>
            <div style="color: var(--text-secondary);">Try clicking one of the built-in Presets in the top bar (e.g. <strong>/bin/ls</strong>, <strong>/usr/bin/true</strong>, or <strong>Synthetic Universal</strong>).</div>
          </div>
        </div>
      </div>
    `;
  }

  // =========================================================================
  // Document Initialization & Slice Switching
  // =========================================================================
  function applyLoadedDocument(doc) {
    state.doc = doc;
    state.hexChunks.clear();
    state.hexPendingChunks.clear();
    state.disasmCache.clear();
    state.history = [];
    state.historyIndex = -1;

    // Prefer arm64 / arm64e slice by default if Universal binary
    let defaultSlice = 0;
    if (Array.isArray(doc.slices) && doc.slices.length > 1) {
      const armIdx = doc.slices.findIndex(s => /arm64/i.test(s.arch_name));
      if (armIdx >= 0) defaultSlice = armIdx;
    }
    state.activeSliceIndex = defaultSlice;

    // Update Status Bar & Presets Highlight
    const fi = doc.file_info || {};
    document.getElementById('status-file').textContent = `${fi.filename || fi.path || 'binary'} (${formatBytes(fi.file_size || 0)})`;
    document.getElementById('status-hash').textContent = `SHA-256: ${(fi.sha256 || '—').slice(0, 16)}…`;
    document.getElementById('status-hash').title = `SHA-256: ${fi.sha256 || '—'}\nMD5: ${fi.md5 || '—'}`;
    if (fi.path) {
      document.getElementById('path-input').value = fi.path;
    }
    renderPresetsBar();
    renderSliceSelector();
    activateSlice(state.activeSliceIndex);
  }

  function renderSliceSelector() {
    const sel = document.getElementById('slice-select');
    if (!sel || !state.doc) return;
    const slices = state.doc.slices || [];
    const isFat = state.doc.file_info && state.doc.file_info.is_fat;
    sel.innerHTML = slices
      .map((s, idx) => {
        const prefix = isFat ? `[Fat #${idx}] ` : '';
        return `<option value="${idx}" ${idx === state.activeSliceIndex ? 'selected' : ''}>${escapeHtml(prefix + s.arch_name)} (${formatBytes(s.slice_size)})</option>`;
      })
      .join('');
  }

  function activateSlice(sliceIdx) {
    const slices = (state.doc && state.doc.slices) || [];
    if (!slices.length) return;
    state.activeSliceIndex = Math.max(0, Math.min(sliceIdx, slices.length - 1));
    const slice = getActiveSlice();

    const baseOff = slice.slice_base_offset || 0;
    state.cursorOffset = baseOff;
    state.structSpan = { abs_offset: baseOff, size: slice.header?.region?.size || 32, label: 'binary_header' };
    state.fieldSpan = null;
    state.activeDisasmSection = '';
    state.activeDisasmVmaddr = '';

    const fmtBadge = document.getElementById('brand-format-badge');
    if (fmtBadge) {
      if (slice.format === 'ELF') {
        fmtBadge.textContent = slice.is_64 ? '0x7F454C46 • ELF64' : '0x7F454C46 • ELF32';
      } else if (slice.format === 'PE') {
        fmtBadge.textContent = slice.is_64 ? 'MZ/PE • PE32+' : 'MZ/PE • PE32';
      } else {
        fmtBadge.textContent = slice.header?.magic || '0xFEEDFACF';
      }
    }

    document.getElementById('status-arch').textContent = `Arch: ${slice.arch_name} (${slice.format_display || slice.overview?.filetype_name || 'Mach-O'})`;

    buildStructureTree();
    renderStructureTree();
    renderMemoryMapRibbon();
    initHexViewport();
    selectTreeNode('overview', { scrollHex: true });
    updateConverterFromOffset(baseOff);
  }

  // =========================================================================
  // Left Sidebar: Build & Render Hierarchical Structure Tree
  // =========================================================================
  function buildStructureTree() {
    state.treeNodesMap.clear();
    state.treeRootNodes = [];
    if (!state.doc) return;

    const fi = state.doc.file_info || {};
    const slice = getActiveSlice();
    if (!slice) return;

    const reg = (node) => {
      state.treeNodesMap.set(node.id, node);
      return node;
    };

    const fmt = slice.format || 'MACHO';
    const isElf = fmt === 'ELF';
    const isPe = fmt === 'PE';

    // 1. Binary Overview Dashboard
    state.treeRootNodes.push(
      reg({
        id: 'overview',
        label: 'Binary Overview',
        icon: 'OV',
        iconClass: 'badge-cyan',
        badge: slice.format_display || slice.overview?.filetype_name || 'MACH-O',
        region: slice.header?.region || { abs_offset: slice.slice_base_offset || 0, size: 32 },
        type: 'overview',
      })
    );

    // 1B. Semantic & Entropy Intelligence Layer
    const sem = slice.semantic_layers || {};
    const entVal = sem.entropy_analysis?.overall_entropy;
    state.treeRootNodes.push(
      reg({
        id: 'semantic_intel',
        label: 'Semantic & Entropy Intel',
        icon: 'SEM',
        iconClass: 'badge-emerald',
        badge: entVal !== undefined ? `${entVal.toFixed(1)}b` : 'INTEL',
        region: slice.header?.region || { abs_offset: slice.slice_base_offset || 0, size: 64 },
        type: 'semantic_intel',
        subtitle: `${sem.entropy_analysis?.overall_classification || 'Entropy'} • ${(sem.capabilities?.categories || []).length} Capabilities • ${sem.provenance?.compiler_family || 'Toolchain'}`,
      })
    );

    // 1C. OS Loader Lifecycle Simulator (Pedagogy Layer)
    const ped = slice.pedagogy || {};
    state.treeRootNodes.push(
      reg({
        id: 'loader_lifecycle',
        label: 'OS Loader Lifecycle',
        icon: 'LDR',
        iconClass: 'badge-amber',
        badge: '6 STAGES',
        region: slice.header?.region || { abs_offset: slice.slice_base_offset || 0, size: 64 },
        type: 'loader_lifecycle',
        subtitle: ped.loader_lifecycle?.loader_name || 'Kernel & Dynamic Linker Execution Walkthrough',
      })
    );

    // 1D. Format Rosetta Stone & Guided Tours
    state.treeRootNodes.push(
      reg({
        id: 'rosetta_stone',
        label: 'Rosetta Stone & Tours',
        icon: 'EDU',
        iconClass: 'badge-purple',
        badge: `${(ped.guided_tours || []).length} TOURS`,
        region: slice.header?.region || { abs_offset: slice.slice_base_offset || 0, size: 64 },
        type: 'rosetta_stone',
        subtitle: 'Mach-O ⇄ ELF ⇄ Windows PE Cross-Format Matrix & Interactive Challenges',
      })
    );

    // 2. Universal Fat Header (if Fat binary)
    if (fi.is_fat && fi.fat_header) {
      state.treeRootNodes.push(
        reg({
          id: 'fat_header',
          label: 'Universal Fat Header',
          icon: 'FAT',
          iconClass: 'badge-purple',
          badge: `${fi.fat_header.nfat_arch || (fi.fat_header.slices_summary || []).length} arch`,
          region: fi.fat_header.region || { abs_offset: 0, size: 48 },
          type: 'fields',
          fields: fi.fat_header.fields || [],
          subtitle: `${fi.fat_header.magic_name || 'FAT_MAGIC'} (${fi.fat_header.magic || '0xcafebabe'})`,
        })
      );
    }

    // 3. Primary File Header (Mach-O Header / ELF Ehdr / PE DOS+NT Header)
    if (slice.header) {
      const hdrLabel = isElf
        ? (slice.header.is_64bit ? 'ELF64 Header (Ehdr)' : 'ELF32 Header (Ehdr)')
        : isPe
        ? (slice.header.is_64bit ? 'PE32+ NT & Optional Header' : 'PE32 NT & Optional Header')
        : (slice.header.is_64bit ? 'Mach64 Header' : 'Mach32 Header');
      const hdrNode = reg({
        id: 'mach_header',
        label: hdrLabel,
        icon: 'HDR',
        iconClass: 'badge-purple',
        sub: hex(slice.header.region?.abs_offset ?? slice.slice_base_offset),
        region: slice.header.region,
        type: 'fields',
        fields: slice.header.fields || [],
        subtitle: `${slice.header.magic_name} • ${slice.header.cputype_name} • ${slice.header.filetype_name}`,
      });
      state.treeNodesMap.set('header_0', hdrNode);
      state.treeRootNodes.push(hdrNode);
    }

    // 4. Load Commands / Program Headers / PE Headers & Data Directories (#0..#N)
    const lcs = slice.load_commands || [];
    const lcChildren = lcs.map((lc) =>
      reg({
        id: `lc_${lc.index}`,
        label: `#${lc.index} ${lc.cmd_name}`,
        icon: isElf ? 'PH' : isPe ? 'DIR' : 'LC',
        iconClass: 'badge-purple',
        sub: lc.summary ? lc.summary.split(' ')[0] : hex(lc.region?.abs_offset),
        region: lc.region,
        type: 'load_command',
        lc,
        fields: lc.fields || [],
        subtitle: lc.summary || `${lc.cmd_name} (${lc.cmdsize} bytes)`,
      })
    );

    const lcGroupLabel = isElf
      ? 'Program Headers & Notes'
      : isPe
      ? 'Headers & Data Directories'
      : 'Load Commands';

    state.treeRootNodes.push(
      reg({
        id: 'load_commands',
        label: lcGroupLabel,
        icon: 'CMD',
        iconClass: 'badge-purple',
        badge: String(lcs.length),
        region: lcs.length
          ? {
              abs_offset: lcs[0].region?.abs_offset || (slice.slice_base_offset + 32),
              size: slice.header?.sizeofcmds || 512,
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
          label: `${sect.sectname}`,
          icon: sect.is_executable ? 'ASM' : 'SEC',
          iconClass: sect.is_executable ? 'badge-cyan' : 'badge-emerald',
          prot: sect.prot || seg.initprot,
          sub: formatBytes(sect.size),
          region: sect.region || { abs_offset: sect.abs_offset, size: sect.size, vmaddr: sect.vmaddr },
          headerRegion: sect.header_region,
          type: 'section',
          segment: seg,
          section: sect,
          fields: sect.fields || [],
          subtitle: `${seg.segname},${sect.sectname} (${sect.section_type || 'S_REGULAR'})`,
        });
        state.treeNodesMap.set(`sect_${sect.segname}_${sect.sectname}`, sectNode);
        return sectNode;
      });

      const segNode = reg({
        id: `seg_${sIdx}`,
        label: seg.segname || `Segment #${sIdx}`,
        icon: 'SEG',
        iconClass: 'badge-cyan',
        prot: seg.initprot,
        badge: sectChildren.length ? String(sectChildren.length) : null,
        region: seg.region || { abs_offset: seg.abs_offset, size: seg.filesize, vmaddr: seg.vmaddr },
        headerRegion: seg.header_region,
        type: 'segment',
        segment: seg,
        fields: seg.fields || [],
        subtitle: `VM: ${seg.vmaddr} (${formatBytes(seg.vmsize_int)}) • File: ${hex(seg.abs_offset)} (${formatBytes(seg.filesize)}) • Prot: ${seg.initprot}/${seg.maxprot}`,
        children: sectChildren,
      });
      state.treeNodesMap.set(`seg_${seg.segname}`, segNode);
      return segNode;
    });

    state.treeRootNodes.push(
      reg({
        id: 'segments',
        label: 'Segments & Sections',
        icon: 'MAP',
        iconClass: 'badge-cyan',
        badge: `${segs.length}`,
        region: segs[0]?.region || slice.header?.region,
        type: 'segments_summary',
        children: segChildren,
      })
    );

    // 6. Disassembly View
    state.treeRootNodes.push(
      reg({
        id: 'disassembly',
        label: 'Disassembly (Code)',
        icon: 'ASM',
        iconClass: 'badge-amber',
        badge: slice.arch_name,
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
    const dyldLabel = isElf
      ? 'Dynamic Linking (PLT/GOT & RELA)'
      : isPe
      ? 'Imports (IAT), Exports & Relocs'
      : 'Dyld & Chained Fixups';
    state.treeRootNodes.push(
      reg({
        id: 'dyld_info',
        label: dyldLabel,
        icon: 'FIX',
        iconClass: 'badge-amber',
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
        label: 'Symbol Table',
        icon: 'SYM',
        iconClass: 'badge-cyan',
        badge: String(syms.length),
        region: syms[0] ? { abs_offset: syms[0].abs_offset, size: syms.length * (syms[0].size || 16) } : slice.header?.region,
        type: 'symtab',
      })
    );

    // 9. Dynamic Symbol Table (LC_DYSYMTAB / PLT / IAT Thunks)
    const dysym = slice.dysymtab || {};
    const indCount = (dysym.indirect_symbols || []).length;
    state.treeRootNodes.push(
      reg({
        id: 'dysymtab',
        label: isElf ? 'PLT / GOT Jump Slots' : isPe ? 'IAT Thunk Table' : 'Dynamic Symbols (Stubs)',
        icon: 'DYS',
        iconClass: 'badge-purple',
        badge: String(indCount),
        region: slice.header?.region,
        type: 'dysymtab',
      })
    );

    // 10. Strings Table & C-String Literals
    const strs = slice.strings || [];
    state.treeRootNodes.push(
      reg({
        id: 'strings',
        label: 'Strings & Literals',
        icon: 'STR',
        iconClass: 'badge-emerald',
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
        label: 'Entry & Function Starts',
        icon: 'FN',
        iconClass: 'badge-cyan',
        badge: String(fnStarts.length || (slice.entry_point ? 1 : 0)),
        region: slice.entry_point?.abs_offset
          ? { abs_offset: slice.entry_point.abs_offset, size: 16, vmaddr: slice.entry_point.vmaddr }
          : slice.header?.region,
        type: 'function_starts',
      })
    );

    // 12. Objective-C Metadata / Fileset Entries (if present or inspectable)
    const objc = slice.objc_metadata || {};
    const objcTotal = (objc.classes?.length || 0) + (objc.selectors?.length || 0) + (objc.protocols?.length || 0) + (slice.fileset_entries?.length || 0);
    if (objcTotal > 0 || objc.present) {
      state.treeRootNodes.push(
        reg({
          id: 'objc_metadata',
          label: 'ObjC & Fileset Metadata',
          icon: 'OBJ',
          iconClass: 'badge-purple',
          badge: String(objcTotal),
          region: slice.header?.region,
          type: 'objc_metadata',
        })
      );
    }

    // 13. Code Signature & Entitlements / Authenticode / ELF Build-ID
    const cs = slice.code_signature_detail || {};
    const csLabel = isPe
      ? 'Authenticode (WIN_CERTIFICATE)'
      : isElf
      ? 'Code Signing & ELF Notes'
      : 'Code Signature & Entitlements';
    state.treeRootNodes.push(
      reg({
        id: 'code_signature',
        label: csLabel,
        icon: 'SIG',
        iconClass: 'badge-pink',
        badge: cs.present ? (cs.code_directory?.cdhash_verified ? 'VERIFIED' : 'SIGNED') : (isElf && slice.elf_metadata?.notes?.length ? `${slice.elf_metadata.notes.length} NOTES` : 'NONE'),
        region: cs.superblob_region || slice.header?.region,
        type: 'code_signature',
      })
    );

    // 14. Security & Hardening Audit
    const sec = slice.security_posture || {};
    const warnCount = (sec.checks || []).filter(c => c.status === 'WARN' || c.status === 'FAIL').length;
    state.treeRootNodes.push(
      reg({
        id: 'security_audit',
        label: 'Security & Hardening Audit',
        icon: 'SEC',
        iconClass: warnCount > 0 ? 'badge-danger' : 'badge-emerald',
        badge: warnCount > 0 ? `${warnCount} WARN` : 'PASS',
        region: slice.header?.region,
        type: 'security_audit',
      })
    );
  }

  function renderStructureTree() {
    const container = document.getElementById('structure-tree');
    if (!container) return;
    const filter = state.treeFilter.trim().toLowerCase();

    const matchesNode = (node) => {
      if (!filter) return true;
      if (node.label.toLowerCase().includes(filter)) return true;
      if (node.subtitle && node.subtitle.toLowerCase().includes(filter)) return true;
      if (node.sub && node.sub.toLowerCase().includes(filter)) return true;
      if (Array.isArray(node.children)) {
        return node.children.some(matchesNode);
      }
      return false;
    };

    const htmlRows = [];
    const renderNode = (node, depth = 0) => {
      if (!matchesNode(node)) return;
      const hasChildren = Array.isArray(node.children) && node.children.length > 0;
      const isExpanded = filter ? true : state.expandedNodeIds.has(node.id);
      const isSelected = state.selectedNodeId === node.id;
      const indentPx = 6 + depth * 14;

      const protBadge = node.prot
        ? `<span class="prot-pill ${protClass(node.prot)}">${escapeHtml(node.prot.toUpperCase())}</span>`
        : '';
      const countBadge = node.badge
        ? `<span class="tree-badge">${escapeHtml(node.badge)}</span>`
        : '';
      const subText = node.sub && !node.badge
        ? `<span class="tree-sub">${escapeHtml(node.sub)}</span>`
        : '';

      htmlRows.push(`
        <div class="tree-node-row ${isSelected ? 'selected' : ''}" data-node-id="${escapeHtml(node.id)}" style="padding-left: ${indentPx}px" role="treeitem" aria-selected="${isSelected}">
          <span class="tree-twisty ${hasChildren ? (isExpanded ? 'expanded' : '') : 'leaf'}" data-twisty-id="${escapeHtml(node.id)}">▶</span>
          <span class="tree-icon ${node.iconClass || 'badge-cyan'}">${escapeHtml(node.icon || '•')}</span>
          <span class="tree-label" title="${escapeHtml(node.subtitle || node.label)}">${escapeHtml(node.label)}</span>
          ${protBadge}${subText}${countBadge}
        </div>
      `);

      if (hasChildren && isExpanded) {
        node.children.forEach(child => renderNode(child, depth + 1));
      }
    };

    state.treeRootNodes.forEach(n => renderNode(n, 0));
    container.innerHTML = htmlRows.join('');
  }

  function selectTreeNode(nodeId, opts = { scrollHex: true, recordHistory: true }) {
    const node = state.treeNodesMap.get(nodeId);
    if (!node) return;
    const canonicalId = node.id;

    // Expand parent if selecting a child node
    if (canonicalId.startsWith('lc_')) state.expandedNodeIds.add('load_commands');
    if (canonicalId.startsWith('seg_') || canonicalId.startsWith('sect_')) state.expandedNodeIds.add('segments');
    if (canonicalId.startsWith('sect_')) {
      const parts = canonicalId.split('_');
      state.expandedNodeIds.add(`seg_${parts[1]}`);
    }

    state.selectedNodeId = canonicalId;
    renderStructureTree();

    if (node.region && typeof node.region.abs_offset === 'number') {
      state.structSpan = {
        abs_offset: node.region.abs_offset,
        size: Math.max(1, node.region.size || 16),
        label: node.label,
      };
      state.fieldSpan = null;
      if (opts.scrollHex) {
        setCursorAndHighlight(node.region.abs_offset, null, { scrollHex: true, recordHistory: false });
      }
    }

    if (opts.recordHistory && !state.suppressHistory) {
      pushHistory({
        sliceIndex: state.activeSliceIndex,
        nodeId,
        cursorOffset: state.cursorOffset,
      });
    }

    renderCenterInspector(node);
    renderMemoryMapRibbon();
  }

  // =========================================================================
  // Top Dual Visual Memory Map Ribbon (File Layout vs Virtual Memory Layout)
  // =========================================================================
  function renderMemoryMapRibbon() {
    const fileTrack = document.getElementById('memmap-file-track');
    const vmTrack = document.getElementById('memmap-vm-track');
    if (!fileTrack || !vmTrack) return;

    const slice = getActiveSlice();
    if (!slice || !state.doc) {
      fileTrack.innerHTML = '';
      vmTrack.innerHTML = '';
      return;
    }

    const scaleFn = (size) => {
      const s = Math.max(1, Number(size || 1));
      return state.memmapScale === 'sqrt' ? Math.sqrt(s) : s;
    };

    const segs = slice.segments || [];

    // 1. Build File Track Blocks
    const fileBlocks = [];
    // Include Mach Header + Load Commands block at start of slice
    const hdrSize = (slice.header?.region?.size || 32) + (slice.header?.sizeofcmds || 0);
    if (hdrSize > 0) {
      fileBlocks.push({
        id: 'mach_header',
        label: 'Hdr+LCs',
        abs_offset: slice.slice_base_offset || 0,
        size: hdrSize,
        vmaddr: slice.segments?.[0]?.vmaddr || '0x0',
        protClass: 'prot-hdr',
        protLabel: 'HDR',
      });
    }

    segs.forEach((seg, idx) => {
      if ((seg.filesize || 0) <= 0) return;
      const pClass = seg.initprot && seg.initprot.includes('w') && seg.initprot.includes('x')
        ? 'prot-rwx'
        : seg.initprot && seg.initprot.includes('x')
        ? 'prot-rx'
        : seg.initprot && seg.initprot.includes('w')
        ? 'prot-rw'
        : 'prot-ro';

      fileBlocks.push({
        id: `seg_${idx}`,
        label: seg.segname,
        abs_offset: seg.abs_offset,
        size: seg.filesize,
        vmaddr: seg.vmaddr,
        vmsize: seg.vmsize_int,
        protClass: pClass,
        protLabel: `${seg.initprot}/${seg.maxprot}`,
        nsects: (seg.sections || []).length,
      });
    });

    if (slice.code_signature_detail?.present && slice.code_signature_detail.superblob_region) {
      const csReg = slice.code_signature_detail.superblob_region;
      fileBlocks.push({
        id: 'code_signature',
        label: 'CodeSign',
        abs_offset: csReg.abs_offset,
        size: csReg.size,
        vmaddr: null,
        protClass: 'prot-cs',
        protLabel: 'SIG',
      });
    }

    const totalFileWeight = fileBlocks.reduce((acc, b) => acc + scaleFn(b.size), 0) || 1;
    fileTrack.innerHTML = fileBlocks
      .map((b) => {
        const pct = ((scaleFn(b.size) / totalFileWeight) * 100).toFixed(2);
        const isActive = state.selectedNodeId === b.id ? 'active-block' : '';
        return `
          <div
            class="memmap-block ${b.protClass} ${isActive}"
            style="width: ${pct}%"
            data-node-id="${escapeHtml(b.id)}"
            data-abs-offset="${b.abs_offset}"
            data-tt-title="${escapeHtml(b.label)} (File Track)"
            data-tt-file="${hex(b.abs_offset)} .. ${hex(b.abs_offset + b.size)} (${formatBytes(b.size)})"
            data-tt-vm="${b.vmaddr ? `${b.vmaddr}` : 'File-Only'}"
            data-tt-prot="${escapeHtml(b.protLabel)}"
          >${escapeHtml(b.label)}</div>
        `;
      })
      .join('');

    // 2. Build Virtual Memory Track Blocks
    const vmBlocks = segs
      .filter((seg) => (seg.vmsize_int || 0) > 0)
      .map((seg, idx) => {
        const isPageZero = seg.segname === '__PAGEZERO';
        // In linear mode, cap __PAGEZERO visual weight so other segments remain visible
        const rawVmSize = isPageZero && state.memmapScale === 'linear'
          ? Math.min(seg.vmsize_int, 65536)
          : isPageZero
          ? Math.min(seg.vmsize_int, 256 * 1024)
          : seg.vmsize_int;

        const pClass = isPageZero
          ? 'prot-pagezero'
          : seg.initprot && seg.initprot.includes('w') && seg.initprot.includes('x')
          ? 'prot-rwx'
          : seg.initprot && seg.initprot.includes('x')
          ? 'prot-rx'
          : seg.initprot && seg.initprot.includes('w')
          ? 'prot-rw'
          : 'prot-ro';

        return {
          id: `seg_${idx}`,
          label: isPageZero ? '__PAGEZERO (//)' : seg.segname,
          abs_offset: seg.abs_offset,
          size: seg.filesize,
          vmaddr: seg.vmaddr,
          vmsize: seg.vmsize_int,
          weight: scaleFn(rawVmSize),
          protClass: pClass,
          protLabel: `${seg.initprot}/${seg.maxprot}`,
        };
      });

    const totalVmWeight = vmBlocks.reduce((acc, b) => acc + b.weight, 0) || 1;
    vmTrack.innerHTML = vmBlocks
      .map((b) => {
        const pct = ((b.weight / totalVmWeight) * 100).toFixed(2);
        const isActive = state.selectedNodeId === b.id ? 'active-block' : '';
        return `
          <div
            class="memmap-block ${b.protClass} ${isActive}"
            style="width: ${pct}%"
            data-node-id="${escapeHtml(b.id)}"
            data-abs-offset="${b.abs_offset}"
            data-tt-title="${escapeHtml(b.label)} (Virtual Memory)"
            data-tt-file="${b.size > 0 ? `${hex(b.abs_offset)} (${formatBytes(b.size)})` : 'Unmapped in File (Zero-fill)'}"
            data-tt-vm="${b.vmaddr} (${formatBytes(b.vmsize)})"
            data-tt-prot="${escapeHtml(b.protLabel)}"
          >${escapeHtml(b.label)}</div>
        `;
      })
      .join('');

    updateMemoryMapPlayhead();
  }

  function updateMemoryMapPlayhead() {
    const phFile = document.getElementById('memmap-playhead-file');
    const fileTrack = document.getElementById('memmap-file-track');
    const slice = getActiveSlice();
    if (!phFile || !fileTrack || !slice) return;

    const sliceStart = slice.slice_base_offset || 0;
    const sliceLen = Math.max(1, slice.slice_size || state.doc?.file_info?.file_size || 1);
    const rel = Math.max(0, Math.min(1, (state.cursorOffset - sliceStart) / sliceLen));
    const trackRect = fileTrack.getBoundingClientRect();
    const containerRect = document.getElementById('memmap-tracks-container').getBoundingClientRect();
    if (trackRect.width > 0) {
      const leftPx = (trackRect.left - containerRect.left) + rel * trackRect.width;
      phFile.style.left = `${leftPx}px`;
      phFile.classList.remove('hidden');
    }
  }

  // =========================================================================
  // Center Context-Sensitive Inspector Renderer
  // =========================================================================
  function renderCenterInspector(node) {
    const badgeEl = document.getElementById('inspector-category-badge');
    const titleEl = document.getElementById('inspector-title');
    const subEl = document.getElementById('inspector-subtitle');
    const pillsEl = document.getElementById('inspector-meta-pills');
    const bodyEl = document.getElementById('inspector-body');
    if (!bodyEl || !node) return;

    badgeEl.className = `inspector-badge ${node.iconClass || 'badge-purple'}`;
    badgeEl.textContent = node.type.replace(/_/g, ' ').toUpperCase();
    titleEl.textContent = node.label;
    subEl.textContent = node.subtitle || '';

    // Render Meta Pills in Inspector Header
    const reg = node.region;
    let pillsHtml = '';
    if (reg && typeof reg.abs_offset === 'number') {
      pillsHtml += `<span class="meta-pill">File Off: <strong>${hex(reg.abs_offset, 6)}</strong></span>`;
      if (reg.vmaddr) {
        pillsHtml += `<span class="meta-pill">VM: <strong>${escapeHtml(reg.vmaddr)}</strong></span>`;
      }
      if (reg.size) {
        pillsHtml += `<span class="meta-pill">Size: <strong>${formatBytes(reg.size)} (${hex(reg.size)})</strong></span>`;
      }
      pillsHtml += `<button class="jump-chip" data-jump-offset="${reg.abs_offset}" data-jump-size="${reg.size || 16}">Focus in Hex ↵</button>`;
    }
    pillsEl.innerHTML = pillsHtml;

    // Route to specialized view renderer
    switch (node.type) {
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
        renderDisassemblyInspector(bodyEl);
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
  }

  // -------------------------------------------------------------------------
  // View 1: Binary Overview Dashboard
  // -------------------------------------------------------------------------
  function renderOverviewInspector(bodyEl) {
    const fi = state.doc?.file_info || {};
    const slice = getActiveSlice();
    if (!slice) return;
    const ov = slice.overview || {};
    const sec = slice.security_posture || {};
    const cs = sec.code_signature || {};

    const fatSlicesHtml = fi.is_fat && fi.fat_header?.slices_summary
      ? `
        <div class="panel-card">
          <div class="panel-card-header">
            <span>Universal Binary Architecture Slices (${fi.fat_header.slices_summary.length})</span>
            <button class="jump-chip" data-select-node="fat_header">Inspect Fat Header →</button>
          </div>
          <div class="struct-table-wrap">
            <table class="struct-table">
              <thead>
                <tr><th>Slice</th><th>Architecture</th><th>CPU Type / Subtype</th><th>Slice Offset</th><th>Size</th><th>Alignment</th><th>Action</th></tr>
              </thead>
              <tbody>
                ${fi.fat_header.slices_summary.map((s, idx) => `
                  <tr class="struct-row ${idx === state.activeSliceIndex ? 'active-field-row' : ''}" data-switch-slice="${idx}">
                    <td>#${idx}</td>
                    <td class="col-name">${escapeHtml(s.arch_name)}</td>
                    <td>${escapeHtml(s.cputype_name)} / ${escapeHtml(s.cpusubtype_name)}</td>
                    <td class="col-offset">${hex(s.offset, 6)}</td>
                    <td>${formatBytes(s.size)} (${hex(s.size)})</td>
                    <td>2^${s.align} (${formatBytes(s.align_bytes)})</td>
                    <td><button class="jump-chip" data-switch-slice="${idx}">${idx === state.activeSliceIndex ? 'Active Slice' : 'Switch Slice'}</button></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `
      : '';

    const dylibs = slice.dylibs || [];
    const rpaths = slice.rpaths || [];

    bodyEl.innerHTML = `
      <div class="overview-container">
        <!-- Top KPI Summary Cards -->
        <div class="kpi-cards-grid">
          <div class="kpi-card">
            <span class="kpi-label">File Type &amp; Arch</span>
            <span class="kpi-value" style="color: var(--rx-fg);">${escapeHtml(ov.filetype_name || slice.header?.filetype_name || 'MH_EXECUTE')}</span>
            <span class="kpi-sub">${escapeHtml(ov.arch_display || slice.arch_name)} • ${escapeHtml(ov.endianness || 'Little-Endian')}</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Entry Point (${escapeHtml(ov.entry_point_type || 'LC_MAIN')})</span>
            <span class="kpi-value" style="color: var(--rw-fg);">${escapeHtml(ov.entry_point_vmaddr || '—')}</span>
            <span class="kpi-sub">
              File Offset: ${hex(ov.entry_point_abs_offset)}
              ${ov.entry_point_vmaddr ? `<button class="jump-chip" data-disasm-vm="${escapeHtml(ov.entry_point_vmaddr)}">Disassemble ↵</button>` : ''}
            </span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Platform &amp; SDK</span>
            <span class="kpi-value">${escapeHtml(ov.platform || 'macOS / Bare-Metal')}</span>
            <span class="kpi-sub">Min OS: ${escapeHtml(ov.minos || '—')} • SDK: ${escapeHtml(ov.sdk || '—')}</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Structure Counts</span>
            <span class="kpi-value">${ov.ncmds || 0} Load Cmds</span>
            <span class="kpi-sub">${ov.segments_count || 0} Segs • ${ov.sections_count || 0} Sects • ${ov.symbols_count || 0} Syms • ${ov.strings_count || 0} Strings</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Hardening &amp; Security</span>
            <span class="kpi-value" style="color: ${sec.has_rwx_segments ? 'var(--danger-fg)' : 'var(--ro-fg)'};">
              ${sec.pie ? 'PIE' : 'No-PIE'} • ${sec.pac_enabled ? 'PAC' : 'Std'} • ${sec.has_rwx_segments ? 'RWX WARN!' : 'W^X Clean'}
            </span>
            <span class="kpi-sub">
              Canary: ${sec.stack_canary ? 'Yes' : 'No'} • Signed: ${cs.present ? (cs.cdhash_verified ? 'Verified' : 'Present') : 'Unsigned'}
              <button class="jump-chip" data-select-node="security_audit">Audit →</button>
            </span>
          </div>
        </div>

        ${fatSlicesHtml}

        <!-- Two Column Breakdown: Binary Identity & Linked Dylibs -->
        <div class="overview-two-col">
          <div class="panel-card">
            <div class="panel-card-header">
              <span>Cryptographic Identity &amp; Slice Metadata</span>
              <button class="jump-chip" data-select-node="mach_header">Mach Header →</button>
            </div>
            <div class="kv-list">
              <div class="kv-row"><span class="kv-key">File Path</span><span class="kv-val">${escapeHtml(fi.path || fi.filename)}</span></div>
              <div class="kv-row"><span class="kv-key">Total File Size / Slice Size</span><span class="kv-val">${formatBytes(fi.file_size)} / ${formatBytes(slice.slice_size)} (@ ${hex(slice.slice_base_offset)})</span></div>
              <div class="kv-row"><span class="kv-key">LC_UUID</span><span class="kv-val" style="color: var(--hdr-fg);">${escapeHtml(ov.uuid || 'None')}</span></div>
              <div class="kv-row"><span class="kv-key">SHA-256 Digest</span><span class="kv-val">${escapeHtml(fi.sha256 || '—')}</span></div>
              <div class="kv-row"><span class="kv-key">MD5 Digest</span><span class="kv-val">${escapeHtml(fi.md5 || '—')}</span></div>
              <div class="kv-row"><span class="kv-key">Header Flags (${escapeHtml(slice.header?.flags_hex || '0x0')})</span><span class="kv-val">${(slice.header?.flags_decoded || []).map(f => `<span class="bitflag-pill">${escapeHtml(f)}</span>`).join(' ') || 'None'}</span></div>
              <div class="kv-row"><span class="kv-key">CodeSign Identifier / CDHash</span><span class="kv-val">${escapeHtml(cs.identifier || '—')} ${cs.cdhash ? `(${escapeHtml(cs.cdhash.slice(0, 20))}…)` : ''}</span></div>
            </div>
          </div>

          <div class="panel-card">
            <div class="panel-card-header">
              <span>Linked Dynamic Libraries (${dylibs.length}) &amp; RPATHs (${rpaths.length})</span>
              <button class="jump-chip" data-select-node="load_commands">All Load Cmds →</button>
            </div>
            <div class="kv-list">
              ${dylibs.length === 0 ? '<div class="kv-row"><span class="kv-key">No LC_LOAD_DYLIB dependencies (Standalone / Static / Firmware)</span></div>' : ''}
              ${dylibs.map(d => `
                <div class="kv-row" style="cursor: pointer;" data-jump-offset="${d.abs_offset}" data-jump-size="${d.size}">
                  <span class="kv-key" style="color: var(--rx-fg); font-family: var(--font-mono);">${escapeHtml(d.name)}</span>
                  <span class="kv-val">v${escapeHtml(d.current_version)} (${escapeHtml(d.cmd_name)})</span>
                </div>
              `).join('')}
              ${rpaths.map(r => `
                <div class="kv-row" style="cursor: pointer;" data-jump-offset="${r.abs_offset}" data-jump-size="${r.size}">
                  <span class="kv-key" style="color: var(--rw-fg);">LC_RPATH</span>
                  <span class="kv-val">${escapeHtml(r.path)}</span>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 2: Structure Field Table View (Headers, Load Commands, Segments, Sections)
  // -------------------------------------------------------------------------
  function renderStructInspector(bodyEl, node) {
    const fields = node.fields || [];
    let extraTopBanner = '';
    let extraBottomSection = '';

    // If this is an executable section, offer a 1-click button to switch to Disassembly
    if (node.type === 'section' && node.section) {
      const s = node.section;
      extraTopBanner = `
        <div class="explorer-toolbar">
          <div style="display: flex; align-items: center; gap: 10px;">
            <span class="prot-pill ${protClass(s.prot)}">${escapeHtml((s.prot || 'r--').toUpperCase())}</span>
            <span>Section Data Offset: <strong style="font-family: var(--font-mono); color: var(--rx-fg);">${hex(s.abs_offset, 6)}</strong></span>
            <span>VM Address: <strong style="font-family: var(--font-mono); color: var(--hdr-fg);">${escapeHtml(s.vmaddr)}</strong></span>
            <span>Size: <strong>${formatBytes(s.size)}</strong></span>
          </div>
          <div style="display: flex; gap: 6px;">
            <button class="jump-chip" data-jump-offset="${s.abs_offset}" data-jump-size="${Math.min(s.size || 64, 256)}">Highlight Section Payload in Hex</button>
            ${s.is_executable ? `<button class="jump-chip" style="background: var(--rw-bg); color: var(--rw-fg); border-color: var(--rw-border);" data-disasm-section="${escapeHtml(s.segname + ',' + s.sectname)}" data-disasm-vm="${escapeHtml(s.vmaddr)}">Disassemble Section ↵</button>` : ''}
          </div>
        </div>
      `;
    }

    // If this is a Segment node, also show a summary table of its child Sections below the struct fields
    if (node.type === 'segment' && node.segment && Array.isArray(node.segment.sections) && node.segment.sections.length > 0) {
      const sIdx = node.segment.index;
      extraBottomSection = `
        <div style="padding: 12px;">
          <div class="panel-card">
            <div class="panel-card-header">Sections in ${escapeHtml(node.segment.segname)} (${node.segment.sections.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead>
                  <tr><th>#</th><th>Section</th><th>VM Address</th><th>File Offset</th><th>Size</th><th>Type &amp; Attributes</th><th>Action</th></tr>
                </thead>
                <tbody>
                  ${node.segment.sections.map((sec, idx) => `
                    <tr class="struct-row" data-select-node="sect_${sIdx}_${idx}">
                      <td>${idx}</td>
                      <td class="col-name">${escapeHtml(sec.segname)},${escapeHtml(sec.sectname)}</td>
                      <td class="col-val">${escapeHtml(sec.vmaddr)}</td>
                      <td class="col-offset">${hex(sec.abs_offset, 6)}</td>
                      <td>${formatBytes(sec.size)} (${hex(sec.size)})</td>
                      <td>${escapeHtml(sec.section_type)} ${(sec.attributes_decoded || []).map(a => `<span class="bitflag-pill">${escapeHtml(a)}</span>`).join(' ')}</td>
                      <td>
                        <button class="jump-chip" data-select-node="sect_${sIdx}_${idx}">Inspect</button>
                        ${sec.is_executable ? `<button class="jump-chip" data-disasm-section="${escapeHtml(sec.segname + ',' + sec.sectname)}" data-disasm-vm="${escapeHtml(sec.vmaddr)}">Disasm</button>` : ''}
                      </td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      `;
    }

    // If Load Command has rich parsed details (e.g., LC_UNIXTHREAD registers or sub-entries), show them
    if (node.type === 'load_command' && node.lc?.details && Object.keys(node.lc.details).length > 0) {
      const det = node.lc.details;
      if (det.registers && Object.keys(det.registers).length > 0) {
        extraBottomSection += `
          <div style="padding: 12px;">
            <div class="panel-card">
              <div class="panel-card-header">Thread Initial Register State (${escapeHtml(det.flavor_name || 'ARM_THREAD_STATE64')})</div>
              <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 6px; padding: 10px; font-family: var(--font-mono); font-size: 11px;">
                ${Object.entries(det.registers).map(([regName, regVal]) => `
                  <div class="dec-cell"><span class="dec-k">${escapeHtml(regName.toUpperCase())}</span><span class="dec-v" style="color: var(--rx-fg);">${escapeHtml(regVal)}</span></div>
                `).join('')}
              </div>
            </div>
          </div>
        `;
      }
    }

    bodyEl.innerHTML = `
      ${extraTopBanner}
      <div class="struct-table-wrap">
        <table class="struct-table">
          <thead>
            <tr>
              <th>File Offset</th>
              <th>Slice Off</th>
              <th>Raw Bytes</th>
              <th>Type</th>
              <th>Field Name</th>
              <th>Parsed Value</th>
              <th>Decoded Meaning / Flags</th>
            </tr>
          </thead>
          <tbody>
            ${fields.map((f, idx) => {
              const bitFlagsHtml = Array.isArray(f.bit_flags) && f.bit_flags.length
                ? `<div class="bitflags-inline">${f.bit_flags
                    .filter(bf => bf.set !== false)
                    .map(bf => `<span class="bitflag-pill" title="Mask: ${escapeHtml(bf.mask || '')}">${escapeHtml(bf.name)} (${escapeHtml(bf.mask || '')})</span>`)
                    .join('')}</div>`
                : '';

              let jumpBtn = '';
              if (typeof f.target_offset === 'number' && f.target_offset > 0) {
                jumpBtn = `<button class="jump-chip" data-jump-offset="${f.target_offset}" data-jump-size="16">Jump → ${hex(f.target_offset)}</button>`;
              } else if (f.target_vmaddr) {
                jumpBtn = `<button class="jump-chip" data-disasm-vm="${escapeHtml(f.target_vmaddr)}">Jump → ${escapeHtml(f.target_vmaddr)}</button>`;
              }

              const ped = f.pedagogy;
              const pedHtml = ped
                ? `
                  <div class="pedagogy-inline-box">
                    <div><strong>Why it matters:</strong> ${escapeHtml(ped.why_it_matters || '')}</div>
                    <div><strong>Loader behavior:</strong> ${escapeHtml(ped.loader_behavior || '')}</div>
                    <div><strong>What if modified:</strong> ${escapeHtml(ped.what_if_modified || '')}</div>
                    <div><strong>Cross-format peer:</strong> <span style="color: var(--rx-fg);">${escapeHtml(ped.cross_format_peer || '')}</span></div>
                  </div>
                `
                : '';

              return `
                <tr
                  class="struct-row"
                  data-field-idx="${idx}"
                  data-abs-offset="${f.abs_offset}"
                  data-field-size="${f.size}"
                  data-field-name="${escapeHtml(f.name)}"
                >
                  <td class="col-offset">${hex(f.abs_offset, 6)}</td>
                  <td class="col-offset">+${hex(f.slice_offset, 4)}</td>
                  <td class="col-bytes" title="${escapeHtml(f.raw_hex)}">${escapeHtml(f.raw_hex)}</td>
                  <td class="col-type">${escapeHtml(f.type)} (${f.size}B)</td>
                  <td class="col-name">${escapeHtml(f.name)}</td>
                  <td class="col-val">${escapeHtml(f.value)}</td>
                  <td class="col-desc">
                    <strong>${escapeHtml(f.interpreted || '')}</strong>
                    ${f.description ? `<span style="color: var(--text-secondary); margin-left: 6px;">— ${escapeHtml(f.description)}</span>` : ''}
                    ${jumpBtn}
                    ${bitFlagsHtml}
                    ${pedHtml}
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
      ${extraBottomSection}
    `;
  }

  function renderLoadCommandsSummaryInspector(bodyEl) {
    const slice = getActiveSlice();
    const lcs = slice?.load_commands || [];
    bodyEl.innerHTML = `
      <div class="struct-table-wrap">
        <table class="struct-table">
          <thead>
            <tr><th>#</th><th>File Offset</th><th>Command</th><th>Cmd ID</th><th>Size</th><th>Summary / Target</th><th>Inspect</th></tr>
          </thead>
          <tbody>
            ${lcs.map(lc => `
              <tr class="struct-row" data-select-node="lc_${lc.index}">
                <td>#${lc.index}</td>
                <td class="col-offset">${hex(lc.region?.abs_offset, 6)}</td>
                <td class="col-name">${escapeHtml(lc.cmd_name)}</td>
                <td class="col-val">${escapeHtml(lc.cmd_hex)}</td>
                <td>${lc.cmdsize} B</td>
                <td class="col-desc">${escapeHtml(lc.summary || '')}</td>
                <td><button class="jump-chip" data-select-node="lc_${lc.index}">Fields →</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderSegmentsSummaryInspector(bodyEl) {
    const slice = getActiveSlice();
    const segs = slice?.segments || [];
    bodyEl.innerHTML = `
      <div class="struct-table-wrap">
        <table class="struct-table">
          <thead>
            <tr><th>#</th><th>Segment</th><th>VM Address</th><th>VM Size</th><th>File Offset</th><th>File Size</th><th>Init / Max Prot</th><th>Sections</th><th>Action</th></tr>
          </thead>
          <tbody>
            ${segs.map((seg, idx) => `
              <tr class="struct-row" data-select-node="seg_${idx}">
                <td>#${idx}</td>
                <td class="col-name">${escapeHtml(seg.segname)}</td>
                <td class="col-val">${escapeHtml(seg.vmaddr)}</td>
                <td>${formatBytes(seg.vmsize_int)} (${escapeHtml(seg.vmsize)})</td>
                <td class="col-offset">${hex(seg.abs_offset, 6)}</td>
                <td>${formatBytes(seg.filesize)}</td>
                <td><span class="prot-pill ${protClass(seg.initprot)}">${escapeHtml(seg.initprot.toUpperCase())} / ${escapeHtml(seg.maxprot.toUpperCase())}</span></td>
                <td>${(seg.sections || []).length}</td>
                <td><button class="jump-chip" data-select-node="seg_${idx}">Inspect →</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 3: Virtualized Symbol Table (`LC_SYMTAB`) & Dynamic Symbols
  // -------------------------------------------------------------------------
  function renderSymbolTableInspector(bodyEl) {
    const slice = getActiveSlice();
    const allSyms = slice?.symbols || [];

    bodyEl.innerHTML = `
      <div class="explorer-toolbar">
        <div class="explorer-filter-group">
          <input
            id="sym-search-input"
            type="text"
            class="explorer-search-input"
            placeholder="Filter ${allSyms.length} symbols by name, section, library, or address…"
            value="${escapeHtml(state.symSearch)}"
            spellcheck="false"
          />
          <div class="filter-pills-group" id="sym-scope-pills">
            <button class="filter-pill-btn ${state.symScope === 'all' ? 'active' : ''}" data-sym-scope="all">All (${allSyms.length})</button>
            <button class="filter-pill-btn ${state.symScope === 'ext' ? 'active' : ''}" data-sym-scope="ext">Defined Ext</button>
            <button class="filter-pill-btn ${state.symScope === 'local' ? 'active' : ''}" data-sym-scope="local">Local</button>
            <button class="filter-pill-btn ${state.symScope === 'undef' ? 'active' : ''}" data-sym-scope="undef">Undefined / Imports</button>
          </div>
        </div>
        <button id="btn-toggle-demangle" class="filter-pill-btn ${state.symDemangle ? 'active' : ''}">
          Demangle C++/Swift: <strong>${state.symDemangle ? 'ON' : 'OFF'}</strong>
        </button>
      </div>

      <div class="virt-table-header">
        <span class="vcol-idx">#</span>
        <span class="vcol-off">Nlist Off</span>
        <span class="vcol-vm">VM Address</span>
        <span class="vcol-type">Scope / Type</span>
        <span class="vcol-sect">Section</span>
        <span class="vcol-lib">Library</span>
        <span class="vcol-name">Symbol Name</span>
      </div>

      <div id="sym-virt-viewport" class="virt-viewport">
        <div id="sym-virt-phantom" class="virt-phantom"></div>
        <div id="sym-virt-rows" class="virt-rows-container"></div>
      </div>
    `;

    const viewport = document.getElementById('sym-virt-viewport');
    const phantom = document.getElementById('sym-virt-phantom');
    const rowsEl = document.getElementById('sym-virt-rows');

    const getFilteredSymbols = () => {
      const q = state.symSearch.trim().toLowerCase();
      return allSyms.filter((s) => {
        if (state.symScope === 'ext' && (!s.is_external || s.type_name === 'UNDF')) return false;
        if (state.symScope === 'local' && (s.is_external || s.type_name === 'UNDF')) return false;
        if (state.symScope === 'undef' && s.type_name !== 'UNDF') return false;
        if (!q) return true;
        return (
          (s.name && s.name.toLowerCase().includes(q)) ||
          (s.demangled && s.demangled.toLowerCase().includes(q)) ||
          (s.section_name && s.section_name.toLowerCase().includes(q)) ||
          (s.library_name && s.library_name.toLowerCase().includes(q)) ||
          (s.n_value && s.n_value.toLowerCase().includes(q))
        );
      });
    };

    let filtered = getFilteredSymbols();
    phantom.style.height = `${filtered.length * VIRT_ROW_HEIGHT}px`;

    const renderVisibleSymRows = () => {
      const scrollTop = viewport.scrollTop;
      const viewHeight = viewport.clientHeight || 500;
      const startIdx = Math.max(0, Math.floor(scrollTop / VIRT_ROW_HEIGHT) - 8);
      const endIdx = Math.min(filtered.length, Math.ceil((scrollTop + viewHeight) / VIRT_ROW_HEIGHT) + 8);

      rowsEl.style.transform = `translateY(${startIdx * VIRT_ROW_HEIGHT}px)`;
      const html = [];
      for (let i = startIdx; i < endIdx; i++) {
        const s = filtered[i];
        const dispName = state.symDemangle && s.demangled ? s.demangled : s.name;
        const badgeCls = s.type_name === 'UNDF' ? 'rw' : s.is_external ? 'rx' : 'ro';
        const scopeLabel = `${s.type_name}${s.is_external ? '•EXT' : '•LOC'}`;
        const targetOff = s.target_abs_offset || s.abs_offset;

        html.push(`
          <div
            class="virt-row"
            data-sym-idx="${s.index}"
            data-abs-offset="${targetOff}"
            data-nlist-offset="${s.abs_offset}"
            data-sym-vm="${escapeHtml(s.n_value)}"
            data-sym-sect="${escapeHtml(s.section_name || '')}"
          >
            <span class="vcol-idx">${s.index}</span>
            <span class="vcol-off">${hex(s.abs_offset, 6)}</span>
            <span class="vcol-vm">${escapeHtml(s.n_value)}</span>
            <span class="vcol-type"><span class="prot-pill ${badgeCls}">${escapeHtml(scopeLabel)}</span></span>
            <span class="vcol-sect">${escapeHtml(s.section_name || '—')}</span>
            <span class="vcol-lib">${escapeHtml(s.library_name || 'SELF')}</span>
            <span class="vcol-name" title="${escapeHtml(s.name)}">${escapeHtml(dispName)}</span>
          </div>
        `);
      }
      rowsEl.innerHTML = html.join('');
    };

    viewport.addEventListener('scroll', renderVisibleSymRows, { passive: true });
    renderVisibleSymRows();

    // Wire filter controls
    const searchInput = document.getElementById('sym-search-input');
    searchInput.addEventListener('input', (e) => {
      state.symSearch = e.target.value;
      filtered = getFilteredSymbols();
      phantom.style.height = `${filtered.length * VIRT_ROW_HEIGHT}px`;
      viewport.scrollTop = 0;
      renderVisibleSymRows();
    });

    document.getElementById('sym-scope-pills').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-sym-scope]');
      if (!btn) return;
      state.symScope = btn.dataset.symScope;
      renderSymbolTableInspector(bodyEl);
    });

    document.getElementById('btn-toggle-demangle').addEventListener('click', () => {
      state.symDemangle = !state.symDemangle;
      renderVisibleSymRows();
      document.getElementById('btn-toggle-demangle').innerHTML = `Demangle C++/Swift: <strong>${state.symDemangle ? 'ON' : 'OFF'}</strong>`;
      document.getElementById('btn-toggle-demangle').classList.toggle('active', state.symDemangle);
    });
  }

  function renderDysymtabInspector(bodyEl) {
    const slice = getActiveSlice();
    const dysym = slice?.dysymtab || {};
    const indirects = dysym.indirect_symbols || [];

    bodyEl.innerHTML = `
      <div class="overview-container">
        <div class="kpi-cards-grid">
          <div class="kpi-card"><span class="kpi-label">Local Symbols</span><span class="kpi-value">${dysym.nlocalsym || 0}</span><span class="kpi-sub">Start index: ${dysym.ilocalsym || 0}</span></div>
          <div class="kpi-card"><span class="kpi-label">External Defined</span><span class="kpi-value">${dysym.nextdefsym || 0}</span><span class="kpi-sub">Start index: ${dysym.iextdefsym || 0}</span></div>
          <div class="kpi-card"><span class="kpi-label">Undefined Symbols</span><span class="kpi-value">${dysym.nundefsym || 0}</span><span class="kpi-sub">Start index: ${dysym.iundefsym || 0}</span></div>
          <div class="kpi-card"><span class="kpi-label">Indirect Stub Entries</span><span class="kpi-value">${indirects.length}</span><span class="kpi-sub">Stub &amp; GOT pointer mappings</span></div>
        </div>

        <div class="panel-card">
          <div class="panel-card-header">Indirect Symbol Table Mappings (${indirects.length})</div>
          <div class="struct-table-wrap">
            <table class="struct-table">
              <thead>
                <tr><th>#</th><th>Stub / Pointer Section</th><th>Slot VM Address</th><th>Symtab Index</th><th>Resolved Symbol Name</th><th>Action</th></tr>
              </thead>
              <tbody>
                ${indirects.length === 0 ? '<tr><td colspan="6" style="color: var(--text-secondary);">No indirect symbol table entries present.</td></tr>' : ''}
                ${indirects.map(ind => `
                  <tr class="struct-row" data-disasm-vm="${escapeHtml(ind.slot_vmaddr)}">
                    <td>#${ind.index}</td>
                    <td class="col-name">${escapeHtml(ind.section || '—')}</td>
                    <td class="col-val">${escapeHtml(ind.slot_vmaddr || '—')}</td>
                    <td>${ind.symtab_index}</td>
                    <td class="col-desc"><strong style="color: var(--rx-fg);">${escapeHtml(ind.symbol_name)}</strong></td>
                    <td><button class="jump-chip" data-disasm-vm="${escapeHtml(ind.slot_vmaddr)}">Disassemble Stub →</button></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 4: Virtualized Strings & Literals Explorer
  // -------------------------------------------------------------------------
  function renderStringsInspector(bodyEl) {
    const slice = getActiveSlice();
    const allStrings = slice?.strings || [];
    const sources = ['all', ...new Set(allStrings.map(s => s.source).filter(Boolean))];

    bodyEl.innerHTML = `
      <div class="explorer-toolbar">
        <div class="explorer-filter-group">
          <input
            id="str-search-input"
            type="text"
            class="explorer-search-input"
            placeholder="Filter ${allStrings.length} strings by content, section, or address…"
            value="${escapeHtml(state.strSearch)}"
            spellcheck="false"
          />
          <div class="filter-pills-group" id="str-source-pills">
            ${sources.map(src => `
              <button class="filter-pill-btn ${state.strSourceFilter === src ? 'active' : ''}" data-str-source="${escapeHtml(src)}">
                ${src === 'all' ? `All (${allStrings.length})` : escapeHtml(src)}
              </button>
            `).join('')}
          </div>
        </div>
      </div>

      <div class="virt-table-header">
        <span class="vcol-idx">#</span>
        <span class="vcol-off">File Offset</span>
        <span class="vcol-vm">VM Address</span>
        <span class="vcol-sect">Source Section</span>
        <span class="vcol-idx">Len</span>
        <span class="vcol-name">String Literal</span>
      </div>

      <div id="str-virt-viewport" class="virt-viewport">
        <div id="str-virt-phantom" class="virt-phantom"></div>
        <div id="str-virt-rows" class="virt-rows-container"></div>
      </div>
    `;

    const viewport = document.getElementById('str-virt-viewport');
    const phantom = document.getElementById('str-virt-phantom');
    const rowsEl = document.getElementById('str-virt-rows');

    const getFilteredStrings = () => {
      const q = state.strSearch.trim().toLowerCase();
      return allStrings.filter((s) => {
        if (state.strSourceFilter !== 'all' && s.source !== state.strSourceFilter) return false;
        if (!q) return true;
        return (
          (s.value && s.value.toLowerCase().includes(q)) ||
          (s.source && s.source.toLowerCase().includes(q)) ||
          (s.vmaddr && s.vmaddr.toLowerCase().includes(q))
        );
      });
    };

    let filtered = getFilteredStrings();
    phantom.style.height = `${filtered.length * VIRT_ROW_HEIGHT}px`;

    const renderVisibleStrRows = () => {
      const scrollTop = viewport.scrollTop;
      const viewHeight = viewport.clientHeight || 500;
      const startIdx = Math.max(0, Math.floor(scrollTop / VIRT_ROW_HEIGHT) - 8);
      const endIdx = Math.min(filtered.length, Math.ceil((scrollTop + viewHeight) / VIRT_ROW_HEIGHT) + 8);

      rowsEl.style.transform = `translateY(${startIdx * VIRT_ROW_HEIGHT}px)`;
      const html = [];
      for (let i = startIdx; i < endIdx; i++) {
        const s = filtered[i];
        html.push(`
          <div
            class="virt-row"
            data-abs-offset="${s.abs_offset}"
            data-field-size="${Math.max(1, s.length || 1)}"
            data-field-name="String @ ${hex(s.abs_offset)}"
          >
            <span class="vcol-idx">${s.index}</span>
            <span class="vcol-off">${hex(s.abs_offset, 6)}</span>
            <span class="vcol-vm">${escapeHtml(s.vmaddr || '—')}</span>
            <span class="vcol-sect">${escapeHtml(s.source || '—')}</span>
            <span class="vcol-idx">${s.length}B</span>
            <span class="vcol-name" style="color: var(--ro-fg);" title="${escapeHtml(s.value)}">"${escapeHtml(s.value)}"</span>
          </div>
        `);
      }
      rowsEl.innerHTML = html.join('');
    };

    viewport.addEventListener('scroll', renderVisibleStrRows, { passive: true });
    renderVisibleStrRows();

    document.getElementById('str-search-input').addEventListener('input', (e) => {
      state.strSearch = e.target.value;
      filtered = getFilteredStrings();
      phantom.style.height = `${filtered.length * VIRT_ROW_HEIGHT}px`;
      viewport.scrollTop = 0;
      renderVisibleStrRows();
    });

    document.getElementById('str-source-pills').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-str-source]');
      if (!btn) return;
      state.strSourceFilter = btn.dataset.strSource;
      renderStringsInspector(bodyEl);
    });
  }

  // -------------------------------------------------------------------------
  // View 5: Interactive Disassembly View (`/api/disassemble`)
  // -------------------------------------------------------------------------
  async function renderDisassemblyInspector(bodyEl) {
    const slice = getActiveSlice();
    if (!slice) return;

    // Collect executable sections
    const execSections = [];
    (slice.segments || []).forEach((seg) => {
      (seg.sections || []).forEach((sec) => {
        if (sec.is_executable || sec.sectname === '__text' || sec.sectname.includes('stub') || sec.sectname.includes('code')) {
          execSections.push({
            key: `${seg.segname},${sec.sectname}`,
            vmaddr: sec.vmaddr,
            size: sec.size,
          });
        }
      });
    });

    if (!state.activeDisasmSection && execSections.length > 0) {
      state.activeDisasmSection = execSections[0].key;
    }

    bodyEl.innerHTML = `
      <div class="explorer-toolbar">
        <div class="explorer-filter-group">
          <span style="font-weight: 600; color: var(--text-secondary);">Executable Section:</span>
          <div class="filter-pills-group" id="disasm-sect-pills">
            ${execSections.map(es => `
              <button class="filter-pill-btn ${state.activeDisasmSection === es.key ? 'active' : ''}" data-disasm-sec-btn="${escapeHtml(es.key)}" data-disasm-sec-vm="${escapeHtml(es.vmaddr)}">
                ${escapeHtml(es.key)} (${formatBytes(es.size)})
              </button>
            `).join('')}
            ${execSections.length === 0 ? `<button class="filter-pill-btn active" data-disasm-sec-btn="" data-disasm-sec-vm="${escapeHtml(slice.entry_point?.vmaddr || '0x0')}">Entry Point / Raw Firmware Code</button>` : ''}
          </div>
        </div>
        <form id="disasm-addr-form" style="display: flex; gap: 5px;">
          <input id="disasm-addr-input" type="text" class="conv-input conv-input-wide" style="background: var(--bg-input); border: 1px solid var(--border-default); border-radius: 3px; height: 24px;" placeholder="VMAddr 0x100003f60" value="${escapeHtml(state.activeDisasmVmaddr)}" />
          <button type="submit" class="btn-conv-action" style="height: 24px;">Disassemble</button>
        </form>
      </div>
      <div id="disasm-results-wrap" class="struct-table-wrap" style="flex: 1; overflow-y: auto;">
        <div style="padding: 20px; color: var(--text-secondary);">Disassembling ${escapeHtml(state.activeDisasmSection || state.activeDisasmVmaddr || slice.arch_name)}…</div>
      </div>
    `;

    document.getElementById('disasm-sect-pills')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-disasm-sec-btn]');
      if (!btn) return;
      state.activeDisasmSection = btn.dataset.disasmSecBtn;
      state.activeDisasmVmaddr = '';
      renderDisassemblyInspector(bodyEl);
    });

    document.getElementById('disasm-addr-form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = document.getElementById('disasm-addr-input').value.trim();
      if (val) {
        state.activeDisasmVmaddr = val;
        state.activeDisasmSection = '';
        renderDisassemblyInspector(bodyEl);
      }
    });

    // Fetch disassembly
    const params = new URLSearchParams({
      slice_index: String(state.activeSliceIndex),
      count: '350',
    });
    if (state.activeDisasmVmaddr) {
      params.set('vmaddr', state.activeDisasmVmaddr);
    } else if (state.activeDisasmSection) {
      params.set('section', state.activeDisasmSection);
    }

    const cacheKey = params.toString();
    let data = state.disasmCache.get(cacheKey);
    if (!data) {
      try {
        const res = await fetch(`/api/disassemble?${params.toString()}`);
        data = await res.json();
        if (res.ok && Array.isArray(data.instructions)) {
          state.disasmCache.set(cacheKey, data);
        }
      } catch (err) {
        data = { error: err.message, instructions: [] };
      }
    }

    const wrap = document.getElementById('disasm-results-wrap');
    if (!wrap) return;
    const insns = data?.instructions || [];
    if (!insns.length) {
      wrap.innerHTML = `<div style="padding: 20px; color: var(--text-secondary);">No instructions decoded for this range.</div>`;
      return;
    }

    const mnemClass = (m) => {
      const low = (m || '').toLowerCase();
      if (low.startsWith('ret')) return 'mnem-ret';
      if (low.startsWith('pac') || low.startsWith('aut') || low.startsWith('xpaci')) return 'mnem-pac';
      if (low.startsWith('b') || low.startsWith('cbz') || low.startsWith('cbnz') || low.startsWith('tbz') || low.startsWith('tbnz') || low.startsWith('jmp') || low.startsWith('call') || low.startsWith('j')) return 'mnem-branch';
      if (low.startsWith('ldr') || low.startsWith('str') || low.startsWith('ldp') || low.startsWith('stp') || low.startsWith('mov')) return 'mnem-mem';
      return 'mnem-alu';
    };

    const rowsHtml = [];
    insns.forEach((insn) => {
      if (insn.symbol_label) {
        rowsHtml.push(`
          <tr>
            <td colspan="6" class="disasm-sym-banner">${escapeHtml(insn.symbol_label)}:</td>
          </tr>
        `);
      }
      const branchBtn = insn.branch_target_vmaddr
        ? `<button class="jump-chip" data-disasm-vm="${escapeHtml(insn.branch_target_vmaddr)}">→ ${escapeHtml(insn.branch_target_vmaddr)}</button>`
        : '';
      rowsHtml.push(`
        <tr
          class="disasm-row"
          data-abs-offset="${insn.abs_offset}"
          data-field-size="${insn.size || 4}"
          data-field-name="${escapeHtml(insn.mnemonic + ' ' + insn.operands)}"
        >
          <td class="col-offset">${hex(insn.abs_offset, 6)}</td>
          <td class="col-val" style="color: var(--hdr-fg);">${escapeHtml(insn.vmaddr)}</td>
          <td class="col-bytes">${escapeHtml(insn.raw_hex)}</td>
          <td class="${mnemClass(insn.mnemonic)}">${escapeHtml(insn.mnemonic)}</td>
          <td style="color: var(--text-bright);">${escapeHtml(insn.operands)} ${branchBtn}</td>
          <td class="disasm-comment">${insn.comment ? `; ${escapeHtml(insn.comment)}` : ''}</td>
        </tr>
      `);
    });

    wrap.innerHTML = `
      <table class="disasm-table">
        <thead>
          <tr><th>File Offset</th><th>VM Address</th><th>Raw Bytes</th><th>Mnemonic</th><th>Operands</th><th>Resolved Symbol / Comment</th></tr>
        </thead>
        <tbody>${rowsHtml.join('')}</tbody>
      </table>
    `;
  }

  // -------------------------------------------------------------------------
  // View 6: Dyld Info & Chained Fixups Inspector
  // -------------------------------------------------------------------------
  function renderDyldInspector(bodyEl) {
    const slice = getActiveSlice();
    const dyld = slice?.dyld_info || {};
    const cf = dyld.chained_fixups || {};
    const fixups = cf.fixups || [];
    const imports = cf.imports || [];
    const exportsList = dyld.exports || [];
    const binds = dyld.binds || [];

    bodyEl.innerHTML = `
      <div class="subtabs-bar" id="dyld-subtabs">
        <button class="subtab-btn ${state.dyldSubTab === 'fixups' ? 'active' : ''}" data-dyld-tab="fixups">Chained Fixups (${fixups.length})</button>
        <button class="subtab-btn ${state.dyldSubTab === 'imports' ? 'active' : ''}" data-dyld-tab="imports">Chained Imports (${imports.length})</button>
        <button class="subtab-btn ${state.dyldSubTab === 'exports' ? 'active' : ''}" data-dyld-tab="exports">Exports Trie (${exportsList.length})</button>
        <button class="subtab-btn ${state.dyldSubTab === 'binds' ? 'active' : ''}" data-dyld-tab="binds">Classic Binds / Rebases (${binds.length + (dyld.rebases?.length || 0)})</button>
      </div>
      <div id="dyld-tab-content" class="struct-table-wrap" style="flex: 1; overflow-y: auto;"></div>
    `;

    const tabContent = document.getElementById('dyld-tab-content');
    if (state.dyldSubTab === 'fixups') {
      tabContent.innerHTML = `
        <table class="struct-table">
          <thead>
            <tr><th>File Offset</th><th>VM Address</th><th>Fixup Type</th><th>Target Symbol / Addend</th><th>PAC Key / Diversity</th></tr>
          </thead>
          <tbody>
            ${fixups.length === 0 ? '<tr><td colspan="5" style="color: var(--text-secondary);">No chained pointer fixups in this binary.</td></tr>' : ''}
            ${fixups.map(fx => `
              <tr class="struct-row" data-abs-offset="${fx.abs_offset}" data-field-size="8" data-field-name="Fixup ${escapeHtml(fx.type)}">
                <td class="col-offset">${hex(fx.abs_offset, 6)}</td>
                <td class="col-val">${escapeHtml(fx.vmaddr)}</td>
                <td><span class="prot-pill ${fx.type && fx.type.includes('AUTH') ? 'rx' : 'rw'}">${escapeHtml(fx.type)}</span></td>
                <td class="col-name">${escapeHtml(fx.symbol || fx.target || `Ordinal #${fx.ordinal ?? 0}`)}</td>
                <td>${fx.pac_key ? `Key: <strong>${escapeHtml(fx.pac_key)}</strong> (div: ${fx.diversity ?? 0}, addr_div: ${Boolean(fx.addr_div)})` : '—'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    } else if (state.dyldSubTab === 'imports') {
      tabContent.innerHTML = `
        <table class="struct-table">
          <thead>
            <tr><th>Ordinal</th><th>Symbol Name</th><th>Library Ordinal</th><th>Target Dynamic Library</th><th>Weak Import</th></tr>
          </thead>
          <tbody>
            ${imports.length === 0 ? '<tr><td colspan="5" style="color: var(--text-secondary);">No chained imports table present.</td></tr>' : ''}
            ${imports.map(imp => `
              <tr class="struct-row">
                <td>#${imp.index}</td>
                <td class="col-name">${escapeHtml(imp.name)}</td>
                <td>${imp.lib_ordinal}</td>
                <td>${escapeHtml(imp.lib_name || 'SELF')}</td>
                <td>${imp.weak_import ? '<span class="prot-pill rw">WEAK</span>' : 'No'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    } else if (state.dyldSubTab === 'exports') {
      tabContent.innerHTML = `
        <table class="struct-table">
          <thead>
            <tr><th>Exported Symbol</th><th>VM Address</th><th>Slice Offset</th><th>Export Flags</th><th>Action</th></tr>
          </thead>
          <tbody>
            ${exportsList.length === 0 ? '<tr><td colspan="5" style="color: var(--text-secondary);">No exports trie entries present.</td></tr>' : ''}
            ${exportsList.map(ex => `
              <tr class="struct-row" data-disasm-vm="${escapeHtml(ex.vmaddr)}">
                <td class="col-name">${escapeHtml(ex.name)}</td>
                <td class="col-val">${escapeHtml(ex.vmaddr)}</td>
                <td class="col-offset">+${hex(ex.offset, 4)}</td>
                <td>${(ex.flags_decoded || []).map(f => `<span class="bitflag-pill">${escapeHtml(f)}</span>`).join(' ') || hex(ex.flags)}</td>
                <td><button class="jump-chip" data-disasm-vm="${escapeHtml(ex.vmaddr)}">Disassemble →</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    } else {
      tabContent.innerHTML = `
        <table class="struct-table">
          <thead>
            <tr><th>Type</th><th>Segment</th><th>VM Address</th><th>Symbol</th><th>Library</th></tr>
          </thead>
          <tbody>
            ${binds.length === 0 ? '<tr><td colspan="5" style="color: var(--text-secondary);">Binary uses modern Chained Fixups instead of legacy bind opcodes.</td></tr>' : ''}
            ${binds.map(b => `
              <tr class="struct-row">
                <td><span class="prot-pill rx">${escapeHtml(b.type || 'BIND')}</span></td>
                <td>${escapeHtml(b.segment || '—')}</td>
                <td class="col-val">${escapeHtml(b.vmaddr || '—')}</td>
                <td class="col-name">${escapeHtml(b.symbol || '—')}</td>
                <td>${escapeHtml(b.library || '—')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    document.getElementById('dyld-subtabs')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-dyld-tab]');
      if (!btn) return;
      state.dyldSubTab = btn.dataset.dyldTab;
      renderDyldInspector(bodyEl);
    });
  }

  // -------------------------------------------------------------------------
  // View 7: Entry Point, Thread State & Function Starts
  // -------------------------------------------------------------------------
  function renderFunctionStartsInspector(bodyEl) {
    const slice = getActiveSlice();
    const ep = slice?.entry_point || {};
    const fns = slice?.function_starts || [];
    const regs = ep.registers || {};

    const regsHtml = Object.keys(regs).length > 0
      ? `
        <div class="panel-card">
          <div class="panel-card-header">LC_UNIXTHREAD Initial CPU Register State (${escapeHtml(ep.thread_flavor || 'ARM_THREAD_STATE64')})</div>
          <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 6px; padding: 12px; font-family: var(--font-mono); font-size: 11px;">
            ${Object.entries(regs).map(([k, v]) => `
              <div class="dec-cell"><span class="dec-k">${escapeHtml(k.toUpperCase())}</span><span class="dec-v" style="color: var(--rx-fg);">${escapeHtml(v)}</span></div>
            `).join('')}
          </div>
        </div>
      `
      : '';

    bodyEl.innerHTML = `
      <div class="overview-container">
        <div class="panel-card">
          <div class="panel-card-header">
            <span>Binary Entry Point (${escapeHtml(ep.type || 'None')})</span>
            ${ep.vmaddr ? `<button class="jump-chip" data-disasm-vm="${escapeHtml(ep.vmaddr)}">Disassemble Entry Point ↵</button>` : ''}
          </div>
          <div class="kv-list">
            <div class="kv-row"><span class="kv-key">Entry Command Type</span><span class="kv-val">${escapeHtml(ep.type || 'None')}</span></div>
            <div class="kv-row"><span class="kv-key">Entry Virtual Address</span><span class="kv-val" style="color: var(--rw-fg);">${escapeHtml(ep.vmaddr || '—')}</span></div>
            <div class="kv-row"><span class="kv-key">Entry File Offset</span><span class="kv-val">${hex(ep.abs_offset)} (Slice +${hex(ep.entryoff)})</span></div>
          </div>
        </div>

        ${regsHtml}

        <div class="panel-card">
          <div class="panel-card-header">Decoded LC_FUNCTION_STARTS (${fns.length} Functions)</div>
          <div class="struct-table-wrap">
            <table class="struct-table">
              <thead>
                <tr><th>#</th><th>File Offset</th><th>Slice Offset</th><th>VM Address</th><th>Resolved Symbol Name</th><th>Action</th></tr>
              </thead>
              <tbody>
                ${fns.length === 0 ? '<tr><td colspan="6" style="color: var(--text-secondary);">No LC_FUNCTION_STARTS table in this binary.</td></tr>' : ''}
                ${fns.map(fn => `
                  <tr class="struct-row" data-abs-offset="${fn.abs_offset}" data-field-size="4" data-field-name="${escapeHtml(fn.name || 'Function')}">
                    <td>#${fn.index}</td>
                    <td class="col-offset">${hex(fn.abs_offset, 6)}</td>
                    <td class="col-offset">+${hex(fn.slice_offset, 4)}</td>
                    <td class="col-val">${escapeHtml(fn.vmaddr)}</td>
                    <td class="col-name">${escapeHtml(fn.name || `sub_${(fn.vmaddr || '').replace(/^0x/, '')}`)}</td>
                    <td><button class="jump-chip" data-disasm-vm="${escapeHtml(fn.vmaddr)}">Disassemble →</button></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 8: Objective-C Metadata & Kernel/Firmware Fileset Entries
  // -------------------------------------------------------------------------
  function renderObjcInspector(bodyEl) {
    const slice = getActiveSlice();
    const objc = slice?.objc_metadata || {};
    const classes = objc.classes || [];
    const selectors = objc.selectors || [];
    const filesets = slice?.fileset_entries || [];

    bodyEl.innerHTML = `
      <div class="overview-container">
        ${filesets.length > 0 ? `
          <div class="panel-card">
            <div class="panel-card-header">MH_FILESET Contained Mach-O Entries (${filesets.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Bundle / Entry ID</th><th>VM Address</th><th>File Offset</th></tr></thead>
                <tbody>
                  ${filesets.map(fe => `
                    <tr class="struct-row" data-abs-offset="${fe.abs_offset}" data-field-size="32">
                      <td class="col-name">${escapeHtml(fe.entry_id)}</td>
                      <td class="col-val">${escapeHtml(fe.vmaddr)}</td>
                      <td class="col-offset">${hex(fe.abs_offset, 6)}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        ` : ''}

        <div class="overview-two-col">
          <div class="panel-card">
            <div class="panel-card-header">Objective-C Classes (${classes.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Class Name</th><th>VM Address / Offset</th></tr></thead>
                <tbody>
                  ${classes.length === 0 ? '<tr><td colspan="2" style="color: var(--text-secondary);">None</td></tr>' : ''}
                  ${classes.map(c => `
                    <tr class="struct-row" data-abs-offset="${c.abs_offset || 0}" data-field-size="8">
                      <td class="col-name">${escapeHtml(typeof c === 'string' ? c : c.name)}</td>
                      <td class="col-val">${escapeHtml(c.vmaddr || hex(c.abs_offset))}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>

          <div class="panel-card">
            <div class="panel-card-header">Objective-C Selectors (${selectors.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Selector (@selector)</th><th>Location</th></tr></thead>
                <tbody>
                  ${selectors.length === 0 ? '<tr><td colspan="2" style="color: var(--text-secondary);">None</td></tr>' : ''}
                  ${selectors.map(s => `
                    <tr class="struct-row" data-abs-offset="${s.abs_offset || 0}" data-field-size="8">
                      <td class="col-name" style="color: var(--ro-fg);">${escapeHtml(typeof s === 'string' ? s : s.name)}</td>
                      <td class="col-val">${escapeHtml(s.vmaddr || hex(s.abs_offset))}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 9: Code Signature / Authenticode / ELF Notes Inspector
  // -------------------------------------------------------------------------
  function renderCodeSignatureInspector(bodyEl) {
    const slice = getActiveSlice();
    const cs = slice?.code_signature_detail || {};
    if (!cs.present) {
      const elfNotes = slice?.elf_metadata?.notes || [];
      if (slice?.format === 'ELF' && elfNotes.length > 0) {
        bodyEl.innerHTML = `
          <div class="overview-container">
            <div class="panel-card">
              <div class="panel-card-header">ELF Notes, GNU Build-ID &amp; Hardware Property Flags (${elfNotes.length})</div>
              <div class="struct-table-wrap">
                <table class="struct-table">
                  <thead><tr><th>File Offset</th><th>Namespace</th><th>Note Type</th><th>Decoded Description</th></tr></thead>
                  <tbody>
                    ${elfNotes.map(n => `
                      <tr class="struct-row" data-abs-offset="${n.abs_offset}" data-field-size="${n.size}">
                        <td class="col-offset">${hex(n.abs_offset, 6)}</td>
                        <td class="col-name">${escapeHtml(n.name)}</td>
                        <td class="col-val">${escapeHtml(n.type_name)}</td>
                        <td class="col-desc">${escapeHtml(n.description)}</td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        `;
        return;
      }
      bodyEl.innerHTML = `
        <div class="overview-container">
          <div class="panel-card">
            <div class="panel-card-header">No Embedded Cryptographic Signature Present</div>
            <div style="padding: 16px; color: var(--text-secondary);">
              This ${escapeHtml(slice?.format_display || 'binary')} slice does not contain an embedded cryptographic signature (<code>LC_CODE_SIGNATURE</code> or <code>WIN_CERTIFICATE</code> Authenticode).
            </div>
          </div>
        </div>
      `;
      return;
    }

    const cd = cs.code_directory || {};
    const blobs = cs.blobs || [];
    const entEntries = cs.entitlements_entries || [];
    const certs = cs.cms_signature?.certificates || [];

    bodyEl.innerHTML = `
      <div class="subtabs-bar" id="cs-subtabs">
        <button class="subtab-btn ${state.csSubTab === 'summary' ? 'active' : ''}" data-cs-tab="summary">SuperBlob &amp; CodeDirectory</button>
        <button class="subtab-btn ${state.csSubTab === 'entitlements' ? 'active' : ''}" data-cs-tab="entitlements">Entitlements (${entEntries.length})</button>
        <button class="subtab-btn ${state.csSubTab === 'slots' ? 'active' : ''}" data-cs-tab="slots">Special &amp; Page Hashes (${(cd.special_slots?.length || 0) + (cd.code_slots_preview?.length || 0)})</button>
        <button class="subtab-btn ${state.csSubTab === 'fields' ? 'active' : ''}" data-cs-tab="fields">Byte-Level Struct Fields</button>
      </div>
      <div id="cs-tab-body" style="flex: 1; overflow-y: auto;"></div>
    `;

    const tabBody = document.getElementById('cs-tab-body');

    if (state.csSubTab === 'summary') {
      tabBody.innerHTML = `
        <div class="overview-container">
          <div class="kpi-cards-grid">
            <div class="kpi-card">
              <span class="kpi-label">Signature Identifier</span>
              <span class="kpi-value" style="color: var(--rx-fg);">${escapeHtml(cd.identifier || '—')}</span>
              <span class="kpi-sub">Team ID: ${escapeHtml(cd.team_id || 'Apple / Ad-Hoc')}</span>
            </div>
            <div class="kpi-card">
              <span class="kpi-label">CDHash Integrity</span>
              <span class="kpi-value" style="color: ${cd.cdhash_verified ? 'var(--ro-fg)' : 'var(--rw-fg)'};">
                ${cd.cdhash_verified ? 'VERIFIED (SHA-256)' : 'PRESENT'}
              </span>
              <span class="kpi-sub" style="font-family: var(--font-mono);">${escapeHtml((cd.cdhash || '').slice(0, 24))}…</span>
            </div>
            <div class="kpi-card">
              <span class="kpi-label">Flags (${escapeHtml(cd.flags || '0x0')})</span>
              <span class="kpi-value">${(cd.flags_decoded || []).join(' | ') || 'Standard'}</span>
              <span class="kpi-sub">Hash: ${escapeHtml(cd.hash_type || 'SHA-256')} • Page: ${cd.page_size || 4096} B</span>
            </div>
            <div class="kpi-card">
              <span class="kpi-label">SuperBlob Layout</span>
              <span class="kpi-value">${cs.blob_count || blobs.length} Blobs</span>
              <span class="kpi-sub">Total Size: ${formatBytes(cs.length)} @ ${hex(cs.superblob_region?.abs_offset)}</span>
            </div>
          </div>

          <div class="overview-two-col">
            <div class="panel-card">
              <div class="panel-card-header">CS_SuperBlob Embedded Blobs (${blobs.length})</div>
              <div class="struct-table-wrap">
                <table class="struct-table">
                  <thead><tr><th>#</th><th>Slot Type</th><th>Blob Magic</th><th>File Offset</th><th>Size</th></tr></thead>
                  <tbody>
                    ${blobs.map(b => `
                      <tr class="struct-row" data-abs-offset="${b.abs_offset}" data-field-size="${Math.min(b.size || 64, 512)}" data-field-name="${escapeHtml(b.type_name)}">
                        <td>#${b.index}</td>
                        <td class="col-name">${escapeHtml(b.type_name)}</td>
                        <td class="col-val">${escapeHtml(b.magic_name)} (${escapeHtml(b.magic)})</td>
                        <td class="col-offset">${hex(b.abs_offset, 6)}</td>
                        <td>${formatBytes(b.size)}</td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              </div>
            </div>

            <div class="panel-card">
              <div class="panel-card-header">CMS Signer &amp; Certificate Chain</div>
              <div class="kv-list">
                <div class="kv-row"><span class="kv-key">Signing Mode</span><span class="kv-val">${cs.cms_signature?.is_adhoc ? 'Ad-Hoc (Local Hash Only)' : 'CMS Cryptographic Signature'}</span></div>
                <div class="kv-row"><span class="kv-key">Full CDHash</span><span class="kv-val">${escapeHtml(cd.cdhash_full || cd.cdhash || '—')}</span></div>
                ${certs.map((c, idx) => `
                  <div class="kv-row">
                    <span class="kv-key">Cert #${idx + 1}</span>
                    <span class="kv-val">${escapeHtml(typeof c === 'string' ? c : `${c.subject_cn} (Issuer: ${c.issuer_cn || c.org || 'Apple'})`)}</span>
                  </div>
                `).join('')}
              </div>
            </div>
          </div>
        </div>
      `;
    } else if (state.csSubTab === 'entitlements') {
      tabBody.innerHTML = `
        <div class="overview-container">
          <div class="panel-card">
            <div class="panel-card-header">Parsed Entitlements &amp; Capability Risk Analysis (${entEntries.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Entitlement Key</th><th>Value</th><th>Risk Level</th><th>Security Note</th></tr></thead>
                <tbody>
                  ${entEntries.length === 0 ? '<tr><td colspan="4" style="color: var(--text-secondary);">No embedded entitlements found in this binary.</td></tr>' : ''}
                  ${entEntries.map(e => `
                    <tr class="struct-row">
                      <td class="col-name">${escapeHtml(e.key)}</td>
                      <td class="col-val">${escapeHtml(JSON.stringify(e.value))}</td>
                      <td><span class="sec-status-pill sec-${e.risk === 'HIGH' ? 'WARN' : 'INFO'}">${escapeHtml(e.risk || 'INFO')}</span></td>
                      <td class="col-desc">${escapeHtml(e.reason || '')}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>

          <div class="panel-card">
            <div class="panel-card-header">Raw XML Entitlements Plist (CSMAGIC_EMBEDDED_ENTITLEMENTS)</div>
            <div style="padding: 10px;">
              <pre class="xml-code-block">${escapeHtml(cs.entitlements_xml || '<!-- No XML Entitlements Blob Present -->')}</pre>
            </div>
          </div>
        </div>
      `;
    } else if (state.csSubTab === 'slots') {
      const specialSlots = cd.special_slots || [];
      const codeSlots = cd.code_slots_preview || [];
      tabBody.innerHTML = `
        <div class="overview-container">
          <div class="panel-card">
            <div class="panel-card-header">Special Slot Hashes (Negative Indices: Info.plist, Requirements, Entitlements, DER)</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Slot Index</th><th>Artifact</th><th>SHA-256 Slot Hash</th><th>Status</th></tr></thead>
                <tbody>
                  ${specialSlots.map(s => `
                    <tr class="struct-row">
                      <td class="col-val">${s.slot}</td>
                      <td class="col-name">${escapeHtml(s.name)}</td>
                      <td class="col-bytes" style="max-width: none;">${escapeHtml(s.hash || '—')}</td>
                      <td><span class="sec-status-pill sec-${s.present ? 'PASS' : 'INFO'}">${s.present ? (s.verified !== false ? 'VERIFIED' : 'PRESENT') : 'EMPTY'}</span></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>

          <div class="panel-card">
            <div class="panel-card-header">Code Page Slot Hashes (${cd.n_code_slots || codeSlots.length} Total Pages, Previewing ${codeSlots.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Page #</th><th>File Offset</th><th>Expected SHA-256 Hash</th><th>Computed On-Disk Hash</th><th>Verification</th></tr></thead>
                <tbody>
                  ${codeSlots.map(p => `
                    <tr class="struct-row" data-abs-offset="${p.file_offset}" data-field-size="4096">
                      <td>Page #${p.page_index}</td>
                      <td class="col-offset">${hex(p.file_offset, 6)}</td>
                      <td class="col-bytes">${escapeHtml(p.expected_hash)}</td>
                      <td class="col-bytes">${escapeHtml(p.actual_hash || p.expected_hash)}</td>
                      <td><span class="sec-status-pill sec-${p.verified !== false ? 'PASS' : 'FAIL'}">${p.verified !== false ? 'MATCH' : 'MISMATCH'}</span></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      `;
    } else {
      const allFields = [...(cs.fields || []), ...(cd.fields || [])];
      renderStructInspector(tabBody, { type: 'fields', fields: allFields });
    }

    document.getElementById('cs-subtabs')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-cs-tab]');
      if (!btn) return;
      state.csSubTab = btn.dataset.csTab;
      renderCodeSignatureInspector(bodyEl);
    });
  }

  // -------------------------------------------------------------------------
  // View 10: Security & Hardening Audit Scorecard
  // -------------------------------------------------------------------------
  function renderSecurityAuditInspector(bodyEl) {
    const slice = getActiveSlice();
    const sec = slice?.security_posture || {};
    const checks = sec.checks || [];

    bodyEl.innerHTML = `
      <div class="overview-container">
        <div class="kpi-cards-grid">
          <div class="kpi-card">
            <span class="kpi-label">ASLR / PIE</span>
            <span class="kpi-value" style="color: ${sec.pie ? 'var(--ro-fg)' : 'var(--rw-fg)'};">${sec.pie ? 'Enabled (MH_PIE)' : 'Disabled'}</span>
            <span class="kpi-sub">Position Independent Executable</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Stack Canary</span>
            <span class="kpi-value" style="color: ${sec.stack_canary ? 'var(--ro-fg)' : 'var(--text-secondary)'};">${sec.stack_canary ? 'Protected' : 'Not Detected'}</span>
            <span class="kpi-sub">___stack_chk_guard / fail</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Pointer Auth (PAC)</span>
            <span class="kpi-value" style="color: ${sec.pac_enabled ? 'var(--rx-fg)' : 'var(--text-secondary)'};">${sec.pac_enabled ? 'ARM64e PAC Active' : 'Standard ABI'}</span>
            <span class="kpi-sub">Signed return addresses &amp; fixups</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">W^X Memory Hygiene</span>
            <span class="kpi-value" style="color: ${sec.has_rwx_segments ? 'var(--danger-fg)' : 'var(--ro-fg)'};">${sec.has_rwx_segments ? 'RWX Segment Detected!' : 'Strict W^X'}</span>
            <span class="kpi-sub">Simultaneous Write + Execute check</span>
          </div>
        </div>

        <div class="panel-card">
          <div class="panel-card-header">Automated Binary Hardening &amp; Vulnerability Checks (${checks.length})</div>
          <div class="security-grid">
            ${checks.map(chk => `
              <div class="sec-check-card">
                <div class="sec-check-top">
                  <span class="sec-check-title">${escapeHtml(chk.title)}</span>
                  <span class="sec-status-pill sec-${escapeHtml(chk.status)}">${escapeHtml(chk.status)}</span>
                </div>
                <div class="sec-check-val">${escapeHtml(chk.value)}</div>
                <div class="sec-check-detail">${escapeHtml(chk.detail)}</div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 11: Semantic & Entropy Intelligence Inspector
  // -------------------------------------------------------------------------
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
    const strIntel = caps.string_intelligence || {};
    const findings = anom.findings || [];

    const entColorClass = (h) => {
      if (h < 1.0) return 'ent-sparse';
      if (h < 4.5) return 'ent-structured';
      if (h < 6.5) return 'ent-code';
      if (h < 7.2) return 'ent-dense';
      return 'ent-packed';
    };

    const sparkBarsHtml = windows
      .map((w) => {
        const pct = Math.max(6, Math.round((w.entropy / 8.0) * 100));
        return `<div class="entropy-bar ${entColorClass(w.entropy)}" style="height: ${pct}%" data-jump-offset="${w.abs_offset}" data-jump-size="${w.size}" title="Offset ${hex(w.abs_offset, 6)} (${formatBytes(w.size)}): ${w.entropy.toFixed(2)} bits/byte [${w.classification}]"></div>`;
      })
      .join('');

    const richHeaderHtml =
      slice.format === 'PE' && slice.pe_metadata?.rich_header?.present
        ? `
          <div class="panel-card">
            <div class="panel-card-header">
              <span>Microsoft PE Rich Header (XOR Key: ${escapeHtml(slice.pe_metadata.rich_header.xor_key)})</span>
              <button class="jump-chip" data-jump-offset="${slice.pe_metadata.rich_header.abs_offset}" data-jump-size="${slice.pe_metadata.rich_header.size}">Focus Rich Header in Hex ↵</button>
            </div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Product ID</th><th>Tool / Compiler Name</th><th>Build Number</th><th>Object Count</th></tr></thead>
                <tbody>
                  ${(slice.pe_metadata.rich_header.entries || []).map(r => `
                    <tr class="struct-row" data-abs-offset="${slice.pe_metadata.rich_header.abs_offset}" data-field-size="${slice.pe_metadata.rich_header.size}">
                      <td class="col-val">${hex(r.prod_id, 4)}</td>
                      <td class="col-name">${escapeHtml(r.product_name)}</td>
                      <td>${r.build_num}</td>
                      <td>${r.use_count}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        `
        : '';

    bodyEl.innerHTML = `
      <div class="overview-container">
        <!-- KPI Cards -->
        <div class="kpi-cards-grid">
          <div class="kpi-card">
            <span class="kpi-label">Overall Shannon Entropy</span>
            <span class="kpi-value" style="color: ${ent.overall_entropy >= 7.2 ? 'var(--danger-fg)' : 'var(--rx-fg)'};">${(ent.overall_entropy ?? 0).toFixed(2)} / 8.00 bits</span>
            <span class="kpi-sub">${escapeHtml(ent.overall_classification || 'Standard')} • Max Window: ${(ent.max_window_entropy ?? 0).toFixed(2)}b</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Compiler &amp; Toolchain</span>
            <span class="kpi-value" style="color: var(--ro-fg);">${escapeHtml(prov.compiler_family || 'System Toolchain')}</span>
            <span class="kpi-sub">Lang: ${escapeHtml((prov.source_languages || []).join(', '))}</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Behavioral Capabilities</span>
            <span class="kpi-value" style="color: var(--rw-fg);">${capCats.length} Active Domains</span>
            <span class="kpi-sub">${caps.total_matched_indicators || 0} API / Symbol / String Indicators</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Structural Anomalies</span>
            <span class="kpi-value" style="color: ${anom.high_severity_count > 0 ? 'var(--danger-fg)' : 'var(--ro-fg)'};">${findings.length} Findings</span>
            <span class="kpi-sub">Strip Level: ${escapeHtml(prov.strip_level || 'Standard')}</span>
          </div>
        </div>

        <!-- Entropy Sparkline & Byte Class Distribution -->
        <div class="panel-card">
          <div class="panel-card-header">
            <span>Shannon Entropy Heatmap (${windows.length} Sliding Windows — Click Any Bar to Jump Hex)</span>
            <span style="color: var(--text-secondary); font-weight: 400;">${escapeHtml(ent.packing_assessment || '')}</span>
          </div>
          <div class="entropy-sparkline-wrap">
            <div class="entropy-sparkline-bars">${sparkBarsHtml}</div>
            <div style="display: flex; justify-content: space-between; font-size: 10.5px; color: var(--text-secondary);">
              <span>0x000000 (Start of Slice)</span>
              <span>Legend: <strong style="color: #8b949e;">Sparse (&lt;1.0)</strong> • <strong style="color: var(--ro-fg);">Structured (1–4.5)</strong> • <strong style="color: var(--rx-fg);">Native Code (4.5–6.5)</strong> • <strong style="color: var(--rw-fg);">Dense (6.5–7.2)</strong> • <strong style="color: var(--danger-fg);">Packed/Crypto (&gt;7.2)</strong></span>
              <span>${hex((slice.slice_base_offset || 0) + (slice.slice_size || 0), 6)} (End)</span>
            </div>

            <div style="margin-top: 6px;">
              <div style="font-size: 10.5px; color: var(--text-secondary); margin-bottom: 4px;">
                Byte Class Distribution — Null (0x00): <strong>${dist.null_pct ?? 0}%</strong> • Printable ASCII (0x20–0x7E): <strong>${dist.ascii_pct ?? 0}%</strong> • Control/Low (0x01–0x1F): <strong>${dist.control_pct ?? 0}%</strong> • High-Bit/Binary (0x80–0xFF): <strong>${dist.high_pct ?? 0}%</strong>
              </div>
              <div class="byte-class-stacked-bar">
                <div style="width: ${dist.null_pct ?? 0}%; background: #30363d;" title="Null Bytes: ${dist.null_pct ?? 0}%"></div>
                <div style="width: ${dist.ascii_pct ?? 0}%; background: var(--ro-fg);" title="Printable ASCII: ${dist.ascii_pct ?? 0}%"></div>
                <div style="width: ${dist.control_pct ?? 0}%; background: var(--rx-fg);" title="Low/Control Bytes: ${dist.control_pct ?? 0}%"></div>
                <div style="width: ${dist.high_pct ?? 0}%; background: var(--hdr-fg);" title="High-Bit Binary Bytes: ${dist.high_pct ?? 0}%"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- Behavioral Capabilities Grid -->
        <div class="panel-card">
          <div class="panel-card-header">Behavioral Capability &amp; Subsystem Taxonomy (${capCats.length} Detected)</div>
          ${capCats.length === 0 ? '<div style="padding: 12px; color: var(--text-secondary);">No specialized subsystem imports/strings matched beyond standard C runtime initialization.</div>' : ''}
          <div class="capability-grid">
            ${capCats.map(cat => `
              <div class="cap-card">
                <div class="sec-check-top">
                  <span class="sec-check-title">${escapeHtml(cat.title)}</span>
                  <span class="sec-status-pill sec-${cat.risk === 'HIGH' ? 'WARN' : 'INFO'}">${escapeHtml(cat.risk)} (${cat.match_count})</span>
                </div>
                <div class="sec-check-detail">${escapeHtml(cat.description)}</div>
                <div class="cap-evidence-list">
                  ${(cat.evidence || []).map(ev => `
                    <button class="jump-chip" data-jump-offset="${ev.abs_offset || 0}" data-jump-size="16" title="${escapeHtml(ev.kind)}: ${escapeHtml(ev.value)}">
                      ${escapeHtml(ev.indicator)}
                    </button>
                  `).join('')}
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Two Column: Section Entropy Table & Provenance / Anomalies -->
        <div class="overview-two-col">
          <div class="panel-card">
            <div class="panel-card-header">Per-Section Entropy &amp; Byte Distribution (${secMetrics.length})</div>
            <div class="struct-table-wrap">
              <table class="struct-table">
                <thead><tr><th>Section</th><th>Size</th><th>Entropy</th><th>Semantic Class</th><th>ASCII / Null</th></tr></thead>
                <tbody>
                  ${secMetrics.map(m => `
                    <tr class="struct-row" data-abs-offset="${m.abs_offset}" data-field-size="${Math.min(m.size || 64, 256)}">
                      <td class="col-name">${escapeHtml(m.name)}</td>
                      <td>${formatBytes(m.size)}</td>
                      <td class="col-val" style="color: ${m.entropy >= 7.2 ? 'var(--danger-fg)' : 'var(--rx-fg)'};">${m.entropy.toFixed(2)} b</td>
                      <td>${escapeHtml(m.classification)}</td>
                      <td>${m.byte_classes?.ascii_pct ?? 0}% / ${m.byte_classes?.null_pct ?? 0}%</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>

          <div class="panel-card">
            <div class="panel-card-header">Structural Anomaly Forensics &amp; Build Provenance</div>
            <div class="kv-list">
              <div class="kv-row"><span class="kv-key">Compiler / Linker</span><span class="kv-val">${escapeHtml(prov.compiler_family)} (${escapeHtml((prov.linker_info || []).join(', ') || 'Standard')})</span></div>
              <div class="kv-row"><span class="kv-key">ABI &amp; Target</span><span class="kv-val">${escapeHtml(prov.abi || 'Standard')}</span></div>
              <div class="kv-row"><span class="kv-key">Debug Artifact / PDB / UUID</span><span class="kv-val">${escapeHtml((prov.debug_artifacts || []).join(' | ') || 'None')}</span></div>
              <div class="kv-row"><span class="kv-key">Extracted URLs / Paths</span><span class="kv-val">${(strIntel.urls?.length || 0)} URLs, ${(strIntel.file_paths?.length || 0)} Paths, ${(strIntel.registry_keys?.length || 0)} Registry Keys</span></div>
              ${findings.map(f => `
                <div class="kv-row" style="cursor: pointer;" data-jump-offset="${f.abs_offset}" data-jump-size="32">
                  <span class="kv-key"><span class="sec-status-pill sec-${f.severity === 'WARN' ? 'WARN' : 'INFO'}">${escapeHtml(f.severity)}</span> ${escapeHtml(f.title)}</span>
                  <span class="kv-val" style="font-family: var(--font-sans); color: var(--text-secondary);">${escapeHtml(f.detail)}</span>
                </div>
              `).join('')}
            </div>
          </div>
        </div>

        ${richHeaderHtml}
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 12: Interactive OS Loader & Execution Lifecycle Simulator
  // -------------------------------------------------------------------------
  function renderLoaderLifecycleInspector(bodyEl) {
    const slice = getActiveSlice();
    if (!slice) return;
    const lc = slice.pedagogy?.loader_lifecycle || {};
    const stages = lc.stages || [];

    bodyEl.innerHTML = `
      <div class="overview-container">
        <div class="panel-card">
          <div class="panel-card-header">
            <span>Interactive 6-Stage OS Loader &amp; Execution Lifecycle — ${escapeHtml(lc.os_family || '')}</span>
            <span style="color: var(--rx-fg); font-family: var(--font-mono);">${escapeHtml(lc.loader_name || '')}</span>
          </div>
          <div style="padding: 10px 12px; color: var(--text-secondary); font-size: 11.5px;">
            Trace how the operating system kernel and user-space dynamic linker transform this on-disk <strong>${escapeHtml(slice.format_display || slice.format)}</strong> file into a live process in virtual memory. Click any stage's <strong>Highlight Bytes in Hex</strong> button to inspect the exact file structure read at that step.
          </div>
          <div class="lifecycle-stepper">
            ${stages.map(st => `
              <div class="lifecycle-stage-card">
                <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="stage-num-badge">${st.stage}</span>
                    <strong style="color: var(--text-bright); font-size: 12.5px;">${escapeHtml(st.title)}</strong>
                  </div>
                  <button class="jump-chip" data-jump-offset="${st.abs_offset || 0}" data-jump-size="${st.size || 32}">Highlight Bytes ↵</button>
                </div>
                <div style="font-family: var(--font-mono); font-size: 10.5px; color: var(--rx-fg);">${escapeHtml(st.actor || '')}</div>
                <div style="font-size: 11.5px; color: var(--text-primary); line-height: 1.45;">${escapeHtml(st.summary || '')}</div>
                <div style="padding: 6px 8px; background: var(--bg-elevated); border-radius: 4px; border: 1px solid var(--border-subtle); font-family: var(--font-mono); font-size: 10.5px;">
                  <div style="color: var(--ro-fg);"><strong>Binary Evidence:</strong> ${escapeHtml(st.binary_state || '')}</div>
                  <div style="color: var(--rw-fg); margin-top: 3px;"><strong>If Corrupted:</strong> ${escapeHtml(st.failure_mode || '')}</div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // View 13: Cross-Format Rosetta Stone Matrix & Guided Learning Tours
  // -------------------------------------------------------------------------
  function renderRosettaAndToursInspector(bodyEl) {
    const slice = getActiveSlice();
    if (!slice) return;
    const ped = slice.pedagogy || {};
    const rows = ped.rosetta_stone || [];
    const tours = ped.guided_tours || [];
    const fmt = slice.format || 'MACHO';

    bodyEl.innerHTML = `
      <div class="overview-container">
        <!-- Guided Learning Tours with Interactive Micro-Challenges -->
        <div class="panel-card">
          <div class="panel-card-header">
            <span>🎓 Guided Reverse Engineering &amp; Format Learning Tours (${tours.length} Tracks)</span>
            <span style="color: var(--hdr-fg);">Click any step to highlight live bytes &amp; test your understanding</span>
          </div>
          <div class="lifecycle-stepper">
            ${tours.map((tour, tIdx) => `
              <div class="tour-card">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                  <strong style="font-size: 12.5px; color: var(--text-bright);">${escapeHtml(tour.title)}</strong>
                  <span class="inspector-badge badge-purple">${escapeHtml(tour.level)} • ${escapeHtml(tour.estimated_time)}</span>
                </div>
                <div style="font-size: 11.5px; color: var(--text-secondary);">${escapeHtml(tour.description)}</div>
                ${(tour.steps || []).map((st, sIdx) => `
                  <div style="padding: 8px; background: var(--bg-elevated); border: 1px solid var(--border-subtle); border-radius: 4px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                      <strong style="color: var(--rx-fg);">Step ${st.step_number}: ${escapeHtml(st.title)}</strong>
                      <button class="jump-chip" data-select-node="${escapeHtml(st.target_node_id || 'overview')}" data-jump-offset="${st.abs_offset || 0}" data-jump-size="${st.size || 32}">Inspect Step ↵</button>
                    </div>
                    <div style="font-size: 11px; color: var(--text-primary); margin-top: 4px;">${escapeHtml(st.narrative)}</div>
                    ${st.challenge ? `
                      <div style="margin-top: 6px; padding-top: 6px; border-top: 1px dashed var(--border-default);">
                        <div style="font-size: 11px; font-weight: 600; color: var(--rw-fg);">Challenge: ${escapeHtml(st.challenge.question)}</div>
                        ${(st.challenge.options || []).map((opt, oIdx) => `
                          <button
                            class="quiz-option-btn"
                            data-quiz-correct="${oIdx === st.challenge.correct_index ? '1' : '0'}"
                            data-quiz-exp="${escapeHtml(st.challenge.explanation || '')}"
                          >${escapeHtml(opt)}</button>
                        `).join('')}
                        <div class="quiz-feedback hidden" style="margin-top: 5px; font-size: 11px; padding: 4px 6px; border-radius: 3px;"></div>
                      </div>
                    ` : ''}
                  </div>
                `).join('')}
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Cross-Format Rosetta Stone Matrix -->
        <div class="panel-card">
          <div class="panel-card-header">
            <span>Cross-Format "Rosetta Stone" Equivalence Matrix (Mach-O ⇄ ELF ⇄ Windows PE)</span>
            <span style="color: var(--ro-fg);">Active Binary Column Highlighted (${escapeHtml(fmt)})</span>
          </div>
          <div class="struct-table-wrap">
            <table class="struct-table">
              <thead>
                <tr>
                  <th>Systems Concept</th>
                  <th style="${fmt === 'MACHO' ? 'color: var(--rx-fg);' : ''}">Apple Mach-O (macOS / iOS)</th>
                  <th style="${fmt === 'ELF' ? 'color: var(--rx-fg);' : ''}">Linux / SVR4 ELF (ELF32/64)</th>
                  <th style="${fmt === 'PE' ? 'color: var(--rx-fg);' : ''}">Windows PE (PE32 / PE32+)</th>
                  <th>Architectural Insight &amp; Action</th>
                </tr>
              </thead>
              <tbody>
                ${rows.map(r => `
                  <tr class="struct-row" data-abs-offset="${r.active_offset || 0}" data-field-size="32">
                    <td class="col-name">${escapeHtml(r.concept)}</td>
                    <td style="${fmt === 'MACHO' ? 'background: rgba(56,139,253,0.08); color: var(--text-bright);' : ''}">${escapeHtml(r.macho)}</td>
                    <td style="${fmt === 'ELF' ? 'background: rgba(56,139,253,0.08); color: var(--text-bright);' : ''}">${escapeHtml(r.elf)}</td>
                    <td style="${fmt === 'PE' ? 'background: rgba(56,139,253,0.08); color: var(--text-bright);' : ''}">${escapeHtml(r.pe)}</td>
                    <td class="col-desc">
                      ${escapeHtml(r.pedagogical_note)}
                      <button class="jump-chip" data-select-node="${escapeHtml(r.active_target_node || 'overview')}" data-jump-offset="${r.active_offset || 0}" data-jump-size="32">Locate in Binary →</button>
                    </td>
                  </tr>
                `).join('')}
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
  function initHexViewport() {
    const phantom = document.getElementById('hex-phantom');
    const fileSize = state.doc?.file_info?.file_size || 0;
    const totalRows = Math.ceil(fileSize / HEX_BYTES_PER_ROW);
    if (phantom) {
      phantom.style.height = `${totalRows * HEX_ROW_HEIGHT}px`;
    }
    renderHexViewport();
  }

  async function ensureHexChunk(chunkOffset) {
    if (state.hexChunks.has(chunkOffset) || state.hexPendingChunks.has(chunkOffset)) {
      return;
    }
    state.hexPendingChunks.add(chunkOffset);
    try {
      const res = await fetch(`/api/hex?offset=${chunkOffset}&length=${HEX_CHUNK_SIZE}&slice_index=${state.activeSliceIndex}`);
      if (!res.ok) return;
      const data = await res.json();
      if (typeof data.hex_bytes === 'string') {
        const clean = data.hex_bytes.replace(/\s+/g, '');
        const bytes = new Uint8Array(clean.length / 2);
        for (let i = 0; i < bytes.length; i++) {
          bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
        }
        state.hexChunks.set(chunkOffset, bytes);
        renderHexViewport();
      } else if (Array.isArray(data.rows)) {
        const bytes = new Uint8Array(data.rows.length * 16);
        let k = 0;
        data.rows.forEach((r) => {
          (r.hex_array || []).forEach((hb) => {
            bytes[k++] = parseInt(hb, 16);
          });
        });
        state.hexChunks.set(chunkOffset, bytes.subarray(0, k));
        renderHexViewport();
      }
    } catch (err) {
      console.warn('Hex chunk fetch error:', err);
    } finally {
      state.hexPendingChunks.delete(chunkOffset);
    }
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

  function renderHexViewport() {
    const viewport = document.getElementById('hex-viewport');
    const rowsContainer = document.getElementById('hex-rows-container');
    if (!viewport || !rowsContainer || !state.doc) return;

    const fileSize = state.doc.file_info?.file_size || 0;
    const totalRows = Math.ceil(fileSize / HEX_BYTES_PER_ROW);
    const scrollTop = viewport.scrollTop;
    const viewHeight = viewport.clientHeight || 380;

    const firstRow = Math.max(0, Math.floor(scrollTop / HEX_ROW_HEIGHT) - 6);
    const lastRow = Math.min(totalRows, Math.ceil((scrollTop + viewHeight) / HEX_ROW_HEIGHT) + 6);

    rowsContainer.style.transform = `translateY(${firstRow * HEX_ROW_HEIGHT}px)`;

    const slice = getActiveSlice();
    const sSpan = state.structSpan;
    const fSpan = state.fieldSpan;

    const htmlRows = [];
    for (let r = firstRow; r < lastRow; r++) {
      const rowOffset = r * HEX_BYTES_PER_ROW;
      let addrLabel = hexNoPrefix(rowOffset, 8);
      if (state.hexAddrMode === 'vm') {
        const vm = absOffsetToVmAddr(rowOffset, slice);
        addrLabel = vm ? vm.replace(/^0x/i, '').toUpperCase().padStart(9, '0') : 'UNMAPPED';
      }

      const byteSpans = [];
      const asciiSpans = [];

      for (let b = 0; b < HEX_BYTES_PER_ROW; b++) {
        const off = rowOffset + b;
        if (off >= fileSize) {
          byteSpans.push(`<span class="hex-byte ${b === 8 ? 'byte-gap' : ''}">  </span>`);
          asciiSpans.push(`<span class="ascii-char"> </span>`);
          continue;
        }

        const val = getByteAtOffset(off);
        const hexStr = val === null ? '··' : val.toString(16).toUpperCase().padStart(2, '0');
        const isZero = val === 0;
        const isPrintable = val !== null && val >= 0x20 && val <= 0x7e;
        const asciiChar = val === null ? '·' : isPrintable ? escapeHtml(String.fromCharCode(val)) : '.';

        const inStruct = sSpan && off >= sSpan.abs_offset && off < sSpan.abs_offset + sSpan.size;
        const inField = fSpan && off >= fSpan.abs_offset && off < fSpan.abs_offset + fSpan.size;
        const isCursor = off === state.cursorOffset;

        const cls = [
          'hex-byte',
          b === 8 ? 'byte-gap' : '',
          isZero ? 'byte-zero' : '',
          inStruct ? 'in-struct-span' : '',
          inField ? 'in-field-span' : '',
          isCursor ? 'cursor-byte' : '',
        ]
          .filter(Boolean)
          .join(' ');

        const asciiCls = [
          'ascii-char',
          !isPrintable ? 'ascii-nonprint' : '',
          inField ? 'in-field-span' : '',
          isCursor ? 'cursor-byte' : '',
        ]
          .filter(Boolean)
          .join(' ');

        byteSpans.push(`<span class="${cls}" data-byte-offset="${off}">${hexStr}</span>`);
        asciiSpans.push(`<span class="${asciiCls}" data-byte-offset="${off}">${asciiChar}</span>`);
      }

      htmlRows.push(`
        <div class="hex-row">
          <span class="hex-row-addr">${addrLabel}</span>
          <span class="hex-row-bytes">${byteSpans.join('')}</span>
          <span class="hex-row-ascii">${asciiSpans.join('')}</span>
        </div>
      `);
    }

    rowsContainer.innerHTML = htmlRows.join('');
  }

  function scrollHexToOffset(absOffset) {
    const viewport = document.getElementById('hex-viewport');
    if (!viewport || !state.doc) return;
    const rowIdx = Math.floor(absOffset / HEX_BYTES_PER_ROW);
    const targetTop = rowIdx * HEX_ROW_HEIGHT;
    const viewHeight = viewport.clientHeight || 350;

    if (targetTop < viewport.scrollTop + HEX_ROW_HEIGHT || targetTop > viewport.scrollTop + viewHeight - HEX_ROW_HEIGHT * 2) {
      viewport.scrollTop = Math.max(0, targetTop - Math.floor(viewHeight / 3));
    }
    renderHexViewport();
  }

  function setCursorAndHighlight(absOffset, fieldSpan = null, opts = { scrollHex: true, recordHistory: true }) {
    if (!state.doc) return;
    const maxOff = Math.max(0, (state.doc.file_info?.file_size || 1) - 1);
    const clamped = Math.max(0, Math.min(Number(absOffset || 0), maxOff));

    state.cursorOffset = clamped;
    if (fieldSpan) {
      state.fieldSpan = fieldSpan;
    }

    document.getElementById('hex-selection-pill').textContent = fieldSpan
      ? `${fieldSpan.label || 'Field'}: ${hex(fieldSpan.abs_offset, 6)} (${fieldSpan.size}B)`
      : `Cursor: ${hex(clamped, 6)}`;

    document.getElementById('status-span').textContent = fieldSpan
      ? `Selected: ${fieldSpan.label || ''} @ ${hex(fieldSpan.abs_offset)} (${fieldSpan.size}B)`
      : `Cursor: ${hex(clamped)}`;

    if (opts.scrollHex) {
      scrollHexToOffset(clamped);
    } else {
      renderHexViewport();
    }

    updateMemoryMapPlayhead();
    fetchLiveByteDecode(clamped);
    updateConverterFromOffset(clamped);
  }

  // =========================================================================
  // Live Byte Inspector / Data Decoder Card (`/api/decode`)
  // =========================================================================
  let decodeAbortController = null;
  async function fetchLiveByteDecode(absOffset) {
    if (decodeAbortController) decodeAbortController.abort();
    decodeAbortController = new AbortController();

    try {
      const res = await fetch(
        `/api/decode?offset=${absOffset}&slice_index=${state.activeSliceIndex}&endian=${state.decoderEndian}`,
        { signal: decodeAbortController.signal }
      );
      if (!res.ok) return;
      const data = await res.json();
      state.lastDecodeData = data;
      renderByteDecoderCard(data);
    } catch (err) {
      if (err.name !== 'AbortError') {
        console.warn('Decode error:', err);
      }
    }
  }

  function renderByteDecoderCard(data) {
    if (!data) return;
    const p = data.primitives || {};

    document.getElementById('dec-u8').textContent = `${p.uint8 ?? '—'} / ${p.int8 ?? '—'}`;
    document.getElementById('dec-u16').textContent = `${p.uint16 ?? '—'} / ${p.int16 ?? '—'}`;
    document.getElementById('dec-u32').textContent = `${p.uint32 ?? '—'} (${p.hex32 || '—'})`;
    document.getElementById('dec-u64').textContent = `${p.uint64 ?? '—'}`;
    document.getElementById('dec-uleb').textContent = p.uleb128 ? `${p.uleb128.value} (${p.uleb128.byte_length}B)` : '—';
    document.getElementById('dec-sleb').textContent = p.sleb128 ? `${p.sleb128.value} (${p.sleb128.byte_length}B)` : '—';
    document.getElementById('dec-float').textContent =
      p.float32 !== undefined && p.float32 !== null ? `${Number(p.float32).toPrecision(4)}` : '—';
    const slice = getActiveSlice();
    const isArm = slice && /arm/i.test(slice.arch_name || '');
    const insnPreview = isArm
      ? (p.arm64_insn && p.arm64_insn !== 'N/A' ? p.arm64_insn : p.x86_insn)
      : (p.x86_insn && p.x86_insn !== 'N/A' ? p.x86_insn : p.arm64_insn);
    document.getElementById('dec-insn').textContent = insnPreview || p.cstring_preview || '—';

    const pedBox = document.getElementById('decoder-pedagogy-box');
    if (pedBox) {
      if (data.field_pedagogy) {
        const fp = data.field_pedagogy;
        pedBox.innerHTML = `<strong style="color: var(--hdr-fg);">${escapeHtml(fp.field_name)}:</strong> ${escapeHtml(fp.why_it_matters || '')} <span style="color: var(--rx-fg);">[Peer: ${escapeHtml(fp.cross_format_peer || '')}]</span>`;
        pedBox.classList.remove('hidden');
      } else {
        pedBox.classList.add('hidden');
      }
    }

    const crumbsEl = document.getElementById('decoder-breadcrumbs');
    const crumbs = data.breadcrumbs || [];
    if (crumbs.length === 0) {
      crumbsEl.innerHTML = `<span class="crumb-empty">Offset ${hex(data.abs_offset, 6)}</span>`;
    } else {
      crumbsEl.innerHTML = crumbs
        .map(
          (c, i) => `
          ${i > 0 ? '<span class="crumb-sep">›</span>' : ''}
          <span class="crumb-pill" data-crumb-offset="${c.abs_offset}" data-crumb-size="${c.size}" data-crumb-id="${escapeHtml(c.id || '')}" title="${hex(c.abs_offset)} (${c.size}B)">
            ${escapeHtml(c.label)}
          </span>
        `
        )
        .join('');
    }
  }

  // =========================================================================
  // Real-Time Address / Offset Converter Bar (`/api/translate`)
  // =========================================================================
  let translateTimeout = null;

  async function runTranslateQuery(query, mode = 'auto') {
    if (!state.doc || query === '' || query === null || query === undefined) return;
    try {
      const params = new URLSearchParams({
        slice_index: String(state.activeSliceIndex),
        query: String(query),
        mode,
      });
      const res = await fetch(`/api/translate?${params.toString()}`);
      if (!res.ok) return;
      const data = await res.json();
      renderConverterResult(data, mode);
    } catch (err) {
      console.warn('Translate error:', err);
    }
  }

  function updateConverterFromOffset(absOffset) {
    clearTimeout(translateTimeout);
    translateTimeout = setTimeout(() => {
      runTranslateQuery(hex(absOffset), 'abs_offset');
    }, 30);
  }

  function renderConverterResult(data, sourceMode) {
    if (!data) return;
    const absIn = document.getElementById('conv-abs-input');
    const sliceIn = document.getElementById('conv-slice-input');
    const vmIn = document.getElementById('conv-vm-input');
    const rvaIn = document.getElementById('conv-rva-input');

    if (document.activeElement !== absIn && typeof data.abs_offset === 'number') {
      absIn.value = hex(data.abs_offset, 6);
    }
    if (document.activeElement !== sliceIn && typeof data.slice_offset === 'number') {
      sliceIn.value = hex(data.slice_offset, 6);
    }
    if (document.activeElement !== vmIn) {
      vmIn.value = data.vmaddr || 'Unmapped';
    }
    rvaIn.value = data.rva ? `+${data.rva}` : '—';

    const statusBadge = document.getElementById('conv-status-badge');
    const segPill = document.getElementById('conv-seg-pill');
    const symPill = document.getElementById('conv-sym-pill');

    statusBadge.textContent = data.status || (data.mapped ? 'MAPPED' : 'UNMAPPED');
    statusBadge.className = `res-status-badge ${data.mapped ? 'status-mapped' : 'status-unmapped'}`;

    if (data.segment) {
      const secStr = data.section ? `,${data.section.sectname}` : '';
      segPill.textContent = `${data.segment.segname}${secStr} (${(data.segment.initprot || '---').toUpperCase()})`;
    } else {
      segPill.textContent = 'File-Only / Header';
    }

    if (data.nearest_symbol) {
      symPill.textContent = `Symbol: ${data.nearest_symbol.display || data.nearest_symbol.name}`;
    } else {
      symPill.textContent = data.vmaddr ? `VM ${data.vmaddr}` : `File ${hex(data.abs_offset)}`;
    }
  }

  // =========================================================================
  // Global Command Palette & Omni-Search (`Cmd+K` / `/api/search`)
  // =========================================================================
  function openCmdkModal() {
    state.cmdkOpen = true;
    const modal = document.getElementById('cmdk-modal');
    const input = document.getElementById('cmdk-input');
    modal.classList.remove('hidden');
    input.focus();
    input.select();
    runCmdkSearch(input.value);
  }

  function closeCmdkModal() {
    state.cmdkOpen = false;
    document.getElementById('cmdk-modal').classList.add('hidden');
  }

  let cmdkTimer = null;
  function runCmdkSearch(rawQuery) {
    clearTimeout(cmdkTimer);
    cmdkTimer = setTimeout(async () => {
      const q = rawQuery.trim();
      if (!q) {
        // Show quick-access structural highlights when empty
        const slice = getActiveSlice();
        const defaults = [
          { category: 'structure', title: 'Binary Overview Dashboard', subtitle: 'Executive summary, slices & hashes', node_id: 'overview', abs_offset: slice?.slice_base_offset || 0 },
          { category: 'structure', title: 'Mach-O Header (mach_header_64)', subtitle: 'Magic, CPU type, flags', node_id: 'mach_header', abs_offset: slice?.slice_base_offset || 0 },
          { category: 'structure', title: 'Disassembly View', subtitle: 'Linear instruction decoder', node_id: 'disassembly', abs_offset: slice?.entry_point?.abs_offset || 0 },
          { category: 'structure', title: 'Code Signature & Entitlements', subtitle: 'SuperBlob, CDHash verification & XML plist', node_id: 'code_signature', abs_offset: slice?.code_signature_detail?.superblob_region?.abs_offset || 0 },
          { category: 'structure', title: 'Security & Hardening Audit', subtitle: 'PIE, Canary, PAC, W^X & Entitlement checks', node_id: 'security_audit', abs_offset: slice?.slice_base_offset || 0 },
        ];
        state.cmdkResults = defaults;
        state.cmdkActiveIdx = 0;
        renderCmdkResults();
        return;
      }

      try {
        const params = new URLSearchParams({
          q,
          slice_index: String(state.activeSliceIndex),
          scope: state.cmdkScope,
        });
        const res = await fetch(`/api/search?${params.toString()}`);
        if (!res.ok) return;
        const data = await res.json();
        state.cmdkResults = data.results || [];
        state.cmdkActiveIdx = 0;
        renderCmdkResults();
      } catch (err) {
        console.warn('Search error:', err);
      }
    }, 60);
  }

  function renderCmdkResults() {
    const container = document.getElementById('cmdk-results');
    if (!container) return;
    if (!state.cmdkResults.length) {
      container.innerHTML = `<div class="cmdk-empty">No matching symbols, strings, structures, or hex byte sequences found.</div>`;
      return;
    }

    const catBadge = (cat) => {
      const c = (cat || '').toLowerCase();
      if (c.includes('sym')) return '<span class="inspector-badge badge-cyan">SYM</span>';
      if (c.includes('str')) return '<span class="inspector-badge badge-emerald">STR</span>';
      if (c.includes('hex')) return '<span class="inspector-badge badge-amber">HEX</span>';
      return '<span class="inspector-badge badge-purple">STRUCT</span>';
    };

    container.innerHTML = state.cmdkResults
      .map(
        (item, idx) => `
        <div class="cmdk-item ${idx === state.cmdkActiveIdx ? 'active' : ''}" data-cmdk-idx="${idx}">
          <div class="cmdk-item-left">
            ${catBadge(item.category)}
            <div style="min-width: 0;">
              <div class="cmdk-item-title">${escapeHtml(item.title)}</div>
              <div class="cmdk-item-sub">${escapeHtml(item.subtitle || '')}</div>
            </div>
          </div>
          <div class="cmdk-item-right">
            ${item.vmaddr ? escapeHtml(item.vmaddr) : hex(item.abs_offset, 6)}
          </div>
        </div>
      `
      )
      .join('');
  }

  function executeCmdkSelection(idx) {
    const item = state.cmdkResults[idx];
    if (!item) return;
    closeCmdkModal();

    if (item.node_id && state.treeNodesMap.has(item.node_id)) {
      selectTreeNode(item.node_id, { scrollHex: false });
    }
    if (typeof item.abs_offset === 'number') {
      setCursorAndHighlight(
        item.abs_offset,
        { abs_offset: item.abs_offset, size: item.size || 8, label: item.title },
        { scrollHex: true, recordHistory: true }
      );
    }
  }

  // =========================================================================
  // Back / Forward Navigation History
  // =========================================================================
  function pushHistory(entry) {
    state.history = state.history.slice(0, state.historyIndex + 1);
    state.history.push(entry);
    state.historyIndex = state.history.length - 1;
    updateHistoryButtons();
  }

  function navigateHistory(delta) {
    const targetIdx = state.historyIndex + delta;
    if (targetIdx < 0 || targetIdx >= state.history.length) return;
    state.historyIndex = targetIdx;
    const entry = state.history[targetIdx];
    state.suppressHistory = true;
    if (entry.sliceIndex !== state.activeSliceIndex) {
      activateSlice(entry.sliceIndex);
    }
    selectTreeNode(entry.nodeId, { scrollHex: false, recordHistory: false });
    setCursorAndHighlight(entry.cursorOffset, null, { scrollHex: true, recordHistory: false });
    state.suppressHistory = false;
    updateHistoryButtons();
  }

  function updateHistoryButtons() {
    document.getElementById('btn-nav-back').disabled = state.historyIndex <= 0;
    document.getElementById('btn-nav-fwd').disabled = state.historyIndex >= state.history.length - 1;
  }

  // =========================================================================
  // Event Listeners & Delegation Setup
  // =========================================================================
  function initEventListeners() {
    // 1. Preset Pills
    document.getElementById('presets-bar').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-preset-path]');
      if (!btn) return;
      loadBinaryByPath(btn.dataset.presetPath);
    });

    // 2. Path Form Load
    document.getElementById('path-load-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const val = document.getElementById('path-input').value.trim();
      if (val) loadBinaryByPath(val);
    });

    // 3. File Upload Input & Full-Window Drag-and-Drop
    document.getElementById('file-upload-input').addEventListener('change', (e) => {
      const file = e.target.files?.[0];
      if (file) {
        uploadBinaryFile(file);
        e.target.value = '';
      }
    });

    const dropOverlay = document.getElementById('dropzone-overlay');
    let dragDepth = 0;
    window.addEventListener('dragenter', (e) => {
      e.preventDefault();
      dragDepth++;
      dropOverlay.classList.remove('hidden');
    });
    window.addEventListener('dragover', (e) => {
      e.preventDefault();
    });
    window.addEventListener('dragleave', (e) => {
      e.preventDefault();
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) dropOverlay.classList.add('hidden');
    });
    window.addEventListener('drop', (e) => {
      e.preventDefault();
      dragDepth = 0;
      dropOverlay.classList.add('hidden');
      const file = e.dataTransfer?.files?.[0];
      if (file) uploadBinaryFile(file);
    });

    // 4. Architecture Slice Selector
    document.getElementById('slice-select').addEventListener('change', (e) => {
      activateSlice(Number(e.target.value));
    });

    // 5. Navigation History Buttons
    document.getElementById('btn-nav-back').addEventListener('click', () => navigateHistory(-1));
    document.getElementById('btn-nav-fwd').addEventListener('click', () => navigateHistory(1));

    // 6. Hex Dock Split Toggle (Right Split vs Bottom Split) & Learn Button
    document.getElementById('btn-open-learn')?.addEventListener('click', () => {
      selectTreeNode('rosetta_stone', { scrollHex: false });
    });

    document.getElementById('btn-toggle-dock').addEventListener('click', () => {
      const main = document.getElementById('workspace-main');
      const label = document.getElementById('dock-label');
      if (state.hexDock === 'right') {
        state.hexDock = 'bottom';
        main.classList.remove('dock-right');
        main.classList.add('dock-bottom');
        label.textContent = 'Bottom Hex';
      } else {
        state.hexDock = 'right';
        main.classList.remove('dock-bottom');
        main.classList.add('dock-right');
        label.textContent = 'Right Hex';
      }
      renderHexViewport();
      updateMemoryMapPlayhead();
    });

    // 7. Memory Map Scale Toggle & Hover Tooltips & Click-to-Jump
    document.getElementById('btn-memmap-scale').addEventListener('click', () => {
      state.memmapScale = state.memmapScale === 'sqrt' ? 'linear' : 'sqrt';
      document.getElementById('memmap-scale-label').textContent = state.memmapScale === 'sqrt' ? 'Sqrt' : 'Linear';
      renderMemoryMapRibbon();
    });

    const tracksContainer = document.getElementById('memmap-tracks-container');
    const tooltip = document.getElementById('global-tooltip');

    tracksContainer.addEventListener('mousemove', (e) => {
      const block = e.target.closest('.memmap-block');
      if (!block) {
        tooltip.classList.add('hidden');
        return;
      }
      tooltip.innerHTML = `
        <div class="tt-title">${escapeHtml(block.dataset.ttTitle)}</div>
        <div class="tt-row"><span>File Range:</span><strong>${escapeHtml(block.dataset.ttFile)}</strong></div>
        <div class="tt-row"><span>VM Range:</span><strong>${escapeHtml(block.dataset.ttVm)}</strong></div>
        <div class="tt-row"><span>Permissions:</span><strong>${escapeHtml(block.dataset.ttProt)}</strong></div>
      `;
      tooltip.classList.remove('hidden');
      const x = Math.min(window.innerWidth - 350, e.clientX + 12);
      const y = e.clientY + 16;
      tooltip.style.left = `${x}px`;
      tooltip.style.top = `${y}px`;
    });

    tracksContainer.addEventListener('mouseleave', () => {
      tooltip.classList.add('hidden');
    });

    tracksContainer.addEventListener('click', (e) => {
      const block = e.target.closest('.memmap-block');
      if (!block) return;
      const nodeId = block.dataset.nodeId;
      if (nodeId && state.treeNodesMap.has(nodeId)) {
        selectTreeNode(nodeId, { scrollHex: true });
      }
    });

    // 8. Real-Time Address / Offset Converter Inputs
    document.getElementById('conv-abs-input').addEventListener('input', (e) => {
      runTranslateQuery(e.target.value.trim(), 'abs_offset');
    });
    document.getElementById('conv-slice-input').addEventListener('input', (e) => {
      runTranslateQuery(e.target.value.trim(), 'slice_offset');
    });
    document.getElementById('conv-vm-input').addEventListener('input', (e) => {
      runTranslateQuery(e.target.value.trim(), 'vmaddr');
    });
    document.getElementById('btn-conv-jump-hex').addEventListener('click', () => {
      const raw = document.getElementById('conv-abs-input').value.trim();
      const off = parseInt(raw, raw.startsWith('0x') ? 16 : 10);
      if (!Number.isNaN(off)) {
        setCursorAndHighlight(off, { abs_offset: off, size: 8, label: 'Translated Offset' }, { scrollHex: true });
      }
    });
    document.getElementById('btn-conv-disasm').addEventListener('click', () => {
      const vm = document.getElementById('conv-vm-input').value.trim();
      if (vm && vm.startsWith('0x')) {
        state.activeDisasmVmaddr = vm;
        state.activeDisasmSection = '';
        selectTreeNode('disassembly', { scrollHex: false });
      }
    });

    // 9. Left Sidebar Tree Filter & Click Delegation
    const treeFilterIn = document.getElementById('tree-filter-input');
    const treeClearBtn = document.getElementById('btn-tree-clear');
    treeFilterIn.addEventListener('input', (e) => {
      state.treeFilter = e.target.value;
      treeClearBtn.classList.toggle('hidden', !state.treeFilter);
      renderStructureTree();
    });
    treeClearBtn.addEventListener('click', () => {
      state.treeFilter = '';
      treeFilterIn.value = '';
      treeClearBtn.classList.add('hidden');
      renderStructureTree();
    });

    document.getElementById('structure-tree').addEventListener('click', (e) => {
      const twisty = e.target.closest('[data-twisty-id]');
      if (twisty && !twisty.classList.contains('leaf')) {
        e.stopPropagation();
        const id = twisty.dataset.twistyId;
        if (state.expandedNodeIds.has(id)) {
          state.expandedNodeIds.delete(id);
        } else {
          state.expandedNodeIds.add(id);
        }
        renderStructureTree();
        return;
      }
      const row = e.target.closest('[data-node-id]');
      if (!row) return;
      const id = row.dataset.nodeId;
      const node = state.treeNodesMap.get(id);
      if (node && Array.isArray(node.children) && node.children.length > 0) {
        state.expandedNodeIds.add(id);
      }
      selectTreeNode(id, { scrollHex: true });
    });

    // 10. Center Inspector Delegated Clicks (Fields, Jump Chips, Slice Switches, Disassembly Links, Quiz Buttons)
    document.getElementById('center-inspector').addEventListener('click', (e) => {
      const quizBtn = e.target.closest('.quiz-option-btn');
      if (quizBtn) {
        e.stopPropagation();
        const isCorrect = quizBtn.dataset.quizCorrect === '1';
        const exp = quizBtn.dataset.quizExp || '';
        const parent = quizBtn.parentElement;
        parent.querySelectorAll('.quiz-option-btn').forEach(b => b.classList.remove('correct', 'wrong'));
        quizBtn.classList.add(isCorrect ? 'correct' : 'wrong');
        const fb = parent.querySelector('.quiz-feedback');
        if (fb) {
          fb.classList.remove('hidden');
          fb.style.background = isCorrect ? 'var(--ro-bg)' : 'var(--danger-bg)';
          fb.style.color = isCorrect ? 'var(--ro-fg)' : 'var(--danger-fg)';
          fb.textContent = (isCorrect ? '✓ Correct! ' : '✗ Try again: ') + exp;
        }
        return;
      }

      // Switch slice button
      const sliceBtn = e.target.closest('[data-switch-slice]');
      if (sliceBtn) {
        const idx = Number(sliceBtn.dataset.switchSlice);
        document.getElementById('slice-select').value = String(idx);
        activateSlice(idx);
        return;
      }

      // Select tree node chip
      const selNodeBtn = e.target.closest('[data-select-node]');
      if (selNodeBtn) {
        selectTreeNode(selNodeBtn.dataset.selectNode, { scrollHex: true });
        return;
      }

      // Disassemble at VM address or Section
      const disasmBtn = e.target.closest('[data-disasm-vm], [data-disasm-section]');
      if (disasmBtn) {
        e.stopPropagation();
        state.activeDisasmSection = disasmBtn.dataset.disasmSection || '';
        state.activeDisasmVmaddr = disasmBtn.dataset.disasmVm || '';
        selectTreeNode('disassembly', { scrollHex: false });
        return;
      }

      // Explicit Jump Offset chip
      const jumpChip = e.target.closest('[data-jump-offset]');
      if (jumpChip) {
        e.stopPropagation();
        const off = Number(jumpChip.dataset.jumpOffset);
        const sz = Number(jumpChip.dataset.jumpSize || 16);
        setCursorAndHighlight(off, { abs_offset: off, size: sz, label: 'Target Range' }, { scrollHex: true });
        return;
      }

      // Symbol Virtual Row Click
      const symRow = e.target.closest('[data-sym-idx]');
      if (symRow) {
        document.querySelectorAll('.virt-row.selected').forEach(el => el.classList.remove('selected'));
        symRow.classList.add('selected');
        const off = Number(symRow.dataset.absOffset);
        setCursorAndHighlight(off, { abs_offset: off, size: 16, label: symRow.querySelector('.vcol-name')?.textContent }, { scrollHex: true });
        return;
      }

      // Structure Field / Disasm Row / String Virtual Row Click
      const fieldRow = e.target.closest('[data-abs-offset]');
      if (fieldRow) {
        document.querySelectorAll('.struct-row.active-field-row, .disasm-row.selected, .virt-row.selected').forEach(el => {
          el.classList.remove('active-field-row', 'selected');
        });
        fieldRow.classList.add('active-field-row', 'selected');
        const off = Number(fieldRow.dataset.absOffset);
        const sz = Number(fieldRow.dataset.fieldSize || 4);
        const name = fieldRow.dataset.fieldName || 'Field';
        setCursorAndHighlight(off, { abs_offset: off, size: sz, label: name }, { scrollHex: true });
      }
    });

    // 11. Synchronized Hex Viewport Scroll & Clicks
    const hexViewport = document.getElementById('hex-viewport');
    hexViewport.addEventListener('scroll', renderHexViewport, { passive: true });

    hexViewport.addEventListener('click', (e) => {
      const byteEl = e.target.closest('[data-byte-offset]');
      if (!byteEl) return;
      const off = Number(byteEl.dataset.byteOffset);
      setCursorAndHighlight(off, null, { scrollHex: false });
    });

    document.getElementById('btn-hex-addr-mode').addEventListener('click', () => {
      state.hexAddrMode = state.hexAddrMode === 'file' ? 'vm' : 'file';
      document.getElementById('hex-addr-mode-label').textContent = state.hexAddrMode === 'file' ? 'File Offset' : 'VM Address';
      document.getElementById('hex-col-offset-title').textContent = state.hexAddrMode === 'file' ? 'OFFSET' : 'VMADDR';
      renderHexViewport();
    });

    document.getElementById('hex-goto-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const raw = document.getElementById('hex-goto-input').value.trim();
      if (!raw) return;
      const val = parseInt(raw, raw.startsWith('0x') ? 16 : 10);
      if (!Number.isNaN(val)) {
        setCursorAndHighlight(val, { abs_offset: val, size: 4, label: `Goto ${hex(val)}` }, { scrollHex: true });
      }
    });

    document.getElementById('btn-decoder-endian').addEventListener('click', () => {
      state.decoderEndian = state.decoderEndian === 'little' ? 'big' : 'little';
      document.getElementById('decoder-endian-label').textContent = state.decoderEndian === 'little' ? 'Little' : 'Big';
      fetchLiveByteDecode(state.cursorOffset);
    });

    document.getElementById('decoder-breadcrumbs').addEventListener('click', (e) => {
      const crumb = e.target.closest('[data-crumb-offset]');
      if (!crumb) return;
      const off = Number(crumb.dataset.crumbOffset);
      const sz = Number(crumb.dataset.crumbSize || 16);
      const id = crumb.dataset.crumbId;
      if (id && state.treeNodesMap.has(id)) {
        selectTreeNode(id, { scrollHex: false });
      }
      setCursorAndHighlight(off, { abs_offset: off, size: sz, label: crumb.textContent.trim() }, { scrollHex: true });
    });

    // 12. Cmd+K Omni-Search Modal
    document.getElementById('btn-open-cmdk').addEventListener('click', openCmdkModal);
    document.getElementById('cmdk-modal').addEventListener('click', (e) => {
      if (e.target.id === 'cmdk-modal') closeCmdkModal();
    });
    document.getElementById('cmdk-input').addEventListener('input', (e) => {
      runCmdkSearch(e.target.value);
    });
    document.getElementById('cmdk-scopes').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-scope]');
      if (!btn) return;
      state.cmdkScope = btn.dataset.scope;
      document.querySelectorAll('.cmdk-scope-btn').forEach(b => b.classList.toggle('active', b === btn));
      runCmdkSearch(document.getElementById('cmdk-input').value);
    });
    document.getElementById('cmdk-results').addEventListener('click', (e) => {
      const item = e.target.closest('[data-cmdk-idx]');
      if (!item) return;
      executeCmdkSelection(Number(item.dataset.cmdkIdx));
    });

    // 13. Global Keyboard Shortcuts
    window.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (state.cmdkOpen) closeCmdkModal();
        else openCmdkModal();
        return;
      }

      if (state.cmdkOpen) {
        if (e.key === 'Escape') {
          e.preventDefault();
          closeCmdkModal();
        } else if (e.key === 'ArrowDown') {
          e.preventDefault();
          state.cmdkActiveIdx = Math.min(state.cmdkResults.length - 1, state.cmdkActiveIdx + 1);
          renderCmdkResults();
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          state.cmdkActiveIdx = Math.max(0, state.cmdkActiveIdx - 1);
          renderCmdkResults();
        } else if (e.key === 'Enter') {
          e.preventDefault();
          executeCmdkSelection(state.cmdkActiveIdx);
        }
        return;
      }

      const activeTag = document.activeElement?.tagName;
      if (activeTag === 'INPUT' || activeTag === 'TEXTAREA' || activeTag === 'SELECT') {
        if (e.key === 'Escape') document.activeElement.blur();
        return;
      }

      if (e.key === '/') {
        e.preventDefault();
        openCmdkModal();
      } else if (e.key.toLowerCase() === 'g') {
        e.preventDefault();
        const vmIn = document.getElementById('conv-vm-input');
        vmIn.focus();
        vmIn.select();
      } else if (e.key.toLowerCase() === 'h') {
        e.preventDefault();
        document.getElementById('btn-hex-addr-mode').click();
      } else if (e.key === '[') {
        e.preventDefault();
        navigateHistory(-1);
      } else if (e.key === ']') {
        e.preventDefault();
        navigateHistory(1);
      }
    });

    // 14. Draggable Split Pane Resizers
    initPaneResizers();
    window.addEventListener('resize', () => {
      renderHexViewport();
      updateMemoryMapPlayhead();
    });
  }

  function initPaneResizers() {
    const resLeft = document.getElementById('resizer-left');
    const resHex = document.getElementById('resizer-hex');

    let activeResizer = null;

    resLeft.addEventListener('mousedown', () => {
      activeResizer = 'left';
      resLeft.classList.add('dragging');
    });
    resHex.addEventListener('mousedown', () => {
      activeResizer = 'hex';
      resHex.classList.add('dragging');
    });

    window.addEventListener('mousemove', (e) => {
      if (!activeResizer) return;
      if (activeResizer === 'left') {
        const w = Math.max(210, Math.min(480, e.clientX));
        document.documentElement.style.setProperty('--sidebar-width', `${w}px`);
      } else if (activeResizer === 'hex') {
        if (state.hexDock === 'right') {
          const w = Math.max(420, Math.min(780, window.innerWidth - e.clientX));
          document.documentElement.style.setProperty('--hex-pane-width', `${w}px`);
        } else {
          const h = Math.max(180, Math.min(550, window.innerHeight - e.clientY - 24));
          document.documentElement.style.setProperty('--hex-pane-height', `${h}px`);
        }
        renderHexViewport();
      }
      updateMemoryMapPlayhead();
    });

    window.addEventListener('mouseup', () => {
      if (activeResizer) {
        resLeft.classList.remove('dragging');
        resHex.classList.remove('dragging');
        activeResizer = null;
      }
    });
  }

  // =========================================================================
  // Application Bootstrap
  // =========================================================================
  async function bootstrap() {
    initEventListeners();
    await fetchPresets();

    // Check URL query param `?file=...` or default to first existing preset or `/bin/ls`
    const urlParams = new URLSearchParams(window.location.search);
    const requestedFile = urlParams.get('file');
    if (requestedFile) {
      await loadBinaryByPath(requestedFile);
      return;
    }

    const firstExistingPreset = state.presets.find(p => p.exists !== false);
    await loadBinaryByPath(firstExistingPreset ? firstExistingPreset.path : '/bin/ls');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }
})();
