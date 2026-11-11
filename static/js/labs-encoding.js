/**
 * BinaryStudio - Labs: "how bytes become meaning".
 *
 *   1. Instruction encoding explorer  (view `labs.encoding`, and inline under the selected
 *      disassembly row while Learn mode is on). All machine-code decoding happens in Python
 *      (POST /api/labs/encoding/decode); this file only renders the answer and edits bytes.
 *   2. Data representation playground (view `labs.numbers`): integers, IEEE-754, LEB128,
 *      alignment, flag sets, address arithmetic. Entirely client-side, document-independent.
 *
 * Part 1 of this file (`M`) is pure arithmetic with no DOM access. It uses BigInt wherever a value
 * can exceed 2^53, because a JavaScript number silently loses precision above that. `M` is also
 * exported as a CommonJS module so the unit tests can run it under node.
 */
(function (root) {
  'use strict';

  // =====================================================================================
  // Part 1: arithmetic (no DOM)
  // =====================================================================================
  const M = {};
  const B = BigInt;

  M.mask = (bits) => (1n << B(bits)) - 1n;
  M.wrap = (v, bits) => BigInt.asUintN(bits, v);
  M.toSigned = (v, bits) => BigInt.asIntN(bits, v);

  /**
   * Parse what a person types for an integer: decimal (optionally signed), 0x hex, 0b binary,
   * 0o octal, or a character literal 'A'. Underscores and spaces between digits are ignored.
   * -> {ok, value (BigInt, the mathematical value), error}
   */
  M.parseBig = function (text) {
    let s = String(text === undefined || text === null ? '' : text).trim();
    if (!s) return { ok: false, error: 'empty' };
    if (s.length > 400) return { ok: false, error: 'too long' };
    const ch = /^'(.)'$/u.exec(s);
    if (ch) return { ok: true, value: B(ch[1].codePointAt(0)) };
    let neg = false;
    if (s[0] === '+' || s[0] === '-') {
      neg = s[0] === '-';
      s = s.slice(1).trim();
    }
    s = s.replace(/[_\s]/g, '');
    let value;
    try {
      if (/^0x[0-9a-f]+$/i.test(s)) value = B(s);
      else if (/^0b[01]+$/i.test(s)) value = B(s);
      else if (/^0o[0-7]+$/i.test(s)) value = B(s);
      else if (/^[0-9]+$/.test(s)) value = B(s);
      else return { ok: false, error: 'not a number' };
    } catch (err) {
      return { ok: false, error: 'not a number' };
    }
    return { ok: true, value: neg ? -value : value };
  };

  /** Parse for an N-bit register: value wrapped modulo 2^N, plus whether it fitted. */
  M.parseInteger = function (text, bits) {
    const p = M.parseBig(text);
    if (!p.ok) return p;
    const max = M.mask(bits);
    const min = -(1n << B(bits - 1));
    return { ok: true, value: M.wrap(p.value, bits), fits: p.value >= min && p.value <= max, typed: p.value };
  };

  M.hex = (v, bits) => '0x' + M.wrap(v, bits).toString(16).padStart(Math.ceil(bits / 4), '0');
  M.bin = (v, bits) => M.wrap(v, bits).toString(2).padStart(bits, '0');
  M.binGrouped = (v, bits) => M.bin(v, bits).replace(/(.{8})(?=.)/g, '$1 ');
  M.oct = (v, bits) => '0o' + M.wrap(v, bits).toString(8);

  /** The bytes that hold an N-bit value in memory, in address order. */
  M.bytesOf = function (v, bits, little) {
    const out = [];
    const u = M.wrap(v, bits);
    for (let i = 0; i < bits / 8; i++) out.push(Number((u >> B(8 * i)) & 0xffn));
    return little ? out : out.reverse();
  };
  M.fromBytes = function (bytes, little) {
    let v = 0n;
    const list = little ? Array.from(bytes).reverse() : Array.from(bytes);
    for (const b of list) v = (v << 8n) | B(b & 0xff);
    return v;
  };
  M.byteSwap = (v, bits) => M.fromBytes(M.bytesOf(v, bits, true), false);

  M.rotl = function (v, bits, n) {
    const k = B(((n % bits) + bits) % bits);
    const u = M.wrap(v, bits);
    return M.wrap((u << k) | (u >> (B(bits) - k)), bits);
  };
  M.sar = (v, bits, n) => M.wrap(M.toSigned(v, bits) >> B(n), bits);

  const CONTROL_NAMES = ['NUL', 'SOH', 'STX', 'ETX', 'EOT', 'ENQ', 'ACK', 'BEL', 'BS', 'TAB', 'LF', 'VT', 'FF', 'CR', 'SO', 'SI',
    'DLE', 'DC1', 'DC2', 'DC3', 'DC4', 'NAK', 'SYN', 'ETB', 'CAN', 'EM', 'SUB', 'ESC', 'FS', 'GS', 'RS', 'US'];
  /** What the value is as a character code. -> {text, note} */
  M.charOf = function (v, bits) {
    const u = M.wrap(v, bits);
    if (u < 32n) return { text: CONTROL_NAMES[Number(u)], note: 'ASCII control character' };
    if (u === 127n) return { text: 'DEL', note: 'ASCII control character' };
    if (u < 127n) return { text: "'" + String.fromCharCode(Number(u)) + "'", note: 'ASCII' };
    if (bits === 8) return { text: '', note: 'not ASCII (above 0x7f); what it shows depends on the text encoding' };
    if (u > 0x10ffffn || (u >= 0xd800n && u <= 0xdfffn)) return { text: '', note: 'not a Unicode code point' };
    return { text: "'" + String.fromCodePoint(Number(u)) + "'", note: 'Unicode code point U+' + u.toString(16).toUpperCase().padStart(4, '0') };
  };

  // ---- IEEE-754 ---------------------------------------------------------------------
  M.FLOAT = { 32: { exp: 8, mant: 23, bias: 127 }, 64: { exp: 11, mant: 52, bias: 1023 } };

  /** Exact decimal expansion of a finite binary float (every float is a finite decimal). */
  M.floatExactDecimal = function (bitsValue, width) {
    const f = M.FLOAT[width];
    const u = M.wrap(bitsValue, width);
    const sign = u >> B(width - 1);
    const exp = Number((u >> B(f.mant)) & M.mask(f.exp));
    const mant = u & M.mask(f.mant);
    if (exp === Number(M.mask(f.exp))) return null;
    const m = exp === 0 ? mant : mant | (1n << B(f.mant));
    const e = (exp === 0 ? 1 : exp) - f.bias - f.mant;
    let text;
    if (e >= 0) {
      text = (m << B(e)).toString();
    } else {
      const k = -e;
      const ip = m >> B(k);
      const frac = m & M.mask(k);
      text = ip.toString();
      if (frac !== 0n) text += '.' + (frac * 5n ** B(k)).toString().padStart(k, '0').replace(/0+$/, '');
    }
    return (sign ? '-' : '') + text;
  };

  /** A finite float as an exact fraction num / den (magnitude only), or null for infinity and NaN. */
  M.floatRational = function (bitsValue, width) {
    const f = M.FLOAT[width];
    const u = M.wrap(bitsValue, width);
    const exp = Number((u >> B(f.mant)) & M.mask(f.exp));
    const mant = u & M.mask(f.mant);
    if (exp === Number(M.mask(f.exp))) return null;
    const m = exp === 0 ? mant : mant | (1n << B(f.mant));
    const e = (exp === 0 ? 1 : exp) - f.bias - f.mant;
    return e >= 0 ? { num: m << B(e), den: 1n } : { num: m, den: 1n << B(-e) };
  };

  /** Number value of a bit pattern (float32 values are exact as doubles). */
  M.floatValue = function (bitsValue, width) {
    const dv = new DataView(new ArrayBuffer(8));
    if (width === 32) {
      dv.setUint32(0, Number(M.wrap(bitsValue, 32)));
      return dv.getFloat32(0);
    }
    dv.setBigUint64(0, M.wrap(bitsValue, 64));
    return dv.getFloat64(0);
  };

  /** Parse a decimal string exactly: -> {ok, sign, num, den} with value = num / den, or {special}. */
  M.parseDecimalExact = function (text) {
    const s = String(text).trim().toLowerCase().replace(/_/g, '');
    if (!s || s.length > 400) return { ok: false };
    const sp = /^([+-]?)(inf|infinity|nan)$/.exec(s);
    if (sp) return { ok: true, special: sp[2] === 'nan' ? 'nan' : 'inf', sign: sp[1] === '-' ? 1 : 0 };
    const m = /^([+-]?)(\d*)(?:\.(\d*))?(?:e([+-]?\d{1,6}))?$/.exec(s);
    if (!m || (!m[2] && !m[3])) return { ok: false };
    const digits = (m[2] || '') + (m[3] || '');
    let exp10 = (m[4] ? parseInt(m[4], 10) : 0) - (m[3] ? m[3].length : 0);
    const num = B(digits || '0');
    const sign = m[1] === '-' ? 1 : 0;
    if (num === 0n) return { ok: true, sign, num: 0n, den: 1n };
    // Far outside the double range: decide without building enormous integers.
    const magnitude = digits.replace(/^0+/, '').length + exp10;
    if (magnitude > 400) return { ok: true, sign, huge: true };
    if (magnitude < -400) return { ok: true, sign, tiny: true };
    if (exp10 >= 0) return { ok: true, sign, num: num * 10n ** B(exp10), den: 1n };
    return { ok: true, sign, num, den: 10n ** B(-exp10) };
  };

  function bitLength(v) {
    return v === 0n ? 0 : v.toString(2).length;
  }

  /** Round the exact rational num/den to the nearest float (ties to even). -> bit pattern (BigInt). */
  M.roundToFloat = function (sign, num, den, width) {
    const f = M.FLOAT[width];
    const p = f.mant + 1;
    const signBit = B(sign) << B(width - 1);
    const expMax = Number(M.mask(f.exp));
    if (num === 0n) return signBit;
    let e = bitLength(num) - bitLength(den); // 2^e <= num/den < 2^(e+1), after the correction below
    const ge = e >= 0 ? num >= den << B(e) : num << B(-e) >= den;
    if (!ge) e -= 1;
    const emin = 1 - f.bias;
    const qexp = Math.max(e, emin) - (p - 1); // exponent of one unit in the last place
    let n = num;
    let d = den;
    if (qexp >= 0) d <<= B(qexp);
    else n <<= B(-qexp);
    let q = n / d;
    const r = n % d;
    const twice = r * 2n;
    if (twice > d || (twice === d && (q & 1n))) q += 1n;
    let exp = Math.max(e, emin);
    if (q >> B(p)) {
      q >>= 1n;
      exp += 1;
    }
    if (q >> B(p - 1) === 0n) return signBit | q; // subnormal (or zero): biased exponent 0
    const biased = exp + f.bias;
    if (biased >= expMax) return signBit | (B(expMax) << B(f.mant)); // overflow -> infinity
    return signBit | (B(biased) << B(f.mant)) | (q & M.mask(f.mant));
  };

  /** Decimal text -> the nearest float of the given width. -> {ok, bits, exact} */
  M.floatEncode = function (text, width) {
    const f = M.FLOAT[width];
    const d = M.parseDecimalExact(text);
    if (!d.ok) return { ok: false };
    const signBit = B(d.sign) << B(width - 1);
    const inf = M.mask(f.exp) << B(f.mant);
    if (d.special === 'inf' || d.huge) return { ok: true, bits: signBit | inf, exact: !d.huge };
    if (d.special === 'nan') return { ok: true, bits: signBit | inf | (1n << B(f.mant - 1)), exact: true };
    if (d.tiny) return { ok: true, bits: signBit, exact: false };
    const bits = M.roundToFloat(d.sign, d.num, d.den, width);
    // exact when the stored value equals the typed value
    const back = M.floatRational(bits, width);
    return { ok: true, bits, exact: back !== null && back.num * d.den === d.num * back.den };
  };

  /** Shortest decimal text that converts back to exactly this float. */
  M.floatShortest = function (bitsValue, width) {
    const x = M.floatValue(bitsValue, width);
    if (!Number.isFinite(x)) return Number.isNaN(x) ? 'NaN' : x > 0 ? 'Infinity' : '-Infinity';
    if (x === 0) return Object.is(x, -0) ? '-0' : '0';
    if (width === 64) return String(x);
    for (let precision = 1; precision <= 9; precision++) {
      const s = x.toPrecision(precision);
      const back = M.floatEncode(s, 32);
      if (back.ok && back.bits === M.wrap(bitsValue, 32)) return String(Number(s));
    }
    return String(x);
  };

  /** Split a bit pattern into IEEE-754 fields and classify it. */
  M.floatDecode = function (bitsValue, width) {
    const f = M.FLOAT[width];
    const u = M.wrap(bitsValue, width);
    const sign = Number(u >> B(width - 1));
    const exp = Number((u >> B(f.mant)) & M.mask(f.exp));
    const mant = u & M.mask(f.mant);
    const expMax = Number(M.mask(f.exp));
    let kind;
    if (exp === expMax) kind = mant === 0n ? 'infinity' : (mant >> B(f.mant - 1)) ? 'quiet NaN' : 'signalling NaN';
    else if (exp === 0) kind = mant === 0n ? 'zero' : 'subnormal';
    else kind = 'normal';
    const unbiased = kind === 'normal' ? exp - f.bias : kind === 'subnormal' || kind === 'zero' ? 1 - f.bias : null;
    return {
      width, sign, exp, mant, kind, unbiased, bias: f.bias, expBits: f.exp, mantBits: f.mant,
      value: M.floatValue(u, width), exact: M.floatExactDecimal(u, width), shortest: M.floatShortest(u, width),
    };
  };

  // ---- LEB128 -----------------------------------------------------------------------
  M.LEB_MAX_BYTES = 19; // enough for a 128-bit value; DWARF and Mach-O never need more than 10 for 64 bits

  M.ulebEncode = function (value) {
    if (value < 0n) return { ok: false, error: 'ULEB128 encodes unsigned values only; use SLEB128 for negative numbers.' };
    const bytes = [];
    const steps = [];
    let v = value;
    do {
      const group = Number(v & 0x7fn);
      v >>= 7n;
      const more = v !== 0n;
      const byte = group | (more ? 0x80 : 0);
      steps.push({ group, more, byte, rest: v });
      bytes.push(byte);
    } while (v !== 0n && bytes.length < 64);
    return { ok: true, bytes, steps };
  };

  M.slebEncode = function (value) {
    const bytes = [];
    const steps = [];
    let v = value;
    for (;;) {
      const group = Number(v & 0x7fn);
      v >>= 7n; // BigInt >> is an arithmetic shift: it keeps the sign
      const signBit = (group & 0x40) !== 0;
      const done = (v === 0n && !signBit) || (v === -1n && signBit);
      const byte = group | (done ? 0 : 0x80);
      steps.push({ group, more: !done, byte, rest: v, signBit });
      bytes.push(byte);
      if (done || bytes.length >= 64) break;
    }
    return { ok: true, bytes, steps };
  };

  function lebDecode(bytes, signed) {
    const steps = [];
    let value = 0n;
    let shift = 0n;
    let i = 0;
    for (;;) {
      if (i >= bytes.length) {
        return { ok: false, error: i === 0 ? 'No bytes.' : 'The last byte has its continuation bit (0x80) set, so the value is incomplete.', steps };
      }
      if (i >= M.LEB_MAX_BYTES) return { ok: false, error: 'More than ' + M.LEB_MAX_BYTES + ' bytes: not decoded.', steps };
      const byte = bytes[i] & 0xff;
      const group = byte & 0x7f;
      const more = (byte & 0x80) !== 0;
      value |= B(group) << shift;
      steps.push({ byte, group, more, shift: Number(shift), partial: value });
      shift += 7n;
      i += 1;
      if (!more) {
        let signExtended = false;
        if (signed && (byte & 0x40)) {
          value -= 1n << shift;
          signExtended = true;
        }
        const fits64 = signed ? value >= -(1n << 63n) && value <= (1n << 63n) - 1n : value <= M.mask(64);
        return { ok: true, value, length: i, steps, signExtended, bits: Number(shift), fits64, rest: bytes.length - i };
      }
    }
  }
  M.ulebDecode = (bytes) => lebDecode(bytes, false);
  M.slebDecode = (bytes) => lebDecode(bytes, true);

  /** Hex text -> array of byte values, or null. Accepts spaces, commas, 0x prefixes. */
  M.parseHexBytes = function (text, maxBytes) {
    const cleaned = String(text || '').replace(/\\x|0x/gi, ' ').replace(/[,;:_]/g, ' ').trim();
    if (!cleaned) return [];
    const out = [];
    for (const tok of cleaned.split(/\s+/)) {
      if (!/^[0-9a-f]+$/i.test(tok) || tok.length % 2) return null;
      for (let i = 0; i < tok.length; i += 2) out.push(parseInt(tok.slice(i, i + 2), 16));
      if (maxBytes && out.length > maxBytes) return null;
    }
    return out;
  };

  // ---- alignment ----------------------------------------------------------------------
  M.isPowerOfTwo = (a) => a > 0n && (a & (a - 1n)) === 0n;
  M.alignDown = (v, a) => (a <= 0n ? v : v - (v % a));
  M.alignUp = (v, a) => (a <= 0n ? v : v % a === 0n ? v : v + (a - (v % a)));
  M.padding = (v, a) => M.alignUp(v, a) - v;

  // ---- flag tables --------------------------------------------------------------------
  // Values and names as defined by <mach-o/loader.h>, the ELF gABI and the PE/COFF specification.
  // tests/test_labs_encoding.py checks them against the tables the parsers use.
  const F = (mask, name, desc) => ({ mask: B(mask), name, desc: desc || '' });
  M.FLAG_TABLES = [
    { id: 'macho.header.flags', format: 'Mach-O', label: 'mach_header.flags', bits: 32, flags: [
      F(0x1, 'MH_NOUNDEFS', 'No undefined references'), F(0x2, 'MH_INCRLINK', 'Output of an incremental link'),
      F(0x4, 'MH_DYLDLINK', 'Input for the dynamic linker'), F(0x8, 'MH_BINDATLOAD', 'Bind undefined references at load'),
      F(0x10, 'MH_PREBOUND', 'Undefined references are prebound'), F(0x20, 'MH_SPLIT_SEGS', 'Read-only and read-write segments split'),
      F(0x40, 'MH_LAZY_INIT', 'Shared library init routine runs lazily'), F(0x80, 'MH_TWOLEVEL', 'Two-level namespace bindings'),
      F(0x100, 'MH_FORCE_FLAT', 'Force flat namespace bindings'), F(0x200, 'MH_NOMULTIDEFS', 'No multiple definitions in sub-images'),
      F(0x400, 'MH_NOFIXPREBINDING', 'Do not notify the prebinding agent'), F(0x800, 'MH_PREBINDABLE', 'Not prebound but can be'),
      F(0x1000, 'MH_ALLMODSBOUND', 'Binds to all two-level namespace modules'),
      F(0x2000, 'MH_SUBSECTIONS_VIA_SYMBOLS', 'Sections can be divided at symbols for dead stripping'),
      F(0x4000, 'MH_CANONICAL', 'Canonicalised by unprebinding'), F(0x8000, 'MH_WEAK_DEFINES', 'Contains external weak symbols'),
      F(0x10000, 'MH_BINDS_TO_WEAK', 'Uses weak symbols'), F(0x20000, 'MH_ALLOW_STACK_EXECUTION', 'Stack may be executable'),
      F(0x40000, 'MH_ROOT_SAFE', 'Safe for uid 0 processes'), F(0x80000, 'MH_SETUID_SAFE', 'Safe for setuid processes'),
      F(0x100000, 'MH_NO_REEXPORTED_DYLIBS', 'No re-exported dylibs'), F(0x200000, 'MH_PIE', 'Position-independent executable (ASLR)'),
      F(0x400000, 'MH_DEAD_STRIPPABLE_DYLIB', 'Dylib can be dropped if unused'),
      F(0x800000, 'MH_HAS_TLV_DESCRIPTORS', 'Has thread-local variable descriptors'),
      F(0x1000000, 'MH_NO_HEAP_EXECUTION', 'Heap is not executable'), F(0x2000000, 'MH_APP_EXTENSION_SAFE', 'Safe for app extensions'),
      F(0x4000000, 'MH_NLIST_OUTOFSYNC_WITH_DYLDINFO', 'External symbols in nlist do not include all symbols in the dyld info'),
      F(0x8000000, 'MH_SIM_SUPPORT', 'Simulator support'),
      F(0x10000000, 'MH_IMPLICIT_PAGEZERO', 'Main executable has no __PAGEZERO segment; the loader keeps the low addresses unmapped'),
      F(0x80000000, 'MH_DYLIB_IN_CACHE', 'Dylib is part of the shared cache'),
    ] },
    { id: 'macho.vm_prot', format: 'Mach-O', label: 'segment initprot / maxprot (vm_prot_t)', bits: 32, flags: [
      F(0x1, 'VM_PROT_READ', 'Readable'), F(0x2, 'VM_PROT_WRITE', 'Writable'), F(0x4, 'VM_PROT_EXECUTE', 'Executable'),
    ] },
    { id: 'macho.segment.flags', format: 'Mach-O', label: 'segment_command.flags', bits: 32, flags: [
      F(0x1, 'SG_HIGHVM', 'File contents occupy the high part of the VM space'), F(0x2, 'SG_FVMLIB', 'Fixed VM library segment'),
      F(0x4, 'SG_NORELOC', 'Nothing relocated in or to this segment'), F(0x8, 'SG_PROTECTED_VERSION_1', 'Segment is encrypted'),
      F(0x10, 'SG_READ_ONLY', 'Made read-only after fixups'),
    ] },
    { id: 'macho.section.flags', format: 'Mach-O', label: 'section.flags (type + attributes)', bits: 32,
      fields: [{ mask: 0xffn, name: 'section type', values: {
        0: 'S_REGULAR', 1: 'S_ZEROFILL', 2: 'S_CSTRING_LITERALS', 3: 'S_4BYTE_LITERALS', 4: 'S_8BYTE_LITERALS',
        5: 'S_LITERAL_POINTERS', 6: 'S_NON_LAZY_SYMBOL_POINTERS', 7: 'S_LAZY_SYMBOL_POINTERS', 8: 'S_SYMBOL_STUBS',
        9: 'S_MOD_INIT_FUNC_POINTERS', 10: 'S_MOD_TERM_FUNC_POINTERS', 11: 'S_COALESCED', 12: 'S_GB_ZEROFILL',
        13: 'S_INTERPOSING', 14: 'S_16BYTE_LITERALS', 15: 'S_DTRACE_DOF', 16: 'S_LAZY_DYLIB_SYMBOL_POINTERS',
        17: 'S_THREAD_LOCAL_REGULAR', 18: 'S_THREAD_LOCAL_ZEROFILL', 19: 'S_THREAD_LOCAL_VARIABLES',
        20: 'S_THREAD_LOCAL_VARIABLE_POINTERS', 21: 'S_THREAD_LOCAL_INIT_FUNCTION_POINTERS', 22: 'S_INIT_FUNC_OFFSETS' } }],
      flags: [
        F(0x80000000, 'S_ATTR_PURE_INSTRUCTIONS', 'Only machine instructions'), F(0x40000000, 'S_ATTR_NO_TOC', 'Coalesced symbols not in a table of contents'),
        F(0x20000000, 'S_ATTR_STRIP_STATIC_SYMS', 'Static symbols may be stripped'), F(0x10000000, 'S_ATTR_NO_DEAD_STRIP', 'No dead stripping'),
        F(0x08000000, 'S_ATTR_LIVE_SUPPORT', 'Live if what it references is live'), F(0x04000000, 'S_ATTR_SELF_MODIFYING_CODE', 'Self-modifying code'),
        F(0x02000000, 'S_ATTR_DEBUG', 'Debug section'), F(0x400, 'S_ATTR_SOME_INSTRUCTIONS', 'Contains some instructions'),
        F(0x200, 'S_ATTR_EXT_RELOC', 'Has external relocations'), F(0x100, 'S_ATTR_LOC_RELOC', 'Has local relocations'),
      ] },
    { id: 'elf.p_flags', format: 'ELF', label: 'program header p_flags', bits: 32,
      fields: [{ mask: 0x0ff00000n, name: 'PF_MASKOS (OS-specific)', values: {} }, { mask: 0xf0000000n, name: 'PF_MASKPROC (processor-specific)', values: {} }],
      flags: [F(0x1, 'PF_X', 'Execute'), F(0x2, 'PF_W', 'Write'), F(0x4, 'PF_R', 'Read')] },
    { id: 'elf.sh_flags', format: 'ELF', label: 'section header sh_flags', bits: 64, flags: [
      F(0x1, 'SHF_WRITE', 'Writable at run time'), F(0x2, 'SHF_ALLOC', 'Occupies memory at run time'),
      F(0x4, 'SHF_EXECINSTR', 'Executable machine instructions'), F(0x10, 'SHF_MERGE', 'May be merged'),
      F(0x20, 'SHF_STRINGS', 'NUL-terminated strings'), F(0x40, 'SHF_INFO_LINK', 'sh_info holds a section index'),
      F(0x80, 'SHF_LINK_ORDER', 'Ordering requirement'), F(0x100, 'SHF_OS_NONCONFORMING', 'OS-specific processing required'),
      F(0x200, 'SHF_GROUP', 'Member of a section group'), F(0x400, 'SHF_TLS', 'Thread-local storage'),
      F(0x800, 'SHF_COMPRESSED', 'Compressed data'), F(0x80000000, 'SHF_EXCLUDE', 'Excluded from the output (processor-specific range)'),
    ] },
    { id: 'pe.characteristics', format: 'PE', label: 'IMAGE_FILE_HEADER.Characteristics', bits: 16, flags: [
      F(0x0001, 'IMAGE_FILE_RELOCS_STRIPPED', 'No base relocations: must load at ImageBase'),
      F(0x0002, 'IMAGE_FILE_EXECUTABLE_IMAGE', 'Valid executable image'), F(0x0004, 'IMAGE_FILE_LINE_NUMS_STRIPPED', 'COFF line numbers removed (deprecated)'),
      F(0x0008, 'IMAGE_FILE_LOCAL_SYMS_STRIPPED', 'COFF local symbols removed (deprecated)'),
      F(0x0010, 'IMAGE_FILE_AGGRESIVE_WS_TRIM', 'Aggressively trim working set (obsolete)'),
      F(0x0020, 'IMAGE_FILE_LARGE_ADDRESS_AWARE', 'Can handle addresses above 2 GB'),
      F(0x0080, 'IMAGE_FILE_BYTES_REVERSED_LO', 'Little endian (deprecated)'), F(0x0100, 'IMAGE_FILE_32BIT_MACHINE', '32-bit word machine'),
      F(0x0200, 'IMAGE_FILE_DEBUG_STRIPPED', 'Debug information removed'),
      F(0x0400, 'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP', 'Copy to swap if on removable media'),
      F(0x0800, 'IMAGE_FILE_NET_RUN_FROM_SWAP', 'Copy to swap if on network media'), F(0x1000, 'IMAGE_FILE_SYSTEM', 'System file'),
      F(0x2000, 'IMAGE_FILE_DLL', 'Dynamic-link library'), F(0x4000, 'IMAGE_FILE_UP_SYSTEM_ONLY', 'Uniprocessor only'),
      F(0x8000, 'IMAGE_FILE_BYTES_REVERSED_HI', 'Big endian (deprecated)'),
    ] },
    { id: 'pe.dll_characteristics', format: 'PE', label: 'IMAGE_OPTIONAL_HEADER.DllCharacteristics', bits: 16, flags: [
      F(0x0020, 'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA', '64-bit high-entropy ASLR'),
      F(0x0040, 'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE', 'Can be relocated at load time (ASLR)'),
      F(0x0080, 'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY', 'Code integrity checks enforced'),
      F(0x0100, 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT', 'Compatible with DEP / NX'),
      F(0x0200, 'IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', 'Do not isolate the image'),
      F(0x0400, 'IMAGE_DLLCHARACTERISTICS_NO_SEH', 'No structured exception handling'),
      F(0x0800, 'IMAGE_DLLCHARACTERISTICS_NO_BIND', 'Do not bind the image'),
      F(0x1000, 'IMAGE_DLLCHARACTERISTICS_APPCONTAINER', 'Must run in an AppContainer'),
      F(0x2000, 'IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', 'WDM driver'),
      F(0x4000, 'IMAGE_DLLCHARACTERISTICS_GUARD_CF', 'Control Flow Guard'),
      F(0x8000, 'IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', 'Terminal Server aware'),
    ] },
    { id: 'pe.section.characteristics', format: 'PE', label: 'IMAGE_SECTION_HEADER.Characteristics', bits: 32,
      fields: [{ mask: 0x00f00000n, name: 'IMAGE_SCN_ALIGN (object files only)', values: {
        0: 'default', 1: 'IMAGE_SCN_ALIGN_1BYTES', 2: 'IMAGE_SCN_ALIGN_2BYTES', 3: 'IMAGE_SCN_ALIGN_4BYTES', 4: 'IMAGE_SCN_ALIGN_8BYTES',
        5: 'IMAGE_SCN_ALIGN_16BYTES', 6: 'IMAGE_SCN_ALIGN_32BYTES', 7: 'IMAGE_SCN_ALIGN_64BYTES', 8: 'IMAGE_SCN_ALIGN_128BYTES',
        9: 'IMAGE_SCN_ALIGN_256BYTES', 10: 'IMAGE_SCN_ALIGN_512BYTES', 11: 'IMAGE_SCN_ALIGN_1024BYTES',
        12: 'IMAGE_SCN_ALIGN_2048BYTES', 13: 'IMAGE_SCN_ALIGN_4096BYTES', 14: 'IMAGE_SCN_ALIGN_8192BYTES' } }],
      flags: [
        F(0x00000008, 'IMAGE_SCN_TYPE_NO_PAD', 'Not padded to the next boundary (obsolete)'), F(0x00000020, 'IMAGE_SCN_CNT_CODE', 'Executable code'),
        F(0x00000040, 'IMAGE_SCN_CNT_INITIALIZED_DATA', 'Initialised data'), F(0x00000080, 'IMAGE_SCN_CNT_UNINITIALIZED_DATA', 'Uninitialised data'),
        F(0x00000100, 'IMAGE_SCN_LNK_OTHER', 'Reserved'), F(0x00000200, 'IMAGE_SCN_LNK_INFO', 'Comments or other information (object files)'),
        F(0x00000800, 'IMAGE_SCN_LNK_REMOVE', 'Will not be part of the image (object files)'),
        F(0x00001000, 'IMAGE_SCN_LNK_COMDAT', 'COMDAT data (object files)'), F(0x00008000, 'IMAGE_SCN_GPREL', 'Referenced through the global pointer'),
        F(0x01000000, 'IMAGE_SCN_LNK_NRELOC_OVFL', 'Extended relocations'), F(0x02000000, 'IMAGE_SCN_MEM_DISCARDABLE', 'Can be discarded'),
        F(0x04000000, 'IMAGE_SCN_MEM_NOT_CACHED', 'Cannot be cached'), F(0x08000000, 'IMAGE_SCN_MEM_NOT_PAGED', 'Not pageable'),
        F(0x10000000, 'IMAGE_SCN_MEM_SHARED', 'Shared in memory'), F(0x20000000, 'IMAGE_SCN_MEM_EXECUTE', 'Executable'),
        F(0x40000000, 'IMAGE_SCN_MEM_READ', 'Readable'), F(0x80000000, 'IMAGE_SCN_MEM_WRITE', 'Writable'),
      ] },
  ];

  function lowestBit(mask) {
    let n = 0;
    while (((mask >> B(n)) & 1n) === 0n) n++;
    return n;
  }

  /** Decode a value against one table. -> {table, set, clear, fields, unknown} */
  M.decodeFlags = function (tableId, value) {
    const table = M.FLAG_TABLES.find((t) => t.id === tableId);
    if (!table) return null;
    const v = M.wrap(value, table.bits);
    let known = 0n;
    const set = [];
    const clear = [];
    for (const f of table.flags) {
      known |= f.mask;
      ((v & f.mask) === f.mask ? set : clear).push(f);
    }
    const fields = [];
    for (const fld of table.fields || []) {
      known |= fld.mask;
      const raw = (v & fld.mask) >> B(lowestBit(fld.mask));
      const name = fld.values[Number(raw)];
      fields.push({ name: fld.name, mask: fld.mask, raw, text: name !== undefined ? name : raw === 0n ? 'none' : 'value ' + raw.toString() + ' (no name)' });
    }
    return { table, value: v, set, clear, fields, unknown: v & ~known & M.mask(table.bits) };
  };

  // ---- address arithmetic ---------------------------------------------------------------
  /**
   * The same rules as the address translator of the tool (backend/service.py translate_address):
   *   VA -> offset: the first segment with vmaddr <= VA < vmaddr + vmsize; if VA - vmaddr is below
   *                 filesize the byte is in the file at fileoff + (VA - vmaddr), otherwise the page
   *                 is zero-filled and has no bytes in the file. __PAGEZERO never maps.
   *   offset -> VA: the first segment with filesize > 0 and fileoff <= offset < fileoff + filesize.
   * layout: {imageBase, segments: [{name, vmaddr, vmsize, fileoff, filesize}]} (all BigInt)
   * mode: 'va' | 'rva' | 'offset'
   */
  M.translate = function (layout, mode, value) {
    const steps = [];
    const hx = (v) => (v < 0n ? '-0x' + (-v).toString(16) : '0x' + v.toString(16));
    const out = { status: 'UNMAPPED', mapped: false, segment: -1, va: null, rva: null, offset: null, steps };
    const base = layout.imageBase;
    if (mode === 'va' || mode === 'rva') {
      let va = value;
      if (mode === 'rva') {
        va = base + value;
        steps.push('VA = image base + RVA = ' + hx(base) + ' + ' + hx(value) + ' = ' + hx(va));
      }
      out.va = va;
      out.rva = va - base;
      if (mode === 'va') steps.push('RVA = VA - image base = ' + hx(va) + ' - ' + hx(base) + ' = ' + hx(out.rva));
      for (let i = 0; i < layout.segments.length; i++) {
        const s = layout.segments[i];
        if (s.name === '__PAGEZERO') continue;
        if (s.vmaddr <= va && va < s.vmaddr + s.vmsize) {
          out.segment = i;
          out.mapped = true;
          const rel = va - s.vmaddr;
          steps.push(hx(s.vmaddr) + ' <= ' + hx(va) + ' < ' + hx(s.vmaddr + s.vmsize) + ': inside ' + (s.name || 'segment ' + i));
          steps.push('offset inside it = VA - start = ' + hx(va) + ' - ' + hx(s.vmaddr) + ' = ' + hx(rel));
          if (rel < s.filesize) {
            out.offset = s.fileoff + rel;
            out.status = 'MAPPED';
            steps.push(hx(rel) + ' < file size ' + hx(s.filesize) + ': the byte is in the file');
            steps.push('file offset = file start + offset inside = ' + hx(s.fileoff) + ' + ' + hx(rel) + ' = ' + hx(out.offset));
          } else {
            out.status = 'UNMAPPED_ZEROFILL';
            steps.push(hx(rel) + ' >= file size ' + hx(s.filesize) + ': past the bytes stored in the file. The loader zero-fills this part; there is no file offset.');
          }
          return out;
        }
      }
      steps.push('No segment contains ' + hx(va) + '.');
      return out;
    }
    out.offset = value;
    for (let i = 0; i < layout.segments.length; i++) {
      const s = layout.segments[i];
      if (s.filesize > 0n && s.fileoff <= value && value < s.fileoff + s.filesize) {
        out.segment = i;
        out.mapped = true;
        out.status = 'MAPPED';
        const rel = value - s.fileoff;
        out.va = s.vmaddr + rel;
        out.rva = out.va - base;
        steps.push(hx(s.fileoff) + ' <= ' + hx(value) + ' < ' + hx(s.fileoff + s.filesize) + ': inside the file bytes of ' + (s.name || 'segment ' + i));
        steps.push('offset inside it = ' + hx(value) + ' - ' + hx(s.fileoff) + ' = ' + hx(rel));
        steps.push('VA = start + offset inside = ' + hx(s.vmaddr) + ' + ' + hx(rel) + ' = ' + hx(out.va));
        steps.push('RVA = VA - image base = ' + hx(out.va) + ' - ' + hx(base) + ' = ' + hx(out.rva));
        return out;
      }
    }
    steps.push('No segment has file bytes at offset ' + hx(value) + ' (headers, padding between sections, or data that is not loaded such as symbol tables and signatures).');
    return out;
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = M;
  if (!root || !root.BinaryStudio) return;

  // =====================================================================================
  // Part 2: user interface
  // =====================================================================================
  const BS = root.BinaryStudio;
  const html = BS.util.html;
  const doc = root.document;
  BS.labs = BS.labs || {};
  BS.labs.encodingMath = M;

  const LIMITS = { maxBytes: 256, maxInstructions: 64 };
  const ARCHS = [
    { id: 'arm64', label: 'AArch64 (A64)' },
    { id: 'x86_64', label: 'x86-64 (64-bit mode)' },
    { id: 'x86', label: 'x86 (32-bit mode)' },
  ];
  const SAMPLES = {
    arm64: { hex: 'fd 7b bf a9 fd 03 00 91 00 00 00 90 00 00 40 f9 05 00 00 94 fd 7b c1 a8 c0 03 5f d6', pc: '0x100003f50' },
    x86_64: { hex: '55 48 89 e5 48 8d 3d 36 0f 00 00 8b 44 8f 10 e8 0c 00 00 00 5d c3', pc: '0x100003f50' },
    x86: { hex: '55 89 e5 8b 45 08 8d 04 85 10 00 00 00 e8 0c 00 00 00 5d c3', pc: '0x8048400' },
  };

  function archOfSlice(slice) {
    const name = String((slice && slice.arch_name) || '').toLowerCase();
    if (name.startsWith('arm64') || name === 'aarch64') return 'arm64';
    if (name === 'x86_64' || name === 'amd64' || name === 'x64') return 'x86_64';
    if (name === 'i386' || name === 'x86' || name === 'i686') return 'x86';
    return null;
  }

  const hexOfBytes = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(' ');
  const parseAddr = (text) => {
    const p = M.parseBig(text);
    return p.ok && p.value >= 0n && p.value <= M.mask(64) ? p.value : null;
  };

  /** Keep keyboard focus on "the same" control across a re-render. */
  function keepFocus(host, renderFn) {
    const active = doc.activeElement;
    const key = active && host.contains(active) ? active.getAttribute('data-fk') : null;
    renderFn();
    if (key) {
      const again = host.querySelector('[data-fk="' + key.replace(/[^A-Za-z0-9_.:-]/g, '') + '"]');
      if (again) again.focus({ preventScroll: true });
    }
  }
  function hydrateSpans(host) {
    host.querySelectorAll('[data-span]').forEach((el) => {
      el.style.gridColumn = 'span ' + Math.max(1, Math.min(64, Number(el.dataset.span) || 1));
    });
  }

  // -------------------------------------------------------------------------------------
  // Explorer component: decodes a byte buffer and renders the selected instruction's fields.
  // -------------------------------------------------------------------------------------
  /**
   * The one boundary for /api/labs/encoding/decode: every number the explorer renders or loops
   * over is checked here (integers, bit ranges, array lengths), and only the keys the view uses
   * are kept. Returns a normalised copy, or null for a response of an unexpected shape.
   */
  function checkDecodeResponse(res, nBytes, arch) {
    const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
    const text = (v, max) => (v === null || v === undefined ? '' : typeof v === 'string' ? v.slice(0, max || 2000) : undefined);
    const strList = (v) => {
      if (v === undefined || v === null) return [];
      if (!Array.isArray(v) || v.length > 64) return null;
      const out = v.map((x) => text(x));
      return out.includes(undefined) ? null : out;
    };
    if (!res || typeof res !== 'object' || !Array.isArray(res.instructions)) return null;
    if (res.instructions.length > Math.min(LIMITS.maxInstructions, Math.max(1, nBytes))) return null;
    const a64 = arch === 'arm64';
    const insns = [];
    for (const raw of res.instructions) {
      if (!raw || typeof raw !== 'object') return null;
      if (!isInt(raw.offset, 0, Math.max(0, nBytes - 1)) || !isInt(raw.size, 0, a64 ? 4 : 15)) return null;
      const insn = {
        offset: raw.offset, size: raw.size,
        status: text(raw.status, 40), text: text(raw.text, 400), pc: text(raw.pc, 40), hex: text(raw.hex, 120),
        encoding_class: text(raw.encoding_class, 200), target: text(raw.target, 40),
        gaps: strList(raw.gaps), steps: strList(raw.steps), notes: strList(raw.notes), fields: [],
      };
      if (Object.values(insn).some((v) => v === undefined || v === null)) return null;
      const fields = raw.fields === undefined || raw.fields === null ? [] : raw.fields;
      if (!Array.isArray(fields) || fields.length > 64) return null;
      for (const f of fields) {
        if (!f || typeof f !== 'object') return null;
        const out = { name: text(f.name, 80), kind: text(f.kind, 20), bits: text(f.bits, 130), value_hex: text(f.value_hex, 40), meaning: text(f.meaning) };
        if (Object.values(out).includes(undefined)) return null;
        if (a64) {
          if (!isInt(f.lo, 0, 31) || !isInt(f.hi, f.lo, 31)) return null;
          out.width = f.hi - f.lo + 1;
        } else {
          if (!isInt(f.nbytes, 1, 15) || !isInt(f.byte, 0, 15 - f.nbytes)) return null;
          if (f.nbytes === 1 ? !isInt(f.lo, 0, 7) || !isInt(f.hi, f.lo, 7) : (f.hi !== undefined && !isInt(f.hi, 0, 127)) || (f.lo !== undefined && !isInt(f.lo, 0, 127))) return null;
          out.nbytes = f.nbytes;
          out.byte = f.byte;
          out.width = f.nbytes > 1 ? f.nbytes * 8 : f.hi - f.lo + 1;
        }
        out.hi = Number.isInteger(f.hi) ? f.hi : 7;
        out.lo = Number.isInteger(f.lo) ? f.lo : 0;
        insn.fields.push(out);
      }
      insns.push(insn);
    }
    return { instructions: insns, stop_reason: text(res.stop_reason, 400) || '' };
  }

  function createExplorer(host, opts) {
    const options = opts || {};
    const st = {
      arch: 'arm64', bytes: new Uint8Array(0), orig: new Uint8Array(0), pc: 0n, result: null, origTexts: null,
      sel: 0, active: -1, error: '', seq: 0, abort: null, destroyed: false,
    };

    async function decode(keepOriginal) {
      const seq = ++st.seq;
      if (st.abort) st.abort.abort();
      st.abort = typeof AbortController === 'function' ? new AbortController() : null;
      if (!st.bytes.length) {
        st.result = null;
        st.error = '';
        render();
        return;
      }
      try {
        const body = {
          arch: st.arch, hex: hexOfBytes(st.bytes), pc: '0x' + st.pc.toString(16),
          max_instructions: options.single ? 1 : LIMITS.maxInstructions,
        };
        const res = await BS.api.post('/api/labs/encoding/decode', body, { doc: null, slice_index: null },
          st.abort ? { signal: st.abort.signal } : undefined);
        if (seq !== st.seq || st.destroyed) return;
        const checked = checkDecodeResponse(res, st.bytes.length, st.arch);
        if (!checked) throw new Error('The server sent an unexpected response to the decode request.');
        st.result = checked;
        st.error = '';
        if (!keepOriginal) st.origTexts = (res.instructions || []).map((i) => ({ offset: i.offset, text: i.text }));
        if (st.sel >= (res.instructions || []).length) st.sel = 0;
      } catch (err) {
        if (err && err.name === 'AbortError') return;
        if (seq !== st.seq || st.destroyed) return;
        st.result = null;
        st.error = String((err && err.message) || 'The request failed.');
      }
      render();
      if (options.onDecoded) options.onDecoded(st);
    }

    function load(arch, bytes, pc) {
      st.arch = arch;
      st.bytes = Uint8Array.from(bytes).slice(0, LIMITS.maxBytes);
      st.orig = st.bytes.slice();
      st.pc = pc;
      st.sel = 0;
      st.active = -1;
      return decode(false);
    }

    function fieldBits(insn, f) {
      // -> list of absolute bit positions {byte, bit} that the field covers
      const out = [];
      if (st.arch === 'arm64') {
        for (let b = f.hi; b >= f.lo; b--) out.push({ byte: insn.offset + (b >> 3), bit: b & 7 });
      } else if (f.nbytes === 1) {
        for (let b = f.hi; b >= f.lo; b--) out.push({ byte: insn.offset + f.byte, bit: b });
      } else {
        for (let i = 0; i < f.nbytes; i++) for (let b = 7; b >= 0; b--) out.push({ byte: insn.offset + f.byte + i, bit: b });
      }
      return out;
    }

    function fieldWidth(f) {
      return st.arch !== 'arm64' && f.nbytes > 1 ? f.nbytes * 8 : f.hi - f.lo + 1;
    }

    function writeField(insn, f, value) {
      const width = fieldWidth(f);
      const v = M.wrap(value, width);
      if (st.arch === 'arm64') {
        let word = M.fromBytes(st.bytes.slice(insn.offset, insn.offset + 4), true);
        word = (word & ~(M.mask(width) << B(f.lo))) | (v << B(f.lo));
        M.bytesOf(word, 32, true).forEach((b, i) => { st.bytes[insn.offset + i] = b; });
      } else if (f.nbytes === 1) {
        const at = insn.offset + f.byte;
        st.bytes[at] = Number((B(st.bytes[at]) & ~(M.mask(width) << B(f.lo)) & 0xffn) | (v << B(f.lo)));
      } else {
        M.bytesOf(v, width, true).forEach((b, i) => { st.bytes[insn.offset + f.byte + i] = b; });
      }
      decode(true);
    }

    function toggleBit(byteIndex, bit) {
      if (byteIndex < 0 || byteIndex >= st.bytes.length) return;
      st.bytes[byteIndex] ^= 1 << bit;
      decode(true);
    }

    function reset() {
      st.bytes = st.orig.slice();
      decode(true);
    }

    const changedBit = (byteIndex, bit) => ((st.bytes[byteIndex] ^ st.orig[byteIndex]) >> bit) & 1;
    // a one- or two-bit field has room for a letter or two: REX.W -> W
    const shortLabel = (name, width) => (width <= 2 ? String(name).replace(/^REX\./, '') : name);
    const kindClass = (kind) => 'lenc-k-' + (['opc', 'reg', 'imm', 'disp', 'cond', 'mod', 'unknown', 'fixed'].includes(kind) ? kind : 'fixed');

    function a64FieldsValid(insn) {
      // the strip is drawn from the field list: accept it only if it tiles bits 31..0 exactly
      let next = 31;
      for (const f of insn.fields || []) {
        if (!Number.isInteger(f.hi) || !Number.isInteger(f.lo) || f.hi !== next || f.lo > f.hi || f.lo < 0) return false;
        next = f.lo - 1;
      }
      return next === -1;
    }

    function renderA64Strip(insn) {
      const fields = insn.fields || [];
      const labels = fields.map((f, i) => html`<button type="button" class="lenc-flabel ${kindClass(f.kind)} ${st.active === i ? 'lenc-active' : ''}" data-span="${f.width}" data-field="${i}" data-fk="fl${i}" title="${f.name} [${f.hi}:${f.lo}]">${shortLabel(f.name, f.width)}</button>`);
      const bits = [];
      const idx = [];
      fields.forEach((f, i) => {
        for (let b = f.hi; b >= f.lo; b--) {
          const byteIndex = insn.offset + (b >> 3);
          const on = (st.bytes[byteIndex] >> (b & 7)) & 1;
          bits.push(html`<button type="button" class="lenc-bit ${kindClass(f.kind)} ${b === f.lo ? 'lenc-last' : ''} ${st.active === i ? 'lenc-active' : ''} ${changedBit(byteIndex, b & 7) ? 'lenc-changed' : ''}" data-byte="${byteIndex}" data-bit="${b & 7}" data-fk="b${byteIndex}.${b & 7}" aria-pressed="${on ? 'true' : 'false'}" aria-label="bit ${b} of the instruction word, field ${f.name}, value ${on}" title="bit ${b} (${f.name}): toggle">${on}</button>`);
          idx.push(html`<div class="lenc-bitidx">${b}</div>`);
        }
      });
      const mem = [3, 2, 1, 0].map((k) => html`<div class="lenc-membyte" data-span="8" title="Byte at offset +${k} of the instruction holds word bits ${k * 8 + 7}:${k * 8}">byte +${k} = ${st.bytes[insn.offset + k].toString(16).padStart(2, '0')}</div>`);
      return html`<div class="lenc-strip-wrap"><div class="lenc-a64" role="group" aria-label="Bits of the instruction word, most significant first">${labels}${bits}${idx}${mem}</div></div>
        <div class="lenc-note">The word is shown with bit 31 on the left. In memory the four bytes are stored least significant first (little-endian), so the byte at the lowest address (+0) is the right-hand group.</div>`;
    }

    function renderX86Strip(insn) {
      const fields = insn.fields || [];
      const blocks = [];
      const size = Math.max(0, Math.min(Number(insn.size) || 0, 15, st.bytes.length - insn.offset));
      for (let i = 0; i < size; i++) {
        const byteIndex = insn.offset + i;
        const here = [];
        fields.forEach((f, fi) => {
          if (f.nbytes === 1 && f.byte === i) here.push({ f, fi, hi: f.hi, lo: f.lo, label: f.name });
          else if (f.nbytes > 1 && i >= f.byte && i < f.byte + f.nbytes) here.push({ f, fi, hi: 7, lo: 0, label: f.name + ' [' + (i - f.byte) + ']' });
        });
        here.sort((a, b) => b.hi - a.hi);
        const labels = [];
        const bits = [];
        let next = 7;
        const pushBits = (hi, lo, f, fi) => {
          for (let b = hi; b >= lo; b--) {
            const on = (st.bytes[byteIndex] >> b) & 1;
            const kind = f ? f.kind : 'unknown';
            bits.push(html`<button type="button" class="lenc-bit ${kindClass(kind)} ${b === lo ? 'lenc-last' : ''} ${f && st.active === fi ? 'lenc-active' : ''} ${changedBit(byteIndex, b) ? 'lenc-changed' : ''}" data-byte="${byteIndex}" data-bit="${b}" data-fk="b${byteIndex}.${b}" aria-pressed="${on ? 'true' : 'false'}" aria-label="byte ${i} bit ${b}${f ? ', field ' + f.name : ''}, value ${on}" title="byte +${i}, bit ${b}${f ? ' (' + f.name + ')' : ''}: toggle">${on}</button>`);
          }
        };
        here.forEach((h) => {
          if (h.hi < next) {
            labels.push(html`<span class="lenc-flabel lenc-k-unknown" data-span="${next - h.hi}">?</span>`);
            pushBits(next, h.hi + 1, null, -1);
          }
          labels.push(html`<button type="button" class="lenc-flabel ${kindClass(h.f.kind)} ${st.active === h.fi ? 'lenc-active' : ''}" data-span="${h.hi - h.lo + 1}" data-field="${h.fi}" data-fk="fl${h.fi}.${i}" title="${h.f.name}">${shortLabel(h.label, h.hi - h.lo + 1)}</button>`);
          pushBits(h.hi, h.lo, h.f, h.fi);
          next = h.lo - 1;
        });
        if (next >= 0) {
          labels.push(html`<span class="lenc-flabel lenc-k-unknown" data-span="${next + 1}" title="Not decoded">not decoded</span>`);
          pushBits(next, 0, null, -1);
        }
        blocks.push(html`<div class="lenc-byte"><div class="lenc-bytehex">${st.bytes[byteIndex].toString(16).padStart(2, '0')}</div>${labels}${bits}<div class="lenc-byteidx">+${i}</div></div>`);
      }
      return html`<div class="lenc-strip-wrap"><div class="lenc-x86" role="group" aria-label="Bytes of the instruction in memory order, each with bit 7 on the left">${blocks}</div></div>
        <div class="lenc-note">Bytes are shown in memory order (lowest address first), each with bit 7 on the left. Multi-byte displacements and immediates are little-endian: their first byte is the least significant.</div>`;
    }

    function renderFields(insn) {
      const rows = (insn.fields || []).map((f, i) => {
        const width = fieldWidth(f);
        const editable = !['fixed', 'unknown'].includes(f.kind);
        const where = st.arch === 'arm64' ? (f.hi === f.lo ? String(f.hi) : f.hi + ':' + f.lo)
          : f.nbytes > 1 ? 'bytes +' + f.byte + '..+' + (f.byte + f.nbytes - 1)
          : 'byte +' + f.byte + (f.hi === 7 && f.lo === 0 ? '' : ' [' + (f.hi === f.lo ? f.hi : f.hi + ':' + f.lo) + ']');
        let shown = String(f.value_hex);
        if (width <= 6) {
          try {
            shown = String(BigInt(f.value_hex));
          } catch (err) {
            /* not a number: show what the server sent, as text */
          }
        }
        return html`<tr class="${st.active === i ? 'lenc-active' : ''}" data-field="${i}">
          <td><span class="lenc-fname ${kindClass(f.kind)}">${f.name}</span></td>
          <td class="lenc-fbits">${where}</td>
          <td class="lenc-fbits">${f.bits}</td>
          <td>${editable ? html`<input class="lenc-input lenc-fval" type="text" data-edit="${i}" data-fk="fv${i}" value="${shown}" aria-label="Value of field ${f.name} (${width} bits)" spellcheck="false" autocomplete="off" />` : html`<span class="lenc-fbits">${shown}</span>`}</td>
          <td class="lenc-fmeaning">${f.meaning}</td>
        </tr>`;
      });
      return html`<table class="lenc-fields"><thead><tr><th>Field</th><th>Position</th><th>Bits</th><th>Value</th><th>Meaning</th></tr></thead><tbody>${rows}</tbody></table>`;
    }

    function renderInsn(insn) {
      const was = st.origTexts && st.origTexts.find((o) => o.offset === insn.offset);
      const changed = st.bytes.some((b, i) => b !== st.orig[i]);
      const statusNote = insn.status === 'decoded' ? ''
        : insn.status === 'partial' ? 'partly decoded'
        : insn.status === 'truncated' ? 'incomplete' : 'not decoded';
      return html`<div class="lenc-card">
        <div class="lenc-card-head">
          <span class="lenc-text ${insn.text ? '' : 'lenc-insn-undecoded'}">${insn.text || 'not decoded'}</span>
          ${insn.encoding_class ? html`<span class="lenc-class">${insn.encoding_class}${statusNote ? ' · ' + statusNote : ''}</span>` : statusNote ? html`<span class="lenc-class">${statusNote}</span>` : ''}
          ${insn.target ? html`<span class="lenc-target" title="Computed address">→ ${insn.target}</span>` : ''}
          <span class="lenc-spacer"></span>
          ${changed && was && was.text !== insn.text ? html`<span class="lenc-was" title="Before your changes">was: ${was.text || 'not decoded'}</span>` : ''}
          ${changed ? html`<button type="button" class="lenc-btn" data-act="reset" data-fk="reset">Restore original bytes</button>` : ''}
          ${options.onOpenLab ? html`<button type="button" class="lenc-btn" data-act="openlab" data-fk="openlab">Open in the encoding lab</button>` : ''}
        </div>
        <div class="lenc-card-body">
          ${insn.size && Number.isInteger(insn.offset) && insn.offset >= 0 ? (st.arch === 'arm64' ? (insn.size === 4 && insn.offset + 4 <= st.bytes.length && a64FieldsValid(insn) ? renderA64Strip(insn) : '') : renderX86Strip(insn)) : ''}
          ${(insn.gaps || []).map((g) => html`<div class="lenc-gap" role="note"><strong>Not decoded.</strong> ${g}</div>`)}
          ${(insn.fields || []).length ? renderFields(insn) : ''}
          ${(insn.steps || []).length ? html`<div><div class="lenc-subhead">How the values are computed</div><ol class="lenc-steps">${insn.steps.map((s) => html`<li>${s}</li>`)}</ol></div>` : ''}
          ${(insn.notes || []).length ? html`<div><div class="lenc-subhead">Notes</div><ul class="lenc-notes">${insn.notes.map((s) => html`<li>${s}</li>`)}</ul></div>` : ''}
          <div class="lenc-note">Click a field to highlight its bits. Click a bit (or press Space on it) to flip it, or type a new field value and press Enter: the changed bytes are decoded again. Nothing is executed.</div>
        </div>
      </div>`;
    }

    function render() {
      if (st.destroyed) return;
      keepFocus(host, () => {
        if (st.error) {
          host.innerHTML = html`<div class="lenc-error" role="alert">${st.error}</div>`;
          return;
        }
        const res = st.result;
        if (!res || !(res.instructions || []).length) {
          host.innerHTML = '';
          return;
        }
        const insns = res.instructions;
        const sel = insns[Math.min(st.sel, insns.length - 1)];
        const list = insns.length > 1 || !options.single
          ? html`<div class="lenc-list" role="listbox" aria-label="Decoded instructions">${insns.map((insn, i) => html`<button type="button" role="option" class="lenc-insn" data-insn="${i}" data-fk="i${i}" aria-selected="${i === st.sel ? 'true' : 'false'}" aria-current="${i === st.sel ? 'true' : 'false'}">
              <span class="lenc-insn-addr">${insn.pc}</span><span class="lenc-insn-bytes">${insn.hex}</span>
              <span class="${insn.text ? '' : 'lenc-insn-undecoded'}">${insn.text || (insn.status === 'truncated' ? 'incomplete instruction' : 'not decoded')}</span></button>`)}</div>`
          : '';
        host.innerHTML = html`${list}
          ${res.stop_reason ? html`<div class="lenc-gap" role="note"><strong>Decoding stopped.</strong> ${res.stop_reason}</div>` : ''}
          ${renderInsn(sel)}`;
        hydrateSpans(host);
      });
    }

    function currentInsn() {
      const list = (st.result && st.result.instructions) || [];
      return list[Math.min(st.sel, list.length - 1)] || null;
    }

    function onClick(e) {
      const t = e.target;
      const insnBtn = t.closest('[data-insn]');
      if (insnBtn) {
        st.sel = Number(insnBtn.dataset.insn);
        st.active = -1;
        render();
        return;
      }
      const bit = t.closest('.lenc-bit');
      if (bit) {
        toggleBit(Number(bit.dataset.byte), Number(bit.dataset.bit));
        return;
      }
      const act = t.closest('[data-act]');
      if (act) {
        if (act.dataset.act === 'reset') reset();
        else if (act.dataset.act === 'openlab' && options.onOpenLab) options.onOpenLab(st);
        return;
      }
      if (t.closest('input')) return;
      const fieldEl = t.closest('[data-field]');
      if (fieldEl) {
        const i = Number(fieldEl.dataset.field);
        st.active = st.active === i ? -1 : i;
        render();
      }
    }

    function onKey(e) {
      const t = e.target;
      if (t.matches && t.matches('input[data-edit]') && e.key === 'Enter') {
        e.preventDefault();
        applyEdit(t);
        return;
      }
      if (t.classList && t.classList.contains('lenc-bit') && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) {
        const all = Array.from(host.querySelectorAll('.lenc-bit'));
        const next = all[all.indexOf(t) + (e.key === 'ArrowRight' ? 1 : -1)];
        if (next) {
          e.preventDefault();
          next.focus();
        }
        return;
      }
      if (t.classList && t.classList.contains('lenc-insn') && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
        const all = Array.from(host.querySelectorAll('.lenc-insn'));
        const next = all[all.indexOf(t) + (e.key === 'ArrowDown' ? 1 : -1)];
        if (next) {
          e.preventDefault();
          next.focus();
          next.click();
        }
      }
    }

    function applyEdit(input) {
      const insn = currentInsn();
      const f = insn && insn.fields[Number(input.dataset.edit)];
      if (!f) return;
      const width = fieldWidth(f);
      const p = M.parseInteger(input.value, width);
      if (!p.ok || !p.fits) {
        input.classList.add('lenc-bad');
        input.title = p.ok ? 'Does not fit in ' + width + ' bits.' : 'Not a number. Use decimal, 0x hex or 0b binary.';
        return;
      }
      st.active = Number(input.dataset.edit);
      writeField(insn, f, p.value);
    }

    function onChange(e) {
      if (e.target.matches && e.target.matches('input[data-edit]')) applyEdit(e.target);
    }

    host.addEventListener('click', onClick);
    host.addEventListener('keydown', onKey);
    host.addEventListener('change', onChange);

    return {
      load,
      state: st,
      destroy() {
        st.destroyed = true;
        if (st.abort) st.abort.abort();
        host.removeEventListener('click', onClick);
        host.removeEventListener('keydown', onKey);
        host.removeEventListener('change', onChange);
      },
    };
  }

  // -------------------------------------------------------------------------------------
  // View: labs.encoding
  // -------------------------------------------------------------------------------------
  const saved = BS.storage.get('labs.encoding', null) || {};
  const lab = {
    arch: ARCHS.some((a) => a.id === saved.arch) ? saved.arch : null,
    hex: typeof saved.hex === 'string' ? saved.hex.slice(0, 2048) : '',
    pc: typeof saved.pc === 'string' ? saved.pc.slice(0, 40) : '',
    words: saved.words === true,
    explorer: null,
    note: '',
    // Bytes and an address taken from the open document (or from a link) stay in memory only:
    // while `derived` is set, the fields are not written to storage, and storage keeps the last
    // bytes and address the user typed (or an example).
    derived: false,
    typedHex: typeof saved.hex === 'string' ? saved.hex.slice(0, 2048) : '',
    typedPc: typeof saved.pc === 'string' ? saved.pc.slice(0, 40) : '',
  };
  const persistLab = BS.util.debounce(() => {
    if (!lab.derived) {
      lab.typedHex = lab.hex;
      lab.typedPc = lab.pc;
    }
    BS.storage.set('labs.encoding', { arch: lab.arch, hex: lab.typedHex, pc: lab.typedPc, words: lab.words });
  }, 300);

  function labBytes() {
    // -> {bytes} | {error}
    const text = lab.hex.trim();
    if (!text) return { error: '' };
    if (lab.words && lab.arch === 'arm64') {
      const toks = text.replace(/0x/gi, ' ').replace(/[,;]/g, ' ').trim().split(/\s+/);
      const out = [];
      for (const tok of toks) {
        if (!/^[0-9a-f]{8}$/i.test(tok)) return { error: 'In word mode each group must be 8 hex digits, for example 910003fd.' };
        const w = parseInt(tok, 16);
        out.push(w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, (w >>> 24) & 0xff);
      }
      if (out.length > LIMITS.maxBytes) return { error: 'At most ' + LIMITS.maxBytes + ' bytes are decoded at a time.' };
      return { bytes: out };
    }
    const bytes = M.parseHexBytes(text, LIMITS.maxBytes);
    if (bytes === null) return { error: 'Type bytes as pairs of hex digits (for example 48 89 e5), at most ' + LIMITS.maxBytes + ' bytes.' };
    return { bytes };
  }

  function renderEncodingView(bodyEl, ctx) {
    if (lab.explorer) lab.explorer.destroy();
    const params = ctx.params || {};
    const sliceArch = archOfSlice(ctx.slice);
    if (typeof params.hex === 'string' && params.hex) {
      lab.hex = params.hex.slice(0, 2048);
      lab.words = false;
      if (ARCHS.some((a) => a.id === params.arch)) lab.arch = params.arch;
      lab.pc = typeof params.pc === 'string' ? params.pc.slice(0, 40) : '0x0';
      lab.derived = true;
    }
    if (!lab.arch) lab.arch = sliceArch || 'arm64';
    if (!lab.hex) {
      lab.hex = SAMPLES[lab.arch].hex;
      lab.pc = SAMPLES[lab.arch].pc;
    }
    const hasDoc = Boolean(ctx.doc);
    // The open file's own bytes are only offered when its architecture is one the decoder knows.
    // For anything else (32-bit ARM, RISC-V, PowerPC, MIPS, ...) the lab says so and stays a tool
    // for bytes the user types: decoding that file's code as A64 or x86 would be meaningless.
    const fileArchKnown = hasDoc && sliceArch !== null;
    const fileArchName = hasDoc && ctx.slice ? String((ctx.slice.overview && ctx.slice.overview.arch_display) || ctx.slice.arch_name || 'an unknown architecture') : '';
    const entry = fileArchKnown && ctx.slice && ctx.slice.overview && ctx.slice.overview.entry_point_abs_offset !== undefined && ctx.slice.overview.entry_point_abs_offset !== null;
    bodyEl.innerHTML = html`<div class="lenc-root">
      <div class="lenc-controls" id="lenc-form" role="group" aria-label="Bytes to decode">
        <label class="lenc-field-label">Architecture
          <select class="lenc-select" id="lenc-arch">${ARCHS.map((a) => html`<option value="${a.id}">${a.label}</option>`)}</select>
        </label>
        <label class="lenc-field-label lenc-grow">Bytes (hex)
          <input class="lenc-input lenc-input-hex" id="lenc-hex" type="text" spellcheck="false" autocomplete="off" maxlength="2048" placeholder="48 89 e5 …" />
        </label>
        <label class="lenc-field-label">Address of the first byte
          <input class="lenc-input lenc-input-pc" id="lenc-pc" type="text" spellcheck="false" autocomplete="off" maxlength="40" placeholder="0x0" />
        </label>
        <button type="button" class="lenc-btn" id="lenc-go">Decode</button>
        <button type="button" class="lenc-btn" id="lenc-words" aria-pressed="false" title="A disassembler prints an A64 instruction as one 32-bit number (for example 910003fd). In memory its bytes are in the opposite order (fd 03 00 91). Turn this on to paste words.">Input is 32-bit words</button>
        <button type="button" class="lenc-btn" id="lenc-sample">Example</button>
        ${fileArchKnown ? html`<button type="button" class="lenc-btn" id="lenc-cursor" title="Decode the bytes at the hex cursor of the open file">Bytes at cursor</button>` : ''}
        ${entry ? html`<button type="button" class="lenc-btn" id="lenc-entry" title="Decode the bytes at the entry point of the open file">Bytes at entry point</button>` : ''}
      </div>
      ${hasDoc && !fileArchKnown ? html`<div class="lenc-note" id="lenc-unsupported" role="note">The open file is for ${fileArchName}, which is not disassembled here. This lab decodes AArch64, x86-64 and x86 bytes that you type or paste; it does not read code from this file.</div>` : ''}
      <div class="lenc-note" id="lenc-status" aria-live="polite"></div>
      <div id="lenc-host"></div>
      <div class="lenc-note">
        The breakdown comes from this lab's own tables for the instructions compilers emit most often, checked against llvm-objdump.
        Anything outside them is reported as not decoded: Advanced SIMD beyond a few forms and SVE on AArch64; VEX/EVEX (AVX),
        the 0F 38 / 0F 3A opcode maps, x87 and MMX on x86. Where the length of such an x86 instruction follows from its opcode map
        it is stepped over and decoding continues; an undefined opcode has no length to know, so decoding stops there.
      </div>
    </div>`;
    const $ = (id) => bodyEl.querySelector('#' + id);
    const archSel = $('lenc-arch');
    const hexIn = $('lenc-hex');
    const pcIn = $('lenc-pc');
    const wordsBtn = $('lenc-words');
    const status = $('lenc-status');
    archSel.value = lab.arch;
    hexIn.value = lab.hex;
    pcIn.value = lab.pc;
    lab.explorer = createExplorer($('lenc-host'), {});

    const syncWords = () => {
      wordsBtn.hidden = lab.arch !== 'arm64';
      wordsBtn.setAttribute('aria-pressed', lab.words && lab.arch === 'arm64' ? 'true' : 'false');
    };
    const run = () => {
      lab.arch = archSel.value;
      lab.hex = hexIn.value;
      lab.pc = pcIn.value;
      persistLab();
      syncWords();
      const pc = lab.pc.trim() ? parseAddr(lab.pc) : 0n;
      pcIn.classList.toggle('lenc-bad', pc === null);
      const got = labBytes();
      hexIn.classList.toggle('lenc-bad', Boolean(got.error));
      if (got.error || pc === null) {
        status.textContent = got.error || 'The address must be a number between 0 and 2^64 - 1 (decimal or 0x hex).';
        status.classList.add('lenc-error');
        return;
      }
      status.classList.remove('lenc-error');
      status.textContent = lab.note;
      lab.note = '';
      lab.explorer.load(lab.arch, got.bytes || [], pc);
    };
    $('lenc-go').addEventListener('click', run);
    $('lenc-form').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && e.target.matches('input')) {
        e.preventDefault();
        run();
      }
    });
    archSel.addEventListener('change', run);
    wordsBtn.addEventListener('click', () => {
      lab.words = !lab.words;
      run();
    });
    // Clearing the bytes field ends a document-derived session: what is typed next is the user's.
    hexIn.addEventListener('input', () => {
      if (!hexIn.value.trim()) lab.derived = false;
    });
    $('lenc-sample').addEventListener('click', () => {
      lab.arch = archSel.value;
      lab.words = false;
      lab.derived = false;
      hexIn.value = SAMPLES[lab.arch].hex;
      pcIn.value = SAMPLES[lab.arch].pc;
      run();
    });
    const cursorBtn = $('lenc-cursor');
    if (cursorBtn) cursorBtn.addEventListener('click', () => loadFromDocument('cursor'));
    const entryBtn = $('lenc-entry');
    if (entryBtn) entryBtn.addEventListener('click', () => loadFromDocument('entry'));
    syncWords();
    if (params.from === 'cursor' || params.from === 'entry') {
      if (fileArchKnown) loadFromDocument(params.from);
      else run();
    } else {
      run();
    }

    async function loadFromDocument(which) {
      const slice = BS.getActiveSlice();
      if (!BS.state.doc || !slice) return;
      const arch = archOfSlice(slice);
      let abs = BS.state.cursorOffset || 0;
      let pcText = null;
      if (which === 'entry') {
        abs = Number(slice.overview.entry_point_abs_offset);
        pcText = String(slice.overview.entry_point_vmaddr || '');
      }
      try {
        if (!pcText) {
          const tr = await BS.api.get('/api/translate', { query: String(abs), mode: 'abs_offset' });
          pcText = tr && tr.vmaddr ? String(tr.vmaddr) : null;
        }
        const count = (arch || lab.arch) === 'arm64' ? 32 : 48;
        const bytes = await BS.hex.getBytes(abs, count);
        if (!bodyEl.isConnected) return;
        if (!bytes.length) {
          status.textContent = 'There are no bytes at that position.';
          return;
        }
        if (arch) archSel.value = arch;
        lab.words = false;
        lab.derived = true;
        hexIn.value = hexOfBytes(bytes);
        pcIn.value = pcText || BS.util.hex(abs);
        lab.note = (which === 'entry' ? 'Entry point' : 'Cursor') + ': file offset ' + BS.util.hex(abs)
          + (pcText ? ', address ' + pcText : ' (this offset is not mapped to an address; the file offset is used instead)')
          + (arch ? '' : '. The architecture of this file is not one the lab decodes; choose one to try anyway.')
          + '. The last instruction may be cut off where the sample of bytes ends.';
        run();
      } catch (err) {
        status.textContent = 'Could not read the bytes: ' + String((err && err.message) || 'request failed');
        status.classList.add('lenc-error');
      }
    }
  }

  BS.registerView({
    id: 'labs.encoding', title: 'Instruction encoding', icon: 'ENC', group: 'Labs', order: 300,
    subtitle: 'How the bits of a machine instruction map to its operands',
    render: renderEncodingView,
    dispose() {
      if (lab.explorer) lab.explorer.destroy();
      lab.explorer = null;
    },
  });

  // -------------------------------------------------------------------------------------
  // Inline breakdown under the selected disassembly row (Learn mode only)
  // -------------------------------------------------------------------------------------
  const inline = { explorer: null, row: null, forRow: null };

  function closeInline() {
    if (inline.explorer) inline.explorer.destroy();
    if (inline.row && inline.row.parentNode) inline.row.parentNode.removeChild(inline.row);
    inline.explorer = inline.row = inline.forRow = null;
  }

  async function showInlineFor(row) {
    if (!BS.learn.isOn() || !row || !row.isConnected) return;
    if (inline.forRow === row && inline.row && inline.row.isConnected) return;
    closeInline();
    const arch = archOfSlice(BS.getActiveSlice());
    if (!arch) return;
    const abs = Number(row.dataset.absOffset);
    const addrCell = row.querySelector('.col-addr');
    const pc = parseAddr(addrCell ? addrCell.textContent.trim() : '') || 0n;
    const tr = doc.createElement('tr');
    tr.className = 'lenc-inline-row learn-only';
    const td = doc.createElement('td');
    td.colSpan = row.children.length || 6;
    const wrap = doc.createElement('div');
    wrap.className = 'lenc-inline';
    const host = doc.createElement('div');
    host.className = 'lenc-root';
    wrap.appendChild(host);
    td.appendChild(wrap);
    tr.appendChild(td);
    row.parentNode.insertBefore(tr, row.nextSibling);
    inline.row = tr;
    inline.forRow = row;
    const explorer = createExplorer(host, {
      single: true,
      onOpenLab(st) {
        const insn = st.result && st.result.instructions && st.result.instructions[0];
        const size = insn ? insn.size : st.bytes.length;
        BS.nav.openView('labs.encoding', { arch: st.arch, hex: hexOfBytes(st.orig.slice(0, size)).replace(/ /g, ''), pc: '0x' + st.pc.toString(16) });
      },
    });
    inline.explorer = explorer;
    try {
      const bytes = await BS.hex.getBytes(abs, arch === 'arm64' ? 4 : 15);
      if (inline.explorer !== explorer || !tr.isConnected) return;
      await explorer.load(arch, bytes, pc);
    } catch (err) {
      if (inline.explorer === explorer) host.textContent = 'Could not read the instruction bytes.';
    }
  }

  doc.addEventListener('click', (e) => {
    if (!e.target || !e.target.closest) return;
    if (e.target.closest('.lenc-inline-row')) return;
    const row = e.target.closest('tr.disasm-row');
    if (!row) return;
    if (e.target.closest('button, a')) return; // jump chips navigate away
    // the core marks the row as selected in its own click handler; run after it
    setTimeout(() => showInlineFor(row), 0);
  });
  BS.on('learnmode:changed', ({ on }) => {
    if (!on) closeInline();
    else {
      const row = doc.querySelector('tr.disasm-row.selected');
      if (row) showInlineFor(row);
    }
  });
  BS.on('view:rendered', ({ id }) => {
    if (inline.row && !inline.row.isConnected) closeInline();
    if (id === 'disassembly' && BS.learn.isOn()) {
      const row = doc.querySelector('tr.disasm-row.selected');
      if (row) showInlineFor(row);
    }
  });
  BS.on('doc:loaded', closeInline);
  BS.on('doc:closed', closeInline);

  // -------------------------------------------------------------------------------------
  // View: labs.numbers
  // -------------------------------------------------------------------------------------
  const TABS = [
    { id: 'int', label: 'Integers', keywords: 'signed unsigned two\'s complement hex binary octal endianness byte order' },
    { id: 'float', label: 'Floating point', keywords: 'ieee 754 float double sign exponent mantissa nan infinity' },
    { id: 'leb', label: 'LEB128', keywords: 'uleb128 sleb128 varint dwarf' },
    { id: 'align', label: 'Alignment', keywords: 'padding page round up down' },
    { id: 'flags', label: 'Flag sets', keywords: 'characteristics p_flags sh_flags mach header bits' },
    { id: 'addr', label: 'Address arithmetic', keywords: 'rva va file offset image base section translate' },
  ];
  const numSaved = BS.storage.get('labs.numbers', null) || {};
  const num = {
    tab: TABS.some((t) => t.id === numSaved.tab) ? numSaved.tab : 'int',
    int: { bits: [8, 16, 32, 64].includes(numSaved.intBits) ? numSaved.intBits : 32, text: typeof numSaved.intText === 'string' ? numSaved.intText.slice(0, 80) : '-2' },
    float: { width: numSaved.floatWidth === 32 ? 32 : 64, text: typeof numSaved.floatText === 'string' ? numSaved.floatText.slice(0, 80) : '0.1' },
    leb: { signed: numSaved.lebSigned === true, value: typeof numSaved.lebValue === 'string' ? numSaved.lebValue.slice(0, 80) : '624485', bytes: typeof numSaved.lebBytes === 'string' ? numSaved.lebBytes.slice(0, 120) : 'e5 8e 26' },
    align: { value: typeof numSaved.alignValue === 'string' ? numSaved.alignValue.slice(0, 80) : '0x1234', to: typeof numSaved.alignTo === 'string' ? numSaved.alignTo.slice(0, 80) : '0x1000' },
    flags: { table: M.FLAG_TABLES.some((t) => t.id === numSaved.flagTable) ? numSaved.flagTable : 'pe.characteristics', text: typeof numSaved.flagText === 'string' ? numSaved.flagText.slice(0, 80) : '0x2022' },
    addr: null,
  };
  const persistNum = BS.util.debounce(() => BS.storage.set('labs.numbers', {
    tab: num.tab, intBits: num.int.bits, intText: num.int.text, floatWidth: num.float.width, floatText: num.float.text,
    lebSigned: num.leb.signed, lebValue: num.leb.value, lebBytes: num.leb.bytes, alignValue: num.align.value, alignTo: num.align.to,
    flagTable: num.flags.table, flagText: num.flags.text,
  }), 300);

  const kv = (rows) => html`<div class="lnum-kv">${rows.filter(Boolean).map(([k, v]) => html`<div class="lnum-k">${k}</div><div class="lnum-v">${v}</div>`)}</div>`;
  const bx = (v) => '0x' + v.toString(16);
  const byteList = (bytes) => bytes.map((b) => b.toString(16).padStart(2, '0')).join(' ');

  function bitGrid(value, bits, classOf) {
    const groups = [];
    for (let hi = bits - 1; hi >= 0; hi -= 8) {
      const cells = [];
      for (let b = hi; b > hi - 8; b--) {
        const on = (value >> B(b)) & 1n;
        cells.push(html`<button type="button" class="lnum-bit ${classOf ? classOf(b) : ''}" data-bit="${b}" data-fk="nb${b}" aria-pressed="${on ? 'true' : 'false'}" aria-label="bit ${b}, value ${on}" title="bit ${b} (2^${b}): toggle">${on}</button>`);
      }
      const byte = Number((value >> B(hi - 7)) & 0xffn);
      groups.push(html`<div class="lnum-bytegroup"><div class="lnum-bytecap"><span>${hi}</span><span>${hi - 7}</span></div>${cells}<div class="lnum-bytehex">${byte.toString(16).padStart(2, '0')}</div></div>`);
    }
    return html`<div class="lnum-bits" role="group" aria-label="Bits, most significant first">${groups}</div>`;
  }
  function bitKeys(e, panel) {
    const t = e.target;
    if (!t.classList || !t.classList.contains('lnum-bit')) return;
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    const all = Array.from(panel.querySelectorAll('.lnum-bit'));
    const next = all[all.indexOf(t) + (e.key === 'ArrowRight' ? 1 : -1)];
    if (next) {
      e.preventDefault();
      next.focus();
    }
  }

  // ---- integers ----
  function tabInt(panel) {
    const s = num.int;
    let value = 0n;
    panel.innerHTML = html`
      <div class="lnum-row">
        <label class="lnum-label">Width
          <select class="lnum-select" id="lnum-int-bits">${[8, 16, 32, 64].map((b) => html`<option value="${b}">${b} bits</option>`)}</select>
        </label>
        <label class="lnum-label">Value (decimal, -decimal, 0x hex, 0b binary, 0o octal or 'c')
          <input class="lnum-input lnum-input-wide" id="lnum-int-in" type="text" spellcheck="false" maxlength="80" autocomplete="off" />
        </label>
        <div class="lnum-row" role="group" aria-label="Operations">
          ${[['not', 'NOT', 'Invert every bit'], ['neg', 'Negate', "Two's complement: invert every bit, then add 1"], ['inc', '+1', 'Add one (wraps around)'], ['dec', '-1', 'Subtract one (wraps around)'],
            ['shl', '<< 1', 'Shift left by one'], ['shr', '>> 1 logical', 'Shift right, filling with 0'], ['sar', '>> 1 arithmetic', 'Shift right, copying the sign bit'],
            ['rol', 'Rotate left', 'Rotate left by one'], ['bswap', 'Swap bytes', 'Reverse the byte order']].map(([id, label, title]) => html`<button type="button" class="lnum-btn" data-op="${id}" title="${title}">${label}</button>`)}
        </div>
      </div>
      <div class="lnum-note lnum-error" id="lnum-int-msg" aria-live="polite"></div>
      <div id="lnum-int-grid"></div>
      <div id="lnum-int-out"></div>`;
    const input = panel.querySelector('#lnum-int-in');
    const sel = panel.querySelector('#lnum-int-bits');
    const msg = panel.querySelector('#lnum-int-msg');
    sel.value = String(s.bits);
    input.value = s.text;

    function show() {
      const bits = s.bits;
      const signed = M.toSigned(value, bits);
      const le = M.bytesOf(value, bits, true);
      const be = M.bytesOf(value, bits, false);
      const ch = M.charOf(value, bits);
      const swapped = M.byteSwap(value, bits);
      keepFocus(panel, () => {
        panel.querySelector('#lnum-int-grid').innerHTML = bitGrid(value, bits, (b) => (b === bits - 1 ? 'lnum-msb' : ''));
        panel.querySelector('#lnum-int-out').innerHTML = html`${kv([
          ['Unsigned', value.toString()],
          ['Signed (two\'s complement)', html`${signed.toString()} <span class="lnum-dim">${signed < 0n
            ? `· bit ${bits - 1} is 1, so the value is unsigned - 2^${bits} = ${value} - ${1n << B(bits)}`
            : `· bit ${bits - 1} is 0, so signed and unsigned agree`}</span>`],
          ['Hexadecimal', M.hex(value, bits)],
          ['Binary', M.binGrouped(value, bits)],
          ['Octal', M.oct(value, bits)],
          ['Character', html`${ch.text} <span class="lnum-dim">${ch.note}</span>`],
          bits > 8 ? ['Bytes in memory, little-endian', html`${byteList(le)} <span class="lnum-dim">· least significant byte at the lowest address (x86, AArch64, and all three file formats on those machines)</span>`] : null,
          bits > 8 ? ['Bytes in memory, big-endian', html`${byteList(be)} <span class="lnum-dim">· most significant byte first (network order; Mach-O fat headers)</span>`] : null,
          bits > 8 ? ['Same bytes, other byte order', html`${M.hex(swapped, bits)} = ${swapped.toString()} <span class="lnum-dim">· what you get if the little-endian bytes ${byteList(le)} are read as big-endian</span>`] : null,
          bits < 64 ? ['Zero-extended to 64 bits', M.hex(value, 64)] : null,
          bits < 64 ? ['Sign-extended to 64 bits', html`${M.hex(M.wrap(signed, 64), 64)} <span class="lnum-dim">· the sign bit is copied into the new upper bits, so the signed value stays ${signed.toString()}</span>`] : null,
          ['Range of this width', html`unsigned 0 … ${M.mask(bits).toString()}, signed ${(-(1n << B(bits - 1))).toString()} … ${((1n << B(bits - 1)) - 1n).toString()}`],
        ])}
        <div class="lnum-note">The highlighted bit is the sign bit. Negating a two's-complement number is "invert every bit, then add 1"; the most negative value has no positive counterpart, so negating it gives itself.</div>`;
      });
    }
    function parse() {
      const p = M.parseInteger(input.value, s.bits);
      input.classList.toggle('lnum-bad', !p.ok);
      if (!p.ok) {
        msg.textContent = input.value.trim() ? 'Not a number. Use decimal, 0x hex, 0b binary, 0o octal or a character in single quotes.' : '';
        return;
      }
      msg.textContent = p.fits ? '' : `${p.typed} does not fit in ${s.bits} bits; it was reduced modulo 2^${s.bits}, which is what storing it in a ${s.bits}-bit field does.`;
      value = p.value;
      s.text = input.value;
      persistNum();
      show();
    }
    function setValue(v) {
      value = M.wrap(v, s.bits);
      input.value = M.hex(value, s.bits);
      s.text = input.value;
      input.classList.remove('lnum-bad');
      msg.textContent = '';
      persistNum();
      show();
    }
    input.addEventListener('input', parse);
    sel.addEventListener('change', () => {
      s.bits = Number(sel.value);
      parse();
    });
    panel.addEventListener('click', (e) => {
      const bit = e.target.closest('.lnum-bit');
      if (bit) return setValue(value ^ (1n << B(bit.dataset.bit)));
      const op = e.target.closest('[data-op]');
      if (!op) return undefined;
      const b = s.bits;
      const ops = {
        not: () => ~value, neg: () => -value, inc: () => value + 1n, dec: () => value - 1n, shl: () => value << 1n, shr: () => value >> 1n,
        sar: () => M.sar(value, b, 1), rol: () => M.rotl(value, b, 1), bswap: () => M.byteSwap(value, b),
      };
      return setValue(ops[op.dataset.op]());
    });
    panel.addEventListener('keydown', (e) => bitKeys(e, panel));
    parse();
    if (input.classList.contains('lnum-bad')) setValue(0n);
  }

  // ---- floating point ----
  function tabFloat(panel) {
    const s = num.float;
    let bits = 0n;
    const specials = (w) => {
      const f = M.FLOAT[w];
      const expAll = M.mask(f.exp) << B(f.mant);
      const sign = 1n << B(w - 1);
      return [
        ['+0', 0n], ['-0', sign], ['1.0', B(f.bias) << B(f.mant)], ['smallest subnormal', 1n], ['largest subnormal', M.mask(f.mant)],
        ['smallest normal', 1n << B(f.mant)], ['largest finite', expAll - 1n], ['+infinity', expAll], ['-infinity', sign | expAll],
        ['quiet NaN', expAll | (1n << B(f.mant - 1))], ['signalling NaN', expAll | 1n], ['epsilon (1.0 to next)', B(f.bias - f.mant) << B(f.mant)],
      ];
    };
    panel.innerHTML = html`
      <div class="lnum-row">
        <label class="lnum-label">Format
          <select class="lnum-select" id="lnum-f-width"><option value="32">float32 (binary32, C float)</option><option value="64">float64 (binary64, C double)</option></select>
        </label>
        <label class="lnum-label">Decimal value (for example 0.1, -1.5e-3, inf, nan)
          <input class="lnum-input lnum-input-mid" id="lnum-f-dec" type="text" spellcheck="false" maxlength="80" autocomplete="off" />
        </label>
        <label class="lnum-label">Bit pattern (hex)
          <input class="lnum-input lnum-input-mid" id="lnum-f-hex" type="text" spellcheck="false" maxlength="20" autocomplete="off" />
        </label>
      </div>
      <div class="lnum-row" role="group" aria-label="Special values" id="lnum-f-special"></div>
      <div class="lnum-note lnum-error" id="lnum-f-msg" aria-live="polite"></div>
      <div class="lnum-legend"><span><span class="lnum-chip lnum-f-sign">sign</span> 1 bit</span><span><span class="lnum-chip lnum-f-exp">exponent</span> <span id="lnum-f-eb"></span> bits, biased</span><span><span class="lnum-chip lnum-f-mant">fraction (mantissa)</span> <span id="lnum-f-mb"></span> bits</span></div>
      <div id="lnum-f-grid"></div>
      <div id="lnum-f-out"></div>`;
    const dec = panel.querySelector('#lnum-f-dec');
    const hexIn = panel.querySelector('#lnum-f-hex');
    const sel = panel.querySelector('#lnum-f-width');
    const msg = panel.querySelector('#lnum-f-msg');
    sel.value = String(s.width);
    dec.value = s.text;

    function show(typedNote) {
      const w = s.width;
      const f = M.FLOAT[w];
      const d = M.floatDecode(bits, w);
      panel.querySelector('#lnum-f-eb').textContent = String(f.exp);
      panel.querySelector('#lnum-f-mb').textContent = String(f.mant);
      panel.querySelector('#lnum-f-special').innerHTML = html`${specials(w).map(([label, v]) => html`<button type="button" class="lnum-btn" data-special="${bx(v)}">${label}</button>`)}`;
      const fracBits = M.bin(d.mant, f.mant);
      let formula;
      let meaning;
      if (d.kind === 'normal') {
        formula = `(-1)^${d.sign} x 1.${fracBits} (binary) x 2^(${d.exp} - ${f.bias}) = ${d.sign ? '-' : ''}(1 + ${d.mant}/2^${f.mant}) x 2^${d.unbiased}`;
        meaning = 'Normal number: an implicit leading 1 is put in front of the fraction bits.';
      } else if (d.kind === 'subnormal') {
        formula = `(-1)^${d.sign} x 0.${fracBits} (binary) x 2^${1 - f.bias} = ${d.sign ? '-' : ''}(${d.mant}/2^${f.mant}) x 2^${1 - f.bias}`;
        meaning = `Subnormal: exponent field 0 means there is no implicit leading 1 and the exponent is fixed at ${1 - f.bias} (not ${-f.bias}). This fills the gap between 0 and the smallest normal number.`;
      } else if (d.kind === 'zero') {
        formula = d.sign ? '-0' : '+0';
        meaning = 'Zero: exponent and fraction all 0. +0 and -0 are different bit patterns that compare equal.';
      } else if (d.kind === 'infinity') {
        formula = d.sign ? '-infinity' : '+infinity';
        meaning = 'Infinity: exponent all ones, fraction 0.';
      } else {
        formula = 'not a number';
        meaning = `NaN: exponent all ones, fraction not 0. The top fraction bit distinguishes quiet (1) from signalling (0) NaNs on x86 and Arm; the other ${f.mant - 1} bits are a payload. A NaN compares unequal to everything, including itself.`;
      }
      const exact = d.exact;
      const exactShown = exact === null ? '' : exact.length > 120 ? exact.slice(0, 120) + '… (' + exact.replace(/[-.]/g, '').length + ' digits in total)' : exact;
      const finite = d.kind === 'normal' || d.kind === 'subnormal' || d.kind === 'zero';
      keepFocus(panel, () => {
        panel.querySelector('#lnum-f-grid').innerHTML = bitGrid(M.wrap(bits, w), w, (b) => (b === w - 1 ? 'lnum-f-sign' : b >= f.mant ? 'lnum-f-exp' : 'lnum-f-mant'));
        panel.querySelector('#lnum-f-out').innerHTML = html`${kv([
          ['Class', html`${d.kind} <span class="lnum-dim">· ${meaning}</span>`],
          ['Sign', html`${d.sign} <span class="lnum-dim">· ${d.sign ? 'negative' : 'positive'}</span>`],
          ['Exponent field', html`${d.exp} (${bx(B(d.exp))}) <span class="lnum-dim">${d.unbiased === null ? '· all ones: infinity or NaN' : `· stored with a bias of ${f.bias}; actual exponent ${d.unbiased}`}</span>`],
          ['Fraction field', html`${bx(d.mant)} <span class="lnum-dim">· ${f.mant} bits</span>`],
          ['Value', formula],
          finite ? ['Exact decimal value', html`${exactShown} <span class="lnum-dim">· every finite binary float has an exact, finite decimal expansion</span>`] : null,
          finite ? ['Shortest decimal that reads back as this float', d.shortest] : null,
          typedNote ? ['What you typed', typedNote] : null,
          finite ? ['Neighbours', html`bit pattern + 1: ${M.floatShortest(M.wrap(bits, w) + 1n, w)}${(M.wrap(bits, w) & M.mask(w - 1)) !== 0n ? html`, bit pattern - 1: ${M.floatShortest(M.wrap(bits, w) - 1n, w)}` : ''} <span class="lnum-dim">· for one sign, consecutive bit patterns are consecutive representable values (larger pattern, larger magnitude)</span>`] : null,
          ['Bytes in memory, little-endian', byteList(M.bytesOf(bits, w, true))],
        ])}`;
      });
    }
    function fromDecimal() {
      const r = M.floatEncode(dec.value, s.width);
      dec.classList.toggle('lnum-bad', !r.ok);
      if (!r.ok) {
        msg.textContent = dec.value.trim() ? 'Not a decimal number.' : '';
        return;
      }
      msg.textContent = '';
      bits = r.bits;
      s.text = dec.value;
      persistNum();
      hexIn.value = M.hex(bits, s.width);
      hexIn.classList.remove('lnum-bad');
      show(r.exact ? html`${dec.value.trim()} <span class="lnum-dim">· stored exactly</span>` : html`${dec.value.trim()} <span class="lnum-dim">· cannot be stored exactly; the nearest ${s.width === 32 ? 'float32' : 'float64'} is used (round to nearest, ties to even)</span>`);
    }
    function setBits(v) {
      bits = M.wrap(v, s.width);
      hexIn.value = M.hex(bits, s.width);
      hexIn.classList.remove('lnum-bad');
      dec.value = M.floatShortest(bits, s.width);
      dec.classList.remove('lnum-bad');
      s.text = dec.value;
      msg.textContent = '';
      persistNum();
      show(null);
    }
    dec.addEventListener('input', fromDecimal);
    hexIn.addEventListener('input', () => {
      const t = hexIn.value.trim();
      const p = M.parseBig(/^[0-9a-f]+$/i.test(t) && !/^0x/i.test(t) ? '0x' + t : t);
      const ok = p.ok && p.value >= 0n && p.value <= M.mask(s.width);
      hexIn.classList.toggle('lnum-bad', !ok);
      if (!ok) return;
      bits = p.value;
      dec.value = M.floatShortest(bits, s.width);
      dec.classList.remove('lnum-bad');
      s.text = dec.value;
      persistNum();
      show(null);
    });
    sel.addEventListener('change', () => {
      s.width = Number(sel.value);
      fromDecimal();
    });
    panel.addEventListener('click', (e) => {
      const bit = e.target.closest('.lnum-bit');
      if (bit) return setBits(bits ^ (1n << B(bit.dataset.bit)));
      const sp = e.target.closest('[data-special]');
      if (sp) return setBits(B(sp.dataset.special));
      return undefined;
    });
    panel.addEventListener('keydown', (e) => bitKeys(e, panel));
    fromDecimal();
    if (dec.classList.contains('lnum-bad')) setBits(0n);
  }

  // ---- LEB128 ----
  function tabLeb(panel) {
    const s = num.leb;
    panel.innerHTML = html`
      <div class="lnum-row">
        <div class="lnum-row" role="group" aria-label="Variant">
          <button type="button" class="lnum-btn" data-signed="0">ULEB128 (unsigned)</button>
          <button type="button" class="lnum-btn" data-signed="1">SLEB128 (signed)</button>
        </div>
      </div>
      <div class="lnum-note">LEB128 stores an integer 7 bits at a time, least significant group first. Bit 7 of each byte says whether another byte follows. It is used by DWARF, by Mach-O (export trie, bind and rebase opcodes, function starts) and by WebAssembly.</div>
      <h3 class="lnum-h">Encode</h3>
      <div class="lnum-row"><label class="lnum-label">Integer
        <input class="lnum-input lnum-input-wide" id="lnum-leb-val" type="text" spellcheck="false" maxlength="80" autocomplete="off" /></label></div>
      <div id="lnum-leb-enc"></div>
      <h3 class="lnum-h">Decode</h3>
      <div class="lnum-row"><label class="lnum-label">Bytes (hex)
        <input class="lnum-input lnum-input-wide" id="lnum-leb-bytes" type="text" spellcheck="false" maxlength="120" autocomplete="off" /></label></div>
      <div id="lnum-leb-dec"></div>`;
    const valIn = panel.querySelector('#lnum-leb-val');
    const bytesIn = panel.querySelector('#lnum-leb-bytes');
    valIn.value = s.value;
    bytesIn.value = s.bytes;
    const b7 = (g) => g.toString(2).padStart(7, '0');
    function showEncode() {
      const out = panel.querySelector('#lnum-leb-enc');
      const p = M.parseBig(valIn.value);
      const tooBig = p.ok && (p.value > M.mask(128) || p.value < -(1n << 127n));
      valIn.classList.toggle('lnum-bad', !p.ok || tooBig);
      if (!p.ok || tooBig) {
        out.innerHTML = valIn.value.trim() ? html`<div class="lnum-note lnum-error">${tooBig ? 'Limited to 128-bit values here.' : 'Not an integer.'}</div>` : '';
        return;
      }
      const r = s.signed ? M.slebEncode(p.value) : M.ulebEncode(p.value);
      if (!r.ok) {
        out.innerHTML = html`<div class="lnum-note lnum-error">${r.error}</div>`;
        return;
      }
      out.innerHTML = html`<div class="lnum-tablewrap"><table class="lnum-table"><thead><tr><th>Step</th><th>Low 7 bits</th><th>Remaining value</th><th>More?</th><th>Byte</th></tr></thead><tbody>
        ${r.steps.map((st, i) => html`<tr><td>${i + 1}</td><td>${b7(st.group)}</td><td>${st.rest.toString()}</td>
          <td class="lnum-text">${st.more ? 'yes: set bit 7' : s.signed ? `no: remaining value is ${st.rest < 0n ? '-1' : '0'} and bit 6 (${st.signBit ? 1 : 0}) already gives the sign` : 'no: nothing left'}</td>
          <td>${st.byte.toString(16).padStart(2, '0')} = ${st.more ? '1' : '0'}${b7(st.group)}</td></tr>`)}
        </tbody></table></div>
        ${kv([['Encoded bytes', html`${byteList(r.bytes)} <span class="lnum-dim">· ${r.bytes.length} byte(s)</span>`]])}`;
    }
    function showDecode() {
      const out = panel.querySelector('#lnum-leb-dec');
      const bytes = M.parseHexBytes(bytesIn.value, 64);
      bytesIn.classList.toggle('lnum-bad', bytes === null);
      if (bytes === null || !bytes.length) {
        out.innerHTML = bytes === null ? html`<div class="lnum-note lnum-error">Type bytes as pairs of hex digits.</div>` : '';
        return;
      }
      const r = s.signed ? M.slebDecode(bytes) : M.ulebDecode(bytes);
      const table = html`<div class="lnum-tablewrap"><table class="lnum-table"><thead><tr><th>Byte</th><th>Bit 7 (more)</th><th>Low 7 bits</th><th>Shifted left by</th><th>Value so far</th></tr></thead><tbody>
        ${r.steps.map((st) => html`<tr><td>${st.byte.toString(16).padStart(2, '0')}</td><td>${st.more ? 1 : 0}</td><td>${b7(st.group)} = ${st.group}</td><td>${st.shift}</td><td>${st.partial.toString()}</td></tr>`)}
        </tbody></table></div>`;
      if (!r.ok) {
        out.innerHTML = html`${table}<div class="lnum-note lnum-error">${r.error}</div>`;
        return;
      }
      out.innerHTML = html`${table}${kv([
        s.signed ? ['Sign extension', r.signExtended
          ? `bit 6 of the last byte is 1: the value is negative, subtract 2^${r.bits}`
          : 'bit 6 of the last byte is 0: the value is not negative'] : null,
        ['Value', html`${r.value.toString()} <span class="lnum-dim">· ${r.value < 0n ? '-' : ''}${bx(r.value < 0n ? -r.value : r.value)}</span>`],
        ['Bytes used', html`${r.length}${r.rest ? html` <span class="lnum-dim">· ${r.rest} byte(s) after the end of the value were ignored</span>` : ''}`],
        r.fits64 ? null : ['Note', 'This value does not fit in 64 bits. Readers that keep the result in a 64-bit integer must reject or truncate it.'],
      ])}`;
    }
    function sync() {
      panel.querySelectorAll('[data-signed]').forEach((b) => b.setAttribute('aria-pressed', (b.dataset.signed === '1') === s.signed ? 'true' : 'false'));
      showEncode();
      showDecode();
    }
    valIn.addEventListener('input', () => {
      s.value = valIn.value;
      persistNum();
      showEncode();
    });
    bytesIn.addEventListener('input', () => {
      s.bytes = bytesIn.value;
      persistNum();
      showDecode();
    });
    panel.addEventListener('click', (e) => {
      const b = e.target.closest('[data-signed]');
      if (!b) return;
      s.signed = b.dataset.signed === '1';
      persistNum();
      sync();
    });
    sync();
  }

  // ---- alignment ----
  function tabAlign(panel) {
    const s = num.align;
    panel.innerHTML = html`
      <div class="lnum-row">
        <label class="lnum-label">Value (offset, address or size)
          <input class="lnum-input lnum-input-mid" id="lnum-al-v" type="text" spellcheck="false" maxlength="80" autocomplete="off" /></label>
        <label class="lnum-label">Alignment
          <input class="lnum-input lnum-input-mid" id="lnum-al-a" type="text" spellcheck="false" maxlength="80" autocomplete="off" /></label>
        <div class="lnum-row" role="group" aria-label="Common alignments">
          ${[['4', '4'], ['8', '8'], ['16', '16'], ['0x200', '0x200 · PE FileAlignment'], ['0x1000', '0x1000 · 4 KiB page'], ['0x4000', '0x4000 · 16 KiB page'], ['0x10000', '0x10000 · 64 KiB']].map(([v, label]) => html`<button type="button" class="lnum-btn" data-al="${v}">${label}</button>`)}
        </div>
      </div>
      <div id="lnum-al-out"></div>`;
    const vIn = panel.querySelector('#lnum-al-v');
    const aIn = panel.querySelector('#lnum-al-a');
    vIn.value = s.value;
    aIn.value = s.to;
    function show() {
      const out = panel.querySelector('#lnum-al-out');
      const v = M.parseBig(vIn.value);
      const a = M.parseBig(aIn.value);
      const vOk = v.ok && v.value >= 0n && v.value <= M.mask(64);
      const aOk = a.ok && a.value > 0n && a.value <= M.mask(64);
      vIn.classList.toggle('lnum-bad', !vOk);
      aIn.classList.toggle('lnum-bad', !aOk);
      if (!vOk || !aOk) {
        out.innerHTML = html`<div class="lnum-note lnum-error">${!vOk ? 'The value must be a non-negative integer below 2^64.' : 'The alignment must be a positive integer.'}</div>`;
        return;
      }
      const val = v.value;
      const al = a.value;
      const down = M.alignDown(val, al);
      const up = M.alignUp(val, al);
      const pow2 = M.isPowerOfTwo(al);
      const rem = val % al;
      out.innerHTML = html`${kv([
        ['Remainder', html`${bx(val)} mod ${bx(al)} = ${bx(rem)} <span class="lnum-dim">· ${rem === 0n ? 'already aligned' : 'not aligned'}</span>`],
        ['Aligned down', html`${bx(down)} <span class="lnum-dim">= ${down.toString()} · ${pow2 ? `${bx(val)} & ~${bx(al - 1n)}` : `${bx(val)} - (${bx(val)} mod ${bx(al)})`}</span>`],
        ['Aligned up', html`${bx(up)} <span class="lnum-dim">= ${up.toString()} · ${pow2 ? `(${bx(val)} + ${bx(al - 1n)}) & ~${bx(al - 1n)}` : `next multiple of ${bx(al)} at or above ${bx(val)}`}</span>`],
        ['Padding to add', html`${bx(up - val)} <span class="lnum-dim">= ${(up - val).toString()} byte(s) between the value and the next boundary</span>`],
        ['Units', html`${(down / al).toString()} whole unit(s) below; a size of ${bx(val)} occupies ${(up / al).toString()} unit(s) <span class="lnum-dim">· e.g. pages when the alignment is the page size</span>`],
        ['Power of two', pow2
          ? html`yes, 2^${(al.toString(2).length - 1).toString()} <span class="lnum-dim">· the low ${(al.toString(2).length - 1).toString()} bit(s) of an aligned value are 0, so masking works</span>`
          : html`no <span class="lnum-dim">· the mask trick only works for powers of two; division is needed. File formats require power-of-two alignments (ELF p_align, PE SectionAlignment, Mach-O section align is stored as the exponent)</span>`],
        up > M.mask(64) ? ['Note', 'Aligning up overflows 64 bits. A parser must check for this wrap-around before using the result.'] : null,
      ])}`;
    }
    const onInput = () => {
      s.value = vIn.value;
      s.to = aIn.value;
      persistNum();
      show();
    };
    vIn.addEventListener('input', onInput);
    aIn.addEventListener('input', onInput);
    panel.addEventListener('click', (e) => {
      const b = e.target.closest('[data-al]');
      if (!b) return;
      aIn.value = b.dataset.al;
      onInput();
    });
    show();
  }

  // ---- flags ----
  function tabFlags(panel) {
    const s = num.flags;
    const formats = ['Mach-O', 'ELF', 'PE'];
    panel.innerHTML = html`
      <div class="lnum-row">
        <label class="lnum-label">Field
          <select class="lnum-select" id="lnum-fl-table">${formats.map((fmt) => html`<optgroup label="${fmt}">${M.FLAG_TABLES.filter((t) => t.format === fmt).map((t) => html`<option value="${t.id}">${t.label}</option>`)}</optgroup>`)}</select></label>
        <label class="lnum-label">Value
          <input class="lnum-input lnum-input-mid" id="lnum-fl-v" type="text" spellcheck="false" maxlength="80" autocomplete="off" /></label>
      </div>
      <div id="lnum-fl-out"></div>`;
    const sel = panel.querySelector('#lnum-fl-table');
    const vIn = panel.querySelector('#lnum-fl-v');
    sel.value = s.table;
    vIn.value = s.text;
    let value = 0n;
    function show() {
      const out = panel.querySelector('#lnum-fl-out');
      const d = M.decodeFlags(s.table, value);
      const all = d.table.flags.slice().sort((a, b) => (a.mask < b.mask ? -1 : 1));
      keepFocus(panel, () => {
        out.innerHTML = html`${kv([
          ['Value', html`${M.hex(d.value, d.table.bits)} <span class="lnum-dim">· ${d.table.bits}-bit field</span>`],
          ['Set', d.set.length ? d.set.map((f) => f.name).join(' | ') : html`<span class="lnum-dim">no named flag is set</span>`],
          ...d.fields.map((f) => [f.name, html`${f.text} <span class="lnum-dim">· (value & ${bx(f.mask)}) = ${bx(f.raw)} after shifting: a number stored in a group of bits, not independent flags</span>`]),
          d.unknown ? ['Bits without a name', html`${bx(d.unknown)} <span class="lnum-dim">· set, but not defined in this table (reserved, newer than the table, or not a valid value)</span>`] : null,
        ])}
        <div class="lnum-flags" role="group" aria-label="Flags">${all.map((f, i) => {
          const on = (d.value & f.mask) === f.mask;
          return html`<label class="lnum-flag ${on ? 'lnum-on' : ''}" title="${f.desc}"><input type="checkbox" data-mask="${bx(f.mask)}" data-fk="fl${i}" ${on ? html`checked` : ''} /><span class="lnum-flag-mask">${M.hex(f.mask, d.table.bits)}</span><span class="lnum-flag-name">${f.name}</span><span class="lnum-dim">${f.desc}</span></label>`;
        })}</div>
        <div class="lnum-note">A flag is set when (value & mask) is not 0. Each mask is a single bit, so the value is the bitwise OR (here also the sum) of the masks that are set.</div>`;
      });
    }
    function parse() {
      const table = M.FLAG_TABLES.find((t) => t.id === s.table);
      const p = M.parseBig(vIn.value);
      const ok = p.ok && p.value >= 0n && p.value <= M.mask(table.bits);
      vIn.classList.toggle('lnum-bad', !ok);
      if (!ok) {
        panel.querySelector('#lnum-fl-out').innerHTML = html`<div class="lnum-note lnum-error">Type a non-negative number that fits in ${table.bits} bits.</div>`;
        return;
      }
      value = p.value;
      s.text = vIn.value;
      persistNum();
      show();
    }
    vIn.addEventListener('input', parse);
    sel.addEventListener('change', () => {
      s.table = sel.value;
      parse();
    });
    panel.addEventListener('change', (e) => {
      const box = e.target.closest('input[data-mask]');
      if (!box) return;
      const mask = B(box.dataset.mask);
      value = box.checked ? value | mask : value & ~mask;
      const table = M.FLAG_TABLES.find((t) => t.id === s.table);
      vIn.value = M.hex(value, table.bits);
      s.text = vIn.value;
      persistNum();
      show();
    });
    parse();
  }

  // ---- address arithmetic ----
  const ADDR_PRESETS = {
    pe: { label: 'PE example', imageBase: '0x140000000', sectionAlign: '0x1000', fileAlign: '0x200', query: '0x140002010', mode: 'va', rows: [
      ['headers', '0x140000000', '0x400', '0x0', '0x400'], ['.text', '0x140001000', '0x1a3c', '0x400', '0x1c00'],
      ['.rdata', '0x140003000', '0x8e2', '0x2000', '0xa00'], ['.data', '0x140004000', '0x2400', '0x2a00', '0x200']] },
    elf: { label: 'ELF example', imageBase: '0x400000', sectionAlign: '0x1000', fileAlign: '0x1000', query: '0x401020', mode: 'va', rows: [
      ['LOAD r--', '0x400000', '0x5a8', '0x0', '0x5a8'], ['LOAD r-x', '0x401000', '0x1c5', '0x1000', '0x1c5'],
      ['LOAD rw-', '0x403e10', '0x230', '0x2e10', '0x220']] },
    macho: { label: 'Mach-O example', imageBase: '0x100000000', sectionAlign: '0x4000', fileAlign: '0x4000', query: '0x100003f50', mode: 'va', rows: [
      ['__PAGEZERO', '0x0', '0x100000000', '0x0', '0x0'], ['__TEXT', '0x100000000', '0x4000', '0x0', '0x4000'],
      ['__DATA', '0x100004000', '0x8000', '0x4000', '0x4000'], ['__LINKEDIT', '0x10000c000', '0x4000', '0x8000', '0x2b0']] },
  };
  function addrFromPreset(id) {
    const p = ADDR_PRESETS[id];
    // alignRule: what "aligned" means for the layout. PE and Mach-O require every range to START on a
    // multiple of the alignment. ELF does not: a PT_LOAD may start anywhere, and the rule is that
    // p_vaddr and p_offset are congruent modulo p_align (the example's rw- segment starts at 0x403e10).
    return { imageBase: p.imageBase, sectionAlign: p.sectionAlign, fileAlign: p.fileAlign, query: p.query, mode: p.mode, rows: p.rows.map((r) => r.slice()), source: p.label,
      alignRule: id === 'elf' ? 'congruent' : 'start' };
  }
  function addrFromDocument() {
    const slice = BS.getActiveSlice();
    if (!slice || !Array.isArray(slice.segments) || !slice.segments.length) return null;
    const big = (v) => {
      try {
        return typeof v === 'string' ? B(v) : B(Math.trunc(Number(v) || 0));
      } catch (err) {
        return 0n;
      }
    };
    const rows = slice.segments.slice(0, 24).map((seg) => [String(seg.segname || '').slice(0, 32), bx(big(seg.vmaddr)), bx(big(seg.vmsize)), bx(big(seg.fileoff)), bx(big(seg.filesize))]);
    // the tool uses the first __TEXT segment, or else the first segment that is not __PAGEZERO, as the base for RVAs
    const text = slice.segments.find((seg) => seg.segname === '__TEXT') || slice.segments.find((seg) => seg.segname !== '__PAGEZERO');
    const base = text ? big(text.vmaddr) : 0n;
    const fmt = String(slice.format || '').toUpperCase();
    const entry = slice.overview && slice.overview.entry_point_vmaddr ? String(slice.overview.entry_point_vmaddr) : bx(base);
    // Alignments come from the file where it states them, not from a guess:
    //   PE      OptionalHeader.SectionAlignment / FileAlignment
    //   ELF     the largest p_align of the program headers (one value: the rule is congruence)
    //   Mach-O  has no alignment field for segments; they are page-aligned, and the page is
    //           16 KiB for arm64 slices and 4 KiB for x86 ones
    const headerField = (name) => {
      const f = ((slice.header && slice.header.fields) || []).find((x) => x && x.name === name);
      return f && Number.isFinite(Number(f.raw_value)) && Number(f.raw_value) > 0 ? bx(big(Number(f.raw_value))) : null;
    };
    let sectionAlign = '0x1000';
    let fileAlign = '0x1000';
    if (fmt === 'PE') {
      sectionAlign = headerField('OptionalHeader.SectionAlignment') || '0x1000';
      fileAlign = headerField('OptionalHeader.FileAlignment') || '0x200';
    } else if (fmt === 'ELF') {
      let align = 0;
      slice.segments.forEach((seg) => (seg.fields || []).forEach((f) => {
        if (f && f.name === 'p_align' && Number.isFinite(Number(f.raw_value))) align = Math.max(align, Number(f.raw_value));
      }));
      sectionAlign = fileAlign = align > 1 ? bx(big(align)) : '0x1000';
    } else {
      sectionAlign = fileAlign = String(slice.arch_name || '').toLowerCase().startsWith('arm64') ? '0x4000' : '0x1000';
    }
    return { imageBase: bx(base), sectionAlign, fileAlign, query: entry, mode: 'va', rows, alignRule: fmt === 'ELF' ? 'congruent' : 'start',
      source: 'Open file' + (slice.segments.length > 24 ? ' (first 24 segments)' : '') + '. File offsets are relative to the start of this slice.' };
  }

  function tabAddr(panel) {
    if (!num.addr) num.addr = addrFromPreset('pe');
    const s = num.addr;
    const cols = ['Name', 'Virtual address', 'Virtual size', 'File offset', 'Size in file'];
    function draw() {
      panel.innerHTML = html`
        <div class="lnum-note">A loader copies ranges of the file to ranges of memory. Translating an address is finding the range it falls in and keeping the distance from the start of that range. This is the calculation the address translator of the tool performs.</div>
        <div class="lnum-row">
          ${Object.keys(ADDR_PRESETS).map((id) => html`<button type="button" class="lnum-btn" data-preset="${id}">${ADDR_PRESETS[id].label}</button>`)}
          ${BS.state.doc ? html`<button type="button" class="lnum-btn" data-preset="doc">Use the open file's segments</button>` : ''}
          <span class="lnum-dim">${s.source}</span>
        </div>
        <div class="lnum-row">
          <label class="lnum-label">Image base (where RVA 0 is)
            <input class="lnum-input lnum-input-mid" data-g="imageBase" type="text" spellcheck="false" maxlength="40" value="${s.imageBase}" /></label>
          <label class="lnum-label">Alignment in memory (PE SectionAlignment, page size)
            <input class="lnum-input lnum-input-small" data-g="sectionAlign" type="text" spellcheck="false" maxlength="40" value="${s.sectionAlign}" /></label>
          <label class="lnum-label">Alignment in the file (PE FileAlignment)
            <input class="lnum-input lnum-input-small" data-g="fileAlign" type="text" spellcheck="false" maxlength="40" value="${s.fileAlign}" /></label>
        </div>
        <div class="lnum-tablewrap"><table class="lnum-table lnum-addr-table"><thead><tr>${cols.map((c) => html`<th>${c}</th>`)}<th></th></tr></thead>
          <tbody id="lnum-ad-rows">${s.rows.map((r, i) => html`<tr data-row="${i}">${r.map((cell, c) => html`<td><input class="lnum-input" data-cell="${c}" data-fk="c${i}.${c}" type="text" spellcheck="false" maxlength="40" value="${cell}" aria-label="${cols[c]} of row ${i + 1}" /></td>`)}<td><button type="button" class="lnum-btn" data-del="${i}" data-fk="d${i}" aria-label="Remove row ${i + 1}">Remove</button></td></tr>`)}</tbody></table></div>
        <div class="lnum-row"><button type="button" class="lnum-btn" id="lnum-ad-add" ${s.rows.length >= 32 ? html`disabled` : ''}>Add a row</button></div>
        <ul class="lnum-rownotes" id="lnum-ad-notes" aria-label="What each row means"></ul>
        <div class="lnum-row">
          <label class="lnum-label">Translate
            <input class="lnum-input lnum-input-mid" data-g="query" id="lnum-ad-q" type="text" spellcheck="false" maxlength="40" value="${s.query}" /></label>
          <label class="lnum-label">It is a
            <select class="lnum-select" id="lnum-ad-mode"><option value="va">virtual address (VA)</option><option value="rva">relative virtual address (RVA)</option><option value="offset">file offset</option></select></label>
        </div>
        <div id="lnum-ad-out"></div>`;
      panel.querySelector('#lnum-ad-mode').value = s.mode;
      compute();
    }
    function compute() {
      const out = panel.querySelector('#lnum-ad-out');
      const get = (text) => {
        const p = M.parseBig(text);
        return p.ok && p.value >= 0n && p.value <= M.mask(64) ? p.value : null;
      };
      const base = get(s.imageBase);
      const sa = get(s.sectionAlign);
      const fa = get(s.fileAlign);
      const q = get(s.query);
      panel.querySelectorAll('[data-g]').forEach((el) => el.classList.toggle('lnum-bad', get(el.value) === null));
      const segments = [];
      const rowNotes = [];
      let bad = base === null || q === null;
      s.rows.forEach((r, i) => {
        const nums = r.slice(1).map(get);
        const tr = panel.querySelector('tr[data-row="' + i + '"]');
        nums.forEach((n, c) => tr.querySelector('[data-cell="' + (c + 1) + '"]').classList.toggle('lnum-bad', n === null));
        const label = r[0] || 'row ' + (i + 1);
        if (nums.includes(null)) {
          bad = true;
          rowNotes.push(label + ': not a number');
          return;
        }
        const [vmaddr, vmsize, fileoff, filesize] = nums;
        segments.push({ name: r[0], vmaddr, vmsize, fileoff, filesize });
        const notes = ['memory ' + bx(vmaddr) + ' .. ' + bx(vmaddr + vmsize) + (filesize > 0n ? ', file ' + bx(fileoff) + ' .. ' + bx(fileoff + filesize) : ', no bytes in the file')];
        if (s.alignRule === 'congruent') {
          // ELF: a segment need not start on a page boundary; its address and file offset must agree modulo p_align.
          if (sa && sa > 0n && filesize > 0n && vmaddr % sa !== fileoff % sa) notes.push('VA and file offset differ modulo ' + bx(sa) + ' (ELF requires p_vaddr and p_offset to be congruent modulo p_align)');
        } else {
          if (sa && sa > 0n && vmaddr % sa !== 0n) notes.push('VA is not a multiple of ' + bx(sa));
          if (fa && fa > 0n && filesize > 0n && fileoff % fa !== 0n) notes.push('file offset is not a multiple of ' + bx(fa));
        }
        if (filesize > vmsize) notes.push('more bytes in the file than in memory: the extra ' + bx(filesize - vmsize) + ' are not mapped by this rule');
        else if (filesize < vmsize) notes.push(bx(vmsize - filesize) + ' byte(s) of memory beyond the file data are zero-filled');
        if (sa && sa > 0n) notes.push('next aligned VA after it: ' + bx(M.alignUp(vmaddr + vmsize, sa)));
        rowNotes.push(label + ': ' + notes.join('; '));
      });
      const notesEl = panel.querySelector('#lnum-ad-notes');
      notesEl.replaceChildren(...rowNotes.map((text) => {
        const li = doc.createElement('li');
        li.textContent = text;
        return li;
      }));
      if (bad) {
        out.innerHTML = html`<div class="lnum-note lnum-error">Fill every field with a non-negative number (decimal or 0x hex).</div>`;
        return;
      }
      const r = M.translate({ imageBase: base, segments }, s.mode, q);
      const cls = r.status === 'MAPPED' ? '' : r.status === 'UNMAPPED_ZEROFILL' ? 'lnum-warn' : 'lnum-bad';
      const seg = r.segment >= 0 ? segments[r.segment] : null;
      out.innerHTML = html`${kv([
        ['Result', html`<span class="lnum-status ${cls}">${r.status}</span> ${seg ? html`<span class="lnum-dim">in ${seg.name || 'row ' + (r.segment + 1)}</span>` : ''}`],
        ['Virtual address', r.va === null ? html`<span class="lnum-dim">none</span>` : bx(r.va)],
        ['RVA', r.rva === null ? html`<span class="lnum-dim">none</span>` : r.rva < 0n ? html`-${bx(-r.rva)} <span class="lnum-dim">· below the image base</span>` : bx(r.rva)],
        ['File offset', r.offset === null ? html`<span class="lnum-dim">none: no byte of the file holds this address</span>` : bx(r.offset)],
      ])}
      <div><div class="lenc-subhead">Step by step</div><ol class="lnum-steps">${r.steps.map((t) => html`<li>${t}</li>`)}</ol></div>
      <div class="lnum-note">Rows are tried in order and the first match wins, as in the tool. __PAGEZERO is skipped for addresses: it reserves address space and maps nothing. In a PE file the stored section addresses are RVAs; add ImageBase to get the VA column used here.</div>`;
    }
    panel.oninput = (e) => {
      const t = e.target;
      if (t.dataset.g) s[t.dataset.g] = t.value;
      else if (t.dataset.cell) {
        const tr = t.closest('tr[data-row]');
        s.rows[Number(tr.dataset.row)][Number(t.dataset.cell)] = t.value;
      } else return;
      s.source = t.dataset.g === 'query' ? s.source : 'Edited';
      compute();
    };
    panel.onchange = (e) => {
      if (e.target.id === 'lnum-ad-mode') {
        s.mode = e.target.value;
        compute();
      }
    };
    panel.onclick = (e) => {
      const preset = e.target.closest('[data-preset]');
      if (preset) {
        const next = preset.dataset.preset === 'doc' ? addrFromDocument() : addrFromPreset(preset.dataset.preset);
        if (!next) return BS.ui.toast('The open file has no segments to use.', 'info');
        num.addr = next;
        Object.assign(s, next);
        return keepFocus(panel, draw);
      }
      const del = e.target.closest('[data-del]');
      if (del) {
        s.rows.splice(Number(del.dataset.del), 1);
        s.source = 'Edited';
        return keepFocus(panel, draw);
      }
      if (e.target.id === 'lnum-ad-add' && s.rows.length < 32) {
        s.rows.push(['', '0x0', '0x0', '0x0', '0x0']);
        s.source = 'Edited';
        draw();
        const inputs = panel.querySelectorAll('tr[data-row="' + (s.rows.length - 1) + '"] input');
        if (inputs[0]) inputs[0].focus();
      }
      return undefined;
    };
    draw();
  }

  const TAB_RENDER = { int: tabInt, float: tabFloat, leb: tabLeb, align: tabAlign, flags: tabFlags, addr: tabAddr };

  function renderNumbersView(bodyEl, ctx) {
    const wanted = ctx.params && ctx.params.tab;
    if (TABS.some((t) => t.id === wanted)) num.tab = wanted;
    bodyEl.innerHTML = html`<div class="lnum-root">
      <div class="lnum-tabs" role="tablist" aria-label="Topics">${TABS.map((t) => html`<button type="button" role="tab" class="lnum-tab" id="lnum-tab-${t.id}" data-tab="${t.id}" aria-selected="${t.id === num.tab ? 'true' : 'false'}" aria-controls="lnum-panel" tabindex="${t.id === num.tab ? '0' : '-1'}">${t.label}</button>`)}</div>
      <div class="lnum-panel" id="lnum-panel" role="tabpanel" aria-labelledby="lnum-tab-${num.tab}"></div>
    </div>`;
    const tabs = bodyEl.querySelector('.lnum-tabs');
    function select(id, focus) {
      num.tab = id;
      persistNum();
      tabs.querySelectorAll('.lnum-tab').forEach((b) => {
        const on = b.dataset.tab === id;
        b.setAttribute('aria-selected', on ? 'true' : 'false');
        b.tabIndex = on ? 0 : -1;
        if (on && focus) b.focus();
      });
      // a fresh panel element drops the previous tab's listeners
      const old = bodyEl.querySelector('#lnum-panel');
      const panel = old.cloneNode(false);
      panel.setAttribute('aria-labelledby', 'lnum-tab-' + id);
      old.replaceWith(panel);
      TAB_RENDER[id](panel);
    }
    tabs.addEventListener('click', (e) => {
      const b = e.target.closest('.lnum-tab');
      if (b) select(b.dataset.tab, false);
    });
    tabs.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight' && e.key !== 'Home' && e.key !== 'End') return;
      const i = TABS.findIndex((t) => t.id === num.tab);
      const n = e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1 : (i + (e.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length;
      e.preventDefault();
      select(TABS[n].id, true);
    });
    select(num.tab, false);
  }

  BS.registerView({
    id: 'labs.numbers', title: 'Data representation', icon: 'NUM', group: 'Labs', order: 310,
    subtitle: 'Integers, floating point, LEB128, alignment, flags and address arithmetic',
    render: renderNumbersView,
  });

  // -------------------------------------------------------------------------------------
  // Commands
  // -------------------------------------------------------------------------------------
  const hasDoc = () => Boolean(BS.state.doc);
  BS.registerCommand({
    id: 'labs.encoding.open', title: 'Encoding lab: explore an instruction encoding', section: 'Labs',
    hint: 'Break machine code into its bit fields', keywords: 'opcode modrm sib rex arm64 aarch64 x86 bits fields decode instruction',
    run: () => BS.nav.openView('labs.encoding'),
  });
  BS.registerCommand({
    id: 'labs.encoding.cursor', title: 'Encoding lab: decode the bytes at the cursor', section: 'Labs',
    keywords: 'opcode instruction bits fields decode hex cursor', when: hasDoc,
    run: () => BS.nav.openView('labs.encoding', { from: 'cursor', at: String(BS.state.cursorOffset || 0) }),
  });
  BS.registerCommand({
    id: 'labs.encoding.entry', title: 'Encoding lab: decode the bytes at the entry point', section: 'Labs',
    keywords: 'opcode instruction bits fields decode start main entry',
    when: () => {
      const slice = BS.getActiveSlice();
      return Boolean(slice && slice.overview && slice.overview.entry_point_abs_offset !== undefined && slice.overview.entry_point_abs_offset !== null);
    },
    run: () => BS.nav.openView('labs.encoding', { from: 'entry' }),
  });
  TABS.forEach((t) => {
    BS.registerCommand({
      id: 'labs.numbers.' + t.id, title: 'Number lab: ' + t.label.toLowerCase(), section: 'Labs', keywords: t.keywords + ' data representation playground',
      run: () => BS.nav.openView('labs.numbers', { tab: t.id }),
    });
  });
})(typeof window !== 'undefined' ? window : null);
