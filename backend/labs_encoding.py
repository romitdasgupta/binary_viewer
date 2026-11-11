"""
Encoding lab: field-by-field breakdown of AArch64 and x86 / x86-64 machine code.

Nothing here executes anything. `decode_bytes` takes raw bytes and returns, for
each instruction, the decoded text plus a list of fields that attributes every
bit of the encoding to its role, together with the arithmetic behind computed
values (sign extension, shifts, PC-relative targets).

The tables in this module are written from the architecture manuals (Arm ARM
"A64 instruction set encoding", Intel SDM vol. 2 opcode maps) and cover the
instructions compilers emit most often. They are validated against
llvm-objdump (see tests/test_labs_encoding.py). Anything outside the tables is
reported as "not decoded" rather than guessed:

  * status "decoded"      every bit attributed, text produced by this module
  * status "partial"      the encoding class and its fields are known, but one
                          part (named in `gaps`) is not interpreted
  * status "not_decoded"  only the top-level group (AArch64) or the prefixes
                          (x86) are known; for x86 the length is then unknown,
                          so decoding of the byte stream stops there
  * status "truncated"    the bytes end in the middle of an instruction

Pure Python 3.9 standard library; runs unchanged under Pyodide.
"""

import struct
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import runtime
from .runtime import BadRequest

MAX_INPUT_BYTES = 256      # bytes decoded per request
MAX_INSTRUCTIONS = 64      # instructions returned per request
MAX_HEX_CHARS = 4096       # characters of hex text accepted (separators included)
MAX_BODY_BYTES = 16384     # request body

ARCHS = ("arm64", "x86_64", "x86")
ARCH_LABELS = {"arm64": "AArch64 (A64)", "x86_64": "x86-64 (64-bit mode)", "x86": "x86 (32-bit protected mode)"}

_M64 = (1 << 64) - 1


def _sx(value: int, bits: int) -> int:
    """Sign-extend the low `bits` bits of value."""
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def _hx(value: int) -> str:
    return "-0x%x" % -value if value < 0 else "0x%x" % value


def _binstr(value: int, width: int) -> str:
    return format(value & ((1 << width) - 1), "0%db" % width)


# ===========================================================================
# AArch64
# ===========================================================================
_CONDS = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
_COND_TEXT = [
    "equal (Z == 1)", "not equal (Z == 0)", "unsigned higher or same / carry set (C == 1)",
    "unsigned lower / carry clear (C == 0)", "minus, negative (N == 1)", "plus, positive or zero (N == 0)",
    "overflow (V == 1)", "no overflow (V == 0)", "unsigned higher (C == 1 and Z == 0)",
    "unsigned lower or same (C == 0 or Z == 1)", "signed greater or equal (N == V)", "signed less than (N != V)",
    "signed greater than (Z == 0 and N == V)", "signed less or equal (Z == 1 or N != V)",
    "always", "always (encoding 1111 behaves as 'always', it is not 'never')",
]
_SHIFTS = ["lsl", "lsr", "asr", "ror"]
_EXTENDS = ["uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"]


def _X(n: int, sp: bool = False) -> str:
    return ("sp" if sp else "xzr") if n == 31 else "x%d" % n


def _W(n: int, sp: bool = False) -> str:
    return ("wsp" if sp else "wzr") if n == 31 else "w%d" % n


def _R(sf: int, n: int, sp: bool = False) -> str:
    return _X(n, sp) if sf else _W(n, sp)


def _imm(value: int) -> str:
    return "#" + _hx(value)


class _A64Out:
    """What a class handler fills in."""

    __slots__ = ("mn", "ops", "meaning", "steps", "notes", "target", "status", "gaps", "kinds", "form", "lite",
                 "target_kind")

    def __init__(self, lite: bool = False) -> None:
        self.lite = lite            # text only: skip the per-field explanations (the disassembler's fast path)
        self.target_kind: Optional[str] = None   # "branch" (control flow goes there) or "data" (an address is formed)
        self.mn = ""
        self.ops = ""
        self.meaning: Dict[str, str] = {}
        self.steps: List[str] = []
        self.notes: List[str] = []
        self.target: Optional[int] = None
        self.status = "decoded"
        self.gaps: List[str] = []
        self.kinds: Dict[str, str] = {}
        self.form = ""

    # -- field explanations -------------------------------------------------
    def sf(self, sf: int, name: str = "sf") -> None:
        if self.lite:
            return
        self.kinds[name] = "opc"
        self.meaning[name] = (
            "%s = 1: 64-bit operation, X registers." % name if sf else
            "%s = 0: 32-bit operation, W registers. Writing a W register zeroes the upper 32 bits of the X register." % name)

    def reg(self, field: str, n: int, shown: str, role: str, sp: Optional[bool]) -> None:
        """sp: True -> 31 is the stack pointer here, False -> the zero register, None -> an ordinary number (SIMD/FP)."""
        if self.lite:
            return
        self.kinds[field] = "reg"
        text = "%s = %d: %s, %s." % (field, n, shown, role)
        if sp is True:
            text += (" Register number 31 means the stack pointer in this operand position." if n == 31 else
                     " In this operand position register number 31 would be the stack pointer, not the zero register.")
        elif sp is False:
            text += (" Register number 31 means the zero register in this operand position: it reads as 0 and writes are discarded."
                     if n == 31 else
                     " In this operand position register number 31 would be the zero register, not the stack pointer.")
        self.meaning[field] = text

    def cond(self, field: str, c: int, extra: str = "") -> None:
        if self.lite:
            return
        self.kinds[field] = "cond"
        self.meaning[field] = "%s = %s: condition '%s', true when %s.%s" % (
            field, _binstr(c, 4), _CONDS[c], _COND_TEXT[c], (" " + extra) if extra else "")

    def opc(self, field: str, text: str) -> None:
        self.kinds[field] = "opc"
        self.meaning[field] = text

    def imm(self, field: str, text: str) -> None:
        self.kinds[field] = "imm"
        self.meaning[field] = text

    def partial(self, gap: str) -> None:
        self.status = "partial"
        self.gaps.append(gap)


def _a64_branch_target(o: _A64Out, pc: int, field: str, raw: int, bits: int, what: str) -> int:
    off = _sx(raw, bits) * 4
    target = (pc + off) & _M64
    o.target = target
    o.target_kind = "branch"
    if o.lite:
        return target
    o.imm(field, "%s = 0x%x: a signed %d-bit count of instructions (words), relative to the address of this instruction."
          % (field, raw, bits))
    o.steps.append("%s = %s (%d bits)" % (field, _binstr(raw, bits), bits))
    o.steps.append("offset = SignExtend(%s, %d) * 4 = %d * 4 = %s bytes" % (field, bits, _sx(raw, bits), _hx(off)))
    o.steps.append("%s = PC + offset = 0x%x %s 0x%x = 0x%x" % (what, pc, "-" if off < 0 else "+", abs(off), target))
    o.notes.append("Instructions are 4 bytes and 4-byte aligned, so the low two bits of a branch offset are always 0 "
                   "and are not stored; that is why the field is multiplied by 4.")
    o.target = target
    return target


# --- data processing, immediate -------------------------------------------
def _h_pcrel(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    op, immlo, immhi, rd = f["op"], f["immlo"], f["immhi"], f["Rd"]
    raw = (immhi << 2) | immlo
    imm = _sx(raw, 21)
    o.opc("op", "op = 1: ADRP, the result is a 4 KiB page address." if op else "op = 0: ADR, the result is a byte address.")
    o.imm("immlo", "immlo = %s: the low 2 bits of the 21-bit immediate. They sit apart from the rest, at bits 30:29." % _binstr(immlo, 2))
    o.imm("immhi", "immhi = 0x%x: the high 19 bits of the 21-bit immediate." % immhi)
    o.reg("Rd", rd, _X(rd), "destination", False)
    o.steps.append("imm21 = immhi:immlo = %s:%s = %s" % (_binstr(immhi, 19), _binstr(immlo, 2), _binstr(raw, 21)))
    if op:
        base = pc & ~0xFFF & _M64
        off = imm << 12
        target = (base + off) & _M64
        o.mn = "adrp"
        o.steps.append("offset = SignExtend(imm21, 21) << 12 = %d << 12 = %s" % (imm, _hx(off)))
        o.steps.append("page base = PC with its low 12 bits cleared = 0x%x & ~0xfff = 0x%x" % (pc, base))
        o.steps.append("result = page base + offset = 0x%x %s 0x%x = 0x%x" % (base, "-" if off < 0 else "+", abs(off), target))
        o.notes.append("ADRP only produces the page. The low 12 bits of the final address come from the next instruction, "
                       "typically ADD (address of data) or LDR/STR (scaled 12-bit offset).")
        o.form = "ADRP <Xd>, <label>"
    else:
        target = (pc + imm) & _M64
        o.mn = "adr"
        o.steps.append("offset = SignExtend(imm21, 21) = %s bytes" % _hx(imm))
        o.steps.append("result = PC + offset = 0x%x %s 0x%x = 0x%x" % (pc, "-" if imm < 0 else "+", abs(imm), target))
        o.form = "ADR <Xd>, <label>"
    o.ops = "%s, 0x%x" % (_X(rd), target)
    o.target = target
    o.target_kind = "data"
    return True


def _h_addsub_imm(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, op, s, sh, imm12, rn, rd = f["sf"], f["op"], f["S"], f["sh"], f["imm12"], f["Rn"], f["Rd"]
    o.sf(sf)
    o.opc("op", "op = 1: subtract." if op else "op = 0: add.")
    o.opc("S", "S = 1: set the NZCV flags from the result." if s else "S = 0: flags are not changed.")
    o.opc("sh", "sh = 1: the immediate is shifted left by 12 (imm12 << 12)." if sh else "sh = 0: the immediate is used as is (no shift).")
    value = imm12 << (12 if sh else 0)
    o.imm("imm12", "imm12 = 0x%x: unsigned 12-bit immediate; with sh = %d the operand value is 0x%x." % (imm12, sh, value))
    o.reg("Rn", rn, _R(sf, rn, True), "first operand", True)
    o.reg("Rd", rd, _R(sf, rd, not s), "destination", not s)
    if s:
        o.notes.append("With S = 1 the destination is the zero register when Rd = 31 (the result is discarded: that is CMP / CMN). "
                       "With S = 0, Rd = 31 is the stack pointer.")
    shift = ", lsl #12" if sh else ""
    o.form = "%s%s <Rd|SP>, <Rn|SP>, #<imm12>{, LSL #12}" % ("SUB" if op else "ADD", "S" if s else "")
    if s and rd == 31:
        o.mn = "cmp" if op else "cmn"
        o.ops = "%s, %s%s" % (_R(sf, rn, True), _imm(imm12), shift)
        o.notes.append("%s is an alias of %s with Rd = 31 (zero register)." % (o.mn.upper(), "SUBS" if op else "ADDS"))
    elif not op and not s and imm12 == 0 and not sh and (rd == 31 or rn == 31):
        o.mn = "mov"
        o.ops = "%s, %s" % (_R(sf, rd, True), _R(sf, rn, True))
        o.notes.append("MOV to or from SP is an alias of ADD with a zero immediate. (MOV between ordinary registers is a different "
                       "encoding: ORR with the zero register.)")
    else:
        o.mn = ("sub" if op else "add") + ("s" if s else "")
        o.ops = "%s, %s, %s%s" % (_R(sf, rd, not s), _R(sf, rn, True), _imm(imm12), shift)
    return True


def _decode_bit_masks(n: int, imms: int, immr: int, regsize: int) -> Optional[Tuple[int, int, int, int]]:
    """Arm ARM DecodeBitMasks for a logical immediate: (wmask, esize, S, R), or None if reserved."""
    combined = (n << 6) | ((~imms) & 0x3F)
    length = combined.bit_length() - 1
    if length < 1:
        return None
    esize = 1 << length
    if esize > regsize:
        return None
    levels = esize - 1
    s_val = imms & levels
    r_val = immr & levels
    if s_val == levels:
        return None
    welem = (1 << (s_val + 1)) - 1
    emask = (1 << esize) - 1
    if r_val:
        welem = ((welem >> r_val) | (welem << (esize - r_val))) & emask
    wmask = 0
    for i in range(regsize // esize):
        wmask |= welem << (i * esize)
    return wmask, esize, s_val, r_val


def _is_any_movw_alias(value: int, regsize: int) -> bool:
    """True when `value` can be written by a single MOVZ or MOVN; then MOV is reserved for that encoding and an
    ORR of the same constant is shown as ORR (the rule llvm applies)."""
    mask = (1 << regsize) - 1
    value &= mask
    inverted = (~value) & mask
    for shift in range(0, regsize, 16):
        if (value & ~(0xFFFF << shift)) == 0 or (inverted & ~(0xFFFF << shift)) == 0:
            return True
    return False


def _h_logical_imm(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, opc, n, immr, imms, rn, rd = f["sf"], f["opc"], f["N"], f["immr"], f["imms"], f["Rn"], f["Rd"]
    regsize = 64 if sf else 32
    if not sf and n:
        return False
    dm = _decode_bit_masks(n, imms, immr, regsize)
    if dm is None:
        return False
    wmask, esize, s_val, r_val = dm
    names = ["and", "orr", "eor", "ands"]
    o.sf(sf)
    o.opc("opc", "opc = %s: %s." % (_binstr(opc, 2), names[opc].upper()))
    o.imm("N", "N = %d: together with imms it selects the element size of the repeating bit pattern (here %d bits)." % (n, esize))
    o.imm("immr", "immr = %d: rotate the element right by %d bit(s)." % (immr, r_val))
    o.imm("imms", "imms = %s: after the element-size prefix, the run length minus one (%d ones)." % (_binstr(imms, 6), s_val + 1))
    o.reg("Rn", rn, _R(sf, rn), "first operand", False)
    o.reg("Rd", rd, _R(sf, rd, opc != 3), "destination", opc != 3)
    o.steps.append("element size = %d bits (from N:NOT(imms) = %s: position of the highest set bit)" % (esize, _binstr((n << 6) | ((~imms) & 0x3F), 7)))
    o.steps.append("element = %d one bit(s), rotated right by %d = 0x%x" % (s_val + 1, r_val, wmask & ((1 << esize) - 1)))
    o.steps.append("immediate = element repeated %d time(s) to %d bits = 0x%x" % (regsize // esize, regsize, wmask))
    o.notes.append("Logical immediates are not stored as a number. Only values that are a rotated run of ones, repeated across the "
                   "register, can be encoded; every other constant needs MOVZ/MOVK or a literal load.")
    o.form = "%s <Rd%s>, <Rn>, #<bitmask>" % (names[opc].upper(), "" if opc == 3 else "|SP")
    signed = _sx(wmask, regsize)
    if opc == 3 and rd == 31:
        o.mn = "tst"
        o.ops = "%s, #0x%x" % (_R(sf, rn), wmask)
        o.notes.append("TST is an alias of ANDS with Rd = 31 (zero register).")
    elif opc == 1 and rn == 31 and not _is_any_movw_alias(wmask, regsize):
        o.mn = "mov"
        o.ops = "%s, %s" % (_R(sf, rd, True), _imm(signed))
        o.notes.append("MOV (bitmask immediate) is an alias of ORR with Rn = 31 (zero register). It is only used when the "
                       "constant cannot be produced by a single MOVZ or MOVN.")
    else:
        o.mn = names[opc]
        o.ops = "%s, %s, #0x%x" % (_R(sf, rd, opc != 3), _R(sf, rn), wmask)
    return True


def _h_movewide(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, opc, hw, imm16, rd = f["sf"], f["opc"], f["hw"], f["imm16"], f["Rd"]
    if opc == 1 or (not sf and hw > 1):
        return False
    regsize = 64 if sf else 32
    shift = hw * 16
    names = {0: "movn", 2: "movz", 3: "movk"}
    o.sf(sf)
    o.opc("opc", {0: "opc = 00: MOVN, write NOT(imm16 << shift).",
                  2: "opc = 10: MOVZ, write imm16 << shift and zero every other bit.",
                  3: "opc = 11: MOVK, replace 16 bits and keep the other bits of the register."}[opc])
    o.imm("hw", "hw = %d: the 16-bit immediate goes to bit position %d (hw * 16)." % (hw, shift))
    o.imm("imm16", "imm16 = 0x%x: 16-bit immediate." % imm16)
    o.reg("Rd", rd, _R(sf, rd), "destination", False)
    o.form = "%s <Rd>, #<imm16>{, LSL #<shift>}" % names[opc].upper()
    lsl = ", lsl #%d" % shift if shift else ""
    mask = (1 << regsize) - 1
    if opc == 2:
        value = (imm16 << shift) & mask
        o.steps.append("value = imm16 << (hw * 16) = 0x%x << %d = 0x%x" % (imm16, shift, value))
        if not (imm16 == 0 and hw != 0):
            o.mn, o.ops = "mov", "%s, %s" % (_R(sf, rd), _imm(_sx(value, regsize)))
            o.notes.append("MOV (wide immediate) is the preferred way to write this MOVZ. Disassemblers print the value as a "
                           "signed %d-bit number, so a value with the top bit set is shown negative." % regsize)
            return True
    elif opc == 0:
        value = (~(imm16 << shift)) & mask
        o.steps.append("value = NOT(imm16 << (hw * 16)) = NOT(0x%x) = 0x%x (%d as a signed %d-bit number)"
                       % (imm16 << shift, value, _sx(value, regsize), regsize))
        if not (imm16 == 0 and hw != 0) and not (not sf and imm16 == 0xFFFF):
            o.mn, o.ops = "mov", "%s, %s" % (_R(sf, rd), _imm(_sx(value, regsize)))
            o.notes.append("MOV (inverted wide immediate) is the preferred way to write this MOVN.")
            return True
    else:
        o.steps.append("bits [%d:%d] of %s = 0x%x; other bits unchanged" % (shift + 15, shift, _R(sf, rd), imm16))
    o.mn, o.ops = names[opc], "%s, %s%s" % (_R(sf, rd), _imm(imm16), lsl)
    return True


def _h_bitfield(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, opc, n, immr, imms, rn, rd = f["sf"], f["opc"], f["N"], f["immr"], f["imms"], f["Rn"], f["Rd"]
    if opc == 3 or n != sf:
        return False
    regsize = 64 if sf else 32
    if not sf and ((immr & 0x20) or (imms & 0x20)):
        return False
    base = ["sbfm", "bfm", "ubfm"][opc]
    o.sf(sf)
    o.opc("opc", "opc = %s: %s (%s)." % (_binstr(opc, 2), base.upper(),
                                        ["signed bitfield move: the copied field is sign-extended",
                                         "bitfield move: bits of the destination outside the field are kept",
                                         "unsigned bitfield move: bits outside the field become 0"][opc]))
    o.opc("N", "N = %d: must equal sf." % n)
    o.imm("immr", "immr = %d: right-rotate amount." % immr)
    o.imm("imms", "imms = %d: index of the most significant bit of the source field." % imms)
    o.reg("Rn", rn, _R(sf, rn), "source", False)
    o.reg("Rd", rd, _R(sf, rd), "destination", False)
    o.form = "%s <Rd>, <Rn>, #<immr>, #<imms>" % base.upper()
    o.notes.append("Shifts by a constant, sign/zero extensions and bitfield extracts/inserts are all aliases of %s; "
                   "the disassembler picks the alias from immr and imms." % base.upper())
    rd_s, rn_s = _R(sf, rd), _R(sf, rn)
    top = regsize - 1
    if imms >= immr:
        lsb, width = immr, imms - immr + 1
        o.steps.append("imms >= immr: extract. lsb = immr = %d, width = imms - immr + 1 = %d" % (lsb, width))
    else:
        lsb, width = (regsize - immr) % regsize, imms + 1
        o.steps.append("imms < immr: insert in zero. lsb = (%d - immr) mod %d = %d, width = imms + 1 = %d" % (regsize, regsize, lsb, width))
    if opc == 2:  # UBFM
        if imms == top:
            o.mn, o.ops = "lsr", "%s, %s, #%d" % (rd_s, rn_s, immr)
        elif imms + 1 == immr:
            o.mn, o.ops = "lsl", "%s, %s, #%d" % (rd_s, rn_s, top - imms)
            o.steps.append("imms + 1 == immr: logical shift left by %d - imms = %d" % (top, top - imms))
        elif not sf and immr == 0 and imms in (7, 15):
            o.mn, o.ops = ("uxtb" if imms == 7 else "uxth"), "%s, %s" % (rd_s, rn_s)
        elif imms < immr:
            o.mn, o.ops = "ubfiz", "%s, %s, #%d, #%d" % (rd_s, rn_s, lsb, width)
        else:
            o.mn, o.ops = "ubfx", "%s, %s, #%d, #%d" % (rd_s, rn_s, lsb, width)
    elif opc == 0:  # SBFM
        if imms == top:
            o.mn, o.ops = "asr", "%s, %s, #%d" % (rd_s, rn_s, immr)
        elif immr == 0 and imms in (7, 15):
            o.mn, o.ops = ("sxtb" if imms == 7 else "sxth"), "%s, %s" % (rd_s, _W(rn))
        elif immr == 0 and imms == 31 and sf:
            o.mn, o.ops = "sxtw", "%s, %s" % (rd_s, _W(rn))
        elif imms < immr:
            o.mn, o.ops = "sbfiz", "%s, %s, #%d, #%d" % (rd_s, rn_s, lsb, width)
        else:
            o.mn, o.ops = "sbfx", "%s, %s, #%d, #%d" % (rd_s, rn_s, lsb, width)
    else:  # BFM
        if rn == 31 and (imms < immr or immr == 0):
            # immr == 0 with Rn = 31 could equally be written BFXIL Rd, zr, #0, #width; llvm prefers BFC there too.
            o.mn, o.ops = "bfc", "%s, #%d, #%d" % (rd_s, lsb, width)
            o.notes.append("BFC (clear a bitfield) is the alias used when the source is the zero register.")
        elif imms < immr:
            o.mn, o.ops = "bfi", "%s, %s, #%d, #%d" % (rd_s, rn_s, lsb, width)
        else:
            o.mn, o.ops = "bfxil", "%s, %s, #%d, #%d" % (rd_s, rn_s, lsb, width)
    return True


def _h_extract(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, n, rm, imms, rn, rd = f["sf"], f["N"], f["Rm"], f["imms"], f["Rn"], f["Rd"]
    if n != sf or (not sf and imms & 0x20):
        return False
    o.sf(sf)
    o.opc("N", "N = %d: must equal sf." % n)
    o.reg("Rm", rm, _R(sf, rm), "low part of the pair", False)
    o.imm("imms", "imms = %d: least significant bit of the extracted field inside the pair Rn:Rm." % imms)
    o.reg("Rn", rn, _R(sf, rn), "high part of the pair", False)
    o.reg("Rd", rd, _R(sf, rd), "destination", False)
    o.form = "EXTR <Rd>, <Rn>, <Rm>, #<lsb>"
    if rn == rm:
        o.mn, o.ops = "ror", "%s, %s, %s" % (_R(sf, rd), _R(sf, rn), _imm(imms))
        o.notes.append("ROR by a constant is an alias of EXTR with Rn == Rm.")
    else:
        o.mn, o.ops = "extr", "%s, %s, %s, %s" % (_R(sf, rd), _R(sf, rn), _R(sf, rm), _imm(imms))
    return True


# --- branches, exceptions, system -------------------------------------------
def _h_b(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    op = f["op"]
    o.opc("op", "op = 1: BL, also writes the return address (PC + 4) to x30." if op else "op = 0: B, plain branch.")
    target = _a64_branch_target(o, pc, "imm26", f["imm26"], 26, "target")
    o.mn, o.ops = ("bl" if op else "b"), "0x%x" % target
    o.form = "%s <label>" % ("BL" if op else "B")
    o.notes.append("Range: +/-128 MiB (26 bits * 4).")
    return True


def _h_bcond(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    if f["o0"]:
        return False
    cond = f["cond"]
    o.opc("o0", "o0 = 0: B.cond.")
    o.cond("cond", cond)
    target = _a64_branch_target(o, pc, "imm19", f["imm19"], 19, "target")
    o.mn, o.ops = "b." + _CONDS[cond], "0x%x" % target
    o.form = "B.<cond> <label>"
    o.notes.append("Range: +/-1 MiB (19 bits * 4).")
    return True


def _h_cbz(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, op, rt = f["sf"], f["op"], f["Rt"]
    o.sf(sf)
    o.opc("op", "op = 1: CBNZ, branch if the register is not zero." if op else "op = 0: CBZ, branch if the register is zero.")
    o.reg("Rt", rt, _R(sf, rt), "register tested", False)
    target = _a64_branch_target(o, pc, "imm19", f["imm19"], 19, "target")
    o.mn, o.ops = ("cbnz" if op else "cbz"), "%s, 0x%x" % (_R(sf, rt), target)
    o.form = "%s <Rt>, <label>" % o.mn.upper()
    return True


def _h_tbz(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    b5, op, b40, rt = f["b5"], f["op"], f["b40"], f["Rt"]
    bit = (b5 << 5) | b40
    o.imm("b5", "b5 = %d: bit 5 of the tested bit number; it also selects the register width (1 = X register)." % b5)
    o.opc("op", "op = 1: TBNZ, branch if the bit is 1." if op else "op = 0: TBZ, branch if the bit is 0.")
    o.imm("b40", "b40 = %d: bits 4:0 of the tested bit number." % b40)
    o.reg("Rt", rt, _R(b5, rt), "register tested", False)
    o.steps.append("bit number = b5:b40 = %d:%s = %d" % (b5, _binstr(b40, 5), bit))
    target = _a64_branch_target(o, pc, "imm14", f["imm14"], 14, "target")
    o.mn, o.ops = ("tbnz" if op else "tbz"), "%s, #0x%x, 0x%x" % (_R(b5, rt), bit, target)
    o.form = "%s <Rt>, #<bit>, <label>" % o.mn.upper()
    o.notes.append("Range: +/-32 KiB (14 bits * 4).")
    return True


def _h_branch_reg(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    opc, op2, op3, rn, op4 = f["opc"], f["op2"], f["op3"], f["Rn"], f["op4"]
    if op2 != 0x1F:
        return False
    plain = {0: "br", 1: "blr", 2: "ret"}
    o.opc("op2", "op2 = 11111: fixed for this class.")
    if op3 == 0 and op4 == 0 and opc in plain:
        o.opc("opc", "opc = %s: %s." % (_binstr(opc, 4), {0: "BR, branch to register", 1: "BLR, call through register (x30 = PC + 4)",
                                                         2: "RET, return (a branch that is hinted as a return)"}[opc]))
        o.opc("op3", "op3 = 000000: no pointer authentication.")
        o.reg("Rn", rn, _X(rn), "holds the target address", False)
        o.opc("op4", "op4 = 00000: unused, must be 0.")
        o.mn = plain[opc]
        o.ops = "" if (opc == 2 and rn == 30) else _X(rn)
        if opc == 2:
            o.notes.append("RET has an explicit register operand; x30 (the link register) is the default and is not printed.")
        o.form = "%s <Xn>" % o.mn.upper()
        return True
    if op3 in (2, 3):
        key = "b" if (op3 & 1) else "a"
        if opc in (0, 1) and op4 == 31:
            o.mn, o.ops = ("br" if opc == 0 else "blr") + "a" + key + "z", _X(rn)
            o.opc("opc", "opc = %s: %s with pointer authentication, zero modifier." % (_binstr(opc, 4), "BR" if opc == 0 else "BLR"))
            o.opc("op4", "op4 = 11111: no modifier register (the modifier is zero).")
            o.reg("Rn", rn, _X(rn), "holds the signed target address", False)
        elif opc == 2 and rn == 31 and op4 == 31:
            o.mn, o.ops = "reta" + key, ""
            o.opc("opc", "opc = 0010: RET with pointer authentication of x30, using SP as the modifier.")
            o.opc("op4", "op4 = 11111: fixed.")
            o.opc("Rn", "Rn = 11111: fixed for RETAA / RETAB (the register is always x30).")
        elif opc in (8, 9):
            o.mn, o.ops = ("br" if opc == 8 else "blr") + "a" + key, "%s, %s" % (_X(rn), _X(op4, True))
            o.opc("opc", "opc = %s: %s with pointer authentication and a modifier register." % (_binstr(opc, 4), "BR" if opc == 8 else "BLR"))
            o.reg("op4", op4, _X(op4, True), "modifier (context value mixed into the signature)", True)
            o.reg("Rn", rn, _X(rn), "holds the signed target address", False)
        else:
            return False
        o.opc("op3", "op3 = %s: authenticate first (ARMv8.3 pointer authentication), bit 10 selects the key: %s."
              % (_binstr(op3, 6), "IB" if op3 & 1 else "IA"))
        o.notes.append("The pointer's signature (PAC) in its unused high bits is checked before the branch; a bad signature "
                       "makes the address invalid so the branch faults.")
        o.form = o.mn.upper()
        return True
    return False


def _h_exception(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    opc, imm16, op2, ll = f["opc"], f["imm16"], f["op2"], f["LL"]
    table = {(0, 1): ("svc", "supervisor call (system call into EL1)"), (0, 2): ("hvc", "hypervisor call"),
             (0, 3): ("smc", "secure monitor call"), (1, 0): ("brk", "software breakpoint"), (2, 0): ("hlt", "halting debug breakpoint")}
    if op2 != 0 or (opc, ll) not in table:
        return False
    mn, what = table[(opc, ll)]
    o.opc("opc", "opc = %s and LL = %s select %s: %s." % (_binstr(opc, 3), _binstr(ll, 2), mn.upper(), what))
    o.opc("LL", "LL = %s: see opc." % _binstr(ll, 2))
    o.opc("op2", "op2 = 000: fixed.")
    o.imm("imm16", "imm16 = 0x%x: not used by the processor; the exception handler can read it from the syndrome register." % imm16)
    o.mn, o.ops = mn, _imm(imm16)
    o.form = "%s #<imm16>" % mn.upper()
    return True


_HINTS = {
    0: ("nop", "", "no operation"), 1: ("yield", "", "hint that the thread is spinning"), 2: ("wfe", "", "wait for event"),
    3: ("wfi", "", "wait for interrupt"), 4: ("sev", "", "send event"), 5: ("sevl", "", "send event local"),
    6: ("dgh", "", "data gathering hint"), 16: ("esb", "", "error synchronization barrier"),
    18: ("tsb", "csync", "trace synchronization barrier"), 20: ("csdb", "", "consumption of speculative data barrier"),
    7: ("xpaclri", "", "strip the PAC from x30"),
    8: ("pacia1716", "", "sign x17 with key IA, modifier x16"), 10: ("pacib1716", "", "sign x17 with key IB, modifier x16"),
    12: ("autia1716", "", "authenticate x17 with key IA, modifier x16"), 14: ("autib1716", "", "authenticate x17 with key IB, modifier x16"),
    24: ("paciaz", "", "sign x30 with key IA, zero modifier"), 25: ("paciasp", "", "sign x30 with key IA, modifier SP"),
    26: ("pacibz", "", "sign x30 with key IB, zero modifier"), 27: ("pacibsp", "", "sign x30 with key IB, modifier SP"),
    28: ("autiaz", "", "authenticate x30 with key IA, zero modifier"), 29: ("autiasp", "", "authenticate x30 with key IA, modifier SP"),
    30: ("autibz", "", "authenticate x30 with key IB, zero modifier"), 31: ("autibsp", "", "authenticate x30 with key IB, modifier SP"),
    32: ("bti", "", "branch target: accepts no indirect branch (only marks the location)"),
    34: ("bti", "c", "branch target for indirect calls (BLR) and for BR through x16 or x17"), 36: ("bti", "j", "branch target for indirect jumps (BR)"),
    38: ("bti", "jc", "branch target for indirect calls and jumps"),
}


def _h_hint(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    crm, op2 = f["CRm"], f["op2"]
    number = (crm << 3) | op2
    o.imm("CRm", "CRm = %s: high 4 bits of the hint number." % _binstr(crm, 4))
    o.imm("op2", "op2 = %s: low 3 bits of the hint number." % _binstr(op2, 3))
    o.steps.append("hint number = CRm:op2 = %s:%s = %d" % (_binstr(crm, 4), _binstr(op2, 3), number))
    o.notes.append("All 128 encodings in this space execute as NOP on a processor that does not implement them. That is why "
                   "PAC (PACIASP, AUTIBSP, ...) and BTI instructions were allocated here: code using them still runs on older cores.")
    o.form = "HINT #<imm7>"
    if number in _HINTS:
        mn, ops, what = _HINTS[number]
        o.mn, o.ops = mn, ops
        o.steps.append("hint %d = %s%s: %s" % (number, mn.upper(), (" " + ops) if ops else "", what))
    else:
        o.mn, o.ops = "hint", _imm(number)
        o.partial("Hint number %d has no name in this lab's table (it may be unallocated, or a newer extension); it is "
                  "shown in its generic form." % number)
    return True


_SYSREGS = {
    (3, 3, 13, 0, 2): "TPIDR_EL0", (3, 3, 13, 0, 3): "TPIDRRO_EL0", (3, 3, 4, 2, 0): "NZCV", (3, 3, 4, 4, 0): "FPCR",
    (3, 3, 4, 4, 1): "FPSR", (3, 3, 0, 0, 7): "DCZID_EL0", (3, 3, 0, 0, 1): "CTR_EL0", (3, 3, 14, 0, 2): "CNTVCT_EL0",
    (3, 3, 14, 0, 0): "CNTFRQ_EL0", (3, 0, 0, 0, 0): "MIDR_EL1", (3, 0, 4, 2, 2): "CurrentEL", (3, 3, 4, 2, 1): "DAIF",
}
_BARRIER_OPTS = {15: "sy", 14: "st", 13: "ld", 11: "ish", 10: "ishst", 9: "ishld", 7: "nsh", 6: "nshst", 5: "nshld",
                 3: "osh", 2: "oshst", 1: "oshld"}


def _h_system(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    l, op0, op1, crn, crm, op2, rt = f["L"], f["op0"], f["op1"], f["CRn"], f["CRm"], f["op2"], f["Rt"]
    o.opc("L", "L = 1: read (system register to Xt)." if l else "L = 0: write (Xt to system register), or an instruction without a result.")
    for name, val, w in (("op0", op0, 2), ("op1", op1, 3), ("CRn", crn, 4), ("CRm", crm, 4), ("op2", op2, 3)):
        o.opc(name, "%s = %s: part of the system register / operation number." % (name, _binstr(val, w)))
    if op0 >= 2:
        o.reg("Rt", rt, _X(rt), "general register transferred", False)
        key = (op0, op1, crn, crm, op2)
        name = _SYSREGS.get(key)
        generic = "S%d_%d_C%d_C%d_%d" % key
        o.form = "MRS <Xt>, <sysreg>" if l else "MSR <sysreg>, <Xt>"
        o.steps.append("register = S<op0>_<op1>_C<CRn>_C<CRm>_<op2> = %s%s" % (generic, (" = " + name) if name else ""))
        shown = name or generic
        if not name:
            o.partial("System register name: %s is not in this lab's table of register names; the fields above are correct, "
                      "the name is shown in its generic S<op0>_<op1>_C<n>_C<m>_<op2> form." % generic)
        o.mn = "mrs" if l else "msr"
        o.ops = "%s, %s" % ((_X(rt), shown) if l else (shown, _X(rt)))
        return True
    if op0 == 0 and l == 0 and op1 == 3 and crn == 3 and rt == 31:
        o.opc("Rt", "Rt = 11111: fixed for barriers.")
        if op2 in (2, 6) and crm == 15:
            o.mn, o.ops = ("clrex" if op2 == 2 else "isb"), ""
            o.opc("CRm", "CRm = 1111: the only defined value; it is not printed.")
        elif op2 in (4, 5) and crm in _BARRIER_OPTS:
            o.mn = "dsb" if op2 == 4 else "dmb"
            o.ops = _BARRIER_OPTS[crm]
            o.opc("CRm", "CRm = %s: barrier scope '%s'." % (_binstr(crm, 4), o.ops))
        else:
            return False
        o.form = "barrier"
        return True
    return False


# --- loads and stores --------------------------------------------------------
def _ls_names(size: int, v: int, opc: int) -> Optional[Tuple[str, str, int, bool]]:
    """(mnemonic stem, register name function key, scale log2, is_load) for the common load/store classes."""
    if v == 0:
        if opc == 0:
            return ("str" + ["b", "h", "", ""][size], "x" if size == 3 else "w", size, False)
        if opc == 1:
            return ("ldr" + ["b", "h", "", ""][size], "x" if size == 3 else "w", size, True)
        if opc == 2:
            if size == 3:
                return ("prfm", "prf", 3, True)
            return (["ldrsb", "ldrsh", "ldrsw"][size], "x", size, True)
        if size < 2:
            return (["ldrsb", "ldrsh"][size], "w", size, True)
        return None
    if opc in (0, 1):
        return ("str" if opc == 0 else "ldr", "bhsd"[size], size, opc == 1)
    if size == 0:
        return ("str" if opc == 2 else "ldr", "q", 4, opc == 3)
    return None


def _ls_reg(kind: str, n: int) -> str:
    if kind == "x":
        return _X(n)
    if kind == "w":
        return _W(n)
    if kind == "prf":
        t, lvl, pol = (n >> 3) & 3, (n >> 1) & 3, n & 1
        if t == 3 or lvl == 3:
            return _imm(n)
        return ["pld", "pli", "pst"][t] + "l%d" % (lvl + 1) + ("strm" if pol else "keep")
    return "%s%d" % (kind, n)


def _ls_common(o: _A64Out, f: Dict[str, int], names: Tuple[str, str, int, bool]) -> None:
    size, v, opc, rn, rt = f["size"], f["V"], f["opc"], f["Rn"], f["Rt"]
    stem, kind, scale, is_load = names
    o.opc("size", "size = %s: with V and opc it selects the access size, here %d byte(s)." % (_binstr(size, 2), 1 << scale))
    o.opc("V", "V = 1: the data register is a SIMD&FP register." if v else "V = 0: the data register is a general register.")
    o.opc("opc", "opc = %s: %s." % (_binstr(opc, 2), ("load" if is_load else "store") if kind != "prf" else "prefetch"))
    o.reg("Rn", rn, _X(rn, True), "base address", True)
    if kind == "prf":
        o.opc("Rt", "Rt = %s: prefetch operation, not a register: bits 4:3 type (PLD data, PLI instruction, PST store), "
                    "bits 2:1 cache level minus one, bit 0 policy (0 keep, 1 streaming)." % _binstr(rt, 5))
        if (rt >> 3) == 3 or ((rt >> 1) & 3) == 3:
            o.partial("Prefetch operation %d has no name in this lab's table (type 3 is unallocated; level value 3 is only "
                      "named by a later extension); it is shown as a number." % rt)
    elif kind in ("x", "w"):
        o.reg("Rt", rt, _ls_reg(kind, rt), "register loaded" if is_load else "register stored", False)
    else:
        o.reg("Rt", rt, _ls_reg(kind, rt), "SIMD&FP register loaded" if is_load else "SIMD&FP register stored", None)


def _h_ls_unsigned(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    names = _ls_names(f["size"], f["V"], f["opc"])
    if names is None:
        return False
    stem, kind, scale, _is_load = names
    imm12, rn, rt = f["imm12"], f["Rn"], f["Rt"]
    off = imm12 << scale
    _ls_common(o, f, names)
    o.imm("imm12", "imm12 = 0x%x: unsigned offset in units of the access size (%d byte(s))." % (imm12, 1 << scale))
    o.steps.append("offset = imm12 * %d = 0x%x * %d = 0x%x" % (1 << scale, imm12, 1 << scale, off))
    o.steps.append("address = %s + 0x%x" % (_X(rn, True), off))
    o.notes.append("The offset is unsigned and scaled, so it reaches 0..%d in steps of %d. A negative or unaligned offset needs "
                   "the unscaled form (LDUR / STUR, 9-bit signed)." % (4095 << scale, 1 << scale))
    o.mn = stem
    o.ops = "%s, [%s%s]" % (_ls_reg(kind, rt), _X(rn, True), (", " + _imm(off)) if off else "")
    o.form = "%s <Rt>, [<Xn|SP>{, #<pimm>}]" % stem.upper()
    return True


def _h_ls_imm9(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    names = _ls_names(f["size"], f["V"], f["opc"])
    idx = f["idx"]
    if names is None or idx == 2:
        return False
    stem, kind, _scale, _is_load = names
    imm9, rn, rt = f["imm9"], f["Rn"], f["Rt"]
    off = _sx(imm9, 9)
    if kind == "prf" and idx != 0:
        return False
    _ls_common(o, f, names)
    o.imm("imm9", "imm9 = %s: signed 9-bit byte offset, not scaled." % _binstr(imm9, 9))
    o.opc("idx", "idx = %s: %s." % (_binstr(idx, 2), {0: "unscaled offset, the base register is not changed",
                                                     1: "post-index: the access uses the base, then base += offset",
                                                     3: "pre-index: base += offset, then the access uses the new base"}[idx]))
    o.steps.append("offset = SignExtend(imm9, 9) = %s" % _hx(off))
    reg, base = _ls_reg(kind, rt), _X(rn, True)
    if idx == 0:
        o.mn = {"str": "stur", "ldr": "ldur", "prfm": "prfum"}.get(stem, stem.replace("str", "stur").replace("ldr", "ldur"))
        o.ops = "%s, [%s%s]" % (reg, base, (", " + _imm(off)) if off else "")
        o.steps.append("address = %s %s 0x%x" % (base, "-" if off < 0 else "+", abs(off)))
        o.form = "%s <Rt>, [<Xn|SP>{, #<simm>}]" % o.mn.upper()
    elif idx == 1:
        o.mn, o.ops = stem, "%s, [%s], %s" % (reg, base, _imm(off))
        o.steps.append("address = %s; afterwards %s = %s %s 0x%x" % (base, base, base, "-" if off < 0 else "+", abs(off)))
        o.form = "%s <Rt>, [<Xn|SP>], #<simm>" % stem.upper()
    else:
        o.mn, o.ops = stem, "%s, [%s, %s]!" % (reg, base, _imm(off))
        o.steps.append("%s = %s %s 0x%x; address = the new %s" % (base, base, "-" if off < 0 else "+", abs(off), base))
        o.form = "%s <Rt>, [<Xn|SP>, #<simm>]!" % stem.upper()
    return True


def _h_ls_regoff(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    names = _ls_names(f["size"], f["V"], f["opc"])
    option, s, rm, rn, rt = f["option"], f["S"], f["Rm"], f["Rn"], f["Rt"]
    if names is None or not (option & 2):
        return False
    stem, kind, scale, _is_load = names
    if kind == "prf" and (rt & 0x18) == 0x18:
        return False  # RPRFM (range prefetch) shares this encoding space
    _ls_common(o, f, names)
    ext = {2: "uxtw", 3: "lsl", 6: "sxtw", 7: "sxtx"}[option]
    rm_s = _X(rm) if (option & 1) else _W(rm)
    o.reg("Rm", rm, rm_s, "index register", False)
    o.opc("option", "option = %s: %s." % (_binstr(option, 3), {
        2: "UXTW, the index is a W register, zero-extended to 64 bits",
        3: "LSL, the index is an X register used as is",
        6: "SXTW, the index is a W register, sign-extended to 64 bits",
        7: "SXTX, the index is an X register used as is"}[option]))
    amount = scale if s else 0
    o.opc("S", "S = %d: %s." % (s, ("the index is shifted left by %d (multiplied by the access size)" % scale) if s
                               else "the index is not shifted"))
    o.steps.append("address = %s + (%s(%s) << %d)" % (_X(rn, True), ext.upper() if ext != "lsl" else "", rm_s, amount))
    if s or (ext != "lsl"):
        tail = ", %s" % ext
        if s:
            tail += " #%d" % amount
    else:
        tail = ""
    o.mn = stem
    o.ops = "%s, [%s, %s%s]" % (_ls_reg(kind, rt), _X(rn, True), rm_s, tail)
    o.form = "%s <Rt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]" % stem.upper()
    return True


def _h_ls_pair(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    opc, v, mode, l, imm7, rt2, rn, rt = f["opc"], f["V"], f["mode"], f["L"], f["imm7"], f["Rt2"], f["Rn"], f["Rt"]
    if v == 0:
        if opc == 0:
            kind, scale = "w", 2
        elif opc == 2:
            kind, scale = "x", 3
        elif opc == 1 and l == 1:
            kind, scale = "x", 2
        else:
            return False
    else:
        if opc == 3:
            return False
        kind, scale = "sdq"[opc], 2 + opc
    stem = ("ldp" if l else "stp")
    if v == 0 and opc == 1:
        stem = "ldpsw"
    if mode == 0:
        stem = stem.replace("ldp", "ldnp").replace("stp", "stnp")
        if stem == "ldnpsw":
            return False
    off = _sx(imm7, 7) << scale
    o.opc("opc", "opc = %s: with V it selects the register size, here %d bytes per register%s."
          % (_binstr(opc, 2), 1 << scale, " (LDPSW: two 32-bit words, each sign-extended to 64 bits)" if stem == "ldpsw" else ""))
    o.opc("V", "V = 1: SIMD&FP registers." if v else "V = 0: general registers.")
    o.opc("mode", "mode = %s: %s." % (_binstr(mode, 2), ["no-allocate hint (non-temporal), signed offset",
                                                        "post-index: access at the base, then base += offset",
                                                        "signed offset, the base register is not changed",
                                                        "pre-index: base += offset, then access at the new base"][mode]))
    o.opc("L", "L = 1: load." if l else "L = 0: store.")
    o.imm("imm7", "imm7 = %s: signed 7-bit offset in units of the register size (%d bytes)." % (_binstr(imm7, 7), 1 << scale))
    sp_none = None if v else False
    o.reg("Rt2", rt2, _ls_reg(kind, rt2), "second register (at the higher address)", sp_none)
    o.reg("Rn", rn, _X(rn, True), "base address", True)
    o.reg("Rt", rt, _ls_reg(kind, rt), "first register (at the lower address)", sp_none)
    o.steps.append("offset = SignExtend(imm7, 7) * %d = %d * %d = %s" % (1 << scale, _sx(imm7, 7), 1 << scale, _hx(off)))
    base = _X(rn, True)
    regs = "%s, %s" % (_ls_reg(kind, rt), _ls_reg(kind, rt2))
    if mode == 1:
        o.ops = "%s, [%s], %s" % (regs, base, _imm(off))
        o.steps.append("addresses = %s and %s + %d; afterwards %s = %s %s 0x%x" % (base, base, 1 << scale, base, base, "-" if off < 0 else "+", abs(off)))
    elif mode == 3:
        o.ops = "%s, [%s, %s]!" % (regs, base, _imm(off))
        o.steps.append("%s = %s %s 0x%x; addresses = the new %s and %s + %d" % (base, base, "-" if off < 0 else "+", abs(off), base, base, 1 << scale))
    else:
        o.ops = "%s, [%s%s]" % (regs, base, (", " + _imm(off)) if off else "")
        o.steps.append("addresses = %s %s 0x%x and that + %d" % (base, "-" if off < 0 else "+", abs(off), 1 << scale))
    if not l and not v and rt == 29 and rt2 == 30 and rn == 31:
        o.notes.append("STP x29, x30 at SP is the usual function prologue: it saves the frame pointer and the return address.")
    if l and not v and rt == 29 and rt2 == 30 and rn == 31:
        o.notes.append("LDP x29, x30 at SP is the usual function epilogue: it restores the frame pointer and the return address.")
    o.mn = stem
    o.form = "%s <Rt>, <Rt2>, [<Xn|SP>...]" % stem.upper()
    return True


def _h_ls_literal(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    opc, v, imm19, rt = f["opc"], f["V"], f["imm19"], f["Rt"]
    if v == 0:
        if opc == 3:
            return False
        mn, reg = ["ldr", "ldr", "ldrsw"][opc], [_W(rt), _X(rt), _X(rt)][opc]
        size = [4, 8, 4][opc]
    else:
        if opc == 3:
            return False
        mn, reg, size = "ldr", "%s%d" % ("sdq"[opc], rt), [4, 8, 16][opc]
    o.opc("opc", "opc = %s: with V it selects what is loaded, here %d bytes%s." % (_binstr(opc, 2), size, " sign-extended to 64 bits" if mn == "ldrsw" else ""))
    o.opc("V", "V = 1: SIMD&FP register." if v else "V = 0: general register.")
    o.reg("Rt", rt, reg, "register loaded", None if v else False)
    target = _a64_branch_target(o, pc, "imm19", imm19, 19, "address of the literal")
    o.target_kind = "data"
    o.notes.append("The data is read from the computed address; literal pools are placed in the code section, near the function.")
    o.mn, o.ops = mn, "%s, 0x%x" % (reg, target)
    o.form = "%s <Rt>, <label>" % mn.upper()
    return True


def _h_ls_exclusive(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    size, o2, l, o1, rs, o0, rt2, rn, rt = f["size"], f["o2"], f["L"], f["o1"], f["Rs"], f["o0"], f["Rt2"], f["Rn"], f["Rt"]
    key = (o2 << 3) | (l << 2) | (o1 << 1) | o0
    sfx = ["b", "h", "", ""][size]
    reg = (lambda n: _X(n)) if size == 3 else (lambda n: _W(n))
    base = "[%s]" % _X(rn, True)
    o.opc("size", "size = %s: access size %d byte(s)." % (_binstr(size, 2), 1 << size))
    o.opc("o2", "o2 = %d, L = %d, o1 = %d, o0 = %d together select the operation." % (o2, l, o1, o0))
    o.opc("L", "L = 1: load." if l else "L = 0: store.")
    o.opc("o1", "o1 = %d: see o2." % o1)
    o.opc("o0", "o0 = 1: acquire/release ordering (the 'A' / 'L' in the mnemonic)." if o0 else "o0 = 0: no ordering semantics added.")
    o.reg("Rn", rn, _X(rn, True), "base address (no offset is possible)", True)
    if o1 == 0 and o2 == 0:  # exclusive, single register
        if l:
            if rs != 31 or rt2 != 31:
                return False
            o.mn, o.ops = ("ldaxr" if o0 else "ldxr") + sfx, "%s, %s" % (reg(rt), base)
            o.opc("Rs", "Rs = 11111: unused, must be all ones.")
        else:
            if rt2 != 31:
                return False
            o.mn, o.ops = ("stlxr" if o0 else "stxr") + sfx, "%s, %s, %s" % (_W(rs), reg(rt), base)
            o.reg("Rs", rs, _W(rs), "status result: 0 if the store succeeded, 1 if exclusivity was lost", False)
        o.opc("Rt2", "Rt2 = 11111: unused, must be all ones.")
        o.reg("Rt", rt, reg(rt), "data register", False)
        o.notes.append("LDXR marks the address for exclusive access; STXR stores only if nothing else wrote there since, "
                       "and reports the outcome in the status register. A loop around the pair gives an atomic update.")
    elif o2 == 1 and o1 == 0:  # ordered load / store
        if rs != 31 or rt2 != 31:
            return False
        o.mn = {(0, 1): "stlr", (1, 1): "ldar", (0, 0): "stllr", (1, 0): "ldlar"}[(l, o0)] + sfx
        o.ops = "%s, %s" % (reg(rt), base)
        o.opc("Rs", "Rs = 11111: unused, must be all ones.")
        o.opc("Rt2", "Rt2 = 11111: unused, must be all ones.")
        o.reg("Rt", rt, reg(rt), "data register", False)
    elif o2 == 1 and o1 == 1:  # CAS
        if rt2 != 31:
            return False
        o.mn = "cas" + ("a" if l else "") + ("l" if o0 else "") + sfx
        o.ops = "%s, %s, %s" % (reg(rs), reg(rt), base)
        o.reg("Rs", rs, reg(rs), "expected value in, value read out", False)
        o.opc("Rt2", "Rt2 = 11111: fixed for compare-and-swap.")
        o.reg("Rt", rt, reg(rt), "new value", False)
        o.notes.append("CAS is an ARMv8.1 (LSE) atomic: one instruction instead of an LDXR/STXR loop.")
    else:  # exclusive pair
        if size < 2:
            return False
        preg = (lambda n: _X(n)) if (size & 1) else (lambda n: _W(n))
        if l:
            if rs != 31:
                return False
            o.mn, o.ops = ("ldaxp" if o0 else "ldxp"), "%s, %s, %s" % (preg(rt), preg(rt2), base)
            o.opc("Rs", "Rs = 11111: unused, must be all ones.")
        else:
            o.mn, o.ops = ("stlxp" if o0 else "stxp"), "%s, %s, %s, %s" % (_W(rs), preg(rt), preg(rt2), base)
            o.reg("Rs", rs, _W(rs), "status result", False)
        o.reg("Rt2", rt2, preg(rt2), "second data register", False)
        o.reg("Rt", rt, preg(rt), "first data register", False)
    o.form = o.mn.upper()
    return True


def _h_ls_atomic(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    size, v, a, r, rs, o3, opc, rn, rt = f["size"], f["V"], f["A"], f["R"], f["Rs"], f["o3"], f["opc"], f["Rn"], f["Rt"]
    if v:
        return False
    if o3 == 0:
        stem = ["ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin"][opc]
    elif opc == 0:
        stem = "swp"
    else:
        return False
    sfx = ("a" if a else "") + ("l" if r else "") + ["b", "h", "", ""][size]
    reg = (lambda n: _X(n)) if size == 3 else (lambda n: _W(n))
    o.opc("size", "size = %s: access size %d byte(s)." % (_binstr(size, 2), 1 << size))
    o.opc("V", "V = 0: general registers.")
    o.opc("A", "A = 1: acquire ordering." if a else "A = 0: no acquire ordering.")
    o.opc("R", "R = 1: release ordering." if r else "R = 0: no release ordering.")
    o.reg("Rs", rs, reg(rs), "operand value", False)
    o.opc("o3", "o3 = %d and opc = %s select %s." % (o3, _binstr(opc, 3), stem.upper()))
    o.opc("opc", "opc = %s: see o3." % _binstr(opc, 3))
    o.reg("Rn", rn, _X(rn, True), "address of the memory word", True)
    o.reg("Rt", rt, reg(rt), "receives the old memory value", False)
    o.notes.append("ARMv8.1 (LSE) atomic memory operation: read the old value, combine, write back, as one atomic step.")
    if rt == 31 and not a and o3 == 0:
        o.mn = "st" + stem[2:] + sfx
        o.ops = "%s, [%s]" % (reg(rs), _X(rn, True))
        o.notes.append("With Rt = 31 the old value is discarded; the alias ST%s is used." % stem[2:].upper())
    else:
        o.mn = stem + sfx
        o.ops = "%s, %s, [%s]" % (reg(rs), reg(rt), _X(rn, True))
    o.form = stem.upper() + " <Rs>, <Rt>, [<Xn|SP>]"
    return True


def _h_ls_pac(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    m, s, imm9, w, rn, rt = f["M"], f["S"], f["imm9"], f["W"], f["Rn"], f["Rt"]
    raw = (s << 9) | imm9
    off = _sx(raw, 10) * 8
    o.opc("M", "M = 1: key DB (LDRAB)." if m else "M = 0: key DA (LDRAA).")
    o.imm("S", "S = %d: sign bit of the 10-bit offset; it is stored apart from imm9." % s)
    o.imm("imm9", "imm9 = %s: low 9 bits of the offset, in units of 8 bytes." % _binstr(imm9, 9))
    o.opc("W", "W = 1: pre-index, the authenticated address plus offset is written back to the base." if w else "W = 0: no writeback.")
    o.reg("Rn", rn, _X(rn, True), "signed base pointer", True)
    o.reg("Rt", rt, _X(rt), "register loaded", False)
    o.steps.append("offset = SignExtend(S:imm9, 10) * 8 = %d * 8 = %s" % (_sx(raw, 10), _hx(off)))
    o.notes.append("ARMv8.3: the base pointer is authenticated (its PAC checked and removed) with zero as the modifier, "
                   "then 8 bytes are loaded from base + offset.")
    o.mn = "ldrab" if m else "ldraa"
    o.ops = "%s, [%s%s]%s" % (_X(rt), _X(rn, True), (", " + _imm(off)) if (off or w) else "", "!" if w else "")
    o.form = "%s <Xt>, [<Xn|SP>{, #<simm>}]{!}" % o.mn.upper()
    return True


# --- data processing, register ----------------------------------------------
def _h_logical_sreg(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, opc, shift, n, rm, imm6, rn, rd = f["sf"], f["opc"], f["shift"], f["N"], f["Rm"], f["imm6"], f["Rn"], f["Rd"]
    if not sf and imm6 & 0x20:
        return False
    names = ["and", "bic", "orr", "orn", "eor", "eon", "ands", "bics"]
    mn = names[(opc << 1) | n]
    o.sf(sf)
    o.opc("opc", "opc = %s: %s." % (_binstr(opc, 2), ["AND", "ORR", "EOR", "AND, setting flags"][opc]))
    o.opc("shift", "shift = %s: %s applied to the second operand." % (_binstr(shift, 2), _SHIFTS[shift].upper()))
    o.opc("N", "N = 1: the second operand is inverted first (BIC / ORN / EON / BICS)." if n else "N = 0: the second operand is not inverted.")
    o.reg("Rm", rm, _R(sf, rm), "second operand", False)
    o.imm("imm6", "imm6 = %d: shift amount." % imm6)
    o.reg("Rn", rn, _R(sf, rn), "first operand", False)
    o.reg("Rd", rd, _R(sf, rd), "destination", False)
    sh = ", %s #%d" % (_SHIFTS[shift], imm6) if (imm6 or shift) else ""
    o.form = "%s <Rd>, <Rn>, <Rm>{, <shift> #<amount>}" % mn.upper()
    if mn == "orr" and rn == 31 and imm6 == 0 and shift == 0:
        o.mn, o.ops = "mov", "%s, %s" % (_R(sf, rd), _R(sf, rm))
        o.notes.append("MOV between registers is an alias of ORR with Rn = 31 (zero register): Rd = 0 OR Rm.")
    elif mn == "orn" and rn == 31:
        o.mn, o.ops = "mvn", "%s, %s%s" % (_R(sf, rd), _R(sf, rm), sh)
        o.notes.append("MVN is an alias of ORN with Rn = 31 (zero register).")
    elif mn == "ands" and rd == 31:
        o.mn, o.ops = "tst", "%s, %s%s" % (_R(sf, rn), _R(sf, rm), sh)
        o.notes.append("TST is an alias of ANDS with Rd = 31 (zero register).")
    else:
        o.mn, o.ops = mn, "%s, %s, %s%s" % (_R(sf, rd), _R(sf, rn), _R(sf, rm), sh)
    return True


def _h_addsub_sreg(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, op, s, shift, rm, imm6, rn, rd = f["sf"], f["op"], f["S"], f["shift"], f["Rm"], f["imm6"], f["Rn"], f["Rd"]
    if shift == 3 or (not sf and imm6 & 0x20):
        return False
    o.sf(sf)
    o.opc("op", "op = 1: subtract." if op else "op = 0: add.")
    o.opc("S", "S = 1: set the NZCV flags." if s else "S = 0: flags are not changed.")
    o.opc("shift", "shift = %s: %s applied to the second operand." % (_binstr(shift, 2), _SHIFTS[shift].upper()))
    o.reg("Rm", rm, _R(sf, rm), "second operand", False)
    o.imm("imm6", "imm6 = %d: shift amount." % imm6)
    o.reg("Rn", rn, _R(sf, rn), "first operand", False)
    o.reg("Rd", rd, _R(sf, rd), "destination", False)
    o.notes.append("In the shifted-register form register 31 is the zero register in every position. Adding to SP needs the "
                   "immediate or the extended-register form.")
    sh = ", %s #%d" % (_SHIFTS[shift], imm6) if (imm6 or shift) else ""
    base = ("sub" if op else "add") + ("s" if s else "")
    o.form = "%s <Rd>, <Rn>, <Rm>{, <shift> #<amount>}" % base.upper()
    if s and rd == 31:
        o.mn, o.ops = ("cmp" if op else "cmn"), "%s, %s%s" % (_R(sf, rn), _R(sf, rm), sh)
        o.notes.append("%s is an alias of %s with Rd = 31 (zero register)." % (o.mn.upper(), base.upper()))
    elif op and rn == 31:
        o.mn, o.ops = ("negs" if s else "neg"), "%s, %s%s" % (_R(sf, rd), _R(sf, rm), sh)
        o.notes.append("%s is an alias of %s with Rn = 31 (zero register): 0 - Rm." % (o.mn.upper(), base.upper()))
    else:
        o.mn, o.ops = base, "%s, %s, %s%s" % (_R(sf, rd), _R(sf, rn), _R(sf, rm), sh)
    return True


def _h_addsub_ext(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, op, s, rm, option, imm3, rn, rd = f["sf"], f["op"], f["S"], f["Rm"], f["option"], f["imm3"], f["Rn"], f["Rd"]
    if imm3 > 4:
        return False
    o.sf(sf)
    o.opc("op", "op = 1: subtract." if op else "op = 0: add.")
    o.opc("S", "S = 1: set the NZCV flags." if s else "S = 0: flags are not changed.")
    rm_is_x = sf and (option & 3) == 3
    rm_s = _X(rm) if rm_is_x else _W(rm)
    o.reg("Rm", rm, rm_s, "second operand, before extension", False)
    o.opc("option", "option = %s: %s, the second operand is %s-extended from %d bits." % (
        _binstr(option, 3), _EXTENDS[option].upper(), "sign" if option & 4 else "zero", 8 << (option & 3)))
    o.imm("imm3", "imm3 = %d: left shift applied after the extension (0 to 4)." % imm3)
    o.reg("Rn", rn, _R(sf, rn, True), "first operand", True)
    o.reg("Rd", rd, _R(sf, rd, not s), "destination", not s)
    o.notes.append("This is the form that can use SP as an operand with a register second operand. When SP is involved and the "
                   "extend is the no-op one for the register size (UXTX for 64-bit, UXTW for 32-bit), it is written as LSL or omitted.")
    lsl_form = ((rd == 31 and not s) or rn == 31) and option == (3 if sf else 2)
    if lsl_form:
        ext = ", lsl #%d" % imm3 if imm3 else ""
    else:
        ext = ", %s" % _EXTENDS[option] + (" #%d" % imm3 if imm3 else "")
    base = ("sub" if op else "add") + ("s" if s else "")
    o.form = "%s <Rd|SP>, <Rn|SP>, <R><m>{, <extend> {#<amount>}}" % base.upper()
    if s and rd == 31:
        o.mn, o.ops = ("cmp" if op else "cmn"), "%s, %s%s" % (_R(sf, rn, True), rm_s, ext)
    else:
        o.mn, o.ops = base, "%s, %s, %s%s" % (_R(sf, rd, not s), _R(sf, rn, True), rm_s, ext)
    return True


def _h_adc(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, op, s, rm, rn, rd = f["sf"], f["op"], f["S"], f["Rm"], f["Rn"], f["Rd"]
    o.sf(sf)
    o.opc("op", "op = 1: subtract with carry (SBC)." if op else "op = 0: add with carry (ADC).")
    o.opc("S", "S = 1: set the NZCV flags." if s else "S = 0: flags are not changed.")
    o.reg("Rm", rm, _R(sf, rm), "second operand", False)
    o.reg("Rn", rn, _R(sf, rn), "first operand", False)
    o.reg("Rd", rd, _R(sf, rd), "destination", False)
    base = ("sbc" if op else "adc") + ("s" if s else "")
    o.form = "%s <Rd>, <Rn>, <Rm>" % base.upper()
    if op and rn == 31:
        o.mn, o.ops = ("ngcs" if s else "ngc"), "%s, %s" % (_R(sf, rd), _R(sf, rm))
    else:
        o.mn, o.ops = base, "%s, %s, %s" % (_R(sf, rd), _R(sf, rn), _R(sf, rm))
    return True


def _h_ccmp(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, op, y, cond, is_imm, rn, nzcv = f["sf"], f["op"], f["y"], f["cond"], f["i"], f["Rn"], f["nzcv"]
    o.sf(sf)
    o.opc("op", "op = 1: CCMP (compare, i.e. subtract)." if op else "op = 0: CCMN (compare negative, i.e. add).")
    o.opc("i", "i = 1: the second operand is a 5-bit immediate." if is_imm else "i = 0: the second operand is a register.")
    if is_imm:
        o.imm("y", "imm5 = %d: unsigned immediate compared against." % y)
        second = _imm(y)
    else:
        o.reg("y", y, _R(sf, y), "second operand", False)
        second = _R(sf, y)
    o.cond("cond", cond, "If it is false, the flags are set to nzcv instead of the comparison result.")
    o.reg("Rn", rn, _R(sf, rn), "first operand", False)
    o.imm("nzcv", "nzcv = %s: flag values (N, Z, C, V) used when the condition is false." % _binstr(nzcv, 4))
    o.notes.append("Conditional compare chains conditions without branches: 'if (a == b && c < d)' becomes CMP, CCMP, B.cond.")
    o.mn = "ccmp" if op else "ccmn"
    o.ops = "%s, %s, %s, %s" % (_R(sf, rn), second, _imm(nzcv), _CONDS[cond])
    o.form = "%s <Rn>, <Rm|#imm5>, #<nzcv>, <cond>" % o.mn.upper()
    return True


def _h_csel(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, op, rm, cond, o2, rn, rd = f["sf"], f["op"], f["Rm"], f["cond"], f["o2"], f["Rn"], f["Rd"]
    base = [["csel", "csinc"], ["csinv", "csneg"]][op][o2]
    o.sf(sf)
    o.opc("op", "op = %d and o2 = %d select %s: Rd = cond ? Rn : %s." % (op, o2, base.upper(), {
        "csel": "Rm", "csinc": "Rm + 1", "csinv": "NOT(Rm)", "csneg": "-Rm"}[base]))
    o.opc("o2", "o2 = %d: see op." % o2)
    o.reg("Rm", rm, _R(sf, rm), "value used (after the modification) when the condition is false", False)
    o.cond("cond", cond)
    o.reg("Rn", rn, _R(sf, rn), "value used when the condition is true", False)
    o.reg("Rd", rd, _R(sf, rd), "destination", False)
    o.form = "%s <Rd>, <Rn>, <Rm>, <cond>" % base.upper()
    inv = _CONDS[cond ^ 1]
    aliasable = cond < 14
    if base == "csinc" and rm == rn and aliasable:
        if rn == 31:
            o.mn, o.ops = "cset", "%s, %s" % (_R(sf, rd), inv)
            o.notes.append("CSET Rd, %s is an alias of CSINC Rd, zr, zr, %s: the stored condition is the inverse of the one written." % (inv, _CONDS[cond]))
        else:
            o.mn, o.ops = "cinc", "%s, %s, %s" % (_R(sf, rd), _R(sf, rn), inv)
            o.notes.append("CINC is an alias of CSINC with Rn == Rm and the inverted condition.")
    elif base == "csinv" and rm == rn and aliasable:
        if rn == 31:
            o.mn, o.ops = "csetm", "%s, %s" % (_R(sf, rd), inv)
            o.notes.append("CSETM is an alias of CSINV Rd, zr, zr with the inverted condition.")
        else:
            o.mn, o.ops = "cinv", "%s, %s, %s" % (_R(sf, rd), _R(sf, rn), inv)
            o.notes.append("CINV is an alias of CSINV with Rn == Rm and the inverted condition.")
    elif base == "csneg" and rm == rn and aliasable:
        o.mn, o.ops = "cneg", "%s, %s, %s" % (_R(sf, rd), _R(sf, rn), inv)
        o.notes.append("CNEG is an alias of CSNEG with Rn == Rm and the inverted condition.")
    else:
        o.mn, o.ops = base, "%s, %s, %s, %s" % (_R(sf, rd), _R(sf, rn), _R(sf, rm), _CONDS[cond])
    return True


def _h_dp3(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, op31, rm, o0, ra, rn, rd = f["sf"], f["op31"], f["Rm"], f["o0"], f["Ra"], f["Rn"], f["Rd"]
    key = (op31, o0)
    table = {(0, 0): ("madd", "mul", False), (0, 1): ("msub", "mneg", False),
             (1, 0): ("smaddl", "smull", True), (1, 1): ("smsubl", "smnegl", True),
             (2, 0): ("smulh", None, False), (5, 0): ("umaddl", "umull", True),
             (5, 1): ("umsubl", "umnegl", True), (6, 0): ("umulh", None, False)}
    if key not in table or (op31 != 0 and not sf):
        return False
    base, alias, widening = table[key]
    o.sf(sf)
    o.opc("op31", "op31 = %s and o0 = %d select %s." % (_binstr(op31, 3), o0, base.upper()))
    o.opc("o0", "o0 = 1: the product is subtracted from Ra." if o0 else "o0 = 0: the product is added to Ra.")
    src = (lambda n: _W(n)) if widening else (lambda n: _R(sf, n))
    o.reg("Rm", rm, src(rm), "multiplier", False)
    o.reg("Rn", rn, src(rn), "multiplicand", False)
    o.reg("Rd", rd, _R(sf, rd), "destination", False)
    o.form = "%s <Rd>, <Rn>, <Rm>, <Ra>" % base.upper()
    if alias is None:
        if ra != 31:
            return False
        o.opc("Ra", "Ra = 11111: unused, must be all ones.")
        o.mn, o.ops = base, "%s, %s, %s" % (_X(rd), _X(rn), _X(rm))
        o.notes.append("%s returns the high 64 bits of the 128-bit product." % base.upper())
        return True
    o.reg("Ra", ra, _R(sf, ra), "addend / minuend", False)
    if ra == 31:
        o.mn, o.ops = alias, "%s, %s, %s" % (_R(sf, rd), src(rn), src(rm))
        o.notes.append("%s is an alias of %s with Ra = 31 (zero register)." % (alias.upper(), base.upper()))
    else:
        o.mn, o.ops = base, "%s, %s, %s, %s" % (_R(sf, rd), src(rn), src(rm), _R(sf, ra))
    return True


def _h_dp2(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, rm, opcode, rn, rd = f["sf"], f["Rm"], f["opcode"], f["Rn"], f["Rd"]
    table = {2: ("udiv", "udiv"), 3: ("sdiv", "sdiv"), 8: ("lslv", "lsl"), 9: ("lsrv", "lsr"), 10: ("asrv", "asr"), 11: ("rorv", "ror")}
    o.sf(sf)
    if opcode in table:
        base, shown = table[opcode]
        o.opc("opcode", "opcode = %s: %s." % (_binstr(opcode, 6), base.upper()))
        o.reg("Rm", rm, _R(sf, rm), "second operand (divisor / shift amount)", False)
        o.reg("Rn", rn, _R(sf, rn), "first operand", False)
        o.reg("Rd", rd, _R(sf, rd), "destination", False)
        if base != shown:
            o.notes.append("%s with a register amount is written as %s; the amount is taken modulo the register size." % (base.upper(), shown.upper()))
        if "div" in base:
            o.notes.append("Division by zero does not trap on AArch64: the result is 0.")
        o.mn, o.ops = shown, "%s, %s, %s" % (_R(sf, rd), _R(sf, rn), _R(sf, rm))
        o.form = "%s <Rd>, <Rn>, <Rm>" % base.upper()
        return True
    if opcode == 12 and sf:
        o.opc("opcode", "opcode = 001100: PACGA, compute a generic authentication code.")
        o.reg("Rm", rm, _X(rm, True), "modifier", True)
        o.reg("Rn", rn, _X(rn), "value to sign", False)
        o.reg("Rd", rd, _X(rd), "receives the code in its upper 32 bits", False)
        o.mn, o.ops = "pacga", "%s, %s, %s" % (_X(rd), _X(rn), _X(rm, True))
        o.form = "PACGA <Xd>, <Xn>, <Xm|SP>"
        return True
    if 16 <= opcode <= 23:
        sz, c = opcode & 3, (opcode >> 2) & 1
        if (sz == 3) != bool(sf):
            return False
        o.opc("opcode", "opcode = %s: CRC32%s checksum step over %d byte(s)." % (_binstr(opcode, 6), "C" if c else "", 1 << sz))
        o.reg("Rm", rm, _X(rm) if sz == 3 else _W(rm), "data", False)
        o.reg("Rn", rn, _W(rn), "running checksum", False)
        o.reg("Rd", rd, _W(rd), "destination", False)
        o.mn = "crc32" + ("c" if c else "") + "bhwx"[sz]
        o.ops = "%s, %s, %s" % (_W(rd), _W(rn), _X(rm) if sz == 3 else _W(rm))
        o.form = o.mn.upper()
        return True
    return False


_PAC1 = ["pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb"]


def _h_dp1(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, opcode2, opcode, rn, rd = f["sf"], f["opcode2"], f["opcode"], f["Rn"], f["Rd"]
    o.sf(sf)
    if opcode2 == 0:
        names = {0: "rbit", 1: "rev16", 2: "rev32" if sf else "rev", 4: "clz", 5: "cls"}
        if sf:
            names[3] = "rev"
        if opcode not in names:
            return False
        mn = names[opcode]
        o.opc("opcode2", "opcode2 = 00000: general one-source operations.")
        o.opc("opcode", "opcode = %s: %s (%s)." % (_binstr(opcode, 6), mn.upper(), {
            "rbit": "reverse the bit order", "rev16": "byte-swap each 16-bit half-word", "rev32": "byte-swap each 32-bit word",
            "rev": "byte-swap the whole register", "clz": "count leading zero bits", "cls": "count leading sign bits"}[mn]))
        o.reg("Rn", rn, _R(sf, rn), "source", False)
        o.reg("Rd", rd, _R(sf, rd), "destination", False)
        o.mn, o.ops = mn, "%s, %s" % (_R(sf, rd), _R(sf, rn))
        o.form = "%s <Rd>, <Rn>" % mn.upper()
        return True
    if opcode2 == 1 and sf:
        o.opc("opcode2", "opcode2 = 00001: pointer authentication (ARMv8.3).")
        if opcode < 8:
            mn = _PAC1[opcode]
            o.reg("Rn", rn, _X(rn, True), "modifier (context value)", True)
            o.ops = "%s, %s" % (_X(rd), _X(rn, True))
        elif opcode < 16 and rn == 31:
            mn = _PAC1[opcode - 8][:4] + "z" + _PAC1[opcode - 8][4:]
            o.opc("Rn", "Rn = 11111: fixed, the modifier is zero.")
            o.ops = _X(rd)
        elif opcode in (16, 17) and rn == 31:
            mn = "xpaci" if opcode == 16 else "xpacd"
            o.opc("Rn", "Rn = 11111: fixed.")
            o.ops = _X(rd)
        else:
            return False
        what = ("strip the PAC from" if mn.startswith("xpac") else
                ("sign (add a PAC to)" if mn.startswith("pac") else "authenticate (check and remove the PAC of)"))
        o.opc("opcode", "opcode = %s: %s, %s the pointer in Rd." % (_binstr(opcode, 6), mn.upper(), what))
        o.reg("Rd", rd, _X(rd), "pointer, modified in place", False)
        o.notes.append("Key letters: I = instruction pointer key, D = data pointer key; A / B = which of the two keys of that kind.")
        o.mn = mn
        o.form = mn.upper()
        return True
    return False


# --- scalar floating point ----------------------------------------------------
def _fp(ftype: int) -> Optional[str]:
    return {0: "s", 1: "d", 3: "h"}.get(ftype)


def _ftype_text(o: _A64Out, ftype: int) -> None:
    o.opc("ftype", "ftype = %s: %s precision." % (_binstr(ftype, 2), {0: "single (32-bit, S registers)", 1: "double (64-bit, D registers)",
                                                                       3: "half (16-bit, H registers)"}.get(ftype, "reserved")))


def _h_fp_int(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    sf, ftype, rmode, opcode, rn, rd = f["sf"], f["ftype"], f["rmode"], f["opcode"], f["Rn"], f["Rd"]
    p = _fp(ftype)
    if p is None or p == "h":
        return False
    o.sf(sf)
    _ftype_text(o, ftype)
    key = (rmode, opcode)
    to_int = {(0, 0): "fcvtns", (0, 1): "fcvtnu", (0, 4): "fcvtas", (0, 5): "fcvtau", (1, 0): "fcvtps", (1, 1): "fcvtpu",
              (2, 0): "fcvtms", (2, 1): "fcvtmu", (3, 0): "fcvtzs", (3, 1): "fcvtzu"}
    o.opc("rmode", "rmode = %s: rounding mode / operation group." % _binstr(rmode, 2))
    if key in to_int:
        mn = to_int[key]
        o.opc("opcode", "opcode = %s: with rmode selects %s (floating point to integer; the last letters give rounding and signedness)." % (_binstr(opcode, 3), mn.upper()))
        o.reg("Rn", rn, "%s%d" % (p, rn), "floating-point source", None)
        o.reg("Rd", rd, _R(sf, rd), "integer destination", False)
        o.mn, o.ops = mn, "%s, %s%d" % (_R(sf, rd), p, rn)
    elif key in ((0, 2), (0, 3)):
        mn = "scvtf" if opcode == 2 else "ucvtf"
        o.opc("opcode", "opcode = %s: %s, %s integer to floating point." % (_binstr(opcode, 3), mn.upper(), "signed" if opcode == 2 else "unsigned"))
        o.reg("Rn", rn, _R(sf, rn), "integer source", False)
        o.reg("Rd", rd, "%s%d" % (p, rd), "floating-point destination", None)
        o.mn, o.ops = mn, "%s%d, %s" % (p, rd, _R(sf, rn))
    elif key in ((0, 6), (0, 7)) and ((sf == 0 and ftype == 0) or (sf == 1 and ftype == 1)):
        o.opc("opcode", "opcode = %s: FMOV, copy the bits unchanged between a general and a floating-point register (no conversion)." % _binstr(opcode, 3))
        if opcode == 6:
            o.reg("Rn", rn, "%s%d" % (p, rn), "source", None)
            o.reg("Rd", rd, _R(sf, rd), "destination", False)
            o.ops = "%s, %s%d" % (_R(sf, rd), p, rn)
        else:
            o.reg("Rn", rn, _R(sf, rn), "source", False)
            o.reg("Rd", rd, "%s%d" % (p, rd), "destination", None)
            o.ops = "%s%d, %s" % (p, rd, _R(sf, rn))
        o.mn = "fmov"
    else:
        return False
    o.form = o.mn.upper()
    return True


def _h_fp_dp1(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    ftype, opcode, rn, rd = f["ftype"], f["opcode"], f["Rn"], f["Rd"]
    p = _fp(ftype)
    if p is None or p == "h":
        return False
    _ftype_text(o, ftype)
    names = {0: "fmov", 1: "fabs", 2: "fneg", 3: "fsqrt", 8: "frintn", 9: "frintp", 10: "frintm", 11: "frintz", 12: "frinta",
             14: "frintx", 15: "frinti"}
    dst = p
    if opcode in names:
        mn = names[opcode]
    elif opcode in (4, 5, 7):
        dst = {4: "s", 5: "d", 7: "h"}[opcode]
        if dst == p:
            return False
        mn = "fcvt"
    else:
        return False
    o.opc("opcode", "opcode = %s: %s." % (_binstr(opcode, 6), mn.upper() + (" (convert precision to %s)" % dst.upper() if mn == "fcvt" else "")))
    o.reg("Rn", rn, "%s%d" % (p, rn), "source", None)
    o.reg("Rd", rd, "%s%d" % (dst, rd), "destination", None)
    o.mn, o.ops = mn, "%s%d, %s%d" % (dst, rd, p, rn)
    o.form = "%s <Vd>, <Vn>" % mn.upper()
    return True


def _h_fp_cmp(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    ftype, rm, rn, opcode2 = f["ftype"], f["Rm"], f["Rn"], f["opcode2"]
    p = _fp(ftype)
    if p is None or p == "h" or (opcode2 & 7):
        return False
    zero, e = (opcode2 >> 3) & 1, (opcode2 >> 4) & 1
    if zero and rm != 0:
        return False
    _ftype_text(o, ftype)
    o.opc("opcode2", "opcode2 = %s: bit 4 = %d (%s), bit 3 = %d (%s)." % (
        _binstr(opcode2, 5), e, "FCMPE, signalling: any NaN raises Invalid Operation" if e else "FCMP, quiet",
        zero, "compare with +0.0, Rm is not used" if zero else "compare with Rm"))
    o.reg("Rn", rn, "%s%d" % (p, rn), "first operand", None)
    if zero:
        o.opc("Rm", "Rm = 00000: unused in the compare-with-zero form.")
    else:
        o.reg("Rm", rm, "%s%d" % (p, rm), "second operand", None)
    o.mn = "fcmpe" if e else "fcmp"
    o.ops = "%s%d, %s" % (p, rn, "#0.0" if zero else "%s%d" % (p, rm))
    o.notes.append("The result goes to the NZCV flags. An unordered comparison (a NaN operand) sets C and V.")
    o.form = "%s <Vn>, <Vm>|#0.0" % o.mn.upper()
    return True


def _vfp_expand(imm8: int) -> float:
    sign = -1.0 if imm8 & 0x80 else 1.0
    exp = (((imm8 >> 4) & 7) ^ 4) - 3
    mant = (16 + (imm8 & 15)) / 16.0
    return sign * mant * (2.0 ** exp)


def _h_fp_imm(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    ftype, imm8, rd = f["ftype"], f["imm8"], f["Rd"]
    p = _fp(ftype)
    if p is None or p == "h":
        return False
    value = _vfp_expand(imm8)
    _ftype_text(o, ftype)
    o.imm("imm8", "imm8 = %s = abcdefgh: a = sign, NOT(b):c:d = exponent, e:f:g:h = fraction." % _binstr(imm8, 8))
    o.reg("Rd", rd, "%s%d" % (p, rd), "destination", None)
    exp = (((imm8 >> 4) & 7) ^ 4) - 3
    o.steps.append("sign = %d, exponent = (NOT(b):c:d) - 3 = %d, mantissa = (16 + efgh) / 16 = %g" % (imm8 >> 7, exp, (16 + (imm8 & 15)) / 16.0))
    o.steps.append("value = (-1)^sign * mantissa * 2^exponent = %r" % value)
    o.notes.append("Only 256 values can be encoded this way: +/- (16..31)/16 * 2^(-3..4). 0.0 is not one of them; compilers "
                   "use MOVI or FMOV from the zero register for that.")
    o.mn, o.ops = "fmov", "%s%d, #%.8f" % (p, rd, value)
    o.form = "FMOV <Vd>, #<fpimm>"
    return True


def _h_fp_ccmp(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    ftype, rm, cond, rn, op, nzcv = f["ftype"], f["Rm"], f["cond"], f["Rn"], f["op"], f["nzcv"]
    p = _fp(ftype)
    if p is None or p == "h":
        return False
    _ftype_text(o, ftype)
    o.reg("Rm", rm, "%s%d" % (p, rm), "second operand", None)
    o.cond("cond", cond, "If it is false, the flags are set to nzcv instead.")
    o.reg("Rn", rn, "%s%d" % (p, rn), "first operand", None)
    o.opc("op", "op = 1: FCCMPE (signalling)." if op else "op = 0: FCCMP (quiet).")
    o.imm("nzcv", "nzcv = %s: flags used when the condition is false." % _binstr(nzcv, 4))
    o.mn = "fccmpe" if op else "fccmp"
    o.ops = "%s%d, %s%d, %s, %s" % (p, rn, p, rm, _imm(nzcv), _CONDS[cond])
    o.form = o.mn.upper()
    return True


def _h_fp_dp2(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    ftype, rm, opcode, rn, rd = f["ftype"], f["Rm"], f["opcode"], f["Rn"], f["Rd"]
    p = _fp(ftype)
    names = ["fmul", "fdiv", "fadd", "fsub", "fmax", "fmin", "fmaxnm", "fminnm", "fnmul"]
    if p is None or p == "h" or opcode >= len(names):
        return False
    _ftype_text(o, ftype)
    o.opc("opcode", "opcode = %s: %s." % (_binstr(opcode, 4), names[opcode].upper()))
    o.reg("Rm", rm, "%s%d" % (p, rm), "second operand", None)
    o.reg("Rn", rn, "%s%d" % (p, rn), "first operand", None)
    o.reg("Rd", rd, "%s%d" % (p, rd), "destination", None)
    o.mn, o.ops = names[opcode], "%s%d, %s%d, %s%d" % (p, rd, p, rn, p, rm)
    o.form = "%s <Vd>, <Vn>, <Vm>" % o.mn.upper()
    return True


def _h_fp_csel(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    ftype, rm, cond, rn, rd = f["ftype"], f["Rm"], f["cond"], f["Rn"], f["Rd"]
    p = _fp(ftype)
    if p is None or p == "h":
        return False
    _ftype_text(o, ftype)
    o.reg("Rm", rm, "%s%d" % (p, rm), "value when the condition is false", None)
    o.cond("cond", cond)
    o.reg("Rn", rn, "%s%d" % (p, rn), "value when the condition is true", None)
    o.reg("Rd", rd, "%s%d" % (p, rd), "destination", None)
    o.mn, o.ops = "fcsel", "%s%d, %s%d, %s%d, %s" % (p, rd, p, rn, p, rm, _CONDS[cond])
    o.form = "FCSEL <Vd>, <Vn>, <Vm>, <cond>"
    return True


def _h_fp_dp3(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    ftype, o1, rm, o0, ra, rn, rd = f["ftype"], f["o1"], f["Rm"], f["o0"], f["Ra"], f["Rn"], f["Rd"]
    p = _fp(ftype)
    if p is None or p == "h":
        return False
    mn = [["fmadd", "fmsub"], ["fnmadd", "fnmsub"]][o1][o0]
    _ftype_text(o, ftype)
    o.opc("o1", "o1 = %d and o0 = %d select %s (fused multiply-add: one rounding at the end)." % (o1, o0, mn.upper()))
    o.opc("o0", "o0 = %d: see o1." % o0)
    o.reg("Rm", rm, "%s%d" % (p, rm), "multiplier", None)
    o.reg("Ra", ra, "%s%d" % (p, ra), "addend", None)
    o.reg("Rn", rn, "%s%d" % (p, rn), "multiplicand", None)
    o.reg("Rd", rd, "%s%d" % (p, rd), "destination", None)
    o.mn, o.ops = mn, "%s%d, %s%d, %s%d, %s%d" % (p, rd, p, rn, p, rm, p, ra)
    o.form = "%s <Vd>, <Vn>, <Vm>, <Va>" % mn.upper()
    return True


# --- a little Advanced SIMD ---------------------------------------------------
def _h_simd_logic(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    q, u, size, rm, rn, rd = f["Q"], f["U"], f["size"], f["Rm"], f["Rn"], f["Rd"]
    mn = [["and", "bic", "orr", "orn"], ["eor", "bsl", "bit", "bif"]][u][size]
    arr = "16b" if q else "8b"
    o.opc("Q", "Q = 1: all 128 bits of the vector (16 bytes)." if q else "Q = 0: the low 64 bits of the vector (8 bytes).")
    o.opc("U", "U = %d and size = %s select %s among the bitwise vector operations." % (u, _binstr(size, 2), mn.upper()))
    o.opc("size", "size = %s: see U (for bitwise operations this field selects the operation, not an element size)." % _binstr(size, 2))
    o.reg("Rm", rm, "v%d.%s" % (rm, arr), "second operand", None)
    o.reg("Rn", rn, "v%d.%s" % (rn, arr), "first operand", None)
    o.reg("Rd", rd, "v%d.%s" % (rd, arr), "destination", None)
    o.form = "%s <Vd>.<T>, <Vn>.<T>, <Vm>.<T>" % mn.upper()
    if mn == "orr" and rm == rn:
        o.mn, o.ops = "mov", "v%d.%s, v%d.%s" % (rd, arr, rn, arr)
        o.notes.append("MOV between vector registers is an alias of ORR with Rn == Rm.")
    else:
        o.mn, o.ops = mn, "v%d.%s, v%d.%s, v%d.%s" % (rd, arr, rn, arr, rm, arr)
    return True


def _movi64(value: int) -> str:
    # llvm prints this operand with printf("%#016llx"): 16 columns including the 0x, and no 0x at all for zero.
    return "0000000000000000" if value == 0 else "0x%014x" % value


def _h_simd_movi(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    q, op, cmode, rd = f["Q"], f["op"], f["cmode"], f["Rd"]
    imm8 = (f["abc"] << 5) | f["defgh"]
    if cmode != 14:
        return False
    o.opc("Q", "Q = 1: 128-bit vector." if q else "Q = 0: 64-bit vector.")
    o.opc("op", "op = %d: with cmode = 1110 selects %s." % (op, "a 64-bit pattern where each bit of the immediate expands to one byte" if op else "an 8-bit immediate copied to every byte"))
    o.opc("cmode", "cmode = 1110: see op.")
    o.imm("abc", "a:b:c = %s: the high 3 bits of the 8-bit immediate." % _binstr(f["abc"], 3))
    o.imm("defgh", "d:e:f:g:h = %s: the low 5 bits of the 8-bit immediate." % _binstr(f["defgh"], 5))
    o.steps.append("imm8 = a:b:c:d:e:f:g:h = %s" % _binstr(imm8, 8))
    if op:
        value = 0
        for i in range(8):
            if imm8 & (1 << i):
                value |= 0xFF << (8 * i)
        o.steps.append("each bit of imm8 becomes one byte (0x00 or 0xff): 0x%016x" % value)
        if q:
            o.reg("Rd", rd, "v%d.2d" % rd, "destination", None)
            o.mn, o.ops = "movi", "v%d.2d, #%s" % (rd, _movi64(value))
        else:
            o.reg("Rd", rd, "d%d" % rd, "destination", None)
            o.mn, o.ops = "movi", "d%d, #%s" % (rd, _movi64(value))
        if value == 0:
            o.notes.append("MOVI with #0 is the usual way to zero a vector / floating-point register.")
    else:
        arr = "16b" if q else "8b"
        o.reg("Rd", rd, "v%d.%s" % (rd, arr), "destination", None)
        o.mn, o.ops = "movi", "v%d.%s, #0x%x" % (rd, arr, imm8)
    o.form = "MOVI <Vd>.<T>, #<imm>"
    return True


def _h_udf(f: Dict[str, int], word: int, pc: int, o: _A64Out) -> bool:
    o.imm("imm16", "imm16 = 0x%x: ignored by the processor." % f["imm16"])
    o.mn, o.ops = "udf", _imm(f["imm16"])
    o.notes.append("Permanently undefined: every encoding whose top 16 bits are zero is guaranteed to trap. A run of zero bytes "
                   "in a code section therefore disassembles as UDF #0, and is usually padding or data, not code.")
    o.form = "UDF #<imm16>"
    return True


_A64_CLASS_SPECS = [
    ("Permanently undefined", "0000000000000000 imm16:16", _h_udf),
    ("PC-relative addressing", "op:1 immlo:2 10000 immhi:19 Rd:5", _h_pcrel),
    ("Add/subtract (immediate)", "sf:1 op:1 S:1 100010 sh:1 imm12:12 Rn:5 Rd:5", _h_addsub_imm),
    ("Logical (immediate)", "sf:1 opc:2 100100 N:1 immr:6 imms:6 Rn:5 Rd:5", _h_logical_imm),
    ("Move wide (immediate)", "sf:1 opc:2 100101 hw:2 imm16:16 Rd:5", _h_movewide),
    ("Bitfield", "sf:1 opc:2 100110 N:1 immr:6 imms:6 Rn:5 Rd:5", _h_bitfield),
    ("Extract", "sf:1 00 100111 N:1 0 Rm:5 imms:6 Rn:5 Rd:5", _h_extract),
    ("Unconditional branch (immediate)", "op:1 00101 imm26:26", _h_b),
    ("Conditional branch (immediate)", "01010100 imm19:19 o0:1 cond:4", _h_bcond),
    ("Compare and branch (immediate)", "sf:1 011010 op:1 imm19:19 Rt:5", _h_cbz),
    ("Test and branch (immediate)", "b5:1 011011 op:1 b40:5 imm14:14 Rt:5", _h_tbz),
    ("Unconditional branch (register)", "1101011 opc:4 op2:5 op3:6 Rn:5 op4:5", _h_branch_reg),
    ("Exception generation", "11010100 opc:3 imm16:16 op2:3 LL:2", _h_exception),
    ("Hints", "11010101000000110010 CRm:4 op2:3 11111", _h_hint),
    ("System instructions and registers", "1101010100 L:1 op0:2 op1:3 CRn:4 CRm:4 op2:3 Rt:5", _h_system),
    ("Load/store exclusive, ordered, compare-and-swap", "size:2 001000 o2:1 L:1 o1:1 Rs:5 o0:1 Rt2:5 Rn:5 Rt:5", _h_ls_exclusive),
    ("Load register (literal)", "opc:2 011 V:1 00 imm19:19 Rt:5", _h_ls_literal),
    ("Load/store pair", "opc:2 101 V:1 0 mode:2 L:1 imm7:7 Rt2:5 Rn:5 Rt:5", _h_ls_pair),
    ("Load/store register (9-bit signed offset: unscaled, post-index, pre-index)", "size:2 111 V:1 00 opc:2 0 imm9:9 idx:2 Rn:5 Rt:5", _h_ls_imm9),
    ("Atomic memory operations", "size:2 111 V:1 00 A:1 R:1 1 Rs:5 o3:1 opc:3 00 Rn:5 Rt:5", _h_ls_atomic),
    ("Load/store register (register offset)", "size:2 111 V:1 00 opc:2 1 Rm:5 option:3 S:1 10 Rn:5 Rt:5", _h_ls_regoff),
    ("Load register with pointer authentication", "11111000 M:1 S:1 1 imm9:9 W:1 1 Rn:5 Rt:5", _h_ls_pac),
    ("Load/store register (unsigned immediate)", "size:2 111 V:1 01 opc:2 imm12:12 Rn:5 Rt:5", _h_ls_unsigned),
    ("Logical (shifted register)", "sf:1 opc:2 01010 shift:2 N:1 Rm:5 imm6:6 Rn:5 Rd:5", _h_logical_sreg),
    ("Add/subtract (shifted register)", "sf:1 op:1 S:1 01011 shift:2 0 Rm:5 imm6:6 Rn:5 Rd:5", _h_addsub_sreg),
    ("Add/subtract (extended register)", "sf:1 op:1 S:1 01011 00 1 Rm:5 option:3 imm3:3 Rn:5 Rd:5", _h_addsub_ext),
    ("Add/subtract (with carry)", "sf:1 op:1 S:1 11010000 Rm:5 000000 Rn:5 Rd:5", _h_adc),
    ("Conditional compare", "sf:1 op:1 1 11010010 y:5 cond:4 i:1 0 Rn:5 0 nzcv:4", _h_ccmp),
    ("Conditional select", "sf:1 op:1 0 11010100 Rm:5 cond:4 0 o2:1 Rn:5 Rd:5", _h_csel),
    ("Data-processing (3 source)", "sf:1 00 11011 op31:3 Rm:5 o0:1 Ra:5 Rn:5 Rd:5", _h_dp3),
    ("Data-processing (2 source)", "sf:1 0 0 11010110 Rm:5 opcode:6 Rn:5 Rd:5", _h_dp2),
    ("Data-processing (1 source)", "sf:1 1 0 11010110 opcode2:5 opcode:6 Rn:5 Rd:5", _h_dp1),
    ("Conversion between floating-point and integer", "sf:1 0 0 11110 ftype:2 1 rmode:2 opcode:3 000000 Rn:5 Rd:5", _h_fp_int),
    ("Floating-point data-processing (1 source)", "0 0 0 11110 ftype:2 1 opcode:6 10000 Rn:5 Rd:5", _h_fp_dp1),
    ("Floating-point compare", "0 0 0 11110 ftype:2 1 Rm:5 00 1000 Rn:5 opcode2:5", _h_fp_cmp),
    ("Floating-point immediate", "0 0 0 11110 ftype:2 1 imm8:8 100 00000 Rd:5", _h_fp_imm),
    ("Floating-point conditional compare", "0 0 0 11110 ftype:2 1 Rm:5 cond:4 01 Rn:5 op:1 nzcv:4", _h_fp_ccmp),
    ("Floating-point data-processing (2 source)", "0 0 0 11110 ftype:2 1 Rm:5 opcode:4 10 Rn:5 Rd:5", _h_fp_dp2),
    ("Floating-point conditional select", "0 0 0 11110 ftype:2 1 Rm:5 cond:4 11 Rn:5 Rd:5", _h_fp_csel),
    ("Floating-point data-processing (3 source)", "0 0 0 11111 ftype:2 o1:1 Rm:5 o0:1 Ra:5 Rn:5 Rd:5", _h_fp_dp3),
    ("Advanced SIMD three same (bitwise)", "0 Q:1 U:1 01110 size:2 1 Rm:5 00011 1 Rn:5 Rd:5", _h_simd_logic),
    ("Advanced SIMD modified immediate", "0 Q:1 op:1 0111100000 abc:3 cmode:4 01 defgh:5 Rd:5", _h_simd_movi),
]

_A64_GROUPS = [
    (0x1E000000, 0x00000000, "Reserved / SME"),
    (0x1E000000, 0x04000000, "SVE"),
    (0x1C000000, 0x10000000, "Data Processing -- Immediate"),
    (0x1C000000, 0x14000000, "Branches, Exception Generating and System instructions"),
    (0x0A000000, 0x08000000, "Loads and Stores"),
    (0x0E000000, 0x0A000000, "Data Processing -- Register"),
    (0x0E000000, 0x0E000000, "Data Processing -- Scalar Floating-Point and Advanced SIMD"),
]


def _compile_a64(pattern: str) -> Tuple[int, int, List[Tuple[Optional[str], int, int]]]:
    pos = 32
    mask = 0
    value = 0
    fields: List[Tuple[Optional[str], int, int]] = []
    for tok in pattern.split():
        if ":" in tok:
            name, width_s = tok.split(":")
            width = int(width_s)
            pos -= width
            fields.append((name, pos + width - 1, pos))
        else:
            width = len(tok)
            pos -= width
            for i, ch in enumerate(tok):
                bit = pos + width - 1 - i
                mask |= 1 << bit
                value |= int(ch) << bit
            if fields and fields[-1][0] is None:
                prev = fields.pop()
                fields.append((None, prev[1], pos))
            else:
                fields.append((None, pos + width - 1, pos))
    if pos != 0:
        raise ValueError("A64 pattern does not cover 32 bits: " + pattern)
    return mask, value, fields


_A64_CLASSES = [(title, pattern) + _compile_a64(pattern) + (handler,) for title, pattern, handler in _A64_CLASS_SPECS]


def _a64_field(name: str, hi: int, lo: int, word: int, kind: str, meaning: str) -> Dict[str, Any]:
    width = hi - lo + 1
    value = (word >> lo) & ((1 << width) - 1)
    return {"name": name, "hi": hi, "lo": lo, "width": width, "bits": _binstr(value, width), "value": value,
            "value_hex": "0x%x" % value, "kind": kind, "meaning": meaning}


def decode_a64(word: int, pc: int = 0, lite: bool = False) -> Dict[str, Any]:
    """Break one 32-bit A64 instruction word down into its fields.

    `lite=True` is the disassembler's fast path: the same decode logic and text, without the field list,
    steps and notes (keys: status, mnemonic, operands, text, encoding_class, target, target_kind, gaps)."""
    word &= 0xFFFFFFFF
    pc &= _M64
    for title, pattern, mask, value, layout, handler in _A64_CLASSES:
        if (word & mask) != value:
            continue
        f = {name: (word >> lo) & ((1 << (hi - lo + 1)) - 1) for name, hi, lo in layout if name}
        out = _A64Out(lite)
        if not handler(f, word, pc, out):
            continue
        if lite:
            return {"status": out.status, "mnemonic": out.mn, "operands": out.ops, "text": (out.mn + " " + out.ops).strip(),
                    "encoding_class": title, "gaps": out.gaps, "target_kind": out.target_kind,
                    "target": ("0x%x" % out.target) if out.target is not None else None}
        fields = []
        for name, hi, lo in layout:
            if name is None:
                fields.append(_a64_field("fixed", hi, lo, word, "fixed",
                                         "Fixed bits %d:%d = %s: they identify the encoding class '%s'."
                                         % (hi, lo, _binstr((word >> lo), hi - lo + 1), title)))
            else:
                fields.append(_a64_field(name, hi, lo, word, out.kinds.get(name, "opc"),
                                         out.meaning.get(name, "%s = %s." % (name, _binstr(f[name], hi - lo + 1)))))
        text = (out.mn + " " + out.ops).strip()
        return {"status": out.status, "mnemonic": out.mn, "operands": out.ops, "text": text, "encoding_class": title,
                "pattern": pattern, "form": out.form, "fields": fields, "steps": out.steps, "notes": out.notes,
                "gaps": out.gaps, "target_kind": out.target_kind,
                "target": ("0x%x" % out.target) if out.target is not None else None}
    group = "Unallocated"
    for mask, value, name in _A64_GROUPS:
        if (word & mask) == value:
            group = name
            break
    if lite:
        return {"status": "not_decoded", "mnemonic": "", "operands": "", "text": "", "encoding_class": group, "gaps": [],
                "target": None, "target_kind": None}
    fields = [_a64_field("not decoded", 31, 29, word, "unknown", "Not decoded by this lab.")]
    fields.append(_a64_field("op0", 28, 25, word, "opc",
                             "Bits 28:25 = %s select the top-level encoding group: %s." % (_binstr(word >> 25, 4), group)))
    fields.append(_a64_field("not decoded", 24, 0, word, "unknown", "Not decoded by this lab."))
    return {"status": "not_decoded", "mnemonic": "", "operands": "", "text": "", "encoding_class": group, "pattern": "",
            "form": "", "fields": fields, "steps": [], "notes": [],
            "gaps": ["This word belongs to the group '%s', but it is outside the instruction classes this lab breaks down "
                     "(or it is an unallocated encoding in a class it knows). Only the group selector is shown." % group],
            "target": None, "target_kind": None}


# ===========================================================================
# x86 / x86-64
# ===========================================================================
_R64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
_R32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"] + ["r%dd" % i for i in range(8, 16)]
_R16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"] + ["r%dw" % i for i in range(8, 16)]
_R8_LEGACY = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]
_R8_REX = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"] + ["r%db" % i for i in range(8, 16)]
_SEGS = {0x26: "es", 0x2E: "cs", 0x36: "ss", 0x3E: "ds", 0x64: "fs", 0x65: "gs"}
_CC = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"]
_CC_TEXT = ["overflow (OF=1)", "no overflow (OF=0)", "below, unsigned < (CF=1)", "above or equal, unsigned >= (CF=0)",
            "equal / zero (ZF=1)", "not equal / not zero (ZF=0)", "below or equal, unsigned <= (CF=1 or ZF=1)",
            "above, unsigned > (CF=0 and ZF=0)", "sign (SF=1)", "no sign (SF=0)", "parity even (PF=1)", "parity odd (PF=0)",
            "less, signed < (SF != OF)", "greater or equal, signed >= (SF == OF)", "less or equal, signed <= (ZF=1 or SF != OF)",
            "greater, signed > (ZF=0 and SF == OF)"]
_PTR = {8: "byte", 16: "word", 32: "dword", 64: "qword", 128: "xmmword"}
_ALU = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
_SHIFT_GRP = ["rol", "ror", "rcl", "rcr", "shl", "shr", None, "sar"]

# Table entry: (mnemonic, operand codes, flags). Operand codes follow the Intel SDM opcode-map notation
# (appendix A): E = ModRM r/m (register or memory), G = ModRM reg, I = immediate, J = relative branch,
# M = ModRM memory only, Z = register in the low 3 bits of the opcode, V/W = XMM reg / XMM r/m;
# b/w/d/q = fixed size, v = operand size (16/32/64), z = 16 or 32, y = 32 or 64.
# Flags: "d64" = operand size defaults to 64 bits in 64-bit mode; "64" = only valid in 64-bit mode;
# "32" = only valid outside 64-bit mode; "str" = string instruction (accepts REP); "lock" = may take LOCK.
_X1: Dict[int, Any] = {}
_X2: Dict[int, Any] = {}

for _i, _mn in enumerate(_ALU):
    _b = _i * 8
    _X1[_b + 0] = (_mn, "Eb,Gb", "lock")
    _X1[_b + 1] = (_mn, "Ev,Gv", "lock")
    _X1[_b + 2] = (_mn, "Gb,Eb", "")
    _X1[_b + 3] = (_mn, "Gv,Ev", "")
    _X1[_b + 4] = (_mn, "AL,Ib", "")
    _X1[_b + 5] = (_mn, "rAX,Iz", "")
for _i in range(8):
    _X1[0x40 + _i] = ("inc", "Zv", "32")
    _X1[0x48 + _i] = ("dec", "Zv", "32")
    _X1[0x50 + _i] = ("push", "Zv", "d64")
    _X1[0x58 + _i] = ("pop", "Zv", "d64")
    _X1[0xB0 + _i] = ("mov", "Zb,Ib", "")
    _X1[0xB8 + _i] = ("mov", "Zv,Iv", "")
    if _i:
        _X1[0x90 + _i] = ("xchg", "rAX,Zv", "")
for _i, _c in enumerate(_CC):
    _X1[0x70 + _i] = ("j" + _c, "Jb", "cc d64")
    _X2[0x80 + _i] = ("j" + _c, "Jz", "cc d64")
    _X2[0x90 + _i] = ("set" + _c, "Eb", "cc")
    _X2[0x40 + _i] = ("cmov" + _c, "Gv,Ev", "cc")
_X1.update({
    0x63: ("movsxd", "Gv,Ed", "64"),
    0x68: ("push", "Iz", "d64"), 0x6A: ("push", "Ibs", "d64"),
    0x69: ("imul", "Gv,Ev,Iz", ""), 0x6B: ("imul", "Gv,Ev,Ibs", ""),
    0x80: [(m, "Eb,Ib", "lock") for m in _ALU],
    0x81: [(m, "Ev,Iz", "lock") for m in _ALU],
    0x83: [(m, "Ev,Ibs", "lock") for m in _ALU],
    0x84: ("test", "Eb,Gb", ""), 0x85: ("test", "Ev,Gv", ""),
    0x86: ("xchg", "Eb,Gb", "lock"), 0x87: ("xchg", "Ev,Gv", "lock"),
    0x88: ("mov", "Eb,Gb", ""), 0x89: ("mov", "Ev,Gv", ""), 0x8A: ("mov", "Gb,Eb", ""), 0x8B: ("mov", "Gv,Ev", ""),
    0x8D: ("lea", "Gv,M", ""),
    0x8F: [("pop", "Ev", "d64")] + [None] * 7,
    0x90: ("nop", "", ""),
    0x98: ("cbw/cwde/cdqe", "", ""), 0x99: ("cwd/cdq/cqo", "", ""),
    0xA4: ("movs", "Yb,Xb", "str"), 0xA5: ("movs", "Yv,Xv", "str"),
    0xAA: ("stos", "Yb,AL", "str"), 0xAB: ("stos", "Yv,rAX", "str"),
    0xA8: ("test", "AL,Ib", ""), 0xA9: ("test", "rAX,Iz", ""),
    0xA0: ("mov", "AL,Ob", ""), 0xA1: ("mov", "rAX,Ov", ""), 0xA2: ("mov", "Ob,AL", ""), 0xA3: ("mov", "Ov,rAX", ""),
    0xC0: [(m, "Eb,Ibu", "") if m else None for m in _SHIFT_GRP],
    0xC1: [(m, "Ev,Ibu", "") if m else None for m in _SHIFT_GRP],
    0xD0: [(m, "Eb,1", "") if m else None for m in _SHIFT_GRP],
    0xD1: [(m, "Ev,1", "") if m else None for m in _SHIFT_GRP],
    0xD2: [(m, "Eb,CL", "") if m else None for m in _SHIFT_GRP],
    0xD3: [(m, "Ev,CL", "") if m else None for m in _SHIFT_GRP],
    0xC2: ("ret", "Iw", "d64"), 0xC3: ("ret", "", "d64"), 0xC9: ("leave", "", "d64"),
    0xC6: [("mov", "Eb,Ib", "")] + [None] * 7, 0xC7: [("mov", "Ev,Iz", "")] + [None] * 7,
    0xCC: ("int3", "", ""), 0xCD: ("int", "Ibu", ""),
    0xE8: ("call", "Jz", "d64"), 0xE9: ("jmp", "Jz", "d64"), 0xEB: ("jmp", "Jb", "d64"),
    0xF4: ("hlt", "", ""), 0xF5: ("cmc", "", ""), 0xF8: ("clc", "", ""), 0xF9: ("stc", "", ""),
    0xFA: ("cli", "", ""), 0xFB: ("sti", "", ""), 0xFC: ("cld", "", ""), 0xFD: ("std", "", ""),
    0xF6: [("test", "Eb,Ib", ""), None, ("not", "Eb", "lock"), ("neg", "Eb", "lock"), ("mul", "Eb", ""), ("imul", "Eb", ""),
           ("div", "Eb", ""), ("idiv", "Eb", "")],
    0xF7: [("test", "Ev,Iz", ""), None, ("not", "Ev", "lock"), ("neg", "Ev", "lock"), ("mul", "Ev", ""), ("imul", "Ev", ""),
           ("div", "Ev", ""), ("idiv", "Ev", "")],
    0xFE: [("inc", "Eb", "lock"), ("dec", "Eb", "lock")] + [None] * 6,
    0xFF: [("inc", "Ev", "lock"), ("dec", "Ev", "lock"), ("call", "Ev", "d64"), None, ("jmp", "Ev", "d64"), None,
           ("push", "Ev", "d64"), None],
})


def _sse(ps: Any = None, pd: Any = None, ss: Any = None, sd: Any = None) -> Dict[str, Any]:
    return {k: v for k, v in (("", ps), ("66", pd), ("F3", ss), ("F2", sd)) if v is not None}


def _sse_arith(stem: str) -> Dict[str, Any]:
    return _sse((stem + "ps", "Vx,Wx", ""), (stem + "pd", "Vx,Wx", ""), (stem + "ss", "Vx,Wd", ""), (stem + "sd", "Vx,Wq", ""))


_X2.update({
    0x05: ("syscall", "", "64"), 0x0B: ("ud2", "", ""), 0xA2: ("cpuid", "", ""), 0x31: ("rdtsc", "", ""),
    0x1F: [("nop", "Ev", "")] + [None] * 7,
    0x10: _sse(("movups", "Vx,Wx", ""), ("movupd", "Vx,Wx", ""), ("movss", "Vx,Wd", ""), ("movsd", "Vx,Wq", "")),
    0x11: _sse(("movups", "Wx,Vx", ""), ("movupd", "Wx,Vx", ""), ("movss", "Wd,Vx", ""), ("movsd", "Wq,Vx", "")),
    0x12: _sse(("movlps", "Vx,Wq", "hl"), ("movlpd", "Vx,Mq", "")),
    0x13: _sse(("movlps", "Mq,Vx", ""), ("movlpd", "Mq,Vx", "")),
    0x14: _sse(("unpcklps", "Vx,Wx", ""), ("unpcklpd", "Vx,Wx", "")),
    0x15: _sse(("unpckhps", "Vx,Wx", ""), ("unpckhpd", "Vx,Wx", "")),
    0x16: _sse(("movhps", "Vx,Wq", "lh"), ("movhpd", "Vx,Mq", "")),
    0x17: _sse(("movhps", "Mq,Vx", ""), ("movhpd", "Mq,Vx", "")),
    0x28: _sse(("movaps", "Vx,Wx", ""), ("movapd", "Vx,Wx", "")),
    0x29: _sse(("movaps", "Wx,Vx", ""), ("movapd", "Wx,Vx", "")),
    0x2A: _sse(None, None, ("cvtsi2ss", "Vx,Ey", ""), ("cvtsi2sd", "Vx,Ey", "")),
    0x2C: _sse(None, None, ("cvttss2si", "Gy,Wd", ""), ("cvttsd2si", "Gy,Wq", "")),
    0x2D: _sse(None, None, ("cvtss2si", "Gy,Wd", ""), ("cvtsd2si", "Gy,Wq", "")),
    0x2E: _sse(("ucomiss", "Vx,Wd", ""), ("ucomisd", "Vx,Wq", "")),
    0x2F: _sse(("comiss", "Vx,Wd", ""), ("comisd", "Vx,Wq", "")),
    0x50: _sse(("movmskps", "Gd,Ux", ""), ("movmskpd", "Gd,Ux", "")),
    0x51: _sse_arith("sqrt"),
    0x54: _sse(("andps", "Vx,Wx", ""), ("andpd", "Vx,Wx", "")),
    0x55: _sse(("andnps", "Vx,Wx", ""), ("andnpd", "Vx,Wx", "")),
    0x56: _sse(("orps", "Vx,Wx", ""), ("orpd", "Vx,Wx", "")),
    0x57: _sse(("xorps", "Vx,Wx", ""), ("xorpd", "Vx,Wx", "")),
    0x58: _sse_arith("add"), 0x59: _sse_arith("mul"), 0x5C: _sse_arith("sub"), 0x5D: _sse_arith("min"),
    0x5E: _sse_arith("div"), 0x5F: _sse_arith("max"),
    0x5A: _sse(("cvtps2pd", "Vx,Wq", ""), ("cvtpd2ps", "Vx,Wx", ""), ("cvtss2sd", "Vx,Wd", ""), ("cvtsd2ss", "Vx,Wq", "")),
    0x5B: _sse(("cvtdq2ps", "Vx,Wx", ""), ("cvtps2dq", "Vx,Wx", ""), ("cvttps2dq", "Vx,Wx", "")),
    0x6E: _sse(None, ("movd", "Vx,Ey", "")),
    0x7E: _sse(None, ("movd", "Ey,Vx", ""), ("movq", "Vx,Wq", "nw")),
    0xD6: _sse(None, ("movq", "Wq,Vx", "")),
    0x6F: _sse(None, ("movdqa", "Vx,Wx", ""), ("movdqu", "Vx,Wx", "")),
    0x7F: _sse(None, ("movdqa", "Wx,Vx", ""), ("movdqu", "Wx,Vx", "")),
    0x70: _sse(None, ("pshufd", "Vx,Wx,Ibu", ""), ("pshufhw", "Vx,Wx,Ibu", ""), ("pshuflw", "Vx,Wx,Ibu", "")),
    0xC6: _sse(("shufps", "Vx,Wx,Ibu", ""), ("shufpd", "Vx,Wx,Ibu", "")),
    0xC4: _sse(None, ("pinsrw", "Vx,Qw,Ibu", "")),
    0xC5: _sse(None, ("pextrw", "Gd,Ux,Ibu", "")),
    0xC2: _sse(("cmpps", "Vx,Wx,Ibu", "cmp"), ("cmppd", "Vx,Wx,Ibu", "cmp"), ("cmpss", "Vx,Wd,Ibu", "cmp"), ("cmpsd", "Vx,Wq,Ibu", "cmp")),
    0x7C: _sse(None, ("haddpd", "Vx,Wx", ""), None, ("haddps", "Vx,Wx", "")),
    0xD7: _sse(None, ("pmovmskb", "Gd,Ux", "")),
    0xE6: _sse(None, ("cvttpd2dq", "Vx,Wx", ""), ("cvtdq2pd", "Vx,Wq", ""), ("cvtpd2dq", "Vx,Wx", "")),
    0xA3: ("bt", "Ev,Gv", ""), 0xAB: ("bts", "Ev,Gv", "lock"), 0xB3: ("btr", "Ev,Gv", "lock"), 0xBB: ("btc", "Ev,Gv", "lock"),
    0xBA: [None, None, None, None, ("bt", "Ev,Ibu", ""), ("bts", "Ev,Ibu", "lock"), ("btr", "Ev,Ibu", "lock"), ("btc", "Ev,Ibu", "lock")],
    0xA4: ("shld", "Ev,Gv,Ibu", ""), 0xA5: ("shld", "Ev,Gv,CL", ""),
    0xAC: ("shrd", "Ev,Gv,Ibu", ""), 0xAD: ("shrd", "Ev,Gv,CL", ""),
    0xAF: ("imul", "Gv,Ev", ""),
    0xB0: ("cmpxchg", "Eb,Gb", "lock"), 0xB1: ("cmpxchg", "Ev,Gv", "lock"),
    0xC0: ("xadd", "Eb,Gb", "lock"), 0xC1: ("xadd", "Ev,Gv", "lock"),
    0xB6: ("movzx", "Gv,Eb", ""), 0xB7: ("movzx", "Gv,Ew", ""), 0xBE: ("movsx", "Gv,Eb", ""), 0xBF: ("movsx", "Gv,Ew", ""),
    0xB8: {"F3": ("popcnt", "Gv,Ev", "")},
    0xBC: {"": ("bsf", "Gv,Ev", ""), "66": ("bsf", "Gv,Ev", "os"), "F3": ("tzcnt", "Gv,Ev", "")},
    0xBD: {"": ("bsr", "Gv,Ev", ""), "66": ("bsr", "Gv,Ev", "os"), "F3": ("lzcnt", "Gv,Ev", "")},
})
for _i in range(8):
    _X2[0xC8 + _i] = ("bswap", "Zy", "")
for _op, _mn in ((0x60, "punpcklbw"), (0x61, "punpcklwd"), (0x62, "punpckldq"), (0x63, "packsswb"), (0x64, "pcmpgtb"),
                 (0x65, "pcmpgtw"), (0x66, "pcmpgtd"), (0x67, "packuswb"), (0x68, "punpckhbw"), (0x69, "punpckhwd"),
                 (0x6A, "punpckhdq"), (0x6B, "packssdw"), (0x6C, "punpcklqdq"), (0x6D, "punpckhqdq"),
                 (0x74, "pcmpeqb"), (0x75, "pcmpeqw"), (0x76, "pcmpeqd"),
                 (0xD1, "psrlw"), (0xD2, "psrld"), (0xD3, "psrlq"), (0xD4, "paddq"), (0xD5, "pmullw"),
                 (0xD8, "psubusb"), (0xD9, "psubusw"), (0xDA, "pminub"), (0xDB, "pand"), (0xDC, "paddusb"),
                 (0xDD, "paddusw"), (0xDE, "pmaxub"), (0xDF, "pandn"), (0xE0, "pavgb"), (0xE1, "psraw"), (0xE2, "psrad"),
                 (0xE3, "pavgw"), (0xE4, "pmulhuw"), (0xE5, "pmulhw"), (0xE8, "psubsb"), (0xE9, "psubsw"),
                 (0xEA, "pminsw"), (0xEB, "por"), (0xEC, "paddsb"), (0xED, "paddsw"), (0xEE, "pmaxsw"), (0xEF, "pxor"),
                 (0xF1, "psllw"), (0xF2, "pslld"), (0xF3, "psllq"), (0xF4, "pmuludq"), (0xF5, "pmaddwd"), (0xF6, "psadbw"),
                 (0xF8, "psubb"), (0xF9, "psubw"), (0xFA, "psubd"), (0xFB, "psubq"), (0xFC, "paddb"), (0xFD, "paddw"),
                 (0xFE, "paddd")):
    _X2[_op] = {"66": (_mn, "Vx,Wx", "")}
_X2[0x71] = {"66": [None, None, ("psrlw", "Ux,Ibu", ""), None, ("psraw", "Ux,Ibu", ""), None, ("psllw", "Ux,Ibu", ""), None]}
_X2[0x72] = {"66": [None, None, ("psrld", "Ux,Ibu", ""), None, ("psrad", "Ux,Ibu", ""), None, ("pslld", "Ux,Ibu", ""), None]}
_X2[0x73] = {"66": [None, None, ("psrlq", "Ux,Ibu", ""), ("psrldq", "Ux,Ibu", ""), None, None, ("psllq", "Ux,Ibu", ""),
                    ("pslldq", "Ux,Ibu", "")]}

_PREFIX_TEXT = {
    0xF0: ("LOCK", "LOCK: the read-modify-write of the memory operand is atomic. Only valid with a memory destination on a "
                   "small set of instructions; anywhere else it raises #UD."),
    0xF2: ("REPNE", "REPNE/REPNZ: repeat a string instruction while (r/e)cx != 0 and ZF == 0. Before an SSE opcode the same "
                    "byte is a mandatory prefix that selects a different instruction."),
    0xF3: ("REP", "REP/REPE: repeat a string instruction (r/e)cx times (and, for CMPS/SCAS, while ZF == 1). Before an SSE "
                  "opcode the same byte is a mandatory prefix that selects a different instruction."),
    0x66: ("operand-size", "Operand-size override: switches the operand size between 32 and 16 bits. Before an SSE opcode "
                           "the same byte is a mandatory prefix that selects a different instruction."),
    0x67: ("address-size", "Address-size override: effective addresses are computed with 32-bit registers in 64-bit mode "
                           "(16-bit in 32-bit mode)."),
}


class _X86Stop(Exception):
    """Decoding cannot continue. `kind`: 'truncated' or 'not_decoded'."""

    def __init__(self, kind: str, reason: str, length_known: bool = False) -> None:
        Exception.__init__(self, reason)
        self.kind = kind
        self.reason = reason
        self.length_known = length_known   # not decoded, but the bytes consumed so far are the whole instruction


class _X86State:
    __slots__ = ("buf", "start", "pos", "end", "bits", "pc", "fields", "steps", "notes", "prefixes", "rex", "rex_pos",
                 "osz", "asz", "seg", "modrm", "modrm_pos", "mod", "reg", "rm", "mem", "target", "rex_used",
                 "pfx_used", "mand", "pfx_done", "lite", "target_kind")

    def __init__(self, buf: bytes, pos: int, pc: int, bits: int, lite: bool = False) -> None:
        self.lite = lite
        self.target_kind: Optional[str] = None
        self.buf = buf
        self.start = pos
        self.pos = pos
        self.end = min(len(buf), pos + 15)
        self.bits = bits
        self.pc = pc
        self.fields: List[Dict[str, Any]] = []
        self.steps: List[str] = []
        self.notes: List[str] = []
        self.prefixes: List[Tuple[int, int]] = []   # (byte, position)
        self.rex = 0
        self.rex_pos = -1
        self.osz = 32
        self.asz = bits
        self.seg: Optional[str] = None
        self.modrm = -1
        self.modrm_pos = -1
        self.mod = self.reg = self.rm = 0
        self.mem: Optional[Dict[str, Any]] = None
        self.target: Optional[int] = None
        self.rex_used = {"W": "", "R": "", "X": "", "B": ""}
        self.pfx_used: Dict[int, str] = {}
        self.mand = ""
        self.pfx_done = False

    def take(self) -> int:
        if self.pos >= self.end:
            if self.pos - self.start >= 15:
                raise _X86Stop("not_decoded", "An x86 instruction is at most 15 bytes long; this byte sequence does not "
                                              "end within that limit, so it is not a valid instruction.")
            raise _X86Stop("truncated", "The bytes end in the middle of this instruction.")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def rel(self, pos: int) -> int:
        return pos - self.start

    def field(self, name: str, pos: int, nbytes: int, hi: int, lo: int, value: int, kind: str, group: str, meaning: str) -> None:
        if self.lite:
            return
        if nbytes == 1:
            width = hi - lo + 1
            bits = _binstr(value, width)
        else:
            bits = " ".join("%02x" % b for b in self.buf[pos:pos + nbytes])
        self.fields.append({"name": name, "byte": self.rel(pos), "nbytes": nbytes, "hi": hi, "lo": lo, "bits": bits,
                            "value": value if value < (1 << 53) else None, "value_hex": "0x%x" % value, "kind": kind,
                            "group": group, "meaning": meaning})


def _x86_reg(st: _X86State, n: int, size: int) -> str:
    if size == 64:
        return _R64[n]
    if size == 32:
        return _R32[n]
    if size == 16:
        return _R16[n]
    if size == 8:
        return _R8_REX[n] if (st.rex or n >= 8) else _R8_LEGACY[n]
    if size == 128:
        return "xmm%d" % n
    raise _X86Stop("not_decoded", "Unsupported register size.")


def _le_text(raw: bytes) -> str:
    if len(raw) == 1:
        return "byte %02x" % raw[0]
    return "bytes %s read little-endian (last byte is the most significant) = 0x%s" % (
        " ".join("%02x" % b for b in raw), "".join("%02x" % b for b in reversed(raw)))


def _x86_read_imm(st: _X86State, nbytes: int, name: str, kind: str, signed: bool, meaning: str) -> int:
    pos = st.pos
    raw = bytes(st.take() for _ in range(nbytes))
    value = int.from_bytes(raw, "little")
    sval = _sx(value, nbytes * 8) if signed else value
    if st.lite:
        return sval
    text = "%s = %s" % (name, _le_text(raw))
    if signed:
        text += "; as a signed %d-bit number: %s" % (nbytes * 8, _hx(sval))
    st.steps.append(text)
    st.field(name, pos, nbytes, nbytes * 8 - 1, 0, value, kind, kind, meaning)
    return sval


def _x86_skip_modrm(st: _X86State) -> None:
    """Consume a ModRM byte with its SIB byte and displacement, without interpreting the operands. Their layout
    does not depend on the instruction, which is what lets the length of an undecoded instruction be known."""
    if st.asz == 16:
        raise _X86Stop("not_decoded", "16-bit addressing (address-size prefix in 32-bit mode) uses a different ModRM table "
                                      "that this lab does not decode.")
    b = st.take()
    mod, rm = b >> 6, b & 7
    if mod == 3:
        return
    disp = {0: 0, 1: 1, 2: 4}[mod]
    if rm == 4:
        sib = st.take()
        if (sib & 7) == 5 and mod == 0:
            disp = 4
    elif rm == 5 and mod == 0:
        disp = 4
    for _ in range(disp):
        st.take()


# Length rules for instructions that exist but are not in the decode tables: opcode -> (has ModRM, immediate).
# The immediate is a byte count, "z" (2 bytes with an operand-size prefix, else 4) or "p" (a far pointer:
# "z" plus a 16-bit selector). They let the disassembler step over such an instruction instead of guessing
# where the next one starts. Opcodes that are undefined are deliberately absent: there is no length to know.
def _x86_len_table(no_modrm: Any = (), imm8: Any = (), modrm: Any = (), modrm_imm8: Any = ()) -> Dict[int, Tuple[bool, Any]]:
    table: Dict[int, Tuple[bool, Any]] = {}
    for group, rule in ((no_modrm, (False, 0)), (imm8, (False, 1)), (modrm, (True, 0)), (modrm_imm8, (True, 1))):
        for item in group:
            for op in (range(item[0], item[1] + 1) if isinstance(item, tuple) else (item,)):
                table[op] = rule
    return table


_X1_LEN = _x86_len_table(
    no_modrm=[(0x6C, 0x6F), (0x9B, 0x9F), 0xA6, 0xA7, (0xAC, 0xAF), 0xCB, 0xCF, 0xD7, (0xEC, 0xEF), 0xF1],
    imm8=[(0xE0, 0xE7)],             # LOOPNE/LOOPE/LOOP/JCXZ rel8, IN/OUT imm8
    modrm=[0x8C, 0x8E],              # MOV to/from a segment register
)
_X1_LEN[0xC8] = (False, 3)           # ENTER imm16, imm8
_X1_LEN[0xCA] = (False, 2)           # RETF imm16
_X1_LEN_32 = _x86_len_table(         # valid only outside 64-bit mode
    no_modrm=[0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F, 0x60, 0x61, 0xCE, 0xD6],
    imm8=[0xD4, 0xD5],
    modrm=[0x62, 0x63, 0xC4, 0xC5],  # BOUND, ARPL, LES, LDS
    modrm_imm8=[0x82],
)
_X1_LEN_32[0x9A] = _X1_LEN_32[0xEA] = (False, "p")
_X1_GROUP_LEN = {                    # (opcode, ModRM.reg) of opcode groups
    (0xF6, 1): (True, 1), (0xF7, 1): (True, "z"), (0xFF, 3): (True, 0), (0xFF, 5): (True, 0),
    (0xC0, 6): (True, 1), (0xC1, 6): (True, 1), (0xD0, 6): (True, 0), (0xD1, 6): (True, 0), (0xD2, 6): (True, 0),
    (0xD3, 6): (True, 0),
}
_X2_LEN = _x86_len_table(
    no_modrm=[(0x06, 0x09), 0x0E, 0x30, (0x32, 0x35), 0x37, 0x77, 0xA0, 0xA1, 0xA8, 0xA9, 0xAA],
    modrm=[(0x00, 0x03), 0x0D, (0x10, 0x23), (0x28, 0x2F), (0x40, 0x6F), (0x74, 0x76), (0x7C, 0x7F),
           (0x90, 0x9F), 0xA3, 0xA5, 0xAB, (0xAD, 0xB7), 0xB9, (0xBB, 0xC1), 0xC3, 0xC7, (0xD0, 0xFE)],
    modrm_imm8=[0x0F, (0x70, 0x73), 0xA4, 0xAC, 0xBA, 0xC2, (0xC4, 0xC6)],
)


def _x86_skip_by_rule(st: _X86State, rule: Tuple[bool, Any], opsize16: bool) -> None:
    has_modrm, imm = rule
    if has_modrm:
        _x86_skip_modrm(st)
    count = {"z": 2 if opsize16 else 4, "p": 4 if opsize16 else 6}.get(imm, imm)
    for _ in range(count):
        st.take()


def _x86_skip_vex(st: _X86State, lead: int) -> bool:
    """After a VEX (C4, C5) or EVEX (62) lead byte: consume the rest of the instruction if its length follows from
    the opcode map. Maps 1-3 mirror the legacy maps 0F, 0F 38 and 0F 3A: one opcode byte, a ModRM operand (except
    VZEROUPPER/VZEROALL), and an imm8 for all of map 3 and a fixed handful of map 1 opcodes."""
    start = st.pos
    if lead == 0xC5:
        st.take()
        opmap = 1
    elif lead == 0xC4:
        opmap = st.take() & 0x1F
        st.take()
    else:
        opmap = st.take() & 0x07
        st.take()
        st.take()
    if opmap not in (1, 2, 3):
        st.pos = start
        return False
    opcode = st.take()
    if opmap == 1 and opcode == 0x77 and lead != 0x62:
        return True
    _x86_skip_modrm(st)
    if opmap == 3 or (opmap == 1 and opcode in (0x70, 0x71, 0x72, 0x73, 0xC2, 0xC4, 0xC5, 0xC6)):
        st.take()
    return True


def _x86_modrm(st: _X86State, reg_is_ext: Optional[str]) -> None:
    """Read ModRM (+SIB, +displacement) and record their fields. `reg_is_ext`: text when reg is an opcode extension."""
    pos = st.pos
    b = st.take()
    st.modrm, st.modrm_pos = b, pos
    mod, reg, rm = b >> 6, (b >> 3) & 7, b & 7
    st.mod, st.reg, st.rm = mod, reg, rm
    rex_r, rex_x, rex_b = (st.rex >> 2) & 1, (st.rex >> 1) & 1, st.rex & 1
    in64 = st.bits == 64
    if st.asz == 16:
        raise _X86Stop("not_decoded", "16-bit addressing (address-size prefix in 32-bit mode) uses a different ModRM table "
                                      "that this lab does not decode.")
    areg = _R64 if st.asz == 64 else _R32
    mod_text = {
        0: "mod = 00: memory operand without displacement. Exceptions: rm = 101 means a 32-bit displacement with no base "
           "register%s, and rm = 100 means a SIB byte follows." % (" (RIP-relative in 64-bit mode)" if in64 else ""),
        1: "mod = 01: memory operand, base register plus an 8-bit displacement (sign-extended).",
        2: "mod = 10: memory operand, base register plus a 32-bit displacement%s." % (" (sign-extended to 64 bits)" if in64 else ""),
        3: "mod = 11: the r/m operand is a register, there is no memory access.",
    }[mod]
    st.field("mod", pos, 1, 7, 6, mod, "mod", "modrm", mod_text)
    if reg_is_ext is not None:
        st.field("reg", pos, 1, 5, 3, reg, "opc", "modrm",
                 "reg = %s: here not a register but an opcode extension (/%d): %s. REX.R is ignored for it." % (_binstr(reg, 3), reg, reg_is_ext))
    else:
        st.field("reg", pos, 1, 5, 3, reg, "reg", "modrm",
                 "reg = %s: register operand number %d%s. Which register that is depends on the operand size (see the operands)."
                 % (_binstr(reg, 3), reg | (rex_r << 3), (" (REX.R = 1 adds 8 to the 3-bit value %d)" % reg) if rex_r else ""))
    mem: Optional[Dict[str, Any]] = None
    if mod == 3:
        st.field("rm", pos, 1, 2, 0, rm, "reg", "modrm",
                 "rm = %s: register operand number %d%s (mod = 11)." % (_binstr(rm, 3), rm | (rex_b << 3),
                                                                      (" (REX.B = 1 adds 8 to the 3-bit value %d)" % rm) if rex_b else ""))
        st.rex_used["B"] = "extends ModRM.rm"
    else:
        mem = {"base": None, "index": None, "scale": 1, "disp": 0, "rip": False, "has_disp": False}
        disp_size = {0: 0, 1: 1, 2: 4}[mod]
        if rm == 4:
            st.field("rm", pos, 1, 2, 0, rm, "mod", "modrm",
                     "rm = 100 with mod != 11: a SIB byte follows and describes the address. rm = 100 never selects "
                     "rsp/esp (or r12) as a plain base; to use them as a base the SIB byte is required. REX.B is not "
                     "applied here but to SIB.base.")
            spos = st.pos
            sib = st.take()
            scale, index, base = sib >> 6, (sib >> 3) & 7, sib & 7
            st.field("scale", spos, 1, 7, 6, scale, "imm", "sib",
                     "scale = %s: the index register is multiplied by %d (2^scale)." % (_binstr(scale, 2), 1 << scale))
            idx_n = index | (rex_x << 3)
            if idx_n == 4:
                st.field("index", spos, 1, 5, 3, index, "reg", "sib",
                         "index = 100 with REX.X = 0: no index register. This is the exception that makes rsp/esp unusable "
                         "as an index; the scale field is then ignored.")
            else:
                mem["index"], mem["scale"] = areg[idx_n], 1 << scale
                st.field("index", spos, 1, 5, 3, index, "reg", "sib",
                         "index = %s: index register number %d = %s%s." % (
                             _binstr(index, 3), idx_n, areg[idx_n],
                             " (REX.X = 1 adds 8; note that 100 with REX.X = 1 is r12, a valid index)" if rex_x else ""))
                st.rex_used["X"] = "extends SIB.index"
            if base == 5 and mod == 0:
                disp_size = 4
                st.field("base", spos, 1, 2, 0, base, "reg", "sib",
                         "base = 101 with mod = 00: no base register; a 32-bit displacement follows instead. This is the "
                         "exception for 101 (rbp/ebp, r13): to use those as a base, mod must be 01 or 10 with an explicit "
                         "displacement (possibly 0).")
            else:
                base_n = base | (rex_b << 3)
                mem["base"] = areg[base_n]
                st.field("base", spos, 1, 2, 0, base, "reg", "sib",
                         "base = %s: base register number %d = %s%s." % (_binstr(base, 3), base_n, areg[base_n],
                                                                         " (REX.B = 1 adds 8)" if rex_b else ""))
                st.rex_used["B"] = "extends SIB.base"
        elif rm == 5 and mod == 0:
            disp_size = 4
            if in64:
                mem["rip"] = True
                st.field("rm", pos, 1, 2, 0, rm, "mod", "modrm",
                         "rm = 101 with mod = 00: no base register. In 64-bit mode this is RIP-relative addressing: a 32-bit "
                         "displacement follows and is added to the address of the next instruction. REX.B does not change "
                         "this (r13 as a base needs mod = 01 with a zero displacement).")
            else:
                st.field("rm", pos, 1, 2, 0, rm, "mod", "modrm",
                         "rm = 101 with mod = 00: no base register; a 32-bit absolute address (disp32) follows. To use ebp "
                         "as a base, mod must be 01 or 10.")
        else:
            base_n = rm | (rex_b << 3)
            mem["base"] = areg[base_n]
            st.field("rm", pos, 1, 2, 0, rm, "reg", "modrm",
                     "rm = %s: base register number %d = %s%s." % (_binstr(rm, 3), base_n, areg[base_n],
                                                                    " (REX.B = 1 adds 8)" if rex_b else ""))
            st.rex_used["B"] = "extends ModRM.rm"
        if disp_size:
            mem["has_disp"] = True
            mem["disp_pos"] = st.pos
            mem["disp_size"] = disp_size
            mem["disp"] = _x86_read_imm(
                st, disp_size, "disp%d" % (disp_size * 8), "disp", True,
                "Displacement: %d byte(s), little-endian, sign-extended and added to the address." % disp_size)
    st.mem = mem
    if reg_is_ext is None:
        st.rex_used["R"] = "extends ModRM.reg"


def _x86_mem_text(st: _X86State, size: Optional[int]) -> str:
    mem = st.mem
    assert mem is not None
    parts: List[str] = []
    if mem["rip"]:
        parts.append("rip" if st.asz == 64 else "eip")
    if mem["base"]:
        parts.append(mem["base"])
    if mem["index"]:
        # llvm writes the scale of 1 only when there is no base register in front of the index
        parts.append(("%d*%s" % (mem["scale"], mem["index"])) if (mem["scale"] != 1 or not parts) else mem["index"])
    disp = mem["disp"]
    if not parts:
        inner = _hx(disp)   # llvm prints an absolute disp32 as a signed number; the steps show the unsigned address
    else:
        inner = " + ".join(parts)
        if disp:
            inner += " %s 0x%x" % ("-" if disp < 0 else "+", abs(disp))
    seg = (st.seg + ":") if st.seg else ""
    if st.seg:
        st.pfx_used[0] = "seg"
    prefix = (_PTR[size] + " ptr ") if size else ""
    return "%s%s[%s]" % (prefix, seg, inner)


def _x86_imm_text(value: int) -> str:
    return _hx(value)


def _x86_operand(st: _X86State, code: str, opcode: int, flags: str, ctx: Dict[str, Any]) -> Optional[str]:
    """Decode one operand and return its text (None for an implicit operand that is not printed)."""
    osz = st.osz
    rex_r, rex_b = (st.rex >> 2) & 1, st.rex & 1
    kind = code[0]
    sub = code[1:]

    def size_of(s: str) -> int:
        if s == "b":
            return 8
        if s == "w":
            return 16
        if s == "d":
            return 32
        if s == "q":
            return 64
        if s == "v":
            return osz
        if s == "y":
            return 64 if osz == 64 else 32
        if s == "x":
            return 128
        raise _X86Stop("not_decoded", "Operand size code not handled.")

    if code == "AL":
        return "al"
    if code == "CL":
        return "cl"
    if code == "rAX":
        return {16: "ax", 32: "eax", 64: "rax"}[osz]
    if code == "1":
        return None
    if kind == "Q":     # a 32-bit register or a 16-bit memory operand (PINSRW)
        if st.mod == 3:
            return _x86_reg(st, st.rm | (rex_b << 3), 32)
        return _x86_mem_text(st, 16)
    if kind == "E" or kind == "M" or kind == "W" or kind == "U":
        if kind == "M" and st.mod == 3:
            raise _X86Stop("not_decoded", "This opcode requires a memory operand (mod != 11); with mod = 11 it is a different "
                                          "or invalid instruction that this lab does not decode.")
        if kind == "U" and st.mod != 3:
            raise _X86Stop("not_decoded", "This opcode requires a register operand (mod = 11).")
        if code == "M":
            return _x86_mem_text(st, None)
        size = size_of(sub)
        if st.mod == 3:
            n = st.rm | (rex_b << 3)
            if kind in ("W", "U"):
                return "xmm%d" % n
            return _x86_reg(st, n, size)
        return _x86_mem_text(st, size)
    if kind == "G":
        return _x86_reg(st, st.reg | (rex_r << 3), size_of(sub))
    if kind == "V":
        return "xmm%d" % (st.reg | (rex_r << 3))
    if kind == "Z":
        n = (opcode & 7) | (rex_b << 3)
        st.rex_used["B"] = "extends the register number in the opcode byte"
        return _x86_reg(st, n, size_of(sub))
    if kind == "I":
        if sub == "b":      # 8-bit immediate for an 8-bit operation
            v = _x86_read_imm(st, 1, "imm8", "imm", True, "8-bit immediate operand.")
            return _x86_imm_text(v)
        if sub == "bu":     # 8-bit immediate used as an unsigned count / selector
            v = _x86_read_imm(st, 1, "imm8", "imm", False, "8-bit immediate (a count, bit number or selector; not sign-extended).")
            ctx["imm_last"] = v
            return _x86_imm_text(v)
        if sub == "bs":     # 8-bit immediate sign-extended to the operand size
            v = _x86_read_imm(st, 1, "imm8", "imm", True,
                              "8-bit immediate, sign-extended to the %d-bit operand size. Compilers prefer this short form "
                              "whenever the constant fits in -128..127." % osz)
            return _x86_imm_text(v)
        if sub == "w":
            v = _x86_read_imm(st, 2, "imm16", "imm", False, "16-bit immediate.")
            return _x86_imm_text(v)
        if sub == "z":
            if osz == 16:
                v = _x86_read_imm(st, 2, "imm16", "imm", False, "16-bit immediate (the operand size is 16 bits).")
                return _x86_imm_text(v)
            if osz == 64:
                v = _x86_read_imm(st, 4, "imm32", "imm", True,
                                  "32-bit immediate, sign-extended to 64 bits. There is no 64-bit immediate form for this "
                                  "instruction; only MOV r64, imm64 (B8+r with REX.W) carries 8 immediate bytes.")
                return _x86_imm_text(v)
            v = _x86_read_imm(st, 4, "imm32", "imm", False, "32-bit immediate.")
            return _x86_imm_text(v)
        if sub == "v":
            if osz == 64:
                v = _x86_read_imm(st, 8, "imm64", "imm", True, "64-bit immediate: the only x86-64 instruction form with a full 8-byte immediate.")
                return _x86_imm_text(v)
            if osz == 16:
                v = _x86_read_imm(st, 2, "imm16", "imm", False, "16-bit immediate.")
                return _x86_imm_text(v)
            v = _x86_read_imm(st, 4, "imm32", "imm", False,
                              "32-bit immediate." + (" Writing a 32-bit register zeroes the upper 32 bits of the 64-bit register."
                                                     if st.bits == 64 else ""))
            return _x86_imm_text(v)
    if kind == "J":
        nbytes = 1 if sub == "b" else 4
        rel = _x86_read_imm(st, nbytes, "rel%d" % (nbytes * 8), "imm", True,
                            "Relative branch offset: %d byte(s), signed, counted from the end of this instruction." % nbytes)
        ctx["rel"] = rel
        return "<target>"
    if kind == "O":
        nbytes = st.asz // 8
        if st.asz != st.bits:
            raise _X86Stop("not_decoded", "An address-size prefix on a MOV with a memory offset is not decoded by this lab.")
        addr = _x86_read_imm(st, nbytes, "moffs%d" % st.asz, "disp", False,
                             "Memory offset: a full %d-bit absolute address stored in the instruction, with no ModRM byte. "
                             "Only MOV to or from the accumulator (opcodes A0-A3) has this form." % st.asz)
        seg = (st.seg + ":") if st.seg else ""
        if st.seg:
            st.pfx_used[0] = "seg"
        ctx["moffs"] = st.asz
        if not st.seg:
            st.target = addr
            st.target_kind = "data"
        # llvm prints a 64-bit moffs as a signed number
        return "%s ptr %s[%s]" % (_PTR[8 if sub == "b" else osz], seg, _hx(_sx(addr, 64)) if st.asz == 64 else "0x%x" % addr)
    if kind in ("X", "Y"):
        return None
    raise _X86Stop("not_decoded", "Operand type not handled.")


def decode_x86(buf: bytes, pos: int = 0, pc: int = 0, bits: int = 64, lite: bool = False) -> Dict[str, Any]:
    """Break one x86 instruction starting at buf[pos] down into its fields.

    `lite=True` is the disassembler's fast path: same decode logic and text, no field list or steps.
    A "not_decoded" result has `length_known` True when the instruction's length is certain even though its
    operands are not interpreted (VEX/EVEX maps 1-3, the 0F 38 / 0F 3A maps, x87); `size` is then its length."""
    st = _X86State(buf, pos, pc & _M64, bits, lite)
    try:
        return _decode_x86(st)
    except _X86Stop as stop:
        consumed = st.pos - st.start
        if lite:
            known_len = stop.kind == "not_decoded" and stop.length_known
            size = consumed if (stop.kind == "truncated" or known_len) else max(1, consumed)
            return {"status": stop.kind, "size": min(size, len(buf) - st.start) or 1, "mnemonic": "", "operands": "",
                    "text": "", "encoding_class": "", "gaps": [stop.reason], "target": None, "target_kind": None,
                    "length_known": known_len}
        if not st.pfx_done:
            _x86_prefix_fields(st, "", 0)
        if st.rex and not any(f["group"] == "rex" for f in st.fields):
            _x86_rex_field(st)
        st.fields.sort(key=lambda f: (f["byte"], -f["hi"] if f["nbytes"] == 1 else 0))
        known = [f for f in st.fields if f["byte"] + f["nbytes"] <= max(1, consumed)]
        known_len = stop.kind == "not_decoded" and stop.length_known
        size = consumed if (stop.kind == "truncated" or known_len) else max(1, consumed)
        size = min(size, len(buf) - st.start) or 1
        return {"status": stop.kind, "size": size, "mnemonic": "", "operands": "", "text": "", "encoding_class": "",
                "fields": known, "steps": st.steps, "notes": st.notes, "gaps": [stop.reason], "target": None,
                "target_kind": None, "length_known": known_len}


def _decode_x86(st: _X86State) -> Dict[str, Any]:
    in64 = st.bits == 64
    # 1. legacy prefixes
    while True:
        if st.pos >= st.end:
            st.take()
        b = st.buf[st.pos]
        if b in _PREFIX_TEXT or b in _SEGS:
            st.prefixes.append((b, st.pos))
            st.pos += 1
            continue
        break
    pfx = [b for b, _ in st.prefixes]
    has66, has67 = 0x66 in pfx, 0x67 in pfx
    rep = next((b for b in reversed(pfx) if b in (0xF2, 0xF3)), 0)
    for b in pfx:
        if b in _SEGS:
            st.seg = _SEGS[b]
    if has67:
        st.asz = 32 if in64 else 16
    # 2. REX
    b = st.take()
    if in64 and 0x40 <= b <= 0x4F:
        st.rex, st.rex_pos = b, st.pos - 1
        if st.pos < st.end and (st.buf[st.pos] in _PREFIX_TEXT or st.buf[st.pos] in _SEGS):
            raise _X86Stop("not_decoded", "A REX prefix must be the last prefix, immediately before the opcode. Here another "
                                          "prefix follows it, so the REX byte is ignored by the processor; this lab does not "
                                          "decode that case.")
        b = st.take()
        if 0x40 <= b <= 0x4F:
            raise _X86Stop("not_decoded", "Two REX prefixes in a row: only the last one before the opcode takes effect. This "
                                          "lab does not decode that unusual sequence.")
    # 3. VEX / EVEX / other escapes this lab does not follow
    opcode_pos = st.pos - 1
    if b in (0xC4, 0xC5, 0x62):
        nxt = st.buf[st.pos] if st.pos < st.end else None
        if in64 or (nxt is not None and (nxt & 0xC0) == 0xC0):
            _x86_prefix_fields(st, "", 0)
            name = {0xC4: "3-byte VEX", 0xC5: "2-byte VEX", 0x62: "EVEX"}[b]
            st.field("escape", opcode_pos, 1, 7, 0, b, "fixed", "opcode",
                     "%02x: %s prefix (AVX / AVX-512 and related extensions)." % (b, name))
            if _x86_skip_vex(st, b):
                raise _X86Stop("not_decoded", "%s-encoded instructions are not decoded by this lab. The length (%d bytes) "
                                              "follows from the prefix and its opcode map alone, so decoding can continue "
                                              "after it." % (name, st.pos - st.start), True)
            raise _X86Stop("not_decoded", "%s-encoded instructions are not decoded by this lab, and this one uses an opcode "
                                          "map whose instruction lengths it does not know." % name)
    table = _X1
    opmap = "one-byte"
    escape_positions: List[int] = []
    if b == 0x0F:
        escape_positions.append(opcode_pos)
        b = st.take()
        opcode_pos = st.pos - 1
        table = _X2
        opmap = "two-byte (0F)"
        if b in (0x38, 0x3A):
            _x86_prefix_fields(st, "", 0)
            st.field("escape", escape_positions[0], 1, 7, 0, 0x0F, "fixed", "opcode", "0f: escape to the two-byte opcode map.")
            st.field("escape2", opcode_pos, 1, 7, 0, b, "fixed", "opcode", "%02x: escape to the three-byte opcode map 0F %02X." % (b, b))
            st.take()               # the opcode byte inside the three-byte map
            _x86_skip_modrm(st)     # every instruction of both maps has a ModRM operand ...
            if b == 0x3A:
                st.take()           # ... and those of 0F 3A end with an imm8
            raise _X86Stop("not_decoded", "The three-byte opcode maps (0F 38, 0F 3A: SSSE3, SSE4, AES, ...) are not decoded "
                                          "by this lab. The length (%d bytes) follows from the map alone, so decoding can "
                                          "continue after it." % (st.pos - st.start), True)
    opcode = b
    # special fixed sequences
    if table is _X2 and opcode == 0x1E and rep == 0xF3 and st.pos < st.end and st.buf[st.pos] in (0xFA, 0xFB):
        last = st.take()
        st.mand = "F3"
        _x86_prefix_fields(st, "F3", 0)
        st.field("escape", escape_positions[0], 1, 7, 0, 0x0F, "fixed", "opcode", "0f: escape to the two-byte opcode map.")
        st.field("opcode", opcode_pos, 1, 7, 0, opcode, "fixed", "opcode", "1e: with the F3 prefix and the next byte, ENDBR.")
        st.field("opcode", st.pos - 1, 1, 7, 0, last, "fixed", "opcode",
                 "%02x: selects %s." % (last, "ENDBR64" if last == 0xFA else "ENDBR32"))
        st.notes.append("ENDBR marks a valid target for indirect branches (Intel CET indirect branch tracking). The encoding "
                        "was chosen from the reserved-NOP opcode space (0F 1E), so older processors execute it as a NOP.")
        mn = "endbr64" if last == 0xFA else "endbr32"
        return _x86_result(st, mn, "", "Control-flow enforcement (CET)")
    entry = table.get(opcode)
    if entry is None:
        _x86_prefix_fields(st, "", 0)
        for ep in escape_positions:
            st.field("escape", ep, 1, 7, 0, 0x0F, "fixed", "opcode", "0f: escape to the two-byte opcode map.")
        st.field("opcode", opcode_pos, 1, 7, 0, opcode, "unknown", "opcode", "Opcode %02x in the %s map: not in this lab's table." % (opcode, opmap))
        if table is _X1 and 0xD8 <= opcode <= 0xDF:
            _x86_skip_modrm(st)     # every x87 opcode is followed by a ModRM byte and has no immediate
            raise _X86Stop("not_decoded", "x87 floating-point instructions (opcodes D8-DF) are not decoded by this lab. The "
                                          "length (%d bytes) follows from the ModRM byte, so decoding can continue after it."
                           % (st.pos - st.start), True)
        rule = _X2_LEN.get(opcode) if table is _X2 else (_X1_LEN.get(opcode) or (None if in64 else _X1_LEN_32.get(opcode)))
        if rule is not None:
            _x86_skip_by_rule(st, rule, has66)
            raise _X86Stop("not_decoded", "Opcode %s%02x is a valid instruction that this lab does not decode. Its length "
                                          "(%d bytes) follows from its place in the opcode map, so decoding can continue "
                                          "after it." % ("0f " if table is _X2 else "", opcode, st.pos - st.start), True)
        raise _X86Stop("not_decoded", "Opcode %s%02x is outside this lab's opcode table (undefined, or a rarely used "
                                      "instruction). Its length is therefore unknown."
                       % ("0f " if table is _X2 else "", opcode))
    mand = ""
    if isinstance(entry, dict):
        mand = "F3" if rep == 0xF3 else ("F2" if rep == 0xF2 else ("66" if has66 else ""))
        sel = entry.get(mand)
        if sel is None:
            _x86_prefix_fields(st, "", 0)
            for ep in escape_positions:
                st.field("escape", ep, 1, 7, 0, 0x0F, "fixed", "opcode", "0f: escape to the two-byte opcode map.")
            st.field("opcode", opcode_pos, 1, 7, 0, opcode, "unknown", "opcode", "Opcode 0f %02x: this prefix combination is not in this lab's table." % opcode)
            rule = _X2_LEN.get(opcode)
            if rule is not None:
                _x86_skip_by_rule(st, rule, False)
                raise _X86Stop("not_decoded", "Opcode 0f %02x with %s is not decoded by this lab (for example the MMX form "
                                              "without a 66 prefix). Its length (%d bytes) follows from its place in the "
                                              "opcode map, so decoding can continue after it."
                               % (opcode, ("mandatory prefix " + mand.lower()) if mand else "no mandatory prefix",
                                  st.pos - st.start), True)
            raise _X86Stop("not_decoded", "Opcode 0f %02x with %s is not in this lab's table."
                           % (opcode, ("mandatory prefix " + mand.lower()) if mand else "no mandatory prefix"))
        entry = sel
        if not isinstance(entry, list) and entry[2] == "os":
            mand = ""
        st.mand = mand
    group_ext: Optional[int] = None
    if isinstance(entry, list):
        if st.pos >= st.end:
            st.take()
        group_ext = (st.buf[st.pos] >> 3) & 7
        sel = entry[group_ext]
        if sel is None:
            _x86_prefix_fields(st, mand, 0)
            for ep in escape_positions:
                st.field("escape", ep, 1, 7, 0, 0x0F, "fixed", "opcode", "0f: escape to the two-byte opcode map.")
            st.field("opcode", opcode_pos, 1, 7, 0, opcode, "fixed", "opcode", "Opcode %02x: an opcode group; ModRM.reg selects the instruction." % opcode)
            rule = _X2_LEN.get(opcode) if table is _X2 else _X1_GROUP_LEN.get((opcode, group_ext))
            if rule is not None:
                _x86_skip_by_rule(st, rule, has66)
                raise _X86Stop("not_decoded", "Opcode %02x /%d is not decoded by this lab. Its length (%d bytes) follows from "
                                              "its place in the opcode map, so decoding can continue after it."
                               % (opcode, group_ext, st.pos - st.start), True)
            raise _X86Stop("not_decoded", "Opcode %02x /%d is not in this lab's table." % (opcode, group_ext))
        entry = sel
    mn, opspec, flags = entry
    if flags == "64" and not in64:
        rule = (False, 0) if table is _X2 else _X1_LEN_32.get(opcode)     # 0F 05 is SYSCALL in every mode
        if rule is not None:
            _x86_skip_by_rule(st, rule, has66)
        raise _X86Stop("not_decoded", ("Opcode 0f 05 (SYSCALL) is decoded by this lab only in 64-bit mode: outside it Intel "
                                       "processors raise #UD and only AMD processors execute it."
                                       if table is _X2 else
                                       "Opcode %02x is a different instruction outside 64-bit mode; not decoded by this lab." % opcode),
                       rule is not None)
    codes = [c for c in opspec.split(",") if c]
    rex_w = (st.rex >> 3) & 1
    if has66 and mand != "66":
        if any(c[0] == "J" for c in codes):
            raise _X86Stop("not_decoded", "An operand-size prefix on a relative branch is treated differently by Intel and AMD "
                                          "processors in 64-bit mode (and truncates the target to 16 bits in 32-bit mode); "
                                          "this lab does not decode it.")
        if mn == "bswap":
            raise _X86Stop("not_decoded", "BSWAP with a 16-bit operand size has an undefined result; not decoded by this lab.", True)
    # 4. operand size
    opsize_by_66 = has66 and mand != "66"
    if in64:
        if "d64" in flags:
            st.osz = 64 if rex_w else (16 if opsize_by_66 else 64)
        elif rex_w:
            st.osz = 64
        elif opsize_by_66:
            st.osz = 16
        else:
            st.osz = 32
    else:
        st.osz = 16 if opsize_by_66 else 32
    uses_v = any(c[1:] in ("v", "z", "y") or c == "rAX" for c in codes) or mn in ("cbw/cwde/cdqe", "cwd/cdq/cqo")
    if rex_w:
        if "d64" in flags:
            st.rex_used["W"] = "has no effect: this instruction already defaults to 64-bit operands"
        elif uses_v or any(c[1:] == "y" for c in codes):
            st.rex_used["W"] = "selects 64-bit operand size"
    # 5. prefix + opcode fields
    _x86_prefix_fields(st, mand, 1 if (opsize_by_66 and uses_v) else 0)
    for ep in escape_positions:
        st.field("escape", ep, 1, 7, 0, 0x0F, "fixed", "opcode",
                 "0f: escape byte. The next byte is looked up in the two-byte opcode map instead of the one-byte map.")
    has_z = any(c[0] == "Z" for c in codes)
    if has_z:
        st.field("opcode", opcode_pos, 1, 7, 3, opcode >> 3, "fixed", "opcode",
                 "Opcode bits 7:3 = %s: %s with the register number in the low 3 bits of the opcode byte (written %02X+r)."
                 % (_binstr(opcode >> 3, 5), mn.upper(), opcode & 0xF8))
        st.field("r", opcode_pos, 1, 2, 0, opcode & 7, "reg", "opcode",
                 "r = %s: register number %d%s." % (_binstr(opcode & 7, 3), (opcode & 7) | ((st.rex & 1) << 3),
                                                    " (REX.B = 1 adds 8)" if st.rex & 1 else ""))
    elif "cc" in flags:
        st.field("opcode", opcode_pos, 1, 7, 4, opcode >> 4, "fixed", "opcode",
                 "Opcode bits 7:4 = %s: the conditional family %s." % (_binstr(opcode >> 4, 4), {"j": "Jcc", "s": "SETcc", "c": "CMOVcc"}[mn[0]]))
        st.field("cc", opcode_pos, 1, 3, 0, opcode & 15, "cond", "opcode",
                 "cc = %s: condition '%s', true when %s. Flipping the lowest bit negates the condition."
                 % (_binstr(opcode & 15, 4), _CC[opcode & 15], _CC_TEXT[opcode & 15]))
    elif table is _X1 and (opcode < 0x40 and (opcode & 7) < 4 or 0x88 <= opcode <= 0x8B):
        st.field("opcode", opcode_pos, 1, 7, 2, opcode >> 2, "fixed", "opcode",
                 "Opcode bits 7:2 = %s: %s." % (_binstr(opcode >> 2, 6), mn.upper()))
        d, w = (opcode >> 1) & 1, opcode & 1
        st.field("d", opcode_pos, 1, 1, 1, d, "opc", "opcode",
                 "d = %d: direction. %s" % (d, "ModRM.reg is the destination, r/m is the source." if d
                                           else "ModRM.r/m is the destination, reg is the source."))
        st.field("w", opcode_pos, 1, 0, 0, w, "opc", "opcode",
                 "w = %d: %s." % (w, "full operand size (16/32/64 bits, chosen by prefixes)" if w else "8-bit operands"))
    else:
        text = "Opcode %02x in the %s map: %s" % (opcode, opmap, mn.upper() if group_ext is None else "an opcode group; ModRM.reg selects the instruction")
        st.field("opcode", opcode_pos, 1, 7, 0, opcode, "fixed", "opcode", text + ".")
    # 6. ModRM
    needs_modrm = any(c[0] in "EGMVWUQ" for c in codes) or group_ext is not None
    if needs_modrm:
        _x86_modrm(st, ("selects %s" % mn.upper()) if group_ext is not None else None)
    # 7. operands
    ctx: Dict[str, Any] = {}
    shown: List[str] = []
    for code in codes:
        text = _x86_operand(st, code, opcode, flags, ctx)
        if text is not None:
            shown.append(text)
            # name the register each register field selects, now that the operand size is known
            where = None
            if code[0] in "GV":
                where = ("modrm", "reg")
            elif code[0] in "EWUQ" and st.mod == 3:
                where = ("modrm", "rm")
            elif code[0] == "Z":
                where = ("opcode", "r")
            if where:
                for f in st.fields:
                    if f["group"] == where[0] and f["name"] == where[1] and f["kind"] == "reg":
                        f["meaning"] = f["meaning"].replace(
                            " Which register that is depends on the operand size (see the operands).", "") + " Here: %s." % text
    if st.pos - st.start > 15:
        raise _X86Stop("not_decoded", "The instruction would be longer than 15 bytes, which is invalid.")
    length = st.pos - st.start
    next_ip = (st.pc + length) & ((1 << st.bits) - 1)
    # 8. computed targets
    if "rel" in ctx:
        rel = ctx["rel"]
        target = (next_ip + rel) & ((1 << st.bits) - 1)
        st.target = target
        st.target_kind = "branch"
        st.steps.append("address of the next instruction = 0x%x + %d (length) = 0x%x" % (st.pc, length, next_ip))
        st.steps.append("target = next + rel = 0x%x %s 0x%x = 0x%x" % (next_ip, "-" if rel < 0 else "+", abs(rel), target))
        shown = [("0x%x" % target) if s == "<target>" else s for s in shown]
        st.notes.append("Relative branches are measured from the end of the instruction, not its start, so the same target "
                        "needs a different offset in the 2-byte and the 5/6-byte forms.")
    if st.mem is not None and st.mem["rip"]:
        disp = st.mem["disp"]
        target = (next_ip + disp) & ((1 << st.asz) - 1)
        st.target = target
        st.target_kind = "data"
        st.steps.append("address of the next instruction = 0x%x + %d (length) = 0x%x" % (st.pc, length, next_ip))
        st.steps.append("effective address = RIP + disp32 = 0x%x %s 0x%x = 0x%x" % (next_ip, "-" if disp < 0 else "+", abs(disp), target))
        st.notes.append("RIP here is the address of the next instruction. If an immediate follows the displacement, it still "
                        "counts: the base is the end of the whole instruction.")
    elif st.mem is not None and not st.mem["base"] and not st.mem["index"]:
        if not st.seg:      # with a segment override the address is relative to that segment's base
            st.target = st.mem["disp"] & ((1 << st.asz) - 1)
            st.target_kind = "data"
        st.steps.append("effective address = disp32%s = 0x%x (absolute%s)" % (
            " sign-extended to 64 bits" if st.asz == 64 else "", st.mem["disp"] & ((1 << st.asz) - 1),
            ", relative to the segment base" if st.seg else ""))
    # 9. mnemonic details that depend on operand size or prefixes
    cls = "General-purpose"
    if mn == "cbw/cwde/cdqe":
        mn = {16: "cbw", 32: "cwde", 64: "cdqe"}[st.osz]
        st.notes.append("98 sign-extends the accumulator in place: CBW (al to ax), CWDE (ax to eax), CDQE (eax to rax), by operand size.")
    elif mn == "cwd/cdq/cqo":
        mn = {16: "cwd", 32: "cdq", 64: "cqo"}[st.osz]
        st.notes.append("99 sign-extends the accumulator into (r/e)dx: the usual step before IDIV.")
    elif mn == "mov" and ctx.get("moffs") == 64:
        mn = "movabs"
        st.notes.append("MOVABS is the assembler's name for the MOV forms that carry a full 64-bit address or immediate.")
    elif mn == "mov" and opspec == "Zv,Iv" and st.osz == 64:
        mn = "movabs"
        st.notes.append("MOVABS is the assembler's name for MOV with a full 64-bit immediate.")
    elif mn == "nop" and opcode == 0x90 and table is _X1:
        if st.rex & 1:
            mn, shown = "xchg", [{16: "ax", 32: "eax", 64: "rax"}[st.osz], _x86_reg(st, 8, st.osz)]
            st.rex_used["B"] = "turns 90 (NOP) into XCHG r8, rAX"
        elif rep == 0xF3 and not st.rex:
            mn = "pause"
            st.pfx_used[0xF3] = "mand"
            st.notes.append("F3 90 is PAUSE, a spin-loop hint. Without the prefix, 90 is NOP (historically XCHG eax, eax).")
        elif has66:
            st.notes.append("66 90 is a two-byte NOP (formally XCHG ax, ax). Compilers use it, and longer forms such as "
                            "0F 1F /0 with redundant prefixes, to pad code to an alignment boundary.")
        else:
            st.notes.append("90 is NOP. It is the encoding of XCHG (e)ax, (e)ax, which is defined to do nothing; in 64-bit "
                            "mode it does not zero the upper half of rax as a real 32-bit XCHG would.")
    elif "str" in flags:
        if st.asz == 16:
            raise _X86Stop("not_decoded", "String instructions with 16-bit addressing are not decoded by this lab.", True)
        sz = 8 if opspec.endswith("b") or "b," in opspec else st.osz
        suffix = {8: "b", 16: "w", 32: "d", 64: "q"}[sz]
        di = ("rdi" if st.asz == 64 else "edi")
        si = ("rsi" if st.asz == 64 else "esi")
        if mn == "movs":
            shown = ["%s ptr es:[%s]" % (_PTR[sz], di), "%s ptr %s[%s]" % (_PTR[sz], (st.seg + ":") if st.seg else "", si)]
        else:
            shown = ["%s ptr es:[%s]" % (_PTR[sz], di), {8: "al", 16: "ax", 32: "eax", 64: "rax"}[sz]]
        mn = mn + suffix
        if rep:
            mn = ("rep " if rep == 0xF3 else "repne ") + mn
            st.pfx_used[rep] = "rep"
        st.notes.append("String instructions use implicit operands: (r/e)si as source pointer, (r/e)di as destination pointer, "
                        "both advanced by the element size after each step (direction given by DF).")
        cls = "String"
    if opspec.startswith("V") or opspec.startswith("W") or "Vx" in opspec or "Ux" in opspec:
        cls = "SSE / SSE2"
        if flags in ("hl", "lh") and st.mod == 3:
            mn = "movhlps" if flags == "hl" else "movlhps"
            st.notes.append("With a register source (mod = 11) this opcode is %s; with a memory source it is %s."
                            % (mn.upper(), "MOVLPS" if flags == "hl" else "MOVHPS"))
        if flags == "cmp":
            pred = ctx.get("imm_last", 0)
            if pred > 7:
                raise _X86Stop("not_decoded", "Comparison predicates above 7 exist only for the VEX-encoded forms.", True)
            names = ["eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord"]
            mn = "cmp" + names[pred] + mn[3:]
            shown = shown[:-1]
            st.notes.append("0F C2 is one compare instruction with the predicate in its immediate byte (%d = %s). Assemblers "
                            "and disassemblers fold the predicate into the mnemonic." % (pred, names[pred].upper()))
        if mn == "movd" and st.osz == 64:
            mn = "movq"
        if flags == "nw" and rex_w:
            raise _X86Stop("not_decoded", "REX.W on this opcode is not decoded by this lab (disassemblers disagree on it).", True)
    if mn in ("shl", "shr", "sar", "rol", "ror", "rcl", "rcr") and opspec.endswith(",1"):
        st.notes.append("D0/D1 shift by exactly one; the count is implied by the opcode and is not stored.")
    if mn == "xchg" and st.modrm >= 0 and st.mod == 3:
        shown = shown[::-1]   # llvm writes the register-register form with ModRM.reg first
    if mn in ("call", "jmp") and opspec == "Ev":
        if has66:
            raise _X86Stop("not_decoded", "An operand-size prefix on an indirect branch is treated differently by Intel and "
                                          "AMD processors; this lab does not decode it.", True)
        cls = "Indirect branch"
        st.notes.append("The target address is read from the register or memory operand (an indirect branch). Through a "
                        "RIP-relative slot this is how calls reach imported functions (GOT / IAT entries).")
    if 0xF0 in pfx:
        if "lock" in flags and st.mem is not None:
            mn = "lock " + mn
            st.pfx_used[0xF0] = "lock"
        else:
            raise _X86Stop("not_decoded", "LOCK is only valid on certain instructions with a memory destination; this "
                                          "combination raises #UD on a processor and is not decoded by this lab.", True)
    if rep and rep not in st.pfx_used and mand not in ("F2", "F3"):
        if rep == 0xF3 and table is _X1 and opcode == 0xC3 and len(pfx) == 1:
            mn = "rep ret"
            st.pfx_used[0xF3] = "rep"
            st.notes.append("REP before RET changes nothing architecturally. Compilers emitted this two-byte return to avoid "
                            "a branch-predictor penalty on AMD K8/K10 processors when a return is itself a branch target.")
        else:
            raise _X86Stop("not_decoded", "An F2/F3 prefix on this opcode is not a repeat prefix this lab understands "
                                          "(it may be a hint such as BND or XACQUIRE, or be ignored).", True)
    if st.seg and 0 not in st.pfx_used:
        if not (mn.startswith("j") or mn in ("nop",)):
            raise _X86Stop("not_decoded", "A segment-override prefix with no memory operand is not decoded by this lab.", True)
    if has67 and "str" not in flags and "moffs" not in ctx and (st.mem is None or not (st.mem["base"] or st.mem["index"] or st.mem["rip"])):
        raise _X86Stop("not_decoded", "An address-size prefix that changes nothing (no register-based memory operand) is not "
                                      "decoded by this lab.", True)
    if has66 and mand != "66" and not uses_v and mn != "nop":
        raise _X86Stop("not_decoded", "An operand-size prefix on an instruction it does not apply to is not decoded by this lab.", True)
    if len(pfx) != len(set(pfx)) and not (mn == "nop" and all(b_ == 0x66 or pfx.count(b_) == 1 for b_ in pfx)):
        raise _X86Stop("not_decoded", "Repeated prefixes (used as padding in long NOPs) are not decoded by this lab.", True)
    if st.rex:
        _x86_rex_field(st)
    return _x86_result(st, mn, ", ".join(shown), cls)


def _x86_prefix_fields(st: _X86State, mand: str, opsize_used: int) -> None:
    st.pfx_done = True
    mand_byte = {"66": 0x66, "F2": 0xF2, "F3": 0xF3}.get(mand)
    for b, pos in st.prefixes:
        if b in _SEGS:
            st.field("segment", pos, 1, 7, 0, b, "opc", "prefix",
                     "%02x: segment override %s. The memory operand is addressed relative to the %s segment base%s."
                     % (b, _SEGS[b].upper(), _SEGS[b].upper(),
                        " (in 64-bit mode only FS and GS have a non-zero base; they usually point at thread-local data)"
                        if st.bits == 64 else ""))
            continue
        name, text = _PREFIX_TEXT[b]
        if b == mand_byte:
            st.field("mandatory prefix", pos, 1, 7, 0, b, "fixed", "prefix",
                     "%02x: here a mandatory prefix. Together with the 0F opcode that follows it selects the instruction; it "
                     "does not act as %s." % (b, {"66": "an operand-size override", "F2": "REPNE", "F3": "REP"}[mand]))
        else:
            if b == 0x66 and opsize_used:
                text += " Here it selects 16-bit operands."
            st.field(name, pos, 1, 7, 0, b, "opc", "prefix", "%02x: %s" % (b, text))


def _x86_rex_field(st: _X86State) -> None:
    pos, rex = st.rex_pos, st.rex
    fields = [f for f in st.fields]
    st.fields = []
    st.field("REX", pos, 1, 7, 4, rex >> 4, "fixed", "rex",
             "0100: marks a REX prefix (bytes 40-4F in 64-bit mode). It must come immediately before the opcode. Its presence "
             "alone also changes 8-bit register numbers 4-7 from ah/ch/dh/bh to spl/bpl/sil/dil.")
    info = (("W", 3, "W = 1: 64-bit operand size.", "W = 0: operand size is the default (usually 32 bits)."),
            ("R", 2, "R = 1: adds 8 to ModRM.reg (r8-r15, xmm8-xmm15).", "R = 0: ModRM.reg selects registers 0-7."),
            ("X", 1, "X = 1: adds 8 to SIB.index.", "X = 0: SIB.index selects registers 0-7."),
            ("B", 0, "B = 1: adds 8 to ModRM.rm, SIB.base or the register in the opcode byte.",
             "B = 0: ModRM.rm / SIB.base / opcode register selects registers 0-7."))
    for name, bit, on, off in info:
        v = (rex >> bit) & 1
        used = st.rex_used.get(name, "")
        text = on if v else off
        if v and used:
            text += " Here it %s." % used
        elif v and name == "W":
            text += " This instruction has no operand whose size the bit could change, so it has no effect here."
        elif v:
            text += " This instruction has no such field, so the bit has no effect here."
        st.field("REX." + name, pos, 1, bit, bit, v, "opc", "rex", text)
    st.fields = fields + st.fields


def _x86_result(st: _X86State, mn: str, ops: str, cls: str) -> Dict[str, Any]:
    st.fields.sort(key=lambda f: (f["byte"], -f["hi"] if f["nbytes"] == 1 else 0))
    length = st.pos - st.start
    return {"status": "decoded", "size": length, "mnemonic": mn, "operands": ops, "text": (mn + " " + ops).strip(),
            "encoding_class": cls, "fields": st.fields, "steps": st.steps, "notes": st.notes, "gaps": [],
            "target": ("0x%x" % st.target) if st.target is not None else None, "target_kind": st.target_kind,
            "length_known": True}


# ===========================================================================
# Byte-stream decoding and the HTTP endpoint
# ===========================================================================
def decode_bytes(arch: str, data: bytes, pc: int = 0, max_instructions: int = MAX_INSTRUCTIONS) -> Dict[str, Any]:
    """Decode up to `max_instructions` instructions from `data` (at most MAX_INPUT_BYTES are looked at)."""
    if arch not in ARCHS:
        raise ValueError("unknown architecture")
    data = bytes(data[:MAX_INPUT_BYTES])
    max_instructions = max(1, min(int(max_instructions), MAX_INSTRUCTIONS))
    pc &= _M64
    out: List[Dict[str, Any]] = []
    pos = 0
    stopped = None
    while pos < len(data) and len(out) < max_instructions:
        runtime.check_deadline()
        cur_pc = (pc + pos) & _M64
        if arch == "arm64":
            if len(data) - pos < 4:
                out.append({"offset": pos, "size": len(data) - pos, "pc": "0x%x" % cur_pc,
                            "hex": " ".join("%02x" % b for b in data[pos:]), "status": "truncated", "mnemonic": "",
                            "operands": "", "text": "", "encoding_class": "", "fields": [], "steps": [], "notes": [],
                            "gaps": ["An A64 instruction is always 4 bytes; only %d byte(s) remain." % (len(data) - pos)],
                            "target": None})
                pos = len(data)
                break
            raw = data[pos:pos + 4]
            word = struct.unpack("<I", raw)[0]
            insn = decode_a64(word, cur_pc)
            insn.update({"offset": pos, "size": 4, "pc": "0x%x" % cur_pc, "hex": " ".join("%02x" % b for b in raw),
                         "word": "0x%08x" % word})
            insn["steps"] = ["word = bytes %s read little-endian = 0x%08x" % (" ".join("%02x" % b for b in raw), word)] + insn["steps"]
            out.append(insn)
            pos += 4
        else:
            insn = decode_x86(data, pos, cur_pc, 64 if arch == "x86_64" else 32)
            size = insn["size"]
            insn.update({"offset": pos, "pc": "0x%x" % cur_pc, "hex": " ".join("%02x" % b for b in data[pos:pos + size])})
            out.append(insn)
            pos += size
            if insn["status"] == "truncated" or (insn["status"] != "decoded" and not insn.get("length_known")):
                stopped = insn["status"]
                break
    result: Dict[str, Any] = {
        "arch": arch, "arch_label": ARCH_LABELS[arch], "pc": "0x%x" % pc, "bytes_total": len(data), "bytes_decoded": pos,
        "instructions": out, "remaining": len(data) - pos, "stopped": stopped,
        "limits": {"max_bytes": MAX_INPUT_BYTES, "max_instructions": MAX_INSTRUCTIONS},
    }
    if stopped == "not_decoded" and pos < len(data):
        result["stop_reason"] = ("x86 instructions have variable length. The length of the instruction above is unknown, so "
                                 "the %d byte(s) after it are not decoded: any guess at where the next instruction starts "
                                 "could be wrong." % (len(data) - pos))
    return result


def parse_hex(text: str, words: bool = False) -> bytes:
    """Hex text to bytes. Accepts spaces, commas, 0x prefixes and \\x escapes. With `words`, each group of 8 hex
    digits is a 32-bit instruction word as a disassembler prints it and is stored little-endian."""
    if not isinstance(text, str):
        raise BadRequest("'hex' must be a string of hexadecimal digits.")
    if len(text) > MAX_HEX_CHARS:
        raise BadRequest("'hex' is too long (limit: %d characters)." % MAX_HEX_CHARS)
    cleaned = text.replace("\\x", " ").replace("0x", " ").replace("0X", " ")
    for ch in ",;:_\t\r\n":
        cleaned = cleaned.replace(ch, " ")
    tokens = cleaned.split()
    out = bytearray()
    for tok in tokens:
        if any(c not in "0123456789abcdefABCDEF" for c in tok):
            raise BadRequest("'hex' contains characters that are not hexadecimal digits.")
        if words:
            if len(tok) != 8:
                raise BadRequest("In word mode each group must be 8 hex digits (one 32-bit instruction word).")
            out += bytes.fromhex(tok)[::-1]
        else:
            if len(tok) % 2:
                raise BadRequest("'hex' has an odd number of digits in '%s'; bytes are two digits each." % tok[:16])
            out += bytes.fromhex(tok)
        if len(out) > MAX_INPUT_BYTES:
            raise BadRequest("At most %d bytes can be decoded per request." % MAX_INPUT_BYTES)
    if not out:
        raise BadRequest("'hex' is empty.")
    return bytes(out)


def _parse_pc(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        raise BadRequest("'pc' must be an address (number or hex string).")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if len(text) > 40:
            raise BadRequest("'pc' is too long.")
        try:
            number = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
        except ValueError:
            raise BadRequest("'pc' is not a valid address.")
    else:
        raise BadRequest("'pc' must be an address (number or hex string).")
    if number < 0 or number > _M64:
        raise BadRequest("'pc' must be between 0 and 2^64 - 1.")
    return number


def info() -> Dict[str, Any]:
    return {
        "archs": [{"id": a, "label": ARCH_LABELS[a]} for a in ARCHS],
        "limits": {"max_bytes": MAX_INPUT_BYTES, "max_instructions": MAX_INSTRUCTIONS, "max_hex_chars": MAX_HEX_CHARS},
        "a64_classes": [title for title, _p, _m, _v, _l, _h in _A64_CLASSES],
        "x86_length_only": ["VEX / EVEX maps 1-3 (AVX, AVX-512)", "three-byte opcode maps (0F 38, 0F 3A)", "x87 (D8-DF)"],
        "x86_not_decoded": ["VEX / EVEX (AVX, AVX-512)", "three-byte opcode maps (0F 38, 0F 3A)", "x87 (D8-DF)", "MMX",
                            "16-bit addressing", "privileged and rarely emitted instructions"],
    }


def handle_decode(body: Dict[str, Any]) -> Dict[str, Any]:
    arch = body.get("arch")
    if not isinstance(arch, str) or arch not in ARCHS:
        raise BadRequest("'arch' must be one of: %s." % ", ".join(ARCHS))
    mode = body.get("input", "bytes")
    if mode not in ("bytes", "words"):
        raise BadRequest("'input' must be 'bytes' or 'words'.")
    if mode == "words" and arch != "arm64":
        raise BadRequest("'input': 'words' only applies to arm64, where every instruction is one 32-bit word.")
    data = parse_hex(body.get("hex"), words=(mode == "words"))
    pc = _parse_pc(body.get("pc"))
    limit = body.get("max_instructions", MAX_INSTRUCTIONS)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise BadRequest("'max_instructions' must be an integer.")
    return decode_bytes(arch, data, pc, max(1, min(limit, MAX_INSTRUCTIONS)))


def register_routes(router: Any) -> None:
    """POST /api/labs/encoding/decode, GET /api/labs/encoding/info. Stateless: no document is read."""

    def decode(req: Any) -> Dict[str, Any]:
        return handle_decode(req.json())

    def get_info(req: Any) -> Dict[str, Any]:
        return info()

    router.register("POST", "/api/labs/encoding/decode", decode, max_body=MAX_BODY_BYTES)
    router.register("GET", "/api/labs/encoding/info", get_info)
