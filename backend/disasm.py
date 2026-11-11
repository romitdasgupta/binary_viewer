"""
Layer 3: windowed disassembly for ARM64 and x86 / x86-64, with symbol and string cross-references.

Any other architecture (32-bit ARM / Thumb, RISC-V, PowerPC, MIPS, ...) is not disassembled:
`disassemble_window` returns no rows and an `unsupported_reason`, see `instruction_set`.

There is one instruction decoder in this project: the tables in `labs_encoding`, which are checked
against llvm-objdump (tests/test_labs_encoding.py). This module is the product-facing wrapper around
it. It walks a window of a section, turns each decoded instruction into a listing row, and adds what
only the listing knows: symbol labels, branch targets, references to strings and import slots.

What is not decoded is shown as data, never as a guessed instruction:

  * ARM64: a word outside the tables is `.long 0x...` with the encoding group in the comment.
  * x86: VEX/EVEX, the 0F 38 / 0F 3A maps and x87 are not decoded, but their length follows from the
    encoding rules, so they become one `.byte` row of the right size and the stream stays in step.
    For any other undecoded opcode the length is unknown: one byte is shown as `.byte` and decoding
    resumes at the next byte, as every linear disassembler does. The rows after it are then a best
    guess until the next anchor, and the comment says so. Anchors are symbol addresses and function
    starts: no instruction is allowed to run across one, which puts the stream back in step there.
  * Mach-O LC_DATA_IN_CODE ranges (jump tables inside __text) are shown as `.byte/.short/.long`.

In local mode x86 code of a file on disk is still passed to llvm-objdump / objdump when one is
installed; the built-in decoder is what public and in-browser (WASM) deployments always use.
Both paths print Intel syntax with unsuffixed mnemonics.
"""

import bisect
import os
import re
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from . import labs_encoding as _enc
from . import runtime

# Short notes for instructions whose name alone says little. Everything else is left to the operands
# and to Learn mode; the comment column is mainly for cross-references.
_A64_NOTES: Dict[str, str] = {
    (mn + " " + ops).strip(): what[0].upper() + what[1:]
    for mn, ops, what in _enc._HINTS.values()
    if mn.startswith(("pac", "aut", "bti", "xpac"))
}
_A64_NOTES.update({
    "retaa": "Return, authenticating x30 with key IA and SP as modifier",
    "retab": "Return, authenticating x30 with key IB and SP as modifier",
})

_A64_GROUP_SHORT = {
    "Data Processing -- Scalar Floating-Point and Advanced SIMD": "Advanced SIMD / floating-point",
    "Data Processing -- Immediate": "data-processing (immediate) encoding outside the tables",
    "Data Processing -- Register": "data-processing (register) encoding outside the tables",
    "Branches, Exception Generating and System instructions": "branch / system encoding outside the tables",
    "Loads and Stores": "load / store encoding outside the tables",
    "Reserved / SME": "reserved encoding",
    "SVE": "SVE",
    "Unallocated": "unallocated encoding",
}


def _a64_decode(word: int, pc: int) -> Tuple[str, str, Optional[str], Optional[int], Optional[str]]:
    """(mnemonic, operands, comment, target, target kind) for one A64 word."""
    res = _enc.decode_a64(word, pc, lite=True)
    if res["status"] == "not_decoded":
        group = _A64_GROUP_SHORT.get(res["encoding_class"], res["encoding_class"])
        return (".long", f"0x{word:08x}", f"not decoded: {group}", None, None)
    target = int(res["target"], 16) if res["target"] else None
    return (res["mnemonic"], res["operands"], _A64_NOTES.get(res["text"]), target, res["target_kind"])


def decode_arm64_insn(word: int, pc: int = 0) -> Tuple[str, str, Optional[str], Optional[int]]:
    """
    Decode one AArch64 (ARM64 / ARM64e) instruction word.
    Returns (mnemonic, operands, comment, target_vmaddr). The target is the address the instruction
    computes: a branch destination, or the address formed by ADR / ADRP / a literal load.
    A word outside the decoder's tables is returned as (".long", "0x........", reason, None).
    """
    mnem, ops, comment, target, _kind = _a64_decode(word, pc)
    return (mnem, ops, comment, target)


def instruction_set(arch_name: Any) -> Optional[str]:
    """Which built-in decoder applies to a slice: "arm64", "x86" or None.

    Only A64 (every Mach-O arm64 variant, ELF EM_AARCH64, PE ARM64) and x86 / x86-64 are
    decoded. 32-bit ARM / Thumb, RISC-V, PowerPC, MIPS and anything else have no decoder:
    their bytes must not be run through the A64 tables, which would print a plausible-looking
    but meaningless listing.
    """
    name = str(arch_name or "").lower()
    if name.startswith("arm64") or name == "aarch64":
        return "arm64"
    if name in ("x86_64", "x86_64h", "i386", "x86", "amd64"):
        return "x86"
    return None


def unsupported_reason(slice_data: Dict[str, Any]) -> str:
    """Why a slice is not disassembled, in words for the user."""
    arch_name = str(slice_data.get("arch_name") or "unknown")
    display = str((slice_data.get("overview") or {}).get("arch_display") or "")
    what = f"{display} ({arch_name})" if display and display.lower() != arch_name.lower() else arch_name
    return (f"This file is for {what}, which BinaryStudio does not disassemble. "
            "Instructions are decoded for x86, x86-64 and AArch64 only; the bytes are in the hex view.")


def decode_single_arm64_preview(raw_bytes: bytes, vmaddr: int = 0) -> str:
    """Formats a 4-byte sequence as a human-readable ARM64 instruction string for /api/decode."""
    if len(raw_bytes) < 4:
        return "insufficient bytes"
    word = struct.unpack("<I", raw_bytes[:4])[0]
    mnem, ops, _, _ = decode_arm64_insn(word, vmaddr)
    return f"{mnem} {ops}".strip()


_X86_LEGACY_PREFIXES = frozenset((0xF0, 0xF2, 0xF3, 0x66, 0x67, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65))


def _x86_family_note(chunk: bytes, is_64: bool) -> str:
    """Which family an undecoded x86 instruction of known length belongs to."""
    i = 0
    while i < len(chunk) and chunk[i] in _X86_LEGACY_PREFIXES:
        i += 1
    if is_64 and i < len(chunk) and 0x40 <= chunk[i] <= 0x4F:
        i += 1
    lead = chunk[i] if i < len(chunk) else 0
    if lead in (0xC4, 0xC5):
        return "VEX-encoded (AVX)"
    if lead == 0x62:
        return "EVEX-encoded (AVX-512)"
    if lead == 0x0F:
        return "0F 38 / 0F 3A opcode map (SSSE3, SSE4, AES)"
    if 0xD8 <= lead <= 0xDF:
        return "x87 floating-point"
    return "outside the built-in tables"


def _byte_list(chunk: bytes) -> str:
    return ", ".join(f"0x{b:02x}" for b in chunk)


def _x86_decode(buf: bytes, pos: int, pc: int, is_64: bool) -> Tuple[int, str, str, Optional[str], Optional[int], Optional[str], bool]:
    """(length, mnemonic, operands, comment, target, target kind, in_step) for the instruction at buf[pos].

    `in_step` is False only when the instruction is not decoded AND its length is unknown, i.e. when the
    caller cannot know where the next instruction starts."""
    res = _enc.decode_x86(buf, pos, pc, 64 if is_64 else 32, lite=True)
    status = res["status"]
    if status == "decoded":
        target = int(res["target"], 16) if res["target"] else None
        return (res["size"], res["mnemonic"], res["operands"], None, target, res["target_kind"], True)
    if status == "truncated":
        chunk = buf[pos:pos + 15]
        return (max(1, len(chunk)), ".byte", _byte_list(chunk) or "0x00", "incomplete instruction: the bytes end here", None, None, True)
    if res.get("length_known"):
        chunk = buf[pos:pos + res["size"]]
        note = f"not decoded: {_x86_family_note(chunk, is_64)}, {len(chunk)} bytes"
        return (len(chunk), ".byte", _byte_list(chunk), note, None, None, True)
    return (1, ".byte", f"0x{buf[pos]:02x}",
            "not decoded; its length is unknown, so decoding resumes at the next byte and may be out of step", None, None, False)


def decode_x86_64_insn(buf: bytes, pos: int, pc: int, is_64: bool = True) -> Tuple[int, str, str, Optional[str], Optional[int]]:
    """
    Decode one x86 (is_64=False: 32-bit protected mode) or x86-64 instruction at buf[pos], Intel syntax.
    Returns (byte_len, mnemonic, operands, comment, target_vmaddr). The target is a direct branch
    destination, or the address of a RIP-relative / absolute memory operand.

    What the tables do not cover comes back as data: (n, ".byte", "0x.., 0x..", reason, None) with the
    instruction's real length when that is certain (VEX/EVEX, 0F 38 / 0F 3A, x87), else a single byte.
    """
    if len(buf) - pos <= 0:
        return (1, ".byte", "0x00", None, None)
    length, mnem, ops, comment, target, _kind, _in_step = _x86_decode(buf, pos, pc, is_64)
    return (length, mnem, ops, comment, target)


OBJDUMP_PATHS = [
    "/Library/Developer/CommandLineTools/usr/bin/llvm-objdump",
    "/usr/bin/llvm-objdump",
    "/usr/bin/objdump",
]


def _find_objdump() -> Optional[str]:
    for p in OBJDUMP_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


OBJDUMP_LINE_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*([a-zA-Z0-9_.]+)(?:\s+(.*))?$"
)
_BARE_ADDRESS_RE = re.compile(r"^0x([0-9a-fA-F]+)$")
_LEADING_ADDRESS_RE = re.compile(r"^0x([0-9a-fA-F]+)\b")
_SYMBOL_ANNOTATION_RE = re.compile(r"\s*<[^>]*>")

# AArch64 instructions whose first operand is read, not written (so it does not end an ADRP page).
_A64_NO_WRITE = ("str", "stur", "stp", "stnp", "cmp", "cmn", "tst", "ccmp", "ccmn", "cbz", "cbnz", "tbz", "tbnz",
                 "prfm", "prfum", "msr", "fcmp", "fcmpe", "fccmp", "fccmpe", "stlr", "stllr", "nop")
_A64_MEM_RE = re.compile(r"\[(x\d+|sp)(?:, #(-?0x[0-9a-f]+))?\]$")
_DICE_ELEMENT = {"DICE_KIND_JUMP_TABLE8": 1, "DICE_KIND_JUMP_TABLE16": 2, "DICE_KIND_JUMP_TABLE32": 4,
                 "DICE_KIND_ABS_JUMP_TABLE32": 4, "DICE_KIND_DATA": 4}
_DATA_DIRECTIVE = {1: ".byte", 2: ".short", 4: ".long"}


def _string_preview(text: str) -> str:
    return text[:48].replace("\n", "\\n")


def _reference_comment(addr: int, sym_by_vm: Dict[int, str], str_by_vm: Dict[int, str]) -> Optional[str]:
    """What is known about a referenced address: a symbol, a string, or nothing."""
    if addr in sym_by_vm:
        return f"-> {sym_by_vm[addr]}"
    if addr in str_by_vm:
        return f'"{_string_preview(str_by_vm[addr])}" @ 0x{addr:x}'
    return None


_DICE_KIND_ELEMENT = {1: 4, 2: 1, 3: 2, 4: 4, 5: 4}   # data_in_code_entry.kind -> bytes per element
_MAX_DICE_ENTRIES = 16384


def _data_in_code_ranges(slice_data: Dict[str, Any], raw_slice_bytes: bytes = b"") -> List[Tuple[int, int, int]]:
    """Sorted [(slice offset, end, element size)] from Mach-O LC_DATA_IN_CODE.

    The table itself is read when the load command says where it is (the parsed document keeps only its
    first entries); otherwise the entries the parser recorded are used."""
    ranges: List[Tuple[int, int, int]] = []
    for lc in slice_data.get("load_commands", []) or []:
        if not isinstance(lc, dict) or lc.get("cmd_name") != "LC_DATA_IN_CODE":
            continue
        details = lc.get("details") or {}
        dataoff, datasize = details.get("dataoff"), details.get("datasize")
        if (isinstance(dataoff, int) and isinstance(datasize, int) and 0 <= dataoff and datasize >= 8
                and dataoff + datasize <= len(raw_slice_bytes)):
            for i in range(min(datasize // 8, _MAX_DICE_ENTRIES)):
                start, length, kind = struct.unpack_from("<IHH", raw_slice_bytes, dataoff + i * 8)
                if length > 0:
                    ranges.append((start, start + length, _DICE_KIND_ELEMENT.get(kind, 1)))
            continue
        for entry in details.get("entries", []) or []:
            try:
                start = int(str(entry["offset"]), 16)
                length = int(entry["length"])
            except (KeyError, TypeError, ValueError):
                continue
            if length > 0:
                ranges.append((start, start + length, _DICE_ELEMENT.get(str(entry.get("kind")), 1)))
    ranges.sort()
    return ranges


def _row(vm: int, slice_off: int, slice_base_offset: int, chunk: bytes, mnem: str, ops: str, label: Optional[str],
         comment: Optional[str], branch_target: Optional[int], ref: Optional[int] = None) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "vmaddr": f"0x{vm:x}",
        "slice_offset": slice_off,
        "abs_offset": slice_base_offset + slice_off,
        "size": len(chunk),
        "raw_hex": " ".join(f"{b:02x}" for b in chunk),
        "mnemonic": mnem,
        "operands": ops,
        "symbol_label": label,
        "comment": comment,
        "branch_target_vmaddr": f"0x{branch_target:x}" if branch_target is not None else None,
    }
    if ref is not None:
        row["ref_vmaddr"] = f"0x{ref:x}"   # address of data the instruction refers to (not a branch)
    return row


def _data_row(vm: int, slice_off: int, slice_base_offset: int, chunk: bytes, label: Optional[str]) -> Dict[str, Any]:
    directive = _DATA_DIRECTIVE.get(len(chunk))
    if directive:
        ops = "0x%0*x" % (len(chunk) * 2, int.from_bytes(chunk, "little"))
    else:
        directive, ops = ".byte", _byte_list(chunk)
    return _row(vm, slice_off, slice_base_offset, chunk, directive, ops, label, "data in code (jump table or literal data)", None)


def disassemble_window(
    slice_data: Dict[str, Any],
    raw_slice_bytes: bytes,
    slice_base_offset: int,
    start_vmaddr: int,
    count: int = 200,
    file_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Disassembles up to `count` instructions starting at `start_vmaddr` in the given slice.

    ARM64 always uses the built-in decoder. x86 / x86_64 uses llvm-objdump (or
    objdump) only when the runtime allows external tools and the file is on disk,
    and otherwise the built-in decoder. Both paths emit Intel syntax with the
    same mnemonic spelling ("push", "call", "ret"), so what the user sees does
    not depend on which decoder ran; the result's `decoder` field says which.

    Each row has `branch_target_vmaddr` only for a direct branch or call. An address the
    instruction merely refers to (RIP-relative data, ADRP+ADD, a literal) is in `ref_vmaddr`.
    Rows with mnemonic `.byte` / `.short` / `.long` are bytes that were not decoded as an
    instruction; their comment says why.
    """
    count = max(1, min(count, 1000))
    arch_name = slice_data.get("arch_name", "arm64")
    family = instruction_set(arch_name)
    if family is None:
        # No rows and a reason, rather than another architecture's decoding of these bytes.
        return {
            "slice_index": slice_data.get("slice_index", 0),
            "arch_name": arch_name,
            "section": "",
            "start_vmaddr": f"0x{start_vmaddr:x}",
            "instructions": [],
            "decoder": None,
            "syntax": None,
            "supported": False,
            "unsupported_reason": unsupported_reason(slice_data),
        }

    # Find enclosing section or segment for start_vmaddr
    target_section = None
    target_segment = None
    for seg in slice_data.get("segments", []):
        for sect in seg.get("sections", []):
            s_vm = sect["vmaddr_int"]
            s_sz = sect["size"]
            if s_vm <= start_vmaddr < s_vm + s_sz:
                target_section = sect
                target_segment = seg
                break
        if target_section:
            break
        seg_vm = seg["vmaddr_int"]
        seg_sz = seg["vmsize_int"]
        if seg_vm <= start_vmaddr < seg_vm + seg_sz:
            target_segment = seg

    if not target_segment:
        # Default to first executable section
        for seg in slice_data.get("segments", []):
            for sect in seg.get("sections", []):
                if sect.get("is_executable"):
                    target_section = sect
                    target_segment = seg
                    start_vmaddr = sect["vmaddr_int"]
                    break
            if target_section:
                break

    if not target_segment:
        return {
            "slice_index": slice_data.get("slice_index", 0),
            "arch_name": arch_name,
            "section": "unmapped",
            "start_vmaddr": f"0x{start_vmaddr:x}",
            "instructions": [],
        }

    if target_section:
        sec_label = f"{target_section['segname']},{target_section['sectname']}"
        base_slice_off = target_section["slice_offset"] + (start_vmaddr - target_section["vmaddr_int"])
        max_bytes = max(0, (target_section["vmaddr_int"] + target_section["size"]) - start_vmaddr)
        if isinstance(target_section.get("raw_size"), int):
            # PE: only SizeOfRawData bytes of the section exist in the file; the rest of
            # VirtualSize is zero-filled at load time and has no bytes to decode.
            max_bytes = min(max_bytes, max(0, target_section["raw_size"] - (start_vmaddr - target_section["vmaddr_int"])))
    else:
        sec_label = target_segment["segname"]
        base_slice_off = target_segment["fileoff"] + (start_vmaddr - target_segment["vmaddr_int"])
        max_bytes = max(0, (target_segment["vmaddr_int"] + target_segment["filesize"]) - start_vmaddr)

    # Lookup tables for symbols and strings by VMAddr
    sym_by_vm: Dict[int, str] = {}
    code_starts: List[int] = []     # addresses where an instruction is known to begin
    for s in slice_data.get("symbols", []):
        if s.get("type_name") == "SECT" and s.get("n_value_int", 0) > 0:
            sym_by_vm[s["n_value_int"]] = s.get("demangled") or s.get("name", "")
            code_starts.append(s["n_value_int"])
    for fs in slice_data.get("function_starts", []):
        vm_i = int(fs["vmaddr"], 16)
        code_starts.append(vm_i)
        if vm_i not in sym_by_vm:
            sym_by_vm[vm_i] = fs.get("name", f"sub_{vm_i:x}")
    for ind in slice_data.get("dysymtab", {}).get("indirect_symbols", []):
        slot_vm = int(ind["slot_vmaddr"], 16)
        sym_by_vm[slot_vm] = f"imp.{ind['symbol_name']}"

    str_by_vm: Dict[int, str] = {}
    for st in slice_data.get("strings", []):
        if st.get("vmaddr"):
            str_by_vm[int(st["vmaddr"], 16)] = st.get("value", "")

    instructions: List[Dict[str, Any]] = []
    limit_bytes = max(0, min(max_bytes, len(raw_slice_bytes) - base_slice_off))
    dice = _data_in_code_ranges(slice_data, raw_slice_bytes)
    dice_starts = [r[0] for r in dice]

    def data_range_at(slice_off: int) -> Optional[Tuple[int, int, int]]:
        i = bisect.bisect_right(dice_starts, slice_off) - 1
        return dice[i] if i >= 0 and slice_off < dice[i][1] else None

    is_x86 = family == "x86"

    # Try llvm-objdump / GNU objdump for x86_64 / i386 when file exists on disk,
    # then fall back to the built-in x86/x86_64 decoder.
    if is_x86:
        objdump_bin = _find_objdump() if runtime.get_config().allow_external_tools else None
        if objdump_bin and file_path and os.path.isfile(file_path):
            stop_vmaddr = start_vmaddr + min(max_bytes, count * 8)
            cmd = [objdump_bin, "-d"]
            if "llvm-objdump" in objdump_bin:
                cmd.append(f"--arch={arch_name}")
                cmd.append("--x86-asm-syntax=intel")
            else:
                cmd.extend(["-M", "intel"])
            cmd.extend([
                f"--start-address=0x{start_vmaddr:x}",
                f"--stop-address=0x{stop_vmaddr:x}",
                file_path,
            ])
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        m = OBJDUMP_LINE_RE.match(line)
                        if m and len(instructions) < count:
                            vm_val = int(m.group(1), 16)
                            raw_hex_str = " ".join(m.group(2).strip().lower().split())
                            byte_len = len(raw_hex_str.split())
                            mnem = m.group(3).strip()
                            ops_raw = (m.group(4) or "").strip()
                            comment = None
                            if "#" in ops_raw:
                                parts = ops_raw.split("#", 1)
                                ops_raw = parts[0].strip()
                                comment = parts[1].strip().lstrip("#").strip()
                            # objdump's own "<symbol+offset>" annotations are replaced by ours below
                            ops_raw = _SYMBOL_ANNOTATION_RE.sub("", ops_raw).strip()
                            if comment:
                                comment = _SYMBOL_ANNOTATION_RE.sub("", comment).strip() or None
                            sl_off = base_slice_off + (vm_val - start_vmaddr)
                            branch_tgt = None
                            ref_tgt = None
                            if mnem.startswith("j") or mnem == "callq" or mnem == "call":
                                hex_m = _BARE_ADDRESS_RE.match(ops_raw)   # a direct target, not a displacement
                                if hex_m:
                                    branch_tgt = int(hex_m.group(1), 16)
                                    if branch_tgt in sym_by_vm:
                                        comment = f"-> {sym_by_vm[branch_tgt]}"
                            if branch_tgt is None and comment:
                                addr_m = _LEADING_ADDRESS_RE.match(comment)   # "# 0x..." of a RIP-relative operand
                                if addr_m:
                                    ref_tgt = int(addr_m.group(1), 16)
                                    comment = _reference_comment(ref_tgt, sym_by_vm, str_by_vm) or f"0x{ref_tgt:x}"
                            row = {
                                "vmaddr": f"0x{vm_val:x}",
                                "slice_offset": sl_off,
                                "abs_offset": slice_base_offset + sl_off,
                                "size": byte_len,
                                "raw_hex": raw_hex_str,
                                "mnemonic": mnem,
                                "operands": ops_raw,
                                "symbol_label": sym_by_vm.get(vm_val),
                                "comment": comment,
                                "branch_target_vmaddr": f"0x{branch_tgt:x}" if branch_tgt is not None else None,
                            }
                            if ref_tgt is not None:
                                row["ref_vmaddr"] = f"0x{ref_tgt:x}"
                            instructions.append(row)
                    if instructions:
                        return {
                            "slice_index": slice_data.get("slice_index", 0),
                            "arch_name": arch_name,
                            "section": sec_label,
                            "start_vmaddr": f"0x{start_vmaddr:x}",
                            "instructions": instructions,
                            "decoder": "objdump",
                            "syntax": "intel",
                        }
            except Exception:
                pass
            instructions = []

        # Built-in x86 / x86_64 stream decoder
        is_64_x86 = (arch_name == "x86_64")
        window_end = start_vmaddr + limit_bytes
        anchors = sorted({a for a in code_starts if start_vmaddr < a < window_end})
        anchors.extend(sorted({start_vmaddr + (r[0] - base_slice_off) for r in dice
                               if base_slice_off < r[0] < base_slice_off + limit_bytes}))
        anchors.sort()
        cur_rel = 0
        steps = 0
        while cur_rel < limit_bytes and len(instructions) < count:
            steps += 1
            if not steps & 0xFF:
                runtime.check_deadline()
            cur_slice_off = base_slice_off + cur_rel
            cur_vm = start_vmaddr + cur_rel
            label = sym_by_vm.get(cur_vm)
            data_range = data_range_at(cur_slice_off)
            if data_range is not None:
                size = min(data_range[2], data_range[1] - cur_slice_off, limit_bytes - cur_rel)
                instructions.append(_data_row(cur_vm, cur_slice_off, slice_base_offset,
                                              raw_slice_bytes[cur_slice_off:cur_slice_off + size], label))
                cur_rel += max(1, size)
                continue
            # Nothing past the end of the section, and nothing past the next anchor, belongs to this instruction.
            room = limit_bytes - cur_rel
            i = bisect.bisect_right(anchors, cur_vm)
            anchor = anchors[i] if i < len(anchors) else None
            chunk = raw_slice_bytes[cur_slice_off:cur_slice_off + min(15, room)]
            b_len, mnem, ops, comment, target, kind, _in_step = _x86_decode(chunk, 0, cur_vm, is_64_x86)
            if anchor is not None and cur_vm + b_len > anchor:
                b_len = anchor - cur_vm
                chunk = chunk[:b_len]
                mnem, ops, target, kind = ".byte", _byte_list(chunk), None, None
                comment = (f"shown as data: an instruction decoded here would run across "
                           f"{sym_by_vm.get(anchor) or 'the data'} at 0x{anchor:x}")
            branch_target = None
            ref = None
            if target is not None:
                if kind == "branch":
                    branch_target = target
                    if target in sym_by_vm:
                        comment = f"-> {sym_by_vm[target]}"
                else:
                    ref = target
                    comment = _reference_comment(target, sym_by_vm, str_by_vm)
                    if comment is None and "rip" in ops:
                        comment = f"0x{target:x}"   # like objdump's "# 0x..." for a RIP-relative operand
            instructions.append(_row(cur_vm, cur_slice_off, slice_base_offset, chunk[:b_len], mnem, ops, label,
                                     comment, branch_target, ref))
            cur_rel += max(1, b_len)

        return {
            "slice_index": slice_data.get("slice_index", 0),
            "arch_name": arch_name,
            "section": sec_label,
            "start_vmaddr": f"0x{start_vmaddr:x}",
            "instructions": instructions,
            "decoder": "builtin",
            "syntax": "intel",
        }

    # ARM64 / ARM64e: fixed 4-byte instructions, with an ADRP page tracker for ADRP+ADD / ADRP+LDR pairs
    num_insns = min(count, limit_bytes // 4)
    adrp_pages: Dict[str, int] = {}

    for i in range(num_insns):
        if i and not i & 0xFF:
            runtime.check_deadline()
        cur_vm = start_vmaddr + i * 4
        cur_slice_off = base_slice_off + i * 4
        if cur_slice_off + 4 > len(raw_slice_bytes):
            break
        raw_word_bytes = raw_slice_bytes[cur_slice_off : cur_slice_off + 4]
        label = sym_by_vm.get(cur_vm)
        if label is not None:
            adrp_pages.clear()      # a new function: nothing is known about the registers
        if data_range_at(cur_slice_off) is not None:
            instructions.append(_data_row(cur_vm, cur_slice_off, slice_base_offset, raw_word_bytes, label))
            continue
        word = struct.unpack("<I", raw_word_bytes)[0]

        mnem, ops, comment, target, kind = _a64_decode(word, cur_vm)
        branch_target = target if kind == "branch" else None
        ref = target if kind == "data" else None

        # Track ADRP pages so that the instruction that completes the address can name what it refers to.
        parts = [p.strip() for p in ops.split(",")] if ops else []
        dest = parts[0] if parts else ""
        dest_x = "x" + dest[1:] if dest[:1] == "w" and dest[1:].isdigit() else dest
        if mnem == "adrp" and target is not None:
            adrp_pages[dest_x] = target
            comment = _reference_comment(target, sym_by_vm, str_by_vm)
        elif mnem == "adr" and target is not None:
            adrp_pages.pop(dest_x, None)
            comment = _reference_comment(target, sym_by_vm, str_by_vm)
        elif mnem == "add" and len(parts) == 3 and parts[1] in adrp_pages and parts[2].startswith("#0x"):
            ref = adrp_pages[parts[1]] + int(parts[2][1:], 16)
            comment = _reference_comment(ref, sym_by_vm, str_by_vm) or f"0x{ref:x}"
            adrp_pages.pop(dest_x, None)
        elif mnem.startswith(("ldr", "str")) and len(parts) >= 2:
            mem = _A64_MEM_RE.search(ops)
            if mem and mem.group(1) in adrp_pages:
                ref = adrp_pages[mem.group(1)] + (int(mem.group(2), 16) if mem.group(2) else 0)
                comment = _reference_comment(ref, sym_by_vm, str_by_vm) or f"[0x{ref:x}]"
            if mnem.startswith("ldr"):
                adrp_pages.pop(dest_x, None)
        elif mnem in ("bl", "blr", "b", "br", "ret") or mnem.startswith(("blra", "bra", "reta")):
            adrp_pages.clear()      # a call may change any scratch register; after a jump the flow is elsewhere
        elif adrp_pages and not mnem.startswith(_A64_NO_WRITE):
            adrp_pages.pop(dest_x, None)    # the register is overwritten: it no longer holds the page
            if mnem.startswith(("ldp", "ldnp", "ldxp", "ldaxp")) and len(parts) > 1:
                adrp_pages.pop(parts[1], None)

        if branch_target is not None and branch_target in sym_by_vm:
            comment = f"-> {sym_by_vm[branch_target]}"

        instructions.append(_row(cur_vm, cur_slice_off, slice_base_offset, raw_word_bytes, mnem, ops, label,
                                 comment, branch_target, ref))

    return {
        "slice_index": slice_data.get("slice_index", 0),
        "arch_name": arch_name,
        "section": sec_label,
        "start_vmaddr": f"0x{start_vmaddr:x}",
        "instructions": instructions,
        "decoder": "builtin",
        "syntax": "arm64",
    }
