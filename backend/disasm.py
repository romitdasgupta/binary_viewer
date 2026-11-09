"""
Layer 3: Windowed ARM64 & x86_64 Disassembler with Native Pure-Python ARM64 Decoder
and macOS llvm-objdump / otool Integration + Symbol/String Cross-Referencing.
"""

import os
import re
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple


def _reg64(r: int, sp_at_31: bool = False) -> str:
    if r == 31:
        return "sp" if sp_at_31 else "xzr"
    if r == 29:
        return "x29"
    if r == 30:
        return "x30"
    return f"x{r}"


def _reg32(r: int, sp_at_31: bool = False) -> str:
    if r == 31:
        return "wsp" if sp_at_31 else "wzr"
    return f"w{r}"


def _sign_extend(val: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (val & (sign_bit - 1)) - (val & sign_bit)


def decode_arm64_insn(word: int, pc: int = 0) -> Tuple[str, str, Optional[str], Optional[int]]:
    """
    Pure-Python AArch64 (ARM64 / ARM64e) instruction decoder.
    Returns (mnemonic, operands, comment, branch_target_vmaddr).
    """
    # System / PAC / Hint instructions
    if word == 0xD503201F:
        return ("nop", "", "No Operation", None)
    if word == 0xD503233F:
        return ("paciasp", "", "PAC Sign LR (x30) with SP using Key IA", None)
    if word == 0xD503237F:
        return ("pacibsp", "", "PAC Sign LR (x30) with SP using Key IB", None)
    if word == 0xD50323BF:
        return ("autiasp", "", "PAC Authenticate LR (x30) with SP using Key IA", None)
    if word == 0xD50323FF:
        return ("autibsp", "", "PAC Authenticate LR (x30) with SP using Key IB", None)
    if word == 0xD503245F:
        return ("bti", "c", "Branch Target Identification (Call)", None)
    if word == 0xD65F03C0:
        return ("ret", "", "Return from subroutine (branch to x30)", None)
    if word == 0xD65F0BFF:
        return ("retaa", "", "PAC Authenticated Return (Key IA)", None)
    if word == 0xD65F0FFF:
        return ("retab", "", "PAC Authenticated Return (Key IB)", None)

    # RET Xn
    if (word & 0xFFFFFC1F) == 0xD65F0000:
        rn = (word >> 5) & 0x1F
        return ("ret", _reg64(rn), None, None)

    # BR / BLR Xn
    if (word & 0xFFFFFC1F) == 0xD61F0000:
        rn = (word >> 5) & 0x1F
        return ("br", _reg64(rn), "Indirect branch", None)
    if (word & 0xFFFFFC1F) == 0xD63F0000:
        rn = (word >> 5) & 0x1F
        return ("blr", _reg64(rn), "Indirect call", None)

    # Braa / Blraa (ARM64e PAC indirect branch/call)
    if (word & 0xFEFFF800) == 0xD71F0000:
        rn = (word >> 5) & 0x1F
        rm = word & 0x1F
        is_link = bool((word >> 21) & 1)
        mnem = "blraa" if is_link else "braa"
        return (mnem, f"{_reg64(rn)}, {_reg64(rm, True)}", "PAC Authenticated Indirect Branch/Call", None)

    # SVC / BRK / UDF
    if (word & 0xFFE0001F) == 0xD4000001:
        imm16 = (word >> 5) & 0xFFFF
        return ("svc", f"#0x{imm16:x}", "Supervisor Call (Syscall)", None)
    if (word & 0xFFE0001F) == 0xD4200000:
        imm16 = (word >> 5) & 0xFFFF
        return ("brk", f"#0x{imm16:x}", "Software Breakpoint Trap", None)
    if (word & 0xFFFF0000) == 0x00000000:
        imm16 = word & 0xFFFF
        return ("udf", f"#0x{imm16:x}", "Undefined Instruction", None)

    # Unconditional Branch B / BL (imm26)
    op_top6 = (word >> 26) & 0x3F
    if op_top6 in (0b000101, 0b100101):
        is_bl = op_top6 == 0b100101
        imm26 = _sign_extend(word & 0x03FFFFFF, 26) * 4
        target = (pc + imm26) & 0xFFFFFFFFFFFFFFFF
        mnem = "bl" if is_bl else "b"
        return (mnem, f"0x{target:x}", "Function Call" if is_bl else "Unconditional Branch", target)

    # Conditional Branch B.<cond>
    if (word & 0xFF000010) == 0x54000000:
        imm19 = _sign_extend((word >> 5) & 0x7FFFF, 19) * 4
        cond_code = word & 0xF
        conds = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
        target = (pc + imm19) & 0xFFFFFFFFFFFFFFFF
        return (f"b.{conds[cond_code]}", f"0x{target:x}", None, target)

    # CBZ / CBNZ
    if (word & 0x7E000000) == 0x34000000:
        sf = (word >> 31) & 1
        is_nz = (word >> 24) & 1
        imm19 = _sign_extend((word >> 5) & 0x7FFFF, 19) * 4
        rt = word & 0x1F
        reg = _reg64(rt) if sf else _reg32(rt)
        target = (pc + imm19) & 0xFFFFFFFFFFFFFFFF
        return ("cbnz" if is_nz else "cbz", f"{reg}, 0x{target:x}", None, target)

    # ADR / ADRP
    if (word & 0x1F000000) == 0x10000000:
        is_adrp = (word >> 31) & 1
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm21 = _sign_extend((immhi << 2) | immlo, 21)
        rd = word & 0x1F
        if is_adrp:
            target = ((pc & ~0xFFF) + (imm21 << 12)) & 0xFFFFFFFFFFFFFFFF
            return ("adrp", f"{_reg64(rd)}, 0x{target:x}", f"Page base 0x{target:x}", target)
        else:
            target = (pc + imm21) & 0xFFFFFFFFFFFFFFFF
            return ("adr", f"{_reg64(rd)}, 0x{target:x}", f"Address 0x{target:x}", target)

    # ADD / SUB (immediate)
    if (word & 0x1F000000) == 0x11000000:
        sf = (word >> 31) & 1
        op_sub = (word >> 30) & 1
        set_flags = (word >> 29) & 1
        sh = (word >> 22) & 1
        imm12 = (word >> 10) & 0xFFF
        rn = (word >> 5) & 0x1F
        rd = word & 0x1F
        r_fn = _reg64 if sf else _reg32
        shift_str = ", lsl #12" if sh else ""
        if set_flags and rd == 31:
            return ("cmp" if op_sub else "cmn", f"{r_fn(rn, True)}, #0x{imm12:x}{shift_str}", None, None)
        if not op_sub and not set_flags and imm12 == 0 and not sh and (rd == 31 or rn == 31):
            return ("mov", f"{r_fn(rd, True)}, {r_fn(rn, True)}", "Register move (SP/FP)", None)
        mnem = ("sub" if op_sub else "add") + ("s" if set_flags else "")
        return (
            mnem,
            f"{r_fn(rd, not set_flags)}, {r_fn(rn, True)}, #0x{imm12:x}{shift_str}",
            None,
            None,
        )

    # MOVZ / MOVN / MOVK (wide immediate)
    if (word & 0x1F800000) == 0x12800000:
        sf = (word >> 31) & 1
        opc = (word >> 29) & 0x3
        hw = ((word >> 21) & 0x3) * 16
        imm16 = (word >> 5) & 0xFFFF
        rd = word & 0x1F
        r_fn = _reg64 if sf else _reg32
        if opc == 0b10 and hw == 0:
            return ("mov", f"{r_fn(rd)}, #0x{imm16:x}", f"Immediate {imm16}", None)
        if opc == 0b00 and hw == 0:
            val = ~imm16
            return ("mov", f"{r_fn(rd)}, #{val}", None, None)
        mnems = {0: "movn", 2: "movz", 3: "movk"}
        mnem = mnems.get(opc, "movz")
        lsl = f", lsl #{hw}" if hw else ""
        return (mnem, f"{r_fn(rd)}, #0x{imm16:x}{lsl}", None, None)

    # ORR register (MOV alias when Rn == XZR)
    if (word & 0x7FE0FFE0) == 0x2A0003E0:
        sf = (word >> 31) & 1
        rm = (word >> 16) & 0x1F
        rd = word & 0x1F
        r_fn = _reg64 if sf else _reg32
        return ("mov", f"{r_fn(rd)}, {r_fn(rm)}", None, None)

    # STP / LDP (Load/Store Pair of Registers)
    if (word & 0x3E000000) == 0x28000000:
        opc = (word >> 30) & 0x3
        mode = (word >> 23) & 0x3
        is_load = (word >> 22) & 1
        imm7 = _sign_extend((word >> 15) & 0x7F, 7)
        rt2 = (word >> 10) & 0x1F
        rn = (word >> 5) & 0x1F
        rt = word & 0x1F
        is_64 = (opc & 0x2) != 0
        scale = 8 if is_64 else 4
        offset = imm7 * scale
        r_fn = _reg64 if is_64 else _reg32
        mnem = "ldp" if is_load else "stp"
        off_str = f", #{offset}" if offset != 0 else ""
        if mode == 0b11:  # Pre-indexed
            addr_op = f"[{_reg64(rn, True)}{off_str}]!"
        elif mode == 0b01:  # Post-indexed
            addr_op = f"[{_reg64(rn, True)}], #{offset}"
        else:  # Signed offset
            addr_op = f"[{_reg64(rn, True)}{off_str}]"
        comment = (
            "Prologue frame setup"
            if (not is_load and rt == 29 and rt2 == 30)
            else "Epilogue frame restore"
            if (is_load and rt == 29 and rt2 == 30)
            else None
        )
        return (mnem, f"{r_fn(rt)}, {r_fn(rt2)}, {addr_op}", comment, None)

    # LDR / STR (unsigned immediate)
    if (word & 0x3B000000) == 0x39000000:
        size_bits = (word >> 30) & 0x3
        opc = (word >> 22) & 0x3
        imm12 = (word >> 10) & 0xFFF
        rn = (word >> 5) & 0x1F
        rt = word & 0x1F
        is_load = (opc & 1) != 0
        scale = 1 << size_bits
        offset = imm12 * scale
        r_fn = _reg64 if size_bits == 3 else _reg32
        mnem = {
            (0, False): "strb",
            (0, True): "ldrb",
            (1, False): "strh",
            (1, True): "ldrh",
            (2, False): "str",
            (2, True): "ldr",
            (3, False): "str",
            (3, True): "ldr",
        }.get((size_bits, is_load), "ldr" if is_load else "str")
        off_str = f", #0x{offset:x}" if offset else ""
        return (mnem, f"{r_fn(rt)}, [{_reg64(rn, True)}{off_str}]", None, None)

    return (".long", f"0x{word:08x}", None, None)


def decode_single_arm64_preview(raw_bytes: bytes, vmaddr: int = 0) -> str:
    """Formats a 4-byte sequence as a human-readable ARM64 instruction string for /api/decode."""
    if len(raw_bytes) < 4:
        return "insufficient bytes"
    word = struct.unpack("<I", raw_bytes[:4])[0]
    mnem, ops, _, _ = decode_arm64_insn(word, vmaddr)
    return f"{mnem} {ops}".strip()


X86_REG64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
X86_REG32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]


def decode_x86_64_insn(buf: bytes, pos: int, pc: int, is_64: bool = True) -> Tuple[int, str, str, Optional[str], Optional[int]]:
    """
    Lightweight pure-Python x86 / x86_64 instruction decoder for common prologues, calls,
    branches, RIP-relative addressing, and syscalls.
    Returns (byte_len, mnemonic, operands, comment, branch_target_vmaddr).
    """
    rem = len(buf) - pos
    if rem <= 0:
        return (1, ".byte", "0x00", None, None)

    b0 = buf[pos]
    # ENDBR64 (f3 0f 1e fa) / ENDBR32 (f3 0f 1e fb)
    if rem >= 4 and buf[pos : pos + 4] == b"\xf3\x0f\x1e\xfa":
        return (4, "endbr64", "", "Intel CET Indirect Branch Target", None)
    if rem >= 4 and buf[pos : pos + 4] == b"\xf3\x0f\x1e\xfb":
        return (4, "endbr32", "", "Intel CET Indirect Branch Target", None)

    # Single-byte common instructions
    if b0 == 0x90:
        return (1, "nop", "", None, None)
    if b0 == 0xC3:
        return (1, "ret", "", "Return from procedure", None)
    if b0 == 0xC9:
        return (1, "leave", "", "Restore stack frame", None)
    if b0 == 0xCC:
        return (1, "int3", "", "Software breakpoint trap", None)
    if rem >= 2 and b0 == 0x0F and buf[pos + 1] == 0x05:
        return (2, "syscall", "", "System call into Ring 0 kernel", None)
    if rem >= 2 and b0 == 0xCD:
        return (2, "int", f"0x{buf[pos + 1]:02x}", "Software interrupt", None)

    # PUSH / POP r64/r32 (0x50..0x5F)
    if 0x50 <= b0 <= 0x57:
        rname = X86_REG64[b0 - 0x50] if is_64 else X86_REG32[b0 - 0x50]
        return (1, "push", rname, None, None)
    if 0x58 <= b0 <= 0x5F:
        rname = X86_REG64[b0 - 0x58] if is_64 else X86_REG32[b0 - 0x58]
        return (1, "pop", rname, None, None)

    # Direct CALL rel32 (E8) / JMP rel32 (E9) / JMP rel8 (EB)
    if b0 in (0xE8, 0xE9) and rem >= 5:
        rel32 = struct.unpack_from("<i", buf, pos + 1)[0]
        tgt = (pc + 5 + rel32) & 0xFFFFFFFFFFFFFFFF
        mnem = "call" if b0 == 0xE8 else "jmp"
        return (5, mnem, f"0x{tgt:x}", "Relative call" if b0 == 0xE8 else "Relative jump", tgt)
    if b0 == 0xEB and rem >= 2:
        rel8 = struct.unpack_from("<b", buf, pos + 1)[0]
        tgt = (pc + 2 + rel8) & 0xFFFFFFFFFFFFFFFF
        return (2, "jmp", f"0x{tgt:x}", None, tgt)
    if 0x70 <= b0 <= 0x7F and rem >= 2:
        jcc_names = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]
        rel8 = struct.unpack_from("<b", buf, pos + 1)[0]
        tgt = (pc + 2 + rel8) & 0xFFFFFFFFFFFFFFFF
        return (2, jcc_names[b0 - 0x70], f"0x{tgt:x}", None, tgt)

    # Indirect CALL / JMP via RIP-relative or absolute [disp32] (FF 15 / FF 25)
    if rem >= 6 and b0 == 0xFF and buf[pos + 1] in (0x15, 0x25):
        is_call = (buf[pos + 1] == 0x15)
        disp32 = struct.unpack_from("<i", buf, pos + 2)[0]
        slot_vm = ((pc + 6 + disp32) if is_64 else (disp32 & 0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
        mnem = "call" if is_call else "jmp"
        op_str = f"qword ptr [rip + 0x{disp32:x}]" if is_64 else f"dword ptr [0x{slot_vm:x}]"
        return (6, mnem, op_str, f"GOT/IAT slot @ 0x{slot_vm:x}", slot_vm)

    # PUSH imm32 (68) / PUSH imm8 (6A)
    if b0 == 0x68 and rem >= 5:
        imm32 = struct.unpack_from("<I", buf, pos + 1)[0]
        return (5, "push", f"0x{imm32:x}", None, None)
    if b0 == 0x6A and rem >= 2:
        return (2, "push", f"0x{buf[pos + 1]:x}", None, None)

    # MOV reg32, imm32 (B8..BF)
    if 0xB8 <= b0 <= 0xBF and rem >= 5:
        imm32 = struct.unpack_from("<I", buf, pos + 1)[0]
        return (5, "mov", f"{X86_REG32[b0 - 0xB8]}, 0x{imm32:x}", None, None)

    # 32-bit xor/mov/sub/add without REX
    if rem >= 2 and b0 == 0x31:
        modrm = buf[pos + 1]
        if (modrm & 0xC0) == 0xC0:
            r1 = X86_REG32[modrm & 7]
            r2 = X86_REG32[(modrm >> 3) & 7]
            return (2, "xor", f"{r1}, {r2}", "Zero register" if r1 == r2 else None, None)
    if rem >= 2 and b0 == 0x89:
        modrm = buf[pos + 1]
        if (modrm & 0xC0) == 0xC0:
            r_dst = X86_REG32[modrm & 7]
            r_src = X86_REG32[(modrm >> 3) & 7]
            return (2, "mov", f"{r_dst}, {r_src}", None, None)
    if rem >= 3 and b0 == 0x83:
        modrm = buf[pos + 1]
        imm8 = buf[pos + 2]
        subop = (modrm >> 3) & 7
        reg = X86_REG32[modrm & 7]
        mnem = {0: "add", 5: "sub", 7: "cmp"}.get(subop, "alu")
        return (3, mnem, f"{reg}, 0x{imm8:x}", None, None)

    # REX.W (0x48 / 0x4C) 64-bit instructions
    if is_64 and rem >= 3 and b0 in (0x48, 0x4C):
        op = buf[pos + 1]
        modrm = buf[pos + 2]
        reg_idx = ((modrm >> 3) & 7) + (8 if (b0 & 0x04) else 0)
        rm_idx = (modrm & 7) + (8 if (b0 & 0x01) else 0)
        if op == 0x89 and (modrm & 0xC0) == 0xC0:
            return (3, "mov", f"{X86_REG64[rm_idx]}, {X86_REG64[reg_idx]}", None, None)
        if op == 0x31 and (modrm & 0xC0) == 0xC0:
            return (3, "xor", f"{X86_REG64[rm_idx]}, {X86_REG64[reg_idx]}", None, None)
        if op == 0x83 and rem >= 4 and (modrm & 0xC0) == 0xC0:
            imm8 = buf[pos + 3]
            subop = (modrm >> 3) & 7
            mnem = {0: "add", 5: "sub", 7: "cmp"}.get(subop, "alu")
            return (4, mnem, f"{X86_REG64[rm_idx]}, 0x{imm8:x}", None, None)
        if op in (0x8D, 0x8B) and (modrm & 0xC7) == 0x05 and rem >= 7:
            disp32 = struct.unpack_from("<i", buf, pos + 3)[0]
            tgt = (pc + 7 + disp32) & 0xFFFFFFFFFFFFFFFF
            mnem = "lea" if op == 0x8D else "mov"
            return (7, mnem, f"{X86_REG64[reg_idx]}, [rip + 0x{disp32:x}]", f"Target @ 0x{tgt:x}", tgt)

    return (1, ".byte", f"0x{b0:02x}", None, None)


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
    Uses built-in AArch64 decoder + symbol/string cross-referencing for ARM64,
    and llvm-objdump for x86_64/i386 or enhanced mnemonics.
    """
    count = max(1, min(count, 1000))
    arch_name = slice_data.get("arch_name", "arm64")

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
    else:
        sec_label = target_segment["segname"]
        base_slice_off = target_segment["fileoff"] + (start_vmaddr - target_segment["vmaddr_int"])
        max_bytes = max(0, (target_segment["vmaddr_int"] + target_segment["filesize"]) - start_vmaddr)

    # Lookup tables for symbols and strings by VMAddr
    sym_by_vm: Dict[int, str] = {}
    for s in slice_data.get("symbols", []):
        if s.get("type_name") == "SECT" and s.get("n_value_int", 0) > 0:
            sym_by_vm[s["n_value_int"]] = s.get("demangled") or s.get("name", "")
    for fs in slice_data.get("function_starts", []):
        vm_i = int(fs["vmaddr"], 16)
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

    # Try llvm-objdump / GNU objdump for x86_64 / i386 when file exists on disk,
    # then fall back to the pure-Python x86/x86_64 decoder.
    if arch_name.startswith("x86") or arch_name == "i386":
        objdump_bin = _find_objdump()
        if objdump_bin and file_path and os.path.isfile(file_path):
            stop_vmaddr = start_vmaddr + min(max_bytes, count * 8)
            cmd = [objdump_bin, "-d"]
            if "llvm-objdump" in objdump_bin:
                cmd.append(f"--arch={arch_name}")
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
                                comment = parts[1].strip()
                            sl_off = base_slice_off + (vm_val - start_vmaddr)
                            branch_tgt = None
                            if mnem.startswith("j") or mnem == "callq" or mnem == "call":
                                hex_m = re.search(r"0x([0-9a-fA-F]+)", ops_raw)
                                if hex_m:
                                    tgt_val = int(hex_m.group(1), 16)
                                    branch_tgt = f"0x{tgt_val:x}"
                                    if tgt_val in sym_by_vm and not comment:
                                        comment = f"-> {sym_by_vm[tgt_val]}"
                            instructions.append({
                                "vmaddr": f"0x{vm_val:x}",
                                "slice_offset": sl_off,
                                "abs_offset": slice_base_offset + sl_off,
                                "size": byte_len,
                                "raw_hex": raw_hex_str,
                                "mnemonic": mnem,
                                "operands": ops_raw,
                                "symbol_label": sym_by_vm.get(vm_val),
                                "comment": comment,
                                "branch_target_vmaddr": branch_tgt,
                            })
                    if instructions:
                        return {
                            "slice_index": slice_data.get("slice_index", 0),
                            "arch_name": arch_name,
                            "section": sec_label,
                            "start_vmaddr": f"0x{start_vmaddr:x}",
                            "instructions": instructions,
                        }
            except Exception:
                pass

        # Pure-Python x86 / x86_64 stream decoder fallback
        is_64_x86 = (arch_name == "x86_64")
        cur_rel = 0
        limit_bytes = min(max_bytes, len(raw_slice_bytes) - base_slice_off)
        while cur_rel < limit_bytes and len(instructions) < count:
            cur_slice_off = base_slice_off + cur_rel
            cur_vm = start_vmaddr + cur_rel
            b_len, mnem, ops, comment, branch_target = decode_x86_64_insn(
                raw_slice_bytes, cur_slice_off, cur_vm, is_64=is_64_x86
            )
            raw_insn_bytes = raw_slice_bytes[cur_slice_off : cur_slice_off + b_len]
            raw_hex = " ".join(f"{b:02x}" for b in raw_insn_bytes)
            if branch_target is not None:
                if branch_target in sym_by_vm:
                    comment = f"-> {sym_by_vm[branch_target]}"
                elif branch_target in str_by_vm:
                    s_preview = str_by_vm[branch_target][:48].replace("\n", "\\n")
                    comment = f'"{s_preview}" @ 0x{branch_target:x}'
            instructions.append({
                "vmaddr": f"0x{cur_vm:x}",
                "slice_offset": cur_slice_off,
                "abs_offset": slice_base_offset + cur_slice_off,
                "size": b_len,
                "raw_hex": raw_hex,
                "mnemonic": mnem,
                "operands": ops,
                "symbol_label": sym_by_vm.get(cur_vm),
                "comment": comment,
                "branch_target_vmaddr": f"0x{branch_target:x}" if branch_target is not None else None,
            })
            cur_rel += max(1, b_len)

        return {
            "slice_index": slice_data.get("slice_index", 0),
            "arch_name": arch_name,
            "section": sec_label,
            "start_vmaddr": f"0x{start_vmaddr:x}",
            "instructions": instructions,
        }

    # ARM64 / ARM64e deterministic decoder with ADRP+ADD / ADRP+LDR tracker
    num_insns = min(count, max_bytes // 4)
    adrp_pages: Dict[str, int] = {}

    for i in range(num_insns):
        cur_vm = start_vmaddr + i * 4
        cur_slice_off = base_slice_off + i * 4
        if cur_slice_off + 4 > len(raw_slice_bytes):
            break
        raw_word_bytes = raw_slice_bytes[cur_slice_off : cur_slice_off + 4]
        word = struct.unpack("<I", raw_word_bytes)[0]
        raw_hex = " ".join(f"{b:02x}" for b in raw_word_bytes)

        mnem, ops, comment, branch_target = decode_arm64_insn(word, cur_vm)

        # Track ADRP + ADD/LDR pairs for automatic string & symbol cross-referencing
        if mnem == "adrp" and branch_target is not None:
            reg_name = ops.split(",")[0].strip()
            adrp_pages[reg_name] = branch_target
        elif mnem in ("add", "ldr") and "," in ops:
            parts = [p.strip() for p in ops.split(",")]
            if len(parts) >= 3 and mnem == "add":
                dst_reg, src_reg, imm_part = parts[0], parts[1], parts[2]
                if src_reg in adrp_pages and imm_part.startswith("#0x"):
                    try:
                        resolved_vm = adrp_pages[src_reg] + int(imm_part[1:], 16)
                        if resolved_vm in str_by_vm:
                            s_preview = str_by_vm[resolved_vm][:48].replace("\n", "\\n")
                            comment = f'"{s_preview}" @ 0x{resolved_vm:x}'
                            branch_target = resolved_vm
                        elif resolved_vm in sym_by_vm:
                            comment = f"-> {sym_by_vm[resolved_vm]} @ 0x{resolved_vm:x}"
                            branch_target = resolved_vm
                    except ValueError:
                        pass

        if branch_target is not None and branch_target in sym_by_vm:
            sym_target_name = sym_by_vm[branch_target]
            comment = f"-> {sym_target_name}"

        instructions.append({
            "vmaddr": f"0x{cur_vm:x}",
            "slice_offset": cur_slice_off,
            "abs_offset": slice_base_offset + cur_slice_off,
            "size": 4,
            "raw_hex": raw_hex,
            "mnemonic": mnem,
            "operands": ops,
            "symbol_label": sym_by_vm.get(cur_vm),
            "comment": comment,
            "branch_target_vmaddr": f"0x{branch_target:x}" if branch_target is not None else None,
        })

    return {
        "slice_index": slice_data.get("slice_index", 0),
        "arch_name": arch_name,
        "section": sec_label,
        "start_vmaddr": f"0x{start_vmaddr:x}",
        "instructions": instructions,
    }
