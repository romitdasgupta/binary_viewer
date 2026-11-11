"""
Layer 2B: ELF32 & ELF64 (Executable and Linkable Format) Structural Binary Parser
and Linux / Embedded Firmware Security Hardening Audit Engine.
Supports Little-Endian (ELFDATA2LSB) & Big-Endian (ELFDATA2MSB), ET_EXEC, ET_DYN,
ET_REL, and ET_CORE across x86_64, i386, AArch64 (ARM64), ARM32, RISC-V, PowerPC, and MIPS.
"""

import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from . import runtime
from .buffer import BinaryBuffer, BinaryFormatError, SegmentLookup, add_warning, make_region
from .constants import ANALYSIS_LIMITS

ELF_MAGIC = b"\x7fELF"
# A whole NUL-delimited C string made only of printable ASCII / tab / LF / CR.
_CSTRING_RUN_3 = re.compile(rb"(?:^|(?<=\x00))[\x20-\x7e\t\n\r]{3,}(?=\x00|\Z)")

ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATA2LSB = 1
ELFDATA2MSB = 2

ELF_OSABI_NAMES: Dict[int, str] = {
    0: "UNIX System V ABI",
    1: "HP-UX",
    2: "NetBSD",
    3: "GNU/Linux",
    6: "Solaris",
    7: "AIX",
    8: "IRIX",
    9: "FreeBSD",
    12: "OpenBSD",
    64: "ARM EABI",
    97: "ARM",
    255: "Standalone (Embedded/Firmware)",
}

ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4

ELF_TYPE_INFO: Dict[int, Tuple[str, str]] = {
    ET_NONE: ("ET_NONE", "Unknown ELF File Type"),
    ET_REL: ("ET_REL", "Relocatable Object File (.o / Kernel Module .ko)"),
    ET_EXEC: ("ET_EXEC", "Fixed-Address Executable Binary"),
    ET_DYN: ("ET_DYN", "Position-Independent Executable (PIE) or Shared Object (.so)"),
    ET_CORE: ("ET_CORE", "Process Core Dump Image"),
}

ELF_MACHINE_INFO: Dict[int, Tuple[str, str, str]] = {
    3: ("i386", "EM_386", "Intel 80386 (x86 32-bit)"),
    8: ("mips", "EM_MIPS", "MIPS (all MIPS I to MIPS64 variants)"),
    20: ("ppc", "EM_PPC", "PowerPC 32-bit"),
    21: ("ppc64", "EM_PPC64", "PowerPC 64-bit"),
    40: ("arm", "EM_ARM", "ARM 32-bit (AArch32 / Thumb)"),
    62: ("x86_64", "EM_X86_64", "AMD x86-64 (64-bit)"),
    183: ("arm64", "EM_AARCH64", "ARM 64-bit (AArch64)"),
    243: ("riscv64", "EM_RISCV", "RISC-V (RV32/RV64)"),
}

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_GNU_PROPERTY = 0x6474E553

PHDR_TYPE_NAMES: Dict[int, str] = {
    PT_NULL: "PT_NULL",
    PT_LOAD: "PT_LOAD",
    PT_DYNAMIC: "PT_DYNAMIC",
    PT_INTERP: "PT_INTERP",
    PT_NOTE: "PT_NOTE",
    PT_SHLIB: "PT_SHLIB",
    PT_PHDR: "PT_PHDR",
    PT_TLS: "PT_TLS",
    PT_GNU_EH_FRAME: "PT_GNU_EH_FRAME",
    PT_GNU_STACK: "PT_GNU_STACK",
    PT_GNU_RELRO: "PT_GNU_RELRO",
    PT_GNU_PROPERTY: "PT_GNU_PROPERTY",
}

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_PREINIT_ARRAY = 16
SHT_RELR = 19
SHT_GNU_HASH = 0x6FFFFFF6
SHT_GNU_VERDEF = 0x6FFFFFFD
SHT_GNU_VERNEED = 0x6FFFFFFE
SHT_GNU_VERSYM = 0x6FFFFFFF

SHDR_TYPE_NAMES: Dict[int, str] = {
    SHT_NULL: "SHT_NULL",
    SHT_PROGBITS: "SHT_PROGBITS",
    SHT_SYMTAB: "SHT_SYMTAB",
    SHT_STRTAB: "SHT_STRTAB",
    SHT_RELA: "SHT_RELA",
    SHT_HASH: "SHT_HASH",
    SHT_DYNAMIC: "SHT_DYNAMIC",
    SHT_NOTE: "SHT_NOTE",
    SHT_NOBITS: "SHT_NOBITS",
    SHT_REL: "SHT_REL",
    SHT_SHLIB: "SHT_SHLIB",
    SHT_DYNSYM: "SHT_DYNSYM",
    SHT_INIT_ARRAY: "SHT_INIT_ARRAY",
    SHT_FINI_ARRAY: "SHT_FINI_ARRAY",
    SHT_PREINIT_ARRAY: "SHT_PREINIT_ARRAY",
    SHT_GNU_HASH: "SHT_GNU_HASH",
    SHT_GNU_VERDEF: "SHT_GNU_VERDEF",
    SHT_GNU_VERNEED: "SHT_GNU_VERNEED",
    SHT_GNU_VERSYM: "SHT_GNU_VERSYM",
}

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_MERGE = 0x10
SHF_STRINGS = 0x20
SHF_INFO_LINK = 0x40
SHF_TLS = 0x400

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_BIND_NOW = 24
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_RUNPATH = 29
DT_FLAGS = 30
DT_GNU_HASH = 0x6FFFFEF5
DT_FLAGS_1 = 0x6FFFFFFB
DT_RELR = 36
DT_VERSYM = 0x6FFFFFF0
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF

DYNAMIC_TAG_NAMES: Dict[int, str] = {
    DT_NULL: "DT_NULL",
    DT_NEEDED: "DT_NEEDED",
    DT_PLTRELSZ: "DT_PLTRELSZ",
    DT_PLTGOT: "DT_PLTGOT",
    DT_HASH: "DT_HASH",
    DT_STRTAB: "DT_STRTAB",
    DT_SYMTAB: "DT_SYMTAB",
    DT_RELA: "DT_RELA",
    DT_RELASZ: "DT_RELASZ",
    DT_RELAENT: "DT_RELAENT",
    DT_STRSZ: "DT_STRSZ",
    DT_SYMENT: "DT_SYMENT",
    DT_INIT: "DT_INIT",
    DT_FINI: "DT_FINI",
    DT_SONAME: "DT_SONAME",
    DT_RPATH: "DT_RPATH",
    DT_SYMBOLIC: "DT_SYMBOLIC",
    DT_REL: "DT_REL",
    DT_RELSZ: "DT_RELSZ",
    DT_RELENT: "DT_RELENT",
    DT_PLTREL: "DT_PLTREL",
    DT_DEBUG: "DT_DEBUG",
    DT_TEXTREL: "DT_TEXTREL",
    DT_JMPREL: "DT_JMPREL",
    DT_BIND_NOW: "DT_BIND_NOW",
    DT_INIT_ARRAY: "DT_INIT_ARRAY",
    DT_FINI_ARRAY: "DT_FINI_ARRAY",
    DT_INIT_ARRAYSZ: "DT_INIT_ARRAYSZ",
    DT_FINI_ARRAYSZ: "DT_FINI_ARRAYSZ",
    DT_RUNPATH: "DT_RUNPATH",
    DT_FLAGS: "DT_FLAGS",
    DT_GNU_HASH: "DT_GNU_HASH",
    DT_FLAGS_1: "DT_FLAGS_1",
}

DF_ORIGIN = 0x1
DF_SYMBOLIC = 0x2
DF_TEXTREL = 0x4
DF_BIND_NOW = 0x8
DF_STATIC_TLS = 0x10

DF_1_NOW = 0x00000001
DF_1_NODELETE = 0x00000008
DF_1_NOOPEN = 0x00000040
DF_1_ORIGIN = 0x00000080
DF_1_NODEFLIB = 0x00000800
DF_1_PIE = 0x08000000

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6
STT_GNU_IFUNC = 10

STT_NAMES: Dict[int, str] = {
    STT_NOTYPE: "NOTYPE",
    STT_OBJECT: "OBJECT",
    STT_FUNC: "FUNC",
    STT_SECTION: "SECTION",
    STT_FILE: "FILE",
    STT_COMMON: "COMMON",
    STT_TLS: "TLS",
    STT_GNU_IFUNC: "IFUNC",
}

RELOC_NAMES_X86_64: Dict[int, str] = {
    0: "R_X86_64_NONE",
    1: "R_X86_64_64",
    2: "R_X86_64_PC32",
    5: "R_X86_64_COPY",
    6: "R_X86_64_GLOB_DAT",
    7: "R_X86_64_JUMP_SLOT",
    8: "R_X86_64_RELATIVE",
    37: "R_X86_64_IRELATIVE",
}

RELOC_NAMES_I386: Dict[int, str] = {
    0: "R_386_NONE",
    1: "R_386_32",
    2: "R_386_PC32",
    5: "R_386_COPY",
    6: "R_386_GLOB_DAT",
    7: "R_386_JMP_SLOT",
    8: "R_386_RELATIVE",
}

RELOC_NAMES_AARCH64: Dict[int, str] = {
    0: "R_AARCH64_NONE",
    257: "R_AARCH64_ABS64",
    1024: "R_AARCH64_COPY",
    1025: "R_AARCH64_GLOB_DAT",
    1026: "R_AARCH64_JUMP_SLOT",
    1027: "R_AARCH64_RELATIVE",
    1032: "R_AARCH64_IRELATIVE",
}

RELOC_NAMES_ARM: Dict[int, str] = {
    0: "R_ARM_NONE",
    2: "R_ARM_ABS32",
    20: "R_ARM_COPY",
    21: "R_ARM_GLOB_DAT",
    22: "R_ARM_JUMP_SLOT",
    23: "R_ARM_RELATIVE",
}


def _pf_to_prot_str(p_flags: int) -> Tuple[str, int, List[Dict[str, Any]]]:
    r = bool(p_flags & PF_R)
    w = bool(p_flags & PF_W)
    x = bool(p_flags & PF_X)
    prot_str = f"{'r' if r else '-'}{'w' if w else '-'}{'x' if x else '-'}"
    # Canonical VM_PROT bitmask: READ=1, WRITE=2, EXECUTE=4
    prot_raw = (1 if r else 0) | (2 if w else 0) | (4 if x else 0)
    bits = [
        {"name": "PF_X", "mask": "0x1", "set": x, "desc": "Execute permission"},
        {"name": "PF_W", "mask": "0x2", "set": w, "desc": "Write permission"},
        {"name": "PF_R", "mask": "0x4", "set": r, "desc": "Read permission"},
    ]
    return prot_str, prot_raw, bits


def _shf_to_attrs(sh_flags: int) -> Tuple[List[str], List[Dict[str, Any]]]:
    flag_defs = [
        (SHF_WRITE, "SHF_WRITE", "Writable during execution"),
        (SHF_ALLOC, "SHF_ALLOC", "Occupies memory during execution"),
        (SHF_EXECINSTR, "SHF_EXECINSTR", "Contains executable machine instructions"),
        (SHF_MERGE, "SHF_MERGE", "Might be merged to eliminate duplication"),
        (SHF_STRINGS, "SHF_STRINGS", "Contains null-terminated character strings"),
        (SHF_INFO_LINK, "SHF_INFO_LINK", "sh_info holds section header table index"),
        (SHF_TLS, "SHF_TLS", "Holds Thread-Local Storage (TLS)"),
    ]
    names = [name for mask, name, _ in flag_defs if sh_flags & mask]
    bits = [
        {"name": name, "mask": f"0x{mask:x}", "set": bool(sh_flags & mask), "desc": desc}
        for mask, name, desc in flag_defs
    ]
    return names, bits


class _StrTable:
    """
    Zero-copy view of a string table inside the file. Lookups are bounded to the
    table and to max_len bytes, so neither huge nor unterminated tables cost more
    than O(max_len) per string, and many sections sharing one table cost nothing.
    """

    __slots__ = ("data", "start", "end")

    def __init__(self, data: bytes, start: int, size: int) -> None:
        self.data = data
        self.start = max(0, start)
        self.end = max(self.start, min(len(data), start + max(0, size)))

    def __bool__(self) -> bool:
        return self.end > self.start

    def get(self, off: int, max_len: int = 512) -> str:
        if off < 0:
            return ""
        a = self.start + off
        if a >= self.end:
            return ""
        lim = min(self.end, a + max_len)
        nul = self.data.find(b"\x00", a, lim)
        return self.data[a : (nul if nul != -1 else lim)].decode("utf-8", errors="replace")


def _read_strtab(blob: Any, str_off: int, max_len: int = 512) -> str:
    """NUL-terminated string at str_off, bounded so an unterminated table costs O(max_len)."""
    if isinstance(blob, _StrTable):
        return blob.get(str_off, max_len)
    if str_off < 0 or str_off >= len(blob):
        return ""
    nul = blob.find(b"\x00", str_off, str_off + max_len)
    if nul == -1:
        return blob[str_off : str_off + max_len].decode("utf-8", errors="replace")
    return blob[str_off:nul].decode("utf-8", errors="replace")


def _demangle_elf_symbol(name: str) -> str:
    if not name:
        return name
    clean = name.split("@")[0]  # Strip @GLIBC_2.2.5 version suffix for demangling
    if clean.startswith("_Z") and len(clean) > 2:
        # Lightweight pure-Python Itanium C++ ABI demangler fallback
        rest = clean[2:]
        nested = []
        if rest.startswith("N"):
            rest = rest[1:]
            while rest and rest[0].isdigit():
                m = re.match(r"^(\d+)(.*)", rest)
                if not m:
                    break
                ln = int(m.group(1))
                part = m.group(2)[:ln]
                nested.append(part)
                rest = m.group(2)[ln:]
                if rest.startswith("E"):
                    rest = rest[1:]
                    break
        else:
            m = re.match(r"^(\d+)(.*)", rest)
            if m:
                ln = int(m.group(1))
                nested.append(m.group(2)[:ln])
                rest = m.group(2)[ln:]
        if nested:
            return "::".join(nested) + "()"
    return name


# ---------------------------------------------------------------------------
# .note.gnu.property (NT_GNU_PROPERTY_TYPE_0)
# ---------------------------------------------------------------------------
# Property types 0xc0000000..0xdfffffff are processor-specific: the same number
# means different things on different machines (0xc0000000 is the AArch64
# feature word; on x86 the feature word is 0xc0000002), so a property is only
# decoded against the table of the file's own e_machine.
EM_386 = 3
EM_X86_64 = 62
EM_AARCH64 = 183

_GNU_PROPERTY_GENERIC: Dict[int, Tuple[str, List[Tuple[int, str]]]] = {
    1: ("GNU_PROPERTY_STACK_SIZE", []),
    2: ("GNU_PROPERTY_NO_COPY_ON_PROTECTED", []),
    0xB0008000: ("GNU_PROPERTY_1_NEEDED", [(0x1, "INDIRECT_EXTERN_ACCESS")]),
}
_GNU_PROPERTY_X86: Dict[int, Tuple[str, List[Tuple[int, str]]]] = {
    0xC0000002: ("GNU_PROPERTY_X86_FEATURE_1_AND", [(0x1, "IBT"), (0x2, "SHSTK")]),
    0xC0008002: ("GNU_PROPERTY_X86_ISA_1_NEEDED", [(0x1, "x86-64-baseline"), (0x2, "x86-64-v2"), (0x4, "x86-64-v3"), (0x8, "x86-64-v4")]),
    0xC0010002: ("GNU_PROPERTY_X86_ISA_1_USED", [(0x1, "x86-64-baseline"), (0x2, "x86-64-v2"), (0x4, "x86-64-v3"), (0x8, "x86-64-v4")]),
    0xC0008001: ("GNU_PROPERTY_X86_FEATURE_2_NEEDED", []),
    0xC0010001: ("GNU_PROPERTY_X86_FEATURE_2_USED", []),
}
_GNU_PROPERTY_AARCH64: Dict[int, Tuple[str, List[Tuple[int, str]]]] = {
    0xC0000000: ("GNU_PROPERTY_AARCH64_FEATURE_1_AND", [(0x1, "BTI"), (0x2, "PAC"), (0x4, "GCS")]),
}
# Names shown in the hardening audit for the control-flow bits of the feature word.
_GNU_CFI_LABELS: Dict[Tuple[str, str], str] = {
    ("GNU_PROPERTY_X86_FEATURE_1_AND", "IBT"): "Intel CET IBT",
    ("GNU_PROPERTY_X86_FEATURE_1_AND", "SHSTK"): "Intel CET SHSTK",
    ("GNU_PROPERTY_AARCH64_FEATURE_1_AND", "BTI"): "ARM64 BTI",
    ("GNU_PROPERTY_AARCH64_FEATURE_1_AND", "PAC"): "ARM64 PAC",
    ("GNU_PROPERTY_AARCH64_FEATURE_1_AND", "GCS"): "ARM64 GCS",
}


def decode_gnu_property(e_machine: int, pr_type: int, data: bytes, endian_char: str = "<") -> Dict[str, Any]:
    """One property of an NT_GNU_PROPERTY_TYPE_0 note, decoded for `e_machine`.

    Returns {type, type_name, value, flags, cfi, known}. `cfi` lists the
    control-flow features the property declares (the labels used by the audit);
    a processor-specific type that this machine does not define is reported by
    number and decodes to nothing.
    """
    table = dict(_GNU_PROPERTY_GENERIC)
    if e_machine in (EM_386, EM_X86_64):
        table.update(_GNU_PROPERTY_X86)
    elif e_machine == EM_AARCH64:
        table.update(_GNU_PROPERTY_AARCH64)
    value: Optional[int] = None
    if len(data) >= 8 and pr_type == 1:
        value = struct.unpack_from(endian_char + "Q", data, 0)[0]
    elif len(data) >= 4:
        value = struct.unpack_from(endian_char + "I", data, 0)[0]
    entry = table.get(pr_type)
    if entry is None:
        scope = "processor-specific" if 0xC0000000 <= pr_type <= 0xDFFFFFFF else ("user" if pr_type >= 0xE0000000 else "generic")
        return {"type": pr_type, "type_name": f"0x{pr_type:08x} ({scope}, not defined for this machine)",
                "value": value, "flags": [], "cfi": [], "known": False}
    name, bits = entry
    flags = [label for mask, label in bits if value is not None and value & mask]
    cfi = [_GNU_CFI_LABELS[(name, f)] for f in flags if (name, f) in _GNU_CFI_LABELS]
    return {"type": pr_type, "type_name": name, "value": value, "flags": flags, "cfi": cfi, "known": True}


def evaluate_elf_security_posture(
    e_type: int,
    e_machine: int,
    phdrs: List[Dict[str, Any]],
    dyn_tags: Dict[int, List[int]],
    symbols: List[Dict[str, Any]],
    rpaths: List[Dict[str, Any]],
    gnu_properties: List[str],
    has_symtab: bool,
    build_id: str,
) -> Dict[str, Any]:
    """
    9-Point Linux / Embedded ELF Binary Security & Hardening Scorecard.
    """
    checks: List[Dict[str, Any]] = []

    # 1. PIE (Position Independent Executable)
    df_1 = dyn_tags.get(DT_FLAGS_1, [0])[0] if DT_FLAGS_1 in dyn_tags else 0
    df_0 = dyn_tags.get(DT_FLAGS, [0])[0] if DT_FLAGS in dyn_tags else 0
    has_interp = any(p["p_type"] == PT_INTERP for p in phdrs)
    is_pie = (e_type == ET_DYN)
    if e_type == ET_DYN:
        kind_label = "PIE Executable (ET_DYN with DF_1_PIE or PT_INTERP)" if (df_1 & DF_1_PIE or has_interp) else "Position-Independent Shared Object (ET_DYN)"
        checks.append({
            "id": "pie",
            "title": "Position Independent Executable (PIE / ASLR)",
            "status": "PASS",
            "value": f"Enabled ({kind_label})",
            "detail": "ELF header type is ET_DYN: every address in the file is relative to a load base chosen at run time (by the kernel for a PIE, by ld.so through mmap for a shared object), so ASLR can randomize it.",
        })
    elif e_type == ET_EXEC:
        checks.append({
            "id": "pie",
            "title": "Position Independent Executable (PIE / ASLR)",
            "status": "FAIL",
            "value": "Disabled (ET_EXEC Fixed Base)",
            "detail": "ELF header type is ET_EXEC; the image's own segments are mapped at the fixed addresses in its program headers. The stack, mmap regions and shared libraries are still randomized.",
        })
    else:
        checks.append({
            "id": "pie",
            "title": "Position Independent Executable (PIE / ASLR)",
            "status": "INFO",
            "value": f"{ELF_TYPE_INFO.get(e_type, ('ELF', ''))[0]}",
            "detail": "Not a loadable image (relocatable object, core dump or other type); load-address randomization does not apply.",
        })

    # 2. RELRO (Relocation Read-Only)
    has_relro_phdr = any(p["p_type"] == PT_GNU_RELRO for p in phdrs)
    has_bind_now = (
        (DT_BIND_NOW in dyn_tags)
        or bool(df_0 & DF_BIND_NOW)
        or bool(df_1 & DF_1_NOW)
    )
    if has_relro_phdr and has_bind_now:
        checks.append({
            "id": "relro",
            "title": "GOT Hardening (RELRO & BIND_NOW)",
            "status": "PASS",
            "value": "Full RELRO (PT_GNU_RELRO + BIND_NOW)",
            "detail": "A BIND_NOW flag makes ld.so resolve every GOT and PLT slot at startup; it then mprotect()s the PT_GNU_RELRO range, which the linker laid out to include .got.plt, read-only.",
        })
    elif has_relro_phdr:
        checks.append({
            "id": "relro",
            "title": "GOT Hardening (RELRO & BIND_NOW)",
            "status": "WARN",
            "value": "Partial RELRO (PT_GNU_RELRO only)",
            "detail": "ld.so makes the PT_GNU_RELRO range (.got, .dynamic, .init_array, ...) read-only after relocation, but without BIND_NOW the lazily bound PLT slots in .got.plt stay writable.",
        })
    else:
        checks.append({
            "id": "relro",
            "title": "GOT Hardening (RELRO & BIND_NOW)",
            "status": "FAIL" if e_type in (ET_EXEC, ET_DYN) else "INFO",
            "value": "No RELRO",
            "detail": "No PT_GNU_RELRO segment: the GOT and other relocated pointers stay writable for the life of the process, so a memory-write bug can redirect calls through them.",
        })

    # 3. Non-Executable Stack (PT_GNU_STACK)
    stack_phdrs = [p for p in phdrs if p["p_type"] == PT_GNU_STACK]
    if stack_phdrs:
        st_flags = stack_phdrs[0]["p_flags"]
        if st_flags & PF_X:
            checks.append({
                "id": "nx_stack",
                "title": "Non-Executable Stack (NX / PT_GNU_STACK)",
                "status": "FAIL",
                "value": "Executable Stack (RWE)",
                "detail": "PT_GNU_STACK has PF_X set, so Linux maps the stack executable; data written to the stack can be run as code.",
            })
        else:
            checks.append({
                "id": "nx_stack",
                "title": "Non-Executable Stack (NX / PT_GNU_STACK)",
                "status": "PASS",
                "value": "Requested (RW- Non-Executable)",
                "detail": "PT_GNU_STACK omits PF_X, so the kernel maps the stack without execute permission (enforced where the CPU has NX).",
            })
    else:
        checks.append({
            "id": "nx_stack",
            "title": "Non-Executable Stack (NX / PT_GNU_STACK)",
            "status": "WARN" if e_type in (ET_EXEC, ET_DYN) else "INFO",
            "value": "Missing PT_GNU_STACK Header",
            "detail": "No PT_GNU_STACK program header; the kernel applies its per-architecture default. Linux 5.8 and later: non-executable on x86-64 and arm64; on 32-bit x86 and 32-bit ARM the stack is executable and READ_IMPLIES_EXEC makes every readable mapping executable.",
        })

    # 4. Stack Canary
    sym_names = {s["name"].split("@")[0] for s in symbols}
    has_canary = bool(
        {"__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie"} & sym_names
    )
    if has_canary:
        checks.append({
            "id": "stack_canary",
            "title": "Stack Smashing Protection (Canary)",
            "status": "PASS",
            "value": "Present (__stack_chk_fail)",
            "detail": "The stack-protector failure handler or guard is referenced, so at least one function checks a canary before returning. Which functions are covered depends on the -fstack-protector level used.",
        })
    else:
        checks.append({
            "id": "stack_canary",
            "title": "Stack Smashing Protection (Canary)",
            "status": "INFO",
            "value": "Not Detected",
            "detail": "No __stack_chk_fail symbol found: built without -fstack-protector, no function met the instrumentation criteria, or the name is gone (statically linked and stripped).",
        })

    # 5. Hardware Control-Flow Integrity (Intel CET IBT/SHSTK or ARM64 PAC/BTI)
    cfi_enabled = len(gnu_properties) > 0
    if cfi_enabled:
        checks.append({
            "id": "cfi_cet_pac",
            "title": "Hardware Control-Flow Integrity (CET / PAC / BTI)",
            "status": "PASS",
            "value": " | ".join(gnu_properties),
            "detail": "The .note.gnu.property note marks the image as compatible with these features (IBT/BTI: indirect-branch landing pads; SHSTK/GCS: shadow stack; PAC: signed return addresses). The note is decoded for this file's machine: x86 and AArch64 use different property numbers. Enforcement still depends on CPU, kernel and libc support.",
        })
    else:
        checks.append({
            "id": "cfi_cet_pac",
            "title": "Hardware Control-Flow Integrity (CET / PAC / BTI)",
            "status": "INFO",
            "value": "Baseline ABI (No CET/BTI Note)",
            "detail": "No .note.gnu.property x86 CET (IBT/SHSTK) or AArch64 (BTI/PAC) feature bits found.",
        })

    # 6. W^X Memory Protection Hygiene
    rwx_segs = [
        f"PT_LOAD#{p['index']} (vaddr 0x{p['p_vaddr']:x})"
        for p in phdrs
        if p["p_type"] == PT_LOAD and (p["p_flags"] & (PF_W | PF_X)) == (PF_W | PF_X)
    ]
    has_textrel = (DT_TEXTREL in dyn_tags) or bool(df_0 & DF_TEXTREL)
    if has_textrel:
        rwx_segs.append("DT_TEXTREL (Text Relocations)")
    has_rwx = len(rwx_segs) > 0
    if has_rwx:
        checks.append({
            "id": "rwx",
            "title": "W^X Memory Protection Hygiene",
            "status": "FAIL",
            "value": f"RWX / TEXTREL: {', '.join(rwx_segs)}",
            "detail": "A PT_LOAD segment is both writable and executable, or the image has text relocations (DT_TEXTREL / DF_TEXTREL), which make ld.so write to code pages while relocating.",
        })
    else:
        checks.append({
            "id": "rwx",
            "title": "W^X Memory Protection Hygiene",
            "status": "PASS",
            "value": "No W+X segment requested",
            "detail": "No PT_LOAD segment has simultaneous PF_W and PF_X flags, and no DT_TEXTREL is present.",
        })

    # 7. FORTIFY_SOURCE (_chk functions)
    fortified_syms = sorted(s for s in sym_names if s.startswith("__") and s.endswith("_chk"))
    if fortified_syms:
        checks.append({
            "id": "fortify",
            "title": "Libc Buffer Fortification (_FORTIFY_SOURCE)",
            "status": "PASS",
            "value": f"Enabled ({len(fortified_syms)} *_chk symbols)",
            "detail": f"References length-checked libc variants emitted by _FORTIFY_SOURCE: {', '.join(fortified_syms[:4])}. Only calls where the compiler knew the destination size are checked.",
        })
    else:
        checks.append({
            "id": "fortify",
            "title": "Libc Buffer Fortification (_FORTIFY_SOURCE)",
            "status": "INFO",
            "value": "No *_chk Symbols Detected",
            "detail": "No __*_chk functions referenced: built without _FORTIFY_SOURCE or without optimization, or every checked call was resolved at compile time.",
        })

    # 8. RPATH / RUNPATH Hygiene
    if not rpaths:
        checks.append({
            "id": "rpath",
            "title": "Dynamic Search Path (RPATH / RUNPATH) Hygiene",
            "status": "PASS",
            "value": "No DT_RPATH / DT_RUNPATH",
            "detail": "The image adds no search directories of its own. ld.so still consults LD_LIBRARY_PATH (ignored for setuid/setgid programs), the ld.so cache and the default library directories.",
        })
    else:
        rp_list = [r["path"] for r in rpaths]
        has_deprecated_rpath = any(r.get("cmd") == "DT_RPATH" for r in rpaths)
        risky = [p for p in rp_list if p in (".", "..", "") or p.startswith("./") or p.startswith("/tmp")]
        checks.append({
            "id": "rpath",
            "title": "Dynamic Search Path (RPATH / RUNPATH) Hygiene",
            "status": "FAIL" if risky else ("WARN" if has_deprecated_rpath else "INFO"),
            "value": f"{len(rp_list)} Path(s): {', '.join(rp_list[:2])}",
            "detail": (
                f"Insecure relative/writable search path detected: {', '.join(risky)}"
                if risky
                else f"Configured dynamic search paths: {', '.join(rp_list)}"
            ),
        })

    # 9. Build-ID & Symbol Stripping State
    checks.append({
        "id": "build_id_symbols",
        "title": "Build-ID Provenance & Symbol Stripping",
        "status": "PASS" if build_id else "INFO",
        "value": f"{'Build-ID Present' if build_id else 'No Build-ID'} • {'Unstripped (.symtab)' if has_symtab else 'Stripped (.dynsym only)'}",
        "detail": (
            f"GNU Build-ID {build_id[:24]}... recorded in .note.gnu.build-id."
            if build_id
            else "No .note.gnu.build-id note found. The build ID is an identifier chosen by the linker (by default a hash of the output), not a signature."
        ),
    })

    relro_mode = "Full" if (has_relro_phdr and has_bind_now) else ("Partial" if has_relro_phdr else "None")
    nx_stack_enabled = bool(stack_phdrs and not (stack_phdrs[0]["p_flags"] & PF_X))

    return {
        "pie": is_pie,
        "relro": relro_mode,
        "nx_stack": nx_stack_enabled,
        "arc": bool(fortified_syms),
        "stack_canary": has_canary,
        "pac_enabled": cfi_enabled,
        "has_rwx_segments": has_rwx,
        "has_restrict_segment": has_relro_phdr and has_bind_now,
        "is_encrypted": False,
        "stripped_symbols": not has_symtab,
        # ELF has no embedded signature format; the build ID is in overview.uuid / elf_metadata.
        "code_signature": {
            "present": False,
            "is_adhoc": False,
            "hardened_runtime": False,
            "library_validation": False,
            "cdhash": "",
            "cdhash_verified": False,
            "identifier": "",
            "team_id": "",
            "certificates": [],
        },
        "checks": checks,
    }


def parse_elf_slice(full_data: bytes, path: str = "<memory>") -> Dict[str, Any]:
    if len(full_data) < 52 or full_data[:4] != ELF_MAGIC:
        raise BinaryFormatError("Invalid ELF header (expected 0x7f 'E' 'L' 'F' and at least 52 bytes).")

    ei_class = full_data[4]
    ei_data = full_data[5]
    ei_version = full_data[6]
    ei_osabi = full_data[7]
    ei_abiversion = full_data[8]

    is_64 = (ei_class == ELFCLASS64)
    little_endian = (ei_data != ELFDATA2MSB)
    file_size = len(full_data)

    buf = BinaryBuffer(full_data, slice_base=0, slice_size=file_size, little_endian=little_endian)

    e_type = buf.u16(16)
    e_machine = buf.u16(18)
    e_version = buf.u32(20)
    if is_64:
        e_entry = buf.u64(24)
        e_phoff = buf.u64(32)
        e_shoff = buf.u64(40)
        e_flags = buf.u32(48)
        e_ehsize = buf.u16(52)
        e_phentsize = buf.u16(54)
        e_phnum = buf.u16(56)
        e_shentsize = buf.u16(58)
        e_shnum = buf.u16(60)
        e_shstrndx = buf.u16(62)
        hdr_size = 64
    else:
        e_entry = buf.u32(24)
        e_phoff = buf.u32(28)
        e_shoff = buf.u32(32)
        e_flags = buf.u32(36)
        e_ehsize = buf.u16(40)
        e_phentsize = buf.u16(42)
        e_phnum = buf.u16(44)
        e_shentsize = buf.u16(46)
        e_shnum = buf.u16(48)
        e_shstrndx = buf.u16(50)
        hdr_size = 52

    arch_short, machine_macro, arch_display = ELF_MACHINE_INFO.get(
        e_machine, (f"elf_mach_{e_machine}", f"EM_{e_machine}", f"ELF Machine {e_machine}")
    )
    if e_machine == 243 and not is_64:
        arch_short = "riscv32"

    ft_name, ft_desc = ELF_TYPE_INFO.get(e_type, (f"ET_0x{e_type:x}", "ELF Binary"))
    osabi_name = ELF_OSABI_NAMES.get(ei_osabi, f"OSABI_{ei_osabi}")
    magic_str = "ELF64" if is_64 else "ELF32"

    # Record Ehdr StructFields
    buf.record_field("e_ident[EI_MAG]", "char[4]", 0, 4, 0x7F454C46, "7f 45 4c 46", "\\x7fELF", "ELF Magic Number")
    buf.record_field("e_ident[EI_CLASS]", "uint8", 4, 1, ei_class, f"0x{ei_class:02x}", "ELFCLASS64 (64-bit)" if is_64 else "ELFCLASS32 (32-bit)", "Architecture Word Size Class")
    buf.record_field("e_ident[EI_DATA]", "uint8", 5, 1, ei_data, f"0x{ei_data:02x}", "ELFDATA2LSB (Little-Endian)" if little_endian else "ELFDATA2MSB (Big-Endian)", "Data Encoding Endianness")
    buf.record_field("e_ident[EI_VERSION]", "uint8", 6, 1, ei_version, str(ei_version), "EV_CURRENT (1)", "ELF Header Version")
    buf.record_field("e_ident[EI_OSABI]", "uint8", 7, 1, ei_osabi, f"0x{ei_osabi:02x}", osabi_name, "Operating System / ABI Identification")
    buf.record_field("e_ident[EI_ABIVERSION]", "uint8", 8, 1, ei_abiversion, str(ei_abiversion), f"ABI v{ei_abiversion}", "ABI Version")
    buf.record_field("e_type", "uint16", 16, 2, e_type, f"0x{e_type:04x}", f"{ft_name} ({ft_desc})", "Object file type")
    buf.record_field("e_machine", "uint16", 18, 2, e_machine, f"0x{e_machine:04x}", f"{machine_macro} ({arch_display})", "Target instruction set architecture")
    buf.record_field("e_version", "uint32", 20, 4, e_version, f"0x{e_version:x}", "EV_CURRENT", "Object file version")

    if is_64:
        buf.record_field("e_entry", "Elf64_Addr", 24, 8, e_entry, f"0x{e_entry:x}", f"Entry VMAddr 0x{e_entry:x}", "Virtual address to which system transfers control", target_vmaddr=f"0x{e_entry:x}" if e_entry else None)
        buf.record_field("e_phoff", "Elf64_Off", 32, 8, e_phoff, f"0x{e_phoff:x}", f"File offset 0x{e_phoff:x}", "Program header table file offset", target_offset=e_phoff if e_phoff else None)
        buf.record_field("e_shoff", "Elf64_Off", 40, 8, e_shoff, f"0x{e_shoff:x}", f"File offset 0x{e_shoff:x}", "Section header table file offset", target_offset=e_shoff if e_shoff else None)
        buf.record_field("e_flags", "uint32", 48, 4, e_flags, f"0x{e_flags:08x}", f"0x{e_flags:x}", "Processor-specific flags")
        buf.record_field("e_ehsize", "uint16", 52, 2, e_ehsize, str(e_ehsize), f"{e_ehsize} bytes", "ELF header size")
        buf.record_field("e_phentsize", "uint16", 54, 2, e_phentsize, str(e_phentsize), f"{e_phentsize} bytes", "Program header entry size")
        buf.record_field("e_phnum", "uint16", 56, 2, e_phnum, str(e_phnum), f"{e_phnum} program headers", "Number of program header entries")
        buf.record_field("e_shentsize", "uint16", 58, 2, e_shentsize, str(e_shentsize), f"{e_shentsize} bytes", "Section header entry size")
        buf.record_field("e_shnum", "uint16", 60, 2, e_shnum, str(e_shnum), f"{e_shnum} sections", "Number of section header entries")
        buf.record_field("e_shstrndx", "uint16", 62, 2, e_shstrndx, str(e_shstrndx), f"Section #{e_shstrndx}", "Section header string table index")
    else:
        buf.record_field("e_entry", "Elf32_Addr", 24, 4, e_entry, f"0x{e_entry:x}", f"Entry VMAddr 0x{e_entry:x}", "Virtual address to which system transfers control", target_vmaddr=f"0x{e_entry:x}" if e_entry else None)
        buf.record_field("e_phoff", "Elf32_Off", 28, 4, e_phoff, f"0x{e_phoff:x}", f"File offset 0x{e_phoff:x}", "Program header table file offset", target_offset=e_phoff if e_phoff else None)
        buf.record_field("e_shoff", "Elf32_Off", 32, 4, e_shoff, f"0x{e_shoff:x}", f"File offset 0x{e_shoff:x}", "Section header table file offset", target_offset=e_shoff if e_shoff else None)
        buf.record_field("e_flags", "uint32", 36, 4, e_flags, f"0x{e_flags:08x}", f"0x{e_flags:x}", "Processor-specific flags")
        buf.record_field("e_ehsize", "uint16", 40, 2, e_ehsize, str(e_ehsize), f"{e_ehsize} bytes", "ELF header size")
        buf.record_field("e_phentsize", "uint16", 42, 2, e_phentsize, str(e_phentsize), f"{e_phentsize} bytes", "Program header entry size")
        buf.record_field("e_phnum", "uint16", 44, 2, e_phnum, str(e_phnum), f"{e_phnum} program headers", "Number of program header entries")
        buf.record_field("e_shentsize", "uint16", 46, 2, e_shentsize, str(e_shentsize), f"{e_shentsize} bytes", "Section header entry size")
        buf.record_field("e_shnum", "uint16", 48, 2, e_shnum, str(e_shnum), f"{e_shnum} sections", "Number of section header entries")
        buf.record_field("e_shstrndx", "uint16", 50, 2, e_shstrndx, str(e_shstrndx), f"Section #{e_shstrndx}", "Section header string table index")

    header_fields = buf.reset_fields()
    warnings: List[Dict[str, Any]] = []
    intervals: List[Dict[str, Any]] = [
        {
            "id": "mach_header",
            "label": f"{magic_str}_Ehdr",
            "category": "header",
            "abs_offset": 0,
            "size": hdr_size,
            "vmaddr": None,
        }
    ]

    # ------------------------------------------------------------------------
    # 1. Parse Section Header Table (Shdr)
    # ------------------------------------------------------------------------
    raw_shdrs: List[Dict[str, Any]] = []
    shstrtab_bytes: Any = b""
    sh_ent_sz = e_shentsize or (64 if is_64 else 40)
    sh_limit = ANALYSIS_LIMITS["elf_section_headers"]
    max_sh = min(e_shnum, sh_limit) if (e_shoff > 0 and e_shoff < file_size) else 0
    if e_shnum > sh_limit and max_sh:
        add_warning(warnings, "section_headers_truncated", f"e_shnum is {e_shnum:,}; only the first {sh_limit:,} section headers are parsed.", limit=sh_limit, total=e_shnum)
    if e_shnum and e_shoff >= file_size:
        add_warning(warnings, "section_headers_past_eof", "e_shoff points past the end of the file; section headers are not shown.")

    if max_sh > 0 and 0 <= e_shstrndx < max_sh:
        str_hdr_off = e_shoff + e_shstrndx * sh_ent_sz
        if str_hdr_off + sh_ent_sz <= file_size:
            shstr_off = buf.u64(str_hdr_off + 24) if is_64 else buf.u32(str_hdr_off + 16)
            shstr_sz = buf.u64(str_hdr_off + 32) if is_64 else buf.u32(str_hdr_off + 20)
            if shstr_off < file_size:
                shstrtab_bytes = _StrTable(full_data, shstr_off, min(shstr_sz, file_size - shstr_off))

    for i in range(max_sh):
        runtime.check_deadline()
        sh_off = e_shoff + i * sh_ent_sz
        if sh_off + sh_ent_sz > file_size:
            add_warning(warnings, "section_headers_truncated_eof", f"Section header table is cut off by the end of the file after {i} entries.")
            break
        sh_buf = buf.clone_with_fields()
        sh_name_idx = sh_buf.u32(sh_off)
        sh_type = sh_buf.u32(sh_off + 4)
        sname = _read_strtab(shstrtab_bytes, sh_name_idx) or (f"sect_{i}" if i > 0 else "NULL")
        stype_name = SHDR_TYPE_NAMES.get(sh_type, f"SHT_0x{sh_type:x}")

        if is_64:
            sh_flags = sh_buf.u64(sh_off + 8)
            sh_addr = sh_buf.u64(sh_off + 16)
            sh_offset = sh_buf.u64(sh_off + 24)
            sh_size = sh_buf.u64(sh_off + 32)
            sh_link = sh_buf.u32(sh_off + 40)
            sh_info = sh_buf.u32(sh_off + 44)
            sh_addralign = sh_buf.u64(sh_off + 48)
            sh_entsize = sh_buf.u64(sh_off + 56)
            flag_names, flag_bits = _shf_to_attrs(sh_flags)

            sh_buf.record_field("sh_name", "uint32", sh_off, 4, sh_name_idx, f"0x{sh_name_idx:x}", sname, "Section name string table index")
            sh_buf.record_field("sh_type", "uint32", sh_off + 4, 4, sh_type, f"0x{sh_type:x}", stype_name, "Section header type")
            sh_buf.record_field("sh_flags", "uint64", sh_off + 8, 8, sh_flags, f"0x{sh_flags:x}", " | ".join(flag_names) or "0x0", "Section attribute flags", bit_flags=flag_bits)
            sh_buf.record_field("sh_addr", "Elf64_Addr", sh_off + 16, 8, sh_addr, f"0x{sh_addr:x}", f"0x{sh_addr:x}", "Virtual memory address", target_vmaddr=f"0x{sh_addr:x}" if sh_addr else None)
            sh_buf.record_field("sh_offset", "Elf64_Off", sh_off + 24, 8, sh_offset, f"0x{sh_offset:x}", f"File offset 0x{sh_offset:x}", "File offset of section content", target_offset=sh_offset if sh_type != SHT_NOBITS and sh_offset > 0 else None)
            sh_buf.record_field("sh_size", "uint64", sh_off + 32, 8, sh_size, f"0x{sh_size:x}", f"{sh_size:,} bytes", "Section size in bytes")
            sh_buf.record_field("sh_link", "uint32", sh_off + 40, 4, sh_link, str(sh_link), f"Section #{sh_link}")
            sh_buf.record_field("sh_info", "uint32", sh_off + 44, 4, sh_info, str(sh_info))
            sh_buf.record_field("sh_addralign", "uint64", sh_off + 48, 8, sh_addralign, str(sh_addralign))
            sh_buf.record_field("sh_entsize", "uint64", sh_off + 56, 8, sh_entsize, str(sh_entsize))
        else:
            sh_flags = sh_buf.u32(sh_off + 8)
            sh_addr = sh_buf.u32(sh_off + 12)
            sh_offset = sh_buf.u32(sh_off + 16)
            sh_size = sh_buf.u32(sh_off + 20)
            sh_link = sh_buf.u32(sh_off + 24)
            sh_info = sh_buf.u32(sh_off + 28)
            sh_addralign = sh_buf.u32(sh_off + 32)
            sh_entsize = sh_buf.u32(sh_off + 36)
            flag_names, flag_bits = _shf_to_attrs(sh_flags)

            sh_buf.record_field("sh_name", "uint32", sh_off, 4, sh_name_idx, f"0x{sh_name_idx:x}", sname)
            sh_buf.record_field("sh_type", "uint32", sh_off + 4, 4, sh_type, f"0x{sh_type:x}", stype_name)
            sh_buf.record_field("sh_flags", "uint32", sh_off + 8, 4, sh_flags, f"0x{sh_flags:x}", " | ".join(flag_names) or "0x0", bit_flags=flag_bits)
            sh_buf.record_field("sh_addr", "Elf32_Addr", sh_off + 12, 4, sh_addr, f"0x{sh_addr:x}", target_vmaddr=f"0x{sh_addr:x}" if sh_addr else None)
            sh_buf.record_field("sh_offset", "Elf32_Off", sh_off + 16, 4, sh_offset, f"0x{sh_offset:x}", target_offset=sh_offset if sh_type != SHT_NOBITS and sh_offset > 0 else None)
            sh_buf.record_field("sh_size", "uint32", sh_off + 20, 4, sh_size, f"0x{sh_size:x}", f"{sh_size:,} bytes")
            sh_buf.record_field("sh_link", "uint32", sh_off + 24, 4, sh_link, str(sh_link))
            sh_buf.record_field("sh_info", "uint32", sh_off + 28, 4, sh_info, str(sh_info))
            sh_buf.record_field("sh_addralign", "uint32", sh_off + 32, 4, sh_addralign, str(sh_addralign))
            sh_buf.record_field("sh_entsize", "uint32", sh_off + 36, 4, sh_entsize, str(sh_entsize))

        is_nobits = (sh_type == SHT_NOBITS)
        is_exec = bool(sh_flags & SHF_EXECINSTR)
        prot_str = f"{'r' if (sh_flags & SHF_ALLOC) else '-'}{'w' if (sh_flags & SHF_WRITE) else '-'}{'x' if is_exec else '-'}"

        raw_shdrs.append({
            "sh_index": i,
            "sectname": sname,
            "sh_type": sh_type,
            "section_type": stype_name,
            "sh_flags": sh_flags,
            "attributes_decoded": flag_names,
            "vmaddr": f"0x{sh_addr:x}",
            "vmaddr_int": sh_addr,
            "size": sh_size,
            "slice_offset": sh_offset,
            "abs_offset": sh_offset,
            "align": sh_addralign,
            "sh_link": sh_link,
            "sh_info": sh_info,
            "sh_entsize": sh_entsize,
            "is_executable": is_exec,
            "is_zerofill": is_nobits,
            "prot": prot_str,
            "header_region": make_region(sh_off, sh_off, sh_ent_sz),
            "fields": sh_buf.get_fields(),
        })

    # ------------------------------------------------------------------------
    # 2. Parse Program Header Table (Phdr) -> load_commands & segments
    # ------------------------------------------------------------------------
    load_commands: List[Dict[str, Any]] = []
    phdrs: List[Dict[str, Any]] = []
    segments: List[Dict[str, Any]] = []
    ph_ent_sz = e_phentsize or (56 if is_64 else 32)
    ph_limit = ANALYSIS_LIMITS["elf_program_headers"]
    max_ph = min(e_phnum, ph_limit) if (e_phoff > 0 and e_phoff < file_size) else 0
    if e_phnum > ph_limit and max_ph:
        add_warning(warnings, "program_headers_truncated", f"e_phnum is {e_phnum:,}; only the first {ph_limit:,} program headers are parsed.", limit=ph_limit, total=e_phnum)
    interp_path = ""

    for i in range(max_ph):
        runtime.check_deadline()
        ph_off = e_phoff + i * ph_ent_sz
        if ph_off + ph_ent_sz > file_size:
            add_warning(warnings, "program_headers_truncated_eof", f"Program header table is cut off by the end of the file after {i} entries.")
            break
        ph_buf = buf.clone_with_fields()
        p_type = ph_buf.u32(ph_off)
        p_type_name = PHDR_TYPE_NAMES.get(p_type, f"PT_0x{p_type:x}")

        if is_64:
            p_flags = ph_buf.u32(ph_off + 4)
            p_offset = ph_buf.u64(ph_off + 8)
            p_vaddr = ph_buf.u64(ph_off + 16)
            p_paddr = ph_buf.u64(ph_off + 24)
            p_filesz = ph_buf.u64(ph_off + 32)
            p_memsz = ph_buf.u64(ph_off + 40)
            p_align = ph_buf.u64(ph_off + 48)
            prot_str, prot_raw, prot_bits = _pf_to_prot_str(p_flags)

            ph_buf.record_field("p_type", "uint32", ph_off, 4, p_type, f"0x{p_type:x}", p_type_name, "Program header segment type")
            ph_buf.record_field("p_flags", "uint32", ph_off + 4, 4, p_flags, f"0x{p_flags:x}", prot_str.upper(), "Segment memory permissions", bit_flags=prot_bits)
            ph_buf.record_field("p_offset", "Elf64_Off", ph_off + 8, 8, p_offset, f"0x{p_offset:x}", f"File offset 0x{p_offset:x}", "Segment file offset", target_offset=p_offset if p_filesz > 0 else None)
            ph_buf.record_field("p_vaddr", "Elf64_Addr", ph_off + 16, 8, p_vaddr, f"0x{p_vaddr:x}", f"0x{p_vaddr:x}", "Virtual address in memory", target_vmaddr=f"0x{p_vaddr:x}" if p_vaddr else None)
            ph_buf.record_field("p_paddr", "Elf64_Addr", ph_off + 24, 8, p_paddr, f"0x{p_paddr:x}", f"0x{p_paddr:x}", "Physical address")
            ph_buf.record_field("p_filesz", "uint64", ph_off + 32, 8, p_filesz, f"0x{p_filesz:x}", f"{p_filesz:,} bytes", "Bytes mapped from file")
            ph_buf.record_field("p_memsz", "uint64", ph_off + 40, 8, p_memsz, f"0x{p_memsz:x}", f"{p_memsz:,} bytes", "Bytes mapped in virtual memory")
            ph_buf.record_field("p_align", "uint64", ph_off + 48, 8, p_align, f"0x{p_align:x}", f"{p_align} byte alignment")
        else:
            p_offset = ph_buf.u32(ph_off + 4)
            p_vaddr = ph_buf.u32(ph_off + 8)
            p_paddr = ph_buf.u32(ph_off + 12)
            p_filesz = ph_buf.u32(ph_off + 16)
            p_memsz = ph_buf.u32(ph_off + 20)
            p_flags = ph_buf.u32(ph_off + 24)
            p_align = ph_buf.u32(ph_off + 28)
            prot_str, prot_raw, prot_bits = _pf_to_prot_str(p_flags)

            ph_buf.record_field("p_type", "uint32", ph_off, 4, p_type, f"0x{p_type:x}", p_type_name, "Program header segment type")
            ph_buf.record_field("p_offset", "Elf32_Off", ph_off + 4, 4, p_offset, f"0x{p_offset:x}", f"File offset 0x{p_offset:x}", target_offset=p_offset if p_filesz > 0 else None)
            ph_buf.record_field("p_vaddr", "Elf32_Addr", ph_off + 8, 4, p_vaddr, f"0x{p_vaddr:x}", f"0x{p_vaddr:x}", target_vmaddr=f"0x{p_vaddr:x}" if p_vaddr else None)
            ph_buf.record_field("p_paddr", "Elf32_Addr", ph_off + 12, 4, p_paddr, f"0x{p_paddr:x}")
            ph_buf.record_field("p_filesz", "uint32", ph_off + 16, 4, p_filesz, f"0x{p_filesz:x}", f"{p_filesz:,} bytes")
            ph_buf.record_field("p_memsz", "uint32", ph_off + 20, 4, p_memsz, f"0x{p_memsz:x}", f"{p_memsz:,} bytes")
            ph_buf.record_field("p_flags", "uint32", ph_off + 24, 4, p_flags, f"0x{p_flags:x}", prot_str.upper(), bit_flags=prot_bits)
            ph_buf.record_field("p_align", "uint32", ph_off + 28, 4, p_align, f"0x{p_align:x}")

        summary = f"{p_type_name} VM 0x{p_vaddr:x} ({prot_str}) File 0x{p_offset:x}+0x{p_filesz:x}"
        if p_type == PT_INTERP and p_offset < file_size and p_filesz > 0:
            interp_str, _ = buf.cstr_at(p_offset, min(p_filesz, 256))
            interp_path = interp_str
            summary = f"{interp_str}"
            ph_buf.record_field("interpreter", "char[]", p_offset, len(interp_str) + 1, interp_str, interp_str, interp_str, "Dynamic loader path")

        ph_entry = {
            "index": i,
            "p_type": p_type,
            "p_type_name": p_type_name,
            "p_flags": p_flags,
            "prot": prot_str,
            "prot_raw": prot_raw,
            "p_offset": p_offset,
            "p_vaddr": p_vaddr,
            "p_paddr": p_paddr,
            "p_filesz": p_filesz,
            "p_memsz": p_memsz,
            "p_align": p_align,
            "fields": ph_buf.get_fields(),
            "region": make_region(ph_off, ph_off, ph_ent_sz, f"0x{p_vaddr:x}" if p_vaddr else None, p_memsz),
        }
        phdrs.append(ph_entry)

        load_commands.append({
            "index": i,
            "cmd": p_type,
            "cmd_hex": f"0x{p_type:x}",
            "cmd_name": p_type_name,
            "cmdsize": ph_ent_sz,
            "req_dyld": p_type in (PT_INTERP, PT_DYNAMIC),
            "summary": summary,
            "region": make_region(ph_off, ph_off, ph_ent_sz, f"0x{p_vaddr:x}" if p_vaddr else None, p_memsz),
            "fields": ph_entry["fields"],
            "details": {"vaddr": f"0x{p_vaddr:x}", "offset": p_offset, "filesz": p_filesz, "memsz": p_memsz, "flags": prot_str},
        })

    # Build PT_LOAD segments & map Shdr sections into them
    all_sections_ordered: List[Dict[str, Any]] = []
    pt_loads = [p for p in phdrs if p["p_type"] == PT_LOAD]
    if len(pt_loads) > ANALYSIS_LIMITS["segments"]:
        add_warning(warnings, "segments_truncated", f"Only the first {ANALYSIS_LIMITS['segments']} PT_LOAD segments are mapped.", limit=ANALYSIS_LIMITS["segments"], total=len(pt_loads))
        pt_loads = pt_loads[: ANALYSIS_LIMITS["segments"]]
    assigned_sh_indices = set()
    # Sections that can live in a PT_LOAD, with their match keys precomputed;
    # assigned ones are dropped so later segments scan fewer candidates.
    mappable = [
        (sh, sh["slice_offset"], sh["vmaddr_int"], sh["is_zerofill"])
        for sh in raw_shdrs
        if sh["sh_index"] != 0 and ((sh["sh_flags"] & SHF_ALLOC) or sh["sh_type"] in (SHT_NOTE, SHT_DYNAMIC))
    ]

    for load_idx, pl in enumerate(pt_loads):
        runtime.check_deadline()
        p_off = pl["p_offset"]
        p_fsz = pl["p_filesz"]
        p_vm = pl["p_vaddr"]
        p_msz = pl["p_memsz"]
        prot_str = pl["prot"]
        prot_raw = pl["prot_raw"]

        if pl["p_flags"] & PF_X:
            segname = f"LOAD_{load_idx}_TEXT" if len(pt_loads) > 1 else "LOAD_TEXT"
        elif pl["p_flags"] & PF_W:
            segname = f"LOAD_{load_idx}_DATA"
        else:
            segname = f"LOAD_{load_idx}_RO"

        seg_sections: List[Dict[str, Any]] = []
        file_end = p_off + max(1, p_fsz)
        vm_end = p_vm + p_msz
        still_unassigned = []
        for entry in mappable:
            sh, sh_off, sh_vm, sh_zf = entry
            in_file_range = (not sh_zf) and (p_off <= sh_off < file_end)
            in_vm_range = (p_msz > 0) and (p_vm <= sh_vm < vm_end)
            if not (in_file_range or in_vm_range):
                still_unassigned.append(entry)
            else:
                assigned_sh_indices.add(sh["sh_index"])
                sec_copy = dict(sh)
                sec_copy["index"] = len(all_sections_ordered)
                sec_copy["segname"] = segname
                sec_copy["align_bytes"] = max(1, sh["align"])
                sec_copy["reloff"] = 0
                sec_copy["nreloc"] = 0
                sec_copy["flags"] = sh["sh_flags"]
                sec_copy["flags_hex"] = f"0x{sh['sh_flags']:x}"
                sec_copy["reserved1"] = sh["sh_link"]
                sec_copy["reserved2"] = sh["sh_info"]
                sec_copy["region"] = make_region(
                    sh["abs_offset"],
                    sh["slice_offset"],
                    0 if sh["is_zerofill"] else sh["size"],
                    sh["vmaddr"],
                    sh["size"],
                )
                seg_sections.append(sec_copy)
                all_sections_ordered.append(sec_copy)

                if not sh["is_zerofill"] and sh["size"] > 0:
                    intervals.append({
                        "id": f"sect_{segname}_{sh['sectname']}",
                        "label": f"Section {sh['sectname']}",
                        "category": "code" if sh["is_executable"] else "section",
                        "abs_offset": sh["abs_offset"],
                        "size": sh["size"],
                        "vmaddr": sh["vmaddr"],
                    })
        mappable = still_unassigned

        flag_list = [name for mask, name in ((PF_R, "PF_R"), (PF_W, "PF_W"), (PF_X, "PF_X")) if pl["p_flags"] & mask]
        seg_obj = {
            "index": len(segments),
            "segname": segname,
            "vmaddr": f"0x{p_vm:x}",
            "vmaddr_int": p_vm,
            "vmsize": f"0x{p_msz:x}",
            "vmsize_int": p_msz,
            "fileoff": p_off,
            "filesize": p_fsz,
            "abs_offset": p_off,
            "initprot": prot_str,
            "maxprot": prot_str,
            "initprot_raw": prot_raw,
            "maxprot_raw": prot_raw,
            "nsects": len(seg_sections),
            "flags": pl["p_flags"],
            "flags_decoded": flag_list,
            "region": make_region(p_off, p_off, p_fsz, f"0x{p_vm:x}", p_msz),
            "header_region": pl["region"],
            "fields": pl["fields"],
            "sections": seg_sections,
        }
        segments.append(seg_obj)

    # Handle ET_REL (.o files) or binaries with unmapped ALLOC sections
    unassigned_alloc = [
        sh for sh in raw_shdrs if sh["sh_index"] > 0 and sh["sh_index"] not in assigned_sh_indices and sh["size"] > 0
    ]
    if not segments and unassigned_alloc:
        synth_vm = 0x10000
        seg_sections = []
        min_off = min((s["slice_offset"] for s in unassigned_alloc if s["slice_offset"] > 0), default=0)
        max_end = max(s["slice_offset"] + s["size"] for s in unassigned_alloc) if unassigned_alloc else file_size
        for sh in unassigned_alloc:
            sec_copy = dict(sh)
            sec_copy["index"] = len(all_sections_ordered)
            sec_copy["segname"] = "ELF_SECTIONS"
            if sec_copy["vmaddr_int"] == 0 and (sh["sh_flags"] & SHF_ALLOC):
                sec_copy["vmaddr_int"] = synth_vm + sh["slice_offset"]
                sec_copy["vmaddr"] = f"0x{sec_copy['vmaddr_int']:x}"
            sec_copy["align_bytes"] = max(1, sh["align"])
            sec_copy["reloff"] = 0
            sec_copy["nreloc"] = 0
            sec_copy["flags"] = sh["sh_flags"]
            sec_copy["flags_hex"] = f"0x{sh['sh_flags']:x}"
            sec_copy["reserved1"] = sh["sh_link"]
            sec_copy["reserved2"] = sh["sh_info"]
            sec_copy["region"] = make_region(
                sh["abs_offset"],
                sh["slice_offset"],
                0 if sh["is_zerofill"] else sh["size"],
                sec_copy["vmaddr"],
                sh["size"],
            )
            seg_sections.append(sec_copy)
            all_sections_ordered.append(sec_copy)
            if not load_commands:
                load_commands.append({
                    "index": len(load_commands),
                    "cmd": sh["sh_type"],
                    "cmd_hex": f"0x{sh['sh_type']:x}",
                    "cmd_name": f"SHDR {sh['sectname']}",
                    "cmdsize": sh_ent_sz,
                    "req_dyld": False,
                    "summary": f"{sh['sectname']} ({sh['section_type']}) {sh['size']} B",
                    "region": sh["header_region"],
                    "fields": sh["fields"],
                    "details": {},
                })
        segments.append({
            "index": 0,
            "segname": "ELF_SECTIONS",
            "vmaddr": f"0x{synth_vm:x}",
            "vmaddr_int": synth_vm,
            "vmsize": f"0x{max_end:x}",
            "vmsize_int": max_end,
            "fileoff": min_off,
            "filesize": max(0, max_end - min_off),
            "abs_offset": min_off,
            "initprot": "r-x",
            "maxprot": "rwx",
            "initprot_raw": 5,
            "maxprot_raw": 7,
            "nsects": len(seg_sections),
            "flags": 0,
            "flags_decoded": ["ET_REL_SYNTH"],
            "region": make_region(min_off, min_off, max(0, max_end - min_off), f"0x{synth_vm:x}", max_end),
            "header_region": make_region(e_shoff, e_shoff, max_sh * sh_ent_sz),
            "fields": [],
            "sections": seg_sections,
        })

    # Helper to convert VMAddr -> file offset using PT_LOAD segments
    seg_lookup = SegmentLookup(segments)

    def vm_to_file_off(vm: int) -> Optional[int]:
        return seg_lookup.file_offset(vm)

    # ------------------------------------------------------------------------
    # 3. Parse ELF Notes (.note.gnu.build-id, .note.ABI-tag, .note.gnu.property)
    # ------------------------------------------------------------------------
    build_id_hex = ""
    abi_minos_str = ""
    gnu_properties: List[str] = []          # control-flow features declared for this machine (audit labels)
    gnu_property_entries: List[Dict[str, Any]] = []   # every decoded property of the note
    notes_list: List[Dict[str, Any]] = []
    note_ranges: List[Tuple[int, int]] = []
    for p in phdrs:
        if p["p_type"] == PT_NOTE and p["p_filesz"] > 0:
            note_ranges.append((p["p_offset"], p["p_filesz"]))
    if not note_ranges:
        for sh in raw_shdrs:
            if sh["sh_type"] == SHT_NOTE and sh["size"] > 0:
                note_ranges.append((sh["slice_offset"], sh["size"]))

    notes_limit = ANALYSIS_LIMITS["elf_notes"]
    seen_note_ranges = set()
    for n_off, n_sz in note_ranges:
        if (n_off, n_sz) in seen_note_ranges:
            continue
        seen_note_ranges.add((n_off, n_sz))
        cur = n_off
        end = min(file_size, n_off + n_sz)
        while cur + 12 <= end:
            if len(notes_list) >= notes_limit:
                add_warning(warnings, "notes_truncated", f"Only the first {notes_limit} ELF notes are decoded.", limit=notes_limit)
                break
            runtime.check_deadline()
            note_start = cur
            namesz = buf.u32(cur)
            descsz = buf.u32(cur + 4)
            ntype = buf.u32(cur + 8)
            cur += 12
            name_aligned = (namesz + 3) & ~3
            desc_aligned = (descsz + 3) & ~3
            if cur + name_aligned + desc_aligned > end:
                break
            n_name = buf.read_bytes(cur, max(0, namesz - 1)).decode("ascii", errors="replace")
            desc_bytes = buf.read_bytes(cur + name_aligned, descsz)
            cur += name_aligned + desc_aligned

            note_type_name = f"NT_{ntype}"
            note_desc_str = desc_bytes.hex()
            if n_name == "GNU":
                if ntype == 3 and descsz > 0:  # NT_GNU_BUILD_ID
                    build_id_hex = desc_bytes.hex()
                    note_type_name = "NT_GNU_BUILD_ID"
                    note_desc_str = f"Build-ID: {build_id_hex}"
                elif ntype == 1 and descsz >= 16:  # NT_GNU_ABI_TAG
                    os_id, maj, min_v, sub_v = struct.unpack(f"{buf.endian_char}IIII", desc_bytes[:16])
                    os_tag = "Linux" if os_id == 0 else f"OS_{os_id}"
                    abi_minos_str = f"{os_tag} {maj}.{min_v}.{sub_v}"
                    note_type_name = "NT_GNU_ABI_TAG"
                    note_desc_str = f"ABI: {abi_minos_str}"
                elif ntype == 5 and descsz >= 8:  # NT_GNU_PROPERTY_TYPE_0
                    note_type_name = "NT_GNU_PROPERTY_TYPE_0"
                    p_cur = 0
                    prop_steps = 0
                    note_props: List[str] = []
                    align_step = 8 if is_64 else 4
                    while p_cur + 8 <= len(desc_bytes) and prop_steps < 256:
                        prop_steps += 1
                        pr_type, pr_datasz = struct.unpack_from(f"{buf.endian_char}II", desc_bytes, p_cur)
                        p_cur += 8
                        if p_cur + pr_datasz > len(desc_bytes):
                            break
                        prop = decode_gnu_property(e_machine, pr_type, desc_bytes[p_cur:p_cur + pr_datasz], buf.endian_char)
                        prop["abs_offset"] = note_start + 12 + name_aligned + p_cur - 8
                        prop["size"] = 8 + pr_datasz
                        if len(gnu_property_entries) < 64:
                            gnu_property_entries.append(prop)
                        for label in prop["cfi"]:
                            if label not in gnu_properties:
                                gnu_properties.append(label)
                        shown = prop["type_name"]
                        if prop["flags"]:
                            shown += " = " + " | ".join(prop["flags"])
                        elif prop["value"] is not None:
                            shown += f" = 0x{prop['value']:x}"
                        note_props.append(shown)
                        p_cur += (pr_datasz + (align_step - 1)) & ~(align_step - 1)
                    note_desc_str = "; ".join(note_props) if note_props else "GNU Property"
            notes_list.append({
                "name": n_name,
                "type": ntype,
                "type_name": note_type_name,
                "description": note_desc_str,
                "abs_offset": note_start,
                "size": cur - note_start,
            })

    # ------------------------------------------------------------------------
    # 4. Parse .dynamic Section / PT_DYNAMIC
    # ------------------------------------------------------------------------
    dyn_tags: Dict[int, List[int]] = {}
    dylibs: List[Dict[str, Any]] = []
    rpaths: List[Dict[str, Any]] = []
    dyn_off = 0
    dyn_sz = 0
    for p in phdrs:
        if p["p_type"] == PT_DYNAMIC and p["p_filesz"] > 0:
            dyn_off, dyn_sz = p["p_offset"], p["p_filesz"]
            break
    if dyn_off == 0:
        for sh in raw_shdrs:
            if sh["sh_type"] == SHT_DYNAMIC and sh["size"] > 0:
                dyn_off, dyn_sz = sh["slice_offset"], sh["size"]
                break

    # Find .dynstr bytes
    dynstr_bytes: Any = _StrTable(full_data, 0, 0)
    for sh in raw_shdrs:
        if sh["sectname"] == ".dynstr" and sh["size"] > 0 and sh["slice_offset"] < file_size:
            dynstr_bytes = _StrTable(full_data, sh["slice_offset"], min(sh["size"], file_size - sh["slice_offset"]))
            break

    if dyn_off > 0 and dyn_off < file_size:
        d_ent_sz = 16 if is_64 else 8
        dyn_limit = ANALYSIS_LIMITS["elf_dynamic_entries"]
        n_dyn = min(dyn_limit, dyn_sz // d_ent_sz)
        for i in range(n_dyn):
            if i == dyn_limit - 1:
                add_warning(warnings, "dynamic_truncated", f"Only the first {dyn_limit} .dynamic entries are read.", limit=dyn_limit)
            pos = dyn_off + i * d_ent_sz
            if pos + d_ent_sz > file_size:
                break
            d_tag = buf.u64(pos) if is_64 else buf.u32(pos)
            d_val = buf.u64(pos + 8) if is_64 else buf.u32(pos + 4)
            if d_tag == DT_NULL:
                break
            dyn_tags.setdefault(d_tag, []).append(d_val)

        # Fallback .dynstr via DT_STRTAB if section headers are stripped
        if not dynstr_bytes and DT_STRTAB in dyn_tags:
            st_foff = vm_to_file_off(dyn_tags[DT_STRTAB][0])
            st_sz = dyn_tags.get(DT_STRSZ, [4096])[0]
            if st_foff is not None and st_foff < file_size:
                dynstr_bytes = _StrTable(full_data, st_foff, min(st_sz, file_size - st_foff))

        for val in dyn_tags.get(DT_NEEDED, []):
            lib_name = _read_strtab(dynstr_bytes, val) or f"lib_offset_{val}"
            dylibs.append({
                "index": len(dylibs),
                "cmd_name": "DT_NEEDED",
                "name": lib_name,
                "current_version": "ELF Shared Object",
                "compat_version": "SYSV",
                "timestamp": 0,
                "is_weak": False,
                "is_reexport": False,
            })

        for tag_id, tag_label in ((DT_RPATH, "DT_RPATH"), (DT_RUNPATH, "DT_RUNPATH")):
            for val in dyn_tags.get(tag_id, []):
                raw_rp = _read_strtab(dynstr_bytes, val)
                for part in raw_rp.split(":"):
                    if part:
                        rpaths.append({
                            "index": len(rpaths),
                            "path": part,
                            "cmd": tag_label,
                            "abs_offset": dyn_off,
                        })

    # ------------------------------------------------------------------------
    # 4b. Symbol versioning (.gnu.version / .gnu.version_r)
    # ------------------------------------------------------------------------
    # ELF has no per-symbol "comes from library X" record. The one place a file
    # ties an undefined symbol to a library is symbol versioning: .gnu.version
    # gives each .dynsym entry a version index, and .gnu.version_r (Verneed)
    # says which DT_NEEDED file each required version was found in at link time.
    versym_off = 0
    versym_count = 0
    verneed_off = 0
    verneed_count = 0
    verneed_strtab: Any = dynstr_bytes
    for sh in raw_shdrs:
        if sh["sh_type"] == SHT_GNU_VERSYM and sh["size"] >= 2 and 0 < sh["slice_offset"] < file_size:
            versym_off, versym_count = sh["slice_offset"], sh["size"] // 2
        elif sh["sh_type"] == SHT_GNU_VERNEED and sh["size"] >= 16 and 0 < sh["slice_offset"] < file_size:
            verneed_off, verneed_count = sh["slice_offset"], sh["sh_info"] or sh["size"] // 16
            if 0 < sh["sh_link"] < len(raw_shdrs):
                link_sh = raw_shdrs[sh["sh_link"]]
                if link_sh["size"] > 0 and link_sh["slice_offset"] < file_size:
                    verneed_strtab = _StrTable(full_data, link_sh["slice_offset"], min(link_sh["size"], file_size - link_sh["slice_offset"]))
    if not versym_off and DT_VERSYM in dyn_tags:
        foff = vm_to_file_off(dyn_tags[DT_VERSYM][0])
        if foff is not None and 0 < foff < file_size:
            versym_off, versym_count = foff, (file_size - foff) // 2
    if not verneed_off and DT_VERNEED in dyn_tags:
        foff = vm_to_file_off(dyn_tags[DT_VERNEED][0])
        if foff is not None and 0 < foff < file_size:
            verneed_off, verneed_count = foff, dyn_tags.get(DT_VERNEEDNUM, [0])[0]

    verneed_by_index: Dict[int, Tuple[str, str]] = {}   # version index -> (file, version name)
    version_needs: List[Dict[str, Any]] = []
    if verneed_off:
        vn_cur = verneed_off
        for _ in range(min(verneed_count, 256)):
            runtime.check_deadline()
            if vn_cur + 16 > file_size:
                break
            vn_cnt = buf.u16(vn_cur + 2)
            vn_file = buf.u32(vn_cur + 4)
            vn_aux = buf.u32(vn_cur + 8)
            vn_next = buf.u32(vn_cur + 12)
            need_file = _read_strtab(verneed_strtab, vn_file)
            need_versions: List[str] = []
            aux_cur = vn_cur + vn_aux
            for _aux in range(min(vn_cnt, 256)):
                if vn_aux == 0 or aux_cur + 16 > file_size:
                    break
                vna_other = buf.u16(aux_cur + 6)
                vna_name = buf.u32(aux_cur + 8)
                vna_next = buf.u32(aux_cur + 12)
                ver_name = _read_strtab(verneed_strtab, vna_name)
                if need_file and (vna_other & 0x7FFF) >= 2:
                    verneed_by_index.setdefault(vna_other & 0x7FFF, (need_file, ver_name))
                if ver_name:
                    need_versions.append(ver_name)
                if vna_next == 0:
                    break
                aux_cur += vna_next
            if need_file:
                version_needs.append({"file": need_file, "versions": need_versions, "abs_offset": vn_cur})
            if vn_next == 0:
                break
            vn_cur += vn_next

    needed_ordinal = {d["name"]: d["index"] + 1 for d in reversed(dylibs)}

    def dynsym_origin(dynsym_index: int) -> Tuple[str, str]:
        """(library, version) the file records for .dynsym entry `dynsym_index`, or ("", "")."""
        if not verneed_by_index or not 0 <= dynsym_index < versym_count:
            return ("", "")
        pos = versym_off + dynsym_index * 2
        if pos + 2 > file_size:
            return ("", "")
        return verneed_by_index.get(buf.u16(pos) & 0x7FFF, ("", ""))

    # ------------------------------------------------------------------------
    # 5. Parse Symbol Tables (.dynsym and .symtab)
    # ------------------------------------------------------------------------
    symbols: List[Dict[str, Any]] = []
    dynsym_names: List[str] = []
    has_symtab = False
    sym_sections = [sh for sh in raw_shdrs if sh["sh_type"] in (SHT_DYNSYM, SHT_SYMTAB)]
    sym_limit = ANALYSIS_LIMITS["symbols"]
    dynsym_name_limit = sym_limit * 4
    sym_struct = struct.Struct(buf.endian_char + ("IBBHQQ" if is_64 else "IIIBBH"))

    for sh in sym_sections:
        if sh["sh_type"] == SHT_SYMTAB:
            has_symtab = True
        s_off = sh["slice_offset"]
        s_sz = sh["size"]
        ent_sz = sh["sh_entsize"] or (24 if is_64 else 16)
        if s_off <= 0 or s_off >= file_size or ent_sz <= 0:
            continue

        # Locate linked string table
        strtab_blob = dynstr_bytes
        if 0 < sh["sh_link"] < len(raw_shdrs):
            link_sh = raw_shdrs[sh["sh_link"]]
            if link_sh["slice_offset"] < file_size:
                strtab_blob = _StrTable(
                    full_data, link_sh["slice_offset"], min(link_sh["size"], file_size - link_sh["slice_offset"])
                )

        declared = s_sz // ent_sz
        budget = sym_limit - len(symbols)
        if budget <= 0:
            add_warning(warnings, "symbols_truncated", f"Only the first {sym_limit:,} symbols are shown.", limit=sym_limit)
            break
        if declared > budget:
            add_warning(warnings, "symbols_truncated", f"{sh['sectname']} has {declared:,} entries; only {sym_limit:,} symbols in total are shown.", limit=sym_limit, total=declared)
        for idx in range(min(declared, budget, dynsym_name_limit)):
            runtime.check_deadline()
            ent_off = s_off + idx * ent_sz
            if ent_off + ent_sz > file_size:
                break
            if is_64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = sym_struct.unpack(buf.read_bytes(ent_off, 24))
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = sym_struct.unpack(buf.read_bytes(ent_off, 16))

            sym_str = _read_strtab(strtab_blob, st_name)
            if sh["sh_type"] == SHT_DYNSYM:
                dynsym_names.append(sym_str)
            if idx == 0 and not sym_str:
                continue

            st_bind = st_info >> 4
            st_type = st_info & 0xF
            if st_type in (STT_SECTION, STT_FILE) and not sym_str:
                continue

            if st_shndx == 0:
                type_name = "UNDF"
                sec_name = ""
            elif st_shndx == 0xFFF1:
                type_name = "ABS"
                sec_name = "ABS"
            else:
                type_name = "SECT"
                sec_name = raw_shdrs[st_shndx]["sectname"] if st_shndx < len(raw_shdrs) else f"sect_{st_shndx}"

            target_foff = vm_to_file_off(st_value) if st_value > 0 else None
            is_dynsym = sh["sh_type"] == SHT_DYNSYM
            origin_lib, origin_ver = dynsym_origin(idx) if (is_dynsym and st_shndx == 0) else ("", "")
            symbols.append({
                "index": len(symbols),
                "name": sym_str or f"anon_{idx}",
                "demangled": _demangle_elf_symbol(sym_str or f"anon_{idx}"),
                "n_type": st_info,
                "type_name": type_name,
                "stt_type": STT_NAMES.get(st_type, f"STT_{st_type}"),
                "is_stab": False,
                "is_external": st_bind in (STB_GLOBAL, STB_WEAK),
                "is_private_ext": (st_other & 0x3) != 0,
                "is_weak": (st_bind == STB_WEAK),
                "n_sect": st_shndx if st_shndx < 255 else 0,
                "section_name": sec_name,
                "n_desc": st_other,
                # An undefined symbol names a library only through its version requirement
                # (see 4b); without one the providing library is not recorded in the file.
                "library_ordinal": needed_ordinal.get(origin_lib, 0),
                "library_name": origin_lib if st_shndx == 0 else (".dynsym" if is_dynsym else ".symtab"),
                "library_source": ("verneed" if origin_lib else "unknown") if st_shndx == 0 else "",
                "version": origin_ver,
                "n_value": f"0x{st_value:x}",
                "n_value_int": st_value,
                "symbol_size": st_size,
                "abs_offset": ent_off,
                "slice_offset": ent_off,
                "size": ent_sz,
                "target_abs_offset": target_foff,
            })

    # ------------------------------------------------------------------------
    # 6. Parse Relocations (.rela.dyn, .rela.plt, .rel.dyn, .rel.plt) -> dyld_info
    # ------------------------------------------------------------------------
    reloc_map = (
        RELOC_NAMES_X86_64
        if e_machine == 62
        else RELOC_NAMES_AARCH64
        if e_machine == 183
        else RELOC_NAMES_I386
        if e_machine == 3
        else RELOC_NAMES_ARM
        if e_machine == 40
        else {}
    )
    fixups_preview: List[Dict[str, Any]] = []
    imports_list: List[Dict[str, Any]] = []
    exports_list: List[Dict[str, Any]] = []
    indirect_symbols: List[Dict[str, Any]] = []

    import_names = set()
    export_names = set()
    imp_limit = ANALYSIS_LIMITS["imports"]
    exp_limit = ANALYSIS_LIMITS["exports"]
    import_index: Dict[str, int] = {}
    for sym in symbols:
        if sym["type_name"] == "UNDF" and sym["name"]:
            # .symtab repeats .dynsym's undefined symbols, spelled "name@VERSION" and without
            # version indices: one import per symbol, keeping the entry that carries the library.
            base_name = sym["name"].split("@", 1)[0] or sym["name"]
            if base_name in import_names:
                known = imports_list[import_index[base_name]] if base_name in import_index else None
                if known is not None and not known["lib_name"] and sym.get("library_source") == "verneed":
                    known.update({"lib_name": sym["library_name"], "lib_ordinal": sym["library_ordinal"],
                                  "lib_source": "verneed", "version": sym.get("version", "")})
                continue
            if len(imports_list) >= imp_limit:
                add_warning(warnings, "imports_truncated", f"Only the first {imp_limit:,} imported symbols are listed.", limit=imp_limit)
                continue
            import_names.add(base_name)
            import_index[base_name] = len(imports_list)
            imports_list.append({
                "index": len(imports_list),
                "name": sym["name"],
                # 0 / "" = the file does not say which library provides this symbol.
                "lib_ordinal": sym["library_ordinal"],
                "lib_name": sym["library_name"],
                "lib_source": sym.get("library_source") or "unknown",
                "version": sym.get("version", ""),
                "weak_import": sym["is_weak"],
            })
        elif sym["type_name"] == "SECT" and sym["is_external"] and sym["n_value_int"] > 0:
            if sym["name"] in export_names:
                continue
            if len(exports_list) >= exp_limit:
                add_warning(warnings, "exports_truncated", f"Only the first {exp_limit:,} exported symbols are listed.", limit=exp_limit)
                continue
            export_names.add(sym["name"])
            exports_list.append({
                "name": sym["name"],
                "vmaddr": sym["n_value"],
                "offset": sym["target_abs_offset"] or 0,
                "flags": 0,
                "flags_decoded": [sym.get("stt_type", "FUNC")],
            })

    rel_sections = [sh for sh in raw_shdrs if sh["sh_type"] in (SHT_RELA, SHT_REL)]
    for rsh in rel_sections:
        r_off = rsh["slice_offset"]
        r_sz = rsh["size"]
        is_rela = (rsh["sh_type"] == SHT_RELA)
        default_ent = (24 if is_rela else 16) if is_64 else (12 if is_rela else 8)
        r_ent = rsh["sh_entsize"] or default_ent
        if r_off <= 0 or r_off >= file_size or r_ent <= 0:
            continue
        fix_limit = ANALYSIS_LIMITS["fixups_preview"]
        declared_rel = r_sz // r_ent
        n_rel = min(256, declared_rel, fix_limit - len(fixups_preview))
        if declared_rel > n_rel:
            add_warning(warnings, "relocations_truncated", f"Relocation sections are previewed (up to 256 entries each, {fix_limit:,} in total).", limit=fix_limit)
        for idx in range(max(0, n_rel)):
            runtime.check_deadline()
            pos = r_off + idx * r_ent
            if pos + r_ent > file_size:
                break
            if is_64:
                r_offset = buf.u64(pos)
                r_info = buf.u64(pos + 8)
                r_addend = buf.unpack_at("q", pos + 16)[0] if is_rela else 0
                r_sym = r_info >> 32
                r_type = r_info & 0xFFFFFFFF
            else:
                r_offset = buf.u32(pos)
                r_info = buf.u32(pos + 4)
                r_addend = buf.i32(pos + 8) if is_rela else 0
                r_sym = r_info >> 8
                r_type = r_info & 0xFF

            r_type_name = reloc_map.get(r_type, f"R_TYPE_{r_type}")
            sym_name = dynsym_names[r_sym] if 0 < r_sym < len(dynsym_names) else (f"0x{r_addend:x}" if r_addend else f"sym_{r_sym}")
            target_foff = vm_to_file_off(r_offset) or pos

            fixups_preview.append({
                "vmaddr": f"0x{r_offset:x}",
                "abs_offset": target_foff,
                "type": r_type_name,
                "ordinal": r_sym if r_sym > 0 else None,
                "symbol": sym_name,
                "pac_key": None,
                "diversity": r_addend,
                "addr_div": False,
            })
            if "JUMP_SLOT" in r_type_name or "JMP_SLOT" in r_type_name or "GLOB_DAT" in r_type_name:
                indirect_symbols.append({
                    "section_name": rsh["sectname"],
                    "slot_index": idx,
                    "slot_vmaddr": f"0x{r_offset:x}",
                    "indirect_value": r_sym,
                    "symbol_name": sym_name,
                })

    # Which relocation record formats the file actually uses: REL (addend stored in the
    # relocated field), RELA (explicit addend) and/or RELR (packed relative relocations).
    # This is a property of each relocation section, not of the word size.
    reloc_kinds: List[str] = []
    for kind_name, present in (
        ("REL", any(sh["sh_type"] == SHT_REL for sh in rel_sections) or DT_REL in dyn_tags
                or (dyn_tags.get(DT_PLTREL, [0])[0] == DT_REL and DT_JMPREL in dyn_tags)),
        ("RELA", any(sh["sh_type"] == SHT_RELA for sh in rel_sections) or DT_RELA in dyn_tags
                 or (dyn_tags.get(DT_PLTREL, [0])[0] == DT_RELA and DT_JMPREL in dyn_tags)),
        ("RELR", any(sh["sh_type"] == SHT_RELR for sh in raw_shdrs) or DT_RELR in dyn_tags),
    ):
        if present:
            reloc_kinds.append(kind_name)
    reloc_kinds_label = " + ".join(reloc_kinds) if reloc_kinds else "no relocation records"

    dyld_info_obj = {
        "has_dyld_info": len(dyn_tags) > 0,
        "has_chained_fixups": len(fixups_preview) > 0,
        "has_exports_trie": len(exports_list) > 0,
        "chained_fixups": {
            "fixups_version": 1,
            "pointer_format": f"ELF {reloc_kinds_label} ({arch_short})",
            "imports_format": ".dynsym undefined symbols" + (" + .gnu.version_r (library per versioned symbol)" if verneed_by_index else " (providing library not recorded)"),
            "imports_count": len(imports_list),
            "chains_count": len(rel_sections),
            "segments": [],
            "imports": imports_list,
            "fixups": fixups_preview,
            "region": make_region(dyn_off, dyn_off, dyn_sz),
            "fields": [],
        } if (fixups_preview or imports_list) else None,
        "exports": exports_list,
        "rebases": [],
        "binds": [],
    }

    # ------------------------------------------------------------------------
    # 7. Extract Strings (.rodata, .comment, .dynstr)
    # ------------------------------------------------------------------------
    strings_list: List[Dict[str, Any]] = []
    compiler_comments: List[str] = []
    strings_limit = ANALYSIS_LIMITS["strings"]
    scan_budget = ANALYSIS_LIMITS["string_scan_bytes"]
    for sh in raw_shdrs:
        if len(strings_list) >= strings_limit:
            add_warning(warnings, "strings_truncated", f"Only the first {strings_limit:,} strings are shown.", limit=strings_limit)
            break
        if scan_budget <= 0:
            add_warning(warnings, "strings_scan_budget", "String extraction stopped after scanning its byte budget; later sections were not scanned.", limit=ANALYSIS_LIMITS["string_scan_bytes"])
            break
        sname = sh["sectname"]
        if (
            sname in (".rodata", ".comment", ".interp")
            or (sh["sh_flags"] & SHF_STRINGS)
            or "rodata" in sname
        ):
            s_off = sh["slice_offset"]
            s_sz = min(sh["size"], 131072, scan_budget)
            if s_off <= 0 or s_off + s_sz > file_size:
                continue
            scan_budget -= s_sz
            raw_sec = buf.read_bytes(s_off, s_sz)
            # NUL-separated runs of printable ASCII (plus tab / newline / CR), at least
            # 3 bytes long, as before -- matched in C, not one iteration per NUL byte.
            for m in _CSTRING_RUN_3.finditer(raw_sec):
                if len(strings_list) >= strings_limit:
                    break
                runtime.check_deadline()
                pos = m.start()
                s_val = m.group(0).decode("ascii")
                s_vm = sh["vmaddr_int"] + pos if sh["vmaddr_int"] else 0
                strings_list.append({
                    "index": len(strings_list),
                    "source": sname,
                    "vmaddr": f"0x{s_vm:x}",
                    "slice_offset": s_off + pos,
                    "abs_offset": s_off + pos,
                    "length": len(s_val),
                    "encoding": "UTF-8",
                    "value": s_val,
                })
                if sname == ".comment" and len(compiler_comments) < 32:
                    compiler_comments.append(s_val)

    # Function starts from FUNC symbols
    function_starts = [
        {
            "index": idx,
            "vmaddr": s["n_value"],
            "slice_offset": s["target_abs_offset"] or 0,
            "abs_offset": s["target_abs_offset"] or 0,
            "name": s["demangled"] or s["name"],
        }
        for idx, s in enumerate(
            sorted(
                [sym for sym in symbols if sym.get("stt_type") in ("FUNC", "IFUNC") and sym["n_value_int"] > 0],
                key=lambda x: x["n_value_int"],
            )[:1000]
        )
    ]

    entry_foff = vm_to_file_off(e_entry) or 0
    entry_point_info = {
        "type": "Ehdr.e_entry",
        "entryoff": entry_foff,
        "vmaddr": f"0x{e_entry:x}",
        "abs_offset": entry_foff,
        "stacksize": 0,
        "thread_flavor": interp_path or None,
        "registers": {},
    }

    header_obj = {
        "magic": "0x7f454c46",
        "magic_name": f"{magic_str} ({'LSB' if little_endian else 'MSB'})",
        "is_64bit": is_64,
        "little_endian": little_endian,
        "cputype": e_machine,
        "cputype_name": machine_macro,
        "cpusubtype": ei_osabi,
        "cpusubtype_name": osabi_name,
        "filetype": e_type,
        "filetype_name": ft_name,
        "ncmds": len(load_commands),
        "sizeofcmds": e_phnum * ph_ent_sz,
        "flags": e_flags,
        "flags_hex": f"0x{e_flags:08x}",
        "flags_decoded": [ft_name, osabi_name] + gnu_properties,
        "region": make_region(0, 0, hdr_size, segments[0]["vmaddr"] if segments else None, hdr_size),
        "fields": header_fields,
    }

    security_posture = evaluate_elf_security_posture(
        e_type=e_type,
        e_machine=e_machine,
        phdrs=phdrs,
        dyn_tags=dyn_tags,
        symbols=symbols,
        rpaths=rpaths,
        gnu_properties=gnu_properties,
        has_symtab=has_symtab,
        build_id=build_id_hex,
    )

    memory_map: List[Dict[str, Any]] = []
    for seg in segments:
        memory_map.append({
            "kind": "segment",
            "segname": seg["segname"],
            "sectname": None,
            "vmaddr": seg["vmaddr"],
            "vmaddr_int": seg["vmaddr_int"],
            "vmsize": seg["vmsize_int"],
            "slice_offset": seg["fileoff"],
            "abs_offset": seg["abs_offset"],
            "filesize": seg["filesize"],
            "prot": seg["initprot"],
            "maxprot": seg["maxprot"],
            "flags_decoded": seg["flags_decoded"],
        })
        for sect in seg["sections"]:
            memory_map.append({
                "kind": "section",
                "segname": sect["segname"],
                "sectname": sect["sectname"],
                "vmaddr": sect["vmaddr"],
                "vmaddr_int": sect["vmaddr_int"],
                "vmsize": sect["size"],
                "slice_offset": sect["slice_offset"],
                "abs_offset": sect["abs_offset"],
                "filesize": 0 if sect["is_zerofill"] else sect["size"],
                "prot": sect["prot"],
                "maxprot": seg["maxprot"],
                "flags_decoded": [sect["section_type"]] + sect["attributes_decoded"],
            })

    # ELF has no in-format code signature. A build ID identifies a build and the
    # GNU property note declares CPU features; neither signs anything, so they are
    # reported where they belong (overview.uuid, elf_metadata.build_id / notes /
    # gnu_property_entries and the "cfi_cet_pac" / "build_id_symbols" checks) and
    # this record says, truthfully, that no signature is present. The frontend shows
    # the ELF notes table in the signature node when `present` is false.
    code_sig_detail = {
        "present": False,
        "kind": "none",
        "note": "ELF defines no embedded signature. The build ID and GNU properties are in elf_metadata.",
        "superblob_region": None,
        "magic": None,
        "length": 0,
        "blob_count": 0,
        "fields": [],
        "blobs": [],
        "code_directory": None,
        "entitlements_xml": "",
        "entitlements_dict": {},
        "entitlements_entries": [],
        "cms_signature": {"present": False, "is_adhoc": False, "size": 0, "certificates": []},
    }

    overview_obj = {
        "format": "ELF",
        "filetype_name": ft_name,
        "filetype_desc": ft_desc,
        "arch_display": arch_display,
        "endianness": "Little-Endian" if little_endian else "Big-Endian",
        "is_64bit": is_64,
        "uuid": build_id_hex,
        "platform": osabi_name,
        "minos": abi_minos_str or "SYSV / Linux",
        "sdk": compiler_comments[0] if compiler_comments else (interp_path or "ELF ABI"),
        "source_version": interp_path,
        "entry_point_vmaddr": f"0x{e_entry:x}",
        "entry_point_abs_offset": entry_foff,
        "entry_point_type": "Ehdr.e_entry",
        "ncmds": len(load_commands),
        "sizeofcmds": e_phnum * ph_ent_sz,
        "segments_count": len(segments),
        "sections_count": len(all_sections_ordered),
        "symbols_count": len(symbols),
        "strings_count": len(strings_list),
        "dylibs_count": len(dylibs),
    }

    return {
        "slice_index": 0,
        "format": "elf",
        "arch_name": arch_short,
        "slice_base_offset": 0,
        "slice_size": file_size,
        "overview": overview_obj,
        "header": header_obj,
        "load_commands": load_commands,
        "segments": segments,
        "memory_map": memory_map,
        "dylibs": dylibs,
        "rpaths": rpaths,
        "entry_point": entry_point_info,
        "dyld_info": dyld_info_obj,
        "symbols": symbols,
        "dysymtab": {
            "present": len(indirect_symbols) > 0,
            "ilocalsym": 0,
            "nlocalsym": sum(1 for s in symbols if not s["is_external"]),
            "iextdefsym": 0,
            "nextdefsym": sum(1 for s in symbols if s["is_external"] and s["type_name"] == "SECT"),
            "iundefsym": 0,
            "nundefsym": sum(1 for s in symbols if s["type_name"] == "UNDF"),
            "indirect_symbols": indirect_symbols,
            "fields": [],
        },
        "function_starts": function_starts,
        "strings": strings_list,
        "objc_metadata": {"present": False, "classes": [], "selectors": [], "protocols": []},
        "fileset_entries": [],
        "code_signature_detail": code_sig_detail,
        "security_posture": security_posture,
        "intervals": intervals,
        "elf_metadata": {
            "interpreter": interp_path,
            "build_id": build_id_hex,
            "abi_tag": abi_minos_str,
            "gnu_properties": gnu_properties,
            "gnu_property_entries": gnu_property_entries,
            "version_needs": version_needs,
            "compiler_comments": compiler_comments,
            "notes": notes_list,
        },
        "warnings": warnings,
        "truncated": bool(warnings),
    }
