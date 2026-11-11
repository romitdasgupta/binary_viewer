"""
Layer 2C: Windows PE32 & PE32+ (Portable Executable / COFF) Structural Binary Parser
and Exploit Mitigation / Authenticode Audit Engine.
Supports PE32 (32-bit x86/ARM) & PE32+ (64-bit AMD64/ARM64), .exe, .dll, and .sys drivers,
including XOR-encoded Rich Header decryption, 16 Data Directories, IAT/ILT/EAT,
Base Relocations, CodeView RSDS PDB extraction, and WIN_CERTIFICATE Authenticode.
"""

import datetime
import hashlib
import re
import struct
import uuid
from typing import Any, Dict, List, Optional, Tuple

from . import runtime
from .buffer import BinaryBuffer, BinaryFormatError, add_warning, make_region
from .codesign import parse_cms_certificates
from .constants import ANALYSIS_LIMITS

IMAGE_DOS_SIGNATURE = 0x5A4D  # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550  # "PE\0\0"
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

PE_MACHINE_INFO: Dict[int, Tuple[str, str, str]] = {
    0x014C: ("i386", "IMAGE_FILE_MACHINE_I386", "Intel 386 / x86 (32-bit)"),
    0x8664: ("x86_64", "IMAGE_FILE_MACHINE_AMD64", "AMD64 / x86-64 (64-bit)"),
    0x01C0: ("arm", "IMAGE_FILE_MACHINE_ARM", "ARM Little-Endian (32-bit)"),
    0x01C4: ("arm", "IMAGE_FILE_MACHINE_ARMNT", "ARM Thumb-2 (32-bit)"),
    0xAA64: ("arm64", "IMAGE_FILE_MACHINE_ARM64", "ARM64 (AArch64 64-bit)"),
    0x5064: ("riscv64", "IMAGE_FILE_MACHINE_RISCV64", "RISC-V 64-bit"),
}

PE_SUBSYSTEM_NAMES: Dict[int, str] = {
    0: "IMAGE_SUBSYSTEM_UNKNOWN",
    1: "IMAGE_SUBSYSTEM_NATIVE (Drivers and native processes)",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI (Console)",
    5: "IMAGE_SUBSYSTEM_OS2_CUI",
    7: "IMAGE_SUBSYSTEM_POSIX_CUI",
    8: "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
    9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    11: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
    12: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
    13: "IMAGE_SUBSYSTEM_EFI_ROM",
    14: "IMAGE_SUBSYSTEM_XBOX",
    16: "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
}

FILE_CHARACTERISTICS_FLAGS = [
    (0x0001, "IMAGE_FILE_RELOCS_STRIPPED", "Base relocations stripped (must load at preferred ImageBase)"),
    (0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE", "Valid executable image"),
    (0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED", "COFF line numbers stripped"),
    (0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED", "COFF local symbols stripped"),
    (0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE", "Application can handle >2 GB addresses"),
    (0x0100, "IMAGE_FILE_32BIT_MACHINE", "32-bit word architecture"),
    (0x0200, "IMAGE_FILE_DEBUG_STRIPPED", "Debugging information stripped"),
    (0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", "Copy to swap if on removable media"),
    (0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP", "Copy to swap if on network media"),
    (0x1000, "IMAGE_FILE_SYSTEM", "System/kernel-mode file"),
    (0x2000, "IMAGE_FILE_DLL", "Dynamic-Link Library (DLL)"),
    (0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY", "Uniprocessor machine only"),
]

DLL_CHARACTERISTICS_FLAGS = [
    (0x0020, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", "Image can handle a high-entropy 64-bit virtual address space"),
    (0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", "Image can be relocated at load time (opts in to ASLR)"),
    (0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", "Code Integrity checks are enforced (signature verified at load)"),
    (0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", "Image is compatible with DEP / NX (non-executable data pages)"),
    (0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", "Isolation aware, do not isolate image"),
    (0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH", "Does not use structured exception handling; no handler in this image may be called"),
    (0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND", "Do not bind image"),
    (0x1000, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER", "Must execute in an AppContainer sandbox"),
    (0x2000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", "WDM kernel driver"),
    (0x4000, "IMAGE_DLLCHARACTERISTICS_GUARD_CF", "Image supports Control Flow Guard (CFG)"),
    (0x8000, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", "Terminal Server aware"),
]

SECTION_CHARACTERISTICS_FLAGS = [
    (0x00000020, "IMAGE_SCN_CNT_CODE", "Section contains executable code"),
    (0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA", "Section contains initialized data"),
    (0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA", "Section contains uninitialized data (BSS)"),
    (0x02000000, "IMAGE_SCN_MEM_DISCARDABLE", "Section can be discarded as needed"),
    (0x04000000, "IMAGE_SCN_MEM_NOT_CACHED", "Section cannot be cached"),
    (0x08000000, "IMAGE_SCN_MEM_NOT_PAGED", "Section is not pageable"),
    (0x10000000, "IMAGE_SCN_MEM_SHARED", "Section can be shared in memory"),
    (0x20000000, "IMAGE_SCN_MEM_EXECUTE", "Section can be executed as code"),
    (0x40000000, "IMAGE_SCN_MEM_READ", "Section can be read"),
    (0x80000000, "IMAGE_SCN_MEM_WRITE", "Section can be written to"),
]

DATA_DIRECTORY_NAMES = [
    "EXPORT_TABLE",
    "IMPORT_TABLE",
    "RESOURCE_TABLE",
    "EXCEPTION_TABLE",
    "CERTIFICATE_TABLE",
    "BASE_RELOCATION_TABLE",
    "DEBUG_DIRECTORY",
    "ARCHITECTURE",
    "GLOBAL_PTR",
    "TLS_TABLE",
    "LOAD_CONFIG_TABLE",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT_DESCRIPTOR",
    "CLR_RUNTIME_HEADER",
    "RESERVED_DIRECTORY",
]

RICH_PROD_NAMES: Dict[int, str] = {
    # Product ids as tabulated by richprint's comp_id.txt. Visual Studio 2015 and
    # later all use the 0x00FF-0x010E range; the build number tells them apart.
    0x0000: "Unmarked objects (old)",
    0x0001: "Import0 (unmarked objects / imports)",
    0x0083: "Utc1500_C (VS2008 C compiler)",
    0x0084: "Utc1500_CPP (VS2008 C++ compiler)",
    0x0091: "Linker900 (VS2008 linker)",
    0x0093: "Implib900 (VS2008 import library record)",
    0x0094: "Cvtres900 (VS2008 resource converter)",
    0x009D: "Linker1000 (VS2010 linker)",
    0x009E: "Masm1000 (VS2010 MASM)",
    0x00AA: "Utc1600_C (VS2010 C compiler)",
    0x00AB: "Utc1600_CPP (VS2010 C++ compiler)",
    0x00FF: "Cvtres1400 (VS2015+ resource converter)",
    0x0100: "Export1400 (VS2015+ export record)",
    0x0101: "Implib1400 (VS2015+ import library record)",
    0x0102: "Linker1400 (VS2015+ linker)",
    0x0103: "Masm1400 (VS2015+ MASM)",
    0x0104: "Utc1900_C (VS2015+ C compiler)",
    0x0105: "Utc1900_CPP (VS2015+ C++ compiler)",
    0x0108: "Utc1900_LTCG_C (VS2015+ C, link-time code generation)",
    0x0109: "Utc1900_LTCG_CPP (VS2015+ C++, link-time code generation)",
}

DEBUG_TYPE_NAMES: Dict[int, str] = {
    0: "IMAGE_DEBUG_TYPE_UNKNOWN",
    1: "IMAGE_DEBUG_TYPE_COFF",
    2: "IMAGE_DEBUG_TYPE_CODEVIEW",
    3: "IMAGE_DEBUG_TYPE_FPO",
    4: "IMAGE_DEBUG_TYPE_MISC",
    5: "IMAGE_DEBUG_TYPE_EXCEPTION",
    6: "IMAGE_DEBUG_TYPE_FIXUP",
    7: "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
    8: "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",
    9: "IMAGE_DEBUG_TYPE_BORLAND",
    10: "IMAGE_DEBUG_TYPE_RESERVED10",
    11: "IMAGE_DEBUG_TYPE_CLSID",
    12: "IMAGE_DEBUG_TYPE_VC_FEATURE",
    13: "IMAGE_DEBUG_TYPE_POGO",
    14: "IMAGE_DEBUG_TYPE_ILTCG",
    15: "IMAGE_DEBUG_TYPE_MPX",
    16: "IMAGE_DEBUG_TYPE_REPRO",
    17: "IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB",
    19: "IMAGE_DEBUG_TYPE_PDBCHECKSUM",
    20: "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS",
}

BASE_RELOC_TYPES: Dict[int, str] = {
    0: "IMAGE_REL_BASED_ABSOLUTE",
    1: "IMAGE_REL_BASED_HIGH",
    2: "IMAGE_REL_BASED_LOW",
    3: "IMAGE_REL_BASED_HIGHLOW",
    4: "IMAGE_REL_BASED_HIGHADJ",
    5: "IMAGE_REL_BASED_MACHINE_SPECIFIC_5",
    9: "IMAGE_REL_BASED_MACHINE_SPECIFIC_9",
    10: "IMAGE_REL_BASED_DIR64",
}


def _decode_bitflags(val: int, table: List[Tuple[int, str, str]]) -> Tuple[List[str], List[Dict[str, Any]]]:
    names = [name for mask, name, _ in table if val & mask]
    bits = [
        {"name": name, "mask": f"0x{mask:x}", "set": bool(val & mask), "desc": desc}
        for mask, name, desc in table
    ]
    return names, bits


def _scn_to_prot(ch: int) -> Tuple[str, int, List[str], List[Dict[str, Any]]]:
    r = bool(ch & 0x40000000)
    w = bool(ch & 0x80000000)
    x = bool(ch & 0x20000000) or bool(ch & 0x00000020)
    prot_str = f"{'r' if r else '-'}{'w' if w else '-'}{'x' if x else '-'}"
    prot_raw = (1 if r else 0) | (2 if w else 0) | (4 if x else 0)
    names, bits = _decode_bitflags(ch, SECTION_CHARACTERISTICS_FLAGS)
    return prot_str, prot_raw, names, bits


IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_ARM = 0x01C0
IMAGE_FILE_MACHINE_ARMNT = 0x01C4
IMAGE_FILE_MACHINE_IA64 = 0x0200
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

# Size of one function-table entry in the exception directory (.pdata), by machine
# (PE/COFF specification, "The .pdata Section"). x64 and Itanium entries are three
# RVAs; ARM, ARMv7 (Thumb-2) and ARM64 entries are a begin RVA plus one word that
# either packs the unwind data or holds the RVA of an .xdata record.
PDATA_ENTRY_SIZE: Dict[int, int] = {
    IMAGE_FILE_MACHINE_AMD64: 12,
    IMAGE_FILE_MACHINE_IA64: 12,
    IMAGE_FILE_MACHINE_ARM64: 8,
    IMAGE_FILE_MACHINE_ARMNT: 8,
    IMAGE_FILE_MACHINE_ARM: 8,
}

# IMAGE_LOAD_CONFIG_DIRECTORY.GuardFlags (winnt.h / PE-COFF specification).
GUARD_FLAGS = [
    (0x00000100, "IMAGE_GUARD_CF_INSTRUMENTED", "Module performs control-flow integrity checks using system-supplied support"),
    (0x00000200, "IMAGE_GUARD_CFW_INSTRUMENTED", "Module performs control-flow and write integrity checks"),
    (0x00000400, "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT", "Module contains valid control-flow target metadata"),
    (0x00000800, "IMAGE_GUARD_SECURITY_COOKIE_UNUSED", "Module does not make use of the /GS security cookie"),
    (0x00001000, "IMAGE_GUARD_PROTECT_DELAYLOAD_IAT", "Module supports read-only delay-load IAT"),
    (0x00002000, "IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION", "Delay-load import table is in its own .didat section"),
    (0x00004000, "IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT", "Module contains suppressed-export information"),
    (0x00008000, "IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION", "Module enables suppression of exports"),
    (0x00010000, "IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT", "Module contains longjmp target information"),
    (0x00020000, "IMAGE_GUARD_RF_INSTRUMENTED", "Module contains return-flow instrumentation and metadata"),
    (0x00040000, "IMAGE_GUARD_RF_ENABLE", "Module requests that the OS enable return-flow protection"),
    (0x00080000, "IMAGE_GUARD_RF_STRICT", "Module requests return-flow protection in strict mode"),
    (0x00100000, "IMAGE_GUARD_RETPOLINE_PRESENT", "Module was built with retpoline support"),
    (0x00400000, "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT", "Module contains exception-handling continuation target information"),
    (0x00800000, "IMAGE_GUARD_XFG_ENABLED", "Module was built with eXtended Flow Guard"),
]
IMAGE_GUARD_CF_INSTRUMENTED = 0x00000100
IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400


# ============================================================================
# Integrity values computed from the bytes: CheckSum and the Authenticode hash
# ============================================================================
def pe_layout(data: bytes) -> Optional[Dict[str, Any]]:
    """Offsets needed for the PE checksum and the Authenticode hash, or None if not a PE."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    if nt + 24 + 2 > len(data) or data[nt:nt + 4] != b"PE\0\0":
        return None
    opt = nt + 24
    nsects, opt_size = struct.unpack_from("<H", data, nt + 6)[0], struct.unpack_from("<H", data, nt + 20)[0]
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        dirs = opt + 96
    elif magic == 0x20B:
        dirs = opt + 112
    else:
        return None
    if opt + 68 > len(data):
        return None
    out: Dict[str, Any] = {"checksum_off": opt + 64, "stored_checksum": struct.unpack_from("<I", data, opt + 64)[0],
                           "cert_dir_off": None, "cert_off": 0, "cert_size": 0, "sections": [],
                           "headers_size": struct.unpack_from("<I", data, opt + 60)[0]}
    n_dirs = struct.unpack_from("<I", data, dirs - 4)[0] if dirs <= len(data) else 0
    if n_dirs > 4 and dirs + 5 * 8 <= len(data):
        out["cert_dir_off"] = dirs + 4 * 8
        out["cert_off"], out["cert_size"] = struct.unpack_from("<II", data, dirs + 4 * 8)
    table = opt + opt_size
    for i in range(min(nsects, 96)):
        entry = table + i * 40
        if entry + 40 > len(data):
            break
        raw_size, raw_ptr = struct.unpack_from("<II", data, entry + 16)
        if raw_size:
            out["sections"].append((raw_ptr, raw_size))
    return out


def pe_checksum(data: bytes, checksum_off: int) -> int:
    """The PE image checksum: 16-bit one's-complement sum of the file with the
    CheckSum field taken as zero, plus the file length."""
    total = 0
    view = memoryview(data)
    even = len(data) & ~1
    step = 1 << 16
    for pos in range(0, even, step):
        runtime.check_deadline()
        chunk = view[pos:min(even, pos + step)]
        total += sum(struct.unpack("<%dH" % (len(chunk) // 2), chunk))
    if len(data) & 1:
        total += data[-1]
    if 0 <= checksum_off and checksum_off + 4 <= len(data):
        total -= struct.unpack_from("<H", data, checksum_off)[0] + struct.unpack_from("<H", data, checksum_off + 2)[0]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (total + len(data)) & 0xFFFFFFFF


def authenticode_digest(data: bytes, layout: Dict[str, Any], algorithm: str = "sha256") -> str:
    """The Authenticode PE image hash (hex), following the published procedure:
    headers without CheckSum and without the Certificate Table directory entry,
    then each section's raw data in file order, then any trailing data that is
    not the certificate table."""
    h = hashlib.new(algorithm)
    size = len(data)
    cks = layout["checksum_off"]
    cert_dir = layout["cert_dir_off"]
    headers_end = max(0, min(size, layout["headers_size"]))
    h.update(data[:cks])
    if cert_dir is not None and cert_dir + 8 <= headers_end:
        h.update(data[cks + 4:cert_dir])
        h.update(data[cert_dir + 8:headers_end])
    else:
        h.update(data[cks + 4:headers_end])
    hashed = headers_end
    for ptr, raw in sorted(layout["sections"]):
        runtime.check_deadline()
        start, end = max(0, min(size, ptr)), max(0, min(size, ptr + raw))
        h.update(data[start:end])
        hashed += raw
    # Whatever follows the sections, except the certificate table. The published procedure
    # assumes the table is the last thing in the file; excluding its actual range gives the
    # same result for such files and stays meaningful for files that put it elsewhere.
    cert_start, cert_end = layout["cert_off"], layout["cert_off"] + layout["cert_size"]
    if not (layout["cert_off"] and layout["cert_size"] and cert_end <= size):
        cert_start = cert_end = size
    hashed = max(0, min(size, hashed))
    if hashed < cert_start:
        h.update(data[hashed:cert_start])
    if max(hashed, cert_end) < size:
        h.update(data[max(hashed, cert_end):size])
    return h.hexdigest()


# DER encodings of the digest algorithm OIDs an Authenticode signature may name.
_DIGEST_OIDS = [
    ("sha256", bytes.fromhex("608648016503040201")),
    ("sha384", bytes.fromhex("608648016503040202")),
    ("sha512", bytes.fromhex("608648016503040203")),
    ("sha1", bytes.fromhex("2b0e03021a")),
    ("md5", bytes.fromhex("2a864886f70d0205")),
]


def authenticode_status(data: bytes, layout: Dict[str, Any], blob: bytes) -> Dict[str, Any]:
    """Whether a certificate-table blob contains this file's Authenticode image hash.

    The image hash is computed for each digest algorithm the blob names and looked
    for in the blob (the signature stores it in SpcIndirectDataContent). A match
    shows the signed content is this file's content; the signature over it and the
    certificate chain are NOT evaluated."""
    named = [name for name, oid in _DIGEST_OIDS if oid in blob]
    size = len(data)
    # In a well-formed image the sections' raw data does not overlap, so hashing it reads the
    # file about once. A section table that claims far more than the file holds (many sections
    # aliasing one range) would make the hash read the file once per section: such an image
    # has no meaningful Authenticode hash, and none is computed.
    claimed = sum(max(0, min(size, ptr + raw) - min(size, ptr)) for ptr, raw in layout["sections"])
    if claimed > 2 * size + 4096:
        return {"algorithm": named[0] if named else "", "image_digest": "", "digest_in_signature": False,
                "algorithms_named": named, "not_computed": "section raw data overlaps; the image hash is not defined"}
    available: List[str] = []
    for name in named:
        try:
            digest = authenticode_digest(data, layout, name)
        except ValueError:
            continue          # this Python build does not provide the algorithm (for example MD5 under FIPS)
        available.append(name)
        if bytes.fromhex(digest) in blob:
            return {"algorithm": name, "image_digest": digest, "digest_in_signature": True, "algorithms_named": named}
    first = available[0] if available else "sha256"
    return {"algorithm": first, "image_digest": authenticode_digest(data, layout, first),
            "digest_in_signature": False, "algorithms_named": named}


def is_pe_bytes(data: bytes) -> bool:
    if len(data) < 0x58:
        return False
    if struct.unpack_from("<H", data, 0)[0] != IMAGE_DOS_SIGNATURE:
        return False
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
        return False
    return struct.unpack_from("<I", data, e_lfanew)[0] == IMAGE_NT_SIGNATURE


def _parse_rich_header(buf: BinaryBuffer, e_lfanew: int) -> Optional[Dict[str, Any]]:
    if e_lfanew <= 0x48 or e_lfanew > buf.slice_size:
        return None
    # The Rich header sits in the DOS stub; only the first bytes of a (possibly
    # huge, attacker-sized) stub are searched, and the DanS scan below is bounded
    # by the same window.
    stub_slice = buf.read_bytes(0x40, min(e_lfanew - 0x40, ANALYSIS_LIMITS["pe_rich_scan_bytes"]))
    rich_idx = stub_slice.find(b"Rich")
    if rich_idx == -1 or rich_idx + 8 > len(stub_slice):
        return None

    rich_abs = 0x40 + rich_idx
    xor_key = buf.u32(rich_abs + 4)

    # Scan backwards from rich_abs - 4 to 0x40 looking for "DanS" (0x536E6144) ^ xor_key
    dans_abs = None
    for pos in range(rich_abs - 4, 0x3C, -4):
        dw = buf.u32(pos)
        if (dw ^ xor_key) == 0x536E6144:  # "DanS"
            dans_abs = pos
            break

    if dans_abs is None:
        return None

    rh_buf = buf.clone_with_fields()
    rh_buf.record_field("DanS_magic", "uint32", dans_abs, 4, buf.u32(dans_abs), f"0x{buf.u32(dans_abs):08x}", f"DanS (XOR 0x{xor_key:08x})", "Rich Header start marker")

    entries: List[Dict[str, Any]] = []
    cur = dans_abs + 16  # Skip DanS + 3 zero padding dwords
    idx = 0
    while cur + 8 <= rich_abs and idx < 64:
        raw_comp = rh_buf.u32(cur)
        raw_cnt = rh_buf.u32(cur + 4)
        comp_id = raw_comp ^ xor_key
        use_cnt = raw_cnt ^ xor_key
        prod_id = (comp_id >> 16) & 0xFFFF
        build_ver = comp_id & 0xFFFF
        prod_name = RICH_PROD_NAMES.get(prod_id, f"MSVC_Tool_0x{prod_id:x}")
        rh_buf.record_field(
            f"entry[{idx}].comp_id",
            "uint32",
            cur,
            4,
            raw_comp,
            f"0x{comp_id:08x}",
            f"{prod_name} (build {build_ver})",
            "XOR-encoded @comp.id product & build number",
        )
        rh_buf.record_field(
            f"entry[{idx}].count",
            "uint32",
            cur + 4,
            4,
            raw_cnt,
            str(use_cnt),
            f"{use_cnt} objects",
            "Object count built with this tool",
        )
        entries.append({
            "prod_id": prod_id,
            "prod_name": prod_name,
            "product_name": prod_name,
            "build": build_ver,
            "build_num": build_ver,
            "count": use_cnt,
            "use_count": use_cnt,
        })
        cur += 8
        idx += 1

    rh_buf.record_field("Rich_magic", "char[4]", rich_abs, 4, 0x68636952, "52 69 63 68", "Rich", "Rich Header end marker")
    rh_buf.record_field("xor_checksum", "uint32", rich_abs + 4, 4, xor_key, f"0x{xor_key:08x}", f"XOR Key 0x{xor_key:08x}", "Rich Header checksum & XOR key")

    return {
        "present": True,
        "offset": dans_abs,
        "abs_offset": dans_abs,
        "size": (rich_abs + 8) - dans_abs,
        "xor_key": f"0x{xor_key:08x}",
        "entries": entries,
        "fields": rh_buf.get_fields(),
        "region": make_region(dans_abs, dans_abs, (rich_abs + 8) - dans_abs),
    }


def evaluate_pe_security_posture(
    is_64: bool,
    characteristics: int,
    dll_characteristics: int,
    subsystem: int,
    sections: List[Dict[str, Any]],
    entry_rva: int,
    has_relocs: bool,
    has_pdata: bool,
    load_config: Dict[str, Any],
    tls_callbacks: List[str],
    code_sig_detail: Dict[str, Any],
    machine: Optional[int] = None,
    symbol_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    9-Point Windows PE32 / PE32+ Exploit Mitigation & Authenticode Scorecard.
    """
    checks: List[Dict[str, Any]] = []
    if machine is None:
        machine = IMAGE_FILE_MACHINE_AMD64 if is_64 else IMAGE_FILE_MACHINE_I386
    is_x86_32 = machine == IMAGE_FILE_MACHINE_I386
    machine_label = PE_MACHINE_INFO.get(machine, ("", f"machine 0x{machine:04x}", ""))[1].replace("IMAGE_FILE_MACHINE_", "")
    symbol_info = symbol_info or {}

    # 1. ASLR (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    relocs_stripped = bool(characteristics & 0x0001)
    dynamic_base = bool(dll_characteristics & 0x0040)
    is_aslr = dynamic_base and not relocs_stripped
    if is_aslr:
        checks.append({
            "id": "pie",
            "title": "Address Space Layout Randomization (DYNAMIC_BASE)",
            "status": "PASS",
            "value": "Enabled (DYNAMIC_BASE)",
            "detail": "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) is set and IMAGE_FILE_RELOCS_STRIPPED is clear, so Windows may load the image at a randomized base and apply its base relocations.",
        })
    elif dynamic_base and relocs_stripped:
        checks.append({
            "id": "pie",
            "title": "Address Space Layout Randomization (DYNAMIC_BASE)",
            "status": "WARN",
            "value": "DYNAMIC_BASE Set but RELOCS_STRIPPED",
            "detail": "DYNAMIC_BASE is set, but IMAGE_FILE_RELOCS_STRIPPED says the file has no base relocations, so it can only be loaded at its preferred ImageBase and is not randomized.",
        })
    else:
        checks.append({
            "id": "pie",
            "title": "Address Space Layout Randomization (DYNAMIC_BASE)",
            "status": "FAIL",
            "value": "Disabled (Fixed ImageBase)",
            "detail": "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set; the image loads at its preferred ImageBase unless that range is taken or system policy forces relocation (mandatory ASLR).",
        })

    # 2. High-Entropy 64-bit ASLR (HIGH_ENTROPY_VA)
    high_entropy = bool(dll_characteristics & 0x0020)
    if is_64:
        if high_entropy and is_aslr:
            checks.append({
                "id": "high_entropy_va",
                "title": "64-Bit High-Entropy ASLR (HIGH_ENTROPY_VA)",
                "status": "PASS",
                "value": "Enabled (high-entropy 64-bit ASLR)",
                "detail": "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (0x0020) declares that the image copes with addresses above 4 GB, so 64-bit ASLR may use more random bits (for example 24 bits, 1 TB of variance, for bottom-up allocations). It only has an effect together with DYNAMIC_BASE.",
            })
        else:
            checks.append({
                "id": "high_entropy_va",
                "title": "64-Bit High-Entropy ASLR (HIGH_ENTROPY_VA)",
                "status": "WARN",
                "value": "Not in effect on 64-bit PE32+",
                "detail": "HIGH_ENTROPY_VA is clear, or it is set without a usable DYNAMIC_BASE; for an EXE, Windows then uses the lower-entropy randomisation (or none) for the process's bottom-up allocations.",
            })
    else:
        checks.append({
            "id": "high_entropy_va",
            "title": "64-Bit High-Entropy ASLR (HIGH_ENTROPY_VA)",
            "status": "INFO",
            "value": "N/A (32-bit PE32)",
            "detail": "High-Entropy VA applies only to 64-bit PE32+ images.",
        })

    # 3. DEP / NX (IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    #    The flag only decides anything for 32-bit x86 processes. x64, ARM and ARM64
    #    processes always run with DEP, so its absence there is not a weakness.
    nx_compat = bool(dll_characteristics & 0x0100)
    dep_title = "Data Execution Prevention (NX_COMPAT / DEP)"
    if nx_compat:
        checks.append({
            "id": "dep_nx",
            "title": dep_title,
            "status": "PASS",
            "value": "Enabled (NX_COMPAT)",
            "detail": "IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100) marks the image as compatible with DEP. On a 32-bit EXE it opts the process in to non-executable stack and heap under the client default (OptIn) policy; x64, ARM and ARM64 processes always run with DEP.",
        })
    elif is_x86_32:
        checks.append({
            "id": "dep_nx",
            "title": dep_title,
            "status": "FAIL",
            "value": "NX_COMPAT Not Set",
            "detail": "NX_COMPAT is not set. A 32-bit EXE without it runs with DEP off under the Windows client default (OptIn) policy, leaving stack and heap executable.",
        })
    else:
        checks.append({
            "id": "dep_nx",
            "title": dep_title,
            "status": "INFO",
            "value": f"NX_COMPAT not set (no effect on {machine_label})",
            "detail": f"NX_COMPAT is not set, but the flag matters only to 32-bit x86 processes. {machine_label} processes always run with DEP on, whatever this flag says.",
        })
    # What the process gets: DEP is unconditional except on 32-bit x86, where the flag decides.
    dep_in_effect = nx_compat or not is_x86_32

    # 4. Control Flow Guard: the header flag DECLARES support; the load configuration
    #    shows whether the image was actually built with the checks and their metadata.
    guard_cf = bool(dll_characteristics & 0x4000)
    lc_present = bool(load_config.get("present"))
    guard_flags = int(load_config.get("guard_flags") or 0)
    guard_fn_table = int(load_config.get("guard_cf_function_table") or 0)
    guard_fn_count = int(load_config.get("guard_cf_function_count") or 0)
    guard_check_ptr = int(load_config.get("guard_cf_check_function_pointer") or 0)
    cfg_instrumented = bool(guard_flags & IMAGE_GUARD_CF_INSTRUMENTED)
    cfg_table = bool(guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT) and guard_fn_table != 0 and guard_fn_count > 0
    cfg_title = "Control Flow Guard (GUARD_CF)"
    if not lc_present:
        lc_facts = "The image has no load configuration directory, which is where the compiler records the CFG check pointer, the table of valid call targets and GuardFlags."
    elif not load_config.get("has_guard_fields"):
        lc_facts = f"The load configuration directory is {load_config.get('size', 0)} bytes, too short to contain the Control Flow Guard fields."
    else:
        lc_facts = (
            f"Load configuration: GuardFlags 0x{guard_flags:08x} ({', '.join(load_config.get('guard_flags_decoded') or []) or 'no flags'}), "
            f"GuardCFFunctionTable 0x{guard_fn_table:x} with {guard_fn_count:,} entr{'y' if guard_fn_count == 1 else 'ies'}, "
            f"GuardCFCheckFunctionPointer 0x{guard_check_ptr:x}."
        )
    cfg_scope = " Only forward edges (indirect calls and jumps) are covered, and enforcement also needs CFG to be on for the process."
    if guard_cf and cfg_instrumented and cfg_table:
        checks.append({
            "id": "cfg",
            "title": cfg_title,
            "status": "PASS",
            "value": f"Declared and instrumented ({guard_fn_count:,} valid call target{'s' if guard_fn_count != 1 else ''})",
            "detail": "IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) is set, and the load configuration has IMAGE_GUARD_CF_INSTRUMENTED and a populated Guard CF function table, from which Windows builds the bitmap of valid indirect-call targets. " + lc_facts + cfg_scope,
        })
    elif guard_cf:
        checks.append({
            "id": "cfg",
            "title": cfg_title,
            "status": "WARN",
            "value": "Declared in the header, but not instrumented" if not cfg_instrumented else "Declared and instrumented, but no call-target table",
            "detail": "IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) declares CFG support, but the load configuration does not show a CFG build ("
            + ("IMAGE_GUARD_CF_INSTRUMENTED is clear" if not cfg_instrumented else "the Guard CF function table is absent or empty")
            + "), so the image carries no checks or no target list for Windows to enforce. " + lc_facts,
        })
    elif cfg_instrumented or cfg_table:
        # Linkers set IMAGE_GUARD_CF_INSTRUMENTED when any input object was compiled with
        # /guard:cf, even if the image itself is linked without it.
        checks.append({
            "id": "cfg",
            "title": cfg_title,
            "status": "INFO",
            "value": "Not enabled (instrumented code present, header flag clear)",
            "detail": "The load configuration carries Control Flow Guard metadata, but IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) is clear, so the loader does not treat the image as CFG-aware and any compiled-in checks always pass. " + lc_facts,
        })
    else:
        checks.append({
            "id": "cfg",
            "title": cfg_title,
            "status": "INFO",
            "value": "Not Enabled",
            "detail": "IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) is not set, and the load configuration shows no Control Flow Guard instrumentation. " + lc_facts,
        })
    cfg_effective = guard_cf and cfg_instrumented and cfg_table

    # 5. SEH Protection. SafeSEH and NO_SEH are 32-bit x86 concepts: only there are
    #    exception handler records kept on the stack. Every other machine finds handlers
    #    through the function tables in .pdata, so the question does not arise.
    no_seh = bool(dll_characteristics & 0x0400)
    seh_table = int(load_config.get("se_handler_table") or 0)
    seh_count = int(load_config.get("se_handler_count") or 0)
    seh_title = "Exception Handler Hardening (SafeSEH / .pdata)"
    if not is_x86_32:
        checks.append({
            "id": "seh",
            "title": seh_title,
            "status": "INFO",
            "value": f"Not applicable ({machine_label}: table-based exception handling)",
            "detail": f"SafeSEH protects the stack-based exception handler chain of 32-bit x86. {machine_label} images locate handlers through the function tables of the exception directory (.pdata"
            + (", present in this image" if has_pdata else ", absent from this image")
            + "); no handler pointers are kept on the stack, so there is nothing for SafeSEH to protect.",
        })
    elif no_seh:
        checks.append({
            "id": "seh",
            "title": seh_title,
            "status": "PASS",
            "value": "Protected (NO_SEH)",
            "detail": "IMAGE_DLLCHARACTERISTICS_NO_SEH (0x0400): the image declares that it has no structured exception handlers, so the dispatcher will not call any handler located in it.",
        })
    elif seh_table and seh_count:
        checks.append({
            "id": "seh",
            "title": seh_title,
            "status": "PASS",
            "value": f"Protected (SafeSEH table, {seh_count:,} handler{'s' if seh_count != 1 else ''})",
            "detail": f"The load configuration lists {seh_count:,} registered handler{'s' if seh_count != 1 else ''} (SEHandlerTable 0x{seh_table:x}); the dispatcher refuses any other handler address inside this image. Modules loaded without SafeSEH are not covered, which SEHOP addresses system-wide.",
        })
    else:
        checks.append({
            "id": "seh",
            "title": seh_title,
            "status": "WARN",
            "value": "Unprotected 32-bit SEH",
            "detail": "32-bit x86 image that neither disables SEH (NO_SEH) nor registers a SafeSEH handler table (SEHandlerTable / SEHandlerCount) in its load configuration.",
        })

    # 6. Stack Buffer Security Cookie (/GS)
    sec_cookie = load_config.get("security_cookie", 0)
    has_gs = bool(sec_cookie)
    if has_gs:
        checks.append({
            "id": "stack_canary",
            "title": "Stack Buffer Security Cookie (/GS)",
            "status": "PASS",
            "value": f"Present (Cookie @ 0x{sec_cookie:x})",
            "detail": "IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookie points at the /GS cookie, which is given a random value at start-up. This shows a /GS-aware runtime; which functions carry a cookie check is decided per function by the compiler.",
        })
    else:
        checks.append({
            "id": "stack_canary",
            "title": "Stack Buffer Security Cookie (/GS)",
            "status": "INFO",
            "value": "No LoadConfig SecurityCookie",
            "detail": "No SecurityCookie pointer in the Load Config directory (built without /GS, no Load Config, or a non-MSVC toolchain that uses another scheme).",
        })

    # 7. W^X Section Hygiene & Entry Point Validation
    rwx_sections = [
        f"{s['sectname']} ({s['prot']})"
        for s in sections
        if "w" in s.get("prot", "") and "x" in s.get("prot", "")
    ]
    has_rwx = len(rwx_sections) > 0
    if has_rwx:
        checks.append({
            "id": "rwx",
            "title": "W^X Section Permission Hygiene",
            "status": "FAIL",
            "value": f"RWX Detected: {', '.join(rwx_sections)}",
            "detail": "One or more PE sections have simultaneous IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE flags.",
        })
    else:
        checks.append({
            "id": "rwx",
            "title": "W^X Section Permission Hygiene",
            "status": "PASS",
            "value": "No W+X section requested",
            "detail": "No PE sections allow simultaneous Write and Execute permissions.",
        })

    # 8. Force Integrity & Pre-Main TLS Callback Inspection
    force_integrity = bool(dll_characteristics & 0x0080)
    if tls_callbacks:
        checks.append({
            "id": "tls_integrity",
            "title": "TLS Pre-Entry Callbacks & Image Integrity",
            "status": "WARN",
            "value": f"{len(tls_callbacks)} TLS Callback(s): {', '.join(tls_callbacks[:2])}",
            "detail": "IMAGE_DIRECTORY_ENTRY_TLS lists callbacks that the loader calls before AddressOfEntryPoint, and again on thread creation and exit. Legitimate runtimes use them; so do anti-debugging tricks.",
        })
    elif force_integrity:
        checks.append({
            "id": "tls_integrity",
            "title": "TLS Pre-Entry Callbacks & Image Integrity",
            "status": "PASS",
            "value": "FORCE_INTEGRITY Enabled • No TLS Callbacks",
            "detail": "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY asks Windows to refuse to load the image unless its signature verifies; no TLS callbacks are registered.",
        })
    else:
        checks.append({
            "id": "tls_integrity",
            "title": "TLS Pre-Entry Callbacks & Image Integrity",
            "status": "PASS",
            "value": "Clean (No Pre-Main TLS Callbacks)",
            "detail": "No pre-main TLS callback hooks registered in IMAGE_DIRECTORY_ENTRY_TLS.",
        })

    # 9. Authenticode (WIN_CERTIFICATE). What is checked here is whether the blob
    #    contains this file's image hash; the signature and chain are never evaluated.
    cs_present = bool(code_sig_detail.get("present"))
    certs = code_sig_detail.get("cms_signature", {}).get("certificates", [])
    cert_names = [c.get("subject_cn", "") for c in certs if c.get("subject_cn")]
    auth = code_sig_detail.get("authenticode") or {}
    digest_ok = bool(auth.get("digest_in_signature"))
    sig_title = "Authenticode Digital Signature (WIN_CERTIFICATE)"
    not_evaluated = " The signature over that hash and the certificate chain are not evaluated here, and the name shown is the first certificate in the blob, which need not be the signer."
    if cs_present and digest_ok:
        signer = cert_names[0] if cert_names else "PKCS#7 SignedData"
        checks.append({
            "id": "codesign",
            "title": sig_title,
            "status": "PASS",
            "value": f"Signature present; image hash matches ({signer})",
            "detail": f"The certificate table ({code_sig_detail.get('length', 0):,} bytes) contains this file's Authenticode image hash ({str(auth.get('algorithm', '')).upper()} {auth.get('image_digest', '')}), so the signed content is this file's content." + not_evaluated,
        })
    elif cs_present and auth.get("not_computed"):
        checks.append({
            "id": "codesign",
            "title": sig_title,
            "status": "WARN",
            "value": "Certificate table present; image hash not computed",
            "detail": f"A WIN_CERTIFICATE table is present ({code_sig_detail.get('length', 0):,} bytes), but this file's Authenticode image hash was not computed: {auth['not_computed']}." + not_evaluated,
        })
    elif cs_present:
        signer = cert_names[0] if cert_names else "PKCS#7 SignedData"
        checks.append({
            "id": "codesign",
            "title": sig_title,
            "status": "WARN",
            "value": f"Certificate table present; image hash not found in it ({signer})",
            "detail": f"A WIN_CERTIFICATE table is present ({code_sig_detail.get('length', 0):,} bytes), but it does not contain this file's Authenticode image hash ({str(auth.get('algorithm', '') or 'sha256').upper()} {auth.get('image_digest', '')}): the file was changed after signing, the blob is not an Authenticode signature of this file, or it uses a digest this tool does not compute." + not_evaluated,
        })
    else:
        checks.append({
            "id": "codesign",
            "title": sig_title,
            "status": "INFO" if subsystem != 1 else "FAIL",
            "value": "Unsigned (No CERTIFICATE_TABLE)",
            "detail": "No embedded Authenticode WIN_CERTIFICATE table in DataDirectory[4]. The file may still be catalog-signed, which cannot be seen from the file itself.",
        })

    # Symbols: a PE image is "stripped" when it carries no COFF symbol table. Debug
    # information normally lives outside the image (a PDB named by the debug directory).
    coff_symbols = bool(symbol_info.get("coff_symbol_table"))

    return {
        "pie": is_aslr,
        "arc": nx_compat,
        "dep_in_effect": dep_in_effect,
        "stack_canary": has_gs,
        "pac_enabled": cfg_effective,
        "cfg_declared": guard_cf,
        "cfg_instrumented": cfg_instrumented and cfg_table,
        "has_rwx_segments": has_rwx,
        "has_restrict_segment": force_integrity or guard_cf,
        "is_encrypted": False,
        "stripped_symbols": not coff_symbols,
        "symbols_state": symbol_info.get("summary", ""),
        "code_signature": {
            # `present`: a certificate table exists. `cdhash` is the Authenticode image hash and
            # `cdhash_verified` says the table contains it; the signature itself is never verified.
            "present": cs_present,
            "is_adhoc": False,
            "hardened_runtime": False,
            "library_validation": force_integrity,
            "cdhash": auth.get("image_digest", "") if cs_present else "",
            "cdhash_verified": cs_present and digest_ok,
            "identifier": cert_names[0] if cert_names else "",
            "team_id": "Authenticode PKCS#7" if cs_present else "",
            "certificates": cert_names,
        },
        "checks": checks,
    }


def parse_pe_slice(full_data: bytes, path: str = "<memory>") -> Dict[str, Any]:
    if not is_pe_bytes(full_data):
        raise BinaryFormatError("Invalid Windows PE header (expected 'MZ' + valid e_lfanew -> 'PE\\0\\0').")

    file_size = len(full_data)
    buf = BinaryBuffer(full_data, slice_base=0, slice_size=file_size, little_endian=True)

    # ------------------------------------------------------------------------
    # 1. Parse IMAGE_DOS_HEADER (0x00..0x40) & Rich Header
    # ------------------------------------------------------------------------
    dos_buf = buf.clone_with_fields()
    e_magic = dos_buf.u16(0)
    e_cblp = dos_buf.u16(2)
    e_cp = dos_buf.u16(4)
    e_lfarlc = dos_buf.u16(0x18)
    e_lfanew = dos_buf.u32(0x3C)

    dos_buf.record_field("e_magic", "uint16", 0, 2, e_magic, f"0x{e_magic:04x}", "MZ (IMAGE_DOS_SIGNATURE)", "MS-DOS MZ executable magic")
    dos_buf.record_field("e_cblp", "uint16", 2, 2, e_cblp, str(e_cblp), f"{e_cblp} bytes", "Bytes on last page of file")
    dos_buf.record_field("e_cp", "uint16", 4, 2, e_cp, str(e_cp), f"{e_cp} pages", "Pages in file")
    dos_buf.record_field("e_lfarlc", "uint16", 0x18, 2, e_lfarlc, f"0x{e_lfarlc:x}", f"Offset 0x{e_lfarlc:x}", "File address of relocation table")
    dos_buf.record_field("e_lfanew", "uint32", 0x3C, 4, e_lfanew, f"0x{e_lfanew:x}", f"NT Headers @ 0x{e_lfanew:x}", "File offset to IMAGE_NT_HEADERS", target_offset=e_lfanew)

    load_commands: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    intervals: List[Dict[str, Any]] = [
        {"id": "dos_header", "label": "IMAGE_DOS_HEADER", "category": "header", "abs_offset": 0, "size": 64, "vmaddr": None}
    ]

    load_commands.append({
        "index": 0,
        "cmd": IMAGE_DOS_SIGNATURE,
        "cmd_hex": "0x5a4d",
        "cmd_name": "IMAGE_DOS_HEADER",
        "cmdsize": 64,
        "req_dyld": False,
        "summary": f"MZ Header -> e_lfanew = 0x{e_lfanew:x}",
        "region": make_region(0, 0, 64),
        "fields": dos_buf.get_fields(),
        "details": {"e_lfanew": f"0x{e_lfanew:x}"},
    })

    rich_info = _parse_rich_header(buf, e_lfanew)
    if rich_info:
        load_commands.append({
            "index": len(load_commands),
            "cmd": 0x68636952,
            "cmd_hex": "0x68636952",
            "cmd_name": "IMAGE_RICH_HEADER",
            "cmdsize": rich_info["size"],
            "req_dyld": False,
            "summary": f"MSVC Toolchain Fingerprint ({len(rich_info['entries'])} @comp.id records, XOR {rich_info['xor_key']})",
            "region": rich_info["region"],
            "fields": rich_info["fields"],
            "details": {"xor_key": rich_info["xor_key"], "entries": rich_info["entries"]},
        })
        intervals.append({
            "id": "rich_header",
            "label": "Rich Header (MSVC)",
            "category": "header",
            "abs_offset": rich_info["offset"],
            "size": rich_info["size"],
            "vmaddr": None,
        })

    # ------------------------------------------------------------------------
    # 2. Parse IMAGE_NT_HEADERS (Signature + COFF FileHeader + OptionalHeader)
    # ------------------------------------------------------------------------
    nt_buf = buf.clone_with_fields()
    nt_sig = nt_buf.u32(e_lfanew)
    coff_off = e_lfanew + 4
    machine = nt_buf.u16(coff_off)
    num_sections = nt_buf.u16(coff_off + 2)
    time_date_stamp = nt_buf.u32(coff_off + 4)
    ptr_symtab = nt_buf.u32(coff_off + 8)
    num_syms = nt_buf.u32(coff_off + 12)
    size_opt_hdr = nt_buf.u16(coff_off + 16)
    characteristics = nt_buf.u16(coff_off + 18)

    arch_short, machine_macro, arch_display = PE_MACHINE_INFO.get(
        machine, (f"pe_mach_0x{machine:x}", f"IMAGE_FILE_MACHINE_0x{machine:x}", f"PE Machine 0x{machine:x}")
    )
    char_names, char_bits = _decode_bitflags(characteristics, FILE_CHARACTERISTICS_FLAGS)
    try:
        ts_str = datetime.datetime.fromtimestamp(time_date_stamp, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        ts_str = f"0x{time_date_stamp:08x}"

    nt_buf.record_field("Signature", "uint32", e_lfanew, 4, nt_sig, f"0x{nt_sig:08x}", "PE\\0\\0 (IMAGE_NT_SIGNATURE)", "Portable Executable signature")
    nt_buf.record_field("FileHeader.Machine", "uint16", coff_off, 2, machine, f"0x{machine:04x}", f"{machine_macro} ({arch_display})", "Target CPU architecture")
    nt_buf.record_field("FileHeader.NumberOfSections", "uint16", coff_off + 2, 2, num_sections, str(num_sections), f"{num_sections} sections", "Number of section headers")
    nt_buf.record_field("FileHeader.TimeDateStamp", "uint32", coff_off + 4, 4, time_date_stamp, f"0x{time_date_stamp:08x}", ts_str, "Link time, seconds since 1970-01-01 UTC (a hash, not a time, in reproducible builds)")
    nt_buf.record_field("FileHeader.PointerToSymbolTable", "uint32", coff_off + 8, 4, ptr_symtab, f"0x{ptr_symtab:x}")
    nt_buf.record_field("FileHeader.NumberOfSymbols", "uint32", coff_off + 12, 4, num_syms, str(num_syms))
    nt_buf.record_field("FileHeader.SizeOfOptionalHeader", "uint16", coff_off + 16, 2, size_opt_hdr, f"{size_opt_hdr} (0x{size_opt_hdr:x})", f"{size_opt_hdr} bytes")
    nt_buf.record_field("FileHeader.Characteristics", "uint16", coff_off + 18, 2, characteristics, f"0x{characteristics:04x}", " | ".join(char_names) or "0x0", "COFF file characteristics", bit_flags=char_bits)

    opt_off = coff_off + 20
    opt_magic = nt_buf.u16(opt_off) if opt_off + 2 <= file_size else IMAGE_NT_OPTIONAL_HDR64_MAGIC
    is_64 = (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    magic_name = "PE32+ (64-bit)" if is_64 else "PE32 (32-bit)"

    maj_linker = nt_buf.u8(opt_off + 2)
    min_linker = nt_buf.u8(opt_off + 3)
    size_of_code = nt_buf.u32(opt_off + 4)
    size_init_data = nt_buf.u32(opt_off + 8)
    size_uninit_data = nt_buf.u32(opt_off + 12)
    entry_rva = nt_buf.u32(opt_off + 16)
    base_of_code = nt_buf.u32(opt_off + 20)

    if is_64:
        image_base = nt_buf.u64(opt_off + 24)
        sect_align = nt_buf.u32(opt_off + 32)
        file_align = nt_buf.u32(opt_off + 36)
        maj_os = nt_buf.u16(opt_off + 40)
        min_os = nt_buf.u16(opt_off + 42)
        maj_subsys = nt_buf.u16(opt_off + 48)
        min_subsys = nt_buf.u16(opt_off + 50)
        size_of_image = nt_buf.u32(opt_off + 56)
        size_of_headers = nt_buf.u32(opt_off + 60)
        checksum = nt_buf.u32(opt_off + 64)
        subsystem = nt_buf.u16(opt_off + 68)
        dll_chars = nt_buf.u16(opt_off + 70)
        num_rva_and_sizes = nt_buf.u32(opt_off + 108)
        dd_off = opt_off + 112
    else:
        base_of_data = nt_buf.u32(opt_off + 24)
        image_base = nt_buf.u32(opt_off + 28)
        sect_align = nt_buf.u32(opt_off + 32)
        file_align = nt_buf.u32(opt_off + 36)
        maj_os = nt_buf.u16(opt_off + 40)
        min_os = nt_buf.u16(opt_off + 42)
        maj_subsys = nt_buf.u16(opt_off + 48)
        min_subsys = nt_buf.u16(opt_off + 50)
        size_of_image = nt_buf.u32(opt_off + 56)
        size_of_headers = nt_buf.u32(opt_off + 60)
        checksum = nt_buf.u32(opt_off + 64)
        subsystem = nt_buf.u16(opt_off + 68)
        dll_chars = nt_buf.u16(opt_off + 70)
        num_rva_and_sizes = nt_buf.u32(opt_off + 92)
        dd_off = opt_off + 96

    subsys_name = PE_SUBSYSTEM_NAMES.get(subsystem, f"SUBSYSTEM_{subsystem}")
    dll_char_names, dll_char_bits = _decode_bitflags(dll_chars, DLL_CHARACTERISTICS_FLAGS)

    nt_buf.record_field("OptionalHeader.Magic", "uint16", opt_off, 2, opt_magic, f"0x{opt_magic:04x}", magic_name, "Optional Header format magic")
    nt_buf.record_field("OptionalHeader.LinkerVersion", "uint16", opt_off + 2, 2, (maj_linker << 8) | min_linker, f"{maj_linker}.{min_linker}", f"Linker version {maj_linker}.{min_linker}")
    nt_buf.record_field("OptionalHeader.SizeOfCode", "uint32", opt_off + 4, 4, size_of_code, f"0x{size_of_code:x}", f"{size_of_code:,} bytes")
    nt_buf.record_field("OptionalHeader.AddressOfEntryPoint", "uint32", opt_off + 16, 4, entry_rva, f"0x{entry_rva:x}", f"RVA 0x{entry_rva:x} (VM 0x{image_base + entry_rva:x})", "Entry point RVA relative to ImageBase", target_vmaddr=f"0x{image_base + entry_rva:x}" if entry_rva else None)
    nt_buf.record_field("OptionalHeader.BaseOfCode", "uint32", opt_off + 20, 4, base_of_code, f"0x{base_of_code:x}")
    if is_64:
        nt_buf.record_field("OptionalHeader.ImageBase", "uint64", opt_off + 24, 8, image_base, f"0x{image_base:x}", f"0x{image_base:x}", "Preferred virtual base address in memory")
    else:
        nt_buf.record_field("OptionalHeader.ImageBase", "uint32", opt_off + 28, 4, image_base, f"0x{image_base:x}", f"0x{image_base:x}", "Preferred virtual base address in memory")
    nt_buf.record_field("OptionalHeader.SectionAlignment", "uint32", opt_off + 32, 4, sect_align, f"0x{sect_align:x}", f"{sect_align:,} bytes (VM Page Alignment)")
    nt_buf.record_field("OptionalHeader.FileAlignment", "uint32", opt_off + 36, 4, file_align, f"0x{file_align:x}", f"{file_align:,} bytes (Disk Sector Alignment)")
    nt_buf.record_field("OptionalHeader.SizeOfImage", "uint32", opt_off + 56, 4, size_of_image, f"0x{size_of_image:x}", f"{size_of_image:,} bytes")
    nt_buf.record_field("OptionalHeader.SizeOfHeaders", "uint32", opt_off + 60, 4, size_of_headers, f"0x{size_of_headers:x}", f"{size_of_headers:,} bytes")
    nt_buf.record_field("OptionalHeader.CheckSum", "uint32", opt_off + 64, 4, checksum, f"0x{checksum:08x}", f"0x{checksum:08x}")
    nt_buf.record_field("OptionalHeader.Subsystem", "uint16", opt_off + 68, 2, subsystem, str(subsystem), subsys_name, "Windows execution subsystem")
    nt_buf.record_field("OptionalHeader.DllCharacteristics", "uint16", opt_off + 70, 2, dll_chars, f"0x{dll_chars:04x}", " | ".join(dll_char_names) or "0x0", "Exploit mitigation & loader flags", bit_flags=dll_char_bits)

    nt_hdr_total_size = 24 + size_opt_hdr
    header_fields = nt_buf.reset_fields()

    intervals.append({
        "id": "mach_header",
        "label": "IMAGE_NT_HEADERS",
        "category": "header",
        "abs_offset": e_lfanew,
        "size": nt_hdr_total_size,
        "vmaddr": f"0x{image_base + e_lfanew:x}",
    })

    # ------------------------------------------------------------------------
    # 3. Parse IMAGE_SECTION_HEADER Table -> segments & sections
    # ------------------------------------------------------------------------
    sect_table_off = opt_off + size_opt_hdr
    max_sects = min(num_sections, ANALYSIS_LIMITS["pe_sections"])
    if num_sections > max_sects:
        add_warning(warnings, "sections_truncated", f"NumberOfSections is {num_sections:,}; only the first {max_sects} section headers are parsed (the Windows loader limit).", limit=max_sects, total=num_sections)
    segments: List[Dict[str, Any]] = []
    all_sections_ordered: List[Dict[str, Any]] = []

    # First pseudo-segment: HEADERS
    hdr_end_off = min(file_size, size_of_headers or sect_table_off + max_sects * 40)
    segments.append({
        "index": 0,
        "segname": "HEADERS",
        "vmaddr": f"0x{image_base:x}",
        "vmaddr_int": image_base,
        "vmsize": f"0x{max(hdr_end_off, sect_align or 0x1000):x}",
        "vmsize_int": max(hdr_end_off, sect_align or 0x1000),
        "fileoff": 0,
        "filesize": hdr_end_off,
        "abs_offset": 0,
        "initprot": "r--",
        "maxprot": "r--",
        "initprot_raw": 1,
        "maxprot_raw": 1,
        "nsects": 0,
        "flags": 0,
        "flags_decoded": ["PE_HEADERS"],
        "region": make_region(0, 0, hdr_end_off, f"0x{image_base:x}", max(hdr_end_off, sect_align or 0x1000)),
        "header_region": make_region(e_lfanew, e_lfanew, nt_hdr_total_size),
        "fields": header_fields,
        "sections": [],
    })

    for s_idx in range(max_sects):
        sh_off = sect_table_off + s_idx * 40
        if sh_off + 40 > file_size:
            break
        s_buf = buf.clone_with_fields()
        sname = s_buf.fixed_cstr(sh_off, 8) or f"sect_{s_idx}"
        v_size = s_buf.u32(sh_off + 8)
        v_addr = s_buf.u32(sh_off + 12)
        raw_size = s_buf.u32(sh_off + 16)
        raw_ptr = s_buf.u32(sh_off + 20)
        reloc_ptr = s_buf.u32(sh_off + 24)
        lineno_ptr = s_buf.u32(sh_off + 28)
        num_relocs = s_buf.u16(sh_off + 32)
        num_linenos = s_buf.u16(sh_off + 34)
        scn_chars = s_buf.u32(sh_off + 36)

        prot_str, prot_raw, scn_flag_names, scn_flag_bits = _scn_to_prot(scn_chars)
        s_vm = image_base + v_addr
        # Size in memory is VirtualSize (the loader rounds it up to SectionAlignment); only
        # when a linker left VirtualSize at 0 does SizeOfRawData stand in for it. SizeOfRawData
        # is the size on disk, rounded up to FileAlignment, and may be larger or smaller.
        eff_vmsz = v_size if v_size else raw_size

        s_buf.record_field("Name", "char[8]", sh_off, 8, sname, sname, sname, "Section name")
        s_buf.record_field("VirtualSize", "uint32", sh_off + 8, 4, v_size, f"0x{v_size:x}", f"{v_size:,} bytes", "Size in virtual memory")
        s_buf.record_field("VirtualAddress", "uint32", sh_off + 12, 4, v_addr, f"0x{v_addr:x}", f"RVA 0x{v_addr:x} (VM 0x{s_vm:x})", "Section RVA", target_vmaddr=f"0x{s_vm:x}")
        s_buf.record_field("SizeOfRawData", "uint32", sh_off + 16, 4, raw_size, f"0x{raw_size:x}", f"{raw_size:,} bytes", "Initialized size on disk")
        s_buf.record_field("PointerToRawData", "uint32", sh_off + 20, 4, raw_ptr, f"0x{raw_ptr:x}", f"File offset 0x{raw_ptr:x}", "File offset of section data", target_offset=raw_ptr if raw_size > 0 else None)
        s_buf.record_field("Characteristics", "uint32", sh_off + 36, 4, scn_chars, f"0x{scn_chars:08x}", " | ".join(scn_flag_names) or "0x0", "Section flags & permissions", bit_flags=scn_flag_bits)

        is_exec = "x" in prot_str
        is_zerofill = (raw_size == 0 and v_size > 0)
        sec_type_str = "CNT_CODE" if (scn_chars & 0x20) else ("CNT_UNINITIALIZED_DATA" if is_zerofill else "CNT_INITIALIZED_DATA")

        sec_obj = {
            "index": len(all_sections_ordered),
            "sectname": sname,
            "segname": sname,
            "rva": v_addr,
            "vmaddr": f"0x{s_vm:x}",
            "vmaddr_int": s_vm,
            "size": eff_vmsz,
            "virtual_size": v_size,
            "raw_size": raw_size,
            "slice_offset": raw_ptr,
            "abs_offset": raw_ptr,
            "align": sect_align,
            "align_bytes": max(1, sect_align),
            "reloff": reloc_ptr,
            "nreloc": num_relocs,
            "flags": scn_chars,
            "flags_hex": f"0x{scn_chars:08x}",
            "section_type": sec_type_str,
            "attributes_decoded": scn_flag_names,
            "reserved1": 0,
            "reserved2": 0,
            "is_executable": is_exec,
            "is_zerofill": is_zerofill,
            "prot": prot_str,
            "region": make_region(raw_ptr, raw_ptr, raw_size, f"0x{s_vm:x}", eff_vmsz),
            "header_region": make_region(sh_off, sh_off, 40),
            "fields": s_buf.get_fields(),
        }
        all_sections_ordered.append(sec_obj)

        seg_obj = {
            "index": len(segments),
            "segname": sname,
            "vmaddr": f"0x{s_vm:x}",
            "vmaddr_int": s_vm,
            "vmsize": f"0x{eff_vmsz:x}",
            "vmsize_int": eff_vmsz,
            "fileoff": raw_ptr,
            "filesize": raw_size,
            "abs_offset": raw_ptr,
            "initprot": prot_str,
            "maxprot": prot_str,
            "initprot_raw": prot_raw,
            "maxprot_raw": prot_raw,
            "nsects": 1,
            "flags": scn_chars,
            "flags_decoded": scn_flag_names,
            "region": make_region(raw_ptr, raw_ptr, raw_size, f"0x{s_vm:x}", eff_vmsz),
            "header_region": make_region(sh_off, sh_off, 40),
            "fields": sec_obj["fields"],
            "sections": [sec_obj],
        }
        segments.append(seg_obj)

        if raw_size > 0 and raw_ptr > 0:
            intervals.append({
                "id": f"sect_{sname}_{sname}",
                "label": f"PE Section {sname}",
                "category": "code" if is_exec else "section",
                "abs_offset": raw_ptr,
                "size": raw_size,
                "vmaddr": f"0x{s_vm:x}",
            })

    # RVA -> File Offset translator
    rva_table = [
        (sec["rva"], sec["rva"] + max(sec["size"], sec["raw_size"]), sec["raw_size"], sec["slice_offset"])
        for sec in all_sections_ordered
    ]

    def rva_to_file_off(rva: int) -> Optional[int]:
        if rva <= 0:
            return None
        for s_rva, s_end, s_raw, s_off in rva_table:
            if s_rva <= rva < s_end:
                delta = rva - s_rva
                if delta < s_raw:
                    return s_off + delta
        if rva < hdr_end_off:
            return rva
        return None

    # ------------------------------------------------------------------------
    # 4. Parse IMAGE_DATA_DIRECTORY[16]
    # ------------------------------------------------------------------------
    data_dirs: Dict[str, Tuple[int, int, int]] = {}  # name -> (rva, size, dir_entry_off)
    max_dirs = min(num_rva_and_sizes, 16)
    for d_idx in range(max_dirs):
        d_pos = dd_off + d_idx * 8
        if d_pos + 8 > opt_off + size_opt_hdr or d_pos + 8 > file_size:
            break
        d_rva = buf.u32(d_pos)
        d_sz = buf.u32(d_pos + 4)
        d_name = DATA_DIRECTORY_NAMES[d_idx]
        data_dirs[d_name] = (d_rva, d_sz, d_pos)
        if d_rva == 0 and d_sz == 0:
            continue

        # Note: CERTIFICATE_TABLE VirtualAddress is a raw file offset!
        is_cert = (d_name == "CERTIFICATE_TABLE")
        target_foff = d_rva if is_cert else rva_to_file_off(d_rva)
        target_vm = None if is_cert else f"0x{image_base + d_rva:x}"

        d_buf = buf.clone_with_fields()
        d_buf.record_field(
            "VirtualAddress",
            "uint32",
            d_pos,
            4,
            d_rva,
            f"0x{d_rva:x}",
            f"File Offset 0x{d_rva:x}" if is_cert else f"RVA 0x{d_rva:x} (File 0x{(target_foff or 0):x})",
            "File offset of WIN_CERTIFICATE" if is_cert else f"RVA of {d_name}",
            target_offset=target_foff,
            target_vmaddr=target_vm,
        )
        d_buf.record_field("Size", "uint32", d_pos + 4, 4, d_sz, f"0x{d_sz:x}", f"{d_sz:,} bytes", f"Byte size of {d_name}")

        load_commands.append({
            "index": len(load_commands),
            "cmd": d_idx,
            "cmd_hex": f"0x{d_idx:x}",
            "cmd_name": f"DATA_DIR_{d_name}",
            "cmdsize": 8,
            "req_dyld": d_name in ("IMPORT_TABLE", "IAT", "BASE_RELOCATION_TABLE"),
            "summary": f"{'FileOff' if is_cert else 'RVA'} 0x{d_rva:x} ({d_sz:,} bytes)",
            "region": make_region(target_foff or d_pos, target_foff or d_pos, d_sz if target_foff else 8, target_vm, d_sz),
            "fields": d_buf.get_fields(),
            "details": {"rva": f"0x{d_rva:x}", "size": d_sz, "file_offset": target_foff},
        })

    # ------------------------------------------------------------------------
    # 5. Parse Imports (IMAGE_IMPORT_DESCRIPTOR)
    # ------------------------------------------------------------------------
    dylibs: List[Dict[str, Any]] = []
    imports_list: List[Dict[str, Any]] = []
    symbols: List[Dict[str, Any]] = []
    indirect_symbols: List[Dict[str, Any]] = []

    imp_rva, imp_sz, _ = data_dirs.get("IMPORT_TABLE", (0, 0, 0))
    imp_foff = rva_to_file_off(imp_rva)
    imp_limit = ANALYSIS_LIMITS["imports"]
    if imp_foff is not None and imp_foff + 20 <= file_size:
        cur_imp = imp_foff
        for _ in range(ANALYSIS_LIMITS["pe_import_descriptors"]):
            runtime.check_deadline()
            if cur_imp + 20 > file_size:
                break
            if len(imports_list) >= imp_limit:
                add_warning(warnings, "imports_truncated", f"Only the first {imp_limit:,} imports are listed.", limit=imp_limit)
                break
            orig_first_thunk = buf.u32(cur_imp)
            imp_ts = buf.u32(cur_imp + 4)
            fwd_chain = buf.u32(cur_imp + 8)
            name_rva = buf.u32(cur_imp + 12)
            first_thunk = buf.u32(cur_imp + 16)
            if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break

            name_foff = rva_to_file_off(name_rva)
            dll_name = buf.cstr_at(name_foff, 128)[0] if name_foff is not None else f"dll_0x{name_rva:x}"
            lib_ord = len(dylibs) + 1
            dylibs.append({
                "index": len(dylibs),
                "cmd_name": "IMAGE_IMPORT_DESCRIPTOR",
                "name": dll_name,
                "current_version": f"ILT 0x{orig_first_thunk:x}",
                "compat_version": f"IAT 0x{first_thunk:x}",
                "timestamp": imp_ts,
                "is_weak": False,
                "is_reexport": False,
            })

            thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
            thunk_foff = rva_to_file_off(thunk_rva)
            ptr_sz = 8 if is_64 else 4
            ord_flag = (1 << 63) if is_64 else (1 << 31)

            if thunk_foff is not None:
                for t_idx in range(ANALYSIS_LIMITS["pe_thunks_per_dll"]):
                    if len(imports_list) >= imp_limit:
                        add_warning(warnings, "imports_truncated", f"Only the first {imp_limit:,} imports are listed.", limit=imp_limit)
                        break
                    runtime.check_deadline()
                    t_pos = thunk_foff + t_idx * ptr_sz
                    if t_pos + ptr_sz > file_size:
                        break
                    t_val = buf.u64(t_pos) if is_64 else buf.u32(t_pos)
                    if t_val == 0:
                        break
                    if t_val & ord_flag:
                        ord_num = t_val & 0xFFFF
                        fn_name = f"Ordinal#{ord_num}"
                    else:
                        hn_rva = t_val & 0x7FFFFFFF
                        hn_foff = rva_to_file_off(hn_rva)
                        if hn_foff is not None and hn_foff + 2 < file_size:
                            fn_name, _ = buf.cstr_at(hn_foff + 2, 256)
                        else:
                            fn_name = f"import_0x{hn_rva:x}"

                    iat_slot_vm = image_base + first_thunk + t_idx * ptr_sz if first_thunk else 0
                    iat_slot_foff = rva_to_file_off(first_thunk + t_idx * ptr_sz) if first_thunk else t_pos

                    imports_list.append({
                        "index": len(imports_list),
                        "name": fn_name,
                        "lib_ordinal": lib_ord,
                        "lib_name": dll_name,
                        "weak_import": False,
                    })
                    symbols.append({
                        "index": len(symbols),
                        "name": fn_name,
                        "demangled": fn_name,
                        "n_type": 0,
                        "type_name": "UNDF",
                        "is_stab": False,
                        "is_external": True,
                        "is_private_ext": False,
                        "is_weak": False,
                        "n_sect": 0,
                        "section_name": ".idata",
                        "n_desc": 0,
                        "library_ordinal": lib_ord,
                        "library_name": dll_name,
                        "n_value": f"0x{iat_slot_vm:x}",
                        "n_value_int": iat_slot_vm,
                        "abs_offset": iat_slot_foff or t_pos,
                        "slice_offset": iat_slot_foff or t_pos,
                        "size": ptr_sz,
                        "target_abs_offset": iat_slot_foff,
                    })
                    if iat_slot_vm:
                        indirect_symbols.append({
                            "section_name": f"IAT ({dll_name})",
                            "slot_index": len(indirect_symbols),
                            "slot_vmaddr": f"0x{iat_slot_vm:x}",
                            "indirect_value": len(imports_list) - 1,
                            "symbol_name": fn_name,
                        })

            cur_imp += 20

    # ------------------------------------------------------------------------
    # 6. Parse Exports (IMAGE_EXPORT_DIRECTORY)
    # ------------------------------------------------------------------------
    exports_list: List[Dict[str, Any]] = []
    exp_rva, exp_sz, _ = data_dirs.get("EXPORT_TABLE", (0, 0, 0))
    exp_foff = rva_to_file_off(exp_rva)
    if exp_foff is not None and exp_foff + 40 <= file_size:
        ord_base = buf.u32(exp_foff + 16)
        exp_limit = ANALYSIS_LIMITS["exports"]
        declared_funcs = buf.u32(exp_foff + 20)
        declared_names = buf.u32(exp_foff + 24)
        num_funcs = min(declared_funcs, exp_limit)
        num_names = min(declared_names, exp_limit)
        if declared_funcs > exp_limit or declared_names > exp_limit:
            add_warning(warnings, "exports_truncated", f"Export directory declares {max(declared_funcs, declared_names):,} entries; only the first {exp_limit:,} are listed.", limit=exp_limit, total=max(declared_funcs, declared_names))
        addr_funcs_rva = buf.u32(exp_foff + 28)
        addr_names_rva = buf.u32(exp_foff + 32)
        addr_ords_rva = buf.u32(exp_foff + 36)

        funcs_foff = rva_to_file_off(addr_funcs_rva)
        names_foff = rva_to_file_off(addr_names_rva)
        ords_foff = rva_to_file_off(addr_ords_rva)

        ord_to_name: Dict[int, str] = {}
        if names_foff is not None and ords_foff is not None:
            for i in range(num_names):
                runtime.check_deadline()
                if names_foff + (i + 1) * 4 > file_size or ords_foff + (i + 1) * 2 > file_size:
                    break
                n_rva = buf.u32(names_foff + i * 4)
                o_idx = buf.u16(ords_foff + i * 2)
                n_foff = rva_to_file_off(n_rva)
                if n_foff is not None:
                    ord_to_name[o_idx] = buf.cstr_at(n_foff, 256)[0]

        if funcs_foff is not None:
            for f_idx in range(num_funcs):
                runtime.check_deadline()
                if funcs_foff + (f_idx + 1) * 4 > file_size:
                    break
                fn_rva = buf.u32(funcs_foff + f_idx * 4)
                if fn_rva == 0:
                    continue
                raw_exp_name = ord_to_name.get(f_idx, f"Ordinal_{ord_base + f_idx}")
                exp_name = raw_exp_name
                is_forwarder = (exp_rva <= fn_rva < exp_rva + exp_sz)
                fn_vm = image_base + fn_rva
                fn_foff = rva_to_file_off(fn_rva)
                flags_dec = ["EXPORT_FORWARDER"] if is_forwarder else ["EXPORT_REGULAR"]
                fwd_target: Optional[str] = None
                if is_forwarder and fn_foff is not None:
                    fwd_target, _ = buf.cstr_at(fn_foff, 128)
                    exp_name = f"{raw_exp_name} -> {fwd_target}"

                exports_list.append({
                    "name": raw_exp_name,
                    "display_name": exp_name,
                    "forwarder": fwd_target,
                    "vmaddr": f"0x{fn_vm:x}",
                    "offset": fn_rva,
                    "flags": ord_base + f_idx,
                    "flags_decoded": flags_dec,
                })
                symbols.append({
                    "index": len(symbols),
                    "name": ord_to_name.get(f_idx, f"Ordinal_{ord_base + f_idx}"),
                    "demangled": exp_name,
                    "n_type": 0x0F,
                    "type_name": "SECT",
                    "is_stab": False,
                    "is_external": True,
                    "is_private_ext": False,
                    "is_weak": False,
                    "n_sect": 1,
                    "section_name": ".text",
                    "n_desc": 0,
                    "library_ordinal": 0,
                    "library_name": "EXPORT",
                    "n_value": f"0x{fn_vm:x}",
                    "n_value_int": fn_vm,
                    "abs_offset": fn_foff or (funcs_foff + f_idx * 4),
                    "slice_offset": fn_foff or (funcs_foff + f_idx * 4),
                    "size": 4,
                    "target_abs_offset": fn_foff,
                })

    # ------------------------------------------------------------------------
    # 7. Parse Base Relocations (IMAGE_BASE_RELOCATION in .reloc)
    # ------------------------------------------------------------------------
    fixups_preview: List[Dict[str, Any]] = []
    reloc_blocks_count = 0
    rel_rva, rel_sz, _ = data_dirs.get("BASE_RELOCATION_TABLE", (0, 0, 0))
    rel_foff = rva_to_file_off(rel_rva)
    if rel_foff is not None and rel_sz >= 8:
        cur_rel = rel_foff
        end_rel = min(file_size, rel_foff + rel_sz)
        # Blocks are counted over the whole table (up to a cap) but only the first
        # entries are decoded for preview; the scan itself is bounded so a table of
        # padding entries cannot turn into millions of iterations.
        entries_budget = ANALYSIS_LIMITS["pe_base_reloc_entries"]
        while cur_rel + 8 <= end_rel and reloc_blocks_count < ANALYSIS_LIMITS["pe_base_reloc_blocks"]:
            runtime.check_deadline()
            page_rva = buf.u32(cur_rel)
            block_sz = buf.u32(cur_rel + 4)
            if block_sz < 8 or cur_rel + block_sz > end_rel:
                break
            reloc_blocks_count += 1
            n_entries = (block_sz - 8) // 2
            if len(fixups_preview) >= 128 or entries_budget <= 0:
                cur_rel += block_sz
                continue
            scan = min(n_entries, entries_budget)
            entries_budget -= scan
            for e_idx in range(scan):
                if len(fixups_preview) >= 128:
                    break
                word = buf.u16(cur_rel + 8 + e_idx * 2)
                r_type = (word >> 12) & 0xF
                r_off = word & 0xFFF
                if r_type == 0:  # IMAGE_REL_BASED_ABSOLUTE padding
                    continue
                target_rva = page_rva + r_off
                target_vm = image_base + target_rva
                target_foff = rva_to_file_off(target_rva) or (cur_rel + 8 + e_idx * 2)
                fixups_preview.append({
                    "vmaddr": f"0x{target_vm:x}",
                    "abs_offset": target_foff,
                    "type": BASE_RELOC_TYPES.get(r_type, f"REL_BASED_{r_type}"),
                    "ordinal": None,
                    "symbol": f"Page 0x{page_rva:x} + 0x{r_off:x}",
                    "pac_key": None,
                    "diversity": 0,
                    "addr_div": False,
                })
            cur_rel += block_sz

    # ------------------------------------------------------------------------
    # 8. Parse Debug Directory (CodeView RSDS PDB GUID + Path)
    # ------------------------------------------------------------------------
    pdb_guid_str = ""
    pdb_path_str = ""
    debug_entries_list: List[Dict[str, Any]] = []
    debug_types: List[str] = []
    dbg_rva, dbg_sz, _ = data_dirs.get("DEBUG_DIRECTORY", (0, 0, 0))
    dbg_foff = rva_to_file_off(dbg_rva)
    if dbg_foff is not None and dbg_sz >= 28 and dbg_foff + 28 <= file_size:
        n_dbg = min(ANALYSIS_LIMITS["pe_debug_entries"], dbg_sz // 28)
        for i in range(n_dbg):
            d_off = dbg_foff + i * 28
            if d_off + 28 > file_size:
                break
            dbg_type = buf.u32(d_off + 12)
            sz_data = buf.u32(d_off + 16)
            ptr_raw = buf.u32(d_off + 24)
            debug_types.append(DEBUG_TYPE_NAMES.get(dbg_type, f"IMAGE_DEBUG_TYPE_{dbg_type}"))
            if dbg_type == 2 and not pdb_guid_str and ptr_raw + 24 <= file_size:  # IMAGE_DEBUG_TYPE_CODEVIEW
                cv_sig = buf.read_bytes(ptr_raw, 4)
                if cv_sig == b"RSDS":
                    raw_guid = buf.read_bytes(ptr_raw + 4, 16)
                    cv_age = buf.u32(ptr_raw + 20)
                    pdb_guid_str = f"{str(uuid.UUID(bytes_le=raw_guid)).upper()}-{cv_age}"
                    pdb_path_str, _ = buf.cstr_at(ptr_raw + 24, min(256, max(1, sz_data - 24)))
                    debug_entries_list.append({
                        "type": "IMAGE_DEBUG_TYPE_CODEVIEW (RSDS)",
                        "guid": pdb_guid_str,
                        "age": cv_age,
                        "pdb_path": pdb_path_str,
                        "abs_offset": ptr_raw,
                    })

    # Symbol state. "Stripped" for a PE means: no COFF symbol table in the image. MSVC never
    # writes one (its symbols go to a PDB that the debug directory names); MinGW and Go do
    # unless told to strip. The header's *_STRIPPED characteristics are recorded as declared.
    coff_symtab_present = ptr_symtab != 0 and num_syms > 0 and ptr_symtab < file_size
    debug_stripped_flag = bool(characteristics & 0x0200)
    if coff_symtab_present:
        sym_summary = f"COFF symbol table present ({num_syms:,} records)"
    else:
        sym_summary = "No COFF symbol table"
    if pdb_path_str:
        sym_summary += f"; debug info in a separate PDB ({os_filename(pdb_path_str)})"
    elif debug_types:
        sym_summary += f"; debug directory: {', '.join(sorted(set(debug_types)))}"
    else:
        sym_summary += "; no debug directory"
    if debug_stripped_flag:
        sym_summary += "; IMAGE_FILE_DEBUG_STRIPPED set"
    symbol_info = {
        "coff_symbol_table": coff_symtab_present,
        "coff_symbol_count": num_syms if coff_symtab_present else 0,
        "pointer_to_symbol_table": ptr_symtab,
        "debug_directory_types": debug_types,
        "pdb_referenced": bool(pdb_path_str),
        "debug_stripped_flag": debug_stripped_flag,                      # IMAGE_FILE_DEBUG_STRIPPED
        "line_nums_stripped_flag": bool(characteristics & 0x0004),      # deprecated, usually 0
        "local_syms_stripped_flag": bool(characteristics & 0x0008),     # deprecated, usually 0
        "summary": sym_summary,
    }

    # ------------------------------------------------------------------------
    # 9. Parse TLS Directory, Load Config & Exception Table (.pdata)
    # ------------------------------------------------------------------------
    tls_callbacks: List[str] = []
    tls_rva, tls_sz, _ = data_dirs.get("TLS_TABLE", (0, 0, 0))
    tls_foff = rva_to_file_off(tls_rva)
    if tls_foff is not None and tls_foff + (40 if is_64 else 24) <= file_size:
        cb_va = buf.u64(tls_foff + 24) if is_64 else buf.u32(tls_foff + 12)
        if cb_va > image_base:
            cb_foff = rva_to_file_off(cb_va - image_base)
            ptr_sz = 8 if is_64 else 4
            if cb_foff is not None:
                for i in range(16):
                    if cb_foff + (i + 1) * ptr_sz > file_size:
                        break
                    fn_va = buf.u64(cb_foff + i * ptr_sz) if is_64 else buf.u32(cb_foff + i * ptr_sz)
                    if fn_va == 0:
                        break
                    tls_callbacks.append(f"0x{fn_va:x}")

    # Load configuration. The structure starts with its own Size and has grown over the
    # years; a field exists only if Size reaches past it. (The data directory's size is
    # not reliable for this: 32-bit linkers write 0x40 there for compatibility.)
    load_config_info: Dict[str, Any] = {"present": False}
    lc_rva, lc_sz, _ = data_dirs.get("LOAD_CONFIG_TABLE", (0, 0, 0))
    lc_foff = rva_to_file_off(lc_rva)
    if lc_foff is not None and lc_foff + 4 <= file_size:
        lc_struct_size = buf.u32(lc_foff)
        lc_avail = max(0, min(lc_struct_size, file_size - lc_foff))
        ptr = 8 if is_64 else 4

        def lc_ptr(off: int) -> int:
            if off + ptr > lc_avail:
                return 0
            return buf.u64(lc_foff + off) if is_64 else buf.u32(lc_foff + off)

        def lc_u32(off: int) -> int:
            return buf.u32(lc_foff + off) if off + 4 <= lc_avail else 0

        o_cookie, o_seh, o_sehn, o_chk, o_disp, o_tbl, o_cnt, o_flags = (
            (88, 96, 104, 112, 120, 128, 136, 144) if is_64 else (60, 64, 68, 72, 76, 80, 84, 88)
        )
        guard_flags_val = lc_u32(o_flags)
        guard_names, _guard_bits = _decode_bitflags(guard_flags_val, GUARD_FLAGS)
        load_config_info = {
            "present": True,
            "abs_offset": lc_foff,
            "size": lc_struct_size,
            "directory_size": lc_sz,
            "security_cookie": lc_ptr(o_cookie),
            # SEHandlerTable / SEHandlerCount exist in both layouts but are used on x86 only.
            "se_handler_table": lc_ptr(o_seh) if machine == IMAGE_FILE_MACHINE_I386 else 0,
            "se_handler_count": lc_ptr(o_sehn) if machine == IMAGE_FILE_MACHINE_I386 else 0,
            "has_guard_fields": lc_avail >= o_flags + 4,
            "guard_cf_check_function_pointer": lc_ptr(o_chk),
            "guard_cf_dispatch_function_pointer": lc_ptr(o_disp),
            "guard_cf_function_table": lc_ptr(o_tbl),
            "guard_cf_function_count": lc_ptr(o_cnt),
            "guard_flags": guard_flags_val,
            "guard_flags_hex": f"0x{guard_flags_val:08x}",
            "guard_flags_decoded": guard_names,
            # Each Guard CF table entry is a 4-byte RVA plus this many extra bytes.
            "guard_cf_function_table_extra_bytes": (guard_flags_val >> 28) & 0xF,
        }

    # Exception directory (.pdata): one fixed-size record per function. The record size
    # depends on the machine; walking it with the wrong stride yields nonsense addresses.
    function_starts: List[Dict[str, Any]] = []
    exc_rva, exc_sz, _ = data_dirs.get("EXCEPTION_TABLE", (0, 0, 0))
    exc_foff = rva_to_file_off(exc_rva)
    pdata_entry_size = PDATA_ENTRY_SIZE.get(machine, 0)
    has_pdata = exc_foff is not None and exc_sz >= 8 and machine != IMAGE_FILE_MACHINE_I386
    pdata_count = 0
    if has_pdata and not pdata_entry_size:
        add_warning(warnings, "pdata_unknown_layout", f"The exception directory of machine 0x{machine:04x} is not decoded (unknown function-table entry size).")
    elif has_pdata and exc_foff is not None:
        pdata_count = exc_sz // pdata_entry_size
        n_rf = min(ANALYSIS_LIMITS["pe_pdata_entries"], pdata_count)
        if pdata_count > n_rf:
            add_warning(warnings, "pdata_truncated", f"The exception directory has {pdata_count:,} function entries; only the first {n_rf:,} are listed.", limit=n_rf, total=pdata_count)
        # Thumb-2 function addresses carry the interworking bit in bit 0.
        addr_mask = ~1 if machine in (IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_ARM) else ~0
        for i in range(n_rf):
            runtime.check_deadline()
            pos = exc_foff + i * pdata_entry_size
            if pos + pdata_entry_size > file_size:
                break
            begin_rva = buf.u32(pos) & addr_mask
            if begin_rva == 0:
                break
            fn_vm = image_base + begin_rva
            fn_foff = rva_to_file_off(begin_rva) or 0
            function_starts.append({
                "index": len(function_starts),
                "vmaddr": f"0x{fn_vm:x}",
                "slice_offset": fn_foff,
                "abs_offset": fn_foff,
                "name": f"pdata_fn_{fn_vm:x}",
            })

    # Always include Entry Point in function_starts
    ep_vm = image_base + entry_rva if entry_rva else image_base
    ep_foff = rva_to_file_off(entry_rva) or 0
    if entry_rva > 0 and not any(f["vmaddr"] == f"0x{ep_vm:x}" for f in function_starts):
        function_starts.insert(0, {
            "index": 0,
            "vmaddr": f"0x{ep_vm:x}",
            "slice_offset": ep_foff,
            "abs_offset": ep_foff,
            "name": "_pe_entry_point",
        })
        symbols.insert(0, {
            "index": 0,
            "name": "_pe_entry_point",
            "demangled": "AddressOfEntryPoint",
            "n_type": 0x0F,
            "type_name": "SECT",
            "is_stab": False,
            "is_external": True,
            "is_private_ext": False,
            "is_weak": False,
            "n_sect": 1,
            "section_name": ".text",
            "n_desc": 0,
            "library_ordinal": 0,
            "library_name": "ENTRY",
            "n_value": f"0x{ep_vm:x}",
            "n_value_int": ep_vm,
            "abs_offset": ep_foff,
            "slice_offset": ep_foff,
            "size": 16,
            "target_abs_offset": ep_foff,
        })

    # ------------------------------------------------------------------------
    # 10. Parse Authenticode Certificate Table (WIN_CERTIFICATE)
    # ------------------------------------------------------------------------
    cert_foff, cert_sz, _ = data_dirs.get("CERTIFICATE_TABLE", (0, 0, 0))
    code_sig_detail: Dict[str, Any] = {
        "present": False,
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
    if cert_foff > 0 and cert_sz >= 8 and cert_foff + 8 <= file_size:
        c_buf = buf.clone_with_fields()
        dw_len = c_buf.u32(cert_foff)
        w_rev = c_buf.u16(cert_foff + 4)
        w_type = c_buf.u16(cert_foff + 6)
        c_buf.record_field("dwLength", "uint32", cert_foff, 4, dw_len, f"0x{dw_len:x}", f"{dw_len:,} bytes", "WIN_CERTIFICATE total byte length")
        c_buf.record_field("wRevision", "uint16", cert_foff + 4, 2, w_rev, f"0x{w_rev:04x}", "WIN_CERT_REVISION_2_0" if w_rev == 0x0200 else f"0x{w_rev:x}")
        c_buf.record_field("wCertificateType", "uint16", cert_foff + 6, 2, w_type, f"0x{w_type:04x}", "WIN_CERT_TYPE_PKCS_SIGNED_DATA" if w_type == 2 else f"Type {w_type}")

        pkcs_bytes = buf.read_bytes(cert_foff + 8, max(0, min(dw_len - 8, file_size - (cert_foff + 8))))
        certs = parse_cms_certificates(pkcs_bytes)
        # The Authenticode image hash of this file, and whether the blob contains it. That is
        # an integrity fact about the bytes; the signature and its chain are not evaluated.
        layout = pe_layout(full_data)
        if layout is not None:
            auth = authenticode_status(full_data, layout, bytes(pkcs_bytes))
        else:
            auth = {"algorithm": "", "image_digest": "", "digest_in_signature": False, "algorithms_named": []}
        auth["signature_evaluated"] = False
        algo_label = str(auth["algorithm"] or "sha256").upper().replace("SHA", "SHA-")

        code_sig_detail = {
            "present": True,
            "kind": "authenticode",
            "authenticode": auth,
            "superblob_region": make_region(cert_foff, cert_foff, min(dw_len, file_size - cert_foff)),
            "magic": "WIN_CERTIFICATE (Authenticode)",
            "length": dw_len,
            "blob_count": 1,
            "fields": c_buf.get_fields(),
            "blobs": [{
                "index": 0,
                "type": w_type,
                "type_name": "WIN_CERT_TYPE_PKCS_SIGNED_DATA",
                "offset": cert_foff,
                "magic": f"0x{w_rev:04x}",
                "magic_name": "Authenticode PKCS#7",
                "length": dw_len,
                "region": make_region(cert_foff, cert_foff, min(dw_len, file_size - cert_foff)),
            }],
            "code_directory": {
                "version": w_rev,
                "flags_int": dll_chars,
                "flags_decoded": dll_char_names,
                "hash_type": f"Authenticode image hash ({algo_label})",
                "identifier": certs[0]["subject_cn"] if certs else os_filename(path),
                "team_id": certs[0]["org"] if certs else "Authenticode",
                # The image hash computed from this file; "verified" = the certificate table
                # contains it. The PKCS#7 signature and certificate chain are not checked.
                "cdhash": auth["image_digest"],
                "cdhash_verified": bool(auth["digest_in_signature"]),
                "page_size": sect_align or 4096,
                "n_special_slots": 0,
                "n_code_slots": len(all_sections_ordered),
                "special_slots": [],
                "code_slots_preview": [],
            },
            # PE has no entitlements; DllCharacteristics are in the header, not in the signature.
            "entitlements_xml": "",
            "entitlements_dict": {},
            "entitlements_entries": [],
            "cms_signature": {
                "present": True,
                "is_adhoc": len(certs) == 0,
                "size": len(pkcs_bytes),
                "certificates": certs,
            },
        }
        intervals.append({
            "id": "code_signature",
            "label": "WIN_CERTIFICATE (Authenticode)",
            "category": "signature",
            "abs_offset": cert_foff,
            "size": min(dw_len, file_size - cert_foff),
            "vmaddr": None,
        })

    # ------------------------------------------------------------------------
    # 11. Extract ASCII & UTF-16LE Strings from Data Sections
    # ------------------------------------------------------------------------
    strings_list: List[Dict[str, Any]] = []
    ascii_re = re.compile(rb"[\x20-\x7e]{5,256}")
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){5,128}")

    strings_limit = ANALYSIS_LIMITS["strings"]
    ascii_limit = (strings_limit * 3) // 4
    scan_budget = ANALYSIS_LIMITS["string_scan_bytes"]
    for sec in all_sections_ordered:
        if len(strings_list) >= strings_limit:
            add_warning(warnings, "strings_truncated", f"Only the first {strings_limit:,} strings are shown.", limit=strings_limit)
            break
        if scan_budget <= 0:
            add_warning(warnings, "strings_scan_budget", "String extraction stopped after scanning its byte budget; later sections were not scanned.", limit=ANALYSIS_LIMITS["string_scan_bytes"])
            break
        if sec["raw_size"] <= 0 or sec["slice_offset"] >= file_size:
            continue
        runtime.check_deadline()
        scan_len = min(sec["raw_size"], 131072, scan_budget)
        scan_budget -= scan_len
        raw_sec = buf.read_bytes(sec["slice_offset"], scan_len)
        for m in ascii_re.finditer(raw_sec):
            if len(strings_list) >= ascii_limit:
                add_warning(warnings, "strings_truncated", f"Only the first {strings_limit:,} strings are shown.", limit=strings_limit)
                break
            s_val = m.group(0).decode("ascii", errors="replace")
            rel_o = sec["slice_offset"] + m.start()
            s_vm = sec["vmaddr_int"] + m.start()
            strings_list.append({
                "index": len(strings_list),
                "source": sec["sectname"],
                "vmaddr": f"0x{s_vm:x}",
                "slice_offset": rel_o,
                "abs_offset": rel_o,
                "length": len(s_val),
                "encoding": "ASCII",
                "value": s_val,
            })
        for m in utf16_re.finditer(raw_sec):
            if len(strings_list) >= strings_limit:
                add_warning(warnings, "strings_truncated", f"Only the first {strings_limit:,} strings are shown.", limit=strings_limit)
                break
            s_val = m.group(0).decode("utf-16-le", errors="replace")
            rel_o = sec["slice_offset"] + m.start()
            s_vm = sec["vmaddr_int"] + m.start()
            strings_list.append({
                "index": len(strings_list),
                "source": f"{sec['sectname']} (UTF-16LE)",
                "vmaddr": f"0x{s_vm:x}",
                "slice_offset": rel_o,
                "abs_offset": rel_o,
                "length": len(m.group(0)),
                "encoding": "UTF-16LE",
                "value": s_val,
            })

    if characteristics & 0x2000:
        ft_name = "PE_DLL"
        ft_desc = "Windows Dynamic-Link Library (.dll)"
    elif subsystem == 1:
        ft_name = "PE_SYS_DRIVER"
        ft_desc = "Windows native-subsystem image (typically a kernel-mode driver, .sys)"
    else:
        ft_name = "PE32+_EXECUTABLE" if is_64 else "PE32_EXECUTABLE"
        ft_desc = f"Windows {magic_name} Executable (.exe)"

    dyld_info_obj = {
        "has_dyld_info": len(imports_list) > 0 or len(exports_list) > 0,
        "has_chained_fixups": len(fixups_preview) > 0 or len(imports_list) > 0,
        "has_exports_trie": len(exports_list) > 0,
        "chained_fixups": {
            "fixups_version": 1,
            "pointer_format": "PE64 DIR64 BaseReloc + IAT" if is_64 else "PE32 HIGHLOW BaseReloc + IAT",
            "imports_format": "IMAGE_IMPORT_DESCRIPTOR (ILT/IAT)",
            "imports_count": len(imports_list),
            "chains_count": reloc_blocks_count,
            "segments": [],
            "imports": imports_list,
            "fixups": fixups_preview,
            "region": make_region(imp_foff or 0, imp_foff or 0, imp_sz),
            "fields": [],
        } if (fixups_preview or imports_list) else None,
        "exports": exports_list,
        "rebases": [],
        "binds": [],
    }

    header_obj = {
        "magic": f"0x{opt_magic:04x}",
        "magic_name": magic_name,
        "is_64bit": is_64,
        "little_endian": True,
        "cputype": machine,
        "cputype_name": machine_macro,
        "cpusubtype": subsystem,
        "cpusubtype_name": subsys_name,
        "filetype": characteristics,
        "filetype_name": ft_name,
        "ncmds": len(load_commands),
        "sizeofcmds": size_of_headers,
        "flags": dll_chars,
        "flags_hex": f"0x{dll_chars:04x}",
        "flags_decoded": char_names + dll_char_names,
        "region": make_region(e_lfanew, e_lfanew, nt_hdr_total_size, f"0x{image_base + e_lfanew:x}", nt_hdr_total_size),
        "fields": header_fields,
    }

    security_posture = evaluate_pe_security_posture(
        is_64=is_64,
        characteristics=characteristics,
        dll_characteristics=dll_chars,
        subsystem=subsystem,
        sections=all_sections_ordered,
        entry_rva=entry_rva,
        has_relocs=(reloc_blocks_count > 0),
        has_pdata=has_pdata,
        load_config=load_config_info,
        tls_callbacks=tls_callbacks,
        code_sig_detail=code_sig_detail,
        machine=machine,
        symbol_info=symbol_info,
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
                "filesize": 0 if sect["is_zerofill"] else sect["raw_size"],
                "prot": sect["prot"],
                "maxprot": seg["maxprot"],
                "flags_decoded": [sect["section_type"]] + sect["attributes_decoded"],
            })

    overview_obj = {
        "format": "PE",
        "filetype_name": ft_name,
        "filetype_desc": ft_desc,
        "arch_display": arch_display,
        "endianness": "Little-Endian",
        "is_64bit": is_64,
        "uuid": pdb_guid_str,
        "platform": subsys_name,
        "minos": f"Windows NT {maj_os}.{min_os} (Subsys {maj_subsys}.{min_subsys})",
        "sdk": f"Linker version {maj_linker}.{min_linker}",
        "source_version": pdb_path_str or ts_str,
        "entry_point_vmaddr": f"0x{ep_vm:x}",
        "entry_point_abs_offset": ep_foff,
        "entry_point_type": "OptionalHeader.AddressOfEntryPoint",
        "ncmds": len(load_commands),
        "sizeofcmds": size_of_headers,
        "segments_count": len(segments),
        "sections_count": len(all_sections_ordered),
        "symbols_count": len(symbols),
        "strings_count": len(strings_list),
        "dylibs_count": len(dylibs),
    }

    return {
        "slice_index": 0,
        "format": "pe",
        "arch_name": arch_short,
        "slice_base_offset": 0,
        "slice_size": file_size,
        "overview": overview_obj,
        "header": header_obj,
        "load_commands": load_commands,
        "segments": segments,
        "memory_map": memory_map,
        "dylibs": dylibs,
        "rpaths": [],
        "entry_point": {
            "type": "AddressOfEntryPoint",
            "entryoff": ep_foff,
            "vmaddr": f"0x{ep_vm:x}",
            "abs_offset": ep_foff,
            "stacksize": 0,
            "thread_flavor": f"RVA 0x{entry_rva:x}",
            "registers": {},
        },
        "dyld_info": dyld_info_obj,
        "symbols": symbols,
        "dysymtab": {
            "present": len(indirect_symbols) > 0,
            "ilocalsym": 0,
            "nlocalsym": 0,
            "iextdefsym": 0,
            "nextdefsym": len(exports_list),
            "iundefsym": 0,
            "nundefsym": len(imports_list),
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
        "pe_metadata": {
            "image_base": f"0x{image_base:x}",
            "entry_point_rva": f"0x{entry_rva:x}",
            "timestamp_utc": ts_str,
            "linker_version": f"{maj_linker}.{min_linker}",
            "pdb_guid": pdb_guid_str,
            "pdb_path": pdb_path_str,
            "debug_entries": debug_entries_list,
            "symbol_info": symbol_info,
            "load_config": load_config_info,
            "exception_table": {"present": bool(has_pdata), "entry_size": pdata_entry_size, "entries": pdata_count},
            "rich_header": rich_info if rich_info else {"present": False, "entries": []},
            "tls_callbacks": tls_callbacks,
            "tls_info": {
                "present": bool(tls_callbacks),
                "callbacks": tls_callbacks,
            },
        },
        "warnings": warnings,
        "truncated": bool(warnings),
    }


def os_filename(p: str) -> str:
    return p.replace("\\", "/").split("/")[-1]
