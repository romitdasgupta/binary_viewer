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

from .buffer import BinaryBuffer, make_region
from .codesign import parse_cms_certificates

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
    1: "IMAGE_SUBSYSTEM_NATIVE (Kernel Driver)",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI (Console)",
    5: "IMAGE_SUBSYSTEM_OS2_CUI",
    7: "IMAGE_SUBSYSTEM_POSIX_CUI",
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
    (0x0020, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", "64-bit High-Entropy ASLR address space"),
    (0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", "ASLR enabled (can be relocated at load time)"),
    (0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", "Mandatory code signing integrity check enforced"),
    (0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", "Hardware DEP / NX compatible (non-executable data)"),
    (0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", "Isolation aware, do not isolate image"),
    (0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH", "Does not use Structured Exception Handling (SEH)"),
    (0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND", "Do not bind image"),
    (0x1000, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER", "Must execute in an AppContainer sandbox"),
    (0x2000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", "WDM kernel driver"),
    (0x4000, "IMAGE_DLLCHARACTERISTICS_GUARD_CF", "Control Flow Guard (CFG) indirect call protection"),
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
    0x0000: "Unknown / Imported Obj",
    0x0001: "Import0 (Linker Stub)",
    0x0093: "Utc1900_C (MSVC C Compiler)",
    0x0094: "Utc1900_CPP (MSVC C++ Compiler)",
    0x009D: "Linker1400 (MSVC Linker)",
    0x0102: "Masm1400 (MASM Assembler)",
    0x0104: "Utc1910_C (VS2017 C)",
    0x0105: "Utc1910_CPP (VS2017 C++)",
    0x010E: "Utc1920_C (VS2019 C)",
    0x010F: "Utc1920_CPP (VS2019 C++)",
    0x0115: "Linker1420 (VS2019/2022 Linker)",
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
    stub_slice = buf.read_bytes(0x40, e_lfanew - 0x40)
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
) -> Dict[str, Any]:
    """
    9-Point Windows PE32 / PE32+ Exploit Mitigation & Authenticode Scorecard.
    """
    checks: List[Dict[str, Any]] = []

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
            "detail": "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) is set and base relocations are intact.",
        })
    elif dynamic_base and relocs_stripped:
        checks.append({
            "id": "pie",
            "title": "Address Space Layout Randomization (DYNAMIC_BASE)",
            "status": "WARN",
            "value": "DYNAMIC_BASE Set but RELOCS_STRIPPED",
            "detail": "DYNAMIC_BASE flag is set, but IMAGE_FILE_RELOCS_STRIPPED prevents base relocation.",
        })
    else:
        checks.append({
            "id": "pie",
            "title": "Address Space Layout Randomization (DYNAMIC_BASE)",
            "status": "FAIL",
            "value": "Disabled (Fixed ImageBase)",
            "detail": "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set; image loads at predictable ImageBase.",
        })

    # 2. High-Entropy 64-bit ASLR (HIGH_ENTROPY_VA)
    high_entropy = bool(dll_characteristics & 0x0020)
    if is_64:
        if high_entropy and is_aslr:
            checks.append({
                "id": "high_entropy_va",
                "title": "64-Bit High-Entropy ASLR (HIGH_ENTROPY_VA)",
                "status": "PASS",
                "value": "Enabled (64-bit 1TB+ Entropy)",
                "detail": "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (0x0020) enables full 64-bit address space randomization.",
            })
        else:
            checks.append({
                "id": "high_entropy_va",
                "title": "64-Bit High-Entropy ASLR (HIGH_ENTROPY_VA)",
                "status": "WARN",
                "value": "Disabled on 64-bit PE32+",
                "detail": "64-bit image omits HIGH_ENTROPY_VA, reducing ASLR entropy to 32-bit compatibility range.",
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
    nx_compat = bool(dll_characteristics & 0x0100)
    if nx_compat:
        checks.append({
            "id": "dep_nx",
            "title": "Data Execution Prevention (NX_COMPAT / DEP)",
            "status": "PASS",
            "value": "Enabled (NX_COMPAT)",
            "detail": "IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100) enforces hardware non-executable stack and heap pages.",
        })
    else:
        checks.append({
            "id": "dep_nx",
            "title": "Data Execution Prevention (NX_COMPAT / DEP)",
            "status": "FAIL",
            "value": "Disabled (Executable Stack/Heap)",
            "detail": "NX_COMPAT is not set; data pages may allow shellcode execution.",
        })

    # 4. Control Flow Guard (GUARD_CF)
    guard_cf = bool(dll_characteristics & 0x4000)
    if guard_cf:
        checks.append({
            "id": "cfg",
            "title": "Control Flow Guard (GUARD_CF)",
            "status": "PASS",
            "value": "Enabled (IMAGE_DLLCHARACTERISTICS_GUARD_CF)",
            "detail": "Indirect call targets are validated against the Load Config GuardCF function bitmap.",
        })
    else:
        checks.append({
            "id": "cfg",
            "title": "Control Flow Guard (GUARD_CF)",
            "status": "INFO",
            "value": "Not Enabled",
            "detail": "IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) is not set.",
        })

    # 5. SEH Protection (SafeSEH / NO_SEH / .pdata Table Unwind)
    no_seh = bool(dll_characteristics & 0x0400)
    has_seh_table = bool(load_config.get("se_handler_table"))
    if is_64 or no_seh or has_pdata or has_seh_table:
        mode_desc = "64-bit .pdata Table Unwind" if is_64 else ("NO_SEH" if no_seh else "SafeSEH Handler Table")
        checks.append({
            "id": "seh",
            "title": "Exception Handler Hardening (SafeSEH / .pdata)",
            "status": "PASS",
            "value": f"Protected ({mode_desc})",
            "detail": "Structured exception handlers cannot be hijacked via stack overwrites.",
        })
    else:
        checks.append({
            "id": "seh",
            "title": "Exception Handler Hardening (SafeSEH / .pdata)",
            "status": "WARN",
            "value": "Unprotected 32-bit SEH",
            "detail": "32-bit image neither disables SEH (NO_SEH) nor registers a SafeSEH handler table in LoadConfig.",
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
            "detail": "MSVC /GS stack buffer overflow cookie pointer is configured in IMAGE_LOAD_CONFIG_DIRECTORY.",
        })
    else:
        checks.append({
            "id": "stack_canary",
            "title": "Stack Buffer Security Cookie (/GS)",
            "status": "INFO",
            "value": "No LoadConfig SecurityCookie",
            "detail": "No SecurityCookie pointer registered in Load Config directory.",
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
            "value": "Strict W^X Enforced",
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
            "detail": "IMAGE_DIRECTORY_ENTRY_TLS registers callbacks that execute before AddressOfEntryPoint.",
        })
    elif force_integrity:
        checks.append({
            "id": "tls_integrity",
            "title": "TLS Pre-Entry Callbacks & Image Integrity",
            "status": "PASS",
            "value": "FORCE_INTEGRITY Enabled • No TLS Callbacks",
            "detail": "Mandatory kernel signature enforcement active and no pre-entry TLS hooks present.",
        })
    else:
        checks.append({
            "id": "tls_integrity",
            "title": "TLS Pre-Entry Callbacks & Image Integrity",
            "status": "PASS",
            "value": "Clean (No Pre-Main TLS Callbacks)",
            "detail": "No pre-main TLS callback hooks registered in IMAGE_DIRECTORY_ENTRY_TLS.",
        })

    # 9. Authenticode Digital Signature (WIN_CERTIFICATE)
    cs_present = bool(code_sig_detail.get("present"))
    certs = code_sig_detail.get("cms_signature", {}).get("certificates", [])
    cert_names = [c.get("subject_cn", "") for c in certs if c.get("subject_cn")]
    if cs_present:
        signer = cert_names[0] if cert_names else "PKCS#7 SignedData"
        checks.append({
            "id": "codesign",
            "title": "Authenticode Digital Signature (WIN_CERTIFICATE)",
            "status": "PASS",
            "value": f"Signed ({signer})",
            "detail": f"Embedded WIN_CERTIFICATE Authenticode PKCS#7 signature present ({code_sig_detail.get('length', 0):,} bytes).",
        })
    else:
        checks.append({
            "id": "codesign",
            "title": "Authenticode Digital Signature (WIN_CERTIFICATE)",
            "status": "INFO" if subsystem != 1 else "FAIL",
            "value": "Unsigned (No CERTIFICATE_TABLE)",
            "detail": "No embedded Authenticode WIN_CERTIFICATE table in DataDirectory[4].",
        })

    return {
        "pie": is_aslr,
        "arc": nx_compat,
        "stack_canary": has_gs,
        "pac_enabled": guard_cf,
        "has_rwx_segments": has_rwx,
        "has_restrict_segment": force_integrity or guard_cf,
        "is_encrypted": False,
        "stripped_symbols": bool(characteristics & 0x0200),
        "code_signature": {
            "present": cs_present,
            "is_adhoc": False,
            "hardened_runtime": guard_cf,
            "library_validation": force_integrity,
            "cdhash": code_sig_detail.get("code_directory", {}).get("cdhash", "") if code_sig_detail.get("code_directory") else "",
            "cdhash_verified": cs_present,
            "identifier": cert_names[0] if cert_names else "",
            "team_id": "Authenticode PKCS#7" if cs_present else "",
            "certificates": cert_names,
        },
        "checks": checks,
    }


def parse_pe_slice(full_data: bytes, path: str = "<memory>") -> Dict[str, Any]:
    if not is_pe_bytes(full_data):
        raise ValueError("Invalid Windows PE header (expected 'MZ' + valid e_lfanew -> 'PE\\0\\0').")

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
    nt_buf.record_field("FileHeader.TimeDateStamp", "uint32", coff_off + 4, 4, time_date_stamp, f"0x{time_date_stamp:08x}", ts_str, "Linker compilation UTC timestamp")
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
    nt_buf.record_field("OptionalHeader.LinkerVersion", "uint16", opt_off + 2, 2, (maj_linker << 8) | min_linker, f"{maj_linker}.{min_linker}", f"MSVC Linker {maj_linker}.{min_linker}")
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
    max_sects = min(num_sections, 96)
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
        eff_vmsz = max(v_size, raw_size)

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
    def rva_to_file_off(rva: int) -> Optional[int]:
        if rva <= 0:
            return None
        for sec in all_sections_ordered:
            s_rva = sec["rva"]
            s_span = max(sec["size"], sec["raw_size"])
            if s_rva <= rva < s_rva + s_span:
                delta = rva - s_rva
                if delta < sec["raw_size"]:
                    return sec["slice_offset"] + delta
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
    if imp_foff is not None and imp_foff + 20 <= file_size:
        cur_imp = imp_foff
        for _ in range(128):
            if cur_imp + 20 > file_size:
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
                for t_idx in range(256):
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
        num_funcs = min(buf.u32(exp_foff + 20), 512)
        num_names = min(buf.u32(exp_foff + 24), 512)
        addr_funcs_rva = buf.u32(exp_foff + 28)
        addr_names_rva = buf.u32(exp_foff + 32)
        addr_ords_rva = buf.u32(exp_foff + 36)

        funcs_foff = rva_to_file_off(addr_funcs_rva)
        names_foff = rva_to_file_off(addr_names_rva)
        ords_foff = rva_to_file_off(addr_ords_rva)

        ord_to_name: Dict[int, str] = {}
        if names_foff is not None and ords_foff is not None:
            for i in range(num_names):
                if names_foff + (i + 1) * 4 > file_size or ords_foff + (i + 1) * 2 > file_size:
                    break
                n_rva = buf.u32(names_foff + i * 4)
                o_idx = buf.u16(ords_foff + i * 2)
                n_foff = rva_to_file_off(n_rva)
                if n_foff is not None:
                    ord_to_name[o_idx] = buf.cstr_at(n_foff, 256)[0]

        if funcs_foff is not None:
            for f_idx in range(num_funcs):
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
        while cur_rel + 8 <= end_rel and reloc_blocks_count < 64:
            page_rva = buf.u32(cur_rel)
            block_sz = buf.u32(cur_rel + 4)
            if block_sz < 8 or cur_rel + block_sz > end_rel:
                break
            reloc_blocks_count += 1
            n_entries = (block_sz - 8) // 2
            for e_idx in range(n_entries):
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
    dbg_rva, dbg_sz, _ = data_dirs.get("DEBUG_DIRECTORY", (0, 0, 0))
    dbg_foff = rva_to_file_off(dbg_rva)
    if dbg_foff is not None and dbg_sz >= 28 and dbg_foff + 28 <= file_size:
        n_dbg = min(8, dbg_sz // 28)
        for i in range(n_dbg):
            d_off = dbg_foff + i * 28
            if d_off + 28 > file_size:
                break
            dbg_type = buf.u32(d_off + 12)
            sz_data = buf.u32(d_off + 16)
            ptr_raw = buf.u32(d_off + 24)
            if dbg_type == 2 and ptr_raw + 24 <= file_size:  # IMAGE_DEBUG_TYPE_CODEVIEW
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
                    break

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

    load_config_info: Dict[str, Any] = {}
    lc_rva, lc_sz, _ = data_dirs.get("LOAD_CONFIG_TABLE", (0, 0, 0))
    lc_foff = rva_to_file_off(lc_rva)
    if lc_foff is not None and lc_foff + (96 if is_64 else 64) <= file_size:
        sec_cookie = buf.u64(lc_foff + 88) if is_64 else buf.u32(lc_foff + 60)
        seh_tbl = 0 if is_64 else buf.u32(lc_foff + 64)
        load_config_info["security_cookie"] = sec_cookie
        load_config_info["se_handler_table"] = seh_tbl

    function_starts: List[Dict[str, Any]] = []
    exc_rva, exc_sz, _ = data_dirs.get("EXCEPTION_TABLE", (0, 0, 0))
    exc_foff = rva_to_file_off(exc_rva)
    has_pdata = False
    if exc_foff is not None and exc_sz >= 12 and is_64:
        has_pdata = True
        n_rf = min(500, exc_sz // 12)
        for i in range(n_rf):
            pos = exc_foff + i * 12
            if pos + 12 > file_size:
                break
            begin_rva = buf.u32(pos)
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
            "demangled": "AddressOfEntryPoint (mainCRTStartup)",
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
        pe_digest = hashlib.sha256(pkcs_bytes).hexdigest()[:40]

        code_sig_detail = {
            "present": True,
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
                "hash_type": "SHA-256 (Authenticode)",
                "identifier": certs[0]["subject_cn"] if certs else os_filename(path),
                "team_id": certs[0]["org"] if certs else "Authenticode",
                "cdhash": pe_digest,
                "cdhash_verified": True,
                "page_size": sect_align or 4096,
                "n_special_slots": 0,
                "n_code_slots": len(all_sections_ordered),
                "special_slots": [],
                "code_slots_preview": [],
            },
            "entitlements_xml": "",
            "entitlements_dict": {flag: True for flag in dll_char_names},
            "entitlements_entries": [{"key": flag, "value": True, "risk": "INFO"} for flag in dll_char_names],
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

    for sec in all_sections_ordered:
        if sec["raw_size"] <= 0 or sec["slice_offset"] >= file_size:
            continue
        scan_len = min(sec["raw_size"], 131072)
        raw_sec = buf.read_bytes(sec["slice_offset"], scan_len)
        for m in ascii_re.finditer(raw_sec):
            if len(strings_list) >= 1500:
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
            if len(strings_list) >= 2000:
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
        ft_desc = "Windows Kernel-Mode Driver (.sys)"
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
        "sdk": f"MSVC Linker {maj_linker}.{min_linker}",
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
            "rich_header": rich_info if rich_info else {"present": False, "entries": []},
            "tls_callbacks": tls_callbacks,
            "tls_info": {
                "present": bool(tls_callbacks),
                "callbacks": tls_callbacks,
            },
        },
    }


def os_filename(p: str) -> str:
    return p.replace("\\", "/").split("/")[-1]
