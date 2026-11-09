"""
Layer 2: Universal (Fat) & Mach-O 32/64 Structural Binary Parser.
Supports Userland Executables, Dylibs, Bundles, Kexts, Kernelcaches (MH_FILESET),
and Standalone Firmware Images (MH_PRELOAD).
"""

import hashlib
import os
import re
import struct
import subprocess
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from .buffer import BinaryBuffer, make_region
from .codesign import parse_code_signature
from .constants import (
    BUILD_TOOLS,
    CHAINED_IMPORT_FORMATS,
    CHAINED_PTR_FORMATS,
    CPU_TYPE_ARM64,
    CPU_TYPE_X86_64,
    DICE_KINDS,
    EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE,
    EXPORT_SYMBOL_FLAGS_KIND_MASK,
    EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
    EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL,
    EXPORT_SYMBOL_FLAGS_REEXPORT,
    EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER,
    EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
    FAT_CIGAM,
    FAT_CIGAM_64,
    FAT_MAGIC,
    FAT_MAGIC_64,
    FILETYPE_INFO,
    INDIRECT_SYMBOL_ABS,
    INDIRECT_SYMBOL_LOCAL,
    LC_BUILD_VERSION,
    LC_CODE_SIGNATURE,
    LC_DATA_IN_CODE,
    LC_DYLD_CHAINED_FIXUPS,
    LC_DYLD_ENVIRONMENT,
    LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_INFO,
    LC_DYLD_INFO_ONLY,
    LC_DYSYMTAB,
    LC_ENCRYPTION_INFO,
    LC_ENCRYPTION_INFO_64,
    LC_FILESET_ENTRY,
    LC_FUNCTION_STARTS,
    LC_ID_DYLIB,
    LC_ID_DYLINKER,
    LC_LAZY_LOAD_DYLIB,
    LC_LOAD_DYLIB,
    LC_LOAD_DYLINKER,
    LC_LOAD_UPWARD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_MAIN,
    LC_REEXPORT_DYLIB,
    LC_REQ_DYLD,
    LC_RPATH,
    LC_SEGMENT,
    LC_SEGMENT_64,
    LC_SOURCE_VERSION,
    LC_SYMTAB,
    LC_THREAD,
    LC_UNIXTHREAD,
    LC_UUID,
    LC_VERSION_MIN_IPHONEOS,
    LC_VERSION_MIN_MACOSX,
    LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
    LOAD_COMMAND_NAMES,
    MAGIC_NAMES,
    MH_CIGAM,
    MH_CIGAM_64,
    MH_MAGIC,
    MH_MAGIC_64,
    MH_PRELOAD,
    N_EXT,
    N_PEXT,
    N_SECT,
    N_STAB,
    N_TYPE,
    N_TYPE_NAMES,
    N_UNDF,
    PAC_KEYS,
    PLATFORMS,
    VM_PROT_EXECUTE,
    decode_cpu_arch,
    decode_header_flags,
    decode_section_flags,
    decode_segment_flags,
    decode_vm_prot_flags,
    format_packed_version,
    format_source_version,
    format_vm_prot,
)
from .elf_parser import ELF_MAGIC, parse_elf_slice
from .pe_parser import is_pe_bytes, parse_pe_slice
from .pedagogy import build_pedagogy_bundle
from .security import evaluate_security_posture
from .semantics import build_semantic_layers


# ============================================================================
# Batch C++ / Swift Symbol Demangler
# ============================================================================
def _batch_demangle(names: List[str]) -> Dict[str, str]:
    """
    Demangles C++ (_Z / __Z) and Swift (_$s / _$S) symbol names using system `c++filt`
    with a fast pure-Python fallback.
    """
    to_demangle = [
        n
        for n in set(names)
        if n.startswith("__Z") or n.startswith("_Z") or n.startswith("_$s") or n.startswith("$s")
    ]
    if not to_demangle:
        return {}

    result: Dict[str, str] = {}
    cpp_candidates = [n for n in to_demangle if n.startswith("__Z") or n.startswith("_Z")]
    if cpp_candidates and os.path.exists("/usr/bin/c++filt"):
        try:
            proc = subprocess.run(
                ["/usr/bin/c++filt", "-_"],
                input="\n".join(cpp_candidates),
                capture_output=True,
                text=True,
                timeout=2,
            )
            if proc.returncode == 0:
                lines = proc.stdout.splitlines()
                for orig, dem in zip(cpp_candidates, lines):
                    result[orig] = dem.strip()
        except Exception:
            pass

    for n in to_demangle:
        if n not in result:
            if n.startswith("_") and not n.startswith("__"):
                result[n] = n[1:]
            else:
                result[n] = n
    return result


# ============================================================================
# Exports Trie Parser (Cycle-Safe)
# ============================================================================
def parse_exports_trie(
    slice_buf: BinaryBuffer,
    trie_off: int,
    trie_size: int,
    text_vmaddr: int,
    max_exports: int = 2000,
) -> List[Dict[str, Any]]:
    if trie_size <= 0 or trie_off + trie_size > slice_buf.slice_size:
        return []

    exports: List[Dict[str, Any]] = []
    visited: Set[int] = set()

    # Queue of (relative_node_offset, symbol_prefix)
    stack: List[Tuple[int, str]] = [(0, "")]
    while stack and len(exports) < max_exports:
        rel_off, prefix = stack.pop()
        if rel_off < 0 or rel_off >= trie_size or rel_off in visited:
            continue
        visited.add(rel_off)

        cur = trie_off + rel_off
        term_size, sz_len = slice_buf.read_uleb128(cur)
        cur += sz_len

        if term_size != 0:
            info_cur = cur
            flags, fl_len = slice_buf.read_uleb128(info_cur)
            info_cur += fl_len
            flags_decoded: List[str] = []
            kind = flags & EXPORT_SYMBOL_FLAGS_KIND_MASK
            if kind == EXPORT_SYMBOL_FLAGS_KIND_REGULAR:
                flags_decoded.append("EXPORT_SYMBOL_FLAGS_KIND_REGULAR")
            elif kind == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL:
                flags_decoded.append("EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL")
            elif kind == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE:
                flags_decoded.append("EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE")

            if flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION:
                flags_decoded.append("EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION")

            sym_offset = 0
            if flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
                flags_decoded.append("EXPORT_SYMBOL_FLAGS_REEXPORT")
                _ord, ord_len = slice_buf.read_uleb128(info_cur)
                info_cur += ord_len
                _imp_name, _ = slice_buf.cstr_at(info_cur, 256)
            elif flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
                flags_decoded.append("EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER")
                sym_offset, s_len = slice_buf.read_uleb128(info_cur)
                info_cur += s_len
            else:
                sym_offset, s_len = slice_buf.read_uleb128(info_cur)
                info_cur += s_len

            vm_val = (text_vmaddr + sym_offset) if kind != EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE else sym_offset
            exports.append({
                "name": prefix,
                "vmaddr": f"0x{vm_val:x}",
                "offset": sym_offset,
                "flags": flags,
                "flags_decoded": flags_decoded,
            })

        children_pos = cur + term_size
        if children_pos >= trie_off + trie_size:
            continue
        num_children = slice_buf.u8(children_pos)
        children_pos += 1
        child_entries: List[Tuple[int, str]] = []
        for _ in range(num_children):
            if children_pos >= trie_off + trie_size:
                break
            edge_str, edge_len = slice_buf.cstr_at(children_pos, 256)
            if edge_len <= 0:
                break
            children_pos += edge_len
            child_rel_off, c_len = slice_buf.read_uleb128(children_pos)
            children_pos += c_len
            child_entries.append((child_rel_off, prefix + edge_str))

        for child_entry in reversed(child_entries):
            stack.append(child_entry)

    return exports


# ============================================================================
# Chained Fixups Parser (LC_DYLD_CHAINED_FIXUPS)
# ============================================================================
def parse_chained_fixups(
    slice_buf: BinaryBuffer,
    dataoff: int,
    datasize: int,
    segments: List[Dict[str, Any]],
    dylibs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if datasize < 28 or dataoff + datasize > slice_buf.slice_size:
        return {}

    cf_buf = slice_buf.clone_with_fields()
    fixups_version = cf_buf.u32(dataoff)
    starts_offset = cf_buf.u32(dataoff + 4)
    imports_offset = cf_buf.u32(dataoff + 8)
    symbols_offset = cf_buf.u32(dataoff + 12)
    imports_count = cf_buf.u32(dataoff + 16)
    imports_format = cf_buf.u32(dataoff + 20)
    symbols_format = cf_buf.u32(dataoff + 24)

    imp_fmt_name = CHAINED_IMPORT_FORMATS.get(imports_format, f"FORMAT_{imports_format}")

    cf_buf.record_field("fixups_version", "uint32", dataoff, 4, fixups_version, str(fixups_version))
    cf_buf.record_field("starts_offset", "uint32", dataoff + 4, 4, starts_offset, f"0x{starts_offset:x}")
    cf_buf.record_field("imports_offset", "uint32", dataoff + 8, 4, imports_offset, f"0x{imports_offset:x}")
    cf_buf.record_field("symbols_offset", "uint32", dataoff + 12, 4, symbols_offset, f"0x{symbols_offset:x}")
    cf_buf.record_field("imports_count", "uint32", dataoff + 16, 4, imports_count, str(imports_count))
    cf_buf.record_field("imports_format", "uint32", dataoff + 20, 4, imports_format, imp_fmt_name)
    cf_buf.record_field("symbols_format", "uint32", dataoff + 24, 4, symbols_format, str(symbols_format))

    # Parse imports table
    imports_list: List[Dict[str, Any]] = []
    imp_base = dataoff + imports_offset
    sym_base = dataoff + symbols_offset
    max_imports = min(imports_count, 500)

    for i in range(max_imports):
        if imports_format == 1:  # DYLD_CHAINED_IMPORT (4 bytes)
            pos = imp_base + i * 4
            if pos + 4 > dataoff + datasize:
                break
            raw_imp = cf_buf.u32(pos)
            lib_ord = raw_imp & 0xFF
            weak_imp = bool((raw_imp >> 8) & 1)
            name_off = (raw_imp >> 9) & 0x7FFFFF
        elif imports_format == 2:  # DYLD_CHAINED_IMPORT_ADDEND (8 bytes)
            pos = imp_base + i * 8
            if pos + 8 > dataoff + datasize:
                break
            raw_imp = cf_buf.u32(pos)
            lib_ord = raw_imp & 0xFF
            weak_imp = bool((raw_imp >> 8) & 1)
            name_off = (raw_imp >> 9) & 0x7FFFFF
        else:  # DYLD_CHAINED_IMPORT_ADDEND64 (16 bytes)
            pos = imp_base + i * 16
            if pos + 16 > dataoff + datasize:
                break
            raw_imp = cf_buf.u64(pos)
            lib_ord = raw_imp & 0xFFFF
            weak_imp = bool((raw_imp >> 16) & 1)
            name_off = (raw_imp >> 32) & 0xFFFFFFFF

        sym_name, _ = cf_buf.cstr_at(sym_base + name_off, 512)
        if 1 <= lib_ord <= len(dylibs):
            lib_name = dylibs[lib_ord - 1]["name"]
        elif lib_ord == 0:
            lib_name = "SELF"
        elif lib_ord in (0xFE, 0xFFFE):
            lib_name = "FLAT_LOOKUP"
        elif lib_ord in (0xFF, 0xFFFF):
            lib_name = "WEAK_LOOKUP"
        else:
            lib_name = f"ORDINAL_{lib_ord}"

        imports_list.append({
            "index": i,
            "name": sym_name,
            "lib_ordinal": lib_ord,
            "lib_name": lib_name,
            "weak_import": weak_imp,
        })

    # Parse dyld_chained_starts_in_image
    pointer_format_name = "DYLD_CHAINED_PTR_64"
    chains_count = 0
    fixups_preview: List[Dict[str, Any]] = []
    starts_seg_summaries: List[Dict[str, Any]] = []

    starts_pos = dataoff + starts_offset
    if starts_offset > 0 and starts_pos + 4 <= dataoff + datasize:
        seg_count = cf_buf.u32(starts_pos)
        for seg_idx in range(min(seg_count, 32)):
            seg_info_off = cf_buf.u32(starts_pos + 4 + seg_idx * 4)
            if seg_info_off == 0:
                continue
            s_pos = starts_pos + seg_info_off
            if s_pos + 22 > dataoff + datasize:
                continue
            s_size = cf_buf.u32(s_pos)
            page_size = cf_buf.u16(s_pos + 4)
            ptr_fmt = cf_buf.u16(s_pos + 6)
            seg_offset = cf_buf.u64(s_pos + 8)
            max_valid_ptr = cf_buf.u32(s_pos + 16)
            page_count = cf_buf.u16(s_pos + 20)
            pointer_format_name = CHAINED_PTR_FORMATS.get(ptr_fmt, f"PTR_FMT_{ptr_fmt}")

            valid_pages = 0
            for p_idx in range(min(page_count, 256)):
                p_start = cf_buf.u16(s_pos + 22 + p_idx * 2)
                if p_start == 0xFFFF:
                    continue
                valid_pages += 1
                chains_count += 1

                # Walk first few fixup chain slots in this page for preview
                if len(fixups_preview) < 128 and seg_idx < len(segments):
                    seg_obj = segments[seg_idx]
                    chain_slice_off = seg_obj["fileoff"] + p_idx * page_size + (p_start & 0x0FFF)
                    steps = 0
                    while (
                        0 <= chain_slice_off + 8 <= slice_buf.slice_size
                        and steps < 32
                        and len(fixups_preview) < 128
                    ):
                        steps += 1
                        raw_ptr = slice_buf.u64(chain_slice_off)
                        f_vmaddr = seg_obj["vmaddr_int"] + (chain_slice_off - seg_obj["fileoff"])
                        f_abs = slice_buf.slice_base + chain_slice_off

                        # Decode ARM64E vs 64-bit pointer formats
                        if ptr_fmt in (1, 7, 9, 10, 12):  # ARM64E family
                            auth = bool((raw_ptr >> 63) & 1)
                            bind = bool((raw_ptr >> 62) & 1)
                            stride = 8 if ptr_fmt in (1, 9, 12) else 4
                            next_step = (raw_ptr >> 51) & 0x7FF
                            if auth and bind:
                                ordinal = raw_ptr & 0xFFFF if ptr_fmt != 12 else raw_ptr & 0xFFFFFF
                                diversity = (raw_ptr >> 32) & 0xFFFF
                                addr_div = bool((raw_ptr >> 48) & 1)
                                key_id = (raw_ptr >> 49) & 0x3
                                sym_n = imports_list[ordinal]["name"] if ordinal < len(imports_list) else f"ord_{ordinal}"
                                fixups_preview.append({
                                    "vmaddr": f"0x{f_vmaddr:x}",
                                    "abs_offset": f_abs,
                                    "type": "AUTH_BIND",
                                    "ordinal": ordinal,
                                    "symbol": sym_n,
                                    "pac_key": PAC_KEYS.get(key_id, "IA"),
                                    "diversity": diversity,
                                    "addr_div": addr_div,
                                })
                            elif auth and not bind:
                                target_off = raw_ptr & 0xFFFFFFFF
                                diversity = (raw_ptr >> 32) & 0xFFFF
                                addr_div = bool((raw_ptr >> 48) & 1)
                                key_id = (raw_ptr >> 49) & 0x3
                                fixups_preview.append({
                                    "vmaddr": f"0x{f_vmaddr:x}",
                                    "abs_offset": f_abs,
                                    "type": "AUTH_REBASE",
                                    "ordinal": None,
                                    "symbol": f"target +0x{target_off:x}",
                                    "pac_key": PAC_KEYS.get(key_id, "IA"),
                                    "diversity": diversity,
                                    "addr_div": addr_div,
                                })
                            elif not auth and bind:
                                ordinal = raw_ptr & 0xFFFF if ptr_fmt != 12 else raw_ptr & 0xFFFFFF
                                sym_n = imports_list[ordinal]["name"] if ordinal < len(imports_list) else f"ord_{ordinal}"
                                fixups_preview.append({
                                    "vmaddr": f"0x{f_vmaddr:x}",
                                    "abs_offset": f_abs,
                                    "type": "BIND",
                                    "ordinal": ordinal,
                                    "symbol": sym_n,
                                    "pac_key": None,
                                    "diversity": 0,
                                    "addr_div": False,
                                })
                            else:
                                target_off = raw_ptr & 0x7FFFFFFFFFF
                                fixups_preview.append({
                                    "vmaddr": f"0x{f_vmaddr:x}",
                                    "abs_offset": f_abs,
                                    "type": "REBASE",
                                    "ordinal": None,
                                    "symbol": f"target 0x{target_off:x}",
                                    "pac_key": None,
                                    "diversity": 0,
                                    "addr_div": False,
                                })
                            if next_step == 0:
                                break
                            chain_slice_off += next_step * stride
                        else:  # DYLD_CHAINED_PTR_64 / DYLD_CHAINED_PTR_64_OFFSET
                            bind = bool((raw_ptr >> 63) & 1)
                            next_step = (raw_ptr >> 51) & 0xFFF
                            if bind:
                                ordinal = raw_ptr & 0xFFFFFF
                                sym_n = imports_list[ordinal]["name"] if ordinal < len(imports_list) else f"ord_{ordinal}"
                                fixups_preview.append({
                                    "vmaddr": f"0x{f_vmaddr:x}",
                                    "abs_offset": f_abs,
                                    "type": "BIND_64",
                                    "ordinal": ordinal,
                                    "symbol": sym_n,
                                    "pac_key": None,
                                    "diversity": 0,
                                    "addr_div": False,
                                })
                            else:
                                target_off = raw_ptr & 0xFFFFFFFFF
                                fixups_preview.append({
                                    "vmaddr": f"0x{f_vmaddr:x}",
                                    "abs_offset": f_abs,
                                    "type": "REBASE_64",
                                    "ordinal": None,
                                    "symbol": f"target 0x{target_off:x}",
                                    "pac_key": None,
                                    "diversity": 0,
                                    "addr_div": False,
                                })
                            if next_step == 0:
                                break
                            chain_slice_off += next_step * 4

            starts_seg_summaries.append({
                "segment_index": seg_idx,
                "page_size": page_size,
                "pointer_format": pointer_format_name,
                "segment_offset": f"0x{seg_offset:x}",
                "page_count": page_count,
                "active_pages": valid_pages,
            })

    return {
        "fixups_version": fixups_version,
        "pointer_format": pointer_format_name,
        "imports_format": imp_fmt_name,
        "imports_count": imports_count,
        "chains_count": chains_count,
        "segments": starts_seg_summaries,
        "imports": imports_list,
        "fixups": fixups_preview,
        "region": make_region(slice_buf.slice_base + dataoff, dataoff, datasize),
        "fields": cf_buf.get_fields(),
    }


# ============================================================================
# Slice Parser
# ============================================================================
def _parse_macho_slice(
    full_data: bytes,
    slice_index: int,
    slice_base: int,
    slice_size: int,
) -> Dict[str, Any]:
    raw_magic_le = struct.unpack_from("<I", full_data, slice_base)[0]
    if raw_magic_le == MH_MAGIC_64:
        is_64 = True
        little_endian = True
    elif raw_magic_le == MH_CIGAM_64:
        is_64 = True
        little_endian = False
    elif raw_magic_le == MH_MAGIC:
        is_64 = False
        little_endian = True
    elif raw_magic_le == MH_CIGAM:
        is_64 = False
        little_endian = False
    else:
        is_64 = True
        little_endian = True

    buf = BinaryBuffer(
        full_data,
        slice_base=slice_base,
        slice_size=slice_size,
        little_endian=little_endian,
    )

    magic = buf.u32(0)
    cputype = buf.u32(4)
    cpusubtype = buf.u32(8)
    filetype = buf.u32(12)
    ncmds = buf.u32(16)
    sizeofcmds = buf.u32(20)
    flags = buf.u32(24)
    hdr_size = 32 if is_64 else 28

    arch_short, cputype_name, cpusubtype_name, arch_display = decode_cpu_arch(
        cputype, cpusubtype
    )
    ft_name, ft_desc = FILETYPE_INFO.get(
        filetype, (f"MH_FILETYPE_0x{filetype:x}", "Mach-O Binary")
    )
    flags_decoded, flags_bit_list = decode_header_flags(flags)
    magic_name = MAGIC_NAMES.get(raw_magic_le, f"0x{magic:08x}")

    buf.record_field("magic", "uint32", 0, 4, magic, f"0x{magic:08x}", magic_name, "Mach-O header magic number")
    buf.record_field("cputype", "uint32", 4, 4, cputype, f"0x{cputype:08x}", cputype_name, arch_display)
    buf.record_field("cpusubtype", "uint32", 8, 4, cpusubtype, f"0x{cpusubtype:08x}", cpusubtype_name, "CPU subtype & capability flags")
    buf.record_field("filetype", "uint32", 12, 4, filetype, f"0x{filetype:x}", ft_name, ft_desc)
    buf.record_field("ncmds", "uint32", 16, 4, ncmds, str(ncmds), f"{ncmds} load commands", "Number of load commands following header")
    buf.record_field("sizeofcmds", "uint32", 20, 4, sizeofcmds, f"{sizeofcmds} (0x{sizeofcmds:x})", f"{sizeofcmds:,} bytes", "Total byte size of all load commands")
    buf.record_field(
        "flags",
        "uint32",
        24,
        4,
        flags,
        f"0x{flags:08x}",
        " | ".join(flags_decoded) if flags_decoded else "0x0",
        "Header execution and linking flags",
        bit_flags=flags_bit_list,
    )
    if is_64:
        reserved = buf.u32(28)
        buf.record_field("reserved", "uint32", 28, 4, reserved, f"0x{reserved:08x}", "0x0 (Reserved)", "64-bit alignment padding")

    header_fields = buf.reset_fields()

    # Collections populated while iterating load commands
    load_commands: List[Dict[str, Any]] = []
    segments: List[Dict[str, Any]] = []
    all_sections_ordered: List[Dict[str, Any]] = []  # 1-indexed for n_sect
    dylibs: List[Dict[str, Any]] = []
    rpaths: List[Dict[str, Any]] = []
    fileset_entries: List[Dict[str, Any]] = []
    intervals: List[Dict[str, Any]] = []

    uuid_str = ""
    platform_str = "macOS"
    minos_str = ""
    sdk_str = ""
    source_version_str = ""
    entry_point_info: Dict[str, Any] = {
        "type": "NONE",
        "entryoff": 0,
        "vmaddr": "0x0",
        "abs_offset": slice_base,
        "stacksize": 0,
        "thread_flavor": None,
        "registers": {},
    }
    symtab_cmd: Optional[Dict[str, int]] = None
    dysymtab_cmd: Optional[Dict[str, Any]] = None
    code_sig_cmd: Optional[Tuple[int, int]] = None
    chained_fixups_cmd: Optional[Tuple[int, int]] = None
    exports_trie_cmd: Optional[Tuple[int, int]] = None
    dyld_info_cmd: Optional[Dict[str, int]] = None
    func_starts_cmd: Optional[Tuple[int, int]] = None
    encryption_info: Dict[str, Any] = {"present": False, "cryptoff": 0, "cryptsize": 0, "cryptid": 0}

    cmd_off = hdr_size
    max_cmds = min(ncmds, 512)

    for cmd_idx in range(max_cmds):
        if cmd_off + 8 > slice_size:
            break
        lc_buf = buf.clone_with_fields()
        cmd = lc_buf.u32(cmd_off)
        cmdsize = lc_buf.u32(cmd_off + 4)
        if cmdsize < 8 or cmd_off + cmdsize > slice_size:
            break

        cmd_name = LOAD_COMMAND_NAMES.get(cmd, f"LC_UNKNOWN_0x{cmd:x}")
        req_dyld = bool(cmd & LC_REQ_DYLD)

        lc_buf.record_field("cmd", "uint32", cmd_off, 4, cmd, f"0x{cmd:x}", cmd_name, "Load command identifier")
        lc_buf.record_field("cmdsize", "uint32", cmd_off + 4, 4, cmdsize, f"{cmdsize} (0x{cmdsize:x})", f"{cmdsize} bytes", "Total size of load command")

        summary = cmd_name
        details: Dict[str, Any] = {}

        # --- LC_SEGMENT_64 / LC_SEGMENT ---
        if cmd in (LC_SEGMENT_64, LC_SEGMENT):
            seg_is_64 = cmd == LC_SEGMENT_64
            segname = lc_buf.fixed_cstr(cmd_off + 8, 16)
            lc_buf.record_field("segname", "char[16]", cmd_off + 8, 16, segname, segname, segname, "Segment name")
            if seg_is_64:
                vmaddr = lc_buf.u64(cmd_off + 24)
                vmsize = lc_buf.u64(cmd_off + 32)
                fileoff = lc_buf.u64(cmd_off + 40)
                filesize = lc_buf.u64(cmd_off + 48)
                maxprot = lc_buf.u32(cmd_off + 56)
                initprot = lc_buf.u32(cmd_off + 60)
                nsects = lc_buf.u32(cmd_off + 64)
                s_flags = lc_buf.u32(cmd_off + 68)
                sect_hdr_base = cmd_off + 72
                sect_hdr_size = 80

                lc_buf.record_field("vmaddr", "uint64", cmd_off + 24, 8, vmaddr, f"0x{vmaddr:x}", f"0x{vmaddr:x}", "Virtual memory start address", target_vmaddr=f"0x{vmaddr:x}")
                lc_buf.record_field("vmsize", "uint64", cmd_off + 32, 8, vmsize, f"0x{vmsize:x}", f"{vmsize:,} bytes", "Virtual memory size")
                lc_buf.record_field("fileoff", "uint64", cmd_off + 40, 8, fileoff, f"0x{fileoff:x}", f"Slice offset 0x{fileoff:x}", "File offset of segment", target_offset=slice_base + fileoff if filesize > 0 else None)
                lc_buf.record_field("filesize", "uint64", cmd_off + 48, 8, filesize, f"0x{filesize:x}", f"{filesize:,} bytes", "Bytes mapped from file")
                lc_buf.record_field("maxprot", "vm_prot_t", cmd_off + 56, 4, maxprot, f"0x{maxprot:x}", format_vm_prot(maxprot), "Maximum VM protection", bit_flags=decode_vm_prot_flags(maxprot))
                lc_buf.record_field("initprot", "vm_prot_t", cmd_off + 60, 4, initprot, f"0x{initprot:x}", format_vm_prot(initprot), "Initial VM protection", bit_flags=decode_vm_prot_flags(initprot))
                lc_buf.record_field("nsects", "uint32", cmd_off + 64, 4, nsects, str(nsects), f"{nsects} sections", "Number of section headers")
                s_flags_names, s_flags_bits = decode_segment_flags(s_flags)
                lc_buf.record_field("flags", "uint32", cmd_off + 68, 4, s_flags, f"0x{s_flags:x}", " | ".join(s_flags_names) if s_flags_names else "0x0", "Segment flags", bit_flags=s_flags_bits)
            else:
                vmaddr = lc_buf.u32(cmd_off + 24)
                vmsize = lc_buf.u32(cmd_off + 28)
                fileoff = lc_buf.u32(cmd_off + 32)
                filesize = lc_buf.u32(cmd_off + 36)
                maxprot = lc_buf.u32(cmd_off + 40)
                initprot = lc_buf.u32(cmd_off + 44)
                nsects = lc_buf.u32(cmd_off + 48)
                s_flags = lc_buf.u32(cmd_off + 52)
                sect_hdr_base = cmd_off + 56
                sect_hdr_size = 68

                lc_buf.record_field("vmaddr", "uint32", cmd_off + 24, 4, vmaddr, f"0x{vmaddr:x}", f"0x{vmaddr:x}")
                lc_buf.record_field("vmsize", "uint32", cmd_off + 28, 4, vmsize, f"0x{vmsize:x}", f"{vmsize:,} bytes")
                lc_buf.record_field("fileoff", "uint32", cmd_off + 32, 4, fileoff, f"0x{fileoff:x}", f"Slice offset 0x{fileoff:x}", target_offset=slice_base + fileoff if filesize > 0 else None)
                lc_buf.record_field("filesize", "uint32", cmd_off + 36, 4, filesize, f"0x{filesize:x}", f"{filesize:,} bytes")
                lc_buf.record_field("maxprot", "vm_prot_t", cmd_off + 40, 4, maxprot, f"0x{maxprot:x}", format_vm_prot(maxprot), bit_flags=decode_vm_prot_flags(maxprot))
                lc_buf.record_field("initprot", "vm_prot_t", cmd_off + 44, 4, initprot, f"0x{initprot:x}", format_vm_prot(initprot), bit_flags=decode_vm_prot_flags(initprot))
                lc_buf.record_field("nsects", "uint32", cmd_off + 48, 4, nsects, str(nsects))
                s_flags_names, s_flags_bits = decode_segment_flags(s_flags)
                lc_buf.record_field("flags", "uint32", cmd_off + 52, 4, s_flags, f"0x{s_flags:x}", " | ".join(s_flags_names) if s_flags_names else "0x0", bit_flags=s_flags_bits)

            init_prot_str = format_vm_prot(initprot)
            max_prot_str = format_vm_prot(maxprot)
            seg_fields = list(lc_buf.get_fields())

            # Parse Sections in Segment
            seg_sections: List[Dict[str, Any]] = []
            for s_idx in range(min(nsects, 256)):
                sh_off = sect_hdr_base + s_idx * sect_hdr_size
                if sh_off + sect_hdr_size > cmd_off + cmdsize:
                    break
                sec_buf = buf.clone_with_fields()
                sectname = sec_buf.fixed_cstr(sh_off, 16)
                sect_segname = sec_buf.fixed_cstr(sh_off + 16, 16)
                sec_buf.record_field("sectname", "char[16]", sh_off, 16, sectname, sectname, sectname)
                sec_buf.record_field("segname", "char[16]", sh_off + 16, 16, sect_segname, sect_segname, sect_segname)

                if seg_is_64:
                    s_addr = sec_buf.u64(sh_off + 32)
                    s_size = sec_buf.u64(sh_off + 40)
                    s_offset = sec_buf.u32(sh_off + 48)
                    s_align = sec_buf.u32(sh_off + 52)
                    s_reloff = sec_buf.u32(sh_off + 56)
                    s_nreloc = sec_buf.u32(sh_off + 60)
                    sec_flags = sec_buf.u32(sh_off + 64)
                    res1 = sec_buf.u32(sh_off + 68)
                    res2 = sec_buf.u32(sh_off + 72)
                    res3 = sec_buf.u32(sh_off + 76)
                    sec_type_name, sec_attrs, sec_flag_bits = decode_section_flags(sec_flags)

                    sec_buf.record_field("addr", "uint64", sh_off + 32, 8, s_addr, f"0x{s_addr:x}", f"0x{s_addr:x}", target_vmaddr=f"0x{s_addr:x}")
                    sec_buf.record_field("size", "uint64", sh_off + 40, 8, s_size, f"0x{s_size:x}", f"{s_size:,} bytes")
                    sec_buf.record_field("offset", "uint32", sh_off + 48, 4, s_offset, f"0x{s_offset:x}", f"Slice offset 0x{s_offset:x}", target_offset=slice_base + s_offset if s_offset > 0 else None)
                    sec_buf.record_field("align", "uint32", sh_off + 52, 4, s_align, f"2^{s_align}", f"{1 << min(s_align, 30)} bytes")
                    sec_buf.record_field("reloff", "uint32", sh_off + 56, 4, s_reloff, f"0x{s_reloff:x}")
                    sec_buf.record_field("nreloc", "uint32", sh_off + 60, 4, s_nreloc, str(s_nreloc))
                    sec_buf.record_field("flags", "uint32", sh_off + 64, 4, sec_flags, f"0x{sec_flags:08x}", " | ".join([sec_type_name] + sec_attrs), bit_flags=sec_flag_bits)
                    sec_buf.record_field("reserved1", "uint32", sh_off + 68, 4, res1, str(res1), f"Indirect sym index {res1}")
                    sec_buf.record_field("reserved2", "uint32", sh_off + 72, 4, res2, str(res2), f"Stub size {res2}" if res2 else "0")
                    sec_buf.record_field("reserved3", "uint32", sh_off + 76, 4, res3, str(res3))
                else:
                    s_addr = sec_buf.u32(sh_off + 32)
                    s_size = sec_buf.u32(sh_off + 36)
                    s_offset = sec_buf.u32(sh_off + 40)
                    s_align = sec_buf.u32(sh_off + 44)
                    s_reloff = sec_buf.u32(sh_off + 48)
                    s_nreloc = sec_buf.u32(sh_off + 52)
                    sec_flags = sec_buf.u32(sh_off + 56)
                    res1 = sec_buf.u32(sh_off + 60)
                    res2 = sec_buf.u32(sh_off + 64)
                    sec_type_name, sec_attrs, sec_flag_bits = decode_section_flags(sec_flags)

                    sec_buf.record_field("addr", "uint32", sh_off + 32, 4, s_addr, f"0x{s_addr:x}", target_vmaddr=f"0x{s_addr:x}")
                    sec_buf.record_field("size", "uint32", sh_off + 36, 4, s_size, f"0x{s_size:x}")
                    sec_buf.record_field("offset", "uint32", sh_off + 40, 4, s_offset, f"0x{s_offset:x}", target_offset=slice_base + s_offset if s_offset > 0 else None)
                    sec_buf.record_field("align", "uint32", sh_off + 44, 4, s_align, f"2^{s_align}")
                    sec_buf.record_field("reloff", "uint32", sh_off + 48, 4, s_reloff, f"0x{s_reloff:x}")
                    sec_buf.record_field("nreloc", "uint32", sh_off + 52, 4, s_nreloc, str(s_nreloc))
                    sec_buf.record_field("flags", "uint32", sh_off + 56, 4, sec_flags, f"0x{sec_flags:08x}", " | ".join([sec_type_name] + sec_attrs), bit_flags=sec_flag_bits)
                    sec_buf.record_field("reserved1", "uint32", sh_off + 60, 4, res1, str(res1))
                    sec_buf.record_field("reserved2", "uint32", sh_off + 64, 4, res2, str(res2))

                is_zerofill = sec_type_name in ("S_ZEROFILL", "S_GB_ZEROFILL", "S_THREAD_LOCAL_ZEROFILL")
                sec_abs_off = (slice_base + s_offset) if (not is_zerofill and s_offset > 0) else (slice_base + fileoff)
                is_exec = (
                    "S_ATTR_PURE_INSTRUCTIONS" in sec_attrs
                    or "S_ATTR_SOME_INSTRUCTIONS" in sec_attrs
                    or bool(initprot & VM_PROT_EXECUTE)
                )

                sec_obj = {
                    "index": len(all_sections_ordered),
                    "sectname": sectname,
                    "segname": sect_segname or segname,
                    "vmaddr": f"0x{s_addr:x}",
                    "vmaddr_int": s_addr,
                    "size": s_size,
                    "slice_offset": s_offset,
                    "abs_offset": sec_abs_off,
                    "align": s_align,
                    "align_bytes": 1 << min(s_align, 30),
                    "reloff": s_reloff,
                    "nreloc": s_nreloc,
                    "flags": sec_flags,
                    "flags_hex": f"0x{sec_flags:08x}",
                    "section_type": sec_type_name,
                    "attributes_decoded": sec_attrs,
                    "reserved1": res1,
                    "reserved2": res2,
                    "is_executable": is_exec,
                    "is_zerofill": is_zerofill,
                    "prot": init_prot_str,
                    "region": make_region(
                        sec_abs_off,
                        s_offset,
                        0 if is_zerofill else s_size,
                        f"0x{s_addr:x}",
                        s_size,
                    ),
                    "header_region": make_region(
                        slice_base + sh_off, sh_off, sect_hdr_size
                    ),
                    "fields": sec_buf.get_fields(),
                }
                seg_sections.append(sec_obj)
                all_sections_ordered.append(sec_obj)

                if not is_zerofill and s_size > 0 and s_offset > 0:
                    intervals.append({
                        "id": f"sect_{sect_segname}_{sectname}",
                        "label": f"Section {sect_segname},{sectname}",
                        "category": "code" if is_exec else "section",
                        "abs_offset": sec_abs_off,
                        "size": s_size,
                        "vmaddr": f"0x{s_addr:x}",
                    })

            seg_abs_off = slice_base + fileoff
            seg_obj = {
                "index": len(segments),
                "segname": segname,
                "vmaddr": f"0x{vmaddr:x}",
                "vmaddr_int": vmaddr,
                "vmsize": f"0x{vmsize:x}",
                "vmsize_int": vmsize,
                "fileoff": fileoff,
                "filesize": filesize,
                "abs_offset": seg_abs_off,
                "initprot": init_prot_str,
                "maxprot": max_prot_str,
                "initprot_raw": initprot,
                "maxprot_raw": maxprot,
                "nsects": nsects,
                "flags": s_flags,
                "flags_decoded": s_flags_names,
                "region": make_region(
                    seg_abs_off, fileoff, filesize, f"0x{vmaddr:x}", vmsize
                ),
                "header_region": make_region(slice_base + cmd_off, cmd_off, cmdsize),
                "fields": seg_fields,
                "sections": seg_sections,
            }
            segments.append(seg_obj)
            if filesize > 0:
                intervals.append({
                    "id": f"seg_{segname}",
                    "label": f"{cmd_name} ({segname})",
                    "category": "segment",
                    "abs_offset": seg_abs_off,
                    "size": filesize,
                    "vmaddr": f"0x{vmaddr:x}",
                })

            summary = f"{segname} (vm: 0x{vmaddr:x}..0x{vmaddr + vmsize:x}, prot: {init_prot_str}/{max_prot_str})"
            details = {
                "segname": segname,
                "vmaddr": f"0x{vmaddr:x}",
                "vmsize": f"0x{vmsize:x}",
                "fileoff": fileoff,
                "filesize": filesize,
                "initprot": init_prot_str,
                "maxprot": max_prot_str,
                "nsects": nsects,
            }

        # --- Dylib Commands ---
        elif cmd in (
            LC_LOAD_DYLIB,
            LC_ID_DYLIB,
            LC_LOAD_WEAK_DYLIB,
            LC_REEXPORT_DYLIB,
            LC_LAZY_LOAD_DYLIB,
            LC_LOAD_UPWARD_DYLIB,
        ) and cmdsize >= 24:
            str_off = lc_buf.u32(cmd_off + 8)
            timestamp = lc_buf.u32(cmd_off + 12)
            cur_ver = lc_buf.u32(cmd_off + 16)
            compat_ver = lc_buf.u32(cmd_off + 20)
            dylib_path, str_len = (
                lc_buf.cstr_at(cmd_off + str_off, max(0, cmdsize - str_off))
                if str_off < cmdsize
                else ("", 0)
            )
            cur_ver_str = format_packed_version(cur_ver)
            compat_ver_str = format_packed_version(compat_ver)

            lc_buf.record_field("name.offset", "uint32", cmd_off + 8, 4, str_off, f"0x{str_off:x}", f"'{dylib_path}'")
            lc_buf.record_field("timestamp", "uint32", cmd_off + 12, 4, timestamp, str(timestamp))
            lc_buf.record_field("current_version", "uint32", cmd_off + 16, 4, cur_ver, f"0x{cur_ver:x}", cur_ver_str)
            lc_buf.record_field("compatibility_version", "uint32", cmd_off + 20, 4, compat_ver, f"0x{compat_ver:x}", compat_ver_str)
            if str_off < cmdsize:
                lc_buf.record_field("name", "string", cmd_off + str_off, cmdsize - str_off, dylib_path, dylib_path, dylib_path)

            if cmd != LC_ID_DYLIB:
                dylibs.append({
                    "index": len(dylibs),
                    "cmd_name": cmd_name,
                    "name": dylib_path,
                    "timestamp": timestamp,
                    "current_version": cur_ver_str,
                    "compatibility_version": compat_ver_str,
                    "abs_offset": slice_base + cmd_off,
                    "slice_offset": cmd_off,
                    "size": cmdsize,
                    "fields": list(lc_buf.get_fields()),
                })
            summary = f"{dylib_path} (v{cur_ver_str}, compat {compat_ver_str})"
            details = {"name": dylib_path, "current_version": cur_ver_str, "compatibility_version": compat_ver_str}

        # --- LC_RPATH ---
        elif cmd == LC_RPATH and cmdsize >= 12:
            str_off = lc_buf.u32(cmd_off + 8)
            rpath_str, _ = lc_buf.cstr_at(cmd_off + str_off, max(0, cmdsize - str_off))
            lc_buf.record_field("path.offset", "uint32", cmd_off + 8, 4, str_off, f"0x{str_off:x}", rpath_str)
            if str_off < cmdsize:
                lc_buf.record_field("path", "string", cmd_off + str_off, cmdsize - str_off, rpath_str, rpath_str, rpath_str)
            rpaths.append({
                "path": rpath_str,
                "abs_offset": slice_base + cmd_off,
                "slice_offset": cmd_off,
                "size": cmdsize,
            })
            summary = rpath_str
            details = {"path": rpath_str}

        # --- LC_LOAD_DYLINKER / LC_ID_DYLINKER / LC_DYLD_ENVIRONMENT ---
        elif cmd in (LC_LOAD_DYLINKER, LC_ID_DYLINKER, LC_DYLD_ENVIRONMENT) and cmdsize >= 12:
            str_off = lc_buf.u32(cmd_off + 8)
            s_val, _ = lc_buf.cstr_at(cmd_off + str_off, max(0, cmdsize - str_off))
            lc_buf.record_field("name.offset", "uint32", cmd_off + 8, 4, str_off, f"0x{str_off:x}", s_val)
            if str_off < cmdsize:
                lc_buf.record_field("name", "string", cmd_off + str_off, cmdsize - str_off, s_val, s_val, s_val)
            summary = s_val
            details = {"name": s_val}

        # --- LC_UUID ---
        elif cmd == LC_UUID and cmdsize >= 24:
            raw_uuid = lc_buf.read_bytes(cmd_off + 8, 16)
            uuid_str = str(uuid.UUID(bytes=raw_uuid)).upper()
            lc_buf.record_field("uuid", "uint8[16]", cmd_off + 8, 16, uuid_str, uuid_str, uuid_str)
            summary = uuid_str
            details = {"uuid": uuid_str}

        # --- LC_BUILD_VERSION ---
        elif cmd == LC_BUILD_VERSION and cmdsize >= 24:
            plat_id = lc_buf.u32(cmd_off + 8)
            minos_raw = lc_buf.u32(cmd_off + 12)
            sdk_raw = lc_buf.u32(cmd_off + 16)
            ntools = lc_buf.u32(cmd_off + 20)
            platform_str = PLATFORMS.get(plat_id, f"Platform({plat_id})")
            minos_str = format_packed_version(minos_raw)
            sdk_str = format_packed_version(sdk_raw)
            lc_buf.record_field("platform", "uint32", cmd_off + 8, 4, plat_id, str(plat_id), platform_str)
            lc_buf.record_field("minos", "uint32", cmd_off + 12, 4, minos_raw, f"0x{minos_raw:x}", minos_str)
            lc_buf.record_field("sdk", "uint32", cmd_off + 16, 4, sdk_raw, f"0x{sdk_raw:x}", sdk_str)
            lc_buf.record_field("ntools", "uint32", cmd_off + 20, 4, ntools, str(ntools))
            tools_list = []
            for t_i in range(min(ntools, 16)):
                t_off = cmd_off + 24 + t_i * 8
                if t_off + 8 > cmd_off + cmdsize:
                    break
                t_id = lc_buf.u32(t_off)
                t_ver = lc_buf.u32(t_off + 4)
                t_name = BUILD_TOOLS.get(t_id, f"tool_{t_id}")
                t_ver_str = format_packed_version(t_ver)
                lc_buf.record_field(f"tools[{t_i}].tool", "uint32", t_off, 4, t_id, str(t_id), t_name)
                lc_buf.record_field(f"tools[{t_i}].version", "uint32", t_off + 4, 4, t_ver, f"0x{t_ver:x}", t_ver_str)
                tools_list.append({"tool": t_name, "version": t_ver_str})
            summary = f"{platform_str} (minos {minos_str}, sdk {sdk_str})"
            details = {"platform": platform_str, "minos": minos_str, "sdk": sdk_str, "tools": tools_list}

        # --- Legacy LC_VERSION_MIN_* ---
        elif cmd in (
            LC_VERSION_MIN_MACOSX,
            LC_VERSION_MIN_IPHONEOS,
            LC_VERSION_MIN_TVOS,
            LC_VERSION_MIN_WATCHOS,
        ) and cmdsize >= 16:
            v_raw = lc_buf.u32(cmd_off + 8)
            s_raw = lc_buf.u32(cmd_off + 12)
            minos_str = format_packed_version(v_raw)
            sdk_str = format_packed_version(s_raw)
            lc_buf.record_field("version", "uint32", cmd_off + 8, 4, v_raw, f"0x{v_raw:x}", minos_str)
            lc_buf.record_field("sdk", "uint32", cmd_off + 12, 4, s_raw, f"0x{s_raw:x}", sdk_str)
            summary = f"minos {minos_str}, sdk {sdk_str}"
            details = {"minos": minos_str, "sdk": sdk_str}

        # --- LC_SOURCE_VERSION ---
        elif cmd == LC_SOURCE_VERSION and cmdsize >= 16:
            sv_raw = lc_buf.u64(cmd_off + 8)
            source_version_str = format_source_version(sv_raw)
            lc_buf.record_field("version", "uint64", cmd_off + 8, 8, sv_raw, f"0x{sv_raw:x}", source_version_str)
            summary = source_version_str
            details = {"version": source_version_str}

        # --- LC_MAIN ---
        elif cmd == LC_MAIN and cmdsize >= 24:
            entryoff = lc_buf.u64(cmd_off + 8)
            stacksize = lc_buf.u64(cmd_off + 16)
            lc_buf.record_field("entryoff", "uint64", cmd_off + 8, 8, entryoff, f"0x{entryoff:x}", f"Slice offset 0x{entryoff:x}", target_offset=slice_base + entryoff)
            lc_buf.record_field("stacksize", "uint64", cmd_off + 16, 8, stacksize, f"0x{stacksize:x}", f"{stacksize:,} bytes")
            entry_point_info = {
                "type": "LC_MAIN",
                "entryoff": entryoff,
                "vmaddr": "0x0",  # Resolved after __TEXT is known
                "abs_offset": slice_base + entryoff,
                "stacksize": stacksize,
                "thread_flavor": None,
                "registers": {},
            }
            summary = f"entryoff: 0x{entryoff:x}, stacksize: 0x{stacksize:x}"
            details = {"entryoff": entryoff, "stacksize": stacksize}

        # --- LC_UNIXTHREAD / LC_THREAD (Firmware & Kernel Entry State) ---
        elif cmd in (LC_UNIXTHREAD, LC_THREAD) and cmdsize >= 16:
            flavor = lc_buf.u32(cmd_off + 8)
            count = lc_buf.u32(cmd_off + 12)
            lc_buf.record_field("flavor", "uint32", cmd_off + 8, 4, flavor, str(flavor), "ARM_THREAD_STATE64 (6)" if flavor == 6 else f"Flavor {flavor}")
            lc_buf.record_field("count", "uint32", cmd_off + 12, 4, count, str(count), f"{count} uint32 words")
            regs: Dict[str, str] = {}
            pc_val = 0
            reg_base = cmd_off + 16
            if cputype == CPU_TYPE_ARM64 and flavor == 6 and cmdsize >= 16 + 272:
                for r_i in range(29):
                    rv = lc_buf.u64(reg_base + r_i * 8)
                    regs[f"x{r_i}"] = f"0x{rv:016x}"
                    if r_i < 4 or rv != 0:
                        lc_buf.record_field(f"x{r_i}", "uint64", reg_base + r_i * 8, 8, rv, f"0x{rv:016x}")
                fp_v = lc_buf.u64(reg_base + 29 * 8)
                lr_v = lc_buf.u64(reg_base + 30 * 8)
                sp_v = lc_buf.u64(reg_base + 31 * 8)
                pc_val = lc_buf.u64(reg_base + 32 * 8)
                cpsr_v = lc_buf.u32(reg_base + 33 * 8)
                regs["fp"] = f"0x{fp_v:016x}"
                regs["lr"] = f"0x{lr_v:016x}"
                regs["sp"] = f"0x{sp_v:016x}"
                regs["pc"] = f"0x{pc_val:016x}"
                regs["cpsr"] = f"0x{cpsr_v:08x}"
                lc_buf.record_field("fp (x29)", "uint64", reg_base + 29 * 8, 8, fp_v, f"0x{fp_v:016x}")
                lc_buf.record_field("lr (x30)", "uint64", reg_base + 30 * 8, 8, lr_v, f"0x{lr_v:016x}")
                lc_buf.record_field("sp", "uint64", reg_base + 31 * 8, 8, sp_v, f"0x{sp_v:016x}")
                lc_buf.record_field("pc", "uint64", reg_base + 32 * 8, 8, pc_val, f"0x{pc_val:016x}", "Firmware Entry Point PC", target_vmaddr=f"0x{pc_val:x}")
                lc_buf.record_field("cpsr", "uint32", reg_base + 33 * 8, 4, cpsr_v, f"0x{cpsr_v:08x}")
            elif cputype == CPU_TYPE_X86_64 and cmdsize >= 16 + 168:
                x86_regs = ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags"]
                for r_i, r_name in enumerate(x86_regs):
                    if reg_base + (r_i + 1) * 8 <= cmd_off + cmdsize:
                        rv = lc_buf.u64(reg_base + r_i * 8)
                        regs[r_name] = f"0x{rv:016x}"
                        if r_name in ("rsp", "rip", "rax", "rdi"):
                            lc_buf.record_field(r_name, "uint64", reg_base + r_i * 8, 8, rv, f"0x{rv:016x}")
                        if r_name == "rip":
                            pc_val = rv

            entry_point_info = {
                "type": cmd_name,
                "entryoff": 0,
                "vmaddr": f"0x{pc_val:x}",
                "abs_offset": slice_base,
                "stacksize": 0,
                "thread_flavor": f"ARM_THREAD_STATE64 ({flavor})" if flavor == 6 else f"THREAD_STATE ({flavor})",
                "registers": regs,
            }
            summary = f"Entry PC: 0x{pc_val:x} ({entry_point_info['thread_flavor']})"
            details = entry_point_info

        # --- LC_SYMTAB ---
        elif cmd == LC_SYMTAB and cmdsize >= 24:
            symoff = lc_buf.u32(cmd_off + 8)
            nsyms = lc_buf.u32(cmd_off + 12)
            stroff = lc_buf.u32(cmd_off + 16)
            strsize = lc_buf.u32(cmd_off + 20)
            lc_buf.record_field("symoff", "uint32", cmd_off + 8, 4, symoff, f"0x{symoff:x}", f"Slice offset 0x{symoff:x}", target_offset=slice_base + symoff)
            lc_buf.record_field("nsyms", "uint32", cmd_off + 12, 4, nsyms, str(nsyms), f"{nsyms:,} symbols")
            lc_buf.record_field("stroff", "uint32", cmd_off + 16, 4, stroff, f"0x{stroff:x}", f"Slice offset 0x{stroff:x}", target_offset=slice_base + stroff)
            lc_buf.record_field("strsize", "uint32", cmd_off + 20, 4, strsize, f"0x{strsize:x}", f"{strsize:,} bytes")
            symtab_cmd = {"symoff": symoff, "nsyms": nsyms, "stroff": stroff, "strsize": strsize}
            summary = f"{nsyms:,} symbols (symoff: 0x{symoff:x}, stroff: 0x{stroff:x})"
            details = symtab_cmd
            if nsyms > 0:
                intervals.append({
                    "id": "symtab_table",
                    "label": "Symbol Table (nlist)",
                    "category": "symtab",
                    "abs_offset": slice_base + symoff,
                    "size": nsyms * (16 if is_64 else 12),
                    "vmaddr": None,
                })
            if strsize > 0:
                intervals.append({
                    "id": "symtab_strings",
                    "label": "Symbol String Table",
                    "category": "strings",
                    "abs_offset": slice_base + stroff,
                    "size": strsize,
                    "vmaddr": None,
                })

        # --- LC_DYSYMTAB ---
        elif cmd == LC_DYSYMTAB and cmdsize >= 80:
            ilocalsym = lc_buf.u32(cmd_off + 8)
            nlocalsym = lc_buf.u32(cmd_off + 12)
            iextdefsym = lc_buf.u32(cmd_off + 16)
            nextdefsym = lc_buf.u32(cmd_off + 20)
            iundefsym = lc_buf.u32(cmd_off + 24)
            nundefsym = lc_buf.u32(cmd_off + 28)
            indirectsymoff = lc_buf.u32(cmd_off + 56)
            nindirectsyms = lc_buf.u32(cmd_off + 60)

            lc_buf.record_field("ilocalsym", "uint32", cmd_off + 8, 4, ilocalsym, str(ilocalsym))
            lc_buf.record_field("nlocalsym", "uint32", cmd_off + 12, 4, nlocalsym, str(nlocalsym), f"{nlocalsym} local symbols")
            lc_buf.record_field("iextdefsym", "uint32", cmd_off + 16, 4, iextdefsym, str(iextdefsym))
            lc_buf.record_field("nextdefsym", "uint32", cmd_off + 20, 4, nextdefsym, str(nextdefsym), f"{nextdefsym} external defined")
            lc_buf.record_field("iundefsym", "uint32", cmd_off + 24, 4, iundefsym, str(iundefsym))
            lc_buf.record_field("nundefsym", "uint32", cmd_off + 28, 4, nundefsym, str(nundefsym), f"{nundefsym} undefined imported")
            lc_buf.record_field("indirectsymoff", "uint32", cmd_off + 56, 4, indirectsymoff, f"0x{indirectsymoff:x}", target_offset=slice_base + indirectsymoff if indirectsymoff else None)
            lc_buf.record_field("nindirectsyms", "uint32", cmd_off + 60, 4, nindirectsyms, str(nindirectsyms))

            dysymtab_cmd = {
                "present": True,
                "ilocalsym": ilocalsym,
                "nlocalsym": nlocalsym,
                "iextdefsym": iextdefsym,
                "nextdefsym": nextdefsym,
                "iundefsym": iundefsym,
                "nundefsym": nundefsym,
                "indirectsymoff": indirectsymoff,
                "nindirectsyms": nindirectsyms,
                "fields": list(lc_buf.get_fields()),
            }
            summary = f"local: {nlocalsym}, extdef: {nextdefsym}, undef: {nundefsym}, indirect: {nindirectsyms}"
            details = dysymtab_cmd

        # --- Linkedit Data Commands (Code Signature, Chained Fixups, Exports Trie, Function Starts, Data-in-Code) ---
        elif cmd in (
            LC_CODE_SIGNATURE,
            LC_DYLD_CHAINED_FIXUPS,
            LC_DYLD_EXPORTS_TRIE,
            LC_FUNCTION_STARTS,
            LC_DATA_IN_CODE,
        ) and cmdsize >= 16:
            dataoff = lc_buf.u32(cmd_off + 8)
            datasize = lc_buf.u32(cmd_off + 12)
            lc_buf.record_field("dataoff", "uint32", cmd_off + 8, 4, dataoff, f"0x{dataoff:x}", f"Slice offset 0x{dataoff:x}", target_offset=slice_base + dataoff)
            lc_buf.record_field("datasize", "uint32", cmd_off + 12, 4, datasize, f"0x{datasize:x}", f"{datasize:,} bytes")
            summary = f"dataoff: 0x{dataoff:x}, datasize: {datasize:,} bytes"
            details = {"dataoff": dataoff, "datasize": datasize}

            if cmd == LC_CODE_SIGNATURE:
                code_sig_cmd = (dataoff, datasize)
                intervals.append({
                    "id": "codesig_blob",
                    "label": "Code Signature SuperBlob",
                    "category": "codesign",
                    "abs_offset": slice_base + dataoff,
                    "size": datasize,
                    "vmaddr": None,
                })
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                chained_fixups_cmd = (dataoff, datasize)
            elif cmd == LC_DYLD_EXPORTS_TRIE:
                exports_trie_cmd = (dataoff, datasize)
            elif cmd == LC_FUNCTION_STARTS:
                func_starts_cmd = (dataoff, datasize)
            elif cmd == LC_DATA_IN_CODE:
                dice_entries = []
                for d_i in range(min(datasize // 8, 128)):
                    d_pos = dataoff + d_i * 8
                    if d_pos + 8 <= slice_size:
                        d_off = lc_buf.u32(d_pos)
                        d_len = lc_buf.u16(d_pos + 4)
                        d_kind = lc_buf.u16(d_pos + 6)
                        dice_entries.append({
                            "offset": f"0x{d_off:x}",
                            "length": d_len,
                            "kind": DICE_KINDS.get(d_kind, f"KIND_{d_kind}"),
                        })
                details["entries"] = dice_entries

        # --- LC_DYLD_INFO / LC_DYLD_INFO_ONLY ---
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY) and cmdsize >= 48:
            rebase_off = lc_buf.u32(cmd_off + 8)
            rebase_size = lc_buf.u32(cmd_off + 12)
            bind_off = lc_buf.u32(cmd_off + 16)
            bind_size = lc_buf.u32(cmd_off + 20)
            weak_bind_off = lc_buf.u32(cmd_off + 24)
            weak_bind_size = lc_buf.u32(cmd_off + 28)
            lazy_bind_off = lc_buf.u32(cmd_off + 32)
            lazy_bind_size = lc_buf.u32(cmd_off + 36)
            export_off = lc_buf.u32(cmd_off + 40)
            export_size = lc_buf.u32(cmd_off + 44)

            lc_buf.record_field("rebase_off", "uint32", cmd_off + 8, 4, rebase_off, f"0x{rebase_off:x}")
            lc_buf.record_field("rebase_size", "uint32", cmd_off + 12, 4, rebase_size, f"{rebase_size} bytes")
            lc_buf.record_field("bind_off", "uint32", cmd_off + 16, 4, bind_off, f"0x{bind_off:x}")
            lc_buf.record_field("bind_size", "uint32", cmd_off + 20, 4, bind_size, f"{bind_size} bytes")
            lc_buf.record_field("export_off", "uint32", cmd_off + 40, 4, export_off, f"0x{export_off:x}")
            lc_buf.record_field("export_size", "uint32", cmd_off + 44, 4, export_size, f"{export_size} bytes")

            dyld_info_cmd = {
                "rebase_off": rebase_off,
                "rebase_size": rebase_size,
                "bind_off": bind_off,
                "bind_size": bind_size,
                "weak_bind_off": weak_bind_off,
                "weak_bind_size": weak_bind_size,
                "lazy_bind_off": lazy_bind_off,
                "lazy_bind_size": lazy_bind_size,
                "export_off": export_off,
                "export_size": export_size,
            }
            summary = f"rebase: {rebase_size}B, bind: {bind_size}B, export: {export_size}B"
            details = dyld_info_cmd

        # --- LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 ---
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64) and cmdsize >= 20:
            cryptoff = lc_buf.u32(cmd_off + 8)
            cryptsize = lc_buf.u32(cmd_off + 12)
            cryptid = lc_buf.u32(cmd_off + 16)
            lc_buf.record_field("cryptoff", "uint32", cmd_off + 8, 4, cryptoff, f"0x{cryptoff:x}")
            lc_buf.record_field("cryptsize", "uint32", cmd_off + 12, 4, cryptsize, f"0x{cryptsize:x}")
            lc_buf.record_field("cryptid", "uint32", cmd_off + 16, 4, cryptid, str(cryptid), "Unencrypted (0)" if cryptid == 0 else f"Encrypted (ID {cryptid})")
            encryption_info = {
                "present": True,
                "cryptoff": cryptoff,
                "cryptsize": cryptsize,
                "cryptid": cryptid,
            }
            summary = f"cryptid: {cryptid}, cryptoff: 0x{cryptoff:x}, cryptsize: 0x{cryptsize:x}"
            details = encryption_info

        # --- LC_FILESET_ENTRY (XNU Kernelcache) ---
        elif cmd == LC_FILESET_ENTRY and cmdsize >= 32:
            f_vmaddr = lc_buf.u64(cmd_off + 8)
            f_fileoff = lc_buf.u64(cmd_off + 16)
            entry_id_off = lc_buf.u32(cmd_off + 24)
            entry_id, _ = lc_buf.cstr_at(cmd_off + entry_id_off, max(0, cmdsize - entry_id_off))
            lc_buf.record_field("vmaddr", "uint64", cmd_off + 8, 8, f_vmaddr, f"0x{f_vmaddr:x}")
            lc_buf.record_field("fileoff", "uint64", cmd_off + 16, 8, f_fileoff, f"0x{f_fileoff:x}", target_offset=slice_base + f_fileoff)
            lc_buf.record_field("entry_id", "string", cmd_off + entry_id_off, cmdsize - entry_id_off, entry_id, entry_id)
            fe_obj = {
                "entry_id": entry_id,
                "vmaddr": f"0x{f_vmaddr:x}",
                "fileoff": f_fileoff,
                "abs_offset": slice_base + f_fileoff,
            }
            fileset_entries.append(fe_obj)
            summary = f"{entry_id} @ vm 0x{f_vmaddr:x}"
            details = fe_obj

        load_commands.append({
            "index": cmd_idx,
            "cmd": cmd,
            "cmd_hex": f"0x{cmd:x}",
            "cmd_name": cmd_name,
            "cmdsize": cmdsize,
            "req_dyld": req_dyld,
            "summary": summary,
            "region": make_region(slice_base + cmd_off, cmd_off, cmdsize),
            "fields": lc_buf.get_fields(),
            "details": details,
        })
        intervals.append({
            "id": f"lc_{cmd_idx}",
            "label": f"Load Command #{cmd_idx}: {cmd_name}",
            "category": "load_command",
            "abs_offset": slice_base + cmd_off,
            "size": cmdsize,
            "vmaddr": None,
        })

        cmd_off += cmdsize

    # Find __TEXT base vmaddr for relative offsets
    text_vmaddr = 0
    for seg in segments:
        if seg["segname"] == "__TEXT":
            text_vmaddr = seg["vmaddr_int"]
            break
    if text_vmaddr == 0 and segments:
        for seg in segments:
            if seg["segname"] != "__PAGEZERO":
                text_vmaddr = seg["vmaddr_int"]
                break

    # Resolve entry_point VMAddr / abs_offset
    if entry_point_info["type"] == "LC_MAIN":
        ep_vm = text_vmaddr + entry_point_info["entryoff"]
        entry_point_info["vmaddr"] = f"0x{ep_vm:x}"
        entry_point_info["abs_offset"] = slice_base + entry_point_info["entryoff"]
    elif entry_point_info["type"] in ("LC_UNIXTHREAD", "LC_THREAD"):
        ep_vm = int(entry_point_info["vmaddr"], 16)
        for seg in segments:
            if seg["vmaddr_int"] <= ep_vm < seg["vmaddr_int"] + seg["vmsize_int"]:
                sl_off = seg["fileoff"] + (ep_vm - seg["vmaddr_int"])
                entry_point_info["entryoff"] = sl_off
                entry_point_info["abs_offset"] = slice_base + sl_off
                break

    intervals.append({
        "id": f"header_{slice_index}",
        "label": "mach_header_64" if is_64 else "mach_header",
        "category": "header",
        "abs_offset": slice_base,
        "size": hdr_size,
        "vmaddr": f"0x{text_vmaddr:x}" if text_vmaddr else None,
    })

    # Parse Symbol Table (LC_SYMTAB)
    symbols: List[Dict[str, Any]] = []
    if symtab_cmd:
        symoff = symtab_cmd["symoff"]
        nsyms = min(symtab_cmd["nsyms"], 10000)
        stroff = symtab_cmd["stroff"]
        strsize = symtab_cmd["strsize"]
        ent_size = 16 if is_64 else 12

        raw_sym_names: List[str] = []
        parsed_raw_syms: List[Tuple[int, int, int, int, int, int, str]] = []

        for s_i in range(nsyms):
            pos = symoff + s_i * ent_size
            if pos + ent_size > slice_size:
                break
            n_strx = buf.u32(pos)
            n_type = buf.u8(pos + 4)
            n_sect = buf.u8(pos + 5)
            n_desc = buf.u16(pos + 6)
            n_value = buf.u64(pos + 8) if is_64 else buf.u32(pos + 8)

            sym_name = ""
            if 0 < n_strx < strsize:
                sym_name, _ = buf.cstr_at(stroff + n_strx, 512)
            raw_sym_names.append(sym_name)
            parsed_raw_syms.append((s_i, pos, n_strx, n_type, n_sect, n_desc, n_value, sym_name))

        demangled_map = _batch_demangle(raw_sym_names)

        for s_i, pos, n_strx, n_type, n_sect, n_desc, n_value, sym_name in parsed_raw_syms:
            is_stab = bool(n_type & N_STAB)
            is_pext = bool(n_type & N_PEXT)
            is_ext = bool(n_type & N_EXT)
            type_masked = n_type & N_TYPE
            type_name = "STAB" if is_stab else N_TYPE_NAMES.get(type_masked, f"0x{type_masked:x}")

            sec_name = ""
            if type_masked == N_SECT and 1 <= n_sect <= len(all_sections_ordered):
                sec_ref = all_sections_ordered[n_sect - 1]
                sec_name = f"{sec_ref['segname']},{sec_ref['sectname']}"

            lib_ord = (n_desc >> 8) & 0xFF
            if type_masked == N_UNDF and is_ext:
                if 1 <= lib_ord <= len(dylibs):
                    lib_name = os.path.basename(dylibs[lib_ord - 1]["name"])
                elif lib_ord == 0:
                    lib_name = "SELF"
                elif lib_ord == 0xFE:
                    lib_name = "DYNAMIC_LOOKUP"
                elif lib_ord == 0xFF:
                    lib_name = "EXECUTABLE"
                else:
                    lib_name = f"ORDINAL_{lib_ord}"
            else:
                lib_name = "SELF"

            target_abs_off: Optional[int] = None
            if type_masked == N_SECT and n_value > 0:
                for seg in segments:
                    if seg["vmaddr_int"] <= n_value < seg["vmaddr_int"] + seg["filesize"]:
                        target_abs_off = slice_base + seg["fileoff"] + (n_value - seg["vmaddr_int"])
                        break

            symbols.append({
                "index": s_i,
                "name": sym_name,
                "demangled": demangled_map.get(sym_name, sym_name),
                "n_strx": n_strx,
                "n_type": n_type,
                "n_type_hex": f"0x{n_type:02x}",
                "type_name": type_name,
                "is_external": is_ext,
                "is_private_external": is_pext,
                "is_stab": is_stab,
                "n_sect": n_sect,
                "section_name": sec_name,
                "n_desc": n_desc,
                "library_ordinal": lib_ord,
                "library_name": lib_name,
                "n_value": f"0x{n_value:x}",
                "n_value_int": n_value,
                "abs_offset": slice_base + pos,
                "slice_offset": pos,
                "size": ent_size,
                "target_abs_offset": target_abs_off,
            })

    # Parse Indirect Symbol Table (LC_DYSYMTAB)
    indirect_symbols: List[Dict[str, Any]] = []
    if dysymtab_cmd and dysymtab_cmd.get("nindirectsyms", 0) > 0:
        ind_off = dysymtab_cmd["indirectsymoff"]
        n_ind = min(dysymtab_cmd["nindirectsyms"], 2000)
        for sec in all_sections_ordered:
            s_type = sec["section_type"]
            if s_type in (
                "S_SYMBOL_STUBS",
                "S_LAZY_SYMBOL_POINTERS",
                "S_NON_LAZY_SYMBOL_POINTERS",
                "S_LAZY_DYLIB_SYMBOL_POINTERS",
            ):
                stride = sec["reserved2"] if sec["reserved2"] > 0 else (8 if is_64 else 4)
                if stride <= 0:
                    continue
                count_slots = sec["size"] // stride
                start_ind_idx = sec["reserved1"]
                for slot_i in range(min(count_slots, 512)):
                    table_idx = start_ind_idx + slot_i
                    if table_idx >= n_ind or ind_off + (table_idx + 1) * 4 > slice_size:
                        break
                    sym_idx = buf.u32(ind_off + table_idx * 4)
                    if sym_idx & INDIRECT_SYMBOL_LOCAL:
                        sym_name = "INDIRECT_SYMBOL_LOCAL"
                    elif sym_idx & INDIRECT_SYMBOL_ABS:
                        sym_name = "INDIRECT_SYMBOL_ABS"
                    elif sym_idx < len(symbols):
                        sym_name = symbols[sym_idx]["name"]
                    else:
                        sym_name = f"sym_{sym_idx}"

                    slot_vm = sec["vmaddr_int"] + slot_i * stride
                    indirect_symbols.append({
                        "index": len(indirect_symbols),
                        "section": f"{sec['segname']},{sec['sectname']}",
                        "slot_vmaddr": f"0x{slot_vm:x}",
                        "symtab_index": sym_idx,
                        "symbol_name": sym_name,
                    })

    dysymtab_obj = (
        {
            "present": True,
            "ilocalsym": dysymtab_cmd["ilocalsym"],
            "nlocalsym": dysymtab_cmd["nlocalsym"],
            "iextdefsym": dysymtab_cmd["iextdefsym"],
            "nextdefsym": dysymtab_cmd["nextdefsym"],
            "iundefsym": dysymtab_cmd["iundefsym"],
            "nundefsym": dysymtab_cmd["nundefsym"],
            "indirect_symbols": indirect_symbols,
            "fields": dysymtab_cmd["fields"],
        }
        if dysymtab_cmd
        else {
            "present": False,
            "ilocalsym": 0,
            "nlocalsym": 0,
            "iextdefsym": 0,
            "nextdefsym": 0,
            "iundefsym": 0,
            "nundefsym": 0,
            "indirect_symbols": [],
            "fields": [],
        }
    )

    # Parse Dyld Info, Exports Trie, and Chained Fixups
    chained_fixups_obj: Dict[str, Any] = {}
    if chained_fixups_cmd:
        chained_fixups_obj = parse_chained_fixups(
            buf, chained_fixups_cmd[0], chained_fixups_cmd[1], segments, dylibs
        )

    exports_list: List[Dict[str, Any]] = []
    if exports_trie_cmd:
        exports_list = parse_exports_trie(
            buf, exports_trie_cmd[0], exports_trie_cmd[1], text_vmaddr
        )
    elif dyld_info_cmd and dyld_info_cmd.get("export_size", 0) > 0:
        exports_list = parse_exports_trie(
            buf, dyld_info_cmd["export_off"], dyld_info_cmd["export_size"], text_vmaddr
        )

    dyld_info_obj = {
        "has_dyld_info": dyld_info_cmd is not None,
        "has_chained_fixups": bool(chained_fixups_obj),
        "has_exports_trie": len(exports_list) > 0,
        "chained_fixups": chained_fixups_obj if chained_fixups_obj else None,
        "exports": exports_list,
        "rebases": [],
        "binds": [],
    }

    # Parse LC_FUNCTION_STARTS
    function_starts: List[Dict[str, Any]] = []
    if func_starts_cmd:
        fs_off, fs_size = func_starts_cmd
        sym_lookup = {
            s["n_value_int"]: s["name"]
            for s in symbols
            if s["type_name"] == "SECT" and s["n_value_int"] > 0 and not s["is_stab"]
        }
        cur_fs = fs_off
        end_fs = min(slice_size, fs_off + fs_size)
        addr_accum = 0
        while cur_fs < end_fs and len(function_starts) < 5000:
            delta, d_len = buf.read_uleb128(cur_fs)
            cur_fs += d_len
            if delta == 0:
                break
            addr_accum += delta
            fn_vm = text_vmaddr + addr_accum
            fn_name = sym_lookup.get(fn_vm, f"sub_{fn_vm:x}")
            function_starts.append({
                "index": len(function_starts),
                "vmaddr": f"0x{fn_vm:x}",
                "slice_offset": addr_accum,
                "abs_offset": slice_base + addr_accum,
                "name": fn_name,
            })

    # Extract Strings & Objective-C Metadata
    strings_list: List[Dict[str, Any]] = []
    objc_classes: List[str] = []
    objc_selectors: List[str] = []

    string_section_names = {
        "__cstring",
        "__objc_methname",
        "__objc_classname",
        "__objc_methtype",
        "__oslogstring",
    }

    for sec in all_sections_ordered:
        sname = sec["sectname"]
        stype = sec["section_type"]
        if (
            stype == "S_CSTRING_LITERALS"
            or sname in string_section_names
            or "string" in sname.lower()
            or "cfg" in sname.lower()
        ):
            s_off = sec["slice_offset"]
            s_sz = min(sec["size"], 262144)
            if s_off <= 0 or s_off + s_sz > slice_size:
                continue
            raw_sec = buf.read_bytes(s_off, s_sz)
            pos = 0
            while pos < len(raw_sec) and len(strings_list) < 3000:
                nul = raw_sec.find(b"\x00", pos)
                if nul == -1:
                    chunk = raw_sec[pos:]
                    next_pos = len(raw_sec)
                else:
                    chunk = raw_sec[pos:nul]
                    next_pos = nul + 1
                if len(chunk) >= 2:
                    try:
                        s_val = chunk.decode("utf-8")
                        if all(32 <= ord(ch) <= 126 or ch in "\t\n\r" for ch in s_val):
                            s_vm = sec["vmaddr_int"] + pos
                            s_sl_off = s_off + pos
                            strings_list.append({
                                "index": len(strings_list),
                                "source": f"{sec['segname']},{sec['sectname']}",
                                "vmaddr": f"0x{s_vm:x}",
                                "slice_offset": s_sl_off,
                                "abs_offset": slice_base + s_sl_off,
                                "length": len(s_val),
                                "encoding": "UTF-8",
                                "value": s_val,
                            })
                            if sname == "__objc_classname":
                                objc_classes.append(s_val)
                            elif sname == "__objc_methname":
                                objc_selectors.append(s_val)
                    except UnicodeDecodeError:
                        pass
                pos = next_pos

    # For Firmware (MH_PRELOAD) or binaries with few sectioned strings, scan raw printable strings
    if filetype == MH_PRELOAD or len(strings_list) < 5:
        ascii_re = re.compile(rb"[\x20-\x7e]{5,256}")
        seen_offsets = {st["slice_offset"] for st in strings_list}
        for seg in segments:
            if seg["filesize"] <= 0:
                continue
            scan_off = seg["fileoff"]
            scan_len = min(seg["filesize"], 131072)
            raw_seg = buf.read_bytes(scan_off, scan_len)
            for m in ascii_re.finditer(raw_seg):
                rel_o = scan_off + m.start()
                if rel_o in seen_offsets or rel_o < hdr_size + sizeofcmds:
                    continue
                s_val = m.group(0).decode("ascii", errors="replace")
                s_vm = seg["vmaddr_int"] + m.start()
                strings_list.append({
                    "index": len(strings_list),
                    "source": f"{seg['segname']} (raw scan)",
                    "vmaddr": f"0x{s_vm:x}",
                    "slice_offset": rel_o,
                    "abs_offset": slice_base + rel_o,
                    "length": len(s_val),
                    "encoding": "ASCII",
                    "value": s_val,
                })
                if len(strings_list) >= 500:
                    break

    objc_metadata = {
        "present": len(objc_classes) > 0 or len(objc_selectors) > 0,
        "classes": objc_classes,
        "selectors": objc_selectors[:250],
        "protocols": [],
    }

    # Parse Code Signature (LC_CODE_SIGNATURE)
    if code_sig_cmd:
        code_sig_detail = parse_code_signature(buf, code_sig_cmd[0], code_sig_cmd[1])
    else:
        code_sig_detail = {
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

    header_obj = {
        "magic": f"0x{magic:08x}",
        "magic_name": magic_name,
        "is_64bit": is_64,
        "little_endian": little_endian,
        "cputype": cputype,
        "cputype_name": cputype_name,
        "cpusubtype": cpusubtype,
        "cpusubtype_name": cpusubtype_name,
        "filetype": filetype,
        "filetype_name": ft_name,
        "ncmds": ncmds,
        "sizeofcmds": sizeofcmds,
        "flags": flags,
        "flags_hex": f"0x{flags:08x}",
        "flags_decoded": flags_decoded,
        "region": make_region(
            slice_base, 0, hdr_size, f"0x{text_vmaddr:x}" if text_vmaddr else None, hdr_size
        ),
        "fields": header_fields,
    }

    security_posture = evaluate_security_posture(
        header=header_obj,
        segments=segments,
        symbols=symbols,
        rpaths=rpaths,
        dyld_info=dyld_info_obj,
        code_sig_detail=code_sig_detail,
        encryption_info=encryption_info,
    )

    # Flattened Memory Map for Dual-Track Ribbon
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

    overview_obj = {
        "format": "Mach-O",
        "filetype_name": ft_name,
        "filetype_desc": ft_desc,
        "arch_display": arch_display,
        "endianness": "Little-Endian" if little_endian else "Big-Endian",
        "is_64bit": is_64,
        "uuid": uuid_str,
        "platform": platform_str,
        "minos": minos_str,
        "sdk": sdk_str,
        "source_version": source_version_str,
        "entry_point_vmaddr": entry_point_info["vmaddr"],
        "entry_point_abs_offset": entry_point_info["abs_offset"],
        "entry_point_type": entry_point_info["type"],
        "ncmds": ncmds,
        "sizeofcmds": sizeofcmds,
        "segments_count": len(segments),
        "sections_count": len(all_sections_ordered),
        "symbols_count": len(symbols),
        "strings_count": len(strings_list),
        "dylibs_count": len(dylibs),
    }

    return {
        "slice_index": slice_index,
        "format": "macho",
        "arch_name": arch_short,
        "slice_base_offset": slice_base,
        "slice_size": slice_size,
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
        "dysymtab": dysymtab_obj,
        "function_starts": function_starts,
        "strings": strings_list,
        "objc_metadata": objc_metadata,
        "fileset_entries": fileset_entries,
        "code_signature_detail": code_sig_detail,
        "security_posture": security_posture,
        "intervals": intervals,
    }


def _enrich_slice_semantics_and_pedagogy(
    slice_obj: Dict[str, Any], full_data: bytes, file_size: int
) -> Dict[str, Any]:
    fmt_upper = str(slice_obj.get("format", "MACHO")).upper()
    is_64 = bool(slice_obj.get("header", {}).get("is_64bit", True))
    slice_obj["format"] = fmt_upper
    slice_obj["is_64"] = is_64
    if "format_display" not in slice_obj:
        if fmt_upper == "ELF":
            slice_obj["format_display"] = "ELF64" if is_64 else "ELF32"
        elif fmt_upper == "PE":
            slice_obj["format_display"] = "PE32+" if is_64 else "PE32"
        else:
            slice_obj["format_display"] = "Mach-O 64" if is_64 else "Mach-O 32"
    s_base = slice_obj.get("slice_base_offset", 0)
    s_size = slice_obj.get("slice_size", file_size)
    raw_slice = full_data[s_base : min(file_size, s_base + s_size)]
    slice_obj["semantic_layers"] = build_semantic_layers(slice_obj, raw_slice, file_size)
    slice_obj["pedagogy"] = build_pedagogy_bundle(slice_obj)
    return slice_obj


# ============================================================================
# Top-Level Multi-Format Binary Entrypoint (Mach-O / Universal, ELF32/64, PE32/64)
# ============================================================================
def parse_macho_bytes(data: bytes, path: str = "<memory>") -> Dict[str, Any]:
    if len(data) < 28:
        raise ValueError(f"File too small ({len(data)} bytes) to be a valid Mach-O, ELF, or PE binary.")

    file_size = len(data)
    sha256_hex = hashlib.sha256(data).hexdigest()
    md5_hex = hashlib.md5(data).hexdigest()

    # 1. Check for ELF32 / ELF64 (\x7fELF)
    if data[:4] == ELF_MAGIC:
        elf_slice = parse_elf_slice(data, path=path)
        _enrich_slice_semantics_and_pedagogy(elf_slice, data, file_size)
        return {
            "file_info": {
                "path": path,
                "filename": os.path.basename(path),
                "file_size": file_size,
                "sha256": sha256_hex,
                "md5": md5_hex,
                "format": "ELF",
                "format_display": "ELF64" if elf_slice["header"]["is_64bit"] else "ELF32",
                "is_fat": False,
                "fat_header": None,
            },
            "slices": [elf_slice],
        }

    # 2. Check for Windows PE32 / PE32+ ('MZ' + e_lfanew -> 'PE\0\0')
    if is_pe_bytes(data):
        pe_slice = parse_pe_slice(data, path=path)
        _enrich_slice_semantics_and_pedagogy(pe_slice, data, file_size)
        return {
            "file_info": {
                "path": path,
                "filename": os.path.basename(path),
                "file_size": file_size,
                "sha256": sha256_hex,
                "md5": md5_hex,
                "format": "PE",
                "format_display": "PE32+" if pe_slice["header"]["is_64bit"] else "PE32",
                "is_fat": False,
                "fat_header": None,
            },
            "slices": [pe_slice],
        }

    # 3. Universal (Fat) & Thin Mach-O 32/64
    magic_be = struct.unpack_from(">I", data, 0)[0]
    magic_le = struct.unpack_from("<I", data, 0)[0]

    is_fat = False
    fat_header_obj: Optional[Dict[str, Any]] = None
    slices_list: List[Dict[str, Any]] = []

    if magic_be in (FAT_MAGIC, FAT_MAGIC_64, FAT_CIGAM, FAT_CIGAM_64):
        fat_is_64 = magic_be in (FAT_MAGIC_64, FAT_CIGAM_64)
        fat_little = magic_be in (FAT_CIGAM, FAT_CIGAM_64)
        fat_buf = BinaryBuffer(data, 0, file_size, little_endian=fat_little)
        nfat_arch = fat_buf.u32(4)

        # Disambiguate from Java .class files (which also start with 0xCAFEBABE)
        if 0 < nfat_arch <= 32:
            is_fat = True
            magic_name = MAGIC_NAMES.get(magic_be, f"0x{magic_be:08x}")
            fat_buf.record_field(
                "magic",
                "uint32",
                0,
                4,
                magic_be,
                f"0x{magic_be:08x}",
                f"{magic_name} (Universal Binary)",
                "Universal Fat Container Magic",
            )
            fat_buf.record_field(
                "nfat_arch",
                "uint32",
                4,
                4,
                nfat_arch,
                str(nfat_arch),
                f"{nfat_arch} architecture slices",
                "Number of architecture slices in Fat container",
            )

            arch_entry_size = 32 if fat_is_64 else 20
            slices_summary: List[Dict[str, Any]] = []
            for i in range(nfat_arch):
                ent_off = 8 + i * arch_entry_size
                if ent_off + arch_entry_size > file_size:
                    break
                cputype = fat_buf.u32(ent_off)
                cpusubtype = fat_buf.u32(ent_off + 4)
                if fat_is_64:
                    s_offset = fat_buf.u64(ent_off + 8)
                    s_size = fat_buf.u64(ent_off + 16)
                    s_align = fat_buf.u32(ent_off + 24)
                else:
                    s_offset = fat_buf.u32(ent_off + 8)
                    s_size = fat_buf.u32(ent_off + 12)
                    s_align = fat_buf.u32(ent_off + 16)

                arch_short, cputype_name, cpusubtype_name, _ = decode_cpu_arch(
                    cputype, cpusubtype
                )
                fat_buf.record_field(
                    f"arch[{i}].cputype", "uint32", ent_off, 4, cputype, f"0x{cputype:08x}", cputype_name
                )
                fat_buf.record_field(
                    f"arch[{i}].cpusubtype", "uint32", ent_off + 4, 4, cpusubtype, f"0x{cpusubtype:08x}", cpusubtype_name
                )
                if not fat_is_64:
                    fat_buf.record_field(
                        f"arch[{i}].offset", "uint32", ent_off + 8, 4, s_offset, f"0x{s_offset:x}", f"Offset 0x{s_offset:x}", target_offset=s_offset
                    )
                    fat_buf.record_field(
                        f"arch[{i}].size", "uint32", ent_off + 12, 4, s_size, f"0x{s_size:x}", f"{s_size:,} bytes"
                    )
                    fat_buf.record_field(
                        f"arch[{i}].align", "uint32", ent_off + 16, 4, s_align, f"2^{s_align}", f"{1 << min(s_align, 30):,} bytes"
                    )

                slices_summary.append({
                    "slice_index": i,
                    "arch_name": arch_short,
                    "cputype": cputype,
                    "cputype_name": cputype_name,
                    "cpusubtype": cpusubtype,
                    "cpusubtype_name": cpusubtype_name,
                    "offset": s_offset,
                    "size": s_size,
                    "align": s_align,
                    "align_bytes": 1 << min(s_align, 30),
                })

                if s_offset + 28 <= file_size:
                    actual_sz = min(s_size, file_size - s_offset)
                    parsed_slice = _parse_macho_slice(data, i, s_offset, actual_sz)
                    _enrich_slice_semantics_and_pedagogy(parsed_slice, data, file_size)
                    slices_list.append(parsed_slice)

            fat_hdr_total = 8 + nfat_arch * arch_entry_size
            fat_header_obj = {
                "magic": f"0x{magic_be:08x}",
                "magic_name": magic_name,
                "is_64bit": fat_is_64,
                "is_swapped": not fat_little,
                "nfat_arch": nfat_arch,
                "region": make_region(0, 0, fat_hdr_total),
                "fields": fat_buf.get_fields(),
                "slices_summary": slices_summary,
            }

    if not is_fat:
        if magic_le not in (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64):
            raise ValueError(
                f"Unrecognized Mach-O magic 0x{magic_be:08x} in '{path}'. Expected Mach-O (0xFEEDFACF), Universal Fat (0xCAFEBABE), ELF (0x7F454C46), or Windows PE ('MZ')."
            )
        single_slice = _parse_macho_slice(data, 0, 0, file_size)
        _enrich_slice_semantics_and_pedagogy(single_slice, data, file_size)
        slices_list.append(single_slice)

    return {
        "file_info": {
            "path": path,
            "filename": os.path.basename(path),
            "file_size": file_size,
            "sha256": sha256_hex,
            "md5": md5_hex,
            "format": "MACHO",
            "format_display": "Universal Mach-O" if is_fat else ("Mach-O 64" if slices_list[0]["header"]["is_64bit"] else "Mach-O 32"),
            "is_fat": is_fat,
            "fat_header": fat_header_obj,
        },
        "slices": slices_list,
    }


parse_binary_bytes = parse_macho_bytes


def parse_macho_file(path: str) -> Tuple[Dict[str, Any], bytes]:
    abs_path = os.path.abspath(path)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"File not found: {abs_path}")
    with open(abs_path, "rb") as f:
        data = f.read()
    doc = parse_macho_bytes(data, path=abs_path)
    return doc, data
