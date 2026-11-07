"""
Layer 3: AnalysisService — Caching, Windowed Hex Slicing, Live Byte Decoder,
Bidirectional VMAddr <-> FileOffset Translator, Disassembly, and Omni-Search.
"""

import math
import os
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from .buffer import BinaryBuffer
from .disasm import decode_single_arm64_preview, disassemble_window
from .parser import parse_macho_bytes, parse_macho_file


class AnalysisService:
    def __init__(self, workspace_root: str):
        self.workspace_root = os.path.abspath(workspace_root)
        self._cache: Dict[str, Tuple[Dict[str, Any], bytes]] = {}
        self.active_path: Optional[str] = None

    def get_presets(self) -> List[Dict[str, Any]]:
        synth_univ = os.path.join(self.workspace_root, "fixtures", "synthetic_universal")
        synth_fw = os.path.join(self.workspace_root, "fixtures", "synthetic_firmware.preload")
        presets = [
            {
                "id": "synthetic_universal",
                "label": "Synthetic Universal (arm64 + x86_64)",
                "path": synth_univ,
                "description": "Multi-arch test binary with custom segments, C++/ObjC symbols, chained fixups & entitlements",
                "exists": os.path.isfile(synth_univ),
            },
            {
                "id": "synthetic_firmware",
                "label": "Synthetic Firmware (MH_PRELOAD)",
                "path": synth_fw,
                "description": "Standalone ARM64 firmware image with LC_UNIXTHREAD state and RWX segment warning",
                "exists": os.path.isfile(synth_fw),
            },
            {
                "id": "bin_ls",
                "label": "/bin/ls",
                "path": "/bin/ls",
                "description": "macOS Universal system utility (arm64e PAC + x86_64) with Apple Code Signature",
                "exists": os.path.isfile("/bin/ls"),
            },
            {
                "id": "usr_bin_true",
                "label": "/usr/bin/true",
                "path": "/usr/bin/true",
                "description": "Minimal macOS Universal Mach-O executable",
                "exists": os.path.isfile("/usr/bin/true"),
            },
        ]
        return presets

    def load_file(self, path: str) -> Dict[str, Any]:
        if not os.path.isabs(path):
            candidate = os.path.join(self.workspace_root, path)
            abs_path = os.path.abspath(candidate) if os.path.isfile(candidate) else os.path.abspath(path)
        else:
            abs_path = os.path.abspath(path)
        if abs_path in self._cache and os.path.isfile(abs_path):
            self.active_path = abs_path
            return self._cache[abs_path][0]

        doc, raw_bytes = parse_macho_file(abs_path)
        self._cache[abs_path] = (doc, raw_bytes)
        self.active_path = abs_path
        return doc

    def load_uploaded_bytes(self, filename: str, raw_bytes: bytes) -> Dict[str, Any]:
        safe_name = os.path.basename(filename) or "uploaded_binary"
        virtual_path = f"<upload:{safe_name}>"
        doc = parse_macho_bytes(raw_bytes, path=virtual_path)
        self._cache[virtual_path] = (doc, raw_bytes)
        self.active_path = virtual_path
        return doc

    def _resolve_active(self, path: Optional[str] = None) -> Tuple[Dict[str, Any], bytes, str]:
        target_path = path or self.active_path
        if not target_path:
            # Default to /usr/bin/true or first available preset
            for p in self.get_presets():
                if p["exists"]:
                    target_path = p["path"]
                    break
        if not target_path:
            raise ValueError("No binary file is currently loaded.")
        if target_path not in self._cache:
            self.load_file(target_path)
        doc, raw_bytes = self._cache[target_path]
        return doc, raw_bytes, target_path

    def _get_slice(self, doc: Dict[str, Any], slice_index: int) -> Dict[str, Any]:
        slices = doc.get("slices", [])
        if not slices:
            raise ValueError("No Mach-O slices available in document.")
        idx = max(0, min(slice_index, len(slices) - 1))
        return slices[idx]

    # ========================================================================
    # Address / Offset Translation (O(log N) / Segment Interval Lookup)
    # ========================================================================
    def _abs_offset_to_vmaddr(self, slice_obj: Dict[str, Any], abs_offset: int) -> Optional[int]:
        slice_base = slice_obj["slice_base_offset"]
        slice_off = abs_offset - slice_base
        if slice_off < 0 or slice_off >= slice_obj["slice_size"]:
            return None
        for seg in slice_obj.get("segments", []):
            if seg["filesize"] > 0 and seg["fileoff"] <= slice_off < seg["fileoff"] + seg["filesize"]:
                return seg["vmaddr_int"] + (slice_off - seg["fileoff"])
        return None

    def translate_address(
        self,
        slice_index: int = 0,
        query: str = "0",
        mode: str = "auto",
        path: Optional[str] = None,
    ) -> Dict[str, Any]:
        doc, _, _ = self._resolve_active(path)
        slice_obj = self._get_slice(doc, slice_index)
        slice_base = slice_obj["slice_base_offset"]

        q_clean = str(query).strip()
        if not q_clean:
            q_val = 0
        else:
            try:
                q_val = int(q_clean, 16) if q_clean.lower().startswith("0x") else int(q_clean, 0)
            except ValueError:
                try:
                    q_val = int(q_clean, 16)
                except ValueError:
                    q_val = 0

        # Determine text base for RVA and auto-detection
        text_vm = 0
        for seg in slice_obj.get("segments", []):
            if seg["segname"] == "__TEXT":
                text_vm = seg["vmaddr_int"]
                break
        if text_vm == 0 and slice_obj.get("segments"):
            for seg in slice_obj["segments"]:
                if seg["segname"] != "__PAGEZERO":
                    text_vm = seg["vmaddr_int"]
                    break

        resolved_mode = mode
        if mode == "auto":
            if text_vm > 0 and q_val >= text_vm:
                resolved_mode = "vmaddr"
            elif slice_base > 0 and q_val >= slice_base and q_val < slice_base + slice_obj["slice_size"]:
                resolved_mode = "abs_offset"
            else:
                resolved_mode = "slice_offset"

        matched_seg: Optional[Dict[str, Any]] = None
        matched_sect: Optional[Dict[str, Any]] = None
        vmaddr_val: Optional[int] = None
        slice_off_val: Optional[int] = None
        abs_off_val: Optional[int] = None
        status = "UNMAPPED"
        mapped = False

        if resolved_mode == "vmaddr":
            vmaddr_val = q_val
            for seg in slice_obj.get("segments", []):
                if seg["segname"] == "__PAGEZERO":
                    continue
                s_vm = seg["vmaddr_int"]
                s_vmsz = seg["vmsize_int"]
                if s_vm <= vmaddr_val < s_vm + s_vmsz:
                    matched_seg = seg
                    rel_vm = vmaddr_val - s_vm
                    if rel_vm < seg["filesize"]:
                        slice_off_val = seg["fileoff"] + rel_vm
                        abs_off_val = slice_base + slice_off_val
                        status = "MAPPED"
                        mapped = True
                    else:
                        status = "UNMAPPED_ZEROFILL"
                        mapped = True
                    for sect in seg.get("sections", []):
                        if sect["vmaddr_int"] <= vmaddr_val < sect["vmaddr_int"] + sect["size"]:
                            matched_sect = sect
                            break
                    break
        else:
            if resolved_mode == "abs_offset":
                abs_off_val = q_val
                slice_off_val = q_val - slice_base
            else:
                slice_off_val = q_val
                abs_off_val = slice_base + q_val

            if 0 <= slice_off_val < slice_obj["slice_size"]:
                for seg in slice_obj.get("segments", []):
                    if seg["filesize"] > 0 and seg["fileoff"] <= slice_off_val < seg["fileoff"] + seg["filesize"]:
                        matched_seg = seg
                        vmaddr_val = seg["vmaddr_int"] + (slice_off_val - seg["fileoff"])
                        status = "MAPPED"
                        mapped = True
                        for sect in seg.get("sections", []):
                            if not sect.get("is_zerofill") and sect["slice_offset"] <= slice_off_val < sect["slice_offset"] + sect["size"]:
                                matched_sect = sect
                                break
                        break

        # Find nearest preceding symbol if vmaddr_val is resolved
        nearest_sym_obj: Optional[Dict[str, Any]] = None
        if vmaddr_val is not None:
            best_sym = None
            best_delta = None
            for sym in slice_obj.get("symbols", []):
                if sym["type_name"] == "SECT" and not sym["is_stab"] and sym["n_value_int"] > 0:
                    delta = vmaddr_val - sym["n_value_int"]
                    if 0 <= delta < 0x100000:
                        if best_delta is None or delta < best_delta:
                            best_delta = delta
                            best_sym = sym
            if best_sym is not None and best_delta is not None:
                nearest_sym_obj = {
                    "name": best_sym["name"],
                    "demangled": best_sym["demangled"],
                    "vmaddr": best_sym["n_value"],
                    "offset_from_symbol": best_delta,
                    "display": f"{best_sym['name']} + 0x{best_delta:x}",
                }

        rva_val = (vmaddr_val - text_vm) if (vmaddr_val is not None and vmaddr_val >= text_vm) else None

        return {
            "query": query,
            "mode_resolved": resolved_mode,
            "mapped": mapped,
            "status": status,
            "vmaddr": f"0x{vmaddr_val:x}" if vmaddr_val is not None else None,
            "rva": f"0x{rva_val:x}" if rva_val is not None else None,
            "slice_offset": slice_off_val,
            "abs_offset": abs_off_val,
            "segment": (
                {
                    "segname": matched_seg["segname"],
                    "vmaddr": matched_seg["vmaddr"],
                    "vmsize": matched_seg["vmsize"],
                    "initprot": matched_seg["initprot"],
                    "maxprot": matched_seg["maxprot"],
                }
                if matched_seg
                else None
            ),
            "section": (
                {
                    "sectname": matched_sect["sectname"],
                    "segname": matched_sect["segname"],
                    "vmaddr": matched_sect["vmaddr"],
                    "size": matched_sect["size"],
                    "abs_offset": matched_sect["abs_offset"],
                }
                if matched_sect
                else None
            ),
            "nearest_symbol": nearest_sym_obj,
        }

    # ========================================================================
    # Windowed Hex Viewer Endpoint (/api/hex)
    # ========================================================================
    def get_hex_slice(
        self,
        offset: int = 0,
        length: int = 4096,
        slice_index: int = 0,
        path: Optional[str] = None,
    ) -> Dict[str, Any]:
        doc, raw_bytes, _ = self._resolve_active(path)
        file_size = len(raw_bytes)
        slice_obj = self._get_slice(doc, slice_index)
        slice_base = slice_obj["slice_base_offset"]

        abs_offset = max(0, min(offset, max(0, file_size - 1)))
        clamped_len = max(16, min(length, 65536))
        end_offset = min(file_size, abs_offset + clamped_len)
        window_bytes = raw_bytes[abs_offset:end_offset]

        rows: List[Dict[str, Any]] = []
        row_start = (abs_offset // 16) * 16
        row_end = min(file_size, ((end_offset + 15) // 16) * 16)

        for r_off in range(row_start, row_end, 16):
            chunk = raw_bytes[r_off : min(file_size, r_off + 16)]
            hex_arr = [f"{b:02x}" for b in chunk]
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            vm_val = self._abs_offset_to_vmaddr(slice_obj, r_off)
            rows.append({
                "abs_offset": r_off,
                "slice_offset": r_off - slice_base,
                "vmaddr": f"0x{vm_val:x}" if vm_val is not None else None,
                "hex_array": hex_arr,
                "ascii": ascii_str,
            })

        # Collect structural annotations overlapping [row_start, row_end)
        annotations: List[Dict[str, Any]] = []
        if doc["file_info"]["is_fat"] and doc["file_info"]["fat_header"]:
            fh_reg = doc["file_info"]["fat_header"]["region"]
            if fh_reg["abs_offset"] < row_end and (fh_reg["abs_offset"] + fh_reg["size"]) > row_start:
                annotations.append({
                    "id": "fat_header",
                    "label": "fat_header",
                    "category": "header",
                    "abs_offset": fh_reg["abs_offset"],
                    "size": fh_reg["size"],
                })

        for iv in slice_obj.get("intervals", []):
            iv_start = iv["abs_offset"]
            iv_end = iv_start + iv["size"]
            if iv["size"] > 0 and iv_start < row_end and iv_end > row_start:
                annotations.append({
                    "id": iv["id"],
                    "label": iv["label"],
                    "category": iv["category"],
                    "abs_offset": iv_start,
                    "size": iv["size"],
                })

        return {
            "abs_offset": abs_offset,
            "length": len(window_bytes),
            "file_size": file_size,
            "hex_bytes": window_bytes.hex(),
            "rows": rows,
            "annotations": annotations,
        }

    # ========================================================================
    # Live Multi-Format Byte Decoder & Breadcrumb Resolver (/api/decode)
    # ========================================================================
    def decode_bytes_at(
        self,
        offset: int,
        slice_index: int = 0,
        endian: str = "little",
        path: Optional[str] = None,
    ) -> Dict[str, Any]:
        doc, raw_bytes, _ = self._resolve_active(path)
        file_size = len(raw_bytes)
        slice_obj = self._get_slice(doc, slice_index)
        slice_base = slice_obj["slice_base_offset"]

        abs_off = max(0, min(offset, max(0, file_size - 1)))
        slice_off = abs_off - slice_base
        vm_val = self._abs_offset_to_vmaddr(slice_obj, abs_off)

        window = raw_bytes[abs_off : min(file_size, abs_off + 16)].ljust(16, b"\x00")
        raw_hex_8 = " ".join(f"{b:02x}" for b in raw_bytes[abs_off : min(file_size, abs_off + 8)])
        e_char = "<" if endian.lower() != "big" else ">"

        u8 = window[0]
        i8 = struct.unpack("b", window[:1])[0]
        u16 = struct.unpack(f"{e_char}H", window[:2])[0]
        i16 = struct.unpack(f"{e_char}h", window[:2])[0]
        u32 = struct.unpack(f"{e_char}I", window[:4])[0]
        i32 = struct.unpack(f"{e_char}i", window[:4])[0]
        u64 = struct.unpack(f"{e_char}Q", window[:8])[0]
        i64 = struct.unpack(f"{e_char}q", window[:8])[0]
        f32_raw = struct.unpack(f"{e_char}f", window[:4])[0]
        f64_raw = struct.unpack(f"{e_char}d", window[:8])[0]

        f32 = None if (math.isnan(f32_raw) or math.isinf(f32_raw)) else round(f32_raw, 6)
        f64 = None if (math.isnan(f64_raw) or math.isinf(f64_raw)) else round(f64_raw, 6)

        temp_buf = BinaryBuffer(raw_bytes, 0, file_size)
        uleb_val, uleb_len = temp_buf.read_uleb128(abs_off)
        sleb_val, sleb_len = temp_buf.read_sleb128(abs_off)
        cstr_val, _ = temp_buf.cstr_at(abs_off, 64)
        cstr_clean = "".join(ch if 32 <= ord(ch) <= 126 else "." for ch in cstr_val[:32])

        arm64_str = decode_single_arm64_preview(
            raw_bytes[abs_off : min(file_size, abs_off + 4)],
            vm_val if vm_val is not None else abs_off,
        )

        # Build structural breadcrumbs from largest enclosing container down to exact field
        breadcrumbs: List[Dict[str, Any]] = []
        if slice_base <= abs_off < slice_base + slice_obj["slice_size"]:
            breadcrumbs.append({
                "id": f"slice_{slice_index}",
                "label": f"Slice #{slice_index} ({slice_obj['arch_name']})",
                "abs_offset": slice_base,
                "size": slice_obj["slice_size"],
            })

        matching_ivs = [
            iv
            for iv in slice_obj.get("intervals", [])
            if iv["abs_offset"] <= abs_off < iv["abs_offset"] + iv["size"]
        ]
        matching_ivs.sort(key=lambda x: x["size"], reverse=True)
        for iv in matching_ivs:
            breadcrumbs.append({
                "id": iv["id"],
                "label": iv["label"],
                "abs_offset": iv["abs_offset"],
                "size": iv["size"],
            })

        # Check field-level match in header or load commands
        all_field_lists = [slice_obj["header"].get("fields", [])]
        if doc["file_info"].get("fat_header"):
            all_field_lists.append(doc["file_info"]["fat_header"].get("fields", []))
        for lc in slice_obj.get("load_commands", []):
            all_field_lists.append(lc.get("fields", []))
        for seg in slice_obj.get("segments", []):
            for sect in seg.get("sections", []):
                all_field_lists.append(sect.get("fields", []))

        for flist in all_field_lists:
            for f_obj in flist:
                if f_obj["abs_offset"] <= abs_off < f_obj["abs_offset"] + f_obj["size"]:
                    breadcrumbs.append({
                        "id": f"field_{f_obj['name']}",
                        "label": f"{f_obj['name']} ({f_obj['interpreted']})",
                        "abs_offset": f_obj["abs_offset"],
                        "size": f_obj["size"],
                    })
                    break

        return {
            "abs_offset": abs_off,
            "slice_offset": slice_off,
            "vmaddr": f"0x{vm_val:x}" if vm_val is not None else None,
            "raw_hex": raw_hex_8,
            "breadcrumbs": breadcrumbs,
            "primitives": {
                "uint8": u8,
                "int8": i8,
                "uint16": u16,
                "int16": i16,
                "uint32": u32,
                "int32": i32,
                "hex32": f"0x{u32:08x}",
                "uint64": f"0x{u64:016x}",
                "int64": str(i64),
                "float32": f32,
                "float64": f64,
                "uleb128": {"value": uleb_val, "byte_length": uleb_len},
                "sleb128": {"value": sleb_val, "byte_length": sleb_len},
                "cstring_preview": cstr_clean,
                "arm64_insn": arm64_str,
            },
        }

    # ========================================================================
    # Disassembly Service (/api/disassemble)
    # ========================================================================
    def disassemble(
        self,
        slice_index: int = 0,
        vmaddr: Optional[str] = None,
        section: Optional[str] = None,
        count: int = 200,
        path: Optional[str] = None,
    ) -> Dict[str, Any]:
        doc, raw_bytes, resolved_path = self._resolve_active(path)
        slice_obj = self._get_slice(doc, slice_index)
        slice_base = slice_obj["slice_base_offset"]
        slice_size = slice_obj["slice_size"]
        raw_slice = raw_bytes[slice_base : slice_base + slice_size]

        start_vm: Optional[int] = None
        if section:
            for seg in slice_obj.get("segments", []):
                for sect in seg.get("sections", []):
                    full_sec_name = f"{sect['segname']},{sect['sectname']}"
                    if section in (full_sec_name, sect["sectname"]):
                        start_vm = sect["vmaddr_int"]
                        break
                if start_vm is not None:
                    break

        if vmaddr and start_vm is None:
            try:
                start_vm = int(str(vmaddr), 16) if str(vmaddr).startswith("0x") else int(str(vmaddr), 0)
            except ValueError:
                start_vm = None

        if start_vm is None:
            # Prefer __TEXT,__text or entry_point
            ep_str = slice_obj.get("entry_point", {}).get("vmaddr", "0x0")
            ep_int = int(ep_str, 16) if ep_str.startswith("0x") else 0
            if ep_int > 0:
                start_vm = ep_int
            else:
                for seg in slice_obj.get("segments", []):
                    for sect in seg.get("sections", []):
                        if sect.get("is_executable") and sect["size"] > 0:
                            start_vm = sect["vmaddr_int"]
                            break
                    if start_vm is not None:
                        break

        if start_vm is None:
            start_vm = 0

        disk_path = resolved_path if os.path.isfile(resolved_path) else None
        return disassemble_window(
            slice_data=slice_obj,
            raw_slice_bytes=raw_slice,
            slice_base_offset=slice_base,
            start_vmaddr=start_vm,
            count=count,
            file_path=disk_path,
        )

    # ========================================================================
    # Omni-Search Service (/api/search)
    # ========================================================================
    def search(
        self,
        query: str,
        slice_index: int = 0,
        scope: str = "all",
        path: Optional[str] = None,
    ) -> Dict[str, Any]:
        doc, raw_bytes, _ = self._resolve_active(path)
        slice_obj = self._get_slice(doc, slice_index)

        q = query.strip()
        if not q:
            return {"query": query, "results": []}

        # Prefix operators from UI/UX spec:
        # `@` -> symbols, `"` -> strings, `#` -> load commands/structures, `0x` -> address
        effective_scope = scope
        if q.startswith("@"):
            effective_scope = "symbols"
            q = q[1:].strip()
        elif q.startswith('"'):
            effective_scope = "strings"
            q = q.strip('"').strip()
        elif q.startswith("#"):
            effective_scope = "structures"
            q = q[1:].strip()

        q_lower = q.lower()
        results: List[Dict[str, Any]] = []

        # 1. Address Jump Match
        if q_lower.startswith("0x") or q_lower.isdigit():
            tr = self.translate_address(slice_index=slice_index, query=q, mode="auto", path=path)
            if tr.get("mapped"):
                results.append({
                    "category": "address",
                    "title": f"Jump to {tr['vmaddr']} (File Offset 0x{(tr['abs_offset'] or 0):x})",
                    "subtitle": f"{tr['segment']['segname'] if tr['segment'] else ''} {tr['section']['sectname'] if tr['section'] else ''} • {tr['nearest_symbol']['display'] if tr['nearest_symbol'] else tr['status']}".strip(),
                    "vmaddr": tr["vmaddr"],
                    "abs_offset": tr["abs_offset"],
                    "size": 16,
                    "node_id": "hex",
                })

        # 2. Symbols Search
        if effective_scope in ("all", "symbols"):
            for sym in slice_obj.get("symbols", []):
                if q_lower in sym["name"].lower() or q_lower in sym["demangled"].lower():
                    results.append({
                        "category": "symbol",
                        "title": sym["demangled"] if sym["demangled"] != sym["name"] else sym["name"],
                        "subtitle": f"{sym['section_name'] or sym['library_name']} • {'External' if sym['is_external'] else 'Local'} ({sym['type_name']})",
                        "vmaddr": sym["n_value"] if sym["n_value_int"] > 0 else None,
                        "abs_offset": sym["target_abs_offset"] or sym["abs_offset"],
                        "size": sym["size"],
                        "node_id": "symtab",
                    })
                    if len(results) >= 100:
                        break

        # 3. Strings Search
        if effective_scope in ("all", "strings") and len(results) < 120:
            for st in slice_obj.get("strings", []):
                if q_lower in st["value"].lower():
                    results.append({
                        "category": "string",
                        "title": st["value"][:80],
                        "subtitle": f"{st['source']} • {st['length']} bytes @ {st['vmaddr']}",
                        "vmaddr": st["vmaddr"],
                        "abs_offset": st["abs_offset"],
                        "size": st["length"],
                        "node_id": "strings",
                    })
                    if len(results) >= 120:
                        break

        # 4. Load Commands & Sections Search
        if effective_scope in ("all", "structures") and len(results) < 140:
            for lc in slice_obj.get("load_commands", []):
                if q_lower in lc["cmd_name"].lower() or q_lower in lc["summary"].lower():
                    results.append({
                        "category": "load_command",
                        "title": f"#{lc['index']} {lc['cmd_name']}",
                        "subtitle": lc["summary"],
                        "vmaddr": None,
                        "abs_offset": lc["region"]["abs_offset"],
                        "size": lc["region"]["size"],
                        "node_id": f"lc_{lc['index']}",
                    })
            for seg in slice_obj.get("segments", []):
                for sect in seg.get("sections", []):
                    label = f"{sect['segname']},{sect['sectname']}"
                    if q_lower in label.lower():
                        results.append({
                            "category": "section",
                            "title": label,
                            "subtitle": f"VM {sect['vmaddr']} • {sect['size']:,} bytes ({sect['section_type']})",
                            "vmaddr": sect["vmaddr"],
                            "abs_offset": sect["abs_offset"],
                            "size": sect["size"],
                            "node_id": f"sect_{sect['segname']}_{sect['sectname']}",
                        })

        # 5. Raw Hex Byte Pattern Search (e.g. "cf fa ed fe" or "7f2303d5")
        hex_candidate = re.sub(r"\s+", "", q_lower)
        if (
            effective_scope in ("all", "hex")
            and len(hex_candidate) >= 4
            and len(hex_candidate) % 2 == 0
            and all(c in "0123456789abcdef" for c in hex_candidate)
        ):
            pattern = bytes.fromhex(hex_candidate)
            start_pos = 0
            matches_found = 0
            while matches_found < 20:
                idx = raw_bytes.find(pattern, start_pos)
                if idx == -1:
                    break
                vm_hit = self._abs_offset_to_vmaddr(slice_obj, idx)
                results.append({
                    "category": "hex",
                    "title": f"Hex Match: {' '.join(f'{b:02x}' for b in pattern)}",
                    "subtitle": f"File Offset 0x{idx:x}" + (f" • VM 0x{vm_hit:x}" if vm_hit else ""),
                    "vmaddr": f"0x{vm_hit:x}" if vm_hit else None,
                    "abs_offset": idx,
                    "size": len(pattern),
                    "node_id": "hex",
                })
                matches_found += 1
                start_pos = idx + 1

        return {"query": query, "results": results}
