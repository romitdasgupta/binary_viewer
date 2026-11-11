"""
Resolution of content against an open document.

`resolve(locator, doc, slice)` turns a locator (see dsl.py) into the tree node to
select and the byte range to highlight in *this* file, or reports that the
structure does not exist here.

`compute_task(spec, doc, slice)` turns a task specification from tours.py into a
concrete question for this file together with its expected answer. Expected
answers are always computed from the document; nothing is hard-coded per sample.

Everything read from the document is attacker-controlled. Values substituted into
text go through `clean()`; nothing here trusts offsets or sizes to be in range.
"""

import re
from typing import Any, Dict, List, Optional

FORMAT_NAMES = {"macho": "Mach-O", "elf": "ELF", "pe": "PE"}

# Node ids the core tree always provides while a document is open.
_ALWAYS_NODES = {
    "overview", "semantic_intel", "loader_lifecycle", "mach_header", "load_commands", "segments", "disassembly",
    "dyld_info", "symtab", "dysymtab", "strings", "function_starts", "code_signature", "security_audit",
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def fmt_of(slice_doc: Dict[str, Any]) -> str:
    fmt = str(slice_doc.get("format") or "macho").lower()
    return fmt if fmt in FORMAT_NAMES else "macho"


def per_format(value: Any, fmt: str) -> Any:
    """Pick the entry for `fmt` out of a {"macho":…, "elf":…, "pe":…} value; other values pass through."""
    if isinstance(value, dict) and value and all(k in FORMAT_NAMES for k in value):
        return value.get(fmt)
    return value


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def clean(value: Any, limit: int = 80) -> str:
    """A document string made safe to substitute into rich text: printable, no markup characters."""
    text = "".join(ch if 0x20 <= ord(ch) < 0x7F else "?" for ch in str(value))
    text = re.sub(r"[`\[\]*{}|]", "", text)
    return text[:limit]


def hexs(value: Any) -> str:
    try:
        return "0x%x" % int(value)
    except (TypeError, ValueError):
        return "0x0"


def to_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError:
            return None
    return None


def _norm_name(name: Any) -> str:
    return re.sub(r"\[\d+\]", "[]", str(name))


def find_field(fields: Any, names: Any) -> Optional[Dict[str, Any]]:
    """First field whose name is one of `names` (exact match, then with array indices removed)."""
    if not isinstance(fields, list):
        return None
    for name in as_list(names):
        for field in fields:
            if isinstance(field, dict) and field.get("name") == name:
                return field
    for name in as_list(names):
        for field in fields:
            if isinstance(field, dict) and _norm_name(field.get("name")) == name:
                return field
    return None


def is_little_endian(slice_doc: Dict[str, Any]) -> bool:
    """Byte order of the multi-byte fields of this slice's own structures (PE: always little)."""
    if fmt_of(slice_doc) == "pe":
        return True
    value = (slice_doc.get("header") or {}).get("little_endian")
    return True if value is None else bool(value)


def _range_ok(doc: Dict[str, Any], offset: Any, size: Any) -> bool:
    file_size = to_int((doc.get("file_info") or {}).get("file_size")) or 0
    return isinstance(offset, int) and not isinstance(offset, bool) and 0 <= offset < max(file_size, 1) and \
        isinstance(size, int) and size >= 0


def vm_to_abs(slice_doc: Dict[str, Any], vmaddr: int) -> Optional[int]:
    """File offset of the byte mapped at `vmaddr`, or None if no file byte is mapped there."""
    for seg in slice_doc.get("segments") or []:
        base = to_int(seg.get("vmaddr_int"))
        size = to_int(seg.get("filesize"))
        off = to_int(seg.get("abs_offset"))
        if base is None or size is None or off is None:
            continue
        if base <= vmaddr < base + size:
            return off + (vmaddr - base)
    return None


def segment_for_vmaddr(slice_doc: Dict[str, Any], vmaddr: int) -> Optional[int]:
    """Index of the segment whose address range contains `vmaddr`."""
    for index, seg in enumerate(slice_doc.get("segments") or []):
        base = to_int(seg.get("vmaddr_int"))
        size = to_int(seg.get("vmsize_int"))
        if base is None or size is None:
            continue
        if base <= vmaddr < base + size:
            return index
    return None


def _prot(seg: Dict[str, Any]) -> str:
    return str(seg.get("initprot") or "").lower()


def pick_segment(slice_doc: Dict[str, Any], pick: str, name: Any = None) -> Optional[int]:
    segs = slice_doc.get("segments") or []
    fmt = fmt_of(slice_doc)
    wanted = [str(n) for n in as_list(per_format(name, fmt))]
    for index, seg in enumerate(segs):
        prot = _prot(seg)
        filesize = to_int(seg.get("filesize")) or 0
        vmsize = to_int(seg.get("vmsize_int")) or 0
        if pick == "exec" and "x" in prot and filesize > 0:
            return index
        if pick == "data" and "w" in prot and "x" not in prot:
            return index
        if pick == "rwx" and "w" in prot and "x" in prot:
            return index
        if pick == "zerofill" and "r" in prot and filesize > 0 and vmsize > filesize and _real_segment(seg, fmt):
            return index
        if pick == "first" and filesize > 0 and _real_segment(seg, fmt):
            return index
        if pick == "readonly" and "r" in prot and "w" not in prot and filesize > 0 and _real_segment(seg, fmt):
            return index
        if pick == "name" and str(seg.get("segname")) in wanted:
            return index
    return None


def _real_segment(seg: Dict[str, Any], fmt: str) -> bool:
    """False for the PE pseudo-segment that stands for the header pages."""
    return not (fmt == "pe" and str(seg.get("segname")) == "HEADERS")


def _region(obj: Any) -> Optional[Dict[str, int]]:
    if isinstance(obj, dict) and isinstance(obj.get("abs_offset"), int) and not isinstance(obj.get("abs_offset"), bool):
        return {"abs_offset": obj["abs_offset"], "size": max(0, to_int(obj.get("size")) or 0)}
    return None


def find_lc(slice_doc: Dict[str, Any], names: Any) -> Optional[Dict[str, Any]]:
    wanted = [str(n) for n in as_list(per_format(names, fmt_of(slice_doc)))]
    lcs = slice_doc.get("load_commands") or []
    for name in wanted:
        for lc in lcs:
            if isinstance(lc, dict) and lc.get("cmd_name") == name:
                return lc
    return None


def find_section(slice_doc: Dict[str, Any], names: Any) -> Optional[Dict[str, Any]]:
    """{'seg_index', 'sect_index', 'section', 'segment'} for the first section with one of `names`."""
    wanted = [str(n) for n in as_list(per_format(names, fmt_of(slice_doc)))]
    segs = slice_doc.get("segments") or []
    for name in wanted:
        for si, seg in enumerate(segs):
            for ci, sect in enumerate(seg.get("sections") or []):
                if sect.get("sectname") == name:
                    return {"seg_index": si, "sect_index": ci, "section": sect, "segment": seg}
    return None


def _missing(reason: str) -> Dict[str, Any]:
    return {"available": False, "reason": reason}


def _found(node_id: str, label: str, region: Optional[Dict[str, int]] = None, **extra: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"available": True, "node_id": node_id, "label": label, "abs_offset": None, "size": None}
    if region:
        out["abs_offset"] = region["abs_offset"]
        out["size"] = max(1, region["size"])
    out.update(extra)
    return out


def _field_result(node_id: str, field: Optional[Dict[str, Any]], what: str) -> Dict[str, Any]:
    if not field or not isinstance(field.get("abs_offset"), int):
        return _missing("This file has no %s." % what)
    return _found(node_id, clean(field.get("name")), {"abs_offset": field["abs_offset"], "size": to_int(field.get("size")) or 1},
                  field=clean(field.get("name")))


# ---------------------------------------------------------------------------
# Locator resolution
# ---------------------------------------------------------------------------
def resolve(loc: Dict[str, Any], doc: Dict[str, Any], slice_doc: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve one locator. Never raises on a malformed document."""
    try:
        result = _resolve(loc, doc, slice_doc)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return _missing("This part of the file could not be located.")
    if result.get("available") and result.get("abs_offset") is not None:
        if not _range_ok(doc, result["abs_offset"], result["size"]):
            return _missing("The structure points outside the file.")
    return result


def _resolve(loc: Dict[str, Any], doc: Dict[str, Any], slice_doc: Dict[str, Any]) -> Dict[str, Any]:
    fmt = fmt_of(slice_doc)
    kind = loc.get("kind")
    header = slice_doc.get("header") or {}

    if kind == "header":
        region = _region(header.get("region"))
        return _found("mach_header", "file header", region) if region else _missing("This file has no decoded header.")

    if kind == "fat":
        fat = (doc.get("file_info") or {}).get("fat_header")
        if not fat:
            return _missing("This is not a universal (fat) file.")
        if loc.get("name"):
            index = to_int(slice_doc.get("fat_arch_index"))
            if index is None:
                index = to_int(slice_doc.get("slice_index")) or 0
            name = str(loc["name"]).replace("[]", "[%d]" % index)
            return _field_result("fat_header", find_field(fat.get("fields"), name), "field %s in its universal header" % loc["name"])
        return _found("fat_header", "universal header", _region(fat.get("region")))

    if kind == "field":
        where = loc.get("where")
        if where == "header":
            names = per_format(loc.get("name"), fmt)
            if not names:
                return _missing("%s has no such header field." % FORMAT_NAMES[fmt])
            return _field_result("mach_header", find_field(header.get("fields"), names), "such header field")
        if where == "lc":
            lc = find_lc(slice_doc, loc.get("cmd"))
            if not lc:
                return _missing(_no_lc(loc.get("cmd"), fmt))
            return _field_result("lc_%d" % int(lc["index"]), find_field(lc.get("fields"), per_format(loc.get("name"), fmt)), "such field")
        if where == "segment":
            index = pick_segment(slice_doc, str(loc.get("pick")), loc.get("name"))
            if index is None:
                return _missing(_no_segment(str(loc.get("pick"))))
            seg = slice_doc["segments"][index]
            names = per_format(loc.get("field"), fmt)
            if not names:
                return _missing("%s has no such segment field." % FORMAT_NAMES[fmt])
            return _field_result("seg_%d" % index, find_field(seg.get("fields"), names), "such segment field")
        if where == "section":
            hit = find_section(slice_doc, loc.get("names"))
            if not hit:
                return _missing(_no_section(loc.get("names"), fmt))
            return _field_result("sect_%d_%d" % (hit["seg_index"], hit["sect_index"]),
                                 find_field(hit["section"].get("fields"), per_format(loc.get("field"), fmt)), "such section field")
        return _missing("Unknown location.")

    if kind == "lc":
        lc = find_lc(slice_doc, loc.get("cmd"))
        if not lc:
            return _missing(_no_lc(loc.get("cmd"), fmt))
        return _found("lc_%d" % int(lc["index"]), clean(lc.get("cmd_name")), _region(lc.get("region")))

    if kind == "segment":
        index = pick_segment(slice_doc, str(loc.get("pick")), loc.get("name"))
        if index is None:
            return _missing(_no_segment(str(loc.get("pick"))))
        seg = slice_doc["segments"][index]
        region = _region(seg.get("header_region")) if loc.get("part") == "header" else None
        if region is None:
            region = _region(seg.get("region"))
            if region is None or region["size"] == 0:
                region = _region(seg.get("header_region")) or region
        return _found("seg_%d" % index, clean(seg.get("segname")) or "segment", region, vmaddr=clean(seg.get("vmaddr")))

    if kind == "section":
        hit = find_section(slice_doc, loc.get("names"))
        if not hit:
            return _missing(_no_section(loc.get("names"), fmt))
        sect = hit["section"]
        region = _region(sect.get("header_region")) if loc.get("part") == "header" else None
        if region is None:
            region = _region(sect.get("region")) or _region({"abs_offset": sect.get("abs_offset"), "size": sect.get("size")})
            if region and region["size"] > 256:
                region = {"abs_offset": region["abs_offset"], "size": 256}
            if region is None or region["size"] == 0:
                region = _region(sect.get("header_region")) or region
        return _found("sect_%d_%d" % (hit["seg_index"], hit["sect_index"]), clean(sect.get("sectname")), region,
                      vmaddr=clean(sect.get("vmaddr")))

    if kind == "entry":
        ep = slice_doc.get("entry_point") or {}
        off = ep.get("abs_offset")
        vm = to_int(ep.get("vmaddr"))
        if not isinstance(off, int) or isinstance(off, bool) or vm is None or vm_to_abs(slice_doc, vm) is None:
            return _missing("This file has no entry point that maps to bytes in the file.")
        return _found("disassembly", "entry point", {"abs_offset": off, "size": 16}, vmaddr=hexs(vm), disasm=True)

    if kind == "entry_field":
        if fmt == "macho":
            for cmd, name in (("LC_MAIN", "entryoff"), ("LC_UNIXTHREAD", "pc"), ("LC_UNIXTHREAD", "rip"), ("LC_UNIXTHREAD", "eip")):
                lc = find_lc(slice_doc, [cmd])
                field = find_field(lc.get("fields"), name) if lc else None
                if field:
                    return _field_result("lc_%d" % int(lc["index"]), field, "entry point field")
            return _missing("This file has no entry point command.")
        name = "e_entry" if fmt == "elf" else "OptionalHeader.AddressOfEntryPoint"
        return _field_result("mach_header", find_field(header.get("fields"), name), "entry point field")

    if kind == "view":
        node = per_format(loc.get("node"), fmt)
        if not node:
            return _missing("There is no such view for %s files." % FORMAT_NAMES[fmt])
        if node == "fat_header" and not (doc.get("file_info") or {}).get("fat_header"):
            return _missing("This is not a universal (fat) file.")
        if node not in _ALWAYS_NODES and node != "fat_header":
            return _missing("That view is not available for this file.")
        return _found(str(node), str(node))

    if kind == "symbol":
        pick = loc.get("pick") or "first"
        for sym in slice_doc.get("symbols") or []:
            undefined = sym.get("type_name") == "UNDF"
            if pick == "undefined" and not undefined:
                continue
            if pick == "defined" and undefined:
                continue
            region = _region(sym)
            if region and region["size"] > 0:
                return _found("symtab", clean(sym.get("name")) or "symbol", region)
        return _missing("This file has no %s symbol entry." % ("undefined" if pick == "undefined" else "such"))

    if kind == "string":
        for item in slice_doc.get("strings") or []:
            off = item.get("abs_offset")
            if isinstance(off, int) and not isinstance(off, bool):
                return _found("strings", "string", {"abs_offset": off, "size": max(1, to_int(item.get("length")) or 1)},
                              vmaddr=clean(item.get("vmaddr") or ""))
        return _missing("No strings were found in this file.")

    if kind == "import_slot":
        slot = first_import_slot(slice_doc)
        if not slot:
            return _missing("This file has no import pointer slots.")
        return _found("dysymtab", clean(slot["symbol"]) or "import slot", {"abs_offset": slot["abs_offset"], "size": slot["size"]},
                      vmaddr=hexs(slot["vmaddr"]))

    if kind == "fixup":
        fixups = (((slice_doc.get("dyld_info") or {}).get("chained_fixups") or {}).get("fixups")) or []
        width = 8 if slice_doc.get("is_64", True) else 4
        for fx in fixups:
            off = fx.get("abs_offset")
            if isinstance(off, int) and not isinstance(off, bool) and off > 0:
                return _found("dyld_info", clean(fx.get("type") or "fixup"), {"abs_offset": off, "size": width},
                              vmaddr=clean(fx.get("vmaddr") or ""))
        return _missing("This file has no load-time fixups.")

    if kind == "signature":
        region = _region((slice_doc.get("code_signature_detail") or {}).get("superblob_region"))
        if not region:
            return _missing("This file has no embedded signature.")
        if region["size"] > 256:
            region = {"abs_offset": region["abs_offset"], "size": 256}
        return _found("code_signature", "signature", region)

    if kind == "debug_id":
        if fmt == "macho":
            lc = find_lc(slice_doc, ["LC_UUID"])
            if lc:
                field = find_field(lc.get("fields"), "uuid")
                return _field_result("lc_%d" % int(lc["index"]), field, "UUID") if field else \
                    _found("lc_%d" % int(lc["index"]), "LC_UUID", _region(lc.get("region")))
            return _missing("This file has no LC_UUID command.")
        if fmt == "elf":
            for item in ((slice_doc.get("elf_metadata") or {}).get("notes")) or []:
                if item.get("type_name") == "NT_GNU_BUILD_ID" and _region(item):
                    return _found("code_signature", "build ID note", _region(item))
            return _missing("This file has no build ID note.")
        lc = find_lc(slice_doc, ["DATA_DIR_DEBUG_DIRECTORY"])
        if not lc:
            return _missing("This file has no debug directory.")
        entries = ((slice_doc.get("pe_metadata") or {}).get("debug_entries")) or []
        for item in entries:
            off = item.get("abs_offset")
            if isinstance(off, int) and not isinstance(off, bool) and off > 0:
                return _found("lc_%d" % int(lc["index"]), "CodeView record", {"abs_offset": off, "size": 24})
        return _found("lc_%d" % int(lc["index"]), "debug directory", _region(lc.get("region")))

    return _missing("Unknown location.")


def _no_lc(names: Any, fmt: str) -> str:
    wanted = as_list(per_format(names, fmt))
    if not wanted:
        return "%s files have no such structure." % FORMAT_NAMES[fmt]
    return "This file has no %s." % " or ".join(str(n) for n in wanted[:3])


def _no_section(names: Any, fmt: str) -> str:
    wanted = as_list(per_format(names, fmt))
    if not wanted:
        return "%s files have no such section." % FORMAT_NAMES[fmt]
    return "This file has no %s section." % " or ".join(str(n) for n in wanted[:3])


def _no_segment(pick: str) -> str:
    return {
        "exec": "This file has no executable segment with bytes in the file.",
        "data": "This file has no writable data segment.",
        "rwx": "No segment of this file is both writable and executable.",
        "zerofill": "No segment of this file is larger in memory than in the file.",
        "name": "This file has no segment of that name.",
    }.get(pick, "This file has no such segment.")


def first_import_slot(slice_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The first pointer slot (GOT / IAT entry, not stub code) that has bytes in the file."""
    width = 8 if slice_doc.get("is_64", True) else 4
    entries = ((slice_doc.get("dysymtab") or {}).get("indirect_symbols")) or []
    for item in entries:
        where = str(item.get("section") or item.get("section_name") or "").lower()
        if "stub" in where:
            continue
        vm = to_int(item.get("slot_vmaddr"))
        if vm is None:
            continue
        off = vm_to_abs(slice_doc, vm)
        if off is None:
            continue
        return {"abs_offset": off, "size": width, "vmaddr": vm, "symbol": item.get("symbol_name") or ""}
    return None


# ---------------------------------------------------------------------------
# Facts about a document, for substitution into tour text
# ---------------------------------------------------------------------------
def facts(doc: Dict[str, Any], slice_doc: Dict[str, Any]) -> Dict[str, str]:
    fmt = fmt_of(slice_doc)
    header = slice_doc.get("header") or {}
    ep = slice_doc.get("entry_point") or {}
    segs = slice_doc.get("segments") or []
    out: Dict[str, str] = {
        "format": FORMAT_NAMES[fmt],
        "arch": clean(slice_doc.get("arch_name") or "unknown"),
        "bits": "64" if slice_doc.get("is_64", True) else "32",
        "header_name": {"macho": "Mach-O header", "elf": "ELF header", "pe": "PE headers"}[fmt],
        "cmd_noun": {"macho": "load commands", "elf": "program headers", "pe": "data directories and headers"}[fmt],
        "ncmds": str(to_int(header.get("ncmds")) or 0),
        "nsegs": str(len(segs)),
        "entry_vm": clean(ep.get("vmaddr") or "none"),
        "entry_off": hexs(ep.get("abs_offset")) if isinstance(ep.get("abs_offset"), int) else "none",
        "file_name": clean((doc.get("file_info") or {}).get("filename") or "this file"),
        "magic_name": clean(header.get("magic_name") or ""),
        "filetype": clean(header.get("filetype_name") or ""),
    }
    little = is_little_endian(slice_doc)
    out["byte_order"] = "little-endian" if little else "big-endian"
    out["byte_order_rule"] = ("the least significant byte comes first, so read a number's bytes from right to left" if little
                              else "the most significant byte comes first, so read a number's bytes from left to right")
    index = pick_segment(slice_doc, "exec")
    if index is not None:
        seg = segs[index]
        out.update({
            "exec_seg": clean(seg.get("segname")), "exec_prot": clean(seg.get("initprot")),
            "exec_vm": clean(seg.get("vmaddr")), "exec_off": hexs(seg.get("abs_offset")),
        })
    libs = slice_doc.get("dylibs") or []
    out["nlibs"] = str(len(libs))
    out["first_lib"] = clean(libs[0].get("name"), 120) if libs and isinstance(libs[0], dict) else "none"
    return out


_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


def fill(text: str, values: Dict[str, str]) -> str:
    """Replace {name} placeholders that have a value; leave anything else untouched."""
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(1), m.group(0)), text)


# ---------------------------------------------------------------------------
# Tasks: questions answered in the tool, with expected answers computed here
# ---------------------------------------------------------------------------
def _segment_options(slice_doc: Dict[str, Any]) -> List[Dict[str, str]]:
    options = []
    for index, seg in enumerate((slice_doc.get("segments") or [])[:32]):
        options.append({"node_id": "seg_%d" % index,
                        "label": "%s  %s  %s" % (clean(seg.get("segname")) or "segment %d" % index, clean(seg.get("vmaddr")), clean(seg.get("initprot")))})
    return options


def _writable_target(slice_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The permissions field of the code segment (executable, not writable, with bytes in the
    file), with the bit that adds write.

    The task's explanation is about W^X ("a code segment changed this way is writable and
    executable at once"), so the target has to be a segment that holds code: not the first
    read-only segment, which in ELF is the one that maps the file's headers. A file whose
    executable segments are all writable already has no such target and the task is not offered.
    """
    fmt = fmt_of(slice_doc)
    name, bit = {"macho": ("initprot", 0x2), "elf": ("p_flags", 0x2), "pe": ("Characteristics", 0x80000000)}[fmt]
    for index, seg in enumerate(slice_doc.get("segments") or []):
        prot = _prot(seg)
        if "x" not in prot or "w" in prot or not _real_segment(seg, fmt) or (to_int(seg.get("filesize")) or 0) == 0:
            continue
        field = find_field(seg.get("fields"), name)
        raw = to_int(field.get("raw_value")) if field else None
        if field is None or raw is None or not isinstance(field.get("abs_offset"), int) or raw & bit:
            continue
        return {"index": index, "segment": seg, "field": field, "raw": raw, "bit": bit, "name": name}
    return None


def _pe_section_for_rva(slice_doc: Dict[str, Any], rva: int) -> Optional[Dict[str, int]]:
    for index, seg in enumerate(slice_doc.get("segments") or []):
        if not _real_segment(seg, "pe"):
            continue
        fields = seg.get("fields")
        va = to_int((find_field(fields, "VirtualAddress") or {}).get("raw_value"))
        vsize = to_int((find_field(fields, "VirtualSize") or {}).get("raw_value"))
        rsize = to_int((find_field(fields, "SizeOfRawData") or {}).get("raw_value"))
        raw = to_int((find_field(fields, "PointerToRawData") or {}).get("raw_value"))
        if None in (va, vsize, rsize, raw):
            continue
        if va <= rva < va + rsize:
            return {"index": index, "va": va, "raw": raw}
    return None


def is_pie(slice_doc: Dict[str, Any]) -> Optional[bool]:
    """What the header declares about load-address randomisation of this image, from its fields.

    Mach-O: MH_PIE of a main executable. ELF: ET_DYN versus ET_EXEC. PE: DYNAMIC_BASE set AND
    IMAGE_FILE_RELOCS_STRIPPED clear (an image without relocations cannot be moved, whatever
    DllCharacteristics says). None where the question does not apply (not a main executable,
    or a field is missing)."""
    fmt = fmt_of(slice_doc)
    fields = (slice_doc.get("header") or {}).get("fields")
    if fmt == "macho":
        filetype = to_int((find_field(fields, "filetype") or {}).get("raw_value"))
        flags = to_int((find_field(fields, "flags") or {}).get("raw_value"))
        if filetype != 2 or flags is None:
            return None
        return bool(flags & 0x200000)
    if fmt == "elf":
        e_type = to_int((find_field(fields, "e_type") or {}).get("raw_value"))
        if e_type not in (2, 3):
            return None
        return e_type == 3
    chars = to_int((find_field(fields, "OptionalHeader.DllCharacteristics") or {}).get("raw_value"))
    file_chars = to_int((find_field(fields, "FileHeader.Characteristics") or {}).get("raw_value"))
    if chars is None or file_chars is None:
        return None
    return bool(chars & 0x0040) and not (file_chars & 0x0001)


# The two answers of the "is_pie" task. They state what the header declares, so exactly one is
# true for any file: "it is loaded at its linked address" would be false for an arm64 Mach-O
# without MH_PIE (the kernel refuses to run it) and for a PE that is rebased on a collision.
_PIE_OPTIONS = {
    "macho": ["Yes. MH_PIE is set: the kernel loads the main executable at a random offset from its linked address.",
              "No. MH_PIE is clear: the header does not allow the main executable to be moved."],
    "elf": ["Yes. The type is ET_DYN: the loader chooses the address the file is mapped at.",
            "No. The type is ET_EXEC: each segment must be mapped at exactly its p_vaddr."],
    "pe": ["Yes. DYNAMIC_BASE is set and the relocations are present: the image opts in to ASLR.",
           "No. DYNAMIC_BASE is clear, or the relocations were stripped: the image does not opt in to ASLR."],
}

# The three answers of the "entry_kind" task. The question asks how the FORMAT DEFINES the field,
# and each answer names its own mechanics, so that a numeric coincidence (an ET_DYN file linked at
# address 0, a code segment whose file offset equals its address) does not make a second one right.
_ENTRY_KIND_OPTIONS = [
    "A file offset: a distance from the first byte of the file",
    "A virtual address: the address itself, in the coordinates the file was linked in",
    "An RVA: a distance to be added to the ImageBase field of the header",
]


def compute_task(spec: Dict[str, Any], doc: Dict[str, Any], slice_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """A concrete task for this document, or None if it does not apply here."""
    try:
        task = _compute_task(spec, doc, slice_doc)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return None
    if task is None:
        return None
    given = task.get("values", {})
    values = facts(doc, slice_doc)
    values.update(given)
    fmt = fmt_of(slice_doc)
    prompt = per_format(spec.get("prompt"), fmt)
    explain = per_format(spec.get("explain"), fmt)
    if not prompt:
        return None
    task["prompt"] = fill(str(prompt), values)
    task["explain"] = fill(str(explain or ""), values)
    task["id"] = spec.get("id", "")
    if task["kind"] == "value":
        # JSON numbers lose precision above 2**53; clients compare against this text.
        task["expect_text"] = hexs(task["expect"])
    return task


def _compute_task(spec: Dict[str, Any], doc: Dict[str, Any], slice_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    fmt = fmt_of(slice_doc)
    kind = spec.get("kind")
    calc = spec.get("calc")
    segs = slice_doc.get("segments") or []

    # ---- point at bytes -----------------------------------------------------
    if kind == "bytes":
        if calc == "addr_to_offset":
            for item in slice_doc.get("strings") or []:
                vm = to_int(item.get("vmaddr"))
                if vm is None:
                    continue
                off = vm_to_abs(slice_doc, vm)
                if off is None or not _range_ok(doc, off, 1):
                    continue
                return {"kind": "bytes", "ranges": [{"abs_offset": off, "size": 1}], "node_id": None,
                        "values": {"address": hexs(vm), "answer": hexs(off)}}
            return None
        if calc == "entry_code":
            ep = slice_doc.get("entry_point") or {}
            vm = to_int(ep.get("vmaddr"))
            off = vm_to_abs(slice_doc, vm) if vm is not None else None
            if off is None or not _range_ok(doc, off, 1):
                return None
            width = 4 if str(slice_doc.get("arch_name", "")).lower().startswith("arm64") else 1
            return {"kind": "bytes", "ranges": [{"abs_offset": off, "size": width}], "node_id": None,
                    "values": {"address": hexs(vm), "answer": hexs(off)}}
        ranges = []
        node_id = None
        for loc in as_list(spec.get("target")):
            hit = resolve(loc, doc, slice_doc)
            if hit.get("available") and hit.get("abs_offset") is not None:
                ranges.append({"abs_offset": hit["abs_offset"], "size": hit["size"]})
                node_id = node_id or hit["node_id"]
        if not ranges:
            return None
        return {"kind": "bytes", "ranges": ranges, "node_id": node_id, "values": {"answer": hexs(ranges[0]["abs_offset"])}}

    # ---- select a node in the tree -------------------------------------------
    if kind == "node":
        if calc == "segment_for_address":
            # Prefer an address outside the code segment (the tour has just shown that one): the first
            # import pointer slot. Statically linked files have none; use the entry point there.
            slot = first_import_slot(slice_doc)
            if slot is not None:
                vm = slot["vmaddr"]
                lead = "At address %s is a pointer that the loader fills in when the program starts." % hexs(vm)
            else:
                vm = to_int((slice_doc.get("entry_point") or {}).get("vmaddr"))
                lead = "The entry point of this file is at address %s." % hexs(vm)
            index = segment_for_vmaddr(slice_doc, vm) if vm is not None else None
            if index is None or len(segs) < 2:
                return None
            return {"kind": "node", "node_ids": ["seg_%d" % index], "options": _segment_options(slice_doc),
                    "values": {"address": hexs(vm), "lead": lead, "what": "slot" if slot is not None else "entry",
                               "answer": clean(segs[index].get("segname"))}}
        if calc == "exec_segments":
            ids = ["seg_%d" % i for i, seg in enumerate(segs) if "x" in _prot(seg)]
            if not ids or len(segs) < 2:
                return None
            return {"kind": "node", "node_ids": ids, "options": _segment_options(slice_doc),
                    "values": {"answer": ", ".join(clean(segs[int(i[4:])].get("segname")) for i in ids)}}
        if calc == "rwx_segments":
            ids = ["seg_%d" % i for i, seg in enumerate(segs) if "x" in _prot(seg) and "w" in _prot(seg)]
            if not ids:
                return None
            return {"kind": "node", "node_ids": ids, "options": _segment_options(slice_doc),
                    "values": {"answer": ", ".join(clean(segs[int(i[4:])].get("segname")) for i in ids)}}
        ids = []
        label = ""
        for loc in as_list(spec.get("target")):
            hit = resolve(loc, doc, slice_doc)
            if hit.get("available"):
                ids.append(hit["node_id"])
                label = label or hit.get("label", "")
        if not ids:
            return None
        return {"kind": "node", "node_ids": ids, "options": [], "values": {"answer": clean(label)}}

    # ---- type a number --------------------------------------------------------
    if kind == "value":
        if calc == "make_writable":
            target = _writable_target(slice_doc)
            if not target:
                return None
            expect = target["raw"] | target["bit"]
            field = target["field"]
            return {"kind": "value", "expect": expect, "show": {"node_id": "seg_%d" % target["index"], "abs_offset": field["abs_offset"],
                                                               "size": to_int(field.get("size")) or 4, "label": target["name"]},
                    "values": {"seg": clean(target["segment"].get("segname")), "prot": clean(target["segment"].get("initprot")),
                               "field": target["name"], "current": hexs(target["raw"]), "bit": hexs(target["bit"]), "answer": hexs(expect)}}
        if calc == "zerofill_size":
            index = pick_segment(slice_doc, "zerofill")
            if index is None:
                return None
            seg = segs[index]
            expect = (to_int(seg.get("vmsize_int")) or 0) - (to_int(seg.get("filesize")) or 0)
            region = _region(seg.get("header_region"))
            return {"kind": "value", "expect": expect,
                    "show": dict(region, node_id="seg_%d" % index, label=clean(seg.get("segname"))) if region else None,
                    "values": {"seg": clean(seg.get("segname")), "answer": "%d (%s)" % (expect, hexs(expect))}}
        if calc == "rva_to_offset":
            if fmt != "pe":
                return None
            field = find_field((slice_doc.get("header") or {}).get("fields"), "OptionalHeader.AddressOfEntryPoint")
            rva = to_int(field.get("raw_value")) if field else None
            hit = _pe_section_for_rva(slice_doc, rva) if rva is not None else None
            if hit is None:
                return None
            expect = hit["raw"] + (rva - hit["va"])
            seg = segs[hit["index"]]
            return {"kind": "value", "expect": expect, "show": {"node_id": "seg_%d" % hit["index"], "abs_offset": None, "size": None, "label": ""},
                    "values": {"rva": hexs(rva), "seg": clean(seg.get("segname")), "va": hexs(hit["va"]), "raw": hexs(hit["raw"]), "answer": hexs(expect)}}
        if calc == "library_count":
            count = len(slice_doc.get("dylibs") or [])
            if count == 0:
                return None
            return {"kind": "value", "expect": count, "show": None, "values": {"answer": str(count)}}
        hit = resolve(spec.get("target") or {}, doc, slice_doc)
        if not hit.get("available") or hit.get("abs_offset") is None:
            return None
        field = _field_at(doc, slice_doc, hit)
        if field is None:
            return None
        if calc == "le_value":
            raw_hex = str(field.get("raw_hex") or "")
            data = bytes(int(b, 16) for b in raw_hex.split())
            if not data or len(data) > 8 or len(data) != (to_int(field.get("size")) or 0):
                return None
            # Decode in the byte order of THIS file (a big-endian ELF or Mach-O stores the most
            # significant byte first); the prompt names the same order through {byte_order}.
            expect = int.from_bytes(data, "little" if is_little_endian(slice_doc) else "big")
            parsed = to_int(field.get("raw_value"))
            if parsed is not None and parsed != expect:
                return None   # the parser read this field differently: no single right answer
            return {"kind": "value", "expect": expect, "show": {k: hit[k] for k in ("node_id", "abs_offset", "size", "label")},
                    "values": {"bytes": raw_hex, "field": clean(field.get("name")), "offset": hexs(field.get("abs_offset")), "answer": hexs(expect)}}
        expect = to_int(field.get("raw_value"))
        if expect is None:
            return None
        return {"kind": "value", "expect": expect, "show": {k: hit[k] for k in ("node_id", "abs_offset", "size", "label")},
                "values": {"field": clean(field.get("name")), "answer": "%d (%s)" % (expect, hexs(expect))}}

    # ---- choose one ------------------------------------------------------------
    if kind == "choice":
        if calc == "is_pie":
            pie = is_pie(slice_doc)
            if pie is None:
                return None
            return {"kind": "choice", "options": list(_PIE_OPTIONS[fmt]),
                    "correct": 0 if pie else 1, "values": {"answer": "Yes" if pie else "No"}}
        if calc == "is_dynamic":
            if fmt == "pe":
                return None
            dynamic = find_lc(slice_doc, {"macho": ["LC_LOAD_DYLINKER"], "elf": ["PT_INTERP"]}) is not None
            return {"kind": "choice", "options": ["Yes. It names a dynamic linker.", "No. It names none."],
                    "correct": 0 if dynamic else 1, "values": {"answer": "yes" if dynamic else "no"}}
        if calc == "import_library":
            imports = (((slice_doc.get("dyld_info") or {}).get("chained_fixups") or {}).get("imports")) or []
            # Only real libraries count: a Mach-O import may carry a special ordinal (flat or weak
            # lookup, the main executable) that names no library.
            real = set(str(d.get("name") or "") for d in (slice_doc.get("dylibs") or []) if isinstance(d, dict))
            libs: List[str] = []
            for item in imports:
                name = str(item.get("lib_name") or "")
                if name and name in real and name not in libs:
                    libs.append(name)
            if len(libs) < 2:
                return None
            chosen = next((i for i in imports if str(i.get("lib_name") or "") == libs[-1] and i.get("name")), None)
            if chosen is None:
                return None
            options = libs[:6]
            if libs[-1] not in options:
                options[-1] = libs[-1]
            return {"kind": "choice", "options": [clean(o, 120) for o in options], "correct": options.index(libs[-1]),
                    "values": {"symbol": clean(chosen.get("name")), "answer": clean(libs[-1], 120)}}
        if calc == "first_arg_register":
            arch = str(slice_doc.get("arch_name") or "").lower()
            options = ["rdi", "rcx", "x0", "None: arguments are passed on the stack"]
            if arch.startswith("arm64"):
                correct = 2
            elif arch == "x86_64":
                correct = 1 if fmt == "pe" else 0
            elif arch == "i386":
                correct = 3
            else:
                return None
            return {"kind": "choice", "options": options, "correct": correct, "values": {"answer": options[correct]}}
        if calc == "entry_kind":
            options = list(_ENTRY_KIND_OPTIONS)
            if fmt == "macho":
                if find_lc(slice_doc, ["LC_MAIN"]) is not None:
                    correct = 0
                elif find_lc(slice_doc, ["LC_UNIXTHREAD"]) is not None:
                    correct = 1
                else:
                    return None
            else:
                correct = 1 if fmt == "elf" else 2
            short = ["a file offset", "a virtual address", "an RVA (an offset from the image base)"][correct]
            return {"kind": "choice", "options": options, "correct": correct, "values": {"answer": short}}
        options = [str(o) for o in as_list(per_format(spec.get("options"), fmt))]
        correct = to_int(per_format(spec.get("correct"), fmt))
        if len(options) < 2 or correct is None or not 0 <= correct < len(options):
            return None
        return {"kind": "choice", "options": options, "correct": correct, "values": {"answer": options[correct]}}

    return None


def _field_at(doc: Dict[str, Any], slice_doc: Dict[str, Any], hit: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The parsed field that a resolved locator points at."""
    lists: List[Any] = [(slice_doc.get("header") or {}).get("fields")]
    fat = (doc.get("file_info") or {}).get("fat_header")
    if fat:
        lists.append(fat.get("fields"))
    for lc in slice_doc.get("load_commands") or []:
        lists.append(lc.get("fields"))
    for seg in slice_doc.get("segments") or []:
        lists.append(seg.get("fields"))
        for sect in seg.get("sections") or []:
            lists.append(sect.get("fields"))
    for fields in lists:
        for field in fields or []:
            if isinstance(field, dict) and field.get("abs_offset") == hit["abs_offset"] and (to_int(field.get("size")) or 1) == hit["size"]:
                return field
    return None
