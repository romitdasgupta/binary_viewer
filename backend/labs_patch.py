"""
Labs: patch-and-observe, guided experiments, the minimal-ELF builder and
document comparison.

Nothing in this module executes anything. An "experiment" is an edit to bytes
followed by a fresh analysis of a derived copy; the original document is never
modified. Everything that touches bytes or Documents lives here, behind the
router, so the same code serves the HTTP server and the in-browser (Pyodide)
build. The JavaScript side only presents what these endpoints return.

Endpoints (registered by `register_labs_patch_routes`):

  POST /api/patch              {doc, patches:[{offset, hex, label?}], replace?}
                               -> {doc_id, document, diff, patches, parent, identical}
                               (`document` is omitted when `identical`: nothing changed,
                               the caller already holds the parent)
  GET  /api/download           doc=            -> the document's bytes (attachment)
  POST /api/labs/resolve       {doc, slice_index?, op:{kind, ...}}
                               -> {ok, patches:[{offset, hex, label}], changes:[...]} or {ok:false, error}
                               kinds: field | flag | fill | experiment
  GET  /api/labs/experiments   doc=? slice_index=?  -> the catalogue, resolved against the document
  GET  /api/labs/compare       a=, b=          -> {diff}
  GET  /api/labs/build/options                 -> the builder's form description
  POST /api/labs/build         {arch, type, base, flags, payload, ...}
                               -> {ok, hex, regions, notes, ...} or {ok:false, error}

Model: the client holds a list of byte patches against a *root* document and
sends the whole list each time; the server applies it to the root's bytes,
stores the result as a derived (`p_`) document and returns a structural diff
of root -> derived. Higher-level edits (set a field, toggle a flag, apply an
experiment) are first turned into byte patches by /api/labs/resolve, so the
patch list is always plain bytes and can be exported, imported and replayed.

Limits enforced here (all server-side):
  * config.max_patch_bytes  total bytes across one patch set
  * MAX_PATCHES             entries in one patch set
  * every patch must lie inside the file; patches never change its size
  * a dedicated token bucket for /api/patch in rate-limited modes, on top of the
    router's per-client limit: every call pays one token before any work, and
    every analysis it then causes (the patched copy, and each re-parse made to
    find the patch that broke it) pays again in proportion to the file's size
  * every one of those analyses goes through AnalysisService like an upload's:
    one slot of the concurrency cap, the parse deadline, a worker process
  * derived documents go through the same store as uploads: they count against
    the cache and the per-client share, and expire the same way
"""

import bisect
import hashlib
import secrets
import struct
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from . import runtime
from .api import ApiRequest, ApiResponse, ApiRouter, TokenBucketLimiter, int_param, str_param
from . import pe_parser as _pe
from .parser import parse_macho_bytes
from .runtime import BadRequest, Forbidden, ParseFailed, RateLimited, TooLarge, check_deadline, encode_json
from .service import DOC_COST_FACTOR, DocEntry

MAX_PATCHES = 4096            # entries in one patch set
SQUASH_MAX_PATCHES = 512      # dead entries are removed from lists up to this long
MAX_LABEL_CHARS = 120
MAX_FIELD_CHANGES = 400       # changed fields reported per slice
MAX_RECORD_CHANGES = 200      # changed / added / removed segments, sections, commands per slice
MAX_BYTE_RANGES = 200         # changed byte runs reported
MAX_NAME_SAMPLES = 40         # symbol / string names listed per bucket
MAX_CODE_PAGES = 65536        # Mach-O code pages verified per slice
COMPARE_BYTES_MAX = 4 * 1024 * 1024  # two unrelated files are compared byte by byte only up to this size
LOCATE_MAX_PATCHES = 16       # find the first breaking patch only for small sets ...
LOCATE_MAX_BYTES = 8 * 1024 * 1024  # ... of small files
LOCATE_MAX_WORK_BYTES = 32 * 1024 * 1024  # bytes re-analysed to find it, per request (4 probes of the largest file)
LOCATE_MAX_SECONDS = 6.0      # wall-clock time spent finding it, per request
PATCH_RATE_FACTOR = 10        # /api/patch calls allowed per upload the mode allows
COST_UNIT_BYTES = 4 * 1024 * 1024   # one extra rate-limit token per this many bytes re-analysed

HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


# ============================================================================
# Small helpers
# ============================================================================
def _clean_text(value: Any, limit: int = MAX_LABEL_CHARS) -> str:
    """A client-supplied label, reduced to one printable line."""
    text = "".join(ch if (0x20 <= ord(ch) < 0x7F or ord(ch) > 0x9F) else " " for ch in str(value or ""))
    return " ".join(text.split())[:limit]


def _hex_spaced(data: bytes, limit: int = 32) -> str:
    shown = " ".join("%02x" % b for b in data[:limit])
    return shown + (" ..." if len(data) > limit else "")


def _slice_fmt(slice_obj: Dict[str, Any]) -> str:
    fmt = str(slice_obj.get("format") or "").upper()
    return fmt if fmt in ("ELF", "PE") else "MACHO"


def _is_unparsed(doc: Dict[str, Any]) -> bool:
    return bool((doc.get("file_info") or {}).get("unparsed"))


def _as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().replace("_", "")
        if not text or len(text) > 40:
            return None
        try:
            return int(text, 16) if text.lower().startswith(("0x", "-0x")) else int(text, 10)
        except ValueError:
            return None
    return None


def _derived_filename(name: str) -> str:
    """`a.exe` -> `a.patched.exe`; `ls` -> `ls.patched`; already patched names are kept."""
    name = str(name or "binary")
    if ".patched" in name:
        return name
    stem, dot, ext = name.rpartition(".")
    if dot and stem and 0 < len(ext) <= 8 and ext.isalnum():
        return f"{stem}.patched.{ext}"
    return name + ".patched"


# ============================================================================
# Patch sets
# ============================================================================
def parse_patches(raw: Any, file_size: int, max_bytes: int) -> List[Dict[str, Any]]:
    """Validate a client patch list. Returns [{offset, data, label}] in the order given.

    Every rejection is a BadRequest / TooLarge with a message that names the entry.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise BadRequest("'patches' must be a list of {offset, hex} objects.")
    if len(raw) > MAX_PATCHES:
        raise TooLarge(f"A patch set may hold at most {MAX_PATCHES:,} entries; this one has {len(raw):,}.")
    out: List[Dict[str, Any]] = []
    total = 0
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise BadRequest(f"Patch #{index + 1} is not an object.")
        offset = item.get("offset")
        if isinstance(offset, str):
            offset = _as_int(offset)
        if isinstance(offset, bool) or not isinstance(offset, int):
            raise BadRequest(f"Patch #{index + 1}: 'offset' must be an integer.")
        text = item.get("hex")
        if not isinstance(text, str):
            raise BadRequest(f"Patch #{index + 1}: 'hex' must be a string of hex digits.")
        if len(text) > 4 * max_bytes + 64:
            raise TooLarge(f"Patch #{index + 1} is larger than the limit of {max_bytes:,} bytes.")
        digits = "".join(text.split())
        if not digits:
            raise BadRequest(f"Patch #{index + 1} has no bytes.")
        if len(digits) % 2 or not HEX_DIGITS.issuperset(digits):
            raise BadRequest(f"Patch #{index + 1}: 'hex' must be an even number of hex digits.")
        size = len(digits) // 2
        if offset < 0 or offset >= file_size or offset + size > file_size:
            raise BadRequest(
                f"Patch #{index + 1} covers 0x{max(offset, 0):x}..0x{max(offset, 0) + size:x}, outside the file "
                f"(size 0x{file_size:x}). Patches cannot grow or shrink a file."
                if -(1 << 64) < offset < (1 << 64) else f"Patch #{index + 1}: offset is outside the file."
            )
        total += size
        if total > max_bytes:
            raise TooLarge(f"The patch set changes more than {max_bytes:,} bytes, the limit on this server.")
        out.append({"offset": offset, "data": bytes.fromhex(digits), "label": _clean_text(item.get("label"))})
    return out


def apply_patches(data: bytes, patches: List[Dict[str, Any]]) -> bytes:
    """A patched copy of `data`. Later patches win where they overlap earlier ones."""
    buf = bytearray(data)
    for patch in patches:
        start = patch["offset"]
        buf[start:start + len(patch["data"])] = patch["data"]
    if len(buf) != len(data):  # cannot happen for validated patches; never return a resized file
        raise BadRequest("A patch would change the size of the file.")
    return bytes(buf)


def squash_patches(data: bytes, patches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The same edit with dead entries removed: ones a later entry overwrites
    completely, and ones that leave the parent's bytes as they were (and shadow
    nothing). Applying the result gives exactly the same bytes. Long lists are
    returned as they are; the pairwise check is quadratic."""
    if len(patches) > SQUASH_MAX_PATCHES:
        return patches
    kept: List[Dict[str, Any]] = []
    for patch in patches:
        start, end = patch["offset"], patch["offset"] + len(patch["data"])
        kept = [q for q in kept if not (start <= q["offset"] and q["offset"] + len(q["data"]) <= end)]
        if patch["data"] == data[start:end] and not any(q["offset"] < end and start < q["offset"] + len(q["data"]) for q in kept):
            continue
        kept.append(patch)
    return kept


def _patch_ranges(patches: List[Dict[str, Any]]) -> List[Tuple[int, int]]:
    """Merged, sorted [start, end) ranges covered by a patch set."""
    spans = sorted((p["offset"], p["offset"] + len(p["data"])) for p in patches)
    merged: List[Tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def _changed_runs(before: bytes, after: bytes, ranges: Optional[List[Tuple[int, int]]]) -> Tuple[List[Tuple[int, int]], bool]:
    """([start, end) runs where the two buffers differ, comparable?).

    With `ranges` only those spans are inspected (a patch set); otherwise the
    whole of two equally long buffers. Buffers of different length are not
    byte-comparable.
    """
    if len(before) != len(after):
        return [], False
    if ranges is None:
        ranges = [(0, len(before))]
    runs: List[Tuple[int, int]] = []
    for start, end in ranges:
        pos = start
        while pos < end:
            check_deadline()
            chunk_end = min(end, pos + 4096)
            if before[pos:chunk_end] == after[pos:chunk_end]:
                pos = chunk_end
                continue
            i = pos
            while i < chunk_end:
                if before[i] != after[i]:
                    j = i + 1
                    while j < chunk_end and before[j] != after[j]:
                        j += 1
                    if runs and runs[-1][1] == i:
                        runs[-1] = (runs[-1][0], j)
                    else:
                        runs.append((i, j))
                    i = j
                else:
                    i += 1
            pos = chunk_end
    return runs, True


class _RangeSet:
    """Overlap queries against sorted, disjoint [start, end) ranges."""

    def __init__(self, ranges: List[Tuple[int, int]]) -> None:
        self.ranges = ranges
        self._starts = [r[0] for r in ranges]

    def overlaps(self, start: int, size: int) -> bool:
        if size <= 0 or not self.ranges:
            return False
        idx = bisect.bisect_right(self._starts, start + size - 1) - 1
        return idx >= 0 and self.ranges[idx][1] > start

    def __bool__(self) -> bool:
        return bool(self.ranges)


# ============================================================================
# Walking a Document: structures and their fields
# ============================================================================
_COMMAND_NOUN = {"ELF": "Program header", "PE": "Header", "MACHO": "Load command"}
_HEADER_LABEL = {"ELF": "ELF header", "PE": "PE headers", "MACHO": "Mach-O header"}
# Containers that never hold field lists worth walking generically (large, or handled explicitly).
_SKIP_KEYS = frozenset((
    "header", "load_commands", "segments", "symbols", "strings", "intervals", "memory_map", "semantic_layers",
    "pedagogy", "function_starts", "overview", "security_posture", "dylibs", "rpaths", "objc_metadata",
))


def _is_field_list(value: Any) -> bool:
    return (isinstance(value, list) and bool(value) and isinstance(value[0], dict)
            and "abs_offset" in value[0] and "name" in value[0] and "size" in value[0])


def _first_offset(fields: List[Dict[str, Any]], region: Optional[Dict[str, Any]] = None) -> Optional[int]:
    if isinstance(region, dict) and isinstance(region.get("abs_offset"), int):
        return region["abs_offset"]
    if fields:
        off = fields[0].get("abs_offset")
        return off if isinstance(off, int) else None
    return None


def iter_structs(doc: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """Every decoded structure of a Document, as
    {slice, kind, label, node, fields, offset, cmp, rec}.

    `node` is the id of the tree node that shows the structure; `cmp` is a
    key that identifies the "same" structure in a different file; `offset` is
    where its header lives in this file.
    """
    info = doc.get("file_info") or {}
    fat = info.get("fat_header")
    if isinstance(fat, dict) and _is_field_list(fat.get("fields")):
        yield {"slice": -1, "kind": "fat", "label": "Fat header", "node": "fat_header", "fields": fat["fields"],
               "offset": 0, "cmp": ("fat",), "rec": fat}
    for pos, sl in enumerate(doc.get("slices") or []):
        if not isinstance(sl, dict):
            continue
        fmt = _slice_fmt(sl)
        header = sl.get("header") or {}
        if _is_field_list(header.get("fields")):
            yield {"slice": pos, "kind": "hdr", "label": _HEADER_LABEL[fmt], "node": "mach_header",
                   "fields": header["fields"], "offset": _first_offset(header["fields"], header.get("region")),
                   "cmp": ("hdr",), "rec": header}
        seen: Dict[Tuple[Any, ...], int] = {}
        for lc in sl.get("load_commands") or []:
            check_deadline()
            fields = lc.get("fields") or []
            name = str(lc.get("cmd_name") or "")
            occ = seen[("lc", name)] = seen.get(("lc", name), -1) + 1
            yield {"slice": pos, "kind": "lc", "label": f"{_COMMAND_NOUN[fmt]} #{lc.get('index')} {name}",
                   "node": f"lc_{lc.get('index')}", "fields": fields,
                   "offset": _first_offset(fields, lc.get("region") if fmt != "PE" else None),
                   "cmp": ("lc", name, occ), "rec": lc}
        for s_idx, seg in enumerate(sl.get("segments") or []):
            check_deadline()
            segname = str(seg.get("segname") or "")
            occ = seen[("seg", segname)] = seen.get(("seg", segname), -1) + 1
            fields = seg.get("fields") or []
            yield {"slice": pos, "kind": "seg", "label": f"Segment {segname}", "node": f"seg_{s_idx}",
                   "fields": fields, "offset": _first_offset(fields, seg.get("header_region")),
                   "cmp": ("seg", segname, occ), "rec": seg}
            for c_idx, sect in enumerate(seg.get("sections") or []):
                sectname = str(sect.get("sectname") or "")
                full = f"{sect.get('segname')},{sectname}" if fmt == "MACHO" else sectname
                occ = seen[("sect", full)] = seen.get(("sect", full), -1) + 1
                fields = sect.get("fields") or []
                yield {"slice": pos, "kind": "sect", "label": f"Section {full}", "node": f"sect_{s_idx}_{c_idx}",
                       "fields": fields, "offset": _first_offset(fields, sect.get("header_region")),
                       "cmp": ("sect", full, occ), "rec": sect}
        sig = sl.get("code_signature_detail") or {}
        if _is_field_list(sig.get("fields")):
            yield {"slice": pos, "kind": "sig", "label": "Signature container", "node": "code_signature",
                   "fields": sig["fields"], "offset": _first_offset(sig["fields"]), "cmp": ("sig",), "rec": sig}
        cd = sig.get("code_directory") or {}
        if _is_field_list(cd.get("fields")):
            yield {"slice": pos, "kind": "cd", "label": "CodeDirectory", "node": "code_signature",
                   "fields": cd["fields"], "offset": _first_offset(cd["fields"]), "cmp": ("cd",), "rec": cd}
        # Anything else that carries a field list (dysymtab, Rich header, ...), found generically.
        stack: List[Tuple[str, Any, int]] = [(k, v, 0) for k, v in sl.items() if k not in _SKIP_KEYS and k != "code_signature_detail"]
        while stack:
            path, value, depth = stack.pop()
            if isinstance(value, dict):
                if _is_field_list(value.get("fields")):
                    yield {"slice": pos, "kind": "other", "label": path.replace("_", " "), "node": None,
                           "fields": value["fields"], "offset": _first_offset(value["fields"]),
                           "cmp": ("other", path), "rec": value}
                if depth < 3:
                    for key, child in value.items():
                        if key != "fields" and isinstance(child, dict):
                            stack.append((f"{path}.{key}", child, depth + 1))


def field_endianness(field: Dict[str, Any], siblings: List[Dict[str, Any]], data: bytes,
                     default_little: bool = True) -> Optional[str]:
    """'little' / 'big' for an integer field, or None when its bytes are not a plain integer.

    The byte order is not recorded in a Document, so it is read off the field
    itself: whichever order turns its bytes into its `raw_value`. A field whose
    bytes read the same both ways (zero, 0x0101, one byte) takes the order of
    its siblings, then of the slice.
    """
    def probe(f: Dict[str, Any]) -> Optional[str]:
        raw_value = f.get("raw_value")
        size = f.get("size")
        off = f.get("abs_offset")
        if isinstance(raw_value, bool) or not isinstance(raw_value, int) or not isinstance(size, int):
            return None
        if not isinstance(off, int) or size <= 0 or size > 8 or off < 0 or off + size > len(data):
            return None
        raw = data[off:off + size]
        little = int.from_bytes(raw, "little") == raw_value
        big = int.from_bytes(raw, "big") == raw_value
        if little and big:
            return "both"
        if little:
            return "little"
        if big:
            return "big"
        return None

    own = probe(field)
    if own in ("little", "big"):
        return own
    if own is None:
        return None
    votes = {"little": 0, "big": 0}
    for other in siblings:
        got = probe(other)
        if got in votes:
            votes[got] += 1
    if votes["little"] != votes["big"]:
        return "little" if votes["little"] > votes["big"] else "big"
    return "little" if default_little else "big"


def _slice_little(slice_obj: Optional[Dict[str, Any]]) -> bool:
    header = (slice_obj or {}).get("header") or {}
    return header.get("little_endian") is not False


def find_field(doc: Dict[str, Any], abs_offset: int, size: Optional[int] = None,
               name: Optional[str] = None) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """(structure, field) for the field at `abs_offset` (first match in document order)."""
    for st in iter_structs(doc):
        for field in st["fields"]:
            if field.get("abs_offset") != abs_offset:
                continue
            if size is not None and field.get("size") != size:
                continue
            if name is not None and field.get("name") != name:
                continue
            return st, field
    return None


def _named_field(fields: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    for field in fields or []:
        if field.get("name") == name:
            return field
    return None


def _flag_mask(flag: Dict[str, Any]) -> Optional[int]:
    return _as_int(flag.get("mask"))


# ============================================================================
# Integrity facts computed from the bytes themselves
# ============================================================================
# The checksum and the Authenticode image hash have one implementation, in the PE
# parser (which reports them for every file); the lab recomputes them for both sides
# of a patch. tests/test_audit_logic.py checks them against Microsoft-signed images.
_pe_layout = _pe.pe_layout
pe_checksum = _pe.pe_checksum
authenticode_digest = _pe.authenticode_digest


def pe_integrity(data: bytes) -> Optional[Dict[str, Any]]:
    layout = _pe_layout(data)
    if layout is None:
        return None
    computed = pe_checksum(data, layout["checksum_off"])
    out: Dict[str, Any] = {
        "checksum_offset": layout["checksum_off"],
        "checksum_stored": "0x%08x" % layout["stored_checksum"],
        "checksum_computed": "0x%08x" % computed,
        "checksum_ok": computed == layout["stored_checksum"],
        "signed": False,
    }
    cert_off, cert_size = layout["cert_off"], layout["cert_size"]
    if cert_off and cert_size and cert_off + cert_size <= len(data):
        blob = data[cert_off:cert_off + cert_size]
        out["signed"] = True
        out["cert_offset"], out["cert_size"] = cert_off, cert_size
        embedded = None
        for algorithm in ("sha256", "sha1", "sha384", "sha512", "md5"):
            digest = authenticode_digest(data, layout, algorithm)
            if algorithm == "sha256":
                out["image_hash_sha256"] = digest
            if bytes.fromhex(digest) in blob:
                embedded = algorithm
                break
        # True: the signature holds this file's image hash. False is only
        # claimed by a caller that saw True for the unpatched file.
        out["embedded_hash_matches"] = embedded is not None
        out["embedded_hash_algorithm"] = embedded
    return out


_CS_DIGESTS: Dict[int, Tuple[str, int]] = {1: ("sha1", 20), 2: ("sha256", 32), 3: ("sha256", 20), 4: ("sha384", 48)}


def _cd_params(slice_obj: Dict[str, Any]) -> Optional[Dict[str, int]]:
    """Where a Mach-O slice's CodeDirectory keeps its page hashes, from the decoded fields."""
    sig = slice_obj.get("code_signature_detail") or {}
    cd = sig.get("code_directory") or {}
    fields = cd.get("fields") or []
    blob = next((b for b in sig.get("blobs") or [] if b.get("type") == 0 and isinstance(b.get("abs_offset"), int)), None)
    if not fields or blob is None:
        return None
    values: Dict[str, int] = {}
    for name in ("hashOffset", "nCodeSlots", "codeLimit", "hashSize", "hashType", "pageSize"):
        field = _named_field(fields, name)
        if field is None or not isinstance(field.get("raw_value"), int):
            return None
        values[name] = field["raw_value"]
    if values["hashType"] not in _CS_DIGESTS or not 0 < values["hashSize"] <= 64 or values["pageSize"] >= 32:
        return None
    values["cd_offset"] = blob["abs_offset"]
    values["cd_size"] = int(blob.get("size") or 0)
    values["base"] = int(slice_obj.get("slice_base_offset") or 0)
    values["page"] = 1 << values["pageSize"] if values["pageSize"] else 0
    return values


def macho_page_status(data: bytes, params: Dict[str, int], pages: Iterable[int]) -> Dict[int, Dict[str, Any]]:
    """{page: {ok, expected, actual, file_offset}} for the requested code pages."""
    algorithm, _ = _CS_DIGESTS[params["hashType"]]
    hash_size = params["hashSize"]
    out: Dict[int, Dict[str, Any]] = {}
    page_size = params["page"] or max(1, params["codeLimit"])  # pageSize 0: one hash over everything
    for page in pages:
        check_deadline()
        if page < 0 or page >= params["nCodeSlots"]:
            continue
        slot = params["cd_offset"] + params["hashOffset"] + page * hash_size
        start = params["base"] + page * page_size
        end = params["base"] + min((page + 1) * page_size, params["codeLimit"])
        if slot + hash_size > len(data) or slot < 0 or end > len(data) or end <= start:
            out[page] = {"ok": False, "expected": "", "actual": "", "file_offset": start}
            continue
        expected = data[slot:slot + hash_size]
        actual = hashlib.new(algorithm, data[start:end]).digest()[:hash_size]
        out[page] = {"ok": actual == expected, "expected": expected.hex(), "actual": actual.hex(), "file_offset": start}
    return out


def macho_failing_pages(slice_obj: Dict[str, Any], data: bytes, limit: int = MAX_CODE_PAGES) -> Optional[Dict[str, Any]]:
    """Check every code page of a signed Mach-O slice: {pages, failing:[...], checked, capped}."""
    params = _cd_params(slice_obj)
    if params is None:
        return None
    count = min(params["nCodeSlots"], limit)
    status = macho_page_status(data, params, range(count))
    failing = [page for page in sorted(status) if not status[page]["ok"]]
    return {"pages": params["nCodeSlots"], "checked": count, "capped": count < params["nCodeSlots"],
            "failing": failing[:64], "failing_count": len(failing), "page_size": params["page"]}


# ============================================================================
# Structural diff
# ============================================================================
def _field_view(field: Dict[str, Any]) -> Dict[str, Any]:
    return {"raw_hex": str(field.get("raw_hex") or ""), "value": str(field.get("value") if field.get("value") is not None else ""),
            "interpreted": str(field.get("interpreted") or "")}


def _set_flags(field: Dict[str, Any]) -> Dict[str, str]:
    return {str(f.get("name")): str(f.get("mask")) for f in field.get("bit_flags") or []
            if isinstance(f, dict) and f.get("set")}


def _slice_label(sl: Dict[str, Any]) -> str:
    return str(sl.get("arch_name") or sl.get("format_display") or "slice")


def _match_slices(before: Dict[str, Any], after: Dict[str, Any], mode: str) -> List[Tuple[Optional[int], Optional[int]]]:
    """Pairs (index in before, index in after). Patch mode pairs slices by where
    they sit in the file; compare mode by architecture."""
    b_slices = before.get("slices") or []
    a_slices = after.get("slices") or []

    def key(sl: Dict[str, Any], seen: Dict[Any, int]) -> Any:
        base = sl.get("slice_base_offset") if mode == "patch" else _slice_label(sl)
        seen[base] = seen.get(base, -1) + 1
        return (base, seen[base])

    seen_b: Dict[Any, int] = {}
    seen_a: Dict[Any, int] = {}
    b_keys = [key(sl, seen_b) for sl in b_slices]
    a_keys = [key(sl, seen_a) for sl in a_slices]
    pairs: List[Tuple[Optional[int], Optional[int]]] = []
    used = set()
    for bi, bk in enumerate(b_keys):
        ai = a_keys.index(bk) if bk in a_keys else None
        if ai is not None:
            used.add(ai)
        pairs.append((bi, ai))
    if mode == "compare" and len(b_slices) == 1 and len(a_slices) == 1 and pairs == [(0, None)]:
        return [(0, 0)]  # two thin files are compared with each other whatever their architectures
    pairs.extend((None, ai) for ai in range(len(a_slices)) if ai not in used)
    return pairs


def _lands_in(slice_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Where the entry point falls: segment, section, protection."""
    entry = slice_obj.get("entry_point") or {}
    vm = _as_int(entry.get("vmaddr"))
    if vm is None or not entry.get("type"):
        return None
    out: Dict[str, Any] = {"type": str(entry.get("type")), "vmaddr": "0x%x" % vm, "abs_offset": entry.get("abs_offset"),
                           "mapped": False, "segment": None, "section": None, "prot": None, "executable": False}
    for seg in slice_obj.get("segments") or []:
        start, size = seg.get("vmaddr_int"), seg.get("vmsize_int")
        if not isinstance(start, int) or not isinstance(size, int) or not start <= vm < start + size:
            continue
        prot = str(seg.get("initprot") or "")
        if prot == "---" and not seg.get("filesize"):
            continue  # __PAGEZERO and its like map nothing
        out.update(mapped=True, segment=str(seg.get("segname") or ""), prot=prot, executable="x" in prot)
        for sect in seg.get("sections") or []:
            s_vm, s_size = sect.get("vmaddr_int"), sect.get("size")
            if isinstance(s_vm, int) and isinstance(s_size, int) and s_vm <= vm < s_vm + s_size:
                out["section"] = str(sect.get("sectname") or "")
                break
        break
    return out


def _prop_changes(before: Dict[str, Any], after: Dict[str, Any], props: Iterable[str]) -> List[Dict[str, Any]]:
    out = []
    for prop in props:
        b, a = before.get(prop), after.get(prop)
        if b != a:
            out.append({"prop": prop, "before": b, "after": a})
    return out


def _diff_records(before: List[Dict[str, Any]], after: List[Dict[str, Any]],
                  key: Callable[[Dict[str, Any], int, Dict[Any, int]], Any],
                  label: Callable[[Dict[str, Any]], str], props: Tuple[str, ...],
                  node: Callable[[Dict[str, Any], int], Optional[str]]) -> Dict[str, Any]:
    """Generic list diff: records are paired by `key`, then compared on `props`."""
    def index(items: List[Dict[str, Any]]) -> Dict[Any, Tuple[int, Dict[str, Any]]]:
        seen: Dict[Any, int] = {}
        out: Dict[Any, Tuple[int, Dict[str, Any]]] = {}
        for pos, item in enumerate(items):
            out.setdefault(key(item, pos, seen), (pos, item))
        return out

    b_idx, a_idx = index(before), index(after)
    changed, added, removed = [], [], []
    for k, (pos, item) in b_idx.items():
        check_deadline()
        other = a_idx.get(k)
        if other is None:
            removed.append({"label": label(item), "node": node(item, pos)})
            continue
        changes = _prop_changes(item, other[1], props)
        if changes:
            changed.append({"label": label(other[1]), "node": node(other[1], other[0]), "changes": changes})
    for k, (pos, item) in a_idx.items():
        if k not in b_idx:
            added.append({"label": label(item), "node": node(item, pos)})
    total = len(changed) + len(added) + len(removed)
    return {"changed": changed[:MAX_RECORD_CHANGES], "added": added[:MAX_RECORD_CHANGES],
            "removed": removed[:MAX_RECORD_CHANGES], "total": total,
            "truncated": max(0, len(changed) - MAX_RECORD_CHANGES) + max(0, len(added) - MAX_RECORD_CHANGES)
            + max(0, len(removed) - MAX_RECORD_CHANGES)}


def _name_occurrence_key(name_of: Callable[[Dict[str, Any]], Any]) -> Callable[[Dict[str, Any], int, Dict[Any, int]], Any]:
    def key(item: Dict[str, Any], _pos: int, seen: Dict[Any, int]) -> Any:
        name = name_of(item)
        seen[name] = seen.get(name, -1) + 1
        return (name, seen[name])
    return key


def _offset_key(offset_of: Callable[[Dict[str, Any]], Any],
                fallback: Callable[[Dict[str, Any]], Any]) -> Callable[[Dict[str, Any], int, Dict[Any, int]], Any]:
    def key(item: Dict[str, Any], _pos: int, seen: Dict[Any, int]) -> Any:
        off = offset_of(item)
        if isinstance(off, int):
            return ("@", off)
        name = fallback(item)
        seen[name] = seen.get(name, -1) + 1
        return (name, seen[name])
    return key


def _region_off(item: Dict[str, Any], key: str) -> Optional[int]:
    region = item.get(key)
    off = region.get("abs_offset") if isinstance(region, dict) else None
    if isinstance(off, int):
        return off
    return _first_offset(item.get("fields") or [])


_SEG_PROPS = ("segname", "vmaddr", "vmsize", "fileoff", "filesize", "initprot", "maxprot", "nsects", "flags_decoded")
_SECT_PROPS = ("sectname", "vmaddr", "size", "abs_offset", "section_type", "attributes_decoded", "prot", "is_executable")
_LC_PROPS = ("cmd_name", "cmdsize", "summary")
_SIG_PROPS = ("present", "magic", "length", "blob_count")
_CD_PROPS = ("identifier", "team_id", "hash_type", "flags_decoded", "cdhash", "cdhash_verified", "n_code_slots", "code_limit")


def _scalar_changes(before: Any, after: Any, skip: Tuple[str, ...] = ()) -> List[Dict[str, Any]]:
    """Changed scalar (or list-of-scalar) members of two dicts."""
    out = []
    if not isinstance(before, dict) or not isinstance(after, dict):
        return out
    for key in list(before.keys()) + [k for k in after.keys() if k not in before]:
        if key in skip:
            continue
        b, a = before.get(key), after.get(key)
        if b == a:
            continue
        simple = lambda v: v is None or isinstance(v, (str, int, float, bool)) or (  # noqa: E731
            isinstance(v, list) and len(v) <= 64 and all(isinstance(x, (str, int, float, bool)) for x in v))
        if simple(b) and simple(a):
            out.append({"prop": key, "before": b, "after": a})
    return out


def _set_diff(before: Iterable[Any], after: Iterable[Any], limit: int = MAX_NAME_SAMPLES) -> Dict[str, Any]:
    b_count: Dict[Any, int] = {}
    a_count: Dict[Any, int] = {}
    for item in before:
        b_count[item] = b_count.get(item, 0) + 1
    for item in after:
        a_count[item] = a_count.get(item, 0) + 1
    removed = [k for k, n in b_count.items() if a_count.get(k, 0) < n]
    added = [k for k, n in a_count.items() if b_count.get(k, 0) < n]
    return {"added": added[:limit], "removed": removed[:limit], "added_count": len(added), "removed_count": len(removed),
            "before_count": sum(b_count.values()), "after_count": sum(a_count.values())}


def _where(structs: List[Dict[str, Any]], slices: List[Dict[str, Any]], offset: int) -> Dict[str, Any]:
    """The innermost decoded thing that contains a file offset."""
    best: Optional[Tuple[int, str, Optional[str]]] = None
    for st in structs:
        for field in st["fields"]:
            off, size = field.get("abs_offset"), field.get("size")
            if isinstance(off, int) and isinstance(size, int) and off <= offset < off + size:
                if best is None or size < best[0]:
                    best = (size, f"{st['label']} · {field.get('name')}", st["node"])
    if best is not None:
        return {"label": best[1], "node": best[2]}
    hit: Optional[Tuple[int, str, Optional[str]]] = None
    for sl in slices:
        for iv in sl.get("intervals") or []:
            off, size = iv.get("abs_offset"), iv.get("size")
            if isinstance(off, int) and isinstance(size, int) and off <= offset < off + size:
                if hit is None or size < hit[0]:
                    hit = (size, str(iv.get("label") or iv.get("id")), None)
    if hit is not None:
        return {"label": hit[1], "node": hit[2]}
    return {"label": "outside any decoded structure", "node": None}


def _diff_fields_patch(b_structs: List[Dict[str, Any]], a_structs: List[Dict[str, Any]], slice_pos_before: int,
                       slice_pos_after: Optional[int], touched: _RangeSet, before_data: bytes, after_data: bytes,
                       default_little: bool) -> Tuple[List[Dict[str, Any]], int]:
    """Fields of one slice that a patch changed: every field whose bytes were
    touched, plus fields whose bytes are the same but which now decode differently."""
    after_index: Dict[Tuple[int, int, str], Dict[str, Any]] = {}
    for st in a_structs:
        if st["slice"] != slice_pos_after:
            continue
        for field in st["fields"]:
            after_index.setdefault((field.get("abs_offset"), field.get("size"), field.get("name")), field)
    out: List[Dict[str, Any]] = []
    seen = set()
    total = 0
    for st in b_structs:
        if st["slice"] != slice_pos_before:
            continue
        for field in st["fields"]:
            check_deadline()
            off, size, name = field.get("abs_offset"), field.get("size"), field.get("name")
            if not isinstance(off, int) or not isinstance(size, int):
                continue
            ident = (off, size, name)
            if ident in seen:
                continue
            seen.add(ident)
            twin = after_index.get(ident)
            hit = touched.overlaps(off, size) and before_data[off:off + size] != after_data[off:off + size]
            if not hit and (twin is None or (twin.get("value") == field.get("value")
                                             and twin.get("interpreted") == field.get("interpreted"))):
                continue
            total += 1
            if len(out) >= MAX_FIELD_CHANGES:
                continue
            record: Dict[str, Any] = {
                "struct": st["label"], "struct_kind": st["kind"], "node": st["node"], "name": str(name),
                "abs_offset": off, "size": size, "kind": "bytes" if hit else "meaning", "before": _field_view(field),
            }
            endian = field_endianness(field, st["fields"], before_data, default_little)
            new_int = int.from_bytes(after_data[off:off + size], endian) if (hit and endian and off + size <= len(after_data)) else None
            if twin is not None:
                record["after"] = _field_view(twin)
            else:
                record["after"] = {"raw_hex": _hex_spaced(after_data[off:off + size], 17),
                                   "value": ("0x%x" % new_int) if new_int is not None else "", "interpreted": ""}
                record["undecoded"] = True
            if hit:
                record["after"]["raw_hex"] = _hex_spaced(after_data[off:off + size], 17)
                record["before"]["raw_hex"] = _hex_spaced(before_data[off:off + size], 17)
            flags = field.get("bit_flags") or []
            if flags:
                was = _set_flags(field)
                if twin is not None:
                    now = _set_flags(twin)
                elif new_int is not None:
                    now = {str(f.get("name")): str(f.get("mask")) for f in flags
                           if _flag_mask(f) and (new_int & _flag_mask(f)) == _flag_mask(f)}  # type: ignore[operator]
                else:
                    now = was
                record["flags_set"] = [{"name": n, "mask": m} for n, m in now.items() if n not in was]
                record["flags_cleared"] = [{"name": n, "mask": m} for n, m in was.items() if n not in now]
            if isinstance(field.get("raw_value"), int) and not isinstance(field.get("raw_value"), bool):
                record["before_int"] = field["raw_value"]
                if twin is not None and isinstance(twin.get("raw_value"), int):
                    record["after_int"] = twin["raw_value"]
                elif new_int is not None:
                    record["after_int"] = new_int
            out.append(record)
    return out, total


def _diff_fields_compare(b_structs: List[Dict[str, Any]], a_structs: List[Dict[str, Any]], bi: int, ai: int
                         ) -> Tuple[List[Dict[str, Any]], int]:
    """Fields of the same structure in two different files that decode differently."""
    def index(structs: List[Dict[str, Any]], pos: int) -> Dict[Any, Tuple[Dict[str, Any], Dict[str, Any]]]:
        out: Dict[Any, Tuple[Dict[str, Any], Dict[str, Any]]] = {}
        for st in structs:
            if st["slice"] != pos:
                continue
            seen: Dict[str, int] = {}
            for field in st["fields"]:
                name = str(field.get("name"))
                seen[name] = seen.get(name, -1) + 1
                out.setdefault((st["cmp"], name, seen[name]), (st, field))
        return out

    b_idx, a_idx = index(b_structs, bi), index(a_structs, ai)
    out: List[Dict[str, Any]] = []
    total = 0
    for ident, (st, field) in b_idx.items():
        check_deadline()
        other = a_idx.get(ident)
        if other is None:
            continue
        twin = other[1]
        if twin.get("value") == field.get("value") and twin.get("interpreted") == field.get("interpreted"):
            continue
        total += 1
        if len(out) >= MAX_FIELD_CHANGES:
            continue
        record: Dict[str, Any] = {"struct": other[0]["label"], "struct_kind": st["kind"], "node": other[0]["node"],
                                  "name": str(field.get("name")), "abs_offset": twin.get("abs_offset"), "size": twin.get("size"),
                                  "kind": "value", "before": _field_view(field), "after": _field_view(twin)}
        if field.get("bit_flags") or twin.get("bit_flags"):
            was, now = _set_flags(field), _set_flags(twin)
            record["flags_set"] = [{"name": n, "mask": m} for n, m in now.items() if n not in was]
            record["flags_cleared"] = [{"name": n, "mask": m} for n, m in was.items() if n not in now]
        out.append(record)
    return out, total


def _signature_changes(b: Dict[str, Any], a: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = [dict(change, scope="signature") for change in _prop_changes(b, a, _SIG_PROPS)]
    b_cd, a_cd = b.get("code_directory") or {}, a.get("code_directory") or {}
    out.extend(dict(change, scope="code_directory") for change in _prop_changes(b_cd, a_cd, _CD_PROPS))
    b_cms, a_cms = b.get("cms_signature") or {}, a.get("cms_signature") or {}
    out.extend(dict(change, scope="cms") for change in _prop_changes(b_cms, a_cms, ("present", "is_adhoc", "size")))

    def slots(cd: Dict[str, Any], key: str, id_key: str) -> Dict[Any, Dict[str, Any]]:
        return {s.get(id_key): s for s in cd.get(key) or [] if isinstance(s, dict)}

    for key, id_key, noun in (("special_slots", "slot", "special slot"), ("code_slots_preview", "page_index", "code page")):
        before_slots, after_slots = slots(b_cd, key, id_key), slots(a_cd, key, id_key)
        for ident, slot in before_slots.items():
            other = after_slots.get(ident)
            if other is not None and other.get("verified") != slot.get("verified"):
                name = slot.get("name") or f"{noun} {ident}"
                out.append({"scope": key, "prop": f"{name} hash matches", "before": slot.get("verified"),
                            "after": other.get("verified"), "abs_offset": other.get("file_offset")})
    return out


def _finding_key(item: Dict[str, Any]) -> Tuple[str, str]:
    return (str(item.get("id") or item.get("code") or ""), str(item.get("title") or item.get("message") or ""))


def _list_added_removed(before: List[Dict[str, Any]], after: List[Dict[str, Any]]) -> Dict[str, Any]:
    b_keys = {_finding_key(i): i for i in before or [] if isinstance(i, dict)}
    a_keys = {_finding_key(i): i for i in after or [] if isinstance(i, dict)}
    return {"added": [a_keys[k] for k in a_keys if k not in b_keys][:MAX_NAME_SAMPLES],
            "removed": [b_keys[k] for k in b_keys if k not in a_keys][:MAX_NAME_SAMPLES]}


def _diff_slice(b: Dict[str, Any], a: Dict[str, Any], mode: str) -> Dict[str, Any]:
    """Everything about two slices except their field tables."""
    fmt = _slice_fmt(a)
    out: Dict[str, Any] = {}
    if mode == "patch":
        seg_key = _offset_key(lambda s: _region_off(s, "header_region"), lambda s: s.get("segname"))
        sect_key = _offset_key(lambda s: _region_off(s, "header_region"), lambda s: (s.get("segname"), s.get("sectname")))
        lc_key = _offset_key(lambda c: _first_offset(c.get("fields") or [], c.get("region") if fmt != "PE" else None),
                             lambda c: c.get("cmd_name"))
    else:
        seg_key = _name_occurrence_key(lambda s: s.get("segname"))
        sect_key = _name_occurrence_key(lambda s: (s.get("segname"), s.get("sectname")))
        lc_key = _name_occurrence_key(lambda c: c.get("cmd_name"))

    def sections(sl: Dict[str, Any]) -> List[Dict[str, Any]]:
        found = []
        for s_idx, seg in enumerate(sl.get("segments") or []):
            for c_idx, sect in enumerate(seg.get("sections") or []):
                found.append(dict(sect, _node=f"sect_{s_idx}_{c_idx}"))
        return found

    out["commands"] = _diff_records(
        b.get("load_commands") or [], a.get("load_commands") or [], lc_key,
        lambda c: f"#{c.get('index')} {c.get('cmd_name')}", _LC_PROPS, lambda c, _pos: f"lc_{c.get('index')}")
    out["segments"] = _diff_records(
        b.get("segments") or [], a.get("segments") or [], seg_key,
        lambda s: str(s.get("segname") or ""), _SEG_PROPS, lambda _s, pos: f"seg_{pos}")
    out["sections"] = _diff_records(
        sections(b), sections(a), sect_key,
        lambda s: (f"{s.get('segname')},{s.get('sectname')}" if fmt == "MACHO" else str(s.get("sectname") or "")),
        _SECT_PROPS, lambda s, _pos: s.get("_node"))

    out["overview"] = _scalar_changes(b.get("overview"), a.get("overview"))
    meta = []
    for key in ("elf_metadata", "pe_metadata"):
        meta.extend(dict(change, scope=key) for change in _scalar_changes(b.get(key), a.get(key)))
    out["metadata"] = meta

    b_entry, a_entry = _lands_in(b), _lands_in(a)
    out["entry"] = {"before": b_entry, "after": a_entry} if b_entry != a_entry else None

    b_checks = {c.get("id"): c for c in (b.get("security_posture") or {}).get("checks") or [] if isinstance(c, dict)}
    a_checks = {c.get("id"): c for c in (a.get("security_posture") or {}).get("checks") or [] if isinstance(c, dict)}
    security = []
    for cid in list(b_checks) + [k for k in a_checks if k not in b_checks]:
        bc, ac = b_checks.get(cid), a_checks.get(cid)
        if bc is None or ac is None or any(bc.get(k) != ac.get(k) for k in ("status", "value", "detail")):
            pick = lambda c: None if c is None else {k: c.get(k) for k in ("status", "value", "detail")}  # noqa: E731
            security.append({"id": cid, "title": (ac or bc or {}).get("title"), "before": pick(bc), "after": pick(ac)})
    out["security"] = security

    out["anomalies"] = _list_added_removed(
        ((b.get("semantic_layers") or {}).get("anomalies") or {}).get("findings") or [],
        ((a.get("semantic_layers") or {}).get("anomalies") or {}).get("findings") or [])
    out["warnings"] = _list_added_removed(b.get("warnings") or [], a.get("warnings") or [])
    out["signature"] = _signature_changes(b.get("code_signature_detail") or {}, a.get("code_signature_detail") or {})

    def sym_key(sym: Dict[str, Any]) -> str:
        return str(sym.get("name") or "")

    b_syms, a_syms = b.get("symbols") or [], a.get("symbols") or []
    symbols = _set_diff((sym_key(s) for s in b_syms), (sym_key(s) for s in a_syms))
    # Only names that occur once on each side can be paired without guessing.
    def unique(symbols_list: List[Dict[str, Any]]) -> Dict[str, Optional[Dict[str, Any]]]:
        found: Dict[str, Optional[Dict[str, Any]]] = {}
        for sym in symbols_list:
            name = sym_key(sym)
            found[name] = None if name in found else sym
        return found

    b_by_name, a_by_name = unique(b_syms), unique(a_syms)
    moved = []
    moved_count = 0
    for name, sym in a_by_name.items():
        check_deadline()
        old = b_by_name.get(name)
        if sym is not None and old is not None and (old.get("n_value") != sym.get("n_value") or old.get("type_name") != sym.get("type_name")):
            moved_count += 1
            if len(moved) < MAX_NAME_SAMPLES:
                moved.append({"name": sym_key(sym), "before": f"{old.get('n_value')} {old.get('type_name')}",
                              "after": f"{sym.get('n_value')} {sym.get('type_name')}"})
    symbols["changed"], symbols["changed_count"] = moved, moved_count
    out["symbols"] = symbols
    out["libraries"] = _set_diff((str(d.get("name")) for d in b.get("dylibs") or []),
                                 (str(d.get("name")) for d in a.get("dylibs") or []))
    out["rpaths"] = _set_diff((str(r.get("path")) for r in b.get("rpaths") or []),
                              (str(r.get("path")) for r in a.get("rpaths") or []))
    out["strings"] = _set_diff((str(s.get("value")) for s in b.get("strings") or []),
                               (str(s.get("value")) for s in a.get("strings") or []), 20)
    return out


def _slice_counts(part: Dict[str, Any]) -> Dict[str, int]:
    def rec_total(key: str) -> int:
        return int((part.get(key) or {}).get("total") or 0)

    def ar(key: str) -> int:
        value = part.get(key) or {}
        return len(value.get("added") or []) + len(value.get("removed") or [])

    def names(key: str) -> int:
        value = part.get(key) or {}
        return int(value.get("added_count") or 0) + int(value.get("removed_count") or 0) + int(value.get("changed_count") or 0)

    return {
        "fields": int(part.get("fields_total") or 0),
        "commands": rec_total("commands"), "segments": rec_total("segments"), "sections": rec_total("sections"),
        "overview": len(part.get("overview") or []) + len(part.get("metadata") or []),
        "entry": 1 if part.get("entry") else 0,
        "security": len(part.get("security") or []),
        "anomalies": ar("anomalies"), "warnings": ar("warnings"),
        "signature": len(part.get("signature") or []),
        "symbols": names("symbols"), "libraries": names("libraries") + names("rpaths"), "strings": names("strings"),
    }


def _doc_side(doc: Dict[str, Any], data: bytes) -> Dict[str, Any]:
    info = doc.get("file_info") or {}
    return {"doc_id": doc.get("doc_id"), "filename": info.get("filename"), "size": len(data), "sha256": info.get("sha256"),
            "format": info.get("format_display") or info.get("format"), "parsed": not _is_unparsed(doc),
            "slices": [_slice_label(s) for s in doc.get("slices") or []]}


def _integrity(before: Dict[str, Any], before_data: bytes, after: Dict[str, Any], after_data: bytes,
               pairs: List[Tuple[Optional[int], Optional[int]]], touched: Optional[_RangeSet], mode: str) -> List[Dict[str, Any]]:
    """Checksums and signature hashes recomputed from the bytes of both files."""
    out: List[Dict[str, Any]] = []
    b_pe, a_pe = pe_integrity(before_data), pe_integrity(after_data)
    if (b_pe or a_pe) and b_pe != a_pe:
        out.append({"kind": "pe_checksum", "before": b_pe, "after": a_pe})
    for bi, ai in pairs:
        if bi is None or ai is None:
            continue
        b_slice, a_slice = before["slices"][bi], after["slices"][ai]
        if _slice_fmt(b_slice) != "MACHO":
            continue
        b_params, a_params = _cd_params(b_slice), _cd_params(a_slice)
        if mode == "compare":
            for label, sl, data in (("before", b_slice, before_data), ("after", a_slice, after_data)):
                summary = macho_failing_pages(sl, data, 4096)
                if summary is not None and summary["failing_count"]:
                    out.append({"kind": "macho_pages", "slice": _slice_label(sl), "side": label, "summary": summary, "pages": []})
            continue
        if b_params is None:
            continue
        if a_params is None:
            out.append({"kind": "macho_signature_lost", "slice": _slice_label(b_slice),
                        "abs_offset": b_params["cd_offset"]})
            continue
        page = a_params["page"] or max(1, a_params["codeLimit"])
        cd_touched = touched is not None and touched.overlaps(b_params["cd_offset"], max(1, b_params["cd_size"]))
        layout_changed = any(b_params[k] != a_params[k] for k in ("hashOffset", "nCodeSlots", "codeLimit", "hashSize", "hashType", "pageSize", "cd_offset"))
        if cd_touched or layout_changed:
            wanted: Iterable[int] = range(min(a_params["nCodeSlots"], MAX_CODE_PAGES))
        else:
            hit = set()
            for start, end in (touched.ranges if touched else []):
                lo, hi = start - a_params["base"], end - 1 - a_params["base"]
                if hi < 0 or lo >= a_params["codeLimit"]:
                    continue
                hit.update(range(max(0, lo) // page, min(hi, a_params["codeLimit"] - 1) // page + 1))
            wanted = sorted(hit)[:MAX_CODE_PAGES]
        wanted = list(wanted)
        if not wanted:
            continue
        now = macho_page_status(after_data, a_params, wanted)
        was = macho_page_status(before_data, b_params, wanted)
        pages = []
        for index in wanted:
            n, w = now.get(index), was.get(index)
            if n is None or w is None or n["ok"] == w["ok"]:
                continue
            pages.append({"page": index, "file_offset": n["file_offset"], "size": page, "before_ok": w["ok"], "after_ok": n["ok"],
                          "expected": n["expected"], "actual": n["actual"]})
        if pages:
            broken = sum(1 for p in pages if p["before_ok"] and not p["after_ok"])
            out.append({"kind": "macho_pages", "slice": _slice_label(a_slice), "pages": pages[:64], "page_count": len(pages),
                        "newly_failing": broken, "newly_matching": len(pages) - broken,
                        "code_directory_touched": bool(cd_touched),
                        "flags": list(((a_slice.get("code_signature_detail") or {}).get("code_directory") or {}).get("flags_decoded") or []),
                        "arch": _slice_label(a_slice)})
    return out


def diff_documents(before: Dict[str, Any], before_data: bytes, after: Dict[str, Any], after_data: bytes,
                   mode: str = "patch", patches: Optional[List[Dict[str, Any]]] = None,
                   parse_error: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The structural difference between two Documents.

    mode "patch": `after` is `before` with bytes replaced in place; structures
    are paired by where they sit in the file, the report says which decoded
    fields the changed bytes belong to, and consequences are explained.
    mode "compare": two unrelated files; structures are paired by name.
    """
    ranges = _patch_ranges(patches) if patches is not None else None
    too_large = mode != "patch" and len(before_data) > COMPARE_BYTES_MAX
    runs, comparable = ([], False) if too_large else _changed_runs(before_data, after_data, ranges if mode == "patch" else None)
    touched = _RangeSet(runs)
    b_structs = list(iter_structs(before))
    after_parsed = not _is_unparsed(after)
    a_structs = list(iter_structs(after)) if after_parsed else []
    b_slices, a_slices = before.get("slices") or [], after.get("slices") or []

    byte_ranges = []
    for start, end in runs[:MAX_BYTE_RANGES]:
        where = _where(b_structs, b_slices, start)
        byte_ranges.append({"offset": start, "size": end - start, "before": _hex_spaced(before_data[start:end]),
                            "after": _hex_spaced(after_data[start:end]), "where": where["label"], "node": where["node"]})
    diff: Dict[str, Any] = {
        "mode": mode,
        "before": _doc_side(before, before_data),
        "after": _doc_side(after, after_data),
        "bytes": {"comparable": comparable, "changed": sum(end - start for start, end in runs), "ranges": byte_ranges,
                  "truncated": max(0, len(runs) - MAX_BYTE_RANGES),
                  "why_not": "" if comparable else ("large" if too_large and len(before_data) == len(after_data) else "size")},
        "parse": {"ok": after_parsed, "before_ok": not _is_unparsed(before)},
        "file": [], "slices": [], "integrity": [], "consequences": [],
    }
    if parse_error:
        diff["parse"].update(parse_error)

    b_info, a_info = before.get("file_info") or {}, after.get("file_info") or {}
    for prop in ("file_size", "format_display", "is_fat"):
        if after_parsed and b_info.get(prop) != a_info.get(prop):
            diff["file"].append({"prop": prop, "before": b_info.get(prop), "after": a_info.get(prop)})
    file_warnings = _list_added_removed(b_info.get("warnings") or [], a_info.get("warnings") or []) if after_parsed else {"added": [], "removed": []}
    diff["file_warnings"] = file_warnings

    # The fat header belongs to no slice.
    if mode == "patch":
        fat_fields, fat_total = _diff_fields_patch(b_structs, a_structs, -1, -1, touched, before_data, after_data, False)
    else:
        fat_fields, fat_total = _diff_fields_compare(b_structs, a_structs, -1, -1)
    diff["file_fields"] = fat_fields

    pairs = _match_slices(before, after, mode) if after_parsed else [(i, None) for i in range(len(b_slices))]
    totals: Dict[str, int] = {"fields": fat_total}
    for bi, ai in pairs:
        check_deadline()
        if bi is None:
            diff["slices"].append({"label": _slice_label(a_slices[ai]), "status": "added", "before_index": None, "after_index": ai})  # type: ignore[index]
            continue
        b_slice = b_slices[bi]
        part: Dict[str, Any] = {"label": _slice_label(b_slice), "before_index": bi, "after_index": ai,
                                "format": _slice_fmt(b_slice)}
        if mode == "patch":
            fields, total = _diff_fields_patch(b_structs, a_structs, bi, ai, touched, before_data, after_data, _slice_little(b_slice))
        elif ai is not None:
            fields, total = _diff_fields_compare(b_structs, a_structs, bi, ai)
        else:
            fields, total = [], 0
        part["fields"], part["fields_total"] = fields, total
        if ai is None:
            part["status"] = "unparsed" if not after_parsed else "removed"
        else:
            a_slice = a_slices[ai]
            if mode == "compare" and _slice_label(a_slice) != part["label"]:
                part["label"] = f"{part['label']} / {_slice_label(a_slice)}"
            part.update(_diff_slice(b_slice, a_slice, mode))
            part["status"] = "same"
        part["counts"] = _slice_counts(part)
        if part.get("status") == "same" and any(part["counts"].values()):
            part["status"] = "changed"
        for key, value in part["counts"].items():
            totals[key] = totals.get(key, 0) + value
        diff["slices"].append(part)

    diff["integrity"] = _integrity(before, before_data, after, after_data, pairs, touched if mode == "patch" else None, mode) \
        if after_parsed or mode == "patch" else []
    if not after_parsed and mode == "patch":
        # The headers no longer parse, but checksums and page hashes are properties of the bytes.
        diff["integrity"] = [item for item in diff["integrity"] if item["kind"] == "pe_checksum"]
    totals["integrity"] = len(diff["integrity"])
    totals["bytes"] = diff["bytes"]["changed"]
    totals["file"] = len(diff["file"]) + len(file_warnings["added"]) + len(file_warnings["removed"])
    diff["summary"] = totals
    diff["identical"] = before_data == after_data if comparable else False
    if mode == "patch":
        diff["consequences"] = explain(diff, before, after, after_data)
    return diff


# ============================================================================
# Consequences: what a structural change means to a real loader
# ============================================================================
# Each text states what the named loader does with the changed structure and
# under which conditions. They are selected by what changed, never by which
# experiment (if any) made the change. "basis" says where the statement comes
# from; nothing here has been (or may be) established by running the file.
TEXT: Dict[str, Dict[str, str]] = {
    "elf.stack_exec": {
        "title": "The stack becomes executable",
        "text": "PT_GNU_STACK carries no data; the kernel reads only its p_flags. With PF_X set, Linux maps the initial "
                "stack with execute permission, and glibc gives thread stacks the same protection. Kernels before 5.8 "
                "also set READ_IMPLIES_EXEC in this case (x86, arm64), which made every readable mapping executable; "
                "from 5.8 on only the stack is affected. The kernel sets up the initial stack without consulting a "
                "security module: SELinux checks its execstack permission only when a process later makes its stack "
                "executable with mprotect, as ld.so does for a library that asks for it. This describes a main "
                "program; in a shared library the header is read by the dynamic loader when it loads the library, "
                "not by the kernel.",
        "basis": "Linux fs/binfmt_elf.c, fs/exec.c (setup_arg_pages), arch/x86/include/asm/elf.h, "
                 "security/selinux/hooks.c (selinux_file_mprotect); glibc nptl/allocatestack.c, elf/dl-load.c",
    },
    "elf.stack_nx": {
        "title": "The stack becomes non-executable",
        "text": "With PF_X clear in PT_GNU_STACK the kernel maps the stack without execute permission. Code that relies "
                "on an executable stack (GCC nested-function trampolines, some old JITs) would fault.",
        "basis": "Linux fs/binfmt_elf.c",
    },
    "elf.stack_default": {
        "title": "No PT_GNU_STACK header any more",
        "text": "Without a PT_GNU_STACK header the kernel falls back to a per-architecture default. On x86-64 and arm64 "
                "since Linux 5.8 that default is a non-executable stack; 32-bit x86 and 32-bit ARM processes instead get "
                "READ_IMPLIES_EXEC, which makes every readable mapping executable. glibc keeps a default of its own for "
                "the thread stacks it allocates, and on x86-64 that default is still executable.",
        "basis": "Linux arch/x86/include/asm/elf.h, arch/arm64/include/asm/elf.h, arch/arm/kernel/elf.c; "
                 "glibc sysdeps/x86_64/stackinfo.h, nptl/allocatestack.c",
    },
    "elf.segment_wx": {
        "title": "A segment is writable and executable",
        "text": "The kernel maps each PT_LOAD with the protections in p_flags (PF_R, PF_W, PF_X become PROT_READ, "
                "PROT_WRITE, PROT_EXEC). With W and X both set, the bytes of this segment are writable and executable "
                "at run time, so anything that can write there can change the code that runs. Mainline Linux maps it as "
                "asked; a security module may refuse (SELinux requires execmem for a private mapping that is both "
                "writable and executable).",
        "basis": "Linux fs/binfmt_elf.c (elf_map, make_prot); SELinux hooks.c (file_map_prot_check)",
    },
    "elf.segment_prot": {
        "title": "Segment permissions changed",
        "text": "The kernel maps each PT_LOAD with the protections in p_flags (PF_R, PF_W, PF_X become PROT_READ, "
                "PROT_WRITE, PROT_EXEC). Code in a segment without PF_X faults when executed; a store to a segment "
                "without PF_W faults.",
        "basis": "Linux fs/binfmt_elf.c (elf_map, make_prot)",
    },
    "elf.et_exec": {
        "title": "The main image is no longer position-independent",
        "text": "With e_type = ET_EXEC the kernel maps every PT_LOAD at exactly its p_vaddr: the main image gets no "
                "random load offset. The stack, the mmap area and shared libraries are still randomised. The kernel "
                "does not read DT_FLAGS_1, so a DF_1_PIE flag left behind there changes nothing.",
        "basis": "Linux fs/binfmt_elf.c (load_elf_binary)",
    },
    "elf.et_exec_low": {
        "title": "Its addresses are too low to map",
        "text": "This file was linked to be relocated, so its lowest PT_LOAD address is {addr}. As ET_EXEC it must be "
                "mapped exactly there, below vm.mmap_min_addr (65536 on most distributions; the kernel's built-in "
                "default is 4096). That mapping is refused for a process without CAP_SYS_RAWIO. The old program has "
                "been discarded by then, so execve cannot return an error: the new process is killed with SIGSEGV.",
        "basis": "Linux mm/Kconfig (DEFAULT_MMAP_MIN_ADDR), security/commoncap.c (cap_mmap_addr), fs/binfmt_elf.c, "
                 "fs/exec.c (point of no return)",
    },
    "elf.et_dyn": {
        "title": "The header now claims position independence",
        "text": "With e_type = ET_DYN the kernel chooses a load address and adds the same offset to every PT_LOAD and "
                "to e_entry. That only works if the code was built position-independent and its relocations cover every "
                "absolute address; the header cannot make it so. The audit reads e_type, so it reports PIE regardless.",
        "basis": "Linux fs/binfmt_elf.c (load_elf_binary)",
    },
    "elf.e_type_other": {
        "title": "Not an executable file type",
        "text": "Linux executes only ET_EXEC and ET_DYN files. For any other e_type the ELF loader declines the file "
                "and execve fails with ENOEXEC.",
        "basis": "Linux fs/binfmt_elf.c (load_elf_binary)",
    },
    "elf.relro_gone": {
        "title": "RELRO is no longer applied",
        "text": "RELRO is applied by the dynamic loader, not the kernel: after relocating, ld.so calls "
                "mprotect(PROT_READ) on the range PT_GNU_RELRO describes (glibc: _dl_protect_relro; musl and bionic do "
                "the same; in a statically linked glibc program the C library's start-up code makes the call). Without "
                "the header that call never happens, and the range (.got, .dynamic, .init_array and the like) stays "
                "writable for the life of the process.",
        "basis": "glibc elf/dl-reloc.c, elf/dl-support.c; the kernel ignores PT_GNU_RELRO",
    },
    "elf.load_gone": {
        "title": "A segment is no longer mapped",
        "text": "Only PT_LOAD headers are mapped. Whatever this header described is absent from memory at run time; "
                "code or data that refers to it faults.",
        "basis": "Linux fs/binfmt_elf.c",
    },
    "elf.interp_gone": {
        "title": "No program interpreter",
        "text": "Without PT_INTERP the kernel starts the program at e_entry directly instead of starting ld.so. A "
                "dynamically linked program then runs with none of its relocations applied or libraries loaded.",
        "basis": "Linux fs/binfmt_elf.c",
    },
    "elf.interp_path": {
        "title": "A different program interpreter",
        "text": "The kernel opens the PT_INTERP path and maps that file as the program interpreter. If the path does "
                "not exist, execve fails with ENOENT, reported as 'No such file or directory' against the program "
                "although the missing file is the interpreter.",
        "basis": "Linux fs/binfmt_elf.c (open_exec of elf_interpreter)",
    },
    "elf.entry": {
        "title": "Execution starts somewhere else",
        "text": "Control is transferred to e_entry (plus the load offset for ET_DYN): by the kernel directly for a "
                "static program, or by ld.so once it has finished when there is a PT_INTERP. Nothing checks that the "
                "address holds code.",
        "basis": "Linux fs/binfmt_elf.c; AT_ENTRY in the auxiliary vector",
    },
    "elf.magic": {
        "title": "Not recognised as ELF",
        "text": "The ELF loader compares the first four bytes with 7f 45 4c 46 and declines the file otherwise. The "
                "kernel then offers it to its other handlers (scripts starting with #!, binfmt_misc registrations); "
                "when none accepts, execve fails with ENOEXEC. A shell that receives ENOEXEC usually retries the file "
                "as a shell script.",
        "basis": "Linux fs/binfmt_elf.c, fs/exec.c",
    },
    "elf.ei_data": {
        "title": "Tools and the kernel now disagree about this file",
        "text": "Tools that honour EI_DATA (this viewer, readelf, objdump, file) now read every multi-byte field in the "
                "other byte order, which turns the headers into nonsense. The Linux kernel does not consult EI_DATA on "
                "x86-64 or arm64: its acceptance test there is the magic, e_type and e_machine, read in the CPU's own "
                "byte order, so it would treat the file exactly as before. glibc's ld.so does check e_ident for the "
                "libraries it opens itself, but not for a main program the kernel has already mapped.",
        "basis": "Linux fs/binfmt_elf.c and elf_check_arch (arch/x86, arch/arm64); glibc elf/dl-load.c (open_verify)",
    },
    "elf.e_machine": {
        "title": "A different machine type",
        "text": "The kernel accepts an ELF only if e_machine names an architecture it can run; otherwise the ELF "
                "loader declines it and execve fails with ENOEXEC ('Exec format error'), unless a binfmt_misc handler "
                "such as qemu-user is registered for that machine.",
        "basis": "Linux elf_check_arch",
    },
    "elf.sections": {
        "title": "Section headers changed: tools notice, loaders do not",
        "text": "Section headers are not used to load or run a program: the kernel and ld.so work from program headers "
                "alone. This change affects tools that walk sections (linkers, debuggers, disassemblers, strip, this "
                "viewer), not execution.",
        "basis": "ELF gABI: the section header table is optional in an executable",
    },
    "pe.dynamic_base_off": {
        "title": "The image is no longer randomised",
        "text": "Without DYNAMIC_BASE the Windows loader maps the image at OptionalHeader.ImageBase every time; it "
                "relocates only if that range is already taken. HIGH_ENTROPY_VA has no effect without DYNAMIC_BASE. "
                "The 'Force randomization for images' mitigation (Mandatory ASLR), where enabled, overrides this for "
                "images that still carry relocations.",
        "basis": "PE/COFF specification (DllCharacteristics); Windows Exploit Protection documentation",
    },
    "pe.dynamic_base_on": {
        "title": "The image opts in to ASLR",
        "text": "With DYNAMIC_BASE the loader chooses the image base itself and applies the base relocations. An image "
                "without relocation data (IMAGE_FILE_RELOCS_STRIPPED, or no .reloc) cannot be moved, so the flag has no "
                "effect there.",
        "basis": "PE/COFF specification (DllCharacteristics)",
    },
    "pe.nx_off": {
        "title": "No longer marked DEP-compatible",
        "text": "NX_COMPAT matters only to 32-bit processes: under the default OptIn policy a 32-bit program without it "
                "runs with DEP off unless it opts in at run time. 64-bit processes (x64, ARM64) always run with DEP on "
                "and ignore the flag. {bits}",
        "basis": "Windows DEP documentation; PE/COFF specification",
    },
    "pe.nx_on": {
        "title": "Marked DEP-compatible",
        "text": "With NX_COMPAT a 32-bit process runs with DEP on under the default OptIn policy. 64-bit processes "
                "always run with DEP on and ignore the flag. {bits}",
        "basis": "Windows DEP documentation; PE/COFF specification",
    },
    "pe.cfg_off": {
        "title": "Control Flow Guard is no longer in effect for this image",
        "text": "Without GUARD_CF the loader does not treat the image as Control Flow Guard aware: it ignores the CFG "
                "tables in the load configuration and leaves the image's check pointer at a routine that returns "
                "immediately, so the compiled-in checks still run but always pass. For an EXE this flag is normally "
                "also what switches CFG on for the process, unless a mitigation policy forces it.",
        "basis": "Windows Control Flow Guard documentation; PE/COFF specification (load configuration). The loader "
                 "details and the per-process rule are from published reverse engineering (Trend Micro, Exploring "
                 "Control Flow Guard in Windows 10, 2015), not from Microsoft documentation",
    },
    "pe.high_entropy_off": {
        "title": "Less address-space entropy",
        "text": "HIGH_ENTROPY_VA on an EXE tells 64-bit Windows that the program tolerates addresses above 4 GiB, and "
                "turns on high-entropy randomisation of its bottom-up allocations (heaps, stacks and other mapped "
                "memory). Without it those allocations get the ordinary, smaller randomisation. How far the image base "
                "itself is randomised depends on whether ImageBase is above 4 GiB, not on this flag. The flag has no "
                "effect on 32-bit images or without DYNAMIC_BASE.",
        "basis": "PE/COFF specification (DllCharacteristics); Microsoft Security Response Center, Software defense: "
                 "mitigating common exploitation techniques (2013)",
    },
    "pe.force_integrity_on": {
        "title": "The loader will insist on a valid signature",
        "text": "FORCE_INTEGRITY makes the loader verify the image's signature before mapping it; an image whose "
                "signature does not verify is not loaded.",
        "basis": "PE/COFF specification (DllCharacteristics); /INTEGRITYCHECK",
    },
    "pe.section_wx": {
        "title": "A section is writable and executable",
        "text": "Windows maps each section with the protections its Characteristics request (MEM_READ, MEM_WRITE, "
                "MEM_EXECUTE). A section that is both writable and executable is mapped that way; the loader does not "
                "object.",
        "basis": "PE/COFF specification (section flags)",
    },
    "pe.section_prot": {
        "title": "Section permissions changed",
        "text": "Windows maps each section with the protections its Characteristics request (MEM_READ, MEM_WRITE, "
                "MEM_EXECUTE). Executing from a section without MEM_EXECUTE raises an access violation when DEP is on.",
        "basis": "PE/COFF specification (section flags)",
    },
    "pe.entry": {
        "title": "Execution starts somewhere else",
        "text": "For an EXE the first thread starts at the address the image was loaded at plus AddressOfEntryPoint, "
                "after any TLS callbacks; for a DLL it is the routine the loader calls on process and thread attach "
                "and detach (the C runtime's wrapper around DllMain). The loader does not check what is there.",
        "basis": "PE/COFF specification (AddressOfEntryPoint)",
    },
    "pe.magic": {
        "title": "Not recognised as a PE image",
        "text": "Windows requires 'MZ' at offset 0 and 'PE\\0\\0' at the offset in e_lfanew. Without them CreateProcess "
                "fails with ERROR_BAD_EXE_FORMAT ('is not a valid Win32 application'). An MZ file with no PE signature "
                "is a DOS program, which 64-bit Windows cannot run.",
        "basis": "PE/COFF specification; CreateProcess documentation",
    },
    "pe.checksum": {
        "title": "The header checksum is stale",
        "text": "OptionalHeader.CheckSum ({stored}) no longer equals the checksum of the file ({computed}). Windows "
                "validates this value for kernel-mode drivers, DLLs loaded at boot and DLLs loaded into critical "
                "system processes; ordinary programs and DLLs load regardless.",
        "basis": "PE/COFF specification (CheckSum); computed here from the bytes",
    },
    "pe.checksum_about": {
        "title": "The header checksum",
        "text": "Any change to the file changes the checksum computed over it, so a CheckSum that matched before no "
                "longer does; the result shows the stored and the computed value side by side. Windows validates this "
                "value for kernel-mode drivers, DLLs loaded at boot and DLLs loaded into critical system processes; "
                "ordinary programs and DLLs load regardless.",
        "basis": "PE/COFF specification (CheckSum)",
    },
    "pe.checksum_never": {
        "title": "The header checksum does not match, and did not before",
        "text": "OptionalHeader.CheckSum ({stored}) did not equal the checksum of the file before this change ({was}) "
                "and does not now ({computed}); linkers leave the field at zero or stale unless asked to set it. "
                "Windows validates this value for kernel-mode drivers, DLLs loaded at boot and DLLs loaded into "
                "critical system processes; ordinary programs and DLLs load regardless.",
        "basis": "PE/COFF specification (CheckSum); computed here from the bytes",
    },
    "pe.checksum_ok": {
        "title": "The header checksum matches the file",
        "text": "OptionalHeader.CheckSum ({stored}) now equals the checksum computed over the file.",
        "basis": "PE/COFF specification (CheckSum); computed here from the bytes",
    },
    "macho.standalone": {
        "title": "Not an image that macOS loads as a process",
        "text": "This is an {type} image. It is loaded by firmware, a boot loader or the kernel's own linker rather "
                "than by execve and dyld, so what this change does at run time depends on that loader. The statements "
                "BinaryStudio makes about how macOS loads a program do not apply to it.",
        "basis": "Mach-O file types in mach-o/loader.h",
    },
    "macho.magic_slice": {
        "title": "One slice of the universal file is no longer a Mach-O",
        "text": "The fat header still lists this slice, but its contents no longer start with a Mach-O magic. The "
                "kernel chooses one slice for the machine it runs on: where it would choose this one the exec fails, "
                "and a machine that prefers another slice is unaffected.",
        "basis": "XNU bsd/kern/kern_exec.c (exec_fat_imgact, exec_mach_imgact)",
    },
    "pe.authenticode": {
        "title": "The Authenticode hash changed",
        "text": "The Authenticode image hash covers the whole file except the CheckSum field, the Certificate Table "
                "directory entry and the certificate table itself. It has changed, so a signature made over the old "
                "hash no longer verifies (signtool verify, the Digital Signatures property page, SmartScreen, WDAC or "
                "AppLocker publisher rules). Windows does not check Authenticode when it loads an ordinary user-mode "
                "program unless such a policy is in force; kernel drivers are always checked on 64-bit Windows. {embedded}",
        "basis": "Windows Authenticode PE signature format; hash computed here from the bytes",
    },
    "pe.section_bounds": {
        "title": "The last section's raw data runs past the end of the file",
        "text": "Windows validates the section table when it creates the image mapping, and the file must be at least "
                "as large as the table says. In the kernel sources Microsoft has published (NT 5.2) the test is on the "
                "end of the last section's raw data: if that lies past the end of the file, the image is refused with "
                "STATUS_INVALID_IMAGE_FORMAT.",
        "basis": "Windows Research Kernel (NT 5.2), base/ntos/mm/creasect.c (MiCreateImageFileMap); not tested on "
                 "current Windows",
    },
    "pe.section_bounds_other": {
        "title": "A section's raw data runs past the end of the file",
        "text": "{name} now claims raw data up to file offset {end}, past the end of the file ({size} bytes), so part "
                "of the section has no bytes behind it. In the kernel sources Microsoft has published (NT 5.2) the "
                "size test that refuses an image looks only at the last section of the table, and this is not the "
                "last one. What Windows does with such a file has not been established here.",
        "basis": "Windows Research Kernel (NT 5.2), base/ntos/mm/creasect.c (MiCreateImageFileMap): the check is on "
                 "the last section only. Unverified for this case",
    },
    "pe.image_base": {
        "title": "ImageBase is not a multiple of 64 KiB",
        "text": "The PE specification requires ImageBase to be a multiple of 64 KiB.",
        "basis": "PE/COFF specification (ImageBase)",
    },
    "macho.pie_off": {
        "title": "The main executable is no longer slid",
        "text": "For a main executable the kernel applies a random slide only when MH_PIE is set. Without it an x86_64 "
                "program is loaded at its linked address every time. XNU requires PIE for dynamically linked arm64 "
                "main executables and fails the load of one without the flag: posix_spawn returns EBADEXEC ('Bad "
                "executable'), and a process that called execve is killed, because the kernel can no longer return to "
                "the old program.",
        "basis": "XNU bsd/kern/mach_loader.c (parse_machfile, pie_required), bsd/kern/kern_exec.c (exec_mach_imgact); "
                 "arm64 result observed on macOS 27 with a re-signed test program",
    },
    "macho.pie_on": {
        "title": "The header now claims position independence",
        "text": "With MH_PIE the kernel slides the main executable by a random page-aligned amount and dyld rebases its "
                "pointers. That only works if the code was built position-independent.",
        "basis": "XNU bsd/kern/mach_loader.c",
    },
    "macho.segment_wx": {
        "title": "A segment is writable and executable",
        "text": "XNU maps a segment with initprot, capped by maxprot. Where code-signing enforcement applies to the "
                "process (always on iOS; on macOS when the signature asks for it, as the hardened runtime does), the "
                "VM refuses a mapping that is writable and executable at once and the launch fails. Otherwise macOS "
                "maps the segment as requested; on an Apple-silicon Mac its code still runs, but a store to it faults.",
        "basis": "XNU osfmk/vm/vm_map.c (vm_map_enter), bsd/kern/mach_loader.c (map_segment). Apple-silicon results "
                 "observed on macOS 27 with ad-hoc signed test programs; Intel behaviour is from the source only",
    },
    "macho.dyld_segment_perms": {
        "title": "dyld refuses this segment's permissions",
        "text": "dyld validates the protection of a few segments by name before it runs anything, whatever the kernel "
                "allowed: {segname} must be exactly {required}, and it is now {now}. The rule applies to images {scope}; "
                "dyld then stops with '{message}' and the process is terminated. dyld makes no such check for "
                "segments with other names.",
        "basis": "dyld mach_o/UnsafeHeader.cpp (validSegment) and Policy.cpp (enforceTextSegmentPermissions, "
                 "enforceReadOnlyLinkedit, enforceDataSegmentPermissions); observed on macOS 27 with ad-hoc signed "
                 "test programs",
    },
    "macho.segment_prot": {
        "title": "Segment permissions changed",
        "text": "XNU maps a segment with initprot and never lets its protection exceed maxprot. Code in a segment "
                "without execute permission faults when reached; a store to one without write permission faults.",
        "basis": "XNU bsd/kern/mach_loader.c (load_segment)",
    },
    "macho.entry_main": {
        "title": "Execution starts somewhere else",
        "text": "dyld calls the address entryoff bytes from the start of the image as main(). Nothing checks that it "
                "is the start of a function.",
        "basis": "LC_MAIN (entry_point_command) in mach-o/loader.h; dyld",
    },
    "macho.entry_thread": {
        "title": "Execution starts somewhere else",
        "text": "LC_UNIXTHREAD supplies the whole initial register state; execution starts at its program counter.",
        "basis": "LC_UNIXTHREAD in mach-o/loader.h; XNU load_unixthread",
    },
    "macho.magic": {
        "title": "Not recognised as Mach-O",
        "text": "The kernel's Mach-O activator accepts only feedface / feedfacf in the machine's own byte order (it "
                "recognises the byte-swapped forms and refuses them with EBADARCH); universal files are recognised by "
                "cafebabe. With any other value no image activator accepts the file and execve fails with ENOEXEC. A "
                "shell that receives ENOEXEC usually retries the file as a shell script.",
        "basis": "XNU bsd/kern/kern_exec.c (exec_mach_imgact, exec_fat_imgact)",
    },
    "macho.filetype": {
        "title": "Not a main executable",
        "text": "execve accepts only MH_EXECUTE as a main program. For any other file type the kernel's Mach-O "
                "activator declines the file and execve fails with ENOEXEC ('Exec format error').",
        "basis": "XNU bsd/kern/kern_exec.c (exec_mach_imgact); observed on macOS 27",
    },
    "macho.cputype": {
        "title": "A different CPU type",
        "text": "The kernel compares cputype and cpusubtype with the machine it runs on. A slice it cannot run is "
                "refused with EBADARCH ('Bad CPU type in executable').",
        "basis": "XNU bsd/kern/kern_exec.c, mach_loader.c (grade_binary)",
    },
    "macho.signature_pages": {
        "title": "Signed code pages no longer match their hashes",
        "text": "The CodeDirectory stores one hash per page of the signed range, and the kernel checks a page against "
                "its hash when the page is first brought into memory. {n} no longer {match}. On Apple-silicon Macs and "
                "on iOS every process must have a valid signature and is killed at that point (SIGKILL, 'Code Signature "
                "Invalid'). On Intel Macs the process only loses its valid status unless its code-signing flags say "
                "otherwise: CS_KILL has it killed and CS_HARD has the page refused, and the hardened runtime sets "
                "both. A page that holds the load commands is checked earlier, during exec. "
                "Re-signing (codesign -f -s -) recomputes the hashes.",
        "basis": "XNU bsd/kern/ubc_subr.c (cs_validate_range), bsd/kern/kern_cs.c (cs_invalid_page), "
                 "bsd/kern/mach_loader.c, osfmk/vm/vm_fault.c; Apple-silicon behaviour observed on macOS 27; hashes "
                 "recomputed here from the bytes",
    },
    "macho.signature_pages_fixed": {
        "title": "Code pages match their hashes again",
        "text": "{n} that did not match the CodeDirectory before now {match}.",
        "basis": "Hashes recomputed here from the bytes",
    },
    "macho.cdhash": {
        "title": "The CodeDirectory itself changed",
        "text": "The CodeDirectory was edited, so its hash (the cdhash) is different. The cdhash is what a CMS "
                "signature signs and what trust caches and launch constraints refer to. A signature with a CMS blob no "
                "longer verifies; an ad-hoc signature has no CMS, so the new cdhash is simply a different identity.",
        "basis": "Apple code-signing format (cs_blobs.h)",
    },
    "macho.segment_bounds": {
        "title": "A segment's file range runs past the end of the file",
        "text": "XNU rejects a segment whose file range (fileoff + filesize) extends past the end of the Mach-O: the "
                "load fails with LOAD_BADMACHO. posix_spawn reports that as EBADMACHO ('Malformed Mach-o file'); a "
                "process that called execve is killed instead, because the kernel can no longer return to the old "
                "program.",
        "basis": "XNU bsd/kern/mach_loader.c (load_segment), bsd/kern/kern_exec.c (exec_mach_imgact); observed on "
                 "macOS 27",
    },
    "entry.not_executable": {
        "title": "The entry point is not in executable memory",
        "text": "The entry point {vm} now falls in {where}, which is mapped {prot}. The first instruction fetch there "
                "faults ({fault}).",
        "basis": "Derived from the segment table of the patched file",
    },
    "entry.unmapped": {
        "title": "The entry point is not mapped",
        "text": "The entry point {vm} is not inside any segment the loader maps. The process would fault on its first "
                "instruction ({fault}).",
        "basis": "Derived from the segment table of the patched file",
    },
    "entry.moved": {
        "title": "Where it lands",
        "text": "The entry point {vm} falls in {where} ({prot}). Whatever bytes are there are executed as "
                "instructions; the disassembly view shows them.",
        "basis": "Derived from the segment table of the patched file",
    },
    "parse.failed": {
        "title": "This viewer can no longer parse the file",
        "text": "{message} Real loaders have their own tolerances, which can be stricter or looser than this parser's.",
        "basis": "This tool's parser",
    },
}

_FAULT = {"ELF": "SIGSEGV", "PE": "access violation 0xC0000005", "MACHO": "EXC_BAD_ACCESS"}


def _note(key: str, refs: Optional[List[Dict[str, Any]]] = None, **fmt: Any) -> Dict[str, Any]:
    entry = TEXT[key]
    text = entry["text"].format(**fmt) if fmt else entry["text"]
    return {"id": key, "title": entry["title"], "text": " ".join(text.split()), "basis": entry["basis"], "refs": refs or []}


def _ref(field: Dict[str, Any]) -> Dict[str, Any]:
    return {"abs_offset": field.get("abs_offset"), "size": field.get("size"), "label": f"{field.get('struct')} · {field.get('name')}",
            "node": field.get("node")}


def _flag_names(items: Optional[List[Dict[str, Any]]]) -> List[str]:
    return [str(i.get("name")) for i in items or []]


def _field_map(doc: Dict[str, Any]) -> Dict[Tuple[Any, Any, Any], Tuple[Dict[str, Any], Dict[str, Any]]]:
    """(abs_offset, size, name) -> (structure, field), first in document order, like `find_field`."""
    out: Dict[Tuple[Any, Any, Any], Tuple[Dict[str, Any], Dict[str, Any]]] = {}
    for st in iter_structs(doc):
        for field in st["fields"]:
            out.setdefault((field.get("abs_offset"), field.get("size"), field.get("name")), (st, field))
    return out


_MACHO_PROCESS_TYPES = ("MH_EXECUTE", "MH_DYLIB", "MH_BUNDLE", "MH_DYLINKER")

# Segment protections dyld insists on, by segment name: (required initprot, as text, which
# images the rule applies to, dyld's message). From dyld's validSegment(); each rule is
# switched on by the SDK the image was built with (its "enforcement epoch").
_DYLD_SEGMENT_PERMS: Dict[str, Tuple[int, str, str, str]] = {
    "__TEXT": (5, "r-x", "built with a 2019 or later SDK (macOS 10.15, iOS 13)", "__TEXT segment permissions is not 'r-x'"),
    "__LINKEDIT": (1, "r--", "built with a 2015 or later SDK (main executables: a 2025 or later SDK)", "__LINKEDIT segment permissions is not 'r--'"),
    "__DATA": (3, "rw-", "built with a 2025 or later SDK (macOS 26, iOS 26)", "__DATA segment permissions is not 'rw-'"),
    "__DATA_CONST": (3, "rw-", "built with a 2025 or later SDK (macOS 26, iOS 26)", "__DATA_CONST segment permissions is not 'rw-'"),
}


def _macho_standalone(slice_obj: Dict[str, Any]) -> bool:
    """True for Mach-O images that execve and dyld do not load (firmware, kexts, objects)."""
    name = str((slice_obj.get("header") or {}).get("filetype_name") or "")
    return bool(name) and name not in _MACHO_PROCESS_TYPES


def explain(diff: Dict[str, Any], before: Dict[str, Any], after: Dict[str, Any], after_data: bytes) -> List[Dict[str, Any]]:
    """Plain-language consequences of a patch diff."""
    notes: List[Dict[str, Any]] = []
    seen = set()

    def add(key: str, refs: Optional[List[Dict[str, Any]]] = None, **fmt: Any) -> None:
        if key in seen:
            for note in notes:
                if note["id"] == key and refs:
                    note["refs"] = (note["refs"] + refs)[:8]
            return
        seen.add(key)
        notes.append(_note(key, refs, **fmt))

    parse = diff.get("parse") or {}
    if not parse.get("ok"):
        add("parse.failed", message=str(parse.get("error") or "The patched file could not be parsed."))
    before_fields = _field_map(before)
    after_fields = _field_map(after) if parse.get("ok") else {}

    def twin_of(field: Dict[str, Any]) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        return after_fields.get((field.get("abs_offset"), field.get("size"), field.get("name")))

    for part in diff.get("slices") or []:
        fmt = part.get("format")
        bi, ai = part.get("before_index"), part.get("after_index")
        if bi is None:
            continue
        b_slice = before["slices"][bi]
        a_slice = after["slices"][ai] if (ai is not None and parse.get("ok")) else None
        is_64 = bool((b_slice.get("header") or {}).get("is_64bit", True))
        for field in part.get("fields") or []:
            if field.get("kind") != "bytes":
                continue
            name = field.get("name")
            kind = field.get("struct_kind")
            ref = [_ref(field)]
            gained, lost = _flag_names(field.get("flags_set")), _flag_names(field.get("flags_cleared"))
            now_flags = None
            if a_slice is not None and not field.get("undecoded"):
                twin = twin_of(field)
                if twin is not None:
                    now_flags = set(_set_flags(twin[1]))
            owner = before_fields.get((field.get("abs_offset"), field.get("size"), name))
            rec = owner[0]["rec"] if owner is not None else {}
            b_int, a_int = field.get("before_int"), field.get("after_int")

            if fmt == "ELF":
                cmd = str(rec.get("cmd_name") or "") if kind in ("lc", "seg") else ""
                if kind in ("lc", "seg") and name == "p_flags":
                    if cmd == "PT_GNU_STACK":
                        if "PF_X" in gained:
                            add("elf.stack_exec", ref)
                        elif "PF_X" in lost:
                            add("elf.stack_nx", ref)
                    elif cmd == "PT_LOAD":
                        both_now = now_flags is not None and {"PF_W", "PF_X"} <= now_flags
                        if both_now and (("PF_W" in gained) or ("PF_X" in gained)):
                            add("elf.segment_wx", ref)
                        elif gained or lost:
                            add("elf.segment_prot", ref)
                elif kind in ("lc", "seg") and name == "p_type" and b_int != a_int:
                    if cmd == "PT_GNU_RELRO":
                        add("elf.relro_gone", ref)
                    elif cmd == "PT_GNU_STACK":
                        add("elf.stack_default", ref)
                    elif cmd == "PT_LOAD":
                        add("elf.load_gone", ref)
                    elif cmd == "PT_INTERP":
                        add("elf.interp_gone", ref)
                elif kind == "hdr" and name == "e_type" and b_int != a_int:
                    if a_int == 2:
                        add("elf.et_exec", ref)
                        loads = [s.get("vmaddr_int") for s in b_slice.get("segments") or [] if isinstance(s.get("vmaddr_int"), int)]
                        if loads and min(loads) < 0x10000:
                            add("elf.et_exec_low", ref, addr="0x%x" % min(loads))
                    elif a_int == 3:
                        add("elf.et_dyn", ref)
                    else:
                        add("elf.e_type_other", ref)
                elif kind == "hdr" and name == "e_entry":
                    add("elf.entry", ref)
                elif kind == "hdr" and name == "e_ident[EI_MAG]":
                    add("elf.magic", ref)
                elif kind == "hdr" and name == "e_ident[EI_DATA]":
                    add("elf.ei_data", ref)
                elif kind == "hdr" and name == "e_machine":
                    add("elf.e_machine", ref)
                elif kind == "sect" or (kind == "hdr" and name in ("e_shoff", "e_shnum", "e_shentsize", "e_shstrndx")):
                    add("elf.sections", ref)
            elif fmt == "PE":
                if name == "OptionalHeader.DllCharacteristics":
                    bits = ("This is a 64-bit image, so nothing changes for it." if is_64
                            else "This is a 32-bit image, so the flag decides its default DEP state.")
                    for flag, key in (("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", "pe.dynamic_base"),
                                      ("IMAGE_DLLCHARACTERISTICS_NX_COMPAT", "pe.nx")):
                        if flag in lost:
                            add(key + "_off", ref, **({"bits": bits} if key == "pe.nx" else {}))
                        elif flag in gained:
                            add(key + "_on", ref, **({"bits": bits} if key == "pe.nx" else {}))
                    if "IMAGE_DLLCHARACTERISTICS_GUARD_CF" in lost:
                        add("pe.cfg_off", ref)
                    if "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA" in lost:
                        add("pe.high_entropy_off", ref)
                    if "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY" in gained:
                        add("pe.force_integrity_on", ref)
                elif name == "Characteristics" and kind in ("seg", "sect"):
                    wx = {"IMAGE_SCN_MEM_WRITE", "IMAGE_SCN_MEM_EXECUTE"}
                    if now_flags is not None and wx <= now_flags and (wx & set(gained)):
                        add("pe.section_wx", ref)
                    elif (wx | {"IMAGE_SCN_MEM_READ"}) & (set(gained) | set(lost)):
                        add("pe.section_prot", ref)
                elif name == "OptionalHeader.AddressOfEntryPoint":
                    add("pe.entry", ref)
                elif name in ("e_magic", "Signature", "OptionalHeader.Magic", "e_lfanew"):
                    add("pe.magic", ref)
                elif name == "OptionalHeader.ImageBase" and isinstance(a_int, int) and a_int % 0x10000:
                    add("pe.image_base", ref)
                elif name in ("SizeOfRawData", "PointerToRawData") and a_slice is not None:
                    twin = twin_of(field)
                    if twin is not None:
                        size_f, ptr_f = _named_field(twin[0]["fields"], "SizeOfRawData"), _named_field(twin[0]["fields"], "PointerToRawData")
                        if size_f and ptr_f and isinstance(size_f.get("raw_value"), int) and isinstance(ptr_f.get("raw_value"), int) \
                                and size_f["raw_value"] and ptr_f["raw_value"] + size_f["raw_value"] > len(after_data):
                            # The published kernel check is on the last section of the table only.
                            # (Compared by position in the file: a document that arrived as JSON has
                            # equal field records for a section and its pseudo-segment, not shared ones.)
                            headers = [sect for seg in a_slice.get("segments") or [] for sect in seg.get("sections") or []]
                            last_size = _named_field(headers[-1].get("fields") or [], "SizeOfRawData") if headers else None
                            if last_size is not None and last_size.get("abs_offset") == size_f.get("abs_offset"):
                                add("pe.section_bounds", ref)
                            else:
                                add("pe.section_bounds_other", ref, name=_clean_text(twin[0].get("label") or "A section"),
                                    end="0x%x" % (ptr_f["raw_value"] + size_f["raw_value"]), size=f"{len(after_data):,}")
            elif _macho_standalone(b_slice):
                add("macho.standalone", ref, type=str((b_slice.get("header") or {}).get("filetype_name") or "non-executable"))
                if kind == "lc" and name in ("pc", "rip", "eip") and "THREAD" in str(rec.get("cmd_name") or ""):
                    add("macho.entry_thread", ref)
            else:  # Mach-O that execve and dyld load
                if kind == "hdr" and name == "flags":
                    if "MH_PIE" in lost:
                        add("macho.pie_off", ref)
                    elif "MH_PIE" in gained:
                        add("macho.pie_on", ref)
                elif name == "magic" and kind in ("hdr", "fat"):
                    add("macho.magic_slice" if (before.get("file_info") or {}).get("is_fat") else "macho.magic", ref)
                elif kind == "hdr" and name == "filetype" and b_int != a_int:
                    add("macho.filetype", ref)
                elif kind == "hdr" and name in ("cputype", "cpusubtype"):
                    add("macho.cputype", ref)
                elif kind in ("lc", "seg") and name in ("initprot", "maxprot"):
                    wx = {"VM_PROT_WRITE", "VM_PROT_EXECUTE"}
                    if now_flags is not None and wx <= now_flags and (wx & set(gained)) and name == "initprot":
                        add("macho.segment_wx", ref)
                    elif gained or lost:
                        add("macho.segment_prot", ref)
                    # dyld's own permission rules are per segment NAME and about initprot only.
                    seg_name = str(rec.get("segname") or ((_named_field(owner[0]["fields"], "segname") or {}).get("raw_value")
                                                          if owner is not None else "") or "")
                    rule = _DYLD_SEGMENT_PERMS.get(seg_name)
                    if rule is not None and name == "initprot" and isinstance(a_int, int) and a_int != rule[0] and b_int == rule[0] \
                            and (b_slice.get("header") or {}).get("filetype_name") != "MH_OBJECT":
                        add("macho.dyld_segment_perms", ref, segname=seg_name, required=rule[1],
                            now="".join(c if a_int & bit else "-" for c, bit in (("r", 1), ("w", 2), ("x", 4))),
                            scope=rule[2], message=rule[3])
                elif kind in ("lc", "seg") and name in ("fileoff", "filesize") and a_slice is not None:
                    twin = twin_of(field)
                    if twin is not None:
                        off_f, size_f = _named_field(twin[0]["fields"], "fileoff"), _named_field(twin[0]["fields"], "filesize")
                        if off_f and size_f and isinstance(off_f.get("raw_value"), int) and isinstance(size_f.get("raw_value"), int) \
                                and size_f["raw_value"] and off_f["raw_value"] + size_f["raw_value"] > int(a_slice.get("slice_size") or 0):
                            add("macho.segment_bounds", ref)
                elif kind == "lc" and name == "entryoff":
                    add("macho.entry_main", ref)
                elif kind == "lc" and name in ("pc", "rip", "eip") and "THREAD" in str(rec.get("cmd_name") or ""):
                    add("macho.entry_thread", ref)

        # A fat header's magic belongs to no slice.
        entry = part.get("entry")
        if entry and entry.get("after") and a_slice is not None:
            land = entry["after"]
            was = entry.get("before") or {}
            fault = _FAULT.get(str(fmt), "a fault")
            where = f"{land.get('segment')}" + (f", section {land.get('section')}" if land.get("section") else "")
            ref = [{"abs_offset": land.get("abs_offset"), "size": 16, "label": "entry point", "node": "disassembly"}] \
                if isinstance(land.get("abs_offset"), int) and land.get("abs_offset") else []
            if fmt == "MACHO" and _macho_standalone(b_slice):
                if land.get("mapped") and land.get("vmaddr") != was.get("vmaddr"):
                    add("entry.moved", ref, vm=land.get("vmaddr"), where=where, prot=land.get("prot"))
            elif not land.get("mapped"):
                add("entry.unmapped", ref, vm=land.get("vmaddr"), fault=fault)
            elif not land.get("executable"):
                add("entry.not_executable", ref, vm=land.get("vmaddr"), where=where, prot=land.get("prot"), fault=fault)
            elif land.get("vmaddr") != was.get("vmaddr"):
                add("entry.moved", ref, vm=land.get("vmaddr"), where=where, prot=land.get("prot"))
        for change in part.get("metadata") or []:
            if change.get("scope") == "elf_metadata" and change.get("prop") == "interpreter" and change.get("after"):
                add("elf.interp_path")

    for field in diff.get("file_fields") or []:
        if field.get("kind") == "bytes" and field.get("name") == "magic":
            add("macho.magic", [_ref(field)])

    for item in diff.get("integrity") or []:
        if item["kind"] == "pe_checksum":
            b, a = item.get("before") or {}, item.get("after") or {}
            cks_ref = [{"abs_offset": a.get("checksum_offset"), "size": 4, "label": "OptionalHeader.CheckSum", "node": "mach_header"}]
            if a and a.get("checksum_ok") is False and b.get("checksum_ok"):
                add("pe.checksum", cks_ref, stored=a.get("checksum_stored"), computed=a.get("checksum_computed"))
            elif a and a.get("checksum_ok") is False and b:
                add("pe.checksum_never", cks_ref, stored=a.get("checksum_stored"), computed=a.get("checksum_computed"),
                    was=b.get("checksum_computed"))
            elif a and a.get("checksum_ok") and b and not b.get("checksum_ok"):
                add("pe.checksum_ok", cks_ref, stored=a.get("checksum_stored"))
            if a.get("signed") and b.get("signed") and a.get("image_hash_sha256") != b.get("image_hash_sha256"):
                if b.get("embedded_hash_matches") and not a.get("embedded_hash_matches"):
                    embedded = "The digest stored in this file's signature matched the image before the change and does not match it now."
                elif b.get("embedded_hash_matches"):
                    embedded = ""
                else:
                    embedded = ("The signature blob in this file does not contain the image hash of the unpatched file either, "
                                "so it was not a verifiable signature to begin with.")
                add("pe.authenticode", [{"abs_offset": a.get("cert_offset"), "size": a.get("cert_size"), "label": "Certificate table", "node": "code_signature"}],
                    embedded=embedded)
        elif item["kind"] == "macho_pages":
            refs = [{"abs_offset": p["file_offset"], "size": p["size"], "label": f"code page {p['page']} ({item.get('slice')})", "node": "code_signature"}
                    for p in item.get("pages") or [] if not p["after_ok"]][:6]
            if item.get("newly_failing"):
                n = item["newly_failing"]
                add("macho.signature_pages", refs, n=f"{n} page of the {item.get('slice')} slice" if n == 1 else f"{n} pages of the {item.get('slice')} slice",
                    match="matches" if n == 1 else "match")
            if item.get("newly_matching"):
                n = item["newly_matching"]
                add("macho.signature_pages_fixed", None, n=f"{n} page" if n == 1 else f"{n} pages", match="matches" if n == 1 else "match")
            if item.get("code_directory_touched"):
                add("macho.cdhash")
    # The specific statement about W+X replaces the general one about permissions.
    for specific, general in (("elf.segment_wx", "elf.segment_prot"), ("pe.section_wx", "pe.section_prot"),
                              ("macho.segment_wx", "macho.segment_prot")):
        if specific in seen:
            notes = [note for note in notes if note["id"] != general]
    return notes


# ============================================================================
# Derived documents, including ones that no longer parse
# ============================================================================
def unparsed_document(parent: Dict[str, Any], data: bytes, filename: str, message: str) -> Dict[str, Any]:
    """A Document for bytes the parser rejects: one empty slice, so the hex view,
    byte decoder and navigation keep working, plus the reason it did not parse."""
    info = parent.get("file_info") or {}
    fmt = str(info.get("format") or "MACHO").upper()
    first = (parent.get("slices") or [{}])[0]
    is_64 = bool((first.get("header") or {}).get("is_64bit", True))
    warning = {"code": "parse_failed", "message": message}
    head = min(len(data), 64)
    slice_obj: Dict[str, Any] = {
        "slice_index": 0, "format": fmt, "arch_name": "unparsed", "slice_base_offset": 0, "slice_size": len(data),
        "format_display": "Unparsed", "is_64": is_64, "unparsed": True,
        "overview": {"format": fmt, "filetype_name": "Unparsed", "filetype_desc": message, "arch_display": "unknown",
                     "endianness": "", "is_64bit": is_64, "ncmds": 0, "sizeofcmds": 0, "segments_count": 0,
                     "sections_count": 0, "symbols_count": 0, "strings_count": 0, "dylibs_count": 0},
        "header": {"magic": "0x" + data[:4].hex(), "magic_name": "not recognised", "is_64bit": is_64, "little_endian": True,
                   "ncmds": 0, "sizeofcmds": 0, "flags": 0, "flags_hex": "", "flags_decoded": [],
                   "region": {"abs_offset": 0, "slice_offset": 0, "size": head, "vmaddr": None, "vmsize": None}, "fields": []},
        "load_commands": [], "segments": [], "memory_map": [], "dylibs": [], "rpaths": [], "entry_point": {},
        "dyld_info": {"has_dyld_info": False, "has_chained_fixups": False, "has_exports_trie": False,
                      "chained_fixups": None, "exports": [], "rebases": [], "binds": []},
        "symbols": [], "dysymtab": {"present": False, "indirect_symbols": [], "fields": []}, "function_starts": [],
        "strings": [], "objc_metadata": {"present": False, "classes": [], "selectors": [], "protocols": []},
        "fileset_entries": [], "code_signature_detail": {"present": False, "fields": [], "blobs": []},
        # One entry, so that the audit view says why it is empty rather than reporting a clean bill.
        "security_posture": {"checks": [{"id": "unparsed", "title": "File could not be parsed", "status": "WARN",
                                         "value": "No audit", "detail": message}],
                             "code_signature": {"present": False}},
        "intervals": [], "warnings": [warning], "truncated": True,
        "semantic_layers": {"entropy_analysis": {"sections": [], "section_metrics": [], "windows": [], "sliding_windows": []},
                            "capabilities": {"cards": [], "categories": [], "string_intelligence": {}},
                            "provenance": {}, "anomalies": {"total_count": 0, "high_severity_count": 0, "findings": []}},
        "pedagogy": {"loader_lifecycle": {"stages": []}, "rosetta_stone": [], "guided_tours": []},
    }
    return {
        "file_info": {"path": f"<patched:{filename}>", "filename": filename, "file_size": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
                      "format": fmt, "format_display": "Unparsed", "is_fat": False, "fat_header": None,
                      "warnings": [warning], "unparsed": True, "parse_error": message},
        "slices": [slice_obj],
    }


def _bisect_culprit(service: Any, parent: DocEntry, patches: List[Dict[str, Any]],
                    pay: Optional[Callable[[int], bool]]) -> Optional[int]:
    """Index of a patch at which the file stops parsing, found by bisection, or None
    when that cannot be afforded.

    The parent parses (no patches applied) and the whole set does not, so there is a
    prefix length k where k-1 patches still parse and k do not; patch k-1 is the
    culprit. Halving finds one in log2(n) probes instead of n (four for sixteen
    patches). Each probe is a full analysis, so each one

      * goes through `service.probe_parse`: a slot of the concurrency cap, the parse
        deadline, a worker process — the same accounting as an upload;
      * is paid for first (`pay(bytes)`, the caller's rate-limit bucket);
      * counts against a per-request budget of bytes and of seconds.

    Running out of any of these, or finding the server busy, ends the search without
    an answer; the request itself still succeeds, only less precisely."""
    size = len(parent.data)
    low, high = 0, len(patches)        # `low` patches parse; `high` do not
    started = time.monotonic()
    worked = 0
    while high - low > 1:
        left = LOCATE_MAX_SECONDS - (time.monotonic() - started)
        if left <= 0 or worked + size > LOCATE_MAX_WORK_BYTES:
            return None
        if pay is not None and not pay(size):
            return None
        worked += size
        middle = (low + high) // 2
        try:
            with runtime.parse_deadline(left):
                reason = service.probe_parse(apply_patches(parent.data, patches[:middle]))
        except runtime.ParseBudgetExceeded:
            check_deadline()           # the request's own deadline: that one does end the request
            return None
        except runtime.Busy:
            return None
        if reason is None:
            low = middle
        else:
            high = middle
    return high - 1


def _locate_failure(service: Any, parent: DocEntry, patches: List[Dict[str, Any]],
                    pay: Optional[Callable[[int], bool]] = None) -> Optional[Dict[str, Any]]:
    """Which patch makes the file unparseable, and which decoded fields it touches."""
    culprit_index: Optional[int] = None
    if len(patches) == 1:
        culprit_index = 0
    elif len(patches) <= LOCATE_MAX_PATCHES and len(parent.data) <= LOCATE_MAX_BYTES and not _is_unparsed(parent.doc):
        culprit_index = _bisect_culprit(service, parent, patches, pay)
    structs = list(iter_structs(parent.doc))
    chosen = [patches[culprit_index]] if culprit_index is not None else patches
    touched = _RangeSet(_patch_ranges(chosen))
    hits: List[Dict[str, Any]] = []
    seen = set()
    for st in structs:
        for field in st["fields"]:
            off, size = field.get("abs_offset"), field.get("size")
            if not isinstance(off, int) or not isinstance(size, int) or (off, size) in seen:
                continue
            if touched.overlaps(off, size):
                seen.add((off, size))
                hits.append({"label": f"{st['label']} · {field.get('name')}", "node": st["node"], "abs_offset": off, "size": size,
                             "was": str(field.get("interpreted") or field.get("value") or "")})
                if len(hits) >= 12:
                    break
        if len(hits) >= 12:
            break
    if culprit_index is None and not hits:
        return None
    out: Dict[str, Any] = {"structures": hits}
    if culprit_index is not None:
        patch = patches[culprit_index]
        out.update(patch_index=culprit_index, offset=patch["offset"], size=len(patch["data"]), label=patch.get("label") or "",
                   isolated=len(patches) > 1)
    return out


def make_derived(service: Any, parent: DocEntry, data: bytes, owner: Optional[str],
                 patches: List[Dict[str, Any]],
                 pay: Optional[Callable[[int], bool]] = None) -> Tuple[DocEntry, Optional[Dict[str, Any]]]:
    """Store `data` as a derived document of `parent`. Returns (entry, parse error or None).

    Bytes the parser rejects still become a document (see `unparsed_document`),
    so the user can look at what they made and undo it. `pay(bytes)` is asked before
    each extra analysis made to find the patch that broke the file (see `_bisect_culprit`)."""
    filename = _derived_filename(parent.filename)
    try:
        return service.add_derived(filename, data, owner=owner, parent=parent.doc_id), None
    except ParseFailed as exc:
        message = str(exc) or "The file could not be parsed."
    # Everything that can still fail or time out happens before the document is
    # stored: a request that does not complete must not leave a copy in the cache
    # that nobody was told the id of.
    error: Dict[str, Any] = {"error": message}
    culprit = _locate_failure(service, parent, patches, pay)
    if culprit is not None:
        error["culprit"] = culprit
    doc_id = "p_" + secrets.token_hex(16)
    doc = unparsed_document(parent.doc, data, filename, message)
    doc["doc_id"] = doc_id
    encoded = encode_json(doc)
    entry = DocEntry(doc_id, "derived", doc, data, filename, cost=len(data) + DOC_COST_FACTOR * len(encoded),
                     encoded=encoded, owner=owner, parent_id=parent.doc_id)
    service.store.put(entry)
    return entry, error


# ============================================================================
# Turning edits into byte patches
# ============================================================================
class NotApplicable(Exception):
    """An experiment cannot be applied to this document; the message says why."""


def _encode_field(doc: Dict[str, Any], data: bytes, st: Dict[str, Any], field: Dict[str, Any], value: Any) -> bytes:
    size = int(field.get("size") or 0)
    off = int(field.get("abs_offset") or 0)
    if size <= 0 or off < 0 or off + size > len(data):
        raise BadRequest("That field lies outside the file.")
    text = value if isinstance(value, str) else None
    if text is not None and text.strip().lower().startswith("hex:"):
        digits = "".join(text.strip()[4:].split())
        if len(digits) != size * 2 or not HEX_DIGITS.issuperset(digits):
            raise BadRequest(f"Expected exactly {size} bytes ({size * 2} hex digits).")
        return bytes.fromhex(digits)
    raw_value = field.get("raw_value")
    if isinstance(raw_value, str) and not isinstance(raw_value, bool):
        if text is None:
            raise BadRequest("This field holds text; give its new value as text.")
        encoded = text.encode("utf-8", "replace")
        if len(encoded) > size:
            raise BadRequest(f"The text is {len(encoded)} bytes; the field holds {size}.")
        return encoded.ljust(size, b"\0")
    number = _as_int(value)
    if number is None:
        raise BadRequest("Enter a number (decimal, or hex with a 0x prefix), or hex:… for raw bytes.")
    slice_obj = (doc.get("slices") or [None])[st["slice"]] if st["slice"] >= 0 else None
    endian = field_endianness(field, st["fields"], data, _slice_little(slice_obj) if st["slice"] >= 0 else False)
    if endian is None:
        raise BadRequest("This field is not stored as a plain integer; edit its bytes in the hex view (or use hex:… here).")
    if number < 0:
        number += 1 << (8 * size)
    if not 0 <= number < (1 << (8 * size)):
        raise BadRequest(f"That value does not fit in {size} byte{'s' if size != 1 else ''}.")
    return number.to_bytes(size, endian)


def _change(offset: int, new: bytes, data: bytes, label: str) -> Dict[str, Any]:
    return {"offset": offset, "hex": new.hex(), "size": len(new), "before_hex": data[offset:offset + len(new)].hex(), "label": label}


def _minimal(change: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Trim bytes that do not change from both ends of a change; None if nothing changes."""
    new, old = bytes.fromhex(change["hex"]), bytes.fromhex(change["before_hex"])
    if new == old:
        return None
    lead = 0
    while lead < len(new) and new[lead] == old[lead]:
        lead += 1
    tail = len(new)
    while tail > lead and new[tail - 1] == old[tail - 1]:
        tail -= 1
    return dict(change, offset=change["offset"] + lead, hex=new[lead:tail].hex(), before_hex=old[lead:tail].hex(), size=tail - lead)


def resolve_field_op(doc: Dict[str, Any], data: bytes, op: Dict[str, Any]) -> List[Dict[str, Any]]:
    offset = _as_int(op.get("offset"))
    size = _as_int(op.get("size"))
    if offset is None:
        raise BadRequest("'offset' is required.")
    found = find_field(doc, offset, size, op.get("name") if isinstance(op.get("name"), str) else None)
    if found is None:
        raise BadRequest("There is no decoded field at that offset in this document.")
    st, field = found
    label = f"{st['label']} · {field.get('name')}"
    if op.get("kind") == "flag":
        raw_value = field.get("raw_value")
        if isinstance(raw_value, bool) or not isinstance(raw_value, int):
            raise BadRequest("This field is not a flags word.")
        flag = None
        for candidate in field.get("bit_flags") or []:
            if candidate.get("name") == op.get("flag") or (op.get("mask") is not None and _flag_mask(candidate) == _as_int(op.get("mask"))):
                flag = candidate
                break
        mask = _flag_mask(flag) if flag is not None else _as_int(op.get("mask"))
        if not mask or mask < 0 or mask >= (1 << (8 * int(field.get("size") or 0))):
            raise BadRequest("Unknown flag for this field.")
        want = op.get("set")
        is_set = (raw_value & mask) == mask
        turn_on = (not is_set) if want is None else bool(want)
        new_value = (raw_value | mask) if turn_on else (raw_value & ~mask)
        name = str((flag or {}).get("name") or "0x%x" % mask)
        label = f"{label}: {'set' if turn_on else 'clear'} {name}"
        new = _encode_field(doc, data, st, field, new_value)
    else:
        new = _encode_field(doc, data, st, field, op.get("value"))
        label = f"{label} = {_clean_text(op.get('value'), 40)}"
    change = _minimal(_change(int(field["abs_offset"]), new, data, label))
    return [change] if change else []


def resolve_fill_op(data: bytes, op: Dict[str, Any], max_bytes: int) -> List[Dict[str, Any]]:
    offset, size, value = _as_int(op.get("offset")), _as_int(op.get("size")), _as_int(op.get("byte"))
    if offset is None or size is None or value is None:
        raise BadRequest("'offset', 'size' and 'byte' are required.")
    if not 0 <= value <= 0xFF:
        raise BadRequest("The fill value must be one byte (00 to ff).")
    if size <= 0 or offset < 0 or offset + size > len(data):
        raise BadRequest("The range to fill lies outside the file.")
    if size > max_bytes:
        raise TooLarge(f"A patch may change at most {max_bytes:,} bytes.")
    change = _change(offset, bytes([value]) * size, data, f"fill 0x{offset:x}+{size} with {value:02x}")
    return [change] if change["hex"] != change["before_hex"] else []


# ============================================================================
# Guided experiments
# ============================================================================
class _Ctx:
    """What an experiment may look at: one slice of a parsed document and its bytes."""

    def __init__(self, doc: Dict[str, Any], data: bytes, slice_index: int) -> None:
        self.doc = doc
        self.data = data
        slices = doc.get("slices") or []
        self.slice_index = max(0, min(slice_index, len(slices) - 1)) if slices else 0
        self.slice: Dict[str, Any] = slices[self.slice_index] if slices else {}
        self.fmt = _slice_fmt(self.slice) if slices else ""
        self.base = int(self.slice.get("slice_base_offset") or 0)
        self.size = int(self.slice.get("slice_size") or len(data))

    # -- lookups ---------------------------------------------------------------
    def header_field(self, name: str) -> Dict[str, Any]:
        field = _named_field((self.slice.get("header") or {}).get("fields") or [], name)
        if field is None:
            raise NotApplicable(f"This file's header has no {name} field.")
        return field

    def commands(self, cmd_name: str) -> List[Dict[str, Any]]:
        return [lc for lc in self.slice.get("load_commands") or [] if lc.get("cmd_name") == cmd_name]

    def struct_for(self, fields: List[Dict[str, Any]]) -> Dict[str, Any]:
        """The structure a field list belongs to.

        The ELF and PE parsers give two structures the very same list where one is made from
        the other (a program header and its segment; the PE headers and the HEADERS
        pseudo-segment; a PE section and its pseudo-segment). The lab names such a field after
        the first of them in document order, as `find_field` does. Object identity cannot be
        what decides that: a document that crossed a process boundary as JSON (the parse
        workers, the in-browser engine) has two equal lists instead of one shared list, and
        the answer must not depend on how the document got here. So for those formats lists
        are compared by what they describe. In a Mach-O slice a segment and its load command
        are separate structures with separate lists, and the list that was passed in decides.
        """
        shared_lists = _slice_fmt(self.slice) != "MACHO"
        want = [(f.get("abs_offset"), f.get("size"), f.get("name")) for f in fields] if shared_lists else None
        for st in iter_structs(self.doc):
            if st["slice"] != self.slice_index:
                continue
            if st["fields"] is fields or (want and len(st["fields"]) == len(want)
                                          and [(f.get("abs_offset"), f.get("size"), f.get("name")) for f in st["fields"]] == want):
                return st
        return {"slice": self.slice_index, "fields": fields, "label": "structure", "node": None}

    # -- edits -----------------------------------------------------------------
    def set_int(self, fields: List[Dict[str, Any]], name: str, value: int, label: str) -> Dict[str, Any]:
        field = _named_field(fields, name)
        if field is None:
            raise NotApplicable(f"The {name} field was not decoded in this file.")
        st = self.struct_for(fields)
        new = _encode_field(self.doc, self.data, st, field, value)
        change = _minimal(_change(int(field["abs_offset"]), new, self.data, label))
        if change is None:
            raise NotApplicable(f"{name} already has that value.")
        change.update(field=name, struct=st["label"], node=st["node"], field_offset=field["abs_offset"], field_size=field["size"],
                      before_value=str(field.get("value")), after_value="0x%x" % value)
        return change

    def flag(self, fields: List[Dict[str, Any]], name: str, flag_name: str, on: bool, label: str) -> Dict[str, Any]:
        field = _named_field(fields, name)
        if field is None or not isinstance(field.get("raw_value"), int):
            raise NotApplicable(f"The {name} field was not decoded in this file.")
        flag = next((f for f in field.get("bit_flags") or [] if f.get("name") == flag_name), None)
        mask = _flag_mask(flag) if flag else None
        if not mask:
            raise NotApplicable(f"{name} has no {flag_name} bit in this format.")
        raw = field["raw_value"]
        if ((raw & mask) == mask) == on:
            raise NotApplicable(f"{flag_name} is already {'set' if on else 'clear'} in this file.")
        change = self.set_int(fields, name, (raw | mask) if on else (raw & ~mask), label)
        change.update(flag=flag_name, mask="0x%x" % mask, flag_set=on)
        return change

    def byte(self, offset: int, value: int, label: str, struct: str = "", node: Optional[str] = None) -> Dict[str, Any]:
        if not 0 <= offset < len(self.data):
            raise NotApplicable("That byte lies outside the file.")
        change = _change(offset, bytes([value & 0xFF]), self.data, label)
        change.update(struct=struct, node=node, field_offset=offset, field_size=1,
                      before_value="0x%02x" % self.data[offset], after_value="0x%02x" % (value & 0xFF))
        return change


def _exp_elf_code_writable(ctx: _Ctx) -> List[Dict[str, Any]]:
    for lc in ctx.commands("PT_LOAD"):
        flags = _named_field(lc.get("fields") or [], "p_flags")
        if flags and isinstance(flags.get("raw_value"), int) and flags["raw_value"] & 1 and not flags["raw_value"] & 2:
            return [ctx.flag(lc["fields"], "p_flags", "PF_W", True, f"PT_LOAD #{lc.get('index')}: set PF_W on the code segment")]
    raise NotApplicable("No PT_LOAD segment is executable and not yet writable.")


def _exp_elf_exec_stack(ctx: _Ctx) -> List[Dict[str, Any]]:
    stacks = ctx.commands("PT_GNU_STACK")
    if not stacks:
        raise NotApplicable("This file has no PT_GNU_STACK program header.")
    return [ctx.flag(stacks[0]["fields"], "p_flags", "PF_X", True, "PT_GNU_STACK: set PF_X")]


def _exp_elf_no_pie(ctx: _Ctx) -> List[Dict[str, Any]]:
    header = (ctx.slice.get("header") or {}).get("fields") or []
    e_type = ctx.header_field("e_type")
    if e_type.get("raw_value") != 3:
        raise NotApplicable("e_type is not ET_DYN, so this file is not position-independent to begin with.")
    return [ctx.set_int(header, "e_type", 2, "e_type: ET_DYN -> ET_EXEC")]


def _exp_elf_no_relro(ctx: _Ctx) -> List[Dict[str, Any]]:
    relro = ctx.commands("PT_GNU_RELRO")
    if not relro:
        raise NotApplicable("This file has no PT_GNU_RELRO program header.")
    return [ctx.set_int(relro[0]["fields"], "p_type", 0, "PT_GNU_RELRO: p_type -> PT_NULL")]


def _exp_elf_entry(ctx: _Ctx) -> List[Dict[str, Any]]:
    header = (ctx.slice.get("header") or {}).get("fields") or []
    entry = ctx.header_field("e_entry")
    for seg in ctx.slice.get("segments") or []:
        prot = str(seg.get("initprot") or "")
        if "x" not in prot and "w" in prot and isinstance(seg.get("vmaddr_int"), int) and seg.get("filesize"):
            if seg["vmaddr_int"] != entry.get("raw_value"):
                return [ctx.set_int(header, "e_entry", seg["vmaddr_int"],
                                    f"e_entry -> 0x{seg['vmaddr_int']:x} (start of {seg.get('segname')})")]
    if not isinstance(entry.get("raw_value"), int):
        raise NotApplicable("e_entry was not decoded.")
    return [ctx.set_int(header, "e_entry", entry["raw_value"] + 1, "e_entry + 1")]


def _exp_elf_magic(ctx: _Ctx) -> List[Dict[str, Any]]:
    magic = ctx.header_field("e_ident[EI_MAG]")
    return [ctx.byte(int(magic["abs_offset"]) + 1, 0x00, "e_ident[EI_MAG1]: 'E' -> 00", "ELF header", "mach_header")]


def _exp_elf_endian(ctx: _Ctx) -> List[Dict[str, Any]]:
    field = ctx.header_field("e_ident[EI_DATA]")
    current = field.get("raw_value")
    if current not in (1, 2):
        raise NotApplicable("EI_DATA is neither ELFDATA2LSB nor ELFDATA2MSB.")
    header = (ctx.slice.get("header") or {}).get("fields") or []
    return [ctx.set_int(header, "e_ident[EI_DATA]", 2 if current == 1 else 1,
                        "e_ident[EI_DATA]: " + ("LSB -> MSB" if current == 1 else "MSB -> LSB"))]


def _exp_elf_section_bounds(ctx: _Ctx) -> List[Dict[str, Any]]:
    pick = None
    for seg in ctx.slice.get("segments") or []:
        for sect in seg.get("sections") or []:
            if not _named_field(sect.get("fields") or [], "sh_size") or sect.get("is_zerofill"):
                continue
            if pick is None or sect.get("sectname") == ".text":
                pick = sect
    if pick is None:
        raise NotApplicable("This file has no section headers.")
    return [ctx.set_int(pick["fields"], "sh_size", 0x7FFFFFF0, f"{pick.get('sectname')}: sh_size -> 0x7ffffff0 (past the end of the file)")]


def _exp_elf_interp(ctx: _Ctx) -> List[Dict[str, Any]]:
    interp = str((ctx.slice.get("elf_metadata") or {}).get("interpreter") or "")
    if not interp:
        raise NotApplicable("This file has no PT_INTERP (it is statically linked).")
    start = ctx.data.find(interp.encode("utf-8", "replace") + b"\0", ctx.base, ctx.base + ctx.size)
    if start < 0:
        raise NotApplicable("The interpreter path could not be located in the file.")
    last = start + len(interp.encode("utf-8", "replace")) - 1
    new = ord("X") if ctx.data[last] != ord("X") else ord("Y")
    return [ctx.byte(last, new, f"PT_INTERP path: last character -> '{chr(new)}'", "Interpreter path", None)]


def _pe_dll_flag(flag: str, label: str) -> Callable[[_Ctx], List[Dict[str, Any]]]:
    def run(ctx: _Ctx) -> List[Dict[str, Any]]:
        header = (ctx.slice.get("header") or {}).get("fields") or []
        return [ctx.flag(header, "OptionalHeader.DllCharacteristics", "IMAGE_DLLCHARACTERISTICS_" + flag, False, label)]
    return run


def _pe_code_section(ctx: _Ctx) -> Dict[str, Any]:
    for seg in ctx.slice.get("segments") or []:
        for sect in seg.get("sections") or []:
            chars = _named_field(sect.get("fields") or [], "Characteristics")
            if chars and isinstance(chars.get("raw_value"), int) and chars["raw_value"] & 0x20000000:
                return sect
    raise NotApplicable("No section of this image is executable.")


def _exp_pe_section_writable(ctx: _Ctx) -> List[Dict[str, Any]]:
    sect = _pe_code_section(ctx)
    return [ctx.flag(sect["fields"], "Characteristics", "IMAGE_SCN_MEM_WRITE", True, f"{sect.get('sectname')}: set IMAGE_SCN_MEM_WRITE")]


def _exp_pe_entry(ctx: _Ctx) -> List[Dict[str, Any]]:
    header = (ctx.slice.get("header") or {}).get("fields") or []
    entry = ctx.header_field("OptionalHeader.AddressOfEntryPoint")
    for seg in ctx.slice.get("segments") or []:
        for sect in seg.get("sections") or []:
            rva = _named_field(sect.get("fields") or [], "VirtualAddress")
            chars = _named_field(sect.get("fields") or [], "Characteristics")
            if rva and chars and isinstance(chars.get("raw_value"), int) and not chars["raw_value"] & 0x20000000 \
                    and isinstance(rva.get("raw_value"), int) and rva["raw_value"] != entry.get("raw_value"):
                return [ctx.set_int(header, "OptionalHeader.AddressOfEntryPoint", rva["raw_value"],
                                    f"AddressOfEntryPoint -> RVA 0x{rva['raw_value']:x} (start of {sect.get('sectname')})")]
    raise NotApplicable("Every section of this image is executable, so there is no non-executable place to point the entry at.")


def _exp_pe_magic(ctx: _Ctx) -> List[Dict[str, Any]]:
    dos = next((lc for lc in ctx.slice.get("load_commands") or [] if _named_field(lc.get("fields") or [], "e_magic")), None)
    if dos is None:
        raise NotApplicable("The DOS header was not decoded.")
    field = _named_field(dos["fields"], "e_magic")
    return [ctx.byte(int(field["abs_offset"]), 0x00, "e_magic: 'M' -> 00", "IMAGE_DOS_HEADER", f"lc_{dos.get('index')}")]  # type: ignore[index]


def _exp_pe_section_bounds(ctx: _Ctx) -> List[Dict[str, Any]]:
    last = None
    for seg in ctx.slice.get("segments") or []:
        for sect in seg.get("sections") or []:
            if _named_field(sect.get("fields") or [], "SizeOfRawData"):
                last = sect
    if last is None:
        raise NotApplicable("This image has no sections.")
    size = len(ctx.data) * 2 + 0x1000
    return [ctx.set_int(last["fields"], "SizeOfRawData", size & 0xFFFFFFFF, f"{last.get('sectname')}: SizeOfRawData -> 0x{size & 0xFFFFFFFF:x} (past the end of the file)")]


def _exp_pe_tamper(ctx: _Ctx) -> List[Dict[str, Any]]:
    sect = _pe_code_section(ctx)
    off, size = sect.get("abs_offset"), sect.get("raw_size", sect.get("size"))   # its bytes on disk
    if not isinstance(off, int) or not isinstance(size, int) or size <= 0 or off + size > len(ctx.data):
        raise NotApplicable("The code section has no bytes in the file.")
    target = off + size // 2
    return [ctx.byte(target, ctx.data[target] ^ 0xFF, f"{sect.get('sectname')}: invert one byte at 0x{target:x}",
                     f"Section {sect.get('sectname')}", None)]


def _macho_segment(ctx: _Ctx, want: Callable[[Dict[str, Any]], bool], why: str) -> Dict[str, Any]:
    for seg in ctx.slice.get("segments") or []:
        if _named_field(seg.get("fields") or [], "initprot") and want(seg):
            return seg
    raise NotApplicable(why)


def _exp_macho_code_writable(ctx: _Ctx) -> List[Dict[str, Any]]:
    seg = _macho_segment(ctx, lambda s: "x" in str(s.get("initprot")) and "w" not in str(s.get("initprot")),
                         "No segment is executable and not yet writable.")
    name = seg.get("segname")
    changes = [ctx.flag(seg["fields"], "initprot", "VM_PROT_WRITE", True, f"{name}: set VM_PROT_WRITE in initprot")]
    try:
        changes.insert(0, ctx.flag(seg["fields"], "maxprot", "VM_PROT_WRITE", True, f"{name}: set VM_PROT_WRITE in maxprot"))
    except NotApplicable:
        pass  # maxprot already allows writing
    return changes


def _exp_macho_no_pie(ctx: _Ctx) -> List[Dict[str, Any]]:
    header = (ctx.slice.get("header") or {}).get("fields") or []
    return [ctx.flag(header, "flags", "MH_PIE", False, "Mach-O header flags: clear MH_PIE")]


def _exp_macho_entry(ctx: _Ctx) -> List[Dict[str, Any]]:
    mains = ctx.commands("LC_MAIN")
    if mains:
        seg = _macho_segment(ctx, lambda s: "x" not in str(s.get("initprot")) and "w" in str(s.get("initprot")) and bool(s.get("filesize")),
                             "There is no writable, non-executable segment to point the entry at.")
        return [ctx.set_int(mains[0]["fields"], "entryoff", int(seg.get("fileoff") or 0),
                            f"LC_MAIN entryoff -> 0x{int(seg.get('fileoff') or 0):x} (start of {seg.get('segname')})")]
    for lc in ctx.slice.get("load_commands") or []:
        if "THREAD" in str(lc.get("cmd_name")):
            pc = _named_field(lc.get("fields") or [], "pc") or _named_field(lc.get("fields") or [], "rip")
            if pc and isinstance(pc.get("raw_value"), int):
                return [ctx.set_int(lc["fields"], str(pc["name"]), pc["raw_value"] + 4, f"{lc.get('cmd_name')}: {pc['name']} + 4")]
    raise NotApplicable("This file has neither LC_MAIN nor a thread-state command.")


def _exp_macho_magic(ctx: _Ctx) -> List[Dict[str, Any]]:
    magic = ctx.header_field("magic")
    off = int(magic["abs_offset"])
    return [ctx.byte(off, ctx.data[off] ^ 0xFF, "Mach-O magic: invert the first byte", "Mach-O header", "mach_header")]


def _exp_macho_tamper(ctx: _Ctx) -> List[Dict[str, Any]]:
    params = _cd_params(ctx.slice)
    if params is None:
        raise NotApplicable("This slice has no code signature with page hashes.")
    target = None
    for seg in ctx.slice.get("segments") or []:
        for sect in seg.get("sections") or []:
            if sect.get("is_executable") and isinstance(sect.get("abs_offset"), int) and isinstance(sect.get("size"), int) and sect["size"] > 0:
                target = (sect["abs_offset"] + sect["size"] // 2, f"{sect.get('segname')},{sect.get('sectname')}")
                break
        if target:
            break
    if target is None or not ctx.base <= target[0] < ctx.base + params["codeLimit"]:
        raise NotApplicable("No executable section lies inside the signed range.")
    page = (target[0] - ctx.base) // (params["page"] or max(1, params["codeLimit"]))
    change = ctx.byte(target[0], ctx.data[target[0]] ^ 0xFF, f"{target[1]}: invert one byte at 0x{target[0]:x} (signed page {page})",
                      f"Section {target[1]}", "code_signature")
    change["page"] = page
    return [change]


def _exp_macho_segment_bounds(ctx: _Ctx) -> List[Dict[str, Any]]:
    seg = None
    for candidate in ctx.slice.get("segments") or []:
        if _named_field(candidate.get("fields") or [], "filesize") and candidate.get("filesize"):
            seg = candidate
    if seg is None:
        raise NotApplicable("No segment has bytes in the file.")
    size = ctx.size * 2 + 0x4000
    return [ctx.set_int(seg["fields"], "filesize", size, f"{seg.get('segname')}: filesize -> 0x{size:x} (past the end of the file)")]


# id, format, title, sample preset, what the learner is told beforehand, what to look at, loader statement keys, resolver
EXPERIMENTS: List[Dict[str, Any]] = [
    {"id": "elf.code-writable", "format": "ELF", "title": "Make a code segment writable", "sample": "synthetic_elf64",
     "setup": "Every PT_LOAD program header carries a p_flags word that says how its bytes are mapped: read, write, "
              "execute. Linkers keep code read-and-execute and data read-and-write, never both. This sets PF_W on the "
              "segment that holds the code.",
     "look": [["security_audit", "Hardening: the W^X check"], ["segments", "Segments: the protection column"]],
     "loader": ["elf.segment_wx"], "run": _exp_elf_code_writable},
    {"id": "elf.exec-stack", "format": "ELF", "title": "Make the stack executable", "sample": "synthetic_elf64",
     "setup": "PT_GNU_STACK is a program header with no contents. It exists only so that its p_flags can tell the "
              "kernel whether the stack may be executed. This sets PF_X in it.",
     "look": [["security_audit", "Hardening: the non-executable stack check"]],
     "loader": ["elf.stack_exec"], "run": _exp_elf_exec_stack},
    {"id": "elf.no-pie", "format": "ELF", "title": "Turn off PIE", "sample": "synthetic_elf64",
     "setup": "A position-independent executable is an ELF whose e_type is ET_DYN: the kernel may place it anywhere. "
              "This rewrites e_type to ET_EXEC, which means 'map me exactly at the addresses in my program headers'.",
     "look": [["security_audit", "Hardening: the PIE check"], ["mach_header", "ELF header: e_type"]],
     "loader": ["elf.et_exec"], "run": _exp_elf_no_pie},
    {"id": "elf.no-relro", "format": "ELF", "title": "Remove RELRO", "sample": "synthetic_elf64",
     "setup": "PT_GNU_RELRO names a range that the dynamic loader makes read-only once it has finished relocating: "
              "the GOT and friends. This turns that program header into PT_NULL, an ignored entry.",
     "look": [["security_audit", "Hardening: the RELRO check"], ["load_commands", "Program headers: the entry that was PT_GNU_RELRO"]],
     "loader": ["elf.relro_gone"], "run": _exp_elf_no_relro},
    {"id": "elf.entry", "format": "ELF", "title": "Point the entry at data", "sample": "synthetic_elf64",
     "setup": "e_entry is the address of the first instruction. This points it at the start of the writable data "
              "segment instead of at code.",
     "look": [["function_starts", "Entry point & functions"], ["disassembly", "Disassembly at the new entry"]],
     "loader": ["elf.entry"], "run": _exp_elf_entry},
    {"id": "elf.interp", "format": "ELF", "title": "Break the interpreter path", "sample": "synthetic_elf64",
     "setup": "A dynamically linked ELF names its dynamic loader in PT_INTERP, as a plain path string. This changes "
              "the last character of that path so that it names a file that does not exist.",
     "look": [["overview", "Overview: the interpreter"], ["load_commands", "Program headers: PT_INTERP"]],
     "loader": ["elf.interp_path"], "run": _exp_elf_interp},
    {"id": "elf.magic", "format": "ELF", "title": "Flip the magic", "sample": "synthetic_elf64",
     "setup": "An ELF file starts with the four bytes 7f 'E' 'L' 'F'. This zeroes the 'E'.",
     "look": [["labs.patch", "What changed: the parse result"]],
     "loader": ["elf.magic"], "run": _exp_elf_magic},
    {"id": "elf.endian", "format": "ELF", "title": "Swap the endianness byte", "sample": "synthetic_elf64",
     "setup": "e_ident[EI_DATA] says whether the multi-byte fields of the file are little- or big-endian. This flips "
              "it without touching anything else, so the file now lies about its own byte order.",
     "look": [["labs.patch", "What changed: how every header field now decodes"], ["mach_header", "ELF header"]],
     "loader": ["elf.ei_data"], "run": _exp_elf_endian},
    {"id": "elf.section-bounds", "format": "ELF", "title": "Break a section's bounds", "sample": "synthetic_elf64",
     "setup": "Section headers describe the file for linkers and debuggers. This gives one section a size that runs "
              "far past the end of the file.",
     "look": [["labs.patch", "What changed: warnings and anomalies"], ["segments", "Segments & sections"]],
     "loader": ["elf.sections"], "run": _exp_elf_section_bounds},
    {"id": "pe.no-aslr", "format": "PE", "title": "Turn off ASLR", "sample": "synthetic_pe64",
     "setup": "OptionalHeader.DllCharacteristics is a set of opt-in bits. DYNAMIC_BASE (0x0040) tells the Windows "
              "loader that the image may be placed at a random base. This clears it.",
     "look": [["security_audit", "Hardening: the ASLR checks"], ["mach_header", "PE headers: DllCharacteristics"]],
     "loader": ["pe.dynamic_base_off"], "run": _pe_dll_flag("DYNAMIC_BASE", "DllCharacteristics: clear DYNAMIC_BASE")},
    {"id": "pe.no-nx", "format": "PE", "title": "Drop NX_COMPAT", "sample": "synthetic_pe64",
     "setup": "NX_COMPAT (0x0100) declares that the image works with Data Execution Prevention. This clears it.",
     "look": [["security_audit", "Hardening: the DEP check"]],
     "loader": ["pe.nx_off"], "loader_fmt": {"bits": "Whether anything changes therefore depends on whether the image is 32-bit."},
     "run": _pe_dll_flag("NX_COMPAT", "DllCharacteristics: clear NX_COMPAT")},
    {"id": "pe.no-cfg", "format": "PE", "title": "Clear GUARD_CF", "sample": "synthetic_pe64",
     "setup": "GUARD_CF (0x4000) declares that the image was built with Control Flow Guard and carries the tables "
              "for it. This clears the flag and leaves the tables in place.",
     "look": [["security_audit", "Hardening: the Control Flow Guard check"]],
     "loader": ["pe.cfg_off"], "run": _pe_dll_flag("GUARD_CF", "DllCharacteristics: clear GUARD_CF")},
    {"id": "pe.section-writable", "format": "PE", "title": "Make the code section writable", "sample": "synthetic_pe64",
     "setup": "Each section header has a Characteristics word; MEM_READ, MEM_WRITE and MEM_EXECUTE are three of its "
              "bits. This sets MEM_WRITE on the section that holds the code.",
     "look": [["security_audit", "Hardening: the W^X check"], ["segments", "Sections: the protection column"]],
     "loader": ["pe.section_wx"], "run": _exp_pe_section_writable},
    {"id": "pe.entry", "format": "PE", "title": "Point the entry at data", "sample": "synthetic_pe64",
     "setup": "AddressOfEntryPoint is an RVA: an offset from the image base. This points it at the start of a "
              "section that is not executable.",
     "look": [["function_starts", "Entry point & functions"], ["disassembly", "Disassembly at the new entry"]],
     "loader": ["pe.entry"], "run": _exp_pe_entry},
    {"id": "pe.tamper-signed", "format": "PE", "title": "Change one signed byte", "sample": "synthetic_pe64",
     "setup": "A PE carries two integrity values: the CheckSum in its optional header and, if it is signed, an "
              "Authenticode hash inside the certificate table. In the sample both match the file to begin with: the "
              "checksum is the checksum of its bytes, and its (synthetic, self-made) signature holds its image hash. "
              "This inverts one byte in the middle of the code; afterwards neither matches.",
     "look": [["labs.patch", "What changed: checksum and Authenticode hash"], ["code_signature", "Authenticode"]],
     "loader": ["pe.checksum_about", "pe.authenticode"], "loader_fmt": {"embedded": ""}, "run": _exp_pe_tamper},
    {"id": "pe.magic", "format": "PE", "title": "Flip the magic", "sample": "synthetic_pe64",
     "setup": "A PE file starts with a DOS header whose first two bytes are 'M' 'Z'. This zeroes the 'M'.",
     "look": [["labs.patch", "What changed: the parse result"]],
     "loader": ["pe.magic"], "run": _exp_pe_magic},
    {"id": "pe.section-bounds", "format": "PE", "title": "Break a section's bounds", "sample": "synthetic_pe64",
     "setup": "A section header says where the section's bytes are in the file (PointerToRawData) and how many "
              "there are (SizeOfRawData). This makes the last section claim more bytes than the file has.",
     "look": [["labs.patch", "What changed: warnings and anomalies"], ["segments", "Sections"]],
     "loader": ["pe.section_bounds"], "run": _exp_pe_section_bounds},
    {"id": "macho.code-writable", "format": "MACHO", "title": "Make a code segment writable", "sample": "synthetic_universal",
     "setup": "Each LC_SEGMENT command has two protection words: initprot, what the segment is mapped with, and "
              "maxprot, the most it may ever be given. This adds write permission to both for the segment that holds "
              "the code.",
     "look": [["security_audit", "Hardening: the W^X check"], ["segments", "Segments: the protection column"]],
     "loader": ["macho.segment_wx"], "run": _exp_macho_code_writable},
    {"id": "macho.no-pie", "format": "MACHO", "title": "Turn off PIE", "sample": "synthetic_universal",
     "setup": "MH_PIE (0x200000) in the Mach-O header's flags tells the kernel that the main executable may be "
              "loaded at a random address. This clears it.",
     "look": [["security_audit", "Hardening: the PIE check"], ["mach_header", "Mach-O header: flags"]],
     "loader": ["macho.pie_off"], "run": _exp_macho_no_pie},
    {"id": "macho.entry", "format": "MACHO", "title": "Move the entry point", "sample": "synthetic_universal",
     "setup": "LC_MAIN gives the entry point as entryoff, a file offset from the start of the image; older and "
              "standalone images use LC_UNIXTHREAD, which gives a full register state. This moves the entry away from "
              "the code it pointed at.",
     "look": [["function_starts", "Entry point & functions"], ["disassembly", "Disassembly at the new entry"]],
     "loader": ["macho.entry_main"], "run": _exp_macho_entry},
    {"id": "macho.tamper-page", "format": "MACHO", "title": "Corrupt one signed page", "sample": "synthetic_universal",
     "setup": "A Mach-O code signature holds a CodeDirectory with one hash for every page of the file up to the "
              "signature. This inverts a single byte of code and leaves the signature alone.",
     "look": [["labs.patch", "What changed: which page hash fails"], ["code_signature", "Code signature: page hashes"],
              ["security_audit", "Hardening: the code signature check"]],
     "loader": ["macho.signature_pages"], "loader_fmt": {"n": "The page that holds the changed byte will", "match": "match"},
     "run": _exp_macho_tamper},
    {"id": "macho.magic", "format": "MACHO", "title": "Flip the magic", "sample": "synthetic_universal",
     "setup": "A Mach-O image starts with feedface (32-bit) or feedfacf (64-bit), stored in the file's own byte "
              "order; in a universal file each slice starts with its own. This inverts the first byte of the magic "
              "of the slice you are looking at.",
     "look": [["labs.patch", "What changed: the slice, or the whole file, stops parsing"]],
     "loader": ["macho.magic", "macho.magic_slice"], "run": _exp_macho_magic},
    {"id": "macho.segment-bounds", "format": "MACHO", "title": "Break a segment's bounds", "sample": "synthetic_universal",
     "setup": "A segment command says which bytes of the file to map: fileoff and filesize. This makes the last "
              "segment claim more bytes than the file has.",
     "look": [["labs.patch", "What changed: warnings and anomalies"], ["segments", "Segments"]],
     "loader": ["macho.segment_bounds"], "run": _exp_macho_segment_bounds},
]
_EXPERIMENTS_BY_ID = {exp["id"]: exp for exp in EXPERIMENTS}


def _experiment_loader_text(exp: Dict[str, Any]) -> List[Dict[str, str]]:
    out = []
    for key in exp["loader"]:
        entry = TEXT[key]
        text = entry["text"]
        if "{" in text:
            text = text.format(**exp.get("loader_fmt", {}))
        out.append({"id": key, "title": entry["title"], "text": " ".join(text.split()), "basis": entry["basis"]})
    return out


def resolve_experiment(exp_id: str, doc: Dict[str, Any], data: bytes, slice_index: int) -> List[Dict[str, Any]]:
    exp = _EXPERIMENTS_BY_ID.get(str(exp_id))
    if exp is None:
        raise BadRequest("Unknown experiment.")
    if _is_unparsed(doc):
        raise NotApplicable("This file does not parse at the moment. Undo the change that broke it first.")
    ctx = _Ctx(doc, data, slice_index)
    if ctx.fmt != exp["format"]:
        raise NotApplicable(f"This experiment needs a {_FORMAT_NAMES[exp['format']]} file.")
    changes = [c for c in (exp["run"](ctx) or []) if c]
    for change in changes:
        change["label"] = f"{exp['title']} · {change['label']}"[:MAX_LABEL_CHARS]
    return changes


_FORMAT_NAMES = {"ELF": "ELF", "PE": "PE", "MACHO": "Mach-O"}


def experiment_catalogue(doc: Optional[Dict[str, Any]], data: bytes, slice_index: int) -> Dict[str, Any]:
    """Every experiment, each resolved against the open document where it applies."""
    items = []
    fmt = None
    if doc is not None and doc.get("slices"):
        fmt = _Ctx(doc, data, slice_index).fmt
    for exp in EXPERIMENTS:
        check_deadline()
        item: Dict[str, Any] = {
            "id": exp["id"], "format": exp["format"], "format_name": _FORMAT_NAMES[exp["format"]], "title": exp["title"],
            "setup": exp["setup"], "look": [{"node": node, "label": label} for node, label in exp["look"]],
            "loader": _experiment_loader_text(exp), "sample": exp["sample"], "applicable": False, "reason": "", "changes": [],
        }
        if doc is None:
            item["reason"] = "Open a file, or the sample, to try it."
        elif fmt != exp["format"]:
            item["reason"] = f"Needs a {_FORMAT_NAMES[exp['format']]} file."
        else:
            try:
                item["changes"] = resolve_experiment(exp["id"], doc, data, slice_index)
                item["applicable"] = bool(item["changes"])
                if not item["changes"]:
                    item["reason"] = "Nothing to change in this file."
            except NotApplicable as exc:
                item["reason"] = str(exc)
            except BadRequest as exc:
                item["reason"] = exc.message
        items.append(item)
    caveat = ""
    if doc is not None and fmt == "MACHO" and _macho_standalone(_Ctx(doc, data, slice_index).slice):
        caveat = _note("macho.standalone", type=str((_Ctx(doc, data, slice_index).slice.get("header") or {}).get("filetype_name")))["text"]
    return {"experiments": items, "format": fmt, "caveat": caveat}


# ============================================================================
# Minimal ELF64 builder
# ============================================================================
PT_LOAD = 1
PT_GNU_STACK = 0x6474E551
_BUILD_ARCH: Dict[str, Dict[str, Any]] = {
    "x86_64": {"label": "x86-64", "e_machine": 62, "machine_name": "EM_X86_64", "align": 0x1000},
    "aarch64": {"label": "AArch64", "e_machine": 183, "machine_name": "EM_AARCH64", "align": 0x10000},
}
# Fixed, pre-assembled, position-independent Linux snippets. They are data: this
# tool shows their bytes and never runs them. Each is a list of (bytes, text).
_PAYLOADS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "x86_64": {
        "exit42": {"label": "exit(42)", "about": "Calls exit(42): system call 60 with 42 in rdi.", "code": [
            ("bf2a000000", "mov edi, 42"), ("b83c000000", "mov eax, 60"), ("0f05", "syscall")]},
        "hello": {"label": "write(1, \"hi\\n\", 3); exit(0)", "about": "Writes three bytes to standard output, then exits with status 0.", "code": [
            ("b801000000", "mov eax, 1"), ("bf01000000", "mov edi, 1"), ("488d3510000000", "lea rsi, [rip + 0x10]"),
            ("ba03000000", "mov edx, 3"), ("0f05", "syscall"), ("b83c000000", "mov eax, 60"), ("31ff", "xor edi, edi"),
            ("0f05", "syscall"), ("68690a", ".ascii \"hi\\n\"")]},
        "spin": {"label": "loop forever", "about": "A two-byte jump to itself.", "code": [("ebfe", "jmp $")]},
        "trap": {"label": "breakpoint trap", "about": "One int3: the process stops with SIGTRAP.", "code": [("cc", "int3")]},
    },
    "aarch64": {
        "exit42": {"label": "exit(42)", "about": "Calls exit(42): system call 93 with 42 in x0.", "code": [
            ("400580d2", "mov x0, #42"), ("a80b80d2", "mov x8, #93"), ("010000d4", "svc #0")]},
        "hello": {"label": "write(1, \"hi\\n\", 3); exit(0)", "about": "Writes three bytes to standard output, then exits with status 0.", "code": [
            ("200080d2", "mov x0, #1"), ("e1000010", "adr x1, #28"), ("620080d2", "mov x2, #3"), ("080880d2", "mov x8, #64"),
            ("010000d4", "svc #0"), ("000080d2", "mov x0, #0"), ("a80b80d2", "mov x8, #93"), ("010000d4", "svc #0"),
            ("68690a00", ".ascii \"hi\\n\\0\"")]},
        "spin": {"label": "loop forever", "about": "A branch to itself.", "code": [("00000014", "b .")]},
        "trap": {"label": "breakpoint trap", "about": "One brk: the process stops with SIGTRAP.", "code": [("000020d4", "brk #0")]},
    },
}
_ET = {"exec": (2, "ET_EXEC"), "dyn": (3, "ET_DYN")}


def build_options() -> Dict[str, Any]:
    return {
        "formats": [{"id": "elf64", "label": "ELF64 executable (Linux)"}],
        "arches": [{"id": key, "label": spec["label"], "align": spec["align"],
                    "payloads": [{"id": pid, "label": p["label"], "about": p["about"],
                                  "bytes": sum(len(code) // 2 for code, _ in p["code"])} for pid, p in _PAYLOADS[key].items()]}
                   for key, spec in _BUILD_ARCH.items()],
        "types": [{"id": "exec", "label": "ET_EXEC (fixed address)"}, {"id": "dyn", "label": "ET_DYN (static PIE)"}],
        "defaults": {"format": "elf64", "arch": "x86_64", "type": "exec", "base": "0x400000", "flags": "rx",
                     "payload": "exit42", "gnu_stack": True, "stack_exec": False, "entry": ""},
    }


def build_minimal_elf(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Assemble a minimal ELF64 from a form, with every byte accounted for.

    Layout: the ELF header (64 bytes), one or two program headers (56 bytes
    each), then the payload. One PT_LOAD maps the whole file, headers
    included, from file offset 0 to `base`.
    """
    arch_id = str(spec.get("arch") or "x86_64")
    arch = _BUILD_ARCH.get(arch_id)
    if arch is None:
        raise BadRequest("Unknown architecture; use x86_64 or aarch64.")
    type_id = str(spec.get("type") or "exec")
    if type_id not in _ET:
        raise BadRequest("Unknown file type; use exec or dyn.")
    e_type, e_type_name = _ET[type_id]
    payload_id = str(spec.get("payload") or "exit42")
    payload = _PAYLOADS[arch_id].get(payload_id)
    if payload is None:
        raise BadRequest("Unknown payload.")
    flags_text = "rx" if spec.get("flags") is None else str(spec.get("flags")).lower()
    if len(flags_text) > 3 or any(ch not in "rwx" for ch in flags_text):
        raise BadRequest("Segment flags are a combination of r, w and x.")
    p_flags = (4 if "r" in flags_text else 0) | (2 if "w" in flags_text else 0) | (1 if "x" in flags_text else 0)
    base = _as_int(spec.get("base") if spec.get("base") not in (None, "") else ("0" if type_id == "dyn" else "0x400000"))
    if base is None or base < 0 or base >= (1 << 47):
        raise BadRequest("The base address must be a number below 2^47 (the user half of a 48-bit address space).")
    align = arch["align"]
    if base % align:
        raise BadRequest(f"The base address must be a multiple of the segment alignment (0x{align:x}): "
                         "a loader maps whole pages, so p_vaddr and p_offset must agree modulo p_align.")
    gnu_stack = bool(spec.get("gnu_stack", True))
    stack_exec = bool(spec.get("stack_exec", False))

    phnum = 2 if gnu_stack else 1
    code = b"".join(bytes.fromhex(chunk) for chunk, _ in payload["code"])
    payload_off = 64 + 56 * phnum
    total = payload_off + len(code)
    entry_text = spec.get("entry")
    if entry_text in (None, ""):
        entry = base + payload_off
        entry_custom = False
    else:
        entry = _as_int(entry_text)
        if entry is None or entry < 0 or entry >= (1 << 64):
            raise BadRequest("The entry address must be a 64-bit number.")
        entry_custom = True

    regions: List[Dict[str, Any]] = []
    out = bytearray()

    def put(group: str, name: str, raw: bytes, value: str, meaning: str) -> None:
        regions.append({"group": group, "name": name, "offset": len(out), "size": len(raw), "hex": raw.hex(),
                        "value": value, "meaning": meaning})
        out.extend(raw)

    le = lambda fmt, v: struct.pack("<" + fmt, v)  # noqa: E731
    put("ehdr", "e_ident[EI_MAG]", b"\x7fELF", "7f 'E' 'L' 'F'", "Magic number: this is an ELF file.")
    put("ehdr", "e_ident[EI_CLASS]", b"\x02", "ELFCLASS64", "64-bit structures follow.")
    put("ehdr", "e_ident[EI_DATA]", b"\x01", "ELFDATA2LSB", "Multi-byte fields are little-endian.")
    put("ehdr", "e_ident[EI_VERSION]", b"\x01", "EV_CURRENT", "ELF version 1, the only one.")
    put("ehdr", "e_ident[EI_OSABI]", b"\x00", "ELFOSABI_NONE", "System V ABI; what Linux toolchains emit.")
    put("ehdr", "e_ident[EI_ABIVERSION]", b"\x00", "0", "ABI version.")
    put("ehdr", "e_ident[EI_PAD]", b"\x00" * 7, "zeros", "Padding to 16 bytes.")
    put("ehdr", "e_type", le("H", e_type), e_type_name,
        "ET_EXEC: map at the stated addresses." if type_id == "exec" else "ET_DYN: the loader may choose the base address.")
    put("ehdr", "e_machine", le("H", arch["e_machine"]), arch["machine_name"], f"The instruction set: {arch['label']}.")
    put("ehdr", "e_version", le("I", 1), "1", "ELF version again.")
    put("ehdr", "e_entry", le("Q", entry), "0x%x" % entry, "Address of the first instruction to run.")
    put("ehdr", "e_phoff", le("Q", 64), "64", "File offset of the program header table: right after this header.")
    put("ehdr", "e_shoff", le("Q", 0), "0", "No section header table.")
    put("ehdr", "e_flags", le("I", 0), "0", "Processor-specific flags: none.")
    put("ehdr", "e_ehsize", le("H", 64), "64", "Size of this header.")
    put("ehdr", "e_phentsize", le("H", 56), "56", "Size of one program header.")
    put("ehdr", "e_phnum", le("H", phnum), str(phnum), "Number of program headers.")
    put("ehdr", "e_shentsize", le("H", 64), "64", "Size of one section header (there are none).")
    put("ehdr", "e_shnum", le("H", 0), "0", "Number of section headers: none.")
    put("ehdr", "e_shstrndx", le("H", 0), "SHN_UNDEF", "No section name table.")
    prot = "".join(ch if p_flags & bit else "-" for ch, bit in (("r", 4), ("w", 2), ("x", 1)))
    put("phdr0", "p_type", le("I", PT_LOAD), "PT_LOAD", "A segment to map into memory.")
    put("phdr0", "p_flags", le("I", p_flags), prot, "Protection of the mapping: PF_R = 4, PF_W = 2, PF_X = 1.")
    put("phdr0", "p_offset", le("Q", 0), "0", "The segment starts at the beginning of the file, headers included.")
    put("phdr0", "p_vaddr", le("Q", base), "0x%x" % base, "Where the first byte of the segment appears in memory.")
    put("phdr0", "p_paddr", le("Q", base), "0x%x" % base, "Physical address; unused on Linux, set like p_vaddr by convention.")
    put("phdr0", "p_filesz", le("Q", total), str(total), "Bytes taken from the file: the whole file.")
    put("phdr0", "p_memsz", le("Q", total), str(total), "Bytes occupied in memory: the same, there is no .bss.")
    put("phdr0", "p_align", le("Q", align), "0x%x" % align, "p_vaddr and p_offset agree modulo this.")
    if gnu_stack:
        sflags = 6 | (1 if stack_exec else 0)
        put("phdr1", "p_type", le("I", PT_GNU_STACK), "PT_GNU_STACK", "No contents; only its flags matter.")
        put("phdr1", "p_flags", le("I", sflags), "rwx" if stack_exec else "rw-",
            "The stack is executable." if stack_exec else "The stack is not executable.")
        for name in ("p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz"):
            put("phdr1", name, le("Q", 0), "0", "Unused for PT_GNU_STACK.")
        put("phdr1", "p_align", le("Q", 16), "16", "Conventional value; not used.")
    for chunk, text in payload["code"]:
        raw = bytes.fromhex(chunk)
        is_data = text.startswith(".")
        put("payload", "0x%x" % (base + len(out)), raw, text, "Data used by the code above." if is_data else "Instruction.")
    if len(out) != total:  # the layout arithmetic above and the emitted bytes must agree
        raise RuntimeError("builder layout mismatch")

    notes: List[Dict[str, str]] = [
        {"level": "info", "text": f"{total} bytes: a 64-byte ELF header, {phnum} program header{'s' if phnum != 1 else ''} of 56 bytes, "
                                  f"and a {len(code)}-byte payload at file offset {payload_off} (0x{payload_off:x})."},
        {"level": "info", "text": "There are no section headers. Loaders work from program headers; sections exist for linkers and debuggers."},
    ]
    seg_end = base + total
    if not entry_custom:
        notes.append({"level": "info", "text": f"e_entry is the payload's first byte: base 0x{base:x} + offset 0x{payload_off:x} = 0x{entry:x}."})
    elif not base <= entry < seg_end:
        notes.append({"level": "warn", "text": f"e_entry 0x{entry:x} is outside the only segment (0x{base:x}..0x{seg_end:x}); "
                                               "the process would fault on its first instruction."})
    elif entry != base + payload_off:
        notes.append({"level": "warn", "text": f"e_entry 0x{entry:x} is inside the segment but not at the payload (0x{base + payload_off:x}); "
                                               "whatever bytes are there would be executed as instructions."})
    if not p_flags & 1:
        notes.append({"level": "warn", "text": "The segment is not executable (no PF_X), so the entry point is in memory the CPU may not execute; "
                                               "the process would fault with SIGSEGV on its first instruction."})
    if not p_flags & 4:
        notes.append({"level": "warn", "text": "The segment is not readable (no PF_R). The code still runs. Whether its bytes can also be read depends on the CPU: "
                                               "Linux makes the mapping execute-only on x86-64 with protection keys and on arm64 with Enhanced PAN, "
                                               "and elsewhere execute permission implies read."})
    if (p_flags & 3) == 3:
        notes.append({"level": "warn", "text": TEXT["elf.segment_wx"]["text"]})
    if type_id == "exec" and base < 0x10000:
        notes.append({"level": "warn", "text": f"Base 0x{base:x} is below the usual vm.mmap_min_addr (65536 on most distributions); "
                                               "there the mapping is refused for a process without CAP_SYS_RAWIO, and the new process is killed with SIGSEGV."})
    if type_id == "dyn":
        notes.append({"level": "info", "text": "As ET_DYN with no PT_INTERP and no dynamic section this is a static PIE without relocations: "
                                               "the kernel adds a random offset to p_vaddr and e_entry. That is only correct because these "
                                               "payloads use no absolute addresses."})
    if gnu_stack and stack_exec:
        notes.append({"level": "warn", "text": TEXT["elf.stack_exec"]["text"]})
    if not gnu_stack:
        notes.append({"level": "info", "text": TEXT["elf.stack_default"]["text"]})
    notes.append({"level": "info", "text": f"Meant for Linux on {arch['label']}. BinaryStudio never runs it; download it to try it on a machine you control."})

    data = bytes(out)
    result: Dict[str, Any] = {
        "format": "elf64", "arch": arch_id, "filename": f"minimal-{arch_id}-{payload_id}.elf", "size": total, "hex": data.hex(),
        "sha256": hashlib.sha256(data).hexdigest(), "regions": regions,
        "groups": [{"id": "ehdr", "label": "ELF header", "offset": 0, "size": 64},
                   {"id": "phdr0", "label": "Program header 0 (PT_LOAD)", "offset": 64, "size": 56}]
        + ([{"id": "phdr1", "label": "Program header 1 (PT_GNU_STACK)", "offset": 120, "size": 56}] if gnu_stack else [])
        + [{"id": "payload", "label": f"Payload: {payload['label']}", "offset": payload_off, "size": len(code)}],
        "entry": "0x%x" % entry, "base": "0x%x" % base, "payload_offset": payload_off, "payload_about": payload["about"],
        "notes": notes,
    }
    # Read the result back with the project's own parser: the builder and the parser were
    # written independently, so agreement is evidence that the bytes mean what the form says.
    try:
        parsed = parse_macho_bytes(data, path=result["filename"])
        sl = parsed["slices"][0]
        segs = sl.get("segments") or []
        result["verify"] = {
            "ok": True, "format": parsed["file_info"].get("format_display"), "type": (sl.get("header") or {}).get("filetype_name"),
            "machine": (sl.get("header") or {}).get("cputype_name"), "entry": (sl.get("entry_point") or {}).get("vmaddr"),
            "segments": [{"vmaddr": s.get("vmaddr"), "filesize": s.get("filesize"), "prot": s.get("initprot")} for s in segs],
            "warnings": [str(w.get("message")) for w in sl.get("warnings") or []],
        }
    except ValueError as exc:
        result["verify"] = {"ok": False, "error": _clean_text(str(exc), 300)}
    return result


# ============================================================================
# Routes
# ============================================================================
def register_labs_patch_routes(router: ApiRouter) -> None:
    service = router.service
    config = router.config
    upload_rate = float(config.upload_rate_limit_per_minute or 0)
    patch_limiter = TokenBucketLimiter(upload_rate * PATCH_RATE_FACTOR, 0, config.rate_limiter_max_clients)

    def charge(req: ApiRequest, cost: float) -> None:
        allowed, retry = patch_limiter.allow(req.client_id, cost)
        if not allowed:
            raise RateLimited("Too many patches in a short time. Wait a moment and try again.",
                              headers={"Retry-After": str(max(1, int(retry + 0.999)))})

    def analysis_cost(size: int) -> float:
        return 1.0 + size // COST_UNIT_BYTES

    def need_patch() -> None:
        if not config.allow_patch:
            raise Forbidden("Patching is disabled on this server.")

    def body_doc(body: Dict[str, Any], req: Optional[ApiRequest] = None) -> DocEntry:
        # The id travels in the JSON body; the X-BS-Doc header (which the router has
        # already folded into the query) is accepted too.
        doc_id = body.get("doc") or (req.query.get("doc") if req is not None else None)
        if not isinstance(doc_id, str) or not doc_id:
            raise BadRequest("Missing required 'doc'.")
        return service.get_entry(doc=doc_id)

    def patch(req: ApiRequest) -> ApiResponse:
        need_patch()
        body = req.json()
        # Paid before any work is done for this request, whatever it turns out to be.
        charge(req, 1.0)
        parent = body_doc(body, req)
        patches = parse_patches(body.get("patches"), len(parent.data), int(config.max_patch_bytes))
        new_data = apply_patches(parent.data, patches)
        patches = squash_patches(parent.data, patches)
        normalized = [{"offset": p["offset"], "hex": p["data"].hex(), "label": p["label"],
                       "before": parent.data[p["offset"]:p["offset"] + len(p["data"])].hex()} for p in patches]
        if new_data == parent.data:
            # Nothing changed, so there is no new document and none is sent: the caller
            # holds the parent already, and its JSON can be tens of megabytes.
            diff = diff_documents(parent.doc, parent.data, parent.doc, parent.data, "patch", patches)
            return ApiResponse.json({"doc_id": parent.doc_id, "parent": parent.doc_id, "identical": True,
                                     "patches": normalized, "diff": diff})
        # The analysis of the patched copy, in proportion to its size (the token above
        # was the first of these).
        extra = analysis_cost(len(parent.data)) - 1.0
        if extra > 0:
            charge(req, extra)

        def pay(size: int) -> bool:
            return patch_limiter.allow(req.client_id, analysis_cost(size))[0]

        derived, error = make_derived(service, parent, new_data, req.client_id, patches, pay)
        try:
            diff = diff_documents(parent.doc, parent.data, derived.doc, derived.data, "patch", patches, parse_error=error)
            envelope = {"doc_id": derived.doc_id, "parent": parent.doc_id, "identical": False, "patches": normalized, "diff": diff}
            response = ApiResponse.document(derived, envelope)
        except BaseException:
            # The caller will never learn this document's id; do not keep it.
            service.store.remove(derived.doc_id)
            raise
        replace = body.get("replace")
        if isinstance(replace, str) and replace.startswith("p_") and replace not in (derived.doc_id, parent.doc_id):
            # Holding the id of a derived document is the capability to drop it; the
            # client names the copy this one supersedes so the cache does not fill with stale ones.
            if len(replace) == 34 and all(ch in "0123456789abcdef" for ch in replace[2:]):
                service.store.remove(replace)
        return response

    def download(req: ApiRequest) -> ApiResponse:
        if not config.allow_download:
            raise Forbidden("Downloads are disabled on this server.")
        doc = str_param(req.query, "doc")
        path = str_param(req.query, "path")
        if path is not None and not config.allow_path_load:
            raise Forbidden("Loading files by server path is not available on this server.")
        if not doc and not path:
            raise BadRequest("Missing required 'doc' parameter.")
        entry = service.get_entry(doc=doc or None, path=path or None)
        response = ApiResponse.binary(entry.data, entry.filename)
        response.etag = entry.data_etag()
        return response

    def resolve(req: ApiRequest) -> Dict[str, Any]:
        need_patch()
        body = req.json()
        entry = body_doc(body, req)
        op = body.get("op")
        if not isinstance(op, dict):
            raise BadRequest("Missing 'op'.")
        kind = op.get("kind")
        if kind not in ("field", "flag", "fill", "experiment"):
            raise BadRequest("Unknown op kind; use field, flag, fill or experiment.")
        if kind == "experiment" and str(op.get("id")) not in _EXPERIMENTS_BY_ID:
            raise BadRequest("Unknown experiment.")
        slice_index = _as_int(body.get("slice_index")) or 0
        # An edit that cannot be made (a value that does not fit, no such field, an
        # experiment that does not apply) is an answer about the document, not a failed
        # request: 200 with ok=false and the reason, so a typo is not an HTTP error.
        try:
            if kind in ("field", "flag"):
                changes = resolve_field_op(entry.doc, entry.data, op)
            elif kind == "fill":
                changes = resolve_fill_op(entry.data, op, int(config.max_patch_bytes))
            else:
                changes = resolve_experiment(str(op.get("id")), entry.doc, entry.data, max(0, slice_index))
        except NotApplicable as exc:
            return {"ok": False, "error": str(exc), "patches": [], "changes": []}
        except (BadRequest, TooLarge) as exc:
            return {"ok": False, "error": exc.message, "patches": [], "changes": []}
        return {"ok": True, "patches": [{"offset": c["offset"], "hex": c["hex"], "label": c["label"]} for c in changes], "changes": changes}

    def experiments(req: ApiRequest) -> Dict[str, Any]:
        doc = str_param(req.query, "doc")
        if not doc:
            return experiment_catalogue(None, b"", 0)
        entry = service.get_entry(doc=doc)
        return experiment_catalogue(entry.doc, entry.data, int_param(req.query, "slice_index", 0, 0, 1 << 20))

    def compare(req: ApiRequest) -> Dict[str, Any]:
        a, b = str_param(req.query, "a"), str_param(req.query, "b")
        if not a or not b:
            raise BadRequest("Both 'a' and 'b' are required.")
        first, second = service.get_entry(doc=a), service.get_entry(doc=b)
        return {"diff": diff_documents(first.doc, first.data, second.doc, second.data, "compare")}

    def options(req: ApiRequest) -> Dict[str, Any]:
        return build_options()

    def build(req: ApiRequest) -> Dict[str, Any]:
        body = req.json()
        if str(body.get("format") or "elf64") != "elf64":
            raise BadRequest("Only the elf64 builder exists.")
        # A form value the builder cannot use is reported in the answer (the form is
        # rebuilt on every keystroke); only a malformed request is an HTTP error.
        try:
            return dict(build_minimal_elf(body), ok=True)
        except BadRequest as exc:
            return {"ok": False, "error": exc.message}

    router.register("POST", "/api/patch", patch)
    router.register("GET", "/api/download", download)
    router.register("POST", "/api/labs/resolve", resolve, max_body=64 * 1024)
    router.register("GET", "/api/labs/experiments", experiments)
    router.register("GET", "/api/labs/compare", compare)
    router.register("GET", "/api/labs/build/options", options)
    router.register("POST", "/api/labs/build", build, max_body=16 * 1024)
