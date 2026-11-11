"""
LC_CODE_SIGNATURE SuperBlob, CodeDirectory Live Hash Verifier, XML & ASN.1 DER Entitlements,
and CMS/PKCS#7 Certificate Chain Extractor.
"""

import datetime
import hashlib
import plistlib
import re
from typing import Any, Dict, List, Optional, Tuple

from . import runtime
from .buffer import BinaryBuffer, add_warning, make_region
from .constants import (
    ANALYSIS_LIMITS,
    CS_FLAGS,
    CS_HASHTYPES,
    CS_MAGIC_NAMES,
    CS_SLOT_NAMES,
    CS_SPECIAL_SLOT_NAMES,
    CSMAGIC_BLOBWRAPPER,
    CSMAGIC_CODEDIRECTORY,
    CSMAGIC_EMBEDDED_DER_ENTITLEMENTS,
    CSMAGIC_EMBEDDED_ENTITLEMENTS,
    CSMAGIC_EMBEDDED_SIGNATURE,
    CSMAGIC_EMBEDDED_SIGNATURE_OLD,
    CSSLOT_ALTERNATE_CODEDIRECTORIES,
    CSSLOT_CODEDIRECTORY,
    CSSLOT_DER_ENTITLEMENTS,
    CSSLOT_ENTITLEMENTS,
    CSSLOT_INFOSLOT,
    CSSLOT_REQUIREMENTS,
    CSSLOT_RESOURCEDIR,
    CSSLOT_SIGNATURESLOT,
)


ENTITLEMENT_RISK_RULES: Dict[str, Tuple[str, str]] = {
    "com.apple.security.get-task-allow": (
        "HIGH",
        "Allows debugger attachment and task_for_pid() inspection",
    ),
    "get-task-allow": (
        "HIGH",
        "iOS/macOS debugger & task port access entitlement",
    ),
    "task_for_pid-allow": (
        "HIGH",
        "Permits controlling other processes via task_for_pid()",
    ),
    "com.apple.security.cs.allow-jit": (
        "MEDIUM",
        "Allows creating writable and executable (MAP_JIT) memory pages",
    ),
    "com.apple.security.cs.allow-unsigned-executable-memory": (
        "HIGH",
        "Disables code signing page enforcement for anonymous executable memory",
    ),
    "com.apple.security.cs.disable-library-validation": (
        "HIGH",
        "Allows loading plug-ins or dylibs signed by arbitrary third-party teams",
    ),
    "com.apple.security.cs.allow-dyld-environment-variables": (
        "HIGH",
        "Allows DYLD_INSERT_LIBRARIES and other dyld environment variables",
    ),
    "com.apple.security.cs.debugger": (
        "HIGH",
        "Grants system-level debugger privileges",
    ),
    "platform-application": (
        "MEDIUM",
        "Marks binary as an Apple platform trust-cache application",
    ),
    "com.apple.private.security.no-sandbox": (
        "HIGH",
        "Exempts process from App Sandbox enforcement",
    ),
    "com.apple.private.skip-library-validation": (
        "HIGH",
        "Private entitlement bypassing library validation",
    ),
}


def _classify_entitlement_risk(key: str, val: Any) -> Tuple[str, str]:
    if key in ENTITLEMENT_RISK_RULES:
        risk, reason = ENTITLEMENT_RISK_RULES[key]
        if val is False:
            return "LOW", f"Disabled ({reason})"
        return risk, reason
    if key.startswith("com.apple.private."):
        return "MEDIUM", "Apple private/internal system entitlement"
    if key.startswith("com.apple.rootless."):
        return "HIGH", "System Integrity Protection (SIP) privilege entitlement"
    if key == "com.apple.security.app-sandbox" and val is True:
        return "INFO", "Enables macOS App Sandbox containment"
    return "LOW", "Standard application capability entitlement"


def _compute_digest(data: bytes, hash_type: int) -> bytes:
    if hash_type == 1:
        return hashlib.sha1(data).digest()
    elif hash_type == 2:
        return hashlib.sha256(data).digest()
    elif hash_type == 3:
        return hashlib.sha256(data).digest()[:20]
    elif hash_type == 4:
        return hashlib.sha384(data).digest()
    elif hash_type == 5:
        return hashlib.sha512(data).digest()
    return hashlib.sha256(data).digest()


def _decode_cs_flags(flags: int) -> Tuple[List[str], List[Dict[str, Any]]]:
    names = []
    bits = []
    for mask, name, desc in CS_FLAGS:
        is_set = bool(flags & mask)
        if is_set:
            names.append(name)
        bits.append({
            "name": name,
            "mask": f"0x{mask:08x}",
            "set": is_set,
            "description": desc,
        })
    return names, bits


# ============================================================================
# Lightweight ASN.1 DER Decoder for DER Entitlements (0xfade7172) & CMS Certs
# ============================================================================
def _read_asn1_length(data: bytes, pos: int) -> Tuple[int, int]:
    if pos >= len(data):
        return 0, pos
    first = data[pos]
    pos += 1
    if (first & 0x80) == 0:
        return first, pos
    num_bytes = first & 0x7F
    if num_bytes == 0 or pos + num_bytes > len(data):
        return 0, pos
    length = int.from_bytes(data[pos : pos + num_bytes], "big")
    return length, pos + num_bytes


def _parse_der_entitlements_node(data: bytes, pos: int, end: int, depth: int = 0) -> Tuple[Any, int]:
    if pos >= end or pos >= len(data):
        return None, end
    if depth > ANALYSIS_LIMITS["der_depth"]:
        # Too deeply nested to be a real entitlements blob; stop descending.
        return None, end
    tag = data[pos]
    pos += 1
    length, pos = _read_asn1_length(data, pos)
    content_end = min(end, pos + length)
    content = data[pos:content_end]

    # Universal tags
    if tag == 0x01:  # BOOLEAN
        return (bool(content[0]) if content else False), content_end
    elif tag == 0x02:  # INTEGER
        if len(content) > 8:
            # Not a plausible entitlement value; a multi-KB integer would also be
            # quadratic to render as decimal.
            return content[:64].hex(), content_end
        return int.from_bytes(content, "big", signed=True), content_end
    elif tag in (0x0C, 0x13, 0x16, 0x1E):  # UTF8String, PrintableString, IA5String
        return content.decode("utf-8", errors="replace"), content_end
    elif tag == 0x04:  # OCTET STRING
        return content.hex(), content_end
    elif tag in (0x30, 0x31) or (tag & 0x20):  # SEQUENCE, SET, or Constructed context tag
        items = []
        sub_pos = pos
        while sub_pos < content_end:
            runtime.check_deadline()
            val, next_pos = _parse_der_entitlements_node(data, sub_pos, content_end, depth + 1)
            if next_pos <= sub_pos:
                break
            items.append(val)
            sub_pos = next_pos
        # Check if this is a key-value pair [str, any] or dictionary of pairs
        if (
            len(items) == 2
            and isinstance(items[0], str)
            and tag == 0x30
        ):
            return (items[0], items[1]), content_end
        if all(isinstance(x, tuple) and len(x) == 2 and isinstance(x[0], str) for x in items) and items:
            return {k: v for k, v in items}, content_end
        return items, content_end

    return content.hex(), content_end


def _json_safe(value: Any) -> Tuple[Any, bool]:
    """
    Converts a decoded plist / DER value into JSON-safe data (bytes -> hex,
    datetime -> ISO string, tuples -> lists), bounded in depth and node count.
    Iterative, so hostile nesting cannot hit the recursion limit (or overflow
    the much smaller WASM stack). Returns (value, was_truncated).
    """
    max_depth = ANALYSIS_LIMITS["plist_depth"]
    budget = [ANALYSIS_LIMITS["plist_nodes"]]
    truncated = [False]

    def leaf(v: Any) -> Any:
        if isinstance(v, bool) or v is None:
            return v
        if isinstance(v, int):
            if -(1 << 63) <= v < (1 << 64):
                return v
            truncated[0] = True
            return f"0x{v & ((1 << 256) - 1):x}"[:80]
        if isinstance(v, float):
            return v if v == v and v not in (float("inf"), float("-inf")) else str(v)
        if isinstance(v, (bytes, bytearray)):
            return bytes(v[:4096]).hex()
        if isinstance(v, (datetime.datetime, datetime.date)):
            return v.isoformat()
        if isinstance(v, str):
            return v
        return str(v)[:4096]

    root_holder: List[Any] = [None]
    # (source, depth, container, key_or_index)
    stack: List[Tuple[Any, int, Any, Any]] = [(value, 0, root_holder, 0)]
    while stack:
        src, depth, parent, key = stack.pop()
        budget[0] -= 1
        if budget[0] < 0:
            truncated[0] = True
            parent[key] = None
            continue
        if isinstance(src, dict):
            if depth >= max_depth:
                truncated[0] = True
                parent[key] = {}
                continue
            out: Dict[str, Any] = {}
            parent[key] = out
            for k, v in src.items():
                ks = k if isinstance(k, str) else str(k)
                out[ks] = None
                stack.append((v, depth + 1, out, ks))
        elif isinstance(src, (list, tuple)):
            if depth >= max_depth:
                truncated[0] = True
                parent[key] = []
                continue
            out_list: List[Any] = [None] * len(src)
            parent[key] = out_list
            for i, v in enumerate(src):
                stack.append((v, depth + 1, out_list, i))
        else:
            parent[key] = leaf(src)
    return root_holder[0], truncated[0]


_HUGE_PLIST_INTEGER = re.compile(rb"<integer>\s*[-+]?\d{40}")
_PLIST_CONTAINER_TAG = re.compile(rb"<(/?)(?:array|dict)\s*(/?)>")
# plistlib builds arbitrarily deep nesting iteratively, but freeing a container nested a few
# thousand levels deep recurses in C. Under Pyodide (WASM) that overflows the JS stack and kills
# the interpreter (measured: fatal at 5000 levels, fine at 4500, Pyodide 314.0.7), so refuse
# deep documents before building them. Real entitlements nest a handful of levels.
_MAX_PLIST_PARSE_DEPTH = 256


def _plist_too_deep(xml_bytes: bytes, limit: int = _MAX_PLIST_PARSE_DEPTH) -> bool:
    depth = 0
    for m in _PLIST_CONTAINER_TAG.finditer(xml_bytes):
        if m.group(2):  # <array/>, <dict/>
            continue
        depth += -1 if m.group(1) else 1
        if depth > limit:
            return True
    return False


def _load_entitlements_plist(xml_bytes: bytes) -> Dict[str, Any]:
    """XML plist only (entitlements are XML); binary plists are not attempted."""
    head = xml_bytes[:64].lstrip()
    if not (head.startswith(b"<?xml") or head.startswith(b"<plist") or head.startswith(b"<!DOCTYPE")):
        return {}
    if _HUGE_PLIST_INTEGER.search(xml_bytes):
        # Decimal -> int conversion is quadratic in CPython 3.9; no real
        # entitlement holds a 40-digit integer.
        return {}
    if _plist_too_deep(xml_bytes):
        return {}
    try:
        # plistlib refuses XML entity declarations, so entity-expansion bombs fail here.
        parsed = plistlib.loads(xml_bytes)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _entitlements_decodable(payload: bytes, warnings: List[Dict[str, Any]]) -> bool:
    """Whether an entitlements blob (XML or DER) may be decoded: it must be within
    the per-blob limit, and the file as a whole within its entitlement budget.
    Decoding costs up to half a second per megabyte and cannot be interrupted;
    real entitlements are a few kilobytes."""
    size = len(payload)
    limit = ANALYSIS_LIMITS["entitlements_bytes"]
    if size > limit:
        add_warning(warnings, "entitlements_too_large", f"A {size:,}-byte entitlements blob exceeds the {limit:,}-byte analysis limit and was not decoded.", limit=limit)
        return False
    budget = ANALYSIS_LIMITS["entitlements_file_bytes"]
    if not runtime.spend_budget("entitlements_file_bytes", size, budget):
        add_warning(warnings, "entitlements_budget_exceeded", f"This file holds more than {budget:,} bytes of entitlements across its slices; the remaining blobs were not decoded.", limit=budget)
        return False
    return True


def decode_der_entitlements(der_payload: bytes) -> Dict[str, Any]:
    """Decodes Apple's CE (CoreEntitlements) ASN.1 DER blob into a dictionary."""
    try:
        parsed, _ = _parse_der_entitlements_node(der_payload, 0, len(der_payload))
        if isinstance(parsed, list):
            for elem in parsed:
                if isinstance(elem, dict):
                    return elem
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return {}


# ============================================================================
# Lightweight X.509 / CMS Certificate Subject & Issuer Extractor
# ============================================================================
# OIDs in DER bytes:
OID_COMMON_NAME = b"\x06\x03\x55\x04\x03"        # 2.5.4.3 (CN)
OID_ORG_NAME = b"\x06\x03\x55\x04\x0a"           # 2.5.4.10 (O)
OID_ORG_UNIT_NAME = b"\x06\x03\x55\x04\x0b"      # 2.5.4.11 (OU)


def _extract_oid_strings(der_bytes: bytes, oid_pattern: bytes) -> List[str]:
    results: List[str] = []
    start = 0
    limit = ANALYSIS_LIMITS["cert_names"]
    # A blob can repeat the OID every few bytes without ever following it with a
    # string, so the occurrences examined are bounded too, not only the names kept.
    candidates = ANALYSIS_LIMITS["cert_name_candidates"]
    while len(results) < limit and candidates > 0:
        candidates -= 1
        runtime.check_deadline()
        idx = der_bytes.find(oid_pattern, start)
        if idx == -1:
            break
        val_pos = idx + len(oid_pattern)
        if val_pos + 2 <= len(der_bytes):
            str_tag = der_bytes[val_pos]
            if str_tag in (0x0C, 0x13, 0x14, 0x16, 0x1E):
                str_len, content_start = _read_asn1_length(der_bytes, val_pos + 1)
                if 0 < str_len <= 256 and content_start + str_len <= len(der_bytes):
                    raw_s = der_bytes[content_start : content_start + str_len]
                    if str_tag == 0x1E:
                        s = raw_s.decode("utf-16-be", errors="replace")
                    else:
                        s = raw_s.decode("utf-8", errors="replace")
                    s = s.strip()
                    if s:
                        results.append(s)
        start = idx + len(oid_pattern)
    return results


def parse_cms_certificates(cms_bytes: bytes) -> List[Dict[str, str]]:
    """
    Extracts certificate Subject CN, Issuer CN, and Organization from a CMS/PKCS#7 signature blob.
    In X.509 certificates embedded in CMS SignedData, each certificate has Issuer followed by Subject.
    """
    if not cms_bytes or len(cms_bytes) < 32:
        return []
    cms_bytes = cms_bytes[: ANALYSIS_LIMITS["cms_bytes"]]
    cns = _extract_oid_strings(cms_bytes, OID_COMMON_NAME)
    orgs = _extract_oid_strings(cms_bytes, OID_ORG_NAME)

    certs: List[Dict[str, str]] = []
    # In each X.509 TBSCertificate, Issuer CN appears first, Subject CN appears second.
    if len(cns) >= 2:
        for i in range(0, len(cns) - 1, 2):
            issuer_cn = cns[i]
            subject_cn = cns[i + 1]
            if len(orgs) == len(cns):
                org = orgs[i + 1]  # names are aligned: the subject's O
            else:
                org = orgs[i // 2] if (i // 2) < len(orgs) else (orgs[0] if orgs else "Apple Inc.")
            # Avoid duplicate cert entries
            if not any(c["subject_cn"] == subject_cn and c["issuer_cn"] == issuer_cn for c in certs):
                certs.append({
                    "subject_cn": subject_cn,
                    "issuer_cn": issuer_cn,
                    "org": org,
                })
    elif len(cns) == 1:
        certs.append({
            "subject_cn": cns[0],
            "issuer_cn": cns[0],
            "org": orgs[0] if orgs else "",
        })
    return _order_chain(certs)


def _order_chain(certs: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    CMS stores certificates in no particular order (Apple's are intermediate,
    root, leaf). Return them leaf first, then each issuer, the way `codesign -dv`
    lists Authority= lines, so certs[0] is the actual signer.
    """
    if len(certs) < 2:
        return certs
    issuers = {c["issuer_cn"] for c in certs if c["issuer_cn"] != c["subject_cn"]}
    leaves = [c for c in certs if c["subject_cn"] not in issuers]
    if not leaves:
        return certs
    ordered: List[Dict[str, str]] = []
    current: Optional[Dict[str, str]] = leaves[0]
    while current is not None and current not in ordered:
        ordered.append(current)
        if current["issuer_cn"] == current["subject_cn"]:
            break
        current = next((c for c in certs if c["subject_cn"] == current["issuer_cn"] and c not in ordered), None)
    ordered.extend(c for c in certs if c not in ordered)
    return ordered


# ============================================================================
# Main LC_CODE_SIGNATURE Parser
# ============================================================================
def parse_code_signature(
    slice_buf: BinaryBuffer, dataoff: int, datasize: int,
    warnings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Parses the embedded CS_SuperBlob at `dataoff` (relative to slice_buf) of length `datasize`.
    All Code Signature structures are Big-Endian (`>`).
    """
    if warnings is None:
        warnings = []
    if datasize < 8 or dataoff + 8 > slice_buf.slice_size:
        if datasize > 0:
            add_warning(warnings, "code_signature_out_of_range", "LC_CODE_SIGNATURE points outside the file; signature not shown.")
        return {
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
            "cms_signature": {"present": False, "is_adhoc": True, "size": 0, "certificates": []},
        }

    cs_buf = slice_buf.clone_with_fields(little_endian=False)
    magic = cs_buf.u32(dataoff, ">")
    length = cs_buf.u32(dataoff + 4, ">")
    magic_name = CS_MAGIC_NAMES.get(magic, f"0x{magic:08x}")

    cs_buf.record_field(
        "magic",
        "uint32",
        dataoff,
        4,
        magic,
        f"0x{magic:08x}",
        magic_name,
        "Code Signature SuperBlob magic number (Big-Endian)",
    )
    cs_buf.record_field(
        "length",
        "uint32",
        dataoff + 4,
        4,
        length,
        f"{length} (0x{length:x})",
        f"{length:,} bytes",
        "Total byte length of SuperBlob",
    )

    blobs: List[Dict[str, Any]] = []
    slot_raw_blobs: Dict[int, bytes] = {}
    code_directories: List[Tuple[int, int, int]] = []  # (slot_type, blob_slice_off, blob_len)

    entitlements_xml = ""
    entitlements_dict: Dict[str, Any] = {}
    der_entitlements_dict: Dict[str, Any] = {}
    cms_signature_info: Dict[str, Any] = {
        "present": False,
        "is_adhoc": True,
        "size": 0,
        "certificates": [],
    }

    if magic in (CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_EMBEDDED_SIGNATURE_OLD) and datasize >= 12:
        count = cs_buf.u32(dataoff + 8, ">")
        cs_buf.record_field(
            "count",
            "uint32",
            dataoff + 8,
            4,
            count,
            str(count),
            f"{count} sub-blobs",
            "Number of CS_BlobIndex entries in SuperBlob",
        )
        max_count = min(count, ANALYSIS_LIMITS["cs_blobs"])
        if count > max_count:
            add_warning(warnings, "cs_blobs_truncated", f"SuperBlob declares {count:,} sub-blobs; only the first {max_count} are read.", limit=max_count, total=count)
        blob_limit = ANALYSIS_LIMITS["cs_blob_bytes"]
        # Index entries are free to name the same sub-blob again and again (64 entries
        # that all point at one megabyte of plist used to cost 64 plist parses, per
        # slice). Each distinct (offset, length) is therefore read once and decoded
        # once per interpretation, and what is read counts against a budget for this
        # signature and one for the whole file (all slices; see runtime.work_budgets).
        read_blobs: Dict[Tuple[int, int], bytes] = {}
        decoded_once: set = set()
        signature_budget = ANALYSIS_LIMITS["cs_signature_bytes"]
        budget_warned = False
        for i in range(max_count):
            runtime.check_deadline()
            idx_off = dataoff + 12 + i * 8
            if idx_off + 8 > dataoff + datasize:
                break
            slot_type = cs_buf.u32(idx_off, ">")
            blob_rel_off = cs_buf.u32(idx_off + 4, ">")
            blob_slice_off = dataoff + blob_rel_off

            slot_name = CS_SLOT_NAMES.get(
                slot_type,
                f"CSSLOT_ALT_CODEDIRECTORY_{slot_type - 0x1000}"
                if 0x1000 <= slot_type < 0x1010
                else f"CSSLOT_0x{slot_type:x}",
            )
            cs_buf.record_field(
                f"index[{i}].type",
                "uint32",
                idx_off,
                4,
                slot_type,
                f"0x{slot_type:x}",
                slot_name,
                f"Sub-blob #{i} slot type",
            )
            cs_buf.record_field(
                f"index[{i}].offset",
                "uint32",
                idx_off + 4,
                4,
                blob_rel_off,
                f"0x{blob_rel_off:x}",
                f"Slice offset 0x{blob_slice_off:x} (abs 0x{cs_buf.slice_base + blob_slice_off:x})",
                f"Sub-blob #{i} offset relative to SuperBlob",
                target_offset=cs_buf.slice_base + blob_slice_off,
            )

            if blob_slice_off + 8 <= slice_buf.slice_size:
                b_magic = cs_buf.u32(blob_slice_off, ">")
                b_len = cs_buf.u32(blob_slice_off + 4, ">")
                b_magic_name = CS_MAGIC_NAMES.get(b_magic, f"0x{b_magic:08x}")
                # b_len comes from the file: clamp to the bytes that exist and only
                # materialise the blob kinds that are hashed or decoded below.
                avail = max(0, slice_buf.slice_size - blob_slice_off)
                needs_bytes = (
                    b_magic in (CSMAGIC_EMBEDDED_ENTITLEMENTS, CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, CSMAGIC_BLOBWRAPPER)
                    or slot_type in (CSSLOT_REQUIREMENTS, CSSLOT_ENTITLEMENTS, CSSLOT_DER_ENTITLEMENTS, CSSLOT_SIGNATURESLOT)
                )
                read_len = min(b_len, avail)
                cap = ANALYSIS_LIMITS["cms_bytes"] if (b_magic == CSMAGIC_BLOBWRAPPER or slot_type == CSSLOT_SIGNATURESLOT) else blob_limit
                if needs_bytes and read_len > cap:
                    add_warning(warnings, "cs_blob_too_large", f"A {read_len:,}-byte code-signature sub-blob exceeds the {cap:,}-byte analysis limit and was not decoded.", limit=cap)
                    needs_bytes = False
                blob_key = (blob_slice_off, read_len)
                if needs_bytes and blob_key not in read_blobs:
                    if signature_budget < read_len or not runtime.spend_budget(
                            "cs_file_bytes", read_len, ANALYSIS_LIMITS["cs_file_bytes"]):
                        if not budget_warned:
                            budget_warned = True
                            add_warning(warnings, "cs_budget_exceeded", "The code-signature sub-blobs of this file add up to more than the analysis budget; the remaining ones were not decoded.", limit=ANALYSIS_LIMITS["cs_file_bytes"])
                        needs_bytes = False
                    else:
                        signature_budget -= read_len
                        read_blobs[blob_key] = cs_buf.read_bytes(blob_slice_off, read_len)
                raw_blob = read_blobs[blob_key] if needs_bytes else b""
                if needs_bytes and slot_type in (CSSLOT_REQUIREMENTS, CSSLOT_ENTITLEMENTS, CSSLOT_DER_ENTITLEMENTS):
                    slot_raw_blobs[slot_type] = raw_blob

                blobs.append({
                    "index": i,
                    "type": slot_type,
                    "type_name": slot_name,
                    "magic": f"0x{b_magic:08x}",
                    "magic_name": b_magic_name,
                    "abs_offset": cs_buf.slice_base + blob_slice_off,
                    "slice_offset": blob_slice_off,
                    "size": b_len,
                })

                if b_magic == CSMAGIC_CODEDIRECTORY:
                    if len(code_directories) < ANALYSIS_LIMITS["cs_blobs"] and (slot_type, blob_slice_off, b_len) not in code_directories:
                        code_directories.append((slot_type, blob_slice_off, b_len))
                elif b_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS or slot_type == CSSLOT_ENTITLEMENTS:
                    if ("xml", blob_key) in decoded_once:
                        continue  # the same bytes, already decoded this way
                    decoded_once.add(("xml", blob_key))
                    xml_bytes = raw_blob[8:] if len(raw_blob) >= 8 else b""
                    entitlements_xml = xml_bytes.decode("utf-8", errors="replace").strip()
                    if _plist_too_deep(xml_bytes):   # a linear scan; such a plist is never built
                        add_warning(warnings, "entitlements_truncated", "Entitlements are nested or sized beyond the analysis limits; deeper values are omitted.")
                        entitlements_dict = {}
                    elif _entitlements_decodable(xml_bytes, warnings):
                        entitlements_dict = _load_entitlements_plist(xml_bytes)
                    else:
                        entitlements_dict = {}
                elif (
                    b_magic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS
                    or slot_type == CSSLOT_DER_ENTITLEMENTS
                ):
                    if ("der", blob_key) in decoded_once:
                        continue
                    decoded_once.add(("der", blob_key))
                    der_bytes = raw_blob[8:] if len(raw_blob) >= 8 else b""
                    der_entitlements_dict = decode_der_entitlements(der_bytes) if _entitlements_decodable(der_bytes, warnings) else {}
                elif b_magic == CSMAGIC_BLOBWRAPPER or slot_type == CSSLOT_SIGNATURESLOT:
                    if ("cms", blob_key) in decoded_once:
                        continue
                    decoded_once.add(("cms", blob_key))
                    cms_payload = raw_blob[8:] if len(raw_blob) >= 8 else b""
                    certs = parse_cms_certificates(cms_payload)
                    cms_signature_info = {
                        "present": len(cms_payload) > 0,
                        "is_adhoc": len(cms_payload) == 0,
                        "size": len(cms_payload),
                        "certificates": certs,
                    }

    # Merge DER entitlements if XML was absent
    if not entitlements_dict and der_entitlements_dict:
        entitlements_dict = der_entitlements_dict
    if entitlements_dict:
        safe, was_truncated = _json_safe(entitlements_dict)
        entitlements_dict = safe if isinstance(safe, dict) else {}
        if was_truncated:
            add_warning(warnings, "entitlements_truncated", "Entitlements are nested or sized beyond the analysis limits; deeper values are omitted.")

    entitlements_entries: List[Dict[str, Any]] = []
    for k, v in entitlements_dict.items():
        risk, reason = _classify_entitlement_risk(k, v)
        val_type = (
            "boolean"
            if isinstance(v, bool)
            else "integer"
            if isinstance(v, int)
            else "array"
            if isinstance(v, list)
            else "dict"
            if isinstance(v, dict)
            else "string"
        )
        entitlements_entries.append({
            "key": k,
            "value": v,
            "type": val_type,
            "risk": risk,
            "reason": reason,
        })

    # Choose best CodeDirectory (prefer SHA-256 if multiple exist, or primary slot 0)
    cd_detail: Optional[Dict[str, Any]] = None
    if code_directories:
        chosen_cd = code_directories[0]
        for cd_candidate in code_directories:
            _, c_off, c_len = cd_candidate
            if c_len >= 44:
                ht = cs_buf.u8(c_off + 36)
                if ht == 2:  # SHA-256
                    chosen_cd = cd_candidate
                    break
        cd_detail = _parse_code_directory(
            slice_buf, chosen_cd[1], chosen_cd[2], slot_raw_blobs
        )
        if cd_detail and not (cd_detail.get("flags_int", 0) & 0x2) and cms_signature_info["present"]:
            cms_signature_info["is_adhoc"] = False

    return {
        "present": True,
        "superblob_region": make_region(
            slice_buf.slice_base + dataoff, dataoff, datasize
        ),
        "magic": f"0x{magic:08x}",
        "length": length,
        "blob_count": len(blobs),
        "fields": cs_buf.get_fields(),
        "blobs": blobs,
        "code_directory": cd_detail,
        "entitlements_xml": entitlements_xml,
        "entitlements_dict": entitlements_dict,
        "entitlements_entries": entitlements_entries,
        "cms_signature": cms_signature_info,
    }


def _parse_code_directory(
    slice_buf: BinaryBuffer,
    cd_off: int,
    cd_len: int,
    slot_raw_blobs: Dict[int, bytes],
) -> Optional[Dict[str, Any]]:
    if cd_len < 44:
        return None

    cd_buf = slice_buf.clone_with_fields(little_endian=False)
    magic = cd_buf.u32(cd_off, ">")
    length = cd_buf.u32(cd_off + 4, ">")
    version = cd_buf.u32(cd_off + 8, ">")
    flags = cd_buf.u32(cd_off + 12, ">")
    hash_offset = cd_buf.u32(cd_off + 16, ">")
    ident_offset = cd_buf.u32(cd_off + 20, ">")
    n_special_slots = cd_buf.u32(cd_off + 24, ">")
    n_code_slots = cd_buf.u32(cd_off + 28, ">")
    code_limit = cd_buf.u32(cd_off + 32, ">")
    hash_size = cd_buf.u8(cd_off + 36)
    hash_type = cd_buf.u8(cd_off + 37)
    platform = cd_buf.u8(cd_off + 38)
    page_size_shift = cd_buf.u8(cd_off + 39)
    page_size = (1 << page_size_shift) if page_size_shift < 32 else 4096
    spare2 = cd_buf.u32(cd_off + 40, ">")

    flags_decoded, flags_bit_list = _decode_cs_flags(flags)
    hash_type_name = CS_HASHTYPES.get(hash_type, f"HashType({hash_type})")

    ident_str, _ = (
        cd_buf.cstr_at(cd_off + ident_offset, 512) if ident_offset < cd_len else ("", 0)
    )

    cd_buf.record_field("magic", "uint32", cd_off, 4, magic, f"0x{magic:08x}", "CSMAGIC_CODEDIRECTORY")
    cd_buf.record_field("length", "uint32", cd_off + 4, 4, length, str(length), f"{length} bytes")
    cd_buf.record_field("version", "uint32", cd_off + 8, 4, version, f"0x{version:x}", f"v{version >> 16}.{(version >> 8) & 0xff}.{version & 0xff}")
    cd_buf.record_field(
        "flags",
        "uint32",
        cd_off + 12,
        4,
        flags,
        f"0x{flags:08x}",
        " | ".join(flags_decoded) if flags_decoded else "0x0",
        "CodeDirectory enforcement flags",
        bit_flags=flags_bit_list,
    )
    cd_buf.record_field("hashOffset", "uint32", cd_off + 16, 4, hash_offset, f"0x{hash_offset:x}", f"Code slot 0 at +0x{hash_offset:x}")
    cd_buf.record_field("identOffset", "uint32", cd_off + 20, 4, ident_offset, f"0x{ident_offset:x}", f"Identifier: '{ident_str}'")
    cd_buf.record_field("nSpecialSlots", "uint32", cd_off + 24, 4, n_special_slots, str(n_special_slots), f"{n_special_slots} special slots")
    cd_buf.record_field("nCodeSlots", "uint32", cd_off + 28, 4, n_code_slots, str(n_code_slots), f"{n_code_slots} code pages")
    cd_buf.record_field("codeLimit", "uint32", cd_off + 32, 4, code_limit, f"0x{code_limit:x}", f"{code_limit:,} bytes signed")
    cd_buf.record_field("hashSize", "uint8", cd_off + 36, 1, hash_size, str(hash_size), f"{hash_size} bytes per hash")
    cd_buf.record_field("hashType", "uint8", cd_off + 37, 1, hash_type, str(hash_type), hash_type_name)
    cd_buf.record_field("platform", "uint8", cd_off + 38, 1, platform, str(platform), f"Platform ID {platform}")
    cd_buf.record_field("pageSize", "uint8", cd_off + 39, 1, page_size_shift, f"2^{page_size_shift}", f"{page_size} bytes")

    team_id = ""
    if version >= 0x20100 and cd_len >= 48:
        scatter_offset = cd_buf.u32(cd_off + 44, ">")
        cd_buf.record_field("scatterOffset", "uint32", cd_off + 44, 4, scatter_offset, f"0x{scatter_offset:x}")
    if version >= 0x20200 and cd_len >= 52:
        team_offset = cd_buf.u32(cd_off + 48, ">")
        if 0 < team_offset < cd_len:
            team_id, _ = cd_buf.cstr_at(cd_off + team_offset, 256)
        cd_buf.record_field("teamOffset", "uint32", cd_off + 48, 4, team_offset, f"0x{team_offset:x}", f"TeamID: '{team_id or 'None'}'")

    exec_seg_base = 0
    exec_seg_limit = 0
    exec_seg_flags = 0
    if version >= 0x20400 and cd_len >= 88:
        exec_seg_base = cd_buf.u64(cd_off + 64, ">")
        exec_seg_limit = cd_buf.u64(cd_off + 72, ">")
        exec_seg_flags = cd_buf.u64(cd_off + 80, ">")
        cd_buf.record_field("execSegBase", "uint64", cd_off + 64, 8, exec_seg_base, f"0x{exec_seg_base:x}", "Executable segment file offset")
        cd_buf.record_field("execSegLimit", "uint64", cd_off + 72, 8, exec_seg_limit, f"0x{exec_seg_limit:x}", f"{exec_seg_limit:,} bytes")
        cd_buf.record_field("execSegFlags", "uint64", cd_off + 80, 8, exec_seg_flags, f"0x{exec_seg_flags:x}")

    # Compute CDHash of the entire CodeDirectory blob
    raw_cd_bytes = cd_buf.read_bytes(cd_off, min(length, cd_len))
    full_cd_digest = _compute_digest(raw_cd_bytes, hash_type)
    cdhash_full = full_cd_digest.hex()
    cdhash_20 = full_cd_digest[:20].hex()

    # Special Slots (-1 down to -nSpecialSlots)
    special_slots_list: List[Dict[str, Any]] = []
    slot_to_superblob_type = {
        2: CSSLOT_REQUIREMENTS,
        5: CSSLOT_ENTITLEMENTS,
        7: CSSLOT_DER_ENTITLEMENTS,
    }
    max_special = min(n_special_slots, 16)
    for s_idx in range(1, max_special + 1):
        slot_pos = cd_off + hash_offset - (s_idx * hash_size)
        if slot_pos < cd_off or slot_pos + hash_size > cd_off + cd_len:
            continue
        expected_bytes = cd_buf.read_bytes(slot_pos, hash_size)
        is_present = any(b != 0 for b in expected_bytes)
        slot_name = CS_SPECIAL_SLOT_NAMES.get(s_idx, f"Special Slot -{s_idx}")
        verified: Optional[bool] = None
        if is_present and s_idx in slot_to_superblob_type:
            sb_type = slot_to_superblob_type[s_idx]
            if sb_type in slot_raw_blobs:
                actual_digest = _compute_digest(slot_raw_blobs[sb_type], hash_type)[:hash_size]
                verified = actual_digest == expected_bytes
        special_slots_list.append({
            "slot": -s_idx,
            "name": slot_name,
            "hash": expected_bytes.hex(),
            "present": is_present,
            "verified": verified,
        })

    # Verify Code Slots (sample first 16 pages + last page for instant speed)
    code_slots_preview: List[Dict[str, Any]] = []
    all_sampled_verified = True
    indices_to_check = list(range(min(n_code_slots, 16)))
    if n_code_slots > 16 and (n_code_slots - 1) not in indices_to_check:
        indices_to_check.append(n_code_slots - 1)

    for page_idx in indices_to_check:
        slot_pos = cd_off + hash_offset + (page_idx * hash_size)
        if slot_pos + hash_size > cd_off + cd_len:
            break
        expected_hash_bytes = cd_buf.read_bytes(slot_pos, hash_size)
        page_file_off = page_idx * page_size
        page_end_off = min(page_file_off + page_size, code_limit)
        if page_end_off > page_file_off and page_end_off <= slice_buf.slice_size:
            page_bytes = slice_buf.read_bytes(page_file_off, page_end_off - page_file_off)
            actual_hash_bytes = _compute_digest(page_bytes, hash_type)[:hash_size]
            page_ok = actual_hash_bytes == expected_hash_bytes
        else:
            actual_hash_bytes = b""
            page_ok = False
        if not page_ok:
            all_sampled_verified = False
        code_slots_preview.append({
            "page_index": page_idx,
            "file_offset": page_file_off,
            "expected_hash": expected_hash_bytes.hex(),
            "actual_hash": actual_hash_bytes.hex(),
            "verified": page_ok,
        })

    return {
        "version": f"0x{version:x}",
        "flags": f"0x{flags:08x}",
        "flags_int": flags,
        "flags_decoded": flags_decoded,
        "hash_type": hash_type_name,
        "page_size": page_size,
        "identifier": ident_str,
        "team_id": team_id,
        "cdhash": cdhash_20,
        "cdhash_full": cdhash_full,
        "cdhash_verified": all_sampled_verified and len(code_slots_preview) > 0,
        "n_special_slots": n_special_slots,
        "n_code_slots": n_code_slots,
        "code_limit": code_limit,
        "exec_seg_base": exec_seg_base,
        "exec_seg_limit": exec_seg_limit,
        "exec_seg_flags": exec_seg_flags,
        "special_slots": special_slots_list,
        "code_slots_preview": code_slots_preview,
        "fields": cd_buf.get_fields(),
    }
