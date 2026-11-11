"""
Small constructors used by the content modules. They only build plain dicts and
lists; nothing here is needed to *read* the content (see backend/learn_content.py
for the published data format).
"""

from typing import Any, Dict, List, Optional

FORMATS = ("macho", "elf", "pe")


# ---------------------------------------------------------------------------
# Locators: a declarative "where is this in the open file" description.
# backend/learn/resolve.py turns one into {node_id, abs_offset, size, ...}.
# A value that differs per format is written as {"macho": ..., "elf": ..., "pe": ...};
# a missing key means "does not exist in that format".
# ---------------------------------------------------------------------------
def header() -> Dict[str, Any]:
    return {"kind": "header"}


def fat(name: Optional[str] = None) -> Dict[str, Any]:
    loc: Dict[str, Any] = {"kind": "fat"}
    if name:
        loc["name"] = name
    return loc


def hfield(macho: Any = None, elf: Any = None, pe: Any = None) -> Dict[str, Any]:
    """A field of the main file header (mach_header / Elf_Ehdr / NT headers)."""
    return {"kind": "field", "where": "header", "name": _per_format(macho, elf, pe)}


def lc(macho: Any = None, elf: Any = None, pe: Any = None, field: Any = None) -> Dict[str, Any]:
    """A load command / program header / PE header or data directory, by cmd_name."""
    loc: Dict[str, Any] = {"kind": "lc", "cmd": _per_format(macho, elf, pe)}
    if field is not None:
        loc["kind"] = "field"
        loc["where"] = "lc"
        loc["name"] = field
    return loc


def segment(pick: str = "exec", part: str = "data", field: Any = None, name: Any = None) -> Dict[str, Any]:
    """pick: exec | data | zerofill | rwx | first | name.   part: data | header."""
    loc: Dict[str, Any] = {"kind": "segment", "pick": pick, "part": part}
    if name is not None:
        loc["name"] = name
    if field is not None:
        loc["kind"] = "field"
        loc["where"] = "segment"
        loc["field"] = field
    return loc


def section(macho: Any = None, elf: Any = None, pe: Any = None, part: str = "data", field: Any = None) -> Dict[str, Any]:
    loc: Dict[str, Any] = {"kind": "section", "names": _per_format(macho, elf, pe), "part": part}
    if field is not None:
        loc["kind"] = "field"
        loc["where"] = "section"
        loc["field"] = field
    return loc


def entry() -> Dict[str, Any]:
    return {"kind": "entry"}


def entry_field() -> Dict[str, Any]:
    return {"kind": "entry_field"}


def view(node: Any) -> Dict[str, Any]:
    return {"kind": "view", "node": node}


def symbol(pick: str = "first") -> Dict[str, Any]:
    return {"kind": "symbol", "pick": pick}


def string() -> Dict[str, Any]:
    return {"kind": "string"}


def import_slot() -> Dict[str, Any]:
    return {"kind": "import_slot"}


def fixup() -> Dict[str, Any]:
    return {"kind": "fixup"}


def signature() -> Dict[str, Any]:
    return {"kind": "signature"}


def debug_id() -> Dict[str, Any]:
    return {"kind": "debug_id"}


def _per_format(macho: Any, elf: Any, pe: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if macho is not None:
        out["macho"] = macho
    if elf is not None:
        out["elf"] = elf
    if pe is not None:
        out["pe"] = pe
    return out


# ---------------------------------------------------------------------------
# Content records
# ---------------------------------------------------------------------------
def see(label: str, at: Dict[str, Any], formats: Optional[List[str]] = None, optional: bool = False) -> Dict[str, Any]:
    """A "see it in this file" action. `optional` marks a structure that a well-formed file of the
    format may not have at all (a writable and executable segment, a TLS directory)."""
    item: Dict[str, Any] = {"label": label, "at": at}
    if formats:
        item["formats"] = list(formats)
    if optional:
        item["optional"] = True
    return item


def wrong(claim: str, reality: str) -> Dict[str, str]:
    """A common misconception and the correction."""
    return {"claim": claim, "reality": reality}


def ul(*items: str) -> Dict[str, Any]:
    return {"type": "list", "items": list(items)}


def ol(*items: str) -> Dict[str, Any]:
    return {"type": "list", "ordered": True, "items": list(items)}


def code(text: str, caption: str = "") -> Dict[str, Any]:
    block: Dict[str, Any] = {"type": "code", "text": text}
    if caption:
        block["caption"] = caption
    return block


def table(head: List[str], rows: List[List[str]]) -> Dict[str, Any]:
    return {"type": "table", "head": list(head), "rows": [list(r) for r in rows]}


def note(text: str) -> Dict[str, Any]:
    return {"type": "note", "text": text}


def concept(
    id: str,
    title: str,
    level: int,
    summary: str,
    body: List[Any],
    macho: List[Any],
    elf: List[Any],
    pe: List[Any],
    see: List[Dict[str, Any]],
    misconceptions: List[Dict[str, str]],
    next: List[str],
    differences: str = "",
    sources: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "id": id,
        "title": title,
        "level": level,
        "summary": summary,
        "body": body,
        "formats": {"macho": macho, "elf": elf, "pe": pe},
        "differences": differences,
        "see": see,
        "misconceptions": misconceptions,
        "next": list(next),
        "sources": list(sources or []),
    }
