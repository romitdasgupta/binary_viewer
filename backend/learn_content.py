"""
Learning content: the public interface.

All teaching material in BinaryStudio is data. It lives in backend/learn/ as plain
Python structures, is served as JSON under /api/learn/*, and can be rendered by
anything: the in-app Learn views (static/js/learn.js), the WebAssembly build
(same routes, same engine), or a generator of static article pages.

===============================================================================
DATA FORMAT (version 1)
===============================================================================

Rich text
---------
Strings described as "rich" use four inline constructs and nothing else:

    `code`                    literal code or a name from a file format
    *emphasis*
    [[term-id]]               link to a glossary term, shown as the term's display form
    [[term-id|shown text]]    the same, with other text
    [[concept:concept-id|shown text]]   link to a concept (text optional: the concept title)

Everything else is literal text. There is no HTML and no nesting. `plain(text)`
returns the text with the markup removed. Strings described as "plain" contain
no markup.

Blocks
------
A body is a list of blocks. A block is either a rich string (one paragraph) or:

    {"type": "list", "items": [rich, ...], "ordered": bool (optional)}
    {"type": "code", "text": literal, "caption": plain (optional)}
    {"type": "table", "head": [rich, ...], "rows": [[rich, ...], ...]}
    {"type": "note", "text": rich}        a qualification or stated simplification

Module       {"id", "title", "summary"}                           (curriculum order)
Concept      {"id"          stable slug; the URL of an article page
              "module"      module id
              "order"       1-based position in the curriculum
              "level"       1 first contact | 2 working knowledge | 3 advanced
              "title", "summary" (plain)
              "body"        [block]: the format-independent explanation
              "formats"     {"macho": [block], "elf": [block], "pe": [block]}
              "differences" rich: why the formats differ ("" if nothing to add)
              "see"         [{"id", "label" (plain), "at": locator, "formats": [..] (optional),
                              "optional": true if a well-formed file may lack the structure}]
                            "see it in this file" actions; resolved per document by /api/learn/resolve
              "misconceptions" [{"claim" (plain), "reality" (rich)}]
              "next"        [concept id]
              "sources"     [plain]: primary sources the text was checked against}
Term         {"id", "term", "short" (plain, one or two sentences), "aka": [plain],
              "see": [term id], "concept": concept id, "match": [exact strings the app underlines]}
Field        {"key" ("elf.ehdr.e_entry"), "format", "struct", "field",
              "meaning", "reader", "if_wrong", "peers" (all plain), "concept"}
Comparison   {"id", "title", "macho", "elf", "pe", "why" (rich), "concept", "at": locator, "formats" (optional)}
Mnemonic     {"title", "text" (rich), "concept"}, keyed by arch ("x86" | "arm64") and mnemonic; members of a
             large family are {"title", "family"} and take "text" and "concept" from "families"[family].
             "prefixes" explains x86 prefixes printed before a mnemonic ("lock add", "rep movsb").
Idiom        {"id", "arch", "title", "text" (rich), "concept", "steps": [...]}  (see learn/instructions.py)
Tour         {"id", "title", "level", "minutes", "summary", "formats", "concepts", "samples": {format: preset id},
              "steps": [{"id", "title", "text", "show": locator | None, "task": spec | None}]}
             Tours are templates; /api/learn/tour instantiates one for a document (see below).

A locator is a small dict describing a place in a file independent of any
particular file ({"kind": "field", "where": "header", "name": {...}}, …). Static
renderers can ignore locators; they only matter with a document open.

===============================================================================
ROUTES (all GET, all JSON)
===============================================================================
    /api/learn/index         modules, concept summaries, tour summaries, counts
    /api/learn/concepts      every concept in full, in curriculum order
    /api/learn/concept?id=   one concept in full
    /api/learn/glossary      every term
    /api/learn/fields        field reference grouped by structure, plus the flat catalog
    /api/learn/instructions  mnemonics and idioms
    /api/learn/compare       the cross-format comparison rows
    /api/learn/tours         tour summaries (no document needed)
    /api/learn/tour?id=&doc=&slice_index=
                             the tour instantiated for a document: steps that apply to it, each with
                             "show" resolved to {node_id, abs_offset, size, label, vmaddr?, disasm?} and
                             "task" resolved to a concrete question with its expected answer:
                               bytes   {"ranges": [{abs_offset, size}]}
                               node    {"node_ids": [...], "options": [{node_id, label}]}
                               value   {"expect": int}
                               choice  {"options": [...], "correct": index}
                             plus "prompt" and "explain" (rich), and "values": the document values that
                             were substituted into them (address, answer, ...). If the tour does not apply:
                             {"available": false, "reason", "sample"}.
    /api/learn/resolve?scope=concept:<id>|compare&doc=&slice_index=
                             the "see it in this file" actions of a concept (or the comparison rows)
                             resolved against a document: [{"id", "label", "available", "node_id",
                             "abs_offset", "size", "vmaddr", "disasm", "reason", "samples": [preset id]}].
                             Without `doc`, every action is unavailable and carries its samples.

Python: index(), concepts(), concept(id), glossary(), fields(), instructions(), compare(),
tours(), build_tour(id, doc, slice), resolve_scope(scope, doc, slice), validate(), plain().

Standard library only; importable inside Pyodide.
"""

import re
from typing import Any, Dict, Iterator, List, Optional

from . import runtime
from .learn import CONCEPTS, MODULES
from .learn import compare as _compare
from .learn import fields as _fields
from .learn import glossary as _glossary
from .learn import instructions as _instructions
from .learn import resolve as _resolve
from .learn import tours as _tours

CONTENT_VERSION = 1
FORMATS = ("macho", "elf", "pe")
LEVELS = {1: "First contact", 2: "Working knowledge", 3: "Advanced"}

_LINK = re.compile(r"\[\[([^\]|]+)(?:\|([^\]]*))?\]\]")


# ---------------------------------------------------------------------------
# Static content
# ---------------------------------------------------------------------------
def _concept_by_id() -> Dict[str, Dict[str, Any]]:
    return {c["id"]: c for c in CONCEPTS}


def _summary(c: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": c["id"], "module": c["module"], "order": c["order"], "level": c["level"],
            "title": c["title"], "summary": c["summary"]}


def _tour_summary(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": t["id"], "title": t["title"], "level": t["level"], "minutes": t["minutes"], "summary": t["summary"],
            "formats": t["formats"], "concepts": t["concepts"], "samples": t["samples"],
            "steps": len(t["steps"]), "tasks": sum(1 for s in t["steps"] if s.get("task"))}


def counts() -> Dict[str, Any]:
    by_format = {f: sum(1 for k in _fields.CATALOG if k.startswith(f + ".")) for f in FORMATS}
    return {
        "modules": len(MODULES), "concepts": len(CONCEPTS), "terms": len(_glossary.TERMS),
        "tours": len(_tours.TOURS), "tasks": sum(1 for t in _tours.TOURS for s in t["steps"] if s.get("task")),
        "fields": by_format, "comparison_rows": len(_compare.ROWS),
        "mnemonics": {arch: len(table) for arch, table in _instructions.MNEMONICS.items()},
        "idioms": len(_instructions.IDIOMS),
    }


def index() -> Dict[str, Any]:
    return {"version": CONTENT_VERSION, "levels": {str(k): v for k, v in LEVELS.items()}, "modules": MODULES,
            "concepts": [_summary(c) for c in CONCEPTS], "tours": [_tour_summary(t) for t in _tours.TOURS],
            "counts": counts()}


def concepts() -> List[Dict[str, Any]]:
    return CONCEPTS


def concept(concept_id: str) -> Optional[Dict[str, Any]]:
    return _concept_by_id().get(concept_id)


def glossary() -> List[Dict[str, Any]]:
    return _glossary.TERMS


def fields() -> Dict[str, Any]:
    return {"structs": _fields.reference(), "catalog": _fields.CATALOG}


def instructions() -> Dict[str, Any]:
    return {"mnemonics": _instructions.MNEMONICS, "families": _instructions.FAMILIES, "prefixes": _instructions.PREFIXES,
            "conditions": _instructions.CONDITIONS, "idioms": _instructions.IDIOMS}


def compare() -> List[Dict[str, Any]]:
    return _compare.ROWS


def tours() -> List[Dict[str, Any]]:
    return [_tour_summary(t) for t in _tours.TOURS]


def plain(text: Any) -> str:
    """Rich text with the markup removed."""
    def link(match: "re.Match[str]") -> str:
        target, shown = match.group(1), match.group(2)
        if shown:
            return shown
        if target.startswith("concept:"):
            hit = _concept_by_id().get(target[8:])
            return hit["title"] if hit else target[8:]
        term = _glossary.by_id().get(target)
        return term["term"] if term else target
    out = _LINK.sub(link, str(text))
    out = re.sub(r"`([^`]*)`", r"\1", out)
    return re.sub(r"\*([^*\s][^*]*)\*", r"\1", out)


# ---------------------------------------------------------------------------
# Content resolved against a document
# ---------------------------------------------------------------------------
def _action(item: Dict[str, Any], doc: Optional[Dict[str, Any]], slice_doc: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"id": item.get("id", ""), "label": item.get("label", ""), "formats": item.get("formats") or list(FORMATS),
                           "optional": bool(item.get("optional"))}
    if doc is None or slice_doc is None:
        out.update({"available": False, "reason": "Open a file to see this."})
        return out
    fmt = _resolve.fmt_of(slice_doc)
    if fmt not in out["formats"]:
        names = " and ".join(_resolve.FORMAT_NAMES[f] for f in out["formats"])
        out.update({"available": False, "reason": "This applies to %s files." % names})
        return out
    out.update(_resolve.resolve(item["at"], doc, slice_doc))
    return out


def resolve_scope(scope: str, doc: Optional[Dict[str, Any]], slice_doc: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The "see it in this file" actions of `scope`, resolved. scope: 'concept:<id>' or 'compare'."""
    if scope == "compare":
        items = [{"id": "compare." + r["id"], "label": r["title"], "at": r["at"], "formats": r.get("formats")} for r in _compare.ROWS]
    elif scope.startswith("concept:"):
        hit = concept(scope[8:])
        if hit is None:
            raise runtime.NotFound("No such concept.")
        items = hit["see"]
    else:
        raise runtime.BadRequest("Unknown 'scope'; use concept:<id> or compare.")
    return [_action(item, doc, slice_doc) for item in items]


def build_tour(tour_id: str, doc: Dict[str, Any], slice_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The tour instantiated for a document, or None if there is no such tour."""
    tour = _tours.by_id().get(tour_id)
    if tour is None:
        return None
    fmt = _resolve.fmt_of(slice_doc)
    base = {"id": tour["id"], "title": tour["title"], "level": tour["level"], "minutes": tour["minutes"],
            "summary": tour["summary"], "format": fmt, "concepts": tour["concepts"]}
    if fmt not in tour["formats"]:
        names = " and ".join(_resolve.FORMAT_NAMES[f] for f in tour["formats"])
        return dict(base, available=False, steps=[], reason="This tour is for %s files." % names,
                    sample=tour["samples"].get(tour["formats"][0]))
    if tour.get("requires"):
        needed = _resolve.resolve(tour["requires"], doc, slice_doc)
        if not needed.get("available"):
            return dict(base, available=False, steps=[], reason=needed.get("reason", "This tour does not apply to this file."),
                        sample=tour["samples"].get(fmt))
    values = _resolve.facts(doc, slice_doc)
    steps: List[Dict[str, Any]] = []
    for spec in tour["steps"]:
        text = _resolve.per_format(spec["text"], fmt)
        if not text:
            continue
        show = None
        if spec.get("show"):
            show = _resolve.resolve(spec["show"], doc, slice_doc)
            if not show.get("available"):
                continue
        task = _resolve.compute_task(spec["task"], doc, slice_doc) if spec.get("task") else None
        if spec.get("needs_task") and task is None:
            continue
        steps.append({"id": spec["id"], "title": spec["title"], "text": _resolve.fill(str(text), values), "show": show, "task": task})
    return dict(base, available=bool(steps), steps=steps, reason="" if steps else "No step of this tour applies to this file.",
                sample=tour["samples"].get(fmt))


def annotate_instructions(rows: List[Dict[str, Any]], arch_name: Any) -> List[Dict[str, Any]]:
    """Idioms found in a list of {mnemonic, operands, comment} rows (see learn/instructions.py)."""
    return _instructions.annotate(rows, _instructions.arch_family(arch_name))


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------
def _strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            for item in _strings(value):
                yield item
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            for item in _strings(value):
                yield item


def links_in(obj: Any) -> List[str]:
    """Every [[target]] referenced anywhere inside `obj`."""
    out: List[str] = []
    for text in _strings(obj):
        out.extend(m.group(1) for m in _LINK.finditer(text))
    return out


def validate() -> List[str]:
    """Problems in the static content: duplicate ids, dangling links, malformed records. Empty when sound."""
    problems: List[str] = []
    slug = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
    term_ids = [t["id"] for t in _glossary.TERMS]
    concept_ids = [c["id"] for c in CONCEPTS]
    module_ids = [m["id"] for m in MODULES]
    tour_ids = [t["id"] for t in _tours.TOURS]
    for name, ids in (("term", term_ids), ("concept", concept_ids), ("module", module_ids), ("tour", tour_ids),
                      ("comparison row", [r["id"] for r in _compare.ROWS]), ("idiom", [i["id"] for i in _instructions.IDIOMS])):
        for dup in sorted(set(i for i in ids if ids.count(i) > 1)):
            problems.append("duplicate %s id: %s" % (name, dup))
        for bad in [i for i in ids if not slug.match(i)]:
            problems.append("%s id is not a slug: %s" % (name, bad))
    terms, known_concepts = set(term_ids), set(concept_ids)

    def check_links(where: str, obj: Any) -> None:
        for target in links_in(obj):
            if target.startswith("concept:"):
                if target[8:] not in known_concepts:
                    problems.append("%s links to unknown concept %s" % (where, target[8:]))
            elif target not in terms:
                problems.append("%s links to unknown term %s" % (where, target))

    for c in CONCEPTS:
        where = "concept " + c["id"]
        if c.get("module") not in module_ids:
            problems.append(where + " has no module")
        if c["level"] not in LEVELS:
            problems.append(where + " has a bad level")
        for key in ("body", "formats", "differences", "misconceptions"):
            check_links(where, c[key])
        for fmt in FORMATS:
            if not c["formats"].get(fmt):
                problems.append("%s has no %s section" % (where, fmt))
        if not c["see"]:
            problems.append(where + " has no 'see it in this file' action")
        if not c["misconceptions"]:
            problems.append(where + " has no misconceptions")
        for target in c["next"]:
            if target not in known_concepts:
                problems.append("%s: next -> unknown concept %s" % (where, target))
            if target == c["id"]:
                problems.append("%s: next points at itself" % where)
        seen = [a["id"] for a in c["see"]]
        if len(set(seen)) != len(seen):
            problems.append(where + " has duplicate action ids")
    for t in _glossary.TERMS:
        where = "term " + t["id"]
        if not t["term"] or not t["short"]:
            problems.append(where + " is incomplete")
        if "[[" in t["short"] or "`" in t["short"]:
            problems.append(where + ": short text must be plain")
        for target in t["see"]:
            if target not in terms:
                problems.append("%s: see -> unknown term %s" % (where, target))
        if t["concept"] not in known_concepts:
            problems.append("%s: unknown concept %s" % (where, t["concept"]))
    for key, entry in _fields.CATALOG.items():
        where = "field " + key
        for part in ("meaning", "reader", "if_wrong", "peers"):
            if not entry[part].strip():
                problems.append("%s: empty %s" % (where, part))
            if "[[" in entry[part] or "`" in entry[part]:
                problems.append("%s: %s must be plain text" % (where, part))
        if entry["concept"] not in known_concepts:
            problems.append("%s: unknown concept %s" % (where, entry["concept"]))
    for row in _compare.ROWS:
        where = "comparison row " + row["id"]
        check_links(where, [row[f] for f in FORMATS] + [row["why"]])
        if row["concept"] not in known_concepts:
            problems.append("%s: unknown concept %s" % (where, row["concept"]))
    for legacy in _compare.LEGACY_IDS:
        if legacy not in _compare.by_id():
            problems.append("legacy comparison id missing: " + legacy)
    for family_id, family in _instructions.FAMILIES.items():
        check_links("instruction family " + family_id, family["text"])
        if family["concept"] not in known_concepts:
            problems.append("instruction family %s: unknown concept %s" % (family_id, family["concept"]))
    for arch, table in _instructions.MNEMONICS.items():
        for name, entry in table.items():
            where = "mnemonic %s/%s" % (arch, name)
            if not entry.get("title"):
                problems.append(where + " has no title")
            if "family" in entry:
                if entry["family"] not in _instructions.FAMILIES:
                    problems.append("%s: unknown family %s" % (where, entry["family"]))
                continue
            check_links(where, entry["text"])
            if entry["concept"] not in known_concepts:
                problems.append("%s: unknown concept %s" % (where, entry["concept"]))
    for idiom in _instructions.IDIOMS:
        where = "idiom " + idiom["id"]
        check_links(where, idiom["text"])
        if idiom["concept"] not in known_concepts:
            problems.append("%s: unknown concept %s" % (where, idiom["concept"]))
        if idiom["arch"] not in _instructions.MNEMONICS:
            problems.append(where + ": unknown arch")
        for step in idiom["steps"]:
            for part in ("m", "o", "t"):
                if part in step:
                    try:
                        re.compile(step[part])
                    except re.error as exc:
                        problems.append("%s: bad expression %r (%s)" % (where, step[part], exc))
        if idiom["steps"][0].get("opt") or idiom["steps"][0].get("gap"):
            problems.append(where + ": the first step cannot be optional or have a gap")
    for tour in _tours.TOURS:
        where = "tour " + tour["id"]
        check_links(where, [tour["summary"], [s["text"] for s in tour["steps"]],
                            [[s["task"]["prompt"], s["task"]["explain"]] for s in tour["steps"] if s.get("task")]])
        for target in tour["concepts"]:
            if target not in known_concepts:
                problems.append("%s: unknown concept %s" % (where, target))
        step_ids = [s["id"] for s in tour["steps"]]
        if len(set(step_ids)) != len(step_ids):
            problems.append(where + " has duplicate step ids")
        task_ids = [s["task"]["id"] for s in tour["steps"] if s.get("task")]
        if len(set(task_ids)) != len(task_ids):
            problems.append(where + " has duplicate task ids")
        for fmt in tour["formats"]:
            if fmt not in FORMATS or fmt not in tour["samples"]:
                problems.append("%s: no sample for %s" % (where, fmt))
    return problems


# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------
def _slice_of(doc: Dict[str, Any], index: int) -> Dict[str, Any]:
    slices = doc.get("slices") or []
    if not slices:
        raise runtime.BadRequest("The document has no slices.")
    return slices[index] if 0 <= index < len(slices) else slices[0]


def _int(query: Dict[str, str], key: str) -> int:
    try:
        return max(0, min(1 << 20, int(str(query.get(key, "0")).strip() or "0", 0)))
    except ValueError:
        return 0


def register_learn_routes(router: Any) -> None:
    """Register GET /api/learn/* on an ApiRouter (see backend/api.py)."""
    service = router.service
    sample_cache: Dict[str, List[str]] = {}

    def open_document(req: Any) -> Any:
        doc_id = req.query.get("doc") or None
        path = req.query.get("path") or None
        if path is not None and not router.config.allow_path_load:
            raise runtime.Forbidden("Loading files by server path is not available on this server.")
        if not doc_id and not path:
            return None, None
        doc = service.get_entry(doc=doc_id, path=path).doc
        return doc, _slice_of(doc, _int(req.query, "slice_index"))

    def samples_for(scope: str, actions: List[Dict[str, Any]]) -> None:
        """Attach, to each unavailable action, the built-in samples in which it can be seen."""
        if scope not in sample_cache_scopes:
            found: Dict[str, Dict[str, List[str]]] = {}  # action id -> format -> preset ids
            for preset in service.get_presets():
                pid = str(preset.get("id", ""))
                if not pid.startswith("synthetic_") or not preset.get("exists"):
                    continue
                try:
                    doc = service.get_entry(doc="preset:" + pid).doc
                except Exception:  # noqa: BLE001 - a sample that cannot be parsed is not offered
                    continue
                for slice_doc in (doc.get("slices") or [])[:4]:
                    fmt = _resolve.fmt_of(slice_doc)
                    for item in resolve_scope(scope, doc, slice_doc):
                        if item.get("available"):
                            hits = found.setdefault(item["id"], {}).setdefault(fmt, [])
                            if pid not in hits:
                                hits.append(pid)
            for action_id, by_format in found.items():
                # One sample per format, the standard one for that format where it qualifies.
                picks = []
                for fmt in FORMATS:
                    hits = by_format.get(fmt) or []
                    if hits:
                        standard = _tours.DEFAULT_SAMPLES[fmt]
                        picks.append(standard if standard in hits else hits[0])
                sample_cache[action_id] = picks
            sample_cache_scopes.add(scope)
        for action in actions:
            if not action.get("available"):
                action["samples"] = sample_cache.get(action["id"], [])

    sample_cache_scopes = set()

    def handler(req: Any) -> Any:
        name = req.route[len("/api/learn/"):].strip("/")
        query = req.query
        if name == "index":
            return index()
        if name == "concepts":
            return {"version": CONTENT_VERSION, "modules": MODULES, "concepts": concepts()}
        if name == "concept":
            hit = concept(str(query.get("id", "")))
            if hit is None:
                raise runtime.NotFound("No such concept.")
            return hit
        if name == "glossary":
            return {"version": CONTENT_VERSION, "terms": glossary()}
        if name == "fields":
            return fields()
        if name == "instructions":
            return instructions()
        if name == "compare":
            return {"rows": compare()}
        if name == "tours":
            return {"tours": tours()}
        if name == "tour":
            doc, slice_doc = open_document(req)
            if doc is None:
                raise runtime.BadRequest("Missing required 'doc' parameter.")
            built = build_tour(str(query.get("id", "")), doc, slice_doc)
            if built is None:
                raise runtime.NotFound("No such tour.")
            return built
        if name == "resolve":
            scope = str(query.get("scope", ""))
            if len(scope) > 120:
                raise runtime.BadRequest("Parameter 'scope' is too long.")
            doc, slice_doc = open_document(req)
            actions = resolve_scope(scope, doc, slice_doc)
            samples_for(scope, actions)
            return {"scope": scope, "actions": actions}
        raise runtime.NotFound("No such learning resource.")

    router.register("GET", "/api/learn/*", handler)
