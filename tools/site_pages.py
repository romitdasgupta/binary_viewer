#!/usr/bin/env python3
"""
BinaryStudio public-site layer: indexable learning pages, site files, and the advertising policy.

    python3 tools/site_pages.py --out DIR [--site-url URL] [--ads JSON|@file]   write the site files to DIR
    python3 tools/site_pages.py --csp [--ads JSON|@file]                        print the CSP of each page kind

Used by
  * tools/build_static.py   add_to_build(): the pages and site files go into dist/, the content-page
                            CSP into _headers, the normalised ads config into the app's /api/config.
  * backend/server.py       SiteContent: generated once per server, in memory, on first request (at
                            start-up in public mode), served at the same paths as in the static build.
                            In memory because the content comes from the running engine's own data (it
                            can never be stale), a deployed filesystem may be read-only, and it costs
                            ~0.5 s once.

Generated paths (relative to the site root)
  learn/                        landing page: modules and concepts in curriculum order
  learn/<concept-id>/           one article per concept
  learn/glossary/               every term, one anchor per term (#<term-id>)
  learn/compare/                Mach-O, ELF and PE side by side, one anchor per row
  learn/fields/                 field reference index; learn/fields/<format>/ one page per format
  robots.txt
  sitemap.xml                   only with a site URL (the protocol requires absolute URLs)
  ads.txt                       only when ads are enabled and the config declares seller lines
  .well-known/security.txt      only when a security contact is configured

Pages are HTML + static/css/site.css. They carry no script at all unless an ad provider that needs one
is enabled for content pages, and then only static/js/ads.js (same origin). Every string taken from the
Learn data is HTML-escaped here; the rich-text markup of backend/learn_content.py (`code`, *em*,
[[term]], [[concept:id]]) is the only thing that becomes tags.

===================================================================================================
ADVERTISING (off by default)
===================================================================================================
Configured as the `ads` object of /api/config: BINARYSTUDIO_ADS for the server, --ads (or the same
variable) for the static build. Shape:

    {"enabled": true,
     "provider": "house" | "ethicalads" | "frame",
     "slots": {"content": {"height": 150},     content pages (the default placement)
               "footer":  {"height": 90}},     the app's footer strip: a separate, explicit opt-in
     "options": {...}}                        provider options, plus the common ones below

Threat model: a third-party script running in the app's origin could read a user's binary out of the
page or the worker. So no provider here ever runs third-party code in our origin:
  house       units written in the config, rendered by our code as inert text / image / link. No
              third-party request at all unless a unit's image is hosted elsewhere.
  ethicalads  our code fetches one ad decision as JSON from EthicalAds' decision API and renders it as
              inert text / image / link; their script is never loaded. View counted with their
              view pixel once half the unit is on screen.
  frame       a sandboxed iframe (allow-scripts allow-popups allow-popups-to-escape-sandbox, never
              allow-same-origin) of a URL on ANOTHER origin, for a network or sponsor tag the operator
              hosts there. The frame has an opaque origin: it cannot reach the page, its storage or the
              API (the API refuses Origin: null).
Conventional script networks are not offered in the same origin on purpose (see the site report for
AdSense, Carbon). Units never animate, never cover content, are labelled, reserve their height before
they load, and collapse to nothing when blocked, refused or unfilled.

Common options:  label ("Advertisement" | "Sponsored" | "Sponsor" | "Ad"),
                 respect_dnt (default true: no network request when DNT or Global Privacy Control is on),
                 consent (default false; true for frame): ask first, load nothing until answered,
                 consent_text (plain text, shown in the prompt),
                 ads_txt: ["example.com, pub-123, DIRECT", ...]
house:           units: [{title, text, url, image?, image_alt?, image_width?, image_height?, sponsor?}]
ethicalads:      publisher (required), ad_type ("image" | "text"), keywords [..], campaign_types [..],
                 api (default https://server.ethicalads.io), media (default [https://media.ethicalads.io])
frame:           src (required, https, another origin), title

ads_csp_extra(ads, "content" | "app") gives the CSP sources a configuration needs; the server and the
static build add them to the content pages' CSP, and to the app shell's only when the footer slot is on.

Standard library only; Python 3.9+.
"""

import argparse
import hashlib
import html
import json
import os
import re
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO, "static")
APP_NAME = "BinaryStudio"
FORMAT_NAMES = {"macho": "Mach-O", "elf": "ELF", "pe": "PE"}
FORMATS = ("macho", "elf", "pe")
LEVEL_SCHEMA = {1: "Beginner", 2: "Intermediate", 3: "Advanced"}

CSPExtra = List[Tuple[str, List[str]]]


def _backend() -> Any:
    if REPO not in sys.path:
        sys.path.insert(0, REPO)
    import backend  # noqa: F401  (build-time / server import)

    return backend


# ===================================================================================================
# Advertising policy
# ===================================================================================================
PLACEMENTS = ("content", "footer")
PROVIDERS = ("house", "ethicalads", "frame")
PROVIDER_NAMES = {"house": "house units", "ethicalads": "EthicalAds", "frame": "framed ad"}
LABELS = ("Advertisement", "Sponsored", "Sponsor", "Ad")
ETHICALADS_API = "https://server.ethicalads.io"
ETHICALADS_MEDIA = "https://media.ethicalads.io"
ETHICALADS_ABOUT = "https://www.ethicalads.io/advertisers/"
DEFAULT_HEIGHT = {"content": 150, "footer": 90}
MIN_HEIGHT, MAX_HEIGHT = 60, 250
DISABLED_ADS: Dict[str, Any] = {"enabled": False, "provider": None, "slots": {}, "options": {}}
_SLUG = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_ADS_TXT_RECORD = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}\s*,\s*[A-Za-z0-9._:-]{1,128}\s*,\s*(DIRECT|RESELLER)"
                             r"(\s*,\s*[A-Za-z0-9]{1,64})?$", re.I)
_ADS_TXT_VARIABLE = re.compile(r"^(contact|subdomain|inventorypartnerdomain|ownerdomain|managerdomain)=[^\s,]{1,256}$", re.I)


def _plain(value: Any, what: str, limit: int, required: bool = True) -> str:
    text = "" if value is None else str(value)
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ValueError("%s must not contain control characters" % what)
    text = " ".join(text.split())
    if required and not text:
        raise ValueError("%s is required" % what)
    if len(text) > limit:
        raise ValueError("%s is longer than %d characters" % (what, limit))
    return text


def _is_loopback(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def _url(value: Any, what: str, relative: bool = False) -> str:
    """An https URL (http only for loopback hosts, for local testing), or with `relative` a
    same-origin path. Never javascript:, data:, credentials or a protocol-relative URL."""
    text = _plain(value, what, 2048)
    if relative and text.startswith("/") and not text.startswith("//") and "\\" not in text:
        return text
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower()
        _ = parts.port
    except ValueError:
        raise ValueError("%s is not a valid URL" % what)
    if parts.scheme == "https" or (parts.scheme == "http" and _is_loopback(host)):
        if host and not parts.username and not parts.password and "\\" not in text:
            return text
    raise ValueError("%s must be an https:// URL%s" % (what, " or a path starting with /" if relative else ""))


def origin_of(url: str) -> Optional[str]:
    """scheme://host[:port] of an absolute URL; None for a same-origin path."""
    if url.startswith("/"):
        return None
    parts = urlsplit(url)
    return "%s://%s" % (parts.scheme, parts.netloc.lower())


def normalize_ads(raw: Any) -> Dict[str, Any]:
    """The validated, complete ads configuration (what /api/config publishes). Raises ValueError."""
    if raw is None or raw == {}:
        return json.loads(json.dumps(DISABLED_ADS))
    if not isinstance(raw, dict):
        raise ValueError("ads must be a JSON object")
    unknown = set(raw) - {"enabled", "provider", "slots", "options"}
    if unknown:
        raise ValueError("ads: unknown key(s) %s" % ", ".join(sorted(unknown)))
    if not raw.get("enabled"):
        return json.loads(json.dumps(DISABLED_ADS))
    provider = raw.get("provider")
    if provider not in PROVIDERS:
        raise ValueError("ads.provider must be one of %s" % ", ".join(PROVIDERS))
    slots_in = raw.get("slots") or {"content": {}}
    if not isinstance(slots_in, dict):
        raise ValueError("ads.slots must be an object")
    slots: Dict[str, Dict[str, int]] = {}
    for name, spec in slots_in.items():
        if name not in PLACEMENTS:
            raise ValueError("ads.slots: unknown placement %r (use content and/or footer)" % name)
        spec = spec or {}
        if not isinstance(spec, dict):
            raise ValueError("ads.slots.%s must be an object" % name)
        height = spec.get("height", DEFAULT_HEIGHT[name])
        if not isinstance(height, int) or isinstance(height, bool) or not MIN_HEIGHT <= height <= MAX_HEIGHT:
            raise ValueError("ads.slots.%s.height must be an integer from %d to %d" % (name, MIN_HEIGHT, MAX_HEIGHT))
        slots[name] = {"height": int(round(height / 10.0)) * 10}
    if not slots:
        raise ValueError("ads.slots must name at least one placement")
    opts_in = raw.get("options") or {}
    if not isinstance(opts_in, dict):
        raise ValueError("ads.options must be an object")
    opts: Dict[str, Any] = {}
    label = opts_in.get("label", "Advertisement")
    if label not in LABELS:
        raise ValueError("ads.options.label must be one of %s" % ", ".join(LABELS))
    opts["label"] = label
    opts["respect_dnt"] = bool(opts_in.get("respect_dnt", True))
    opts["consent"] = bool(opts_in.get("consent", provider == "frame"))
    opts["consent_text"] = _plain(opts_in.get("consent_text", ""), "ads.options.consent_text", 300, required=False)
    lines = opts_in.get("ads_txt") or []
    if not isinstance(lines, list) or len(lines) > 50:
        raise ValueError("ads.options.ads_txt must be a list of at most 50 lines")
    clean_lines = []
    for line in lines:
        text = _plain(line, "ads.options.ads_txt line", 300)
        if not (_ADS_TXT_RECORD.match(text) or _ADS_TXT_VARIABLE.match(text)):
            raise ValueError("ads.options.ads_txt: not an ads.txt record: %r" % text)
        clean_lines.append(text)
    opts["ads_txt"] = clean_lines

    if provider == "house":
        units = opts_in.get("units")
        if not isinstance(units, list) or not 1 <= len(units) <= 20:
            raise ValueError("ads.options.units must be a list of 1 to 20 units")
        out_units = []
        for i, unit in enumerate(units):
            if not isinstance(unit, dict):
                raise ValueError("ads.options.units[%d] must be an object" % i)
            where = "ads.options.units[%d]" % i
            item = {
                "title": _plain(unit.get("title"), where + ".title", 80),
                "text": _plain(unit.get("text", ""), where + ".text", 220, required=False),
                "url": _url(unit.get("url"), where + ".url", relative=True),
                "sponsor": _plain(unit.get("sponsor", ""), where + ".sponsor", 60, required=False),
            }
            if unit.get("image"):
                item["image"] = _url(unit["image"], where + ".image", relative=True)
                item["image_alt"] = _plain(unit.get("image_alt", ""), where + ".image_alt", 120, required=False)
                for key, default in (("image_width", 120), ("image_height", 90)):
                    value = unit.get(key, default)
                    if not isinstance(value, int) or isinstance(value, bool) or not 16 <= value <= 400:
                        raise ValueError("%s.%s must be an integer from 16 to 400" % (where, key))
                    item[key] = value
            out_units.append(item)
        opts["units"] = out_units
    elif provider == "ethicalads":
        publisher = str(opts_in.get("publisher") or "")
        if not _SLUG.match(publisher):
            raise ValueError("ads.options.publisher must be your EthicalAds publisher id ([A-Za-z0-9_-])")
        opts["publisher"] = publisher
        ad_type = opts_in.get("ad_type", "image")
        if ad_type not in ("image", "text"):
            raise ValueError("ads.options.ad_type must be image or text")
        opts["ad_type"] = ad_type
        for key, limit in (("keywords", 10), ("campaign_types", 3)):
            values = opts_in.get(key) or []
            if not isinstance(values, list) or len(values) > limit or not all(isinstance(v, str) and _SLUG.match(v) for v in values):
                raise ValueError("ads.options.%s must be a list of at most %d slugs" % (key, limit))
            opts[key] = list(values)
        opts["api"] = origin_of(_url(opts_in.get("api", ETHICALADS_API), "ads.options.api"))
        media = opts_in.get("media", [ETHICALADS_MEDIA])
        if not isinstance(media, list) or not 1 <= len(media) <= 4:
            raise ValueError("ads.options.media must list 1 to 4 image origins")
        opts["media"] = [origin_of(_url(m, "ads.options.media")) for m in media]
        opts["attribution_url"] = ETHICALADS_ABOUT
        opts["provider_name"] = "EthicalAds"
    elif provider == "frame":
        src = _url(opts_in.get("src"), "ads.options.src")
        opts["src"] = src
        opts["origin"] = origin_of(src)
        opts["title"] = _plain(opts_in.get("title", "Advertisement"), "ads.options.title", 80)
        opts["provider_name"] = _plain(opts_in.get("provider_name", "an ad network"), "ads.options.provider_name", 60)
    return {"enabled": True, "provider": provider, "slots": slots, "options": opts}


def check_frame_isolation(ads: Dict[str, Any], site_url: Optional[str]) -> None:
    """A framed ad must come from another origin than the site, or the sandbox is all that separates it."""
    if ads.get("enabled") and ads.get("provider") == "frame" and site_url:
        if ads["options"]["origin"] == origin_of(site_url):
            raise ValueError("ads.options.src must be on a different origin from the site (%s)" % origin_of(site_url))


def ads_csp_extra(ads: Dict[str, Any], placement: str) -> CSPExtra:
    """CSP sources a configuration needs. placement: 'content' (content pages) or 'app' (the app shell,
    which only ever gets any when the footer slot is configured)."""
    slot = "footer" if placement == "app" else "content"
    if not ads or not ads.get("enabled") or slot not in (ads.get("slots") or {}):
        return []
    opts = ads.get("options") or {}
    provider = ads.get("provider")
    if provider == "house":
        origins = sorted({o for o in (origin_of(u["image"]) for u in opts.get("units", []) if u.get("image")) if o})
        return [("img-src", origins)] if origins else []
    if provider == "ethicalads":
        return [("connect-src", [opts["api"]]), ("img-src", [opts["api"]] + list(opts["media"]))]
    if provider == "frame":
        return [("frame-src", [opts["origin"]])]
    return []


def ads_txt(ads: Dict[str, Any]) -> Optional[str]:
    """ads.txt, or None when there is nothing to declare."""
    if not ads or not ads.get("enabled"):
        return None
    lines = (ads.get("options") or {}).get("ads_txt") or []
    if not lines:
        return None
    return "# Generated by tools/site_pages.py from the ads configuration.\n" + "\n".join(lines) + "\n"


def content_needs_script(ads: Dict[str, Any]) -> bool:
    """House units on content pages are rendered at generation time; everything else needs ads.js."""
    return bool(ads.get("enabled") and "content" in ads.get("slots", {}) and ads.get("provider") != "house")


# ===================================================================================================
# Site options
# ===================================================================================================
class SiteOptions:
    def __init__(self, site_url: Optional[str] = None, ads: Any = None, source_url: Optional[str] = None,
                 security_contact: Optional[str] = None, security_expires_days: int = 365,
                 static_dir: str = STATIC) -> None:
        self.site_url = _url(site_url, "site URL").rstrip("/") if site_url else None
        self.ads = normalize_ads(ads)
        check_frame_isolation(self.ads, self.site_url)
        self.source_url = _url(source_url, "source URL") if source_url else None
        contact = None
        if security_contact:
            contact = _plain(security_contact, "security contact", 300)
            if not contact.startswith(("mailto:", "https://", "tel:")):
                raise ValueError("security contact must be a mailto:, https:// or tel: URI")
        self.security_contact = contact
        self.security_expires_days = security_expires_days
        self.static_dir = static_dir

    @classmethod
    def from_config(cls, config: Any, static_dir: str = STATIC) -> "SiteOptions":
        links = getattr(config, "links", None) or {}
        return cls(site_url=getattr(config, "site_url", None), ads=getattr(config, "ads", None),
                   source_url=links.get("source"), security_contact=getattr(config, "security_contact", None),
                   static_dir=static_dir)

    def csp_extra(self, placement: str) -> CSPExtra:
        return ads_csp_extra(self.ads, placement)


# ===================================================================================================
# Learn data and sample resolution
# ===================================================================================================
def load_learn_data() -> Dict[str, Any]:
    _backend()
    from backend import learn_content as L
    from backend.learn import tours

    return {
        "modules": L.index()["modules"], "concepts": L.concepts(), "terms": L.glossary(),
        "compare": L.compare(), "fields": L.fields()["structs"], "levels": dict(L.LEVELS),
        "default_samples": dict(tours.DEFAULT_SAMPLES),
    }


def resolve_samples(get_doc: Callable[[str], Optional[Dict[str, Any]]], data: Dict[str, Any]) -> Dict[str, Any]:
    """Where each concept's "see it in this file" actions (and each comparison row) can be seen in the
    built-in samples: {concepts: {id: {action_id: {fmt: link}}}, compare: {row_id: {fmt: link}},
    presets: {pid: label}}. link = {sample, slice, node_id, off}. get_doc(preset_id) -> Document|None."""
    _backend()
    from backend import learn_content as L
    from backend.learn import resolve as R
    from backend.service import SYNTHETIC_PRESETS

    defaults = data["default_samples"]
    order = sorted(SYNTHETIC_PRESETS, key=lambda p: (p[0] not in defaults.values(), SYNTHETIC_PRESETS.index(p)))
    out: Dict[str, Any] = {"concepts": {}, "compare": {}, "presets": {}}
    for pid, label, _filename, _fmt, _desc in order:
        try:
            doc = get_doc(pid)
        except Exception:  # noqa: BLE001 - a sample that cannot be opened is simply not offered
            doc = None
        if not doc:
            continue
        out["presets"][pid] = label
        for index, slice_doc in enumerate((doc.get("slices") or [])[:4]):
            fmt = R.fmt_of(slice_doc)
            scopes = [("concepts", c["id"], "concept:" + c["id"]) for c in data["concepts"]] + [("compare", None, "compare")]
            for bucket, cid, scope in scopes:
                try:
                    actions = L.resolve_scope(scope, doc, slice_doc)
                except Exception:  # noqa: BLE001 - unknown ids in injected test data
                    continue
                for action in actions:
                    if not action.get("available") or not action.get("node_id"):
                        continue
                    key = action["id"]
                    target = out[bucket].setdefault(cid, {}) if cid else out[bucket]
                    per_fmt = target.setdefault(key, {})
                    if fmt not in per_fmt:
                        per_fmt[fmt] = {"sample": pid, "slice": index if len(doc.get("slices") or []) > 1 else None,
                                        "node_id": str(action["node_id"]), "off": action.get("abs_offset")}
    return out


def service_doc_getter(service: Any) -> Callable[[str], Optional[Dict[str, Any]]]:
    def get(pid: str) -> Optional[Dict[str, Any]]:
        return service.get_entry(doc="preset:" + pid).doc
    return get


def standalone_doc_getter(workspace_root: str = REPO) -> Callable[[str], Optional[Dict[str, Any]]]:
    _backend()
    from backend import runtime
    from backend.service import AnalysisService

    service = AnalysisService(workspace_root, runtime.RuntimeConfig("public"))
    return service_doc_getter(service)


# ===================================================================================================
# HTML helpers
# ===================================================================================================
def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def json_script(payload: Any) -> str:
    """JSON safe inside <script type="application/...json">: no '<', '>' or '&' can end the element."""
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return (text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def anchor_id(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", text).strip("-") or "x"


_TOKEN = re.compile(r"`([^`]*)`|\[\[([^\]|]+)(?:\|([^\]]*))?\]\]|\*([^*\s][^*]*)\*")


def file_version(static_dir: str, rel: str) -> str:
    try:
        with open(os.path.join(static_dir, *rel.split("/")), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:12]
    except OSError:
        return "0"


def app_hash(doc: Optional[str] = None, view: Optional[str] = None, params: Optional[Dict[str, str]] = None,
             slice_index: Optional[int] = None, off: Optional[int] = None) -> str:
    """The app's deep-link fragment (static/app.js parseLocationHash)."""
    parts = []
    if doc:
        parts.append("doc=" + quote(doc, safe=":"))
    if slice_index is not None:
        parts.append("slice=%d" % slice_index)
    if view:
        parts.append("view=" + quote(view, safe=":"))
    for key, value in (params or {}).items():
        parts.append("p.%s=%s" % (key, quote(str(value), safe="")))
    if off:
        parts.append("off=0x%x" % off)
    return "#" + "&".join(parts)


# ===================================================================================================
# Page builder
# ===================================================================================================
class SiteBuilder:
    def __init__(self, data: Dict[str, Any], options: SiteOptions, samples: Optional[Dict[str, Any]] = None) -> None:
        self.data = data
        self.opt = options
        self.samples = samples or {"concepts": {}, "compare": {}, "presets": {}}
        self.concepts = sorted(data["concepts"], key=lambda c: c.get("order", 0))
        self.concept_by_id = {c["id"]: c for c in self.concepts}
        self.terms = {t["id"]: t for t in data["terms"]}
        self.modules = {m["id"]: m for m in data["modules"]}
        self.levels = data.get("levels") or {}
        self.files: Dict[str, bytes] = {}
        self.pages: List[Dict[str, str]] = []
        self._used_terms: List[str] = []
        reserved = {"glossary", "compare", "fields"}
        clash = reserved & set(self.concept_by_id)
        if clash:
            raise ValueError("concept ids collide with section pages: %s" % ", ".join(sorted(clash)))
        bad = [c for c in self.concept_by_id if not re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", c)]
        if bad:
            raise ValueError("concept ids must be slugs: %s" % ", ".join(bad[:5]))
        v = options.static_dir
        self.css_v = file_version(v, "css/site.css")
        self.ads_css_v = file_version(v, "css/ads.css")
        self.ads_js_v = file_version(v, "js/ads.js")

    # -- rich text ----------------------------------------------------------------------------------
    def rich(self, text: Any, root: str) -> str:
        text = "" if text is None else str(text)
        out: List[str] = []
        pos = 0
        for m in _TOKEN.finditer(text):
            out.append(esc(text[pos:m.start()]))
            if m.group(1) is not None:
                out.append("<code>%s</code>" % esc(m.group(1)))
            elif m.group(2) is not None:
                out.append(self.link(m.group(2), m.group(3), root))
            else:
                out.append("<em>%s</em>" % esc(m.group(4)))
            pos = m.end()
        out.append(esc(text[pos:]))
        return "".join(out)

    def link(self, target: str, shown: Optional[str], root: str) -> str:
        if target.startswith("concept:"):
            hit = self.concept_by_id.get(target[8:])
            if hit is None:
                return esc(shown or target[8:])
            return '<a href="%slearn/%s/">%s</a>' % (root, esc(hit["id"]), esc(shown or hit["title"]))
        term = self.terms.get(target)
        if term is None:
            return esc(shown or target)
        if term["id"] not in self._used_terms:
            self._used_terms.append(term["id"])
        return '<a class="term" href="%slearn/glossary/#%s" title="%s">%s</a>' % (
            root, esc(term["id"]), esc(term["short"]), esc(shown or term["term"]))

    def blocks(self, blocks: Any, root: str) -> str:
        out: List[str] = []
        for block in blocks or []:
            if isinstance(block, str):
                out.append("<p>%s</p>" % self.rich(block, root))
            elif not isinstance(block, dict):
                continue
            elif block.get("type") == "list":
                tag = "ol" if block.get("ordered") else "ul"
                items = "".join("<li>%s</li>" % self.rich(i, root) for i in block.get("items") or [])
                out.append("<%s>%s</%s>" % (tag, items, tag))
            elif block.get("type") == "code":
                cap = block.get("caption")
                out.append('<figure class="code"><pre><code>%s</code></pre>%s</figure>' % (
                    esc(block.get("text", "")), "<figcaption>%s</figcaption>" % esc(cap) if cap else ""))
            elif block.get("type") == "table":
                head = "".join('<th scope="col">%s</th>' % self.rich(h, root) for h in block.get("head") or [])
                rows = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % self.rich(c, root) for c in row)
                               for row in block.get("rows") or [])
                out.append('<div class="table-wrap"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (head, rows))
            elif block.get("type") == "note":
                out.append('<div class="note" role="note"><p>%s</p></div>' % self.rich(block.get("text", ""), root))
        return "\n".join(out)

    def plain(self, text: Any) -> str:
        def link(m: "re.Match[str]") -> str:
            target, shown = m.group(2), m.group(3)
            if m.group(1) is not None:
                return m.group(1)
            if m.group(4) is not None:
                return m.group(4)
            if shown:
                return shown
            if target.startswith("concept:"):
                hit = self.concept_by_id.get(target[8:])
                return hit["title"] if hit else target[8:]
            term = self.terms.get(target)
            return term["term"] if term else target
        return _TOKEN.sub(link, "" if text is None else str(text))

    # -- page frame ---------------------------------------------------------------------------------
    @staticmethod
    def root_of(path: str) -> str:
        return "../" * path.count("/")

    def url_of(self, path: str) -> str:
        rel = path[: -len("index.html")] if path.endswith("index.html") else path
        return (self.opt.site_url + "/" + rel) if self.opt.site_url else None  # type: ignore[return-value]

    def ad_slot(self, path: str, root: str) -> str:
        ads = self.opt.ads
        if not (ads.get("enabled") and "content" in ads.get("slots", {})):
            return ""
        height = ads["slots"]["content"]["height"]
        label = ads["options"]["label"]
        inner = ""
        if ads["provider"] == "house":
            units = ads["options"]["units"]
            unit = units[int(hashlib.sha256(path.encode()).hexdigest(), 16) % len(units)]
            inner = self.house_unit(unit, label, root)
        return ('<aside class="ad-slot ad-h-%d" data-ad-slot="content" aria-label="%s">%s</aside>'
                % (height, esc(label), inner))

    @staticmethod
    def house_unit(unit: Dict[str, Any], label: str, root: str) -> str:
        url = unit["url"]
        if url.startswith("/"):
            url = root + url.lstrip("/")
        img = ""
        if unit.get("image"):
            src = unit["image"]
            if src.startswith("/"):
                src = root + src.lstrip("/")
            img = '<img class="bs-ad-img" src="%s" alt="%s" width="%d" height="%d" loading="lazy" decoding="async">' % (
                esc(src), esc(unit.get("image_alt", "")), unit["image_width"], unit["image_height"])
        sponsor = (" · " + esc(unit["sponsor"])) if unit.get("sponsor") else ""
        text = ('<span class="bs-ad-body">%s</span>' % esc(unit["text"])) if unit.get("text") else ""
        return ('<div class="bs-ad"><span class="bs-ad-label">%s%s</span>'
                '<a class="bs-ad-link" href="%s" rel="sponsored noopener" target="_blank">%s'
                '<span class="bs-ad-copy"><strong class="bs-ad-title">%s</strong>%s</span></a></div>'
                % (esc(label), sponsor, esc(url), img, esc(unit["title"]), text))

    def page(self, path: str, title: str, description: str, main: str, crumbs: List[Tuple[str, Optional[str]]],
             rail: str = "", jsonld: Optional[List[Dict[str, Any]]] = None, og_type: str = "article") -> None:
        root = self.root_of(path)
        if path in self.files:
            raise ValueError("duplicate page path " + path)
        url = self.url_of(path)
        canonical = url or "./"
        ads = self.opt.ads
        head: List[str] = [
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            '<meta name="color-scheme" content="dark light">',
            "<title>%s</title>" % esc(title + " — " + APP_NAME),
            '<meta name="description" content="%s">' % esc(description),
            '<link rel="canonical" href="%s">' % esc(canonical),
            '<link rel="icon" href="%sfavicon.svg" type="image/svg+xml">' % root,
            '<link rel="icon" href="%sfavicon.ico" sizes="32x32">' % root,
            '<meta property="og:site_name" content="%s">' % APP_NAME,
            '<meta property="og:type" content="%s">' % og_type,
            '<meta property="og:title" content="%s">' % esc(title),
            '<meta property="og:description" content="%s">' % esc(description),
            '<meta name="twitter:card" content="summary">',
        ]
        if url:
            head.append('<meta property="og:url" content="%s">' % esc(url))
        head.append('<link rel="stylesheet" href="%sstatic/css/site.css?v=%s">' % (root, self.css_v))
        slot = self.ad_slot(path, root)
        if slot:
            head.append('<link rel="stylesheet" href="%sstatic/css/ads.css?v=%s">' % (root, self.ads_css_v))
            if content_needs_script(ads):
                head.append('<script type="application/json" id="bs-ads-config">%s</script>' % json_script(ads))
                head.append('<script defer src="%sstatic/js/ads.js?v=%s"></script>' % (root, self.ads_js_v))
        if jsonld and self.opt.site_url:
            for item in jsonld:
                head.append('<script type="application/ld+json">%s</script>' % json_script(item))
        crumb_html = ""
        if crumbs:
            items = []
            for label, href in crumbs:
                items.append('<li><a href="%s">%s</a></li>' % (esc(href), esc(label)) if href
                             else '<li aria-current="page">%s</li>' % esc(label))
            crumb_html = '<nav class="crumbs" aria-label="Breadcrumb"><ol>%s</ol></nav>' % "".join(items)
        footer_links = ['<a href="%sabout.html">About</a>' % root, '<a href="%sprivacy.html">Privacy</a>' % root,
                        '<a href="%sterms.html">Terms</a>' % root]
        if self.opt.source_url:
            footer_links.append('<a href="%s" rel="noopener">Source</a>' % esc(self.opt.source_url))
        body = (
            '<a class="skip-link" href="#main">Skip to the content</a>\n'
            '<header class="site-header"><div class="site-header-inner">'
            '<a class="site-brand" href="%(r)s">%(app)s</a>'
            '<nav class="site-nav" aria-label="Sections"><a href="%(r)slearn/">Learn</a>'
            '<a href="%(r)slearn/glossary/">Glossary</a><a href="%(r)slearn/compare/">Comparison</a>'
            '<a href="%(r)slearn/fields/">Field reference</a></nav>'
            '<a class="site-open" href="%(r)s">Open the tool</a></div></header>\n'
            '<div class="site-layout%(railcls)s">%(crumbs)s\n<main id="main" class="site-main" tabindex="-1">\n%(main)s\n</main>\n'
            '%(rail)s</div>\n'
            '<footer class="site-footer"><div class="site-footer-inner"><p>%(app)s reads Mach-O, ELF and PE files. '
            'Nothing you open is ever executed.</p><nav aria-label="Site">%(links)s</nav></div></footer>\n'
        ) % {"r": root, "app": APP_NAME, "crumbs": crumb_html, "main": main,
             "rail": ('<aside class="site-rail" aria-label="Related">%s%s</aside>\n' % (rail, slot)) if (rail or slot) else "",
             "railcls": " has-rail" if (rail or slot) else "", "links": " ".join(footer_links)}
        doc = '<!DOCTYPE html>\n<html lang="en">\n<head>\n%s\n</head>\n<body>\n%s</body>\n</html>\n' % ("\n".join(head), body)
        self.files[path] = doc.encode("utf-8")
        self.pages.append({"path": path, "title": title, "description": description, "url": url or ""})

    def breadcrumb_ld(self, crumbs: List[Tuple[str, str]]) -> Dict[str, Any]:
        return {"@context": "https://schema.org", "@type": "BreadcrumbList",
                "itemListElement": [{"@type": "ListItem", "position": i + 1, "name": name, "item": url}
                                    for i, (name, url) in enumerate(crumbs)]}

    # -- deep links ---------------------------------------------------------------------------------
    def sample_label(self, pid: str) -> str:
        return self.samples["presets"].get(pid, pid)

    def concept_formats(self, concept: Dict[str, Any]) -> List[str]:
        fmts: List[str] = []
        for item in concept.get("see") or []:
            for f in item.get("formats") or list(FORMATS):
                if f in FORMATS and f not in fmts:
                    fmts.append(f)
        return [f for f in FORMATS if f in (fmts or FORMATS)]

    def concept_sample(self, concept: Dict[str, Any], fmt: str) -> Optional[str]:
        found = self.samples["concepts"].get(concept["id"], {})
        default = self.data["default_samples"].get(fmt)
        hits = [links[fmt]["sample"] for links in found.values() if fmt in links]
        if default in hits or (not hits and default in self.samples["presets"]):
            return default
        return hits[0] if hits else None

    # -- pages --------------------------------------------------------------------------------------
    def build(self) -> Dict[str, bytes]:
        self.landing()
        for i, concept in enumerate(self.concepts):
            self.concept_page(concept, self.concepts[i - 1] if i > 0 else None,
                              self.concepts[i + 1] if i + 1 < len(self.concepts) else None)
        self.glossary_page()
        self.compare_page()
        self.fields_pages()
        return self.files

    def counts_line(self) -> str:
        n_fields = sum(len(s.get("fields") or []) for s in self.data["fields"])
        return ("%d articles in curriculum order, a glossary of %d terms, a side-by-side comparison of the "
                "three formats in %d rows, and a reference to %d header fields."
                % (len(self.concepts), len(self.terms), len(self.data["compare"]), n_fields))

    def landing(self) -> None:
        path, root = "learn/index.html", "../"
        parts = ['<article class="prose"><header class="page-head"><h1>Learn Mach-O, ELF and PE</h1>',
                 '<p class="lede">How executables and libraries are laid out on disk, how they are linked and loaded, '
                 'and what the security features in them do. %s</p>' % esc(self.counts_line()),
                 '<p class="lede">The same material is in the Learn section of the tool, where each article can point at '
                 'the structures it describes in an open file. <a href="%s%s">Open the learning path in the tool</a>.</p></header>'
                 % (root, esc(app_hash(view="learn.home")))]
        for module in self.data["modules"]:
            items = [c for c in self.concepts if c.get("module") == module["id"]]
            if not items:
                continue
            parts.append('<section class="module" id="%s"><h2>%s</h2><p>%s</p><ol class="concept-list">'
                         % (esc(anchor_id(module["id"])), esc(module["title"]), esc(module.get("summary", ""))))
            for c in items:
                parts.append('<li><a href="%s/">%s</a> <span class="level level-%d">%s</span><p>%s</p></li>' % (
                    esc(c["id"]), esc(c["title"]), int(c.get("level", 1)), esc(self.levels.get(c.get("level"), "")),
                    esc(c.get("summary", ""))))
            parts.append("</ol></section>")
        parts.append('<section><h2>Reference</h2><ul class="ref-list"><li><a href="glossary/">Glossary</a>: every term used in '
                     'the articles and the tool.</li><li><a href="compare/">Format comparison</a>: the same job done by '
                     'Mach-O, ELF and PE.</li><li><a href="fields/">Field reference</a>: what each header field means, '
                     'who reads it, and what happens when it is wrong.</li></ul></section></article>')
        rail = self.rail_toc([(anchor_id(m["id"]), m["title"]) for m in self.data["modules"]], "Modules")
        ld = None
        if self.opt.site_url:
            ld = [{"@context": "https://schema.org", "@type": "CollectionPage", "name": "Learn Mach-O, ELF and PE",
                   "url": self.url_of(path), "description": self.counts_line(),
                   "hasPart": [{"@type": "TechArticle", "headline": c["title"], "url": self.url_of("learn/%s/index.html" % c["id"])}
                               for c in self.concepts]}]
        self.page(path, "Learn Mach-O, ELF and PE", "Articles, a glossary and a field reference for Mach-O, ELF and PE "
                  "executables: layout on disk, linking, loading and mitigations.", "\n".join(parts),
                  [("Learn", None)], rail, ld, og_type="website")

    def rail_toc(self, items: List[Tuple[str, str]], heading: str = "On this page") -> str:
        if not items:
            return ""
        return '<nav class="toc" aria-label="%s"><h2>%s</h2><ul>%s</ul></nav>' % (
            esc(heading), esc(heading), "".join('<li><a href="#%s">%s</a></li>' % (esc(a), esc(t)) for a, t in items))

    def concept_page(self, c: Dict[str, Any], prev: Optional[Dict[str, Any]], nxt: Optional[Dict[str, Any]]) -> None:
        path = "learn/%s/index.html" % c["id"]
        root = "../../"
        self._used_terms = []
        module = self.modules.get(c.get("module"), {"title": "", "id": ""})
        level = self.levels.get(c.get("level"), "")
        toc: List[Tuple[str, str]] = []
        opens = []
        for fmt in self.concept_formats(c):
            pid = self.concept_sample(c, fmt)
            if pid:
                opens.append('<a href="%s%s">%s sample (%s)</a>' % (root, esc(app_hash("preset:" + pid, "learn.home", {"c": c["id"]})),
                                                                     esc(FORMAT_NAMES[fmt]), esc(self.sample_label(pid))))
        parts = ['<article class="prose"><header class="page-head">',
                 '<p class="eyebrow">%s · %s</p>' % (esc(module.get("title", "")), esc(level)),
                 "<h1>%s</h1>" % esc(c["title"]), '<p class="lede">%s</p>' % esc(c.get("summary", ""))]
        if opens:
            parts.append('<p class="open-in-tool">Read this in the tool with a sample open: %s</p>' % " · ".join(opens))
        parts.append("</header>")
        parts.append(self.blocks(c.get("body"), root))
        toc.append(("formats", "In each format"))
        parts.append('<section id="formats"><h2>In each format</h2>')
        for fmt in FORMATS:
            blocks = (c.get("formats") or {}).get(fmt)
            if blocks:
                parts.append('<h3 id="%s">%s</h3>%s' % (fmt, FORMAT_NAMES[fmt], self.blocks(blocks, root)))
        parts.append("</section>")
        if c.get("differences"):
            toc.append(("differences", "Why the formats differ"))
            parts.append('<section id="differences"><h2>Why the formats differ</h2><p>%s</p></section>' % self.rich(c["differences"], root))
        see_items = []
        found = self.samples["concepts"].get(c["id"], {})
        for item in c.get("see") or []:
            links = found.get(item.get("id"), {})
            anchors = []
            for fmt in FORMATS:
                hit = links.get(fmt)
                if hit:
                    anchors.append('<a href="%s%s">%s</a>' % (root, esc(app_hash(
                        "preset:" + hit["sample"], hit["node_id"], None, hit["slice"], hit["off"])), esc(FORMAT_NAMES[fmt])))
            where = (" — open in the %s sample" % " · ".join(anchors)) if anchors else \
                ' — <span class="muted">not present in the built-in samples; open a file of your own in the tool</span>'
            see_items.append("<li>%s%s</li>" % (esc(item.get("label", "")), where))
        if see_items:
            toc.append(("see", "See it in a file"))
            parts.append('<section id="see"><h2>See it in a file</h2><ul class="see-list">%s</ul></section>' % "".join(see_items))
        if c.get("misconceptions"):
            toc.append(("misconceptions", "Common misconceptions"))
            parts.append('<section id="misconceptions"><h2>Common misconceptions</h2><dl class="misconceptions">%s</dl></section>' % "".join(
                "<dt>%s</dt><dd>%s</dd>" % (esc(m.get("claim", "")), self.rich(m.get("reality", ""), root)) for m in c["misconceptions"]))
        if c.get("sources"):
            toc.append(("sources", "Checked against"))
            parts.append('<section id="sources"><h2>Checked against</h2><ul>%s</ul></section>' % "".join(
                "<li>%s</li>" % esc(s) for s in c["sources"]))
        pager = []
        if prev:
            pager.append('<a class="pager-prev" rel="prev" href="../%s/"><span>Previous</span>%s</a>' % (esc(prev["id"]), esc(prev["title"])))
        if nxt:
            pager.append('<a class="pager-next" rel="next" href="../%s/"><span>Next</span>%s</a>' % (esc(nxt["id"]), esc(nxt["title"])))
        parts.append('<nav class="pager" aria-label="Curriculum">%s</nav></article>' % "".join(pager))
        rail = [self.rail_toc(toc)]
        nexts = [self.concept_by_id[n] for n in c.get("next") or [] if n in self.concept_by_id]
        if nexts:
            rail.append('<nav class="related" aria-label="Read next"><h2>Read next</h2><ul>%s</ul></nav>' % "".join(
                '<li><a href="../%s/">%s</a></li>' % (esc(n["id"]), esc(n["title"])) for n in nexts))
        if self._used_terms:
            rail.append('<nav class="related" aria-label="Terms used here"><h2>Terms used here</h2><ul>%s</ul></nav>' % "".join(
                '<li><a href="../glossary/#%s">%s</a></li>' % (esc(t), esc(self.terms[t]["term"])) for t in self._used_terms[:14]))
        ld = None
        if self.opt.site_url:
            ld = [{"@context": "https://schema.org", "@type": "TechArticle", "headline": c["title"],
                   "description": c.get("summary", ""), "url": self.url_of(path), "inLanguage": "en",
                   "isAccessibleForFree": True, "educationalLevel": LEVEL_SCHEMA.get(c.get("level"), ""),
                   "learningResourceType": "article",
                   "isPartOf": {"@type": "CollectionPage", "name": "Learn Mach-O, ELF and PE", "url": self.url_of("learn/index.html")}},
                  self.breadcrumb_ld([("Learn", self.url_of("learn/index.html")), (c["title"], self.url_of(path))])]
        self.page(path, c["title"], c.get("summary", ""), "\n".join(parts),
                  [("Learn", "../"), (module.get("title", ""), "../#" + anchor_id(module.get("id", ""))), (c["title"], None)],
                  "".join(rail), ld)

    def glossary_page(self) -> None:
        path, root = "learn/glossary/index.html", "../../"
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for t in sorted(self.terms.values(), key=lambda t: t["term"].lstrip("._").lower()):
            first = t["term"].lstrip("._")[:1].upper()
            key = first if first.isalpha() else "#"
            groups.setdefault(key, []).append(t)
        letters = sorted(groups, key=lambda k: (k == "#", k))
        parts = ['<article class="prose"><header class="page-head"><h1>Glossary</h1><p class="lede">%d terms used in the '
                 'articles and in the tool, each with a short definition and the article that explains it. '
                 '<a href="%s%s">Open the glossary in the tool</a>.</p></header>' % (len(self.terms), root, esc(app_hash(view="learn.glossary"))),
                 '<nav class="letters" aria-label="Letters"><ul>%s</ul></nav>' % "".join(
                     '<li><a href="#letter-%s">%s</a></li>' % (esc("sym" if k == "#" else k), esc(k)) for k in letters)]
        for k in letters:
            parts.append('<section id="letter-%s"><h2>%s</h2><dl class="glossary">' % (esc("sym" if k == "#" else k), esc(k)))
            for t in groups[k]:
                aka = (' <span class="aka">also %s</span>' % esc(", ".join(t.get("aka") or []))) if t.get("aka") else ""
                extra = []
                concept = self.concept_by_id.get(t.get("concept"))
                if concept:
                    extra.append('Explained in <a href="../%s/">%s</a>' % (esc(concept["id"]), esc(concept["title"])))
                see = [self.terms[s] for s in t.get("see") or [] if s in self.terms]
                if see:
                    extra.append("See also " + ", ".join('<a href="#%s">%s</a>' % (esc(s["id"]), esc(s["term"])) for s in see))
                extra.append('<a href="%s%s">In the tool</a>' % (root, esc(app_hash(view="learn.glossary", params={"t": t["id"]}))))
                parts.append('<dt id="%s"><dfn>%s</dfn>%s</dt><dd><p>%s</p><p class="term-links">%s</p></dd>' % (
                    esc(t["id"]), esc(t["term"]), aka, esc(t["short"]), " · ".join(extra)))
            parts.append("</dl></section>")
        parts.append("</article>")
        ld = None
        if self.opt.site_url:
            base = self.url_of(path)
            ld = [{"@context": "https://schema.org", "@type": "DefinedTermSet", "name": "BinaryStudio glossary", "url": base,
                   "hasDefinedTerm": [{"@type": "DefinedTerm", "@id": base + "#" + t["id"], "name": t["term"],
                                       "description": t["short"], "url": base + "#" + t["id"]} for t in self.terms.values()]},
                  self.breadcrumb_ld([("Learn", self.url_of("learn/index.html")), ("Glossary", base)])]
        self.page(path, "Glossary of binary-format terms", "Short definitions of %d terms from Mach-O, ELF and PE: "
                  "headers, segments, symbols, relocations, linking, loading and mitigations." % len(self.terms),
                  "\n".join(parts), [("Learn", "../"), ("Glossary", None)], "", ld, og_type="website")

    def compare_page(self) -> None:
        path, root = "learn/compare/index.html", "../../"
        parts = ['<article class="prose wide"><header class="page-head"><h1>Mach-O, ELF and PE side by side</h1>'
                 '<p class="lede">The same job, done by each of the three formats: %d aspects, each with the reason the '
                 'formats differ. <a href="%s%s">Open the comparison in the tool</a>.</p></header>'
                 % (len(self.data["compare"]), root, esc(app_hash(view="learn.compare")))]
        found = self.samples.get("compare", {})
        toc = []
        for row in self.data["compare"]:
            rid = anchor_id(row["id"])
            toc.append((rid, row["title"]))
            cols = []
            links = found.get("compare." + row["id"], {})
            for fmt in FORMATS:
                hit = links.get(fmt)
                see = ('<p class="cmp-see"><a href="%s%s">See it in the %s sample</a></p>' % (root, esc(app_hash(
                    "preset:" + hit["sample"], hit["node_id"], None, hit["slice"], hit["off"])), esc(FORMAT_NAMES[fmt]))) if hit else ""
                cols.append('<div class="cmp-col"><h3>%s</h3><p>%s</p>%s</div>' % (FORMAT_NAMES[fmt], self.rich(row.get(fmt, ""), root), see))
            concept = self.concept_by_id.get(row.get("concept"))
            more = (' <a href="../%s/">%s</a>' % (esc(concept["id"]), esc(concept["title"]))) if concept else ""
            parts.append('<section class="cmp-row" id="%s"><h2>%s</h2><div class="cmp-grid">%s</div>'
                         '<p class="why"><strong>Why they differ.</strong> %s%s</p></section>' % (
                             esc(rid), esc(row["title"]), "".join(cols), self.rich(row.get("why", ""), root),
                             (" Explained in" + more + ".") if more else ""))
        parts.append("</article>")
        ld = None
        if self.opt.site_url:
            ld = [self.breadcrumb_ld([("Learn", self.url_of("learn/index.html")), ("Format comparison", self.url_of(path))])]
        self.page(path, "Mach-O, ELF and PE compared", "How Mach-O, ELF and PE each identify a file, describe "
                  "memory, import symbols, relocate and sign code, and why they differ.", "\n".join(parts),
                  [("Learn", "../"), ("Format comparison", None)], self.rail_toc(toc, "Aspects"), ld)

    def fields_pages(self) -> None:
        by_fmt: Dict[str, List[Dict[str, Any]]] = {f: [] for f in FORMATS}
        for s in self.data["fields"]:
            if s.get("format") in by_fmt:
                by_fmt[s["format"]].append(s)
        idx_parts = ['<article class="prose"><header class="page-head"><h1>Field reference</h1><p class="lede">What each '
                     'header field means, which program reads it, and what happens when it holds a wrong value.</p></header>']
        for fmt in FORMATS:
            structs = by_fmt[fmt]
            if not structs:
                continue
            n = sum(len(s.get("fields") or []) for s in structs)
            idx_parts.append('<section><h2><a href="%s/">%s</a></h2><p>%d structures, %d fields.</p><ul class="struct-list">%s</ul></section>' % (
                fmt, FORMAT_NAMES[fmt], len(structs), n, "".join('<li><a href="%s/#%s">%s</a></li>' % (
                    fmt, esc(anchor_id(s["id"])), esc(s.get("title", s["id"]))) for s in structs)))
        idx_parts.append("</article>")
        self.page("learn/fields/index.html", "Field reference for Mach-O, ELF and PE",
                  "The meaning of every decoded header field of Mach-O, ELF and PE, who reads it, and what a wrong value does.",
                  "\n".join(idx_parts), [("Learn", "../"), ("Field reference", None)], "", None, og_type="website")
        default = self.data["default_samples"]
        for fmt in FORMATS:
            structs = by_fmt[fmt]
            if not structs:
                continue
            path, root = "learn/fields/%s/index.html" % fmt, "../../../"
            name = FORMAT_NAMES[fmt]
            doc = ("preset:" + default[fmt]) if default.get(fmt) in self.samples["presets"] else None
            parts = ['<article class="prose wide"><header class="page-head"><h1>%s field reference</h1><p class="lede">%d structures. '
                     'For each field: what it means, who reads it, what happens when it is wrong, and the nearest '
                     'equivalent in the other formats. <a href="%s%s">Open this reference in the tool%s</a>.</p></header>'
                     % (esc(name), len(structs), root, esc(app_hash(doc, "learn.fields", {"f": fmt})),
                        (" with the %s sample" % esc(self.sample_label(default[fmt]))) if doc else "")]
            used: set = set()
            toc = []
            for s in structs:
                sid = anchor_id(s["id"])
                toc.append((sid, s.get("title", s["id"])))
                parts.append('<section class="struct" id="%s"><h2>%s</h2>' % (esc(sid), esc(s.get("title", s["id"]))))
                for f in s.get("fields") or []:
                    fid = anchor_id(f["key"])
                    while fid in used or fid == sid:
                        fid += "-"
                    used.add(fid)
                    concept = self.concept_by_id.get(f.get("concept"))
                    more = ('<p class="field-more">Explained in <a href="../../%s/">%s</a></p>' % (
                        esc(concept["id"]), esc(concept["title"]))) if concept else ""
                    parts.append('<div class="field" id="%s"><h3><code>%s</code></h3><dl>'
                                 '<dt>Meaning</dt><dd>%s</dd><dt>Read by</dt><dd>%s</dd>'
                                 '<dt>If it is wrong</dt><dd>%s</dd><dt>In other formats</dt><dd>%s</dd></dl>%s</div>' % (
                                     esc(fid), esc(f.get("field", "")), esc(f.get("meaning", "")), esc(f.get("reader", "")),
                                     esc(f.get("if_wrong", "")), esc(f.get("peers", "")), more))
                parts.append("</section>")
            parts.append("</article>")
            ld = None
            if self.opt.site_url:
                ld = [self.breadcrumb_ld([("Learn", self.url_of("learn/index.html")),
                                          ("Field reference", self.url_of("learn/fields/index.html")),
                                          (name, self.url_of(path))])]
            self.page(path, "%s field reference" % name, "Every decoded %s header field: meaning, reader, the effect "
                      "of a wrong value, and the equivalent in the other formats." % name, "\n".join(parts),
                      [("Learn", "../../"), ("Field reference", "../"), (name, None)], self.rail_toc(toc, "Structures"), ld)


# ===================================================================================================
# Site files
# ===================================================================================================
STATIC_PAGES = [("index.html", "BinaryStudio"), ("about.html", "About"), ("privacy.html", "Privacy"), ("terms.html", "Terms")]

SECURITY_TXT_TEMPLATE = """\
# Generated by tools/site_pages.py (RFC 9116). Fill in the contact before publishing.
Contact: {contact}
Expires: {expires}
Preferred-Languages: en
{canonical}"""


def security_txt(options: SiteOptions, now: Optional[float] = None) -> Optional[str]:
    if not options.security_contact:
        return None
    now = time.time() if now is None else now
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + options.security_expires_days * 86400))
    canonical = ("Canonical: %s/.well-known/security.txt\n" % options.site_url) if options.site_url else ""
    return SECURITY_TXT_TEMPLATE.format(contact=options.security_contact, expires=expires, canonical=canonical)


def robots_txt(options: SiteOptions) -> str:
    lines = ["# Generated by tools/site_pages.py", "User-agent: *", "Allow: /", "Disallow: /api/"]
    if options.site_url:
        lines.append("Sitemap: %s/sitemap.xml" % options.site_url)
    return "\n".join(lines) + "\n"


def sitemap_xml(options: SiteOptions, page_paths: List[str]) -> Optional[str]:
    if not options.site_url:
        return None
    urls = []
    for path in page_paths:
        rel = path[: -len("index.html")] if path.endswith("index.html") else path
        urls.append("  <url><loc>%s</loc></url>" % esc(options.site_url + "/" + rel))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            + "\n".join(urls) + "\n</urlset>\n")


def generate_site(options: SiteOptions, data: Optional[Dict[str, Any]] = None,
                  samples: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, bytes], List[Dict[str, str]]]:
    """(files, page metadata). files: path relative to the site root -> bytes."""
    data = data if data is not None else load_learn_data()
    builder = SiteBuilder(data, options, samples)
    files = dict(builder.build())
    pages = builder.pages
    static_pages = [p for p, _ in STATIC_PAGES if os.path.isfile(os.path.join(options.static_dir, p))]
    files["robots.txt"] = robots_txt(options).encode("utf-8")
    sitemap = sitemap_xml(options, static_pages + [p["path"] for p in pages])
    if sitemap:
        files["sitemap.xml"] = sitemap.encode("utf-8")
    txt = ads_txt(options.ads)
    if txt:
        files["ads.txt"] = txt.encode("utf-8")
    sec = security_txt(options)
    if sec:
        files[".well-known/security.txt"] = sec.encode("utf-8")
    return files, pages


# ===================================================================================================
# Static build integration (tools/build_static.py)
# ===================================================================================================
def options_from_env(environ: Optional[Dict[str, str]] = None, site_url: Optional[str] = None,
                     ads: Any = None, security_contact: Optional[str] = None,
                     source_url: Optional[str] = None) -> SiteOptions:
    """The static build reads the same variables as the server; explicit arguments win."""
    env = dict(os.environ) if environ is None else environ
    if ads is None and env.get("BINARYSTUDIO_ADS", "").strip():
        ads = env["BINARYSTUDIO_ADS"]
    if isinstance(ads, str):
        ads = load_json_arg(ads)
    return SiteOptions(site_url=site_url or env.get("BINARYSTUDIO_SITE_URL") or None, ads=ads,
                       source_url=source_url or env.get("BINARYSTUDIO_SOURCE_URL") or None,
                       security_contact=security_contact or env.get("BINARYSTUDIO_SECURITY_CONTACT") or None)


def load_json_arg(text: str) -> Any:
    text = text.strip()
    if text.startswith("@"):
        with open(os.path.expanduser(text[1:]), "r", encoding="utf-8") as f:
            return json.load(f)
    return json.loads(text)


def add_to_build(files: Dict[str, bytes], options: SiteOptions) -> List[str]:
    """Add the site files to a static build's file map. Returns the paths added."""
    site_files, _pages = generate_site(options, samples=resolve_samples(standalone_doc_getter(), load_learn_data()))
    for path, data in site_files.items():
        files[path] = data
    return sorted(site_files)


def headers_rules(app_csp: str, content_csp: str, app_paths: List[str]) -> List[str]:
    """Extra _headers rules when content pages get a wider CSP than the app shell.

    `/*` carries the content CSP; each app path carries the app CSP as well. A host that joins the two
    (Cloudflare Pages does, with a comma) makes the browser enforce both policies, whose intersection
    is exactly the app CSP because the content CSP only adds sources to it. index.html also carries the
    app CSP in a <meta> tag, so the app document is held to it even on a host that keeps only one."""
    if app_csp == content_csp:
        return []
    out: List[str] = []
    for path in app_paths:
        out += [path, "  Content-Security-Policy: " + app_csp, ""]
    return out


# ===================================================================================================
# Server integration (backend/server.py)
# ===================================================================================================
class SiteHit:
    __slots__ = ("status", "body", "content_type", "kind", "location")

    def __init__(self, status: int, body: bytes, content_type: str, kind: str, location: Optional[str] = None) -> None:
        self.status = status
        self.body = body
        self.content_type = content_type
        self.kind = kind            # 'content' (HTML page) | 'file'
        self.location = location    # redirect target


_TYPES = {".html": "text/html; charset=utf-8", ".txt": "text/plain; charset=utf-8", ".xml": "application/xml; charset=utf-8"}


class SiteContent:
    """The generated site for one server: built once (lazily, or by warm()), then served from memory."""

    def __init__(self, workspace_root: str, config: Any, service: Any = None, log: Any = None) -> None:
        self.static_dir = os.path.join(os.path.abspath(workspace_root), "static")
        self.options = SiteOptions.from_config(config, self.static_dir)
        self.config = config
        self.service = service
        self.log = log
        self._files: Optional[Dict[str, bytes]] = None
        self._lock = threading.Lock()
        # What the rest of the server sees: the validated ads config and the CSP each page kind gets.
        config.ads = self.options.ads
        config.ads_csp = {"app": self.options.csp_extra("app"), "content": self.options.csp_extra("content")}

    def files(self) -> Dict[str, bytes]:
        if self._files is None:
            with self._lock:
                if self._files is None:
                    data = load_learn_data()
                    getter = service_doc_getter(self.service) if self.service is not None else standalone_doc_getter()
                    files, _ = generate_site(self.options, data, resolve_samples(getter, data))
                    self._files = files
        return self._files

    warm = files

    def lookup(self, url_path: str) -> Optional[SiteHit]:
        """A generated file for an already validated URL path (no query), or None."""
        if not (url_path.startswith("/learn") or url_path in ("/robots.txt", "/sitemap.xml", "/ads.txt",
                                                              "/.well-known/security.txt")):
            return None
        if any(seg in (".", "..") for seg in url_path.split("/")) or "\\" in url_path or "%" in url_path:
            return None
        files = self.files()
        rel = url_path.lstrip("/")
        if rel == "" or rel.endswith("/"):
            rel += "index.html"
        if rel in files:
            ext = os.path.splitext(rel)[1]
            return SiteHit(200, files[rel], _TYPES.get(ext, "application/octet-stream"),
                           "content" if ext == ".html" else "file")
        if (rel + "/index.html") in files:
            return SiteHit(301, b"", "", "file", location=url_path + "/")
        return None


def load_for_server(workspace_root: str, config: Any, service: Any = None, log: Any = None) -> SiteContent:
    return SiteContent(workspace_root, config, service, log)


# ===================================================================================================
# CLI
# ===================================================================================================
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Generate BinaryStudio's static learning pages and site files.")
    ap.add_argument("--out", help="write the generated files into this directory")
    ap.add_argument("--site-url", help="absolute URL of the site root (canonical links, sitemap)")
    ap.add_argument("--ads", help="ads configuration: JSON, or @file.json")
    ap.add_argument("--security-contact", help="Contact for /.well-known/security.txt (mailto: or https:)")
    ap.add_argument("--csp", action="store_true", help="print the CSP of the app shell and of content pages")
    args = ap.parse_args(argv)
    try:
        options = options_from_env(site_url=args.site_url, ads=args.ads, security_contact=args.security_contact)
    except (ValueError, OSError) as exc:
        sys.stderr.write("site_pages: %s\n" % exc)
        return 2
    if args.csp:
        _backend()
        from backend.runtime import build_csp

        print("app shell:     " + build_csp(options.csp_extra("app")))
        print("content pages: " + build_csp(options.csp_extra("content")))
    if args.out:
        files, pages = generate_site(options, samples=resolve_samples(standalone_doc_getter(), load_learn_data()))
        for rel, data in files.items():
            dest = os.path.join(os.path.abspath(args.out), *rel.split("/"))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(data)
        sys.stderr.write("wrote %d files (%d pages) to %s\n" % (len(files), len(pages), args.out))
    if not args.out and not args.csp:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
