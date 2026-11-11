"""
The public-site layer (tools/site_pages.py, static/*.html, static/js/ads.js, static/css/site.css).

  PageTests        every generated page and every static site page is well-formed HTML with a unique
                   title, description and canonical URL; every internal link and anchor resolves;
                   every deep link into the app names a real sample, view and parameter
  EscapingTests    hostile Learn data and hostile ad config cannot inject markup
  SiteFileTests    robots.txt / sitemap.xml / ads.txt / security.txt agree with each other and the config
  AdsPolicyTests   config validation, and the CSP delta of each provider
  DisabledTests    with ads off: no ad markup, script, stylesheet or third-party origin anywhere
  ServerTests      the Python server: routes, redirects, 404 page, ETag, and app-shell vs content CSP
                   under each provider configuration
  StaticBuildTests the static build with a provider configured: _headers, baked-in config, no precache
"""

import html.parser
import io
import json
import os
import re
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urljoin, urlsplit

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from backend import runtime  # noqa: E402
from backend.api import EventLog  # noqa: E402
from backend.service import SYNTHETIC_PRESETS  # noqa: E402

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("site_pages_under_test", os.path.join(REPO, "tools", "site_pages.py"))
site_pages = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(site_pages)  # type: ignore[union-attr]

STATIC = os.path.join(REPO, "static")
STATIC_PAGES = ["about.html", "privacy.html", "terms.html", "404.html"]
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
LEARN_VIEWS = {"learn.home", "learn.tours", "learn.glossary", "learn.compare", "learn.fields"}
PRESET_IDS = {p[0] for p in SYNTHETIC_PRESETS}
URL_RE = re.compile(r"\bhttps?://([a-z0-9.-]+\.[a-z]{2,})", re.I)

_SAMPLES: Dict[str, Any] = {}


def samples() -> Dict[str, Any]:
    if not _SAMPLES:
        _SAMPLES.update(site_pages.resolve_samples(site_pages.standalone_doc_getter(REPO), site_pages.load_learn_data()))
    return _SAMPLES


def generate(**kw: Any) -> Tuple[Dict[str, bytes], List[Dict[str, str]]]:
    data = kw.pop("data", None)
    return site_pages.generate_site(site_pages.SiteOptions(**kw), data, samples() if data is None else None)


class Doc(html.parser.HTMLParser):
    """Collects tags, ids, links and text; fails on mis-nested or unclosed elements."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: List[str] = []
        self.errors: List[str] = []
        self.ids: List[str] = []
        self.tags: List[Tuple[str, Dict[str, str]]] = []
        self.title = ""
        self._in_title = False
        self.doctype = False
        self.script_text: List[str] = []
        self._in_script = False

    def handle_decl(self, decl: str) -> None:
        self.doctype = self.doctype or decl.lower() == "doctype html"

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        self.tags.append((tag, a))
        if "id" in a:
            self.ids.append(a["id"])
        if tag == "title":
            self._in_title = True
        if tag == "script":
            self._in_script = True
        if tag not in VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.stack and self.stack[-1] == tag:
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID:
            self.errors.append("end tag for void element " + tag)
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append("unexpected </%s>, open: %s" % (tag, self.stack[-3:]))
            if tag in self.stack:
                while self.stack and self.stack.pop() != tag:
                    pass
            return
        self.stack.pop()
        if tag == "title":
            self._in_title = False
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._in_script:
            self.script_text.append(data)

    def attr(self, tag: str, attr_name: str, **match: str) -> List[str]:
        return [a[attr_name] for t, a in self.tags
                if t == tag and attr_name in a and all(a.get(k) == v for k, v in match.items())]


def parse(data: bytes) -> Doc:
    d = Doc()
    d.feed(data.decode("utf-8"))
    d.close()
    if d.stack:
        d.errors.append("unclosed: %s" % d.stack)
    return d


def site_view(files: Dict[str, bytes]) -> Dict[str, bytes]:
    """Every page a visitor can reach: generated files plus the static site pages at the root."""
    out = dict(files)
    for name in STATIC_PAGES + ["favicon.ico", "favicon.svg"]:
        with open(os.path.join(STATIC, name), "rb") as f:
            out[name] = f.read()
    out["index.html"] = b"<!DOCTYPE html><html lang=en><head><title>app</title></head><body></body></html>"
    for rel in ("css/site.css", "css/ads.css", "js/ads.js"):
        with open(os.path.join(STATIC, *rel.split("/")), "rb") as f:
            out["static/" + rel] = f.read()
    return out


def target_of(page_path: str, href: str) -> Tuple[str, str]:
    """(site-relative file path, fragment) for an internal href on `page_path`."""
    base = "http://site.example/" + page_path
    url = urljoin(base, href)
    parts = urlsplit(url)
    path = unquote(parts.path).lstrip("/")
    if path == "" or path.endswith("/"):
        path += "index.html"
    return path, parts.fragment


class PageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.files, cls.pages = generate(site_url="https://binarystudio.example")
        cls.all = site_view(cls.files)
        cls.docs = {p: parse(b) for p, b in cls.all.items() if p.endswith(".html")}

    def test_counts_match_the_data(self) -> None:
        data = site_pages.load_learn_data()
        paths = set(self.files)
        for c in data["concepts"]:
            self.assertIn("learn/%s/index.html" % c["id"], paths)
        for p in ("learn/index.html", "learn/glossary/index.html", "learn/compare/index.html", "learn/fields/index.html",
                  "learn/fields/macho/index.html", "learn/fields/elf/index.html", "learn/fields/pe/index.html"):
            self.assertIn(p, paths)
        gloss = self.docs["learn/glossary/index.html"]
        for t in data["terms"]:
            self.assertIn(t["id"], gloss.ids, t["id"])
        self.assertEqual(len(self.pages), len(data["concepts"]) + 7)

    def test_well_formed(self) -> None:
        for path, d in self.docs.items():
            if path == "index.html":
                continue
            self.assertTrue(d.doctype, path)
            self.assertEqual(d.errors, [], path)
            self.assertEqual(d.attr("html", "lang"), ["en"], path)
            self.assertEqual(len(d.attr("meta", "charset")), 1, path)
            self.assertEqual(len(d.attr("main", "id")), 1, path)
            self.assertEqual(sum(1 for t, _ in d.tags if t == "h1"), 1, path)
            dupes = sorted({i for i in d.ids if d.ids.count(i) > 1})
            self.assertEqual(dupes, [], path)
            self.assertFalse(any("style" in a for _, a in d.tags), path + " has an inline style attribute")
            self.assertFalse(any(k.startswith("on") for _, a in d.tags for k in a), path + " has an inline handler")
            for t, a in d.tags:
                if t == "script":
                    self.assertTrue(a.get("type") in ("application/json", "application/ld+json") or a.get("src"), path)
                if t == "img":
                    self.assertIn("alt", a, path)

    def test_unique_titles_descriptions_canonicals(self) -> None:
        titles, descs, canon = {}, {}, {}
        for path, d in self.docs.items():
            if path in ("index.html", "404.html"):
                continue
            title = d.title.strip()
            desc = d.attr("meta", "content", name="description")
            can = d.attr("link", "href", rel="canonical")
            self.assertTrue(title and len(desc) == 1 and desc[0].strip() and len(can) == 1, path)
            resolved = urljoin("https://binarystudio.example/" + path, can[0])
            self.assertTrue(resolved.startswith("https://binarystudio.example/"), path)
            expected = "https://binarystudio.example/" + (path[:-len("index.html")] if path.endswith("index.html") else path)
            self.assertEqual(resolved, expected, path)
            for store, value in ((titles, title), (descs, desc[0]), (canon, resolved)):
                self.assertNotIn(value, store, "%s duplicates %s" % (path, store.get(value)))
                store[value] = path
        self.assertIn('content="noindex"', self.all["404.html"].decode())

    def test_canonical_without_site_url_is_the_page_itself(self) -> None:
        files, _ = generate()
        for path in ("learn/index.html", "learn/aslr/index.html", "learn/fields/pe/index.html"):
            d = parse(files[path])
            self.assertEqual(d.attr("link", "href", rel="canonical"), ["./"])
            self.assertNotIn(b"application/ld+json", files[path])

    def test_internal_links_and_anchors_resolve(self) -> None:
        checked = 0
        for path, d in self.docs.items():
            if path == "index.html":
                continue
            # 404.html is served at arbitrary depths, so it uses root-relative links.
            hrefs = d.attr("a", "href") + d.attr("link", "href") + d.attr("script", "src") + d.attr("img", "src")
            for href in hrefs:
                if href.startswith(("http://", "https://")):
                    self.assertTrue(href.startswith("https://binarystudio.example/"), (path, href))
                    href = href[len("https://binarystudio.example"):]
                if href.startswith("#"):
                    self.assertIn(href[1:], d.ids, (path, href))
                    continue
                target, frag = target_of("x/y/z.html" if path == "404.html" else path, href)
                target = target.split("?", 1)[0]
                self.assertIn(target, self.all, "%s -> %s" % (path, href))
                if frag and target != "index.html":
                    self.assertIn(frag, self.docs[target].ids, "%s -> %s" % (path, href))
                checked += 1
        self.assertGreater(checked, 2000)

    def test_deep_links_name_real_samples_views_and_params(self) -> None:
        data = site_pages.load_learn_data()
        concepts = {c["id"] for c in data["concepts"]}
        terms = {t["id"] for t in data["terms"]}
        node_ids = set()
        for per_concept in samples()["concepts"].values():
            for links in per_concept.values():
                node_ids |= {v["node_id"] for v in links.values()}
        for links in samples()["compare"].values():
            node_ids |= {v["node_id"] for v in links.values()}
        n = 0
        for path, d in self.docs.items():
            for href in d.attr("a", "href"):
                target, frag = target_of(path, href)
                if target != "index.html" or not frag:
                    continue
                pairs = dict(p.split("=", 1) for p in frag.split("&"))
                pairs = {k: unquote(v) for k, v in pairs.items()}
                self.assertLessEqual(set(pairs), {"doc", "slice", "view", "off", "p.c", "p.t", "p.f"}, href)
                if "doc" in pairs:
                    self.assertRegex(pairs["doc"], r"^preset:[A-Za-z0-9_.-]{1,80}$")
                    self.assertIn(pairs["doc"][7:], PRESET_IDS, href)
                view = pairs.get("view")
                self.assertTrue(view in LEARN_VIEWS or view in node_ids, href)
                if view not in LEARN_VIEWS:
                    self.assertIn("doc", pairs, href)
                if "p.c" in pairs:
                    self.assertIn(pairs["p.c"], concepts)
                if "p.t" in pairs:
                    self.assertIn(pairs["p.t"], terms)
                if "p.f" in pairs:
                    self.assertIn(pairs["p.f"], ("macho", "elf", "pe"))
                if "off" in pairs:
                    self.assertRegex(pairs["off"], r"^0x[0-9a-f]+$")
                n += 1
        self.assertGreater(n, 300)

    def test_structured_data_is_valid_json_and_truthful(self) -> None:
        for path, raw in self.files.items():
            if not path.endswith(".html"):
                continue
            for block in re.findall(rb'<script type="application/ld\+json">(.*?)</script>', raw, re.S):
                obj = json.loads(block.decode("utf-8"))
                self.assertEqual(obj["@context"], "https://schema.org")
                keys = set()

                def walk(o: Any) -> None:
                    if isinstance(o, dict):
                        keys.update(o)
                        for v in o.values():
                            walk(v)
                    elif isinstance(o, list):
                        for v in o:
                            walk(v)
                walk(obj)
                # Nothing claimed that the data does not support: no authors, dates, ratings or prices.
                self.assertFalse(keys & {"author", "datePublished", "dateModified", "aggregateRating", "review", "offers"}, path)


HOSTILE = '<script>alert(1)</script>"><img src=x onerror=alert(2)>&amp;\u2028</script>'


def hostile_data() -> Dict[str, Any]:
    data = json.loads(json.dumps(site_pages.load_learn_data()))
    c = data["concepts"][0]
    c["title"] = "T " + HOSTILE
    c["summary"] = "S " + HOSTILE
    c["body"] = [
        "Para %s `<b>code</b>` *<i>em</i>* [[bit|<u>shown</u>]] [[concept:%s|<s>x</s>]] [[no-such-term]] [[concept:nope]]" % (HOSTILE, data["concepts"][1]["id"]),
        {"type": "list", "items": [HOSTILE], "ordered": True},
        {"type": "code", "text": "</code></pre>" + HOSTILE, "caption": HOSTILE},
        {"type": "table", "head": [HOSTILE], "rows": [[HOSTILE, "`" + HOSTILE + "`"]]},
        {"type": "note", "text": HOSTILE},
        {"type": "unknown", "text": HOSTILE},
    ]
    c["misconceptions"] = [{"claim": HOSTILE, "reality": HOSTILE}]
    c["sources"] = [HOSTILE]
    c["see"] = [{"id": "x.1", "label": HOSTILE, "at": {}}]
    data["terms"][0]["term"] = HOSTILE
    data["terms"][0]["short"] = HOSTILE
    data["terms"][0]["aka"] = [HOSTILE]
    data["modules"][0]["title"] = HOSTILE
    data["compare"][0]["title"] = HOSTILE
    data["compare"][0]["why"] = HOSTILE
    data["fields"][0]["title"] = HOSTILE
    data["fields"][0]["fields"][0]["meaning"] = HOSTILE
    data["fields"][0]["fields"][0]["field"] = HOSTILE
    data["fields"][0]["fields"][0]["key"] = HOSTILE
    return data


class EscapingTests(unittest.TestCase):
    def check(self, files: Dict[str, bytes], allowed_scripts: int = 0) -> None:
        for path, raw in files.items():
            if not path.endswith(".html"):
                continue
            text = raw.decode("utf-8")
            self.assertNotIn("<script>alert", text, path)
            self.assertNotIn("<img src=x", text, path)
            self.assertNotIn("<b>code", text, path)
            self.assertNotIn("<u>shown", text, path)
            d = parse(raw)
            self.assertEqual(d.errors, [], path)
            self.assertFalse(any(k.startswith("on") for _, a in d.tags for k in a), path)
            for t, a in d.tags:
                self.assertNotIn(t, ("b", "i", "u", "s", "iframe", "object", "embed"), path)
                if t == "img":
                    self.assertNotEqual(a.get("src"), "x", path)
            # Data islands parse as JSON and their content never ends the element.
            for block in re.findall(r'<script type="application/(?:ld\+)?json"[^>]*>(.*?)</script>', text, re.S):
                json.loads(block)
                self.assertNotIn("<", block)

    def test_hostile_learn_data_is_escaped(self) -> None:
        files, _ = site_pages.generate_site(site_pages.SiteOptions(site_url="https://binarystudio.example"), hostile_data(), None)
        self.check(files)
        page = files["learn/%s/index.html" % site_pages.load_learn_data()["concepts"][0]["id"]].decode()
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("<code>&lt;b&gt;code&lt;/b&gt;</code>", page)
        self.assertIn("<em>&lt;i&gt;em&lt;/i&gt;</em>", page)
        self.assertIn("no-such-term", page)  # unknown links degrade to text

    def test_hostile_house_unit_and_island_are_escaped(self) -> None:
        ads = {"enabled": True, "provider": "house", "slots": {"content": {}},
               "options": {"units": [{"title": HOSTILE[:80], "text": HOSTILE, "url": "/about.html?q=\"><x", "sponsor": "<b>s</b>"}]}}
        files, _ = generate(ads=ads)
        self.check(files)
        ads2 = {"enabled": True, "provider": "ethicalads", "slots": {"content": {}},
                "options": {"publisher": "p", "consent_text": "</script><script>alert(3)</script>"}}
        files2, _ = generate(ads=ads2)
        self.check(files2)
        island = re.search(rb'id="bs-ads-config">(.*?)</script>', files2["learn/index.html"]).group(1)
        self.assertEqual(json.loads(island)["options"]["consent_text"], "</script><script>alert(3)</script>")

    def test_concept_ids_must_be_slugs_and_not_collide(self) -> None:
        data = site_pages.load_learn_data()
        bad = json.loads(json.dumps(data))
        bad["concepts"][0]["id"] = "../../etc"
        with self.assertRaises(ValueError):
            site_pages.SiteBuilder(bad, site_pages.SiteOptions())
        bad["concepts"][0]["id"] = "glossary"
        with self.assertRaises(ValueError):
            site_pages.SiteBuilder(bad, site_pages.SiteOptions())


class SiteFileTests(unittest.TestCase):
    def test_robots_and_sitemap_agree(self) -> None:
        files, pages = generate(site_url="https://binarystudio.example/sub/")
        robots = files["robots.txt"].decode()
        self.assertIn("Sitemap: https://binarystudio.example/sub/sitemap.xml\n", robots)
        self.assertIn("Disallow: /api/", robots)
        locs = re.findall(r"<loc>([^<]+)</loc>", files["sitemap.xml"].decode())
        self.assertEqual(len(locs), len(set(locs)))
        expected = {"https://binarystudio.example/sub/" + (p["path"][:-10] if p["path"].endswith("index.html") else p["path"]) for p in pages}
        expected |= {"https://binarystudio.example/sub/" + n for n in ("about.html", "privacy.html", "terms.html")}
        expected.add("https://binarystudio.example/sub/")
        self.assertEqual(set(locs), expected)
        self.assertNotIn("404", files["sitemap.xml"].decode())

    def test_no_sitemap_without_site_url(self) -> None:
        files, _ = generate()
        self.assertNotIn("sitemap.xml", files)
        self.assertNotIn("Sitemap:", files["robots.txt"].decode())

    def test_ads_txt_only_when_there_is_something_to_declare(self) -> None:
        line = "google.com, pub-0000000000000000, DIRECT, f08c47fec0942fa0"
        self.assertNotIn("ads.txt", generate()[0])
        self.assertNotIn("ads.txt", generate(ads={"enabled": False, "options": {"ads_txt": [line]}})[0])
        house = {"enabled": True, "provider": "house", "options": {"units": [{"title": "t", "url": "/"}]}}
        self.assertNotIn("ads.txt", generate(ads=house)[0])
        house["options"]["ads_txt"] = [line, "contact=ads@binarystudio.example"]
        txt = generate(ads=house)[0]["ads.txt"].decode()
        self.assertIn(line + "\n", txt)
        for bad in ("google.com pub-1 DIRECT", "x, y, MAYBE", "a.com, p, DIRECT\nevil.com, p, DIRECT", "<script>"):
            house["options"]["ads_txt"] = [bad]
            with self.assertRaises(ValueError, msg=bad):
                site_pages.normalize_ads(house)

    def test_security_txt_only_with_a_contact(self) -> None:
        self.assertNotIn(".well-known/security.txt", generate()[0])
        txt = generate(security_contact="mailto:security@binarystudio.example", site_url="https://binarystudio.example")[0][
            ".well-known/security.txt"].decode()
        self.assertIn("Contact: mailto:security@binarystudio.example\n", txt)
        self.assertRegex(txt, r"Expires: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
        self.assertIn("Canonical: https://binarystudio.example/.well-known/security.txt", txt)
        with self.assertRaises(ValueError):
            site_pages.SiteOptions(security_contact="javascript:alert(1)")


class AdsPolicyTests(unittest.TestCase):
    def test_disabled_shapes(self) -> None:
        for raw in (None, {}, {"enabled": False}, {"enabled": False, "provider": "frame"}):
            self.assertEqual(site_pages.normalize_ads(raw), runtime.RuntimeConfig("local").ads)

    def test_validation(self) -> None:
        bad = [
            {"enabled": True, "provider": "adsense"},
            {"enabled": True, "provider": "house", "options": {"units": []}},
            {"enabled": True, "provider": "house", "options": {"units": [{"title": "t", "url": "javascript:alert(1)"}]}},
            {"enabled": True, "provider": "house", "options": {"units": [{"title": "t", "url": "//evil.example/"}]}},
            {"enabled": True, "provider": "house", "options": {"units": [{"title": "t", "url": "http://evil.example/"}]}},
            {"enabled": True, "provider": "house", "options": {"units": [{"title": "t", "url": "/", "image": "data:image/png;base64,AA"}]}},
            {"enabled": True, "provider": "house", "slots": {"sidebar": {}}, "options": {"units": [{"title": "t", "url": "/"}]}},
            {"enabled": True, "provider": "house", "slots": {"content": {"height": 900}}, "options": {"units": [{"title": "t", "url": "/"}]}},
            {"enabled": True, "provider": "house", "options": {"label": "Recommended", "units": [{"title": "t", "url": "/"}]}},
            {"enabled": True, "provider": "ethicalads", "options": {"publisher": "a b"}},
            {"enabled": True, "provider": "ethicalads", "options": {"publisher": "p", "api": "http://evil.example"}},
            {"enabled": True, "provider": "frame", "options": {}},
            {"enabled": True, "provider": "frame", "options": {"src": "https://u:p@ads.example/"}},
            {"enabled": True, "provider": "house", "extra": 1},
        ]
        for raw in bad:
            with self.assertRaises(ValueError, msg=json.dumps(raw)):
                site_pages.normalize_ads(raw)
        with self.assertRaises(ValueError):
            site_pages.SiteOptions(site_url="https://binarystudio.example",
                                   ads={"enabled": True, "provider": "frame", "options": {"src": "https://binarystudio.example/ad.html"}})

    def test_csp_delta_per_provider(self) -> None:
        cases = [
            ({"provider": "house", "options": {"units": [{"title": "t", "url": "/", "image": "/static/sponsor.png"}]}}, []),
            ({"provider": "house", "options": {"units": [{"title": "t", "url": "https://sponsor.example/",
                                                          "image": "https://img.sponsor.example/a.png"}]}},
             [("img-src", ["https://img.sponsor.example"])]),
            ({"provider": "ethicalads", "options": {"publisher": "p"}},
             [("connect-src", ["https://server.ethicalads.io"]),
              ("img-src", ["https://server.ethicalads.io", "https://media.ethicalads.io"])]),
            ({"provider": "frame", "options": {"src": "https://ads.other.example/unit.html"}},
             [("frame-src", ["https://ads.other.example"])]),
        ]
        for spec, delta in cases:
            content_only = site_pages.normalize_ads(dict(spec, enabled=True, slots={"content": {}}))
            both = site_pages.normalize_ads(dict(spec, enabled=True, slots={"content": {}, "footer": {}}))
            self.assertEqual(site_pages.ads_csp_extra(content_only, "content"), delta)
            self.assertEqual(site_pages.ads_csp_extra(content_only, "app"), [], "content-only ads must not widen the app")
            self.assertEqual(site_pages.ads_csp_extra(both, "app"), delta)
            app_only = site_pages.normalize_ads(dict(spec, enabled=True, slots={"footer": {}}))
            self.assertEqual(site_pages.ads_csp_extra(app_only, "content"), [])

    def test_ads_js_has_no_third_party_origin_and_no_innerhtml(self) -> None:
        with open(os.path.join(STATIC, "js", "ads.js"), encoding="utf-8") as f:
            js = f.read()
        self.assertEqual(URL_RE.findall(js), [])
        code = re.sub(r"/\*.*?\*/|//[^\n]*", "", js, flags=re.S)
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                       "allow-same-origin", "allow-top-navigation", ".style."):
            self.assertNotIn(banned, code, banned)
        self.assertIn("'allow-scripts allow-popups allow-popups-to-escape-sandbox'", code)
        self.assertIn("rel = 'sponsored noopener'", code)
        with open(os.path.join(STATIC, "css", "ads.css"), encoding="utf-8") as f:
            css = re.sub(r"/\*.*?\*/", "", f.read(), flags=re.S)
        for banned in ("animation", "transition", "position: fixed", "position: sticky", "@keyframes"):
            self.assertNotIn(banned, css)


class DisabledTests(unittest.TestCase):
    def test_no_ad_markup_or_requests_and_identical_output(self) -> None:
        a, _ = generate()
        b, _ = generate(ads={"enabled": False, "provider": "house", "slots": {"content": {}}, "options": {}})
        self.assertEqual(a, b)
        for path, raw in a.items():
            for needle in (b"ad-slot", b"ads.js", b"ads.css", b"bs-ads-config", b"Advertisement"):
                self.assertNotIn(needle, raw, path)

    def test_no_third_party_origins_anywhere(self) -> None:
        files, _ = generate()
        for path, raw in site_view(files).items():
            if path.endswith((".ico",)):
                continue
            hosts = [h for h in URL_RE.findall(raw.decode("utf-8", "replace")) if h != "www.w3.org" and not h.endswith(".example")]
            self.assertEqual(hosts, [], path)

    def test_app_shell_does_not_reference_ads(self) -> None:
        with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
            index = re.sub(r"<!--.*?-->", "", f.read(), flags=re.S)
        self.assertNotIn("ads.js", index)
        self.assertNotIn("ads.css", index)
        with open(os.path.join(STATIC, "app.js"), encoding="utf-8") as f:
            app = f.read()
        # The only loader is behind the explicit footer opt-in.
        self.assertIn("if (footerSlot && !document.getElementById('bs-ads-script'))", app)

    def test_static_site_pages_load_no_script(self) -> None:
        for name in STATIC_PAGES:
            with open(os.path.join(STATIC, name), "rb") as f:
                self.assertNotIn(b"<script", f.read(), name)

    def test_placeholders_are_marked(self) -> None:
        found = set()
        for name in STATIC_PAGES:
            with open(os.path.join(STATIC, name), encoding="utf-8") as f:
                text = f.read()
            found |= set(re.findall(r'<mark class="fill">\[([^\]]+)\]</mark>', text))
            self.assertEqual(len(re.findall(r"\[[A-Z0-9][^\]<\[]{3,}\]", text)),
                             len(re.findall(r'<mark class="fill">\[', text)), name + ": an unmarked placeholder")
        for key in ("OPERATOR NAME", "CONTACT EMAIL", "JURISDICTION"):
            self.assertIn(key, found)


class ServerTests(unittest.TestCase):
    def start(self, **cfg: Any) -> str:
        from backend.server import create_server

        mode = cfg.pop("mode", "public")
        server = create_server(REPO, "127.0.0.1", 0, config=runtime.RuntimeConfig(mode, **cfg), log=EventLog(stream=io.StringIO()))
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:%d" % server.server_address[1]

    @staticmethod
    def get(url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a: Any, **k: Any) -> None:
                return None

        opener = urllib.request.build_opener(NoRedirect)
        try:
            with opener.open(urllib.request.Request(url, headers=headers or {}), timeout=20) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()

    def test_routes(self) -> None:
        base = self.start()
        s, h, b = self.get(base + "/learn/")
        self.assertEqual((s, h["content-type"]), (200, "text/html; charset=utf-8"))
        self.assertEqual(h["cache-control"], "no-cache")
        s2, _, _ = self.get(base + "/learn/", {"If-None-Match": h["etag"]})
        self.assertEqual(s2, 304)
        s, h, _ = self.get(base + "/learn/aslr")
        self.assertEqual((s, h["location"]), (301, "/learn/aslr/"))
        for path in ("/learn/aslr/", "/learn/aslr/index.html", "/learn/glossary/", "/learn/fields/pe/", "/robots.txt",
                     "/favicon.ico", "/favicon.svg", "/privacy.html", "/terms.html", "/about.html"):
            self.assertEqual(self.get(base + path)[0], 200, path)
        for path in ("/sitemap.xml", "/ads.txt", "/.well-known/security.txt", "/learn/nope/", "/learn/../index.html",
                     "/learn/%2e%2e/backend/server.py", "/static/robots.txt"):
            self.assertIn(self.get(base + path)[0], (400, 404), path)
        s, h, b = self.get(base + "/no-such-page", {"Accept": "text/html,*/*"})
        self.assertEqual((s, h["content-type"]), (404, "text/html; charset=utf-8"))
        self.assertIn(b"Page not found", b)
        s, h, b = self.get(base + "/no-such-page")
        self.assertEqual((s, json.loads(b)["code"]), (404, "not_found"))

    def test_configured_site_files(self) -> None:
        base = self.start(site_url="https://binarystudio.example", security_contact="mailto:s@binarystudio.example",
                          ads={"enabled": True, "provider": "house", "options": {
                              "units": [{"title": "Sponsor", "url": "/about.html"}], "ads_txt": ["example.com, 1, DIRECT"]}})
        self.assertEqual(self.get(base + "/sitemap.xml")[0], 200)
        self.assertEqual(self.get(base + "/ads.txt")[2], b"# Generated by tools/site_pages.py from the ads configuration.\nexample.com, 1, DIRECT\n")
        self.assertIn(b"Contact: mailto:s@binarystudio.example", self.get(base + "/.well-known/security.txt")[2])
        page = self.get(base + "/learn/aslr/")[2]
        self.assertIn(b'class="ad-slot ad-h-150" data-ad-slot="content"', page)
        self.assertIn(b'rel="sponsored noopener"', page)
        self.assertNotIn(b"ads.js", page)  # house units need no script on content pages
        cfg = json.loads(self.get(base + "/api/config")[2])["ads"]
        self.assertEqual(cfg["provider"], "house")
        self.assertNotIn("footer", cfg["slots"])

    def test_app_vs_content_csp_under_each_provider(self) -> None:
        base_csp = runtime.build_csp([])
        configs = [
            (None, [], []),
            ({"enabled": True, "provider": "house", "options": {"units": [{"title": "t", "url": "/", "image": "https://img.sponsor.example/a.png"}]}},
             [], [("img-src", ["https://img.sponsor.example"])]),
            ({"enabled": True, "provider": "ethicalads", "options": {"publisher": "p"}},
             [], [("connect-src", ["https://server.ethicalads.io"]), ("img-src", ["https://server.ethicalads.io", "https://media.ethicalads.io"])]),
            ({"enabled": True, "provider": "ethicalads", "slots": {"content": {}, "footer": {}}, "options": {"publisher": "p"}},
             [("connect-src", ["https://server.ethicalads.io"]), ("img-src", ["https://server.ethicalads.io", "https://media.ethicalads.io"])],
             [("connect-src", ["https://server.ethicalads.io"]), ("img-src", ["https://server.ethicalads.io", "https://media.ethicalads.io"])]),
            ({"enabled": True, "provider": "frame", "slots": {"footer": {}}, "options": {"src": "https://ads.other.example/u.html"}},
             [("frame-src", ["https://ads.other.example"])], []),
        ]
        for ads, app_extra, content_extra in configs:
            kw = {"ads": ads} if ads else {}
            base = self.start(**kw)
            app = self.get(base + "/")[1]["content-security-policy"]
            asset = self.get(base + "/static/app.js")[1]["content-security-policy"]
            content = self.get(base + "/learn/aslr/")[1]["content-security-policy"]
            legal = self.get(base + "/privacy.html")[1]["content-security-policy"]
            self.assertEqual(app, runtime.build_csp(app_extra), ads)
            self.assertEqual(asset, app, ads)
            self.assertEqual(content, runtime.build_csp(content_extra), ads)
            self.assertEqual(legal, content, ads)
            if not app_extra:
                self.assertEqual(app, base_csp, "the app shell is never widened by content-page ads")

    def test_local_mode_generates_on_demand(self) -> None:
        base = self.start(mode="local")
        s, _, b = self.get(base + "/learn/glossary/")
        self.assertEqual(s, 200)
        self.assertIn(b'id="relocation"', b)


class StaticBuildTests(unittest.TestCase):
    def test_build_with_content_and_footer_ads(self) -> None:
        sys.path.insert(0, os.path.join(REPO, "tools"))
        try:
            import build_static  # noqa: WPS433
        finally:
            sys.path.remove(os.path.join(REPO, "tools"))
        ads = {"enabled": True, "provider": "ethicalads", "slots": {"content": {}, "footer": {"height": 80}},
               "options": {"publisher": "p", "ads_txt": ["ethicalads.example, p, DIRECT"]}}
        content_only = {"enabled": True, "provider": "ethicalads", "slots": {"content": {}}, "options": {"publisher": "p"}}
        for spec, footer in ((ads, True), (content_only, False)):
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "dist")
                opts = site_pages.SiteOptions(site_url="https://binarystudio.example", ads=spec)
                build_static.build(out, build_static.default_cache_dir(), offline=True, skip_runtime=True, site=opts)
                with open(os.path.join(out, "_headers"), encoding="utf-8") as f:
                    rules = build_static.parse_headers_file(f.read())
                wasm = [("script-src", ["'wasm-unsafe-eval'"])]
                app_csp = runtime.build_csp(wasm + (site_pages.ads_csp_extra(opts.ads, "app")))
                content_csp = runtime.build_csp(wasm + site_pages.ads_csp_extra(opts.ads, "content"))
                self.assertEqual(build_static.headers_for(rules, "/learn/aslr/")["Content-Security-Policy"], content_csp)
                for path in ("/", "/index.html", "/assets/app.0123456789ab.js", "/sw.js"):
                    policies = [p.strip() for p in build_static.headers_for(rules, path)["Content-Security-Policy"].split(", ")]
                    if content_csp == app_csp:
                        self.assertEqual(policies, [app_csp], path)
                    else:
                        # Both enforced: the app CSP is a strict subset of the content CSP, so the
                        # intersection is the app CSP.
                        self.assertEqual(sorted(policies), sorted([content_csp, app_csp]), path)
                with open(os.path.join(out, "index.html"), encoding="utf-8") as f:
                    index = f.read()
                meta = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', index).group(1)
                self.assertEqual(meta, build_static.meta_csp(app_csp))
                self.assertTrue(os.path.isfile(os.path.join(out, "learn", "aslr", "index.html")))
                self.assertTrue(os.path.isfile(os.path.join(out, "sitemap.xml")))
                with open(os.path.join(out, "sw.js"), encoding="utf-8") as f:
                    self.assertNotIn("learn/", f.read())
                manifest = None
                for name in os.listdir(os.path.join(out, "assets")):
                    if name.startswith("transport."):
                        with open(os.path.join(out, "assets", name), encoding="utf-8") as f:
                            manifest = f.read()
                self.assertIsNotNone(manifest)
                self.assertEqual('"footer":{"height":80}' in manifest, footer)
                self.assertEqual(os.path.isfile(os.path.join(out, "ads.txt")), footer)


if __name__ == "__main__":
    unittest.main()
