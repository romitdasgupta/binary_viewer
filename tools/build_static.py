#!/usr/bin/env python3
"""
Build BinaryStudio as a static website that runs the analysis engine in the visitor's browser.

    python3 tools/build_static.py --out dist/            build (downloads Pyodide once, then offline)
    python3 tools/build_static.py --out dist/ --offline  never touch the network (cache must be populated)
    python3 tools/build_static.py --serve dist/          serve a build locally with the headers in dist/_headers

The Python backend runs unchanged inside Pyodide (CPython compiled to WebAssembly) in a Web Worker;
uploaded files never leave the device and there is no server to attack. The output is plain files
for any static host (Cloudflare Pages, Netlify, S3 + CDN, GitHub Pages with caveats).

Pyodide is obtained at build time, never committed and never fetched from a CDN at run time:
the pinned release archive is downloaded once into a cache directory outside the repository
($BINARYSTUDIO_PYODIDE_CACHE, else $XDG_CACHE_HOME/binarystudio/pyodide, else
~/.cache/binarystudio/pyodide), its SHA-256 is checked against the value recorded below on every
build (a mismatch aborts the build), and only the five files the core runtime needs are copied
into the output under a versioned path. Once the cache holds the archive the build works offline.

Output layout (dist/):
    index.html                    the app shell: content-hashed asset references, the in-browser
                                  transport injected as the first feature script, a <meta> CSP
    assets/                       content-hashed files only (immutable; long cache lifetime):
        app.<h>.js, styles.<h>.css, <feature>.<h>.js|css    everything index.html references
        transport.<h>.js          page side: BS.api.setTransport + queue + worker lifecycle
        engine-worker.<h>.js      the module worker that runs Pyodide and the router
        engine.<h>.zip            backend package + glue + the six sample binaries
        wasm.<h>.css
        pyodide-<version>/        pyodide.mjs, pyodide.asm.mjs, pyodide.asm.wasm,
                                  python_stdlib.zip, pyodide-lock.json (trimmed: no packages)
    static/                       the unhashed static tree, for pages other than index.html
    <top-level static files>      privacy.html, robots.txt, ... (whatever static/ has at its top)
    sw.js                         offline support (versioned cache per build)
    _headers                      response headers in the Cloudflare Pages / Netlify format
    build-info.json               version, file list and sizes
Standard library only; Python 3.9+.
"""

import argparse
import fnmatch
import gzip
import hashlib
import http.server
import io
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Tuple

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO, "static")
WASM_SRC = os.path.join(STATIC, "wasm")

# ---------------------------------------------------------------------------
# Pinned runtime. To upgrade: change all four, run the build once with network, run
# tests/test_static_build.py and the parity check, and update the numbers in the docs.
# 314.0.7: the newest stable Pyodide release (CPython 3.14.2) when this was pinned; the "core"
# archive holds just the interpreter and the standard library, none of the scientific packages.
# The SHA-256 below matches the digest GitHub publishes for the release asset.
# ---------------------------------------------------------------------------
PYODIDE_VERSION = "314.0.7"
PYODIDE_ARCHIVE = "pyodide-core-314.0.7.tar.bz2"
PYODIDE_URL = "https://github.com/pyodide/pyodide/releases/download/314.0.7/pyodide-core-314.0.7.tar.bz2"
PYODIDE_SHA256 = "2abdcc2e35208af406e07724cffa85bc582ced97e9028383ecf5462541393f95"
# What the core runtime needs, and nothing else (no .d.ts, no node CLI shims, no python.exe).
PYODIDE_FILES = ["pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json"]
# Fetched by the worker with progress before Pyodide asks for them (the big ones).
PYODIDE_PREFETCH = ["pyodide.asm.wasm", "python_stdlib.zip", "pyodide.asm.mjs"]

# ---------------------------------------------------------------------------
# What the engine bundle holds
# ---------------------------------------------------------------------------
# backend/ is shipped whole (so new modules and data files of other features are picked up with no
# change here) except these, which the browser has no use for: the HTTP server and the generator
# that compiles the sample binaries with a host toolchain, and the server's analysis worker
# processes (process control and `resource`; there are no processes in a browser).
BACKEND_EXCLUDE = {"server.py", "fixtures.py", "workers.py", "parse_worker.py"}
SKIP_NAMES = {"__pycache__", ".DS_Store", "Thumbs.db"}
SKIP_SUFFIXES = (".pyc", ".pyo", ".orig", ".rej", ".swp", "~")

# Runtime limits for the in-browser engine (RuntimeConfig overrides; see backend/runtime.py).
# max_upload_bytes: measured in headless Chrome 156 (macOS, arm64) with Pyodide 314.0.7, files of
# 128 MiB, 243 MiB (a real Mach-O), 512 MiB and 1 GiB open and answer every core call (WebAssembly
# heap 0.16 / 0.40 / 0.66 / 1.2 GiB); 1.5 GiB still parsed (heap 1.6 GiB, 16 s). The page holds
# its own copy of the file and the heap can never exceed 4 GiB or shrink, and phones have far less
# memory, so the limit is set at half the largest size verified end to end. Larger files: run
# BinaryStudio locally. The document cache is small for the same reasons; the core re-uploads an
# evicted document transparently (410 doc_expired).
MIB = 1024 * 1024
WASM_OVERRIDES: Dict[str, Any] = {
    "max_upload_bytes": 512 * MIB,
    "cache_max_docs": 6,
    "cache_max_bytes": 768 * MIB,
}
# The page-side watchdog: a request still running this long after the router's own parse budget
# expired means the engine is stuck; the worker is replaced.
WATCHDOG_GRACE_SECONDS = 30

ASSET_DIR = "assets"
TRANSPORT_PLACEHOLDER = "/*@@BS_WASM_MANIFEST@@*/ null"
SW_PRECACHE_PLACEHOLDER = "/*@@PRECACHE@@*/ []"
SW_BUILD_PLACEHOLDER = "@@BUILD_ID@@"

# Long-lived cache only for content-addressed files. Nothing else gets a Cache-Control here, so
# no path matches two rules that set the same header (hosts join duplicates with a comma).
IMMUTABLE = "public, max-age=31536000, immutable"


class BuildError(Exception):
    pass


def log(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def short_hash(data: bytes) -> str:
    return sha256_bytes(data)[:12]


def fmt_bytes(n: int) -> str:
    return "%.2f MB" % (n / 1e6) if n >= 100000 else "%.1f kB" % (n / 1e3)


# ---------------------------------------------------------------------------
# Pyodide
# ---------------------------------------------------------------------------
def default_cache_dir() -> str:
    env = os.environ.get("BINARYSTUDIO_PYODIDE_CACHE")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = os.path.abspath(os.path.expanduser(xdg)) if xdg else os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "binarystudio", "pyodide")


def pyodide_archive_path(cache_dir: str) -> str:
    return os.path.join(cache_dir, PYODIDE_ARCHIVE)


def ensure_pyodide_archive(cache_dir: str, offline: bool) -> str:
    """The verified archive in the cache, downloading it first if needed and allowed."""
    path = pyodide_archive_path(cache_dir)
    if os.path.isfile(path):
        got = sha256_file(path)
        if got != PYODIDE_SHA256:
            raise BuildError(
                "Pyodide archive in the cache does NOT match the pinned SHA-256.\n"
                "  file:     %s\n  expected: %s\n  actual:   %s\n"
                "Delete the file to download it again; if the mismatch persists, do not ship." % (path, PYODIDE_SHA256, got))
        return path
    if offline:
        raise BuildError("Pyodide %s is not in the cache (%s) and --offline was given." % (PYODIDE_VERSION, path))
    os.makedirs(cache_dir, exist_ok=True)
    part = path + ".part"
    log("Downloading %s ..." % PYODIDE_URL)
    req = urllib.request.Request(PYODIDE_URL, headers={"User-Agent": "binarystudio-build"})
    h = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=120) as res, open(part, "wb") as out:
        while True:
            chunk = res.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            out.write(chunk)
    if h.hexdigest() != PYODIDE_SHA256:
        os.unlink(part)
        raise BuildError("Downloaded Pyodide archive does NOT match the pinned SHA-256 (expected %s, got %s). "
                         "Nothing was cached." % (PYODIDE_SHA256, h.hexdigest()))
    os.replace(part, path)
    return path


def load_pyodide_archive(path: str) -> bytes:
    """The archive's bytes, read once and checked against the pinned SHA-256.

    What is verified is the buffer that is then extracted, not the file: checking the file
    and opening it a second time to extract would leave a window in which another process
    could swap it (time of check / time of use)."""
    with open(path, "rb") as f:
        data = f.read()
    got = sha256_bytes(data)
    if got != PYODIDE_SHA256:
        raise BuildError(
            "Pyodide archive does NOT match the pinned SHA-256.\n"
            "  file:     %s\n  expected: %s\n  actual:   %s\n"
            "Delete the file to download it again; if the mismatch persists, do not ship." % (path, PYODIDE_SHA256, got))
    return data


def extract_pyodide(archive: Any) -> Dict[str, bytes]:
    """The needed runtime files, from the archive's verified bytes (`archive`: those bytes, or
    a path that is read once and verified here). Members are never written to disk by tar, so
    a hostile archive could not escape; names are matched exactly."""
    data = bytes(archive) if isinstance(archive, (bytes, bytearray)) else load_pyodide_archive(archive)
    if sha256_bytes(data) != PYODIDE_SHA256:
        raise BuildError("Pyodide archive bytes do NOT match the pinned SHA-256; refusing to extract them.")
    wanted = {"pyodide/" + name: name for name in PYODIDE_FILES}
    out: Dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:bz2") as tar:
        for member in tar.getmembers():
            name = wanted.get(member.name.lstrip("./"))
            if name is None or not member.isfile():
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            out[name] = handle.read()
    missing = [n for n in PYODIDE_FILES if n not in out]
    if missing:
        raise BuildError("Pyodide archive lacks %s" % ", ".join(missing))
    # The lock file lists ~360 optional packages. None are used; listing none means nothing can
    # ever be auto-loaded, and it saves a download.
    lock = json.loads(out["pyodide-lock.json"].decode("utf-8"))
    out["pyodide-lock.json"] = json.dumps({"info": lock["info"], "packages": {}}, separators=(",", ":")).encode()
    return out


# ---------------------------------------------------------------------------
# Engine bundle
# ---------------------------------------------------------------------------
def _skip(name: str) -> bool:
    return name in SKIP_NAMES or name.startswith(".") or name.endswith(SKIP_SUFFIXES)


def preset_fixture_files() -> List[str]:
    sys.path.insert(0, REPO)
    try:
        from backend.service import SYNTHETIC_PRESETS  # noqa: WPS433 (build-time import)
    finally:
        sys.path.remove(REPO)
    return [filename for _pid, _label, filename, _fmt, _desc in SYNTHETIC_PRESETS]


def bundle_members() -> List[Tuple[str, str]]:
    """(archive name, source path), sorted: the backend package, the glue, the sample binaries."""
    members: List[Tuple[str, str]] = []
    backend = os.path.join(REPO, "backend")
    for root, dirs, files in os.walk(backend):
        dirs[:] = sorted(d for d in dirs if not _skip(d))
        rel_root = os.path.relpath(root, REPO).replace(os.sep, "/")
        for name in sorted(files):
            if _skip(name):
                continue
            if rel_root == "backend" and name in BACKEND_EXCLUDE:
                continue
            members.append((rel_root + "/" + name, os.path.join(root, name)))
    members.append(("bs_wasm_glue.py", os.path.join(WASM_SRC, "bs_wasm_glue.py")))
    for filename in preset_fixture_files():
        src = os.path.join(REPO, "fixtures", filename)
        if not os.path.isfile(src):
            raise BuildError("Sample binary missing: fixtures/%s (run python3 -m backend.fixtures)" % filename)
        members.append(("fixtures/" + filename, src))
    return sorted(members)


def build_bundle() -> bytes:
    """A deterministic zip: fixed timestamps and permissions, sorted entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for arcname, src in bundle_members():
            info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(src, "rb") as f:
                zf.writestr(info, f.read())
    return buf.getvalue()


SMOKE = r'''
import json, sys
root = sys.argv[1]
sys.path.insert(0, root)
import bs_wasm_glue as g
g.init(sys.argv[2], root)
out = {}
def call(method, route, query=None, body=b"", headers=None):
    status, hdrs, data = g.handle(method, route, json.dumps(query or {}), json.dumps(headers or {}), body)
    return status, json.loads(hdrs), data
s, h, d = call("GET", "/api/config"); assert s == 200, (s, d)
out["config"] = json.loads(d)
s, h, d = call("GET", "/api/presets"); assert s == 200, (s, d)
out["presets"] = json.loads(d)["presets"]
for p in out["presets"]:
    s, h, d = call("GET", "/api/parse", {"doc": p["doc"]})
    assert s == 200, (p["doc"], s, d[:300])
    s, h, d = call("GET", "/api/hex", {"doc": p["doc"], "offset": "0", "length": "64"})
    assert s == 200, (p["doc"], s, d[:300])
from backend import runtime
out["csp"] = runtime.build_csp([("script-src", ["'wasm-unsafe-eval'"])])
out["server_csp"] = runtime.RuntimeConfig("public").content_security_policy()
out["routes"] = g._router.routes()
out["parse_timeout"] = g._config.parse_timeout_seconds
out["modules"] = sorted(m for m in sys.modules if m == "backend" or m.startswith("backend."))
print(json.dumps(out))
'''


def smoke_test_bundle(bundle: bytes, overrides: Dict[str, Any]) -> Dict[str, Any]:
    """Unpack the bundle alone into a temp dir and run it under this CPython in an isolated
    interpreter (-I: no user site, no cwd on the path), exactly as the worker will. It must
    import without the repository and answer the core routes for every sample."""
    with tempfile.TemporaryDirectory(prefix="bs-bundle-") as tmp:
        with zipfile.ZipFile(io.BytesIO(bundle)) as zf:
            zf.extractall(tmp)
        proc = subprocess.run([sys.executable, "-I", "-c", SMOKE, tmp, json.dumps(overrides)],
                              cwd=tmp, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise BuildError("The engine bundle failed its smoke test under CPython:\n" + proc.stderr[-3000:])
        return json.loads(proc.stdout.strip().splitlines()[-1])


# ---------------------------------------------------------------------------
# App shell
# ---------------------------------------------------------------------------
REF_RE = re.compile(r'(<(?:script|link)\b[^>]*?\b(?:src|href)=")(static/[^"?#]+)(")', re.I)
CSS_URL_RE = re.compile(r"url\(\s*['\"]?(?!data:|#)([^'\")]+)", re.I)


def hashed_name(rel: str, data: bytes) -> str:
    stem, ext = posixpath.splitext(posixpath.basename(rel))
    return "%s/%s.%s%s" % (ASSET_DIR, stem, short_hash(data), ext)


def meta_csp(csp: str) -> str:
    # frame-ancestors, sandbox and report-* are ignored (with a console warning) in a <meta> CSP.
    keep = [d.strip() for d in csp.split(";") if d.strip() and d.split()[0] not in ("frame-ancestors", "sandbox", "report-uri", "report-to")]
    return "; ".join(keep)


def links_for_static() -> Dict[str, Optional[str]]:
    """Footer links as paths relative to the site root, only for pages that exist."""
    links: Dict[str, Optional[str]] = {"source": None}
    for key in ("privacy", "terms", "about"):
        name = key + ".html"
        links[key] = name if os.path.isfile(os.path.join(STATIC, name)) else None
    return links


def copy_tree_static(out: str, files: Dict[str, bytes]) -> None:
    """The unhashed static tree under static/, and its top-level files at the site root."""
    for root, dirs, names in os.walk(STATIC):
        rel_root = os.path.relpath(root, STATIC).replace(os.sep, "/")
        dirs[:] = sorted(d for d in dirs if not _skip(d) and not (rel_root == "." and d == "wasm"))
        for name in sorted(names):
            if _skip(name) or name.endswith(".py"):
                continue
            rel = name if rel_root == "." else rel_root + "/" + name
            with open(os.path.join(root, name), "rb") as f:
                data = f.read()
            if rel == "index.html":
                continue
            files["static/" + rel] = data
            # Pages and well-known files (privacy.html, robots.txt, ads.txt) also at the root, where
            # the Python server answers them too. Scripts and styles stay under static/ only.
            if rel_root == "." and not name.endswith((".js", ".css")):
                files[rel] = data


def _site_pages() -> Any:
    """tools/site_pages.py: the learning pages, robots.txt / sitemap / ads.txt, and the ads policy."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("binarystudio_site_pages", os.path.join(REPO, "tools", "site_pages.py"))
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def build(out_dir: str, cache_dir: str, offline: bool, skip_runtime: bool, site: Any = None) -> Dict[str, Any]:
    """`site`: a site_pages.SiteOptions (site URL, ads, security contact); default: from the
    BINARYSTUDIO_SITE_URL / BINARYSTUDIO_ADS / BINARYSTUDIO_SECURITY_CONTACT variables."""
    t0 = time.time()
    site_pages = _site_pages()
    if site is None:
        site = site_pages.options_from_env()
    files: Dict[str, bytes] = {}  # output path (posix, relative) -> bytes

    # 1. Runtime
    runtime_files: Dict[str, bytes] = {}
    if not skip_runtime:
        # ensure_* makes sure a verified archive is in the cache (downloading it if allowed);
        # the bytes that are extracted are then read once and verified in memory.
        runtime_files = extract_pyodide(load_pyodide_archive(ensure_pyodide_archive(cache_dir, offline)))
    pyo_dir = "%s/pyodide-%s/" % (ASSET_DIR, PYODIDE_VERSION)
    for name, data in runtime_files.items():
        files[pyo_dir + name] = data

    # 2. Engine bundle, smoke-tested on its own
    overrides = dict(WASM_OVERRIDES)
    overrides["links"] = links_for_static()
    if site.ads.get("enabled"):
        overrides["ads"] = site.ads  # BS.config.ads in the in-browser app (the footer slot is opt-in)
    bundle = build_bundle()
    smoke = smoke_test_bundle(bundle, overrides)
    bundle_path = "%s/engine.%s.zip" % (ASSET_DIR, short_hash(bundle))
    files[bundle_path] = bundle

    # 3. Worker and styles
    def asset(src_rel: str, data: Optional[bytes] = None) -> str:
        if data is None:
            with open(os.path.join(REPO, src_rel), "rb") as f:
                data = f.read()
        name = hashed_name(src_rel, data)
        files[name] = data
        return name

    worker_path = asset("static/wasm/engine-worker.js")
    wasm_css_path = asset("static/wasm/wasm.css")

    # 4. Manifest -> transport
    config = smoke["config"]
    manifest = {
        "worker": worker_path,
        "pyodide": {"version": PYODIDE_VERSION, "module": pyo_dir + "pyodide.mjs", "indexURL": pyo_dir},
        "bundle": {"url": bundle_path, "sha256": sha256_bytes(bundle), "size": len(bundle)},
        "prefetch": [{"url": pyo_dir + n, "size": len(runtime_files.get(n, b""))} for n in PYODIDE_PREFETCH],
        "runtimeBytes": sum(len(v) for v in runtime_files.values()) + len(bundle),
        "overrides": overrides,
        "config": config,
        "presets": smoke["presets"],
        "hardTimeoutSeconds": int(smoke["parse_timeout"] or 120) + WATCHDOG_GRACE_SECONDS,
        "serviceWorker": "sw.js",
    }
    with open(os.path.join(WASM_SRC, "transport.js"), "r", encoding="utf-8") as f:
        transport_src = f.read()
    if TRANSPORT_PLACEHOLDER not in transport_src:
        raise BuildError("static/wasm/transport.js lost its manifest placeholder")
    transport_src = transport_src.replace(TRANSPORT_PLACEHOLDER, json.dumps(manifest, separators=(",", ":"), sort_keys=True))
    transport_path = asset("static/wasm/transport.js", transport_src.encode("utf-8"))

    # 5. index.html: hash every static/ reference, inject the transport, add a <meta> CSP
    with open(os.path.join(STATIC, "index.html"), "r", encoding="utf-8") as f:
        html = f.read()
    referenced: List[str] = []

    def rewrite(m: "re.Match[str]") -> str:
        rel = m.group(2)
        src = os.path.join(REPO, *rel.split("/"))
        if not os.path.isfile(src):
            raise BuildError("index.html references %s, which does not exist" % rel)
        with open(src, "rb") as fh:
            data = fh.read()
        if rel.endswith(".css") and any(not u.startswith(("/", "http:", "https:")) for u in CSS_URL_RE.findall(data.decode("utf-8", "replace"))):
            # Relative url() references would break if the file moved; version it in place instead.
            referenced.append(rel)
            return m.group(1) + rel + "?v=" + short_hash(data) + m.group(3)
        referenced.append(rel)
        return m.group(1) + asset(rel, data) + m.group(3)

    # Only real tags: the comments in index.html describe the slots with example tags.
    parts = re.split(r"(<!--.*?-->)", html, flags=re.S)
    html = "".join(part if part.startswith("<!--") else REF_RE.sub(rewrite, part) for part in parts)
    app_tag = re.search(r'<script\b[^>]*\bsrc="assets/app\.[0-9a-f]+\.js"[^>]*></script>', html)
    if not app_tag:
        raise BuildError("index.html no longer loads static/app.js with a plain <script> tag")
    inject = ('\n  <!-- Static build: the analysis engine runs in this tab (static/wasm/, tools/build_static.py). -->\n'
              '  <link rel="stylesheet" href="%s" />\n  <script defer src="%s"></script>' % (wasm_css_path, transport_path))
    html = html[:app_tag.end()] + inject + html[app_tag.end():]
    charset = re.search(r'<meta charset="[^"]*"\s*/?>', html, re.I)
    if not charset:
        raise BuildError("index.html has no <meta charset>")
    csp = smoke["csp"]
    wasm_csp = [("script-src", ["'wasm-unsafe-eval'"])]
    if site.csp_extra("app"):
        csp = runtime_build_csp(wasm_csp + site.csp_extra("app"))
    content_csp = runtime_build_csp(wasm_csp + site.csp_extra("content")) if site.csp_extra("content") else csp
    meta = '\n  <meta http-equiv="Content-Security-Policy" content="%s" />' % meta_csp(csp).replace('"', "&quot;")
    html = html[:charset.end()] + meta + html[charset.end():]
    files["index.html"] = html.encode("utf-8")

    # 6. The rest of the static tree, unhashed
    copy_tree_static(out_dir, files)
    # 6b. Learning pages, robots.txt, sitemap.xml, ads.txt, security.txt (tools/site_pages.py)
    site_paths = set(site_pages.add_to_build(files, site))

    # 7. Service worker. The build id covers every file of the build (index.html names the hashed
    #    transport, which embeds the manifest), so any change anywhere gives a new cache.
    build_id = short_hash(json.dumps(sorted((k, sha256_bytes(v)) for k, v in files.items())).encode())
    precache = sorted(p for p in files if p != "index.html" and not p.startswith("static/") and "/" in p
                      and p not in site_paths)
    precache = [] if skip_runtime else ["./", "index.html"] + precache
    with open(os.path.join(WASM_SRC, "sw.js"), "r", encoding="utf-8") as f:
        sw = f.read()
    if SW_PRECACHE_PLACEHOLDER not in sw or SW_BUILD_PLACEHOLDER not in sw:
        raise BuildError("static/wasm/sw.js lost its placeholders")
    sw = sw.replace(SW_PRECACHE_PLACEHOLDER, json.dumps(precache)).replace(SW_BUILD_PLACEHOLDER, build_id)
    files["sw.js"] = sw.encode("utf-8")

    # 8. Headers
    files["_headers"] = headers_file(csp, content_csp).encode("utf-8")

    # 9. Write
    if os.path.isdir(out_dir):
        marker = os.path.join(out_dir, "build-info.json")
        if os.listdir(out_dir) and not os.path.isfile(marker):
            raise BuildError("%s exists and is not a previous build (no build-info.json); refusing to delete it" % out_dir)
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)
    for rel, data in files.items():
        dest = os.path.join(out_dir, *rel.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data)

    info = summarize(files, runtime_files, pyo_dir, bundle_path, skip_runtime)
    info.update({
        "app": config.get("app"), "version": config.get("version"), "build_id": build_id,
        "pyodide": {"version": PYODIDE_VERSION, "archive": PYODIDE_ARCHIVE, "sha256": PYODIDE_SHA256,
                    "included": not skip_runtime},
        "engine_modules": smoke["modules"],
        "routes": [" ".join(r) for r in smoke["routes"]],
        "index_references": referenced,
        "limits": config.get("limits"),
        "csp": csp,
    })
    # build-info.json is published with the site on purpose: it says exactly which build is
    # being served (versions, the pinned runtime hash, every file and its size), which is what
    # someone verifying a deployment needs, and nothing in it is secret: all of it can be read
    # off the files next to it. It must say nothing about the machine that built it.
    info_text = json.dumps(info, indent=1, sort_keys=True)
    leak = _local_identifier_in(info_text, cache_dir, out_dir)
    if leak:
        raise BuildError("build-info.json would publish a detail of the build machine (%s); not written." % leak)
    with open(os.path.join(out_dir, "build-info.json"), "w", encoding="utf-8") as f:
        f.write(info_text)
    info["seconds"] = round(time.time() - t0, 2)
    return info


def _local_identifier_in(text: str, *paths: str) -> Optional[str]:
    """Which kind of build-machine detail `text` contains (a local path, the user name, the
    host name), or None. Names shorter than three characters are not searched for: they
    would match by accident."""
    import getpass
    import socket

    lowered = text.lower()
    candidates = [("the repository path", REPO), ("the home directory", os.path.expanduser("~"))]
    candidates += [("a local path", os.path.abspath(path)) for path in paths if path]
    try:
        candidates.append(("the user name", getpass.getuser()))
    except Exception:  # noqa: BLE001 - no user database entry (containers)
        pass
    try:
        host = socket.gethostname()
        candidates += [("the host name", host), ("the host name", host.split(".")[0])]
    except OSError:
        pass
    for what, value in candidates:
        value = str(value or "").strip().lower()
        if len(value) < 4 or value in ("root", "user", "build", "static", "runner", "localhost"):
            continue
        # Paths anywhere; names only as whole words ("mac" must not match "macho").
        if "path" in what or "directory" in what:
            found = value in lowered
        else:
            found = re.search(r"(?<![a-z0-9])" + re.escape(value) + r"(?![a-z0-9])", lowered) is not None
        if found:
            return what
    return None


def summarize(files: Dict[str, bytes], runtime_files: Dict[str, bytes], pyo_dir: str, bundle_path: str,
              skip_runtime: bool) -> Dict[str, Any]:
    def sizes(paths: List[str]) -> Dict[str, int]:
        raw = sum(len(files[p]) for p in paths)
        gz = sum(len(gzip.compress(files[p], 9, mtime=0)) for p in paths)
        return {"files": len(paths), "raw": raw, "gzip": gz}

    all_paths = sorted(files)
    engine = [p for p in all_paths if p.startswith(pyo_dir)] + [bundle_path]
    first_load = ["index.html"] + [p for p in all_paths if p.startswith(ASSET_DIR + "/") and not p.startswith(pyo_dir)]
    return {
        "sizes": {
            "total_shipped": sizes(all_paths),
            "engine_runtime_and_bundle": sizes(engine),
            "first_visit_download": sizes(first_load + [p for p in engine if p not in first_load]),
        },
        "files": {p: len(files[p]) for p in all_paths},
        "runtime_missing": skip_runtime,
    }


def runtime_build_csp(extra: List[Tuple[str, List[str]]]) -> str:
    sys.path.insert(0, REPO)
    try:
        from backend.runtime import build_csp
    finally:
        sys.path.remove(REPO)
    return build_csp(extra)


def headers_file(csp: str, content_csp: Optional[str] = None) -> str:
    """Response headers for Cloudflare Pages / Netlify (`_headers`). Mirrors what the Python
    server sends for pages (backend/api.py security_headers), with 'wasm-unsafe-eval' added to
    script-src so the browser may compile the engine's WebAssembly, and nothing broader."""
    sys.path.insert(0, REPO)
    try:
        from backend.runtime import DEFAULT_PERMISSIONS_POLICY
    finally:
        sys.path.remove(REPO)
    lines = [
        "# Generated by tools/build_static.py. Every response gets the security headers; only",
        "# content-hashed files get a long cache lifetime (hosts revalidate everything else).",
        "# Hosts that ignore this file (GitHub Pages, plain S3) must send the same headers some other",
        "# way; index.html carries a <meta> CSP as a fallback, which cannot express frame-ancestors",
        "# and does not cover the worker script.",
        "/*",
        "  Content-Security-Policy: " + (content_csp or csp),
        "  X-Content-Type-Options: nosniff",
        "  X-Frame-Options: DENY",
        "  Referrer-Policy: no-referrer",
        "  Cross-Origin-Opener-Policy: same-origin",
        "  Cross-Origin-Resource-Policy: same-origin",
        "  Permissions-Policy: " + DEFAULT_PERMISSIONS_POLICY,
        "  Strict-Transport-Security: max-age=31536000",
        "",
        "/%s/*" % ASSET_DIR,
        "  Cache-Control: " + IMMUTABLE,
        "",
    ]
    if content_csp and content_csp != csp:
        # Ads widen the CSP of content pages only. The app's paths get the app CSP as a second policy;
        # the browser enforces both, i.e. exactly the app CSP (see tools/site_pages.py headers_rules).
        lines[5:5] = ["# Content pages: the CSP above includes the configured ad provider's sources. The app shell",
                      "# and its assets below also get the app's own CSP, so for them nothing is widened."]
        lines += _site_pages().headers_rules(csp, content_csp, ["/", "/index.html", "/sw.js", "/%s/*" % ASSET_DIR])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Local static server that applies dist/_headers (test tooling; stdlib only)
# ---------------------------------------------------------------------------
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".json": "application/json", ".wasm": "application/wasm", ".zip": "application/zip",
    ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8",
    ".woff2": "font/woff2", ".webmanifest": "application/manifest+json",
}
COMPRESSIBLE = (".html", ".js", ".mjs", ".css", ".json", ".wasm", ".svg", ".txt")


def parse_headers_file(text: str) -> List[Tuple[str, List[Tuple[str, str]]]]:
    rules: List[Tuple[str, List[Tuple[str, str]]]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[:1].isspace():
            rules.append((raw.strip(), []))
        elif rules and ":" in raw:
            name, value = raw.strip().split(":", 1)
            rules[-1][1].append((name.strip(), value.strip()))
    return rules


def headers_for(rules: List[Tuple[str, List[Tuple[str, str]]]], path: str) -> Dict[str, str]:
    """All headers of every matching rule; a header set by two rules is joined with ', '
    (what Cloudflare Pages does)."""
    out: Dict[str, str] = {}
    for pattern, headers in rules:
        if fnmatch.fnmatchcase(path, pattern):
            for name, value in headers:
                out[name] = (out[name] + ", " + value) if name in out else value
    return out


def make_handler(root: str, request_log: Optional[List[Dict[str, Any]]] = None, gzip_enabled: bool = True):
    root = os.path.realpath(root)
    with open(os.path.join(root, "_headers"), "r", encoding="utf-8") as f:
        rules = parse_headers_file(f.read())
    gz_cache: Dict[str, bytes] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "static"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet
            pass

        def _resolve(self, url_path: str) -> Optional[str]:
            path = urllib.request.unquote(url_path.split("?", 1)[0].split("#", 1)[0])
            if "\x00" in path or "\\" in path:
                return None
            parts = [p for p in path.split("/") if p]
            if any(p.startswith(".") for p in parts):
                return None
            full = os.path.realpath(os.path.join(root, *parts))
            if full != root and not full.startswith(root + os.sep):
                return None
            if os.path.isdir(full):
                full = os.path.join(full, "index.html")
            return full if os.path.isfile(full) and os.path.basename(full) != "_headers" else None

        def _send_file(self, head: bool) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            if request_log is not None:
                request_log.append({"method": self.command, "path": self.path, "body_bytes": len(body),
                                    "body_sha256": sha256_bytes(body) if body else None})
            url_path = self.path.split("?", 1)[0]
            extra = headers_for(rules, url_path)
            if self.command not in ("GET", "HEAD"):
                self._reply(405, b"Method not allowed", "text/plain; charset=utf-8", extra, head)
                return
            full = self._resolve(self.path)
            if full is None:
                self._reply(404, b"Not found", "text/plain; charset=utf-8", extra, head)
                return
            with open(full, "rb") as f:
                data = f.read()
            etag = '"%s"' % sha256_bytes(data)[:20]
            extra = dict(extra)
            extra["ETag"] = etag
            if self.headers.get("If-None-Match") == etag:
                self._reply(304, b"", None, extra, True)
                return
            ext = os.path.splitext(full)[1].lower()
            ctype = CONTENT_TYPES.get(ext, "application/octet-stream")
            if gzip_enabled and ext in COMPRESSIBLE and "gzip" in (self.headers.get("Accept-Encoding") or ""):
                if full not in gz_cache:
                    gz_cache[full] = gzip.compress(data, 6, mtime=0)
                data = gz_cache[full]
                extra["Content-Encoding"] = "gzip"
                extra["Vary"] = "Accept-Encoding"
            self._reply(200, data, ctype, extra, head)

        def _reply(self, status: int, data: bytes, ctype: Optional[str], headers: Dict[str, str], head: bool) -> None:
            self.send_response(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if not head and status != 304:
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True  # the browser went away (navigation, cancelled fetch)

        def do_GET(self) -> None:
            self._send_file(False)

        def do_HEAD(self) -> None:
            self._send_file(True)

        def do_POST(self) -> None:
            self._send_file(False)

        do_PUT = do_POST
        do_DELETE = do_POST
        do_OPTIONS = do_POST

    return Handler


def serve(root: str, host: str, port: int, request_log_path: Optional[str]) -> None:
    log_list: List[Dict[str, Any]] = []
    server = http.server.ThreadingHTTPServer((host, port), make_handler(root, log_list))
    sys.stdout.write("LISTENING %d\n" % server.server_address[1])
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if request_log_path:
            with open(request_log_path, "w", encoding="utf-8") as f:
                json.dump(log_list, f)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Build (or serve) the static, in-browser BinaryStudio site.")
    ap.add_argument("--out", default=os.path.join(REPO, "dist"), help="output directory (default: dist/)")
    ap.add_argument("--pyodide-cache", default=default_cache_dir(), help="where the Pyodide archive is cached")
    ap.add_argument("--offline", action="store_true", help="never use the network; the cache must hold Pyodide")
    ap.add_argument("--skip-runtime", action="store_true",
                    help="build without Pyodide (for tests on machines without the cache); the site will not run")
    ap.add_argument("--serve", metavar="DIR", help="serve a built site with the headers from its _headers file")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--request-log", help="with --serve: write every request (path, body size, hash) here on exit")
    ap.add_argument("--site-url", help="absolute URL of the site root: canonical links, sitemap.xml (or BINARYSTUDIO_SITE_URL)")
    ap.add_argument("--ads", help="ads configuration as JSON or @file.json (or BINARYSTUDIO_ADS); see tools/site_pages.py")
    ap.add_argument("--security-contact", help="Contact for /.well-known/security.txt (or BINARYSTUDIO_SECURITY_CONTACT)")
    args = ap.parse_args(argv)

    if args.serve:
        serve(args.serve, args.host, args.port, args.request_log)
        return 0
    try:
        site = _site_pages().options_from_env(site_url=args.site_url, ads=args.ads, security_contact=args.security_contact)
        info = build(os.path.abspath(args.out), args.pyodide_cache, args.offline, args.skip_runtime, site)
    except (BuildError, ValueError, OSError) as exc:
        log("BUILD FAILED: %s" % exc)
        return 2
    s = info["sizes"]
    log("Built %s %s (build %s) into %s in %.1fs" % (info["app"], info["version"], info["build_id"], args.out, info["seconds"]))
    log("  Pyodide %s %s" % (PYODIDE_VERSION, "" if info["pyodide"]["included"] else "(NOT INCLUDED: --skip-runtime)"))
    for key, label in (("total_shipped", "everything shipped"), ("engine_runtime_and_bundle", "engine (Pyodide + bundle)"),
                       ("first_visit_download", "first visit downloads")):
        log("  %-28s %3d files  %10s raw  %10s gzip" % (label, s[key]["files"], fmt_bytes(s[key]["raw"]), fmt_bytes(s[key]["gzip"])))
    log("  routes: %d   engine modules: %d   upload limit: %s" % (
        len(info["routes"]), len(info["engine_modules"]), fmt_bytes(info["limits"]["max_upload_bytes"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
