"""
Tests for the static, in-browser build (tools/build_static.py, static/wasm/).

The module builds the site once into a temporary directory. When the pinned Pyodide archive is
in the build cache (see tools/build_static.py) the build is complete and offline; otherwise it is
built with --skip-runtime and every test that needs the runtime is skipped with a message saying
how to populate the cache. Nothing here uses the network.

Always run (plain CPython, no network):
  BundleTests       the engine bundle, unpacked on its own, imports and answers router requests
                    in wasm mode under this interpreter; no subprocess is ever started
  OutputTests       no local paths, no third-party origins, nothing that should not ship,
                    every index.html reference resolves, the manifest is consistent
  HeadersTests      _headers carries the Python server's page CSP plus 'wasm-unsafe-eval' in
                    script-src and nothing else different; cache rules never overlap; the local
                    static server applies them
Need the Pyodide runtime (+ node for parity, + Chrome for the browser test):
  EngineParityTests the same request plan through CPython (this interpreter) and through the
                    shipped Pyodide (in node), compared response by response
  BrowserTests      the built site in headless Chrome under the exact _headers: boots, opens a
                    sample and an upload, no CSP violations, no request to another origin, the
                    uploaded bytes never appear in any request

Full parity report with extra inputs and the Python server as a third leg:
    python3 tests/test_static_build.py --parity [--dist DIR] [FILE ...]
"""

import base64
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Tuple

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from backend import runtime  # noqa: E402

_spec = importlib.util.spec_from_file_location("build_static", os.path.join(REPO, "tools", "build_static.py"))
build_static = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(build_static)  # type: ignore[union-attr]

NODE = shutil.which("node") or ("/opt/homebrew/bin/node" if os.path.exists("/opt/homebrew/bin/node") else None)
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
NO_RUNTIME = ("Pyodide %s is not in the build cache (%s); runtime-dependent tests skipped. "
              "Populate it once with network: python3 tools/build_static.py --out dist/"
              % (build_static.PYODIDE_VERSION, build_static.default_cache_dir()))

DIST = ""
HAS_RUNTIME = False
_TMP = ""


def setUpModule() -> None:
    global DIST, HAS_RUNTIME, _TMP
    _TMP = tempfile.mkdtemp(prefix="bs-static-test-")
    DIST = os.path.join(_TMP, "dist")
    archive = build_static.pyodide_archive_path(build_static.default_cache_dir())
    HAS_RUNTIME = os.path.isfile(archive)
    info = build_static.build(DIST, build_static.default_cache_dir(), offline=True, skip_runtime=not HAS_RUNTIME)
    assert os.path.isfile(os.path.join(DIST, "index.html")), info


def tearDownModule() -> None:
    if _TMP:
        shutil.rmtree(_TMP, ignore_errors=True)


def dist_files() -> List[str]:
    out = []
    for root, _dirs, files in os.walk(DIST):
        for name in files:
            out.append(os.path.relpath(os.path.join(root, name), DIST).replace(os.sep, "/"))
    return sorted(out)


def read_manifest(dist: str) -> Dict[str, Any]:
    names = [n for n in os.listdir(os.path.join(dist, "assets")) if re.match(r"transport\.[0-9a-f]+\.js$", n)]
    assert len(names) == 1, names
    with open(os.path.join(dist, "assets", names[0]), "r", encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"const MANIFEST = (\{.*?\});\n", src)
    assert m, "manifest not injected"
    return json.loads(m.group(1))


def bundle_path(dist: str) -> str:
    return os.path.join(dist, *read_manifest(dist)["bundle"]["url"].split("/"))


def parse_csp(text: str) -> Dict[str, List[str]]:
    return {parts[0]: parts[1:] for parts in (d.split() for d in text.split(";")) if parts}


# ---------------------------------------------------------------------------
# Running the bundle under CPython (a subprocess, isolated: -I, only the bundle on the path)
# ---------------------------------------------------------------------------
CPYTHON_RUNNER = r'''
import json, os, sys, base64
root, plan_path, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, root)
import subprocess
def _refuse(*a, **k):
    raise AssertionError("subprocess used in wasm mode: %r" % (a[:1],))
subprocess.run = subprocess.Popen = subprocess.call = subprocess.check_output = _refuse
import bs_wasm_glue as g
plan = json.load(open(plan_path))
g.init(json.dumps(plan["overrides"]), root)
docs = {}
def subst(v):
    if isinstance(v, str) and v.startswith("$DOC:"):
        return docs.get(v[5:], "u_" + "0" * 32)
    if isinstance(v, dict):
        return {k: subst(x) for k, x in v.items()}
    if isinstance(v, list):
        return [subst(x) for x in v]
    return v
results = []
for i, step in enumerate(plan["steps"]):
    body = b""
    if step.get("file"):
        body = open(step["file"], "rb").read()
    elif step.get("json") is not None:
        body = json.dumps(subst(step["json"])).encode()
    elif step.get("raw") is not None:
        body = step["raw"].encode()
    status, headers, data = g.handle(step["method"], step["route"], json.dumps(subst(step.get("query") or {})),
                                     json.dumps(step.get("headers") or {}), body)
    if step.get("save") and status == 200:
        docs[step["save"]] = json.loads(data).get("doc_id") or ""
    with open(os.path.join(out_dir, "%05d.bin" % i), "wb") as f:
        f.write(data)
    results.append({"status": status, "ctype": json.loads(headers).get("content-type", "")})
json.dump({"results": results, "modules": sorted(m for m in sys.modules if m.startswith("backend")),
           "python": sys.version.split()[0]}, open(os.path.join(out_dir, "results.json"), "w"))
'''

NODE_RUNNER = r'''
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const [planPath, outDir] = process.argv.slice(2);
const plan = JSON.parse(readFileSync(planPath, 'utf8'));
const t0 = performance.now();
const { loadPyodide } = await import(pathToFileURL(join(plan.indexDir, 'pyodide.mjs')).href);
const indexURL = plan.indexDir.endsWith('/') ? plan.indexDir : plan.indexDir + '/';
const py = await loadPyodide({ indexURL, packageBaseUrl: indexURL, lockFileURL: indexURL + 'pyodide-lock.json' });
py.unpackArchive(new Uint8Array(readFileSync(plan.bundle)), 'zip', { extractDir: '/app' });
py.runPython('import sys\nsys.path.insert(0, "/app")');
const glue = py.pyimport('bs_wasm_glue');
glue.init(JSON.stringify(plan.overrides), '/app');
const loadMs = performance.now() - t0;
const docs = {};
const subst = (v) => {
  if (typeof v === 'string' && v.startsWith('$DOC:')) return docs[v.slice(5)] || 'u_' + '0'.repeat(32);
  if (Array.isArray(v)) return v.map(subst);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, subst(x)]));
  return v;
};
const results = [];
for (let i = 0; i < plan.steps.length; i++) {
  const step = plan.steps[i];
  let body;
  if (step.file) body = new Uint8Array(readFileSync(step.file));
  else if (step.json !== undefined && step.json !== null) body = new TextEncoder().encode(JSON.stringify(subst(step.json)));
  else if (typeof step.raw === 'string') body = new TextEncoder().encode(step.raw);
  writeFileSync(join(outDir, 'current.json'), JSON.stringify({ i, step }));
  const t = performance.now();
  const r = glue.handle(step.method, step.route, JSON.stringify(subst(step.query || {})), JSON.stringify(step.headers || {}), body);
  const status = r.get(0);
  const headers = JSON.parse(r.get(1));
  const proxy = r.get(2);
  const view = proxy.getBuffer('u8');
  const data = view.data.slice();
  view.release(); proxy.destroy(); r.destroy();
  if (step.save && status === 200) docs[step.save] = JSON.parse(new TextDecoder().decode(data)).doc_id || '';
  writeFileSync(join(outDir, String(i).padStart(5, '0') + '.bin'), data);
  results.push({ status, ctype: headers['content-type'] || '', ms: Math.round(performance.now() - t) });
}
const modules = JSON.parse(py.runPython('import json, sys\njson.dumps(sorted(m for m in sys.modules if m.startswith("backend")))'));
writeFileSync(join(outDir, 'results.json'), JSON.stringify({ results, modules, python: py.runPython('import sys\nsys.version.split()[0]'), loadMs }));
'''

PLAN_MAKER = r'''
import json, os, sys
from urllib.parse import quote
root, inputs_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, root)
import bs_wasm_glue as g
spec = json.load(open(inputs_path))
g.init(json.dumps(spec["overrides"]), root)
CORE = {("GET", "/api/config"), ("GET", "/api/presets"), ("GET", "/api/parse"), ("POST", "/api/parse"),
        ("POST", "/api/upload"), ("GET", "/api/hex"), ("GET", "/api/decode"), ("GET", "/api/translate"),
        ("GET", "/api/disassemble"), ("GET", "/api/search")}
steps = [{"method": "GET", "route": "/api/config"}, {"method": "GET", "route": "/api/presets"}]
def call(method, route, query=None, body=b"", headers=None):
    s, h, d = g.handle(method, route, json.dumps(query or {}), json.dumps(headers or {}), body)
    return s, d
for inp in spec["inputs"]:
    name = inp["name"]
    if inp["kind"] == "preset":
        ref = inp["doc"]
        steps.append({"method": "GET", "route": "/api/parse", "query": {"doc": ref}, "input": name})
        s, d = call("GET", "/api/parse", {"doc": ref})
    else:
        ref = "$DOC:" + name
        hdrs = {"content-type": "application/octet-stream", "x-filename": quote(os.path.basename(inp["file"]))}
        steps.append({"method": "POST", "route": "/api/upload", "file": inp["file"], "headers": hdrs, "save": name, "input": name})
        s, d = call("POST", "/api/upload", None, open(inp["file"], "rb").read(), hdrs)
    if s != 200:
        continue
    doc = json.loads(d)
    size = doc["file_info"].get("file_size") or doc["file_info"].get("size") or 0
    slices = doc.get("slices") or []
    for si, sl in enumerate(slices[:2]):
        base = {"doc": ref, "slice_index": str(si)}
        def add(route, **q):
            query = dict(base); query.update({k: str(v) for k, v in q.items()})
            steps.append({"method": "GET", "route": route, "query": query, "input": name})
        sb, ss = sl.get("slice_base_offset", 0), sl.get("slice_size", 0)
        offsets = sorted(set(max(0, o) for o in (0, sb, sb + 32, sb + ss // 2, sb + ss - 16, sb + ss + 64, size - 1)))
        for off in offsets:
            add("/api/hex", offset=off, length=256)
            add("/api/decode", offset=off, endian="little")
        add("/api/hex", offset=sb, length=65536)
        add("/api/decode", offset=sb + 16, endian="big")
        ep = (sl.get("entry_point") or {}).get("vmaddr")
        execs = []
        for seg in sl.get("segments", [])[:16]:
            for sect in seg.get("sections", [])[:64]:
                if sect.get("is_executable") and sect.get("size"):
                    execs.append(sect)
        for q in filter(None, [ep, "0x0", hex(sb + 64), "64", "zzz"]):
            add("/api/translate", query=q)
        add("/api/translate", abs_offset=sb + 8)
        add("/api/translate", slice_offset=16)
        add("/api/disassemble", count=64)
        if ep:
            add("/api/disassemble", vmaddr=ep, count=200)
        for sect in execs[:3]:
            add("/api/disassemble", section="%s,%s" % (sect["segname"], sect["sectname"]), count=120)
        syms = [s for s in sl.get("symbols", []) if s.get("name")][:3]
        strs = [s for s in sl.get("strings", []) if len(s.get("value", "")) > 3][:2]
        queries = ["main", "@_", "\"lib", "#LC", "#text", "text", "zzzz_none", "0x" + "%x" % (sb + 16)]
        queries += [s["name"][:12] for s in syms] + ["\"" + s["value"][:10] for s in strs]
        head = open(inp["file"], "rb").read(sb + 8)[sb:sb + 4].hex() if inp.get("file") else "7f454c46"
        queries.append(head)
        for q in queries:
            add("/api/search", q=q)
        for scope in ("symbols", "strings", "structures", "hex"):
            add("/api/search", q="a", scope=scope)
    # Endpoints registered by other features (learn, labs, ...): exercised generically.
    for method, route in g._router.routes():
        if (method, route) in CORE:
            continue
        r = route[:-1] + "index" if route.endswith("/*") else route
        if method == "GET":
            steps.append({"method": "GET", "route": r, "query": {"doc": ref, "slice_index": "0"}, "input": name})
            steps.append({"method": "GET", "route": r, "query": {}, "input": name})
        elif method == "POST":
            steps.append({"method": "POST", "route": r, "json": {"doc": ref}, "headers": {"content-type": "application/json"}, "input": name})
# Feature endpoints with real parameters (whatever exists in this tree; discovered, not assumed).
routes = set(g._router.routes())
J = {"content-type": "application/json"}
def jcall(method, route, query=None, body=None):
    s, d = call(method, route, query, json.dumps(body).encode() if body is not None else b"", J if body is not None else None)
    try:
        return s, json.loads(d)
    except ValueError:
        return s, None
if ("GET", "/api/learn/*") in routes:
    for name in ("index", "concepts", "glossary", "fields", "instructions", "compare", "tours", "nope"):
        steps.append({"method": "GET", "route": "/api/learn/" + name})
    s, data = jcall("GET", "/api/learn/concepts")
    for c in ((data or {}).get("concepts") or [])[:5]:
        if isinstance(c, dict) and c.get("id"):
            steps.append({"method": "GET", "route": "/api/learn/concept", "query": {"id": str(c["id"])}})
    s, data = jcall("GET", "/api/learn/tours")
    for t in ((data or {}).get("tours") or [])[:6]:
        if isinstance(t, dict) and t.get("id"):
            for ref in ("preset:synthetic_elf64", "preset:synthetic_universal", "preset:synthetic_pe32"):
                steps.append({"method": "GET", "route": "/api/learn/tour", "query": {"id": str(t["id"]), "doc": ref, "slice_index": "0"}})
    for scope in ("header", "segments", "symbols", "load_commands", "x"):
        steps.append({"method": "GET", "route": "/api/learn/resolve", "query": {"scope": scope, "doc": "preset:synthetic_elf64"}})
if ("GET", "/api/labs/encoding/info") in routes:
    steps.append({"method": "GET", "route": "/api/labs/encoding/info"})
    s, info = jcall("GET", "/api/labs/encoding/info")
    archs = [a if isinstance(a, str) else (a.get("id") if isinstance(a, dict) else None) for a in ((info or {}).get("archs") or (info or {}).get("arches") or ["x86_64", "x86", "arm64"])]
    for arch in [a for a in archs if a][:4]:
        for hx in ("4889e5c3", "fd7bbfa9fd030091c0035fd6", "90", "zz"):
            steps.append({"method": "POST", "route": "/api/labs/encoding/decode", "json": {"arch": arch, "hex": hx}, "headers": J})
if ("GET", "/api/labs/build/options") in routes:
    steps.append({"method": "GET", "route": "/api/labs/build/options"})
    s, opts = jcall("GET", "/api/labs/build/options")
    steps.append({"method": "POST", "route": "/api/labs/build", "json": {"format": "elf64"}, "headers": J, "save": "built"})
if ("GET", "/api/labs/compare") in routes:
    steps.append({"method": "GET", "route": "/api/labs/compare", "query": {"a": "preset:synthetic_elf64", "b": "preset:synthetic_elf32"}})
if ("POST", "/api/patch") in routes:
    for inp in spec["inputs"][:8]:
        ref = inp["doc"] if inp["kind"] == "preset" else "$DOC:" + inp["name"]
        key = inp["name"] + ":patched"
        steps.append({"method": "POST", "route": "/api/patch", "json": {"doc": ref, "patches": [{"offset": 16, "hex": "00ff"}, {"offset": 64, "hex": "90"}]}, "headers": J, "save": key})
        steps.append({"method": "GET", "route": "/api/parse", "query": {"doc": "$DOC:" + key}})
        if ("GET", "/api/download") in routes:
            steps.append({"method": "GET", "route": "/api/download", "query": {"doc": "$DOC:" + key}})
        if ("GET", "/api/labs/compare") in routes:
            steps.append({"method": "GET", "route": "/api/labs/compare", "query": {"a": ref, "b": "$DOC:" + key}})
    steps.append({"method": "POST", "route": "/api/patch", "json": {"doc": "preset:synthetic_elf64", "patches": [{"offset": 10 ** 9, "hex": "00"}]}, "headers": J})
    steps.append({"method": "POST", "route": "/api/patch", "json": {"doc": "preset:synthetic_elf64", "patches": "nope"}, "headers": J})
# Errors must have the same shape everywhere.
steps += [
    {"method": "GET", "route": "/api/parse", "query": {"path": "/etc/passwd"}},
    {"method": "GET", "route": "/api/parse", "query": {"doc": "path:/etc/passwd"}},
    {"method": "GET", "route": "/api/parse", "query": {"doc": "u_" + "1" * 32}},
    {"method": "GET", "route": "/api/parse", "query": {"doc": "preset:nope"}},
    {"method": "GET", "route": "/api/hex", "query": {}},
    {"method": "GET", "route": "/api/nope"},
    {"method": "DELETE", "route": "/api/parse"},
    {"method": "POST", "route": "/api/parse", "json": None, "headers": {"content-type": "application/json"}},
    {"method": "POST", "route": "/api/parse", "json": {"doc": [[[[[[[[[[["deep"]]]]]]]]]]]}, "headers": {"content-type": "application/json"}},
    {"method": "POST", "route": "/api/upload", "file": None, "headers": {"content-type": "application/octet-stream"}},
]
# Nesting that CPython rejects with a RecursionError but that would overflow the WASM stack.
for depth in (900, 5000, 100000):
    raw = '{"doc": ' + "[" * depth + "]" * depth + "}"
    steps.append({"method": "POST", "route": "/api/parse", "raw": raw, "headers": {"content-type": "application/json"}})
json.dump({"steps": steps}, open(out_path, "w"))
'''

DOC_ID_RE = re.compile(r"\b[up]_[0-9a-f]{32}\b")
REF_RE = re.compile(r"\(ref [0-9a-f]{8}\)")


def normalize(data: bytes) -> Any:
    text = data.decode("utf-8", "replace")
    text = DOC_ID_RE.sub("<doc>", text)
    text = REF_RE.sub("(ref <ref>)", text)
    try:
        return json.loads(text)
    except ValueError:
        return text


def json_diff(a: Any, b: Any, path: str = "$", out: Optional[List[str]] = None, limit: int = 12) -> List[str]:
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    if type(a) != type(b):  # noqa: E721
        out.append("%s: %r != %r" % (path, str(a)[:80], str(b)[:80]))
    elif isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append("%s.%s: only in %s" % (path, k, "first" if k in a else "second"))
            else:
                json_diff(a[k], b[k], "%s.%s" % (path, k), out, limit)
    elif isinstance(a, list):
        if len(a) != len(b):
            out.append("%s: length %d != %d" % (path, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            json_diff(x, y, "%s[%d]" % (path, i), out, limit)
    elif a != b:
        out.append("%s: %r != %r" % (path, str(a)[:80], str(b)[:80]))
    return out


def hostile_inputs(directory: str) -> List[Dict[str, Any]]:
    """Inputs that once killed the interpreter under Pyodide: entitlement plists nested thousands of
    levels deep (freeing them recursed past the JS stack). Placed first, so the uploads after them
    run while the engine holds (and later frees) whatever the parser built from them."""
    sys.path.insert(0, os.path.join(REPO, "tests"))
    try:
        import test_robustness as tr  # the crafted-binary helpers of the robustness suite
    finally:
        sys.path.remove(os.path.join(REPO, "tests"))
    import struct

    os.makedirs(directory, exist_ok=True)
    out = []
    for depth in (20000, 300, 30):
        plist = (b'<?xml version="1.0"?><plist version="1.0"><dict><key>k</key>' + b"<array>" * depth
                 + b"</array>" * depth + b"</dict></plist>")
        blob = tr.macho_with_signature(tr.superblob([(5, struct.pack(">II", 0xFADE7171, 8 + len(plist)) + plist)]))
        path = os.path.join(directory, "deep_plist_%d.bin" % depth)
        with open(path, "wb") as f:
            f.write(blob)
        out.append({"name": "upload:deep_plist_%d" % depth, "kind": "upload", "file": path})
    return out


def default_inputs(extra: Optional[List[str]] = None, hostile_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    inputs: List[Dict[str, Any]] = hostile_inputs(hostile_dir) if hostile_dir else []
    for pid, _label, filename, _fmt, _desc in __import__("backend.service", fromlist=["x"]).SYNTHETIC_PRESETS:
        inputs.append({"name": "preset:" + pid, "kind": "preset", "doc": "preset:" + pid})
        inputs.append({"name": "upload:" + filename, "kind": "upload", "file": os.path.join(REPO, "fixtures", filename)})
    for path in ["/bin/ls", "/usr/bin/true"] + list(extra or []):
        if os.path.isfile(path):
            inputs.append({"name": "upload:" + path, "kind": "upload", "file": os.path.abspath(path)})
    return inputs


def run_parity(dist: str, inputs: List[Dict[str, Any]], work: str, with_server: bool = False) -> Dict[str, Any]:
    """Plan once, run under CPython and under Pyodide (node), optionally over HTTP against the
    Python server in public mode; returns per-step differences."""
    dist, work = os.path.abspath(dist), os.path.abspath(work)
    manifest = read_manifest(dist)
    root = os.path.join(work, "bundle")
    with zipfile.ZipFile(bundle_path(dist)) as zf:
        zf.extractall(root)
    spec_path = os.path.join(work, "inputs.json")
    with open(spec_path, "w") as f:
        json.dump({"inputs": inputs, "overrides": manifest["overrides"]}, f)
    plan_path = os.path.join(work, "plan.json")
    subprocess.run([sys.executable, "-I", "-c", PLAN_MAKER, root, spec_path, plan_path], check=True, cwd=root, timeout=1800)
    with open(plan_path) as f:
        plan = json.load(f)
    plan["overrides"] = manifest["overrides"]
    plan["indexDir"] = os.path.join(dist, *manifest["pyodide"]["indexURL"].strip("/").split("/"))
    plan["bundle"] = bundle_path(dist)
    with open(plan_path, "w") as f:
        json.dump(plan, f)

    legs = {"cpython": os.path.join(work, "cpython"), "pyodide": os.path.join(work, "pyodide")}
    for d in legs.values():
        os.makedirs(d, exist_ok=True)
    t = time.time()
    subprocess.run([sys.executable, "-I", "-c", CPYTHON_RUNNER, root, plan_path, legs["cpython"]], check=True, cwd=root, timeout=3600)
    cpy_s = time.time() - t
    runner = os.path.join(work, "runner.mjs")
    with open(runner, "w") as f:
        f.write(NODE_RUNNER)
    t = time.time()
    proc = subprocess.run([NODE, "--max-old-space-size=8192", runner, plan_path, legs["pyodide"]], capture_output=True, text=True, timeout=3600)
    if proc.returncode != 0:
        current = ""
        try:
            with open(os.path.join(legs["pyodide"], "current.json")) as f:
                current = f.read()[:600]
        except OSError:
            pass
        raise AssertionError("node/Pyodide runner failed at %s:\n%s" % (
            current, "\n".join(l[:300] for l in proc.stderr.splitlines()[-25:])))
    pyo_s = time.time() - t
    if with_server:
        legs["server"] = os.path.join(work, "server")
        os.makedirs(legs["server"], exist_ok=True)
        run_plan_over_http(plan, legs["server"])

    results = {}
    for leg, d in legs.items():
        with open(os.path.join(d, "results.json")) as f:
            results[leg] = json.load(f)
    diffs: Dict[str, List[Dict[str, Any]]] = {leg: [] for leg in legs if leg != "cpython"}
    for i, step in enumerate(plan["steps"]):
        with open(os.path.join(legs["cpython"], "%05d.bin" % i), "rb") as f:
            ref = normalize(f.read())
        for leg in diffs:
            st_a, st_b = results["cpython"]["results"][i]["status"], results[leg]["results"][i]["status"]
            with open(os.path.join(legs[leg], "%05d.bin" % i), "rb") as f:
                other = normalize(f.read())
            if leg == "server" and step["route"] == "/api/config":
                continue  # mode, limits and features differ by design
            d = json_diff(ref, other)
            if st_a != st_b:
                d.insert(0, "status %s != %s" % (st_a, st_b))
            if d:
                diffs[leg].append({"step": i, "input": step.get("input"), "route": step["route"],
                                   "query": step.get("query"), "diff": d})
    return {"steps": len(plan["steps"]), "diffs": diffs, "results": results, "plan": plan,
            "seconds": {"cpython": round(cpy_s, 1), "pyodide": round(pyo_s, 1)}}


def run_plan_over_http(plan: Dict[str, Any], out_dir: str) -> None:
    """Replay the plan against the real Python HTTP server in public mode (rate limits off)."""
    from backend.server import create_server

    cfg = runtime.RuntimeConfig("public", rate_limit_per_minute=0, upload_rate_limit_per_minute=0,
                                max_upload_bytes=plan["overrides"].get("max_upload_bytes", 256 << 20),
                                parse_timeout_seconds=120.0, max_concurrent_parses=0, max_document_bytes=0,
                                hard_parse_timeout_seconds=0, cache_max_docs=plan["overrides"].get("cache_max_docs", 32),
                                cache_max_bytes=plan["overrides"].get("cache_max_bytes", 512 << 20),
                                cache_client_share=0.0, doc_ttl_seconds=0)
    log = __import__("backend.api", fromlist=["x"]).EventLog(stream=io.StringIO())
    server = create_server(REPO, "127.0.0.1", 0, config=cfg, log=log)
    port = server.server_address[1]
    th = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    th.start()
    docs: Dict[str, str] = {}

    def subst(v: Any) -> Any:
        if isinstance(v, str) and v.startswith("$DOC:"):
            return docs.get(v[5:], "u_" + "0" * 32)
        if isinstance(v, dict):
            return {k: subst(x) for k, x in v.items()}
        if isinstance(v, list):
            return [subst(x) for x in v]
        return v

    results = []
    try:
        for i, step in enumerate(plan["steps"]):
            query = urllib.parse.urlencode(subst(step.get("query") or {}))
            url = "http://127.0.0.1:%d%s%s" % (port, step["route"], ("?" + query) if query else "")
            body = None
            if step.get("file"):
                with open(step["file"], "rb") as f:
                    body = f.read()
            elif step.get("json") is not None:
                body = json.dumps(subst(step["json"])).encode()
            elif step.get("raw") is not None:
                body = step["raw"].encode()
            elif step["method"] in ("POST", "PUT"):
                body = b""
            req = urllib.request.Request(url, data=body, method=step["method"], headers=dict(step.get("headers") or {}))
            try:
                with urllib.request.urlopen(req, timeout=600) as res:
                    status, data, ctype = res.status, res.read(), res.headers.get("content-type", "")
            except urllib.error.HTTPError as exc:
                status, data, ctype = exc.code, exc.read(), exc.headers.get("content-type", "")
            if step.get("save") and status == 200:
                docs[step["save"]] = json.loads(data).get("doc_id") or ""
            with open(os.path.join(out_dir, "%05d.bin" % i), "wb") as f:
                f.write(data)
            results.append({"status": status, "ctype": ctype})
    finally:
        server.shutdown()
        server.server_close()
    with open(os.path.join(out_dir, "results.json"), "w") as f:
        json.dump({"results": results}, f)


# ---------------------------------------------------------------------------
# Tests that always run
# ---------------------------------------------------------------------------
BUNDLE_CHECK = r'''
import json, os, sys
root = sys.argv[1]
sys.path.insert(0, root)
import subprocess
calls = []
def refuse(*a, **k):
    calls.append(a[:1]); raise AssertionError("subprocess in wasm mode")
subprocess.run = subprocess.Popen = subprocess.call = subprocess.check_output = refuse
import bs_wasm_glue as g
g.init(sys.argv[2], root)
def call(method, route, query=None, body=b"", headers=None):
    s, h, d = g.handle(method, route, json.dumps(query or {}), json.dumps(headers or {}), body)
    return s, json.loads(h), d
out = {}
s, h, d = call("GET", "/api/config"); out["config"] = [s, json.loads(d)]
s, h, d = call("GET", "/api/presets"); out["presets"] = [s, json.loads(d)]
out["parse"] = {}
for p in out["presets"][1]["presets"]:
    s, h, d = call("GET", "/api/parse", {"doc": p["doc"]})
    doc = json.loads(d)
    out["parse"][p["id"]] = [s, doc.get("doc_id"), doc.get("file_info", {}).get("path")]
data = open(os.path.join(root, "fixtures", "synthetic_elf64"), "rb").read()
s, h, d = call("POST", "/api/upload", None, data, {"content-type": "application/octet-stream", "x-filename": "a%2Fb%0A.bin"})
up = json.loads(d)
out["upload"] = [s, up.get("doc_id", ""), up.get("file_info", {}).get("filename")]
doc = up.get("doc_id")
for route, q in (("/api/hex", {"offset": "0", "length": "64"}), ("/api/decode", {"offset": "0"}),
                 ("/api/translate", {"query": "0x0"}), ("/api/disassemble", {"count": "20"}),
                 ("/api/search", {"q": "main"})):
    q = dict(q, doc=doc, slice_index="0")
    s, h, d = call("GET", route, q)
    out[route] = s
s, h, d = call("GET", "/api/parse", {"path": "/etc/passwd"}); out["path_param"] = [s, json.loads(d)]
s, h, d = call("GET", "/api/parse", {"doc": "path:/etc/passwd"}); out["path_doc"] = [s, json.loads(d)]
s, h, d = call("GET", "/api/nope"); out["unknown"] = [s, json.loads(d)]
s, h, d = call("POST", "/api/upload", None, b"\x00" * 64, {"content-type": "application/octet-stream"})
out["garbage"] = [s, json.loads(d)]
out["oversize"] = call("POST", "/api/upload", None, b"\x7fELF" + b"\x00" * (g._config.max_upload_bytes), {"content-type": "application/octet-stream"})[0]
def _oom(req):
    raise MemoryError()
g._router.register("GET", "/api/_test_oom", _oom)
s, h, d = call("GET", "/api/_test_oom"); out["oom"] = [s, json.loads(d), g.should_recycle()]
g.init(sys.argv[2], root)
out["recycle_after_init"] = g.should_recycle()
s, h, d = call("POST", "/api/parse", None, ('{"doc": ' + "[" * 50000 + "]" * 50000 + "}").encode(), {"content-type": "application/json"})
out["deep_json"] = [s, json.loads(d)]
out["subprocess_calls"] = len(calls)
out["modules"] = sorted(m for m in sys.modules if m.startswith("backend"))
out["forbidden_imports"] = sorted(m for m in ("socket", "http.client", "urllib.request", "js", "pyodide.http", "ssl") if m in sys.modules)
out["stats"] = json.loads(g.stats())
print(json.dumps(out))
'''


class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = read_manifest(DIST)
        cls.tmp = tempfile.mkdtemp(prefix="bs-bundle-")
        with zipfile.ZipFile(bundle_path(DIST)) as zf:
            cls.names = zf.namelist()
            zf.extractall(cls.tmp)
        proc = subprocess.run([sys.executable, "-I", "-c", BUNDLE_CHECK, cls.tmp, json.dumps(cls.manifest["overrides"])],
                              cwd=cls.tmp, capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            raise AssertionError("bundle check failed:\n" + proc.stderr[-3000:])
        cls.out = json.loads(proc.stdout.strip().splitlines()[-1])

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_config_is_wasm_mode_and_restricted(self) -> None:
        status, config = self.out["config"]
        self.assertEqual(status, 200)
        self.assertEqual(config["mode"], "wasm")
        self.assertEqual(config["features"]["path_load"], False)
        self.assertEqual(config["features"]["host_presets"], False)
        self.assertEqual(config["features"]["external_tools"], False)
        self.assertEqual(config["limits"]["max_upload_bytes"], build_static.WASM_OVERRIDES["max_upload_bytes"])
        self.assertEqual(config, self.manifest["config"], "the static /api/config must equal the engine's answer")

    def test_presets_are_the_six_samples_without_paths(self) -> None:
        status, data = self.out["presets"]
        self.assertEqual(status, 200)
        ids = [p["id"] for p in data["presets"]]
        self.assertEqual(len(ids), 6, ids)
        self.assertTrue(all(p["exists"] for p in data["presets"]))
        self.assertTrue(all("path" not in p for p in data["presets"]))
        self.assertEqual(data["presets"], self.manifest["presets"])
        for pid, (s, doc_id, path) in self.out["parse"].items():
            self.assertEqual(s, 200, pid)
            self.assertEqual(doc_id, "preset:" + pid)
            self.assertEqual(path, "<preset:%s>" % pid)

    def test_upload_and_doc_scoped_calls(self) -> None:
        s, doc_id, filename = self.out["upload"]
        self.assertEqual(s, 200)
        self.assertRegex(doc_id, r"^u_[0-9a-f]{32}$")
        self.assertEqual(filename, "b.bin")  # path stripped, control character dropped
        for route in ("/api/hex", "/api/decode", "/api/translate", "/api/disassemble", "/api/search"):
            self.assertEqual(self.out[route], 200, route)

    def test_errors_are_contract_shaped(self) -> None:
        for key, status in (("path_param", 403), ("path_doc", 403), ("unknown", 404), ("garbage", 422)):
            s, body = self.out[key]
            self.assertEqual(s, status, key)
            self.assertEqual(set(body), {"error", "code"}, key)
            self.assertNotIn("Traceback", body["error"])
        self.assertEqual(self.out["oversize"], 413)

    def test_memory_error_becomes_out_of_memory_and_recycles(self) -> None:
        status, body, recycle = self.out["oom"]
        self.assertEqual(status, 507)
        self.assertEqual(body["code"], "out_of_memory")
        self.assertTrue(recycle)
        self.assertFalse(self.out["recycle_after_init"])

    def test_deeply_nested_json_is_refused_before_parsing(self) -> None:
        status, body = self.out["deep_json"]
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "Request body is not valid JSON.", "code": "bad_request"})

    def test_never_starts_a_subprocess_and_has_no_network_imports(self) -> None:
        self.assertEqual(self.out["subprocess_calls"], 0)
        self.assertEqual(self.out["forbidden_imports"], [])
        self.assertNotIn("backend.server", self.out["modules"])
        self.assertNotIn("backend.fixtures", self.out["modules"])

    def test_bundle_contents(self) -> None:
        names = set(self.names)
        self.assertIn("bs_wasm_glue.py", names)
        self.assertIn("backend/__init__.py", names)
        self.assertIn("backend/api.py", names)
        for excluded in ("backend/server.py", "backend/fixtures.py"):
            self.assertNotIn(excluded, names)
        fixtures = sorted(n for n in names if n.startswith("fixtures/"))
        self.assertEqual(len(fixtures), 6, fixtures)
        for n in names:
            self.assertFalse(n.startswith(("tests/", "docs/", "deploy/", ".git", "static/")), n)
            self.assertNotIn("__pycache__", n)
            self.assertFalse(n.endswith((".pyc", ".DS_Store")), n)
        with zipfile.ZipFile(bundle_path(DIST)) as zf:
            for info in zf.infolist():
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))

    def test_bundle_is_deterministic(self) -> None:
        self.assertEqual(build_static.build_bundle(), build_static.build_bundle())


class OutputTests(unittest.TestCase):
    TEXT_EXT = (".html", ".js", ".mjs", ".css", ".json", ".txt", ".xml", ".svg", ".webmanifest", "_headers", ".py")

    def texts(self) -> List[Tuple[str, str]]:
        """(name, text) for every text file shipped, including the files inside the engine bundle."""
        out = []
        for rel in dist_files():
            path = os.path.join(DIST, rel)
            if rel.endswith(self.TEXT_EXT):
                with open(path, "rb") as f:
                    out.append((rel, f.read().decode("utf-8", "replace")))
            elif rel.endswith(".zip") and "/pyodide-" not in rel:
                with zipfile.ZipFile(path) as zf:
                    for n in zf.namelist():
                        if n.endswith(self.TEXT_EXT):
                            out.append((rel + "!" + n, zf.read(n).decode("utf-8", "replace")))
        return out

    def test_no_absolute_local_paths(self) -> None:
        needles = {REPO, os.path.realpath(REPO), os.path.expanduser("~"), build_static.default_cache_dir(), _TMP}
        user = os.path.basename(os.path.expanduser("~"))
        needles |= {"/Users/" + user, "/home/" + user}
        for rel, text in self.texts():
            for needle in needles:
                self.assertNotIn(needle, text, "%s contains the local path %s" % (rel, needle))

    def test_no_third_party_origins(self) -> None:
        url_re = re.compile(r"\bhttps?://([a-z0-9.-]+\.[a-z]{2,})", re.I)
        # Not requests: the SVG namespace; placeholder hosts in backend docstrings (RFC 2606 .example).
        allowed = {"www.w3.org"}
        for rel, text in self.texts():
            if "/pyodide-" in rel:
                continue
            for host in url_re.findall(text):
                if host.lower() in allowed or host.lower().endswith(".example"):
                    continue
                self.fail("%s references %s" % (rel, host))

    def test_pyodide_cdn_default_is_overridden(self) -> None:
        if not HAS_RUNTIME:
            self.skipTest(NO_RUNTIME)
        pyo = [r for r in dist_files() if "/pyodide-" in r]
        hosts = set()
        for rel in pyo:
            if rel.endswith((".mjs", ".json")):
                with open(os.path.join(DIST, rel), "r", encoding="utf-8", errors="replace") as f:
                    hosts |= set(re.findall(r"https?://([a-z0-9.-]+)", f.read()))
        # pyodide.mjs carries one inert default (its package CDN). The worker always passes
        # packageBaseUrl (same origin) and the lock file lists no packages, so it is never used;
        # BrowserTests proves no request leaves the origin.
        self.assertLessEqual(hosts, {"cdn.jsdelivr.net"})
        with open(os.path.join(REPO, "static", "wasm", "engine-worker.js"), encoding="utf-8") as f:
            worker = f.read()
        self.assertIn("packageBaseUrl: msg.pyodide.indexURL", worker)
        with open(os.path.join(DIST, read_manifest(DIST)["pyodide"]["indexURL"], "pyodide-lock.json")) as f:
            self.assertEqual(json.load(f)["packages"], {})

    def test_nothing_that_should_not_ship(self) -> None:
        files = dist_files()
        for rel in files:
            top = rel.split("/")[0]
            self.assertNotIn(top, ("tests", "docs", "deploy", "backend", "fixtures", "tools", ".git"), rel)
            self.assertFalse(any(part.startswith(".") for part in rel.split("/")), rel)
            self.assertFalse(rel.endswith((".py", ".pyc", ".md", ".d.ts", ".exe", ".bat")), rel)
            self.assertNotIn("Dockerfile", rel)
            self.assertFalse(rel.startswith("static/wasm/"), "unbuilt engine sources shipped: " + rel)
        if HAS_RUNTIME:
            pyo = sorted(r.rsplit("/", 1)[1] for r in files if "/pyodide-" in r)
            self.assertEqual(pyo, sorted(build_static.PYODIDE_FILES))

    def test_index_references_resolve_and_transport_is_first(self) -> None:
        with open(os.path.join(DIST, "index.html"), encoding="utf-8") as f:
            html = f.read()
        body = re.sub(r"<!--.*?-->", "", html, flags=re.S)
        refs = re.findall(r'(?:src|href)="([^"#]+)"', body)
        local = [r.split("?", 1)[0] for r in refs if not r.startswith(("#", "data:"))]
        self.assertTrue(local)
        for r in local:
            self.assertTrue(os.path.isfile(os.path.join(DIST, *r.split("/"))), r)
        scripts = re.findall(r"<script\b([^>]*)>", body)
        srcs = [re.search(r'src="([^"]+)"', s).group(1) for s in scripts]
        self.assertRegex(srcs[0], r"^assets/app\.[0-9a-f]{12}\.js$")
        self.assertRegex(srcs[1], r"^assets/transport\.[0-9a-f]{12}\.js$")
        self.assertIn("defer", scripts[1])
        self.assertNotRegex(body, r"<script(?![^>]*\bsrc=)[^>]*>", "no inline scripts")
        # Every feature file index.html references in the source tree is in the build.
        with open(os.path.join(REPO, "static", "index.html"), encoding="utf-8") as f:
            src = re.sub(r"<!--.*?-->", "", f.read(), flags=re.S)
        n_src = len(re.findall(r'(?:src|href)="static/', src))
        built = [r for r in refs if r.startswith("assets/") or (r.startswith("static/") and "?v=" in r)]
        self.assertEqual(len(built), n_src + 2, "every static/ reference is versioned, plus the transport and its CSS")

    def test_meta_csp_matches_headers(self) -> None:
        with open(os.path.join(DIST, "index.html"), encoding="utf-8") as f:
            html = f.read()
        meta = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1).replace("&quot;", '"')
        header = parse_csp(self.headers_csp())
        header.pop("frame-ancestors")
        self.assertEqual(parse_csp(meta), header)

    def test_manifest_consistent(self) -> None:
        m = read_manifest(DIST)
        self.assertEqual(m["config"]["mode"], "wasm")
        self.assertEqual(m["pyodide"]["version"], build_static.PYODIDE_VERSION)
        with open(bundle_path(DIST), "rb") as f:
            data = f.read()
        self.assertEqual(build_static.sha256_bytes(data), m["bundle"]["sha256"])
        self.assertEqual(len(data), m["bundle"]["size"])
        self.assertTrue(os.path.isfile(os.path.join(DIST, *m["worker"].split("/"))))
        if HAS_RUNTIME:
            for f in m["prefetch"]:
                path = os.path.join(DIST, *f["url"].split("/"))
                self.assertEqual(os.path.getsize(path), f["size"], f["url"])
        for rel in [m["worker"], m["bundle"]["url"]]:
            self.assertTrue(rel.startswith("assets/"))

    def test_service_worker_precache_exists(self) -> None:
        with open(os.path.join(DIST, "sw.js"), encoding="utf-8") as f:
            sw = f.read()
        self.assertNotIn("@@", sw)
        pre = json.loads(re.search(r"const PRECACHE = (\[.*?\]);", sw).group(1))
        if HAS_RUNTIME:
            self.assertIn("index.html", pre)
            for p in pre:
                if p != "./":
                    self.assertTrue(os.path.isfile(os.path.join(DIST, *p.split("/"))), p)
            self.assertTrue(any(p.endswith("pyodide.asm.wasm") for p in pre))

    def test_build_fails_loudly_on_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as cache:
            with open(build_static.pyodide_archive_path(cache), "wb") as f:
                f.write(b"not the pinned archive")
            with self.assertRaises(build_static.BuildError) as ctx:
                build_static.ensure_pyodide_archive(cache, offline=True)
            self.assertIn("SHA-256", str(ctx.exception))
            with self.assertRaises(build_static.BuildError):
                build_static.ensure_pyodide_archive(os.path.join(cache, "empty"), offline=True)

    @staticmethod
    def headers_csp() -> str:
        with open(os.path.join(DIST, "_headers"), encoding="utf-8") as f:
            rules = build_static.parse_headers_file(f.read())
        return build_static.headers_for(rules, "/index.html")["Content-Security-Policy"]


class HeadersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with open(os.path.join(DIST, "_headers"), encoding="utf-8") as f:
            cls.rules = build_static.parse_headers_file(f.read())
        # What the Python server really sends for a page in public mode.
        from backend.api import EventLog
        from backend.server import create_server

        server = create_server(REPO, "127.0.0.1", 0, config=runtime.RuntimeConfig("public"), log=EventLog(stream=io.StringIO()))
        th = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        th.start()
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/" % server.server_address[1], timeout=10) as res:
                cls.server_headers = {k.lower(): v for k, v in res.headers.items()}
        finally:
            server.shutdown()
            server.server_close()

    def test_csp_is_server_csp_plus_wasm_unsafe_eval_only(self) -> None:
        static = parse_csp(build_static.headers_for(self.rules, "/")["Content-Security-Policy"])
        server = parse_csp(self.server_headers["content-security-policy"])
        self.assertIn("'wasm-unsafe-eval'", static["script-src"])
        self.assertNotIn("'unsafe-eval'", static["script-src"])
        static["script-src"] = [s for s in static["script-src"] if s != "'wasm-unsafe-eval'"]
        self.assertEqual(static, server)
        self.assertEqual(static["worker-src"], ["'self'"])
        for sources in static.values():
            for s in sources:
                self.assertFalse(s.startswith(("http:", "https:", "*", "blob:")), s)

    def test_other_security_headers_match_server(self) -> None:
        h = {k.lower(): v for k, v in build_static.headers_for(self.rules, "/").items()}
        for name in ("x-content-type-options", "x-frame-options", "referrer-policy", "cross-origin-opener-policy",
                     "cross-origin-resource-policy", "permissions-policy"):
            self.assertEqual(h.get(name), self.server_headers.get(name), name)

    def test_cache_rules_never_overlap(self) -> None:
        for path in ("/", "/index.html", "/sw.js", "/assets/app.0123456789ab.js", "/assets/pyodide-x/pyodide.asm.wasm",
                     "/static/styles.css"):
            h = build_static.headers_for(self.rules, path)
            cc = h.get("Cache-Control", "")
            self.assertNotIn(",  ", cc)
            self.assertLessEqual(cc.count("max-age"), 1, path)
            if path.startswith("/assets/"):
                self.assertEqual(cc, build_static.IMMUTABLE)
            else:
                self.assertEqual(cc, "", path)

    def test_local_static_server_applies_headers(self) -> None:
        import http.server

        log: List[Dict[str, Any]] = []
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), build_static.make_handler(DIST, log))
        th = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        th.start()
        base = "http://127.0.0.1:%d" % server.server_address[1]
        try:
            with urllib.request.urlopen(base + "/", timeout=10) as res:
                self.assertEqual(res.headers["Content-Security-Policy"], build_static.headers_for(self.rules, "/")["Content-Security-Policy"])
                self.assertIsNone(res.headers.get("Cache-Control"))
            worker = read_manifest(DIST)["worker"]
            with urllib.request.urlopen(base + "/" + worker, timeout=10) as res:
                self.assertEqual(res.headers["Cache-Control"], build_static.IMMUTABLE)
                self.assertTrue(res.headers["Content-Type"].startswith("text/javascript"))
                self.assertIn("'wasm-unsafe-eval'", res.headers["Content-Security-Policy"])
            for bad in ("/_headers", "/../README.md", "/.git/config", "/%2e%2e/README.md"):
                try:
                    urllib.request.urlopen(base + bad, timeout=10)
                    self.fail("served " + bad)
                except urllib.error.HTTPError as exc:
                    self.assertEqual(exc.code, 404, bad)
            if HAS_RUNTIME:
                wasm = read_manifest(DIST)["pyodide"]["indexURL"] + "pyodide.asm.wasm"
                with urllib.request.urlopen(base + "/" + wasm, timeout=10) as res:
                    self.assertEqual(res.headers["Content-Type"], "application/wasm")
        finally:
            server.shutdown()
            server.server_close()


# ---------------------------------------------------------------------------
# Runtime-dependent tests
# ---------------------------------------------------------------------------
class EngineParityTests(unittest.TestCase):
    def setUp(self) -> None:
        if not HAS_RUNTIME:
            self.skipTest(NO_RUNTIME)
        if not NODE:
            self.skipTest("node is not installed; the Pyodide parity check runs the shipped runtime in node")

    def test_cpython_and_pyodide_answer_identically(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bs-parity-") as work:
            report = run_parity(DIST, default_inputs(hostile_dir=os.path.join(work, "hostile")), work)
        diffs = report["diffs"]["pyodide"]
        self.assertGreater(report["steps"], 300)
        statuses = [r["status"] for r in report["results"]["pyodide"]["results"]]
        self.assertGreater(statuses.count(200), 250)
        self.assertEqual(report["results"]["cpython"]["modules"], report["results"]["pyodide"]["modules"])
        self.assertEqual(diffs, [], json.dumps(diffs[:5], indent=1))


BROWSER_SCRIPT = r'''
// Headless Chrome over CDP, no dependencies. argv: baseURL, uploadFile
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const [base, uploadFile, chromePath] = process.argv.slice(2);
const dir = mkdtempSync(join(tmpdir(), 'bs-chrome-'));
const chrome = spawn(chromePath, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${dir}`, '--no-first-run',
  '--no-default-browser-check', '--disable-extensions', '--disable-background-networking', '--disable-component-update',
  '--disable-sync', '--disable-features=OptimizationHints,MediaRouter', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
const fail = (m) => { console.log(JSON.stringify({ fatal: m })); try { chrome.kill('SIGKILL'); } catch {} process.exit(1); };
setTimeout(() => fail('overall timeout'), 150000);
const wsUrl = await new Promise((res, rej) => { let b = ''; chrome.stderr.on('data', (d) => { b += d; const m = b.match(/DevTools listening on (ws:\/\/\S+)/); if (m) res(m[1]); }); setTimeout(() => rej(new Error('chrome start')), 20000); });
const ws = new WebSocket(wsUrl); await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const sessions = new Map();
ws.onmessage = (ev) => { const m = JSON.parse(ev.data); if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result); } else if (m.method) { (sessions.get(m.sessionId) || (() => {}))(m.method, m.params, m.sessionId); } };
const send = (method, params = {}, sessionId) => new Promise((res, rej) => { const i = ++id; pending.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });
const requests = []; const problems = [];
const onEvent = (method, params, sid) => {
  if (method === 'Network.requestWillBeSent') requests.push({ url: params.request.url, method: params.request.method, post: params.request.hasPostData || false });
  else if (method === 'Log.entryAdded' && params.entry.level === 'error' && !/favicon\.ico/.test(params.entry.url || '')) problems.push(params.entry.text);
  else if (method === 'Runtime.exceptionThrown') problems.push('exception: ' + (params.exceptionDetails.exception?.description || params.exceptionDetails.text));
  else if (method === 'Runtime.consoleAPICalled' && params.type === 'error') problems.push('console.error: ' + params.args.map((a) => a.value ?? a.description).join(' '));
  else if (method === 'Target.attachedToTarget') { const s = params.sessionId; sessions.set(s, onEvent); send('Network.enable', {}, s).catch(() => {}); send('Log.enable', {}, s).catch(() => {}); send('Runtime.enable', {}, s).catch(() => {}); send('Runtime.runIfWaitingForDebugger', {}, s).catch(() => {}); }
};
const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
sessions.set(sessionId, onEvent);
for (const m of ['Page.enable', 'Runtime.enable', 'Log.enable', 'Network.enable']) await send(m, {}, sessionId);
await send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sessionId);
const evalJs = async (expr) => { const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }, sessionId); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text); return r.result.value; };
const waitFor = async (expr, ms) => { const t = Date.now(); while (Date.now() - t < ms) { try { const v = await evalJs(expr); if (v) return v; } catch {} await new Promise((r) => setTimeout(r, 50)); } throw new Error('timeout: ' + expr); };
const out = {};
try {
  await send('Page.navigate', { url: base }, sessionId);
  out.shellMs = await waitFor("document.getElementById('status-text')?.textContent === 'Ready' && Math.round(performance.now())", 15000);
  out.queuedBeforeReady = await evalJs("window.BinaryStudioEngine.state !== 'ready'");
  const early = evalJs("BS.openPreset('synthetic_pe64').then((d) => d && d.doc_id)");
  out.engine = await waitFor("window.BinaryStudioEngine.state === 'ready' && window.BinaryStudioEngine.timings()", 90000);
  out.earlyPreset = await early;
  out.mode = await evalJs("BS.config.mode");
  out.preset = await evalJs("BS.openPreset('synthetic_universal').then((d) => d && d.doc_id)");
  out.hex = await evalJs("BS.api.get('/api/hex', {offset: 0, length: 16}).then((r) => r.hex_bytes)");
  const b64 = readFileSync(uploadFile).toString('base64');
  out.upload = await evalJs(`(async () => { const bin = atob(${JSON.stringify(b64)}); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); const d = await BS.loadBytes('marker.bin', u); return d && d.doc_id; })()`);
  out.search = await evalJs("BS.api.get('/api/search', {q: 'main'}).then((r) => r.results.length)");
  out.disasm = await evalJs("BS.api.get('/api/disassemble', {count: 10}).then((r) => (r.instructions || r.lines || []).length)");
  // Stop a long request: the engine restarts, the open document comes back through doc_expired recovery.
  out.cancel = await evalJs(`(async () => {
    const E = window.BinaryStudioEngine;
    for (let i = 0; i < 20; i++) {
      const p = BS.api.get('/api/disassemble', {count: 1000}).then(() => 'answered', (e) => e.code);
      for (let k = 0; k < 200 && !E.busy; k++) await new Promise((r) => setTimeout(r, 0));
      if (!E.busy) { await p; continue; }
      // A request queued behind the one being stopped must survive the restart.
      const q = BS.api.get('/api/hex', {offset: 0, length: 16}).then((r) => r.hex_bytes, (e) => 'error ' + e.code);
      await new Promise((r) => setTimeout(r, 0));
      if (!E.busy || !E.queued) { await p; await q; continue; }
      if (E.cancel()) return [await p, await q];
      await p; await q;
    }
    return 'never caught busy';
  })()`);
  await waitFor("window.BinaryStudioEngine.state === 'ready'", 60000);
  out.afterRestart = await evalJs("BS.api.get('/api/hex', {offset: 0, length: 16}).then((r) => r.hex_bytes)");
  out.restarts = await evalJs("window.BinaryStudioEngine.timings().restarts");
} catch (e) { out.error = String(e.message || e); }
out.requests = requests; out.problems = problems;
console.log(JSON.stringify(out));
try { await send('Browser.close'); } catch {}
chrome.kill('SIGKILL'); try { rmSync(dir, { recursive: true, force: true }); } catch {}
process.exit(0);
'''


class BrowserTests(unittest.TestCase):
    def setUp(self) -> None:
        if not HAS_RUNTIME:
            self.skipTest(NO_RUNTIME)
        if not NODE or not os.path.exists(CHROME):
            self.skipTest("needs node and Google Chrome (%s)" % CHROME)

    def test_site_runs_under_its_own_headers_and_stays_on_origin(self) -> None:
        import http.server

        log: List[Dict[str, Any]] = []
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), build_static.make_handler(DIST, log))
        th = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        th.start()
        base = "http://127.0.0.1:%d/" % server.server_address[1]
        marker = os.urandom(48)
        with tempfile.TemporaryDirectory() as tmp:
            upload = os.path.join(tmp, "marker.bin")
            with open(os.path.join(REPO, "fixtures", "synthetic_elf64"), "rb") as f:
                data = f.read()
            with open(upload, "wb") as f:
                f.write(data + marker)
            script = os.path.join(tmp, "browser.mjs")
            with open(script, "w") as f:
                f.write(BROWSER_SCRIPT)
            try:
                proc = subprocess.run([NODE, script, base, upload, CHROME], capture_output=True, text=True, timeout=200)
            finally:
                server.shutdown()
                server.server_close()
        lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
        self.assertTrue(lines, proc.stdout[-2000:] + proc.stderr[-2000:])
        out = json.loads(lines[-1])
        self.assertNotIn("fatal", out)
        self.assertNotIn("error", out, out.get("error"))
        self.assertEqual(out["problems"], [], "console errors / CSP violations")
        self.assertEqual(out["mode"], "wasm")
        self.assertEqual(out["earlyPreset"], "preset:synthetic_pe64", "a request made before the engine was ready must wait, not fail")
        self.assertEqual(out["preset"], "preset:synthetic_universal")
        self.assertRegex(out["upload"] or "", r"^u_[0-9a-f]{32}$")
        self.assertGreater(out["search"], 0)
        self.assertIsInstance(out["cancel"], list, out["cancel"])
        self.assertEqual(out["cancel"][0], "cancelled")
        self.assertEqual(out["cancel"][1], data[:16].hex(), "the queued request survived the restart")
        self.assertEqual(out["afterRestart"], data[:16].hex())
        self.assertGreaterEqual(out["restarts"], 1)
        origin = base.rstrip("/")
        others = [r["url"] for r in out["requests"] if not r["url"].startswith((origin, "data:", "about:", "blob:"))]
        self.assertEqual(others, [], "requests to other origins")
        self.assertFalse([r for r in out["requests"] if r["method"] != "GET"], "the site only ever GETs")
        # The static server saw every request the browser made to it: none carried a body.
        self.assertTrue(log)
        self.assertEqual([e for e in log if e["body_bytes"]], [])
        self.assertEqual([e for e in log if e["method"] != "GET"], [])
        self.assertFalse(any("marker" in e["path"] for e in log))


# ---------------------------------------------------------------------------
# Full parity report (manual)
# ---------------------------------------------------------------------------
def _parity_main(argv: List[str]) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Engine parity: CPython vs Pyodide (vs the Python server).")
    ap.add_argument("--parity", action="store_true")
    ap.add_argument("--dist", help="an existing build (default: build one into a temp dir)")
    ap.add_argument("--no-server", action="store_true", help="skip the HTTP server leg")
    ap.add_argument("--json", help="write the full diff report here")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args(argv)
    global DIST, HAS_RUNTIME, _TMP
    if args.dist:
        DIST = os.path.abspath(args.dist)
    else:
        setUpModule()
    if not NODE:
        print("node is required")
        return 2
    with tempfile.TemporaryDirectory(prefix="bs-parity-") as work:
        report = run_parity(DIST, default_inputs(args.files, hostile_dir=os.path.join(work, "hostile")), work,
                            with_server=not args.no_server)
    print("steps: %d   cpython %ss   pyodide %ss" % (report["steps"], report["seconds"]["cpython"], report["seconds"]["pyodide"]))
    print("python: cpython %s, pyodide %s" % (report["results"]["cpython"]["python"], report["results"]["pyodide"]["python"]))
    statuses: Dict[int, int] = {}
    for r in report["results"]["cpython"]["results"]:
        statuses[r["status"]] = statuses.get(r["status"], 0) + 1
    print("statuses (cpython):", dict(sorted(statuses.items())))
    for leg, diffs in report["diffs"].items():
        print("\n%s vs cpython: %d differing responses" % (leg, len(diffs)))
        for d in diffs[:40]:
            print("  #%d %s %s %s" % (d["step"], d["input"], d["route"], json.dumps(d["query"])[:120]))
            for line in d["diff"][:6]:
                print("      " + line)
    if args.json:
        with open(args.json, "w") as f:
            json.dump({k: v for k, v in report.items() if k != "plan"}, f, indent=1)
    if not args.dist:
        tearDownModule()
    return 0 if not any(report["diffs"].values()) else 1


if __name__ == "__main__":
    if "--parity" in sys.argv:
        sys.exit(_parity_main(sys.argv[1:]))
    unittest.main()
