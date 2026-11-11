"""
Security tests for the API router, the document store and the HTTP adapter.

Each class pins down one way the pre-2.0 server could be abused:

  * any file readable through `path=` (+ /api/hex)            -> RouterPublicModeTests, HttpPublicModeTests
  * one global "active document" shared by every visitor      -> test_uploads_are_isolated*, test_no_implicit_document
  * unbounded cache / uploads / base64 doubling               -> DocumentStoreTests, test_oversize_*
  * `Access-Control-Allow-Origin: *`, DNS rebinding, CSRF     -> CrossSiteCheckTests, Http*ModeTests
  * tracebacks in 500 responses                               -> test_internal_errors_do_not_leak
  * static path containment by string prefix                  -> StaticPathTests, test_static_traversal_over_http
  * no timeouts, no rate limits, unbounded threads            -> RateLimitTests, test_slow_request_head_*, test_connection_cap

Servers listen on an ephemeral loopback port and are shut down by each class.
Nothing here changes the process-wide runtime config.
"""

import base64
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKSPACE_ROOT)

from backend import runtime, service as service_module
from backend.api import (
    ApiRequest,
    ApiResponse,
    EventLog,
    TokenBucketLimiter,
    allowed_host_names,
    build_router,
    client_key,
    cross_site_reason,
    host_allowed,
    redact_doc_id,
    resolve_client_address,
    security_headers,
)
from backend.fixtures import ensure_fixtures
from backend.runtime import RuntimeConfig
from backend.server import create_server, resolve_static_path
from backend.service import AnalysisService, DocEntry, DocumentStore

SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "x-frame-options",
)

FIXTURES = ensure_fixtures(WORKSPACE_ROOT)
with open(FIXTURES["synthetic_elf64"], "rb") as _f:
    ELF_BYTES = _f.read()
with open(FIXTURES["synthetic_pe64"], "rb") as _f:
    PE_BYTES = _f.read()


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def public_config(**overrides):
    values = dict(rate_limit_per_minute=0, upload_rate_limit_per_minute=0, hard_parse_timeout_seconds=0)
    values.update(overrides)
    return RuntimeConfig("public", **values)


def make_router(config=None, clock=None):
    config = config or public_config()
    clock = clock or time.monotonic
    log = EventLog(stream=io.StringIO())
    service = AnalysisService(WORKSPACE_ROOT, config, clock=clock)
    return build_router(service, config, log=log, clock=clock), service, log


def call(router, method, route, query=None, body=b"", headers=None, client="203.0.113.7"):
    resp = router.handle(ApiRequest(method, route, query or {}, body, headers or {}, client))
    payload = None
    if resp.content_type.startswith("application/json") and resp.body:
        payload = json.loads(resp.body.decode("utf-8"))
    return resp, payload


def upload(router, data, name="sample.bin", client="203.0.113.7"):
    return call(router, "POST", "/api/upload", body=data,
                headers={"Content-Type": "application/octet-stream", "X-Filename": name}, client=client)


# =============================================================================
# The router, with no socket anywhere
# =============================================================================
class RouterPublicModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.router, cls.service, cls.log = make_router()

    def test_router_works_without_a_socket(self) -> None:
        resp, cfg = call(self.router, "GET", "/api/config")
        self.assertEqual(resp.status, 200)
        self.assertEqual(cfg["mode"], "public")
        self.assertEqual(cfg["app"], "BinaryStudio")
        self.assertFalse(cfg["features"]["path_load"])
        self.assertFalse(cfg["features"]["host_presets"])
        self.assertFalse(cfg["features"]["external_tools"])
        self.assertEqual(cfg["limits"]["max_upload_bytes"], self.router.config.max_upload_bytes)
        for key in ("ads", "links"):
            self.assertIn(key, cfg)

    def test_api_modules_import_no_transport(self) -> None:
        # The WASM build imports the router inside Pyodide: no sockets, no HTTP server.
        code = (
            "import sys; sys.path.insert(0, %r); import backend.runtime, backend.api; "
            "print(sorted(m for m in ('socket', 'socketserver', 'http.server', 'ssl', 'subprocess', 'select') "
            "if m in sys.modules))" % WORKSPACE_ROOT
        )
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "[]")
        # service.py itself must not reach for a transport either (its parser imports are another matter).
        with open(os.path.join(WORKSPACE_ROOT, "backend", "service.py"), encoding="utf-8") as f:
            source = f.read()
        for module in ("socket", "http.server", "socketserver", "subprocess"):
            self.assertIsNone(re.search(r"^\s*(import|from)\s+%s\b" % re.escape(module), source, re.M), module)

    def test_arbitrary_file_read_is_refused_everywhere(self) -> None:
        for route in ("/api/parse", "/api/hex", "/api/decode", "/api/translate", "/api/disassemble", "/api/search"):
            for target in ("/etc/passwd", "/etc/hosts", "../../../etc/passwd", "fixtures/synthetic_elf64"):
                resp, payload = call(self.router, "GET", route, {"path": target, "q": "root", "offset": "0"})
                self.assertEqual(resp.status, 403, (route, target))
                self.assertEqual(payload["code"], "forbidden")
                self.assertNotIn(b"root:", resp.body)
            # The path must not win even next to a valid doc id.
            resp, payload = call(self.router, "GET", route, {"path": "/etc/passwd", "doc": "preset:synthetic_elf64"})
            self.assertEqual(resp.status, 403, route)

        resp, payload = call(self.router, "POST", "/api/parse", body=json.dumps({"path": "/etc/passwd"}).encode(),
                             headers={"Content-Type": "application/json"})
        self.assertEqual((resp.status, payload["code"]), (403, "forbidden"))

        for doc in ("path:/etc/passwd", "path:" + FIXTURES["synthetic_elf64"]):
            resp, payload = call(self.router, "GET", "/api/hex", {"doc": doc})
            self.assertEqual((resp.status, payload["code"]), (403, "forbidden"))
        for doc in ("/etc/passwd", "../../etc/passwd", "u_../../etc/passwd", "preset:../../etc/passwd",
                    "preset:/etc/passwd", "preset:synthetic_elf64/../../x", "file:///etc/passwd", "u_" + "g" * 32,
                    "U_" + "0" * 32, "u_" + "0" * 31, "u_" + "0" * 33, "\x00", "preset:"):
            resp, payload = call(self.router, "GET", "/api/hex", {"doc": doc})
            self.assertEqual(resp.status, 400, doc)
            self.assertEqual(payload["code"], "bad_request", doc)

    def test_service_itself_refuses_paths(self) -> None:
        # Defence in depth: even code that bypasses the router cannot load a path in public mode.
        with self.assertRaises(runtime.Forbidden):
            self.service.load_file("/etc/passwd")
        with self.assertRaises(runtime.Forbidden):
            self.service.get_entry(path=FIXTURES["synthetic_elf64"])
        with self.assertRaises(runtime.Forbidden):
            self.service.get_hex_slice(path="/etc/passwd")
        self.assertIsNone(self.service.active_doc_id)

    def test_no_implicit_document(self) -> None:
        upload(self.router, ELF_BYTES)
        for route in ("/api/hex", "/api/decode", "/api/translate", "/api/disassemble", "/api/search", "/api/parse"):
            resp, payload = call(self.router, "GET", route, {"q": "main"})
            self.assertEqual(resp.status, 400, route)
            self.assertEqual(payload["code"], "bad_request")
        self.assertIsNone(self.service.active_doc_id)

    def test_presets_are_synthetic_only_and_hide_server_paths(self) -> None:
        resp, payload = call(self.router, "GET", "/api/presets")
        presets = payload["presets"]
        self.assertEqual(len(presets), 6)
        for preset in presets:
            self.assertNotIn("path", preset)
            self.assertTrue(preset["id"].startswith("synthetic_"))
            self.assertEqual(preset["doc"], "preset:" + preset["id"])
            self.assertIn(preset["format"], ("MACHO", "ELF", "PE"))
            for key in ("label", "description", "exists"):
                self.assertIn(key, preset)
        self.assertNotIn(WORKSPACE_ROOT.encode(), resp.body)

        for preset in presets:
            resp, doc = call(self.router, "GET", "/api/parse", {"doc": preset["doc"]})
            self.assertEqual(resp.status, 200, preset["id"])
            self.assertEqual(doc["doc_id"], preset["doc"])
            self.assertNotIn(WORKSPACE_ROOT.encode(), resp.body, preset["id"])
            self.assertNotIn(b"/fixtures/", resp.body, preset["id"])

        for doc in ("preset:bin_ls", "preset:usr_bin_true", "preset:nope"):
            resp, payload = call(self.router, "GET", "/api/parse", {"doc": doc})
            self.assertEqual((resp.status, payload["code"]), (404, "not_found"), doc)

    def test_uploads_are_isolated_by_unguessable_id(self) -> None:
        resp_a, doc_a = upload(self.router, ELF_BYTES, "alice.elf", client="198.51.100.1")
        resp_b, doc_b = upload(self.router, PE_BYTES, "bob.exe", client="198.51.100.2")
        self.assertEqual((resp_a.status, resp_b.status), (200, 200))
        id_a, id_b = doc_a["doc_id"], doc_b["doc_id"]
        self.assertRegex(id_a, r"^u_[0-9a-f]{32}$")
        self.assertRegex(id_b, r"^u_[0-9a-f]{32}$")
        self.assertNotEqual(id_a, id_b)

        # Each id reaches exactly its own bytes, whoever asks and in whatever order.
        for client in ("198.51.100.1", "198.51.100.2"):
            _, hex_a = call(self.router, "GET", "/api/hex", {"doc": id_a, "length": "16"}, client=client)
            _, hex_b = call(self.router, "GET", "/api/hex", {"doc": id_b, "length": "16"}, client=client)
            self.assertEqual(hex_a["hex_bytes"], ELF_BYTES[:16].hex())
            self.assertEqual(hex_b["hex_bytes"], PE_BYTES[:16].hex())
        _, parsed = call(self.router, "GET", "/api/parse", {"doc": id_a})
        self.assertEqual(parsed["file_info"]["filename"], "alice.elf")

        # Bob uploading did not change what Alice's requests mean, and without an id there is nothing.
        resp, payload = call(self.router, "GET", "/api/hex", {"length": "16"}, client="198.51.100.1")
        self.assertEqual(resp.status, 400)

        # The same bytes uploaded twice get two unrelated ids.
        _, again = upload(self.router, ELF_BYTES, "alice.elf")
        self.assertNotEqual(again["doc_id"], id_a)

        # Ids are not enumerable: a near miss is indistinguishable from an expired document.
        near = id_a[:-1] + ("0" if id_a[-1] != "0" else "1")
        resp, payload = call(self.router, "GET", "/api/hex", {"doc": near})
        self.assertEqual((resp.status, payload["code"]), (410, "doc_expired"))

    def test_upload_filename_is_untrusted(self) -> None:
        nasty = "..%2F..%2Fetc%2Fpasswd%0D%0AX-Injected%3A%201%00%E2%80%AEexe.fdp"
        resp, doc = upload(self.router, ELF_BYTES, nasty)
        self.assertEqual(resp.status, 200)
        name = doc["file_info"]["filename"]
        for bad in ("/", "\\", "\r", "\n", "\x00", "\u202e", ".."):
            self.assertNotIn(bad, name)
        self.assertLessEqual(len(name), 120)
        resp, doc = upload(self.router, ELF_BYTES, "A" * 5000)
        self.assertLessEqual(len(doc["file_info"]["filename"]), 120)

    def test_oversize_upload_is_rejected(self) -> None:
        router, service, _ = make_router(public_config(max_upload_bytes=4096))
        # ... from the declared length alone, before any body exists:
        early = router.preflight("POST", "/api/upload", {"content-type": "application/octet-stream"},
                                 "203.0.113.9", 4097)
        self.assertIsNotNone(early)
        self.assertEqual(early.status, 413)
        self.assertEqual(json.loads(early.body)["code"], "too_large")
        self.assertIsNone(router.preflight("POST", "/api/upload", {"content-type": "application/octet-stream"},
                                           "203.0.113.9", 4096))
        # ... and again on the real size, should a transport lie about it:
        resp, payload = upload(router, b"\x7fELF" + b"\x00" * 5000)
        self.assertEqual((resp.status, payload["code"]), (413, "too_large"))
        self.assertEqual(len(service.store), 0)
        # ... and the service enforces it for callers that skip the router.
        with self.assertRaises(runtime.TooLarge):
            service.add_upload("x", b"\x00" * 4097)
        # JSON bodies have their own, much smaller, bound.
        early = router.preflight("POST", "/api/parse", {"content-type": "application/json"}, "c",
                                 router.config.max_json_body_bytes + 1)
        self.assertEqual(early.status, 413)

    def test_base64_json_upload_is_refused(self) -> None:
        body = json.dumps({"filename": "x", "data_base64": base64.b64encode(ELF_BYTES).decode()}).encode()
        resp, payload = call(self.router, "POST", "/api/upload", body=body,
                             headers={"Content-Type": "application/json"})
        self.assertEqual(resp.status, 415)
        for ctype in ("application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "text/plain"):
            resp, payload = call(self.router, "POST", "/api/upload", body=ELF_BYTES, headers={"Content-Type": ctype})
            self.assertEqual(resp.status, 415, ctype)

    def test_empty_and_garbage_uploads_fail_cleanly(self) -> None:
        resp, payload = upload(self.router, b"")
        self.assertEqual((resp.status, payload["code"]), (400, "bad_request"))
        for blob in (b"A", b"\x00" * 64, b"not a binary at all, just text" * 10, os.urandom(2048),
                     b"\x7fELF" + b"\xff" * 2048, b"MZ" + b"\xff" * 2048, b"\xcf\xfa\xed\xfe" + b"\xff" * 2048,
                     b"\xca\xfe\xba\xbe" + b"\xff" * 2048):
            resp, payload = upload(self.router, blob)
            self.assertIn(resp.status, (200, 422), (resp.status, resp.body[:200]))
            self.assertNotIn(b"Traceback", resp.body)
            self.assertNotIn(WORKSPACE_ROOT.encode(), resp.body)
            if resp.status != 200:
                self.assertEqual(payload["code"], "parse_failed")
                self.assertEqual(sorted(payload.keys()), ["code", "error"])

    def test_garbage_parameters_never_reach_a_500(self) -> None:
        _, doc = upload(self.router, ELF_BYTES)
        doc_id = doc["doc_id"]
        cases = [
            ("/api/hex", {"offset": "-1", "length": "-5"}),
            ("/api/hex", {"offset": "9" * 30, "length": "1e9"}),
            ("/api/hex", {"offset": "0x" + "f" * 500}),
            ("/api/hex", {"slice_index": "999999"}),
            ("/api/decode", {"offset": "zzz", "endian": "\x00"}),
            ("/api/decode", {"offset": str(len(ELF_BYTES) + 10)}),
            ("/api/disassemble", {"count": "99999999", "vmaddr": "0xzz"}),
            ("/api/disassemble", {"vmaddr": "-1", "section": "\udcff"}),
            ("/api/search", {"q": "\x00\n", "scope": "zzz"}),
            ("/api/search", {"q": "ff" * 100}),
            ("/api/translate", {"query": "0x" + "f" * 60}),
            ("/api/translate", {"mode": "evil"}),
            ("/api/translate", {"query": ""}),
        ]
        for route, query in cases:
            resp, payload = call(self.router, "GET", route, dict(query, doc=doc_id))
            self.assertLess(resp.status, 500, (route, query, resp.body[:200]))
            self.assertNotIn(b"Traceback", resp.body)
        resp, payload = call(self.router, "GET", "/api/search", {"doc": doc_id, "q": "A" * 5000})
        self.assertEqual(resp.status, 400)
        for body in (b"{", b"[1,2]", b"\xff\xfe", b"[" * 100000, b'{"doc": ' + b"9" * 200000 + b"}", b"null"):
            resp, payload = call(self.router, "POST", "/api/parse", body=body,
                                 headers={"Content-Type": "application/json"})
            self.assertEqual(resp.status, 400, body[:20])
            self.assertEqual(payload["code"], "bad_request")

    def test_unknown_routes_and_methods(self) -> None:
        resp, payload = call(self.router, "GET", "/api/nope")
        self.assertEqual((resp.status, payload["code"]), (404, "not_found"))
        resp, payload = call(self.router, "DELETE", "/api/config")
        self.assertEqual(resp.status, 405)
        self.assertIn("GET", resp.headers.get("Allow", ""))
        resp, payload = call(self.router, "GET", "/api/upload")
        self.assertEqual(resp.status, 405)

    def test_handle_never_raises(self) -> None:
        class Hostile:
            method = "GET"
            route = "/api/config"
            headers = None
            body = None
            client_id = None

            @property
            def query(self):
                raise RuntimeError("boom")

        resp = self.router.handle(Hostile())  # type: ignore[arg-type]
        self.assertGreaterEqual(resp.status, 400)
        resp = self.router.handle(None)  # type: ignore[arg-type]
        self.assertEqual(resp.status, 500)
        self.assertNotIn(b"Traceback", resp.body)

    def test_security_headers_on_every_router_response(self) -> None:
        responses = [
            call(self.router, "GET", "/api/config")[0],
            call(self.router, "GET", "/api/nope")[0],
            call(self.router, "GET", "/api/hex")[0],
            call(self.router, "GET", "/api/hex", {"path": "/etc/passwd"})[0],
            call(self.router, "PUT", "/api/config")[0],
            upload(self.router, b"junk")[0],
            self.router.handle(None),  # type: ignore[arg-type]
        ]
        for resp in responses:
            lowered = {k.lower(): v for k, v in resp.headers.items()}
            for name in SECURITY_HEADERS:
                self.assertIn(name, lowered, (resp.status, name))
            self.assertEqual(lowered["x-content-type-options"], "nosniff")
            self.assertEqual(lowered["cache-control"], "no-store")
            self.assertIn("default-src 'none'", lowered["content-security-policy"])
            self.assertNotIn("access-control-allow-origin", lowered)

    def test_external_tools_are_off_inside_handlers(self) -> None:
        seen = {}

        def probe(req):
            cfg = runtime.get_config()
            seen["mode"] = cfg.mode
            seen["tools"] = cfg.allow_external_tools
            return {"ok": True}

        self.router.register("GET", "/api/_probe", probe)
        call(self.router, "GET", "/api/_probe")
        self.assertEqual(seen, {"mode": "public", "tools": False})
        # ... and the scope ends with the request: the process default is untouched.
        self.assertEqual(runtime.get_config().mode, "local")
        # No uploaded or preset document carries a path an external tool could be pointed at.
        _, doc = upload(self.router, ELF_BYTES)
        self.assertIsNone(self.service.get_entry(doc=doc["doc_id"]).disk_path)
        self.assertIsNone(self.service.get_entry(doc="preset:synthetic_elf64").disk_path)

    def test_no_subprocess_is_ever_started_for_a_request(self) -> None:
        # Uploaded bytes must never be handed to objdump, c++filt, otool or anything else.
        calls = []
        real_run, real_popen = subprocess.run, subprocess.Popen

        def refuse(*args, **kwargs):
            calls.append(args[0] if args else kwargs.get("args"))
            raise AssertionError("subprocess started in public mode")

        subprocess.run = refuse
        subprocess.Popen = refuse  # type: ignore[misc,assignment]
        try:
            router, service, _ = make_router()
            with open(FIXTURES["synthetic_universal"], "rb") as f:
                universal = f.read()                      # C++ symbols: the local-mode demangler shells out
            for blob in (universal, ELF_BYTES, PE_BYTES):  # x86 code: the local-mode disassembler shells out
                resp, doc = upload(router, blob)
                self.assertEqual(resp.status, 200)
                for index in range(len(doc["slices"])):
                    resp, dis = call(router, "GET", "/api/disassemble",
                                     {"doc": doc["doc_id"], "slice_index": str(index), "count": "32"})
                    self.assertEqual(resp.status, 200)
            for preset in service.get_presets():
                resp, _ = call(router, "GET", "/api/disassemble", {"doc": preset["doc"]})
                self.assertEqual(resp.status, 200)
        finally:
            subprocess.run, subprocess.Popen = real_run, real_popen  # type: ignore[misc]
        self.assertEqual(calls, [])

    def test_restricted_modes_cannot_be_loosened_by_options(self) -> None:
        for mode in ("public", "wasm"):
            cfg = RuntimeConfig(mode, allow_path_load=True, allow_host_presets=True, allow_external_tools=True,
                                debug_errors=True)
            self.assertFalse(cfg.allow_path_load)
            self.assertFalse(cfg.allow_host_presets)
            self.assertFalse(cfg.allow_external_tools)
            self.assertFalse(cfg.debug_errors)


class RouterExtensionTests(unittest.TestCase):
    """What later waves rely on: register(), binary responses, prefix routes, error types."""

    def setUp(self) -> None:
        self.router, self.service, self.log_stream = None, None, io.StringIO()
        config = public_config()
        self.service = AnalysisService(WORKSPACE_ROOT, config)
        self.router = build_router(self.service, config, log=EventLog(stream=self.log_stream))

    def test_register_and_binary_download(self) -> None:
        _, doc = upload(self.router, ELF_BYTES, "sample.elf")

        def download(req):
            entry = self.service.get_entry(doc=req.query.get("doc"))
            return ApiResponse.binary(entry.data, entry.filename)

        self.router.register("GET", "/api/download", download)
        resp, _ = call(self.router, "GET", "/api/download", {"doc": doc["doc_id"]})
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, ELF_BYTES)
        self.assertEqual(resp.content_type, "application/octet-stream")
        self.assertIn("attachment", resp.headers["Content-Disposition"])
        self.assertIn("sample.elf", resp.headers["Content-Disposition"])
        self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")
        resp, payload = call(self.router, "GET", "/api/download", {"doc": "u_" + "0" * 32})
        self.assertEqual((resp.status, payload["code"]), (410, "doc_expired"))

    def test_binary_filename_cannot_inject_headers(self) -> None:
        resp = ApiResponse.binary(b"x", 'evil"\r\nSet-Cookie: a=b\r\n\r\n<script>.bin')
        value = resp.headers["Content-Disposition"]
        self.assertNotIn("\r", value)
        self.assertNotIn("\n", value)
        self.assertEqual(value.count('"'), 2)
        self.assertTrue(value.startswith("attachment; filename="))

    def test_prefix_routes_and_api_errors(self) -> None:
        def learn(req):
            if req.route.endswith("/missing"):
                raise runtime.NotFound("No such lesson.")
            return {"route": req.route}

        self.router.register("GET", "/api/learn/*", learn)
        resp, payload = call(self.router, "GET", "/api/learn/elf/relro")
        self.assertEqual(payload, {"route": "/api/learn/elf/relro"})
        resp, payload = call(self.router, "GET", "/api/learn/missing")
        self.assertEqual((resp.status, payload), (404, {"error": "No such lesson.", "code": "not_found"}))
        resp, payload = call(self.router, "POST", "/api/learn/x")
        self.assertEqual(resp.status, 405)

    def test_derived_documents_get_p_ids(self) -> None:
        entry = self.service.add_derived("patched.elf", ELF_BYTES)
        self.assertRegex(entry.doc_id, r"^p_[0-9a-f]{32}$")
        resp, payload = call(self.router, "GET", "/api/hex", {"doc": entry.doc_id, "length": "16"})
        self.assertEqual(payload["hex_bytes"], ELF_BYTES[:16].hex())

    def test_internal_errors_do_not_leak(self) -> None:
        secret = "s3cret-internal-detail /srv/app/private.key"

        def broken(req):
            raise RuntimeError(secret)

        self.router.register("GET", "/api/_broken", broken)
        resp, payload = call(self.router, "GET", "/api/_broken")
        self.assertEqual(resp.status, 500)
        self.assertEqual(payload["code"], "internal")
        self.assertEqual(sorted(payload.keys()), ["code", "error"])
        for needle in (b"Traceback", b"RuntimeError", secret.encode(), b"test_api_security", b'File "', b"trace"):
            self.assertNotIn(needle, resp.body)
        # The server's own log still records where it happened — without the exception text.
        logged = self.log_stream.getvalue()
        record = json.loads(logged.strip().splitlines()[-1])
        self.assertEqual(record["event"], "internal_error")
        self.assertEqual(record["exc"], "RuntimeError")
        self.assertNotIn(secret, logged)
        self.assertIn(record["ref"], payload["error"])

    def test_tracebacks_only_in_local_debug_mode(self) -> None:
        def broken(req):
            raise RuntimeError("kaboom")

        for config, expect_trace in ((RuntimeConfig("local"), False), (RuntimeConfig("local", debug_errors=True), True)):
            service = AnalysisService(WORKSPACE_ROOT, config)
            router = build_router(service, config, log=EventLog(stream=io.StringIO()))
            router.register("GET", "/api/_broken", broken)
            resp, payload = call(router, "GET", "/api/_broken")
            self.assertEqual(resp.status, 500)
            self.assertEqual("trace" in payload, expect_trace)
            self.assertEqual(b"Traceback" in resp.body, expect_trace)

    def test_plain_value_errors_are_generic_in_public_mode(self) -> None:
        def picky(req):
            raise ValueError("could not open /srv/app/data.db")

        self.router.register("GET", "/api/_picky", picky)
        resp, payload = call(self.router, "GET", "/api/_picky")
        self.assertEqual((resp.status, payload["code"]), (400, "bad_request"))
        self.assertNotIn(b"/srv/app", resp.body)


class ParseBudgetTests(unittest.TestCase):
    """CPU and concurrency bounds on analysis."""

    def setUp(self) -> None:
        self._real_parse = service_module.parse_macho_bytes

    def tearDown(self) -> None:
        service_module.parse_macho_bytes = self._real_parse

    def test_runaway_parse_hits_the_deadline(self) -> None:
        def spin(data, path="<memory>"):
            while True:
                runtime.check_deadline()

        service_module.parse_macho_bytes = spin
        router, service, _ = make_router(public_config(parse_timeout_seconds=0.2))
        started = time.monotonic()
        resp, payload = upload(router, ELF_BYTES)
        elapsed = time.monotonic() - started
        self.assertEqual((resp.status, payload["code"]), (422, "timeout"))
        self.assertLess(elapsed, 5.0)
        self.assertNotIn(b"Traceback", resp.body)
        # The slot is released and nothing was cached.
        self.assertEqual(service.running_parses(), 0)
        self.assertEqual(len(service.store), 0)
        service_module.parse_macho_bytes = self._real_parse
        resp, payload = upload(router, ELF_BYTES)
        self.assertEqual(resp.status, 200)

    def test_concurrent_parses_are_capped_not_queued(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        real = self._real_parse

        def slow(data, path="<memory>"):
            entered.set()
            release.wait(10)
            return real(data, path=path)

        service_module.parse_macho_bytes = slow
        router, service, _ = make_router(public_config(max_concurrent_parses=1, parse_queue_seconds=0.05))
        results = []
        worker = threading.Thread(target=lambda: results.append(upload(router, ELF_BYTES)))
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            self.assertEqual(service.running_parses(), 1)
            self.assertGreater(service.oldest_parse_age(), 0.0)
            started = time.monotonic()
            resp, payload = upload(router, PE_BYTES)
            self.assertEqual((resp.status, payload["code"]), (503, "busy"))
            self.assertIn("Retry-After", resp.headers)
            self.assertLess(time.monotonic() - started, 2.0)
            # Reading documents that are already loaded is not blocked by a busy parser.
            resp, _ = call(router, "GET", "/api/config")
            self.assertEqual(resp.status, 200)
        finally:
            release.set()
            worker.join(10)
        self.assertEqual(results[0][0].status, 200)
        self.assertEqual(service.running_parses(), 0)

    def test_oversized_analysis_result_is_refused(self) -> None:
        router, service, _ = make_router(public_config(max_document_bytes=1024))
        resp, payload = upload(router, ELF_BYTES)
        self.assertEqual((resp.status, payload["code"]), (413, "too_large"))
        self.assertEqual(len(service.store), 0)


# =============================================================================
# Document store
# =============================================================================
class DocumentStoreTests(unittest.TestCase):
    @staticmethod
    def entry(doc_id: str, cost: int) -> DocEntry:
        return DocEntry(doc_id, "upload", {"doc_id": doc_id}, b"", "f", cost=cost)

    def test_bounded_by_count(self) -> None:
        store = DocumentStore(max_docs=3, max_bytes=0, ttl_seconds=0)
        for i in range(10):
            store.put(self.entry("u_%d" % i, 10))
        self.assertEqual(len(store), 3)
        self.assertIsNone(store.get("u_0"))
        self.assertIsNotNone(store.get("u_9"))
        self.assertEqual(store.stats()["evictions"], 7)

    def test_bounded_by_bytes_and_lru_order(self) -> None:
        store = DocumentStore(max_docs=100, max_bytes=100, ttl_seconds=0)
        store.put(self.entry("a", 40))
        store.put(self.entry("b", 40))
        self.assertIsNotNone(store.get("a"))      # touch a: b is now least recently used
        store.put(self.entry("c", 40))
        self.assertIsNone(store.get("b"))
        self.assertIsNotNone(store.get("a"))
        self.assertIsNotNone(store.get("c"))
        self.assertLessEqual(store.stats()["bytes"], 100)
        # One entry larger than the whole budget is kept alone rather than looping forever.
        store.put(self.entry("huge", 1000))
        self.assertEqual(len(store), 1)
        self.assertIsNotNone(store.get("huge"))

    def test_idle_ttl(self) -> None:
        clock = FakeClock()
        store = DocumentStore(max_docs=10, max_bytes=0, ttl_seconds=60, clock=clock)
        store.put(self.entry("a", 1))
        store.put(self.entry("b", 1))
        clock.advance(50)
        self.assertIsNotNone(store.get("a"))      # use keeps a alive
        clock.advance(50)
        self.assertIsNotNone(store.get("a"))
        self.assertIsNone(store.get("b"))         # b sat idle for 100s
        clock.advance(61)
        self.assertEqual(store.sweep(), 1)
        self.assertEqual(len(store), 0)

    def test_pinned_entries_outlive_everything(self) -> None:
        clock = FakeClock()
        store = DocumentStore(max_docs=1, max_bytes=1, ttl_seconds=10, clock=clock)
        store.put(self.entry("preset:x", 5), pinned=True)
        for i in range(5):
            store.put(self.entry("u_%d" % i, 5))
        clock.advance(1000)
        store.sweep()
        self.assertIsNotNone(store.get("preset:x"))

    def test_thread_safety(self) -> None:
        store = DocumentStore(max_docs=50, max_bytes=5000, ttl_seconds=0)
        errors = []

        def work(seed: int) -> None:
            try:
                for i in range(400):
                    key = "u_%d" % ((seed * 31 + i) % 120)
                    store.put(self.entry(key, 10 + i % 90))
                    store.get("u_%d" % (i % 120))
                    if i % 50 == 0:
                        store.sweep()
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        stats = store.stats()
        self.assertLessEqual(stats["docs"], 50)
        self.assertLessEqual(stats["bytes"], 5000)
        self.assertGreaterEqual(stats["bytes"], 0)

    def test_expired_document_gives_410_through_the_api(self) -> None:
        clock = FakeClock()
        router, service, _ = make_router(public_config(doc_ttl_seconds=600), clock=clock)
        _, doc = upload(router, ELF_BYTES)
        doc_id = doc["doc_id"]
        clock.advance(599)
        resp, _ = call(router, "GET", "/api/hex", {"doc": doc_id})
        self.assertEqual(resp.status, 200)
        clock.advance(601)
        for route in ("/api/hex", "/api/parse", "/api/decode", "/api/search", "/api/disassemble", "/api/translate"):
            resp, payload = call(router, "GET", route, {"doc": doc_id, "q": "x"})
            self.assertEqual((resp.status, payload["code"]), (410, "doc_expired"), route)
        # Presets never expire.
        resp, _ = call(router, "GET", "/api/hex", {"doc": "preset:synthetic_elf64"})
        self.assertEqual(resp.status, 200)
        # Housekeeping drops expired bytes even if nobody asks for them again.
        _, doc = upload(router, ELF_BYTES)
        self.assertEqual(service.store.stats()["docs"], 1)
        clock.advance(601)
        router.housekeeping()
        self.assertEqual(service.store.stats()["docs"], 0)

    def test_evicted_document_gives_410_through_the_api(self) -> None:
        router, service, _ = make_router(public_config(cache_max_docs=2, cache_client_share=0))
        ids = [upload(router, ELF_BYTES)[1]["doc_id"] for _ in range(4)]
        statuses = [call(router, "GET", "/api/hex", {"doc": d})[0].status for d in ids]
        self.assertEqual(statuses, [410, 410, 200, 200])
        self.assertEqual(service.store.stats()["docs"], 2)

    def test_one_client_cannot_evict_everyone_else(self) -> None:
        router, service, _ = make_router(public_config(cache_max_docs=10, cache_client_share=0.3))
        _, victim = upload(router, PE_BYTES, client="198.51.100.1")
        flood = [upload(router, ELF_BYTES, client="198.51.100.66")[1]["doc_id"] for _ in range(40)]
        # The flooder only ever displaced its own uploads (3 of 10 slots)...
        alive = [d for d in flood if call(router, "GET", "/api/hex", {"doc": d})[0].status == 200]
        self.assertEqual(alive, flood[-3:])
        # ... and the other visitor's document is still there.
        resp, payload = call(router, "GET", "/api/hex", {"doc": victim["doc_id"], "length": "16"})
        self.assertEqual(resp.status, 200)
        self.assertEqual(payload["hex_bytes"], PE_BYTES[:16].hex())
        # The same holds for the byte budget.
        store = DocumentStore(max_docs=100, max_bytes=1000, ttl_seconds=0, client_share=0.3)
        store.put(DocEntry("victim", "upload", {}, b"", "f", cost=200, owner="a"))
        for i in range(50):
            store.put(DocEntry("flood%d" % i, "upload", {}, b"", "f", cost=120, owner="b"))
        self.assertIsNotNone(store.get("victim"))
        self.assertLessEqual(sum(1 for i in range(50) if store.get("flood%d" % i)), 2)

    def test_cache_cost_accounts_for_parsed_size(self) -> None:
        router, service, _ = make_router()
        _, doc = upload(router, ELF_BYTES)
        entry = service.get_entry(doc=doc["doc_id"])
        self.assertGreater(entry.cost, len(ELF_BYTES) + len(json.dumps(entry.doc)))


# =============================================================================
# Rate limiting
# =============================================================================
class RateLimitTests(unittest.TestCase):
    def test_token_bucket(self) -> None:
        clock = FakeClock()
        limiter = TokenBucketLimiter(60, burst=5, clock=clock)
        self.assertEqual([limiter.allow("a")[0] for _ in range(7)], [True] * 5 + [False] * 2)
        allowed, retry = limiter.allow("a")
        self.assertFalse(allowed)
        self.assertAlmostEqual(retry, 1.0, places=3)
        self.assertTrue(limiter.allow("b")[0])        # another client is unaffected
        clock.advance(2.0)                            # 1 token per second
        self.assertEqual([limiter.allow("a")[0] for _ in range(3)], [True, True, False])
        clock.advance(3600)
        self.assertEqual(sum(limiter.allow("a")[0] for _ in range(20)), 5)   # never more than the burst

    def test_memory_is_bounded(self) -> None:
        clock = FakeClock()
        limiter = TokenBucketLimiter(60, burst=5, max_keys=100, clock=clock)
        for i in range(10000):
            limiter.allow("client-%d" % i)
        self.assertEqual(len(limiter), 100)
        clock.advance(600)
        self.assertEqual(limiter.prune(), 100)
        self.assertEqual(len(limiter), 0)

    def test_disabled_limiter(self) -> None:
        limiter = TokenBucketLimiter(0)
        self.assertTrue(all(limiter.allow("a")[0] for _ in range(1000)))
        self.assertEqual(len(limiter), 0)

    def test_router_rate_limits_per_client(self) -> None:
        clock = FakeClock()
        router, _, _ = make_router(public_config(rate_limit_per_minute=60, rate_limit_burst=10), clock=clock)
        statuses = [call(router, "GET", "/api/config", client="198.51.100.5")[0].status for _ in range(15)]
        self.assertEqual(statuses, [200] * 10 + [429] * 5)
        resp, payload = call(router, "GET", "/api/config", client="198.51.100.5")
        self.assertEqual((resp.status, payload["code"]), (429, "rate_limited"))
        self.assertGreaterEqual(int(resp.headers["Retry-After"]), 1)
        # Unknown routes are charged too, so probing is not free.
        resp, _ = call(router, "GET", "/api/nope", client="198.51.100.5")
        self.assertEqual(resp.status, 429)
        resp, _ = call(router, "GET", "/api/config", client="198.51.100.6")
        self.assertEqual(resp.status, 200)
        clock.advance(5)
        statuses = [call(router, "GET", "/api/config", client="198.51.100.5")[0].status for _ in range(7)]
        self.assertEqual(statuses, [200] * 5 + [429] * 2)

    def test_uploads_have_a_stricter_limit(self) -> None:
        clock = FakeClock()
        router, service, _ = make_router(public_config(upload_rate_limit_per_minute=6, upload_rate_limit_burst=2),
                                         clock=clock)
        statuses = [upload(router, ELF_BYTES, client="198.51.100.5")[0].status for _ in range(4)]
        self.assertEqual(statuses, [200, 200, 429, 429])
        self.assertEqual(service.store.stats()["docs"], 2)
        # The limit is decided before the body is read.
        early = router.preflight("POST", "/api/upload", {"content-type": "application/octet-stream"},
                                 "198.51.100.5", len(ELF_BYTES))
        self.assertEqual(early.status, 429)
        # Ordinary requests from the same client still work.
        resp, _ = call(router, "GET", "/api/config", client="198.51.100.5")
        self.assertEqual(resp.status, 200)
        clock.advance(10)
        self.assertEqual(upload(router, ELF_BYTES, client="198.51.100.5")[0].status, 200)

    def test_ipv6_clients_are_limited_per_64(self) -> None:
        self.assertEqual(client_key("2001:db8:aa:bb:1:2:3:4"), client_key("2001:db8:aa:bb:ffff:ffff:ffff:ffff"))
        self.assertNotEqual(client_key("2001:db8:aa:bb::1"), client_key("2001:db8:aa:bc::1"))
        self.assertEqual(client_key("::ffff:192.0.2.9"), "192.0.2.9")
        self.assertEqual(client_key("192.0.2.9"), "192.0.2.9")
        self.assertEqual(client_key("not an address\r\n"), "invalid")

    def test_forwarded_for_is_only_trusted_when_configured(self) -> None:
        plain = RuntimeConfig("public")
        proxied = RuntimeConfig("public", trust_proxy_headers=True)
        spoof = {"x-forwarded-for": "1.1.1.1"}
        # Not configured: the header is ignored, so it cannot be used to dodge the limiter.
        self.assertEqual(resolve_client_address("203.0.113.50", spoof, plain), "203.0.113.50")
        self.assertEqual(resolve_client_address("127.0.0.1", spoof, plain), "127.0.0.1")
        # Configured: the entry appended by the proxy (the last one) counts, not what the client sent.
        chain = {"x-forwarded-for": "6.6.6.6, 198.51.100.77"}
        self.assertEqual(resolve_client_address("127.0.0.1", chain, proxied), "198.51.100.77")
        self.assertEqual(resolve_client_address("10.0.0.2", chain, proxied), "198.51.100.77")
        self.assertEqual(resolve_client_address("::ffff:127.0.0.1", chain, proxied), "198.51.100.77")
        # ... and only from a peer that can be the proxy: a direct public client is not believed.
        for direct in ("8.8.8.8", "203.0.113.50", "2001:4860:4860::8888"):
            self.assertEqual(resolve_client_address(direct, chain, proxied), direct)
        for internal in ("172.17.0.1", "192.168.0.2", "100.64.0.9", "::1", "fd00::2"):
            self.assertEqual(resolve_client_address(internal, chain, proxied), "198.51.100.77")
        for junk in ("", "garbage", "1.1.1.1, <script>", "999.1.1.1"):
            self.assertEqual(resolve_client_address("127.0.0.1", {"x-forwarded-for": junk}, proxied), "127.0.0.1")


# =============================================================================
# Pure HTTP checks
# =============================================================================
class CrossSiteCheckTests(unittest.TestCase):
    def test_host_allowlist(self) -> None:
        local = allowed_host_names(RuntimeConfig("local"), "127.0.0.1")
        for good in ("127.0.0.1", "127.0.0.1:8421", "localhost:8421", "LOCALHOST", "[::1]:8421", "localhost."):
            self.assertTrue(host_allowed(good, local), good)
        for bad in (None, "", "evil.example", "evil.example:8421", "127.0.0.1.evil.example", "localhost.evil.example",
                    "evil-localhost", "127.0.0.1:8421@evil.example", "127.0.0.1:evil", "[::1", "::1",
                    "0.0.0.0", "192.168.1.10", "127.0.0.1, evil.example", "evil.example\r\nHost: localhost"):
            self.assertFalse(host_allowed(bad, local), bad)

        # A wildcard bind adds nothing; a specific one adds itself.
        self.assertFalse(host_allowed("192.168.1.10", allowed_host_names(RuntimeConfig("public"), "0.0.0.0")))
        self.assertTrue(host_allowed("192.168.1.10:80", allowed_host_names(RuntimeConfig("public"), "192.168.1.10")))

        cfg = RuntimeConfig("public", allowed_hosts=["Studio.Example.com", ".example.org"])
        names = allowed_host_names(cfg, "0.0.0.0")
        for good in ("studio.example.com", "studio.example.com:443", "example.org", "a.b.example.org", "localhost"):
            self.assertTrue(host_allowed(good, names), good)
        for bad in ("example.com", "evilstudio.example.com", "studio.example.com.evil.net", "badexample.org"):
            self.assertFalse(host_allowed(bad, names), bad)
        self.assertTrue(host_allowed("anything.at.all", allowed_host_names(RuntimeConfig("public", allowed_hosts=["*"]))))

    def test_cross_site_requests_are_detected(self) -> None:
        host = {"host": "127.0.0.1:8421"}
        ok = [
            {},                                                               # curl, scripts
            {"sec-fetch-site": "same-origin"},
            {"sec-fetch-site": "none"},                                       # typed into the address bar
            {"origin": "http://127.0.0.1:8421"},
            {"origin": "http://127.0.0.1:8421", "sec-fetch-site": "same-origin"},
        ]
        for headers in ok:
            self.assertIsNone(cross_site_reason(dict(host, **headers)), headers)
        refused = [
            {"sec-fetch-site": "cross-site"},
            {"sec-fetch-site": "same-site"},                                  # another port on localhost
            {"sec-fetch-site": "CROSS-SITE"},
            {"sec-fetch-site": "weird"},
            {"origin": "https://evil.example"},
            {"origin": "http://evil.example:8421"},
            {"origin": "http://localhost:8421"},                              # same machine, different origin
            {"origin": "http://127.0.0.1:9999"},
            {"origin": "http://127.0.0.1"},
            {"origin": "null"},                                               # sandboxed frame, file://
            {"origin": ""},
            {"origin": "file://"},
            {"origin": "http://127.0.0.1:8421.evil.example"},
            {"origin": "http://127.0.0.1:8421@evil.example"},
            {"origin": "http://evil.example", "sec-fetch-site": "same-origin"},
        ]
        for headers in refused:
            self.assertIsNotNone(cross_site_reason(dict(host, **headers)), headers)
        # Behind a TLS proxy the Host carries no port and the Origin is https.
        proxied = {"host": "studio.example.com", "origin": "https://studio.example.com"}
        self.assertIsNone(cross_site_reason(proxied))
        self.assertIsNotNone(cross_site_reason(dict(proxied, origin="https://studio.example.com:8443")))
        self.assertIsNotNone(cross_site_reason({"origin": "http://127.0.0.1:8421"}))   # no Host at all

    def test_csp_defaults_and_configuration(self) -> None:
        csp = RuntimeConfig("public").content_security_policy()
        for directive in ("default-src 'none'", "script-src 'self'", "style-src 'self'",
                          "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'",
                          "connect-src 'self'", "img-src 'self' data:", "worker-src 'self'"):
            self.assertIn(directive, csp.split("; "), directive)
        self.assertNotIn("unsafe-eval", csp)
        script = [d for d in csp.split("; ") if d.startswith("script-src")][0]
        self.assertEqual(script, "script-src 'self'")          # no inline script, no eval

        # A later wave can widen it without touching code.
        cfg = RuntimeConfig.from_env("public", {
            "BINARYSTUDIO_CSP_EXTRA": "script-src 'wasm-unsafe-eval' https://ads.example; frame-src https://ads.example; "
                                      "object-src https://plugins.example",
        })
        csp = cfg.content_security_policy().split("; ")
        self.assertIn("script-src 'self' 'wasm-unsafe-eval' https://ads.example", csp)
        self.assertIn("frame-src https://ads.example", csp)
        self.assertIn("object-src https://plugins.example", csp)   # 'none' is replaced, not combined
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(RuntimeConfig("public", csp="default-src 'self'").content_security_policy(), "default-src 'self'")
        # Header injection through configuration is refused at startup.
        for bad in ("script-src 'self'\r\nSet-Cookie: x=1", "script-src https://a.example,https://b.example"):
            with self.assertRaises(ValueError):
                RuntimeConfig("public", csp_extra=bad)
        with self.assertRaises(ValueError):
            RuntimeConfig("public", csp="default-src 'self'\nX: y")

        page = security_headers(RuntimeConfig("public"), "page")
        api = security_headers(RuntimeConfig("public"), "api")
        self.assertIn("script-src 'self'", page["Content-Security-Policy"])
        self.assertIn("default-src 'none'", api["Content-Security-Policy"])
        self.assertNotIn("Strict-Transport-Security", page)
        self.assertIn("max-age=600", security_headers(RuntimeConfig("public", hsts_seconds=600))["Strict-Transport-Security"])

    def test_environment_configuration(self) -> None:
        cfg = RuntimeConfig.from_env(environ={
            "BINARYSTUDIO_MODE": "public", "BINARYSTUDIO_MAX_UPLOAD_MB": "8", "BINARYSTUDIO_TRUST_PROXY": "1",
            "BINARYSTUDIO_ALLOWED_HOSTS": "a.example, b.example", "BINARYSTUDIO_RATE_LIMIT": "30",
            "BINARYSTUDIO_DOC_TTL": "120", "BINARYSTUDIO_ADS": '{"enabled": true, "provider": "x", "evil": 1}',
            "BINARYSTUDIO_SOURCE_URL": "https://example.org/src",
        })
        self.assertEqual(cfg.mode, "public")
        self.assertEqual(cfg.max_upload_bytes, 8 * 1024 * 1024)
        self.assertTrue(cfg.trust_proxy_headers)
        self.assertEqual(cfg.allowed_hosts, ["a.example", "b.example"])
        self.assertEqual((cfg.rate_limit_per_minute, cfg.doc_ttl_seconds), (30, 120))
        self.assertEqual(cfg.public_dict()["ads"], {"enabled": True, "provider": "x", "slots": {}, "options": {}})
        self.assertEqual(cfg.public_dict()["links"]["source"], "https://example.org/src")
        # Flags win over the environment; nothing in the environment can loosen a restricted mode.
        cfg = RuntimeConfig.from_env("public", {"BINARYSTUDIO_MAX_UPLOAD_MB": "8"}, max_upload_bytes=1024)
        self.assertEqual(cfg.max_upload_bytes, 1024)
        for bad in ({"BINARYSTUDIO_MAX_UPLOAD_MB": "-1"}, {"BINARYSTUDIO_TRUST_PROXY": "maybe"},
                    {"BINARYSTUDIO_RATE_LIMIT": "lots"}, {"BINARYSTUDIO_ADS": "[]"}, {"BINARYSTUDIO_MODE": "admin"},
                    {"BINARYSTUDIO_SOURCE_URL": "javascript:alert(1)"}):
            with self.assertRaises(ValueError):
                RuntimeConfig.from_env(environ=bad)
        # Public defaults are bounded everywhere.
        cfg = RuntimeConfig("public")
        for attr in ("max_upload_bytes", "cache_max_docs", "cache_max_bytes", "doc_ttl_seconds", "max_concurrent_parses",
                     "rate_limit_per_minute", "upload_rate_limit_per_minute", "parse_timeout_seconds",
                     "max_connections", "request_timeout_seconds", "max_header_bytes", "max_document_bytes"):
            self.assertGreater(getattr(cfg, attr), 0, attr)
        self.assertGreater(cfg.inflight_upload_budget(), 0)

    def test_event_log_cannot_be_forged(self) -> None:
        stream = io.StringIO()
        log = EventLog(stream=stream)
        log.write("info", "request", route='/x\n{"event":"forged"}', filename="a\r\nb\x1b[31m\u2028c", n=3, skip=None)
        log.write("info", "request", route="A" * 5000)
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["event"], "request")
        self.assertEqual(first["route"], '/x\n{"event":"forged"}')
        self.assertNotIn("skip", first)
        self.assertNotIn("\x1b", stream.getvalue())
        self.assertNotIn("\u2028", stream.getvalue())
        self.assertLess(len(json.loads(lines[1])["route"]), 300)
        # Floods are summarised, not written line for line.
        stream.truncate(0)
        for _ in range(1000):
            log.write_throttled("k", 5, "warn", "refused", client="x")
        self.assertLessEqual(len(stream.getvalue().splitlines()), 10)

    def test_document_ids_are_redacted_for_logs(self) -> None:
        self.assertEqual(redact_doc_id("u_" + "a" * 32), "u_*")
        self.assertEqual(redact_doc_id("p_" + "a" * 32), "p_*")
        self.assertEqual(redact_doc_id("path:/home/me/secret.bin"), "path:*")
        self.assertEqual(redact_doc_id("preset:synthetic_elf64"), "preset:synthetic_elf64")
        self.assertEqual(redact_doc_id("preset:../../x\n"), "preset:?")
        self.assertEqual(redact_doc_id("whatever\n"), "?")
        self.assertIsNone(redact_doc_id(None))


class StaticPathTests(unittest.TestCase):
    """Containment of static files, including the cases a `startswith(root)` test gets wrong."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = os.path.realpath(self.tmp.name)
        self.root = os.path.join(base, "static")
        os.makedirs(os.path.join(self.root, "js"))
        os.makedirs(os.path.join(base, "static_private"))      # sibling sharing the prefix
        os.makedirs(os.path.join(base, "secrets"))
        self.write(os.path.join(self.root, "index.html"), "<!doctype html>")
        self.write(os.path.join(self.root, "js", "app.js"), "ok")
        self.write(os.path.join(self.root, "js", "index.html"), "sub")
        self.write(os.path.join(self.root, ".env"), "TOKEN=1")
        self.write(os.path.join(base, "static_private", "key.pem"), "PRIVATE")
        self.write(os.path.join(base, "secrets", "db.txt"), "SECRET")
        self.outside = os.path.join(base, "secrets", "db.txt")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def write(path: str, text: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def test_serves_only_files_inside_the_root(self) -> None:
        index = os.path.join(self.root, "index.html")
        self.assertEqual(resolve_static_path(self.root, "/"), index)
        self.assertEqual(resolve_static_path(self.root, "/index.html"), index)
        self.assertEqual(resolve_static_path(self.root, "/static/index.html"), index)
        self.assertEqual(resolve_static_path(self.root, "/js/app.js"), os.path.join(self.root, "js", "app.js"))
        self.assertEqual(resolve_static_path(self.root, "/js/"), os.path.join(self.root, "js", "index.html"))
        self.assertEqual(resolve_static_path(self.root, "/js/%61pp.js"), os.path.join(self.root, "js", "app.js"))
        self.assertIsNone(resolve_static_path(self.root, "/js"))               # a directory is not a file
        self.assertIsNone(resolve_static_path(self.root, "/missing.js"))

    def test_traversal_variants(self) -> None:
        attacks = [
            "/../secrets/db.txt", "/..%2fsecrets%2fdb.txt", "/%2e%2e/secrets/db.txt", "/%2E%2E%2Fsecrets/db.txt",
            "/js/../../secrets/db.txt", "/js/..%2f..%2fsecrets/db.txt", "/static/../../secrets/db.txt",
            "/..\\secrets\\db.txt", "/..%5csecrets%5cdb.txt", "/%252e%252e/secrets/db.txt",
            "/....//secrets/db.txt", "/..;/secrets/db.txt", "/.%2e/secrets/db.txt", "/%2e./secrets/db.txt",
            "/js/..%00/secrets/db.txt", "/%c0%ae%c0%ae/secrets/db.txt", "/%ff/../secrets/db.txt",
            "//secrets/db.txt", "/static//../secrets/db.txt",
            # sibling directory whose name merely starts with the root's name
            "/../static_private/key.pem", "/..%2fstatic_private%2fkey.pem", "/%2e%2e/static_private/key.pem",
            # hidden files and oddities inside the root
            "/.env", "/static/.env", "/js/.", "/js/..", "/.", "/..", "/C:/x", "/js/app.js%00.png", "/js/app.js/",
            self.outside, "/" + self.outside, "/static" + self.outside, "file://" + self.outside,
        ]
        for url in attacks:
            self.assertIsNone(resolve_static_path(self.root, url), url)

    def test_symlinks_cannot_escape(self) -> None:
        try:
            os.symlink(self.outside, os.path.join(self.root, "leak.txt"))
            os.symlink(os.path.dirname(self.outside), os.path.join(self.root, "leakdir"))
            os.symlink(os.path.join(self.root, "js", "app.js"), os.path.join(self.root, "alias.js"))
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        self.assertIsNone(resolve_static_path(self.root, "/leak.txt"))
        self.assertIsNone(resolve_static_path(self.root, "/leakdir/db.txt"))
        # A link that stays inside the root is fine.
        self.assertEqual(resolve_static_path(self.root, "/alias.js"), os.path.join(self.root, "js", "app.js"))


# =============================================================================
# The real HTTP server
# =============================================================================
class ServerCase(unittest.TestCase):
    config: RuntimeConfig

    @classmethod
    def make_config(cls) -> RuntimeConfig:
        raise NotImplementedError

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = cls.make_config()
        cls.log_stream = io.StringIO()
        cls.server = create_server(WORKSPACE_ROOT, host="127.0.0.1", port=0, config=cls.config,
                                   log=EventLog(stream=cls.log_stream))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(5)

    def request(self, method, path, body=None, headers=None, timeout=15):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        finally:
            conn.close()

    def raw(self, payload: bytes, timeout: float = 5.0) -> bytes:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        try:
            sock.sendall(payload)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    chunks.append(b"<<client timed out waiting>>")
                    break
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            sock.close()

    def upload(self, data: bytes, name: str = "sample.bin", headers=None):
        base = {"Content-Type": "application/octet-stream", "X-Filename": name}
        base.update(headers or {})
        status, hdrs, body = self.request("POST", "/api/upload", data, base)
        return status, hdrs, (json.loads(body) if body else None)

    def log_records(self):
        return [json.loads(line) for line in self.log_stream.getvalue().splitlines() if line.strip()]


class HttpPublicModeTests(ServerCase):
    @classmethod
    def make_config(cls) -> RuntimeConfig:
        return public_config(max_upload_bytes=256 * 1024, request_timeout_seconds=1.0, keepalive_timeout_seconds=1.0,
                             allowed_hosts=["studio.example.com"], max_connections=64, max_connections_per_client=0)

    def test_arbitrary_file_read_over_http(self) -> None:
        for path in ("/api/parse?path=/etc/passwd", "/api/hex?path=/etc/passwd&offset=0&length=4096",
                     "/api/parse?doc=path:/etc/passwd", "/api/decode?path=/etc/hosts", "/api/search?q=root&path=/etc/passwd",
                     "/api/parse?path=%2Fetc%2Fpasswd", "/api/parse?path=..%2F..%2F..%2Fetc%2Fpasswd"):
            status, headers, body = self.request("GET", path)
            self.assertEqual(status, 403, path)
            self.assertEqual(json.loads(body)["code"], "forbidden")
            self.assertNotIn(b"root:", body)
        status, headers, body = self.request("POST", "/api/parse", json.dumps({"path": "/etc/passwd"}),
                                             {"Content-Type": "application/json"})
        self.assertEqual(status, 403)
        # /api/hex with no document used to serve whatever the last visitor loaded.
        status, headers, body = self.request("GET", "/api/hex?offset=0&length=64")
        self.assertEqual(status, 400)

    def test_uploads_are_isolated_over_http(self) -> None:
        status_a, _, doc_a = self.upload(ELF_BYTES, "a.elf")
        status_b, _, doc_b = self.upload(PE_BYTES, "b.exe")
        self.assertEqual((status_a, status_b), (200, 200))
        self.assertNotEqual(doc_a["doc_id"], doc_b["doc_id"])
        _, _, body = self.request("GET", "/api/hex?length=16&doc=" + doc_a["doc_id"])
        self.assertEqual(json.loads(body)["hex_bytes"], ELF_BYTES[:16].hex())
        _, _, body = self.request("GET", "/api/hex?length=16&doc=" + doc_b["doc_id"])
        self.assertEqual(json.loads(body)["hex_bytes"], PE_BYTES[:16].hex())
        status, _, body = self.request("GET", "/api/hex?length=16&doc=u_" + "0" * 32)
        self.assertEqual((status, json.loads(body)["code"]), (410, "doc_expired"))

    def test_oversize_upload_is_refused_before_the_body_is_read(self) -> None:
        head = (b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\n"
                b"Content-Length: 1073741824\r\n\r\n")
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            sock.sendall(head)                       # not one byte of the gigabyte is ever sent
            started = time.monotonic()
            reply = sock.recv(65536)
            self.assertLess(time.monotonic() - started, 0.9)   # sooner than any read timeout
            while b"\r\n\r\n{" not in reply:
                more = sock.recv(65536)
                if not more:
                    break
                reply += more
        finally:
            sock.close()
        self.assertTrue(reply.startswith(b"HTTP/1.1 413"), reply[:60])
        self.assertIn(b"Connection: close", reply)
        self.assertIn(b'"code":"too_large"', reply)
        # "Expect: 100-continue" must not be answered with an invitation to send it.
        reply = self.raw(head.replace(b"\r\n\r\n", b"\r\nExpect: 100-continue\r\n\r\n"))
        self.assertTrue(reply.startswith(b"HTTP/1.1 413"), reply[:60])
        self.assertNotIn(b"100 Continue", reply)
        # One byte over the limit, actually sent.
        status, _, payload = self.upload(b"\x00" * (256 * 1024 + 1))
        self.assertEqual((status, payload["code"]), (413, "too_large"))
        # At the limit the body is read (and then fails to parse, which is fine).
        status, _, payload = self.upload(b"\x00" * (256 * 1024))
        self.assertEqual(status, 422)

    def test_expect_continue_for_an_acceptable_upload(self) -> None:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            sock.sendall(b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\n"
                         b"Expect: 100-continue\r\nConnection: close\r\nContent-Length: %d\r\n\r\n" % len(ELF_BYTES))
            self.assertTrue(sock.recv(4096).startswith(b"HTTP/1.1 100 Continue"))
            sock.sendall(ELF_BYTES)
            reply = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                reply += chunk
        finally:
            sock.close()
        self.assertTrue(reply.startswith(b"HTTP/1.1 200"), reply[:60])

    def test_no_cors_and_cross_origin_requests_refused(self) -> None:
        status, headers, _ = self.request("GET", "/api/config")
        self.assertEqual(status, 200)
        for name in headers:
            self.assertFalse(name.startswith("access-control-"), name)
        status, headers, _ = self.request("OPTIONS", "/api/upload", headers={
            "Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-filename"})
        self.assertIn(status, (204, 403))
        for name in headers:
            self.assertFalse(name.startswith("access-control-"), name)

        for extra in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"},
                      {"Sec-Fetch-Site": "same-site"}, {"Origin": "null"},
                      {"Origin": "http://localhost:%d" % self.port}):
            status, headers, body = self.request("GET", "/api/config", headers=extra)
            self.assertEqual(status, 403, extra)
            self.assertEqual(json.loads(body)["code"], "forbidden")
            status, headers, body = self.upload(ELF_BYTES, headers=extra)
            self.assertEqual(status, 403, extra)
        status, _, _ = self.request("GET", "/api/config", headers={
            "Origin": "http://127.0.0.1:%d" % self.port, "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200)
        # The listener speaks plain HTTP, so an https Origin is another origin even when
        # host and port match. (Behind a TLS proxy the server runs with --trust-proxy and
        # takes the scheme from X-Forwarded-Proto: tests/test_security_regressions.py.)
        status, _, _ = self.request("GET", "/api/config", headers={
            "Host": "studio.example.com", "Origin": "https://studio.example.com", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 403)
        status, _, _ = self.request("GET", "/api/config", headers={
            "Host": "studio.example.com", "Origin": "http://studio.example.com", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200)
        # Bodies an HTML form could send cross-site are never accepted.
        for ctype in ("application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "text/plain"):
            status, _, _ = self.request("POST", "/api/upload", ELF_BYTES, {"Content-Type": ctype})
            self.assertEqual(status, 415, ctype)
        status, _, _ = self.request("POST", "/api/upload", json.dumps({"data_base64": "AAAA"}),
                                    {"Content-Type": "application/json"})
        self.assertEqual(status, 415)

    def test_host_header_allowlist(self) -> None:
        for host in ("evil.example", "evil.example:%d" % self.port, "127.0.0.1.evil.example", "169.254.169.254"):
            for path in ("/", "/api/config", "/static/app.js"):
                status, headers, body = self.request("GET", path, headers={"Host": host})
                self.assertEqual(status, 403, (host, path))
                self.assertNotIn(b"<html", body.lower())
        for host in ("studio.example.com", "localhost:%d" % self.port, "127.0.0.1"):
            status, _, _ = self.request("GET", "/api/config", headers={"Host": host})
            self.assertEqual(status, 200, host)
        reply = self.raw(b"GET /api/config HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.example\r\n\r\n")
        self.assertTrue(reply.startswith(b"HTTP/1.1 403"), reply[:40])
        reply = self.raw(b"GET /api/config HTTP/1.0\r\n\r\n")
        self.assertTrue(reply.startswith(b"HTTP/1.1 403") or reply.startswith(b"HTTP/1.0 403"), reply[:40])
        # The health check is the one thing that answers regardless (orchestrators probe by IP).
        status, _, body = self.request("GET", "/healthz", headers={"Host": "10.0.0.7:8421"})
        self.assertEqual((status, body), (200, b"ok\n"))

    def test_security_headers_on_every_response(self) -> None:
        _, _, doc = self.upload(ELF_BYTES)
        cases = [
            ("GET", "/", {}), ("GET", "/static/app.js", {}), ("GET", "/static/styles.css", {}),
            ("GET", "/missing.html", {}), ("GET", "/api/config", {}), ("GET", "/api/presets", {}),
            ("GET", "/api/hex?doc=" + doc["doc_id"], {}), ("GET", "/api/hex", {}), ("GET", "/api/nope", {}),
            ("GET", "/api/parse?path=/etc/passwd", {}), ("GET", "/api/config", {"Host": "evil.example"}),
            ("GET", "/api/config", {"Origin": "https://evil.example"}), ("DELETE", "/api/config", {}),
            ("PUT", "/", {}), ("OPTIONS", "/api/config", {}), ("GET", "/healthz", {}), ("HEAD", "/", {}),
            ("POST", "/", {}), ("GET", "/..%2f..%2fetc%2fpasswd", {}),
        ]
        for method, path, extra in cases:
            status, headers, _ = self.request(method, path, headers=extra)
            for name in SECURITY_HEADERS:
                self.assertIn(name, headers, (method, path, status, name))
            self.assertEqual(headers["x-content-type-options"], "nosniff")
            self.assertEqual(headers["referrer-policy"], "no-referrer")
            self.assertEqual(headers["cross-origin-opener-policy"], "same-origin")
            self.assertEqual(headers["cross-origin-resource-policy"], "same-origin")
            self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
            self.assertNotIn("Python", headers.get("server", ""))
            self.assertNotIn("access-control-allow-origin", headers)
        # Malformed requests answered by the HTTP layer itself carry them too.
        for payload in (b"NONSENSE\r\n\r\n", b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"):
            reply = self.raw(payload).lower()
            self.assertIn(b"x-content-type-options: nosniff", reply)
            self.assertIn(b"content-security-policy:", reply)

        status, headers, body = self.request("GET", "/")
        csp = headers["content-security-policy"].split("; ")
        for directive in ("default-src 'none'", "script-src 'self'", "style-src 'self'",
                          "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'",
                          "connect-src 'self'", "img-src 'self' data:", "worker-src 'self'"):
            self.assertIn(directive, csp)
        self.assertEqual(headers["cache-control"], "no-cache")
        self.assertIn("text/html", headers["content-type"])

    def test_static_cache_headers(self) -> None:
        status, headers, body = self.request("GET", "/static/app.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", headers["content-type"])
        self.assertRegex(headers["cache-control"], r"^public, max-age=\d+$")
        etag = headers["etag"]
        status, headers2, body2 = self.request("GET", "/static/app.js", headers={"If-None-Match": etag})
        self.assertEqual((status, body2), (304, b""))
        self.assertEqual(headers2["etag"], etag)
        self.assertIn("content-security-policy", headers2)
        status, headers, _ = self.request("GET", "/static/app.js?v=abc123")
        self.assertIn("immutable", headers["cache-control"])
        status, headers, body = self.request("HEAD", "/static/app.js")
        self.assertEqual((status, body), (200, b""))
        self.assertGreater(int(headers["content-length"]), 0)
        status, headers, _ = self.request("GET", "/api/config")
        self.assertEqual(headers["cache-control"], "no-store")

    def test_static_traversal_over_http(self) -> None:
        # Sent on a raw socket so that no client library normalises the path first.
        attacks = [
            "/../binary_viewer.py", "/..%2fbinary_viewer.py", "/%2e%2e/binary_viewer.py", "/%2e%2e%2fbinary_viewer.py",
            "/%2E%2E%2Fbackend%2Fserver.py", "/static/../../binary_viewer.py", "/static/..%2f..%2fbinary_viewer.py",
            "/static/%2e%2e/backend/server.py", "/..%5cbinary_viewer.py", "/%252e%252e/binary_viewer.py",
            "/....//binary_viewer.py", "/..;/binary_viewer.py", "/.%2e/binary_viewer.py", "/static/..%00/binary_viewer.py",
            "/%c0%ae%c0%ae/binary_viewer.py", "//etc/passwd", "/static//etc/passwd", "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/../fixtures/synthetic_elf64", "/static/../fixtures/synthetic_elf64", "/.git/config", "/.gitignore",
            "/static/app.js/../../binary_viewer.py", "/static/app.js%00.css", "/C:/Windows/win.ini",
            "/../static/../tests/test_api_security.py",
        ]
        for path in attacks:
            reply = self.raw(("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" % path).encode("latin-1"))
            status_line = reply.split(b"\r\n", 1)[0]
            self.assertRegex(status_line, rb"^HTTP/1\.1 (404|400) ", path)
            for marker in (b"def main", b"import ", b"root:", b"\x7fELF", b"[core]", b"__pycache__"):
                self.assertNotIn(marker, reply, (path, marker))
        # Raw high bytes and a request target that is not a path at all.
        for payload in (b"GET /\xc0\xae\xc0\xae/binary_viewer.py HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                        b"GET http://127.0.0.1/../binary_viewer.py HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                        b"GET binary_viewer.py HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"):
            reply = self.raw(payload)
            self.assertTrue(reply.startswith(b"HTTP/1.1 400"), reply[:40])
            self.assertNotIn(b"def main", reply)

    def test_request_smuggling_guards(self) -> None:
        cases = {
            b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n"
            b"0\r\n\r\n": b"400",
            b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n": b"400",
            b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcd": b"400",
            b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: +4\r\n\r\nabcd": b"400",
            b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4, 4\r\n\r\nabcd": b"400",
            b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: -1\r\n\r\n": b"400",
            b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0x10\r\n\r\n": b"400",
            b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n": b"411",
            b"GET /api/config HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\n\r\nabcde": b"400",
        }
        for payload, expected in cases.items():
            reply = self.raw(payload)
            self.assertTrue(reply.startswith(b"HTTP/1.1 " + expected), (payload[:70], reply[:40]))
            self.assertEqual(reply.count(b"HTTP/1.1 "), 1, payload[:70])       # nothing after it was served
            self.assertIn(b"Connection: close", reply)
        # A refused request's unread body is never interpreted as the next request.
        reply = self.raw(b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\n"
                         b"Content-Length: 99999999\r\n\r\nGET /api/config HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        self.assertTrue(reply.startswith(b"HTTP/1.1 413"))
        self.assertEqual(reply.count(b"HTTP/1.1 "), 1)
        # Honest pipelining still works.
        reply = self.raw(b"GET /api/config HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                         b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        self.assertEqual(reply.count(b"HTTP/1.1 200"), 2)

    def test_bounded_request_head(self) -> None:
        cases = {
            b"GET /" + b"A" * 20000 + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n": b"414",
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-A: " + b"B" * 40000 + b"\r\n\r\n": b"431",
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n" + b"".join(b"X-%d: 1\r\n" % i for i in range(300)) + b"\r\n": b"431",
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n" + (b"X-Pad: " + b"c" * 1000 + b"\r\n") * 30 + b"\r\n": b"431",
            b"GET /api/hex?" + b"&".join(b"p%d=1" % i for i in range(200)) + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n": b"400",
        }
        for payload, expected in cases.items():
            reply = self.raw(payload)
            self.assertTrue(reply.startswith(b"HTTP/1.1 " + expected), (payload[:40], reply[:40]))
        for payload in (b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 64 + b"\r\n\r\n",
                        b"GET / HTTP/7.3\r\n\r\n", b"\r\n\r\n", b"GET\r\n\r\n", b"GET /\x00 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                        b"TRACE / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", b"CONNECT evil:443 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"):
            reply = self.raw(payload)
            self.assertNotIn(b"Traceback", reply)
            self.assertNotIn(b"<<client timed out waiting>>", reply)
            if reply:
                self.assertRegex(reply.split(b"\r\n", 1)[0], rb"^HTTP/1\.1 [45]\d\d ", payload[:30])
        status, _, _ = self.request("GET", "/healthz")
        self.assertEqual(status, 200)

    def test_slow_request_head_is_cut_off_at_an_absolute_deadline(self) -> None:
        # One byte every 150 ms keeps a per-recv timeout happy forever; the deadline (1 s here) does not care.
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        started = time.monotonic()
        dropped = False
        try:
            for byte in b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: " + b"a" * 100:
                try:
                    sock.sendall(bytes([byte]))
                except OSError:
                    dropped = True
                    break
                time.sleep(0.15)
                if time.monotonic() - started > 4:
                    break
            if not dropped:
                sock.settimeout(1)
                try:
                    reply = sock.recv(4096)
                    dropped = reply == b"" or reply.startswith(b"HTTP/1.1 408")
                except socket.timeout:
                    dropped = False
                except OSError:
                    dropped = True
        finally:
            sock.close()
        self.assertTrue(dropped)
        self.assertLess(time.monotonic() - started, 4.5)

    def test_idle_connections_are_reaped(self) -> None:
        socks = [socket.create_connection(("127.0.0.1", self.port), timeout=5) for _ in range(10)]
        try:
            time.sleep(0.2)
            self.assertGreaterEqual(self.server.open_connections(), 10)
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline and self.server.open_connections() > 0:
                time.sleep(0.1)
            self.assertEqual(self.server.open_connections(), 0)
        finally:
            for sock in socks:
                sock.close()

    def test_slow_body_is_cut_off(self) -> None:
        # Declares 64 KiB, then stalls: deadline = 1 s + 64 KiB / 64 KiB/s = 2 s.
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=6)
        try:
            sock.sendall(b"POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\n"
                         b"Content-Length: 65536\r\n\r\npartial")
            started = time.monotonic()
            reply = sock.recv(4096)
            elapsed = time.monotonic() - started
        finally:
            sock.close()
        self.assertTrue(reply.startswith(b"HTTP/1.1 408"), reply[:40])
        self.assertLess(elapsed, 4.0)

    def test_access_log_is_structured_and_private(self) -> None:
        marker = os.urandom(8).hex()
        self.upload(ELF_BYTES, "report-%s%%0A%%7B%%22event%%22%%3A%%22forged%%22%%7D.bin" % marker)
        _, _, doc = self.upload(ELF_BYTES, "x.bin")
        self.request("GET", "/api/hex?length=16&doc=" + doc["doc_id"])
        self.raw(b'GET /%s%%0a{"event":"forged"} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' % marker.encode())
        self.raw(b'GET / HTTP/1.1\r\nHost: evil"}\x0b{"event":"forged"}\r\nConnection: close\r\n\r\n')
        self.raw(b'BAD\x1b[31m{"event":"forged"}\r\n\r\n')
        time.sleep(0.2)
        text = self.log_stream.getvalue()
        records = self.log_records()                       # every line parses as exactly one JSON object
        self.assertGreater(len(records), 3)
        self.assertFalse([r for r in records if r.get("event") == "forged"])
        self.assertNotIn("\x1b", text)
        requests = [r for r in records if r.get("event") == "request"]
        self.assertTrue(any(r["route"] == "/api/upload" and r["status"] == 200 and r["bytes_in"] == len(ELF_BYTES)
                            for r in requests))
        for record in requests:
            for field in ("ts", "client", "method", "route", "status", "ms"):
                self.assertIn(field, record)
        # The capability to read an upload never reaches the log; nor do its bytes or its name.
        self.assertNotIn(doc["doc_id"], text)
        self.assertIsNone(re.search(r"[up]_[0-9a-f]{32}", text))
        self.assertTrue(any(r.get("doc") == "u_*" for r in requests))
        self.assertNotIn(ELF_BYTES[:24].hex(), text)
        self.assertNotIn("report-" + marker, text)

    def test_many_concurrent_uploads(self) -> None:
        results = []

        def worker(n: int) -> None:
            try:
                status, _, payload = self.upload(ELF_BYTES if n % 2 else PE_BYTES, "f%d" % n)
                results.append((n, status, payload))
            except Exception as exc:  # pragma: no cover
                results.append((n, "exc", repr(exc)))

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(24)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(len(results), 24)
        for n, status, payload in results:
            self.assertIn(status, (200, 503), payload)
        good = [(n, payload) for n, status, payload in results if status == 200]
        self.assertGreater(len(good), 0)
        self.assertEqual(len({payload["doc_id"] for _, payload in good}), len(good))
        for n, payload in good:
            expected = "ELF" if n % 2 else "PE"
            self.assertEqual(payload["file_info"]["format"], expected)      # nobody got someone else's file
        self.assertEqual(self.server.service.running_parses(), 0)
        self.assertLessEqual(self.server.service.store.stats()["docs"], self.config.cache_max_docs)


class HttpLimitsTests(ServerCase):
    @classmethod
    def make_config(cls) -> RuntimeConfig:
        return RuntimeConfig("public", rate_limit_per_minute=60, rate_limit_burst=8, upload_rate_limit_per_minute=6,
                             upload_rate_limit_burst=1, hard_parse_timeout_seconds=0, max_connections=6,
                             max_connections_per_client=0, request_timeout_seconds=2.0)

    def test_1_rate_limit_over_http(self) -> None:
        statuses = [self.request("GET", "/api/config")[0] for _ in range(12)]
        self.assertEqual(statuses[:8], [200] * 8)
        self.assertEqual(statuses[9:], [429] * 3)
        status, headers, body = self.request("GET", "/api/config")
        self.assertEqual(status, 429)
        self.assertEqual(json.loads(body)["code"], "rate_limited")
        self.assertGreaterEqual(int(headers["retry-after"]), 1)
        self.assertIn("content-security-policy", headers)
        # Static files draw on the same budget; the health check does not.
        self.assertEqual(self.request("GET", "/")[0], 429)
        self.assertEqual(self.request("GET", "/healthz")[0], 200)
        # X-Forwarded-For is not believed without --trust-proxy, so it is no way out.
        self.assertEqual(self.request("GET", "/api/config", headers={"X-Forwarded-For": "8.8.8.8"})[0], 429)

    def test_2_connection_cap(self) -> None:
        held = [socket.create_connection(("127.0.0.1", self.port), timeout=5) for _ in range(6)]
        try:
            time.sleep(0.2)
            reply = self.raw(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", timeout=3)
            self.assertTrue(reply.startswith(b"HTTP/1.1 503"), reply[:40])
            self.assertIn(b"Retry-After", reply)
        finally:
            for sock in held:
                sock.close()
        deadline = time.monotonic() + 3
        status = None
        while time.monotonic() < deadline:
            try:
                status = self.request("GET", "/healthz")[0]
            except OSError:
                status = None
            if status == 200:
                break
            time.sleep(0.1)
        self.assertEqual(status, 200)


class HttpLocalModeTests(ServerCase):
    @classmethod
    def make_config(cls) -> RuntimeConfig:
        return RuntimeConfig("local")

    def test_local_conveniences_still_work(self) -> None:
        status, _, body = self.request("GET", "/api/config")
        cfg = json.loads(body)
        self.assertEqual(cfg["mode"], "local")
        self.assertTrue(cfg["features"]["path_load"])
        status, _, body = self.request("GET", "/api/presets")
        presets = json.loads(body)["presets"]
        self.assertEqual(len(presets), 8)
        self.assertTrue(all("path" in p and "doc" in p for p in presets))

        status, _, body = self.request("POST", "/api/parse", json.dumps({"path": FIXTURES["synthetic_elf64"]}),
                                       {"Content-Type": "application/json"})
        doc = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(doc["doc_id"], "path:" + FIXTURES["synthetic_elf64"])
        # v1 clients: no doc parameter, the last loaded file is implied.
        status, _, body = self.request("GET", "/api/hex?offset=0&length=16")
        self.assertEqual(json.loads(body)["hex_bytes"], ELF_BYTES[:16].hex())
        # v2 clients: explicit ids, by path or by preset.
        status, _, body = self.request("GET", "/api/hex?length=16&doc=preset:synthetic_pe64")
        self.assertEqual(json.loads(body)["hex_bytes"], PE_BYTES[:16].hex())
        status, _, body = self.request("GET", "/api/parse?doc=preset:synthetic_pe64")
        self.assertEqual(json.loads(body)["doc_id"], "preset:synthetic_pe64")
        # v1 base64 upload.
        payload = json.dumps({"filename": "legacy.elf", "data_base64": base64.b64encode(ELF_BYTES).decode()})
        status, _, body = self.request("POST", "/api/upload", payload, {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertIn("legacy.elf", json.loads(body)["file_info"]["path"])

    def test_websites_cannot_read_local_files_through_the_server(self) -> None:
        # What a page on evil.example can make the user's browser send to http://127.0.0.1:<port>.
        target = "/api/hex?path=/etc/passwd&offset=0&length=4096"
        browser_variants = (
            {"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"},
            {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"},
            {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"},
            {"Origin": "https://evil.example"},
            {"Origin": "null"},
            {"Origin": "http://localhost:3000", "Sec-Fetch-Site": "same-site"},
        )
        for extra in browser_variants:
            status, headers, body = self.request("GET", target, headers=extra)
            self.assertEqual(status, 403, extra)
            self.assertNotIn(b"hex_bytes", body)
            self.assertNotIn("access-control-allow-origin", headers)
            status, headers, body = self.request("POST", "/api/parse", json.dumps({"path": "/etc/passwd"}),
                                                 dict(extra, **{"Content-Type": "application/json"}))
            self.assertEqual(status, 403, extra)
        # A cross-site request must not even switch the implicit document.
        before = self.server.service.active_doc_id
        self.request("GET", "/api/parse?path=" + FIXTURES["synthetic_pe32"], headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(self.server.service.active_doc_id, before)
        # No response anywhere invites cross-origin reads.
        for path in ("/", "/api/config", "/api/presets", "/static/app.js"):
            _, headers, _ = self.request("GET", path)
            self.assertNotIn("access-control-allow-origin", headers)
            self.assertEqual(headers["cross-origin-resource-policy"], "same-origin")

    def test_dns_rebinding_is_refused(self) -> None:
        # attacker.example now resolves to 127.0.0.1; the browser believes it is same-origin
        # and sends the attacker's name as Host.
        for host in ("attacker.example:%d" % self.port, "attacker.example", "127.0.0.1.attacker.example:%d" % self.port):
            for path in ("/", "/api/presets", "/api/hex?path=/etc/passwd"):
                status, _, body = self.request("GET", path, headers={
                    "Host": host, "Origin": "http://" + host, "Sec-Fetch-Site": "same-origin"})
                self.assertEqual(status, 403, (host, path))
                self.assertNotIn(b"hex_bytes", body)

    def test_errors_are_clean(self) -> None:
        status, _, body = self.request("GET", "/api/parse?path=/nonexistent/file")
        self.assertEqual((status, json.loads(body)["code"]), (404, "not_found"))
        status, _, body = self.request("GET", "/api/parse?path=/etc/passwd")
        self.assertEqual((status, json.loads(body)["code"]), (422, "parse_failed"))
        status, _, body = self.request("GET", "/api/parse?path=/dev/zero")
        self.assertEqual(status, 404)
        status, _, body = self.request("GET", "/api/parse")
        self.assertEqual(status, 400)
        for _, _, body in (self.request("GET", "/api/parse?path=/etc/passwd"), self.request("GET", "/api/nope"),
                           self.request("GET", "/api/hex?doc=u_" + "0" * 32)):
            self.assertNotIn(b"Traceback", body)
            self.assertNotIn(b'"trace"', body)

    def test_static_files_in_local_mode(self) -> None:
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-cache")
        status, headers, _ = self.request("GET", "/static/styles.css")
        self.assertEqual(headers["cache-control"], "no-cache")       # edits show up on reload
        reply = self.raw(b"GET /..%2fbinary_viewer.py HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        self.assertTrue(reply.startswith(b"HTTP/1.1 404"))


class WatchdogTests(unittest.TestCase):
    def test_uninterruptible_parse_hands_the_process_back_to_its_supervisor(self) -> None:
        # check_deadline() is cooperative. A parse that never reaches it cannot be
        # stopped, so past the hard limit the server asks to be restarted.
        real = service_module.parse_macho_bytes
        release = threading.Event()
        entered = threading.Event()
        fatal = threading.Event()

        def stuck(data, path="<memory>"):
            entered.set()
            release.wait(20)                      # never calls check_deadline()
            return real(data, path=path)

        # The last resort only exists for analyses that run in server threads; with the
        # worker pool (the public default) an overrun is killed instead
        # (tests/test_security_regressions.py).
        config = public_config(hard_parse_timeout_seconds=0.3, parse_timeout_seconds=0.1, parse_workers=False)
        log_stream = io.StringIO()
        server = create_server(WORKSPACE_ROOT, host="127.0.0.1", port=0, config=config,
                               log=EventLog(stream=log_stream), housekeeping_interval=0.05)
        server.app.on_fatal = fatal.set
        service_module.parse_macho_bytes = stuck
        worker = threading.Thread(target=lambda: server.service.add_upload("x", ELF_BYTES), daemon=True)
        try:
            self.assertFalse(fatal.wait(0.3))     # an idle server is left alone
            worker.start()
            self.assertTrue(entered.wait(5))
            self.assertTrue(fatal.wait(5))
            self.assertIn('"event":"parse_stuck"', log_stream.getvalue())
        finally:
            release.set()
            worker.join(10)
            service_module.parse_macho_bytes = real
            server.server_close()


class BindSafetyTests(unittest.TestCase):
    def test_local_mode_refuses_non_loopback_addresses(self) -> None:
        for host in ("0.0.0.0", "::", "192.168.1.20", "example.com", ""):
            with self.assertRaises(ValueError) as ctx:
                create_server(WORKSPACE_ROOT, host=host, port=0, config=RuntimeConfig("local"),
                              log=EventLog(stream=io.StringIO()))
            self.assertIn("--public", str(ctx.exception))

    def test_cli_refuses_and_explains(self) -> None:
        script = os.path.join(WORKSPACE_ROOT, "binary_viewer.py")
        env = {k: v for k, v in os.environ.items() if not k.startswith("BINARYSTUDIO_")}
        proc = subprocess.run([sys.executable, script, "--host", "0.0.0.0", "--port", "0"],
                              capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--public", proc.stderr)
        self.assertIn("--i-know-this-is-unsafe", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        for args in (["--public", "--file", "/bin/ls"], ["--public", "--debug"], ["--public", "--max-upload-mb", "0"]):
            proc = subprocess.run([sys.executable, script, "--port", "0"] + args,
                                  capture_output=True, text=True, timeout=20, env=env)
            self.assertEqual(proc.returncode, 2, args)
        proc = subprocess.run([sys.executable, script, "--help"], capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual(proc.returncode, 0)
        for needle in ("--public", "--trust-proxy", "--allowed-host", "--max-upload-mb", "BINARYSTUDIO_ALLOWED_HOSTS",
                       "BINARYSTUDIO_TRUST_PROXY", "BINARYSTUDIO_RATE_LIMIT", "BINARYSTUDIO_CSP_EXTRA"):
            self.assertIn(needle, proc.stdout)

    def test_public_server_process_starts_from_environment(self) -> None:
        script = os.path.join(WORKSPACE_ROOT, "binary_viewer.py")
        env = {k: v for k, v in os.environ.items() if not k.startswith("BINARYSTUDIO_")}
        env.update({"BINARYSTUDIO_MODE": "public", "BINARYSTUDIO_PORT": "0", "BINARYSTUDIO_MAX_UPLOAD_MB": "1"})
        proc = subprocess.Popen([sys.executable, script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            line = proc.stdout.readline().decode()
            match = re.search(r":(\d+)\s*$", line)
            self.assertIsNotNone(match, line)
            conn = HTTPConnection("127.0.0.1", int(match.group(1)), timeout=10)
            conn.request("GET", "/api/config")
            cfg = json.loads(conn.getresponse().read())
            conn.close()
            self.assertEqual(cfg["mode"], "public")
            self.assertEqual(cfg["limits"]["max_upload_bytes"], 1024 * 1024)
            conn = HTTPConnection("127.0.0.1", int(match.group(1)), timeout=10)
            conn.request("GET", "/api/parse?path=/etc/passwd")
            self.assertEqual(conn.getresponse().status, 403)
            conn.close()
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                proc.kill()
            proc.stdout.close()
            proc.stderr.close()
        self.assertEqual(proc.returncode, 0)      # SIGTERM is a clean shutdown


if __name__ == "__main__":
    unittest.main(verbosity=2)
