"""
Regression tests for the findings of the independent security review (November 2026).

One class per finding, numbered as in the review; each test fails on the code
the review was made against. The inputs are small versions of the reviewer's
reproductions, so the whole file runs in well under a minute.

  1  one upload could take the server down           -> Finding01*
  2  unread responses pinned a copy of the document  -> Finding02*
  3  announced uploads reserved the upload budget     -> Finding03*
  4  patch re-parsing outside the parse accounting    -> Finding04*
  5  document ids in URLs (proxy logs)                -> Finding05*
  6  cache accounting evicted a patch's own original  -> Finding06*
  7  tiny request, huge response                      -> Finding07*
  10 lenient header parsing, Origin scheme            -> Finding10*
  11 static build: check-then-reopen of the archive   -> Finding11*

(8 and 9 belong to the analysis and frontend work.) Servers listen on an
ephemeral loopback port and are shut down by each class.
"""

import gzip
import io
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest
from http.client import HTTPConnection

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKSPACE_ROOT)

from backend import codesign, labs_patch, runtime, service as service_module
from backend.api import ApiRequest, EventLog, build_router, cross_site_reason, request_scheme
from backend.fixtures import ensure_fixtures
from backend.runtime import RuntimeConfig
from backend.server import _ByteBudget, create_server, header_block_defect
from backend.service import AnalysisService, DocEntry, DocumentStore, document_cost

FIXTURES = ensure_fixtures(WORKSPACE_ROOT)
with open(FIXTURES["synthetic_elf64"], "rb") as _f:
    ELF_BYTES = _f.read()
with open(FIXTURES["synthetic_universal"], "rb") as _f:
    UNIVERSAL_BYTES = _f.read()

CLIENT = "203.0.113.7"


# =============================================================================
# Inputs
# =============================================================================
def macho_with_superblob(blob_magic: int, slot_type: int, payload: bytes, count: int = 64) -> bytes:
    """A thin arm64 Mach-O whose LC_CODE_SIGNATURE SuperBlob has `count` index entries
    that all point at ONE sub-blob (the reviewer's gen_cs.py)."""
    dataoff = 4096
    blob = struct.pack(">II", blob_magic, 8 + len(payload)) + payload
    blob_rel = 12 + 8 * count
    index = b"".join(struct.pack(">II", slot_type, blob_rel) for _ in range(count))
    superblob = struct.pack(">III", 0xFADE0CC0, blob_rel + len(blob), count) + index + blob
    lc = struct.pack("<IIII", 0x1D, 16, dataoff, len(superblob))
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(lc), 0, 0)
    return (header + lc).ljust(dataoff, b"\0") + superblob


def plist_payload(size: int) -> bytes:
    head = b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>k</key><array>'
    tail = b"</array></dict></plist>"
    return head + b"<dict/>" * ((size - len(head) - len(tail)) // 7) + tail


def fat_of(thin: bytes, copies: int) -> bytes:
    """A universal binary holding `copies` slices with the same content (the reviewer's gen_kill.py)."""
    step = (len(thin) + 4095) // 4096 * 4096
    header = struct.pack(">II", 0xCAFEBABE, copies)
    for i in range(copies):
        header += struct.pack(">IIIII", 0x0100000C, i, 4096 + i * step, len(thin), 12)
    return header.ljust(4096, b"\0") + thin.ljust(step, b"\0") * copies


def big_document_bytes(copies: int = 6) -> bytes:
    """A small file with a large analysis: the slices of the universal fixture, repeated
    (the reviewer's gen_bigdoc.py). Six copies give about 3 MiB of JSON."""
    data = UNIVERSAL_BYTES
    count = struct.unpack(">I", data[4:8])[0]
    slices = []
    for i in range(count):
        cputype, _sub, off, size, _align = struct.unpack(">IIIII", data[8 + i * 20:28 + i * 20])
        slices.append((cputype, data[off:off + size]))
    slices = slices * copies
    header = struct.pack(">II", 0xCAFEBABE, len(slices))
    body = bytearray()
    for i, (cputype, raw) in enumerate(slices):
        header += struct.pack(">IIIII", cputype, i, 16384 + len(body), len(raw), 14)
        body += raw.ljust((len(raw) + 16383) // 16384 * 16384, b"\0")
    return bytes(header.ljust(16384, b"\0") + body)


def public_config(**overrides) -> RuntimeConfig:
    values = dict(rate_limit_per_minute=0, upload_rate_limit_per_minute=0, hard_parse_timeout_seconds=0)
    values.update(overrides)
    return RuntimeConfig("public", **values)


def make_router(config=None):
    config = config or public_config()
    service = AnalysisService(WORKSPACE_ROOT, config)
    return build_router(service, config, log=EventLog(stream=io.StringIO())), service


def call(router, method, route, query=None, body=b"", headers=None, client=CLIENT):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
        headers = dict(headers or {}, **{"Content-Type": "application/json"})
    resp = router.handle(ApiRequest(method, route, query or {}, body, headers or {}, client))
    payload = None
    if resp.content_type.startswith("application/json") and resp.body and "Content-Encoding" not in resp.headers:
        payload = json.loads(resp.body.decode("utf-8"))
    return resp, payload


def upload(router, data, client=CLIENT, headers=None):
    base = {"Content-Type": "application/octet-stream", "X-Filename": "sample.bin"}
    base.update(headers or {})
    return call(router, "POST", "/api/upload", body=data, headers=base, client=client)


class ServerCase(unittest.TestCase):
    """A real server on an ephemeral port, one per class."""

    @classmethod
    def make_config(cls) -> RuntimeConfig:
        return public_config()

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = cls.make_config()
        cls.log_stream = io.StringIO()
        cls.fatal = threading.Event()
        cls.server = create_server(WORKSPACE_ROOT, host="127.0.0.1", port=0, config=cls.config,
                                   log=EventLog(stream=cls.log_stream), housekeeping_interval=0.1)
        cls.server.app.on_fatal = cls.fatal.set
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(5)

    def request(self, method, path, body=None, headers=None, timeout=20):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
                headers = dict(headers or {}, **{"Content-Type": "application/json"})
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        finally:
            conn.close()

    def upload(self, data, headers=None, timeout=20):
        base = {"Content-Type": "application/octet-stream", "X-Filename": "sample.bin"}
        base.update(headers or {})
        status, hdrs, body = self.request("POST", "/api/upload", data, base, timeout=timeout)
        return status, hdrs, (json.loads(body) if body else None)

    def raw(self, payload: bytes, timeout: float = 5.0) -> bytes:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        try:
            sock.sendall(payload)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            sock.close()

    def unread(self, path: str, headers: str = "") -> socket.socket:
        """Send a GET and never read the answer (a tiny receive buffer, as the reviewer used)."""
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sock.connect(("127.0.0.1", self.port))
        sock.sendall(("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n%s\r\n" % (path, self.port, headers)).encode())
        return sock

    def wait_for(self, predicate, seconds: float = 5.0) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return bool(predicate())


# =============================================================================
# 1. One upload must not be able to take the server down
# =============================================================================
class Finding01SignatureWorkTests(unittest.TestCase):
    """(a) 64 index entries naming one sub-blob cost 64 decodes of it, per slice."""

    def setUp(self) -> None:
        self.decodes = []
        self._real = codesign.plistlib.loads

        def counting(data, *args, **kwargs):
            self.decodes.append(len(data))
            return self._real(data, *args, **kwargs)

        codesign.plistlib = type("plistlib_spy", (), {"loads": staticmethod(counting)})  # type: ignore[assignment]

    def tearDown(self) -> None:
        import plistlib

        codesign.plistlib = plistlib

    def parse(self, data: bytes):
        from backend.parser import parse_macho_bytes

        with runtime.use_config(RuntimeConfig("public")), runtime.parse_deadline(30):
            return parse_macho_bytes(data, path="<test>")

    def test_an_aliased_sub_blob_is_decoded_once(self) -> None:
        doc = self.parse(macho_with_superblob(0xFADE7171, 5, plist_payload(96 * 1024)))
        self.assertEqual(len(self.decodes), 1, "one distinct sub-blob, one plist parse (it was 64)")
        detail = doc["slices"][0]["code_signature_detail"]
        self.assertEqual(detail["blob_count"], 64)                 # every index entry is still listed
        self.assertIn("k", detail["entitlements_dict"])

    def test_entitlement_decoding_is_budgeted_across_slices(self) -> None:
        # 12 slices x 200 KiB of entitlements: more than the per-file budget of 1 MiB.
        thin = macho_with_superblob(0xFADE7171, 5, plist_payload(200 * 1024))
        doc = self.parse(fat_of(thin, 12))
        self.assertEqual(len(doc["slices"]), 12)
        self.assertLessEqual(sum(self.decodes), codesign.ANALYSIS_LIMITS["entitlements_file_bytes"])
        self.assertLessEqual(len(self.decodes), 5)
        codes = {w["code"] for sl in doc["slices"] for w in sl["warnings"]}
        self.assertIn("entitlements_budget_exceeded", codes)

    def test_an_oversized_entitlements_blob_is_not_decoded(self) -> None:
        doc = self.parse(macho_with_superblob(0xFADE7171, 5, plist_payload(1024 * 1024 - 16)))   # the reviewer's blob
        self.assertEqual(self.decodes, [])
        self.assertIn("entitlements_too_large", {w["code"] for w in doc["slices"][0]["warnings"]})

    def test_the_reviewers_kill_file_parses_in_a_fraction_of_the_budget(self) -> None:
        # 7 slices x 64 entries x a 1 MiB plist: 53-90 s before (past the 80 s hard timeout under load).
        thin = macho_with_superblob(0xFADE7171, 5, plist_payload(1024 * 1024 - 16))
        started = time.monotonic()
        self.parse(fat_of(thin, 7))
        self.assertLess(time.monotonic() - started, 10.0)

    def test_cms_scan_is_bounded_and_done_once(self) -> None:
        # The CN OID repeated back to back, never followed by a string: 800,000 candidates per scan.
        unit = b"\x06\x03\x55\x04\x03"
        scans = []
        real = codesign.parse_cms_certificates

        def counting(blob):
            scans.append(len(blob))
            return real(blob)

        codesign.parse_cms_certificates = counting
        try:
            started = time.monotonic()
            self.parse(macho_with_superblob(0xFADE0B01, 0x10000, unit * (1024 * 1024 // 5)))
            elapsed = time.monotonic() - started
        finally:
            codesign.parse_cms_certificates = real
        self.assertEqual(len(scans), 1)
        self.assertLess(elapsed, 5.0)


class Finding01DeadlineTests(unittest.TestCase):
    """(b) the deadline check read the clock on every 256th call only."""

    def test_a_coarse_loop_is_stopped_at_its_first_check_after_the_deadline(self) -> None:
        calls = 0
        with self.assertRaises(runtime.ParseBudgetExceeded):
            with runtime.parse_deadline(0.05):
                for _ in range(40):          # 40 calls: far fewer than 256
                    time.sleep(0.01)
                    calls += 1
                    runtime.check_deadline()
        self.assertLess(calls, 20)

    def test_no_deadline_no_check(self) -> None:
        for _ in range(1000):
            runtime.check_deadline()

    def test_work_budgets_are_per_analysis(self) -> None:
        self.assertTrue(runtime.spend_budget("x", 10 ** 9, 5))     # no analysis running: nothing to bound
        with runtime.work_budgets():
            self.assertTrue(runtime.spend_budget("x", 4, 5))
            self.assertFalse(runtime.spend_budget("x", 2, 5))
            with runtime.work_budgets():                           # a nested analysis starts afresh
                self.assertTrue(runtime.spend_budget("x", 5, 5))
            self.assertTrue(runtime.spend_budget("x", 1, 5))


_STUCK_BOOT = ("import sys, time; sys.path.insert(0, sys.argv.pop(1)); import backend.service as s; "
               "s.parse_macho_bytes = lambda data, path='': time.sleep(120); "
               "from backend.parse_worker import main; sys.exit(main())")
_CRASH_BOOT = ("import sys, os; sys.path.insert(0, sys.argv.pop(1)); import backend.service as s; "
               "s.parse_macho_bytes = lambda data, path='': os._exit(77); "
               "from backend.parse_worker import main; sys.exit(main())")


_MEMORY_BOOT = ("import sys\nsys.path.insert(0, sys.argv.pop(1))\nimport backend.service as s\n"
                "def out_of_memory(data, path=''):\n    raise MemoryError()\n"
                "s.parse_macho_bytes = out_of_memory\n"
                "from backend.parse_worker import main\nsys.exit(main())")


class Finding01WorkerProcessTests(ServerCase):
    """(c) an analysis that cannot be interrupted is killed, not waited for; the server stays up."""

    @classmethod
    def make_config(cls) -> RuntimeConfig:
        return public_config(parse_timeout_seconds=0.6, parse_kill_grace_seconds=0.4, hard_parse_timeout_seconds=3.0,
                             max_concurrent_parses=2)

    def setUp(self) -> None:
        from backend import workers

        self.workers = workers
        self._boot = workers._BOOT
        self.pool = self.server.app.pool
        self.assertIsNotNone(self.pool, "public mode analyses uploads in worker processes")

    def tearDown(self) -> None:
        self.workers._BOOT = self._boot
        self._drop_idle_workers()

    def _drop_idle_workers(self) -> None:
        with self.pool._lock:
            idle, self.pool._idle = self.pool._idle, []
            self.pool._live -= len(idle)
        for worker in idle:
            worker.stop(kill=True)

    def test_uploads_are_analysed_outside_the_server_process(self) -> None:
        status, _, doc = self.upload(ELF_BYTES)
        self.assertEqual(status, 200)
        self.assertEqual(doc["file_info"]["format"], "ELF")
        self.assertGreaterEqual(self.pool.spawned, 1)
        pids = self.pool.worker_pids()
        self.assertTrue(pids and all(pid != os.getpid() for pid in pids))
        # The document the server holds is the same one an in-thread parse produces.
        local = AnalysisService(WORKSPACE_ROOT, public_config()).add_upload("sample.bin", ELF_BYTES).doc
        held = dict(self.server.service.get_entry(doc=doc["doc_id"]).doc)
        expected = dict(local)
        held.pop("doc_id"), expected.pop("doc_id")
        self.assertEqual(held, expected)

    def test_a_stuck_analysis_is_killed_and_everything_else_carries_on(self) -> None:
        status, _, before = self.upload(ELF_BYTES)                  # someone else's document
        self.assertEqual(status, 200)
        self._drop_idle_workers()
        self.workers._BOOT = _STUCK_BOOT                            # the next worker never checks its deadline
        killed = self.pool.killed
        result = {}

        def stuck_upload() -> None:
            result["started"] = time.monotonic()
            result["answer"] = self.upload(UNIVERSAL_BYTES, timeout=30)
            result["elapsed"] = time.monotonic() - result["started"]

        thread = threading.Thread(target=stuck_upload, daemon=True)
        thread.start()
        latencies = []
        while thread.is_alive():                                     # other clients, throughout
            started = time.monotonic()
            status, _, _ = self.request("GET", "/api/hex?length=64&doc=" + before["doc_id"])
            latencies.append(time.monotonic() - started)
            self.assertEqual(status, 200)
            time.sleep(0.05)
        thread.join(5)
        status, _, body = result["answer"]
        self.assertEqual((status, body["code"]), (422, "timeout"))
        self.assertLess(result["elapsed"], 0.6 + 0.4 + 2.0)          # budget + grace + slack, not 120 s
        self.assertEqual(self.pool.killed, killed + 1)
        self.assertLess(max(latencies), 1.0)
        self.assertEqual(self.server.service.running_parses(), 0)    # the slot came back
        self.assertFalse(self.fatal.is_set(), "the server must not ask to be restarted")
        self.assertIn('"event":"parse_worker_killed"', self.log_stream.getvalue())
        # A fresh worker serves the next upload, and the earlier document is still there.
        self.workers._BOOT = self._boot
        status, _, _ = self.upload(ELF_BYTES)
        self.assertEqual(status, 200)
        status, _, _ = self.request("GET", "/api/parse?doc=" + before["doc_id"])
        self.assertEqual(status, 200)

    def test_a_crashing_analysis_costs_one_request(self) -> None:
        self._drop_idle_workers()
        self.workers._BOOT = _CRASH_BOOT
        died = self.pool.died
        status, _, body = self.upload(ELF_BYTES)
        self.assertEqual((status, body["code"]), (422, "parse_failed"))
        self.assertNotIn("Traceback", json.dumps(body))
        self.assertEqual(self.pool.died, died + 1)
        self.workers._BOOT = self._boot
        status, _, _ = self.upload(ELF_BYTES)
        self.assertEqual(status, 200)
        self.assertFalse(self.fatal.is_set())

    def test_running_out_of_memory_costs_one_request(self) -> None:
        # What a worker's address-space limit turns a memory blow-up into (the limit itself
        # is the kernel's; RLIMIT_AS is enforced on Linux, not on macOS).
        self._drop_idle_workers()
        self.workers._BOOT = _MEMORY_BOOT
        spawned = self.pool.spawned
        status, _, body = self.upload(ELF_BYTES)
        self.assertEqual((status, body["code"]), (422, "parse_failed"))
        self.assertIn("memory", body["error"])
        self.assertEqual(self.pool.worker_pids(), [], "a worker that ran out of memory is not reused")
        self.workers._BOOT = self._boot
        status, _, _ = self.upload(ELF_BYTES)
        self.assertEqual(status, 200)
        self.assertGreater(self.pool.spawned, spawned + 1)
        self.assertFalse(self.fatal.is_set())

    def test_rejections_come_back_as_the_same_clean_errors(self) -> None:
        status, _, body = self.upload(b"this is not a binary of any kind at all, sorry")
        self.assertEqual((status, body["code"]), (422, "parse_failed"))
        self.assertIn("Unrecognized", body["error"])

    def test_the_analysis_path_never_imports_process_control(self) -> None:
        code = ("import sys, backend.service, backend.api, backend.labs_patch, backend.learn_content\n"
                "bad = [m for m in ('backend.workers', 'backend.parse_worker', 'resource', 'multiprocessing', 'socket') "
                "if m in sys.modules]\nprint(bad)")
        out = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r)\n%s" % (WORKSPACE_ROOT, code)],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.stdout.strip(), "[]", out.stderr[-500:])


class Finding01LocalModeTests(unittest.TestCase):
    def test_local_mode_and_bare_services_analyse_in_thread(self) -> None:
        self.assertEqual(RuntimeConfig("local").parse_worker_count(), 0)
        self.assertEqual(RuntimeConfig("wasm").parse_worker_count(), 0)
        self.assertEqual(RuntimeConfig("public").parse_worker_count(), 4)
        self.assertEqual(RuntimeConfig("public", parse_workers=False).parse_worker_count(), 0)
        server = create_server(WORKSPACE_ROOT, host="127.0.0.1", port=0, config=RuntimeConfig("local"),
                               log=EventLog(stream=io.StringIO()))
        try:
            self.assertIsNone(server.app.pool)
        finally:
            server.server_close()


# =============================================================================
# 2. Unread responses must not each pin a copy of the document
# =============================================================================
class Finding02PatchResponseTests(unittest.TestCase):
    def test_an_empty_patch_returns_no_document_and_is_charged(self) -> None:
        router, service = make_router(public_config(upload_rate_limit_per_minute=1))   # patch bucket: burst 5
        _, doc = upload(router, big_document_bytes(2))
        entry = service.get_entry(doc=doc["doc_id"])
        statuses = []
        for _ in range(7):
            resp, body = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": []})
            statuses.append(resp.status)
            if resp.status == 200:
                self.assertTrue(body["identical"])
                self.assertNotIn("document", body)
                self.assertLess(resp.body_size(), 32 * 1024)          # the (empty) diff, a few KiB
                self.assertLess(resp.body_size(), len(entry.encoded) // 50)
        self.assertEqual(statuses[:5], [200] * 5)
        self.assertEqual(statuses[5:], [429, 429], "identical patches are charged like any other")

    def test_a_patch_response_is_built_from_the_documents_own_buffer(self) -> None:
        router, service = make_router()
        _, doc = upload(router, ELF_BYTES)
        resp, _ = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": [{"offset": 100, "hex": "41"}]})
        self.assertEqual(resp.status, 200)
        body = json.loads(resp.body)
        derived = service.get_entry(doc=body["doc_id"])
        self.assertTrue(any(part is derived.encoded for part in resp.body_parts()), "no per-response copy of the document")
        self.assertEqual(body["document"], derived.doc)
        self.assertFalse(body["identical"])
        # And the plain document responses.
        for method, route, kwargs in (("GET", "/api/parse", {"query": {"doc": body["doc_id"]}}),):
            resp, _ = call(router, method, route, **kwargs)
            self.assertIs(resp.body_parts()[0], derived.encoded)


class Finding02ResponseBudgetTests(ServerCase):
    @classmethod
    def make_config(cls) -> RuntimeConfig:
        # Per client: a quarter of 8 MiB. The test document's JSON is about 3 MiB.
        return public_config(max_inflight_response_bytes=8 * 1024 * 1024, response_stall_seconds=1.5,
                             gzip_responses=False)

    def test_unread_large_responses_are_capped_then_cut_off(self) -> None:
        status, _, doc = self.upload(big_document_bytes())
        self.assertEqual(status, 200)
        path = "/api/parse?doc=" + doc["doc_id"]
        budget = self.server.app.response_budget
        size = len(self.server.service.get_entry(doc=doc["doc_id"]).encoded)
        self.assertGreater(size, 2 * 1024 * 1024)
        holder = self.unread(path)
        try:
            if not self.wait_for(lambda: budget.used("127.0.0.1") >= size, 3.0):
                self.skipTest("the kernel buffered the whole response; nothing is left in flight to cap")
            # A second large response for the same client is refused at once ...
            started = time.monotonic()
            status, headers, body = self.request("GET", path)
            self.assertEqual((status, json.loads(body)["code"]), (503, "busy"))
            self.assertIn("retry-after", headers)
            self.assertLess(time.monotonic() - started, 1.0)
            # ... small answers are not affected ...
            status, _, _ = self.request("GET", "/api/config")
            self.assertEqual(status, 200)
            # ... and the reader that never reads is dropped after the stall time, not after minutes.
            self.assertTrue(self.wait_for(lambda: budget.used() == 0, 6.0), "stalled response was not cut off")
        finally:
            holder.close()
        status, _, body = self.request("GET", path)
        self.assertEqual((status, len(body)), (200, size))

    def test_budget_arithmetic(self) -> None:
        budget = _ByteBudget(100, 40)
        self.assertTrue(budget.reserve(60, "a"))          # alone, a holder may exceed its share
        self.assertFalse(budget.reserve(10, "a"))         # but not add a second one to it
        self.assertTrue(budget.reserve(30, "b"))
        self.assertFalse(budget.reserve(20, "c"))         # the total is full
        budget.release(60, "a")
        self.assertTrue(budget.reserve(20, "c"))
        self.assertEqual((budget.used(), budget.used("a"), budget.used("c")), (50, 0, 20))


class Finding02ProxiedClientCapTests(ServerCase):
    @classmethod
    def make_config(cls) -> RuntimeConfig:
        return public_config(trust_proxy_headers=True, max_connections_per_client=2, body_grace_seconds=3.0,
                             request_timeout_seconds=5.0)

    def test_requests_in_progress_are_capped_per_forwarded_client(self) -> None:
        def hold(address: str) -> socket.socket:
            # An upload whose body never completes: a request in progress for `address`.
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            sock.sendall(("POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Forwarded-For: %s\r\n"
                          "Content-Type: application/octet-stream\r\nContent-Length: 4096\r\n\r\nxx" % (self.port, address)).encode())
            return sock

        held = [hold("203.0.113.9"), hold("203.0.113.9")]
        try:
            self.assertTrue(self.wait_for(lambda: self.server._req_by_client.get("203.0.113.9") == 2))
            status, _, body = self.request("GET", "/api/config", headers={"X-Forwarded-For": "203.0.113.9"})
            self.assertEqual((status, json.loads(body)["code"]), (503, "busy"))
            status, _, _ = self.request("GET", "/api/config", headers={"X-Forwarded-For": "198.51.100.7"})
            self.assertEqual(status, 200, "another client behind the same proxy is not affected")
        finally:
            for sock in held:
                sock.close()
        self.assertTrue(self.wait_for(lambda: "203.0.113.9" not in self.server._req_by_client))
        status, _, _ = self.request("GET", "/api/config", headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(status, 200)


# =============================================================================
# 3. Announcing an upload must not reserve the upload budget
# =============================================================================
class Finding03UploadBudgetTests(ServerCase):
    @classmethod
    def make_config(cls) -> RuntimeConfig:
        return public_config(max_upload_bytes=1024 * 1024, body_grace_seconds=1.0)

    def test_idle_declared_uploads_block_nobody_and_are_dropped_quickly(self) -> None:
        declared = self.config.max_upload_bytes
        socks = []
        for _ in range(4):                                 # 4 x the maximum = the whole in-flight budget
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            sock.sendall(("POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/octet-stream\r\n"
                          "Content-Length: %d\r\n\r\n" % (self.port, declared)).encode())
            socks.append(sock)
        try:
            time.sleep(0.2)
            self.assertEqual(self.server.app.body_budget.used(), 0, "nothing has arrived, nothing is reserved")
            status, _, _ = self.upload(ELF_BYTES)
            self.assertEqual(status, 200, "a real upload goes through while the idle ones sit there")
            started = time.monotonic()
            reply = socks[0].recv(4096)                    # no first byte within the grace period
            self.assertTrue(reply.startswith(b"HTTP/1.1 408"), reply[:40])
            self.assertLess(time.monotonic() - started, 3.0)
        finally:
            for sock in socks:
                sock.close()

    def test_a_trickled_body_is_held_to_the_minimum_rate(self) -> None:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=8)
        try:
            sock.sendall(("POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/octet-stream\r\n"
                          "Content-Length: 1048576\r\n\r\n" % self.port).encode())
            started = time.monotonic()
            reply = b""
            sock.settimeout(0.2)
            while time.monotonic() - started < 6 and not reply:
                try:
                    sock.sendall(b"x" * 16)                # 80 bytes a second: far below 64 KiB/s
                    reply = sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
            elapsed = time.monotonic() - started
        finally:
            sock.close()
        self.assertTrue(reply.startswith(b"HTTP/1.1 408"), reply[:40])
        self.assertLess(elapsed, 4.0)                      # it was 15 s + 16 s for this size, 527 s for 32 MiB

    def test_reservations_are_capped_per_client(self) -> None:
        cfg = RuntimeConfig("public")
        self.assertEqual(cfg.inflight_upload_budget(), 4 * cfg.max_upload_bytes)
        self.assertEqual(cfg.inflight_upload_budget_per_client(), 2 * cfg.max_upload_bytes)
        budget = _ByteBudget(cfg.inflight_upload_budget(), cfg.inflight_upload_budget_per_client())
        chunk = cfg.max_upload_bytes // 4
        # One client, four connections, each sending a maximum-size upload chunk by chunk
        # (each connection passes what it holds itself, as the server does).
        held = [0, 0, 0, 0]
        refused = set()
        for _ in range(4):
            for conn in range(4):
                if conn in refused:
                    continue
                if budget.reserve(chunk, "a", held[conn]):
                    held[conn] += chunk
                else:
                    refused.add(conn)
        self.assertEqual(sum(held), 2 * cfg.max_upload_bytes, "half of the budget, however many connections")
        self.assertEqual(budget.used("a"), sum(held))
        self.assertTrue(refused)
        self.assertTrue(budget.reserve(cfg.max_upload_bytes, "b"), "the rest of the budget is still there for others")
        for conn in range(4):
            budget.release(held[conn], "a")
        self.assertEqual(budget.used("a"), 0)


# =============================================================================
# 4. Finding the patch that broke a file: bounded, accounted, no leftovers
# =============================================================================
class Finding04LocateTests(unittest.TestCase):
    BREAKING = [{"offset": 3000 + i, "hex": "41"} for i in range(15)] + [{"offset": 0, "hex": "00000000"}]

    def setUp(self) -> None:
        self._probe = service_module.probe_bytes
        self._diff = labs_patch.diff_documents

    def tearDown(self) -> None:
        service_module.probe_bytes = self._probe
        labs_patch.diff_documents = self._diff

    def test_bisection_under_the_parse_accounting(self) -> None:
        router, service = make_router()
        _, doc = upload(router, ELF_BYTES)
        probes = []

        def counting(data):
            probes.append(service.running_parses())        # 1 while a probe holds an analysis slot
            return self._probe(data)

        service_module.probe_bytes = counting
        resp, body = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": self.BREAKING})
        self.assertEqual(resp.status, 200)
        culprit = body["diff"]["parse"]["culprit"]
        self.assertEqual(culprit["patch_index"], 15)
        self.assertTrue(culprit["isolated"])
        self.assertEqual(len(probes), 4, "16 patches: 4 probes by bisection (it was up to 16)")
        self.assertEqual(set(probes), {1}, "every probe runs inside an analysis slot")

    def test_bisection_finds_a_culprit_in_the_middle(self) -> None:
        router, _ = make_router()
        _, doc = upload(router, ELF_BYTES)
        patches = [{"offset": 3000 + i, "hex": "41"} for i in range(11)]
        patches[6] = {"offset": 0, "hex": "00000000"}
        resp, body = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": patches})
        self.assertEqual(resp.status, 200)
        self.assertEqual(body["diff"]["parse"]["culprit"]["patch_index"], 6)

    def test_probes_wait_for_a_slot_like_any_parse(self) -> None:
        router, service = make_router(public_config(max_concurrent_parses=1, parse_queue_seconds=0.05))
        _, doc = upload(router, ELF_BYTES)
        calls = []

        def busy(data):
            calls.append(1)
            raise runtime.Busy("busy")

        service_module.probe_bytes = busy
        resp, body = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": self.BREAKING})
        self.assertEqual(resp.status, 200, "a busy server costs the precision, not the request")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("patch_index", body["diff"]["parse"].get("culprit") or {})

    def test_work_is_charged_to_the_patch_bucket(self) -> None:
        router, _ = make_router(public_config(upload_rate_limit_per_minute=1))    # patch bucket: burst 5
        _, doc = upload(router, ELF_BYTES)
        probes = []
        service_module.probe_bytes = lambda data: (probes.append(1), self._probe(data))[1]
        resp, body = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": self.BREAKING})
        self.assertEqual(resp.status, 200)
        self.assertEqual(len(probes), 4)                   # 1 (the request) + 4 probes = the whole burst
        resp, body = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": self.BREAKING})
        self.assertEqual((resp.status, body["code"]), (429, "rate_limited"), "it used to take five such requests")

    def test_probing_stops_when_the_bucket_is_empty(self) -> None:
        router, _ = make_router(public_config(upload_rate_limit_per_minute=1))
        _, doc = upload(router, ELF_BYTES)
        for _ in range(2):                                 # 5 tokens -> 3
            call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": []})
        probes = []
        service_module.probe_bytes = lambda data: (probes.append(1), self._probe(data))[1]
        resp, body = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": self.BREAKING})
        self.assertEqual(resp.status, 200)
        self.assertEqual(len(probes), 2)                   # 1 for the request, 2 left for probes
        self.assertNotIn("patch_index", body["diff"]["parse"].get("culprit") or {})

    def test_a_request_that_fails_leaves_no_document_behind(self) -> None:
        router, service = make_router()
        _, doc = upload(router, ELF_BYTES)
        self.assertEqual(len(service.store), 1)

        def out_of_time(*args, **kwargs):
            raise runtime.ParseBudgetExceeded("too slow")

        labs_patch.diff_documents = out_of_time
        for patches in ([{"offset": 100, "hex": "41"}], self.BREAKING):       # a copy that parses, and one that does not
            resp, body = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": patches})
            self.assertEqual((resp.status, body["code"]), (422, "timeout"))
            self.assertEqual(len(service.store), 1, "the derived copy nobody was told about is gone")

    def test_locating_is_bounded_per_request(self) -> None:
        self.assertLessEqual(labs_patch.LOCATE_MAX_WORK_BYTES, 4 * labs_patch.LOCATE_MAX_BYTES)
        self.assertLessEqual(labs_patch.LOCATE_MAX_SECONDS, RuntimeConfig("public").parse_timeout_seconds / 2)


# =============================================================================
# 5. Document ids travel in headers, not URLs
# =============================================================================
class Finding05DocHeaderTests(ServerCase):
    def test_every_doc_scoped_endpoint_takes_the_id_from_a_header(self) -> None:
        status, _, doc = self.upload(ELF_BYTES)
        doc_id = doc["doc_id"]
        hdr = {"X-BS-Doc": doc_id}
        for path in ("/api/parse", "/api/hex?length=64", "/api/decode?offset=64", "/api/translate?query=0x40",
                     "/api/disassemble?count=4", "/api/search?q=main", "/api/download", "/api/labs/experiments",
                     "/api/learn/resolve?scope=compare"):
            status, _, body = self.request("GET", path, headers=hdr)
            self.assertEqual(status, 200, (path, body[:120]))
            status, _, _ = self.request("GET", path, headers={"X-BS-Doc": "u_" + "0" * 32})
            self.assertEqual(status, 410, path)
        # The header wins over the query, and the query form still works.
        status, _, _ = self.request("GET", "/api/hex?length=64&doc=u_" + "0" * 32, headers=hdr)
        self.assertEqual(status, 200)
        status, _, _ = self.request("GET", "/api/hex?length=64&doc=" + doc_id)
        self.assertEqual(status, 200)
        # Percent-encoded values (what encodeURIComponent produces) are decoded.
        status, _, body = self.request("GET", "/api/parse", headers={"X-BS-Doc": "preset%3Asynthetic_elf64"})
        self.assertEqual((status, json.loads(body)["doc_id"]), (200, "preset:synthetic_elf64"))
        # Comparison: both ids in headers.
        status, _, body = self.request("GET", "/api/labs/compare", headers={"X-BS-Doc-A": doc_id, "X-BS-Doc-B": "preset%3Asynthetic_elf64"})
        self.assertEqual(status, 200, body[:200])
        self.assertIn("diff", json.loads(body))
        # POST bodies keep working, and the header is accepted there too.
        status, _, _ = self.request("POST", "/api/labs/resolve", {"op": {"kind": "fill", "offset": 0, "size": 1, "byte": 0}}, headers=hdr)
        self.assertEqual(status, 200)
        status, _, _ = self.request("POST", "/api/parse", {"doc": doc_id})
        self.assertEqual(status, 200)
        # Nothing of the id is in this server's own log either way.
        self.assertNotIn(doc_id, self.log_stream.getvalue())
        self.assertIn('"doc":"u_*"', self.log_stream.getvalue())

    def test_proxy_configs_keep_ids_out_of_their_logs(self) -> None:
        with open(os.path.join(WORKSPACE_ROOT, "deploy", "Caddyfile"), encoding="utf-8") as f:
            caddy = f.read()
        for needle in ("replace doc REDACTED", "replace a REDACTED", "replace b REDACTED",
                       "request>headers>X-Bs-Doc delete", "request>headers>X-Bs-Doc-A delete",
                       "request>headers>X-Bs-Doc-B delete"):
            self.assertIn(needle, caddy)
        with open(os.path.join(WORKSPACE_ROOT, "deploy", "nginx.conf"), encoding="utf-8") as f:
            nginx = f.read()
        self.assertRegex(nginx, r"(?m)^\s*error_log\s+\S+\s+crit;")
        self.assertNotRegex(nginx, r"(?m)^\s*log_format[^;]*\$request[ ';\"]")
        self.assertNotRegex(nginx, r"(?m)^\s*log_format[^;]*\$(request_uri|args|query_string)")


# =============================================================================
# 6. Cache accounting
# =============================================================================
class Finding06CacheTests(unittest.TestCase):
    @staticmethod
    def entry(doc_id: str, cost: int, owner: str, parent=None) -> DocEntry:
        return DocEntry(doc_id, "upload", {"doc_id": doc_id}, b"", "f", cost=cost, owner=owner, parent_id=parent)

    def test_a_patched_copy_never_evicts_its_own_original(self) -> None:
        store = DocumentStore(max_docs=64, max_bytes=500, ttl_seconds=0, client_share=0.3)   # 150 per client
        store.put(self.entry("other", 40, "a"))
        store.put(self.entry("root", 100, "a"))
        store.put(self.entry("child", 100, "a", parent="root"))
        self.assertIsNotNone(store.get("root"), "the original went to make room for its own patch")
        self.assertIsNotNone(store.get("child"))
        self.assertIsNone(store.get("other"), "the client's other documents go first")
        # The next patch replaces the copy; the pair is the most this client ever holds.
        store.put(self.entry("child2", 100, "a", parent="root"))
        self.assertIsNotNone(store.get("root"))
        self.assertIsNone(store.get("child"))
        self.assertLessEqual(store.stats()["bytes"], 200)

    def test_the_heaviest_client_makes_room_not_the_oldest_document(self) -> None:
        store = DocumentStore(max_docs=64, max_bytes=300, ttl_seconds=0, client_share=0.0)
        store.put(self.entry("light", 50, "b"))                       # the oldest entry
        for i in range(5):
            store.put(self.entry("heavy%d" % i, 100, "a"))
        self.assertIsNotNone(store.get("light"), "a client holding little keeps it while another fills the cache")
        self.assertLessEqual(store.stats()["bytes"], 300)
        self.assertIsNotNone(store.get("heavy4"))
        # Without owners (local mode) the policy is plain LRU, as before.
        plain = DocumentStore(max_docs=2, max_bytes=0, ttl_seconds=0)
        for name in ("a", "b", "c"):
            plain.put(DocEntry(name, "upload", {}, b"", "f", cost=1))
        self.assertEqual((plain.get("a"), plain.get("b") is not None, plain.get("c") is not None), (None, True, True))

    def test_first_patch_keeps_its_root_end_to_end(self) -> None:
        cost = document_cost(len(ELF_BYTES), len(AnalysisService(WORKSPACE_ROOT, public_config()).add_upload("x", ELF_BYTES).encoded))
        # A cache in which one such document fits a client's share and two do not.
        router, service = make_router(public_config(cache_max_bytes=int(cost * 1.5 / 0.3), cache_client_share=0.3))
        _, doc = upload(router, ELF_BYTES)
        resp, body = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": [{"offset": 100, "hex": "41"}]})
        self.assertEqual(resp.status, 200)
        self.assertEqual(service.get_entry(doc=body["doc_id"]).parent_id, doc["doc_id"])
        resp, _ = call(router, "GET", "/api/hex", {"doc": doc["doc_id"], "length": "16"})
        self.assertEqual(resp.status, 200, "410 here is the reviewer's observation")
        resp, _ = call(router, "POST", "/api/patch", body={"doc": doc["doc_id"], "patches": [{"offset": 101, "hex": "42"}],
                                                          "replace": body["doc_id"]})
        self.assertEqual(resp.status, 200)

    def test_the_charged_cost_covers_what_a_document_occupies(self) -> None:
        import gc
        import tracemalloc

        entry = AnalysisService(WORKSPACE_ROOT, public_config()).add_upload("x", UNIVERSAL_BYTES)
        encoded = entry.encoded
        gc.collect()
        tracemalloc.start()
        rebuilt = json.loads(encoded)                # what the server holds when a worker did the parse
        gc.collect()
        objects = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()
        del rebuilt
        held = len(entry.data) + objects + len(encoded) + len(entry.deflated())
        self.assertLessEqual(held, entry.cost)
        self.assertGreater(held, entry.cost * 0.6, "and is not a wild overestimate either")

    def test_default_quota_arithmetic(self) -> None:
        cfg = RuntimeConfig("public")
        largest = document_cost(cfg.max_upload_bytes, cfg.max_document_bytes)
        self.assertGreaterEqual(cfg.cache_max_bytes, 3 * largest)                         # the cache holds three of the largest
        self.assertGreaterEqual(cfg.cache_max_bytes * cfg.cache_client_share, largest)    # a client's share holds one
        self.assertLessEqual(2 * largest, cfg.cache_max_bytes)                            # and an original with its patch fits the cache


# =============================================================================
# 7. Amplification: validators, compression, size-proportional rate limiting
# =============================================================================
class Finding07ResponseTests(unittest.TestCase):
    def test_etag_and_not_modified(self) -> None:
        router, service = make_router()
        _, doc = upload(router, ELF_BYTES)
        resp, _ = call(router, "GET", "/api/parse", {"doc": doc["doc_id"]})
        etag = resp.headers["ETag"]
        self.assertRegex(etag, r'^"[0-9a-z]+"$')
        again, _ = call(router, "GET", "/api/parse", {"doc": doc["doc_id"]}, headers={"If-None-Match": etag})
        self.assertEqual((again.status, again.body), (304, b""))
        self.assertEqual(again.headers["ETag"], etag)
        stale, _ = call(router, "GET", "/api/parse", {"doc": doc["doc_id"]}, headers={"If-None-Match": '"something-else"'})
        self.assertEqual(stale.status, 200)
        # Downloads and other large GET answers have one too; nothing is stored by browsers.
        for route, query in (("/api/download", {"doc": doc["doc_id"]}), ("/api/hex", {"doc": doc["doc_id"], "length": "4096"}),
                             ("/api/learn/index", {})):
            first, _ = call(router, "GET", route, query)
            self.assertIn("ETag", first.headers, route)
            self.assertEqual(first.headers["Cache-Control"], "no-store")
            second, _ = call(router, "GET", route, query, headers={"If-None-Match": first.headers["ETag"]})
            self.assertEqual(second.status, 304, route)
        # The upload response already names the document's validator.
        up, _ = upload(router, ELF_BYTES)
        self.assertIn("ETag", up.headers)

    def test_gzip_from_one_cached_buffer(self) -> None:
        router, service = make_router()
        _, doc = upload(router, UNIVERSAL_BYTES)
        entry = service.get_entry(doc=doc["doc_id"])
        plain, _ = call(router, "GET", "/api/parse", {"doc": doc["doc_id"]})
        self.assertNotIn("Content-Encoding", plain.headers)
        self.assertEqual(plain.headers.get("Vary"), "Accept-Encoding")
        packed, _ = call(router, "GET", "/api/parse", {"doc": doc["doc_id"]}, headers={"Accept-Encoding": "br, gzip"})
        self.assertEqual(packed.headers["Content-Encoding"], "gzip")
        self.assertEqual(gzip.decompress(packed.body), plain.body)
        self.assertLess(packed.body_size(), plain.body_size() // 4)
        self.assertNotEqual(packed.headers["ETag"], plain.headers["ETag"])
        self.assertTrue(any(part is entry.deflated() for part in packed.body_parts()), "compressed once, shared")
        # Either validator revalidates either representation.
        for tag in (plain.headers["ETag"], packed.headers["ETag"]):
            resp, _ = call(router, "GET", "/api/parse", {"doc": doc["doc_id"]}, headers={"If-None-Match": tag, "Accept-Encoding": "gzip"})
            self.assertEqual(resp.status, 304)
        # A document embedded in a patch response reuses the same buffer.
        req = {"doc": doc["doc_id"], "patches": [{"offset": 5000, "hex": "%02x" % (UNIVERSAL_BYTES[5000] ^ 0xFF)}]}
        patched, _ = call(router, "POST", "/api/patch", body=req, headers={"Accept-Encoding": "gzip"})
        self.assertEqual(patched.headers["Content-Encoding"], "gzip")
        body = json.loads(gzip.decompress(patched.body))
        derived = service.get_entry(doc=body["doc_id"])
        self.assertTrue(any(part is derived.deflated() for part in patched.body_parts()))
        self.assertEqual(body["document"], derived.doc)
        # Refused or absent: identity. Small or binary answers: left alone.
        for value in ("gzip;q=0", "identity", ""):
            resp, _ = call(router, "GET", "/api/parse", {"doc": doc["doc_id"]}, headers={"Accept-Encoding": value})
            self.assertNotIn("Content-Encoding", resp.headers, value)
        resp, _ = call(router, "GET", "/api/config", headers={"Accept-Encoding": "gzip"})
        self.assertNotIn("Content-Encoding", resp.headers)
        resp, _ = call(router, "GET", "/api/download", {"doc": doc["doc_id"]}, headers={"Accept-Encoding": "gzip"})
        self.assertNotIn("Content-Encoding", resp.headers)
        # Other JSON is compressed on the way out.
        resp, _ = call(router, "GET", "/api/hex", {"doc": doc["doc_id"], "length": "65536"}, headers={"Accept-Encoding": "gzip"})
        self.assertEqual(resp.headers["Content-Encoding"], "gzip")
        self.assertIn("rows", json.loads(gzip.decompress(resp.body)))

    def test_gzip_can_be_switched_off(self) -> None:
        router, _ = make_router(public_config(gzip_responses=False))
        resp, _ = call(router, "GET", "/api/parse", {"doc": "preset:synthetic_universal"}, headers={"Accept-Encoding": "gzip"})
        self.assertNotIn("Content-Encoding", resp.headers)

    def test_rate_limit_tokens_are_charged_by_response_size(self) -> None:
        # 30 tokens of burst, one more per 64 KiB sent. The preset's JSON is about 1 MiB: 17 tokens a time.
        router, _ = make_router(public_config(rate_limit_per_minute=60, response_bytes_per_token=64 * 1024))
        statuses = [call(router, "GET", "/api/parse", {"doc": "preset:synthetic_universal"})[0].status for _ in range(4)]
        self.assertEqual(statuses[:2], [200, 200])
        self.assertEqual(statuses[2:], [429, 429], "30 requests used to be served, about 30 MiB")
        # Compressed, the same document costs a fraction, and a 304 costs nothing extra.
        router, _ = make_router(public_config(rate_limit_per_minute=60, response_bytes_per_token=64 * 1024))
        gz = {"Accept-Encoding": "gzip"}
        statuses = [call(router, "GET", "/api/parse", {"doc": "preset:synthetic_universal"}, headers=gz)[0].status for _ in range(8)]
        self.assertEqual(statuses, [200] * 8)
        # Other clients have their own bucket.
        resp, _ = call(router, "GET", "/api/config", client="198.51.100.7")
        self.assertEqual(resp.status, 200)

    def test_wasm_mode_is_left_alone(self) -> None:
        cfg = RuntimeConfig("wasm")
        router = build_router(AnalysisService(WORKSPACE_ROOT, cfg), cfg, log=EventLog(stream=io.StringIO()))
        resp, _ = call(router, "GET", "/api/parse", {"doc": "preset:synthetic_elf64"}, headers={"Accept-Encoding": "gzip"})
        self.assertEqual(resp.status, 200)
        self.assertNotIn("Content-Encoding", resp.headers)
        self.assertNotIn("ETag", resp.headers)


class Finding07HttpTests(ServerCase):
    def test_gzip_and_304_over_http(self) -> None:
        path = "/api/parse?doc=preset:synthetic_universal"
        status, headers, plain = self.request("GET", path)
        self.assertEqual(status, 200)
        self.assertNotIn("content-encoding", headers)
        status, gz_headers, packed = self.request("GET", path, headers={"Accept-Encoding": "gzip"})
        self.assertEqual((status, gz_headers["content-encoding"]), (200, "gzip"))
        self.assertEqual(int(gz_headers["content-length"]), len(packed))
        self.assertEqual(gzip.decompress(packed), plain)
        self.assertLess(len(packed), len(plain) // 4)
        status, headers, body = self.request("GET", path, headers={"If-None-Match": gz_headers["etag"], "Accept-Encoding": "gzip"})
        self.assertEqual((status, body), (304, b""))
        self.assertNotIn("content-length", headers)


# =============================================================================
# 10. HTTP parsing strictness and the Origin scheme
# =============================================================================
class Finding10HeaderTests(ServerCase):
    def post(self, extra: bytes, body: bytes = b"{}") -> bytes:
        return self.raw(b"POST /api/parse HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Length: %d\r\n" % (self.port, len(body))
                        + extra + b"Content-Type: application/json\r\nConnection: close\r\n\r\n" + body)

    def test_defective_header_blocks_are_refused(self) -> None:
        ok = self.post(b"")
        self.assertIn(b"Missing required", ok)                       # reached the handler
        for label, extra in (
            ("whitespace before the colon", b"Transfer-Encoding : chunked\r\n"),
            ("folded line", b"X-A: 1\r\n continued\r\n"),
            ("no colon", b"this is not a header\r\n"),
            ("empty name", b": value\r\n"),
            ("space in name", b"X A: 1\r\n"),
            ("bare LF", b"X-A: 1\n"),
            ("NUL in value", b"X-A: a\x00b\r\n"),
        ):
            reply = self.post(extra)
            self.assertTrue(reply.startswith(b"HTTP/1.1 400"), (label, reply[:60]))
            self.assertIn(b"Malformed HTTP request headers", reply, label)
            self.assertNotIn(b"Missing required", reply, label)       # never reached a handler
            self.assertEqual(reply.count(b"HTTP/1.1 "), 1, label)     # and nothing after it was read as a request

    def test_the_smuggling_shape_from_the_review(self) -> None:
        # Content-Length plus a Transfer-Encoding the standard parser silently dropped,
        # along with every header after it.
        reply = self.raw(b"POST /api/parse HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Length: 2\r\nTransfer-Encoding : chunked\r\n"
                         b"Content-Type: application/json\r\n\r\n{}" % self.port)
        self.assertTrue(reply.startswith(b"HTTP/1.1 400"), reply[:60])
        self.assertIn(b"Connection: close", reply)

    def test_header_block_defect_unit(self) -> None:
        self.assertIsNone(header_block_defect([b"Host: x\r\n", b"X-Empty:\r\n", b"Accept: a\tb\r\n", b"\r\n"]))
        self.assertIsNotNone(header_block_defect([b"Host: x\r\n"]))                # never terminated
        self.assertIsNotNone(header_block_defect([b"Host : x\r\n", b"\r\n"]))
        self.assertIsNotNone(header_block_defect([b"\tHost: x\r\n", b"\r\n"]))
        self.assertIsNotNone(header_block_defect([b"Host: x\n", b"\n"]))


class Finding10OriginSchemeTests(unittest.TestCase):
    def test_origin_scheme_is_compared(self) -> None:
        same = {"host": "studio.example.com", "origin": "https://studio.example.com"}
        self.assertIsNone(cross_site_reason(same, "https"))
        self.assertIsNotNone(cross_site_reason(same, "http"))
        self.assertIsNone(cross_site_reason(same, None))                           # scheme unknown: not compared
        plain = {"host": "127.0.0.1:8421", "origin": "http://127.0.0.1:8421"}
        self.assertIsNone(cross_site_reason(plain, "http"))
        self.assertIsNotNone(cross_site_reason(plain, "https"))
        self.assertIsNotNone(cross_site_reason({"host": "127.0.0.1:8421", "origin": "https://127.0.0.1:8421"}, "http"))

    def test_scheme_comes_from_the_listener_or_a_trusted_proxy(self) -> None:
        direct, proxied = RuntimeConfig("public"), RuntimeConfig("public", trust_proxy_headers=True)
        https = {"x-forwarded-proto": "https"}
        self.assertEqual(request_scheme("203.0.113.5", https, direct), "http")     # the header is not believed
        self.assertEqual(request_scheme("127.0.0.1", https, direct), "http")
        self.assertEqual(request_scheme("127.0.0.1", https, proxied), "https")
        self.assertEqual(request_scheme("127.0.0.1", {"x-forwarded-proto": "http, https"}, proxied), "https")
        self.assertEqual(request_scheme("203.0.113.5", https, proxied), "http")    # not from the proxy
        self.assertIsNone(request_scheme("127.0.0.1", {}, proxied))                # a proxy that does not say


class Finding10OriginSchemeHttpTests(ServerCase):
    @classmethod
    def make_config(cls) -> RuntimeConfig:
        return public_config(trust_proxy_headers=True, allowed_hosts=["studio.example.com"])

    def test_behind_a_tls_proxy(self) -> None:
        base = {"Host": "studio.example.com", "X-Forwarded-For": "203.0.113.5", "X-Forwarded-Proto": "https"}
        status, _, _ = self.request("GET", "/api/config", headers=dict(base, Origin="https://studio.example.com"))
        self.assertEqual(status, 200)
        status, _, _ = self.request("GET", "/api/config", headers=dict(base, Origin="http://studio.example.com"))
        self.assertEqual(status, 403)
        self.assertIn("cross_site_rejected", self.log_stream.getvalue())


class Finding10DirectListenerTests(ServerCase):
    def test_https_origin_on_the_plain_listener_is_cross_origin(self) -> None:
        status, _, _ = self.request("GET", "/api/config", headers={"Origin": "http://127.0.0.1:%d" % self.port})
        self.assertEqual(status, 200)
        status, _, _ = self.request("GET", "/api/config", headers={"Origin": "https://127.0.0.1:%d" % self.port})
        self.assertEqual(status, 403)


# =============================================================================
# 11. Static build: what is verified is what is extracted
# =============================================================================
class Finding11StaticBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("bs_build_static_regress", os.path.join(WORKSPACE_ROOT, "tools", "build_static.py"))
        cls.build_static = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.build_static)

    def test_extraction_only_from_verified_bytes(self) -> None:
        import tarfile
        import tempfile

        bs = self.build_static
        # A well-formed archive with the right member names and the wrong hash.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:bz2") as tar:
            for name in bs.PYODIDE_FILES:
                data = b"{}" if name.endswith(".json") else b"evil"
                info = tarfile.TarInfo("pyodide/" + name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        forged = buf.getvalue()
        with self.assertRaises(bs.BuildError):
            bs.extract_pyodide(forged)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, bs.PYODIDE_ARCHIVE)
            with open(path, "wb") as f:
                f.write(forged)
            with self.assertRaises(bs.BuildError):
                bs.load_pyodide_archive(path)
            with self.assertRaises(bs.BuildError):
                bs.extract_pyodide(path)

    def test_the_archive_is_opened_once(self) -> None:
        # extract_pyodide must hand tarfile the bytes it verified, never a path to reopen.
        import inspect

        source = inspect.getsource(self.build_static.extract_pyodide)
        self.assertIn("fileobj=io.BytesIO(data)", source)
        self.assertNotIn("tarfile.open(archive", source)

    def test_build_info_names_nothing_of_the_build_machine(self) -> None:
        bs = self.build_static
        home = os.path.expanduser("~")
        self.assertIsNone(bs._local_identifier_in(json.dumps({"files": {"index.html": 1}, "csp": "default-src 'none'"})))
        if len(home) >= 4:
            self.assertIsNotNone(bs._local_identifier_in(json.dumps({"cache": os.path.join(home, ".cache", "x")})))
        self.assertIsNotNone(bs._local_identifier_in(json.dumps({"out": "/srv/build/out/dist"}), "/srv/build/out/dist"))
        info = os.path.join(WORKSPACE_ROOT, "dist", "build-info.json")
        if os.path.isfile(info):
            with open(info, encoding="utf-8") as f:
                self.assertIsNone(bs._local_identifier_in(f.read()))

    def test_worker_modules_stay_out_of_the_browser_bundle(self) -> None:
        self.assertLessEqual({"workers.py", "parse_worker.py", "server.py"}, set(self.build_static.BACKEND_EXCLUDE))
        names = {arc for arc, _src in self.build_static.bundle_members()}
        self.assertNotIn("backend/workers.py", names)
        self.assertNotIn("backend/parse_worker.py", names)


if __name__ == "__main__":
    unittest.main()
