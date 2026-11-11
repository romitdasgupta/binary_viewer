"""
Glue between the WASM engine worker (static/wasm/engine-worker.js) and the
transport-agnostic API router (backend/api.py).

It is shipped inside the engine bundle next to the `backend` package and runs
inside Pyodide, but it only uses plain Python types, so the same module also
runs under ordinary CPython (tests/test_static_build.py does exactly that).

    init(overrides_json)                      -> None   build config, service and router in `wasm` mode
    handle(method, route, query_json, headers_json, body) -> (status, headers_json, body_bytes)
    stats()                                   -> json   document store numbers, for diagnostics

`body` may be bytes, a memoryview, or a Pyodide JsProxy of a Uint8Array
(anything with `to_bytes()`); it is copied exactly once into a Python bytes object.

The router never raises. One thing it cannot tell a client is that the
interpreter ran out of memory: a MemoryError becomes a generic "internal"
error. This module watches the router's event log for that case and answers
with a precise `out_of_memory` error instead, and flags that the worker should
be recycled (a WebAssembly heap never shrinks, so after a MemoryError the
cleanest recovery is a fresh worker).
"""

import json
import os
import sys

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

from backend import runtime  # noqa: E402
from backend.api import ApiRequest, EventLog, build_router  # noqa: E402
from backend.service import AnalysisService  # noqa: E402

_router = None
_service = None
_config = None
_recycle = False

OOM_MESSAGE = (
    "This file needs more memory than this browser tab can give the analysis engine. "
    "The engine has been restarted. Try a smaller file, or run BinaryStudio locally for very large binaries."
)


class _WatchingLog(EventLog):
    """The normal structured log, plus a note of the last internal error's type."""

    def __init__(self, stream=None):
        EventLog.__init__(self, stream=stream)
        self.last_exc = None

    def write(self, level, event, **fields):
        if event == "internal_error":
            self.last_exc = fields.get("exc")
        EventLog.write(self, level, event, **fields)


_log = _WatchingLog()


def _coerce_override(key, value):
    # JSON has no tuples; csp_extra is a list of [name, [sources]] pairs.
    if key == "csp_extra" and isinstance(value, list):
        return [(str(name), list(sources)) for name, sources in value]
    return value


def init(overrides_json="{}", app_root=None):
    """Build the wasm-mode router. Safe to call again (replaces the previous one)."""
    global _router, _service, _config, _recycle
    overrides = json.loads(overrides_json or "{}")
    overrides = {k: _coerce_override(k, v) for k, v in overrides.items()}
    config = runtime.RuntimeConfig("wasm", **overrides)
    runtime.set_config(config)
    root = app_root or APP_ROOT
    _service = AnalysisService(root, config)
    _router = build_router(_service, config, log=_log)
    _config = config
    _recycle = False
    return None


def handle(method, route, query_json="{}", headers_json="{}", body=None):
    """Serve one request. Returns (status, headers_json, body_bytes); never raises."""
    global _recycle
    if _router is None:
        payload = {"error": "The analysis engine is not initialised.", "code": "internal"}
        return 500, json.dumps({"content-type": "application/json; charset=utf-8"}), json.dumps(payload).encode()
    try:
        if body is None or type(body).__name__ == "JsNull":
            data = b""
        elif isinstance(body, bytes):
            data = body
        elif hasattr(body, "to_bytes"):
            data = body.to_bytes()
        else:
            data = bytes(body)
        query = json.loads(query_json or "{}")
        headers = json.loads(headers_json or "{}")
        query = {str(k): str(v) for k, v in query.items()} if isinstance(query, dict) else {}
        headers = {str(k): str(v) for k, v in headers.items()} if isinstance(headers, dict) else {}
    except MemoryError:
        _recycle = True
        return _error(507, "out_of_memory", OOM_MESSAGE)
    except Exception:
        return _error(400, "bad_request", "Malformed request from the page.")
    if _json_too_deep(headers, data):
        # Same answer the router gives under CPython, where json.loads raises RecursionError.
        return _error(400, "bad_request", "Request body is not valid JSON.")
    _log.last_exc = None
    try:
        resp = _router.handle(ApiRequest(method, route, query, data, headers, client_id="wasm"))
    except MemoryError:  # the router catches Exception; this is belt and braces
        resp = None
        _log.last_exc = "MemoryError"
    data = None  # drop the request body before building the response
    if resp is None or (_log.last_exc == "MemoryError" and (resp.status >= 500)):
        _recycle = True
        return _error(507, "out_of_memory", OOM_MESSAGE)
    out_headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
    out_headers["content-type"] = resp.content_type
    return resp.status, json.dumps(out_headers), bytes(resp.body)


# json.loads recurses in C once per nesting level. CPython 3.9 stops at the recursion limit with a
# RecursionError (which the router turns into a 400); CPython 3.14 under Pyodide checks a stack
# bound that does not account for the JS engine's own stack, so ~10,000 levels overflow it and kill
# the interpreter (measured with Pyodide 314.0.7). Bodies nested deeper than the recursion limit are
# therefore refused here, before the router sees them.
MAX_JSON_DEPTH = 1000


def _json_too_deep(headers, data):
    if not data or (data.count(b"[") + data.count(b"{")) <= MAX_JSON_DEPTH:
        return False
    ctype = headers.get("content-type", "").lower()
    if ctype and "json" not in ctype:
        return False
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return True
        elif byte in (0x5D, 0x7D):
            depth -= 1
    return False


def should_recycle():
    """True after a MemoryError: the worker should be replaced once the response is out."""
    return _recycle


def _error(status, code, message):
    headers = {"content-type": "application/json; charset=utf-8", "cache-control": "no-store"}
    body = json.dumps({"error": message, "code": code}).encode("utf-8")
    return status, json.dumps(headers), body


def stats():
    if _service is None:
        return json.dumps({})
    data = dict(_service.store.stats())
    data["python"] = sys.version.split()[0]
    data["recursion_limit"] = sys.getrecursionlimit()
    return json.dumps(data)
