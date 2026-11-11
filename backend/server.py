"""
HTTP adapter: a thin, hardened shell around `backend.api.ApiRouter` plus the
static file server for the web UI.

The router decides what a request means. This module only moves bytes, and is
where everything specific to sockets lives:

  * absolute deadlines for receiving a request head, and for a body a first-byte
    deadline followed by a minimum rate (a per-recv timeout alone does not stop
    a client that sends one byte at a time, or one that only announces a body)
  * bounded request line, headers and body; bodies over the limit are refused
    from the headers, before a byte of them is read; memory for bodies is
    reserved as the bytes arrive, in total and per client
  * a cap on open connections, in total and per client address (per forwarded
    client address behind a trusted proxy)
  * response bodies are written from shared buffers, never copied per request;
    the bytes in flight are capped in total and per client, and a reader that
    stops reading is cut off after seconds, not minutes
  * analyses run in a pool of worker processes that are killed when they overrun
    (backend/workers.py), so no upload can hold a server thread
  * a strict reading of the header block: anything a proxy might read
    differently (folded lines, whitespace around a name, bare LF) is a 400
  * Host allowlist (DNS rebinding) and cross-site request refusal for /api/
  * request-smuggling hygiene: no Transfer-Encoding, one well-formed
    Content-Length, one Host
  * static files confined to the static directory, with cache and security
    headers
  * one structured log line per request

It never terminates TLS; put a reverse proxy in front for that (see deploy/).
"""

import collections
import os
import socket
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote

from . import runtime
from .api import (
    LOG,
    ApiRequest,
    ApiResponse,
    ApiRouter,
    EventLog,
    allowed_host_names,
    build_router,
    client_key,
    cross_site_reason,
    host_allowed,
    is_loopback_host,
    redact_doc_id,
    request_scheme,
    resolve_client_address,
    security_headers,
)
from .fixtures import ensure_fixtures
from .runtime import RuntimeConfig
from .service import SYNTHETIC_PRESETS, AnalysisService

ALLOWED_METHODS = ("GET", "HEAD", "POST", "OPTIONS")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".py": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".avif": "image/avif",
    ".ico": "image/x-icon",
    ".wasm": "application/wasm",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".zip": "application/zip",
    ".whl": "application/zip",
    ".tar": "application/x-tar",
    ".gz": "application/gzip",
    ".pdf": "application/pdf",
}


# Responses smaller than this are not counted against the in-flight response
# budget (they are bounded by the connection caps: 128 connections x 256 KiB).
RESPONSE_BUDGET_MIN_BYTES = 256 * 1024
_WRITE_CHUNK = 256 * 1024
_HEADER_NAME_CHARS = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class _HeadTooLarge(Exception):
    pass


class _BodyBudgetExceeded(Exception):
    pass


def header_block_defect(lines: List[bytes]) -> Optional[str]:
    """Why a request's header lines (everything after the request line, up to and
    including the empty line) are not acceptable, or None.

    The standard library's parser is lenient in ways that matter when a proxy sits
    in front: at a line it cannot parse (`Transfer-Encoding : chunked`) it silently
    stops and treats the remaining headers as body, and it joins folded lines. Two
    parsers that disagree about a header block is how requests get smuggled, so
    anything other than plain `Name: value CRLF` lines is refused outright.
    """
    ended = False
    for line in lines:
        if ended:
            return "data after the header block"
        if not line.endswith(b"\r\n"):
            return "header line not terminated by CRLF"
        body = line[:-2]
        if not body:
            ended = True
            continue
        if body[:1] in (b" ", b"\t"):
            return "folded header line"
        name, sep, value = body.partition(b":")
        if not sep:
            return "header line without a colon"
        if not name or not _HEADER_NAME_CHARS.issuperset(name):
            return "malformed header name"
        if any(ch < 0x20 and ch != 0x09 or ch == 0x7F for ch in value):
            return "control character in a header value"
    return None if ended else "unterminated header block"


class _SocketReader:
    """A minimal buffered reader over a socket with an absolute deadline and a byte budget.

    `socket.settimeout` bounds each `recv`, so a client can hold a thread for
    as long as it likes by trickling bytes. This reader instead refuses to wait
    past a fixed point in time, and refuses to buffer a request head larger
    than the budget.
    """

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = bytearray()
        self._eof = False
        self._deadline = time.monotonic() + 30.0
        self._after_first: Optional[float] = None
        self._budget: Optional[int] = None
        self.received = 0
        self.head_lines: List[bytes] = []   # the raw lines of the request head being read

    def begin_head(self, idle_seconds: float, head_seconds: float, budget: int) -> None:
        """Wait up to `idle_seconds` for a request to start, then allow
        `head_seconds` in total for the rest of its head."""
        now = time.monotonic()
        self._budget = budget
        self.received = len(self._buf)
        self.head_lines = []
        if self._buf:
            self._deadline, self._after_first = now + head_seconds, None
        else:
            self._deadline, self._after_first = now + idle_seconds, head_seconds

    def begin_body(self, seconds: float) -> None:
        self._budget = None
        self._after_first = None
        self._deadline = time.monotonic() + seconds

    def _fill(self) -> None:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("deadline exceeded")
        self._sock.settimeout(remaining)
        chunk = self._sock.recv(65536)
        if not chunk:
            self._eof = True
            return
        if self._after_first is not None:
            self._deadline, self._after_first = time.monotonic() + self._after_first, None
        self._buf += chunk
        self.received += len(chunk)

    def _take(self, count: int) -> bytes:
        if self._budget is not None:
            self._budget -= count
            if self._budget < 0:
                raise _HeadTooLarge()
        data = bytes(self._buf[:count])
        del self._buf[:count]
        return data

    def readline(self, limit: int = -1) -> bytes:
        line = self._readline(limit)
        if self._budget is not None:      # reading a request head: keep its lines for validation
            self.head_lines.append(line)
        return line

    def _readline(self, limit: int = -1) -> bytes:
        while True:
            index = self._buf.find(b"\n")
            if index >= 0 and (limit < 0 or index < limit):
                return self._take(index + 1)
            if limit >= 0 and len(self._buf) >= limit:
                return self._take(limit)
            if self._budget is not None and len(self._buf) > self._budget:
                raise _HeadTooLarge()
            if self._eof:
                return self._take(len(self._buf))
            self._fill()

    def read_body(self, count: int, grace: float, rate: float, reserve: Callable[[int], bool]) -> bytes:
        """A request body of `count` bytes, or fewer if the peer closed first.

        The sender is held to a schedule from the moment the body is due: nothing
        for `grace` seconds, or at any later point fewer bytes than `rate` per
        second would have delivered (with the same `grace` as slack), raises
        socket.timeout. So a connection that only announces a large body costs a
        thread for `grace` seconds, not for the minutes the whole body would take.

        `reserve(n)` is asked for every chunk once it has arrived; when it says no
        (too many request bodies in memory) _BodyBudgetExceeded is raised.
        """
        self._budget = None
        self._after_first = None
        started = time.monotonic()
        parts: List[bytes] = []
        have = 0
        if self._buf:
            first = self._take(min(len(self._buf), count))
            if not reserve(len(first)):
                raise _BodyBudgetExceeded()
            parts.append(first)
            have = len(first)
        while have < count and not self._eof:
            remaining = grace + have / rate - (time.monotonic() - started)
            if remaining <= 0:
                raise socket.timeout("request body too slow")
            self._sock.settimeout(remaining)
            chunk = self._sock.recv(min(_WRITE_CHUNK, count - have))
            if not chunk:
                self._eof = True
                break
            self.received += len(chunk)
            if not reserve(len(chunk)):
                raise _BodyBudgetExceeded()
            parts.append(chunk)
            have += len(chunk)
        return b"".join(parts)

    def read(self, count: int) -> bytes:
        """Exactly `count` bytes, or fewer if the peer closed first."""
        if count <= len(self._buf):
            return self._take(count)
        parts: List[bytes] = [self._take(len(self._buf))]
        have = len(parts[0])
        while have < count and not self._eof:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("deadline exceeded")
            self._sock.settimeout(remaining)
            chunk = self._sock.recv(min(1 << 20, count - have))
            if not chunk:
                self._eof = True
                break
            parts.append(chunk)
            have += len(chunk)
            self.received += len(chunk)
        return b"".join(parts)

    def pending(self) -> int:
        return len(self._buf)

    def close(self) -> None:
        self._buf = bytearray()

    @property
    def closed(self) -> bool:
        return False

    def flush(self) -> None:
        pass


class _ByteBudget:
    """Bounds bytes held at once (request bodies being buffered, or response bodies
    being written), in total and per client. `limit <= 0` means unbounded.

    One holder may always go over a limit on its own (a body larger than the whole
    budget would otherwise never be accepted); a second one may not join it."""

    def __init__(self, limit: int, client_limit: int = 0) -> None:
        self.limit = limit
        self.client_limit = client_limit
        self._used = 0
        self._by_client: Dict[str, int] = {}
        self._lock = threading.Lock()

    def reserve(self, amount: int, client: Optional[str] = None, held: int = 0) -> bool:
        """Add `amount` for `client`. `held` is what the caller itself already holds
        (so that growing one's own reservation is not mistaken for a second holder)."""
        if self.limit <= 0:
            return True
        with self._lock:
            if self._used + amount > self.limit and self._used > held:
                return False
            if client is not None and self.client_limit > 0:
                mine = self._by_client.get(client, 0)
                if mine + amount > self.client_limit and mine > held:
                    return False
                self._by_client[client] = mine + amount
            self._used += amount
            return True

    def release(self, amount: int, client: Optional[str] = None) -> None:
        if self.limit <= 0 or amount <= 0:
            return
        with self._lock:
            self._used = max(0, self._used - amount)
            if client is not None and self.client_limit > 0:
                left = self._by_client.get(client, 0) - amount
                if left > 0:
                    self._by_client[client] = left
                else:
                    self._by_client.pop(client, None)

    def used(self, client: Optional[str] = None) -> int:
        with self._lock:
            return self._used if client is None else self._by_client.get(client, 0)


def _header_parse_defects(message: Any) -> List[Any]:
    """The defects the standard parser recorded about the header block itself. (It also
    records that the body of a `multipart/...` request is not a multipart document; a
    body is never parsed here, so that says nothing about the request.)"""
    import email.errors as errors

    kinds = (errors.MissingHeaderBodySeparatorDefect, errors.FirstHeaderLineIsContinuationDefect,
             errors.MisplacedEnvelopeHeaderDefect, errors.HeaderDefect)
    return [defect for defect in (getattr(message, "defects", None) or []) if isinstance(defect, kinds)]


class AppContext:
    """Everything a request handler needs; one per server."""

    def __init__(self, config: RuntimeConfig, service: AnalysisService, router: ApiRouter,
                 static_dir: str, bind_host: str, log: EventLog) -> None:
        self.config = config
        self.service = service
        self.router = router
        self.log = log
        self.static_root = os.path.realpath(static_dir)
        self.allowed_hosts = allowed_host_names(config, bind_host)
        self.body_budget = _ByteBudget(config.inflight_upload_budget(), config.inflight_upload_budget_per_client())
        self.response_budget = _ByteBudget(config.max_inflight_response_bytes,
                                           config.inflight_response_budget_per_client())
        self.pool: Any = None  # backend.workers.WorkerPool when analyses run in worker processes
        self.on_fatal: Callable[[], None] = lambda: os._exit(70)
        self.site: Any = None  # tools/site_pages.py SiteContent: generated learning pages, robots.txt, ...


def resolve_static_path(static_root: str, url_path: str) -> Optional[str]:
    """Map a URL path to a regular file inside `static_root`, or None.

    `static_root` must already be a real path. The URL path is percent-decoded
    exactly once. Dot segments, hidden files, backslashes, NULs and colons are
    refused outright; whatever is left is resolved through symlinks and must
    still be the root itself or below `root + separator` — a plain prefix test
    would also accept a sibling such as `static_backup`.
    """
    try:
        decoded = unquote(url_path, errors="strict")
    except UnicodeDecodeError:
        return None
    if "\x00" in decoded or "\\" in decoded or ":" in decoded:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in decoded):
        return None
    segments = [seg for seg in decoded.split("/") if seg != ""]
    if segments and segments[0] == "static":
        segments = segments[1:]
    if not segments or decoded.endswith("/"):
        segments.append("index.html")
    for seg in segments:
        if seg.startswith(".") or len(seg) > 255:
            return None
    if len(segments) > 16:
        return None
    candidate = os.path.realpath(os.path.join(static_root, *segments))
    if candidate != static_root and not candidate.startswith(static_root + os.sep):
        return None
    try:
        if not stat.S_ISREG(os.stat(candidate).st_mode):
            return None
    except OSError:
        return None
    return candidate


def _header_safe(value: str) -> bool:
    return not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


class BinaryStudioRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "BinaryStudio"
    sys_version = ""

    # Filled in per request
    _status = 0
    _sent = 0
    _received = 0
    _log_route = ""
    _log_doc: Optional[str] = None
    _log_code: Optional[str] = None
    _client = "-"
    _expect_continue = False
    _unread_body = 0
    _served = 0
    _entered: Optional[str] = None   # client key counted in the server's per-client request table

    @property
    def app(self) -> AppContext:
        return self.server.app  # type: ignore[attr-defined]

    def version_string(self) -> str:
        return self.server_version  # no Python version in the Server header

    # -- connection lifecycle ---------------------------------------------------
    def setup(self) -> None:
        super().setup()
        try:
            self.rfile.close()
        except Exception:
            pass
        self.rfile = _SocketReader(self.connection)  # type: ignore[assignment]
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def handle_one_request(self) -> None:
        cfg = self.app.config
        reader: _SocketReader = self.rfile  # type: ignore[assignment]
        self._status = self._sent = self._received = 0
        self._log_route, self._log_doc, self._log_code = "", None, None
        self._expect_continue = False
        self._unread_body = 0
        self.command = None  # type: ignore[assignment]
        first = self._served == 0
        try:
            reader.begin_head(
                cfg.request_timeout_seconds if first else cfg.keepalive_timeout_seconds,
                cfg.request_timeout_seconds,
                cfg.max_header_bytes,
            )
            self.raw_requestline = reader.readline(cfg.max_request_line_bytes + 1)
            if not self.raw_requestline:
                self.close_connection = True
                return
            if len(self.raw_requestline) > cfg.max_request_line_bytes:
                self.requestline, self.request_version = "", "HTTP/1.1"
                self._quiet_fail(414, "bad_request", "Request line too long.")
                return
            if not self.parse_request():
                return
            if self.request_version == "HTTP/0.9":
                self.close_connection = True
                return
            # The header block must be exactly what it looks like (see header_block_defect);
            # `headers.defects` is the standard parser's own list of what it could not read.
            defect = header_block_defect(reader.head_lines[1:])
            if defect is None and not self.raw_requestline.endswith(b"\r\n"):
                defect = "request line not terminated by CRLF"
            if defect is None and _header_parse_defects(self.headers):
                defect = "unparseable header block"
            if defect is not None:
                self._quiet_fail(400, "bad_request", "Malformed HTTP request headers.")
                return
            self._served += 1
            if self._served >= cfg.max_requests_per_connection:
                self.close_connection = True
            started = time.monotonic()
            try:
                self._serve()
            finally:
                if self._entered is not None:
                    self.server.leave_client(self._entered)  # type: ignore[attr-defined]
                    self._entered = None
                self._access_log(time.monotonic() - started)
            if self._unread_body and self.close_connection:
                self._linger_close()
        except _HeadTooLarge:
            self._quiet_fail(431, "bad_request", "Request header fields too large.")
        except socket.timeout:
            # Nothing received: an idle keep-alive connection, just close it.
            if reader.received > 0 and self._status == 0:
                self._quiet_fail(408, "timeout", "Request was not received in time.")
            self.close_connection = True
        except (ConnectionError, BrokenPipeError):
            self.close_connection = True
        except OSError:
            self.close_connection = True
        except Exception as exc:
            self.close_connection = True
            self.app.log.write_throttled("handler_error", 5, "error", "handler_error",
                                         exc=type(exc).__name__, client=self._client)
            if self._status == 0:
                self._quiet_fail(500, "internal", "Internal error.")

    def _linger_close(self) -> None:
        """After refusing a request whose body was never read: stop sending, then
        swallow what the client is still pushing for a moment. Closing at once
        would reset the connection and the client might never see the refusal."""
        sock = self.connection
        try:
            self.wfile.flush()
            sock.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + 2.0
            drained = 0
            while drained < 8 * 1024 * 1024:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                chunk = sock.recv(65536)
                if not chunk:
                    break
                drained += len(chunk)
        except OSError:
            pass

    def handle_expect_100(self) -> bool:
        # Do not invite the body yet: `_serve` answers 100 Continue only after the
        # request has passed every check that can be made from its headers.
        self._expect_continue = True
        return True

    # -- logging ------------------------------------------------------------------
    def log_message(self, format: str, *args: Any) -> None:
        # Called by the base class for malformed requests. Arguments can contain
        # the raw request line; the event log escapes them.
        try:
            message = format % args
        except Exception:
            message = format
        self.app.log.write_throttled("http_notice", 5, "info", "http_notice",
                                     client=self.client_address[0], message=message)

    def log_request(self, code: Any = "-", size: Any = "-") -> None:
        pass

    def _access_log(self, elapsed: float) -> None:
        cfg = self.app.config
        status = self._status
        if self._log_route == "/healthz" and status == 200:
            return
        if not cfg.access_log and status < 500 and self._log_code not in ("forbidden",):
            return
        fields = dict(
            client=self._client, method=self.command, route=self._log_route or "?", status=status,
            ms=round(elapsed * 1000.0, 1), bytes_in=self._received, bytes_out=self._sent,
            doc=self._log_doc, code=self._log_code,
        )
        level = "error" if status >= 500 else ("warn" if status >= 400 else "info")
        if status in (429, 503) or self._log_code == "forbidden":
            # A client being refused in bulk must not be able to fill the disk with it.
            self.app.log.write_throttled("refused", 10, level, "request", **fields)
        else:
            self.app.log.write(level, "request", **fields)

    # -- responses ----------------------------------------------------------------
    def _write_timeout(self, size: int) -> float:
        cfg = self.app.config
        rate = max(1024, int(cfg.min_transfer_bytes_per_second))
        return min(600.0, cfg.request_timeout_seconds + size / float(rate))

    def _send(self, status: int, body: Any, content_type: str, headers: Dict[str, str]) -> None:
        """Write one response. `body` is bytes, or a list of buffers to write in order
        (shared with other responses; never joined)."""
        parts: List[bytes] = [part for part in body if part] if isinstance(body, list) else ([body] if body else [])
        total = sum(len(part) for part in parts)
        head_only = self.command == "HEAD"
        reserved = 0
        if total >= RESPONSE_BUDGET_MIN_BYTES and not head_only and status not in (204, 304):
            # Large bodies in flight are bounded, in total and per client: a client that
            # asks for many and reads none would otherwise pin connections and buffers.
            if self.app.response_budget.reserve(total, self._client):
                reserved = total
            else:
                busy = ApiResponse.error(503, "busy", "The server is sending too much at once. Try again in a moment.",
                                         {"Retry-After": "2", "Cache-Control": "no-store"})
                busy.headers.update(security_headers(self.app.config, "api"))
                status, content_type, headers = 503, busy.content_type, busy.headers
                parts, total = [busy.body], len(busy.body)
                self._log_code = "busy"
        try:
            self._send_parts(status, parts, total, content_type, headers, head_only)
        finally:
            if reserved:
                self.app.response_budget.release(reserved, self._client)

    def _send_parts(self, status: int, parts: List[bytes], total: int, content_type: str,
                    headers: Dict[str, str], head_only: bool) -> None:
        self._status = status
        body = parts[0] if len(parts) == 1 else b""
        self.connection.settimeout(self._write_timeout(total))
        self.send_response(status)
        for name, value in headers.items():
            name, value = str(name), str(value)
            if not _header_safe(name) or not _header_safe(value) or ":" in name:
                continue  # never let a value end the header block early
            self.send_header(name, value)
        if content_type and status not in (204, 304):
            self.send_header("Content-Type", content_type)
        if status not in (204, 304):
            self.send_header("Content-Length", str(total))
        if self.close_connection:
            self.send_header("Connection", "close")
        send_body = total > 0 and not head_only and status not in (204, 304)
        try:
            buffered = getattr(self, "_headers_buffer", None)
            if send_body and len(parts) == 1 and total <= 65536 and isinstance(buffered, list) and buffered:
                # Small responses leave in one write (one segment where possible)
                # instead of a header packet followed by a body packet.
                self._headers_buffer = []
                self.wfile.write(b"".join(buffered) + b"\r\n" + body)
                self._sent = total
            else:
                self.end_headers()
                if send_body:
                    self._write_body(parts, total)
        except OSError:
            # The client went away or stopped reading; the log should say so.
            self._log_code = "aborted"
            raise

    def _write_body(self, parts: List[bytes], total: int) -> None:
        """Write the buffers in order, in pieces, each with its own short deadline.

        The whole body still has to fit in `_write_timeout` (the minimum transfer
        rate), but a reader that accepts nothing at all is given up on after
        `response_stall_seconds`: one piece is 256 KiB, which the minimum rate
        delivers in four seconds."""
        stall = max(1.0, float(self.app.config.response_stall_seconds))
        deadline = time.monotonic() + self._write_timeout(total)
        for part in parts:
            view = memoryview(part)
            for start in range(0, len(view), _WRITE_CHUNK):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("response not read in time")
                self.connection.settimeout(min(remaining, stall))
                piece = view[start:start + _WRITE_CHUNK]
                self.wfile.write(piece)
                self._sent += len(piece)

    def _send_api(self, resp: ApiResponse) -> None:
        self._log_code = resp.error_code()
        self._send(resp.status, resp.body_parts(), resp.content_type, resp.headers)

    def _fail(self, status: int, code: str, message: str, headers: Optional[Dict[str, str]] = None) -> None:
        """An error produced by the adapter itself. Always closes the connection."""
        self.close_connection = True
        if getattr(self, "request_version", "HTTP/0.9") == "HTTP/0.9":
            self.request_version = "HTTP/1.1"  # the base class writes no status line for 0.9
        resp = ApiResponse.error(status, code, message, headers)
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.update(security_headers(self.app.config, "api"))
        self._send_api(resp)

    def _quiet_fail(self, status: int, code: str, message: str) -> None:
        """Refuse a request that never got as far as `_serve` (and so has no access-log line)."""
        self.app.log.write_throttled("http_reject", 5, "warn", "request_rejected",
                                     client=client_key(self.client_address[0]), status=status)
        try:
            self._fail(status, code, message)
        except Exception:
            self.close_connection = True

    def send_error(self, code: int, message: Optional[str] = None, explain: Optional[str] = None) -> None:
        # The base class calls this for requests it cannot parse. Its HTML page
        # is replaced by the same JSON shape and headers as every other error.
        self._quiet_fail(int(code), "bad_request", "Malformed HTTP request.")

    # -- request handling ---------------------------------------------------------
    def _single_header(self, name: str) -> Tuple[Optional[str], int]:
        values = self.headers.get_all(name) or []
        return (values[0] if values else None), len(values)

    def _serve(self) -> None:
        app = self.app
        cfg = app.config
        method = self.command or ""
        target = self.path or ""

        # Only origin-form targets made of visible ASCII.
        if not target.startswith("/") or any(ord(ch) <= 0x20 or ord(ch) >= 0x7F for ch in target):
            self._fail(400, "bad_request", "Malformed request target.")
            return
        target = target.split("#", 1)[0]
        path, _, query_string = target.partition("?")
        self._log_route = path if len(path) <= 160 else path[:160] + "..."

        headers: Dict[str, str] = {}
        for name in self.headers.keys():
            lowered = name.lower()
            if lowered not in headers:
                headers[lowered] = ", ".join(self.headers.get_all(name) or [])

        peer = self.client_address[0]
        self._client = client_key(resolve_client_address(peer, headers, cfg))

        if path == "/healthz":
            if method not in ("GET", "HEAD"):
                self._fail(405, "method_not_allowed", "Method not allowed.", {"Allow": "GET, HEAD"})
                return
            extra = {"Cache-Control": "no-store"}
            extra.update(security_headers(cfg, "api"))
            self._drain_guard(headers)
            self._send(200, b"ok\n", "text/plain; charset=utf-8", extra)
            return

        if method not in ALLOWED_METHODS:
            self._fail(405, "method_not_allowed", "Method not allowed.", {"Allow": ", ".join(ALLOWED_METHODS)})
            return

        # Behind a trusted proxy the accept-time cap on connections per address sees
        # only the proxy, so the same number caps the requests in progress per
        # forwarded client instead. Refused at once, before anything is read or parsed.
        if cfg.trust_proxy_headers and cfg.max_connections_per_client > 0:
            if self.server.enter_client(self._client, cfg.max_connections_per_client):  # type: ignore[attr-defined]
                self._entered = self._client
            else:
                self._log_code = "busy"
                self._fail(503, "busy", "Too many requests in progress from this address.", {"Retry-After": "2"})
                return

        # One Host, and one we answer to. This is the DNS-rebinding defence: a page
        # on attacker.example that re-points its name at this server still sends
        # "Host: attacker.example".
        host, host_count = self._single_header("Host")
        if host_count != 1 or not host_allowed(host, app.allowed_hosts):
            self._log_code = "forbidden"
            app.log.write_throttled("host_rejected", 2, "warn", "host_rejected",
                                    client=self._client, host=host or "")
            self._fail(403, "forbidden", "Host not allowed.")
            return
        headers["host"] = host or ""

        # Request-smuggling hygiene. Bodies are only ever delimited by a single
        # plain Content-Length.
        if self.headers.get("Transfer-Encoding") is not None:
            self._fail(400, "bad_request", "Transfer-Encoding is not supported; send Content-Length.")
            return
        raw_length, length_count = self._single_header("Content-Length")
        content_length = 0
        if length_count > 1 or (raw_length is not None and not (raw_length.isascii() and raw_length.isdigit()
                                                                and len(raw_length) <= 15)):
            self._fail(400, "bad_request", "Malformed Content-Length.")
            return
        if raw_length is not None:
            content_length = int(raw_length)
        self._unread_body = content_length
        if content_length > 0 and method != "POST":
            self._fail(400, "bad_request", "This method does not take a request body.")
            return

        if method == "OPTIONS":
            # No Access-Control-* headers are ever sent, so a cross-origin preflight fails in the browser.
            limited = app.router.rate_limit(self._client)
            if limited is not None:
                self._send_api(limited)
                return
            extra = {"Allow": ", ".join(ALLOWED_METHODS), "Cache-Control": "no-store"}
            extra.update(security_headers(cfg, "api"))
            self._send(204, b"", "", extra)
            return

        if path == "/api" or path.startswith("/api/"):
            self._serve_api(method, path, query_string, headers, content_length, raw_length is not None)
            return

        if method == "POST":
            self._fail(405, "method_not_allowed", "Method not allowed.", {"Allow": "GET, HEAD"})
            return
        limited = app.router.rate_limit(self._client)
        if limited is not None:
            self._send_api(limited)
            return
        self._serve_static(path, query_string, headers)

    def _drain_guard(self, headers: Dict[str, str]) -> None:
        """A response sent without reading a declared body must end the connection."""
        length = headers.get("content-length", "0")
        if "transfer-encoding" in headers or length.strip() not in ("", "0"):
            self.close_connection = True

    def _serve_api(self, method: str, path: str, query_string: str, headers: Dict[str, str],
                   content_length: int, has_length: bool) -> None:
        app = self.app
        cfg = app.config
        reader: _SocketReader = self.rfile  # type: ignore[assignment]

        def reject(resp: ApiResponse) -> None:
            # The declared body has not been read, so the connection cannot be reused.
            if content_length > 0:
                self.close_connection = True
            self._send_api(resp)

        reason = cross_site_reason(headers, request_scheme(self.client_address[0], headers, cfg))
        if reason is not None:
            self._log_code = "forbidden"
            app.log.write_throttled("cross_site", 2, "warn", "cross_site_rejected",
                                    client=self._client, route=self._log_route, reason=reason)
            if content_length > 0:
                self.close_connection = True
            self._fail(403, "forbidden", "Cross-site requests are not allowed.")
            return
        if method == "HEAD":
            self._fail(405, "method_not_allowed", "Method not allowed.", {"Allow": "GET, POST"})
            return
        if method == "POST" and not has_length:
            self._fail(411, "bad_request", "Content-Length is required.")
            return

        early = app.router.preflight(method, path, headers, self._client, content_length)
        if early is not None:
            reject(early)
            return

        body = b""
        if content_length > 0:
            # Memory for the body is reserved as its bytes arrive, never from the
            # Content-Length alone: announcing an upload reserves nothing.
            held = [0]
            client = self._client

            def reserve(amount: int) -> bool:
                if not app.body_budget.reserve(amount, client, held[0]):
                    return False
                held[0] += amount
                return True

            try:
                if self._expect_continue:
                    self.connection.settimeout(cfg.request_timeout_seconds)
                    self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                rate = max(1024, int(cfg.min_transfer_bytes_per_second))
                try:
                    grace = float(cfg.body_grace_seconds)
                    if cfg.request_timeout_seconds > 0:
                        grace = min(grace, float(cfg.request_timeout_seconds))  # never more patient than for a head
                    body = reader.read_body(content_length, max(0.5, grace), float(rate), reserve)
                except socket.timeout:
                    self._received = reader.received
                    self._fail(408, "timeout", "Request body was not received in time.")
                    return
                except _BodyBudgetExceeded:
                    self._received = reader.received
                    self._log_code = "busy"
                    self._fail(503, "busy", "The server is receiving too many uploads. Try again in a moment.",
                               {"Retry-After": "3"})
                    return
                self._received = len(body)
                self._unread_body = 0
                if len(body) != content_length:
                    self._fail(400, "bad_request", "Request body ended early.")
                    return
                resp = self._dispatch(method, path, query_string, headers, body)
            finally:
                del body
                app.body_budget.release(held[0], client)
        else:
            resp = self._dispatch(method, path, query_string, headers, b"")
        self._send_api(resp)

    def _dispatch(self, method: str, path: str, query_string: str, headers: Dict[str, str],
                  body: bytes) -> ApiResponse:
        app = self.app
        try:
            pairs = parse_qsl(query_string, keep_blank_values=True, max_num_fields=64, errors="replace")
        except ValueError:
            resp = ApiResponse.error(400, "bad_request", "Too many query parameters.")
            resp.headers.update(security_headers(app.config, "api"))
            return resp
        query: Dict[str, str] = {}
        for key, value in pairs:
            query.setdefault(key, value)
        header_doc = headers.get("x-bs-doc")
        self._log_doc = (redact_doc_id(unquote(header_doc, errors="replace") if header_doc else query.get("doc"))
                         or ("path:*" if "path" in query else None))
        req = ApiRequest(method, path, query, body, headers, self._client)
        resp = app.router.handle(req, preflighted=True)
        return resp

    def _serve_static(self, path: str, query_string: str, headers: Dict[str, str]) -> None:
        app = self.app
        cfg = app.config
        base_headers = security_headers(cfg, "page")
        if app.site is not None and self._serve_site(path, headers, base_headers):
            return
        real = resolve_static_path(app.static_root, path)
        if real is None and app.site is not None and "text/html" in headers.get("accept", ""):
            # Browsers get the site's 404 page; API-style clients keep the JSON error below.
            page = resolve_static_path(app.static_root, "/404.html")
            if page is not None:
                with open(page, "rb") as handle:
                    body404 = handle.read(1 << 20)
                base_headers.update({"Content-Security-Policy": cfg.content_security_policy("content"),
                                     "Cache-Control": "no-store"})
                self._send(404, body404, CONTENT_TYPES[".html"], base_headers)
                return
        if real is None:
            resp = ApiResponse.error(404, "not_found", "Not found.")
            resp.headers.update(base_headers)
            resp.headers["Cache-Control"] = "no-store"
            self._send_api(resp)
            return
        try:
            handle = open(real, "rb")
        except OSError:
            resp = ApiResponse.error(404, "not_found", "Not found.")
            resp.headers.update(base_headers)
            self._send_api(resp)
            return
        with handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode):
                resp = ApiResponse.error(404, "not_found", "Not found.")
                resp.headers.update(base_headers)
                self._send_api(resp)
                return
            ext = os.path.splitext(real)[1].lower()
            ctype = CONTENT_TYPES.get(ext, "application/octet-stream")
            if ext in (".html", ".htm") and os.path.basename(real) != "index.html":
                # Site pages (about, privacy, terms, 404): the content-page CSP, never the app's.
                base_headers["Content-Security-Policy"] = cfg.content_security_policy("content")
            etag = '"%x-%x"' % (getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)), st.st_size)
            if ext in (".html", ".htm") or cfg.static_max_age_seconds <= 0:
                cache = "no-cache"
            elif any(part.startswith("v=") for part in query_string.split("&")):
                cache = "public, max-age=31536000, immutable"
            else:
                cache = "public, max-age=%d" % int(cfg.static_max_age_seconds)
            base_headers.update({"Cache-Control": cache, "ETag": etag})
            candidates = [tag.strip() for tag in headers.get("if-none-match", "").split(",")]
            if etag in candidates or ("W/" + etag) in candidates:
                self._send(304, b"", "", base_headers)
                return
            # Static files are ours and small; one read keeps Content-Length exact.
            body = handle.read(st.st_size + 1)
        self._send(200, body, ctype, base_headers)

    def _serve_site(self, path: str, headers: Dict[str, str], base_headers: Dict[str, str]) -> bool:
        """Generated site files (tools/site_pages.py), from memory. False when `path` is not one."""
        cfg = self.app.config
        try:
            hit = self.app.site.lookup(path)
        except Exception as exc:  # a generator failure must not take static serving down with it
            self.app.log.write_throttled("site_error", 1, "error", "site_error", exc=type(exc).__name__)
            return False
        if hit is None:
            return False
        out = dict(base_headers)
        if hit.location:
            out.update({"Location": hit.location, "Cache-Control": "no-cache"})
            self._send(hit.status, b"", "", out)
            return True
        if hit.kind == "content":
            out["Content-Security-Policy"] = cfg.content_security_policy("content")
        import hashlib

        etag = '"s%s"' % hashlib.sha256(hit.body).hexdigest()[:20]
        out.update({"Cache-Control": "no-cache", "ETag": etag})
        if etag in [tag.strip() for tag in headers.get("if-none-match", "").split(",")]:
            self._send(304, b"", "", out)
        else:
            self._send(hit.status, hit.body, hit.content_type, out)
        return True


def _load_site_layer(workspace_root: str, config: RuntimeConfig, service: AnalysisService, log: EventLog) -> Any:
    """tools/site_pages.py, if this installation ships it (it is optional: without it there are no
    generated pages and ads stay off, because their CSP and validation live there)."""
    import importlib.util

    path = os.path.join(os.path.abspath(workspace_root), "tools", "site_pages.py")
    if not os.path.isfile(path):
        if config.ads.get("enabled"):
            log.write("warn", "ads_disabled", reason="tools/site_pages.py is not installed")
            config.ads = {"enabled": False, "provider": None, "slots": {}, "options": {}}
        return None
    spec = importlib.util.spec_from_file_location("binarystudio_site_pages", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module.load_for_server(workspace_root, config, service, log)  # raises ValueError on a bad ads config


MachOViewerRequestHandler = BinaryStudioRequestHandler


class BinaryStudioServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a ceiling on concurrent connections."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    _REJECT_BODY = b'{"error":"Server is at capacity.","code":"busy"}'
    _REJECT = (b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 2\r\nConnection: close\r\n"
               b"Content-Type: application/json; charset=utf-8\r\nContent-Length: "
               + str(len(_REJECT_BODY)).encode("ascii") + b"\r\n\r\n" + _REJECT_BODY)

    def __init__(self, address: Tuple[str, int], handler: type, app: AppContext) -> None:
        self.app = app
        self._conn_lock = threading.Lock()
        self._conn_total = 0
        self._conn_by_client: Dict[str, int] = {}
        self._req_by_client: Dict[str, int] = {}
        self._stop_housekeeping = threading.Event()
        self._housekeeper: Optional[threading.Thread] = None
        self._parked: "collections.deque" = collections.deque()
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler)

    # -- convenience for callers and tests
    @property
    def router(self) -> ApiRouter:
        return self.app.router

    @property
    def service(self) -> AnalysisService:
        return self.app.service

    @property
    def config(self) -> RuntimeConfig:
        return self.app.config

    def server_bind(self) -> None:
        # HTTPServer.server_bind also resolves the host name with getfqdn(), which can
        # stall for seconds where DNS is unavailable; nothing here needs that name.
        import socketserver

        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = self.server_address[1]

    def enter_client(self, key: str, limit: int) -> bool:
        """Count one more request in progress for a (forwarded) client; False at the limit."""
        with self._conn_lock:
            current = self._req_by_client.get(key, 0)
            if limit > 0 and current >= limit:
                return False
            self._req_by_client[key] = current + 1
            return True

    def leave_client(self, key: str) -> None:
        with self._conn_lock:
            left = self._req_by_client.get(key, 0) - 1
            if left > 0:
                self._req_by_client[key] = left
            else:
                self._req_by_client.pop(key, None)

    def prewarm_workers(self) -> None:
        """Start the analysis worker processes in the background (no-op without a pool)."""
        pool = self.app.pool
        if pool is not None:
            threading.Thread(target=pool.prewarm, name="binarystudio-prewarm", daemon=True).start()

    def _admit(self, key: str) -> bool:
        cfg = self.app.config
        # Behind a trusted proxy every connection comes from the proxy's address; the
        # per-client cap is then applied per request, to the forwarded address (`_serve`).
        per_client = 0 if cfg.trust_proxy_headers else cfg.max_connections_per_client
        with self._conn_lock:
            if cfg.max_connections > 0 and self._conn_total >= cfg.max_connections:
                return False
            if per_client > 0 and self._conn_by_client.get(key, 0) >= per_client:
                return False
            self._conn_total += 1
            self._conn_by_client[key] = self._conn_by_client.get(key, 0) + 1
            return True

    def _release(self, key: str) -> None:
        with self._conn_lock:
            self._conn_total = max(0, self._conn_total - 1)
            left = self._conn_by_client.get(key, 0) - 1
            if left > 0:
                self._conn_by_client[key] = left
            else:
                self._conn_by_client.pop(key, None)

    def open_connections(self) -> int:
        with self._conn_lock:
            return self._conn_total

    def process_request(self, request: Any, client_address: Any) -> None:
        key = client_key(client_address[0])
        if not self._admit(key):
            # Runs on the accept loop: answer without ever blocking. The socket is
            # then parked half-closed for a moment instead of closed, because closing
            # while the client's request is still arriving resets the connection and
            # the client (usually the reverse proxy) would never see the 503.
            try:
                request.setblocking(False)
                request.send(self._REJECT)
                request.shutdown(socket.SHUT_WR)
                self._parked.append((time.monotonic(), request))
            except OSError:
                self.shutdown_request(request)
            self._reap_parked()
            self.app.log.write_throttled("conn_rejected", 1, "warn", "connection_rejected", client=key)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release(key)
            raise

    def _reap_parked(self, everything: bool = False) -> None:
        """Close refused connections that have had their moment; never keep more than 64."""
        now = time.monotonic()
        while self._parked and (everything or len(self._parked) > 64 or now - self._parked[0][0] > 1.0):
            try:
                _, sock = self._parked.popleft()
            except IndexError:
                break
            try:
                sock.close()
            except OSError:
                pass

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release(client_key(client_address[0]))

    def handle_error(self, request: Any, client_address: Any) -> None:
        import sys

        exc_type = sys.exc_info()[0]
        self.app.log.write_throttled("server_error", 5, "error", "connection_error",
                                     exc=exc_type.__name__ if exc_type else None)

    # -- background upkeep --------------------------------------------------------
    def start_housekeeping(self, interval: float = 15.0) -> None:
        if self._housekeeper is not None:
            return

        def loop() -> None:
            app = self.app
            while not self._stop_housekeeping.wait(interval):
                try:
                    app.router.housekeeping()
                    hard = app.config.hard_parse_timeout_seconds
                    if hard > 0 and app.service.oldest_parse_age() > hard:
                        # Last resort, for analyses running in server threads (worker
                        # processes off or unavailable): a thread cannot be killed, and
                        # leaving it would hold an analysis slot for good, so hand the
                        # process back to its supervisor. With the worker pool an overrun
                        # is killed at the parse timeout and this is never reached.
                        app.log.write("critical", "parse_stuck",
                                      seconds=round(app.service.oldest_parse_age(), 1),
                                      action="exiting for supervisor restart")
                        app.on_fatal()
                except Exception:
                    pass

        self._housekeeper = threading.Thread(target=loop, name="binarystudio-housekeeping", daemon=True)
        self._housekeeper.start()

    def service_actions(self) -> None:
        # Called by serve_forever between polls (every half second by default).
        if self._parked:
            self._reap_parked()

    def server_close(self) -> None:
        self._stop_housekeeping.set()
        self._reap_parked(everything=True)
        pool = self.app.pool
        if pool is not None:
            self.app.service.set_executor(None)
            pool.close()
        super().server_close()


def _ensure_fixtures(workspace_root: str, config: RuntimeConfig, log: EventLog) -> None:
    """Build the sample binaries when that is possible and allowed.

    In restricted modes nothing is built if the files are already there (a
    deployed image ships them and its filesystem may be read-only), and a
    failure to build is not fatal: the missing presets are just reported as
    unavailable.
    """
    fixtures_dir = os.path.join(os.path.abspath(workspace_root), "fixtures")
    present = all(os.path.isfile(os.path.join(fixtures_dir, name)) for _, _, name, _, _ in SYNTHETIC_PRESETS)
    if config.mode != "local" and present:
        return
    try:
        ensure_fixtures(workspace_root)
    except Exception as exc:
        if config.mode == "local" and not present:
            raise
        log.write("warn", "fixtures_unavailable", exc=type(exc).__name__)


def create_server(
    workspace_root: str,
    host: str = "127.0.0.1",
    port: int = 8421,
    initial_file: Optional[str] = None,
    config: Optional[RuntimeConfig] = None,
    log: Optional[EventLog] = None,
    housekeeping_interval: float = 15.0,
) -> BinaryStudioServer:
    """Build a server. `config` defaults to the process-wide runtime config (local mode).

    Raises ValueError when asked to expose a local-mode server on a
    non-loopback address without `config.allow_unsafe_bind`.
    """
    config = config if config is not None else runtime.get_config()
    log = log if log is not None else LOG
    if config.mode == "wasm":
        raise ValueError("The wasm runtime mode has no HTTP server.")
    if config.mode == "local" and not is_loopback_host(host) and not config.allow_unsafe_bind:
        raise ValueError(
            f"Refusing to listen on {host!r} in local mode: local mode lets anyone who can reach the port "
            "read any file this user can read. Use --public to host BinaryStudio for other people "
            "(or, to really do this, --i-know-this-is-unsafe)."
        )

    _ensure_fixtures(workspace_root, config, log)
    service = AnalysisService(workspace_root, config)
    router = build_router(service, config, log=log)
    if config.mode != "local":
        service.warm_presets()
    elif initial_file and os.path.isfile(initial_file):
        service.load_file(initial_file)
        config.initial_doc = "path:" + os.path.abspath(initial_file)

    static_dir = os.path.join(os.path.abspath(workspace_root), "static")
    app = AppContext(config, service, router, static_dir, host, log)
    if config.parse_worker_count() > 0:
        # From here on uploads are analysed in worker processes (started on first use,
        # or by `prewarm_workers`). The presets above are our own files and were parsed
        # in-process before the server accepts anything.
        from .workers import WorkerPool

        app.pool = WorkerPool(config, log)
        service.set_executor(app.pool)
    app.site = _load_site_layer(workspace_root, config, service, log)
    if app.site is not None and config.mode != "local":
        app.site.warm()  # generated once at start-up; local mode generates on the first /learn/ request

    class BoundHandler(BinaryStudioRequestHandler):
        pass

    # Kept for code that reached these through the handler class.
    BoundHandler.service = service  # type: ignore[attr-defined]
    BoundHandler.static_dir = static_dir  # type: ignore[attr-defined]

    server = BinaryStudioServer((host, port), BoundHandler, app)
    server.start_housekeeping(housekeeping_interval)
    return server
