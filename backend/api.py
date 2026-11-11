"""
Transport-agnostic API router.

`ApiRouter.handle(ApiRequest) -> ApiResponse` is the whole API surface. The HTTP
server in `server.py` is one adapter over it; the WASM build calls `handle`
directly inside Pyodide. Nothing in this module opens a socket, starts a thread
or imports anything platform specific.

What lives here, so that every transport gets it and it can be tested without
a socket:

  * routing, parameter parsing and the error shape `{"error", "code"}`
  * per-client rate limiting (token buckets, memory bounded)
  * request-size limits, decided from the headers before a body is read
  * the security headers for every response
  * the pure checks an HTTP adapter needs: Host allowlist, cross-site request
    detection, client address derivation
  * the structured event log

New endpoints: `router.register("GET", "/api/thing", handler)` inside
`build_router` (or a `register_<area>_routes(router)` it calls). A handler takes
the `ApiRequest` and returns a dict (sent as JSON) or an `ApiResponse`
(`ApiResponse.binary(data, filename)` for downloads); to fail it raises one of
the `ApiError` types from `runtime`. A route ending in `/*` matches by prefix.
"""

import base64
import binascii
import hashlib
import json
import secrets
import sys
import threading
import time
import traceback
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import quote, unquote, urlsplit

from . import runtime
from .runtime import (
    API_CSP,
    ApiError,
    BadRequest,
    Forbidden,
    ParseBudgetExceeded,
    RuntimeConfig,
    TooLarge,
    encode_json,
    sanitize_filename,
)

JSON_TYPE = "application/json; charset=utf-8"

# The only content types a cross-site HTML form (or a no-preflight fetch) can
# send. No endpoint accepts them, so a request body always needs a preflight
# that this server never grants.
FORM_CONTENT_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")

LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")

# A document id is a bearer capability, and URLs end up in proxy logs, browser
# history and Referer headers. Clients therefore send ids in these request headers
# (percent-encoded) instead of the query string; the query form still works and a
# header wins over it. Maps header -> the query parameter it stands for.
DOC_ID_HEADERS = (("x-bs-doc", "doc"), ("x-bs-doc-a", "a"), ("x-bs-doc-b", "b"))

ETAG_MIN_BYTES = 4096                    # smaller GET answers are not worth a validator
GZIP_MIN_BYTES = 1024                    # smaller bodies are sent as they are
GZIP_DYNAMIC_MAX_BYTES = 8 * 1024 * 1024  # larger bodies are gzipped only from a cached buffer


def _bounded_int(text: str) -> int:
    # Converting a decimal string to an int is quadratic in its length, so a
    # megabyte of digits would otherwise buy seconds of CPU.
    if len(text) > 40:
        raise ValueError("integer too long")
    return int(text)


# ---------------------------------------------------------------------------
# Request / response
# ---------------------------------------------------------------------------
class ApiRequest:
    __slots__ = ("method", "route", "query", "body", "headers", "client_id")

    def __init__(self, method: str, route: str, query: Optional[Dict[str, str]] = None, body: bytes = b"",
                 headers: Optional[Dict[str, str]] = None, client_id: str = "local") -> None:
        self.method = str(method).upper()
        self.route = route
        self.query = dict(query or {})
        self.body = body or b""
        self.headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        self.client_id = client_id

    def json(self) -> Dict[str, Any]:
        """The body as a JSON object ({} when there is no body)."""
        if not self.body:
            return {}
        ctype = self.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype and "json" not in ctype:
            raise ApiError("Expected a JSON body (Content-Type: application/json).", status=415)
        try:
            data = json.loads(self.body.decode("utf-8"), parse_int=_bounded_int)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise BadRequest("Request body is not valid JSON.")
        if not isinstance(data, dict):
            raise BadRequest("Request body must be a JSON object.")
        return data


class ApiResponse:
    """status, headers and a body.

    The body is `body` (bytes) or, for large answers assembled from buffers that
    other responses use too, `parts`: a list of bytes objects that a transport
    writes one after another without ever joining them. Reading `body` of such a
    response joins them (the in-browser build and tests do; the HTTP server never
    does). `etag` is a ready validator for the body when the handler has one, and
    `gzip_parts` a function that returns the same body gzipped, again as parts
    built from shared buffers; the router decides whether either is used.
    """

    __slots__ = ("status", "_body", "parts", "content_type", "headers", "etag", "gzip_parts")

    def __init__(self, status: int = 200, body: Optional[bytes] = b"", content_type: str = JSON_TYPE,
                 headers: Optional[Dict[str, str]] = None, parts: Optional[List[bytes]] = None,
                 etag: Optional[str] = None, gzip_parts: Optional[Callable[[], List[bytes]]] = None) -> None:
        self.status = status
        self._body = None if parts is not None else (body or b"")
        self.parts = parts
        self.content_type = content_type
        self.headers = dict(headers or {})
        self.etag = etag
        self.gzip_parts = gzip_parts

    @property
    def body(self) -> bytes:
        if self._body is None:
            self._body = b"".join(self.parts or [])
        return self._body

    @body.setter
    def body(self, value: bytes) -> None:
        self._body = value
        self.parts = None

    def body_parts(self) -> List[bytes]:
        """The body as the buffers to write, in order."""
        if self.parts is not None:
            return self.parts
        return [self._body] if self._body else []

    def body_size(self) -> int:
        if self.parts is not None:
            return sum(len(part) for part in self.parts)
        return len(self._body or b"")

    @staticmethod
    def json(payload: Any, status: int = 200) -> "ApiResponse":
        return ApiResponse(status, encode_json(payload), JSON_TYPE)

    @staticmethod
    def raw_json(encoded: bytes, status: int = 200) -> "ApiResponse":
        """A response from JSON that is already encoded."""
        return ApiResponse(status, encoded, JSON_TYPE)

    @staticmethod
    def document(entry: Any, envelope: Optional[Dict[str, Any]] = None) -> "ApiResponse":
        """The JSON of a cached document (a `service.DocEntry`), or — with `envelope`
        — a JSON object with those members plus `"document": <the document>`.

        Neither form copies the document: the response is made of the entry's one
        JSON buffer (and, gzipped, of its one deflate buffer) plus a few small pieces.
        """
        body = entry.json_bytes()
        if envelope is None:
            def gzipped() -> List[bytes]:
                return runtime.gzip_from_segments([entry.deflated()], entry.crc32(), len(body))

            return ApiResponse(200, None, JSON_TYPE, parts=[body], etag=entry.etag(), gzip_parts=gzipped)
        head = encode_json(envelope)[:-1] + (b',"document":' if envelope else b'"document":')
        tail = b"}"

        def gzipped_envelope() -> List[bytes]:
            import zlib

            crc = zlib.crc32(tail, zlib.crc32(body, zlib.crc32(head)))
            segments = [runtime.deflate_segment(head), entry.deflated(), runtime.deflate_segment(tail)]
            return runtime.gzip_from_segments(segments, crc, len(head) + len(body) + len(tail))

        return ApiResponse(200, None, JSON_TYPE, parts=[head, body, tail], gzip_parts=gzipped_envelope)

    @staticmethod
    def binary(data: bytes, filename: str, status: int = 200,
               content_type: str = "application/octet-stream") -> "ApiResponse":
        """A file download. The name is sanitised; it cannot break out of the header."""
        name = sanitize_filename(filename, default="download.bin")
        ascii_name = "".join(ch if (ch.isalnum() and ord(ch) < 128) or ch in "._-" else "_" for ch in name)
        disposition = f"attachment; filename=\"{ascii_name or 'download.bin'}\"; filename*=UTF-8''{quote(name, safe='')}"
        # bytes(data) of a bytes object is that object: a download shares the cached file.
        return ApiResponse(status, bytes(data), content_type, {"Content-Disposition": disposition})

    @staticmethod
    def error(status: int, code: str, message: str, headers: Optional[Dict[str, str]] = None) -> "ApiResponse":
        return ApiResponse(status, encode_json({"error": message, "code": code}), JSON_TYPE, headers)

    def error_code(self) -> Optional[str]:
        """The machine code of an error response, for logs."""
        if self.status < 400 or not self.content_type.startswith("application/json"):
            return None
        try:
            return json.loads(self.body.decode("utf-8")).get("code")
        except (ValueError, UnicodeDecodeError, AttributeError):
            return None


# ---------------------------------------------------------------------------
# Structured event log
# ---------------------------------------------------------------------------
class EventLog:
    """One JSON object per line on stderr.

    Every value is serialised with `ensure_ascii`, so nothing a client sends
    (file names, paths, header values) can add a line or smuggle control
    characters into the log. Strings are truncated. Uploaded bytes are never
    passed in.
    """

    MAX_VALUE_CHARS = 240

    def __init__(self, stream: Any = None, clock: Callable[[], float] = time.time) -> None:
        self._stream = stream
        self._clock = clock
        self._lock = threading.Lock()
        self._throttle: Dict[str, List[float]] = {}

    def _trim(self, value: Any) -> Any:
        if isinstance(value, str):
            return value if len(value) <= self.MAX_VALUE_CHARS else value[: self.MAX_VALUE_CHARS] + "..."
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        if isinstance(value, (list, tuple)):
            return [self._trim(item) for item in list(value)[:16]]
        return self._trim(str(value))

    def write(self, level: str, event: str, **fields: Any) -> None:
        now = self._clock()
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % int((now % 1) * 1000)
        record: Dict[str, Any] = {"ts": stamp, "level": level, "event": event}
        for key, value in fields.items():
            if value is not None:
                record[key] = self._trim(value)
        line = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        stream = self._stream if self._stream is not None else sys.stderr
        with self._lock:
            try:
                stream.write(line)
                stream.flush()
            except Exception:
                pass

    def write_throttled(self, key: str, per_second: float, level: str, event: str, **fields: Any) -> None:
        """Like `write`, but at most `per_second` lines per key; the next line that
        does get through carries how many were dropped. Keeps a flood of rejected
        requests from becoming a flood of log lines."""
        now = self._clock()
        with self._lock:
            state = self._throttle.setdefault(key, [now, 0.0, 0.0])  # window start, written, suppressed
            if now - state[0] >= 1.0:
                state[0], state[1] = now, 0.0
            if state[1] >= per_second:
                state[2] += 1
                return
            state[1] += 1
            suppressed, state[2] = int(state[2]), 0.0
        if suppressed:
            fields["suppressed"] = suppressed
        self.write(level, event, **fields)


LOG = EventLog()


def redact_doc_id(doc: Optional[str]) -> Optional[str]:
    """A document id as it may appear in logs: the kind, never the capability."""
    if not doc:
        return None
    doc = str(doc)
    if doc.startswith("preset:"):
        name = doc[len("preset:"):]
        return doc if (0 < len(name) <= 48 and all(ch.isalnum() or ch == "_" for ch in name)) else "preset:?"
    if doc.startswith("path:"):
        return "path:*"
    if doc[:2] in ("u_", "p_"):
        return doc[:2] + "*"
    return "?"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class TokenBucketLimiter:
    """Per-key token buckets with a hard cap on how many keys are remembered.

    `rate_per_minute <= 0` disables the limiter. When the table is full the
    least recently seen key is forgotten.
    """

    def __init__(self, rate_per_minute: float, burst: float = 0, max_keys: int = 20000,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.rate = max(0.0, float(rate_per_minute)) / 60.0
        self.burst = float(burst) if burst and burst > 0 else max(1.0, float(rate_per_minute) / 2.0)
        self.max_keys = max(1, int(max_keys))
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: "OrderedDict[str, List[float]]" = OrderedDict()

    @property
    def enabled(self) -> bool:
        return self.rate > 0

    def allow(self, key: str, cost: float = 1.0) -> Tuple[bool, float]:
        """(allowed, seconds until a retry could succeed)."""
        if not self.enabled:
            return True, 0.0
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = [self.burst, now]
                self._buckets[key] = bucket
                while len(self._buckets) > self.max_keys:
                    self._buckets.popitem(last=False)
            else:
                bucket[0] = min(self.burst, bucket[0] + (now - bucket[1]) * self.rate)
                bucket[1] = now
                self._buckets.move_to_end(key)
            if bucket[0] >= cost:
                bucket[0] -= cost
                return True, 0.0
            return False, (cost - bucket[0]) / self.rate

    def charge(self, key: str, cost: float) -> None:
        """Take `cost` tokens after the fact, for work whose size is only known once
        it is done (a response's bytes). The bucket may go into debt, by at most one
        burst, and the key is refused until it has refilled past zero."""
        if not self.enabled or cost <= 0:
            return
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = [self.burst, now]
                self._buckets[key] = bucket
                while len(self._buckets) > self.max_keys:
                    self._buckets.popitem(last=False)
            else:
                bucket[0] = min(self.burst, bucket[0] + (now - bucket[1]) * self.rate)
                bucket[1] = now
                self._buckets.move_to_end(key)
            bucket[0] = max(-self.burst, bucket[0] - cost)

    def prune(self) -> int:
        """Forget keys whose bucket has refilled; they would start full anyway."""
        if not self.enabled:
            return 0
        now = self._clock()
        with self._lock:
            idle = [key for key, (tokens, last) in self._buckets.items()
                    if tokens + (now - last) * self.rate >= self.burst]
            for key in idle:
                del self._buckets[key]
            return len(idle)

    def __len__(self) -> int:
        with self._lock:
            return len(self._buckets)


# ---------------------------------------------------------------------------
# Pure checks for HTTP adapters
# ---------------------------------------------------------------------------
def split_host_port(value: str) -> Tuple[str, Optional[str]]:
    """('example.com', '8443') from a Host header or URL authority. Lower-cased, no brackets."""
    value = (value or "").strip().lower()
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return "", None
        host, rest = value[1:end], value[end + 1:]
        if rest and not rest.startswith(":"):
            return "", None
        port = rest[1:] if rest.startswith(":") else None
    elif value.count(":") == 1:
        host, port = value.split(":")
    elif value.count(":") > 1:
        return "", None  # an IPv6 literal must be bracketed in a Host header
    else:
        host, port = value, None
    if port is not None and not (port.isdigit() and len(port) <= 5):
        return "", None
    return host.rstrip("."), (port or None)


def is_loopback_host(host: str) -> bool:
    host = (host or "").strip().lower().strip("[]")
    if host == "localhost":
        return True
    ip = normalize_ip(host)
    return ip is not None and ip.is_loopback


def allowed_host_names(config: RuntimeConfig, bind_host: str = "127.0.0.1") -> List[str]:
    """The Host names this server answers to.

    Loopback names are always accepted (health checks, local use). A specific
    bind address is accepted. Anything else — in particular a public domain —
    must be configured; with a wildcard bind nothing more is assumed, which is
    what defeats DNS rebinding.
    """
    names = list(LOOPBACK_HOSTS)
    bind = (bind_host or "").strip().lower().strip("[]")
    if bind and bind not in ("0.0.0.0", "::", "") and bind not in names:
        names.append(bind)
    for item in config.allowed_hosts or []:
        item = str(item).strip().lower()
        if item == "*":
            return ["*"]
        if item.startswith("."):
            host = item
        else:
            host = split_host_port(item)[0]
        if host and host not in names:
            names.append(host)
    return names


def host_allowed(host_header: Optional[str], allowed: List[str]) -> bool:
    if "*" in allowed:
        return True
    if not host_header:
        return False
    host, _port = split_host_port(host_header)
    if not host:
        return False
    for name in allowed:
        if name.startswith("."):
            if host == name[1:] or host.endswith(name):
                return True
        elif host == name:
            return True
    return False


def request_scheme(peer: str, headers: Dict[str, str], config: RuntimeConfig) -> Optional[str]:
    """The scheme the browser used for this request, as far as this server can know.

    The listener itself only speaks plain HTTP. Behind a trusted proxy the proxy
    says what the client used (X-Forwarded-Proto; the last value is the one the
    proxy nearest to us wrote). A trusted proxy that sends no such header leaves
    it unknown (None)."""
    if not config.trust_proxy_headers or not is_internal_address(peer):
        return "http"
    forwarded = headers.get("x-forwarded-proto", "")
    value = forwarded.split(",")[-1].strip().lower() if forwarded else ""
    return value if value in ("http", "https") else None


def cross_site_reason(headers: Dict[str, str], scheme: Optional[str] = None) -> Optional[str]:
    """Why a request must be refused as cross-site, or None when it is acceptable.

    `scheme` is the scheme this request arrived over ('http' or 'https', see
    `request_scheme`); when given, an Origin with the other scheme is another
    origin even if host and port match. None skips that comparison.

    Browsers label every request with `Sec-Fetch-Site`, and send `Origin` on
    every cross-origin request that carries a body. A request that says it
    comes from another site or another origin is refused; `same-site` is not
    good enough (another port on localhost is same-site). Requests with neither
    header come from non-browser clients, which hold no ambient authority.
    """
    site = headers.get("sec-fetch-site")
    if site is not None and site.strip().lower() not in ("same-origin", "none"):
        return "cross-site request (Sec-Fetch-Site: %s)" % site.strip().lower()[:20]
    origin = headers.get("origin")
    if origin is None:
        return None
    origin = origin.strip().lower()
    if origin == "null" or not origin:
        return "opaque origin"
    try:
        parts = urlsplit(origin)
        o_host, o_port = parts.hostname or "", parts.port
    except ValueError:
        return "malformed Origin"
    if parts.scheme not in ("http", "https") or not o_host:
        return "unsupported Origin"
    if scheme in ("http", "https") and parts.scheme != scheme:
        if scheme == "http":
            return ("Origin is https but the request arrived over plain http "
                    "(behind a TLS proxy, start the server with --trust-proxy)")
        return "Origin scheme does not match"
    default_port = 443 if parts.scheme == "https" else 80
    h_host, h_port = split_host_port(headers.get("host", ""))
    if not h_host:
        return "missing Host"
    if o_host.rstrip(".") != h_host:
        return "Origin does not match Host"
    if (o_port or default_port) != (int(h_port) if h_port else default_port):
        return "Origin does not match Host"
    return None


def normalize_ip(address: str) -> Optional[Any]:
    """An ipaddress object for `address` (IPv4-mapped IPv6 unwrapped), or None."""
    try:
        import ipaddress

        ip = ipaddress.ip_address((address or "").strip().split("%")[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


# Where a reverse proxy in front of this server can be connecting from: loopback,
# RFC 1918, carrier-grade NAT space (used by several container platforms),
# link-local, and their IPv6 counterparts. Deliberately an explicit list:
# `ipaddress.is_private` also covers documentation and other special ranges.
_INTERNAL_NETWORKS = (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)
_internal_networks_cache: List[Any] = []


def is_internal_address(address: str) -> bool:
    ip = normalize_ip(address)
    if ip is None:
        return False
    if not _internal_networks_cache:
        import ipaddress

        _internal_networks_cache.extend(ipaddress.ip_network(net) for net in _INTERNAL_NETWORKS)
    return any(ip.version == net.version and ip in net for net in _internal_networks_cache)


def client_key(address: str) -> str:
    """The rate-limit identity for an IP address. IPv6 clients are keyed by /64,
    because one subscriber controls a whole /64 and could otherwise never run dry."""
    ip = normalize_ip(address)
    if ip is None:
        return "invalid"
    if ip.version == 6:
        return str(type(ip)((int(ip) >> 64) << 64)) + "/64"
    return str(ip)


def resolve_client_address(peer: str, headers: Dict[str, str], config: RuntimeConfig) -> str:
    """The client's address: the socket peer, or — only with `trust_proxy_headers`
    and only when the peer is a loopback/private address (`is_internal_address`),
    i.e. plausibly the proxy —
    the last entry of X-Forwarded-For. The last entry is the one the trusted proxy
    appended; everything before it is whatever the client chose to send."""
    if not config.trust_proxy_headers:
        return peer
    if not is_internal_address(peer):
        return peer
    forwarded = headers.get("x-forwarded-for", "")
    candidate = forwarded.split(",")[-1].strip() if forwarded else ""
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    elif candidate.count(":") == 1:
        candidate = candidate.split(":")[0]
    return candidate if normalize_ip(candidate) is not None else peer


def security_headers(config: RuntimeConfig, kind: str = "api") -> Dict[str, str]:
    """Headers for every response. `kind` is 'page' for HTML and static assets,
    'api' for JSON and downloads."""
    headers = {
        "Content-Security-Policy": config.content_security_policy() if kind == "page" else API_CSP,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": config.permissions_policy,
    }
    if config.hsts_seconds > 0:
        headers["Strict-Transport-Security"] = "max-age=%d" % int(config.hsts_seconds)
    return headers


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
Handler = Callable[[ApiRequest], Union[Dict[str, Any], ApiResponse, None]]
BodyLimit = Union[int, Callable[[RuntimeConfig, Dict[str, str]], int], None]


class _Route:
    __slots__ = ("method", "route", "handler", "max_body", "bucket")

    def __init__(self, method: str, route: str, handler: Handler, max_body: BodyLimit, bucket: Optional[str]) -> None:
        self.method = method
        self.route = route
        self.handler = handler
        self.max_body = max_body
        self.bucket = bucket


class ApiRouter:
    def __init__(self, service: Any, config: Optional[RuntimeConfig] = None, log: Optional[EventLog] = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.service = service
        self.config = config if config is not None else getattr(service, "config", None) or runtime.get_config()
        self.log = log if log is not None else LOG
        self._routes: Dict[Tuple[str, str], _Route] = {}
        self._prefix_routes: List[_Route] = []
        cfg = self.config
        self.limiter = TokenBucketLimiter(cfg.rate_limit_per_minute, cfg.rate_limit_burst,
                                          cfg.rate_limiter_max_clients, clock)
        self.upload_limiter = TokenBucketLimiter(cfg.upload_rate_limit_per_minute, cfg.upload_rate_limit_burst,
                                                 cfg.rate_limiter_max_clients, clock)

    # -- registration ---------------------------------------------------------
    def register(self, method: str, route: str, handler: Handler, max_body: BodyLimit = None,
                 bucket: Optional[str] = None) -> None:
        """Add an endpoint.

        `route` is an exact path, or a prefix when it ends in `/*`.
        `max_body` bounds the request body (default: config.max_json_body_bytes).
        `bucket="upload"` also charges the stricter upload rate limit.
        """
        method = str(method).upper()
        if not route.startswith("/"):
            raise ValueError("route must start with '/'")
        entry = _Route(method, route, handler, max_body, bucket)
        if route.endswith("/*"):
            self._prefix_routes = [r for r in self._prefix_routes if (r.method, r.route) != (method, route)]
            self._prefix_routes.append(entry)
            self._prefix_routes.sort(key=lambda r: len(r.route), reverse=True)
        else:
            self._routes[(method, route)] = entry

    def routes(self) -> List[Tuple[str, str]]:
        return sorted(list(self._routes.keys()) + [(r.method, r.route) for r in self._prefix_routes])

    def _find(self, method: str, route: str) -> Tuple[Optional[_Route], List[str]]:
        """(route for this method, methods that exist for this path)."""
        found = self._routes.get((method, route))
        methods = [m for (m, r) in self._routes if r == route]
        for entry in self._prefix_routes:
            if route.startswith(entry.route[:-1]):
                methods.append(entry.method)
                if found is None and entry.method == method:
                    found = entry
        return found, sorted(set(methods))

    # -- limits ---------------------------------------------------------------
    def rate_limit(self, client_id: str) -> Optional[ApiResponse]:
        """Charge one request to `client_id`; an error response when it is over its rate."""
        allowed, retry = self.limiter.allow(client_id)
        if allowed:
            return None
        return self._finalize(self._rate_limited(retry, "Too many requests. Slow down and retry shortly."))

    @staticmethod
    def _rate_limited(retry: float, message: str) -> ApiResponse:
        return ApiResponse.error(429, "rate_limited", message, {"Retry-After": str(max(1, int(retry + 0.999)))})

    def _body_limit(self, entry: _Route, headers: Dict[str, str]) -> int:
        limit = entry.max_body
        if callable(limit):
            return int(limit(self.config, headers))
        if limit is None:
            return int(self.config.max_json_body_bytes)
        return int(limit)

    def preflight(self, method: str, route: str, headers: Dict[str, str], client_id: str,
                  content_length: int) -> Optional[ApiResponse]:
        """Everything that can be decided before a request body exists.

        Returns an error response, or None when the request may proceed. An
        adapter calls this before reading the body and then calls
        `handle(req, preflighted=True)`; rate-limit tokens are charged here.
        """
        try:
            return self._preflight(str(method).upper(), route, headers, client_id, content_length)
        except Exception:
            return self._finalize(self._internal_error(route))

    def _preflight(self, method: str, route: str, headers: Dict[str, str], client_id: str,
                   content_length: int) -> Optional[ApiResponse]:
        limited = self.rate_limit(client_id)
        if limited is not None:
            return limited
        entry, methods = self._find(method, route)
        if entry is None:
            if methods:
                return self._finalize(ApiResponse.error(
                    405, "method_not_allowed", "Method not allowed.",
                    {"Allow": ", ".join(methods)}))
            return self._finalize(ApiResponse.error(404, "not_found", "Unknown API endpoint."))
        if content_length > 0:
            ctype = headers.get("content-type", "").split(";")[0].strip().lower()
            if ctype in FORM_CONTENT_TYPES:
                return self._finalize(ApiResponse.error(
                    415, "bad_request", "Unsupported Content-Type for this endpoint."))
            limit = self._body_limit(entry, headers)
            if content_length > limit:
                return self._finalize(ApiResponse.error(
                    413, "too_large",
                    f"Request body is {content_length:,} bytes; the limit is {limit:,} bytes."))
        if entry.bucket == "upload":
            allowed, retry = self.upload_limiter.allow(client_id)
            if not allowed:
                return self._finalize(self._rate_limited(
                    retry, "Too many uploads. Wait a little before uploading again."))
        return None

    # -- dispatch -------------------------------------------------------------
    def handle(self, req: ApiRequest, preflighted: bool = False) -> ApiResponse:
        """Serve one request. Never raises."""
        try:
            resp = self._finalize(self._handle(req, preflighted), req)
        except Exception:
            try:
                return self._finalize(self._internal_error(getattr(req, "route", "?")))
            except Exception:
                return ApiResponse(500, b'{"error":"Internal error.","code":"internal"}', JSON_TYPE)
        # A request costs one token up front; what it then makes the server send is
        # charged by size, so a 60-byte request cannot buy megabytes for that one token.
        unit = int(self.config.response_bytes_per_token or 0)
        if unit > 0 and self.limiter.enabled:
            try:
                extra = resp.body_size() // unit
                if extra:
                    self.limiter.charge(req.client_id, float(extra))
            except Exception:
                pass
        return resp

    def _handle(self, req: ApiRequest, preflighted: bool) -> ApiResponse:
        cfg = self.config
        if not preflighted:
            early = self._preflight(req.method, req.route, req.headers, req.client_id, len(req.body))
            if early is not None:
                return early
        entry, _methods = self._find(req.method, req.route)
        if entry is None:
            return ApiResponse.error(404, "not_found", "Unknown API endpoint.")
        if len(req.body) > self._body_limit(entry, req.headers):
            return ApiResponse.error(413, "too_large", "Request body is too large.")
        try:
            apply_doc_headers(req)
            with runtime.use_config(cfg), runtime.parse_deadline(cfg.parse_timeout_seconds):
                result = entry.handler(req)
        except ApiError as exc:
            return ApiResponse.error(exc.status, exc.code, exc.message or "Request failed.", exc.headers)
        except ParseBudgetExceeded as exc:
            return ApiResponse.error(422, "timeout", str(exc))
        except ValueError as exc:
            message = _printable(str(exc)) if cfg.mode == "local" else ""
            return ApiResponse.error(400, "bad_request", message or "Bad request.")
        except OSError as exc:
            if cfg.mode != "local":
                return self._internal_error(req.route)
            if isinstance(exc, FileNotFoundError):
                return ApiResponse.error(404, "not_found", _printable(str(exc)))
            if isinstance(exc, PermissionError):
                return ApiResponse.error(403, "forbidden", _printable(str(exc)))
            return ApiResponse.error(400, "bad_request", _printable(str(exc)))
        except Exception:
            return self._internal_error(req.route)
        if isinstance(result, ApiResponse):
            return result
        if result is None:
            return ApiResponse(204, b"", JSON_TYPE)
        return ApiResponse.json(result)

    def _internal_error(self, route: str) -> ApiResponse:
        """Log what happened; tell the client only that something did."""
        ref = secrets.token_hex(4)
        exc_type, exc, tb = sys.exc_info()
        local = self.config.mode == "local"
        frames = ["%s:%d:%s" % (frame.filename.replace("\\", "/").rsplit("/", 1)[-1], frame.lineno or 0, frame.name)
                  for frame in traceback.extract_tb(tb)[-8:]] if tb is not None else []
        self.log.write(
            "error", "internal_error", ref=ref, route=route,
            exc=exc_type.__name__ if exc_type else None, where=frames,
            # Exception text can quote bytes of the file being analysed; keep it out of shared logs.
            message=_printable(str(exc)) if (local and exc is not None) else None,
        )
        payload: Dict[str, Any] = {"error": f"Internal error (ref {ref}).", "code": "internal"}
        if local and self.config.debug_errors and exc is not None:
            payload["trace"] = "".join(traceback.format_exception(exc_type, exc, tb))
        return ApiResponse(500, encode_json(payload), JSON_TYPE)

    def _finalize(self, resp: ApiResponse, req: Optional[ApiRequest] = None) -> ApiResponse:
        headers = dict(resp.headers)
        headers.setdefault("Cache-Control", "no-store")
        headers.update(security_headers(self.config, "api"))
        resp.headers = headers
        if req is not None and resp.status == 200 and self.config.mode != "wasm":
            self._negotiate(req, resp)
        return resp

    def _negotiate(self, req: ApiRequest, resp: ApiResponse) -> None:
        """Validators and content coding for a successful answer.

        * ETag on documents, downloads and any GET answer of 4 KiB or more; a GET
          whose If-None-Match names it gets 304 and no body. `Cache-Control` stays
          `no-store`, so nothing is written to a browser cache: this is for clients
          that still hold the answer and say so.
        * gzip for JSON and text when the client accepts it. Documents come from a
          buffer compressed once per document; other answers are compressed here
          (zlib releases the GIL), up to 8 MiB.
        """
        size = resp.body_size()
        ctype = resp.content_type.split(";")[0].strip().lower()
        compressible = ("json" in ctype or ctype.startswith("text/")) and "Content-Encoding" not in resp.headers
        wants_gzip = (bool(self.config.gzip_responses) and compressible and size >= GZIP_MIN_BYTES
                      and accepts_gzip(req.headers.get("accept-encoding", ""))
                      and (resp.gzip_parts is not None or size <= GZIP_DYNAMIC_MAX_BYTES))
        if compressible and size >= GZIP_MIN_BYTES:
            resp.headers["Vary"] = "Accept-Encoding"
        etag = resp.etag
        if etag is None and req.method == "GET" and size >= ETAG_MIN_BYTES:
            digest = hashlib.sha256()
            for part in resp.body_parts():
                digest.update(part)
            etag = "h" + digest.hexdigest()[:24]
        if etag is not None:
            if req.method == "GET" and etag_matches(req.headers.get("if-none-match", ""), etag):
                resp.headers["ETag"] = '"%s%s"' % (etag, "-gz" if wants_gzip else "")
                resp.status = 304
                resp.body = b""
                resp.gzip_parts = None
                return
        if wants_gzip:
            if resp.gzip_parts is not None:
                parts = resp.gzip_parts()
            else:
                import zlib

                comp = zlib.compressobj(6 if size <= 262144 else runtime.DOCUMENT_GZIP_LEVEL, zlib.DEFLATED, 31)
                parts = [comp.compress(part) for part in resp.body_parts()]
                parts.append(comp.flush())
                parts = [b"".join(parts)]
            if sum(len(part) for part in parts) < size:
                resp._body = None
                resp.parts = parts
                resp.headers["Content-Encoding"] = "gzip"
            else:
                wants_gzip = False
        resp.gzip_parts = None
        if etag is not None:
            # A strong validator names one representation: the gzip one has its own.
            resp.headers["ETag"] = '"%s%s"' % (etag, "-gz" if wants_gzip else "")

    # -- housekeeping -----------------------------------------------------------
    def housekeeping(self) -> None:
        """Drop expired documents and idle rate-limit state. Cheap; call it periodically."""
        try:
            self.service.sweep()
        except Exception:
            pass
        self.limiter.prune()
        self.upload_limiter.prune()


def accepts_gzip(accept_encoding: str) -> bool:
    """Whether an Accept-Encoding header allows gzip (`gzip;q=0` and absence do not)."""
    for item in accept_encoding.split(","):
        name, _, params = item.strip().partition(";")
        if name.strip().lower() not in ("gzip", "x-gzip"):
            continue
        q = params.strip().lower().replace(" ", "")
        if q.startswith("q="):
            try:
                return float(q[2:]) > 0
            except ValueError:
                return False
        return True
    return False


def etag_matches(if_none_match: str, etag: str) -> bool:
    """RFC 9110 weak comparison of an If-None-Match header against our validator;
    the per-encoding suffix is ignored (either representation means "I have it")."""
    if not if_none_match:
        return False
    for item in if_none_match.split(","):
        tag = item.strip()
        if tag == "*":
            return True
        if tag.startswith("W/"):
            tag = tag[2:]
        if len(tag) >= 2 and tag[0] == '"' and tag[-1] == '"':
            tag = tag[1:-1]
            if tag.endswith("-gz"):
                tag = tag[:-3]
            if tag == etag:
                return True
    return False


def apply_doc_headers(req: ApiRequest) -> None:
    """Move document ids sent as request headers (see DOC_ID_HEADERS) into the
    query, where every handler looks for them. A header wins over the query."""
    for header, key in DOC_ID_HEADERS:
        raw = req.headers.get(header)
        if not raw:
            continue
        if len(raw) > 16384:
            raise BadRequest("Malformed document id.")
        req.query[key] = unquote(raw, errors="replace")


def _printable(text: str, limit: int = 300) -> str:
    cleaned = "".join(ch if 0x20 <= ord(ch) < 0x7F or ord(ch) > 0x9F else " " for ch in str(text))
    return " ".join(cleaned.split())[:limit]


# ---------------------------------------------------------------------------
# Parameter helpers
# ---------------------------------------------------------------------------
def int_param(query: Dict[str, str], key: str, default: int = 0, lo: int = 0, hi: int = (1 << 64) - 1) -> int:
    """An integer query parameter (decimal or 0x hex), clamped to [lo, hi].
    Missing or unparsable values give `default`, as the v1 API did."""
    raw = query.get(key)
    if raw is None:
        return default
    raw = str(raw).strip()
    if not raw or len(raw) > 40:
        return default
    try:
        value = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 0)
    except ValueError:
        return default
    return max(lo, min(hi, value))


def str_param(query: Dict[str, str], key: str, default: Optional[str] = None, max_len: int = 4096) -> Optional[str]:
    raw = query.get(key)
    if raw is None:
        return default
    raw = str(raw)
    if len(raw) > max_len:
        raise BadRequest(f"Parameter '{key}' is too long.")
    return raw


def doc_params(req: ApiRequest, config: RuntimeConfig) -> Tuple[Optional[str], Optional[str]]:
    """(doc, path) named by a request. `path` is refused outright where it is not allowed."""
    doc = str_param(req.query, "doc")
    path = str_param(req.query, "path")
    if path is not None and not config.allow_path_load:
        raise Forbidden("Loading files by server path is not available on this server.")
    return (doc or None), (path or None)


# ---------------------------------------------------------------------------
# Core endpoints
# ---------------------------------------------------------------------------
def _upload_body_limit(config: RuntimeConfig, headers: Dict[str, str]) -> int:
    if config.mode == "local" and "json" in headers.get("content-type", "").lower():
        # v1 clients wrap the file in base64 inside JSON; allow for the expansion.
        return config.max_upload_bytes * 4 // 3 + 65536
    return config.max_upload_bytes


def register_core_routes(router: ApiRouter) -> None:
    service = router.service
    config = router.config

    def document_response(entry: Any) -> ApiResponse:
        return ApiResponse.document(entry)

    def get_config(req: ApiRequest) -> Dict[str, Any]:
        return config.public_dict()

    def get_presets(req: ApiRequest) -> Dict[str, Any]:
        return {"presets": service.get_presets()}

    def parse(req: ApiRequest) -> ApiResponse:
        doc, path = doc_params(req, config)
        if req.method == "POST":
            body = req.json()
            body_path = body.get("path")
            if body_path is not None and not config.allow_path_load:
                raise Forbidden("Loading files by server path is not available on this server.")
            doc = doc or (str(body["doc"]) if body.get("doc") else None)
            path = path or (str(body_path) if body_path else None)
        if not doc and not path:
            if config.allow_path_load:
                raise BadRequest("Missing required 'doc' or 'path' parameter.")
            raise BadRequest("Missing required 'doc' parameter.")
        entry = service.get_entry(doc=doc, path=path)
        service.set_active(entry)
        return document_response(entry)

    def upload(req: ApiRequest) -> ApiResponse:
        if not config.allow_upload:
            raise Forbidden("Uploads are disabled on this server.")
        ctype = req.headers.get("content-type", "").split(";")[0].strip().lower()
        filename = unquote(req.headers.get("x-filename") or req.query.get("filename") or "", errors="replace")
        data = req.body
        if "json" in ctype:
            if config.mode != "local":
                raise ApiError("Send the file as a raw application/octet-stream body.", status=415)
            body = req.json()
            filename = str(body.get("filename") or filename)
            try:
                data = base64.b64decode(str(body.get("data_base64") or ""), validate=False)
            except (binascii.Error, ValueError):
                raise BadRequest("'data_base64' is not valid base64.")
        if not data:
            raise BadRequest("Empty binary upload payload.")
        if len(data) > config.max_upload_bytes:
            raise TooLarge(f"File is {len(data):,} bytes; the limit is {config.max_upload_bytes:,} bytes.")
        entry = service.add_upload(filename, data, owner=req.client_id)
        service.set_active(entry)
        return document_response(entry)

    def hex_window(req: ApiRequest) -> Dict[str, Any]:
        doc, path = doc_params(req, config)
        return service.get_hex_slice(
            offset=int_param(req.query, "offset", 0),
            length=int_param(req.query, "length", 4096, 16, 65536),
            slice_index=int_param(req.query, "slice_index", 0, 0, 1 << 20),
            path=path, doc=doc,
        )

    def decode(req: ApiRequest) -> Dict[str, Any]:
        doc, path = doc_params(req, config)
        endian = (str_param(req.query, "endian", "little", 16) or "little").lower()
        return service.decode_bytes_at(
            offset=int_param(req.query, "offset", 0),
            slice_index=int_param(req.query, "slice_index", 0, 0, 1 << 20),
            endian="big" if endian == "big" else "little",
            path=path, doc=doc,
        )

    def translate(req: ApiRequest) -> Dict[str, Any]:
        doc, path = doc_params(req, config)
        q = req.query
        mode = (str_param(q, "mode", "auto", 32) or "auto").lower()
        if mode not in ("auto", "vmaddr", "abs_offset", "slice_offset"):
            raise BadRequest("Unknown 'mode'; use auto, vmaddr, abs_offset or slice_offset.")
        query = None
        for key in ("query", "vmaddr", "abs_offset", "slice_offset"):
            value = str_param(q, key, None, 64)
            if value:
                query = value
                if mode == "auto" and key != "query":
                    mode = key
                break
        return service.translate_address(
            slice_index=int_param(q, "slice_index", 0, 0, 1 << 20),
            query=query or "0", mode=mode, path=path, doc=doc,
        )

    def disassemble(req: ApiRequest) -> Dict[str, Any]:
        doc, path = doc_params(req, config)
        return service.disassemble(
            slice_index=int_param(req.query, "slice_index", 0, 0, 1 << 20),
            vmaddr=str_param(req.query, "vmaddr", None, 64) or None,
            section=str_param(req.query, "section", None, 256) or None,
            count=int_param(req.query, "count", 200, 1, 1000),
            path=path, doc=doc,
        )

    def search(req: ApiRequest) -> Dict[str, Any]:
        doc, path = doc_params(req, config)
        scope = (str_param(req.query, "scope", "all", 32) or "all").lower()
        if scope not in ("all", "symbols", "strings", "structures", "hex"):
            scope = "all"
        return service.search(
            query=str_param(req.query, "q", "", 1024) or "",
            slice_index=int_param(req.query, "slice_index", 0, 0, 1 << 20),
            scope=scope, path=path, doc=doc,
        )

    router.register("GET", "/api/config", get_config)
    router.register("GET", "/api/presets", get_presets)
    router.register("GET", "/api/parse", parse)
    router.register("POST", "/api/parse", parse)
    router.register("POST", "/api/upload", upload, max_body=_upload_body_limit, bucket="upload")
    router.register("GET", "/api/hex", hex_window)
    router.register("GET", "/api/decode", decode)
    router.register("GET", "/api/translate", translate)
    router.register("GET", "/api/disassemble", disassemble)
    router.register("GET", "/api/search", search)


def build_router(service: Any, config: Optional[RuntimeConfig] = None, log: Optional[EventLog] = None,
                 clock: Callable[[], float] = time.monotonic) -> ApiRouter:
    """A router with every endpoint registered."""
    router = ApiRouter(service, config, log=log, clock=clock)
    register_core_routes(router)
    from .labs_patch import register_labs_patch_routes; register_labs_patch_routes(router)  # noqa: E702 - Labs: patch, experiments, builder, compare
    from .labs_encoding import register_routes as register_labs_encoding_routes; register_labs_encoding_routes(router)  # noqa: E702 - Labs: instruction encoding
    from .learn_content import register_learn_routes; register_learn_routes(router)  # noqa: E702 - Learn: curriculum, glossary, tours
    return router
