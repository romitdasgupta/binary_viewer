"""
Process-wide runtime configuration, parse budgets and the shared error types.

Three modes:
  local  - single trusted user on loopback (default for `python3 binary_viewer.py`)
  public - multi-user Internet hosting: no filesystem access from requests,
           no external programs, bounded uploads / cache / CPU time (the HTTP
           server analyses uploads in worker processes of its own interpreter,
           see backend/workers.py; nothing in this module starts a process)
  wasm   - the engine running inside a browser (Pyodide); no server at all

Parsers and the disassembler consult this module instead of taking a config
argument, so the same code runs unchanged in all three modes.

`get_config()` returns the configuration that applies to the *current thread*:
the router and the service scope their own config with `use_config(...)` while
they work, so several servers with different modes can live in one process
(tests do this) without one loosening the other. Outside such a scope it is
the process-wide config installed with `set_config()`.

This module must stay importable inside Pyodide: standard library only, no
sockets, no threads started, nothing platform specific.
"""

import json
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

APP_NAME = "BinaryStudio"
APP_VERSION = "2.0.0"

MODES = ("local", "public", "wasm")

MIB = 1024 * 1024


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class ParseBudgetExceeded(ValueError):
    """Raised when a parse runs past its wall-clock deadline."""


class ApiError(Exception):
    """An error with a stable machine code and HTTP status.

    Handlers and the service raise these; the router turns them into
    `{"error": message, "code": code}`. The message is shown to the user, so
    it must never contain server paths or internals in public mode.
    """

    status = 400
    code = "bad_request"

    def __init__(self, message: str = "", status: Optional[int] = None, code: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None) -> None:
        Exception.__init__(self, message)
        self.message = message
        if status is not None:
            self.status = status
        if code is not None:
            self.code = code
        self.headers = dict(headers or {})

    def __str__(self) -> str:
        return self.message


class BadRequest(ApiError, ValueError):
    status = 400
    code = "bad_request"


class Forbidden(ApiError):
    status = 403
    code = "forbidden"


class NotFound(ApiError, FileNotFoundError):
    status = 404
    code = "not_found"


class DocExpired(ApiError):
    """Unknown, evicted or expired document id. The client re-uploads."""

    status = 410
    code = "doc_expired"


class TooLarge(ApiError, ValueError):
    status = 413
    code = "too_large"


class ParseFailed(ApiError, ValueError):
    status = 422
    code = "parse_failed"


class RateLimited(ApiError):
    status = 429
    code = "rate_limited"


class Busy(ApiError):
    """All analysis slots are taken; the request was not queued."""

    status = 503
    code = "busy"


# ---------------------------------------------------------------------------
# Content-Security-Policy
# ---------------------------------------------------------------------------
# Ordered so the header reads predictably. Scripts get no inline allowance.
# style-src carries no 'unsafe-inline': there is no `style="..."` attribute and no <style>
# element in static/ or in the generated pages (tests/test_audit_logic.py enforces this).
# Styling from script goes through CSSOM properties, which style-src does not restrict.
DEFAULT_CSP: List[Tuple[str, List[str]]] = [
    ("default-src", ["'none'"]),
    ("script-src", ["'self'"]),
    ("style-src", ["'self'"]),
    ("img-src", ["'self'", "data:"]),
    ("font-src", ["'self'"]),
    ("connect-src", ["'self'"]),
    ("worker-src", ["'self'"]),
    ("manifest-src", ["'self'"]),
    ("object-src", ["'none'"]),
    ("base-uri", ["'none'"]),
    ("frame-ancestors", ["'none'"]),
    ("form-action", ["'self'"]),
]

# Applied to JSON and download responses: nothing in them is ever meant to render.
API_CSP = "default-src 'none'; frame-ancestors 'none'; sandbox"

DEFAULT_PERMISSIONS_POLICY = (
    "accelerometer=(), autoplay=(), browsing-topics=(), camera=(), display-capture=(), "
    "geolocation=(), gyroscope=(), hid=(), interest-cohort=(), magnetometer=(), microphone=(), "
    "midi=(), payment=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()"
)


def _reject_header_unsafe(value: str, what: str) -> str:
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"{what} must not contain control characters")
    return value


def parse_csp_directives(text: str) -> List[Tuple[str, List[str]]]:
    """Parse `"script-src 'self' https://x; frame-src https://x"` into ordered pairs."""
    _reject_header_unsafe(text, "Content-Security-Policy")
    out: List[Tuple[str, List[str]]] = []
    for chunk in text.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        name = parts[0].lower()
        if not all(ch.isalnum() or ch == "-" for ch in name):
            raise ValueError(f"Invalid CSP directive name: {name!r}")
        for source in parts[1:]:
            if "," in source:
                raise ValueError(f"Invalid CSP source (contains a comma): {source!r}")
        out.append((name, parts[1:]))
    return out


def build_csp(extra: Optional[List[Tuple[str, List[str]]]] = None) -> str:
    """The default policy with `extra` sources merged in, directive by directive.

    Adding sources to a directive that is `'none'` replaces the `'none'`
    (the two cannot be combined). Unknown directives are appended.
    """
    order = [name for name, _ in DEFAULT_CSP]
    merged: Dict[str, List[str]] = {name: list(sources) for name, sources in DEFAULT_CSP}
    for name, sources in extra or []:
        if name not in merged:
            merged[name] = []
            order.append(name)
        current = merged[name]
        if sources and current == ["'none'"]:
            current = []
        for source in sources:
            if source not in current:
                current.append(source)
        merged[name] = current
    return "; ".join((name + " " + " ".join(merged[name])).strip() for name in order)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
class RuntimeConfig:
    def __init__(self, mode: str = "local", **overrides: Any) -> None:
        if mode not in MODES:
            raise ValueError(f"Unknown runtime mode: {mode!r}")
        self.mode = mode
        restricted = mode != "local"
        public = mode == "public"

        # Capabilities
        self.allow_path_load = not restricted       # arbitrary server filesystem paths
        self.allow_host_presets = not restricted    # /bin/ls, /usr/bin/true
        self.allow_external_tools = not restricted  # objdump / otool / c++filt / swift-demangle
        self.allow_upload = True
        self.allow_patch = True
        self.allow_download = True
        self.debug_errors = False                   # include tracebacks in error responses (local mode only)

        # Limits
        self.max_upload_bytes = 32 * MIB if public else 256 * MIB
        self.max_patch_bytes = 64 * 1024
        self.max_json_body_bytes = MIB
        self.parse_timeout_seconds = 20.0 if public else 120.0
        self.cache_max_docs = 64 if public else 32
        self.cache_max_bytes = 512 * MIB
        # The most of the cache (documents and bytes) one client may occupy before its
        # own oldest uploads are evicted instead of other people's. 0 = no per-client bound.
        # With the defaults: the largest possible document is charged 152 MiB (32 MiB
        # of file + 5 x 24 MiB of JSON, see service.document_cost), so the cache holds
        # three of those and one client's share (153.6 MiB) holds one. A patched copy
        # and its original are kept together even past the share (service.DocumentStore),
        # and when the whole cache is full the client holding the most makes room.
        self.cache_client_share = 0.3 if public else 0.0
        self.doc_ttl_seconds = 30 * 60 if public else 0  # idle time before a document is dropped; 0 = no expiry
        self.max_concurrent_parses = 4 if public else 0  # 0 = unlimited
        self.parse_queue_seconds = 2.0              # how long a request may wait for a parse slot before 503
        self.rate_limit_per_minute = 240 if public else 0
        self.rate_limit_burst = 0                   # 0 = half of the per-minute rate
        self.upload_rate_limit_per_minute = 12 if public else 0
        self.upload_rate_limit_burst = 0            # 0 = half of the per-minute rate
        self.rate_limiter_max_clients = 20000       # memory bound for the limiter tables
        # Serialized size of one analysis result. A small file can describe a
        # huge structure; results past this are refused rather than cached.
        self.max_document_bytes = 24 * MIB if public else 0
        # Last resort for an analysis that runs in a server thread (worker processes
        # off or unavailable): a thread cannot be killed, so a parse still running
        # this long after it started makes the server exit for its supervisor to
        # restart it. With worker processes the stuck worker is killed at the parse
        # timeout and this is never reached. 0 = never.
        self.hard_parse_timeout_seconds = 80.0 if public else 0.0
        # Analyse uploads in separate worker processes (backend/workers.py): a worker
        # that overruns its budget is killed and replaced, a parser crash or memory
        # blow-up stays in that process, and analysis CPU is off the server's threads.
        # Only the HTTP server starts workers; a bare AnalysisService (tests, the CLI,
        # the in-browser build) always analyses in-thread.
        self.parse_workers = public
        # Address-space limit of one worker (RLIMIT_AS, where the platform enforces it); 0 = none.
        self.parse_worker_memory_bytes = 1024 * MIB if public else 0
        # How long past the parse timeout a worker may run before it is killed: the
        # worker's own deadline check normally answers first, with a clean error.
        self.parse_kill_grace_seconds = 3.0

        # HTTP transport
        self.trust_proxy_headers = False            # honour X-Forwarded-For (only behind a trusted proxy)
        self.allowed_hosts: Optional[list] = None   # None = loopback names (+ a specific bind address)
        self.allow_unsafe_bind = False              # local mode on a non-loopback address
        self.request_timeout_seconds = 15.0 if public else 30.0   # whole request line + headers
        self.keepalive_timeout_seconds = 5.0 if public else 15.0  # idle time between requests
        self.min_transfer_bytes_per_second = 64 * 1024            # slower bodies / readers are cut off
        self.max_request_line_bytes = 8192
        self.max_header_bytes = 16384               # request line + all headers
        self.max_connections = 128 if public else 256
        # Open connections per client address. Behind a trusted proxy every connection
        # comes from the proxy, so the same number caps the requests in progress per
        # forwarded client address instead.
        self.max_connections_per_client = 24 if public else 0
        self.max_requests_per_connection = 200
        self.max_inflight_upload_bytes = 0          # 0 = four times max_upload_bytes (public) / unlimited (local)
        # Request-body bytes one client may have buffered at once; 0 = half the total budget.
        self.max_inflight_upload_bytes_per_client = 0
        # A declared request body must start arriving within this long, and from then
        # on keep up with min_transfer_bytes_per_second (this is also the slack of that check).
        self.body_grace_seconds = 5.0 if public else 30.0
        # Response bodies being written at once, in total and per client; past either a
        # large response is refused with 503 instead of queued. 0 = unlimited / a quarter of the total.
        self.max_inflight_response_bytes = 256 * MIB if public else 0
        self.max_inflight_response_bytes_per_client = 0
        # A client that accepts nothing for this long while a response is being written is cut off.
        self.response_stall_seconds = 15.0 if public else 60.0
        # Rate-limit tokens are also charged by response size: one per this many bytes
        # on the wire (so a small request cannot buy megabytes of egress for one token). 0 = off.
        self.response_bytes_per_token = 256 * 1024
        self.gzip_responses = True                  # gzip JSON for clients that accept it
        self.access_log = public                    # one line per request; errors are always logged
        self.static_max_age_seconds = 300 if public else 0

        # Response headers
        self.csp: Optional[str] = None              # full replacement for the page CSP
        self.csp_extra: List[Tuple[str, List[str]]] = []  # sources merged into the default CSP
        self.permissions_policy = DEFAULT_PERMISSIONS_POLICY
        self.hsts_seconds = 0                       # Strict-Transport-Security max-age; 0 = not sent

        # Monetisation (off by default; see docs)
        self.ads: Dict[str, Any] = {"enabled": False, "provider": None, "slots": {}, "options": {}}
        # CSP sources the ads configuration needs, per page kind ({"app": [...], "content": [...]}).
        # Derived from `ads` by the site layer (tools/site_pages.py) at server start; never set by hand.
        self.ads_csp: Dict[str, List[Tuple[str, List[str]]]] = {"app": [], "content": []}
        # Public site: absolute URL of the site root (canonical links, sitemap) and the
        # /.well-known/security.txt Contact. Both optional.
        self.site_url: Optional[str] = None
        self.security_contact: Optional[str] = None
        self.initial_doc: Optional[str] = None  # local mode: document opened by --file
        self.links: Dict[str, Any] = {
            "privacy": "/privacy.html",
            "terms": "/terms.html",
            "about": "/about.html",
            "source": None,
        }

        for key, value in overrides.items():
            if not hasattr(self, key):
                raise ValueError(f"Unknown runtime option: {key!r}")
            setattr(self, key, value)
        self.validate()

    # -- derived values -----------------------------------------------------
    def validate(self) -> None:
        if self.csp is not None:
            _reject_header_unsafe(self.csp, "Content-Security-Policy")
        _reject_header_unsafe(self.permissions_policy, "Permissions-Policy")
        if isinstance(self.csp_extra, str):
            self.csp_extra = parse_csp_directives(self.csp_extra)
        if self.mode != "local":
            # These are what make a restricted mode restricted; no option may turn them on.
            self.allow_path_load = False
            self.allow_host_presets = False
            self.allow_external_tools = False
            self.debug_errors = False
        if self.max_upload_bytes <= 0:
            raise ValueError("max_upload_bytes must be positive")

    def content_security_policy(self, kind: str = "app") -> str:
        """CSP for HTML pages and static assets. kind: 'app' (the app shell and its assets) or
        'content' (learning, legal and other site pages). Ads widen the content kind only, unless
        the in-app footer slot is configured too."""
        if self.csp:
            return self.csp
        extra = list(self.csp_extra) + list((self.ads_csp or {}).get("content" if kind == "content" else "app") or [])
        return build_csp(extra)

    def inflight_upload_budget(self) -> int:
        """Total bytes of request bodies that may be buffered at once; 0 = unlimited."""
        if self.max_inflight_upload_bytes > 0:
            return max(self.max_inflight_upload_bytes, self.max_upload_bytes)
        return 4 * self.max_upload_bytes if self.mode == "public" else 0

    def inflight_upload_budget_per_client(self) -> int:
        """Request-body bytes one client may have buffered at once; 0 = unlimited.
        Never less than one maximum upload, or the largest file could not be sent at all."""
        total = self.inflight_upload_budget()
        if total <= 0:
            return 0
        if self.max_inflight_upload_bytes_per_client > 0:
            return min(total, max(self.max_inflight_upload_bytes_per_client, self.max_upload_bytes))
        return max(total // 2, self.max_upload_bytes)

    def inflight_response_budget_per_client(self) -> int:
        """Response bytes one client may have in flight at once; 0 = unlimited."""
        total = self.max_inflight_response_bytes
        if total <= 0:
            return 0
        if self.max_inflight_response_bytes_per_client > 0:
            return min(total, self.max_inflight_response_bytes_per_client)
        return max(total // 4, 1)

    def parse_worker_count(self) -> int:
        """Worker processes the HTTP server keeps; 0 = analyse in the server process."""
        if not self.parse_workers or self.mode == "wasm":
            return 0
        return self.max_concurrent_parses if self.max_concurrent_parses > 0 else 4

    def public_dict(self) -> Dict[str, Any]:
        """The subset safe to expose at GET /api/config."""
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "mode": self.mode,
            "features": {
                "path_load": self.allow_path_load,
                "host_presets": self.allow_host_presets,
                "upload": self.allow_upload,
                "external_tools": self.allow_external_tools,
                "patch": self.allow_patch,
                "download": self.allow_download,
            },
            "limits": {
                "max_upload_bytes": self.max_upload_bytes,
                "max_patch_bytes": self.max_patch_bytes,
            },
            "ads": self.ads,
            "links": self.links,
            "initial_doc": getattr(self, "initial_doc", None),
        }

    @classmethod
    def from_env(cls, mode: Optional[str] = None, environ: Optional[Dict[str, str]] = None,
                 **overrides: Any) -> "RuntimeConfig":
        """Build a config from BINARYSTUDIO_* variables; `overrides` (CLI flags) win."""
        env = environ if environ is not None else _os_environ()
        if mode is None:
            mode = (env.get("BINARYSTUDIO_MODE") or "local").strip().lower()
        values: Dict[str, Any] = {}
        for name, attr, convert, _help in ENV_VARS:
            if attr is None:
                continue
            raw = env.get(name)
            if raw is None or raw.strip() == "":
                continue
            try:
                values[attr] = convert(raw.strip())
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid value for {name}: {exc}")
        links_source = values.pop("links_source", None)
        values.update(overrides)
        config = cls(mode, **values)
        if links_source:
            config.links = dict(config.links, source=links_source)
        return config


def _os_environ() -> Dict[str, str]:
    import os

    return dict(os.environ)


def _env_bool(raw: str) -> bool:
    value = raw.lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"expected a boolean (1/0, true/false), got {raw!r}")


def _env_megabytes(raw: str) -> int:
    value = float(raw)
    if value <= 0:
        raise ValueError("must be greater than zero")
    return int(value * MIB)


def _env_megabytes_or_zero(raw: str) -> int:
    value = float(raw)
    if value < 0 or value != value:
        raise ValueError("must not be negative")
    return int(value * MIB)


def _env_nonneg_int(raw: str) -> int:
    value = int(raw)
    if value < 0:
        raise ValueError("must not be negative")
    return value


def _env_nonneg_float(raw: str) -> float:
    value = float(raw)
    if value < 0 or value != value:
        raise ValueError("must not be negative")
    return value


def _env_fraction(raw: str) -> float:
    value = float(raw)
    if not (0.0 <= value <= 1.0):
        raise ValueError("must be between 0 and 1")
    return value


def _env_list(raw: str) -> List[str]:
    return [item.strip() for item in raw.replace(",", " ").split() if item.strip()]


def _env_ads(raw: str) -> Dict[str, Any]:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    ads = {"enabled": False, "provider": None, "slots": {}, "options": {}}
    for key in ads:
        if key in data:
            ads[key] = data[key]
    ads["enabled"] = bool(ads["enabled"])
    if not isinstance(ads["slots"], dict) or not isinstance(ads["options"], dict):
        raise ValueError("'slots' and 'options' must be JSON objects")
    return ads


def _env_url(raw: str) -> str:
    if not (raw.startswith("https://") or raw.startswith("http://")):
        raise ValueError("expected an http(s) URL")
    return _reject_header_unsafe(raw, "URL")


# (variable, RuntimeConfig attribute or None when the CLI handles it, converter, help)
ENV_VARS: List[Tuple[str, Optional[str], Callable[[str], Any], str]] = [
    ("BINARYSTUDIO_MODE", None, str, "local (default) or public; same as --public"),
    ("BINARYSTUDIO_HOST", None, str, "bind address; same as --host"),
    ("BINARYSTUDIO_PORT", None, int, "bind port; same as --port"),
    ("BINARYSTUDIO_ALLOWED_HOSTS", "allowed_hosts", _env_list,
     "comma separated Host names to accept; same as repeating --allowed-host"),
    ("BINARYSTUDIO_TRUST_PROXY", "trust_proxy_headers", _env_bool,
     "1 = take the client address from X-Forwarded-For; same as --trust-proxy"),
    ("BINARYSTUDIO_MAX_UPLOAD_MB", "max_upload_bytes", _env_megabytes, "largest accepted upload, in MiB"),
    ("BINARYSTUDIO_RATE_LIMIT", "rate_limit_per_minute", _env_nonneg_int,
     "requests per client per minute; 0 = unlimited"),
    ("BINARYSTUDIO_UPLOAD_RATE_LIMIT", "upload_rate_limit_per_minute", _env_nonneg_int,
     "uploads per client per minute; 0 = unlimited"),
    ("BINARYSTUDIO_MAX_CONCURRENT_PARSES", "max_concurrent_parses", _env_nonneg_int,
     "analyses running at once; 0 = unlimited"),
    ("BINARYSTUDIO_PARSE_TIMEOUT", "parse_timeout_seconds", _env_nonneg_float,
     "seconds one analysis may take; 0 = unlimited"),
    ("BINARYSTUDIO_HARD_PARSE_TIMEOUT", "hard_parse_timeout_seconds", _env_nonneg_float,
     "last resort when analyses run inside the server process: seconds after which a stuck one makes "
     "the server exit for its supervisor to restart; 0 = never"),
    ("BINARYSTUDIO_PARSE_WORKERS", "parse_workers", _env_bool,
     "1 = analyse uploads in worker processes that are killed when they overrun (default with --public); "
     "0 = inside the server process"),
    ("BINARYSTUDIO_PARSE_WORKER_MEMORY_MB", "parse_worker_memory_bytes", _env_megabytes_or_zero,
     "address-space limit of one analysis worker, in MiB (default 1024; 0 = none)"),
    ("BINARYSTUDIO_MAX_INFLIGHT_RESPONSE_MB", "max_inflight_response_bytes", _env_megabytes_or_zero,
     "response bodies being written at once, in MiB (default 256 with --public; a quarter of it per client); "
     "0 = unlimited"),
    ("BINARYSTUDIO_GZIP", "gzip_responses", _env_bool,
     "1 = gzip JSON responses for clients that accept it (default); 0 = leave compression to the proxy"),
    ("BINARYSTUDIO_DOC_TTL", "doc_ttl_seconds", _env_nonneg_int,
     "seconds an idle document stays in memory; 0 = until evicted"),
    ("BINARYSTUDIO_CACHE_MAX_DOCS", "cache_max_docs", _env_nonneg_int, "documents kept in memory"),
    ("BINARYSTUDIO_CACHE_MAX_MB", "cache_max_bytes", _env_megabytes,
     "estimated memory for cached documents, in MiB"),
    ("BINARYSTUDIO_CACHE_CLIENT_SHARE", "cache_client_share", _env_fraction,
     "fraction of the document cache one client may fill (0-1); 0 = no per-client bound"),
    ("BINARYSTUDIO_MAX_DOCUMENT_MB", "max_document_bytes", _env_megabytes,
     "largest analysis result (serialized), in MiB"),
    ("BINARYSTUDIO_MAX_CONNECTIONS", "max_connections", _env_nonneg_int, "open connections; 0 = unlimited"),
    ("BINARYSTUDIO_MAX_CONNECTIONS_PER_CLIENT", "max_connections_per_client", _env_nonneg_int,
     "open connections per client address; 0 = unlimited"),
    ("BINARYSTUDIO_REQUEST_TIMEOUT", "request_timeout_seconds", _env_nonneg_float,
     "seconds to receive a complete request head"),
    ("BINARYSTUDIO_ACCESS_LOG", "access_log", _env_bool, "1 = one log line per request"),
    ("BINARYSTUDIO_STATIC_MAX_AGE", "static_max_age_seconds", _env_nonneg_int,
     "Cache-Control max-age for static assets other than HTML"),
    ("BINARYSTUDIO_CSP_EXTRA", "csp_extra", parse_csp_directives,
     "sources to add to the page CSP, e.g. \"script-src 'wasm-unsafe-eval'; frame-src https://ads.example\""),
    ("BINARYSTUDIO_CSP", "csp", str, "replace the page CSP entirely"),
    ("BINARYSTUDIO_PERMISSIONS_POLICY", "permissions_policy", str, "replace the Permissions-Policy header"),
    ("BINARYSTUDIO_HSTS_SECONDS", "hsts_seconds", _env_nonneg_int,
     "send Strict-Transport-Security with this max-age (only when every request arrives over TLS)"),
    ("BINARYSTUDIO_ADS", "ads", _env_ads,
     "JSON object for /api/config \"ads\": {\"enabled\":true,\"provider\":...,\"slots\":{},\"options\":{}}"),
    ("BINARYSTUDIO_SOURCE_URL", "links_source", _env_url, "URL of the source code, shown in the UI"),
    ("BINARYSTUDIO_SITE_URL", "site_url", _env_url,
     "absolute URL of the site root, for canonical links and sitemap.xml (e.g. https://binarystudio.example)"),
    ("BINARYSTUDIO_SECURITY_CONTACT", "security_contact", str,
     "Contact for /.well-known/security.txt (mailto: or https: URI); without it the file is not served"),
]


_config = RuntimeConfig("local")
_local = threading.local()


def get_config() -> RuntimeConfig:
    """The config in force for the current thread (see `use_config`), else the process-wide one."""
    scoped = getattr(_local, "config", None)
    return scoped if scoped is not None else _config


def set_config(config: RuntimeConfig) -> RuntimeConfig:
    """Install the process-wide config."""
    global _config
    _config = config
    return _config


class use_config:
    """Context manager: make `config` the result of `get_config()` on this thread."""

    def __init__(self, config: Optional[RuntimeConfig]) -> None:
        self.config = config
        self._previous: Optional[RuntimeConfig] = None

    def __enter__(self) -> Optional[RuntimeConfig]:
        self._previous = getattr(_local, "config", None)
        if self.config is not None:
            _local.config = self.config
        return self.config

    def __exit__(self, *exc: Any) -> None:
        _local.config = self._previous


# ---------------------------------------------------------------------------
# Per-thread parse deadline
# ---------------------------------------------------------------------------
class parse_deadline:
    """Context manager: `with parse_deadline(seconds): parse(...)`.

    Nested uses never extend an outer deadline: the earlier of the two applies.
    """

    def __init__(self, seconds: Optional[float] = None) -> None:
        self.seconds = get_config().parse_timeout_seconds if seconds is None else seconds
        self._previous: Optional[float] = None

    def __enter__(self) -> "parse_deadline":
        self._previous = getattr(_local, "deadline", None)
        deadline = (time.monotonic() + self.seconds) if self.seconds and self.seconds > 0 else None
        if self._previous is not None and (deadline is None or self._previous < deadline):
            deadline = self._previous
        _local.deadline = deadline
        return self

    def __exit__(self, *exc: Any) -> None:
        _local.deadline = self._previous


_monotonic = time.monotonic


def check_deadline() -> None:
    """Raise ParseBudgetExceeded once this thread's deadline has passed.

    The clock is read on every call, so the check fires at the first call after
    the deadline however rarely a loop calls it. (It used to read the clock only
    every 256th call: a loop whose iterations take a tenth of a second each could
    then run 25 seconds past its deadline.) One clock read costs no more than the
    counter it replaced — measured at 0.07 microseconds per call on CPython 3.9,
    against 0.11 for the counter, and no measurable difference on whole parses of
    4-28 MiB binaries — so it is still fine inside hot loops.
    """
    deadline = getattr(_local, "deadline", None)
    if deadline is not None and _monotonic() > deadline:
        raise ParseBudgetExceeded("Analysis exceeded its time budget; the file may be malformed or adversarial.")


# ---------------------------------------------------------------------------
# Per-analysis work budgets
# ---------------------------------------------------------------------------
# Some work cannot be interrupted once started (a plist parse, a regex scan, a
# hash) and a file can ask for the same expensive thing many times over, from
# every slice. Such work is bounded by a byte budget that is shared by the whole
# analysis of one file rather than by a per-call limit: the parser entry point
# runs inside `work_budgets()`, and each expensive step asks `spend_budget()`
# before it runs.
class work_budgets:
    """Context manager: one fresh set of budgets for the analysis of one file."""

    def __init__(self) -> None:
        self._previous: Optional[Dict[str, int]] = None

    def __enter__(self) -> "work_budgets":
        self._previous = getattr(_local, "budgets", None)
        _local.budgets = {}
        return self

    def __exit__(self, *exc: Any) -> None:
        _local.budgets = self._previous


def spend_budget(name: str, amount: int, limit: int) -> bool:
    """Charge `amount` units to budget `name` of the analysis running on this
    thread. False, and nothing charged, when that would take it past `limit`.
    Outside `work_budgets()` there is nothing to share a budget with: always True."""
    budgets = getattr(_local, "budgets", None)
    if budgets is None:
        return True
    used = budgets.get(name, 0)
    if used + amount > limit:
        return False
    budgets[name] = used + amount
    return True


def encode_json(payload: Any) -> bytes:
    """Compact UTF-8 JSON. Strings taken from binaries may hold lone surrogates,
    which UTF-8 cannot carry; those documents fall back to ASCII escapes."""
    try:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except UnicodeEncodeError:
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")


# ---------------------------------------------------------------------------
# gzip built from shared, independently compressed pieces
# ---------------------------------------------------------------------------
# A document's JSON is compressed once and that one buffer is then used in every
# response that carries the document, on its own (/api/parse) or embedded in a
# larger object (/api/patch). That works because a deflate stream may be a chain
# of segments, each ending on a flush: `deflate_segment` makes such a segment and
# `gzip_from_segments` frames a chain as one ordinary single-member gzip body.
GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"   # deflate, no name, no mtime, OS unknown
_DEFLATE_END = b"\x03\x00"                                  # an empty final block
DOCUMENT_GZIP_LEVEL = 3   # measured on 3-20 MiB documents: 12 % of the size at about 55 MiB/s (level 6: 10 %, 25 MiB/s)


def deflate_segment(data: bytes, level: int = DOCUMENT_GZIP_LEVEL) -> bytes:
    """Raw deflate of `data`, ending on a byte boundary and not closing the stream."""
    import zlib

    comp = zlib.compressobj(level, zlib.DEFLATED, -15)
    return comp.compress(data) + comp.flush(zlib.Z_FULL_FLUSH)


def gzip_from_segments(segments: List[bytes], crc32: int, size: int) -> List[bytes]:
    """The parts of a gzip body whose content is the concatenation of what the
    segments were made from; `crc32` and `size` are of that whole content."""
    import struct

    trailer = _DEFLATE_END + struct.pack("<II", crc32 & 0xFFFFFFFF, size & 0xFFFFFFFF)
    return [GZIP_HEADER] + list(segments) + [trailer]


MAX_FILENAME_CHARS = 120


def sanitize_filename(name: Any, default: str = "uploaded_binary") -> str:
    """Reduce a client-supplied file name to a short, printable base name.

    The result is only ever displayed; it is never used to open anything.
    """
    text = str(name or "").replace("\\", "/").rsplit("/", 1)[-1]
    try:
        import unicodedata

        # Drops control, format (bidi overrides, zero-width), surrogate and unassigned code points.
        text = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")
    except ImportError:  # pragma: no cover - unicodedata is part of every supported runtime
        text = "".join(ch for ch in text if 0x20 <= ord(ch) < 0x7F)
    text = " ".join(text.split())[:MAX_FILENAME_CHARS].strip()
    return text or default


def deadline_remaining() -> Optional[float]:
    """Seconds left on this thread's deadline, or None when there is none."""
    deadline = getattr(_local, "deadline", None)
    if deadline is None:
        return None
    return deadline - time.monotonic()
