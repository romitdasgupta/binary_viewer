"""
The analysis worker process: the child side of `backend/workers.py`.

The HTTP server (public mode) does not parse uploads in its own threads. It
hands each file to one of a few of these processes over a pair of pipes and waits
for the answer with a deadline. Python cannot interrupt a thread, but it can
kill a process: a worker that overruns the parse budget is killed and replaced,
and the request gets a clean error. The same isolation bounds what one hostile
file can do to memory (RLIMIT_AS, where the platform enforces it) and keeps a
parser crash away from everyone else's documents.

Wire format, both directions:

    magic (4 bytes: b"BSRQ" request, b"BSRS" response)
    header length (uint32, big endian), payload length (uint64, big endian)
    header: JSON object
    payload: bytes

Requests:  {"op": "ping"}
           {"op": "document", "path", "filename", "doc_id", "timeout"}  + the file
           {"op": "probe", "timeout"}                                   + the file
Responses: {"ok": true, ...stats}  + for "document": the document's JSON followed by
                                     its deflate segment (header says where: "json_size")
           {"ok": false, "kind", "message"} with kind one of
                parse_failed | too_large | timeout | memory | internal

Never imported by the server process, by the CLI or by the in-browser build
(tools/build_static.py leaves this file and workers.py out of the engine bundle):
`resource` and process control live only here. Standard library only.
"""

import json
import os
import struct
import sys
import time
from typing import Any, Dict, Optional, Tuple

REQUEST_MAGIC = b"BSRQ"
RESPONSE_MAGIC = b"BSRS"
PREFIX = struct.Struct(">4sIQ")
MAX_HEADER_BYTES = 64 * 1024


def pack_message(magic: bytes, header: Dict[str, Any], payload_size: int) -> bytes:
    encoded = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return PREFIX.pack(magic, len(encoded), payload_size) + encoded


# ---------------------------------------------------------------------------
# Child process
# ---------------------------------------------------------------------------
def _read_exact(fd: int, count: int) -> Optional[bytes]:
    """Exactly `count` bytes from `fd`; None when the stream ended first."""
    if count == 0:
        return b""
    view = memoryview(bytearray(count))
    got = 0
    while got < count:
        chunk = os.readv(fd, [view[got:]]) if hasattr(os, "readv") else None
        if chunk is None:
            data = os.read(fd, min(count - got, 1 << 20))
            if not data:
                return None
            view[got:got + len(data)] = data
            got += len(data)
            continue
        if chunk == 0:
            return None
        got += chunk
    return bytes(view)


def _write_all(fd: int, *parts: bytes) -> None:
    for part in parts:
        view = memoryview(part)
        while view:
            sent = os.write(fd, view[: 1 << 20])
            view = view[sent:]


def _apply_limits(memory_bytes: int) -> Dict[str, Any]:
    """Kernel-enforced bounds for this process. Each is best effort: a platform (or a
    seccomp filter) that refuses one leaves the others, and the parent's deadline, in place."""
    applied: Dict[str, Any] = {}
    try:
        # Linux: if the machine (or the service's memory cgroup) runs out, this process
        # is the one to kill, not the server that holds everybody's documents.
        with open("/proc/self/oom_score_adj", "w") as handle:
            handle.write("1000")
        applied["oom_score_adj"] = 1000
    except OSError:
        pass
    try:
        import resource
    except ImportError:
        return applied
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))   # no core files holding someone's upload
        applied["core"] = 0
    except (ValueError, OSError):
        pass
    if memory_bytes > 0:
        try:
            _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            limit = memory_bytes if hard == resource.RLIM_INFINITY else min(memory_bytes, hard)
            resource.setrlimit(resource.RLIMIT_AS, (limit, hard))
            applied["address_space"] = limit
        except (ValueError, OSError, AttributeError):
            pass
    return applied


def _arm_cpu_limit(seconds: float) -> None:
    """Let the kernel end this process if the coming job burns far more CPU than its
    budget, even if the parent were unable to (soft RLIMIT_CPU -> SIGXCPU, fatal by default)."""
    try:
        import resource

        used = resource.getrusage(resource.RUSAGE_SELF)
        _soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
        want = int(used.ru_utime + used.ru_stime + seconds) + 2
        if hard != resource.RLIM_INFINITY:
            want = min(want, hard)
        resource.setrlimit(resource.RLIMIT_CPU, (want, hard))
    except (ImportError, ValueError, OSError, AttributeError):
        pass


def _peak_rss_bytes() -> int:
    try:
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(peak if sys.platform == "darwin" else peak * 1024)
    except (ImportError, ValueError, OSError):
        return 0


def _quiet_excepthook(exc_type: Any, exc: Any, tb: Any) -> None:
    # Exception text can quote bytes of the file being analysed; the server's log gets the type
    # and where it happened, as for any other internal error.
    import traceback

    frames = ["%s:%d:%s" % (f.filename.replace("\\", "/").rsplit("/", 1)[-1], f.lineno or 0, f.name)
              for f in traceback.extract_tb(tb)[-8:]]
    try:
        sys.stderr.write(json.dumps({"level": "error", "event": "parse_worker_crash", "exc": exc_type.__name__,
                                     "where": frames}) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def _run_job(header: Dict[str, Any], payload: bytes, config: Any) -> Tuple[Dict[str, Any], Tuple[bytes, ...], bool]:
    """(response header, payload parts, keep serving?)"""
    from . import runtime
    from .service import analyse_document, probe_bytes

    op = header.get("op")
    if op == "ping":
        return {"ok": True, "pid": os.getpid(), "python": sys.version.split()[0]}, (), True
    try:
        timeout = float(header.get("timeout") or 0)
    except (TypeError, ValueError):
        timeout = 0.0
    if timeout <= 0:
        timeout = float(config.parse_timeout_seconds or 0)
    if timeout > 0:
        _arm_cpu_limit(timeout + float(config.parse_kill_grace_seconds) + 5.0)
    started = time.monotonic()
    try:
        with runtime.use_config(config), runtime.parse_deadline(timeout if timeout > 0 else None):
            if op == "probe":
                reason = probe_bytes(payload)
                out: Dict[str, Any] = {"ok": True, "parses": reason is None, "reason": reason}
                parts: Tuple[bytes, ...] = ()
            elif op == "document":
                _doc, encoded = analyse_document(
                    payload, str(header.get("path") or "<memory>"), str(header.get("filename") or ""),
                    str(header.get("doc_id") or ""), config)
                del _doc
                # Compressed here, off the server's threads; every gzip response for this
                # document reuses the result.
                deflated = runtime.deflate_segment(encoded)
                out = {"ok": True, "json_size": len(encoded)}
                parts = (encoded, deflated)
            else:
                return {"ok": False, "kind": "internal", "message": "unknown operation"}, (), True
    except runtime.ParseBudgetExceeded as exc:
        return {"ok": False, "kind": "timeout", "message": str(exc)}, (), True
    except runtime.TooLarge as exc:
        return {"ok": False, "kind": "too_large", "message": exc.message}, (), True
    except runtime.ApiError as exc:
        return {"ok": False, "kind": "parse_failed", "message": exc.message}, (), True
    except MemoryError:
        # The heap is in an unknown state; answer and let the pool start a fresh process.
        return {"ok": False, "kind": "memory", "message": ""}, (), False
    except RecursionError:
        return {"ok": False, "kind": "internal", "message": "RecursionError"}, (), False
    except Exception as exc:  # noqa: BLE001 - a parser defect; the type is all that leaves this process
        return {"ok": False, "kind": "internal", "message": type(exc).__name__}, (), True
    out["seconds"] = round(time.monotonic() - started, 3)
    out["peak_rss"] = _peak_rss_bytes()
    return out, parts, True


def main(argv: Optional[list] = None) -> int:
    """Serve requests arriving on stdin, answering on stdout, until stdin closes."""
    args = list(sys.argv[1:] if argv is None else argv)
    settings = json.loads(args[0]) if args else {}
    sys.excepthook = _quiet_excepthook

    # Take the protocol descriptors for ourselves, then point the standard streams
    # elsewhere so that nothing a library prints can corrupt the protocol.
    in_fd = os.dup(0)
    out_fd = os.dup(1)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(2, 1)
    os.close(devnull)

    from . import runtime

    mode = str(settings.get("mode") or "public")
    overrides = {key: settings[key] for key in ("max_document_bytes", "parse_timeout_seconds", "parse_kill_grace_seconds")
                 if key in settings}
    config = runtime.RuntimeConfig(mode, **overrides)
    runtime.set_config(config)
    _apply_limits(int(settings.get("memory_bytes") or 0))
    max_payload = int(settings.get("max_payload_bytes") or 0)

    # Importing the parsers now makes the first request as fast as the rest.
    from . import service  # noqa: F401

    while True:
        prefix = _read_exact(in_fd, PREFIX.size)
        if prefix is None:
            return 0
        magic, header_size, payload_size = PREFIX.unpack(prefix)
        if magic != REQUEST_MAGIC or header_size > MAX_HEADER_BYTES or (max_payload and payload_size > max_payload):
            return 2
        raw_header = _read_exact(in_fd, header_size)
        payload = _read_exact(in_fd, payload_size) if raw_header is not None else None
        if raw_header is None or payload is None:
            return 0
        try:
            header = json.loads(raw_header.decode("utf-8"))
            if not isinstance(header, dict):
                raise ValueError("header")
        except (ValueError, UnicodeDecodeError):
            return 2
        try:
            response, parts, keep = _run_job(header, payload, config)
        except MemoryError:
            response, parts, keep = {"ok": False, "kind": "memory", "message": ""}, (), False
        del payload
        response.setdefault("peak_rss", _peak_rss_bytes())
        try:
            _write_all(out_fd, pack_message(RESPONSE_MAGIC, response, sum(len(p) for p in parts)), *parts)
        except OSError:
            return 0
        del parts
        if not keep:
            return 3


if __name__ == "__main__":
    sys.exit(main())
