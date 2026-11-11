"""
A small pool of analysis worker processes: the parent side of `parse_worker.py`.

`AnalysisService` calls `pool.run(...)` for every analysis once the HTTP server
has given it a pool (`service.set_executor`). The pool hands the file to an idle
worker over a pair of pipes (plain pipes rather than a socket pair, so a sandbox
that only allows the INET address families needs no exception) and waits for the
answer until the parse budget, plus a short grace, has
run out; then it kills the worker, starts another, and the request gets the same
clean `timeout` error an in-thread deadline would have produced. Nothing a single
upload does can therefore hold an analysis slot, or the process, hostage:

  * runs too long            -> the worker is killed at budget + grace
  * needs too much memory    -> the worker's RLIMIT_AS makes the allocation fail
                                (MemoryError, reported) or the worker dies; both
                                are an error for that one request
  * crashes the interpreter  -> that worker is gone; the server and every cached
                                document are untouched

The result that comes back is JSON, never pickle: a worker is the process that
touches hostile bytes, so the server does not let it name objects to build.

Imported only by `backend/server.py`. If a worker cannot be started at all
(no permission to create processes, an exotic platform) the pool says so once
in the log and analyses run in the calling thread, as they do without a pool.
"""

import json
import os
import re
import select
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from . import runtime
from .parse_worker import MAX_HEADER_BYTES, PREFIX, REQUEST_MAGIC, RESPONSE_MAGIC, pack_message

_BOOT = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
         "from backend.parse_worker import main; sys.exit(main())")

SPAWN_TIMEOUT_SECONDS = 20.0
MAX_JOBS_PER_WORKER = 200          # a worker is replaced after this many analyses
# ... and after any analysis that took its peak memory past this: CPython does not hand
# freed memory back, and an idle worker should cost its 35 MiB, not what its largest file
# needed (measured: 190-210 MiB for documents of 12-20 MiB of JSON). A new one starts in 0.15 s.
WORKER_RECYCLE_RSS_BYTES = 128 * 1024 * 1024
_TIMEOUT_MESSAGE = "Analysis exceeded its time budget; the file may be malformed or adversarial."

# A document never holds an integer of more than 20 digits (64 bits; larger values
# are emitted as hex strings). A run of digits this long in a worker's answer is
# either inside a string or an attempt to make int() spend minutes on it.
_LONG_DIGIT_RUN = re.compile(rb"[0-9]{41}")


def _bounded_int(text: str) -> int:
    if len(text) > 40:
        raise ValueError("integer too long")
    return int(text)


class _WorkerTimeout(Exception):
    pass


class _WorkerBroken(Exception):
    pass


class _Worker:
    """One child process and the two pipes to it (non-blocking on this side)."""

    def __init__(self, proc: "subprocess.Popen[bytes]") -> None:
        self.proc = proc
        self.out_fd = proc.stdin.fileno()    # type: ignore[union-attr]  # we write requests here
        self.in_fd = proc.stdout.fileno()    # type: ignore[union-attr]  # and read answers here
        os.set_blocking(self.out_fd, False)
        os.set_blocking(self.in_fd, False)
        self.jobs = 0
        self.peak_rss = 0

    @staticmethod
    def _wait(fd: int, writing: bool, deadline: Optional[float]) -> None:
        """Block until `fd` is ready, or raise _WorkerTimeout at the deadline."""
        timeout: Optional[float] = None
        if deadline is not None:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise _WorkerTimeout()
        if hasattr(select, "poll"):          # no limit on descriptor numbers, unlike select()
            poller = select.poll()
            poller.register(fd, select.POLLOUT if writing else select.POLLIN)
            ready = poller.poll(None if timeout is None else max(1, int(timeout * 1000)))
        else:  # pragma: no cover - platforms without poll()
            r, w, _ = select.select([] if writing else [fd], [fd] if writing else [], [], timeout)
            ready = r or w
        if not ready:
            raise _WorkerTimeout()

    def _send_all(self, data: Any, deadline: Optional[float]) -> None:
        view = memoryview(data)
        while view:
            self._wait(self.out_fd, True, deadline)
            try:
                sent = os.write(self.out_fd, view[: 1 << 20])
            except BlockingIOError:
                continue
            except OSError:
                raise _WorkerBroken()
            view = view[sent:]

    def _recv_exact(self, count: int, deadline: Optional[float]) -> bytearray:
        buf = bytearray(count)
        view = memoryview(buf)
        got = 0
        while got < count:
            self._wait(self.in_fd, False, deadline)
            try:
                n = os.readv(self.in_fd, [view[got:got + (1 << 20)]])
            except BlockingIOError:
                continue
            except OSError:
                raise _WorkerBroken()
            if n == 0:
                raise _WorkerBroken()
            got += n
        return buf

    def exchange(self, header: Dict[str, Any], payload: bytes, seconds: Optional[float],
                 max_response: int) -> Tuple[Dict[str, Any], bytearray]:
        """Send one request and wait for its answer, for at most `seconds` in all."""
        deadline = (time.monotonic() + seconds) if seconds is not None else None
        self._send_all(pack_message(REQUEST_MAGIC, header, len(payload)), deadline)
        if payload:
            self._send_all(payload, deadline)
        magic, header_size, payload_size = PREFIX.unpack(bytes(self._recv_exact(PREFIX.size, deadline)))
        if magic != RESPONSE_MAGIC or header_size > MAX_HEADER_BYTES or payload_size > max_response:
            raise _WorkerBroken()
        try:
            answer = json.loads(bytes(self._recv_exact(header_size, deadline)).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise _WorkerBroken()
        if not isinstance(answer, dict):
            raise _WorkerBroken()
        return answer, self._recv_exact(payload_size, deadline)

    def stop(self, kill: bool = True) -> Optional[int]:
        """End the process (at once, or by closing its input) and reap it."""
        for stream in (self.proc.stdin, self.proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
        try:
            if kill:
                self.proc.kill()
            try:
                return self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                return self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return None


class WorkerPool:
    """At most `size` worker processes, started on demand and reused."""

    def __init__(self, config: runtime.RuntimeConfig, log: Any = None, size: Optional[int] = None,
                 root: Optional[str] = None) -> None:
        self.config = config
        self.log = log
        self.size = max(1, int(size if size is not None else (config.parse_worker_count() or 1)))
        self.root = root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._lock = threading.Lock()
        self._idle: List[_Worker] = []
        self._live = 0
        self._slots = threading.BoundedSemaphore(self.size)
        self._closed = False
        self.disabled = False       # set when no worker could be started; analyses then run in-thread
        self.killed = 0             # workers killed for overrunning (for tests and the log)
        self.died = 0               # workers that went away by themselves
        self.spawned = 0
        max_doc = int(config.max_document_bytes or 0)
        # The answer holds the document's JSON and its deflate segment (never larger
        # than the JSON plus a few bytes per 16 KiB).
        self._max_response = (2 * max_doc + (1 << 20)) if max_doc > 0 else (4 << 30)
        memory = int(config.parse_worker_memory_bytes or 0)
        self._recycle_rss = WORKER_RECYCLE_RSS_BYTES
        self._settings = json.dumps({
            "mode": config.mode,
            "max_document_bytes": max_doc,
            "parse_timeout_seconds": float(config.parse_timeout_seconds or 0),
            "parse_kill_grace_seconds": float(config.parse_kill_grace_seconds),
            "memory_bytes": memory,
            "max_payload_bytes": int(config.max_upload_bytes) + (1 << 20),
        })

    # -- processes ------------------------------------------------------------------
    def _note(self, level: str, event: str, **fields: Any) -> None:
        if self.log is not None:
            try:
                self.log.write(level, event, **fields)
            except Exception:
                pass

    def _spawn(self) -> _Worker:
        env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "LANG", "LC_ALL", "TMPDIR") if key in os.environ}
        proc = subprocess.Popen(
            # -I: no environment variables, no user site, no script directory on the
            # path; -B: nothing is written next to the code. close_fds (the default)
            # keeps the listening socket and every client connection out of the child.
            [sys.executable, "-I", "-B", "-c", _BOOT, self.root, self._settings],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, bufsize=0, close_fds=True,
            cwd=self.root, env=env,
        )
        worker = _Worker(proc)
        try:
            answer, _ = worker.exchange({"op": "ping"}, b"", SPAWN_TIMEOUT_SECONDS, 0)
            if not answer.get("ok"):
                raise _WorkerBroken()
        except (_WorkerTimeout, _WorkerBroken):
            code = worker.stop()
            raise OSError("analysis worker did not start (exit status %r)" % (code,))
        self.spawned += 1
        return worker

    def _checkout(self) -> Optional[_Worker]:
        """An idle worker, or a new one; None when workers cannot be started."""
        with self._lock:
            if self._closed or self.disabled:
                return None
            if self._idle:
                return self._idle.pop()
            self._live += 1
        try:
            return self._spawn()
        except Exception as exc:  # noqa: BLE001 - whatever stops a process from starting
            with self._lock:
                self._live -= 1
                first = not self.disabled and self.spawned == 0
                if self.spawned == 0:
                    self.disabled = True
            if first:
                self._note("error", "parse_workers_unavailable", exc=type(exc).__name__,
                           action="analysing in the server process instead")
            return None

    def _checkin(self, worker: _Worker) -> None:
        retire = worker.jobs >= MAX_JOBS_PER_WORKER or worker.peak_rss > self._recycle_rss
        with self._lock:
            if not retire and not self._closed:
                self._idle.append(worker)
                return
            self._live -= 1
            closed = self._closed
        worker.stop(kill=False)
        if not closed:
            # Have the replacement ready before the next upload needs it.
            threading.Thread(target=self.prewarm, args=(1,), name="binarystudio-worker-spawn", daemon=True).start()

    def _discard(self, worker: _Worker) -> Optional[int]:
        with self._lock:
            self._live -= 1
        return worker.stop(kill=True)

    def prewarm(self, count: Optional[int] = None) -> int:
        """Start workers now so the first uploads do not wait for an interpreter to boot."""
        started: List[_Worker] = []
        for _ in range(min(self.size, count if count is not None else self.size)):
            with self._lock:
                if self._closed or self.disabled or self._live >= self.size:
                    break
                self._live += 1
            try:
                started.append(self._spawn())
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self._live -= 1
                    if self.spawned == 0:
                        self.disabled = True
                self._note("error", "parse_workers_unavailable", exc=type(exc).__name__,
                           action="analysing in the server process instead")
                break
        with self._lock:
            if self._closed:
                leftovers, started = started, []
            else:
                leftovers = []
                self._idle.extend(started)
        for worker in leftovers:
            self._discard(worker)
        return len(started)

    def live_workers(self) -> int:
        with self._lock:
            return self._live

    def worker_pids(self) -> List[int]:
        with self._lock:
            return [w.proc.pid for w in self._idle]

    def close(self) -> None:
        with self._lock:
            self._closed = True
            idle, self._idle = self._idle, []
            self._live -= len(idle)
        for worker in idle:
            worker.stop(kill=True)

    # -- the executor interface used by AnalysisService ---------------------------------
    def run(self, job: str, data: bytes, virtual_path: str, filename: str, doc_id: str,
            remaining: Optional[float]) -> Any:
        """One analysis. `remaining` is what is left of the caller's parse budget in
        seconds (None = no budget). Returns what `AnalysisService._analyse` documents."""
        from .service import analyse_document, probe_bytes

        cfg = self.config
        wait = max(0.0, float(cfg.parse_queue_seconds))
        if not (self._slots.acquire(timeout=wait) if wait > 0 else self._slots.acquire(blocking=False)):
            raise runtime.Busy("The server is busy analysing other files. Try again in a moment.",
                               headers={"Retry-After": "3"})
        try:
            worker = self._checkout()
            if worker is None:
                # No worker processes on this system: same work, in this thread, under the
                # caller's deadline (and the server's watchdog as the last resort).
                if job == "probe":
                    return probe_bytes(data)
                doc, encoded = analyse_document(data, virtual_path, filename, doc_id, cfg)
                return doc, encoded, None
            header = {"op": job, "path": virtual_path, "filename": filename, "doc_id": doc_id,
                      "timeout": remaining if remaining is not None else 0}
            seconds = (remaining + float(cfg.parse_kill_grace_seconds)) if remaining is not None else None
            started = time.monotonic()
            try:
                answer, payload = worker.exchange(header, data, seconds, self._max_response)
            except _WorkerTimeout:
                self._discard(worker)
                self.killed += 1
                self._note("warn", "parse_worker_killed", reason="overran its time budget",
                           seconds=round(time.monotonic() - started, 1), bytes_in=len(data))
                raise runtime.ParseBudgetExceeded(_TIMEOUT_MESSAGE)
            except _WorkerBroken:
                code = self._discard(worker)
                self.died += 1
                self._note("error", "parse_worker_died", exit_status=code,
                           seconds=round(time.monotonic() - started, 1), bytes_in=len(data))
                raise runtime.ParseFailed("The analysis of this file stopped unexpectedly; the file may be "
                                          "malformed, or need more memory than this server allows.")
            worker.jobs += 1
            worker.peak_rss = int(answer.get("peak_rss") or 0)
            if not answer.get("ok") and answer.get("kind") in ("memory", "internal"):
                # It said it is exiting, or its state is suspect: do not reuse it.
                self._discard(worker)
            else:
                self._checkin(worker)
        finally:
            self._slots.release()
        return self._result(job, answer, payload, doc_id)

    def _result(self, job: str, answer: Dict[str, Any], payload: bytearray, doc_id: str) -> Any:
        if not answer.get("ok"):
            kind = answer.get("kind")
            message = str(answer.get("message") or "")
            if kind == "timeout":
                raise runtime.ParseBudgetExceeded(message or _TIMEOUT_MESSAGE)
            if kind == "too_large":
                raise runtime.TooLarge(message or "The analysis of this file is too large to serve.")
            if kind == "parse_failed":
                raise runtime.ParseFailed(message or "The file could not be parsed.")
            if kind == "memory":
                self._note("warn", "parse_worker_memory", action="analysis refused")
                raise runtime.ParseFailed("Analysing this file needs more memory than this server allows.")
            # A defect in a parser. The router logs it as an internal error; the type
            # name is all the worker let out.
            raise RuntimeError("analysis worker: %s" % (message[:80] or "internal error"))
        if job == "probe":
            reason = answer.get("reason")
            return None if answer.get("parses") else (str(reason) if reason else "The file could not be parsed.")
        json_size = answer.get("json_size")
        if not isinstance(json_size, int) or not (0 < json_size <= len(payload)):
            raise RuntimeError("analysis worker: malformed answer")
        view = memoryview(payload)
        encoded = bytes(view[:json_size])
        deflated = bytes(view[json_size:]) or None
        del view
        try:
            if _LONG_DIGIT_RUN.search(encoded):
                doc = json.loads(encoded.decode("utf-8"), parse_int=_bounded_int)
            else:
                doc = json.loads(encoded.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise RuntimeError("analysis worker: answer is not a document")
        if not isinstance(doc, dict) or doc.get("doc_id") != doc_id or not isinstance(doc.get("slices"), list):
            raise RuntimeError("analysis worker: answer is not a document")
        return doc, encoded, deflated
