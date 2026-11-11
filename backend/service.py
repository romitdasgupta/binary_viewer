"""
Layer 3: AnalysisService — the document store, windowed hex slicing, live byte
decoder, bidirectional VMAddr <-> file offset translator, disassembly and search.

Documents are addressed by an opaque id:

  preset:<id>          a built-in sample (never a caller-supplied path)
  u_<32 hex>           an upload; the random id is the only way to reach its bytes
  p_<32 hex>           a document derived from another one (patched bytes)
  path:<absolute path> a file on this machine — local mode only

The store is bounded by document count and by an estimate of memory use, and
in public mode by idle time. Unknown, evicted and expired ids all look the
same to a caller: `DocExpired` (HTTP 410), after which the client re-uploads.

Local mode keeps the older single-user conveniences: `load_file(path)`, the
`path=` argument, and an implicit "active document" used when a call names
none. None of them exist when `config.allow_path_load` is off.

Nothing here touches sockets or starts threads, so the same class runs inside
Pyodide.
"""

import math
import os
import re
import secrets
import stat
import struct
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import runtime
from .buffer import BinaryBuffer
from .disasm import decode_single_arm64_preview, decode_x86_64_insn, disassemble_window, instruction_set
from .parser import parse_macho_bytes
from .runtime import (
    BadRequest,
    Busy,
    DocExpired,
    Forbidden,
    NotFound,
    ParseBudgetExceeded,
    ParseFailed,
    RuntimeConfig,
    TooLarge,
    check_deadline,
    sanitize_filename,
)

RANDOM_ID_RE = re.compile(r"^[up]_[0-9a-f]{32}$")
PRESET_ID_RE = re.compile(r"^[a-z0-9_]{1,48}$")

# Memory charged for a cached document, as a multiple of its JSON size. Measured
# with tracemalloc on the fixtures, macOS system binaries and multi-slice files
# with 14-20 MiB of JSON:
#   the Python objects   1.5x - 3.0x when the parse ran in this process,
#                        2.9x - 3.7x when json.loads rebuilt them from a worker's
#                        result (no objects are shared between fields then)
#   the JSON itself      1x    (one buffer shared by every response)
#   the JSON deflated    0.12x - 0.17x (one buffer shared by every gzip response)
# which is at most 4.9x; charged as 5x, plus the file's bytes (see document_cost).
DOC_COST_FACTOR = 5


def document_cost(data_size: int, json_size: int) -> int:
    """Estimated memory held by one cached document, in bytes."""
    return data_size + DOC_COST_FACTOR * json_size


def analyse_document(data: bytes, virtual_path: str, filename: str, doc_id: str,
                     config: RuntimeConfig) -> Tuple[Dict[str, Any], bytes]:
    """The whole analysis of one file: parse, label, encode. Returns (document, its JSON).

    Runs in a server thread, or in a worker process (backend/parse_worker.py) when
    the server keeps a pool; the caller has set the runtime config and deadline.
    Raises ParseFailed, TooLarge or ParseBudgetExceeded."""
    try:
        doc = parse_macho_bytes(data, path=virtual_path)
    except (ParseBudgetExceeded, runtime.ApiError):
        raise
    except ValueError as exc:
        raise ParseFailed(_clean_message(str(exc)) or "The file could not be parsed.")
    info = doc.get("file_info")
    if isinstance(info, dict):
        info["filename"] = filename
        info["path"] = virtual_path
    doc["doc_id"] = doc_id
    check_deadline()
    encoded = runtime.encode_json(doc)
    if config.max_document_bytes > 0 and len(encoded) > config.max_document_bytes:
        raise TooLarge("The analysis of this file is too large to serve.")
    return doc, encoded


def probe_bytes(data: bytes) -> Optional[str]:
    """None when `data` parses, else the parser's (cleaned) reason."""
    try:
        parse_macho_bytes(data, path="<probe>")
    except (ParseBudgetExceeded, runtime.ApiError):
        raise
    except ValueError as exc:
        return _clean_message(str(exc)) or "The file could not be parsed."
    return None

MAX_SEARCH_QUERY_CHARS = 256
MAX_SEARCH_RESULTS = 200

# (id, label, file under fixtures/, format, description)
SYNTHETIC_PRESETS: List[Tuple[str, str, str, str, str]] = [
    ("synthetic_universal", "Mach-O Universal", "synthetic_universal", "MACHO",
     "Multi-arch Mach-O binary (arm64 + x86_64) with custom segments, C++/ObjC symbols, chained fixups & entitlements"),
    ("synthetic_firmware", "Firmware (MH_PRELOAD)", "synthetic_firmware.preload", "MACHO",
     "Standalone ARM64 firmware image with LC_UNIXTHREAD state and RWX segment warning"),
    ("synthetic_elf64", "ELF64 (x86_64)", "synthetic_elf64", "ELF",
     "Hardened 64-bit Linux PIE with Full RELRO, Intel CET (IBT/SHSTK), Build-ID & PLT/GOT relocations"),
    ("synthetic_elf32", "ELF32 (i386)", "synthetic_elf32", "ELF",
     "32-bit x86 ET_EXEC binary with non-PIE fixed base and executable stack warning"),
    ("synthetic_pe64", "PE32+ (Win64)", "synthetic_pe64.exe", "PE",
     "Windows PE32+ with Rich Header, ASLR/DEP/CFG, IAT Imports, Forwarded Exports, RSDS PDB & Authenticode"),
    ("synthetic_pe32", "PE32 (Win32)", "synthetic_pe32.exe", "PE",
     "32-bit Windows PE32 with pre-main TLS Callback and RWX section anomaly"),
]

# (id, label, absolute path, description) — offered only when config.allow_host_presets
HOST_PRESETS: List[Tuple[str, str, str, str]] = [
    ("bin_ls", "/bin/ls", "/bin/ls", "Host system /bin/ls executable (Mach-O on macOS / ELF64 on Linux)"),
    ("usr_bin_true", "/usr/bin/true", "/usr/bin/true", "Host system /usr/bin/true minimal executable"),
]


def _clean_message(text: str, limit: int = 300) -> str:
    """Make an exception message safe to show: printable, single line, bounded."""
    cleaned = "".join(ch if 0x20 <= ord(ch) < 0x7F or ord(ch) > 0x9F else " " for ch in str(text))
    cleaned = " ".join(cleaned.split())
    return cleaned[:limit]


def _sniff_format(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            magic = handle.read(4)
    except OSError:
        return None
    if magic[:4] == b"\x7fELF":
        return "ELF"
    if magic[:2] == b"MZ":
        return "PE"
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
                 b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
        return "MACHO"
    return None


class DocEntry:
    """One cached document: the parsed result plus the bytes it came from."""

    __slots__ = ("doc_id", "kind", "doc", "data", "filename", "disk_path", "stamp", "cost",
                 "created", "last_access", "pinned", "encoded", "owner", "parent_id",
                 "_etag", "_deflated", "_crc32", "_lock")

    def __init__(self, doc_id: str, kind: str, doc: Dict[str, Any], data: bytes, filename: str,
                 disk_path: Optional[str] = None, stamp: Optional[Tuple[int, int]] = None,
                 cost: int = 0, encoded: Optional[bytes] = None, owner: Optional[str] = None,
                 parent_id: Optional[str] = None, deflated: Optional[bytes] = None) -> None:
        self.owner = owner          # rate-limit identity of the uploader, for the per-client cache share
        # For a derived (patched) document: the document it was made from. The store
        # never evicts that one to make room for this one.
        self.parent_id = parent_id
        self._etag: Optional[str] = None
        # `encoded` as one raw-deflate segment (runtime.deflate_segment), made once and
        # shared by every gzip response that carries the document.
        self._deflated = deflated
        self._crc32: Optional[int] = None
        self._lock = threading.Lock()
        self.doc_id = doc_id
        self.kind = kind            # 'preset' | 'upload' | 'derived' | 'path'
        self.doc = doc
        self.data = data
        self.filename = filename
        self.disk_path = disk_path  # set only for files this process may hand to local tools
        self.stamp = stamp          # (mtime_ns, size) of disk_path when it was read
        self.cost = cost
        self.created = 0.0
        self.last_access = 0.0
        self.pinned = False
        # The document as JSON. Serving this one immutable buffer means a client
        # that asks for a large document and reads it slowly, many times over,
        # ties up connections but not a fresh copy of the document each time.
        self.encoded = encoded

    def json_bytes(self) -> bytes:
        """The document as JSON: the one shared buffer when there is one."""
        if self.encoded is None:
            self.encoded = runtime.encode_json(self.doc)
        return self.encoded

    def etag(self) -> str:
        """A validator for the document's JSON (and so for anything derived from it alone)."""
        if self._etag is None:
            import hashlib

            self._etag = "d" + hashlib.sha256(self.json_bytes()).hexdigest()[:24]
        return self._etag

    def data_etag(self) -> str:
        """A validator for the document's bytes."""
        info = self.doc.get("file_info") if isinstance(self.doc, dict) else None
        digest = info.get("sha256") if isinstance(info, dict) else None
        if not (isinstance(digest, str) and len(digest) == 64):
            import hashlib

            digest = hashlib.sha256(self.data).hexdigest()
        return "b" + digest[:24]

    def crc32(self) -> int:
        if self._crc32 is None:
            import zlib

            self._crc32 = zlib.crc32(self.json_bytes()) & 0xFFFFFFFF
        return self._crc32

    def deflated(self) -> bytes:
        """The JSON as a deflate segment, compressed on first use and then kept.
        (A worker process hands it over ready-made; in-thread it costs the first
        gzip request about 18 ms per MiB of JSON, with the GIL released.)"""
        if self._deflated is None:
            with self._lock:
                if self._deflated is None:
                    self._deflated = runtime.deflate_segment(self.json_bytes())
        return self._deflated


class DocumentStore:
    """Thread-safe LRU of DocEntry, bounded by count, estimated bytes and idle time."""

    def __init__(self, max_docs: int, max_bytes: int, ttl_seconds: float,
                 clock: Callable[[], float] = time.monotonic, client_share: float = 0.0) -> None:
        self.max_docs = max_docs
        self.max_bytes = max_bytes
        self.ttl_seconds = ttl_seconds
        self.client_share = max(0.0, min(1.0, float(client_share)))
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: "OrderedDict[str, DocEntry]" = OrderedDict()
        self._pinned: Dict[str, DocEntry] = {}
        self._bytes = 0
        self.evictions = 0
        self.expirations = 0

    def _expired(self, entry: DocEntry, now: float) -> bool:
        return self.ttl_seconds > 0 and (now - entry.last_access) > self.ttl_seconds

    def _drop(self, doc_id: str) -> None:
        entry = self._entries.pop(doc_id, None)
        if entry is not None:
            self._bytes -= entry.cost

    def get(self, doc_id: str) -> Optional[DocEntry]:
        now = self._clock()
        with self._lock:
            entry = self._pinned.get(doc_id)
            if entry is not None:
                return entry
            entry = self._entries.get(doc_id)
            if entry is None:
                return None
            if self._expired(entry, now):
                self._drop(doc_id)
                self.expirations += 1
                return None
            entry.last_access = now
            self._entries.move_to_end(doc_id)
            return entry

    def put(self, entry: DocEntry, pinned: bool = False) -> DocEntry:
        now = self._clock()
        entry.created = entry.last_access = now
        with self._lock:
            if pinned:
                entry.pinned = True
                self._drop(entry.doc_id)
                self._pinned[entry.doc_id] = entry
                return entry
            self._drop(entry.doc_id)
            self._sweep_locked(now)
            self._entries[entry.doc_id] = entry
            self._bytes += entry.cost
            # Never evicted on behalf of this entry: the entry itself, and the document
            # it was derived from (a patched copy is useless without its original, and
            # the client's next patch is made against the original again).
            protected = {entry.doc_id}
            if entry.parent_id:
                protected.add(entry.parent_id)
            self._enforce_client_share(entry, protected)
            # Then the bounds of the whole cache: evict until within both. The newest
            # entry always stays.
            while len(self._entries) > 1 and (
                (self.max_docs > 0 and len(self._entries) > self.max_docs)
                or (self.max_bytes > 0 and self._bytes > self.max_bytes)
            ):
                victim = self._pick_victim(protected, by_bytes=self.max_bytes > 0 and self._bytes > self.max_bytes)
                if victim is None:
                    break
                self._drop(victim.doc_id)
                self.evictions += 1
            return entry

    def _pick_victim(self, protected: Any, by_bytes: bool) -> Optional[DocEntry]:
        """Who makes room when the whole cache is over a bound: the least recently
        used document of the client that occupies the most (bytes, or documents when
        the count is what is over). So a few clients filling the cache evict one
        another, and a client holding little keeps what it has. Documents without an
        owner (local mode) form one group, which makes this plain LRU there."""
        usage: Dict[Optional[str], int] = {}
        oldest: Dict[Optional[str], DocEntry] = {}
        for candidate in self._entries.values():          # least recently used first
            usage[candidate.owner] = usage.get(candidate.owner, 0) + (candidate.cost if by_bytes else 1)
            if candidate.doc_id not in protected and candidate.owner not in oldest:
                oldest[candidate.owner] = candidate
        if not oldest:
            return None
        heaviest = max(oldest, key=lambda owner: (usage[owner], -oldest[owner].last_access))
        return oldest[heaviest]

    def _enforce_client_share(self, newest: DocEntry, protected: Any = ()) -> None:
        """Make the uploader of `newest` pay for it with its own older documents
        first, so that filling the cache evicts the filler rather than everyone else.

        A patched copy and the original it was made from may together exceed the
        share (two documents of the largest size do): everything else of that client
        goes first and then the pair is kept, so the most one client can hold is its
        share or one such pair, whichever is larger."""
        if self.client_share <= 0 or newest.owner is None:
            return
        doc_quota = max(2, int(self.max_docs * self.client_share)) if self.max_docs > 0 else 0
        byte_quota = int(self.max_bytes * self.client_share) if self.max_bytes > 0 else 0
        mine = [e for e in self._entries.values() if e.owner == newest.owner]   # oldest first
        count = len(mine)
        used = sum(e.cost for e in mine)
        for old in mine:
            if not ((doc_quota and count > doc_quota) or (byte_quota and used > byte_quota)):
                break
            if old is newest or old.doc_id in protected:
                continue
            used -= old.cost
            count -= 1
            self._drop(old.doc_id)
            self.evictions += 1

    def remove(self, doc_id: str) -> bool:
        with self._lock:
            if doc_id in self._entries:
                self._drop(doc_id)
                return True
            return self._pinned.pop(doc_id, None) is not None

    def _sweep_locked(self, now: float) -> int:
        if self.ttl_seconds <= 0:
            return 0
        dead = [doc_id for doc_id, entry in self._entries.items() if self._expired(entry, now)]
        for doc_id in dead:
            self._drop(doc_id)
        self.expirations += len(dead)
        return len(dead)

    def sweep(self) -> int:
        """Drop every expired entry now, so idle uploads do not outlive their TTL."""
        with self._lock:
            return self._sweep_locked(self._clock())

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._pinned.clear()
            self._bytes = 0

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "docs": len(self._entries),
                "pinned": len(self._pinned),
                "bytes": self._bytes,
                "evictions": self.evictions,
                "expirations": self.expirations,
            }

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries) + len(self._pinned)


class AnalysisService:
    def __init__(self, workspace_root: str, config: Optional[RuntimeConfig] = None,
                 clock: Callable[[], float] = time.monotonic):
        self.workspace_root = os.path.abspath(workspace_root)
        self.config = config if config is not None else runtime.get_config()
        self._clock = clock
        self.store = DocumentStore(
            max_docs=self.config.cache_max_docs,
            max_bytes=self.config.cache_max_bytes,
            ttl_seconds=self.config.doc_ttl_seconds,
            clock=clock,
            client_share=self.config.cache_client_share,
        )
        # Legacy single-user state; only ever set when config.allow_path_load is on.
        self.active_doc_id: Optional[str] = None
        self._load_lock = threading.Lock()
        self._slots = (
            threading.BoundedSemaphore(self.config.max_concurrent_parses)
            if self.config.max_concurrent_parses > 0
            else None
        )
        self._running_lock = threading.Lock()
        self._running: Dict[int, float] = {}
        self._running_seq = 0
        self._executor: Any = None  # see set_executor

    # ========================================================================
    # Presets
    # ========================================================================
    def _preset_file(self, preset_id: str) -> Optional[Tuple[str, str]]:
        """(path on this machine, display filename) for a known preset id, else None."""
        for pid, _label, filename, _fmt, _desc in SYNTHETIC_PRESETS:
            if pid == preset_id:
                return os.path.join(self.workspace_root, "fixtures", filename), filename
        if self.config.allow_host_presets:
            for pid, _label, path, _desc in HOST_PRESETS:
                if pid == preset_id:
                    return path, os.path.basename(path)
        return None

    def get_presets(self) -> List[Dict[str, Any]]:
        """Built-in samples. `path` appears only when this instance may load paths."""
        expose_paths = self.config.allow_path_load
        presets: List[Dict[str, Any]] = []
        for pid, label, filename, fmt, desc in SYNTHETIC_PRESETS:
            path = os.path.join(self.workspace_root, "fixtures", filename)
            item: Dict[str, Any] = {
                "id": pid,
                "label": label,
                "description": desc,
                "format": fmt,
                "exists": os.path.isfile(path),
                "doc": f"preset:{pid}",
            }
            if expose_paths:
                item["path"] = path
            presets.append(item)
        if self.config.allow_host_presets:
            for pid, label, path, desc in HOST_PRESETS:
                item = {
                    "id": pid,
                    "label": label,
                    "description": desc,
                    "format": _sniff_format(path),
                    "exists": os.path.isfile(path),
                    "doc": f"preset:{pid}",
                }
                if expose_paths:
                    item["path"] = path
                presets.append(item)
        return presets

    def warm_presets(self) -> int:
        """Parse every available preset now. In restricted modes they are then pinned for good."""
        loaded = 0
        for preset in self.get_presets():
            if not preset["exists"]:
                continue
            try:
                self.get_entry(doc=preset["doc"])
                loaded += 1
            except Exception:
                continue
        return loaded

    # ========================================================================
    # Parsing, bounded
    # ========================================================================
    def _acquire_slot(self) -> bool:
        if self._slots is None:
            return False
        wait = max(0.0, float(self.config.parse_queue_seconds))
        acquired = self._slots.acquire(timeout=wait) if wait > 0 else self._slots.acquire(blocking=False)
        if not acquired:
            raise Busy(
                "The server is busy analysing other files. Try again in a moment.",
                headers={"Retry-After": "3"},
            )
        return True

    def oldest_parse_age(self) -> float:
        """Seconds the longest-running parse has been going; 0 when idle."""
        with self._running_lock:
            if not self._running:
                return 0.0
            return self._clock() - min(self._running.values())

    def running_parses(self) -> int:
        with self._running_lock:
            return len(self._running)

    def set_executor(self, executor: Any) -> None:
        """Run analyses through `executor` (backend/workers.py: a pool of worker
        processes) instead of in the calling thread; None goes back to in-thread.
        Only the HTTP server sets one."""
        self._executor = executor

    def _analyse(self, job: str, data: bytes, virtual_path: str = "<probe>", filename: str = "",
                 doc_id: str = "") -> Any:
        """Every analysis of bytes goes through here: one slot of the concurrency
        cap, the wall-clock budget, and the watchdog's list of running analyses.

        job 'document' -> (document, its JSON, its JSON deflated or None)
        job 'probe'    -> None when the bytes parse, else the parser's message
        """
        cfg = self.config
        held = self._acquire_slot()
        with self._running_lock:
            self._running_seq += 1
            token = self._running_seq
            self._running[token] = self._clock()
        try:
            with runtime.use_config(cfg), runtime.parse_deadline(cfg.parse_timeout_seconds):
                executor = self._executor
                if executor is not None:
                    remaining = runtime.deadline_remaining()
                    if remaining is not None and remaining <= 0:
                        raise ParseBudgetExceeded("Analysis exceeded its time budget; the file may be malformed or adversarial.")
                    return executor.run(job, data, virtual_path, filename, doc_id, remaining)
                if job == "probe":
                    return probe_bytes(data)
                doc, encoded = analyse_document(data, virtual_path, filename, doc_id, cfg)
                return doc, encoded, None
        finally:
            with self._running_lock:
                self._running.pop(token, None)
            if held:
                self._slots.release()  # type: ignore[union-attr]

    def probe_parse(self, data: bytes) -> Optional[str]:
        """Whether `data` parses: None if it does, else why not. Costs a full analysis
        and is accounted like one (slot, deadline, worker process)."""
        return self._analyse("probe", data)

    def _build_entry(self, doc_id: str, kind: str, data: bytes, virtual_path: str, filename: str,
                     disk_path: Optional[str] = None, stamp: Optional[Tuple[int, int]] = None) -> DocEntry:
        doc, encoded, deflated = self._analyse("document", data, virtual_path, filename, doc_id)
        return DocEntry(doc_id, kind, doc, data, filename, disk_path=disk_path, stamp=stamp,
                        cost=document_cost(len(data), len(encoded)), encoded=encoded, deflated=deflated)

    # ========================================================================
    # Adding documents
    # ========================================================================
    def _check_size(self, size: int) -> None:
        if size <= 0:
            raise BadRequest("Empty binary upload payload.")
        if size > self.config.max_upload_bytes:
            raise TooLarge(
                f"File is {size:,} bytes; the limit is {self.config.max_upload_bytes:,} bytes."
            )

    def add_upload(self, filename: Any, data: bytes, owner: Optional[str] = None) -> DocEntry:
        """Parse uploaded bytes and store them under a fresh unguessable id.

        `owner` is the uploader's client id; it only decides whose older
        documents make room (see `DocumentStore`), never who may read."""
        if not self.config.allow_upload:
            raise Forbidden("Uploads are disabled on this server.")
        return self._add_random("u_", "upload", filename, data, owner)

    def add_derived(self, filename: Any, data: bytes, owner: Optional[str] = None,
                    parent: Optional[str] = None) -> DocEntry:
        """Store bytes derived from another document (e.g. a patched copy) under a `p_` id.
        `parent` is the id of the document they were derived from; the store keeps
        that one for as long as it would otherwise evict it to fit this one."""
        return self._add_random("p_", "derived", filename, data, owner, parent)

    def _add_random(self, prefix: str, kind: str, filename: Any, data: bytes,
                    owner: Optional[str] = None, parent: Optional[str] = None) -> DocEntry:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise BadRequest("Upload body must be bytes.")
        data = bytes(data)
        self._check_size(len(data))
        safe_name = sanitize_filename(filename)
        doc_id = prefix + secrets.token_hex(16)
        label = "upload" if kind == "upload" else "patched"
        entry = self._build_entry(doc_id, kind, data, f"<{label}:{safe_name}>", safe_name)
        entry.owner = owner
        entry.parent_id = parent
        return self.store.put(entry)

    def _read_file(self, abs_path: str) -> Tuple[bytes, Tuple[int, int]]:
        try:
            with open(abs_path, "rb") as handle:
                st = os.fstat(handle.fileno())
                if not stat.S_ISREG(st.st_mode):
                    raise NotFound(f"File not found: {abs_path}")
                if st.st_size > self.config.max_upload_bytes:
                    raise TooLarge(
                        f"File is {st.st_size:,} bytes; the limit is {self.config.max_upload_bytes:,} bytes."
                    )
                data = handle.read(self.config.max_upload_bytes + 1)
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            raise NotFound(f"File not found: {abs_path}")
        except PermissionError:
            raise Forbidden(f"Permission denied: {abs_path}")
        if len(data) > self.config.max_upload_bytes:
            raise TooLarge(f"File is larger than the limit of {self.config.max_upload_bytes:,} bytes.")
        return data, (getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)), st.st_size)

    @staticmethod
    def _stat_stamp(path: str) -> Optional[Tuple[int, int]]:
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)), st.st_size)

    def _abs_path(self, path: str) -> str:
        if "\x00" in path:
            raise BadRequest("Invalid path.")
        if not os.path.isabs(path):
            candidate = os.path.join(self.workspace_root, path)
            return os.path.abspath(candidate) if os.path.isfile(candidate) else os.path.abspath(path)
        return os.path.abspath(path)

    def _load_path(self, path: str) -> DocEntry:
        if not self.config.allow_path_load:
            raise Forbidden("Loading files by server path is not available on this server.")
        abs_path = self._abs_path(str(path))
        doc_id = "path:" + abs_path
        return self._load_disk(doc_id, "path", abs_path, abs_path, os.path.basename(abs_path), pinned=False)

    def _load_preset(self, preset_id: str) -> DocEntry:
        if not PRESET_ID_RE.match(preset_id):
            raise BadRequest("Malformed preset id.")
        found = self._preset_file(preset_id)
        if found is None:
            raise NotFound("Unknown preset.")
        disk, filename = found
        local = self.config.allow_path_load
        # Outside local mode the path of a preset on this machine is never revealed
        # and the parsed result never changes, so it is parsed once and pinned.
        virtual = disk if local else f"<preset:{preset_id}>"
        try:
            return self._load_disk(f"preset:{preset_id}", "preset", disk, virtual, filename, pinned=not local)
        except (NotFound, Forbidden):
            if local:
                raise
            raise NotFound("This preset is not available on this server.")

    def _load_disk(self, doc_id: str, kind: str, disk: str, virtual_path: str, filename: str,
                   pinned: bool) -> DocEntry:
        entry = self.store.get(doc_id)
        if entry is not None and (pinned or entry.stamp == self._stat_stamp(disk)):
            return entry
        budget = float(self.config.parse_queue_seconds) + float(self.config.parse_timeout_seconds or 0)
        if not self._load_lock.acquire(timeout=budget if self.config.parse_timeout_seconds else -1):
            raise Busy("The server is busy analysing other files. Try again in a moment.",
                       headers={"Retry-After": "3"})
        try:
            entry = self.store.get(doc_id)
            if entry is not None and (pinned or entry.stamp == self._stat_stamp(disk)):
                return entry
            data, stamp = self._read_file(disk)
            if not data:
                raise ParseFailed("File is empty.")
            built = self._build_entry(
                doc_id, kind, data, virtual_path, filename,
                disk_path=disk if self.config.allow_external_tools else None, stamp=stamp,
            )
            return self.store.put(built, pinned=pinned)
        finally:
            self._load_lock.release()

    # ========================================================================
    # Resolving a document id
    # ========================================================================
    def get_entry(self, doc: Optional[str] = None, path: Optional[str] = None) -> DocEntry:
        """Find (or, for presets and local paths, load) the document a caller named."""
        if path:
            if not self.config.allow_path_load:
                raise Forbidden("Loading files by server path is not available on this server.")
            if not doc:
                return self._load_path(path)
        if not doc:
            return self._implicit_entry()
        doc = str(doc)
        if len(doc) > 4096 or "\x00" in doc:
            raise BadRequest("Malformed document id.")
        if doc.startswith("preset:"):
            return self._load_preset(doc[len("preset:"):])
        if doc.startswith("path:"):
            return self._load_path(doc[len("path:"):])
        if RANDOM_ID_RE.match(doc):
            entry = self.store.get(doc)
            if entry is None:
                raise DocExpired("This document is no longer held by the server. Open the file again.")
            return entry
        raise BadRequest("Malformed document id.")

    def _implicit_entry(self) -> DocEntry:
        """Local mode only: the last document loaded, else the first available preset."""
        if not self.config.allow_path_load:
            raise BadRequest("Missing required 'doc' parameter.")
        if self.active_doc_id:
            try:
                return self.get_entry(doc=self.active_doc_id)
            except DocExpired:
                self.active_doc_id = None
        for preset in self.get_presets():
            if preset["exists"]:
                entry = self._load_path(preset["path"])
                self.active_doc_id = entry.doc_id
                return entry
        raise BadRequest("No binary file is currently loaded.")

    def set_active(self, entry: DocEntry) -> None:
        """Remember `entry` as the implicit document. A no-op outside local mode."""
        if self.config.allow_path_load:
            self.active_doc_id = entry.doc_id

    def get_bytes(self, doc: Optional[str] = None, path: Optional[str] = None) -> bytes:
        return self.get_entry(doc=doc, path=path).data

    def sweep(self) -> int:
        return self.store.sweep()

    # ------------------------------------------------------------------------
    # Older single-user API, used by the CLI and by local-mode callers
    # ------------------------------------------------------------------------
    @property
    def active_path(self) -> Optional[str]:
        if not self.active_doc_id:
            return None
        entry = self.store.get(self.active_doc_id)
        if entry is None:
            return None
        return entry.disk_path or entry.doc.get("file_info", {}).get("path")

    def load_file(self, path: str) -> Dict[str, Any]:
        entry = self._load_path(path)
        self.set_active(entry)
        return entry.doc

    def load_uploaded_bytes(self, filename: str, raw_bytes: bytes) -> Dict[str, Any]:
        entry = self.add_upload(filename, raw_bytes)
        self.set_active(entry)
        return entry.doc

    def _resolve(self, doc: Optional[str], path: Optional[str]) -> DocEntry:
        return self.get_entry(doc=doc, path=path)

    def _get_slice(self, doc: Dict[str, Any], slice_index: int) -> Dict[str, Any]:
        slices = doc.get("slices", [])
        if not slices:
            raise BadRequest("No slices available in document.")
        idx = max(0, min(int(slice_index), len(slices) - 1))
        return slices[idx]

    # ========================================================================
    # Address / Offset Translation (O(log N) / Segment Interval Lookup)
    # ========================================================================
    def _abs_offset_to_vmaddr(self, slice_obj: Dict[str, Any], abs_offset: int) -> Optional[int]:
        slice_base = slice_obj["slice_base_offset"]
        slice_off = abs_offset - slice_base
        if slice_off < 0 or slice_off >= slice_obj["slice_size"]:
            return None
        for seg in slice_obj.get("segments", []):
            if seg["filesize"] > 0 and seg["fileoff"] <= slice_off < seg["fileoff"] + seg["filesize"]:
                return seg["vmaddr_int"] + (slice_off - seg["fileoff"])
        return None

    def translate_address(
        self,
        slice_index: int = 0,
        query: str = "0",
        mode: str = "auto",
        path: Optional[str] = None,
        doc: Optional[str] = None,
    ) -> Dict[str, Any]:
        doc = self._resolve(doc, path).doc
        slice_obj = self._get_slice(doc, slice_index)
        slice_base = slice_obj["slice_base_offset"]

        q_clean = str(query).strip()
        if not q_clean:
            q_val = 0
        else:
            try:
                q_val = int(q_clean, 16) if q_clean.lower().startswith("0x") else int(q_clean, 0)
            except ValueError:
                try:
                    q_val = int(q_clean, 16)
                except ValueError:
                    q_val = 0

        # Determine text base for RVA and auto-detection
        text_vm = 0
        for seg in slice_obj.get("segments", []):
            if seg["segname"] == "__TEXT":
                text_vm = seg["vmaddr_int"]
                break
        if text_vm == 0 and slice_obj.get("segments"):
            for seg in slice_obj["segments"]:
                if seg["segname"] != "__PAGEZERO":
                    text_vm = seg["vmaddr_int"]
                    break

        resolved_mode = mode
        if mode == "auto":
            if text_vm > 0 and q_val >= text_vm:
                resolved_mode = "vmaddr"
            elif slice_base > 0 and q_val >= slice_base and q_val < slice_base + slice_obj["slice_size"]:
                resolved_mode = "abs_offset"
            else:
                resolved_mode = "slice_offset"

        matched_seg: Optional[Dict[str, Any]] = None
        matched_sect: Optional[Dict[str, Any]] = None
        vmaddr_val: Optional[int] = None
        slice_off_val: Optional[int] = None
        abs_off_val: Optional[int] = None
        status = "UNMAPPED"
        mapped = False

        if resolved_mode == "vmaddr":
            vmaddr_val = q_val
            for seg in slice_obj.get("segments", []):
                if seg["segname"] == "__PAGEZERO":
                    continue
                s_vm = seg["vmaddr_int"]
                s_vmsz = seg["vmsize_int"]
                if s_vm <= vmaddr_val < s_vm + s_vmsz:
                    matched_seg = seg
                    rel_vm = vmaddr_val - s_vm
                    if rel_vm < seg["filesize"]:
                        slice_off_val = seg["fileoff"] + rel_vm
                        abs_off_val = slice_base + slice_off_val
                        status = "MAPPED"
                        mapped = True
                    else:
                        status = "UNMAPPED_ZEROFILL"
                        mapped = True
                    for sect in seg.get("sections", []):
                        if sect["vmaddr_int"] <= vmaddr_val < sect["vmaddr_int"] + sect["size"]:
                            matched_sect = sect
                            break
                    break
        else:
            if resolved_mode == "abs_offset":
                abs_off_val = q_val
                slice_off_val = q_val - slice_base
            else:
                slice_off_val = q_val
                abs_off_val = slice_base + q_val

            if 0 <= slice_off_val < slice_obj["slice_size"]:
                for seg in slice_obj.get("segments", []):
                    if seg["filesize"] > 0 and seg["fileoff"] <= slice_off_val < seg["fileoff"] + seg["filesize"]:
                        matched_seg = seg
                        vmaddr_val = seg["vmaddr_int"] + (slice_off_val - seg["fileoff"])
                        status = "MAPPED"
                        mapped = True
                        for sect in seg.get("sections", []):
                            if not sect.get("is_zerofill") and sect["slice_offset"] <= slice_off_val < sect["slice_offset"] + sect["size"]:
                                matched_sect = sect
                                break
                        break

        # Find nearest preceding symbol if vmaddr_val is resolved
        nearest_sym_obj: Optional[Dict[str, Any]] = None
        if vmaddr_val is not None:
            best_sym = None
            best_delta = None
            for sym in slice_obj.get("symbols", []):
                check_deadline()
                if not sym.get("is_stab") and sym.get("n_value_int", 0) > 0:
                    delta = vmaddr_val - sym["n_value_int"]
                    if 0 <= delta < 0x100000:
                        if best_delta is None or delta < best_delta:
                            best_delta = delta
                            best_sym = sym
            if best_sym is not None and best_delta is not None:
                nearest_sym_obj = {
                    "name": best_sym["name"],
                    "demangled": best_sym["demangled"],
                    "vmaddr": best_sym["n_value"],
                    "offset_from_symbol": best_delta,
                    "display": f"{best_sym['name']} + 0x{best_delta:x}",
                }

        rva_val = (vmaddr_val - text_vm) if (vmaddr_val is not None and vmaddr_val >= text_vm) else None

        return {
            "query": query,
            "mode_resolved": resolved_mode,
            "mapped": mapped,
            "status": status,
            "vmaddr": f"0x{vmaddr_val:x}" if vmaddr_val is not None else None,
            "rva": f"0x{rva_val:x}" if rva_val is not None else None,
            "slice_offset": slice_off_val,
            "abs_offset": abs_off_val,
            "segment": (
                {
                    "segname": matched_seg["segname"],
                    "vmaddr": matched_seg["vmaddr"],
                    "vmsize": matched_seg["vmsize"],
                    "initprot": matched_seg["initprot"],
                    "maxprot": matched_seg["maxprot"],
                }
                if matched_seg
                else None
            ),
            "section": (
                {
                    "sectname": matched_sect["sectname"],
                    "segname": matched_sect["segname"],
                    "vmaddr": matched_sect["vmaddr"],
                    "size": matched_sect["size"],
                    "abs_offset": matched_sect["abs_offset"],
                }
                if matched_sect
                else None
            ),
            "nearest_symbol": nearest_sym_obj,
        }

    # ========================================================================
    # Windowed Hex Viewer Endpoint (/api/hex)
    # ========================================================================
    def get_hex_slice(
        self,
        offset: int = 0,
        length: int = 4096,
        slice_index: int = 0,
        path: Optional[str] = None,
        doc: Optional[str] = None,
    ) -> Dict[str, Any]:
        entry = self._resolve(doc, path)
        doc, raw_bytes = entry.doc, entry.data
        file_size = len(raw_bytes)
        slice_obj = self._get_slice(doc, slice_index)
        slice_base = slice_obj["slice_base_offset"]

        abs_offset = max(0, min(offset, max(0, file_size - 1)))
        clamped_len = max(16, min(length, 65536))
        end_offset = min(file_size, abs_offset + clamped_len)
        window_bytes = raw_bytes[abs_offset:end_offset]

        rows: List[Dict[str, Any]] = []
        row_start = (abs_offset // 16) * 16
        row_end = min(file_size, ((end_offset + 15) // 16) * 16)

        for r_off in range(row_start, row_end, 16):
            chunk = raw_bytes[r_off : min(file_size, r_off + 16)]
            hex_arr = [f"{b:02x}" for b in chunk]
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            vm_val = self._abs_offset_to_vmaddr(slice_obj, r_off)
            rows.append({
                "abs_offset": r_off,
                "slice_offset": r_off - slice_base,
                "vmaddr": f"0x{vm_val:x}" if vm_val is not None else None,
                "hex_array": hex_arr,
                "ascii": ascii_str,
            })

        # Collect structural annotations overlapping [row_start, row_end)
        annotations: List[Dict[str, Any]] = []
        if doc["file_info"]["is_fat"] and doc["file_info"]["fat_header"]:
            fh_reg = doc["file_info"]["fat_header"]["region"]
            if fh_reg["abs_offset"] < row_end and (fh_reg["abs_offset"] + fh_reg["size"]) > row_start:
                annotations.append({
                    "id": "fat_header",
                    "label": "fat_header",
                    "category": "header",
                    "abs_offset": fh_reg["abs_offset"],
                    "size": fh_reg["size"],
                })

        for iv in slice_obj.get("intervals", []):
            check_deadline()
            iv_start = iv["abs_offset"]
            iv_end = iv_start + iv["size"]
            if iv["size"] > 0 and iv_start < row_end and iv_end > row_start:
                annotations.append({
                    "id": iv["id"],
                    "label": iv["label"],
                    "category": iv["category"],
                    "abs_offset": iv_start,
                    "size": iv["size"],
                })

        return {
            "abs_offset": abs_offset,
            "length": len(window_bytes),
            "file_size": file_size,
            "hex_bytes": window_bytes.hex(),
            "rows": rows,
            "annotations": annotations,
        }

    # ========================================================================
    # Live Multi-Format Byte Decoder & Breadcrumb Resolver (/api/decode)
    # ========================================================================
    def decode_bytes_at(
        self,
        offset: int,
        slice_index: int = 0,
        endian: str = "little",
        path: Optional[str] = None,
        doc: Optional[str] = None,
    ) -> Dict[str, Any]:
        entry = self._resolve(doc, path)
        doc, raw_bytes = entry.doc, entry.data
        file_size = len(raw_bytes)
        slice_obj = self._get_slice(doc, slice_index)
        slice_base = slice_obj["slice_base_offset"]

        abs_off = max(0, min(offset, max(0, file_size - 1)))
        slice_off = abs_off - slice_base
        vm_val = self._abs_offset_to_vmaddr(slice_obj, abs_off)

        window = raw_bytes[abs_off : min(file_size, abs_off + 16)].ljust(16, b"\x00")
        raw_hex_8 = " ".join(f"{b:02x}" for b in raw_bytes[abs_off : min(file_size, abs_off + 8)])
        e_char = "<" if str(endian).lower() != "big" else ">"

        u8 = window[0]
        i8 = struct.unpack("b", window[:1])[0]
        u16 = struct.unpack(f"{e_char}H", window[:2])[0]
        i16 = struct.unpack(f"{e_char}h", window[:2])[0]
        u32 = struct.unpack(f"{e_char}I", window[:4])[0]
        i32 = struct.unpack(f"{e_char}i", window[:4])[0]
        u64 = struct.unpack(f"{e_char}Q", window[:8])[0]
        i64 = struct.unpack(f"{e_char}q", window[:8])[0]
        f32_raw = struct.unpack(f"{e_char}f", window[:4])[0]
        f64_raw = struct.unpack(f"{e_char}d", window[:8])[0]

        f32 = None if (math.isnan(f32_raw) or math.isinf(f32_raw)) else round(f32_raw, 6)
        f64 = None if (math.isnan(f64_raw) or math.isinf(f64_raw)) else round(f64_raw, 6)

        temp_buf = BinaryBuffer(raw_bytes, 0, file_size)
        uleb_val, uleb_len = temp_buf.read_uleb128(abs_off)
        sleb_val, sleb_len = temp_buf.read_sleb128(abs_off)
        cstr_val, _ = temp_buf.cstr_at(abs_off, 64)
        cstr_clean = "".join(ch if 32 <= ord(ch) <= 126 else "." for ch in cstr_val[:32])

        # The instruction preview is only meaningful for an instruction set that is decoded.
        # For any other architecture both previews are "N/A" and `insn_note` says why, instead
        # of showing these bytes as if they were A64 or x86 code.
        insn_family = instruction_set(slice_obj.get("arch_name"))
        insn_note = None
        if insn_family is None:
            arm64_str = "N/A"
            x86_str = "N/A"
            insn_note = f"not disassembled ({slice_obj.get('arch_name') or 'unknown architecture'})"
        else:
            arm64_str = decode_single_arm64_preview(
                raw_bytes[abs_off : min(file_size, abs_off + 4)],
                vm_val if vm_val is not None else abs_off,
            )
            x86_len, x86_mnem, x86_ops, _, _ = decode_x86_64_insn(
                raw_bytes[abs_off : min(file_size, abs_off + 15)],
                0,
                vm_val if vm_val is not None else abs_off,
                is_64=bool(slice_obj.get("is_64", True)),
            )
            x86_str = f"{x86_mnem} {x86_ops}".strip() if x86_len > 0 else "N/A"

        # Build structural breadcrumbs from largest enclosing container down to exact field
        breadcrumbs: List[Dict[str, Any]] = []
        if slice_base <= abs_off < slice_base + slice_obj["slice_size"]:
            breadcrumbs.append({
                "id": f"slice_{slice_index}",
                "label": f"Slice #{slice_index} ({slice_obj['arch_name']})",
                "abs_offset": slice_base,
                "size": slice_obj["slice_size"],
            })

        matching_ivs = [
            iv
            for iv in slice_obj.get("intervals", [])
            if iv["abs_offset"] <= abs_off < iv["abs_offset"] + iv["size"]
        ]
        matching_ivs.sort(key=lambda x: x["size"], reverse=True)
        for iv in matching_ivs:
            breadcrumbs.append({
                "id": iv["id"],
                "label": iv["label"],
                "abs_offset": iv["abs_offset"],
                "size": iv["size"],
            })

        # Check field-level match in header or load commands
        all_field_lists = [slice_obj["header"].get("fields", [])]
        if doc["file_info"].get("fat_header"):
            all_field_lists.append(doc["file_info"]["fat_header"].get("fields", []))
        for lc in slice_obj.get("load_commands", []):
            all_field_lists.append(lc.get("fields", []))
        for seg in slice_obj.get("segments", []):
            for sect in seg.get("sections", []):
                all_field_lists.append(sect.get("fields", []))

        matched_field_pedagogy = None
        for flist in all_field_lists:
            for f_obj in flist:
                if f_obj["abs_offset"] <= abs_off < f_obj["abs_offset"] + f_obj["size"]:
                    breadcrumbs.append({
                        "id": f"field_{f_obj['name']}",
                        "label": f"{f_obj['name']} ({f_obj['interpreted']})",
                        "abs_offset": f_obj["abs_offset"],
                        "size": f_obj["size"],
                    })
                    if f_obj.get("pedagogy"):
                        matched_field_pedagogy = {
                            "field_name": f_obj["name"],
                            "interpreted": f_obj["interpreted"],
                            **f_obj["pedagogy"],
                        }
                    break

        return {
            "abs_offset": abs_off,
            "slice_offset": slice_off,
            "vmaddr": f"0x{vm_val:x}" if vm_val is not None else None,
            "raw_hex": raw_hex_8,
            "breadcrumbs": breadcrumbs,
            "field_pedagogy": matched_field_pedagogy,
            "primitives": {
                "uint8": u8,
                "int8": i8,
                "uint16": u16,
                "int16": i16,
                "uint32": u32,
                "int32": i32,
                "hex32": f"0x{u32:08x}",
                "uint64": f"0x{u64:016x}",
                "int64": str(i64),
                "float32": f32,
                "float64": f64,
                "uleb128": {"value": uleb_val, "byte_length": uleb_len},
                "sleb128": {"value": sleb_val, "byte_length": sleb_len},
                "cstring_preview": cstr_clean,
                "arm64_insn": arm64_str,
                "x86_insn": x86_str,
                "insn_arch": insn_family,     # "arm64" | "x86" | None (architecture not decoded)
                "insn_note": insn_note,
            },
        }

    # ========================================================================
    # Disassembly Service (/api/disassemble)
    # ========================================================================
    def disassemble(
        self,
        slice_index: int = 0,
        vmaddr: Optional[str] = None,
        section: Optional[str] = None,
        count: int = 200,
        path: Optional[str] = None,
        doc: Optional[str] = None,
    ) -> Dict[str, Any]:
        entry = self._resolve(doc, path)
        doc, raw_bytes = entry.doc, entry.data
        slice_obj = self._get_slice(doc, slice_index)
        slice_base = slice_obj["slice_base_offset"]
        slice_size = slice_obj["slice_size"]
        raw_slice = raw_bytes[slice_base : slice_base + slice_size]

        start_vm: Optional[int] = None
        if section:
            for seg in slice_obj.get("segments", []):
                for sect in seg.get("sections", []):
                    full_sec_name = f"{sect['segname']},{sect['sectname']}"
                    if section in (full_sec_name, sect["sectname"]):
                        start_vm = sect["vmaddr_int"]
                        break
                if start_vm is not None:
                    break

        if vmaddr and start_vm is None:
            try:
                start_vm = int(str(vmaddr), 16) if str(vmaddr).startswith("0x") else int(str(vmaddr), 0)
            except ValueError:
                start_vm = None

        if start_vm is None:
            # Prefer __TEXT,__text or entry_point
            ep_str = str((slice_obj.get("entry_point") or {}).get("vmaddr") or "0x0")
            try:
                ep_int = int(ep_str, 16) if ep_str.startswith("0x") else 0
            except ValueError:
                ep_int = 0
            if ep_int > 0:
                start_vm = ep_int
            else:
                for seg in slice_obj.get("segments", []):
                    for sect in seg.get("sections", []):
                        if sect.get("is_executable") and sect["size"] > 0:
                            start_vm = sect["vmaddr_int"]
                            break
                    if start_vm is not None:
                        break

        if start_vm is None:
            start_vm = 0

        # Only a file this process itself opened by path (local mode) is ever named
        # to an external disassembler; uploads and presets in restricted modes never are.
        cfg = self.config
        disk_path = None
        if cfg.allow_external_tools and entry.disk_path and os.path.isfile(entry.disk_path):
            disk_path = entry.disk_path
        with runtime.use_config(cfg), runtime.parse_deadline(cfg.parse_timeout_seconds):
            return disassemble_window(
                slice_data=slice_obj,
                raw_slice_bytes=raw_slice,
                slice_base_offset=slice_base,
                start_vmaddr=start_vm,
                count=max(1, min(int(count), 1000)),
                file_path=disk_path,
            )

    # ========================================================================
    # Omni-Search Service (/api/search)
    # ========================================================================
    def search(
        self,
        query: str,
        slice_index: int = 0,
        scope: str = "all",
        path: Optional[str] = None,
        doc: Optional[str] = None,
    ) -> Dict[str, Any]:
        entry = self._resolve(doc, path)
        doc_ref = entry.doc_id
        doc, raw_bytes = entry.doc, entry.data
        slice_obj = self._get_slice(doc, slice_index)

        query = str(query)
        if len(query) > MAX_SEARCH_QUERY_CHARS:
            raise BadRequest(f"Search query is longer than {MAX_SEARCH_QUERY_CHARS} characters.")
        q = query.strip()
        if not q:
            return {"query": query, "results": []}

        # Prefix operators from UI/UX spec:
        # `@` -> symbols, `"` -> strings, `#` -> load commands/structures, `0x` -> address
        effective_scope = scope
        if q.startswith("@"):
            effective_scope = "symbols"
            q = q[1:].strip()
        elif q.startswith('"'):
            effective_scope = "strings"
            q = q.strip('"').strip()
        elif q.startswith("#"):
            effective_scope = "structures"
            q = q[1:].strip()

        q_lower = q.lower()
        results: List[Dict[str, Any]] = []

        # 1. Address Jump Match
        if q_lower.startswith("0x") or q_lower.isdigit():
            tr = self.translate_address(slice_index=slice_index, query=q, mode="auto", doc=doc_ref)
            if tr.get("mapped"):
                results.append({
                    "category": "address",
                    "title": f"Jump to {tr['vmaddr']} (File Offset 0x{(tr['abs_offset'] or 0):x})",
                    "subtitle": f"{tr['segment']['segname'] if tr['segment'] else ''} {tr['section']['sectname'] if tr['section'] else ''} • {tr['nearest_symbol']['display'] if tr['nearest_symbol'] else tr['status']}".strip(),
                    "vmaddr": tr["vmaddr"],
                    "abs_offset": tr["abs_offset"],
                    "size": 16,
                    "node_id": "hex",
                })

        # 2. Symbols Search
        if effective_scope in ("all", "symbols"):
            for sym in slice_obj.get("symbols", []):
                check_deadline()
                if q_lower in sym["name"].lower() or q_lower in sym["demangled"].lower():
                    results.append({
                        "category": "symbol",
                        "title": sym["demangled"] if sym["demangled"] != sym["name"] else sym["name"],
                        "subtitle": f"{sym['section_name'] or sym['library_name']} • {'External' if sym['is_external'] else 'Local'} ({sym['type_name']})",
                        "vmaddr": sym["n_value"] if sym["n_value_int"] > 0 else None,
                        "abs_offset": sym["target_abs_offset"] or sym["abs_offset"],
                        "size": sym["size"],
                        "node_id": "symtab",
                    })
                    if len(results) >= 100:
                        break

        # 3. Strings Search
        if effective_scope in ("all", "strings") and len(results) < 120:
            for st in slice_obj.get("strings", []):
                check_deadline()
                if q_lower in st["value"].lower():
                    results.append({
                        "category": "string",
                        "title": st["value"][:80],
                        "subtitle": f"{st['source']} • {st['length']} bytes @ {st['vmaddr']}",
                        "vmaddr": st["vmaddr"],
                        "abs_offset": st["abs_offset"],
                        "size": st["length"],
                        "node_id": "strings",
                    })
                    if len(results) >= 120:
                        break

        # 4. Load Commands & Sections Search
        if effective_scope in ("all", "structures") and len(results) < 140:
            for lc in slice_obj.get("load_commands", []):
                if len(results) >= MAX_SEARCH_RESULTS:
                    break
                if q_lower in lc["cmd_name"].lower() or q_lower in lc["summary"].lower():
                    results.append({
                        "category": "load_command",
                        "title": f"#{lc['index']} {lc['cmd_name']}",
                        "subtitle": lc["summary"],
                        "vmaddr": None,
                        "abs_offset": lc["region"]["abs_offset"],
                        "size": lc["region"]["size"],
                        "node_id": f"lc_{lc['index']}",
                    })
            for seg in slice_obj.get("segments", []):
                for sect in seg.get("sections", []):
                    label = f"{sect['segname']},{sect['sectname']}"
                    if q_lower in label.lower() and len(results) < MAX_SEARCH_RESULTS:
                        results.append({
                            "category": "section",
                            "title": label,
                            "subtitle": f"VM {sect['vmaddr']} • {sect['size']:,} bytes ({sect['section_type']})",
                            "vmaddr": sect["vmaddr"],
                            "abs_offset": sect["abs_offset"],
                            "size": sect["size"],
                            "node_id": f"sect_{sect['segname']}_{sect['sectname']}",
                        })

        # 5. Raw Hex Byte Pattern Search (e.g. "cf fa ed fe" or "7f2303d5")
        hex_candidate = re.sub(r"\s+", "", q_lower)
        if (
            effective_scope in ("all", "hex")
            and len(hex_candidate) >= 4
            and len(hex_candidate) % 2 == 0
            and all(c in "0123456789abcdef" for c in hex_candidate)
        ):
            pattern = bytes.fromhex(hex_candidate)
            start_pos = 0
            matches_found = 0
            while matches_found < 20:
                idx = raw_bytes.find(pattern, start_pos)
                if idx == -1:
                    break
                vm_hit = self._abs_offset_to_vmaddr(slice_obj, idx)
                results.append({
                    "category": "hex",
                    "title": f"Hex Match: {' '.join(f'{b:02x}' for b in pattern)}",
                    "subtitle": f"File Offset 0x{idx:x}" + (f" • VM 0x{vm_hit:x}" if vm_hit else ""),
                    "vmaddr": f"0x{vm_hit:x}" if vm_hit else None,
                    "abs_offset": idx,
                    "size": len(pattern),
                    "node_id": "hex",
                })
                matches_found += 1
                start_pos = idx + 1

        return {"query": query, "results": results}
