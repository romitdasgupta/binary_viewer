#!/usr/bin/env python3
"""
Structure-aware fuzz harness for the BinaryStudio parsers (Mach-O / ELF / PE).

Every case is derived deterministically from (--seed, case index), so any finding
can be reproduced exactly with `--repro-case N` (same seed and corpus).

For each case the full client-facing pipeline runs:

    parse (incl. semantic layers + pedagogy) -> strict JSON encode ->
    hex / decode / translate / disassemble / search service calls

inside a worker process that the parent supervises:
  - time: each case's CPU time is reported against --slow (CPU time, so load from
    sibling workers does not produce false positives); a worker stuck past
    --hard-timeout wall seconds is killed and the case recorded as a hang;
  - memory: every 4th case runs under tracemalloc, every case reports the growth
    of the worker's peak RSS, both against --mem-mb; the parent kills a worker
    whose RSS passes --hard-mem-mb.

Outcomes:
    ok        parsed (possibly partially, with warnings)
    rejected  deliberate rejection: BinaryFormatError / ParseBudgetExceeded
    BUG       anything else: unexpected exception type, plain ValueError,
              non-JSON-serialisable document, slow case, hang, runaway memory

Usage:
    python3 tests/fuzz_harness.py --iterations 20000 --seed 1 --workers 8
    python3 tests/fuzz_harness.py --repro-case 1234 --seed 1        # in-process, prints traceback
    python3 tests/fuzz_harness.py --repro-file crash.bin             # run one file
"""

import argparse
import inspect
import json
import os
import random
import re
import struct
import sys
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend import runtime  # noqa: E402

FIXTURE_NAMES = (
    "synthetic_universal",
    "synthetic_firmware.preload",
    "synthetic_elf64",
    "synthetic_elf32",
    "synthetic_pe64.exe",
    "synthetic_pe32.exe",
)

# Small real binaries that are commonly present on a macOS dev machine. Missing
# ones are skipped; pass --extra-seeds for more.
HOST_SEED_CANDIDATES = (
    "/usr/bin/true",
    "/bin/ls",
    "/bin/cat",
    "/usr/bin/false",
    "/usr/bin/env",
    "/usr/lib/libgmalloc.dylib",
    "/usr/lib/libffi-trampolines.dylib",
    "/usr/lib/libobjc-trampolines.dylib",
    # Real PE32 / PE32+ samples that ship with CPython's pip / setuptools.
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9/site-packages/pip/_vendor/distlib/t32.exe",
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9/site-packages/pip/_vendor/distlib/t64.exe",
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9/site-packages/setuptools/gui-64.exe",
    # Real ELF samples bundled with JetBrains IDEs (Linux helpers): ELF64 x86-64 and
    # AArch64 executables, and a static 32-bit ARM ELF.
    "/Applications/CLion.app/Contents/plugins/clion-radler/DotFiles/linux-x64/JetBrains.Debugger.Worker",
    "/Applications/CLion.app/Contents/plugins/clion-radler/DotFiles/linux-arm64/JetBrains.Debugger.Worker",
    "/Applications/CLion.app/Contents/plugins/clion-radler/DotFiles/linux-arm/jb_zip_unarchiver",
)

MAX_SEED_BYTES = 3_000_000  # larger seeds make every case slow; use them for perf runs instead


# ============================================================================
# Corpus & structural hints
# ============================================================================
class Seed:
    def __init__(self, name: str, data: bytes) -> None:
        self.name = name
        self.data = data
        self.fields: List[Tuple[int, int]] = []      # (abs_offset, size) of every decoded field
        self.count_fields: List[Tuple[int, int]] = []  # fields whose name says count / size / offset
        self.boundaries: List[int] = []               # structural boundaries for truncation / splicing
        self.regions: List[Tuple[int, int]] = []      # (abs_offset, size) of structures for duplication


_COUNT_NAME = re.compile(
    r"(^n[a-z]|num|count|size|_sz|off|ptr|index|ndx|ent|len|addr|rva|first_thunk|thunk|link|info)",
    re.IGNORECASE,
)


def _collect_structure(doc: Any, file_size: int, seed: Seed) -> None:
    fields = set()
    count_fields = set()
    bounds = {0, file_size}
    regions = set()
    stack = [doc]
    visited = 0
    while stack and visited < 400_000:
        node = stack.pop()
        visited += 1
        if isinstance(node, dict):
            off = node.get("abs_offset")
            size = node.get("size")
            if isinstance(off, int) and isinstance(size, int) and 0 <= off < file_size:
                if "raw_hex" in node and 0 < size <= 64:
                    fields.add((off, size))
                    if size in (1, 2, 4, 8) and _COUNT_NAME.search(str(node.get("name", ""))):
                        count_fields.add((off, size))
                bounds.add(off)
                end = off + max(0, size)
                if end <= file_size:
                    bounds.add(end)
                if 8 <= size <= 65536 and end <= file_size:
                    regions.add((off, size))
            for v in node.values():
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(node, list):
            stack.extend(x for x in node if isinstance(x, (dict, list)))
    seed.fields = sorted(fields)
    seed.count_fields = sorted(count_fields)
    seed.boundaries = sorted(bounds)
    seed.regions = sorted(regions)


def load_corpus(extra: Optional[List[str]] = None, include_host: bool = True) -> List[Seed]:
    from backend.fixtures import ensure_fixtures
    from backend.parser import parse_macho_bytes

    ensure_fixtures(ROOT)
    paths = [os.path.join(ROOT, "fixtures", n) for n in FIXTURE_NAMES]
    if include_host:
        paths.extend(HOST_SEED_CANDIDATES)
    paths.extend(extra or [])
    seeds: List[Seed] = []
    seen = set()
    for p in paths:
        try:
            if not os.path.isfile(p) or os.path.getsize(p) > MAX_SEED_BYTES:
                continue
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if data in seen:
            continue
        seen.add(data)
        seed = Seed(p, data)
        try:
            with runtime.parse_deadline(60):
                doc = parse_macho_bytes(data, path=os.path.basename(p))
            _collect_structure(doc, len(data), seed)
        except Exception:
            seed.boundaries = [0, len(data)]
        seeds.append(seed)
    return seeds


# ============================================================================
# Mutation engine
# ============================================================================
def _boundary_values(width: int, file_size: int) -> List[int]:
    vals = [0, 1, 2, 7, 8, 0x7F, 0x80, 0xFE, 0xFF]
    if width >= 2:
        vals += [0x100, 0x1000, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]
    if width >= 4:
        vals += [
            0x10000, 0x100000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFF0, 0xFFFFFFFE, 0xFFFFFFFF,
            file_size, max(0, file_size - 1), file_size + 1, max(0, file_size - 8), file_size // 2,
        ]
    if width >= 8:
        vals += [
            1 << 32, 1 << 48, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
            0xFFFFFFFFFFFFFFF0, 0xFFFFFFFFFFFFFFFF,
        ]
    return vals


def _write_int(buf: bytearray, off: int, width: int, value: int, little: bool) -> None:
    if off < 0 or off + width > len(buf):
        return
    mask = (1 << (8 * width)) - 1
    buf[off:off + width] = (value & mask).to_bytes(width, "little" if little else "big")


def _pick_field(rng: random.Random, seed: Seed, buf: bytearray) -> Tuple[int, int]:
    if seed.count_fields and rng.random() < 0.4:
        off, size = rng.choice(seed.count_fields)
        if off + size <= len(buf):
            return off, size
    if seed.fields and rng.random() < 0.85:
        off, size = rng.choice(seed.fields)
        if off + size <= len(buf):
            return off, size
    width = rng.choice((1, 2, 4, 4, 4, 8))
    if len(buf) <= width:
        return 0, max(1, len(buf))
    # Bias toward the first 4 KiB, where headers / load commands / tables live.
    hi = min(len(buf) - width, 4096) if rng.random() < 0.6 else len(buf) - width
    return rng.randrange(0, max(1, hi)) & ~(min(width, 4) - 1), width


def _mut_bitflip(rng, seed, buf, corpus):
    if not buf:
        return
    n = rng.choice((1, 1, 2, 4, 8, 32))
    for _ in range(n):
        if rng.random() < 0.5 and seed.fields:
            off, size = _pick_field(rng, seed, buf)
            pos = min(len(buf) - 1, off + rng.randrange(max(1, size)))
        else:
            pos = rng.randrange(len(buf))
        buf[pos] ^= 1 << rng.randrange(8)


def _mut_field_boundary(rng, seed, buf, corpus):
    if not buf:
        return
    for _ in range(rng.choice((1, 1, 1, 2, 3, 5))):
        off, size = _pick_field(rng, seed, buf)
        if size in (1, 2, 4, 8):
            width = size
        elif size > 8:
            # Arrays/strings: overwrite a word inside, or smash the whole thing.
            if rng.random() < 0.3:
                fill = rng.choice((b"\x00", b"\xff", b"A", b"\x7f"))
                end = min(len(buf), off + size)
                buf[off:end] = fill * (end - off)
                continue
            width = rng.choice((4, 8))
            off = off + rng.randrange(max(1, size - width + 1))
        else:
            width = 4
        val = rng.choice(_boundary_values(width, len(buf)))
        if rng.random() < 0.15:
            val += rng.randint(-4, 4)
        _write_int(buf, off, width, val, little=rng.random() < 0.75)


def _mut_field_pointer(rng, seed, buf, corpus):
    """Make an offset/size field point at another structure, near EOF, or overlap itself."""
    if not buf:
        return
    off, size = _pick_field(rng, seed, buf)
    width = size if size in (2, 4, 8) else 4
    choice = rng.random()
    if choice < 0.4 and seed.boundaries:
        val = rng.choice(seed.boundaries)
    elif choice < 0.7:
        val = max(0, len(buf) - rng.randint(0, 64))
    else:
        val = off - rng.randint(0, 64)
    _write_int(buf, off, width, val, little=rng.random() < 0.8)


def _mut_overwrite_run(rng, seed, buf, corpus):
    if not buf:
        return
    start = rng.choice(seed.boundaries) if (seed.boundaries and rng.random() < 0.7) else rng.randrange(len(buf))
    start = min(start, len(buf) - 1)
    length = rng.choice((1, 2, 4, 8, 16, 64, 256, 4096))
    fill = rng.choice((b"\x00", b"\xff", b"\x41", b"\x80", b"\x7f", None))
    end = min(len(buf), start + length)
    if fill is None:
        buf[start:end] = bytes(rng.randrange(256) for _ in range(end - start))
    else:
        buf[start:end] = fill * (end - start)


def _mut_splice(rng, seed, buf, corpus):
    donor = rng.choice(corpus).data
    if not donor:
        return
    d_start = rng.randrange(len(donor))
    d_len = min(len(donor) - d_start, rng.choice((4, 16, 64, 256, 1024, 8192)))
    chunk = donor[d_start:d_start + d_len]
    at = rng.choice(seed.boundaries) if (seed.boundaries and rng.random() < 0.7) else rng.randrange(len(buf) + 1)
    at = min(at, len(buf))
    if rng.random() < 0.5:
        buf[at:at + len(chunk)] = chunk          # overwrite (may extend)
    else:
        buf[at:at] = chunk                       # insert (shifts every later offset)


def _mut_duplicate_region(rng, seed, buf, corpus):
    """Repeat a structure (load command, section header, table entry) many times."""
    if not seed.regions:
        return _mut_overwrite_run(rng, seed, buf, corpus)
    off, size = rng.choice(seed.regions)
    if off + size > len(buf):
        return
    chunk = bytes(buf[off:off + size])
    reps = rng.choice((2, 4, 16, 64, 256))
    at = off + size
    blob = chunk * reps
    if len(blob) > 4 * 1024 * 1024:
        blob = blob[: 4 * 1024 * 1024]
    if rng.random() < 0.5:
        buf[at:at + len(blob)] = blob
    else:
        buf[at:at] = blob


def _mut_truncate(rng, seed, buf, corpus):
    if not buf:
        return
    if seed.boundaries and rng.random() < 0.8:
        cut = rng.choice(seed.boundaries) + rng.randint(-3, 3)
    else:
        cut = rng.randrange(len(buf) + 1)
    del buf[max(0, min(len(buf), cut)):]


def _mut_extend(rng, seed, buf, corpus):
    fill = rng.choice((b"\x00", b"\xff", b"\x41"))
    buf.extend(fill * rng.choice((1, 7, 64, 4096, 65536)))


MUTATORS = (
    (_mut_field_boundary, 30),
    (_mut_bitflip, 18),
    (_mut_field_pointer, 14),
    (_mut_truncate, 10),
    (_mut_splice, 8),
    (_mut_overwrite_run, 8),
    (_mut_duplicate_region, 8),
    (_mut_extend, 4),
)
_MUT_FUNCS = [m for m, _ in MUTATORS]
_MUT_WEIGHTS = [w for _, w in MUTATORS]

MAGICS = (
    b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\x7fELF\x02\x01\x01",
    b"\x7fELF\x01\x01\x01", b"\x7fELF\x02\x02\x01", b"MZ",
)


def _generate_degenerate(rng: random.Random) -> Tuple[str, bytes]:
    kind = rng.randrange(6)
    if kind == 0:
        n = rng.randrange(0, 80)
        return "tiny_random", bytes(rng.randrange(256) for _ in range(n))
    if kind == 1:
        b = rng.choice((0x00, 0xFF, 0x41, 0xCF, 0xFE, 0x7F, 0x4D))
        n = rng.choice((0, 1, 27, 28, 32, 64, 4096, 65536, 1 << 20))
        return f"all_{b:02x}_{n}", bytes([b]) * n
    magic = rng.choice(MAGICS)
    tail_len = rng.choice((0, 4, 24, 60, 200, 4096))
    if kind == 2:
        tail = bytes(rng.randrange(256) for _ in range(tail_len))
    elif kind == 3:
        tail = b"\xff" * tail_len
    elif kind == 4:
        tail = b"\x00" * tail_len
    else:
        # MZ with e_lfanew pointing at a PE signature, rest garbage
        body = bytearray(b"MZ" + bytes(rng.randrange(256) for _ in range(0x3A)))
        lfanew = rng.choice((0x40, 0x80, 0xF8))
        body += struct.pack("<I", lfanew)
        body += bytes(rng.randrange(256) for _ in range(lfanew - len(body))) if lfanew > len(body) else b""
        body += b"PE\x00\x00" + bytes(rng.randrange(256) for _ in range(rng.choice((20, 120, 400))))
        return "pe_garbage", bytes(body)
    return f"magic_{magic[:4].hex()}", magic + tail


def generate_case(corpus: List[Seed], seed: int, index: int) -> Tuple[str, bytes]:
    rng = random.Random(f"bs-fuzz:{seed}:{index}")
    if rng.random() < 0.04:
        return _generate_degenerate(rng)
    base = corpus[index % len(corpus)]
    buf = bytearray(base.data)
    n_ops = rng.choice((1, 1, 1, 2, 2, 3, 4, 6))
    ops = []
    for _ in range(n_ops):
        fn = rng.choices(_MUT_FUNCS, weights=_MUT_WEIGHTS)[0]
        fn(rng, base, buf, corpus)
        ops.append(fn.__name__[5:])
    if len(buf) > 48 * 1024 * 1024:
        del buf[48 * 1024 * 1024:]
    return f"{os.path.basename(base.name)}:{'+'.join(ops)}", bytes(buf)


# ============================================================================
# Pipeline
# ============================================================================
def _expected_rejection(exc: BaseException) -> bool:
    """Deliberate rejections: BinaryFormatError, the time budget, or a 4xx API error."""
    from backend.buffer import BinaryFormatError

    if isinstance(exc, (BinaryFormatError, runtime.ParseBudgetExceeded)):
        return True
    api_error = getattr(runtime, "ApiError", None)
    if api_error is not None and isinstance(exc, api_error):
        return int(getattr(exc, "status", 500) or 500) < 500
    return False


def _api_client_error(exc: BaseException) -> bool:
    api_error = getattr(runtime, "ApiError", None)
    return api_error is not None and isinstance(exc, api_error) and int(getattr(exc, "status", 500) or 500) < 500


class _ParseSpy:
    """Wraps the parser the service calls so the original exception survives the
    service's translation of ValueError into an API error."""

    def __init__(self) -> None:
        from backend import parser as parser_mod

        self.real = parser_mod.parse_macho_bytes
        self.last_exc: Optional[BaseException] = None

    def __call__(self, data: bytes, path: str = "<memory>") -> Dict[str, Any]:
        self.last_exc = None
        try:
            return self.real(data, path=path)
        except BaseException as exc:
            self.last_exc = exc
            raise


_SPY: Optional[_ParseSpy] = None


def _install_spy() -> _ParseSpy:
    global _SPY
    if _SPY is None:
        import backend.service as service_mod

        _SPY = _ParseSpy()
        service_mod.parse_macho_bytes = _SPY  # type: ignore[assignment]
    return _SPY


def _internal_warnings(doc: Dict[str, Any]) -> List[str]:
    """Parser sub-analyses that failed and were degraded to a warning are bugs too."""
    out = []
    for sl in doc.get("slices") or []:
        for w in sl.get("warnings") or []:
            if w.get("code") == "analysis_error":
                out.append(w.get("message", ""))
    return out


class _ServiceAdapter:
    """Drives AnalysisService the way a client would, tolerating API evolution."""

    def __init__(self) -> None:
        from backend.service import AnalysisService

        try:
            self.svc = AnalysisService(ROOT)
        except TypeError:
            self.svc = AnalysisService(ROOT, runtime.get_config())  # type: ignore[call-arg]
        self.doc_kwargs: Dict[str, Any] = {}

    def load(self, data: bytes) -> Dict[str, Any]:
        _install_spy()
        doc = self.svc.load_uploaded_bytes("fuzz.bin", data)
        doc_id = doc.get("doc_id") if isinstance(doc, dict) else None
        self.doc_kwargs = {"doc": doc_id} if doc_id else {"path": getattr(self.svc, "active_path", None)}
        return doc

    def call(self, name: str, **kwargs: Any) -> Any:
        fn = getattr(self.svc, name)
        params = inspect.signature(fn).parameters
        for k, v in self.doc_kwargs.items():
            if k in params:
                kwargs[k] = v
            elif k == "doc" and "doc_id" in params:
                kwargs["doc_id"] = v
        return fn(**{k: v for k, v in kwargs.items() if k in params})


def run_pipeline(data: bytes, service_calls: bool = True) -> Tuple[str, str]:
    """
    Returns (outcome, detail). outcome is 'ok' | 'rejected' | 'bug'.
    Must be called inside the runtime config the caller wants (public mode by default).
    """
    stage = "parse"
    try:
        with runtime.parse_deadline(120):
            if service_calls:
                adapter = _ServiceAdapter()
                doc = adapter.load(data)
            else:
                from backend.parser import parse_macho_bytes

                doc = parse_macho_bytes(data, path="fuzz.bin")
        stage = "json"
        json.dumps(doc, allow_nan=False)
        internal = _internal_warnings(doc)
        if internal:
            return "bug", "parse: degraded sub-analysis: " + internal[0][:160]
        if not service_calls:
            return "ok", ""
        slices = doc.get("slices") or []
        if not slices:
            return "bug", "parse: document without slices"
        size = len(data)
        rng = random.Random(size)
        offsets = sorted({0, 1, max(0, size - 1), size // 2, size, size + 100, -5, rng.randrange(max(1, size))})
        for si in range(min(len(slices), 3)):
            sl = slices[si]
            stage = f"hex[{si}]"
            for off in offsets[:4]:
                json.dumps(adapter.call("get_hex_slice", offset=off, length=rng.choice((16, 256, 4096, 1 << 30)), slice_index=si), allow_nan=False)
            stage = f"decode[{si}]"
            for off in offsets:
                json.dumps(adapter.call("decode_bytes_at", offset=off, slice_index=si, endian=rng.choice(("little", "big"))), allow_nan=False)
            stage = f"translate[{si}]"
            queries = ["0", "0x0", "0xffffffffffffffff", "-1", "zzz", "0x" + "f" * 40, str(size)]
            ep = (sl.get("entry_point") or {}).get("vmaddr")
            if isinstance(ep, str):
                queries.append(ep)
            for seg in (sl.get("segments") or [])[:3]:
                if isinstance(seg.get("vmaddr"), str):
                    queries.append(seg["vmaddr"])
            for q in queries:
                for mode in ("auto", "vmaddr", "abs_offset", "slice_offset"):
                    json.dumps(adapter.call("translate_address", slice_index=si, query=q, mode=mode), allow_nan=False)
            stage = f"disassemble[{si}]"
            json.dumps(adapter.call("disassemble", slice_index=si, count=200), allow_nan=False)
            if isinstance(ep, str):
                json.dumps(adapter.call("disassemble", slice_index=si, vmaddr=ep, count=64), allow_nan=False)
            json.dumps(adapter.call("disassemble", slice_index=si, vmaddr="0xffffffffffffffff", count=8), allow_nan=False)
            for seg in (sl.get("segments") or [])[:2]:
                for sect in (seg.get("sections") or [])[:2]:
                    name = f"{sect.get('segname')},{sect.get('sectname')}"
                    json.dumps(adapter.call("disassemble", slice_index=si, section=name, count=32), allow_nan=False)
            stage = f"search[{si}]"
            syms = sl.get("symbols") or []
            qs = ["a", "@_", '"lib', "#LC", "0x1000", "00 00", "cf fa ed fe", "zz", "0x" + "f" * 30, "1234567890123"]
            if syms and isinstance(syms[0].get("name"), str) and syms[0]["name"]:
                qs.append("@" + syms[0]["name"][:6])
            for q in qs:
                json.dumps(adapter.call("search", query=q, slice_index=si), allow_nan=False)
        return "ok", ""
    except Exception as exc:  # noqa: BLE001 - classification is the point
        if stage == "parse" and _SPY is not None and _SPY.last_exc is not None and _SPY.last_exc is not exc:
            # The service translated the parser's exception; classify the original.
            orig = _SPY.last_exc
            _SPY.last_exc = None
            if _expected_rejection(orig):
                return "rejected", f"{type(orig).__name__}: {orig}"[:200]
            exc = orig  # type: ignore[assignment]
        elif stage == "parse" and _expected_rejection(exc):
            return "rejected", f"{type(exc).__name__}: {exc}"[:200]
        elif stage != "parse" and _api_client_error(exc):
            return "ok", f"client error in {stage}: {exc}"[:200]
        tb = traceback.extract_tb(exc.__traceback__)
        where = ""
        for fr in reversed(tb):
            if "/backend/" in fr.filename:
                where = f"{os.path.basename(fr.filename)}:{fr.lineno} in {fr.name}"
                break
        return "bug", f"{stage}: {type(exc).__name__}: {str(exc)[:160]} @ {where}"


# ============================================================================
# Worker / supervisor
# ============================================================================
def _maxrss_bytes() -> int:
    try:
        import resource

        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return r if sys.platform == "darwin" else r * 1024
    except Exception:
        return 0


def _worker_main(conn, seed: int, extra: List[str], include_host: bool, mem_mb: int, use_tracemalloc: bool, service_calls: bool) -> None:
    import tracemalloc

    try:
        import resource

        limit = (mem_mb * 4 + 1024) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except Exception:
        pass
    runtime.set_config(runtime.RuntimeConfig("public"))
    corpus = load_corpus(extra, include_host)
    conn.send(("ready", len(corpus), [s.name for s in corpus]))
    while True:
        msg = conn.recv()
        if msg is None:
            return
        index = msg
        name, data = generate_case(corpus, seed, index)
        # tracemalloc slows Python ~3-5x, so only every 4th case is traced; the
        # rest are timed in CPU seconds (immune to load from sibling workers) and
        # watched through the growth of the process's peak RSS.
        traced = use_tracemalloc and index % 4 == 0
        rss_before = _maxrss_bytes()
        if traced:
            tracemalloc.start()
        c0 = time.process_time()
        try:
            outcome, detail = run_pipeline(data, service_calls=service_calls)
        except MemoryError:
            outcome, detail = "bug", "MemoryError"
        cpu = time.process_time() - c0
        peak = 0
        if traced:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            cpu /= 4.0  # normalise the tracing overhead for the slow-case threshold
        rss_after = _maxrss_bytes()
        peak = max(peak, rss_after - rss_before)
        conn.send(("done", index, name, len(data), outcome, detail, cpu, peak, rss_after))


def _rss_of(pid: int) -> int:
    try:
        import subprocess

        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=2).stdout.strip()
        return int(out) * 1024 if out else 0
    except Exception:
        return 0


def supervise(args: argparse.Namespace) -> int:
    import multiprocessing as mp
    from multiprocessing.connection import wait

    ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
    total = args.iterations
    next_index = args.start
    end_index = args.start + total
    workers: Dict[int, Dict[str, Any]] = {}
    counts = {"ok": 0, "rejected": 0, "bug": 0}
    findings: List[Dict[str, Any]] = []
    slowest: List[Tuple[float, int, str]] = []
    peak_mem: List[Tuple[int, int, str]] = []
    t_start = time.time()
    done = 0
    corpus_names: List[str] = []

    def spawn(wid: int) -> None:
        parent, child = ctx.Pipe()
        p = ctx.Process(
            target=_worker_main,
            args=(child, args.seed, args.extra_seeds, not args.no_host, args.mem_mb, not args.no_tracemalloc, not args.parse_only),
            daemon=True,
        )
        p.start()
        workers[wid] = {"proc": p, "conn": parent, "busy": None, "t0": 0.0, "ready": False, "last_rss": 0.0}

    def record(kind: str, index: int, name: str, detail: str, extra: Dict[str, Any]) -> None:
        counts["bug"] += 1
        f = {"kind": kind, "case": index, "name": name, "detail": detail}
        f.update(extra)
        findings.append(f)
        print(f"  BUG case={index} [{kind}] {name}: {detail}", flush=True)
        if args.save_dir:
            try:
                corpus = _CORPUS_CACHE.get("c") or load_corpus(args.extra_seeds, not args.no_host)
                _CORPUS_CACHE["c"] = corpus
                _, data = generate_case(corpus, args.seed, index)
                os.makedirs(args.save_dir, exist_ok=True)
                with open(os.path.join(args.save_dir, f"case_{args.seed}_{index}.bin"), "wb") as fh:
                    fh.write(data)
            except Exception:
                pass

    for wid in range(args.workers):
        spawn(wid)
    last_tick = time.time()

    try:
        while done < total:
            # Dispatch
            for wid, w in workers.items():
                if w["ready"] and w["busy"] is None and next_index < end_index:
                    w["conn"].send(next_index)
                    w["busy"] = next_index
                    w["t0"] = time.time()
                    next_index += 1
            ready_conns = wait([w["conn"] for w in workers.values()], timeout=0.2)
            for conn in ready_conns:
                wid = next(k for k, w in workers.items() if w["conn"] is conn)
                w = workers[wid]
                try:
                    msg = conn.recv()
                except (EOFError, OSError):
                    idx = w["busy"]
                    if idx is not None:
                        done += 1
                        record("crash", idx, "?", f"worker died (exit {w['proc'].exitcode})", {})
                    w["proc"].join(1)
                    spawn(wid)
                    continue
                if msg[0] == "ready":
                    w["ready"] = True
                    corpus_names = msg[2]
                    continue
                _, idx, name, size, outcome, detail, elapsed, peak, maxrss = msg
                w["busy"] = None
                done += 1
                if outcome == "bug":
                    record("exception", idx, name, detail, {"size": size, "elapsed": round(elapsed, 3)})
                else:
                    counts[outcome] += 1
                if elapsed > args.slow:
                    record("slow", idx, name, f"{elapsed:.2f} CPU-s (outcome {outcome})", {"size": size})
                mem_limit = args.mem_mb * 1024 * 1024
                if peak > mem_limit:
                    record("memory", idx, name, f"peak allocation {peak / 1e6:.0f} MB", {"size": size})
                slowest.append((elapsed, idx, name))
                slowest.sort(reverse=True)
                del slowest[10:]
                peak_mem.append((peak, idx, name))
                peak_mem.sort(reverse=True)
                del peak_mem[10:]
                if maxrss > mem_limit * 3:
                    # Recycle the worker so one heavy case doesn't mask the next.
                    w["conn"].send(None)
                    w["proc"].join(2)
                    spawn(wid)
                if done % args.progress == 0:
                    rate = done / max(1e-6, time.time() - t_start)
                    print(f"[{done}/{total}] ok={counts['ok']} rejected={counts['rejected']} bugs={counts['bug']} ({rate:.0f} cases/s)", flush=True)
            # Watchdog. If the supervisor itself was not scheduled for a while (host
            # suspended / overloaded), don't blame the workers for that gap.
            now = time.time()
            gap = now - last_tick
            last_tick = now
            if gap > 5.0:
                print(f"  (supervisor stalled {gap:.0f}s; extending in-flight deadlines)", flush=True)
                for w in workers.values():
                    if w["busy"] is not None:
                        w["t0"] += gap
            for wid, w in list(workers.items()):
                if w["busy"] is None:
                    continue
                elapsed = now - w["t0"]
                over_mem = False
                if now - w["last_rss"] > 1.0:
                    w["last_rss"] = now
                    over_mem = _rss_of(w["proc"].pid) > args.hard_mem_mb * 1024 * 1024
                if elapsed > args.hard_timeout or over_mem:
                    idx = w["busy"]
                    w["proc"].kill()
                    w["proc"].join(2)
                    done += 1
                    record("hang" if not over_mem else "memory", idx, "?", f"killed after {elapsed:.1f}s" + (" (RSS limit)" if over_mem else ""), {})
                    spawn(wid)
    finally:
        for w in workers.values():
            try:
                w["conn"].send(None)
            except Exception:
                pass
        for w in workers.values():
            w["proc"].join(1)
            if w["proc"].is_alive():
                w["proc"].kill()

    wall = time.time() - t_start
    print("=" * 72)
    print(f"seed={args.seed} cases={done} [{args.start}..{end_index}) wall={wall:.1f}s corpus={len(corpus_names)} seeds")
    print(f"ok={counts['ok']} rejected={counts['rejected']} bugs={counts['bug']}")
    print("slowest:", ", ".join(f"#{i} {e:.2f}s" for e, i, _ in slowest[:5]))
    print("peak allocation:", ", ".join(f"#{i} {m / 1e6:.0f}MB" for m, i, _ in peak_mem[:5]))
    if args.out:
        with open(args.out, "w") as fh:
            json.dump({
                "seed": args.seed, "start": args.start, "cases": done, "wall_seconds": wall,
                "counts": counts, "corpus": corpus_names, "findings": findings,
                "slowest": slowest, "peak_tracemalloc": peak_mem,
            }, fh, indent=1)
    return 1 if counts["bug"] else 0


_CORPUS_CACHE: Dict[str, Any] = {}


def repro(args: argparse.Namespace) -> int:
    runtime.set_config(runtime.RuntimeConfig("public"))
    if args.repro_file:
        with open(args.repro_file, "rb") as fh:
            data = fh.read()
        name = args.repro_file
    else:
        corpus = load_corpus(args.extra_seeds, not args.no_host)
        name, data = generate_case(corpus, args.seed, args.repro_case)
        if args.dump:
            with open(args.dump, "wb") as fh:
                fh.write(data)
    print(f"case {name} ({len(data)} bytes)")
    t0 = time.perf_counter()
    outcome, detail = run_pipeline(data, service_calls=not args.parse_only)
    print(f"{outcome} in {time.perf_counter() - t0:.3f}s {detail}")
    if outcome == "bug" and args.traceback:
        from backend.parser import parse_macho_bytes

        parse_macho_bytes(data, path="repro.bin")  # re-raise with full traceback
    return 0 if outcome != "bug" else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iterations", "-n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--start", type=int, default=0, help="first case index")
    ap.add_argument("--workers", "-j", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--slow", type=float, default=2.0, help="report cases using more CPU seconds than this")
    ap.add_argument("--hard-timeout", type=float, default=20.0, help="kill a worker stuck this long")
    ap.add_argument("--mem-mb", type=int, default=400, help="report cases whose peak allocation (tracemalloc / RSS growth) exceeds this")
    ap.add_argument("--hard-mem-mb", type=int, default=3000, help="kill a worker whose RSS exceeds this")
    ap.add_argument("--no-tracemalloc", action="store_true")
    ap.add_argument("--no-host", action="store_true", help="only use the synthetic fixtures as seeds")
    ap.add_argument("--parse-only", action="store_true", help="skip the service calls")
    ap.add_argument("--extra-seeds", nargs="*", default=[])
    ap.add_argument("--save-dir", default=None)
    ap.add_argument("--out", default=None, help="write a JSON report")
    ap.add_argument("--progress", type=int, default=1000)
    ap.add_argument("--repro-case", type=int, default=None)
    ap.add_argument("--repro-file", default=None)
    ap.add_argument("--dump", default=None, help="with --repro-case: write the case bytes here")
    ap.add_argument("--traceback", action="store_true")
    args = ap.parse_args(argv)
    if args.repro_case is not None or args.repro_file:
        return repro(args)
    return supervise(args)


if __name__ == "__main__":
    sys.exit(main())
