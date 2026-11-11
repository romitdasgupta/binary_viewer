"""
Parser robustness regression suite.

1. A bounded, deterministic slice of the fuzz corpus (tests/fuzz_harness.py) run
   in-process against the synthetic fixtures: every case must either parse (with
   warnings) or be rejected with BinaryFormatError, serialise as strict JSON, and
   survive the client-facing service calls.
2. One targeted regression per distinct bug class fixed during the robustness
   pass, each built from a small hand-crafted hostile file.
"""

import json
import os
import struct
import sys
import time
import tracemalloc
import unittest
from typing import Callable, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.dirname(os.path.abspath(__file__))
for p in (ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

from backend import runtime  # noqa: E402
from backend.buffer import BinaryBuffer, BinaryFormatError  # noqa: E402
from backend.constants import ANALYSIS_LIMITS  # noqa: E402
from backend.parser import parse_macho_bytes  # noqa: E402

import fuzz_harness  # noqa: E402

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
MH_EXECUTE = 2
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_CODE_SIGNATURE = 0x1D
LC_DYLD_EXPORTS_TRIE = 0x80000033


# ============================================================================
# Builders for hostile inputs
# ============================================================================
def macho64(cmds: List[bytes], tail: bytes = b"", ncmds: Optional[int] = None,
            cputype: int = CPU_TYPE_ARM64, pad_to: int = 0) -> bytes:
    body = b"".join(cmds)
    hdr = struct.pack("<IIIIIIII", MH_MAGIC_64, cputype, 0, MH_EXECUTE,
                      len(cmds) if ncmds is None else ncmds, len(body), 0x00200085, 0)
    out = hdr + body
    if pad_to and len(out) < pad_to:
        out += b"\x00" * (pad_to - len(out))
    return out + tail


def lc_segment64(name: bytes, vmaddr: int, vmsize: int, fileoff: int, filesize: int,
                 sections: Tuple[bytes, ...] = (), prot: int = 5, nsects: Optional[int] = None) -> bytes:
    size = 72 + 80 * len(sections)
    return struct.pack("<II16sQQQQIIII", LC_SEGMENT_64, size, name.ljust(16, b"\x00"), vmaddr, vmsize,
                       fileoff, filesize, prot, prot, len(sections) if nsects is None else nsects, 0) + b"".join(sections)


def section64(sectname: bytes, segname: bytes, addr: int, size: int, offset: int,
              flags: int = 0, reserved1: int = 0, reserved2: int = 0) -> bytes:
    return struct.pack("<16s16sQQIIIIIIII", sectname.ljust(16, b"\x00"), segname.ljust(16, b"\x00"),
                       addr, size, offset, 0, 0, 0, flags, reserved1, reserved2, 0)


def lc_linkedit(cmd: int, dataoff: int, datasize: int) -> bytes:
    return struct.pack("<IIII", cmd, 16, dataoff, datasize)


def lc_symtab(symoff: int, nsyms: int, stroff: int, strsize: int) -> bytes:
    return struct.pack("<IIIIII", LC_SYMTAB, 24, symoff, nsyms, stroff, strsize)


def lc_dysymtab(indirectsymoff: int, nindirectsyms: int) -> bytes:
    fields = [0] * 18
    fields[12] = indirectsymoff
    fields[13] = nindirectsyms
    return struct.pack("<II18I", LC_DYSYMTAB, 80, *fields)


def superblob(entries: List[Tuple[int, bytes]], declared_count: Optional[int] = None) -> bytes:
    """CS_SuperBlob with (slot_type, blob_bytes) entries, big-endian."""
    count = len(entries)
    header_len = 12 + 8 * count
    index = b""
    blobs = b""
    for slot, blob in entries:
        index += struct.pack(">II", slot, header_len + len(blobs))
        blobs += blob
    total = header_len + len(blobs)
    return struct.pack(">III", 0xFADE0CC0, total, count if declared_count is None else declared_count) + index + blobs


def macho_with_signature(sig: bytes) -> bytes:
    sig_off = 0x1000
    cmds = [
        lc_segment64(b"__TEXT", 0x100000000, 0x1000, 0, 0x1000),
        lc_segment64(b"__LINKEDIT", 0x100001000, 0x1000 + len(sig), sig_off, len(sig), prot=1),
        lc_linkedit(LC_CODE_SIGNATURE, sig_off, len(sig)),
    ]
    return macho64(cmds, pad_to=sig_off) + sig


def elf64(sections: List[Tuple[str, int, int, int, int, int, int, int, int]], blobs: bytes,
          e_type: int = 3, phdrs: bytes = b"", phnum: int = 0, shstrtab_at_zero: bool = False) -> bytes:
    """
    Minimal ELF64 LE: header, then `blobs` at offset 64 (+phdrs), then section headers.
    sections: (name, type, flags, addr, offset, size, link, info, entsize); a shstrtab
    is appended automatically as the last section.
    """
    data_off = 64 + len(phdrs)
    names = b"\x00"
    name_offs = []
    for sec in sections:
        name_offs.append(len(names))
        names += sec[0].encode() + b"\x00"
    shstr_name = len(names)
    names += b".shstrtab\x00"
    shstr_off = data_off + len(blobs)
    sh_off = shstr_off + len(names)
    sh_off += (-sh_off) % 8
    shdrs = b"\x00" * 64
    for (name, typ, flags, addr, off, size, link, info, ent), noff in zip(sections, name_offs):
        shdrs += struct.pack("<IIQQQQIIQQ", noff, typ, flags, addr, off, size, link, info, 8, ent)
    shdrs += struct.pack("<IIQQQQIIQQ", shstr_name, 3, 0, 0, 0 if shstrtab_at_zero else shstr_off, len(names), 0, 0, 1, 0)
    shnum = len(sections) + 2
    hdr = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack(
        "<HHIQQQIHHHHHH", e_type, 62, 1, 0x1000, 64 if phdrs else 0, sh_off, 0, 64, 56, phnum, 64, shnum, shnum - 1)
    body = hdr + phdrs + blobs + names
    body += b"\x00" * (sh_off - len(body))
    return body + shdrs


def pe32plus(sections: List[Tuple[bytes, int, int, int, int, int]], data_dirs: List[Tuple[int, int]],
             body: bytes, stub: bytes = b"", raw_base: int = 0x400) -> bytes:
    """sections: (name, vsize, rva, raw_size, raw_ptr, characteristics)."""
    e_lfanew = 0x40 + len(stub)
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew) + stub
    n_dd = 16
    opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, 0x200, 0x200, 0, 0x1000, 0x1000)
    opt += struct.pack("<QIIHHHHHHIIIIHHQQQQII", 0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
                       0x10000, raw_base, 0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, n_dd)
    dds = list(data_dirs) + [(0, 0)] * (n_dd - len(data_dirs))
    opt += b"".join(struct.pack("<II", r, s) for r, s in dds)
    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, len(opt), 0x22)
    shdrs = b"".join(struct.pack("<8sIIIIIIHHI", n.ljust(8, b"\x00"), vs, rva, rs, rp, 0, 0, 0, 0, ch)
                     for n, vs, rva, rs, rp, ch in sections)
    head = dos + b"PE\x00\x00" + coff + opt + shdrs
    assert len(head) <= raw_base, "headers overflow raw_base"
    return head + b"\x00" * (raw_base - len(head)) + body


def fat(slices: List[Tuple[int, int]], data: bytes, cputype: int = CPU_TYPE_ARM64) -> bytes:
    hdr = struct.pack(">II", 0xCAFEBABE, len(slices))
    for off, size in slices:
        hdr += struct.pack(">IIIII", cputype, 0, off, size, 12)
    return hdr + data[len(hdr):]


# ============================================================================
# Helpers
# ============================================================================
def measure(fn: Callable[[], object], track_memory: bool = True) -> Tuple[object, float, int]:
    """(result, seconds, tracemalloc peak bytes; 0 when not tracked). Tracking slows Python ~5x."""
    if track_memory:
        tracemalloc.start()
    t0 = time.perf_counter()
    try:
        result = fn()
    finally:
        elapsed = time.perf_counter() - t0
        peak = 0
        if track_memory:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
    return result, elapsed, peak


def warning_codes(doc: dict, slice_index: int = 0) -> List[str]:
    return [w["code"] for w in doc["slices"][slice_index].get("warnings", [])]


MB = 1024 * 1024


class _PublicMode(unittest.TestCase):
    """Run with external tools disabled (public / WASM behaviour)."""

    def setUp(self) -> None:
        self._prev_cfg = runtime.get_config()
        runtime.set_config(runtime.RuntimeConfig("public"))

    def tearDown(self) -> None:
        runtime.set_config(self._prev_cfg)

    def parse_ok(self, data: bytes, max_seconds: float = 2.0, max_peak: Optional[int] = None) -> dict:
        """Parse must succeed, be strict JSON, stay under max_seconds (and max_peak bytes when given)."""
        doc, elapsed, peak = measure(lambda: parse_macho_bytes(data, path="crafted.bin"), track_memory=max_peak is not None)
        if max_peak is None:
            max_peak = 1 << 62
        else:
            max_seconds *= 5  # tracemalloc overhead
        json.dumps(doc, allow_nan=False)  # must be strict-JSON serialisable
        self.assertLess(elapsed, max_seconds, f"parse took {elapsed:.2f}s")
        self.assertLess(peak, max_peak, f"parse peaked at {peak / MB:.0f} MB")
        for sl in doc["slices"]:
            self.assertNotIn("analysis_error", [w["code"] for w in sl.get("warnings", [])])
        return doc  # type: ignore[return-value]


# ============================================================================
# 1. Deterministic fuzz slice
# ============================================================================
class TestFuzzRegressionSlice(_PublicMode):
    CASES = 240
    SEED = 20261109

    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = fuzz_harness.load_corpus(include_host=False)

    def test_fuzz_slice_is_clean(self) -> None:
        bugs = []
        slow = []
        for index in range(self.CASES):
            name, data = fuzz_harness.generate_case(self.corpus, self.SEED, index)
            t0 = time.perf_counter()
            outcome, detail = fuzz_harness.run_pipeline(data, service_calls=(index % 4 == 0))
            elapsed = time.perf_counter() - t0
            if outcome == "bug":
                bugs.append(f"case {index} {name}: {detail}")
            if elapsed > 2.0:
                slow.append(f"case {index} {name}: {elapsed:.2f}s")
        self.assertEqual(bugs, [])
        self.assertEqual(slow, [])

    def test_degenerate_inputs(self) -> None:
        cases = [b"", b"\x00", b"\xff" * 27, b"\xcf\xfa\xed\xfe", b"\x00" * 65536, b"\xff" * 65536,
                 b"\x7fELF" + b"\xff" * 60, b"MZ" + b"\xff" * 200, b"\xca\xfe\xba\xbe" + b"\xff" * 200,
                 b"\xca\xfe\xba\xbe\x00\x00\x00\x01" + b"\xff" * 100, b"\xcf\xfa\xed\xfe" + b"\xff" * 4096]
        for data in cases:
            try:
                doc = parse_macho_bytes(data)
                json.dumps(doc, allow_nan=False)
            except BinaryFormatError:
                pass


# ============================================================================
# 2. Targeted regressions, one per bug class
# ============================================================================
class TestBufferAndRejections(_PublicMode):
    def test_read_bytes_pads_small_reads_but_never_huge_ones(self) -> None:
        # Bug: read_bytes zero-padded any out-of-range read to `size`, so a 32-bit
        # length from the file (e.g. a code-signature blob length) allocated GBs.
        buf = BinaryBuffer(b"\x01\x02\x03\x04")
        self.assertEqual(buf.read_bytes(2, 4), b"\x03\x04\x00\x00")
        (big, _, peak) = measure(lambda: buf.read_bytes(0, 0xFFFFFFF0))
        self.assertEqual(big, b"\x01\x02\x03\x04")
        self.assertLess(peak, MB)
        f = buf.record_field("x", "string", 0, 0xFFFFFFFF, 0)
        self.assertEqual(f["size"], 0xFFFFFFFF)

    def test_deliberate_rejections_use_binary_format_error(self) -> None:
        # Bug: deliberate rejections were plain ValueError, indistinguishable from
        # ValueErrors raised by parser defects.
        for data in (b"short", b"\x00" * 64, b"\x7fELF" + b"\x00" * 20):
            with self.assertRaises(BinaryFormatError):
                parse_macho_bytes(data)

    def test_elf_rel_sections_all_at_offset_zero(self) -> None:
        # Bug: min() over an empty generator raised ValueError for ET_REL files
        # whose allocatable sections all have sh_offset == 0.
        data = elf64([(".text", 1, 0x6, 0, 0, 0x100, 0, 0, 0)], b"", e_type=1, shstrtab_at_zero=True)
        doc = self.parse_ok(data)
        self.assertEqual(doc["file_info"]["format"], "ELF")


class TestFatContainer(_PublicMode):
    def test_fat_without_parseable_slices_is_rejected(self) -> None:
        # Bug: a fat header whose slices all point past EOF produced a document
        # with no slices, which crashed every later API call.
        data = fat([(0x100000, 0x1000)], b"\x00" * 4096)
        with self.assertRaises(BinaryFormatError):
            parse_macho_bytes(data)

    def test_overlapping_fat_slices_are_parsed_once(self) -> None:
        # Bug: 32 fat entries pointing at the same Mach-O multiplied the full
        # analysis 32 times over the same bytes.
        inner = macho64([lc_segment64(b"__TEXT", 0x100000000, 0x4000, 0, 0x4000)], pad_to=0x4000)
        data = bytearray(0x1000) + inner
        data = fat([(0x1000, len(inner))] * 32, bytes(data))
        doc = self.parse_ok(data)
        self.assertEqual(len(doc["slices"]), 1)
        self.assertTrue(any("overlap" in w["code"] for w in doc["file_info"]["warnings"]))


class TestMachOCaps(_PublicMode):
    def test_huge_ncmds_and_section_counts_are_capped(self) -> None:
        # Bug: 512 load commands x 256 sections each = 131k section objects
        # (and 1.5M field dicts) from a 10 MB file.
        sects = tuple(section64(b"__s%d" % i, b"__DATA", 0x200000000 + i, 1, 0) for i in range(256))
        seg = lc_segment64(b"__DATA", 0x200000000, 0x1000, 0, 0, sections=sects, prot=3)
        data = macho64([seg] * 40, ncmds=0xFFFFFFFF)
        doc = self.parse_ok(data, max_peak=300 * MB)
        sl = doc["slices"][0]
        total_sections = sum(len(s["sections"]) for s in sl["segments"])
        self.assertLessEqual(total_sections, ANALYSIS_LIMITS["sections_total"])
        codes = warning_codes(doc)
        self.assertIn("load_commands_truncated", codes)
        self.assertIn("sections_truncated", codes)
        self.assertTrue(sl["truncated"])

    def test_indirect_symbol_tables_are_capped_globally(self) -> None:
        # Bug: every S_SYMBOL_STUBS section re-read up to 512 slots from the same
        # indirect table, so slot count multiplied with section count.
        stub = section64(b"__stubs", b"__TEXT", 0x100000000, 0x100000, 0x400, flags=0x80000408,
                         reserved1=0, reserved2=1)
        seg = lc_segment64(b"__TEXT", 0x100000000, 0x100000, 0, 0x1000, sections=(stub,) * 200)
        data = macho64([seg, lc_dysymtab(0x400, 0xFFFFFFFF)], pad_to=0x400) + b"\x00" * 0x10000
        doc = self.parse_ok(data, max_seconds=2.0)
        ind = doc["slices"][0]["dysymtab"]["indirect_symbols"]
        self.assertLessEqual(len(ind), ANALYSIS_LIMITS["indirect_symbols"])
        self.assertIn("indirect_symbols_truncated", warning_codes(doc))

    def test_symbol_to_segment_lookup_is_not_quadratic(self) -> None:
        # Bug: each N_SECT symbol scanned every segment (512 x 20000 here).
        segs = [lc_segment64(b"S%d" % i, 0x1000 * (i + 1), 0x1000, 0, 0x10) for i in range(512)]
        nsyms = ANALYSIS_LIMITS["symbols"]
        symoff = 0x10000
        nlist = struct.pack("<IBBHQ", 1, 0x0F, 1, 0, 0x1000 * 512 + 8) * nsyms
        strtab = b"\x00_sym\x00"
        cmds = segs + [lc_symtab(symoff, nsyms, symoff + len(nlist), len(strtab))]
        data = macho64(cmds, pad_to=symoff) + nlist + strtab
        doc = self.parse_ok(data, max_seconds=2.0)
        self.assertEqual(len(doc["slices"][0]["symbols"]), nsyms)
        self.assertIsNotNone(doc["slices"][0]["symbols"][0]["target_abs_offset"])

    def test_export_trie_names_and_fanout_are_bounded(self) -> None:
        # Bug: a chain of terminal trie nodes with 255-byte edges produced export
        # names of 255, 510, ... bytes: O(n^2) total (2000 exports -> ~500 MB).
        trie = bytearray()
        n_nodes = 4000
        node_size = 2 + 2 + 255 + 1 + 3
        for i in range(n_nodes):
            nxt = (i + 1) * node_size
            trie += b"\x02\x00\x00" + b"\x01" + b"A" * 255 + b"\x00" + bytes([0x80 | (nxt & 0x7F), 0x80 | ((nxt >> 7) & 0x7F), (nxt >> 14) & 0x7F])
        trie += b"\x02\x00\x00\x00"  # terminal with flags 0, offset 0
        off = 0x1000
        data = macho64([lc_linkedit(LC_DYLD_EXPORTS_TRIE, off, len(trie))], pad_to=off) + bytes(trie)
        doc = self.parse_ok(data)
        for ex in doc["slices"][0]["dyld_info"]["exports"]:
            self.assertLessEqual(len(ex["name"]), ANALYSIS_LIMITS["export_name_chars"])
        self.assertIn("export_name_too_long", warning_codes(doc))

    def test_entropy_of_many_overlapping_huge_sections_is_bounded(self) -> None:
        # Bug: each section was copied in full before sampling; 4096 sections
        # aliasing one large range meant GBs of copying.
        size = 4 * MB
        sects = tuple(section64(b"__d%d" % i, b"__DATA", 0x200000000, size, 0x1000) for i in range(256))
        segs = [lc_segment64(b"__DATA", 0x200000000, size, 0x1000, size, sections=sects, prot=3)] * 16
        data = macho64(segs, pad_to=0x1000) + os.urandom(size)
        doc = self.parse_ok(data, max_seconds=2.0)
        self.assertGreater(len(doc["slices"][0]["semantic_layers"]["entropy_analysis"]["sections"]), 1000)


class TestCodeSignature(_PublicMode):
    def test_huge_blob_length_does_not_allocate(self) -> None:
        # Bug: blob / CodeDirectory lengths (0xFFFFFFF0) were read with zero
        # padding -> multi-GB allocations.
        ent = struct.pack(">II", 0xFADE7171, 0xFFFFFFF0) + b"<plist/>"
        cd = struct.pack(">IIIIIIIIIBBBBI", 0xFADE0C02, 0xFFFFFFF0, 0x20400, 0, 44, 0, 0, 0, 0, 32, 2, 0, 12, 0)
        doc = self.parse_ok(macho_with_signature(superblob([(5, ent), (0, cd)])), max_peak=64 * MB)
        self.assertTrue(doc["slices"][0]["code_signature_detail"]["present"])

    def _plist_doc(self, plist: bytes) -> dict:
        ent = struct.pack(">II", 0xFADE7171, 8 + len(plist)) + plist
        return self.parse_ok(macho_with_signature(superblob([(5, ent)])))

    def test_entitlement_plist_data_and_date_values_are_json_safe(self) -> None:
        # Bug: <data> / <date> plist values (bytes / datetime) made the document
        # unserialisable -> HTTP 500.
        plist = (b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
                 b"<key>blob</key><data>3q2+7w==</data><key>when</key><date>2020-01-02T03:04:05Z</date>"
                 b"<key>big</key><integer>18446744073709551615</integer></dict></plist>")
        ents = self._plist_doc(plist)["slices"][0]["code_signature_detail"]["entitlements_dict"]
        self.assertEqual(ents["blob"], "deadbeef")
        self.assertTrue(ents["when"].startswith("2020-01-02"))

    def test_deeply_nested_entitlements_are_truncated(self) -> None:
        # Bug: 20k nested <array> elements made json.dumps hit RecursionError.
        depth = 20000
        plist = (b'<?xml version="1.0"?><plist version="1.0"><dict><key>k</key>' + b"<array>" * depth
                 + b"</array>" * depth + b"</dict></plist>")
        doc = self._plist_doc(plist)
        self.assertIn("entitlements_truncated", warning_codes(doc))

    def test_huge_plist_integer_is_not_parsed(self) -> None:
        # Bug: a 900k-digit <integer> took seconds to parse (and longer to print).
        plist = b'<?xml version="1.0"?><plist><dict><key>n</key><integer>' + b"9" * 900000 + b"</integer></dict></plist>"
        self._plist_doc(plist)

    def test_der_entitlements_depth_and_integer_size_are_bounded(self) -> None:
        # Bug: unbounded recursion on nested SEQUENCEs (a C-stack risk under
        # Pyodide) and multi-KB INTEGERs rendered as decimal (quadratic).
        def der(tag: int, content: bytes) -> bytes:
            n = len(content)
            if n < 0x80:
                return bytes([tag, n]) + content
            nb = (n.bit_length() + 7) // 8
            return bytes([tag, 0x80 | nb]) + n.to_bytes(nb, "big") + content
        nested = der(0x02, b"\x01")
        for _ in range(3000):
            nested = der(0x30, nested)
        pair = der(0x30, der(0x0C, b"big") + der(0x02, b"\x7f" + b"\xff" * 200000))
        payload = der(0x31, pair + der(0x30, der(0x0C, b"deep") + nested))
        blob = struct.pack(">II", 0xFADE7172, 8 + len(payload)) + payload
        doc = self.parse_ok(macho_with_signature(superblob([(7, blob)])))
        ents = doc["slices"][0]["code_signature_detail"]["entitlements_dict"]
        self.assertIsInstance(ents.get("big"), str)

    def test_cms_with_many_common_names_is_linear(self) -> None:
        # Bug: every CN/O occurrence in the CMS blob was collected and then
        # de-duplicated pairwise (quadratic in the number of names).
        cn = b"\x06\x03\x55\x04\x03\x0c\x04ABCD"
        cms = b"\x30\x80" + cn * 200000
        wrapper = struct.pack(">II", 0xFADE0B01, 8 + len(cms)) + cms
        doc = self.parse_ok(macho_with_signature(superblob([(0x10000, wrapper)])))
        certs = doc["slices"][0]["code_signature_detail"]["cms_signature"]["certificates"]
        self.assertLessEqual(len(certs), ANALYSIS_LIMITS["cert_names"])


class TestElfCaps(_PublicMode):
    def test_unterminated_string_table_is_not_quadratic(self) -> None:
        # Bug: each symbol name lookup searched to the end of an unterminated
        # string table (O(symbols x table size)).
        nsyms = 20000
        strtab = b"A" * (4 * MB)
        syms = b"\x00" * 24 + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0x1000, 0) * (nsyms - 1)
        blobs = strtab + syms
        st_off = 64
        sy_off = 64 + len(strtab)
        secs = [(".dynstr", 3, 2, 0, st_off, len(strtab), 0, 0, 0),
                (".dynsym", 11, 2, 0, sy_off, len(syms), 1, 1, 24)]
        doc = self.parse_ok(elf64(secs, blobs), max_seconds=2.0)
        self.assertGreater(len(doc["slices"][0]["symbols"]), 1000)

    def test_many_symbol_tables_are_capped_in_total(self) -> None:
        # Bug: 2500 symbols *per* symbol table section with up to 512 sections,
        # and each section copied its linked string table again.
        syms = b"\x00" * 24 + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0x1000, 0) * 2499
        strtab = b"\x00name\x00"
        blobs = strtab + syms
        secs = [(".strtab", 3, 0, 0, 64, len(strtab), 0, 0, 0)]
        secs += [(".symtab", 2, 0, 0, 64 + len(strtab), len(syms), 1, 0, 24)] * 400
        doc = self.parse_ok(elf64(secs, blobs), max_seconds=2.0)
        self.assertLessEqual(len(doc["slices"][0]["symbols"]), ANALYSIS_LIMITS["symbols"])
        self.assertIn("symbols_truncated", warning_codes(doc))

    def test_note_flood_and_huge_property_note_are_bounded(self) -> None:
        # Bug: notes were unbounded in count, and a GNU property note walked its
        # whole (file-sized) descriptor 8 bytes at a time.
        big_desc = b"\x00" * (8 * MB)
        prop_note = struct.pack("<III", 4, len(big_desc), 5) + b"GNU\x00" + big_desc
        flood = struct.pack("<III", 0, 0, 1) * 100000
        blobs = prop_note + flood
        secs = [(".note.gnu.property", 7, 2, 0, 64, len(prop_note), 0, 0, 0),
                (".note.flood", 7, 2, 0, 64 + len(prop_note), len(flood), 0, 0, 0)]
        doc = self.parse_ok(elf64(secs, blobs), max_seconds=2.0)
        self.assertLessEqual(len(doc["slices"][0]["elf_metadata"]["notes"]), ANALYSIS_LIMITS["elf_notes"])


class TestPeCaps(_PublicMode):
    def test_base_relocation_padding_scan_is_bounded(self) -> None:
        # Bug: a relocation block of padding (type 0) entries was scanned entry by
        # entry over its whole size (millions of iterations).
        block = struct.pack("<II", 0x1000, 8 + 16 * MB) + b"\x00" * (16 * MB)
        secs = [(b".reloc", len(block), 0x1000, len(block), 0x400, 0x42000040)]
        data = pe32plus(secs, [(0, 0)] * 5 + [(0x1000, len(block))], block)
        doc = self.parse_ok(data, max_seconds=2.0)
        self.assertEqual(doc["file_info"]["format"], "PE")

    def test_rich_header_scan_window_is_bounded(self) -> None:
        # Bug: the DanS backwards scan walked the whole (attacker-sized) DOS stub.
        stub = b"\x00" * (8 * MB) + b"Rich" + b"\x11\x22\x33\x44"
        data = pe32plus([], [], b"", stub=stub, raw_base=0x40 + len(stub) + 0x400)
        doc = self.parse_ok(data, max_seconds=2.0)
        self.assertFalse(doc["slices"][0]["pe_metadata"]["rich_header"]["present"])


class TestRuntimeIntegration(unittest.TestCase):
    def test_parse_deadline_aborts_cleanly(self) -> None:
        corpus = fuzz_harness.load_corpus(include_host=False)
        data = corpus[0].data  # synthetic universal
        with runtime.parse_deadline(1e-9):
            with self.assertRaises(runtime.ParseBudgetExceeded):
                # Enough loop iterations to cross the 256-tick check interval.
                for _ in range(20):
                    parse_macho_bytes(data)

    def test_no_subprocess_when_external_tools_are_disabled(self) -> None:
        import subprocess

        from backend import disasm, parser
        from backend.fixtures import ensure_fixtures

        fixtures = ensure_fixtures(ROOT)
        prev = runtime.get_config()
        runtime.set_config(runtime.RuntimeConfig("public"))
        real_run = subprocess.run

        def forbidden(*a, **k):  # pragma: no cover - only reached on regression
            raise AssertionError(f"subprocess.run called in public mode: {a!r}")

        subprocess.run = forbidden  # type: ignore[assignment]
        try:
            with open(fixtures["synthetic_universal"], "rb") as fh:
                doc = parser.parse_macho_bytes(fh.read())
            x86 = [s for s in doc["slices"] if s["arch_name"].startswith("x86")][0]
            with open(fixtures["synthetic_universal"], "rb") as fh:
                data = fh.read()
            raw = data[x86["slice_base_offset"]: x86["slice_base_offset"] + x86["slice_size"]]
            out = disasm.disassemble_window(x86, raw, x86["slice_base_offset"], 0, 16,
                                            file_path=fixtures["synthetic_universal"])
            self.assertEqual(out["decoder"], "builtin")
        finally:
            subprocess.run = real_run  # type: ignore[assignment]
            runtime.set_config(prev)

    def test_demangler_skips_names_that_would_desync_cxxfilt(self) -> None:
        from backend.parser import _batch_demangle

        names = ["__ZN3foo3barEv", "__ZN3bad\nname", "__ZN3baz3quxEv"]
        out = _batch_demangle(names)
        self.assertEqual(set(out), set(names))
        self.assertIn("foo::bar", out["__ZN3foo3barEv"])
        self.assertIn("baz::qux", out["__ZN3baz3quxEv"])


if __name__ == "__main__":
    unittest.main()
