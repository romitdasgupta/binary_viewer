"""
Tests for the learning content (backend/learn/, backend/learn_content.py, backend/pedagogy.py).

Three kinds of check:
  * integrity of the static content: ids, cross-references, shape, tone;
  * resolution against the sample fixtures: every "see it in this file" action and every tour step;
  * correctness of every tour task: the expected answer computed by the engine is compared with a
    value derived here *independently*, by reading the fixture's raw bytes with `struct`.
"""

import io
import json
import os
import re
import struct
import sys
import unittest

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from backend import learn_content as L
from backend import pedagogy
from backend.api import ApiRequest, EventLog, build_router
from backend.fixtures import ensure_fixtures
from backend.learn import fields as fields_mod
from backend.learn import instructions as insn_mod
from backend.learn import resolve as resolve_mod
from backend.learn import tours as tours_mod
from backend.runtime import RuntimeConfig
from backend.service import AnalysisService

FORMATS = ("macho", "elf", "pe")
PRIMARY = {"macho": "synthetic_universal", "elf": "synthetic_elf64", "pe": "synthetic_pe64"}
FIXTURE_FORMAT = {
    "synthetic_universal": "macho", "synthetic_firmware": "macho",
    "synthetic_elf64": "elf", "synthetic_elf32": "elf",
    "synthetic_pe64": "pe", "synthetic_pe32": "pe",
}


def strings_in(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            for item in strings_in(value):
                yield item
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            for item in strings_in(value):
                yield item


def cstr(data, off):
    end = data.index(b"\0", off)
    return data[off:end].decode("latin-1")


# =============================================================================
# Independent readers of the raw fixture bytes (no code shared with the parsers)
# =============================================================================
class RawMachO:
    DYLIB_CMDS = (0xC, 0x80000018, 0x8000001F, 0x80000023, 0x20)

    def __init__(self, data, base):
        self.data, self.base = data, base
        (self.magic, self.cputype, self.cpusubtype, self.filetype, self.ncmds, self.sizeofcmds,
         self.flags) = struct.unpack_from("<IiiIIII", data, base)
        assert self.magic == 0xFEEDFACF, hex(self.magic)
        self.cmds = []
        off = base + 32
        for _ in range(self.ncmds):
            cmd, size = struct.unpack_from("<II", data, off)
            self.cmds.append((cmd, off, size))
            off += size
        self.segments = []
        self.sections = []
        for cmd, off, _size in self.cmds:
            if cmd != 0x19:
                continue
            name = data[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            maxprot, initprot, nsects, flags = struct.unpack_from("<iiII", data, off + 56)
            self.segments.append({"name": name, "vmaddr": vmaddr, "vmsize": vmsize, "fileoff": base + fileoff, "filesize": filesize,
                                  "r": bool(initprot & 1), "w": bool(initprot & 2), "x": bool(initprot & 4),
                                  "perm_raw": initprot, "write_bit": 2, "flags": flags})
            for i in range(nsects):
                s = off + 72 + i * 80
                addr, size = struct.unpack_from("<QQ", data, s + 32)
                foff, = struct.unpack_from("<I", data, s + 48)
                sflags, = struct.unpack_from("<I", data, s + 64)
                self.sections.append({"name": data[s:s + 16].rstrip(b"\0").decode(), "addr": addr, "size": size,
                                      "off": base + foff, "type": sflags & 0xFF})

    def cmd(self, *wanted):
        return [(c, off, size) for c, off, size in self.cmds if c in wanted]

    def entry_field(self):
        main = self.cmd(0x80000028)
        if main:
            return main[0][1] + 8, 8
        thread = self.cmd(0x5)[0]
        flavor, = struct.unpack_from("<I", self.data, thread[1] + 8)
        assert flavor == 6, "only ARM_THREAD_STATE64 is exercised by the fixtures"
        return thread[1] + 16 + 8 * 32, 8

    def entry_kind(self):
        return 0 if self.cmd(0x80000028) else 1

    def entry_vm(self):
        off, _ = self.entry_field()
        value, = struct.unpack_from("<Q", self.data, off)
        if self.entry_kind() == 1:
            return value
        text = next(s for s in self.segments if s["name"] == "__TEXT")
        return text["vmaddr"] + value

    def is_dynamic(self):
        return bool(self.cmd(0xE))

    def libraries(self):
        return [cstr(self.data, off + struct.unpack_from("<I", self.data, off + 8)[0]) for _c, off, _s in self.cmd(*self.DYLIB_CMDS)]

    def pie(self):
        return bool(self.flags & 0x200000) if self.filetype == 2 else None

    def arch(self):
        return {0x0100000C: "arm64", 0x01000007: "x86_64"}[self.cputype & 0xFFFFFFFF]

    def nsyms(self):
        return struct.unpack_from("<I", self.data, self.cmd(0x2)[0][1] + 12)[0]

    def signature_offset(self):
        return self.base + struct.unpack_from("<I", self.data, self.cmd(0x1D)[0][1] + 8)[0]

    def chained_imports(self):
        """{symbol: library} from LC_DYLD_CHAINED_FIXUPS (imports format 1)."""
        blob = self.base + struct.unpack_from("<I", self.data, self.cmd(0x80000034)[0][1] + 8)[0]
        _ver, _starts, imports_off, symbols_off, count, fmt, _symfmt = struct.unpack_from("<IIIIIII", self.data, blob)
        assert fmt == 1
        libs = self.libraries()
        out = {}
        for i in range(count):
            word, = struct.unpack_from("<I", self.data, blob + imports_off + 4 * i)
            ordinal, name_off = word & 0xFF, word >> 9
            # 0xfd..0xff are the special ordinals (weak lookup, flat lookup, main executable).
            out[cstr(self.data, blob + symbols_off + name_off)] = libs[ordinal - 1] if 1 <= ordinal <= len(libs) else None
        return out


class RawElf:
    def __init__(self, data):
        self.data = data
        assert data[:4] == b"\x7fELF"
        self.is64 = data[4] == 2
        self.e_type, self.e_machine = struct.unpack_from("<HH", data, 16)
        if self.is64:
            self.e_entry, self.e_phoff, self.e_shoff = struct.unpack_from("<QQQ", data, 24)
            self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack_from("<HHHHH", data, 54)
        else:
            self.e_entry, self.e_phoff, self.e_shoff = struct.unpack_from("<III", data, 24)
            self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack_from("<HHHHH", data, 42)
        self.phdrs = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.is64:
                p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz, _al = struct.unpack_from("<IIQQQQQQ", data, off)
                flags_off = off + 4
            else:
                p_type, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_flags, _al = struct.unpack_from("<IIIIIIII", data, off)
                flags_off = off + 24
            self.phdrs.append({"type": p_type, "flags": p_flags, "offset": p_offset, "vaddr": p_vaddr, "filesz": p_filesz,
                               "memsz": p_memsz, "hdr": off, "flags_off": flags_off})
        self.segments = [{"name": "", "vmaddr": p["vaddr"], "vmsize": p["memsz"], "fileoff": p["offset"], "filesize": p["filesz"],
                          "r": bool(p["flags"] & 4), "w": bool(p["flags"] & 2), "x": bool(p["flags"] & 1),
                          "perm_raw": p["flags"], "write_bit": 2} for p in self.phdrs if p["type"] == 1]
        self.sections = []
        if self.e_shoff and self.e_shnum:
            raw = []
            for i in range(self.e_shnum):
                off = self.e_shoff + i * self.e_shentsize
                if self.is64:
                    name, _t, _f, addr, foff, size = struct.unpack_from("<IIQQQQ", data, off)
                else:
                    name, _t, _f, addr, foff, size = struct.unpack_from("<IIIIII", data, off)
                raw.append((name, addr, foff, size))
            strtab = raw[self.e_shstrndx][2]
            self.sections = [{"name": cstr(data, strtab + n), "addr": a, "off": o, "size": s} for n, a, o, s in raw]

    def is_dynamic(self):
        return any(p["type"] == 3 for p in self.phdrs)

    def needed_count(self):
        dyn = [p for p in self.phdrs if p["type"] == 2]
        if not dyn:
            return 0
        off, count = dyn[0]["offset"], 0
        step = 16 if self.is64 else 8
        while True:
            tag, = struct.unpack_from("<q" if self.is64 else "<i", self.data, off)
            if tag == 0:
                return count
            count += tag == 1
            off += step

    def pie(self):
        return self.e_type == 3

    def arch(self):
        return {62: "x86_64", 3: "i386", 183: "arm64"}[self.e_machine]

    def entry_vm(self):
        return self.e_entry

    def entry_field(self):
        return 24, 8 if self.is64 else 4


class RawPe:
    def __init__(self, data):
        self.data = data
        assert data[:2] == b"MZ"
        self.lfanew, = struct.unpack_from("<I", data, 0x3C)
        assert data[self.lfanew:self.lfanew + 4] == b"PE\0\0"
        fh = self.lfanew + 4
        self.machine, self.nsections = struct.unpack_from("<HH", data, fh)
        self.opt_size, self.characteristics = struct.unpack_from("<HH", data, fh + 16)
        self.opt = fh + 20
        self.magic, = struct.unpack_from("<H", data, self.opt)
        self.plus = self.magic == 0x20B
        self.entry_rva, = struct.unpack_from("<I", data, self.opt + 16)
        self.image_base, = struct.unpack_from("<Q" if self.plus else "<I", data, self.opt + (24 if self.plus else 28))
        self.size_of_headers, = struct.unpack_from("<I", data, self.opt + 60)
        self.dll_characteristics, = struct.unpack_from("<H", data, self.opt + 70)
        dirs = self.opt + (112 if self.plus else 96)
        self.dirs = [struct.unpack_from("<II", data, dirs + 8 * i) for i in range(16)]
        self.raw_sections = []
        table = self.opt + self.opt_size
        for i in range(self.nsections):
            off = table + 40 * i
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
            chars, = struct.unpack_from("<I", data, off + 36)
            self.raw_sections.append({"name": data[off:off + 8].rstrip(b"\0").decode(), "va": va, "vsize": vsize, "rsize": rsize,
                                      "rptr": rptr, "chars": chars, "hdr": off})
        self.segments = [{"name": "HEADERS", "vmaddr": self.image_base, "vmsize": self.size_of_headers, "fileoff": 0,
                          "filesize": self.size_of_headers, "r": True, "w": False, "x": False, "perm_raw": 0, "write_bit": 0}]
        for s in self.raw_sections:
            self.segments.append({"name": s["name"], "vmaddr": self.image_base + s["va"], "vmsize": max(s["vsize"], s["rsize"]),
                                  "fileoff": s["rptr"], "filesize": s["rsize"], "r": bool(s["chars"] & 0x40000000),
                                  "w": bool(s["chars"] & 0x80000000), "x": bool(s["chars"] & 0x20000000),
                                  "perm_raw": s["chars"], "write_bit": 0x80000000})

    def rva_to_off(self, rva):
        for s in self.raw_sections:
            if s["va"] <= rva < s["va"] + s["rsize"]:
                return s["rptr"] + (rva - s["va"])
        return None

    def imports(self):
        """[(dll, [function names])] by walking the import directory."""
        rva, _size = self.dirs[1]
        if not rva:
            return []
        out, off = [], self.rva_to_off(rva)
        width = 8 if self.plus else 4
        while True:
            oft, _ts, _fc, name, first = struct.unpack_from("<IIIII", self.data, off)
            if not (oft or name or first):
                return out
            names, thunk = [], self.rva_to_off(oft or first)
            while True:
                entry, = struct.unpack_from("<Q" if self.plus else "<I", self.data, thunk)
                if entry == 0:
                    break
                if not entry >> (width * 8 - 1):
                    names.append(cstr(self.data, self.rva_to_off(entry) + 2))
                thunk += width
            out.append((cstr(self.data, self.rva_to_off(name)), names))
            off += 20

    def pie(self):
        # DYNAMIC_BASE opts in; an image whose relocations were stripped cannot be moved anyway.
        return bool(self.dll_characteristics & 0x40) and not (self.characteristics & 0x0001)

    def arch(self):
        return {0x8664: "x86_64", 0x14C: "i386", 0xAA64: "arm64"}[self.machine]

    def entry_vm(self):
        return self.image_base + self.entry_rva

    def entry_field(self):
        return self.opt + 16, 4

    def is_dynamic(self):
        return bool(self.dirs[1][0])


def raw_vm_to_off(raw, vm):
    for seg in raw.segments:
        if seg["vmaddr"] <= vm < seg["vmaddr"] + seg["filesize"]:
            return seg["fileoff"] + (vm - seg["vmaddr"])
    return None


class FixtureCase(unittest.TestCase):
    """Loads every synthetic fixture once: parsed document, raw bytes, independent raw reader."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures = ensure_fixtures(WORKSPACE_ROOT)
        cls.service = AnalysisService(WORKSPACE_ROOT)
        cls.cases = []  # (name, doc, slice index, slice, data, raw)
        for name in sorted(cls.fixtures):
            with open(cls.fixtures[name], "rb") as handle:
                data = handle.read()
            doc = cls.service.get_entry(doc="preset:" + name).doc
            for index, slice_doc in enumerate(doc["slices"]):
                fmt = FIXTURE_FORMAT[name]
                if fmt == "macho":
                    raw = RawMachO(data, slice_doc["slice_base_offset"])
                elif fmt == "elf":
                    raw = RawElf(data)
                else:
                    raw = RawPe(data)
                cls.cases.append((name, doc, index, slice_doc, data, raw))

    def valid_nodes(self, doc, slice_doc):
        nodes = set(resolve_mod._ALWAYS_NODES)
        if doc["file_info"].get("fat_header"):
            nodes.add("fat_header")
        nodes.update("lc_%d" % lc["index"] for lc in slice_doc["load_commands"])
        for si, seg in enumerate(slice_doc["segments"]):
            nodes.add("seg_%d" % si)
            nodes.update("sect_%d_%d" % (si, ci) for ci in range(len(seg.get("sections", []))))
        return nodes

    def assert_target(self, hit, doc, slice_doc, where):
        self.assertIn(hit["node_id"], self.valid_nodes(doc, slice_doc), where)
        if hit.get("abs_offset") is not None:
            size = doc["file_info"]["file_size"]
            self.assertGreaterEqual(hit["abs_offset"], 0, where)
            self.assertGreater(hit["size"], 0, where)
            self.assertLessEqual(hit["abs_offset"] + 1, size, where)


# =============================================================================
# Static content
# =============================================================================
class TestContentIntegrity(unittest.TestCase):
    def test_validate_reports_nothing(self):
        self.assertEqual(L.validate(), [])

    def test_ids_are_unique_slugs(self):
        slug = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
        for name, items in (("concept", L.concepts()), ("term", L.glossary()), ("tour", tours_mod.TOURS), ("row", L.compare())):
            ids = [i["id"] for i in items]
            self.assertEqual(len(ids), len(set(ids)), name)
            for item_id in ids:
                self.assertRegex(item_id, slug, name)
        actions = [a["id"] for c in L.concepts() for a in c["see"]]
        self.assertEqual(len(actions), len(set(actions)))

    def test_no_dangling_links_anywhere(self):
        terms = {t["id"] for t in L.glossary()}
        concepts = {c["id"] for c in L.concepts()}
        everything = [L.concepts(), L.glossary(), L.compare(), tours_mod.TOURS, L.instructions()]
        targets = L.links_in(everything)
        self.assertGreater(len(targets), 150)
        for target in targets:
            if target.startswith("concept:"):
                self.assertIn(target[8:], concepts)
            else:
                self.assertIn(target, terms)
        for term in L.glossary():
            self.assertTrue(set(term["see"]) <= terms, term["id"])
            self.assertIn(term["concept"], concepts, term["id"])
        for concept in L.concepts():
            self.assertTrue(set(concept["next"]) <= concepts, concept["id"])

    def test_curriculum_covers_the_required_topics(self):
        have = [c["id"] for c in L.concepts()]
        required = [
            "bytes-and-hex", "endianness", "structs-on-disk", "compile-pipeline", "object-files", "sections-vs-segments",
            "symbols", "name-mangling", "relocations", "static-linking", "static-vs-dynamic", "got-plt", "lazy-binding",
            "pe-imports", "dyld-fixups", "process-startup-linux", "process-startup-macos", "process-startup-windows",
            "virtual-memory", "addresses", "pic-pie", "aslr", "stack-and-frames", "calling-conventions", "syscalls",
            "mitigations-overview", "nx-wx", "stack-canaries", "relro", "cfi", "code-signing", "authenticode",
            "entropy-packing", "debug-info", "stripping",
        ]
        for concept_id in required:
            self.assertIn(concept_id, have)
        # It is a sequence: every concept is reachable from the first by following `next`.
        by_id = {c["id"]: c for c in L.concepts()}
        seen, queue = set(), [have[0]]
        while queue:
            current = queue.pop()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(by_id[current]["next"])
        self.assertEqual(seen, set(have))
        self.assertEqual([c["order"] for c in L.concepts()], list(range(1, len(have) + 1)))
        modules = [m["id"] for m in L.index()["modules"]]
        self.assertEqual(sorted(set(c["module"] for c in L.concepts())), sorted(modules))

    def test_every_concept_is_complete(self):
        for concept in L.concepts():
            where = concept["id"]
            self.assertTrue(concept["title"] and concept["summary"], where)
            self.assertGreaterEqual(len(concept["body"]), 2, where)
            for fmt in FORMATS:
                self.assertTrue(concept["formats"][fmt], "%s has nothing for %s" % (where, fmt))
            self.assertTrue(concept["see"], where)
            self.assertTrue(concept["misconceptions"], where)
            self.assertTrue(concept["next"], where)
            for action in concept["see"]:
                self.assertTrue(set(action.get("formats", FORMATS)) <= set(FORMATS), where)

    def test_counts(self):
        counts = L.counts()
        self.assertGreaterEqual(counts["concepts"], 40)
        self.assertGreaterEqual(counts["terms"], 200)
        self.assertGreaterEqual(counts["tours"], 12)
        self.assertGreaterEqual(counts["tasks"], 30)
        self.assertGreaterEqual(counts["fields"]["macho"], 100)
        self.assertGreaterEqual(counts["fields"]["elf"], 38)
        self.assertGreaterEqual(counts["fields"]["pe"], 80)

    def test_tone(self):
        banned = re.compile(r"\b(simply|obviously|of course|amazing|awesome)\b", re.I)
        content = [L.concepts(), L.glossary(), L.fields(), L.compare(), tours_mod.TOURS,
                   insn_mod.MNEMONICS, [[i["title"], i["text"]] for i in insn_mod.IDIOMS]]
        for text in strings_in(content):
            prose = re.sub(r"`[^`]*`", "", text)
            self.assertNotIn("!", prose, text[:80])
            self.assertIsNone(banned.search(prose), text[:80])
            self.assertFalse(any(ord(ch) > 0x2000 for ch in prose), text[:80])

    def test_plain_text_fields_carry_no_markup(self):
        for term in L.glossary():
            self.assertNotRegex(term["short"], r"`|\[\[", term["id"])
        for key, entry in fields_mod.CATALOG.items():
            for part in ("meaning", "reader", "if_wrong", "peers"):
                self.assertNotRegex(entry[part], r"`|\[\[", key)

    def test_plain_removes_markup(self):
        self.assertEqual(L.plain("The [[got|GOT]] and `call` are *not* code."), "The GOT and call are not code.")
        self.assertEqual(L.plain("[[rva]]"), "RVA")
        self.assertEqual(L.plain("[[concept:aslr]]"), "Address space layout randomisation")

    def test_content_is_json(self):
        for payload in (L.index(), L.concepts(), L.glossary(), L.fields(), L.instructions(), L.compare(), L.tours()):
            self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_glossary_covers_the_labels_of_the_tool(self):
        haystack = set()
        for term in L.glossary():
            for text in [term["term"]] + term["aka"] + term["match"]:
                haystack.add(text.lower())
        labels = [
            "load command", "program header", "data directory", "segment", "section", "disassembly", "fixup", "export",
            "import", "relocation", "symbol", "indirect symbols", "PLT", "GOT", "IAT", "entry point", "function starts",
            "Objective-C", "filesets", "code signature", "Authenticode", "Notes", "Build ID", "Hardening", "entropy",
            "capabilities", "Memory map", "file offset", "slice offset", "VM address", "RVA", "ULEB128", "SLEB128", "UNDF",
            "slice", "Universal", "Fat header", "thunk", "string table", "Demangle", "weak", "ordinal", "rebase", "bind",
            "little-endian", "big-endian", "PIE", "ASLR", "RELRO", "NX", "W^X", "PAC", "CET", "CFG", "BTI", "cdhash",
            "entitlements", "UUID", "DWARF", "PDB", "TLS", "DllCharacteristics", "ImageBase", "__PAGEZERO", "__LINKEDIT",
        ]
        for label in labels:
            self.assertIn(label.lower(), haystack, label)

    def test_glossary_match_strings_are_unambiguous(self):
        seen = {}
        for term in L.glossary():
            for text in term["match"]:
                self.assertNotIn(text, seen, "%s is claimed by %s and %s" % (text, seen.get(text), term["id"]))
                seen[text] = term["id"]
                self.assertGreaterEqual(len(text), 2)


# =============================================================================
# Field explanations
# =============================================================================
class TestFieldExplanations(FixtureCase):
    def field_lists(self, doc, slice_doc):
        yield "header", slice_doc["header"]["fields"]
        if doc["file_info"].get("fat_header"):
            yield "fat header", doc["file_info"]["fat_header"]["fields"]
        for lc in slice_doc["load_commands"]:
            yield "command " + lc["cmd_name"], lc["fields"]
        for seg in slice_doc["segments"]:
            yield "segment " + seg["segname"], seg["fields"]
            for sect in seg.get("sections", []):
                yield "section " + sect["sectname"], sect["fields"]

    def test_every_field_of_every_fixture_is_explained(self):
        total = 0
        for name, doc, index, slice_doc, _data, _raw in self.cases:
            for where, fields in self.field_lists(doc, slice_doc):
                for field in fields:
                    total += 1
                    ped = field.get("pedagogy")
                    self.assertIsNotNone(ped, "%s[%d] %s: field %s has no explanation" % (name, index, where, field["name"]))
                    for key in ("why_it_matters", "loader_behavior", "what_if_modified", "cross_format_peer", "key", "concept"):
                        self.assertTrue(ped.get(key), "%s %s.%s" % (name, where, key))
                    self.assertIn(ped["key"], fields_mod.CATALOG)
                    self.assertTrue(ped["key"].startswith(FIXTURE_FORMAT[name] + "."), ped["key"])
        self.assertGreater(total, 1000)

    def test_explanations_depend_on_the_structure_not_only_the_name(self):
        cases = {(name, index): (doc, slice_doc) for name, doc, index, slice_doc, _d, _r in self.cases}
        _doc, macho = cases[("synthetic_universal", 0)]
        header_flags = resolve_mod.find_field(macho["header"]["fields"], "flags")["pedagogy"]
        text_seg = next(s for s in macho["segments"] if s["segname"] == "__TEXT")
        seg_flags = resolve_mod.find_field(text_seg["fields"], "flags")["pedagogy"]
        sect_flags = resolve_mod.find_field(text_seg["sections"][0]["fields"], "flags")["pedagogy"]
        self.assertEqual(header_flags["key"], "macho.mach_header.flags")
        self.assertEqual(seg_flags["key"], "macho.segment_command.flags")
        self.assertEqual(sect_flags["key"], "macho.section.flags")
        self.assertEqual(len({header_flags["why_it_matters"], seg_flags["why_it_matters"], sect_flags["why_it_matters"]}), 3)
        sig = next(lc for lc in macho["load_commands"] if lc["cmd_name"] == "LC_CODE_SIGNATURE")
        self.assertIn("signature", resolve_mod.find_field(sig["fields"], "dataoff")["pedagogy"]["why_it_matters"])
        _doc, pe = cases[("synthetic_pe64", 0)]
        cert = next(lc for lc in pe["load_commands"] if lc["cmd_name"] == "DATA_DIR_CERTIFICATE_TABLE")
        self.assertIn("File offset", resolve_mod.find_field(cert["fields"], "VirtualAddress")["pedagogy"]["why_it_matters"])
        imports = next(lc for lc in pe["load_commands"] if lc["cmd_name"] == "DATA_DIR_IMPORT_TABLE")
        self.assertIn("RVA", resolve_mod.find_field(imports["fields"], "VirtualAddress")["pedagogy"]["why_it_matters"])

    def test_catalog_entries_are_complete_and_grouped(self):
        structs = {s["id"] for s in fields_mod.STRUCTS}
        for key, entry in fields_mod.CATALOG.items():
            self.assertIn("%s.%s" % (entry["format"], entry["struct"]), structs, key)
            for part in ("meaning", "reader", "if_wrong", "peers"):
                self.assertGreater(len(entry[part]), 4, key)
        listed = sum(len(s["fields"]) for s in fields_mod.reference())
        self.assertEqual(listed, len(fields_mod.CATALOG))

    def test_main_structures_are_fully_covered(self):
        expect = {
            "macho.mach_header": ["magic", "cputype", "cpusubtype", "filetype", "ncmds", "sizeofcmds", "flags", "reserved"],
            "macho.segment_command": ["segname", "vmaddr", "vmsize", "fileoff", "filesize", "maxprot", "initprot", "nsects", "flags"],
            "macho.section": ["sectname", "segname", "addr", "size", "offset", "align", "reloff", "nreloc", "flags", "reserved1", "reserved2", "reserved3"],
            "elf.ehdr": ["e_ident[EI_MAG]", "e_ident[EI_CLASS]", "e_ident[EI_DATA]", "e_ident[EI_VERSION]", "e_ident[EI_OSABI]",
                         "e_ident[EI_ABIVERSION]", "e_type", "e_machine", "e_version", "e_entry", "e_phoff", "e_shoff", "e_flags",
                         "e_ehsize", "e_phentsize", "e_phnum", "e_shentsize", "e_shnum", "e_shstrndx"],
            "elf.phdr": ["p_type", "p_flags", "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_align"],
            "elf.shdr": ["sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size", "sh_link", "sh_info", "sh_addralign", "sh_entsize"],
            "pe.file_header": ["Machine", "NumberOfSections", "TimeDateStamp", "PointerToSymbolTable", "NumberOfSymbols",
                               "SizeOfOptionalHeader", "Characteristics"],
            "pe.optional_header": ["Magic", "AddressOfEntryPoint", "ImageBase", "SectionAlignment", "FileAlignment", "SizeOfImage",
                                   "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics", "SizeOfStackReserve",
                                   "NumberOfRvaAndSizes"],
            "pe.section_header": ["Name", "VirtualSize", "VirtualAddress", "SizeOfRawData", "PointerToRawData", "Characteristics"],
        }
        for struct_id, names in expect.items():
            for name in names:
                self.assertIn("%s.%s" % (struct_id, name), fields_mod.CATALOG)

    def test_annotation_budget_bounds_a_huge_slice(self):
        section = {"sectname": "__s", "fields": [{"name": n} for n in ("sectname", "addr", "size", "offset", "flags")]}
        slice_doc = {"format": "MACHO", "header": {"fields": []}, "load_commands": [],
                     "segments": [{"segname": "__X", "fields": [], "sections": [dict(section, fields=[dict(f) for f in section["fields"]]) for _ in range(1000)]}]}
        self.assertEqual(pedagogy.annotate_slice_pedagogy(slice_doc), pedagogy.FIELD_ANNOTATION_BUDGET)

    def test_decode_endpoint_explains_the_field_under_the_cursor(self):
        for name, _doc, index, slice_doc, _data, _raw in self.cases:
            sect = next((s for seg in slice_doc["segments"] for s in seg.get("sections", [])), None)
            if sect is None:
                continue
            field = sect["fields"][-1]
            result = self.service.decode_bytes_at(offset=field["abs_offset"], slice_index=index, doc="preset:" + name)
            self.assertIsNotNone(result.get("field_pedagogy"), name)
            self.assertEqual(result["field_pedagogy"]["field_name"], field["name"])


# =============================================================================
# "See it in this file"
# =============================================================================
class TestSeeActions(FixtureCase):
    def scopes(self):
        return ["concept:" + c["id"] for c in L.concepts()] + ["compare"]

    def test_every_action_resolves_or_explains_on_every_fixture(self):
        for name, doc, index, slice_doc, _data, _raw in self.cases:
            for scope in self.scopes():
                for action in L.resolve_scope(scope, doc, slice_doc):
                    where = "%s[%d] %s" % (name, index, action["id"])
                    if action["available"]:
                        self.assert_target(action, doc, slice_doc, where)
                    else:
                        self.assertTrue(action["reason"], where)

    def test_required_actions_resolve_on_the_primary_sample_of_each_format(self):
        checked = 0
        for name, doc, index, slice_doc, _data, _raw in self.cases:
            fmt = FIXTURE_FORMAT[name]
            if PRIMARY[fmt] != name:
                continue
            for scope in self.scopes():
                for action in L.resolve_scope(scope, doc, slice_doc):
                    if fmt not in action["formats"] or action["optional"]:
                        continue
                    checked += 1
                    self.assertTrue(action["available"], "%s[%d] %s: %s" % (name, index, action["id"], action.get("reason")))
        self.assertGreater(checked, 300)

    def test_every_action_resolves_on_some_fixture_of_each_of_its_formats_or_is_optional(self):
        available = {}
        declared = {}
        for name, doc, _index, slice_doc, _data, _raw in self.cases:
            fmt = FIXTURE_FORMAT[name]
            for scope in self.scopes():
                for action in L.resolve_scope(scope, doc, slice_doc):
                    declared[action["id"]] = action
                    if action["available"]:
                        available.setdefault(action["id"], set()).add(fmt)
        for action_id, action in declared.items():
            self.assertTrue(available.get(action_id), "%s resolves on no fixture at all" % action_id)
            if not action["optional"]:
                self.assertEqual(available[action_id], set(action["formats"]), action_id)

    def test_actions_outside_their_format_say_so(self):
        _name, doc, _i, slice_doc, _d, _r = next(c for c in self.cases if c[0] == "synthetic_elf64")
        actions = L.resolve_scope("concept:pe-imports", doc, slice_doc)
        pe_only = [a for a in actions if a["formats"] == ["pe"]]
        self.assertTrue(pe_only)
        for action in pe_only:
            self.assertFalse(action["available"])
            self.assertIn("PE", action["reason"])

    def test_a_malformed_document_never_raises(self):
        broken = {"format": "ELF", "header": {"fields": "nope"}, "segments": [{"segname": 5, "fields": None}],
                  "load_commands": [{"cmd_name": "PT_LOAD"}], "entry_point": {"vmaddr": "zz", "abs_offset": "x"},
                  "symbols": [None], "strings": [{}], "dysymtab": {"indirect_symbols": [{}]}}
        doc = {"file_info": {"file_size": "many"}, "slices": [broken]}
        for scope in self.scopes():
            for action in L.resolve_scope(scope, doc, broken):
                self.assertIn("available", action)
        for tour in tours_mod.TOURS:
            L.build_tour(tour["id"], doc, broken)

    def test_document_strings_are_cleaned_before_substitution(self):
        self.assertEqual(resolve_mod.clean("a`b[[c]]*d{e}|f\x00g"), "abcdef?g")
        self.assertEqual(len(resolve_mod.clean("x" * 500)), 80)
        self.assertEqual(resolve_mod.fill("{known} {unknown}", {"known": "v"}), "v {unknown}")


# =============================================================================
# Tours and their tasks
# =============================================================================
class TestTours(FixtureCase):
    def built(self):
        for name, doc, index, slice_doc, data, raw in self.cases:
            for tour in tours_mod.TOURS:
                yield name, doc, index, slice_doc, data, raw, L.build_tour(tour["id"], doc, slice_doc)

    def test_every_tour_runs_on_its_sample_with_every_step_resolved(self):
        ran = set()
        for name, doc, index, slice_doc, _data, _raw, built in self.built():
            tour = tours_mod.by_id()[built["id"]]
            fmt = FIXTURE_FORMAT[name]
            if tour["samples"].get(fmt) == name:
                self.assertTrue(built["available"], "%s on %s: %s" % (built["id"], name, built.get("reason")))
                self.assertGreaterEqual(len(built["steps"]), 3, "%s on %s" % (built["id"], name))
                ran.add((built["id"], fmt))
            if not built["available"]:
                self.assertTrue(built["reason"], built["id"])
                continue
            for step in built["steps"]:
                where = "%s[%d] %s/%s" % (name, index, built["id"], step["id"])
                self.assertTrue(step["title"] and step["text"], where)
                self.assertNotRegex(step["text"], r"\{[a-z_]+\}", where)
                if step["show"] is not None:
                    self.assertTrue(step["show"]["available"], where)
                    self.assert_target(step["show"], doc, slice_doc, where)
                task = step["task"]
                if task is not None:
                    self.assertIn(task["kind"], ("bytes", "node", "value", "choice"), where)
                    self.assertTrue(task["prompt"], where)
                    self.assertTrue(task["explain"], where)
                    self.assertNotRegex(task["prompt"] + task["explain"], r"\{[a-z_]+\}", where)
        for tour in tours_mod.TOURS:
            for fmt in tour["formats"]:
                self.assertIn((tour["id"], fmt), ran)

    def test_tours_cover_all_three_formats_and_levels(self):
        for fmt in FORMATS:
            self.assertGreaterEqual(sum(1 for t in tours_mod.TOURS if fmt in t["formats"]), 8, fmt)
        self.assertEqual({t["level"] for t in tours_mod.TOURS}, {1, 2, 3})
        self.assertEqual(sorted(t["level"] for t in tours_mod.TOURS), [t["level"] for t in tours_mod.TOURS])

    def test_a_tour_for_another_format_is_declined_with_a_sample(self):
        _name, doc, _i, slice_doc, _d, _r = next(c for c in self.cases if c[0] == "synthetic_elf64")
        built = L.build_tour("pe-headers", doc, slice_doc)
        self.assertFalse(built["available"])
        self.assertIn("PE", built["reason"])
        self.assertEqual(built["sample"], "synthetic_pe64")
        self.assertIsNone(L.build_tour("no-such-tour", doc, slice_doc))
        _name, doc, _i, slice_doc, _d, _r = next(c for c in self.cases if c[0] == "synthetic_firmware")
        self.assertFalse(L.build_tour("universal", doc, slice_doc)["available"])
        self.assertFalse(L.build_tour("follow-an-import", doc, slice_doc)["available"])

    # ---- independent verification of every expected answer --------------------------
    def doc_segment(self, slice_doc, raw_seg, fmt):
        for index, seg in enumerate(slice_doc["segments"]):
            if seg["vmaddr_int"] == raw_seg["vmaddr"]:
                return index
        self.fail("no document segment at %#x" % raw_seg["vmaddr"])

    def assert_pointer_slot(self, fmt, raw, offset):
        """`offset` is the start of an entry of a table of imported pointers, judged from the raw structures."""
        self.assertIsNotNone(offset)
        if fmt == "macho":
            holder = next(s for s in raw.sections if s["off"] <= offset < s["off"] + s["size"])
            self.assertIn(holder["type"], (6, 7), holder["name"])  # non-lazy or lazy symbol pointers
            self.assertEqual((offset - holder["off"]) % 8, 0)
        elif fmt == "elf":
            holder = next(s for s in raw.sections if s["name"] in (".got", ".got.plt") and s["off"] <= offset < s["off"] + s["size"])
            self.assertEqual((offset - holder["off"]) % (8 if raw.is64 else 4), 0)
        else:
            iat_rva, iat_size = raw.dirs[12]
            start = raw.rva_to_off(iat_rva)
            self.assertTrue(start <= offset < start + iat_size)

    def expected(self, key, name, doc, index, slice_doc, data, raw, task):
        """The expected answer for task `key`, derived from the raw bytes. Returns a comparable value."""
        fmt = FIXTURE_FORMAT[name]
        tour_id, task_id = key
        values = task.get("values", {})

        def node_set(predicate):
            return sorted("seg_%d" % self.doc_segment(slice_doc, s, fmt) for s in raw.segments if predicate(s))

        if task_id == "magic":
            base = raw.base if fmt == "macho" else 0
            return [(base, 2 if fmt == "pe" else 4)]
        if task_id in ("le", "le-pe", "lfanew"):
            if fmt == "macho":
                return struct.unpack_from("<I", data, raw.base)[0]
            if fmt == "elf":
                return struct.unpack_from("<H", data, 18)[0]
            return struct.unpack_from("<I", data, 0x3C)[0]
        if key == ("first-contact", "count"):
            return {"macho": lambda: raw.ncmds, "elf": lambda: raw.e_phnum, "pe": lambda: raw.nsections}[fmt]()
        if key == ("universal", "count"):
            return struct.unpack_from(">I", data, 4)[0]
        if key == ("follow-an-import", "count"):
            if fmt == "macho":
                return len(raw.libraries())
            return raw.needed_count() if fmt == "elf" else len(raw.imports())
        if task_id == "segment":
            vm = int(values["address"], 16)
            if values["what"] == "entry":
                self.assertEqual(vm, raw.entry_vm())
                self.assertFalse(raw.is_dynamic(), "a dynamically linked sample should be asked about an import slot")
            else:
                self.assert_pointer_slot(fmt, raw, raw_vm_to_off(raw, vm))
            self.assertIn(values["address"], task["prompt"])
            holders = [s for s in raw.segments if s["vmaddr"] <= vm < s["vmaddr"] + s["vmsize"]]
            self.assertEqual(len(holders), 1)
            return ["seg_%d" % self.doc_segment(slice_doc, holders[0], fmt)]
        if key == ("file-to-memory", "offset"):
            vm = int(values["address"], 16)
            off = raw_vm_to_off(raw, vm)
            self.assertIsNotNone(off)
            self.assertTrue(32 <= data[off] < 127, "the address should be the first character of a string")
            return [(off, 1)]
        if task_id == "zerofill":
            seg = next(s for s in raw.segments if s["r"] and s["filesize"] > 0 and s["vmsize"] > s["filesize"] and s["name"] != "HEADERS")
            self.assertEqual(slice_doc["segments"][self.doc_segment(slice_doc, seg, fmt)]["segname"], values["seg"])
            return seg["vmsize"] - seg["filesize"]
        if task_id == "rva":
            self.assertEqual(int(values["rva"], 16), raw.entry_rva)
            return raw.rva_to_off(raw.entry_rva)
        if task_id == "exec":
            return node_set(lambda s: s["x"])
        if task_id == "rwx":
            return node_set(lambda s: s["x"] and s["w"])
        if task_id == "writable":
            # The code segment: executable and not yet writable. (This used to pick the first
            # read-only segment, which in ELF is the one that maps the file's headers, although
            # the task's explanation is about making CODE writable.)
            seg = next(s for s in raw.segments if s["x"] and not s["w"] and s["filesize"] > 0 and s["name"] != "HEADERS")
            self.assertEqual(int(values["current"], 16), seg["perm_raw"])
            return seg["perm_raw"] | seg["write_bit"]
        if key == ("entry-point", "field"):
            return [raw.entry_field()]
        if task_id == "kind":
            return {"macho": lambda: raw.entry_kind(), "elf": lambda: 1, "pe": lambda: 2}[fmt]()
        if key == ("entry-point", "code"):
            off = raw_vm_to_off(raw, raw.entry_vm())
            return [(off, 4 if raw.arch() == "arm64" else 1)]
        if task_id == "arg":
            arch = raw.arch()
            return {"arm64": 2, "i386": 3}.get(arch, 1 if fmt == "pe" else 0)
        if task_id == "nsyms":
            return raw.nsyms()
        if task_id == "pie":
            return 0 if raw.pie() else 1
        if task_id == "dynamic":
            return 0 if raw.is_dynamic() else 1
        if key == ("universal", "offset"):
            arch_index = slice_doc["fat_arch_index"]
            field = 8 + 20 * arch_index + 8
            self.assertEqual(struct.unpack_from(">I", data, field)[0], slice_doc["slice_base_offset"])
            return [(field, 4)]
        if task_id == "sig":
            return [(raw.lfanew, 4)]
        if task_id == "phoff":
            return raw.e_phoff
        if task_id == "slot":
            rng = task["ranges"][0]
            self.assert_pointer_slot(fmt, raw, rng["abs_offset"])
            return [(rng["abs_offset"], rng["size"])]
        if task_id == "lib":
            symbol = values["symbol"]
            if fmt == "macho":
                return raw.chained_imports()[symbol]
            return next(dll for dll, names in raw.imports() if symbol in names)
        if task_id == "blob":
            return [(raw.signature_offset() if fmt == "macho" else raw.dirs[4][0], None)]
        return NotImplemented

    def test_every_task_answer_matches_the_raw_bytes(self):
        verified = {}
        for name, doc, index, slice_doc, data, raw, built in self.built():
            if not built["available"]:
                continue
            for step in built["steps"]:
                task = step["task"]
                if task is None:
                    continue
                key = (built["id"], task["id"])
                where = "%s[%d] %s/%s" % (name, index, key[0], key[1])
                want = self.expected(key, name, doc, index, slice_doc, data, raw, task)
                self.assertIsNot(want, NotImplemented, "no independent check for task %s/%s" % key)
                if task["kind"] == "bytes":
                    got = [(r["abs_offset"], r["size"]) for r in task["ranges"]]
                    if want[0][1] is None:
                        self.assertEqual([g[0] for g in got], [w[0] for w in want], where)
                    else:
                        self.assertEqual(got, want, where)
                elif task["kind"] == "node":
                    self.assertEqual(sorted(task["node_ids"]), want, where)
                    self.assertTrue(set(task["node_ids"]) <= self.valid_nodes(doc, slice_doc), where)
                    for option in task["options"]:
                        self.assertIn(option["node_id"], self.valid_nodes(doc, slice_doc), where)
                elif task["kind"] == "value":
                    self.assertEqual(task["expect"], want, where)
                    self.assertEqual(int(task["expect_text"], 16), want, where)
                elif task["kind"] == "choice":
                    self.assertTrue(0 <= task["correct"] < len(task["options"]), where)
                    if isinstance(want, str):
                        self.assertEqual(task["options"][task["correct"]], want, where)
                    else:
                        self.assertEqual(task["correct"], want, where)
                verified.setdefault(key, set()).add(FIXTURE_FORMAT[name])
        declared = {(t["id"], s["task"]["id"]) for t in tours_mod.TOURS for s in t["steps"] if s.get("task")}
        self.assertEqual(set(verified), declared, "tasks that never ran on any fixture: %s" % sorted(declared - set(verified)))
        self.assertGreaterEqual(len(verified), 30)

    def test_answers_agree_with_the_analysis_service(self):
        """A second cross-check: address answers agree with /api/translate."""
        for name, _doc, index, slice_doc, _data, _raw, built in self.built():
            if not built["available"]:
                continue
            for step in built["steps"]:
                task = step["task"]
                if task is None or task["kind"] != "bytes" or "address" not in task.get("values", {}):
                    continue
                translated = self.service.translate_address(slice_index=index, query=task["values"]["address"], mode="vmaddr", doc="preset:" + name)
                self.assertEqual(translated["abs_offset"], task["ranges"][0]["abs_offset"], "%s %s" % (name, task["id"]))

    def test_known_answers_on_the_samples(self):
        """Spot checks against values that are fixed by how the fixtures are built."""
        by_name = {(n, i): (d, s) for n, d, i, s, _data, _raw in self.cases}

        def task(fixture, tour_id, task_id, index=0):
            doc, slice_doc = by_name[(fixture, index)]
            built = L.build_tour(tour_id, doc, slice_doc)
            return next(s["task"] for s in built["steps"] if s["task"] and s["task"]["id"] == task_id)

        self.assertEqual(task("synthetic_elf64", "entry-point", "field")["ranges"], [{"abs_offset": 0x18, "size": 8}])
        self.assertEqual(task("synthetic_pe64", "pe-headers", "rva")["expect"], 0x400)
        self.assertEqual(task("synthetic_pe64", "pe-headers", "lfanew")["expect"], 0x100)
        self.assertEqual(task("synthetic_pe64", "permissions", "writable")["expect"], 0xE0000020)
        self.assertEqual(task("synthetic_elf64", "permissions", "writable")["expect"], 7)   # the r-x PT_LOAD: PF_R|PF_X (5) | PF_W (2)
        self.assertEqual(task("synthetic_universal", "permissions", "writable")["expect"], 7)
        self.assertEqual(task("synthetic_universal", "first-contact", "le")["expect"], 0xFEEDFACF)
        self.assertEqual(task("synthetic_universal", "universal", "count")["expect"], 2)
        macho_lib = task("synthetic_universal", "follow-an-import", "lib")
        self.assertEqual(macho_lib["options"][macho_lib["correct"]], "/usr/lib/libSystem.B.dylib")
        self.assertNotIn("ORDINAL_253", macho_lib["options"])
        self.assertEqual(task("synthetic_elf64", "follow-an-import", "count")["expect"], 2)
        pe_lib = task("synthetic_pe64", "follow-an-import", "lib")
        self.assertEqual(pe_lib["options"][pe_lib["correct"]], "WS2_32.dll")
        self.assertEqual(task("synthetic_pe32", "permissions", "rwx")["node_ids"], ["seg_1"])
        self.assertEqual(task("synthetic_elf32", "hardening-audit", "pie")["correct"], 1)
        self.assertEqual(task("synthetic_elf64", "hardening-audit", "pie")["correct"], 0)
        self.assertEqual(task("synthetic_firmware", "entry-point", "kind")["correct"], 1)
        self.assertEqual(task("synthetic_universal", "entry-point", "kind")["correct"], 0)
        self.assertEqual(task("synthetic_pe64", "entry-point", "arg")["options"][task("synthetic_pe64", "entry-point", "arg")["correct"]], "rcx")
        self.assertEqual(task("synthetic_elf64", "entry-point", "arg")["options"][task("synthetic_elf64", "entry-point", "arg")["correct"]], "rdi")


# =============================================================================
# Instruction help
# =============================================================================
class TestInstructionHelp(FixtureCase):
    def decoder_mnemonics(self):
        """Mnemonics the built-in decoder emits over a deterministic sweep of both instruction sets."""
        from backend import labs_encoding as enc
        import random
        rng = random.Random(7)
        a64, x86 = set(), set()

        def feed(word):
            result = enc.decode_a64(word, 0x1000, lite=True)
            if result["status"] != "not_decoded":
                a64.add(result["mnemonic"])

        for top in range(1 << 11):
            for low in (0, 0x1F, 0x3E0, 0x7C1F, 0x1FFFFF, 0x0F0F0F, 0x155555, 0x0AAAAA, 0x400, 0x800, 0xC00, 0x1F0000, 0x1F03E0, 0xFC00):
                feed((top << 21) | low)
        for _ in range(60000):
            feed(rng.getrandbits(32))
        for hint in range(128):
            feed(0xD503201F | (hint << 5))
        for word in (0xD65F03C0, 0xD65F0BFF, 0xD65F0FFF, 0xD4000001, 0xD4200000, 0):
            feed(word)

        def feedx(seq, bits):
            result = enc.decode_x86(bytes(seq) + b"\x00" * 16, 0, 0x1000, bits, lite=True)
            name = result.get("mnemonic")
            if result.get("status") != "not_decoded" and name and not name.startswith("."):
                x86.add(name)

        modrms = [0x00, 0x05, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8, 0xC9, 0xFA, 0xFB]
        for bits in (64, 32):
            for pre in ([], [0x66], [0xF2], [0xF3], [0x48]):
                if bits == 32 and 0x48 in pre:
                    continue
                for op in range(256):
                    for modrm in modrms:
                        feedx(pre + [op, modrm], bits)
                        feedx(pre + [0x0F, op, modrm], bits)
            for op in (0x80, 0x81, 0x83, 0xC0, 0xC1, 0xD1, 0xD3, 0xF6, 0xF7, 0xFE, 0xFF):
                for reg in range(8):
                    feedx([op, 0xC0 | (reg << 3)], bits)
                    feedx([0xF0, op, reg << 3], bits)
            for op2 in (0x71, 0x72, 0x73, 0xBA, 0xC7, 0xAE, 0x1F):
                for reg in range(8):
                    feedx([0x0F, op2, 0xC0 | (reg << 3)], bits)
                    feedx([0x66, 0x0F, op2, 0xC0 | (reg << 3)], bits)
                    feedx([0x0F, op2, reg << 3], bits)
        return a64, x86

    def test_every_mnemonic_of_the_builtin_decoder_is_explained(self):
        a64, x86 = self.decoder_mnemonics()
        self.assertGreater(len(a64), 250)
        self.assertGreater(len(x86), 280)
        self.assertEqual(sorted(m for m in a64 if insn_mod.lookup("arm64", m) is None), [])
        self.assertEqual(sorted(m for m in x86 if insn_mod.lookup("x86", m) is None), [])
        for arch, names in (("arm64", a64), ("x86", x86)):
            for name in names:
                entry = insn_mod.lookup(arch, name)
                self.assertEqual(set(entry), {"title", "text", "concept"}, name)
                self.assertTrue(entry["title"] and entry["text"], name)

    def test_lookup_rules(self):
        self.assertEqual(insn_mod.lookup("arm64", "b.ne")["title"], "Branch if not equal")
        self.assertIsNone(insn_mod.lookup("x86", "frobnicate"))
        self.assertIsNone(insn_mod.lookup("arm64", ""))
        lock_add = insn_mod.lookup("x86", "lock add")
        self.assertIn("atomic", lock_add["title"])
        self.assertTrue(lock_add["text"].startswith("The `lock` prefix"))
        self.assertIn("Adds the second operand", lock_add["text"])
        self.assertIn("repeated", insn_mod.lookup("x86", "rep  stosq")["title"])
        family = insn_mod.lookup("arm64", "ldaddalb")
        self.assertEqual(family["text"], insn_mod.FAMILIES["a64-atomic"]["text"])
        self.assertEqual(insn_mod.lookup("x86", "cmovne")["title"], "Move if not equal")
        self.assertEqual(insn_mod.lookup("x86", "callq"), insn_mod.lookup("x86", "call"))
        for arch, table in insn_mod.MNEMONICS.items():
            for name in table:
                merged = insn_mod.lookup(arch, name)
                self.assertTrue(merged and merged["text"] and merged["concept"], "%s/%s" % (arch, name))

    def test_idiom_steps_are_patterns_not_regular_expressions(self):
        # The browser matches these with a linear matcher and never compiles a regular expression
        # received over the wire, so the shipped steps must be plain mnemonic lists and patterns.
        for idiom in insn_mod.IDIOMS:
            self.assertTrue(idiom["steps"], idiom["id"])
            for step in idiom["steps"]:
                self.assertLessEqual(set(step), {"mn", "ops", "txt", "opt", "gap"}, idiom["id"])
                self.assertTrue(step["mn"] and all(isinstance(m, str) and m == m.lower() and m.strip() == m for m in step["mn"]), idiom["id"])
                self.assertLessEqual(int(step.get("gap", 0)), 16, idiom["id"])
                for part in ("ops", "txt"):
                    for pattern in step.get(part, []):
                        insn_mod.parse_pattern(pattern)
        for bad in ("", "a{x}", "a*b", "A", "x,  y", "{w", 5, None, "a" * 200):
            with self.assertRaises(ValueError, msg=repr(bad)):
                insn_mod.parse_pattern(bad)

    def test_pattern_matcher(self):
        m = lambda p, t: insn_mod.pattern_matches(p, insn_mod.normalise(t))
        self.assertTrue(m("x29,x30,[sp,#-{hex}]!", "x29, x30, [sp, #-0x10]!"))
        self.assertTrue(m("x29,x30,[sp,#-{hex}]!", "X29,  x30, [sp, #-16]!"))
        self.assertFalse(m("x29,x30,[sp,#-{hex}]!", "x29, x30, [sp, #-16]"))
        self.assertTrue(m("rsp,*", "rsp, 0x20"))
        self.assertFalse(m("rsp,*", "rspx, 0x20"))
        self.assertTrue(m("*ptr [rip*", "qword ptr [rip + 0x2fe2]"))
        self.assertTrue(m("{w},{w=}", "edi, edi"))
        self.assertFalse(m("{w},{w=}", "edi, esi"))
        self.assertFalse(m("{w},{w=}", "edi, edi2"))
        self.assertTrue(m("eax,{imm}", "eax, 60"))
        self.assertTrue(m("eax,{imm}", "eax, 0x3c"))
        self.assertFalse(m("eax,{imm}", "eax, 0x"))
        self.assertTrue(m("x{n},[x{n}*", "x8, [x8, #0x58]"))
        self.assertTrue(m("(a+)+$", "(a+)+$"))  # regular-expression syntax is literal text here
        self.assertFalse(m("(a+)+$", "aaaa"))
        # cost is bounded by len(pattern) x len(text): a long hostile text is cheap
        import time
        t0 = time.time()
        self.assertFalse(m("*" + "{w}," * 25 + "!", "a," * 5000))
        self.assertLess(time.time() - t0, 2.0)

    def rows(self, *items):
        return [{"mnemonic": m, "operands": o, "comment": c} for m, o, c in (i if len(i) == 3 else i + ("",) for i in items)]

    def ids(self, rows, arch):
        return [(a["index"], a["span"], a["id"]) for a in insn_mod.annotate(rows, arch)]

    def test_idioms_x86(self):
        rows = self.rows(("endbr64", ""), ("push", "rbp"), ("mov", "rbp, rsp"), ("sub", "rsp, 0x20"),
                         ("lea", "rdi, [rip + 0x31]"), ("call", "qword ptr [rip + 0x106b]"), ("xor", "eax, eax"),
                         ("leave", ""), ("ret", ""), ("nop", ""), ("nop", ""), ("nop", ""), ("nop", ""),
                         ("mov", "eax, 0x3c"), ("xor", "edi, edi"), ("syscall", ""))
        self.assertEqual(self.ids(rows, "x86"), [(0, 4, "x86-endbr-prologue"), (5, 1, "x86-import-call"), (6, 3, "x86-zero-return"),
                                                 (9, 4, "x86-nop-pad"), (13, 3, "x86-syscall")])
        self.assertEqual(self.ids(self.rows(("push", "ebp"), ("mov", "ebp, esp"), ("leave", ""), ("ret", "")), "x86"),
                         [(0, 2, "x86-prologue"), (2, 2, "x86-epilogue")])
        self.assertEqual(self.ids(self.rows(("jmp", "qword ptr [rip + 0x2fe2]")), "x86"), [(0, 1, "x86-import-stub")])
        self.assertEqual(self.ids(self.rows(("mov", "rax, qword ptr fs:[0x28]")), "x86"), [(0, 1, "x86-canary-load")])
        self.assertEqual(self.ids(self.rows(("mov", "rax, qword ptr [rip + 0x769]", "# literal pool symbol address: ___stack_chk_guard")), "x86"),
                         [(0, 1, "x86-canary-load")])
        self.assertEqual(self.ids(self.rows(("mov", "r10, rcx"), ("mov", "eax, 0x55"), ("syscall", "")), "x86"), [(0, 3, "x86-win-syscall-stub")])
        self.assertEqual(self.ids(self.rows(("mov", "eax, ebx"), ("add", "eax, 0x1")), "x86"), [])

    def test_idioms_arm64(self):
        rows = self.rows(("paciasp", ""), ("stp", "x29, x30, [sp, #-16]!"), ("mov", "x29, sp"), ("adrp", "x0, 0x180000000"),
                         ("add", "x0, x0, #0x500"), ("bl", "0x180000428"), ("ldp", "x29, x30, [sp], #16"), ("autiasp", ""), ("retaa", ""))
        self.assertEqual(self.ids(rows, "arm64"), [(0, 3, "a64-pac-prologue"), (3, 2, "a64-address"), (6, 3, "a64-epilogue-auth")])
        rows = self.rows(("sub", "sp, sp, #0xb0"), ("stp", "x24, x23, [sp, #112]"), ("stp", "x29, x30, [sp, #160]"), ("add", "x29, sp, #0xa0"),
                         ("adrp", "x8, 0x100004000"), ("ldr", "x8, [x8, #0x58]"), ("ldp", "x29, x30, [sp, #160]"), ("add", "sp, sp, #0xb0"), ("ret", ""))
        self.assertEqual(self.ids(rows, "arm64"), [(0, 4, "a64-prologue-sub"), (4, 2, "a64-got-load"), (6, 3, "a64-epilogue")])
        self.assertEqual(self.ids(self.rows(("adrp", "x16, 0x100004000"), ("ldr", "x16, [x16, #0x10]"), ("br", "x16")), "arm64"), [(0, 3, "a64-stub")])
        self.assertEqual(self.ids(self.rows(("mov", "x16, #0x4"), ("svc", "#0x80")), "arm64"), [(0, 2, "a64-syscall-apple")])
        self.assertEqual(self.ids(self.rows(("mov", "x8, #0x5d"), ("svc", "#0x0")), "arm64"), [(0, 2, "a64-syscall-linux")])
        self.assertEqual(self.ids(self.rows(("mov", "x1, #0x1337"), ("svc", "#0x80")), "arm64"), [(1, 1, "a64-svc")])
        self.assertEqual(insn_mod.annotate(rows, None), [])

    def test_the_entry_of_every_fixture_is_recognised(self):
        expected = {
            "x86": {"x86-prologue", "x86-endbr-prologue"},
            "arm64": {"a64-prologue", "a64-prologue-sub", "a64-pac-prologue"},
        }
        for name, _doc, index, slice_doc, _data, _raw in self.cases:
            arch = insn_mod.arch_family(slice_doc["arch_name"])
            self.assertIn(arch, expected, name)
            listing = self.service.disassemble(slice_index=index, vmaddr=slice_doc["entry_point"]["vmaddr"], section=None,
                                               count=40, doc="preset:" + name)
            found = L.annotate_instructions(listing["instructions"], slice_doc["arch_name"])
            self.assertTrue(found, name)
            self.assertEqual(found[0]["index"], 0, "%s[%d]: %s" % (name, index, found[:2]))
            self.assertIn(found[0]["id"], expected[arch], "%s[%d]" % (name, index))
            known = {i["id"] for i in insn_mod.IDIOMS}
            for item in found:
                self.assertIn(item["id"], known)
                self.assertGreaterEqual(item["span"], 1)


# =============================================================================
# The bundle stored in the document
# =============================================================================
class TestDocumentBundle(FixtureCase):
    def test_loader_lifecycle(self):
        for name, doc, index, slice_doc, _data, _raw in self.cases:
            life = slice_doc["pedagogy"]["loader_lifecycle"]
            self.assertEqual([s["stage"] for s in life["stages"]], [1, 2, 3, 4, 5, 6], name)
            self.assertTrue(life["loader_name"], name)
            nodes = self.valid_nodes(doc, slice_doc)
            for stage in life["stages"]:
                where = "%s[%d] stage %d" % (name, index, stage["stage"])
                for key in ("title", "actor", "summary", "binary_state", "failure_mode"):
                    self.assertTrue(stage[key], where)
                    self.assertNotIn("!", stage[key], where)
                self.assertIn(stage["node_id"], nodes, where)
                self.assertTrue(0 <= stage["abs_offset"] < doc["file_info"]["file_size"], where)
                self.assertGreater(stage["size"], 0, where)

    def test_lifecycle_describes_static_and_firmware_files_as_such(self):
        by_name = {n: s for n, _d, _i, s, _data, _raw in self.cases}
        elf32 = by_name["synthetic_elf32"]["pedagogy"]["loader_lifecycle"]
        self.assertIn("statically linked", elf32["loader_name"])
        self.assertIn("no PT_INTERP", elf32["stages"][2]["summary"])
        firmware = by_name["synthetic_firmware"]["pedagogy"]["loader_lifecycle"]
        self.assertIn("MH_PRELOAD", firmware["loader_name"])
        self.assertIn("LC_UNIXTHREAD", firmware["stages"][2]["summary"])
        elf64 = by_name["synthetic_elf64"]["pedagogy"]["loader_lifecycle"]
        self.assertIn("/lib64/ld-linux-x86-64.so.2", elf64["stages"][2]["summary"])
        pe32 = by_name["synthetic_pe32"]["pedagogy"]["loader_lifecycle"]
        self.assertIn("TLS callbacks: 1", pe32["stages"][5]["binary_state"])

    def test_legacy_lists_keep_their_shape(self):
        for name, _doc, _index, slice_doc, _data, _raw in self.cases:
            bundle = slice_doc["pedagogy"]
            self.assertEqual(len(bundle["rosetta_stone"]), 10, name)
            for row in bundle["rosetta_stone"]:
                self.assertEqual(row["active_format"], slice_doc["format"])
                for key in ("macho", "elf", "pe", "why"):
                    self.assertNotRegex(row[key], r"\[\[|`", name)
            self.assertGreaterEqual(len(bundle["guided_tours"]), 3, name)
            for tour in bundle["guided_tours"]:
                challenge = tour["steps"][0]["challenge"]
                self.assertTrue(0 <= challenge["correct_index"] < len(challenge["options"]))
                for step in tour["steps"]:
                    self.assertNotRegex(step["narrative"], r"\[\[|`|\{[a-z_]+\}", name)
        by_name = {n: s for n, _d, _i, s, _data, _raw in self.cases}
        pie = {n: by_name[n]["pedagogy"]["guided_tours"][2]["steps"][0]["challenge"]["correct_index"]
               for n in ("synthetic_elf64", "synthetic_elf32", "synthetic_pe64", "synthetic_pe32")}
        self.assertEqual(pie, {"synthetic_elf64": 0, "synthetic_elf32": 1, "synthetic_pe64": 0, "synthetic_pe32": 1})


# =============================================================================
# HTTP routes
# =============================================================================
class TestLearnApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_fixtures(WORKSPACE_ROOT)

    def router(self, mode):
        config = RuntimeConfig(mode, rate_limit_per_minute=0, upload_rate_limit_per_minute=0) if mode != "local" else RuntimeConfig("local")
        service = AnalysisService(WORKSPACE_ROOT, config)
        return build_router(service, config, log=EventLog(stream=io.StringIO()))

    def get(self, router, route, **query):
        resp = router.handle(ApiRequest("GET", route, query, b"", {}, "203.0.113.9"))
        return resp.status, json.loads(resp.body.decode("utf-8"))

    def test_static_routes(self):
        for mode in ("local", "public", "wasm"):
            router = self.router(mode)
            status, index = self.get(router, "/api/learn/index")
            self.assertEqual(status, 200, mode)
            self.assertEqual(index["counts"]["concepts"], len(L.concepts()))
            self.assertEqual(self.get(router, "/api/learn/concept", id="endianness")[1]["title"], "Byte order (endianness)")
            self.assertEqual(len(self.get(router, "/api/learn/concepts")[1]["concepts"]), len(L.concepts()))
            self.assertEqual(len(self.get(router, "/api/learn/glossary")[1]["terms"]), len(L.glossary()))
            self.assertIn("elf.ehdr.e_entry", self.get(router, "/api/learn/fields")[1]["catalog"])
            self.assertIn("x86", self.get(router, "/api/learn/instructions")[1]["mnemonics"])
            self.assertEqual(len(self.get(router, "/api/learn/compare")[1]["rows"]), len(L.compare()))
            self.assertEqual(len(self.get(router, "/api/learn/tours")[1]["tours"]), len(tours_mod.TOURS))

    def test_errors(self):
        router = self.router("public")
        self.assertEqual(self.get(router, "/api/learn/concept", id="nope")[0], 404)
        self.assertEqual(self.get(router, "/api/learn/nothing")[0], 404)
        self.assertEqual(self.get(router, "/api/learn/tour", id="first-contact")[0], 400)
        self.assertEqual(self.get(router, "/api/learn/tour", id="nope", doc="preset:synthetic_elf64")[0], 404)
        self.assertEqual(self.get(router, "/api/learn/resolve", scope="bogus")[0], 400)
        self.assertEqual(self.get(router, "/api/learn/resolve", scope="concept:nope")[0], 404)
        status, body = self.get(router, "/api/learn/tour", id="first-contact", doc="u_" + "0" * 32)
        self.assertIn(status, (404, 410))
        self.assertIn("code", body)
        self.assertEqual(self.get(router, "/api/learn/index", path="/etc/passwd")[0], 200)
        self.assertEqual(self.get(router, "/api/learn/tour", id="first-contact", path="/bin/ls")[0], 403)
        resp = router.handle(ApiRequest("POST", "/api/learn/index", {}, b"{}", {"content-type": "application/json"}, "203.0.113.9"))
        self.assertEqual(resp.status, 405)

    def test_tour_and_resolve_with_a_document(self):
        router = self.router("public")
        status, tour = self.get(router, "/api/learn/tour", id="file-to-memory", doc="preset:synthetic_elf64", slice_index="0")
        self.assertEqual(status, 200)
        self.assertTrue(tour["available"])
        self.assertEqual(tour["format"], "elf")
        self.assertTrue(any(s["task"] for s in tour["steps"]))
        status, second = self.get(router, "/api/learn/tour", id="universal", doc="preset:synthetic_universal", slice_index="1")
        offset = next(s["task"] for s in second["steps"] if s["task"] and s["task"]["id"] == "offset")
        self.assertEqual(offset["ranges"], [{"abs_offset": 8 + 20 + 8, "size": 4}])
        status, resolved = self.get(router, "/api/learn/resolve", scope="concept:endianness", doc="preset:synthetic_pe64")
        self.assertEqual(status, 200)
        by_id = {a["id"]: a for a in resolved["actions"]}
        self.assertTrue(by_id["endianness.3"]["available"])
        self.assertEqual(by_id["endianness.3"]["abs_offset"], 0x3C)
        self.assertFalse(by_id["endianness.1"]["available"])
        self.assertIn("synthetic_universal", by_id["endianness.1"]["samples"])

    def test_resolve_without_a_document_offers_samples(self):
        router = self.router("wasm")
        status, resolved = self.get(router, "/api/learn/resolve", scope="concept:nx-wx")
        self.assertEqual(status, 200)
        for action in resolved["actions"]:
            self.assertFalse(action["available"])
            self.assertTrue(action["samples"], action["id"])
            for sample in action["samples"]:
                self.assertTrue(sample.startswith("synthetic_"))
        rwx = next(a for a in resolved["actions"] if a["id"] == "nx-wx.1")
        self.assertTrue({"synthetic_firmware", "synthetic_pe32"} & set(rwx["samples"]))


if __name__ == "__main__":
    unittest.main()
