"""
Regression tests for the analysis logic: things the tool computes and reports.

One class per defect that a fact-check of the tool found (the numbers are those of the
defect list): in each case the tool used to state something false about a file, and the
test pins the true statement. Evidence for what "true" is comes from primary sources and
from independent tools; where an independent tool or a real system binary is available
on the machine running the tests it is consulted as well (those tests skip otherwise),
and every defect also has a hermetic test built from bytes made here.

   1  ELF is not "code-signed"; what PE says about Authenticode (presence vs hash match)
   2  ELF imports name a library only where symbol versioning records one
   3  GNU property notes are decoded for the file's own e_machine
   4  MH_PIE is judged only for main executables
   5  A W+X failure needs initprot; maxprot alone is a note
   6  PE NX_COMPAT matters to 32-bit x86 only
   7  SafeSEH is a 32-bit x86 concept
   8  CFG: declared in the header versus instrumented in the load configuration
   9  .pdata entry size depends on the machine
  10  What "stripped" means for a PE
  11  Capabilities match whole API names, not substrings
  12  Guided tasks have one defensible answer
  13  Patch-lab consequences fire only where their evidence applies
  14  MH_IMPLICIT_PAGEZERO and the header flag table
  15  Two stack-canary idioms, not one
  16  Architectures without a decoder are not disassembled
  17  The systemd unit installs everything the server loads
  18  No inline styles in first-party frontend code
  --  arm64e subtypes, PE section sizes, ELF relocation formats, the PE64 fixture

Nothing here executes a binary.
"""

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKSPACE_ROOT)

from backend import constants, disasm, fixtures, labs_patch, pe_parser, semantics  # noqa: E402
from backend import learn_content as L  # noqa: E402
from backend.api import ApiRequest, EventLog, build_router  # noqa: E402
from backend.elf_parser import decode_gnu_property, parse_elf_slice  # noqa: E402
from backend.fixtures import ensure_fixtures  # noqa: E402
from backend.learn import instructions as insn_mod  # noqa: E402
from backend.learn import resolve as resolve_mod  # noqa: E402
from backend.learn import tours as tours_mod  # noqa: E402
from backend.parser import parse_macho_bytes  # noqa: E402
from backend.pe_parser import parse_pe_slice  # noqa: E402
from backend.runtime import RuntimeConfig  # noqa: E402
from backend.service import AnalysisService  # noqa: E402

FIXTURES = ensure_fixtures(WORKSPACE_ROOT)

# Real files that happen to exist on a developer's Mac. Tests that use them skip when absent.
_JB = "/Applications/PyCharm.app/Contents"
_CLION = "/Applications/CLion.app/Contents/plugins/clion-radler/DotFiles"
REAL = {
    "elf_x64_versioned": _JB + "/plugins/python-ce/helpers/pydev/pydevd_attach_to_process/attach_linux_amd64.so",
    "elf_arm64_versioned": _JB + "/plugins/python-ce/helpers/pydev/pydevd_attach_to_process/attach_linux_aarch64.so",
    "elf_arm32": _CLION + "/linux-arm/jb_zip_unarchiver",
    "pe_amd64_signed_cfg": _JB + "/lib/async-profiler/amd64/dbghelp.dll",
    "pe_i386_safeseh": _JB + "/plugins/python-ce/helpers/pydev/pydevd_attach_to_process/attach_x86.dll",
    "pe_arm64_pdata": _JB + "/lib/async-profiler/aarch64/libasyncProfiler.dll",
    "pe_armnt_pdata": _CLION + "/runtimes/win/native/Microsoft.DiaSymReader.Native.arm.dll",
    "macho_dyld": "/usr/lib/dyld",
    "macho_ls": "/bin/ls",
}


def real(name: str) -> Optional[bytes]:
    path = REAL[name]
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        return handle.read()


def fixture_bytes(preset: str) -> bytes:
    with open(FIXTURES[preset], "rb") as handle:
        return handle.read()


def find_tool(*names: str) -> Optional[str]:
    for name in names:
        for candidate in (shutil.which(name), "/opt/homebrew/opt/llvm/bin/" + name, "/usr/local/opt/llvm/bin/" + name):
            if candidate and os.path.isfile(candidate):
                return candidate
    return None


def checks_of(slice_doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {c["id"]: c for c in slice_doc["security_posture"]["checks"]}


# ============================================================================
# Builders
# ============================================================================
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
LC_SEGMENT_64 = 0x19


def macho(filetype: int = 2, flags: int = 0x00200085, segments: Tuple[Tuple[str, int, int], ...] = (("__TEXT", 5, 5),),
          cputype: int = CPU_TYPE_ARM64, cpusubtype: int = 0) -> bytes:
    """A minimal 64-bit Mach-O: header plus one LC_SEGMENT_64 per (name, initprot, maxprot)."""
    cmds = []
    for index, (name, initprot, maxprot) in enumerate(segments):
        cmds.append(struct.pack("<II16sQQQQIIII", LC_SEGMENT_64, 72, name.encode().ljust(16, b"\0"),
                                0x100000000 + index * 0x4000, 0x4000, index * 0x1000, 0x1000, maxprot, initprot, 0, 0))
    body = b"".join(cmds)
    header = struct.pack("<IIIIIIII", MH_MAGIC_64, cputype, cpusubtype, filetype, len(cmds), len(body), flags, 0)
    return (header + body).ljust(max(1, len(segments)) * 0x1000, b"\0")


def macho_slice(**kwargs: Any) -> Dict[str, Any]:
    return parse_macho_bytes(macho(**kwargs), path="crafted.macho")["slices"][0]


SHT_PROGBITS, SHT_STRTAB, SHT_DYNAMIC, SHT_NOTE, SHT_DYNSYM = 1, 3, 6, 7, 11
SHT_GNU_VERNEED, SHT_GNU_VERSYM = 0x6FFFFFFE, 0x6FFFFFFF


def elf(machine: int = 62, little: bool = True, is64: bool = True, e_type: int = 3,
        needed: Tuple[str, ...] = (), imports: Tuple[Tuple[str, int], ...] = (),
        verneed: Tuple[Tuple[str, Tuple[Tuple[str, int], ...]], ...] = (),
        rodata: bytes = b"", property_note: bytes = b"", text: bytes = b"\x90" * 16) -> bytes:
    """A small ELF with a .dynsym of undefined symbols, optional symbol versioning
    (`imports` are (name, version index); `verneed` is ((file, ((version, index), ...)), ...)),
    DT_NEEDED entries, a .rodata, an optional .note.gnu.property and a .text."""
    e = "<" if little else ">"
    ehsize, phentsize, shentsize = (64, 56, 64) if is64 else (52, 32, 40)

    strtab = bytearray(b"\0")

    def s(text_: str) -> int:
        off = len(strtab)
        strtab.extend(text_.encode() + b"\0")
        return off

    need_offs = [s(n) for n in needed]
    sym_offs = [s(n) for n, _ in imports]
    ver_files = [(s(f), [(s(v), idx) for v, idx in versions]) for f, versions in verneed]

    dynsym = bytearray(24 if is64 else 16)
    for off in sym_offs:
        dynsym += struct.pack(e + "IBBHQQ", off, 0x12, 0, 0, 0, 0) if is64 else struct.pack(e + "IIIBBH", off, 0, 0, 0x12, 0, 0)
    versym = struct.pack(e + "%dH" % (1 + len(imports)), 0, *[idx for _n, idx in imports]) if verneed else b""
    vn = bytearray()
    for i, (f_off, versions) in enumerate(ver_files):
        size = 16 + 16 * len(versions)
        vn += struct.pack(e + "HHIII", 1, len(versions), f_off, 16, size if i + 1 < len(ver_files) else 0)
        for j, (v_off, idx) in enumerate(versions):
            vn += struct.pack(e + "IHHII", 0, 0, idx, v_off, 16 if j + 1 < len(versions) else 0)
    dyn = bytearray()
    for off in need_offs:
        dyn += struct.pack(e + ("qQ" if is64 else "iI"), 1, off)
    dyn += struct.pack(e + ("qQ" if is64 else "iI"), 0, 0)

    shstr = bytearray(b"\0")
    sections: List[Tuple[int, int, int, bytes, int, int, int]] = []   # (name, type, flags, data, link, info, entsize)

    def add(name: str, sh_type: int, flags: int, data: bytes, link: int = 0, info: int = 0, entsize: int = 0) -> int:
        name_off = len(shstr)
        shstr.extend(name.encode() + b"\0")
        sections.append((name_off, sh_type, flags, bytes(data), link, info, entsize))
        return len(sections)          # section index (0 is the null section)

    dynstr_index = add(".dynstr", SHT_STRTAB, 2, strtab)
    add(".dynsym", SHT_DYNSYM, 2, dynsym, link=dynstr_index, info=1, entsize=24 if is64 else 16)
    if verneed:
        add(".gnu.version", SHT_GNU_VERSYM, 2, versym, link=2, entsize=2)
        add(".gnu.version_r", SHT_GNU_VERNEED, 2, vn, link=dynstr_index, info=len(ver_files))
    add(".dynamic", SHT_DYNAMIC, 3, dyn, link=dynstr_index, entsize=16 if is64 else 8)
    if rodata:
        add(".rodata", SHT_PROGBITS, 2, rodata)
    if property_note:
        add(".note.gnu.property", SHT_NOTE, 2, property_note)
    text_index = add(".text", SHT_PROGBITS, 6, text)
    shstrndx = add(".shstrtab", SHT_STRTAB, 0, b"")       # data patched in below

    offset = ehsize + phentsize
    blob = bytearray()
    placed = []
    for index, (name_off, sh_type, flags, data, link, info, entsize) in enumerate(sections):
        if index + 1 == shstrndx:
            data = bytes(shstr)
        pad = -offset % 8
        blob += b"\0" * pad
        offset += pad
        placed.append((name_off, sh_type, flags, offset, len(data), link, info, entsize))
        blob += data
        offset += len(data)
    pad = -offset % 8
    blob += b"\0" * pad
    shoff = offset + pad
    entry = placed[text_index - 1][3]

    shdrs = bytearray(shentsize)
    for name_off, sh_type, flags, off, size, link, info, entsize in placed:
        addr = off if flags & 2 else 0
        if is64:
            shdrs += struct.pack(e + "IIQQQQIIQQ", name_off, sh_type, flags, addr, off, size, link, info, 8, entsize)
        else:
            shdrs += struct.pack(e + "IIIIIIIIII", name_off, sh_type, flags, addr, off, size, link, info, 4, entsize)
    total = shoff + len(shdrs)
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1 if little else 2, 1, 0]) + b"\0" * 8
    if is64:
        ehdr = ident + struct.pack(e + "HHIQQQIHHHHHH", e_type, machine, 1, entry, ehsize, shoff, 0, ehsize, phentsize, 1, shentsize, len(placed) + 1, shstrndx)
        phdr = struct.pack(e + "IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000)
    else:
        ehdr = ident + struct.pack(e + "HHIIIIIHHHHHH", e_type, machine, 1, entry, ehsize, shoff, 0, ehsize, phentsize, 1, shentsize, len(placed) + 1, shstrndx)
        phdr = struct.pack(e + "IIIIIIII", 1, 0, 0, 0, total, total, 5, 0x1000)
    return bytes(ehdr + phdr + blob + shdrs)


def gnu_property_note(properties: Tuple[Tuple[int, int], ...], is64: bool = True, little: bool = True) -> bytes:
    """An NT_GNU_PROPERTY_TYPE_0 note holding (pr_type, 32-bit value) properties."""
    e = "<" if little else ">"
    align = 8 if is64 else 4
    desc = b""
    for pr_type, value in properties:
        item = struct.pack(e + "III", pr_type, 4, value)
        desc += item + b"\0" * (-len(item) % align)
    return struct.pack(e + "III", 4, len(desc), 5) + b"GNU\0" + desc


def pe_patch(data: bytes, **fields: int) -> bytes:
    """A copy of a PE with header fields replaced. Keys: machine, characteristics,
    dll_characteristics, symtab (PointerToSymbolTable), nsyms."""
    out = bytearray(data)
    nt = struct.unpack_from("<I", out, 0x3C)[0]
    where = {"machine": (nt + 4, "<H"), "symtab": (nt + 12, "<I"), "nsyms": (nt + 16, "<I"),
             "characteristics": (nt + 22, "<H"), "dll_characteristics": (nt + 24 + 70, "<H")}
    for key, value in fields.items():
        off, fmt = where[key]
        struct.pack_into(fmt, out, off, value)
    return bytes(out)


def pe_field(data: bytes, key: str) -> int:
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    off, fmt = {"characteristics": (nt + 22, "<H"), "dll_characteristics": (nt + 24 + 70, "<H")}[key]
    return struct.unpack_from(fmt, data, off)[0]


def pe_set_directory(data: bytes, index: int, rva: int, size: int) -> bytes:
    out = bytearray(data)
    nt = struct.unpack_from("<I", out, 0x3C)[0]
    magic = struct.unpack_from("<H", out, nt + 24)[0]
    dirs = nt + 24 + (112 if magic == 0x20B else 96)
    struct.pack_into("<II", out, dirs + 8 * index, rva, size)
    return bytes(out)


class _Null:
    def write(self, _text: str) -> None:
        pass

    def flush(self) -> None:
        pass


def make_router():
    config = RuntimeConfig("local")
    service = AnalysisService(WORKSPACE_ROOT, config)
    return build_router(service, config, log=EventLog(stream=_Null())), service


def call(router, method: str, route: str, query: Optional[Dict[str, str]] = None, body: Any = None, raw: Optional[bytes] = None,
         headers: Optional[Dict[str, str]] = None):
    hdrs = dict(headers or {})
    payload = b""
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        hdrs.setdefault("content-type", "application/json")
    if raw is not None:
        payload = raw
    resp = router.handle(ApiRequest(method, route, query or {}, payload, hdrs, "198.51.100.77"))
    data = json.loads(resp.body.decode("utf-8")) if resp.content_type.startswith("application/json") and resp.body else None
    return resp, data


def upload(router, data: bytes, name: str = "sample.bin") -> Dict[str, Any]:
    resp, doc = call(router, "POST", "/api/upload", raw=data, headers={"content-type": "application/octet-stream", "x-filename": name})
    assert resp.status == 200, (resp.status, doc)
    return doc


def patched(router, doc_id: str, patches: List[Dict[str, Any]]) -> Dict[str, Any]:
    resp, out = call(router, "POST", "/api/patch", body={"doc": doc_id, "patches": patches})
    assert resp.status == 200, (resp.status, out)
    return out


def named_field(fields: List[Dict[str, Any]], name: str) -> Dict[str, Any]:
    return next(f for f in fields if f["name"] == name)


# ============================================================================
# 1. ELF has no code signature; PE reports presence and hash match, never "verified"
# ============================================================================
class Defect01SignatureRecord(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.router, cls.service = make_router()

    def test_an_elf_with_a_build_id_and_properties_is_not_signed(self) -> None:
        sl = parse_elf_slice(fixture_bytes("synthetic_elf64"), "synthetic_elf64")
        self.assertTrue(sl["elf_metadata"]["build_id"], "the fixture has a build ID")
        self.assertTrue(sl["elf_metadata"]["gnu_properties"], "and a GNU property note")
        sig = sl["code_signature_detail"]
        self.assertFalse(sig["present"])
        self.assertEqual(sig["kind"], "none")
        self.assertIsNone(sig["code_directory"])
        self.assertEqual((sig["blobs"], sig["entitlements_dict"], sig["entitlements_entries"]), ([], {}, []))
        summary = sl["security_posture"]["code_signature"]
        self.assertFalse(summary["present"])
        self.assertEqual((summary["cdhash"], summary["identifier"], summary["certificates"]), ("", "", []))
        self.assertFalse(summary["cdhash_verified"])

    def test_the_build_id_and_properties_are_still_reported_where_they_belong(self) -> None:
        sl = parse_elf_slice(fixture_bytes("synthetic_elf64"), "synthetic_elf64")
        build_id = sl["elf_metadata"]["build_id"]
        self.assertEqual(sl["overview"]["uuid"], build_id)
        self.assertIn("NT_GNU_BUILD_ID", [n["type_name"] for n in sl["elf_metadata"]["notes"]])
        self.assertEqual(sl["elf_metadata"]["gnu_properties"], ["Intel CET IBT", "Intel CET SHSTK"])
        checks = checks_of(sl)
        self.assertEqual(checks["cfi_cet_pac"]["status"], "PASS")
        self.assertIn("Build-ID Present", checks["build_id_symbols"]["value"])
        self.assertNotIn("codesign", checks, "ELF has no signature check to pass or fail")

    def test_no_elf_is_ever_reported_signed(self) -> None:
        samples = [fixture_bytes("synthetic_elf64"), fixture_bytes("synthetic_elf32"), elf(needed=("libc.so.6",), imports=(("puts", 1),))]
        samples += [d for d in (real("elf_x64_versioned"), real("elf_arm32")) if d]
        for data in samples:
            sl = parse_elf_slice(data, "x")
            self.assertFalse(sl["code_signature_detail"]["present"])
            self.assertFalse(sl["security_posture"]["code_signature"]["present"])

    def test_patching_the_build_id_is_still_visible_in_the_patch_diff(self) -> None:
        # The lab's diff used to show a build-ID change as a "signature" change. With the
        # signature record truthful the change must not vanish: it shows as identity metadata.
        sl = parse_elf_slice(fixture_bytes("synthetic_elf64"), "x")
        note = next(n for n in sl["elf_metadata"]["notes"] if n["type_name"] == "NT_GNU_BUILD_ID")
        offset = note["abs_offset"] + 16          # 12-byte note header + "GNU\0"
        original = fixture_bytes("synthetic_elf64")[offset]
        out = patched(self.router, "preset:synthetic_elf64", [{"offset": offset, "hex": "%02x" % (original ^ 0xFF)}])
        part = out["diff"]["slices"][0]
        self.assertEqual(part["signature"], [])
        self.assertIn("uuid", [c["prop"] for c in part["overview"]])
        self.assertIn(("elf_metadata", "build_id"), [(c["scope"], c["prop"]) for c in part["metadata"]])

    def test_pe_reports_hash_match_and_says_the_signature_is_not_evaluated(self) -> None:
        data = fixture_bytes("synthetic_pe64")
        sl = parse_pe_slice(data, "synthetic_pe64.exe")
        sig = sl["code_signature_detail"]
        self.assertTrue(sig["present"])
        self.assertEqual(sig["kind"], "authenticode")
        auth = sig["authenticode"]
        self.assertEqual(auth["algorithm"], "sha256")
        self.assertTrue(auth["digest_in_signature"])
        self.assertIs(auth["signature_evaluated"], False)
        # The hash shown is the Authenticode image hash (not a hash of the PKCS#7 blob).
        layout = pe_parser.pe_layout(data)
        self.assertEqual(sig["code_directory"]["cdhash"], pe_parser.authenticode_digest(data, layout, "sha256"))
        self.assertIn("Authenticode image hash", sig["code_directory"]["hash_type"])
        self.assertEqual(sig["entitlements_dict"], {}, "DllCharacteristics are not entitlements")
        check = checks_of(sl)["codesign"]
        self.assertEqual(check["status"], "PASS")
        self.assertIn("image hash matches", check["value"])
        self.assertIn("not evaluated", check["detail"])
        self.assertNotIn("verified", check["value"].lower())

    def test_pe_with_a_certificate_table_that_does_not_cover_the_file_is_not_a_pass(self) -> None:
        data = bytearray(fixture_bytes("synthetic_pe64"))
        data[0x600] ^= 0xFF                      # a byte of .text, covered by the image hash
        sl = parse_pe_slice(bytes(data), "tampered.exe")
        self.assertTrue(sl["code_signature_detail"]["present"])
        self.assertFalse(sl["code_signature_detail"]["authenticode"]["digest_in_signature"])
        self.assertFalse(sl["code_signature_detail"]["code_directory"]["cdhash_verified"])
        self.assertFalse(sl["security_posture"]["code_signature"]["cdhash_verified"])
        check = checks_of(sl)["codesign"]
        self.assertEqual(check["status"], "WARN")
        self.assertIn("not found", check["value"])

    def test_a_section_table_that_aliases_the_file_does_not_multiply_the_hashing(self) -> None:
        data = bytearray(fixture_bytes("synthetic_pe64"))
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        table = nt + 24 + struct.unpack_from("<H", data, nt + 20)[0]
        for index in range(3):                                # every section: the whole file
            struct.pack_into("<II", data, table + index * 40 + 16, len(data), 0)
        sl = parse_pe_slice(bytes(data), "aliased.exe")
        auth = sl["code_signature_detail"]["authenticode"]
        self.assertFalse(auth["digest_in_signature"])
        self.assertEqual(auth["image_digest"], "")
        self.assertIn("overlaps", auth["not_computed"])
        self.assertEqual(checks_of(sl)["codesign"]["value"], "Certificate table present; image hash not computed")

    def test_real_signed_pe_images_contain_their_image_hash(self) -> None:
        seen = 0
        for name in ("pe_amd64_signed_cfg", "pe_i386_safeseh", "pe_arm64_pdata", "pe_armnt_pdata"):
            data = real(name)
            if data is None:
                continue
            seen += 1
            sl = parse_pe_slice(data, name)
            self.assertTrue(sl["code_signature_detail"]["authenticode"]["digest_in_signature"], name)
            layout = pe_parser.pe_layout(data)
            self.assertEqual(pe_parser.pe_checksum(data, layout["checksum_off"]), layout["stored_checksum"], name)
        if not seen:
            self.skipTest("no signed PE sample on this machine")

    def test_frontend_does_not_call_a_pe_or_elf_verified(self) -> None:
        with open(os.path.join(WORKSPACE_ROOT, "static", "app.js"), "r", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("isPe ? (cs.code_directory?.cdhash_verified ? 'hash matches' : 'present')", source)
        self.assertIn("ELF has no embedded signature format", source)


# ============================================================================
# 2. ELF imports: library only from symbol versioning
# ============================================================================
class Defect02ElfImportLibraries(unittest.TestCase):
    def build(self) -> Dict[str, Any]:
        # libm is the FIRST DT_NEEDED: the old code attributed every import to it.
        data = elf(needed=("libm.so.6", "libc.so.6"),
                   imports=(("puts", 2), ("cos", 3), ("mystery", 1), ("local_only", 0)),
                   verneed=(("libc.so.6", (("GLIBC_2.2.5", 2),)), ("libm.so.6", (("GLIBC_2.29", 3),))))
        return parse_elf_slice(data, "versions.elf")

    def test_versioned_symbols_name_the_library_their_version_comes_from(self) -> None:
        sl = self.build()
        self.assertEqual([d["name"] for d in sl["dylibs"]], ["libm.so.6", "libc.so.6"])
        imports = {i["name"]: i for i in sl["dyld_info"]["chained_fixups"]["imports"]}
        self.assertEqual((imports["puts"]["lib_name"], imports["puts"]["version"], imports["puts"]["lib_source"]),
                         ("libc.so.6", "GLIBC_2.2.5", "verneed"))
        self.assertEqual((imports["cos"]["lib_name"], imports["cos"]["version"]), ("libm.so.6", "GLIBC_2.29"))
        self.assertEqual(imports["puts"]["lib_ordinal"], 2, "position of libc.so.6 among the DT_NEEDED entries")
        self.assertEqual(imports["cos"]["lib_ordinal"], 1)

    def test_unversioned_symbols_have_no_library(self) -> None:
        imports = {i["name"]: i for i in self.build()["dyld_info"]["chained_fixups"]["imports"]}
        for name in ("mystery", "local_only"):       # version index 1 (global) and 0 (local): no requirement
            self.assertEqual((imports[name]["lib_name"], imports[name]["lib_ordinal"], imports[name]["lib_source"]),
                             ("", 0, "unknown"), name)
        symbols = {s["name"]: s for s in self.build()["symbols"]}
        self.assertEqual(symbols["mystery"]["library_name"], "")
        self.assertEqual(symbols["puts"]["library_name"], "libc.so.6")

    def test_without_versioning_nothing_is_guessed(self) -> None:
        sl = parse_elf_slice(elf(needed=("libfoo.so", "libc.so.6"), imports=(("puts", 0), ("foo_init", 0))), "plain.elf")
        chained = sl["dyld_info"]["chained_fixups"]
        self.assertEqual([(i["name"], i["lib_name"]) for i in chained["imports"]], [("puts", ""), ("foo_init", "")])
        self.assertIn("not recorded", chained["imports_format"])
        # The fixture has two DT_NEEDED entries and no versioning: same there.
        fixture = parse_elf_slice(fixture_bytes("synthetic_elf64"), "x")
        self.assertEqual({i["lib_name"] for i in fixture["dyld_info"]["chained_fixups"]["imports"]}, {""})

    def test_big_endian_and_32_bit_version_tables(self) -> None:
        data = elf(machine=20, little=False, is64=False, needed=("libc.so.6",), imports=(("puts", 2), ("bare", 1)),
                   verneed=(("libc.so.6", (("GLIBC_2.0", 2),)),))
        imports = {i["name"]: i for i in parse_elf_slice(data, "ppc.elf")["dyld_info"]["chained_fixups"]["imports"]}
        self.assertEqual((imports["puts"]["lib_name"], imports["puts"]["version"]), ("libc.so.6", "GLIBC_2.0"))
        self.assertEqual(imports["bare"]["lib_name"], "")

    def test_agrees_with_llvm_readelf_on_a_real_shared_object(self) -> None:
        readelf = find_tool("llvm-readelf", "readelf")
        data = real("elf_x64_versioned")
        if not readelf or data is None:
            self.skipTest("llvm-readelf or the sample is not available")
        out = subprocess.run([readelf, "-V", REAL["elf_x64_versioned"]], capture_output=True, text=True, timeout=30).stdout
        want: Dict[str, str] = {}            # version name -> file, from "Version needs"
        current = None
        for line in out.split("Version needs section", 1)[-1].splitlines():
            m = re.search(r"File:\s*(\S+)", line)
            if m:
                current = m.group(1)
            m = re.search(r"Name:\s*(\S+)", line)
            if m and current:
                want.setdefault(m.group(1), current)
        syms = subprocess.run([readelf, "--dyn-syms", "-W", REAL["elf_x64_versioned"]], capture_output=True, text=True, timeout=30).stdout
        expected = {}
        for line in syms.splitlines():
            m = re.search(r"\sUND\s+(\S+)$", line)
            if m:
                name, _, version = m.group(1).partition("@")
                expected[name] = want.get(version.strip("@"), "") if version else ""
        self.assertGreater(len([v for v in expected.values() if v]), 3)
        got = {i["name"]: i["lib_name"] for i in parse_elf_slice(data, "x")["dyld_info"]["chained_fixups"]["imports"]}
        for name, lib in expected.items():
            if name:
                self.assertEqual(got.get(name), lib, name)


# ============================================================================
# 3. GNU property notes are decoded for the file's machine
# ============================================================================
class Defect03GnuPropertyPerMachine(unittest.TestCase):
    AARCH64_FEATURE_1_AND = 0xC0000000
    X86_FEATURE_1_AND = 0xC0000002

    def props(self, machine: int, pr_type: int, value: int, **kwargs: Any) -> Dict[str, Any]:
        note = gnu_property_note(((pr_type, value),), is64=kwargs.get("is64", True), little=kwargs.get("little", True))
        return parse_elf_slice(elf(machine=machine, property_note=note, **kwargs), "prop.elf")

    def test_the_same_property_number_means_different_things_per_machine(self) -> None:
        # 0xc0000000 is the AArch64 feature word. On x86 it is not the CET word (that is 0xc0000002).
        arm = self.props(183, self.AARCH64_FEATURE_1_AND, 0x3)
        self.assertEqual(arm["elf_metadata"]["gnu_properties"], ["ARM64 BTI", "ARM64 PAC"])
        x86 = self.props(62, self.AARCH64_FEATURE_1_AND, 0x3)
        self.assertEqual(x86["elf_metadata"]["gnu_properties"], [], "an x86-64 file cannot declare BTI / PAC")
        self.assertEqual(checks_of(x86)["cfi_cet_pac"]["status"], "INFO")
        entry = x86["elf_metadata"]["gnu_property_entries"][0]
        self.assertFalse(entry["known"])
        self.assertIn("not defined for this machine", entry["type_name"])

    def test_x86_feature_word_is_not_decoded_on_aarch64(self) -> None:
        x86 = self.props(62, self.X86_FEATURE_1_AND, 0x3)
        self.assertEqual(x86["elf_metadata"]["gnu_properties"], ["Intel CET IBT", "Intel CET SHSTK"])
        i386 = self.props(3, self.X86_FEATURE_1_AND, 0x1, is64=False)
        self.assertEqual(i386["elf_metadata"]["gnu_properties"], ["Intel CET IBT"])
        arm = self.props(183, self.X86_FEATURE_1_AND, 0x3)
        self.assertEqual(arm["elf_metadata"]["gnu_properties"], [], "an AArch64 file cannot declare Intel CET")
        self.assertFalse(checks_of(arm)["cfi_cet_pac"]["status"] == "PASS")

    def test_other_machines_decode_no_processor_specific_property(self) -> None:
        for machine in (40, 243, 20):            # ARM, RISC-V, PowerPC
            sl = self.props(machine, self.AARCH64_FEATURE_1_AND, 0x7)
            self.assertEqual(sl["elf_metadata"]["gnu_properties"], [], machine)

    def test_decoder_tables(self) -> None:
        self.assertEqual(decode_gnu_property(183, 0xC0000000, struct.pack("<I", 0x7))["flags"], ["BTI", "PAC", "GCS"])
        self.assertEqual(decode_gnu_property(62, 0xC0008002, struct.pack("<I", 0x3))["flags"], ["x86-64-baseline", "x86-64-v2"])
        self.assertEqual(decode_gnu_property(62, 0xC0008002, struct.pack("<I", 0x3))["cfi"], [], "an ISA level is not a CFI feature")
        self.assertEqual(decode_gnu_property(183, 0xC0000000, struct.pack(">I", 0x1), ">")["flags"], ["BTI"])
        generic = decode_gnu_property(40, 0xB0008000, struct.pack("<I", 1))
        self.assertEqual((generic["type_name"], generic["flags"]), ("GNU_PROPERTY_1_NEEDED", ["INDIRECT_EXTERN_ACCESS"]))

    def test_agrees_with_llvm_readelf_on_compiler_output(self) -> None:
        # The system compiler on macOS has no Linux targets; an LLVM distribution's clang does.
        clang = next((c for c in ("/opt/homebrew/opt/llvm/bin/clang", "/usr/local/opt/llvm/bin/clang") if os.path.isfile(c)), None)
        readelf = find_tool("llvm-readelf")
        if not clang or not readelf:
            self.skipTest("an LLVM clang with cross targets and llvm-readelf are needed")
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "p.c")
            with open(src, "w") as handle:
                handle.write("int f(int x){return x+1;}\n")
            for target, flag, want in (("aarch64-linux-gnu", "-mbranch-protection=standard", {"BTI", "PAC"}),
                                       ("x86_64-linux-gnu", "-fcf-protection=full", {"IBT", "SHSTK"})):
                obj = os.path.join(tmp, target + ".o")
                built = subprocess.run([clang, "--target=" + target, flag, "-c", src, "-o", obj], capture_output=True, timeout=60)
                if built.returncode != 0:
                    self.skipTest("clang cannot build for " + target)
                listed = subprocess.run([readelf, "-n", obj], capture_output=True, text=True, timeout=30).stdout
                line = next(l for l in listed.splitlines() if "feature:" in l)
                theirs = {t.strip() for t in line.split("feature:", 1)[1].split(",")}
                with open(obj, "rb") as handle:
                    sl = parse_elf_slice(handle.read(), obj)
                ours = set(sl["elf_metadata"]["gnu_property_entries"][0]["flags"])
                self.assertEqual(ours, theirs, target)
                self.assertTrue(want <= ours, target)


# ============================================================================
# 4. MH_PIE applies to main executables only
# ============================================================================
class Defect04MachOPieApplicability(unittest.TestCase):
    NOT_MAIN = {1: "MH_OBJECT", 6: "MH_DYLIB", 7: "MH_DYLINKER", 8: "MH_BUNDLE", 0xA: "MH_DSYM", 0xB: "MH_KEXT_BUNDLE", 9: "MH_DYLIB_STUB", 4: "MH_CORE"}

    def test_file_types_without_mh_pie_are_not_fixed_address_failures(self) -> None:
        for filetype, name in self.NOT_MAIN.items():
            sl = macho_slice(filetype=filetype, flags=0x85)          # MH_PIE clear, as it always is for these
            check = checks_of(sl)["pie"]
            self.assertEqual(check["status"], "INFO", name)
            self.assertEqual(check["value"], "Not applicable (%s)" % name)
            self.assertNotIn("Fixed Address", check["value"])
            self.assertIs(sl["security_posture"]["pie_applicable"], False, name)

    def test_images_the_loader_always_places_itself_count_as_relocatable(self) -> None:
        for filetype in (6, 7, 8, 0xB):             # dylib, dylinker, bundle, kext
            self.assertTrue(macho_slice(filetype=filetype, flags=0x85)["security_posture"]["pie"], filetype)
        for filetype in (1, 0xA, 4):                # object, dSYM, core: never loaded as an image
            self.assertFalse(macho_slice(filetype=filetype, flags=0x85)["security_posture"]["pie"], filetype)

    def test_main_executables_are_still_judged(self) -> None:
        with_pie = macho_slice(filetype=2, flags=0x00200085)
        self.assertEqual(checks_of(with_pie)["pie"]["status"], "PASS")
        self.assertTrue(with_pie["security_posture"]["pie_applicable"])
        without = macho_slice(filetype=2, flags=0x85)
        self.assertEqual((checks_of(without)["pie"]["status"], checks_of(without)["pie"]["value"]), ("FAIL", "Disabled (Fixed Address)"))
        self.assertFalse(without["security_posture"]["pie"])

    def test_dyld_injection_check_is_about_the_main_executable(self) -> None:
        # Related: the absence of __RESTRICT / hardened runtime in a dylib or object is not a warning.
        for filetype in (1, 6, 8, 0xA):
            self.assertEqual(checks_of(macho_slice(filetype=filetype, flags=0x85))["restrict"]["status"], "INFO", filetype)
        self.assertEqual(checks_of(macho_slice(filetype=2))["restrict"]["status"], "WARN")

    def test_the_system_dynamic_linker_and_a_dylib(self) -> None:
        data = real("macho_dyld")
        if data is None:
            self.skipTest("/usr/lib/dyld is not present")
        for sl in parse_macho_bytes(data, path="/usr/lib/dyld")["slices"]:
            self.assertEqual(sl["header"]["filetype_name"], "MH_DYLINKER")
            self.assertEqual(checks_of(sl)["pie"]["status"], "INFO")
            self.assertTrue(sl["security_posture"]["pie"], "XNU slides dyld on every exec")
        ls = real("macho_ls")
        if ls is not None:
            for sl in parse_macho_bytes(ls, path="/bin/ls")["slices"]:
                self.assertEqual(checks_of(sl)["pie"]["status"], "PASS")


# ============================================================================
# 5. W+X: initprot is a failure, maxprot alone is a note
# ============================================================================
class Defect05MachOWriteExecute(unittest.TestCase):
    def test_maxprot_alone_is_not_a_failure(self) -> None:
        # r-x mapped, rwx permitted: the default for __TEXT in Intel binaries from older linkers.
        sl = macho_slice(segments=(("__TEXT", 5, 7), ("__DATA", 3, 7)), cputype=CPU_TYPE_X86_64, cpusubtype=3)
        check = checks_of(sl)["rwx"]
        self.assertEqual(check["status"], "INFO")
        self.assertIn("maxprot allows it", check["value"])
        self.assertFalse(sl["security_posture"]["has_rwx_segments"])
        self.assertEqual(len(sl["security_posture"]["rwx_maxprot_only"]), 2)
        self.assertEqual([a for a in sl["semantic_layers"]["anomalies"]["findings"] if a["id"] == "rwx_memory"], [])

    def test_initprot_write_and_execute_is_a_failure(self) -> None:
        sl = macho_slice(segments=(("__TEXT", 5, 5), ("__JIT", 7, 7)))
        check = checks_of(sl)["rwx"]
        self.assertEqual(check["status"], "FAIL")
        self.assertIn("__JIT", check["value"])
        self.assertTrue(sl["security_posture"]["has_rwx_segments"])
        self.assertEqual(sl["security_posture"]["rwx_maxprot_only"], [])

    def test_clean_file_passes(self) -> None:
        sl = macho_slice(segments=(("__TEXT", 5, 5), ("__DATA", 3, 3)))
        self.assertEqual(checks_of(sl)["rwx"]["status"], "PASS")

    def test_stack_execution_flag_is_a_failure(self) -> None:
        sl = macho_slice(flags=0x00200085 | 0x20000)
        self.assertEqual(checks_of(sl)["rwx"]["status"], "FAIL")
        self.assertIn("MH_ALLOW_STACK_EXECUTION", checks_of(sl)["rwx"]["value"])

    def test_a_relocatable_object_is_not_an_rwx_finding(self) -> None:
        # Every .o has one unnamed segment that the compiler marks rwx; it is never mapped.
        sl = macho_slice(filetype=1, flags=0x2000, segments=(("", 7, 7),))
        self.assertEqual(checks_of(sl)["rwx"]["status"], "INFO")
        self.assertIn("Not applicable", checks_of(sl)["rwx"]["value"])
        self.assertFalse(sl["security_posture"]["has_rwx_segments"])
        self.assertEqual([a for a in sl["semantic_layers"]["anomalies"]["findings"] if a["id"] == "rwx_memory"], [])

    def test_a_compiler_built_object_file(self) -> None:
        clang = shutil.which("clang")
        if not clang or sys.platform != "darwin":
            self.skipTest("needs the macOS system compiler")
        with tempfile.TemporaryDirectory() as tmp:
            src, obj = os.path.join(tmp, "m.c"), os.path.join(tmp, "m.o")
            with open(src, "w") as handle:
                handle.write("int main(void){return 0;}\n")
            if subprocess.run([clang, "-c", src, "-o", obj], capture_output=True, timeout=60).returncode != 0:
                self.skipTest("clang could not compile")
            with open(obj, "rb") as handle:
                sl = parse_macho_bytes(handle.read(), path=obj)["slices"][0]
        self.assertEqual(sl["header"]["filetype_name"], "MH_OBJECT")
        self.assertEqual(sl["segments"][0]["initprot"], "rwx", "the object's single segment really is marked rwx")
        self.assertEqual({checks_of(sl)[k]["status"] for k in ("pie", "rwx", "restrict")}, {"INFO"})


# ============================================================================
# 6. NX_COMPAT matters only to 32-bit x86
# ============================================================================
class Defect06PeDep(unittest.TestCase):
    def dep(self, data: bytes) -> Dict[str, Any]:
        return checks_of(parse_pe_slice(data, "x.exe"))["dep_nx"]

    def test_64_bit_image_without_nx_compat_is_informational(self) -> None:
        data = fixture_bytes("synthetic_pe64")
        cleared = pe_patch(data, dll_characteristics=pe_field(data, "dll_characteristics") & ~0x0100)
        check = self.dep(cleared)
        self.assertEqual(check["status"], "INFO")
        self.assertIn("AMD64", check["value"])
        self.assertIn("always run with DEP", check["detail"])
        self.assertTrue(parse_pe_slice(cleared, "x")["security_posture"]["dep_in_effect"])

    def test_arm_images_without_nx_compat_are_informational(self) -> None:
        base = fixture_bytes("synthetic_pe32")                       # PE32, NX_COMPAT clear
        self.assertEqual(self.dep(pe_patch(base, machine=0x01C4))["status"], "INFO")
        pe64 = fixture_bytes("synthetic_pe64")
        arm64 = pe_patch(pe64, machine=0xAA64, dll_characteristics=pe_field(pe64, "dll_characteristics") & ~0x0100)
        self.assertEqual(self.dep(arm64)["status"], "INFO")

    def test_32_bit_x86_without_nx_compat_still_fails(self) -> None:
        sl = parse_pe_slice(fixture_bytes("synthetic_pe32"), "x")
        self.assertEqual(checks_of(sl)["dep_nx"]["status"], "FAIL")
        self.assertFalse(sl["security_posture"]["dep_in_effect"])

    def test_nx_compat_set_passes_everywhere(self) -> None:
        self.assertEqual(self.dep(fixture_bytes("synthetic_pe64"))["status"], "PASS")
        pe32 = fixture_bytes("synthetic_pe32")
        self.assertEqual(self.dep(pe_patch(pe32, dll_characteristics=0x0100))["status"], "PASS")


# ============================================================================
# 7. SafeSEH is an x86-32 concept
# ============================================================================
class Defect07PeSafeSeh(unittest.TestCase):
    def seh(self, data: bytes) -> Dict[str, Any]:
        return checks_of(parse_pe_slice(data, "x.exe"))["seh"]

    def test_32_bit_arm_is_not_unprotected_seh(self) -> None:
        check = self.seh(pe_patch(fixture_bytes("synthetic_pe32"), machine=0x01C4))
        self.assertEqual(check["status"], "INFO")
        self.assertIn("Not applicable", check["value"])
        self.assertIn("ARMNT", check["value"])
        self.assertNotIn("Unprotected", check["value"])

    def test_64_bit_machines_are_not_applicable(self) -> None:
        for machine in (0x8664, 0xAA64):
            check = self.seh(pe_patch(fixture_bytes("synthetic_pe64"), machine=machine))
            self.assertEqual(check["status"], "INFO", hex(machine))
            self.assertIn("table-based", check["value"])

    def test_x86_32_is_judged_by_no_seh_and_the_handler_table(self) -> None:
        pe32 = fixture_bytes("synthetic_pe32")
        self.assertEqual((self.seh(pe32)["status"], self.seh(pe32)["value"]), ("WARN", "Unprotected 32-bit SEH"))
        no_seh = self.seh(pe_patch(pe32, dll_characteristics=0x0400))
        self.assertEqual((no_seh["status"], no_seh["value"]), ("PASS", "Protected (NO_SEH)"))

    def test_real_images(self) -> None:
        seen = 0
        data = real("pe_i386_safeseh")
        if data is not None:
            seen += 1
            sl = parse_pe_slice(data, "attach_x86.dll")
            check = checks_of(sl)["seh"]
            self.assertEqual(check["status"], "PASS")
            self.assertIn("SafeSEH table", check["value"])
            self.assertGreater(sl["pe_metadata"]["load_config"]["se_handler_count"], 0)
        data = real("pe_armnt_pdata")
        if data is not None:
            seen += 1
            self.assertEqual(checks_of(parse_pe_slice(data, "arm.dll"))["seh"]["status"], "INFO")
        if not seen:
            self.skipTest("no PE sample on this machine")


# ============================================================================
# 8. CFG: declared versus instrumented
# ============================================================================
class Defect08PeControlFlowGuard(unittest.TestCase):
    def cfg(self, data: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        sl = parse_pe_slice(data, "x.exe")
        return checks_of(sl)["cfg"], sl

    def load_config_offset(self, data: bytes) -> int:
        return parse_pe_slice(data, "x")["pe_metadata"]["load_config"]["abs_offset"]

    def test_declared_and_instrumented(self) -> None:
        check, sl = self.cfg(fixture_bytes("synthetic_pe64"))
        self.assertEqual(check["status"], "PASS")
        self.assertEqual(check["value"], "Declared and instrumented (1 valid call target)")
        lc = sl["pe_metadata"]["load_config"]
        self.assertEqual((lc["guard_flags"], lc["guard_cf_function_count"]), (0x500, 1))
        self.assertEqual(lc["guard_flags_decoded"], ["IMAGE_GUARD_CF_INSTRUMENTED", "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT"])
        self.assertTrue(sl["security_posture"]["cfg_declared"] and sl["security_posture"]["cfg_instrumented"])

    def test_declared_but_not_instrumented_is_not_a_pass(self) -> None:
        data = bytearray(fixture_bytes("synthetic_pe64"))
        struct.pack_into("<I", data, self.load_config_offset(bytes(data)) + 0x90, 0)        # GuardFlags = 0
        check, sl = self.cfg(bytes(data))
        self.assertEqual(check["status"], "WARN")
        self.assertEqual(check["value"], "Declared in the header, but not instrumented")
        self.assertTrue(sl["security_posture"]["cfg_declared"])
        self.assertFalse(sl["security_posture"]["cfg_instrumented"])

    def test_declared_without_a_load_configuration(self) -> None:
        check, _ = self.cfg(pe_set_directory(fixture_bytes("synthetic_pe64"), 10, 0, 0))
        self.assertEqual(check["status"], "WARN")
        self.assertIn("no load configuration directory", check["detail"])

    def test_a_load_configuration_too_short_for_the_guard_fields(self) -> None:
        data = bytearray(fixture_bytes("synthetic_pe64"))
        struct.pack_into("<I", data, self.load_config_offset(bytes(data)), 112)           # Size stops before the CFG fields
        check, sl = self.cfg(bytes(data))
        self.assertEqual(check["status"], "WARN")
        self.assertIn("too short", check["detail"])
        self.assertEqual(sl["pe_metadata"]["load_config"]["guard_flags"], 0, "fields past Size are not read")

    def test_instrumented_but_not_declared(self) -> None:
        data = fixture_bytes("synthetic_pe64")
        check, sl = self.cfg(pe_patch(data, dll_characteristics=pe_field(data, "dll_characteristics") & ~0x4000))
        self.assertEqual(check["status"], "INFO")
        self.assertIn("header flag clear", check["value"])
        self.assertFalse(sl["security_posture"]["cfg_declared"])

    def test_neither(self) -> None:
        check, _ = self.cfg(fixture_bytes("synthetic_pe32"))
        self.assertEqual((check["status"], check["value"]), ("INFO", "Not Enabled"))

    def test_real_images_against_llvm_readobj(self) -> None:
        readobj = find_tool("llvm-readobj")
        seen = 0
        for name in ("pe_amd64_signed_cfg", "pe_i386_safeseh", "pe_arm64_pdata"):
            data = real(name)
            if data is None or not readobj:
                continue
            seen += 1
            out = subprocess.run([readobj, "--coff-load-config", REAL[name]], capture_output=True, text=True, timeout=60).stdout
            flags = int(re.search(r"GuardFlags \[ \((0x[0-9A-Fa-f]+)\)", out).group(1), 16)
            count = int(re.search(r"GuardCFFunctionCount: (\d+)", out).group(1))
            size = int(re.search(r"\n\s*Size: (0x[0-9A-Fa-f]+)", out).group(1), 16)
            lc = parse_pe_slice(data, name)["pe_metadata"]["load_config"]
            self.assertEqual((lc["guard_flags"], lc["guard_cf_function_count"], lc["size"]), (flags, count, size), name)
        if not seen:
            self.skipTest("llvm-readobj or the PE samples are not available")


# ============================================================================
# 9. .pdata entries: 12 bytes on x64, 8 on ARM64 and ARM
# ============================================================================
class Defect09PeExceptionTable(unittest.TestCase):
    TABLE_RVA, TABLE_OFF = 0x2680, 0xE80            # unused bytes of the fixture's .rdata

    def with_table(self, machine: int, entries: bytes) -> Dict[str, Any]:
        data = bytearray(pe_patch(fixture_bytes("synthetic_pe64"), machine=machine))
        data[self.TABLE_OFF:self.TABLE_OFF + len(entries)] = entries
        return parse_pe_slice(pe_set_directory(bytes(data), 3, self.TABLE_RVA, len(entries)), "pdata.exe")

    def starts(self, sl: Dict[str, Any]) -> List[str]:
        return [f["vmaddr"] for f in sl["function_starts"] if f["name"].startswith("pdata_fn_")]

    def test_arm64_entries_are_8_bytes(self) -> None:
        # (BeginAddress, UnwindData) x 4. With a 12-byte stride the 2nd "function" would be
        # read from the middle of the table.
        table = b"".join(struct.pack("<II", rva, 0x00200011) for rva in (0x1004, 0x1010, 0x1020, 0x1030))
        sl = self.with_table(0xAA64, table)
        self.assertEqual(self.starts(sl), ["0x140001004", "0x140001010", "0x140001020", "0x140001030"])
        self.assertEqual(sl["pe_metadata"]["exception_table"], {"present": True, "entry_size": 8, "entries": 4})

    def test_32_bit_arm_entries_are_8_bytes_and_drop_the_thumb_bit(self) -> None:
        table = b"".join(struct.pack("<II", rva | 1, 0x00200011) for rva in (0x1004, 0x1010, 0x1020))
        sl = self.with_table(0x01C4, table)
        self.assertEqual(self.starts(sl), ["0x140001004", "0x140001010", "0x140001020"])
        self.assertEqual(sl["pe_metadata"]["exception_table"]["entry_size"], 8)

    def test_x64_entries_are_12_bytes(self) -> None:
        table = b"".join(struct.pack("<III", begin, begin + 8, 0x2690) for begin in (0x1004, 0x1010, 0x1020))
        sl = self.with_table(0x8664, table)
        self.assertEqual(self.starts(sl), ["0x140001004", "0x140001010", "0x140001020"])
        self.assertEqual(sl["pe_metadata"]["exception_table"], {"present": True, "entry_size": 12, "entries": 3})

    def test_real_tables_are_sorted_and_counted_by_the_right_stride(self) -> None:
        # .pdata is sorted by begin address: a wrong stride breaks the order immediately.
        seen = 0
        for name, stride in (("pe_arm64_pdata", 8), ("pe_armnt_pdata", 8), ("pe_amd64_signed_cfg", 12)):
            data = real(name)
            if data is None:
                continue
            seen += 1
            sl = parse_pe_slice(data, name)
            nt = struct.unpack_from("<I", data, 0x3C)[0]
            dirs = nt + 24 + (112 if struct.unpack_from("<H", data, nt + 24)[0] == 0x20B else 96)
            size = struct.unpack_from("<I", data, dirs + 3 * 8 + 4)[0]
            table = sl["pe_metadata"]["exception_table"]
            self.assertEqual((table["entry_size"], table["entries"]), (stride, size // stride), name)
            addrs = [int(f["vmaddr"], 16) for f in sl["function_starts"] if f["name"].startswith("pdata_fn_")]
            self.assertGreater(len(addrs), 100, name)
            self.assertEqual(addrs, sorted(addrs), name)
            self.assertEqual(len(set(addrs)), len(addrs), name)
        if not seen:
            self.skipTest("no PE sample with an exception table on this machine")

    def test_real_arm64_table_against_llvm_readobj(self) -> None:
        readobj = find_tool("llvm-readobj")
        data = real("pe_arm64_pdata")
        if not readobj or data is None:
            self.skipTest("llvm-readobj or the ARM64 PE sample is not available")
        out = subprocess.run([readobj, "--unwind", REAL["pe_arm64_pdata"]], capture_output=True, text=True, timeout=120).stdout
        theirs = [int(m, 16) for m in re.findall(r"Function: (0x[0-9A-Fa-f]+)", out)]
        sl = parse_pe_slice(data, "x")
        ours = [int(f["vmaddr"], 16) for f in sl["function_starts"] if f["name"].startswith("pdata_fn_")]
        self.assertGreater(len(theirs), 100)
        self.assertEqual(ours[:500], theirs[:500])


# ============================================================================
# 10. What "stripped" means for a PE
# ============================================================================
class Defect10PeSymbols(unittest.TestCase):
    def test_an_msvc_style_image_has_no_symbol_table_and_names_its_pdb(self) -> None:
        sl = parse_pe_slice(fixture_bytes("synthetic_pe64"), "x")
        self.assertTrue(sl["security_posture"]["stripped_symbols"])
        info = sl["pe_metadata"]["symbol_info"]
        self.assertFalse(info["coff_symbol_table"])
        self.assertTrue(info["pdb_referenced"])
        self.assertEqual(info["debug_directory_types"], ["IMAGE_DEBUG_TYPE_CODEVIEW"])
        state = sl["security_posture"]["symbols_state"]
        self.assertEqual(state, "No COFF symbol table; debug info in a separate PDB (synthetic_pe64.pdb)")

    def test_a_coff_symbol_table_means_not_stripped(self) -> None:
        data = fixture_bytes("synthetic_pe64")
        sl = parse_pe_slice(pe_patch(data, symtab=0x1400, nsyms=12), "x")
        self.assertFalse(sl["security_posture"]["stripped_symbols"])
        self.assertIn("COFF symbol table present (12 records)", sl["security_posture"]["symbols_state"])
        self.assertEqual(sl["pe_metadata"]["symbol_info"]["coff_symbol_count"], 12)
        # A pointer without a count (what Go's linker leaves behind) is not a symbol table.
        self.assertTrue(parse_pe_slice(pe_patch(data, symtab=0x1400, nsyms=0), "x")["security_posture"]["stripped_symbols"])

    def test_no_debug_directory_and_the_stripped_characteristics(self) -> None:
        sl = parse_pe_slice(fixture_bytes("synthetic_pe32"), "x")
        self.assertEqual(sl["security_posture"]["symbols_state"], "No COFF symbol table; no debug directory")
        flagged = parse_pe_slice(pe_patch(fixture_bytes("synthetic_pe32"), characteristics=0x0102 | 0x0200), "x")
        self.assertTrue(flagged["pe_metadata"]["symbol_info"]["debug_stripped_flag"])
        self.assertTrue(flagged["security_posture"]["symbols_state"].endswith("IMAGE_FILE_DEBUG_STRIPPED set"))

    def test_the_provenance_label_is_the_pe_statement_not_unstripped(self) -> None:
        router, service = make_router()
        for preset in ("synthetic_pe64", "synthetic_pe32"):
            sl = service.load_file(FIXTURES[preset])["slices"][0]
            level = sl["semantic_layers"]["provenance"]["strip_level"]
            self.assertEqual(level, sl["security_posture"]["symbols_state"])
            self.assertNotIn("Unstripped", level)

    def test_real_images_agree_with_llvm_readobj(self) -> None:
        readobj = find_tool("llvm-readobj")
        seen = 0
        for name in ("pe_amd64_signed_cfg", "pe_i386_safeseh", "pe_arm64_pdata"):
            data = real(name)
            if data is None or not readobj:
                continue
            seen += 1
            out = subprocess.run([readobj, "--file-headers", REAL[name]], capture_output=True, text=True, timeout=60).stdout
            count = int(re.search(r"SymbolCount: (\d+)", out).group(1))
            info = parse_pe_slice(data, name)["pe_metadata"]["symbol_info"]
            self.assertEqual(info["coff_symbol_table"], count > 0, name)
            self.assertEqual(info["debug_stripped_flag"], "IMAGE_FILE_DEBUG_STRIPPED" in out, name)
        if not seen:
            self.skipTest("llvm-readobj or the PE samples are not available")


# ============================================================================
# 11. Capabilities: whole API names
# ============================================================================
class Defect11CapabilityMatching(unittest.TestCase):
    RULES = {r["id"]: r for r in semantics.CAPABILITY_RULES}

    def hit(self, rule: str, symbol: str, fmt: str = "") -> bool:
        names, objc_class = semantics.canonical_api_names(symbol, fmt)
        return semantics.match_api(self.RULES[rule], names, objc_class) is not None

    def test_substrings_do_not_match(self) -> None:
        for rule, symbol in (("process", "GetSystemInfo"), ("process", "ecosystem"), ("process", "system_profiler_init"),
                             ("process", "_ZNSt3__112system_errorD1Ev"), ("process", "CreateProcessor"),
                             ("filesystem", "thermostat"), ("filesystem", "statistics"), ("filesystem", "mystat"),
                             ("filesystem", "reopen_log"), ("network", "rebind"), ("network", "boost_bind"),
                             ("network", "unbind_all"), ("network", "disconnect_all"), ("network", "curling"),
                             ("crypto", "Cryptography"), ("crypto", "decrypt_buffer_sha256"), ("dynamic_loading", "my_dlopen"),
                             ("anti_analysis", "sysctl_helper"), ("ipc_system", "ioctl_wrapper")):
            self.assertFalse(self.hit(rule, symbol), (rule, symbol))

    def test_whole_names_match(self) -> None:
        for rule, symbol in (("process", "system"), ("filesystem", "stat"), ("network", "bind"), ("network", "connect"),
                             ("process", "fork"), ("memory_injection", "mprotect"), ("dynamic_loading", "dlopen"),
                             ("anti_analysis", "ptrace"), ("ipc_system", "ioctl"), ("crypto", "EVP_EncryptInit_ex"),
                             ("network", "curl_easy_perform"), ("crypto", "CryptEncrypt"), ("crypto", "BCryptOpenAlgorithmProvider"),
                             ("dynamic_loading", "objc_msgSendSuper2")):
            self.assertTrue(self.hit(rule, symbol), (rule, symbol))

    def test_decorations_are_removed_deliberately(self) -> None:
        self.assertTrue(self.hit("process", "_system", "macho"), "Mach-O: one leading underscore")
        self.assertFalse(self.hit("process", "_system", "elf"), "that underscore is not a decoration in ELF")
        self.assertFalse(self.hit("process", "__system", "macho"), "only one underscore is the decoration")
        self.assertTrue(self.hit("filesystem", "_fopen$UNIX2003", "macho"))
        self.assertTrue(self.hit("filesystem", "_stat$INODE64", "macho"))
        self.assertTrue(self.hit("filesystem", "puts@GLIBC_2.2.5", "elf"))
        self.assertTrue(self.hit("filesystem", "fopen@@GLIBC_2.2.5", "elf"))
        self.assertTrue(self.hit("filesystem", "__printf_chk", "elf"), "the _FORTIFY_SOURCE variant of printf")
        self.assertTrue(self.hit("process", "__imp_CreateProcessW", "pe"))
        self.assertTrue(self.hit("filesystem", "_CreateFileA@28", "pe"), "32-bit stdcall decoration")
        self.assertTrue(self.hit("process", "_OBJC_CLASS_$_NSTask", "macho"))
        self.assertFalse(self.hit("process", "_OBJC_CLASS_$_NSTaskManager", "macho"))

    def test_ansi_and_wide_suffixes_apply_to_win32_names_only(self) -> None:
        for symbol in ("CreateProcessA", "CreateProcessW", "CreateProcess"):
            self.assertTrue(self.hit("process", symbol), symbol)
        self.assertFalse(self.hit("process", "CreateProcessX"))
        self.assertFalse(self.hit("process", "systemW"), "a POSIX name does not take a Win32 suffix")
        self.assertFalse(self.hit("network", "bindA"))
        self.assertTrue(self.hit("process", "NtCreateThreadEx") and self.hit("process", "ZwCreateThreadEx"))

    def test_a_file_whose_imports_merely_contain_api_names_has_no_capability(self) -> None:
        names = ("ecosystem", "thermostat", "rebind", "GetSystemInfo", "printf_hook", "my_socket_pool", "_ZNSt6system5errorD1Ev")
        sl = parse_elf_slice(elf(needed=("libc.so.6",), imports=tuple((n, 0) for n in names)), "x")
        caps = semantics.build_capabilities_and_strings(sl)
        self.assertEqual([c["id"] for c in caps["categories"]], [])
        self.assertEqual(caps["total_matched_indicators"], 0)

    def test_real_imports_are_found_and_labelled_as_imports(self) -> None:
        sl = parse_elf_slice(elf(needed=("libc.so.6",), imports=(("system", 0), ("bind", 0), ("stat", 0))), "x")
        caps = semantics.build_capabilities_and_strings(sl)
        by_id = {c["id"]: c for c in caps["cards"]}
        self.assertEqual({c["id"] for c in caps["categories"]}, {"process", "network", "filesystem"})
        for cap, api in (("process", "system"), ("network", "bind"), ("filesystem", "stat")):
            self.assertEqual([(e["api"], e["kind"]) for e in by_id[cap]["evidence"]], [(api, "import")])
            self.assertEqual(by_id[cap]["strength"], "import")

    def test_string_evidence_is_separate_and_weaker(self) -> None:
        # Names as a program would pass to GetProcAddress / dlsym, plus ordinary words.
        rodata = b"VirtualProtect\0connect\0system\0pthread_create\0this string mentions VirtualAlloc in a sentence\0"
        sl = parse_elf_slice(elf(needed=("libc.so.6",), imports=(("puts", 0),), rodata=rodata), "x")
        caps = semantics.build_capabilities_and_strings(sl)
        by_id = {c["id"]: c for c in caps["cards"]}
        memory = by_id["memory_injection"]
        self.assertFalse(memory["detected"], "a string is not an import")
        self.assertEqual((memory["strength"], memory["evidence"]), ("strings", []))
        self.assertEqual([(e["api"], e["kind"]) for e in memory["weak_evidence"]], [("VirtualProtect", "string")])
        self.assertEqual([e["api"] for e in by_id["process"]["weak_evidence"]], ["pthread_create"],
                         "'system' is an ordinary word; a longer string that contains a name is not a name")
        self.assertEqual(by_id["network"]["weak_evidence"], [], "'connect' is an ordinary word")
        self.assertNotIn("memory_injection", [c["id"] for c in caps["categories"]])
        self.assertIn("memory_injection", [c["id"] for c in caps["weak_categories"]])
        self.assertEqual([c["id"] for c in caps["categories"]], ["filesystem"])

    def test_fixtures(self) -> None:
        router, service = make_router()
        pe = service.load_file(FIXTURES["synthetic_pe64"])["slices"][0]["semantic_layers"]["capabilities"]
        got = {c["id"]: [e["api"] for e in c["evidence"]] for c in pe["categories"]}
        self.assertEqual(got, {"process": ["CreateProcessW"], "memory_injection": ["VirtualAlloc"],
                               "network": ["WSAStartup"], "dynamic_loading": ["GetProcAddress"]})
        elf64 = service.load_file(FIXTURES["synthetic_elf64"])["slices"][0]["semantic_layers"]["capabilities"]
        self.assertEqual({c["id"]: [e["api"] for e in c["evidence"]] for c in elf64["categories"]},
                         {"filesystem": ["puts"], "network": ["socket"]})

    def test_frontend_shows_the_weak_evidence_apart(self) -> None:
        with open(os.path.join(WORKSPACE_ROOT, "static", "app.js"), "r", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("caps.weak_categories", source)
        self.assertIn("Named only in strings", source)


# ============================================================================
# 12. Guided tasks: one defensible answer
# ============================================================================
class Defect12GuidedTasks(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.router, cls.service = make_router()

    def task(self, doc: Dict[str, Any], tour_id: str, task_id: str, index: int = 0) -> Optional[Dict[str, Any]]:
        built = L.build_tour(tour_id, doc, doc["slices"][index])
        return next((s["task"] for s in built["steps"] if s["task"] and s["task"]["id"] == task_id), None)

    def preset(self, name: str) -> Dict[str, Any]:
        return self.service.load_file(FIXTURES[name])

    # ---- le_value -------------------------------------------------------------------------
    def test_a_big_endian_elf_field_is_read_big_endian(self) -> None:
        doc = upload(self.router, elf(machine=20, little=False, is64=False, e_type=2), "ppc32.elf")     # EM_PPC = 20
        self.assertEqual(doc["slices"][0]["overview"]["endianness"], "Big-Endian")
        task = self.task(doc, "first-contact", "le")
        self.assertEqual(task["values"]["bytes"], "00 14")
        self.assertEqual(task["expect"], 20, "00 14 in a big-endian file is 0x14, not 0x1400")
        self.assertIn("big-endian", task["prompt"])
        step = next(s for s in L.build_tour("first-contact", doc, doc["slices"][0])["steps"] if s["id"] == "endian")
        self.assertIn("This file is big-endian", step["text"])
        self.assertIn("left to right", step["text"])

    def test_little_endian_files_are_unchanged(self) -> None:
        task = self.task(self.preset("synthetic_elf64"), "first-contact", "le")
        self.assertEqual(task["expect"], 62)
        self.assertIn("little-endian", task["prompt"])
        self.assertEqual(self.task(self.preset("synthetic_universal"), "first-contact", "le")["expect"], 0xFEEDFACF)

    # ---- is_pie ---------------------------------------------------------------------------
    def test_pe_with_stripped_relocations_does_not_opt_in_to_aslr(self) -> None:
        data = fixture_bytes("synthetic_pe64")
        doc = self.preset("synthetic_pe64")
        self.assertIs(resolve_mod.is_pie(doc["slices"][0]), True)
        stripped = upload(self.router, pe_patch(data, characteristics=pe_field(data, "characteristics") | 0x0001), "stripped.exe")
        self.assertTrue(pe_field(data, "dll_characteristics") & 0x40, "DYNAMIC_BASE is still set")
        self.assertIs(resolve_mod.is_pie(stripped["slices"][0]), False)
        task = self.task(stripped, "hardening-audit", "pie")
        self.assertEqual(task["correct"], 1)
        self.assertIn("relocations were stripped", task["options"][1])
        # The audit agrees with the task.
        self.assertFalse(stripped["slices"][0]["security_posture"]["pie"])

    def test_the_pie_question_is_about_the_header_so_arm64_without_pie_has_one_answer(self) -> None:
        doc = upload(self.router, macho(filetype=2, flags=0x85, cputype=CPU_TYPE_ARM64), "nopie")
        task = self.task(doc, "hardening-audit", "pie")
        self.assertEqual(task["correct"], 1)
        self.assertIn("MH_PIE", task["prompt"])
        for option in task["options"]:
            # "It is loaded at the address it was linked for" is false for arm64: the kernel refuses it.
            self.assertNotIn("is loaded at the address", option)
            self.assertIn("MH_PIE", option)
        self.assertEqual(task["options"][1], "No. MH_PIE is clear: the header does not allow the main executable to be moved.")

    def test_the_pie_task_is_not_offered_where_mh_pie_means_nothing(self) -> None:
        doc = upload(self.router, macho(filetype=6, flags=0x85), "lib.dylib")
        self.assertIsNone(self.task(doc, "hardening-audit", "pie"))

    # ---- entry_kind -----------------------------------------------------------------------
    def test_entry_kind_asks_for_the_definition_and_has_distinct_answers(self) -> None:
        for preset, want in (("synthetic_elf64", 1), ("synthetic_elf32", 1), ("synthetic_pe64", 2), ("synthetic_universal", 0), ("synthetic_firmware", 1)):
            task = self.task(self.preset(preset), "entry-point", "kind")
            self.assertEqual(task["correct"], want, preset)
            self.assertIn("define", task["prompt"])
            self.assertEqual(len(set(task["options"])), 3)
        options = self.task(self.preset("synthetic_elf64"), "entry-point", "kind")["options"]
        # For an ET_DYN file "an offset from the image base" used to be as defensible as "a virtual
        # address". The RVA answer now names the ImageBase header field, which ELF does not have.
        self.assertEqual(self.preset("synthetic_elf64")["slices"][0]["header"]["filetype_name"], "ET_DYN")
        self.assertIn("ImageBase field of the header", options[2])
        self.assertIn("the address itself", options[1])

    # ---- make_writable --------------------------------------------------------------------
    def test_make_writable_targets_the_code_segment(self) -> None:
        for preset in ("synthetic_elf64", "synthetic_pe64", "synthetic_universal", "synthetic_firmware"):
            doc = self.preset(preset)
            sl = doc["slices"][0]
            task = self.task(doc, "permissions", "writable")
            self.assertIsNotNone(task, preset)
            seg = sl["segments"][int(task["show"]["node_id"][4:])]
            self.assertIn("x", seg["initprot"], "%s: %s is not a code segment" % (preset, seg["segname"]))
            self.assertNotIn("w", seg["initprot"], preset)
            self.assertEqual(task["values"]["seg"], seg["segname"])
        elf64 = self.preset("synthetic_elf64")["slices"][0]
        first_readonly = next(s for s in elf64["segments"] if s["initprot"] == "r--")
        task = self.task(self.preset("synthetic_elf64"), "permissions", "writable")
        self.assertNotEqual(task["values"]["seg"], first_readonly["segname"], "not the segment that maps the headers")
        self.assertEqual(task["expect"], 7)                 # PF_R | PF_X | PF_W

    def test_make_writable_is_not_offered_without_a_read_only_code_segment(self) -> None:
        doc = self.preset("synthetic_pe32")                 # its only executable section is already rwx
        self.assertEqual([s["initprot"] for s in doc["slices"][0]["segments"] if "x" in s["initprot"]], ["rwx"])
        self.assertIsNone(self.task(doc, "permissions", "writable"))

    # ---- every choice task, every fixture ---------------------------------------------------
    def test_every_choice_task_has_distinct_options_and_one_marked_answer(self) -> None:
        count = 0
        for preset in FIXTURES:
            doc = self.preset(preset)
            for index, sl in enumerate(doc["slices"]):
                for tour in tours_mod.TOURS:
                    built = L.build_tour(tour["id"], doc, sl)
                    for step in (built or {}).get("steps", []):
                        task = step.get("task")
                        if not task or task["kind"] != "choice":
                            continue
                        count += 1
                        where = "%s[%d] %s/%s" % (preset, index, tour["id"], task["id"])
                        self.assertEqual(len(set(task["options"])), len(task["options"]), where)
                        self.assertTrue(0 <= task["correct"] < len(task["options"]), where)
        self.assertGreater(count, 20)


# ============================================================================
# 13. Patch-lab consequences fire only where the evidence applies
# ============================================================================
class Defect13PatchConsequences(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.router, cls.service = make_router()

    def notes_for_initprot(self, segname: str, value: int) -> Dict[str, str]:
        doc = self.service.load_file(FIXTURES["synthetic_universal"])
        seg = next(s for s in doc["slices"][0]["segments"] if s["segname"] == segname)
        field = named_field(seg["fields"], "initprot")
        out = patched(self.router, "preset:synthetic_universal",
                      [{"offset": field["abs_offset"], "hex": struct.pack("<I", value).hex()}])
        return {n["id"]: n["text"] for n in out["diff"]["consequences"]}

    def test_the_general_statement_about_w_x_makes_no_claim_about_dyld(self) -> None:
        self.assertNotIn("dyld", labs_patch.TEXT["macho.segment_wx"]["text"])
        self.assertNotIn("dyld", labs_patch.TEXT["macho.segment_wx"]["basis"])

    def test_dyld_is_mentioned_for_text_with_its_own_rule(self) -> None:
        notes = self.notes_for_initprot("__TEXT", 7)
        self.assertIn("macho.segment_wx", notes)
        text = notes["macho.dyld_segment_perms"]
        self.assertIn("__TEXT must be exactly r-x, and it is now rwx", text)
        self.assertIn("2019", text)

    def test_dyld_is_not_mentioned_for_a_segment_it_has_no_rule_for(self) -> None:
        doc = self.service.load_file(FIXTURES["synthetic_universal"])
        other = next(s["segname"] for s in doc["slices"][0]["segments"]
                     if s["segname"] not in labs_patch._DYLD_SEGMENT_PERMS and s["segname"] != "__PAGEZERO" and "x" not in s["initprot"])
        notes = self.notes_for_initprot(other, 7)
        self.assertIn("macho.segment_wx", notes, other)
        self.assertNotIn("macho.dyld_segment_perms", notes, other)

    def test_the_data_rule_is_stated_as_its_own_rule(self) -> None:
        notes = self.notes_for_initprot("__DATA", 7)
        self.assertIn("__DATA must be exactly rw-", notes["macho.dyld_segment_perms"])
        self.assertIn("2025", notes["macho.dyld_segment_perms"])
        # The dyld rule is about any deviation, not only W+X: __TEXT made read-only trips it too.
        notes = self.notes_for_initprot("__TEXT", 1)
        self.assertIn("macho.dyld_segment_perms", notes)
        self.assertNotIn("macho.segment_wx", notes)

    def pe_notes(self, section: str) -> List[str]:
        doc = self.service.load_file(FIXTURES["synthetic_pe64"])
        sect = next(s for seg in doc["slices"][0]["segments"] for s in seg["sections"] if s["sectname"] == section)
        field = named_field(sect["fields"], "SizeOfRawData")
        out = patched(self.router, "preset:synthetic_pe64", [{"offset": field["abs_offset"], "hex": struct.pack("<I", 0x100000).hex()}])
        return [n["id"] for n in out["diff"]["consequences"]]

    def test_image_refused_is_claimed_for_the_last_section_only(self) -> None:
        self.assertIn("pe.section_bounds", self.pe_notes(".reloc"))             # the last section of the table
        for section in (".text", ".rdata"):
            notes = self.pe_notes(section)
            self.assertNotIn("pe.section_bounds", notes, section)
            self.assertIn("pe.section_bounds_other", notes, section)
        other = labs_patch.TEXT["pe.section_bounds_other"]
        self.assertIn("has not been established", other["text"])
        self.assertNotIn("is refused", other["text"])
        self.assertIn("Unverified", other["basis"])
        self.assertIn("last section", labs_patch.TEXT["pe.section_bounds"]["title"])


    def test_answers_do_not_depend_on_how_the_document_was_transported(self) -> None:
        # A document parsed in a worker process, or by the in-browser engine, reaches the lab as
        # JSON: lists that the parser shared between two structures are then equal, not identical.
        for preset, path in FIXTURES.items():
            data = fixture_bytes(preset)
            doc = self.service.load_file(path)
            copy = json.loads(json.dumps(doc))
            for index in range(len(doc["slices"])):
                self.assertEqual(labs_patch.experiment_catalogue(copy, data, index),
                                 labs_patch.experiment_catalogue(doc, data, index), "%s[%d]" % (preset, index))
        # ... and the "last section" consequence is recognised in such a document too.
        data = fixture_bytes("synthetic_pe64")
        before = self.service.load_file(FIXTURES["synthetic_pe64"])
        reloc = next(s for seg in before["slices"][0]["segments"] for s in seg["sections"] if s["sectname"] == ".reloc")
        patch = {"offset": named_field(reloc["fields"], "SizeOfRawData")["abs_offset"], "hex": struct.pack("<I", 0x100000).hex()}
        patches = labs_patch.parse_patches([patch], len(data), 65536)
        after_data = labs_patch.apply_patches(data, patches)
        after = upload(self.router, after_data, "after.exe")
        diff = labs_patch.diff_documents(json.loads(json.dumps(before)), data, json.loads(json.dumps(after)), after_data,
                                         mode="patch", patches=patches)
        notes = [n["id"] for n in diff["consequences"]]
        self.assertIn("pe.section_bounds", notes)
        self.assertNotIn("pe.section_bounds_other", notes)


# ============================================================================
# 14. Mach-O header flags
# ============================================================================
class Defect14MachOHeaderFlags(unittest.TestCase):
    def test_implicit_pagezero_is_decoded(self) -> None:
        self.assertEqual(constants.MH_IMPLICIT_PAGEZERO, 0x10000000)
        names, bits = constants.decode_header_flags(0x10200085)
        self.assertIn("MH_IMPLICIT_PAGEZERO", names)
        self.assertEqual(names, ["MH_NOUNDEFS", "MH_DYLDLINK", "MH_TWOLEVEL", "MH_PIE", "MH_IMPLICIT_PAGEZERO"])
        sl = macho_slice(flags=0x10200085)
        self.assertIn("MH_IMPLICIT_PAGEZERO", sl["header"]["flags_decoded"])

    def test_every_bit_of_the_flag_word_that_the_table_names_is_distinct(self) -> None:
        masks = [m for m, _n, _d in constants.MH_HEADER_FLAGS]
        self.assertEqual(len(masks), len(set(masks)))
        for mask in masks:
            self.assertEqual(mask & (mask - 1), 0, hex(mask))
        self.assertEqual(len({n for _m, n, _d in constants.MH_HEADER_FLAGS}), len(masks))

    def test_table_matches_the_sdk_header(self) -> None:
        try:
            sdk = subprocess.run(["xcrun", "--show-sdk-path"], capture_output=True, text=True, timeout=30).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            sdk = ""
        header = os.path.join(sdk, "usr", "include", "mach-o", "loader.h") if sdk else ""
        if not header or not os.path.isfile(header):
            self.skipTest("no macOS SDK on this machine")
        with open(header, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        start = text.index("Constants for the flags field of the mach_header")
        end = text.index("struct load_command", start)
        theirs = {name: int(value, 16) for name, value in re.findall(r"#define\s+(MH_[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)", text[start:end])}
        ours = {name: mask for mask, name, _d in constants.MH_HEADER_FLAGS}
        self.assertGreater(len(theirs), 25)
        self.assertEqual(ours, theirs)
        # File types, from the same header.
        types = {name: int(value, 16) for name, value in re.findall(r"#define\s+(MH_[A-Z_]+)\s+(0x[0-9a-fA-F]+)\s", text[:start])
                 if not name.startswith(("MH_MAGIC", "MH_CIGAM"))}
        self.assertEqual({info[0]: value for value, info in constants.FILETYPE_INFO.items()}, types)

    def test_the_javascript_copy_has_the_flag(self) -> None:
        with open(os.path.join(WORKSPACE_ROOT, "static", "js", "labs-encoding.js"), "r", encoding="utf-8") as handle:
            self.assertIn("F(0x10000000, 'MH_IMPLICIT_PAGEZERO'", handle.read())


# ============================================================================
# 15. Two stack-canary idioms
# ============================================================================
class Defect15CanaryIdioms(unittest.TestCase):
    def ids(self, mnemonic: str, operands: str, comment: str) -> List[str]:
        rows = [{"mnemonic": mnemonic, "operands": operands, "comment": comment}]
        return [a["id"] for a in insn_mod.annotate(rows, "x86")]

    def test_the_failure_routine_and_the_check_routine_are_different_idioms(self) -> None:
        self.assertEqual(self.ids("call", "0x401040", "-> __stack_chk_fail"), ["x86-canary-fail"])
        self.assertEqual(self.ids("call", "qword ptr [rip + 0x2fe2]", "imp.___stack_chk_fail"), ["x86-canary-fail"])
        self.assertEqual(self.ids("call", "0x140001a00", "-> __report_gsfailure"), ["x86-canary-fail"])
        self.assertEqual(self.ids("call", "0x140001a00", "-> __security_check_cookie"), ["x86-gs-cookie-check"])

    def test_texts_say_what_each_one_is(self) -> None:
        by_id = {i["id"]: i for i in insn_mod.IDIOMS}
        fail, check = by_id["x86-canary-fail"], by_id["x86-gs-cookie-check"]
        self.assertNotIn("__security_check_cookie", fail["text"])
        self.assertIn("only when", fail["text"].lower())
        self.assertIn("does not return", fail["text"])
        self.assertIn("before every return", check["text"])
        self.assertIn("Not a failure path", check["text"])
        self.assertIn("returns normally", check["text"])
        self.assertNotIn("failure", check["title"].lower())
        self.assertEqual((fail["concept"], check["concept"], check["arch"]), ("stack-canaries", "stack-canaries", "x86"))

    def test_the_new_idiom_is_published_to_the_frontend(self) -> None:
        router, _service = make_router()
        resp, data = call(router, "GET", "/api/learn/instructions")
        self.assertEqual(resp.status, 200)
        ids = [i["id"] for i in data["idioms"]]
        self.assertIn("x86-gs-cookie-check", ids)
        self.assertLess(ids.index("x86-canary-fail"), ids.index("x86-canary-load"))
        self.assertEqual(L.validate_content() if hasattr(L, "validate_content") else [], [])


# ============================================================================
# 16. Architectures without a decoder
# ============================================================================
class Defect16UnsupportedArchitectures(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.router, cls.service = make_router()

    def assert_not_disassembled(self, data: bytes, name: str, arch: str) -> None:
        doc = upload(self.router, data, name)
        sl = doc["slices"][0]
        self.assertEqual(sl["arch_name"], arch)
        resp, listing = call(self.router, "GET", "/api/disassemble", {"doc": doc["doc_id"], "count": "40"})
        self.assertEqual(resp.status, 200)
        self.assertEqual(listing["instructions"], [], "%s code must not be shown as another architecture's instructions" % arch)
        self.assertIs(listing["supported"], False)
        self.assertIsNone(listing["decoder"])
        self.assertIn("does not disassemble", listing["unsupported_reason"])
        self.assertIn(arch, listing["unsupported_reason"])
        entry = sl["overview"]["entry_point_abs_offset"] or 0
        resp, decoded = call(self.router, "GET", "/api/decode", {"doc": doc["doc_id"], "offset": str(entry)})
        self.assertEqual(resp.status, 200)
        prim = decoded["primitives"]
        self.assertIsNone(prim["insn_arch"])
        self.assertEqual((prim["arm64_insn"], prim["x86_insn"]), ("N/A", "N/A"))
        self.assertIn("not disassembled", prim["insn_note"])
        self.assertIsNone(insn_mod.arch_family(arch), "and Learn mode has no instruction help for it")

    def test_big_endian_ppc32_elf(self) -> None:
        # b 0x10 ; blr -- real PowerPC words, which as A64 would be nonsense.
        self.assert_not_disassembled(elf(machine=20, little=False, is64=False, e_type=2, text=bytes.fromhex("480000104e800020") * 4),
                                     "ppc32.elf", "ppc")

    def test_other_machines(self) -> None:
        for machine, is64, arch in ((40, False, "arm"), (243, True, "riscv64"), (243, False, "riscv32"), (8, False, "mips"), (21, True, "ppc64")):
            self.assert_not_disassembled(elf(machine=machine, is64=is64, e_type=2), arch + ".elf", arch)

    def test_pe_and_macho_machines(self) -> None:
        self.assert_not_disassembled(pe_patch(fixture_bytes("synthetic_pe32"), machine=0x01C4), "armnt.exe", "arm")
        self.assert_not_disassembled(macho(cputype=12, cpusubtype=9, flags=0x85), "armv7.macho", "armv7")

    def test_a_real_32_bit_arm_elf(self) -> None:
        data = real("elf_arm32")
        if data is None:
            self.skipTest("the 32-bit ARM ELF sample is not on this machine")
        self.assert_not_disassembled(data, "jb_zip_unarchiver", "arm")

    def test_supported_architectures_still_decode(self) -> None:
        for preset, family in (("synthetic_elf64", "x86"), ("synthetic_pe32", "x86"), ("synthetic_firmware", "arm64")):
            resp, listing = call(self.router, "GET", "/api/disassemble", {"doc": "preset:" + preset, "count": "8"})
            self.assertGreater(len(listing["instructions"]), 0, preset)
            self.assertNotIn("unsupported_reason", listing)
            resp, decoded = call(self.router, "GET", "/api/decode", {"doc": "preset:" + preset, "offset": "0"})
            self.assertEqual(decoded["primitives"]["insn_arch"], family)
        for name, want in (("arm64", "arm64"), ("arm64e", "arm64"), ("arm64_32", "arm64"), ("x86_64", "x86"), ("x86_64h", "x86"),
                           ("i386", "x86"), ("arm", None), ("armv7", None), ("riscv64", None), ("ppc", None), ("mips", None),
                           ("elf_mach_99", None), ("pe_mach_0x1234", None), ("", None)):
            self.assertEqual(disasm.instruction_set(name), want, name)

    def test_frontend_shows_the_reason_and_does_not_pick_a_decoder_by_name(self) -> None:
        with open(os.path.join(WORKSPACE_ROOT, "static", "app.js"), "r", encoding="utf-8") as handle:
            app = handle.read()
        self.assertIn("data?.unsupported_reason", app)
        self.assertIn("p.insn_arch === 'arm64'", app)
        self.assertNotIn("/arm/i.test(str(slice.arch_name))", app, "a 32-bit ARM file was previewed with the A64 decoder")
        with open(os.path.join(WORKSPACE_ROOT, "static", "js", "labs-encoding.js"), "r", encoding="utf-8") as handle:
            lab = handle.read()
        self.assertIn("fileArchKnown", lab)
        self.assertIn("which is not disassembled here", lab)


# ============================================================================
# 17. Deployment files copy what the server loads
# ============================================================================
class Defect17Deployment(unittest.TestCase):
    def test_systemd_install_steps_include_the_site_layer(self) -> None:
        with open(os.path.join(WORKSPACE_ROOT, "deploy", "binarystudio.service"), "r", encoding="utf-8") as handle:
            text = handle.read()
        copied = " ".join(line for line in text.splitlines() if line.startswith("#   sudo cp") or line.startswith("#   sudo mkdir"))
        for needed in ("binary_viewer.py", "backend", "static", "fixtures", "tools/site_pages.py", "/opt/binarystudio/tools"):
            self.assertIn(needed, copied)

    def test_the_install_steps_produce_a_tree_the_server_starts_from(self) -> None:
        with open(os.path.join(WORKSPACE_ROOT, "deploy", "binarystudio.service"), "r", encoding="utf-8") as handle:
            lines = [l[1:].strip() for l in handle.read().splitlines() if l.startswith("#   sudo")]
        with tempfile.TemporaryDirectory() as dest:
            for line in lines:
                parts = line.replace("sudo ", "").replace("/opt/binarystudio", dest).split()
                if parts[0] == "mkdir":
                    os.makedirs(parts[-1], exist_ok=True)
                elif parts[0] == "cp" and "systemd" not in line:
                    sources, target = [p for p in parts[1:-1] if not p.startswith("-")], parts[-1]
                    for src in sources:
                        full = os.path.join(WORKSPACE_ROOT, src)
                        if os.path.isdir(full):
                            shutil.copytree(full, os.path.join(target, os.path.basename(src)),
                                            ignore=shutil.ignore_patterns("__pycache__"))
                        else:
                            shutil.copy(full, target)
            self.assertTrue(os.path.isfile(os.path.join(dest, "tools", "site_pages.py")))
            self.assertTrue(os.path.isdir(os.path.join(dest, "backend", "learn")))
            probe = ("import sys; sys.path.insert(0, %r)\n"
                     "from backend.runtime import RuntimeConfig\n"
                     "from backend.service import AnalysisService\n"
                     "from backend.api import EventLog\n"
                     "from backend import server\n"
                     "import io\n"
                     "cfg = RuntimeConfig('public')\n"
                     "site = server._load_site_layer(%r, cfg, AnalysisService(%r, cfg), EventLog(stream=io.StringIO()))\n"
                     "print('site-layer', site is not None)\n") % (dest, dest, dest)
            out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=120, cwd=dest)
            self.assertIn("site-layer True", out.stdout, out.stderr[-600:])

    def test_dockerfile_copies_the_same_set(self) -> None:
        with open(os.path.join(WORKSPACE_ROOT, "Dockerfile"), "r", encoding="utf-8") as handle:
            copies = " ".join(l for l in handle.read().splitlines() if l.startswith("COPY"))
        for needed in ("binary_viewer.py", "backend/", "static/", "tools/site_pages.py", "fixtures/"):
            self.assertIn(needed, copies)
        with open(os.path.join(WORKSPACE_ROOT, "deploy", "docker-compose.yml"), "r", encoding="utf-8") as handle:
            compose = handle.read()
        self.assertIn("dockerfile: Dockerfile", compose)
        self.assertIn("context: ..", compose)


# ============================================================================
# 18. No inline styles in first-party frontend code
# ============================================================================
class Defect18InlineStyles(unittest.TestCase):
    INLINE = re.compile(r"""style\s*=\s*["'`]|<style[\s>]|setAttribute\(\s*['"]style['"]|createElement\(\s*['"]style['"]""")

    def sources(self) -> List[str]:
        static = os.path.join(WORKSPACE_ROOT, "static")
        out = [os.path.join(static, n) for n in os.listdir(static) if n.endswith((".html", ".js"))]
        for sub in ("js", "wasm"):
            folder = os.path.join(static, sub)
            if os.path.isdir(folder):
                out += [os.path.join(folder, n) for n in os.listdir(folder) if n.endswith((".js", ".html", ".mjs"))]
        out += [os.path.join(WORKSPACE_ROOT, "tools", n) for n in ("site_pages.py", "build_static.py")]
        return [p for p in out if os.path.isfile(p)]

    def test_no_style_attribute_or_style_element_anywhere(self) -> None:
        found = []
        for path in self.sources():
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle, 1):
                    if self.INLINE.search(line) and "no inline style" not in line:
                        found.append("%s:%d: %s" % (os.path.relpath(path, WORKSPACE_ROOT), number, line.strip()[:120]))
        self.assertEqual(found, [])
        self.assertGreater(len(self.sources()), 8)

    def test_the_csp_comment_no_longer_says_inline_styles_are_used(self) -> None:
        with open(os.path.join(WORKSPACE_ROOT, "backend", "runtime.py"), "r", encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn("because the UI uses inline style attributes", text)


# ============================================================================
# Smaller items
# ============================================================================
class Arm64eSubtypes(unittest.TestCase):
    def test_subtype_12_is_an_arm64e_slice(self) -> None:
        arch, _cpu, sub, display = constants.decode_cpu_arch(CPU_TYPE_ARM64, 0x8000000C)
        self.assertEqual(arch, "arm64e.x1", "the name lipo and file(1) give this slice")
        self.assertEqual(constants.decode_cpu_arch(CPU_TYPE_ARM64, 0x80000002)[0], "arm64e")
        self.assertEqual(disasm.instruction_set(arch), "arm64", "it is still A64 code")
        self.assertEqual(insn_mod.arch_family(arch), "arm64")
        self.assertIn("CPU_SUBTYPE_ARM64E_X1", sub)
        self.assertIn("ARM64e X1", display)
        self.assertTrue(constants.is_arm64e_subtype(0x8000000C) and constants.is_arm64e_subtype(0x80000002) and constants.is_arm64e_subtype(2))
        self.assertFalse(constants.is_arm64e_subtype(0) or constants.is_arm64e_subtype(1) or constants.is_arm64e_subtype(3))
        sl = macho_slice(cputype=CPU_TYPE_ARM64, cpusubtype=0x8000000C)
        self.assertTrue(sl["security_posture"]["pac_enabled"])
        self.assertEqual(checks_of(sl)["pac"]["status"], "PASS")

    def test_the_capability_byte_is_reported_as_abi_version_not_as_a_version_0x80(self) -> None:
        _arch, _cpu, sub, _display = constants.decode_cpu_arch(CPU_TYPE_ARM64, 0x80000002)
        self.assertEqual(sub, "CPU_SUBTYPE_ARM64E (ptrauth ABI version 0)")
        self.assertNotIn("0x80", sub)
        self.assertIn("version 1", constants.decode_cpu_arch(CPU_TYPE_ARM64, 0x81000002)[2])
        self.assertIn("kernel", constants.decode_cpu_arch(CPU_TYPE_ARM64, 0xC0000002)[2])
        self.assertIn("unversioned", constants.decode_cpu_arch(CPU_TYPE_ARM64, 0x00000002)[2])

    def test_system_binary_with_both_arm64e_slices(self) -> None:
        data = real("macho_ls")
        if data is None:
            self.skipTest("/bin/ls is not present")
        slices = parse_macho_bytes(data, path="/bin/ls")["slices"]
        arm64e = [s for s in slices if s["arch_name"].startswith("arm64e")]
        if not arm64e:
            self.skipTest("/bin/ls has no arm64e slice here")
        for sl in arm64e:
            self.assertTrue(sl["security_posture"]["pac_enabled"])
            self.assertNotIn("CPU_SUBTYPE_0x", sl["header"]["cpusubtype_name"])
        names = [s["arch_name"] for s in slices]
        self.assertEqual(len(names), len(set(names)), "each slice of a universal file has its own name")
        lipo = shutil.which("lipo")
        if lipo:
            theirs = subprocess.run([lipo, "-archs", REAL["macho_ls"]], capture_output=True, text=True, timeout=30).stdout.split()
            self.assertEqual(names, theirs)


class PeSectionSizes(unittest.TestCase):
    def test_size_is_the_virtual_size_and_raw_size_is_separate(self) -> None:
        sl = parse_pe_slice(fixture_bytes("synthetic_pe64"), "x")
        text = next(s for seg in sl["segments"] for s in seg["sections"] if s["sectname"] == ".text")
        self.assertEqual((text["size"], text["virtual_size"], text["raw_size"]), (0x300, 0x300, 0x400))
        seg = next(s for s in sl["segments"] if s["segname"] == ".text")
        self.assertEqual((seg["vmsize_int"], seg["filesize"]), (0x300, 0x400))

    def test_a_zero_virtual_size_falls_back_to_the_raw_size(self) -> None:
        data = bytearray(fixture_bytes("synthetic_pe64"))
        sl = parse_pe_slice(bytes(data), "x")
        text = next(s for seg in sl["segments"] for s in seg["sections"] if s["sectname"] == ".text")
        struct.pack_into("<I", data, named_field(text["fields"], "VirtualSize")["abs_offset"], 0)
        again = parse_pe_slice(bytes(data), "x")
        text = next(s for seg in again["segments"] for s in seg["sections"] if s["sectname"] == ".text")
        self.assertEqual((text["size"], text["virtual_size"], text["raw_size"]), (0x400, 0, 0x400))

    def test_disassembly_stops_at_the_bytes_that_exist_on_disk(self) -> None:
        # VirtualSize larger than SizeOfRawData: the tail is zero-fill, not the next section's bytes.
        data = bytearray(fixture_bytes("synthetic_pe64"))
        sl = parse_pe_slice(bytes(data), "x")
        text = next(s for seg in sl["segments"] for s in seg["sections"] if s["sectname"] == ".text")
        struct.pack_into("<I", data, named_field(text["fields"], "VirtualSize")["abs_offset"], 0x900)
        grown = parse_pe_slice(bytes(data), "x")
        listing = disasm.disassemble_window(grown, bytes(data), 0, 0x140001000 + 0x3F0, count=200)
        last = listing["instructions"][-1]
        self.assertLessEqual(last["abs_offset"] + last["size"], 0x400 + 0x400)


class ElfRelocationFormats(unittest.TestCase):
    def test_the_label_follows_the_relocation_sections_not_the_word_size(self) -> None:
        elf64 = parse_elf_slice(fixture_bytes("synthetic_elf64"), "x")
        self.assertEqual(elf64["dyld_info"]["chained_fixups"]["pointer_format"], "ELF RELA (x86_64)")
        # A file with imports and no relocation sections must not claim a format from its class.
        for is64 in (True, False):
            sl = parse_elf_slice(elf(is64=is64, needed=("libc.so.6",), imports=(("puts", 0),)), "x")
            self.assertIn("no relocation records", sl["dyld_info"]["chained_fixups"]["pointer_format"])

    def test_real_files(self) -> None:
        data = real("elf_x64_versioned")
        if data is None:
            self.skipTest("the ELF sample is not on this machine")
        self.assertIn("RELA", parse_elf_slice(data, "x")["dyld_info"]["chained_fixups"]["pointer_format"])


class Pe64Fixture(unittest.TestCase):
    """The synthetic PE32+ sample starts consistent, so that tampering shows a change."""

    def test_checksum_and_signature_match_the_file(self) -> None:
        data = fixture_bytes("synthetic_pe64")
        info = labs_patch.pe_integrity(data)
        self.assertTrue(info["checksum_ok"])
        self.assertEqual(info["checksum_stored"], info["checksum_computed"])
        self.assertTrue(info["signed"])
        self.assertTrue(info["embedded_hash_matches"])
        self.assertEqual(info["embedded_hash_algorithm"], "sha256")

    def test_the_checksum_agrees_with_an_independent_implementation(self) -> None:
        data = fixture_bytes("synthetic_pe64")
        layout = pe_parser.pe_layout(data)
        zeroed = bytearray(data)
        zeroed[layout["checksum_off"]:layout["checksum_off"] + 4] = b"\0\0\0\0"
        total = 0
        for (word,) in struct.iter_unpack("<H", bytes(zeroed) + (b"\0" if len(zeroed) & 1 else b"")):
            total += word
            total = (total & 0xFFFF) + (total >> 16)
        total = (total & 0xFFFF) + (total >> 16)
        self.assertEqual(layout["stored_checksum"], (total + len(data)) & 0xFFFFFFFF)

    def test_the_embedded_digest_is_the_image_hash_by_an_independent_computation(self) -> None:
        data = fixture_bytes("synthetic_pe64")
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        opt = nt + 24
        cert_dir = opt + 112 + 4 * 8
        cert_off, cert_size = struct.unpack_from("<II", data, cert_dir)
        self.assertEqual(cert_off + cert_size, len(data), "the certificate table is the last thing in the file")
        # Authenticode: everything up to the table, minus CheckSum and the table's directory entry.
        hashed = data[:opt + 64] + data[opt + 68:cert_dir] + data[cert_dir + 8:cert_off]
        digest = hashlib.sha256(hashed).digest()
        blob = data[cert_off:cert_off + cert_size]
        self.assertIn(digest, blob)
        self.assertIn(bytes.fromhex("2b060104018237020104"), blob, "SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4)")
        dw_length, revision, cert_type = struct.unpack_from("<IHH", blob, 0)
        self.assertEqual((revision, cert_type), (0x0200, 0x0002))
        self.assertLessEqual(dw_length, cert_size)
        self.assertEqual(cert_size % 8, 0)

    def test_the_signer_is_plainly_synthetic(self) -> None:
        sl = parse_pe_slice(fixture_bytes("synthetic_pe64"), "x")
        certs = sl["code_signature_detail"]["cms_signature"]["certificates"]
        self.assertEqual(certs[0]["subject_cn"], "BinaryStudio Synthetic Corp")
        self.assertEqual(certs[0]["issuer_cn"], "BinaryStudio Root Code Signing CA")
        self.assertIn("synthetic", certs[0]["org"])
        self.assertIn("not a real signer", certs[0]["org"])

    def test_openssl_accepts_the_chain_and_the_signer_signature(self) -> None:
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("openssl is not installed")
        data = fixture_bytes("synthetic_pe64")
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        cert_off, _size = struct.unpack_from("<II", data, nt + 24 + 112 + 4 * 8)
        der = data[cert_off + 8:cert_off + struct.unpack_from("<I", data, cert_off)[0]]

        def tlv(buf: bytes, off: int) -> Tuple[int, int, int]:
            length, head = buf[off + 1], 2
            if length & 0x80:
                count = length & 0x7F
                length, head = int.from_bytes(buf[off + 2:off + 2 + count], "big"), 2 + count
            return buf[off], off + head, length

        def children(buf: bytes, off: int, length: int) -> List[Tuple[int, int, int, int]]:
            out, end = [], off + length
            while off < end:
                tag, value, size = tlv(buf, off)
                out.append((tag, off, value, size))
                off = value + size
            return out

        _t, value, length = tlv(der, 0)
        top = children(der, value, length)
        signed_data = children(der, *tlv(der, top[1][2])[1:])
        certs = children(der, signed_data[3][2], signed_data[3][3])
        signer = children(der, *tlv(der, signed_data[4][2])[1:])
        attrs = b"\x31" + der[signer[3][1] + 1:signer[3][2] + signer[3][3]]
        signature = der[signer[5][2]:signer[5][2] + signer[5][3]]
        with tempfile.TemporaryDirectory() as tmp:
            pems = []
            for index, cert in enumerate(certs):
                der_path, pem_path = os.path.join(tmp, "c%d.der" % index), os.path.join(tmp, "c%d.pem" % index)
                with open(der_path, "wb") as handle:
                    handle.write(der[cert[1]:cert[2] + cert[3]])
                converted = subprocess.run([openssl, "x509", "-inform", "DER", "-in", der_path, "-out", pem_path], capture_output=True, timeout=30)
                self.assertEqual(converted.returncode, 0, converted.stderr)
                pems.append(pem_path)
            self.assertEqual(len(pems), 2)
            chain = subprocess.run([openssl, "verify", "-CAfile", pems[0], pems[1]], capture_output=True, text=True, timeout=30)
            self.assertIn(": OK", chain.stdout, chain.stderr)
            pub = os.path.join(tmp, "pub.pem")
            with open(pub, "wb") as handle:
                handle.write(subprocess.run([openssl, "x509", "-in", pems[1], "-noout", "-pubkey"], capture_output=True, timeout=30).stdout)
            with open(os.path.join(tmp, "attrs.der"), "wb") as handle:
                handle.write(attrs)
            with open(os.path.join(tmp, "sig.bin"), "wb") as handle:
                handle.write(signature)
            verified = subprocess.run([openssl, "dgst", "-sha256", "-verify", pub, "-signature", os.path.join(tmp, "sig.bin"),
                                       os.path.join(tmp, "attrs.der")], capture_output=True, text=True, timeout=30)
            self.assertIn("Verified OK", verified.stdout, verified.stderr)

    def test_the_file_on_disk_is_what_the_builder_makes_and_stale_files_are_replaced(self) -> None:
        built = fixtures.synthetic_pe64_bytes()
        self.assertEqual(built, fixtures.synthetic_pe64_bytes(), "the builder is deterministic")
        self.assertEqual(hashlib.sha256(fixture_bytes("synthetic_pe64")).hexdigest(), hashlib.sha256(built).hexdigest())
        with tempfile.TemporaryDirectory() as tmp:
            stale = os.path.join(tmp, "synthetic_pe64.exe")
            with open(stale, "wb") as handle:
                handle.write(b"MZ" + b"\0" * 7000)           # what an older version would have left: big enough, wrong bytes
            fixtures._build_synthetic_pe64(tmp)
            with open(stale, "rb") as handle:
                self.assertEqual(handle.read(), built)

    def test_tampering_goes_from_matches_to_no_longer_matches(self) -> None:
        router, _service = make_router()
        resp, catalogue = call(router, "GET", "/api/labs/experiments", {"doc": "preset:synthetic_pe64", "slice_index": "0"})
        exp = next(e for e in catalogue["experiments"] if e["id"] == "pe.tamper-signed")
        self.assertTrue(exp["applicable"])
        self.assertIn("both match the file to begin with", exp["setup"])
        out = patched(router, "preset:synthetic_pe64", [{"offset": c["offset"], "hex": c["hex"]} for c in exp["changes"]])
        item = next(i for i in out["diff"]["integrity"] if i["kind"] == "pe_checksum")
        self.assertEqual((item["before"]["checksum_ok"], item["after"]["checksum_ok"]), (True, False))
        self.assertEqual((item["before"]["embedded_hash_matches"], item["after"]["embedded_hash_matches"]), (True, False))
        notes = {n["id"]: n["text"] for n in out["diff"]["consequences"]}
        self.assertEqual(list(notes), ["pe.checksum", "pe.authenticode"])
        self.assertIn("matched the image before the change and does not match it now", notes["pe.authenticode"])
        self.assertNotIn("not a verifiable signature to begin with", notes["pe.authenticode"])
        check = next(c for c in out["diff"]["slices"][0]["security"] if c["id"] == "codesign")
        self.assertEqual((check["before"]["status"], check["after"]["status"]), ("PASS", "WARN"))


if __name__ == "__main__":
    unittest.main()
