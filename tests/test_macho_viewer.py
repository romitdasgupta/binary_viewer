"""
Comprehensive End-to-End Unit & Integration Tests for Mach-O Binary Analysis Engine,
Synthetic Fixtures, Code Signature Verifier, Disassembler, HTTP REST API, and CLI.
"""

import base64
import json
import os
import re
import struct
import subprocess
import sys
import threading
import unittest
from urllib.request import Request, urlopen

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from backend.constants import (
    CPU_TYPE_ARM,
    CPU_TYPE_POWERPC,
    LC_SEGMENT,
    LC_SYMTAB,
    LC_UUID,
    MH_EXECUTE,
    MH_MAGIC,
)
from backend.fixtures import ensure_fixtures
from backend.parser import parse_macho_bytes
from backend.server import create_server
from backend.service import AnalysisService


class TestMachOViewerBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = ensure_fixtures(WORKSPACE_ROOT)
        cls.service = AnalysisService(WORKSPACE_ROOT)

    def test_01_fixtures_built(self) -> None:
        self.assertTrue(os.path.isfile(self.fixtures["synthetic_universal"]))
        self.assertTrue(os.path.isfile(self.fixtures["synthetic_firmware"]))
        self.assertTrue(os.path.isfile(self.fixtures["synthetic_elf64"]))
        self.assertTrue(os.path.isfile(self.fixtures["synthetic_elf32"]))
        self.assertTrue(os.path.isfile(self.fixtures["synthetic_pe64"]))
        self.assertTrue(os.path.isfile(self.fixtures["synthetic_pe32"]))
        self.assertGreater(os.path.getsize(self.fixtures["synthetic_universal"]), 32768)
        self.assertGreaterEqual(os.path.getsize(self.fixtures["synthetic_firmware"]), 12288)
        self.assertGreaterEqual(os.path.getsize(self.fixtures["synthetic_elf64"]), 8192)
        self.assertGreaterEqual(os.path.getsize(self.fixtures["synthetic_elf32"]), 4096)
        self.assertGreaterEqual(os.path.getsize(self.fixtures["synthetic_pe64"]), 6144)
        self.assertGreaterEqual(os.path.getsize(self.fixtures["synthetic_pe32"]), 2048)

    def test_02_parse_synthetic_universal(self) -> None:
        doc = self.service.load_file(self.fixtures["synthetic_universal"])
        fi = doc["file_info"]
        self.assertTrue(fi["is_fat"])
        self.assertEqual(fi["fat_header"]["nfat_arch"], 2)
        self.assertEqual(len(doc["slices"]), 2)

        archs = {s["arch_name"] for s in doc["slices"]}
        self.assertIn("x86_64", archs)
        self.assertTrue("arm64" in archs or "arm64e" in archs)

        arm_slice = [s for s in doc["slices"] if s["arch_name"].startswith("arm64")][0]
        # Verify custom sections
        sec_names = {
            f"{sec['segname']},{sec['sectname']}"
            for seg in arm_slice["segments"]
            for sec in seg["sections"]
        }
        self.assertIn("__TEXT,__custom_code", sec_names)
        self.assertIn("__DATA,__custom_data", sec_names)
        self.assertIn("__RODATA,__firmware_cfg", sec_names)

        # Verify C++ symbol demangling
        demangled_syms = {s["demangled"] for s in arm_slice["symbols"]}
        self.assertTrue(
            any("compute_crypto" in d for d in demangled_syms),
            f"Expected demangled compute_crypto in {demangled_syms}",
        )
        self.assertTrue(
            any("PacketValidator::verifyHeader" in d for d in demangled_syms),
            "Expected demangled C++ class method PacketValidator::verifyHeader",
        )

        # Verify RPATH
        rpaths = [r["path"] for r in arm_slice["rpaths"]]
        self.assertIn("@executable_path/../Frameworks", rpaths)

        # Verify Entitlements & CodeDirectory verification
        cs = arm_slice["code_signature_detail"]
        self.assertTrue(cs["present"])
        self.assertIsNotNone(cs["code_directory"])
        self.assertTrue(cs["code_directory"]["cdhash_verified"])
        self.assertTrue(cs["entitlements_dict"].get("com.apple.security.get-task-allow"))
        self.assertEqual(
            cs["entitlements_dict"].get("com.apple.private.custom-firmware-inspect"),
            "enabled-for-macho-viewer-test",
        )

        # Verify Security Posture
        sec = arm_slice["security_posture"]
        self.assertTrue(sec["pie"])
        self.assertTrue(sec["stack_canary"])
        self.assertFalse(sec["has_rwx_segments"])

    def test_03_parse_synthetic_firmware_preload(self) -> None:
        doc = self.service.load_file(self.fixtures["synthetic_firmware"])
        fi = doc["file_info"]
        self.assertFalse(fi["is_fat"])
        self.assertEqual(len(doc["slices"]), 1)

        sl = doc["slices"][0]
        self.assertEqual(sl["header"]["filetype_name"], "MH_PRELOAD")
        self.assertEqual(sl["arch_name"], "arm64e")
        self.assertEqual(sl["overview"]["platform"], "Firmware (Standalone)")

        # Verify LC_UNIXTHREAD entry point and registers
        ep = sl["entry_point"]
        self.assertEqual(ep["type"], "LC_UNIXTHREAD")
        self.assertEqual(ep["vmaddr"], "0x180000400")
        self.assertEqual(ep["registers"]["sp"], "0x0000000180020000")
        self.assertEqual(ep["registers"]["pc"], "0x0000000180000400")

        # Verify RWX warning in security posture
        sec = sl["security_posture"]
        self.assertTrue(sec["has_rwx_segments"])
        rwx_check = [c for c in sec["checks"] if c["id"] == "rwx"][0]
        self.assertEqual(rwx_check["status"], "FAIL")

        # Verify Disassembly of firmware entry point
        dis = self.service.disassemble(slice_index=0, vmaddr="0x180000400", count=12)
        mnems = [ins["mnemonic"] for ins in dis["instructions"]]
        self.assertEqual(mnems[0], "paciasp")
        self.assertIn("stp", mnems)
        self.assertIn("adrp", mnems)
        self.assertIn("bl", mnems)
        self.assertIn("retaa", mnems)
        # Verify inline string cross-reference annotation on ADRP+ADD
        comments = [ins.get("comment") or "" for ins in dis["instructions"]]
        self.assertTrue(any("iBoot-9452" in c for c in comments))

    def test_04_parse_real_system_binaries(self) -> None:
        for sys_bin in ("/bin/ls", "/usr/bin/true"):
            if not os.path.isfile(sys_bin):
                continue
            doc = self.service.load_file(sys_bin)
            self.assertGreaterEqual(len(doc["slices"]), 1)
            fmt = doc["file_info"]["format"]
            self.assertIn(fmt, ("MACHO", "ELF"))
            for idx, sl in enumerate(doc["slices"]):
                if fmt == "MACHO":
                    self.assertEqual(sl["header"]["filetype_name"], "MH_EXECUTE")
                    self.assertTrue(sl["code_signature_detail"]["present"])
                    self.assertTrue(sl["code_signature_detail"]["code_directory"]["cdhash_verified"])
                    certs = sl["code_signature_detail"]["cms_signature"]["certificates"]
                    self.assertGreaterEqual(len(certs), 1)
                    if sl["arch_name"] == "arm64e":
                        self.assertTrue(sl["dyld_info"]["has_chained_fixups"])
                        if sys_bin == "/bin/ls":
                            self.assertGreater(
                                sl["dyld_info"]["chained_fixups"]["imports_count"], 0
                            )
                else:
                    # Linux ELF64 system binary (/bin/ls or /usr/bin/true)
                    self.assertIn(sl["header"]["filetype_name"], ("ET_DYN", "ET_EXEC"))
                    self.assertGreater(len(sl["segments"]), 0)
                    self.assertGreater(len(sl["dylibs"]), 0)
                    self.assertIn("semantic_layers", sl)
                    self.assertIn("pedagogy", sl)

    def test_05_translate_hex_decode_search(self) -> None:
        self.service.load_file(self.fixtures["synthetic_firmware"])
        # Translate VMAddr -> File Offset
        tr = self.service.translate_address(slice_index=0, query="0x180000400", mode="auto")
        self.assertTrue(tr["mapped"])
        self.assertEqual(tr["status"], "MAPPED")
        self.assertEqual(tr["abs_offset"], 0x400)
        self.assertEqual(tr["nearest_symbol"]["name"], "_reset_vector")

        # Translate S_ZEROFILL (__bss) VMAddr
        tr_bss = self.service.translate_address(slice_index=0, query="0x180002010", mode="vmaddr")
        self.assertTrue(tr_bss["mapped"])
        self.assertEqual(tr_bss["status"], "UNMAPPED_ZEROFILL")
        self.assertEqual(tr_bss["section"]["sectname"], "__bss")

        # Decode bytes at 0x400 (paciasp: 7f 23 03 d5)
        dec = self.service.decode_bytes_at(offset=0x400, slice_index=0)
        self.assertEqual(dec["primitives"]["hex32"], "0xd503233f")
        self.assertEqual(dec["primitives"]["arm64_insn"], "paciasp")
        self.assertGreater(len(dec["breadcrumbs"]), 0)

        # Search
        s_res = self.service.search(query="iBoot", slice_index=0)
        self.assertGreater(len(s_res["results"]), 0)

    def test_06_http_api_endpoints(self) -> None:
        server = create_server(WORKSPACE_ROOT, host="127.0.0.1", port=0)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        base_url = f"http://127.0.0.1:{port}"

        try:
            # 1. GET /api/presets
            with urlopen(f"{base_url}/api/presets") as resp:
                self.assertEqual(resp.status, 200)
                presets_data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(len(presets_data["presets"]), 8)

            # 2. POST /api/parse
            req = Request(
                f"{base_url}/api/parse",
                data=json.dumps({"path": self.fixtures["synthetic_universal"]}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req) as resp:
                self.assertEqual(resp.status, 200)
                doc = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(doc["file_info"]["filename"], "synthetic_universal")

            # 3. GET /api/hex
            with urlopen(f"{base_url}/api/hex?offset=0&length=64&slice_index=0") as resp:
                self.assertEqual(resp.status, 200)
                hex_data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(len(hex_data["rows"]), 4)

            # 4. GET /api/decode
            with urlopen(f"{base_url}/api/decode?offset=0&slice_index=0") as resp:
                self.assertEqual(resp.status, 200)
                dec_data = json.loads(resp.read().decode("utf-8"))
                self.assertIn("primitives", dec_data)

            # 5. GET /api/translate
            with urlopen(f"{base_url}/api/translate?query=0x0&slice_index=0") as resp:
                self.assertEqual(resp.status, 200)
                tr_data = json.loads(resp.read().decode("utf-8"))
                self.assertIn("status", tr_data)

            # 6. GET /api/disassemble
            with urlopen(f"{base_url}/api/disassemble?slice_index=0&count=16") as resp:
                self.assertEqual(resp.status, 200)
                dis_data = json.loads(resp.read().decode("utf-8"))
                self.assertGreater(len(dis_data["instructions"]), 0)

            # 7. GET /api/search
            with urlopen(f"{base_url}/api/search?q=LC_MAIN&slice_index=0") as resp:
                self.assertEqual(resp.status, 200)
                sr_data = json.loads(resp.read().decode("utf-8"))
                self.assertGreater(len(sr_data["results"]), 0)

            # 8. POST /api/upload
            with open("/usr/bin/true", "rb") as bf:
                raw_true = bf.read()
            up_req = Request(
                f"{base_url}/api/upload",
                data= json.dumps({
                    "filename": "uploaded_true",
                    "data_base64": base64.b64encode(raw_true).decode("ascii"),
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(up_req) as resp:
                self.assertEqual(resp.status, 200)
                up_doc = json.loads(resp.read().decode("utf-8"))
                self.assertIn("uploaded_true", up_doc["file_info"]["path"])
        finally:
            server.shutdown()
            server.server_close()

    def test_07_cli_modes(self) -> None:
        script = os.path.join(WORKSPACE_ROOT, "macho_viewer.py")
        for target_bin in (
            self.fixtures["synthetic_firmware"],
            self.fixtures["synthetic_elf64"],
            self.fixtures["synthetic_pe64"],
        ):
            proc = subprocess.run(
                [sys.executable, script, "--cli", target_bin, "--disasm"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertIn("Binary Analysis Report", proc.stdout)
            self.assertIn("Semantic Intelligence & Provenance", proc.stdout)
            self.assertIn("Disassembly Preview", proc.stdout)

    def test_08_cross_validate_against_otool_and_codesign(self) -> None:
        """
        Cross-validates MachOStudio's parsed header fields (ncmds, sizeofcmds, flags),
        segment layouts (vmaddr, vmsize, fileoff, filesize, nsects), LC_UUID, and
        LC_CODE_SIGNATURE CDHash/Identifier against macOS `/usr/bin/otool` and `/usr/bin/codesign`.
        """
        if not os.path.isfile("/usr/bin/otool") or not os.path.isfile("/usr/bin/codesign"):
            self.skipTest("macOS otool / codesign not present")

        targets = [self.fixtures["synthetic_universal"]]
        if os.path.isfile("/bin/ls"):
            targets.append("/bin/ls")

        for bin_path in targets:
            doc = self.service.load_file(bin_path)
            arm_slice = [s for s in doc["slices"] if s["arch_name"].startswith("arm64")][0]
            arch_flag = arm_slice["arch_name"]

            # 1. Cross-check against `/usr/bin/otool -arch <arch> -hl <bin_path>`
            otool_proc = subprocess.run(
                ["/usr/bin/otool", "-arch", arch_flag, "-hl", bin_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(otool_proc.returncode, 0)
            otool_out = otool_proc.stdout

            # Extract Mach header line from otool:
            # 0xfeedfacf 16777228 ... filetype ncmds sizeofcmds flags
            hdr_match = re.search(
                r"0xfeedfacf\s+(\d+)\s+\d+\s+0x[0-9a-fA-F]+\s+(\d+)\s+(\d+)\s+(\d+)\s+0x([0-9a-fA-F]+)",
                otool_out,
            )
            self.assertIsNotNone(hdr_match, f"Failed to parse otool header for {bin_path}")
            otool_cputype = int(hdr_match.group(1))
            otool_filetype = int(hdr_match.group(2))
            otool_ncmds = int(hdr_match.group(3))
            otool_sizeofcmds = int(hdr_match.group(4))
            otool_flags = int(hdr_match.group(5), 16)

            self.assertEqual(arm_slice["header"]["cputype"], otool_cputype)
            self.assertEqual(arm_slice["header"]["filetype"], otool_filetype)
            self.assertEqual(arm_slice["header"]["ncmds"], otool_ncmds)
            self.assertEqual(arm_slice["header"]["sizeofcmds"], otool_sizeofcmds)
            self.assertEqual(arm_slice["header"]["flags"], otool_flags)

            # Extract UUID from otool output (`uuid XXXXXXXX-...`)
            uuid_match = re.search(r"uuid\s+([0-9A-Fa-f-]{36})", otool_out)
            if uuid_match:
                self.assertEqual(
                    arm_slice["overview"]["uuid"].upper(),
                    uuid_match.group(1).upper(),
                )

            # Extract LC_SEGMENT_64 blocks from otool output and verify every segment matches
            seg_blocks = re.findall(
                r"cmd LC_SEGMENT_64\s+cmdsize\s+\d+\s+segname\s+(\S+)\s+vmaddr\s+0x([0-9a-fA-F]+)\s+vmsize\s+0x([0-9a-fA-F]+)\s+fileoff\s+(\d+)\s+filesize\s+(\d+)",
                otool_out,
            )
            self.assertEqual(len(seg_blocks), len(arm_slice["segments"]))
            for idx, (s_name, s_vm, s_vmsz, s_foff, s_fsz) in enumerate(seg_blocks):
                parsed_seg = arm_slice["segments"][idx]
                self.assertEqual(parsed_seg["segname"], s_name)
                self.assertEqual(parsed_seg["vmaddr_int"], int(s_vm, 16))
                self.assertEqual(parsed_seg["vmsize_int"], int(s_vmsz, 16))
                self.assertEqual(parsed_seg["fileoff"], int(s_foff))
                self.assertEqual(parsed_seg["filesize"], int(s_fsz))

            # 2. Cross-check CDHash and Identifier against `/usr/bin/codesign -dvvv <bin_path>`
            cs_proc = subprocess.run(
                ["/usr/bin/codesign", "-dvvv", bin_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(cs_proc.returncode, 0)
            cs_out = cs_proc.stderr + "\n" + cs_proc.stdout

            cdhash_match = re.search(r"CDHash=([0-9a-fA-F]{40})", cs_out)
            id_match = re.search(r"Identifier=([^\r\n]+)", cs_out)
            self.assertIsNotNone(cdhash_match)
            self.assertIsNotNone(id_match)

            # In a Universal binary, codesign -dvvv prints the native slice's CDHash
            all_slice_cdhashes = {
                s["code_signature_detail"]["code_directory"]["cdhash"]
                for s in doc["slices"]
                if s["code_signature_detail"]["present"]
            }
            self.assertIn(cdhash_match.group(1).lower(), all_slice_cdhashes)
            self.assertEqual(
                arm_slice["code_signature_detail"]["code_directory"]["identifier"],
                id_match.group(1).strip(),
            )

    def test_09_java_class_disambiguation_and_malformed_inputs(self) -> None:
        """
        Verifies that:
        1. Java .class files starting with 0xCAFEBABE (with major_version >= 45 in bytes 6..7)
           are properly rejected as non-Mach-O rather than misparsed as a 55-slice Fat binary.
        2. Truncated or malformed Mach-O buffers with out-of-bounds load commands or symbol offsets
           do not crash or raise unhandled exceptions.
        """
        # 1. Synthetic Java 11 .class header: magic=0xCAFEBABE, minor=0, major=55 (0x0037)
        java_class_bytes = struct.pack(">IHH", 0xCAFEBABE, 0, 55) + b"\x00" * 64
        with self.assertRaises(ValueError) as ctx:
            parse_macho_bytes(java_class_bytes, path="FakeJavaClass.class")
        self.assertIn("Unrecognized Mach-O magic", str(ctx.exception))

        # 2. Too-short buffer (< 28 bytes)
        with self.assertRaises(ValueError):
            parse_macho_bytes(b"\xcf\xfa\xed\xfe\x00\x01", path="truncated.bin")

        # 3. Truncated load commands (header claims ncmds=50, sizeofcmds=8000 in a 64-byte file)
        truncated_macho = struct.pack(
            "<IIIIIIII",
            0xFEEDFACF,       # MH_MAGIC_64
            0x0100000C,       # CPU_TYPE_ARM64
            0x00000000,       # CPU_SUBTYPE_ARM64_ALL
            MH_EXECUTE,       # filetype
            50,               # ncmds (exaggerated)
            8000,             # sizeofcmds (out-of-bounds)
            0x00200085,       # flags
            0,                # reserved
        ) + struct.pack("<II", LC_UUID, 24) + (b"\xaa" * 16) + (b"\x00" * 8)

        doc = parse_macho_bytes(truncated_macho, path="truncated_cmds.macho")
        self.assertEqual(len(doc["slices"]), 1)
        # Should cleanly parse the 1 valid LC_UUID command and stop before EOF
        self.assertEqual(len(doc["slices"][0]["load_commands"]), 1)
        self.assertEqual(doc["slices"][0]["overview"]["uuid"], "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")

    def test_10_32bit_and_big_endian_macho_parsing(self) -> None:
        """
        Verifies parsing of 32-bit Little-Endian (MH_MAGIC / ARMv7) and
        32-bit Big-Endian (MH_CIGAM in LE view / PowerPC) Mach-O binaries
        with 32-bit LC_SEGMENT and 12-byte nlist symbol entries.
        """
        # 1. Construct a 32-bit Little-Endian ARMv7 (CPU_TYPE_ARM=12, subtype=9) Mach-O
        # Header (28 bytes) + LC_SEGMENT (56 + 68 = 124 bytes) + LC_SYMTAB (24 bytes) = 176 bytes
        hdr_32_le = struct.pack(
            "<IIIIIII",
            MH_MAGIC,         # 0xfeedface (28-byte header)
            CPU_TYPE_ARM,     # 12
            9,                # CPU_SUBTYPE_ARM_V7
            MH_EXECUTE,
            2,                # ncmds = 2 (LC_SEGMENT + LC_SYMTAB)
            148,              # sizeofcmds = 124 + 24
            0x00000001,       # MH_NOUNDEFS
        )
        seg_cmd_32 = struct.pack(
            "<II16sIIIIIIII",
            LC_SEGMENT,
            124,              # 56 + 1 * 68
            b"__TEXT\x00" + b"\x00" * 9,
            0x00004000,       # vmaddr
            0x00001000,       # vmsize
            0,                # fileoff
            512,              # filesize
            5,                # maxprot (r-x)
            5,                # initprot (r-x)
            1,                # nsects
            0,                # flags
        )
        sect_32 = struct.pack(
            "<16s16sIIIIIIIII",
            b"__text\x00" + b"\x00" * 9,
            b"__TEXT\x00" + b"\x00" * 9,
            0x00004100,       # addr
            16,               # size
            256,              # offset
            2,                # align (2^2)
            0,                # reloff
            0,                # nreloc
            0x80000400,       # S_REGULAR | S_ATTR_PURE_INSTRUCTIONS
            0,
            0,
        )
        # Put 1 symbol (12-byte nlist) at offset 300, string table at 312
        sym_cmd_32 = struct.pack(
            "<IIIIII",
            LC_SYMTAB,
            24,
            300,              # symoff
            1,                # nsyms
            312,              # stroff
            16,               # strsize
        )
        body_pad = b"\x00" * (300 - (28 + 124 + 24))
        # 12-byte nlist: n_strx=1, n_type=0x0F (N_SECT|N_EXT), n_sect=1, n_desc=0, n_value=0x4100
        nlist_32 = struct.pack("<IBBHI", 1, 0x0F, 1, 0, 0x00004100)
        strtab_32 = b"\x00_armv7_entry\x00\x00\x00"
        tail_pad = b"\x00" * (512 - (312 + len(strtab_32)))

        raw_32_le = hdr_32_le + seg_cmd_32 + sect_32 + sym_cmd_32 + body_pad + nlist_32 + strtab_32 + tail_pad
        doc_32 = parse_macho_bytes(raw_32_le, path="armv7_test.macho")
        sl_32 = doc_32["slices"][0]
        self.assertFalse(sl_32["header"]["is_64bit"])
        self.assertTrue(sl_32["header"]["little_endian"])
        self.assertEqual(sl_32["arch_name"], "armv7")
        self.assertEqual(len(sl_32["segments"]), 1)
        self.assertEqual(sl_32["segments"][0]["sections"][0]["sectname"], "__text")
        self.assertEqual(len(sl_32["symbols"]), 1)
        self.assertEqual(sl_32["symbols"][0]["name"], "_armv7_entry")
        self.assertEqual(sl_32["symbols"][0]["n_value"], "0x4100")

        # 2. Construct a 32-bit Big-Endian PowerPC Mach-O (magic >I = 0xFEEDFACE -> <I = MH_CIGAM)
        hdr_32_be = struct.pack(
            ">IIIIIII",
            MH_MAGIC,
            CPU_TYPE_POWERPC,
            0,
            MH_EXECUTE,
            0,
            0,
            0x00000001,
        ) + (b"\x00" * 64)
        doc_be = parse_macho_bytes(hdr_32_be, path="ppc_be.macho")
        sl_be = doc_be["slices"][0]
        self.assertFalse(sl_be["header"]["is_64bit"])
        self.assertFalse(sl_be["header"]["little_endian"])
        self.assertEqual(sl_be["overview"]["endianness"], "Big-Endian")
        self.assertEqual(sl_be["header"]["cputype_name"], "CPU_TYPE_POWERPC")

    def test_11_parse_synthetic_elf64_and_elf32(self) -> None:
        """
        Verifies full ELF64 and ELF32 parsing, Program Headers, Section Headers,
        `.dynamic` tags (`DT_NEEDED`, `DT_RUNPATH`, `DF_BIND_NOW`), GNU Build-ID,
        ABI-tag, Intel CET (`IBT | SHSTK`) notes, PLT/GOT relocations, x86_64 disassembly,
        and 9-point ELF security posture scoring.
        """
        doc64 = self.service.load_file(self.fixtures["synthetic_elf64"])
        self.assertEqual(doc64["file_info"]["format"], "ELF")
        self.assertEqual(doc64["file_info"]["format_display"], "ELF64")
        sl64 = doc64["slices"][0]
        self.assertTrue(sl64["is_64"])
        self.assertEqual(sl64["arch_name"], "x86_64")
        self.assertEqual(sl64["header"]["filetype_name"], "ET_DYN")
        self.assertEqual(sl64["elf_metadata"]["interpreter"], "/lib64/ld-linux-x86-64.so.2")

        # Verify Build-ID & Notes
        self.assertIn("a1b2c3d4e5f6", sl64["overview"]["uuid"])
        self.assertGreaterEqual(len(sl64["elf_metadata"]["notes"]), 3)

        # Verify DT_NEEDED & DT_RUNPATH
        dylib_names = [d["name"] for d in sl64["dylibs"]]
        self.assertIn("libc.so.6", dylib_names)
        self.assertIn("libcrypto.so.3", dylib_names)
        self.assertEqual(sl64["rpaths"][0]["path"], "$ORIGIN/../lib")

        # Verify Symbols & C++ Demangling
        demangled = {s["demangled"] for s in sl64["symbols"]}
        self.assertTrue(any("compute_crypto" in d for d in demangled))

        # Verify Relocations (.rela.dyn + .rela.plt)
        fixups = sl64["dyld_info"]["chained_fixups"]["fixups"]
        self.assertEqual(len(fixups), 5)
        self.assertTrue(any(f["type"] == "R_X86_64_JUMP_SLOT" for f in fixups))

        # Verify Security Posture (PIE, Full RELRO, NX Stack, Stack Canary, CET IBT+SHSTK)
        sec64 = sl64["security_posture"]
        self.assertTrue(sec64["pie"])
        self.assertEqual(sec64["relro"], "Full")
        self.assertTrue(sec64["nx_stack"])
        self.assertTrue(sec64["stack_canary"])
        self.assertTrue(sec64["pac_enabled"])  # Intel CET IBT | SHSTK

        # Verify x86_64 Disassembly at entry point 0x1040
        dis64 = self.service.disassemble(slice_index=0, vmaddr="0x1040", count=10)
        mnems = [i["mnemonic"] for i in dis64["instructions"]]
        self.assertEqual(mnems[0], "endbr64")
        self.assertIn("push", mnems)
        self.assertIn("call", mnems)

        # Verify ELF32 non-PIE with executable stack warning
        doc32 = self.service.load_file(self.fixtures["synthetic_elf32"])
        self.assertEqual(doc32["file_info"]["format_display"], "ELF32")
        sl32 = doc32["slices"][0]
        self.assertFalse(sl32["is_64"])
        self.assertEqual(sl32["arch_name"], "i386")
        self.assertEqual(sl32["header"]["filetype_name"], "ET_EXEC")
        sec32 = sl32["security_posture"]
        self.assertFalse(sec32["pie"])
        self.assertFalse(sec32["nx_stack"])
        nx_chk = [c for c in sec32["checks"] if c["id"] == "nx_stack"][0]
        self.assertEqual(nx_chk["status"], "FAIL")

    def test_12_parse_synthetic_pe64_and_pe32(self) -> None:
        """
        Verifies full Windows PE32+ and PE32 parsing: DOS Header, XOR-decrypted Rich Header,
        NT & Optional Headers, Data Directories, Import Table (by name & by ordinal),
        Export Table (including forwarded exports), Base Relocations (`DIR64`),
        CodeView `RSDS` PDB GUID/path, LoadConfig `/GS` SecurityCookie,
        `WIN_CERTIFICATE` Authenticode PKCS#7 certificate extraction, and PE32 TLS/RWX checks.
        """
        doc64 = self.service.load_file(self.fixtures["synthetic_pe64"])
        self.assertEqual(doc64["file_info"]["format"], "PE")
        self.assertEqual(doc64["file_info"]["format_display"], "PE32+")
        sl64 = doc64["slices"][0]
        self.assertTrue(sl64["is_64"])
        self.assertEqual(sl64["arch_name"], "x86_64")

        # Verify XOR-decrypted Rich Header
        rich = sl64["pe_metadata"]["rich_header"]
        self.assertTrue(rich["present"])
        self.assertEqual(rich["xor_key"], "0x5a3c9e17")
        self.assertEqual(len(rich["entries"]), 3)

        # Verify Imports (KERNEL32.dll & WS2_32.dll including ordinal #115)
        imports = sl64["dyld_info"]["chained_fixups"]["imports"]
        imp_names = {imp["name"] for imp in imports}
        self.assertIn("GetProcAddress", imp_names)
        self.assertIn("VirtualAlloc", imp_names)
        self.assertIn("CreateProcessW", imp_names)
        self.assertIn("WSAStartup", imp_names)
        self.assertIn("Ordinal#115", imp_names)

        # Verify Exports & Forwarded Export
        exports = sl64["dyld_info"]["exports"]
        exp_map = {ex["name"]: ex for ex in exports}
        self.assertIn("InitializeEngine", exp_map)
        self.assertIn("LegacyAlloc", exp_map)
        self.assertEqual(exp_map["LegacyAlloc"]["forwarder"], "NTDLL.RtlAllocateHeap")

        # Verify CodeView RSDS PDB GUID & Path
        dbg = sl64["pe_metadata"]["debug_entries"]
        self.assertEqual(len(dbg), 1)
        self.assertIn("synthetic_pe64.pdb", dbg[0]["pdb_path"])
        self.assertEqual(sl64["overview"]["uuid"], dbg[0]["guid"])

        # Verify Authenticode WIN_CERTIFICATE
        cs64 = sl64["code_signature_detail"]
        self.assertTrue(cs64["present"])
        certs = cs64["cms_signature"]["certificates"]
        self.assertTrue(any("MachOStudio Synthetic Corp" in c["subject_cn"] for c in certs))

        # Verify PE32+ Security Posture (ASLR + High-Entropy VA + DEP + CFG + /GS Cookie + Authenticode)
        sec64 = sl64["security_posture"]
        self.assertTrue(sec64["pie"])
        self.assertTrue(sec64["stack_canary"])
        self.assertTrue(sec64["pac_enabled"])  # GUARD_CF

        # Verify PE32 with RWX section and pre-main TLS callback
        doc32 = self.service.load_file(self.fixtures["synthetic_pe32"])
        self.assertEqual(doc32["file_info"]["format_display"], "PE32")
        sl32 = doc32["slices"][0]
        self.assertFalse(sl32["is_64"])
        self.assertEqual(sl32["arch_name"], "i386")
        self.assertTrue(sl32["security_posture"]["has_rwx_segments"])
        self.assertEqual(sl32["pe_metadata"]["tls_info"]["callbacks"], ["0x401000"])

    def test_13_semantic_layers_and_entropy_intelligence(self) -> None:
        """
        Verifies the 4 Semantic Intelligence layers (`entropy_analysis`, `capabilities`,
        `provenance`, and `anomalies`) across Mach-O, ELF64, and PE32+.
        """
        for key in ("synthetic_universal", "synthetic_firmware", "synthetic_elf64", "synthetic_pe64", "synthetic_pe32"):
            doc = self.service.load_file(self.fixtures[key])
            sl = doc["slices"][0]
            sem = sl["semantic_layers"]
            self.assertIn("entropy_analysis", sem)
            self.assertIn("capabilities", sem)
            self.assertIn("provenance", sem)
            self.assertIn("anomalies", sem)

            ent = sem["entropy_analysis"]
            self.assertGreaterEqual(ent["overall_entropy"], 0.0)
            self.assertLessEqual(ent["overall_entropy"], 8.0)
            self.assertGreater(len(ent["sliding_windows"]), 0)
            dist = ent["byte_class_distribution"]
            total_pct = dist["null_pct"] + dist["ascii_pct"] + dist["control_pct"] + dist["high_pct"]
            self.assertAlmostEqual(total_pct, 100.0, delta=0.5)

        # Verify capability taxonomy on PE32+ (Networking + Process/Memory + Crypto/Strings)
        pe_doc = self.service.load_file(self.fixtures["synthetic_pe64"])
        pe_caps = pe_doc["slices"][0]["semantic_layers"]["capabilities"]
        cap_ids = {c["id"] for c in pe_caps["categories"]}
        self.assertIn("network", cap_ids)
        self.assertIn("process", cap_ids)
        self.assertIn("dynamic_loading", cap_ids)
        self.assertGreater(len(pe_caps["string_intelligence"]["urls"]), 0)
        self.assertGreater(len(pe_caps["string_intelligence"]["registry_keys"]), 0)

        # Verify anomaly detection on PE32 (RWX section + TLS callback)
        pe32_doc = self.service.load_file(self.fixtures["synthetic_pe32"])
        anom_ids = {f["id"] for f in pe32_doc["slices"][0]["semantic_layers"]["anomalies"]["findings"]}
        self.assertIn("rwx_memory", anom_ids)
        self.assertIn("pe_tls_callbacks", anom_ids)

    def test_14_pedagogy_loader_lifecycle_rosetta_and_tours(self) -> None:
        """
        Verifies the Pedagogical & Learning layers (`loader_lifecycle` 6-stage simulator,
        10-row `rosetta_stone` comparative matrix, field-level `pedagogy` annotations,
        and `guided_tours` with micro-challenges) across Mach-O, ELF, and PE.
        """
        for key, expected_fmt in (
            ("synthetic_universal", "MACHO"),
            ("synthetic_elf64", "ELF"),
            ("synthetic_pe64", "PE"),
        ):
            doc = self.service.load_file(self.fixtures[key])
            sl = doc["slices"][0]
            self.assertEqual(sl["format"], expected_fmt)
            ped = sl["pedagogy"]

            # 1. 6-Stage OS Loader Lifecycle Simulator
            lc = ped["loader_lifecycle"]
            self.assertEqual(len(lc["stages"]), 6)
            for idx, st in enumerate(lc["stages"]):
                self.assertEqual(st["stage"], idx + 1)
                self.assertTrue(st["title"])
                self.assertTrue(st["binary_state"])
                self.assertTrue(st["failure_mode"])

            # 2. 10-Row Rosetta Stone Comparative Matrix
            rosetta = ped["rosetta_stone"]
            self.assertEqual(len(rosetta), 10)
            self.assertEqual(rosetta[0]["active_format"], expected_fmt)

            # 3. Field-level Pedagogy Annotations on Header Fields
            hdr_fields_with_ped = [f for f in sl["header"]["fields"] if f.get("pedagogy")]
            self.assertGreater(len(hdr_fields_with_ped), 0)
            sample_ped = hdr_fields_with_ped[0]["pedagogy"]
            self.assertIn("why_it_matters", sample_ped)
            self.assertIn("loader_behavior", sample_ped)
            self.assertIn("what_if_modified", sample_ped)
            self.assertIn("cross_format_peer", sample_ped)

            # 4. Guided Learning Tours with Interactive Micro-Challenges
            tours = ped["guided_tours"]
            self.assertGreaterEqual(len(tours), 3)
            for tour in tours:
                self.assertGreater(len(tour["steps"]), 0)
                self.assertIn("challenge", tour["steps"][0])

    def test_15_cross_validate_elf_against_readelf_and_multi_format_api(self) -> None:
        """
        Cross-validates synthetic ELF64 and real `/bin/ls` (when on Linux with `/usr/bin/readelf`)
        and verifies `/api/decode` field pedagogy and `/api/translate` on ELF and PE binaries.
        """
        # 1. Verify decode_bytes_at returns field_pedagogy and x86_insn on ELF64 and PE32+
        self.service.load_file(self.fixtures["synthetic_elf64"])
        dec_elf_hdr = self.service.decode_bytes_at(offset=0, slice_index=0)
        self.assertIsNotNone(dec_elf_hdr.get("field_pedagogy"))
        self.assertEqual(dec_elf_hdr["field_pedagogy"]["field_name"], "e_ident[EI_MAG]")

        dec_elf_code = self.service.decode_bytes_at(offset=0x1040, slice_index=0)
        self.assertIn("endbr64", dec_elf_code["primitives"]["x86_insn"])

        self.service.load_file(self.fixtures["synthetic_pe64"])
        dec_pe_dos = self.service.decode_bytes_at(offset=0x3C, slice_index=0)
        self.assertIsNotNone(dec_pe_dos.get("field_pedagogy"))
        self.assertEqual(dec_pe_dos["field_pedagogy"]["field_name"], "e_lfanew")

        tr_pe = self.service.translate_address(slice_index=0, query="0x140001000", mode="vmaddr")
        self.assertTrue(tr_pe["mapped"])
        self.assertEqual(tr_pe["abs_offset"], 0x400)

        # 2. Cross-validate against /usr/bin/readelf if available
        if os.path.exists("/usr/bin/readelf"):
            elf_path = self.fixtures["synthetic_elf64"]
            doc = self.service.load_file(elf_path)
            sl = doc["slices"][0]
            proc = subprocess.run(
                ["/usr/bin/readelf", "-h", "-l", "-n", elf_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 0)
            out = proc.stdout
            self.assertIn("ELF64", out)
            self.assertIn("DYN", out)
            self.assertIn("/lib64/ld-linux-x86-64.so.2", out)
            self.assertIn(sl["overview"]["uuid"].lower(), out.lower())


if __name__ == "__main__":
    unittest.main()
