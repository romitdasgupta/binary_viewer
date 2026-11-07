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
        self.assertGreater(os.path.getsize(self.fixtures["synthetic_universal"]), 32768)
        self.assertGreaterEqual(os.path.getsize(self.fixtures["synthetic_firmware"]), 12288)

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
            for idx, sl in enumerate(doc["slices"]):
                self.assertEqual(sl["header"]["filetype_name"], "MH_EXECUTE")
                self.assertTrue(sl["code_signature_detail"]["present"])
                self.assertTrue(sl["code_signature_detail"]["code_directory"]["cdhash_verified"])
                # Verify CMS certificate chain on Apple system binary
                certs = sl["code_signature_detail"]["cms_signature"]["certificates"]
                self.assertGreaterEqual(len(certs), 1)
                # Verify Chained Fixups on arm64e slice
                if sl["arch_name"] == "arm64e":
                    self.assertTrue(sl["dyld_info"]["has_chained_fixups"])
                    if sys_bin == "/bin/ls":
                        self.assertGreater(
                            sl["dyld_info"]["chained_fixups"]["imports_count"], 0
                        )

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
                self.assertEqual(len(presets_data["presets"]), 4)

            # 2. POST /api/parse
            req = Request(
                f"{base_url}/api/parse",
                data=json.dumps({"path": "/usr/bin/true"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req) as resp:
                self.assertEqual(resp.status, 200)
                doc = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(doc["file_info"]["filename"], "true")

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
        proc = subprocess.run(
            [sys.executable, script, "--cli", "/usr/bin/true", "--slice", "arm64e", "--disasm"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Mach-O Binary Analysis Report", proc.stdout)
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


if __name__ == "__main__":
    unittest.main()
