"""
Idempotent Synthetic Mach-O & Firmware Fixture Builder.
Generates:
1. `fixtures/synthetic_universal` (Universal Fat `arm64` + `x86_64` executable with C++/ObjC/C symbols,
   custom segments/sections, RPATH, Chained Fixups, and XML + DER Entitlements).
2. `fixtures/synthetic_firmware.preload` (`MH_PRELOAD` ARM64 standalone firmware image with
   `LC_UNIXTHREAD` ARM_THREAD_STATE64 register state, RWX segment, and raw ARM64 code/strings).
"""

import os
import struct
import subprocess
import tempfile
import uuid

from .constants import (
    CPU_TYPE_ARM64,
    LC_BUILD_VERSION,
    LC_SEGMENT_64,
    LC_SOURCE_VERSION,
    LC_SYMTAB,
    LC_UNIXTHREAD,
    LC_UUID,
    MH_MAGIC_64,
    MH_PRELOAD,
    VM_PROT_EXECUTE,
    VM_PROT_READ,
    VM_PROT_WRITE,
)


ENTITLEMENTS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.private.custom-firmware-inspect</key>
    <string>enabled-for-macho-viewer-test</string>
</dict>
</plist>
"""

SYNTHETIC_CPP_OBJC_SOURCE = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#import <Foundation/Foundation.h>

// Custom section in __TEXT and __DATA and __RODATA
__attribute__((used, section("__TEXT,__custom_code")))
extern "C" int custom_firmware_trampoline(int x) {
    return (x ^ 0x5A5A) + 42;
}

__attribute__((used, section("__DATA,__custom_data")))
uint64_t g_custom_magic_table[4] = {
    0xFEEDFACF11223344ULL,
    0xCAFEBABE55667788ULL,
    0xDEADBEEF99AABBCCULL,
    0x0123456789ABCDEFULL
};

__attribute__((used, section("__RODATA,__firmware_cfg")))
const char g_firmware_config_banner[] = "MACHO_VIEWER_SYNTHETIC_CFG_V2.5: PAC=ON; DEBUG=1; TARGET=AP_ROM";

// Thread-local variable to emit __DATA,__thread_vars
__thread int g_tls_counter = 1337;

// C++ mangled function (_Z14compute_cryptoPKhm)
__attribute__((used, visibility("default")))
uint64_t compute_crypto(const uint8_t* buf, size_t len) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= buf[i];
        hash *= 0x100000001b3ULL;
    }
    return hash + g_tls_counter;
}

namespace MachOViewerEngine {
    class PacketValidator {
    public:
        __attribute__((used, noinline))
        static bool verifyHeader(uint32_t magic, uint32_t flags) {
            return (magic == 0xfeedfacf) && ((flags & 1) == 0);
        }
    };
}

int main(int argc, char** argv) {
    @autoreleasepool {
        uint8_t stack_buf[64];
        memset(stack_buf, argc & 0xff, sizeof(stack_buf));
        uint64_t digest = compute_crypto(stack_buf, sizeof(stack_buf));
        bool ok = MachOViewerEngine::PacketValidator::verifyHeader(0xfeedfacf, (uint32_t)digest);
        NSString *label = [NSString stringWithUTF8String:g_firmware_config_banner];
        printf("Synthetic Universal Binary: %s | Digest=0x%llx | Trampoline=%d | Valid=%d\n",
               [label UTF8String],
               (unsigned long long)digest,
               custom_firmware_trampoline(argc),
               ok ? 1 : 0);
    }
    return 0;
}
"""


def _build_synthetic_universal(fixtures_dir: str) -> str:
    out_path = os.path.join(fixtures_dir, "synthetic_universal")
    ent_path = os.path.join(fixtures_dir, "entitlements.plist")

    with open(ent_path, "w", encoding="utf-8") as f:
        f.write(ENTITLEMENTS_XML)

    if os.path.isfile(out_path) and os.path.getsize(out_path) > 16384:
        return out_path

    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "synth.mm")
        arm64_bin = os.path.join(tmpdir, "synth_arm64")
        x86_bin = os.path.join(tmpdir, "synth_x86_64")

        with open(src_path, "w", encoding="utf-8") as f:
            f.write(SYNTHETIC_CPP_OBJC_SOURCE)

        common_flags = [
            "/usr/bin/clang++",
            "-std=c++17",
            "-O1",
            "-g0",
            "-fstack-protector-all",
            "-fobjc-arc",
            "-framework",
            "Foundation",
            "-Wl,-rpath,@executable_path/../Frameworks",
            "-Wl,-source_version,2048.12.4.1.0",
        ]

        subprocess.run(
            common_flags + ["-arch", "arm64", src_path, "-o", arm64_bin],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            common_flags + ["-arch", "x86_64", src_path, "-o", x86_bin],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["/usr/bin/lipo", "-create", x86_bin, arm64_bin, "-output", out_path],
            check=True,
            capture_output=True,
        )
        # Sign with ad-hoc signature + XML and DER Entitlements
        sign_cmd = [
            "/usr/bin/codesign",
            "-f",
            "-s",
            "-",
            "--entitlements",
            ent_path,
            "--generate-entitlement-der",
            out_path,
        ]
        res = subprocess.run(sign_cmd, capture_output=True)
        if res.returncode != 0:
            subprocess.run(
                ["/usr/bin/codesign", "-f", "-s", "-", "--entitlements", ent_path, out_path],
                check=True,
                capture_output=True,
            )

    return out_path


def _build_synthetic_firmware_preload(fixtures_dir: str) -> str:
    """
    Constructs a byte-exact `MH_PRELOAD` (filetype = 0x5) ARM64 standalone firmware binary
    with:
    - `LC_SEGMENT_64` (`__TEXT`, VM 0x180000000, r-x) containing `__text` and `__cstring`
    - `LC_SEGMENT_64` (`__FIRMWARE_RWX`, VM 0x180004000, rwx/rwx) with `S_REGULAR` + `S_ZEROFILL`
    - `LC_UNIXTHREAD` (`ARM_THREAD_STATE64`) setting initial `pc = 0x180000400`, `sp = 0x180020000`
    - `LC_SYMTAB` with firmware symbols (`_reset_vector`, `_iboot_early_init`, `_sep_mailbox_send`, `_panic_trap`)
    - `LC_UUID`, `LC_BUILD_VERSION` (`PLATFORM_FIRMWARE` = 13), `LC_SOURCE_VERSION`
    - Real ARM64/ARM64e machine instructions (`paciasp`, `stp`, `adrp`, `add`, `bl`, `svc`, `autiasp`, `retaa`)
    - Raw unsectioned firmware strings in `__FIRMWARE_RWX`
    """
    out_path = os.path.join(fixtures_dir, "synthetic_firmware.preload")
    if os.path.isfile(out_path) and os.path.getsize(out_path) >= 12288:
        return out_path

    base_vm = 0x180000000
    text_code_off = 0x400
    text_code_vm = base_vm + text_code_off

    cstring_off = 0x500
    cstring_vm = base_vm + cstring_off

    # Build __TEXT,__cstring payload
    cstrings_raw = (
        b"iBoot-9452.100.4~1 (SecureROM / AP Firmware Target)\x00"
        b"[SEP] Secure Enclave Mailbox Initialized @ 0x204000000\x00"
        b"PANIC: TrustCache hash verification failed in stage2\x00"
    )

    # Build ARM64 instructions at 0x180000400 (_reset_vector & _iboot_early_init)
    # 0x180000400: _reset_vector:
    #   paciasp                     (0xD503233F)
    #   stp x29, x30, [sp, #-16]!   (0xA9BF7BFD)
    #   mov x29, sp                 (0x910003FD)
    #   adrp x0, 0x180000000        (0x90000000)
    #   add x0, x0, #0x500          (0x91140000) -> points to "iBoot-9452.100.4~1..."
    #   bl 0x180000428              (0x94000005) -> calls _iboot_early_init
    #   mov x0, #0x0                (0xD2800000)
    #   ldp x29, x30, [sp], #16     (0xA8C17BFD)
    #   autiasp                     (0xD50323BF)
    #   retaa                       (0xD65F0BFF)
    # 0x180000428: _iboot_early_init:
    #   paciasp                     (0xD503233F)
    #   mov x1, #0x1337             (0xD28266E1)
    #   svc #0x80                   (0xD4001001)
    #   autiasp                     (0xD50323BF)
    #   retaa                       (0xD65F0BFF)
    # 0x18000043C: _panic_trap:
    #   brk #0xdead                 (0xD43BD5A0)
    #   ret                         (0xD65F03C0)
    arm64_words = [
        0xD503233F,
        0xA9BF7BFD,
        0x910003FD,
        0x90000000,
        0x91140000,
        0x94000005,
        0xD2800000,
        0xA8C17BFD,
        0xD50323BF,
        0xD65F0BFF,
        # _iboot_early_init (+0x28):
        0xD503233F,
        0xD28266E1,
        0xD4001001,
        0xD50323BF,
        0xD65F0BFF,
        # _panic_trap (+0x3C):
        0xD43BD5A0,
        0xD65F03C0,
    ]
    code_bytes = b"".join(struct.pack("<I", w) for w in arm64_words)

    # Construct Load Commands:
    # 1. LC_SEGMENT_64 (__TEXT) with 2 sections (__text, __cstring) -> 72 + 2*80 = 232 bytes
    seg_text_hdr = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        232,
        b"__TEXT".ljust(16, b"\x00"),
        base_vm,
        0x1000,
        0,
        0x1000,
        VM_PROT_READ | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_EXECUTE,
        2,
        0,
    )
    sect_text = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text".ljust(16, b"\x00"),
        b"__TEXT".ljust(16, b"\x00"),
        text_code_vm,
        len(code_bytes),
        text_code_off,
        2,
        0,
        0,
        0x80000400,  # S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
        0,
        0,
        0,
    )
    sect_cstring = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__cstring".ljust(16, b"\x00"),
        b"__TEXT".ljust(16, b"\x00"),
        cstring_vm,
        len(cstrings_raw),
        cstring_off,
        0,
        0,
        0,
        0x00000002,  # S_CSTRING_LITERALS
        0,
        0,
        0,
    )
    lc_seg_text = seg_text_hdr + sect_text + sect_cstring

    # 2. LC_SEGMENT_64 (__FIRMWARE_RWX) with 2 sections (__fw_patch, __bss) -> 72 + 2*80 = 232 bytes
    rwx_vm = base_vm + 0x1000
    rwx_fileoff = 0x1000
    rwx_prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
    seg_rwx_hdr = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        232,
        b"__FIRMWARE_RWX".ljust(16, b"\x00"),
        rwx_vm,
        0x2000,  # 0x1000 file-backed + 0x1000 S_ZEROFILL
        rwx_fileoff,
        0x1000,
        rwx_prot,
        rwx_prot,
        2,
        0,
    )
    sect_fw_patch = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__fw_patch".ljust(16, b"\x00"),
        b"__FIRMWARE_RWX".ljust(16, b"\x00"),
        rwx_vm,
        0x200,
        rwx_fileoff,
        3,
        0,
        0,
        0x00000400,  # S_REGULAR | S_ATTR_SOME_INSTRUCTIONS
        0,
        0,
        0,
    )
    sect_bss = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__bss".ljust(16, b"\x00"),
        b"__FIRMWARE_RWX".ljust(16, b"\x00"),
        rwx_vm + 0x1000,
        0x1000,
        0,
        4,
        0,
        0,
        0x00000001,  # S_ZEROFILL
        0,
        0,
        0,
    )
    lc_seg_rwx = seg_rwx_hdr + sect_fw_patch + sect_bss

    # 3. LC_UNIXTHREAD (ARM_THREAD_STATE64: flavor=6, count=68 -> 16 + 272 = 288 bytes)
    x_regs = [0] * 29
    x_regs[0] = base_vm + 0x1000  # boot_args pointer
    x_regs[1] = 0xCAFEBABE00000001
    fp_val = 0x18001FFF0
    lr_val = base_vm + 0x400
    sp_val = 0x180020000
    pc_val = text_code_vm
    cpsr_val = 0x600003C5  # EL1h with DAIF masked
    lc_unixthread = (
        struct.pack("<IIII", LC_UNIXTHREAD, 288, 6, 68)
        + b"".join(struct.pack("<Q", r) for r in x_regs)
        + struct.pack("<QQQQII", fp_val, lr_val, sp_val, pc_val, cpsr_val, 0)
    )

    # 4. LC_UUID (24 bytes)
    fw_uuid = uuid.UUID("18000400-cafe-4b00-9f00-deadbeef1337").bytes
    lc_uuid = struct.pack("<II16s", LC_UUID, 24, fw_uuid)

    # 5. LC_BUILD_VERSION (platform = 13 PLATFORM_FIRMWARE, 1 tool -> 32 bytes)
    lc_build_ver = struct.pack(
        "<IIIIIIII",
        LC_BUILD_VERSION,
        32,
        13,  # PLATFORM_FIRMWARE
        (18 << 16) | (2 << 8) | 0,
        (18 << 16) | (2 << 8) | 0,
        1,
        3,  # ld
        (1115 << 16) | (7 << 8) | 3,
    )

    # 6. LC_SOURCE_VERSION (16 bytes)
    src_ver_packed = (9452 << 40) | (100 << 30) | (4 << 20)
    lc_source_ver = struct.pack("<IIQ", LC_SOURCE_VERSION, 16, src_ver_packed)

    # 7. LC_SYMTAB (24 bytes) -> symbols at 0x2000, strings at 0x2040
    symoff = 0x2000
    sym_names = [
        b"_reset_vector",
        b"_iboot_early_init",
        b"_panic_trap",
        b"_g_fw_patch_table",
    ]
    strtab = b"\x00"
    str_offsets = []
    for sn in sym_names:
        str_offsets.append(len(strtab))
        strtab += sn + b"\x00"
    while len(strtab) % 8 != 0:
        strtab += b"\x00"

    nlist_entries = [
        # (n_strx, n_type=0x0F (N_SECT|N_EXT), n_sect=1, n_desc=0, n_value)
        struct.pack("<IBBHQ", str_offsets[0], 0x0F, 1, 0, text_code_vm),
        struct.pack("<IBBHQ", str_offsets[1], 0x0F, 1, 0, text_code_vm + 0x28),
        struct.pack("<IBBHQ", str_offsets[2], 0x0F, 1, 0, text_code_vm + 0x3C),
        struct.pack("<IBBHQ", str_offsets[3], 0x0F, 3, 0, rwx_vm),
    ]
    symtab_bytes = b"".join(nlist_entries)
    stroff = symoff + len(symtab_bytes)

    lc_symtab = struct.pack(
        "<IIIIII",
        LC_SYMTAB,
        24,
        symoff,
        len(nlist_entries),
        stroff,
        len(strtab),
    )

    all_lcs = (
        lc_seg_text
        + lc_seg_rwx
        + lc_unixthread
        + lc_uuid
        + lc_build_ver
        + lc_source_ver
        + lc_symtab
    )
    ncmds = 7

    # Mach-O 64-bit Header (ARM64e PAC capability subtype 0x80000002, MH_PRELOAD)
    mach_hdr = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        0x80000002,  # CPU_SUBTYPE_ARM64E (PAC ABI)
        MH_PRELOAD,
        ncmds,
        len(all_lcs),
        0x00000001,  # MH_NOUNDEFS
        0,
    )

    img = bytearray(0x3000)
    img[0 : len(mach_hdr)] = mach_hdr
    img[len(mach_hdr) : len(mach_hdr) + len(all_lcs)] = all_lcs
    img[text_code_off : text_code_off + len(code_bytes)] = code_bytes
    img[cstring_off : cstring_off + len(cstrings_raw)] = cstrings_raw

    # Populate RWX segment at 0x1000 with raw unsectioned firmware strings and patch trampolines
    fw_raw_payload = (
        b"FIRMWARE_RAW_TAG::BOOT_ARGS_REV=3::BOARD_ID=0x2A::JTAG_LOCKED=1\x00"
        b"AUTH_MANIFEST::SEP_FIRMWARE_VERSION=2150.40.2\x00"
    )
    img[rwx_fileoff : rwx_fileoff + len(fw_raw_payload)] = fw_raw_payload
    img[symoff : symoff + len(symtab_bytes)] = symtab_bytes
    img[stroff : stroff + len(strtab)] = strtab

    with open(out_path, "wb") as f:
        f.write(img)

    return out_path


def ensure_fixtures(workspace_root: str) -> dict:
    fixtures_dir = os.path.join(os.path.abspath(workspace_root), "fixtures")
    os.makedirs(fixtures_dir, exist_ok=True)
    univ_path = _build_synthetic_universal(fixtures_dir)
    fw_path = _build_synthetic_firmware_preload(fixtures_dir)
    return {
        "synthetic_universal": univ_path,
        "synthetic_firmware": fw_path,
    }
