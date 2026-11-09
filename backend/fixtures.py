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


def _build_synthetic_elf64(fixtures_dir: str) -> str:
    """
    Constructs a byte-exact 64-bit Linux x86_64 PIE (`ET_DYN`) ELF64 binary with:
    - `PT_PHDR`, `PT_INTERP` (`/lib64/ld-linux-x86-64.so.2`), `PT_LOAD` (R, R-X, RW),
      `PT_DYNAMIC`, `PT_NOTE`, `PT_GNU_STACK` (RW, NX enabled), `PT_GNU_RELRO` (Full RELRO with `DF_BIND_NOW`)
    - `.note.ABI-tag` (Linux 5.15.0), `.note.gnu.build-id` (SHA-1), `.note.gnu.property` (Intel CET `IBT | SHSTK`)
    - `.dynsym` & `.dynstr` with `__stack_chk_fail`, `__cxa_finalize`, `puts`, `socket`, `_Z14compute_cryptoPKhm`
    - `.rela.dyn` & `.rela.plt` (`R_X86_64_JUMP_SLOT`, `R_X86_64_GLOB_DAT`, `R_X86_64_RELATIVE`)
    - `.plt` & `.text` with real x86_64 instructions (`endbr64`, `push rbp`, `mov rbp, rsp`, `call`, `leave`, `ret`)
    - `.rodata` with telemetry & URL strings, `.dynamic`, `.got`, `.data`, `.bss`, `.comment`, `.symtab`, `.strtab`, `.shstrtab`
    """
    out_path = os.path.join(fixtures_dir, "synthetic_elf64")
    if os.path.isfile(out_path) and os.path.getsize(out_path) >= 8192:
        return out_path

    img = bytearray(0x3000)

    # Layout offsets:
    # 0x0000: Elf64_Ehdr (64 bytes)
    # 0x0040: Elf64_Phdr * 9 (9 * 56 = 504 bytes -> 0x0040..0x0238)
    # 0x0240: .interp (28 bytes)
    # 0x0260: .note.ABI-tag + .note.gnu.build-id + .note.gnu.property (100 bytes)
    # 0x0300: .dynsym (6 * 24 = 144 bytes)
    # 0x0390: .dynstr (160 bytes)
    # 0x0440: .rela.dyn (2 * 24 = 48 bytes)
    # 0x0470: .rela.plt (3 * 24 = 72 bytes)
    # 0x1000: .plt (48 bytes)
    # 0x1040: .text (64 bytes)
    # 0x1080: .rodata (192 bytes)
    # 0x2000: .dynamic (14 * 16 = 224 bytes)
    # 0x2100: .got (64 bytes)
    # 0x2140: .data (64 bytes)
    # 0x2200: .comment (44 bytes)
    # 0x2240: .symtab (7 * 24 = 168 bytes)
    # 0x22E8: .strtab (140 bytes)
    # 0x2380: .shstrtab (180 bytes)
    # 0x2440: Elf64_Shdr * 16 (16 * 64 = 1024 bytes)

    interp_bytes = b"/lib64/ld-linux-x86-64.so.2\x00"
    img[0x240 : 0x240 + len(interp_bytes)] = interp_bytes

    # Build notes at 0x260:
    # 1. NT_GNU_ABI_TAG (type=1): namesz=4 ("GNU\0"), descsz=16 (OS=0 Linux, 5.15.0)
    note_abi = struct.pack("<III4sIIII", 4, 16, 1, b"GNU\x00", 0, 5, 15, 0)
    # 2. NT_GNU_BUILD_ID (type=3): namesz=4 ("GNU\0"), descsz=20
    build_id_bytes = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f9011223344")
    note_bid = struct.pack("<III4s20s", 4, 20, 3, b"GNU\x00", build_id_bytes)
    # 3. NT_GNU_PROPERTY_TYPE_0 (type=5): namesz=4 ("GNU\0"), descsz=16
    # pr_type = 0xc0000002 (GNU_PROPERTY_X86_FEATURE_1_AND), pr_datasz = 4, data = 3 (IBT | SHSTK), pad = 4B
    note_prop = struct.pack("<III4sIIII", 4, 16, 5, b"GNU\x00", 0xC0000002, 4, 0x3, 0)
    notes_blob = note_abi + note_bid + note_prop
    img[0x260 : 0x260 + len(notes_blob)] = notes_blob

    # Build .dynstr at 0x390
    dynstr_list = [
        b"libc.so.6",
        b"libcrypto.so.3",
        b"$ORIGIN/../lib",
        b"__stack_chk_fail",
        b"__cxa_finalize",
        b"puts",
        b"socket",
        b"_Z14compute_cryptoPKhm",
    ]
    dynstr = b"\x00"
    dynstr_offs = {}
    for s in dynstr_list:
        dynstr_offs[s] = len(dynstr)
        dynstr += s + b"\x00"
    img[0x390 : 0x390 + len(dynstr)] = dynstr

    # Build .dynsym at 0x300 (Elf64_Sym: <IBBHQQ = 24 bytes)
    # STB_GLOBAL=1, STT_FUNC=2 -> st_info = (1<<4)|2 = 0x12
    dynsyms = [
        struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0),  # STN_UNDEF
        struct.pack("<IBBHQQ", dynstr_offs[b"__stack_chk_fail"], 0x12, 0, 0, 0, 0),
        struct.pack("<IBBHQQ", dynstr_offs[b"__cxa_finalize"], 0x22, 0, 0, 0, 0),  # STB_WEAK|STT_FUNC
        struct.pack("<IBBHQQ", dynstr_offs[b"puts"], 0x12, 0, 0, 0, 0),
        struct.pack("<IBBHQQ", dynstr_offs[b"socket"], 0x12, 0, 0, 0, 0),
        struct.pack("<IBBHQQ", dynstr_offs[b"_Z14compute_cryptoPKhm"], 0x12, 0, 6, 0x1040, 36),
    ]
    dynsym_blob = b"".join(dynsyms)
    img[0x300 : 0x300 + len(dynsym_blob)] = dynsym_blob

    # Build .rela.dyn at 0x440 (2 entries * 24B)
    # R_X86_64_RELATIVE = 8, R_X86_64_GLOB_DAT = 6
    rela_dyn = struct.pack("<QQq", 0x2140, (0 << 32) | 8, 0x1040) + struct.pack(
        "<QQq", 0x2100, (2 << 32) | 6, 0
    )
    img[0x440 : 0x440 + len(rela_dyn)] = rela_dyn

    # Build .rela.plt at 0x470 (3 entries * 24B, R_X86_64_JUMP_SLOT = 7)
    rela_plt = (
        struct.pack("<QQq", 0x2108, (1 << 32) | 7, 0)
        + struct.pack("<QQq", 0x2110, (3 << 32) | 7, 0)
        + struct.pack("<QQq", 0x2118, (4 << 32) | 7, 0)
    )
    img[0x470 : 0x470 + len(rela_plt)] = rela_plt

    # Build .plt at 0x1000 (48 bytes)
    plt_code = (
        b"\xf3\x0f\x1e\xfa"  # endbr64
        b"\xff\x25\xfe\x10\x00\x00"  # jmp qword ptr [rip + 0x10fe]
        b"\x68\x00\x00\x00\x00"  # push 0x0
        b"\xe9\xe0\xff\xff\xff"  # jmp 0xfff0
    ).ljust(48, b"\x90")
    img[0x1000 : 0x1000 + len(plt_code)] = plt_code

    # Build .text at 0x1040 (64 bytes of clean x86_64 instructions)
    # 0x1040 (_Z14compute_cryptoPKhm & main):
    #   f3 0f 1e fa              endbr64
    #   55                       push rbp
    #   48 89 e5                 mov rbp, rsp
    #   48 83 ec 20              sub rsp, 0x20
    #   48 8d 3d 31 00 00 00     lea rdi, [rip + 0x31]  ; -> 0x1080 (.rodata string)
    #   e8 ab ff ff ff           call 0x1000            ; -> .plt
    #   31 c0                    xor eax, eax
    #   c9                       leave
    #   c3                       ret
    #   0f 05                    syscall
    #   c3                       ret
    text_code = (
        b"\xf3\x0f\x1e\xfa"
        b"\x55"
        b"\x48\x89\xe5"
        b"\x48\x83\xec\x20"
        b"\x48\x8d\x3d\x31\x00\x00\x00"
        b"\xe8\xab\xff\xff\xff"
        b"\x31\xc0"
        b"\xc9"
        b"\xc3"
        b"\x0f\x05"
        b"\xc3"
    ).ljust(64, b"\x90")
    img[0x1040 : 0x1040 + len(text_code)] = text_code

    # Build .rodata at 0x1080
    rodata_bytes = (
        b"ELF64_SYNTHETIC_SERVICE_V3.0: TLS=1.3; ENDPOINT=https://telemetry.binarystudio.dev/v1/heartbeat\x00"
        b"/etc/ssl/certs/ca-certificates.crt\x00"
        b"AES-256-GCM hardware acceleration enabled\x00"
    )
    img[0x1080 : 0x1080 + len(rodata_bytes)] = rodata_bytes

    # Build .dynamic at 0x2000 (Elf64_Dyn: <qQ = 16 bytes)
    dyn_entries = [
        (1, dynstr_offs[b"libc.so.6"]),  # DT_NEEDED
        (1, dynstr_offs[b"libcrypto.so.3"]),  # DT_NEEDED
        (29, dynstr_offs[b"$ORIGIN/../lib"]),  # DT_RUNPATH
        (5, 0x0390),  # DT_STRTAB
        (6, 0x0300),  # DT_SYMTAB
        (10, len(dynstr)),  # DT_STRSZ
        (11, 24),  # DT_SYMENT
        (7, 0x0440),  # DT_RELA
        (8, len(rela_dyn)),  # DT_RELASZ
        (9, 24),  # DT_RELAENT
        (23, 0x0470),  # DT_JMPREL
        (2, len(rela_plt)),  # DT_PLTRELSZ
        (20, 7),  # DT_PLTREL (DT_RELA)
        (24, 1),  # DT_BIND_NOW
        (30, 0x8),  # DT_FLAGS (DF_BIND_NOW)
        (0x6FFFFFFB, 0x8000001),  # DT_FLAGS_1 (DF_1_NOW | DF_1_PIE)
        (0, 0),  # DT_NULL
    ]
    dyn_blob = b"".join(struct.pack("<qQ", tag, val) for tag, val in dyn_entries)
    img[0x2000 : 0x2000 + len(dyn_blob)] = dyn_blob

    # Build .got at 0x2100 and .data at 0x2140
    img[0x2100 : 0x2120] = struct.pack("<QQQQ", 0x2000, 0x1000, 0x1000, 0x1000)
    img[0x2140 : 0x2160] = b"SYNTHETIC_ELF64_GLOBAL_STATE\x00".ljust(32, b"\x00")

    # Build .comment at 0x2200
    comment_bytes = b"\x00GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0\x00"
    img[0x2200 : 0x2200 + len(comment_bytes)] = comment_bytes

    # Build .strtab at 0x22E8 and .symtab at 0x2240
    strtab_list = [
        b"_start",
        b"main",
        b"_Z14compute_cryptoPKhm",
        b"g_service_config",
        b"__stack_chk_fail",
        b"puts",
    ]
    strtab = b"\x00"
    strtab_offs = {}
    for s in strtab_list:
        strtab_offs[s] = len(strtab)
        strtab += s + b"\x00"
    img[0x22E8 : 0x22E8 + len(strtab)] = strtab

    symtab_entries = [
        struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0),
        struct.pack("<IBBHQQ", strtab_offs[b"_start"], 0x12, 0, 6, 0x1040, 20),
        struct.pack("<IBBHQQ", strtab_offs[b"main"], 0x12, 0, 6, 0x1040, 36),
        struct.pack("<IBBHQQ", strtab_offs[b"_Z14compute_cryptoPKhm"], 0x12, 0, 6, 0x1058, 24),
        struct.pack("<IBBHQQ", strtab_offs[b"g_service_config"], 0x11, 0, 10, 0x2140, 32),
        struct.pack("<IBBHQQ", strtab_offs[b"__stack_chk_fail"], 0x12, 0, 0, 0, 0),
        struct.pack("<IBBHQQ", strtab_offs[b"puts"], 0x12, 0, 0, 0, 0),
    ]
    symtab_blob = b"".join(symtab_entries)
    img[0x2240 : 0x2240 + len(symtab_blob)] = symtab_blob

    # Build .shstrtab at 0x2380
    sec_names = [
        b"",
        b".interp",
        b".note.gnu.build-id",
        b".dynsym",
        b".dynstr",
        b".rela.dyn",
        b".rela.plt",
        b".plt",
        b".text",
        b".rodata",
        b".dynamic",
        b".got",
        b".data",
        b".bss",
        b".comment",
        b".symtab",
        b".strtab",
        b".shstrtab",
    ]
    shstrtab = b""
    sh_offs = {}
    for sn in sec_names:
        sh_offs[sn] = len(shstrtab)
        shstrtab += sn + b"\x00"
    img[0x2380 : 0x2380 + len(shstrtab)] = shstrtab

    # Build Program Headers at 0x0040 (9 * 56 bytes)
    # Elf64_Phdr: <IIQQQQQQ (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)
    phdrs = [
        # PT_PHDR (6), PF_R (4)
        struct.pack("<IIQQQQQQ", 6, 4, 0x40, 0x40, 0x40, 9 * 56, 9 * 56, 8),
        # PT_INTERP (3), PF_R (4)
        struct.pack("<IIQQQQQQ", 3, 4, 0x240, 0x240, 0x240, len(interp_bytes), len(interp_bytes), 1),
        # PT_LOAD #0 (1), PF_R (4) - headers, notes, dynsym, rela
        struct.pack("<IIQQQQQQ", 1, 4, 0x0, 0x0, 0x0, 0x500, 0x500, 0x1000),
        # PT_LOAD #1 (1), PF_R|PF_X (5) - .plt, .text, .rodata
        struct.pack("<IIQQQQQQ", 1, 5, 0x1000, 0x1000, 0x1000, 0x200, 0x200, 0x1000),
        # PT_LOAD #2 (1), PF_R|PF_W (6) - .dynamic, .got, .data, .bss
        struct.pack("<IIQQQQQQ", 1, 6, 0x2000, 0x2000, 0x2000, 0x180, 0x280, 0x1000),
        # PT_DYNAMIC (2), PF_R|PF_W (6)
        struct.pack("<IIQQQQQQ", 2, 6, 0x2000, 0x2000, 0x2000, len(dyn_blob), len(dyn_blob), 8),
        # PT_NOTE (4), PF_R (4)
        struct.pack("<IIQQQQQQ", 4, 4, 0x260, 0x260, 0x260, len(notes_blob), len(notes_blob), 4),
        # PT_GNU_STACK (0x6474e551), PF_R|PF_W (6) -> non-executable stack
        struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16),
        # PT_GNU_RELRO (0x6474e552), PF_R (4)
        struct.pack("<IIQQQQQQ", 0x6474E552, 4, 0x2000, 0x2000, 0x2000, 0x140, 0x140, 1),
    ]
    phdrs_blob = b"".join(phdrs)
    img[0x40 : 0x40 + len(phdrs_blob)] = phdrs_blob

    # Build Section Headers at 0x2440 (18 * 64 bytes)
    # Elf64_Shdr: <IIQQQQIIQQ (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize)
    shdrs = [
        struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),  # 0: SHT_NULL
        struct.pack("<IIQQQQIIQQ", sh_offs[b".interp"], 1, 0x2, 0x240, 0x240, len(interp_bytes), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".note.gnu.build-id"], 7, 0x2, 0x260, 0x260, len(notes_blob), 0, 0, 4, 0),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".dynsym"], 11, 0x2, 0x300, 0x300, len(dynsym_blob), 4, 1, 8, 24),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".dynstr"], 3, 0x2, 0x390, 0x390, len(dynstr), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".rela.dyn"], 4, 0x2, 0x440, 0x440, len(rela_dyn), 3, 0, 8, 24),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".rela.plt"], 4, 0x42, 0x470, 0x470, len(rela_plt), 3, 11, 8, 24),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".plt"], 1, 0x6, 0x1000, 0x1000, len(plt_code), 0, 0, 16, 16),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".text"], 1, 0x6, 0x1040, 0x1040, len(text_code), 0, 0, 16, 0),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".rodata"], 1, 0x2, 0x1080, 0x1080, len(rodata_bytes), 0, 0, 8, 0),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".dynamic"], 6, 0x3, 0x2000, 0x2000, len(dyn_blob), 4, 0, 8, 16),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".got"], 1, 0x3, 0x2100, 0x2100, 0x20, 0, 0, 8, 8),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".data"], 1, 0x3, 0x2140, 0x2140, 0x20, 0, 0, 8, 0),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".bss"], 8, 0x3, 0x2180, 0x2180, 0x100, 0, 0, 8, 0),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".comment"], 1, 0x30, 0, 0x2200, len(comment_bytes), 0, 0, 1, 1),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".symtab"], 2, 0, 0, 0x2240, len(symtab_blob), 16, 1, 8, 24),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".strtab"], 3, 0, 0, 0x22E8, len(strtab), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", sh_offs[b".shstrtab"], 3, 0, 0, 0x2380, len(shstrtab), 0, 0, 1, 0),
    ]
    shdrs_blob = b"".join(shdrs)
    img[0x2440 : 0x2440 + len(shdrs_blob)] = shdrs_blob

    # Build Elf64_Ehdr at 0x0000 (64 bytes)
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        3,  # ET_DYN (PIE executable)
        62,  # EM_X86_64
        1,  # EV_CURRENT
        0x1040,  # e_entry
        0x40,  # e_phoff
        0x2440,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        len(phdrs),  # e_phnum
        64,  # e_shentsize
        len(shdrs),  # e_shnum
        17,  # e_shstrndx
    )
    img[0:64] = ehdr

    with open(out_path, "wb") as f:
        f.write(img)
    return out_path


def _build_synthetic_elf32(fixtures_dir: str) -> str:
    """
    Constructs a byte-exact 32-bit x86 (`EM_386`) ELF32 executable (`ET_EXEC`) with:
    - Non-PIE fixed base `0x08048000`
    - Executable stack (`PT_GNU_STACK` with `PF_R | PF_W | PF_X`) to exercise security warnings
    - `.text`, `.rodata`, `.data`, `.symtab`, `.strtab`, `.shstrtab`
    """
    out_path = os.path.join(fixtures_dir, "synthetic_elf32")
    if os.path.isfile(out_path) and os.path.getsize(out_path) >= 4096:
        return out_path

    img = bytearray(0x1800)
    base_va = 0x08048000

    # x86 32-bit instructions at 0x0400 (.text):
    # 55             push ebp
    # 89 e5          mov ebp, esp
    # 83 ec 10       sub esp, 0x10
    # 31 c0          xor eax, eax
    # c9             leave
    # c3             ret
    text32 = b"\x55\x89\xe5\x83\xec\x10\x31\xc0\xc9\xc3".ljust(32, b"\x90")
    img[0x400 : 0x400 + len(text32)] = text32

    rodata32 = b"ELF32_LEGACY_I386_BINARY_BANNER\x00/bin/sh\x00"
    img[0x440 : 0x440 + len(rodata32)] = rodata32

    # .strtab at 0x600, .symtab at 0x500 (Elf32_Sym: <IIIBBH = 16 bytes)
    strtab = b"\x00_start\x00legacy_exec_helper\x00"
    img[0x600 : 0x600 + len(strtab)] = strtab
    syms32 = [
        struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0),
        struct.pack("<IIIBBH", 1, base_va + 0x400, 16, 0x12, 0, 1),
        struct.pack("<IIIBBH", 8, base_va + 0x410, 16, 0x12, 0, 1),
    ]
    sym_blob = b"".join(syms32)
    img[0x500 : 0x500 + len(sym_blob)] = sym_blob

    shstr = b"\x00.text\x00.rodata\x00.symtab\x00.strtab\x00.shstrtab\x00"
    img[0x700 : 0x700 + len(shstr)] = shstr

    # Elf32_Phdr: <IIIIIIII (32 bytes each) at 0x34
    phdrs32 = [
        # PT_LOAD (1): R-X
        struct.pack("<IIIIIIII", 1, 0, base_va, base_va, 0x500, 0x500, 5, 0x1000),
        # PT_GNU_STACK (0x6474e551): RWE (7 = PF_R|PF_W|PF_X) -> triggers executable stack warning!
        struct.pack("<IIIIIIII", 0x6474E551, 0, 0, 0, 0, 0, 7, 4),
    ]
    ph_blob = b"".join(phdrs32)
    img[0x34 : 0x34 + len(ph_blob)] = ph_blob

    # Elf32_Shdr: <IIIIIIIIII (40 bytes each) at 0x800
    shdrs32 = [
        struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        struct.pack("<IIIIIIIIII", 1, 1, 6, base_va + 0x400, 0x400, len(text32), 0, 0, 16, 0),
        struct.pack("<IIIIIIIIII", 7, 1, 2, base_va + 0x440, 0x440, len(rodata32), 0, 0, 4, 0),
        struct.pack("<IIIIIIIIII", 15, 2, 0, 0, 0x500, len(sym_blob), 4, 1, 4, 16),
        struct.pack("<IIIIIIIIII", 23, 3, 0, 0, 0x600, len(strtab), 0, 0, 1, 0),
        struct.pack("<IIIIIIIIII", 31, 3, 0, 0, 0x700, len(shstr), 0, 0, 1, 0),
    ]
    sh_blob = b"".join(shdrs32)
    img[0x800 : 0x800 + len(sh_blob)] = shdrs_blob = sh_blob

    e_ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8
    ehdr32 = struct.pack(
        "<16sHHIIIIIHHHHHH",
        e_ident,
        2,  # ET_EXEC (non-PIE)
        3,  # EM_386
        1,
        base_va + 0x400,
        0x34,
        0x800,
        0,
        52,
        32,
        len(phdrs32),
        40,
        len(shdrs32),
        5,
    )
    img[0:52] = ehdr32

    with open(out_path, "wb") as f:
        f.write(img)
    return out_path


def _build_synthetic_pe64(fixtures_dir: str) -> str:
    """
    Constructs a byte-exact 64-bit Windows PE32+ (`IMAGE_FILE_MACHINE_AMD64`) executable with:
    - DOS Header (`MZ`) + DOS stub + XOR-encrypted Microsoft Rich Header (`DanS`..`Rich`)
    - `IMAGE_NT_HEADERS64` (`PE\\0\\0`, `0x20B` PE32+, `IMAGE_SUBSYSTEM_WINDOWS_CUI`,
      `DYNAMIC_BASE | HIGH_ENTROPY_VA | NX_COMPAT | GUARD_CF`)
    - 3 Sections: `.text` (RVA `0x1000`), `.rdata` (RVA `0x2000`), `.reloc` (RVA `0x3000`)
    - Import Directory importing `KERNEL32.dll` (`GetProcAddress`, `VirtualAlloc`, `CreateProcessW`)
      and `WS2_32.dll` (`WSAStartup`, ordinal `#115`)
    - Export Directory exporting `InitializeEngine` and a forwarded export `LegacyAlloc -> NTDLL.RtlAllocateHeap`
    - Debug Directory with `IMAGE_DEBUG_TYPE_CODEVIEW` (`RSDS` PDB signature, GUID, age, PDB path)
    - Load Config Directory (`SecurityCookie` `/GS` + Control Flow Guard flags)
    - Base Relocation Table (`.reloc` with `IMAGE_REL_BASED_DIR64`)
    - Security Directory (`WIN_CERTIFICATE` Authenticode PKCS#7 signed data with CN=`BinaryStudio Synthetic Corp`)
    """
    out_path = os.path.join(fixtures_dir, "synthetic_pe64.exe")
    if os.path.isfile(out_path) and os.path.getsize(out_path) >= 6144:
        return out_path

    img = bytearray(0x1C00)
    image_base = 0x140000000

    # 1. DOS Header at 0x0000 (64 bytes, e_lfanew = 0x100)
    dos_hdr = bytearray(64)
    struct.pack_into("<HH", dos_hdr, 0, 0x5A4D, 0x0090)
    struct.pack_into("<I", dos_hdr, 0x3C, 0x100)
    img[0:64] = dos_hdr
    dos_msg = b"This program cannot be run in DOS mode.\r\r\n$"
    img[0x40 : 0x40 + len(dos_msg)] = dos_msg

    # 2. XOR-encoded Rich Header at 0x80..0xC0
    xor_key = 0x5A3C9E17
    rich_plain = [
        0x536E6144 ^ xor_key,  # "DanS"
        0 ^ xor_key,
        0 ^ xor_key,
        0 ^ xor_key,
        ((0x0104 << 16) | 30139) ^ xor_key,  # Utc1900_C (prod_id=0x104, build=30139)
        14 ^ xor_key,
        ((0x0105 << 16) | 30139) ^ xor_key,  # Utc1900_CPP (prod_id=0x105, build=30139)
        9 ^ xor_key,
        ((0x0102 << 16) | 30139) ^ xor_key,  # Linker1400 (prod_id=0x102, build=30139)
        1 ^ xor_key,
        0x68636952,  # "Rich"
        xor_key,
    ]
    rich_bytes = b"".join(struct.pack("<I", w) for w in rich_plain)
    img[0x80 : 0x80 + len(rich_bytes)] = rich_bytes

    # 3. NT Headers at 0x100:
    # Signature (4B) + FileHeader (20B) + OptionalHeader64 (240B) = 264 bytes (0x100..0x208)
    # 3 Section Headers (3 * 40B = 120B) at 0x208..0x280
    nt_off = 0x100
    img[nt_off : nt_off + 4] = b"PE\x00\x00"

    # IMAGE_FILE_HEADER (20B): Machine=0x8664 (AMD64), NumberOfSections=3, TimeDateStamp=0x65F0A120,
    # PointerToSymbolTable=0, NumberOfSymbols=0, SizeOfOptionalHeader=240, Characteristics=0x0022 (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)
    file_hdr = struct.pack("<HHIIIHH", 0x8664, 3, 0x65F0A120, 0, 0, 240, 0x0022)
    img[nt_off + 4 : nt_off + 24] = file_hdr

    # Data Directories (16 * 8B = 128B):
    # 0: Export (RVA 0x2300, sz 0x90)
    # 1: Import (RVA 0x2000, sz 60)
    # 4: Security (FileOffset 0x1800, sz 0x240)
    # 5: BaseReloc (RVA 0x3000, sz 16)
    # 6: Debug (RVA 0x2400, sz 28)
    # 10: LoadConfig (RVA 0x2500, sz 112)
    # 12: IAT (RVA 0x2080, sz 56)
    data_dirs = [(0, 0)] * 16
    data_dirs[0] = (0x2300, 0x90)
    data_dirs[1] = (0x2000, 60)
    data_dirs[4] = (0x1800, 0x240)
    data_dirs[5] = (0x3000, 16)
    data_dirs[6] = (0x2400, 28)
    data_dirs[10] = (0x2500, 112)
    data_dirs[12] = (0x2080, 56)

    # DllCharacteristics = 0x4160 (HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | GUARD_CF)
    opt_hdr_fixed = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # Magic (PE32+)
        14,
        38,  # Linker 14.38
        0x400,  # SizeOfCode
        0x800,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        0x1000,  # AddressOfEntryPoint
        0x1000,  # BaseOfCode
        image_base,  # ImageBase
        0x1000,  # SectionAlignment
        0x200,  # FileAlignment
        10,
        0,  # OS Version 10.0
        1,
        0,  # Image Version 1.0
        10,
        0,  # Subsystem Version 10.0
        0,  # Win32VersionValue
        0x4000,  # SizeOfImage
        0x400,  # SizeOfHeaders
        0x00018A42,  # CheckSum
        3,  # Subsystem (WINDOWS_CUI)
        0x4160,  # DllCharacteristics
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )
    opt_hdr = opt_hdr_fixed + b"".join(struct.pack("<II", rva, sz) for rva, sz in data_dirs)
    img[nt_off + 24 : nt_off + 264] = opt_hdr

    # Section Headers at 0x208 (3 * 40 bytes):
    # 1. .text: RVA 0x1000, VSize 0x300, RawPtr 0x400, RawSize 0x400, Characteristics 0x60000020 (CNT_CODE | MEM_EXECUTE | MEM_READ)
    # 2. .rdata: RVA 0x2000, VSize 0x700, RawPtr 0x800, RawSize 0xC00, Characteristics 0x40000040 (CNT_INITIALIZED_DATA | MEM_READ)
    # 3. .reloc: RVA 0x3000, VSize 0x100, RawPtr 0x1400, RawSize 0x400, Characteristics 0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
    sh_off = nt_off + 264
    sec_hdrs = (
        struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x300, 0x1000, 0x400, 0x400, 0, 0, 0, 0, 0x60000020)
        + struct.pack("<8sIIIIIIHHI", b".rdata\x00\x00", 0x700, 0x2000, 0xC00, 0x800, 0, 0, 0, 0, 0x40000040)
        + struct.pack("<8sIIIIIIHHI", b".reloc\x00\x00", 0x100, 0x3000, 0x400, 0x1400, 0, 0, 0, 0, 0x42000040)
    )
    img[sh_off : sh_off + len(sec_hdrs)] = sec_hdrs

    # 4. Populate .text at file offset 0x400 (RVA 0x1000)
    pe_code = (
        b"\xf3\x0f\x1e\xfa"  # endbr64
        b"\x55"  # push rbp
        b"\x48\x89\xe5"  # mov rbp, rsp
        b"\x48\x83\xec\x20"  # sub rsp, 0x20
        b"\x48\x8d\x0d\x69\x15\x00\x00"  # lea rcx, [rip + 0x1569]
        b"\xff\x15\x6b\x10\x00\x00"  # call qword ptr [rip + 0x106b] (IAT)
        b"\x31\xc0"  # xor eax, eax
        b"\xc9"  # leave
        b"\xc3"  # ret
    ).ljust(64, b"\x90")
    img[0x400 : 0x400 + len(pe_code)] = pe_code

    # 5. Populate .rdata at file offset 0x800 (RVA 0x2000; file_off = rva - 0x2000 + 0x800 = rva - 0x1800)
    def rva_to_off(rva: int) -> int:
        return rva - 0x1800

    # Import Descriptors at RVA 0x2000 (3 * 20B = 60B):
    # Desc 0: KERNEL32.dll (ILT=0x2040, Name=0x2100, IAT=0x2080)
    # Desc 1: WS2_32.dll   (ILT=0x2060, Name=0x2110, IAT=0x20A0)
    # Desc 2: Null terminator
    imp_descs = (
        struct.pack("<IIIII", 0x2040, 0, 0, 0x2100, 0x2080)
        + struct.pack("<IIIII", 0x2060, 0, 0, 0x2110, 0x20A0)
        + struct.pack("<IIIII", 0, 0, 0, 0, 0)
    )
    img[rva_to_off(0x2000) : rva_to_off(0x2000) + len(imp_descs)] = imp_descs

    # Hint/Name table entries at RVA 0x2120..0x21A0:
    img[rva_to_off(0x2100) : rva_to_off(0x2100) + 13] = b"KERNEL32.dll\x00"
    img[rva_to_off(0x2110) : rva_to_off(0x2110) + 11] = b"WS2_32.dll\x00"

    hn1 = struct.pack("<H", 0x01A2) + b"GetProcAddress\x00\x00"
    hn2 = struct.pack("<H", 0x03C0) + b"VirtualAlloc\x00\x00"
    hn3 = struct.pack("<H", 0x0088) + b"CreateProcessW\x00\x00"
    hn4 = struct.pack("<H", 0x0073) + b"WSAStartup\x00\x00"
    img[rva_to_off(0x2120) : rva_to_off(0x2120) + len(hn1)] = hn1
    img[rva_to_off(0x2138) : rva_to_off(0x2138) + len(hn2)] = hn2
    img[rva_to_off(0x2150) : rva_to_off(0x2150) + len(hn3)] = hn3
    img[rva_to_off(0x2168) : rva_to_off(0x2168) + len(hn4)] = hn4

    # ILT & IAT for KERNEL32.dll (RVA 0x2040 and 0x2080)
    k32_thunks = struct.pack("<QQQQ", 0x2120, 0x2138, 0x2150, 0)
    img[rva_to_off(0x2040) : rva_to_off(0x2040) + len(k32_thunks)] = k32_thunks
    img[rva_to_off(0x2080) : rva_to_off(0x2080) + len(k32_thunks)] = k32_thunks

    # ILT & IAT for WS2_32.dll (RVA 0x2060 and 0x20A0) -> 1 by name (0x2168) + 1 by ordinal (#115)
    ws2_thunks = struct.pack("<QQQ", 0x2168, (1 << 63) | 115, 0)
    img[rva_to_off(0x2060) : rva_to_off(0x2060) + len(ws2_thunks)] = ws2_thunks
    img[rva_to_off(0x20A0) : rva_to_off(0x20A0) + len(ws2_thunks)] = ws2_thunks

    # Export Directory at RVA 0x2300 (size 0x90 -> 0x2300..0x2390)
    # 2 exported functions:
    # - InitializeEngine -> RVA 0x1000 (.text)
    # - LegacyAlloc      -> RVA 0x2368 (inside export dir -> forwarded to "NTDLL.RtlAllocateHeap")
    exp_dir = struct.pack(
        "<IIHHIIIIIII",
        0,
        0x65F0A120,
        1,
        0,
        0x2340,  # Name RVA ("synthetic_pe64.exe")
        1,  # Base = 1
        2,  # NumberOfFunctions = 2
        2,  # NumberOfNames = 2
        0x2328,  # AddressOfFunctions
        0x2330,  # AddressOfNames
        0x2338,  # AddressOfNameOrdinals
    )
    img[rva_to_off(0x2300) : rva_to_off(0x2300) + 40] = exp_dir
    img[rva_to_off(0x2328) : rva_to_off(0x2328) + 8] = struct.pack("<II", 0x1000, 0x2368)
    img[rva_to_off(0x2330) : rva_to_off(0x2330) + 8] = struct.pack("<II", 0x2354, 0x2380)
    img[rva_to_off(0x2338) : rva_to_off(0x2338) + 4] = struct.pack("<HH", 0, 1)
    img[rva_to_off(0x2340) : rva_to_off(0x2340) + 19] = b"synthetic_pe64.exe\x00"
    img[rva_to_off(0x2354) : rva_to_off(0x2354) + 17] = b"InitializeEngine\x00"
    img[rva_to_off(0x2368) : rva_to_off(0x2368) + 22] = b"NTDLL.RtlAllocateHeap\x00"
    img[rva_to_off(0x2380) : rva_to_off(0x2380) + 12] = b"LegacyAlloc\x00"

    # Debug Directory at RVA 0x2400 (28 bytes) -> points to RSDS record at RVA 0x2420 (file_off 0xC20)
    rsds_guid = uuid.UUID("9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d").bytes_le
    pdb_path = b"C:\\build\\agent\\work\\macho_studio\\bin\\Release\\synthetic_pe64.pdb\x00"
    rsds_blob = b"RSDS" + rsds_guid + struct.pack("<I", 1) + pdb_path
    dbg_entry = struct.pack(
        "<IIHHIIII",
        0,
        0x65F0A120,
        0,
        0,
        2,  # IMAGE_DEBUG_TYPE_CODEVIEW
        len(rsds_blob),
        0x2420,
        rva_to_off(0x2420),
    )
    img[rva_to_off(0x2400) : rva_to_off(0x2400) + 28] = dbg_entry
    img[rva_to_off(0x2420) : rva_to_off(0x2420) + len(rsds_blob)] = rsds_blob

    # Load Config Directory at RVA 0x2500 (112 bytes) with SecurityCookie = 0x0000000140002580
    load_cfg = bytearray(112)
    struct.pack_into("<I", load_cfg, 0, 112)  # Size
    struct.pack_into("<Q", load_cfg, 0x58, image_base + 0x2580)  # SecurityCookie VA
    img[rva_to_off(0x2500) : rva_to_off(0x2500) + 112] = load_cfg

    # ASCII & UTF-16LE strings in .rdata at RVA 0x2580
    ascii_str = b"PE32+_TELEMETRY_AGENT::https://api.binarystudio.dev/v2/symbols\x00Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    utf16_str = "BinaryStudio Windows PE32+ Security Inspector v3.0".encode("utf-16le") + b"\x00\x00"
    img[rva_to_off(0x2580) : rva_to_off(0x2580) + len(ascii_str)] = ascii_str
    img[rva_to_off(0x2600) : rva_to_off(0x2600) + len(utf16_str)] = utf16_str

    # 6. Populate .reloc at file offset 0x1400 (RVA 0x3000)
    # 1 block of 16 bytes: Page RVA = 0x1000, SizeOfBlock = 16, 4 entries:
    # (IMAGE_REL_BASED_DIR64=10 << 12) | 0x010, (10 << 12) | 0x020, (10 << 12) | 0x030, ABSOLUTE=0 padding
    reloc_block = struct.pack(
        "<IIHHHH",
        0x1000,
        16,
        (10 << 12) | 0x010,
        (10 << 12) | 0x020,
        (10 << 12) | 0x030,
        0,
    )
    img[0x1400 : 0x1400 + len(reloc_block)] = reloc_block

    # 7. Populate WIN_CERTIFICATE (Authenticode PKCS#7) at file offset 0x1800
    # In X.509 TBSCertificate, Issuer CN appears first, followed by Subject CN
    cn_str = b"BinaryStudio Synthetic Corp"
    issuer_str = b"BinaryStudio Root Code Signing CA"
    pkcs7_der = (
        b"\x30\x82\x01\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"
        + b"\x06\x03\x55\x04\x03\x0c"
        + bytes([len(issuer_str)])
        + issuer_str
        + b"\x06\x03\x55\x04\x03\x0c"
        + bytes([len(cn_str)])
        + cn_str
    )
    win_cert = struct.pack("<IHH", 8 + len(pkcs7_der), 0x0200, 0x0002) + pkcs7_der
    img[0x1800 : 0x1800 + len(win_cert)] = win_cert

    with open(out_path, "wb") as f:
        f.write(img)
    return out_path


def _build_synthetic_pe32(fixtures_dir: str) -> str:
    """
    Constructs a 32-bit Windows PE32 (`IMAGE_FILE_MACHINE_I386`) executable with:
    - Fixed non-ASLR base (`0x00400000`), no DEP, no Authenticode
    - An RWX section (`.rwxcode`) and a TLS Callback Directory (`IMAGE_DIRECTORY_ENTRY_TLS`)
      to exercise security warnings and structural anomaly detection
    """
    out_path = os.path.join(fixtures_dir, "synthetic_pe32.exe")
    if os.path.isfile(out_path) and os.path.getsize(out_path) >= 2048:
        return out_path

    img = bytearray(0x1000)
    image_base = 0x00400000

    # DOS Header (e_lfanew = 0x80)
    struct.pack_into("<HH", img, 0, 0x5A4D, 0x0090)
    struct.pack_into("<I", img, 0x3C, 0x80)

    nt_off = 0x80
    img[nt_off : nt_off + 4] = b"PE\x00\x00"
    # IMAGE_FILE_HEADER (Machine=0x014c I386, NumberOfSections=2, SizeOfOptionalHeader=224, Characteristics=0x0102)
    img[nt_off + 4 : nt_off + 24] = struct.pack("<HHIIIHH", 0x014C, 2, 0x65F0A120, 0, 0, 224, 0x0102)

    data_dirs = [(0, 0)] * 16
    data_dirs[9] = (0x2000, 24)  # TLS Directory at RVA 0x2000

    opt_hdr32 = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,  # PE32
        14,
        0,
        0x200,
        0x200,
        0,
        0x1000,
        0x1000,
        0x2000,  # BaseOfData
        image_base,
        0x1000,
        0x200,
        6,
        0,
        1,
        0,
        6,
        0,
        0,
        0x3000,
        0x200,
        0,
        3,  # WINDOWS_CUI
        0x0000,  # No ASLR / DEP / CFG!
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    ) + b"".join(struct.pack("<II", rva, sz) for rva, sz in data_dirs)
    img[nt_off + 24 : nt_off + 248] = opt_hdr32

    # 2 Sections: .rwxcode (RWX = 0xE0000020) and .rdata (R = 0x40000040)
    sh_off = nt_off + 248
    sec_hdrs = struct.pack(
        "<8sIIIIIIHHI", b".rwxcode", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0xE0000020
    ) + struct.pack(
        "<8sIIIIIIHHI", b".rdata\x00\x00", 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0x40000040
    )
    img[sh_off : sh_off + len(sec_hdrs)] = sec_hdrs

    # .rwxcode at 0x200 (RVA 0x1000)
    img[0x200:0x210] = b"\x55\x89\xe5\x31\xc0\xc9\xc3".ljust(16, b"\x90")

    # .rdata at 0x400 (RVA 0x2000): IMAGE_TLS_DIRECTORY32 (24B) + callback array at RVA 0x2020 (VA 0x00402020)
    tls_dir32 = struct.pack(
        "<IIIIII",
        image_base + 0x2040,
        image_base + 0x2050,
        image_base + 0x2060,
        image_base + 0x2020,  # AddressOfCallBacks VA
        0,
        0,
    )
    img[0x400:0x418] = tls_dir32
    # Callback array at 0x420 (RVA 0x2020): 1 callback pointing to 0x00401000, followed by 0
    img[0x420:0x428] = struct.pack("<II", image_base + 0x1000, 0)

    with open(out_path, "wb") as f:
        f.write(img)
    return out_path


def ensure_fixtures(workspace_root: str) -> dict:
    fixtures_dir = os.path.join(os.path.abspath(workspace_root), "fixtures")
    os.makedirs(fixtures_dir, exist_ok=True)
    univ_path = _build_synthetic_universal(fixtures_dir)
    fw_path = _build_synthetic_firmware_preload(fixtures_dir)
    elf64_path = _build_synthetic_elf64(fixtures_dir)
    elf32_path = _build_synthetic_elf32(fixtures_dir)
    pe64_path = _build_synthetic_pe64(fixtures_dir)
    pe32_path = _build_synthetic_pe32(fixtures_dir)
    return {
        "synthetic_universal": univ_path,
        "synthetic_firmware": fw_path,
        "synthetic_elf64": elf64_path,
        "synthetic_elf32": elf32_path,
        "synthetic_pe64": pe64_path,
        "synthetic_pe32": pe32_path,
    }
