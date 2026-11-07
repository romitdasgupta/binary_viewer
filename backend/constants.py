"""
Comprehensive Mach-O, Universal (Fat), Dyld Chained Fixups, and Code Signing Constants.
"""

from typing import Dict, List, Tuple, Any

# ============================================================================
# Magic Constants
# ============================================================================
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

MAGIC_NAMES: Dict[int, str] = {
    FAT_MAGIC: "FAT_MAGIC",
    FAT_CIGAM: "FAT_CIGAM",
    FAT_MAGIC_64: "FAT_MAGIC_64",
    FAT_CIGAM_64: "FAT_CIGAM_64",
    MH_MAGIC: "MH_MAGIC",
    MH_CIGAM: "MH_CIGAM",
    MH_MAGIC_64: "MH_MAGIC_64",
    MH_CIGAM_64: "MH_CIGAM_64",
}

# ============================================================================
# CPU Types & Subtypes
# ============================================================================
CPU_ARCH_MASK = 0xFF000000
CPU_ARCH_ABI64 = 0x01000000
CPU_ARCH_ABI64_32 = 0x02000000

CPU_TYPE_ANY = -1
CPU_TYPE_VAX = 1
CPU_TYPE_MC680x0 = 6
CPU_TYPE_X86 = 7
CPU_TYPE_I386 = 7
CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64  # 0x01000007 (16777223)
CPU_TYPE_MC98000 = 10
CPU_TYPE_HPPA = 11
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64  # 0x0100000C (16777228)
CPU_TYPE_ARM64_32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32  # 0x0200000C (33554444)
CPU_TYPE_MC88000 = 13
CPU_TYPE_SPARC = 14
CPU_TYPE_I860 = 15
CPU_TYPE_POWERPC = 18
CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64
CPU_TYPE_RISCV = 24

CPU_TYPE_NAMES: Dict[int, str] = {
    CPU_TYPE_ANY: "CPU_TYPE_ANY",
    CPU_TYPE_VAX: "CPU_TYPE_VAX",
    CPU_TYPE_MC680x0: "CPU_TYPE_MC680x0",
    CPU_TYPE_I386: "CPU_TYPE_I386",
    CPU_TYPE_X86_64: "CPU_TYPE_X86_64",
    CPU_TYPE_ARM: "CPU_TYPE_ARM",
    CPU_TYPE_ARM64: "CPU_TYPE_ARM64",
    CPU_TYPE_ARM64_32: "CPU_TYPE_ARM64_32",
    CPU_TYPE_POWERPC: "CPU_TYPE_POWERPC",
    CPU_TYPE_POWERPC64: "CPU_TYPE_POWERPC64",
    CPU_TYPE_RISCV: "CPU_TYPE_RISCV",
}

CPU_SUBTYPE_MASK = 0xFF000000
CPU_SUBTYPE_LIB64 = 0x80000000

CPU_SUBTYPES: Dict[int, Dict[int, str]] = {
    CPU_TYPE_I386: {
        3: "CPU_SUBTYPE_I386_ALL",
        4: "CPU_SUBTYPE_486",
        5: "CPU_SUBTYPE_586",
    },
    CPU_TYPE_X86_64: {
        3: "CPU_SUBTYPE_X86_64_ALL",
        4: "CPU_SUBTYPE_X86_64_ARCH1",
        8: "CPU_SUBTYPE_X86_64_H",
    },
    CPU_TYPE_ARM: {
        0: "CPU_SUBTYPE_ARM_ALL",
        5: "CPU_SUBTYPE_ARM_V4T",
        6: "CPU_SUBTYPE_ARM_V6",
        7: "CPU_SUBTYPE_ARM_V5TEJ",
        8: "CPU_SUBTYPE_ARM_XSCALE",
        9: "CPU_SUBTYPE_ARM_V7",
        10: "CPU_SUBTYPE_ARM_V7F",
        11: "CPU_SUBTYPE_ARM_V7S",
        12: "CPU_SUBTYPE_ARM_V7K",
        13: "CPU_SUBTYPE_ARM_V8",
        14: "CPU_SUBTYPE_ARM_V6M",
        15: "CPU_SUBTYPE_ARM_V7M",
        16: "CPU_SUBTYPE_ARM_V7EM",
    },
    CPU_TYPE_ARM64: {
        0: "CPU_SUBTYPE_ARM64_ALL",
        1: "CPU_SUBTYPE_ARM64_V8",
        2: "CPU_SUBTYPE_ARM64E",
    },
    CPU_TYPE_ARM64_32: {
        0: "CPU_SUBTYPE_ARM64_32_ALL",
        1: "CPU_SUBTYPE_ARM64_32_V8",
    },
}


def decode_cpu_arch(cputype: int, cpusubtype: int) -> Tuple[str, str, str, str]:
    """
    Returns (arch_short_name, cputype_name, cpusubtype_name, arch_display_description).
    """
    cputype_name = CPU_TYPE_NAMES.get(cputype, f"CPU_TYPE_UNKNOWN(0x{cputype:08x})")
    sub_masked = cpusubtype & ~CPU_SUBTYPE_MASK
    cap_bits = (cpusubtype & CPU_SUBTYPE_MASK) >> 24

    subtype_map = CPU_SUBTYPES.get(cputype, {})
    base_sub_name = subtype_map.get(sub_masked, f"CPU_SUBTYPE_0x{sub_masked:x}")

    if cputype == CPU_TYPE_ARM64:
        if sub_masked == 2:
            arch_short = "arm64e"
            pac_ver = f"PAC v0x{cap_bits:02x}" if cap_bits else "PAC"
            sub_name = f"{base_sub_name} ({pac_ver})"
            display = f"ARM64e (Pointer Authentication ABI v0x{cap_bits:02x})"
        elif sub_masked == 1:
            arch_short = "arm64v8"
            sub_name = base_sub_name
            display = "ARM64 (AArch64 v8)"
        else:
            arch_short = "arm64"
            sub_name = base_sub_name
            display = "ARM64 (AArch64)"
    elif cputype == CPU_TYPE_ARM64_32:
        arch_short = "arm64_32"
        sub_name = base_sub_name
        display = "ARM64_32 (AArch64 ILP32 watchOS)"
    elif cputype == CPU_TYPE_X86_64:
        arch_short = "x86_64h" if sub_masked == 8 else "x86_64"
        sub_name = f"{base_sub_name} (LIB64)" if (cpusubtype & CPU_SUBTYPE_LIB64) else base_sub_name
        display = "x86_64 (Haswell)" if sub_masked == 8 else "x86_64 (AMD64 / Intel 64)"
    elif cputype == CPU_TYPE_I386:
        arch_short = "i386"
        sub_name = base_sub_name
        display = "i386 (32-bit x86)"
    elif cputype == CPU_TYPE_ARM:
        arm_names = {
            6: "armv6",
            9: "armv7",
            11: "armv7s",
            12: "armv7k",
            14: "armv6m",
            15: "armv7m",
            16: "armv7em",
        }
        arch_short = arm_names.get(sub_masked, "arm")
        sub_name = base_sub_name
        display = f"ARM 32-bit ({arch_short})"
    else:
        arch_short = f"cpu_0x{cputype:x}"
        sub_name = base_sub_name
        display = f"{cputype_name} ({base_sub_name})"

    return arch_short, cputype_name, sub_name, display


# ============================================================================
# File Types (filetype)
# ============================================================================
MH_OBJECT = 0x1
MH_EXECUTE = 0x2
MH_FVMLIB = 0x3
MH_CORE = 0x4
MH_PRELOAD = 0x5
MH_DYLIB = 0x6
MH_DYLINKER = 0x7
MH_BUNDLE = 0x8
MH_DYLIB_STUB = 0x9
MH_DSYM = 0xA
MH_KEXT_BUNDLE = 0xB
MH_FILESET = 0xC
MH_GPU_EXECUTE = 0xD
MH_GPU_DYLIB = 0xE

FILETYPE_INFO: Dict[int, Tuple[str, str]] = {
    MH_OBJECT: ("MH_OBJECT", "Relocatable Object File (.o)"),
    MH_EXECUTE: ("MH_EXECUTE", "Demand Paged Executable File"),
    MH_FVMLIB: ("MH_FVMLIB", "Fixed VM Shared Library File"),
    MH_CORE: ("MH_CORE", "Core Dump File"),
    MH_PRELOAD: ("MH_PRELOAD", "Preloaded Standalone Firmware / Bootloader Image"),
    MH_DYLIB: ("MH_DYLIB", "Dynamically Bound Shared Library (.dylib)"),
    MH_DYLINKER: ("MH_DYLINKER", "Dynamic Link Editor (dyld)"),
    MH_BUNDLE: ("MH_BUNDLE", "Dynamically Bound Bundle File (.bundle)"),
    MH_DYLIB_STUB: ("MH_DYLIB_STUB", "Shared Library Stub for Static Linking"),
    MH_DSYM: ("MH_DSYM", "Companion Debug Symbols File (.dSYM)"),
    MH_KEXT_BUNDLE: ("MH_KEXT_BUNDLE", "XNU Kernel Extension Bundle (.kext)"),
    MH_FILESET: ("MH_FILESET", "Kernelcache / Dyld Shared Cache Fileset Container"),
    MH_GPU_EXECUTE: ("MH_GPU_EXECUTE", "GPU Metal Executable Program"),
    MH_GPU_DYLIB: ("MH_GPU_DYLIB", "GPU Metal Dynamic Library"),
}

# ============================================================================
# Header Flags (mach_header.flags)
# ============================================================================
MH_NOUNDEFS = 0x00000001
MH_INCRLINK = 0x00000002
MH_DYLDLINK = 0x00000004
MH_BINDATLOAD = 0x00000008
MH_PREBOUND = 0x00000010
MH_SPLIT_SEGS = 0x00000020
MH_LAZY_INIT = 0x00000040
MH_TWOLEVEL = 0x00000080
MH_FORCE_FLAT = 0x00000100
MH_NOMULTIDEFS = 0x00000200
MH_NOFIXPREBINDING = 0x00000400
MH_PREBINDABLE = 0x00000800
MH_ALLMODSBOUND = 0x00001000
MH_SUBSECTIONS_VIA_SYMBOLS = 0x00002000
MH_CANONICAL = 0x00004000
MH_WEAK_DEFINES = 0x00008000
MH_BINDS_TO_WEAK = 0x00010000
MH_ALLOW_STACK_EXECUTION = 0x00020000
MH_ROOT_SAFE = 0x00040000
MH_SETUID_SAFE = 0x00080000
MH_NO_REEXPORTED_DYLIBS = 0x00100000
MH_PIE = 0x00200000
MH_DEAD_STRIPPABLE_DYLIB = 0x00400000
MH_HAS_TLV_DESCRIPTORS = 0x00800000
MH_NO_HEAP_EXECUTION = 0x01000000
MH_APP_EXTENSION_SAFE = 0x02000000
MH_NLIST_OUTOFSORT_WITH_DYLDINFO = 0x04000000
MH_SIM_SUPPORT = 0x08000000
MH_DYLIB_IN_CACHE = 0x80000000

MH_HEADER_FLAGS: List[Tuple[int, str, str]] = [
    (0x00000001, "MH_NOUNDEFS", "No undefined references at link time"),
    (0x00000002, "MH_INCRLINK", "Incremental link object"),
    (0x00000004, "MH_DYLDLINK", "Input for the dynamic linker (dyld)"),
    (0x00000008, "MH_BINDATLOAD", "Bind undefined references at load time"),
    (0x00000010, "MH_PREBOUND", "Undefined references are prebound"),
    (0x00000020, "MH_SPLIT_SEGS", "Read-only and read-write segments are split"),
    (0x00000040, "MH_LAZY_INIT", "Shared library init routine is run lazily"),
    (0x00000080, "MH_TWOLEVEL", "Uses two-level namespace bindings"),
    (0x00000100, "MH_FORCE_FLAT", "Force flat namespace bindings"),
    (0x00000200, "MH_NOMULTIDEFS", "No multiple definitions of symbols in sub-images"),
    (0x00000400, "MH_NOFIXPREBINDING", "Do not notify prebinding agent"),
    (0x00000800, "MH_PREBINDABLE", "Not prebound but can be prebound"),
    (0x00001000, "MH_ALLMODSBOUND", "Binds to all two-level namespace modules"),
    (0x00002000, "MH_SUBSECTIONS_VIA_SYMBOLS", "Safe to divide sections into sub-blocks via symbols"),
    (0x00004000, "MH_CANONICAL", "Canonicalized by unprebind operation"),
    (0x00008000, "MH_WEAK_DEFINES", "Final linked image contains external weak symbols"),
    (0x00010000, "MH_BINDS_TO_WEAK", "Final linked image uses weak symbols"),
    (0x00020000, "MH_ALLOW_STACK_EXECUTION", "Allow stack execution (Executable Stack)"),
    (0x00040000, "MH_ROOT_SAFE", "Safe for use in processes with uid 0"),
    (0x00080000, "MH_SETUID_SAFE", "Safe for use in setuid/setgid processes"),
    (0x00100000, "MH_NO_REEXPORTED_DYLIBS", "No LC_REEXPORT_DYLIB load commands"),
    (0x00200000, "MH_PIE", "Position Independent Executable (ASLR Enabled)"),
    (0x00400000, "MH_DEAD_STRIPPABLE_DYLIB", "Linker can dead-strip dylib if unused"),
    (0x00800000, "MH_HAS_TLV_DESCRIPTORS", "Contains Thread-Local Variable (TLV) descriptors"),
    (0x01000000, "MH_NO_HEAP_EXECUTION", "Heap memory is marked non-executable"),
    (0x02000000, "MH_APP_EXTENSION_SAFE", "Linked for use in an App Extension"),
    (0x04000000, "MH_NLIST_OUTOFSORT_WITH_DYLDINFO", "External symbols in nlist not sorted with dyldinfo"),
    (0x08000000, "MH_SIM_SUPPORT", "Allow simulator platform support"),
    (0x80000000, "MH_DYLIB_IN_CACHE", "Dylib is part of the dyld shared cache"),
]


def decode_header_flags(flags: int) -> Tuple[List[str], List[Dict[str, Any]]]:
    names = []
    bit_flags = []
    for mask, name, desc in MH_HEADER_FLAGS:
        is_set = bool(flags & mask)
        if is_set:
            names.append(name)
        bit_flags.append({
            "name": name,
            "mask": f"0x{mask:08x}",
            "set": is_set,
            "description": desc,
        })
    return names, bit_flags


# ============================================================================
# Load Commands (LC_*)
# ============================================================================
LC_REQ_DYLD = 0x80000000

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_SYMSEG = 0x3
LC_THREAD = 0x4
LC_UNIXTHREAD = 0x5
LC_LOADFVMLIB = 0x6
LC_IDFVMLIB = 0x7
LC_IDENT = 0x8
LC_FVMFILE = 0x9
LC_PREPAGE = 0xA
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_DYLINKER = 0xE
LC_ID_DYLINKER = 0xF
LC_PREBOUND_DYLIB = 0x10
LC_ROUTINES = 0x11
LC_SUB_FRAMEWORK = 0x12
LC_SUB_UMBRELLA = 0x13
LC_SUB_CLIENT = 0x14
LC_SUB_LIBRARY = 0x15
LC_TWOLEVEL_HINTS = 0x16
LC_PREBIND_CKSUM = 0x17
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_SEGMENT_64 = 0x19
LC_ROUTINES_64 = 0x1A
LC_UUID = 0x1B
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_SPLIT_INFO = 0x1E
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_LAZY_LOAD_DYLIB = 0x20
LC_ENCRYPTION_INFO = 0x21
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_FUNCTION_STARTS = 0x26
LC_DYLD_ENVIRONMENT = 0x27
LC_MAIN = 0x28 | LC_REQ_DYLD
LC_DATA_IN_CODE = 0x29
LC_SOURCE_VERSION = 0x2A
LC_DYLIB_CODE_SIGN_DRS = 0x2B
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LINKER_OPTION = 0x2D
LC_LINKER_OPTIMIZATION_HINT = 0x2E
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30
LC_NOTE = 0x31
LC_BUILD_VERSION = 0x32
LC_DYLD_EXPORTS_TRIE = 0x33 | LC_REQ_DYLD
LC_DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD
LC_FILESET_ENTRY = 0x35 | LC_REQ_DYLD
LC_ATOM_INFO = 0x36

LOAD_COMMAND_NAMES: Dict[int, str] = {
    LC_SEGMENT: "LC_SEGMENT",
    LC_SYMTAB: "LC_SYMTAB",
    LC_SYMSEG: "LC_SYMSEG",
    LC_THREAD: "LC_THREAD",
    LC_UNIXTHREAD: "LC_UNIXTHREAD",
    LC_LOADFVMLIB: "LC_LOADFVMLIB",
    LC_IDFVMLIB: "LC_IDFVMLIB",
    LC_IDENT: "LC_IDENT",
    LC_FVMFILE: "LC_FVMFILE",
    LC_PREPAGE: "LC_PREPAGE",
    LC_DYSYMTAB: "LC_DYSYMTAB",
    LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
    LC_ID_DYLIB: "LC_ID_DYLIB",
    LC_LOAD_DYLINKER: "LC_LOAD_DYLINKER",
    LC_ID_DYLINKER: "LC_ID_DYLINKER",
    LC_PREBOUND_DYLIB: "LC_PREBOUND_DYLIB",
    LC_ROUTINES: "LC_ROUTINES",
    LC_SUB_FRAMEWORK: "LC_SUB_FRAMEWORK",
    LC_SUB_UMBRELLA: "LC_SUB_UMBRELLA",
    LC_SUB_CLIENT: "LC_SUB_CLIENT",
    LC_SUB_LIBRARY: "LC_SUB_LIBRARY",
    LC_TWOLEVEL_HINTS: "LC_TWOLEVEL_HINTS",
    LC_PREBIND_CKSUM: "LC_PREBIND_CKSUM",
    LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
    LC_SEGMENT_64: "LC_SEGMENT_64",
    LC_ROUTINES_64: "LC_ROUTINES_64",
    LC_UUID: "LC_UUID",
    LC_RPATH: "LC_RPATH",
    LC_CODE_SIGNATURE: "LC_CODE_SIGNATURE",
    LC_SEGMENT_SPLIT_INFO: "LC_SEGMENT_SPLIT_INFO",
    LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
    LC_LAZY_LOAD_DYLIB: "LC_LAZY_LOAD_DYLIB",
    LC_ENCRYPTION_INFO: "LC_ENCRYPTION_INFO",
    LC_DYLD_INFO: "LC_DYLD_INFO",
    LC_DYLD_INFO_ONLY: "LC_DYLD_INFO_ONLY",
    LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
    LC_VERSION_MIN_MACOSX: "LC_VERSION_MIN_MACOSX",
    LC_VERSION_MIN_IPHONEOS: "LC_VERSION_MIN_IPHONEOS",
    LC_FUNCTION_STARTS: "LC_FUNCTION_STARTS",
    LC_DYLD_ENVIRONMENT: "LC_DYLD_ENVIRONMENT",
    LC_MAIN: "LC_MAIN",
    LC_DATA_IN_CODE: "LC_DATA_IN_CODE",
    LC_SOURCE_VERSION: "LC_SOURCE_VERSION",
    LC_DYLIB_CODE_SIGN_DRS: "LC_DYLIB_CODE_SIGN_DRS",
    LC_ENCRYPTION_INFO_64: "LC_ENCRYPTION_INFO_64",
    LC_LINKER_OPTION: "LC_LINKER_OPTION",
    LC_LINKER_OPTIMIZATION_HINT: "LC_LINKER_OPTIMIZATION_HINT",
    LC_VERSION_MIN_TVOS: "LC_VERSION_MIN_TVOS",
    LC_VERSION_MIN_WATCHOS: "LC_VERSION_MIN_WATCHOS",
    LC_NOTE: "LC_NOTE",
    LC_BUILD_VERSION: "LC_BUILD_VERSION",
    LC_DYLD_EXPORTS_TRIE: "LC_DYLD_EXPORTS_TRIE",
    LC_DYLD_CHAINED_FIXUPS: "LC_DYLD_CHAINED_FIXUPS",
    LC_FILESET_ENTRY: "LC_FILESET_ENTRY",
    LC_ATOM_INFO: "LC_ATOM_INFO",
}

# ============================================================================
# Segment & Section Protections and Flags
# ============================================================================
VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2
VM_PROT_EXECUTE = 0x4


def format_vm_prot(prot: int) -> str:
    r = "r" if (prot & VM_PROT_READ) else "-"
    w = "w" if (prot & VM_PROT_WRITE) else "-"
    x = "x" if (prot & VM_PROT_EXECUTE) else "-"
    return f"{r}{w}{x}"


def decode_vm_prot_flags(prot: int) -> List[Dict[str, Any]]:
    return [
        {"name": "VM_PROT_READ", "mask": "0x01", "set": bool(prot & VM_PROT_READ)},
        {"name": "VM_PROT_WRITE", "mask": "0x02", "set": bool(prot & VM_PROT_WRITE)},
        {"name": "VM_PROT_EXECUTE", "mask": "0x04", "set": bool(prot & VM_PROT_EXECUTE)},
    ]


SG_FLAGS: List[Tuple[int, str]] = [
    (0x1, "SG_HIGHVM"),
    (0x2, "SG_FVMLIB"),
    (0x4, "SG_NORELOC"),
    (0x8, "SG_PROTECTED_VERSION_1"),
    (0x10, "SG_READ_ONLY"),
]


def decode_segment_flags(flags: int) -> Tuple[List[str], List[Dict[str, Any]]]:
    names = []
    bits = []
    for mask, name in SG_FLAGS:
        is_set = bool(flags & mask)
        if is_set:
            names.append(name)
        bits.append({"name": name, "mask": f"0x{mask:02x}", "set": is_set})
    return names, bits


SECTION_TYPE_MASK = 0x000000FF
SECTION_ATTRIBUTES_MASK = 0xFFFFFF00

SECTION_TYPES: Dict[int, str] = {
    0x00: "S_REGULAR",
    0x01: "S_ZEROFILL",
    0x02: "S_CSTRING_LITERALS",
    0x03: "S_4BYTE_LITERALS",
    0x04: "S_8BYTE_LITERALS",
    0x05: "S_LITERAL_POINTERS",
    0x06: "S_NON_LAZY_SYMBOL_POINTERS",
    0x07: "S_LAZY_SYMBOL_POINTERS",
    0x08: "S_SYMBOL_STUBS",
    0x09: "S_MOD_INIT_FUNC_POINTERS",
    0x0A: "S_MOD_TERM_FUNC_POINTERS",
    0x0B: "S_COALESCED",
    0x0C: "S_GB_ZEROFILL",
    0x0D: "S_INTERPOSING",
    0x0E: "S_16BYTE_LITERALS",
    0x0F: "S_DTRACE_DOF",
    0x10: "S_LAZY_DYLIB_SYMBOL_POINTERS",
    0x11: "S_THREAD_LOCAL_REGULAR",
    0x12: "S_THREAD_LOCAL_ZEROFILL",
    0x13: "S_THREAD_LOCAL_VARIABLES",
    0x14: "S_THREAD_LOCAL_VARIABLE_POINTERS",
    0x15: "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS",
    0x16: "S_INIT_FUNC_OFFSETS",
}

SECTION_ATTRIBUTES: List[Tuple[int, str]] = [
    (0x80000000, "S_ATTR_PURE_INSTRUCTIONS"),
    (0x40000000, "S_ATTR_NO_TOC"),
    (0x20000000, "S_ATTR_STRIP_STATIC_SYMS"),
    (0x10000000, "S_ATTR_NO_DEAD_STRIP"),
    (0x08000000, "S_ATTR_LIVE_SUPPORT"),
    (0x04000000, "S_ATTR_SELF_MODIFYING_CODE"),
    (0x02000000, "S_ATTR_DEBUG"),
    (0x00000400, "S_ATTR_SOME_INSTRUCTIONS"),
    (0x00000200, "S_ATTR_EXT_RELOC"),
    (0x00000100, "S_ATTR_LOC_RELOC"),
]


def decode_section_flags(flags: int) -> Tuple[str, List[str], List[Dict[str, Any]]]:
    sec_type_val = flags & SECTION_TYPE_MASK
    sec_type_name = SECTION_TYPES.get(sec_type_val, f"S_TYPE_0x{sec_type_val:02x}")
    attrs = []
    bit_flags = [
        {"name": sec_type_name, "mask": f"0x{sec_type_val:02x}", "set": True}
    ]
    for mask, name in SECTION_ATTRIBUTES:
        is_set = bool(flags & mask)
        if is_set:
            attrs.append(name)
        bit_flags.append({"name": name, "mask": f"0x{mask:08x}", "set": is_set})
    return sec_type_name, attrs, bit_flags


# ============================================================================
# Platform & Build Tools (LC_BUILD_VERSION)
# ============================================================================
PLATFORMS: Dict[int, str] = {
    1: "macOS",
    2: "iOS",
    3: "tvOS",
    4: "watchOS",
    5: "bridgeOS",
    6: "Mac Catalyst",
    7: "iOS Simulator",
    8: "tvOS Simulator",
    9: "watchOS Simulator",
    10: "DriverKit",
    11: "visionOS",
    12: "visionOS Simulator",
    13: "Firmware (Standalone)",
    14: "sepOS (Secure Enclave)",
}

BUILD_TOOLS: Dict[int, str] = {
    1: "clang",
    2: "swift",
    3: "ld",
    4: "lld",
    1024: "metal",
    1025: "air-lld",
    1026: "air-nt",
}


def format_packed_version(v: int) -> str:
    major = (v >> 16) & 0xFFFF
    minor = (v >> 8) & 0xFF
    patch = v & 0xFF
    return f"{major}.{minor}.{patch}"


def format_source_version(v: int) -> str:
    a = (v >> 40) & 0xFFFFFF
    b = (v >> 30) & 0x3FF
    c = (v >> 20) & 0x3FF
    d = (v >> 10) & 0x3FF
    e = v & 0x3FF
    return f"{a}.{b}.{c}.{d}.{e}"


# ============================================================================
# Symbol Table Constants (nlist / nlist_64)
# ============================================================================
N_STAB = 0xE0
N_PEXT = 0x10
N_TYPE = 0x0E
N_EXT = 0x01

N_UNDF = 0x00
N_ABS = 0x02
N_SECT = 0x0E
N_PBUD = 0x0C
N_INDR = 0x0A

N_TYPE_NAMES: Dict[int, str] = {
    N_UNDF: "UNDF",
    N_ABS: "ABS",
    N_SECT: "SECT",
    N_PBUD: "PBUD",
    N_INDR: "INDR",
}

INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000

# ============================================================================
# Chained Fixups Constants (LC_DYLD_CHAINED_FIXUPS)
# ============================================================================
DYLD_CHAINED_IMPORT = 1
DYLD_CHAINED_IMPORT_ADDEND = 2
DYLD_CHAINED_IMPORT_ADDEND64 = 3

CHAINED_IMPORT_FORMATS: Dict[int, str] = {
    1: "DYLD_CHAINED_IMPORT",
    2: "DYLD_CHAINED_IMPORT_ADDEND",
    3: "DYLD_CHAINED_IMPORT_ADDEND64",
}

CHAINED_PTR_FORMATS: Dict[int, str] = {
    1: "DYLD_CHAINED_PTR_ARM64E",
    2: "DYLD_CHAINED_PTR_64",
    3: "DYLD_CHAINED_PTR_32",
    4: "DYLD_CHAINED_PTR_32_CACHE",
    5: "DYLD_CHAINED_PTR_32_FIRMWARE",
    6: "DYLD_CHAINED_PTR_64_OFFSET",
    7: "DYLD_CHAINED_PTR_ARM64E_KERNEL",
    8: "DYLD_CHAINED_PTR_64_KERNEL_CACHE",
    9: "DYLD_CHAINED_PTR_ARM64E_USERLAND",
    10: "DYLD_CHAINED_PTR_ARM64E_FIRMWARE",
    11: "DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE",
    12: "DYLD_CHAINED_PTR_ARM64E_USERLAND24",
    13: "DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE",
}

PAC_KEYS: Dict[int, str] = {
    0: "IA",
    1: "IB",
    2: "DA",
    3: "DB",
}

# ============================================================================
# Dyld Legacy Rebase / Bind / Export Constants
# ============================================================================
EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03
EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0x00
EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = 0x01
EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE = 0x02
EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION = 0x04
EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10

# ============================================================================
# Code Signature Constants (LC_CODE_SIGNATURE)
# ============================================================================
CSMAGIC_REQUIREMENT = 0xFADE0C00
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xFADE0B02
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_DETACHED_SIGNATURE = 0xFADE0CC1
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT = 0xFADE8181

CS_MAGIC_NAMES: Dict[int, str] = {
    CSMAGIC_REQUIREMENT: "CSMAGIC_REQUIREMENT",
    CSMAGIC_REQUIREMENTS: "CSMAGIC_REQUIREMENTS",
    CSMAGIC_CODEDIRECTORY: "CSMAGIC_CODEDIRECTORY",
    CSMAGIC_EMBEDDED_SIGNATURE: "CSMAGIC_EMBEDDED_SIGNATURE",
    CSMAGIC_EMBEDDED_SIGNATURE_OLD: "CSMAGIC_EMBEDDED_SIGNATURE_OLD",
    CSMAGIC_EMBEDDED_ENTITLEMENTS: "CSMAGIC_EMBEDDED_ENTITLEMENTS",
    CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: "CSMAGIC_EMBEDDED_DER_ENTITLEMENTS",
    CSMAGIC_DETACHED_SIGNATURE: "CSMAGIC_DETACHED_SIGNATURE",
    CSMAGIC_BLOBWRAPPER: "CSMAGIC_BLOBWRAPPER",
    CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT: "CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT",
}

CSSLOT_CODEDIRECTORY = 0
CSSLOT_INFOSLOT = 1
CSSLOT_REQUIREMENTS = 2
CSSLOT_RESOURCEDIR = 3
CSSLOT_APPLICATION = 4
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_LAUNCH_CONSTRAINT_SELF = 8
CSSLOT_LAUNCH_CONSTRAINT_PARENT = 9
CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE = 10
CSSLOT_LIBRARY_CONSTRAINT = 11
CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
CSSLOT_SIGNATURESLOT = 0x10000
CSSLOT_IDENTIFICATIONSLOT = 0x10001
CSSLOT_TICKETSLOT = 0x10002

CS_SLOT_NAMES: Dict[int, str] = {
    CSSLOT_CODEDIRECTORY: "CSSLOT_CODEDIRECTORY",
    CSSLOT_INFOSLOT: "CSSLOT_INFOSLOT (Info.plist)",
    CSSLOT_REQUIREMENTS: "CSSLOT_REQUIREMENTS",
    CSSLOT_RESOURCEDIR: "CSSLOT_RESOURCEDIR",
    CSSLOT_APPLICATION: "CSSLOT_APPLICATION",
    CSSLOT_ENTITLEMENTS: "CSSLOT_ENTITLEMENTS (XML)",
    CSSLOT_DER_ENTITLEMENTS: "CSSLOT_DER_ENTITLEMENTS (ASN.1 DER)",
    CSSLOT_LAUNCH_CONSTRAINT_SELF: "CSSLOT_LAUNCH_CONSTRAINT_SELF",
    CSSLOT_LAUNCH_CONSTRAINT_PARENT: "CSSLOT_LAUNCH_CONSTRAINT_PARENT",
    CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE: "CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE",
    CSSLOT_LIBRARY_CONSTRAINT: "CSSLOT_LIBRARY_CONSTRAINT",
    CSSLOT_SIGNATURESLOT: "CSSLOT_SIGNATURESLOT (CMS/PKCS#7)",
    CSSLOT_IDENTIFICATIONSLOT: "CSSLOT_IDENTIFICATIONSLOT",
    CSSLOT_TICKETSLOT: "CSSLOT_TICKETSLOT",
}

CS_SPECIAL_SLOT_NAMES: Dict[int, str] = {
    1: "Info.plist",
    2: "Internal Requirements",
    3: "Resource Directory",
    4: "Application Specific",
    5: "Entitlements (XML)",
    6: "DMG RepSpecific",
    7: "Entitlements (DER)",
    8: "Launch Constraint (Self)",
    9: "Launch Constraint (Parent)",
    10: "Launch Constraint (Responsible)",
    11: "Library Constraint",
}

CS_FLAGS: List[Tuple[int, str, str]] = [
    (0x00000001, "CS_VALID", "Dynamically valid"),
    (0x00000002, "CS_ADHOC", "Ad-hoc signed (no cryptographic identity)"),
    (0x00000004, "CS_GET_TASK_ALLOW", "Allows task_for_pid / debugging"),
    (0x00000008, "CS_INSTALLER", "Has installer entitlement"),
    (0x00000010, "CS_FORCED_LV", "Library Validation forced"),
    (0x00000020, "CS_INVALID_ALLOWED", "Invalid page allowed"),
    (0x00000100, "CS_HARD", "Do not load invalid pages"),
    (0x00000200, "CS_KILL", "Kill process if page becomes invalid"),
    (0x00000400, "CS_CHECK_EXPIRATION", "Check certificate expiration"),
    (0x00000800, "CS_RESTRICT", "Restrict dyld debugging / injection"),
    (0x00001000, "CS_ENFORCEMENT", "Require code signing enforcement"),
    (0x00002000, "CS_REQUIRE_LV", "Require Library Validation"),
    (0x00004000, "CS_ENTITLEMENTS_VALIDATED", "Entitlements validated"),
    (0x00008000, "CS_NVRAM_UNRESTRICTED", "NVRAM unrestricted"),
    (0x00010000, "CS_RUNTIME", "Hardened Runtime enabled"),
    (0x00020000, "CS_LINKER_SIGNED", "Automatically signed by linker (ld)"),
]

CS_HASHTYPES: Dict[int, str] = {
    1: "SHA-1 (1)",
    2: "SHA-256 (2)",
    3: "SHA-256 Truncated (3)",
    4: "SHA-384 (4)",
    5: "SHA-512 (5)",
}

DICE_KINDS: Dict[int, str] = {
    1: "DICE_KIND_DATA",
    2: "DICE_KIND_JUMP_TABLE8",
    3: "DICE_KIND_JUMP_TABLE16",
    4: "DICE_KIND_JUMP_TABLE32",
    5: "DICE_KIND_ABS_JUMP_TABLE32",
}
