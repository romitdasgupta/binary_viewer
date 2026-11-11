"""
The cross-format comparison table: one row per idea, with how Mach-O, ELF and PE
each express it, why the idea exists, the concept to read, and a locator that
shows it in the open file.

Cells are rich text (see learn_content for the markup).
"""

from typing import Any, Dict, List

from .dsl import debug_id, entry_field, hfield, import_slot, lc, segment, signature, symbol, view


def row(id: str, title: str, macho: str, elf: str, pe: str, why: str, concept: str, at: Dict[str, Any],
        formats: Any = None) -> Dict[str, Any]:
    out = {"id": id, "title": title, "macho": macho, "elf": elf, "pe": pe, "why": why, "concept": concept, "at": at}
    if formats:
        out["formats"] = list(formats)  # the formats in which `at` can exist
    return out


ROWS: List[Dict[str, Any]] = [
    row("identification", "File identification",
        "`mach_header_64` starting with the magic `0xfeedfacf`; optionally wrapped in a universal header (`0xcafebabe`) that holds one Mach-O file per CPU type.",
        "`Elf64_Ehdr` starting with `7f 45 4c 46`; the next bytes give the class (32 or 64 bit) and the byte order.",
        "`IMAGE_DOS_HEADER` starting with `MZ`; its `e_lfanew` field leads to the signature `PE\\0\\0`, the COFF file header and the optional header.",
        "A loader must be able to reject a file it cannot run after reading a few bytes.",
        "structs-on-disk", hfield(macho="magic", elf="e_ident[EI_MAG]", pe="Signature")),
    row("cpu", "Target CPU",
        "`cputype` and `cpusubtype` in the header; one file can hold several slices.",
        "`e_machine` in the header; one architecture per file.",
        "`Machine` in the COFF file header; one architecture per file.",
        "Machine code is specific to one instruction set, and the system must not start code it cannot execute.",
        "file-formats-overview", hfield(macho="cputype", elf="e_machine", pe="FileHeader.Machine")),
    row("segments", "What is mapped: segments and sections",
        "`LC_SEGMENT_64` commands describe segments; each is followed by the headers of the sections it contains.",
        "Two separate tables: program headers (`PT_LOAD` segments) for loading, section headers for linking and tools.",
        "One table of section headers; each section is mapped on its own, with `FileAlignment` on disk and `SectionAlignment` in memory.",
        "Memory permissions apply to whole pages, so content is grouped by permission into page-aligned units.",
        "sections-vs-segments", view("segments")),
    row("base", "Preferred address and the null-pointer guard",
        "Addresses in the file are absolute; a 64-bit executable is linked at `0x100000000`, above a `__PAGEZERO` segment with no permissions.",
        "`ET_EXEC` files use absolute addresses (traditionally from `0x400000` on x86-64); `ET_DYN` files are linked at 0 and placed by the kernel. The kernel refuses unprivileged mappings below `vm.mmap_min_addr` (64 KiB on most distributions).",
        "`ImageBase` in the optional header (`0x140000000` by default for 64-bit executables); every other address is an RVA relative to it. The lowest 64 KiB of the address space are never mapped.",
        "A dereferenced null pointer should fault, and code needs to know where it was linked to run.",
        "addresses", segment("exec", part="header")),
    row("entry", "Entry point",
        "`LC_MAIN` holds the file offset of `main`, which dyld calls; statically linked files use `LC_UNIXTHREAD` with a full register state.",
        "`e_entry` holds the address of `_start`, the C runtime's start-up code.",
        "`AddressOfEntryPoint` holds the RVA of the C runtime's start-up code (or of a DLL's initialisation routine).",
        "The system must know where to begin executing once the image is mapped.",
        "process-startup-linux", entry_field()),
    row("loader", "The dynamic linker",
        "Named by the file: `LC_LOAD_DYLINKER`. Release kernels accept only `/usr/lib/dyld`.",
        "Named by the file: the `PT_INTERP` segment, for example `/lib64/ld-linux-x86-64.so.2`.",
        "Not named by the file. Every process uses the loader inside `ntdll.dll`.",
        "Loading libraries and resolving symbols is done in user mode, by a program the kernel starts first.",
        "static-vs-dynamic", lc(macho=["LC_LOAD_DYLINKER"], elf=["PT_INTERP"], pe=["DATA_DIR_IMPORT_TABLE"])),
    row("dependencies", "Required libraries",
        "One `LC_LOAD_DYLIB` command per library, holding its install name (a path); `LC_RPATH` adds search directories.",
        "`DT_NEEDED` entries in the dynamic section, holding SONAMEs; `DT_RUNPATH` adds search directories.",
        "One import descriptor per DLL in the import directory, holding a file name.",
        "Shared libraries let programs share code in memory and on disk, and be updated independently.",
        "shared-libraries", lc(macho=["LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB"], elf=["PT_DYNAMIC"], pe=["DATA_DIR_IMPORT_TABLE"])),
    row("indirection", "Calls into other images",
        "A stub in `__TEXT,__stubs` jumps through a pointer in `__DATA_CONST,__got`.",
        "A `.plt` entry jumps through a slot in `.got.plt` (or the call goes through `.got` directly).",
        "The call goes through a slot of the import address table: `call [__imp_Function]`.",
        "The loader fills in one table of pointers, so that code pages stay unmodified and shareable.",
        "got-plt", import_slot()),
    row("fixups", "Load-time relocation",
        "Rebases and binds, encoded as chained fixups (`LC_DYLD_CHAINED_FIXUPS`) or as opcode streams (`LC_DYLD_INFO_ONLY`).",
        "Relocation records in `.rela.dyn` and `.rela.plt`: `R_*_RELATIVE` for rebases, `R_*_GLOB_DAT` and `R_*_JUMP_SLOT` for binds.",
        "Base relocations in `.reloc` for rebasing; imports are bound through the import tables.",
        "Stored pointers must be corrected when the image is not loaded where it was linked, and imported addresses are known only at load time.",
        "relocations", view("dyld_info")),
    row("relro", "Read-only after relocation",
        "The `__DATA_CONST` segment, flagged `SG_READ_ONLY`; dyld makes it read-only after fixups.",
        "The `PT_GNU_RELRO` range; with bind-now it also covers the PLT's pointer slots (full RELRO).",
        "The linker places the import address table in read-only `.rdata`; the loader unprotects it only while binding.",
        "Pointer tables that only the loader needs to write should not stay writable.",
        "relro", view("security_audit")),
    row("initialisers", "Code that runs before main",
        "`__mod_init_func` or `__init_offsets` sections, run by dyld; Objective-C `+load` methods.",
        "`.init_array`, run by the dynamic linker for libraries and by the C library's start-up code for the executable; an executable's `.preinit_array` runs before both.",
        "The C runtime's initialiser tables, and TLS callbacks, which the loader runs before the entry point.",
        "Global objects and runtimes need set-up before the program proper starts.",
        "initializers-tls", view("function_starts")),
    row("symbols", "Symbols",
        "`LC_SYMTAB` (an `nlist_64` array and a string table), grouped by `LC_DYSYMTAB`; exports also in a trie.",
        "`.dynsym` for dynamic linking (always present in dynamic files) and `.symtab` for everything else (removable).",
        "Normally no symbol table in images. Only imported and exported names; the rest is in the PDB.",
        "Names are how separately built pieces find each other, and how people read the result.",
        "symbols", symbol("first")),
    row("signature", "Code signature",
        "`LC_CODE_SIGNATURE`: a SuperBlob with per-page hashes (CodeDirectory), entitlements and a CMS signature. Checked by the kernel as pages are loaded.",
        "No signature in the format. Integrity is provided around the file (packages, IMA, fs-verity).",
        "Authenticode: a PKCS #7 signature in the certificate table at the end of the file, covering a hash of the rest.",
        "The system, or the user, wants to know that the code is unmodified and where it came from.",
        "code-signing", signature(), formats=["macho", "pe"]),
    row("identity", "Build identifier",
        "`LC_UUID`, matched with the UUID of a `.dSYM` bundle.",
        "The `NT_GNU_BUILD_ID` note, matched with a separate debug file.",
        "The GUID and age in the CodeView record of the debug directory, matched with a PDB.",
        "Debug information is kept in a separate file and must be matched to the exact build.",
        "debug-info", debug_id()),
]

# The ten rows published in the legacy `rosetta_stone` list of the document.
LEGACY_IDS = ["identification", "segments", "base", "entry", "loader", "indirection", "fixups", "relro", "initialisers", "signature"]


def by_id() -> Dict[str, Dict[str, Any]]:
    return {r["id"]: r for r in ROWS}
