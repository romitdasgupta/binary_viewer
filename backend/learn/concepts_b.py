"""Curriculum, part 2: Dynamic linking; Loading and memory."""

from .dsl import (code, concept, entry, entry_field, fixup, hfield, import_slot, lc, note, ol, section, see,
                  segment, table, ul, view, wrong)

MODULES = [
    {
        "id": "dynamic",
        "title": "Dynamic linking",
        "summary": "How an image names the libraries it needs and how calls reach them: GOT, PLT, stubs, the IAT, binding and fixups.",
    },
    {
        "id": "loading",
        "title": "Loading and memory",
        "summary": "Virtual memory, the three kinds of address, what the kernel and the dynamic linker do at launch, position independence and ASLR.",
    },
]

CONCEPTS = [
    # ------------------------------------------------------------------ dynamic
    concept(
        id="shared-libraries",
        title="Naming and finding shared libraries",
        level=2,
        summary="An image records the libraries it depends on by name; the dynamic linker turns each name into a file.",
        body=[
            "A dynamically linked image lists its dependencies. Two questions follow: what exactly is recorded, "
            "and how the [[dynamic-linker|dynamic linker]] finds a file for it. The three systems answer both "
            "differently.",
            "In all three, the name is copied into the image at link time from the library that was linked "
            "against, and the search at run time is recursive: each library loaded has dependencies of its own.",
        ],
        macho=[
            "Each dependency is an `LC_LOAD_DYLIB` command holding a full path, the library's "
            "[[install-name|install name]]. The path may start with `@rpath/`, `@executable_path/` or "
            "`@loader_path/`; `@rpath` is replaced in turn by each directory of the run-path list, which dyld "
            "builds from the `LC_RPATH` commands of the images in the chain that led to this load (the "
            "main executable down to the image that names the library). The command also records the "
            "library version the image was built against.",
            "Variants of the command change the rule: `LC_LOAD_WEAK_DYLIB` (the library may be absent), "
            "`LC_REEXPORT_DYLIB` (its symbols are offered as this image's own).",
            "On current systems most system libraries are not separate files on disk. They are merged into the "
            "[[dyld-shared-cache|dyld shared cache]], and dyld resolves their install names inside it.",
        ],
        elf=[
            "Each dependency is a `DT_NEEDED` entry in the `.dynamic` table holding a bare file name, the "
            "library's [[soname|SONAME]], such as `libc.so.6`.",
            "The glibc dynamic linker searches, in order: `DT_RPATH` directories (only if there is no "
            "`DT_RUNPATH`), the `LD_LIBRARY_PATH` environment variable, `DT_RUNPATH` directories, the cache "
            "file `/etc/ld.so.cache`, then the default system directories. `$ORIGIN` in a path stands for the "
            "directory of the image.",
        ],
        pe=[
            "Each dependency is an entry in the import directory holding a file name such as `KERNEL32.dll`, "
            "compared without regard to case. There is no path.",
            "The loader looks the name up in a system list of known DLLs, then in the application's directory, "
            "the system directories and finally the directories in `PATH` (the exact order depends on system "
            "settings and on the API used to load). Names beginning `api-ms-win-` are *API sets*: virtual names "
            "that the loader maps to a real DLL.",
        ],
        differences="Mach-O records where the library is expected to be; ELF and PE record only what it is "
                    "called and leave the location to a search path.",
        see=[
            see("The first dependency recorded in this file",
                lc(macho=["LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB"], elf=["PT_DYNAMIC"], pe=["DATA_DIR_IMPORT_TABLE"])),
            see("A run-path entry", lc(macho=["LC_RPATH"]), ["macho"]),
            see("All dependencies, in the overview", view("overview")),
        ],
        misconceptions=[
            wrong("DT_NEEDED entries are paths.",
                  "They are normally bare SONAMEs. A path appears only if the library was linked without a SONAME and by path."),
            wrong("The path in a Mach-O load command is only a hint.",
                  "It is the path dyld uses, after expanding `@rpath` and similar prefixes, unless an environment variable that the process is allowed to honour overrides it."),
        ],
        next=["got-plt", "elf-dynamic", "pe-imports"],
        sources=["dyld(1), ld.so(8)", "Microsoft: Dynamic-link library search order"],
    ),
    concept(
        id="got-plt",
        title="Calling into another image: GOT, PLT, stubs and the IAT",
        level=2,
        summary="Code reaches imported functions through a table of pointers that the loader fills in, so the code itself never has to be patched.",
        body=[
            "When code calls a function in a shared library, the address of that function is unknown until the "
            "library is loaded. The loader could patch every call instruction, but then code pages would differ "
            "from the file, could not be shared between processes, and would have to be writable.",
            "All three formats use the same alternative: *indirection*. The addresses are collected in a table of "
            "pointers in a data segment. The loader writes each address once into the table. Code reaches the "
            "function by loading the pointer from the table and jumping to it.",
            ul(
                "The table is the [[got|GOT]] (global offset table) in ELF and Mach-O and the [[iat|IAT]] (import "
                "address table) in PE.",
                "The small piece of code that jumps through a table slot is a [[plt|PLT]] entry in ELF, a "
                "[[stub]] in Mach-O and an import thunk in PE.",
            ),
            "References to imported *data* use the same table without a stub: the code loads the pointer and "
            "then dereferences it.",
        ],
        macho=[
            "Stubs are in `__TEXT,__stubs`. Each loads a pointer from `__DATA_CONST,__got` and branches to it. "
            "Older binaries keep the pointers for functions in `__DATA,__la_symbol_ptr` instead. On arm64e the "
            "sections are `__auth_stubs` and `__auth_got`, and the pointers are signed "
            "([[pac|pointer authentication]]).",
            "The link between a slot and a name is the [[indirect-symbol-table|indirect symbol table]]: for each "
            "stub and each pointer slot, in order, the index of a symbol. The section header field `reserved1` "
            "gives the section's first index in it.",
        ],
        elf=[
            "A call goes to an entry in `.plt`, which jumps through a slot in `.got.plt` (relocation type "
            "`JUMP_SLOT`). Imported data and address-of references use `.got` (relocation type `GLOB_DAT`). "
            "Code built with `-fno-plt` calls through the GOT slot directly and has no PLT entry for that call.",
        ],
        pe=[
            "Code compiled with knowledge of the import calls through the IAT slot directly: "
            "`call qword ptr [__imp_Func]`. Otherwise the linker supplies a thunk, a single "
            "`jmp qword ptr [__imp_Func]`, and the call goes to the thunk.",
            "There is one IAT per imported DLL, each a zero-terminated array of pointers. Data directory 12 "
            "covers all of them.",
        ],
        differences="ELF and Mach-O compilers normally do not know whether a function will come from another "
                    "image. They emit an ordinary direct call, and the linker points it at a stub when the "
                    "target turns out to be imported. Windows compilers are told (`__declspec(dllimport)`), "
                    "so the indirect call can be emitted in place.",
        see=[
            see("The pointer slots and the symbols they belong to", view("dysymtab")),
            see("The first pointer slot in the file", import_slot()),
            see("The stub code",
                section(macho=["__stubs", "__auth_stubs"], elf=[".plt", ".plt.sec"]), ["macho", "elf"]),
            see("The pointer table",
                section(macho=["__got", "__auth_got", "__la_symbol_ptr"], elf=[".got", ".got.plt"]), ["macho", "elf"]),
            see("The IAT data directory", lc(pe=["DATA_DIR_IAT"]), ["pe"]),
        ],
        misconceptions=[
            wrong("The GOT contains code.", "It contains pointers. The code that uses them is in the PLT or the stubs."),
            wrong("The IAT and the import table are the same thing.",
                  "The import directory describes what to import. The IAT is the array of slots that receives the resulting addresses."),
            wrong("Every call to a library function runs the symbol lookup again.",
                  "The lookup happens once per slot, at load time or on the first call. After that the slot holds the final address."),
        ],
        next=["lazy-binding", "relro"],
        sources=["System V psABI for x86-64, section on the procedure linkage table", "<mach-o/loader.h> (S_SYMBOL_STUBS, indirect symbols)",
                 "Microsoft PE/COFF specification, the .idata section"],
    ),
    concept(
        id="lazy-binding",
        title="Lazy and eager binding",
        level=3,
        summary="An imported function can be resolved when the image is loaded, or the first time it is called.",
        body=[
            "*Eager* binding resolves every import before the program starts. *Lazy* binding postpones the "
            "lookup of each function until its first call: the table slot initially points at a resolver "
            "routine, which looks the symbol up, overwrites the slot with the real address and jumps there.",
            "Lazy binding shortens start-up for programs that import far more functions than they call. Its "
            "cost is that the slots must stay writable for the life of the process, which makes them a target "
            "for memory-corruption attacks (see [[concept:relro|RELRO and read-only pointer tables]]). For "
            "that reason the trend on every system is toward eager binding.",
        ],
        macho=[
            "The older file layout is built for lazy binding: each slot in `__DATA,__la_symbol_ptr` starts out "
            "pointing into `__TEXT,__stub_helper`, which calls `dyld_stub_binder`. The information for each "
            "lazy bind is in the lazy-bind opcode stream of `LC_DYLD_INFO_ONLY`. Current versions of dyld no "
            "longer wait for the first call: they resolve the lazy-bind entries at load time together with "
            "the ordinary binds, so the helper path is not taken, although the slots stay in writable `__DATA`.",
            "Binaries that use [[chained-fixups|chained fixups]] bind everything at load. They have no lazy "
            "pointers and no stub helper, and their `__got` lives in the read-only-after-fixups segment "
            "`__DATA_CONST`.",
            note("The Apple linker selects chained fixups by default for recent deployment targets (roughly "
                 "macOS 12 and iOS 15 onward); the exact rule depends on the linker version."),
        ],
        elf=[
            "Lazy binding is the traditional default. On x86-64 a `.got.plt` slot initially points back into "
            "its own PLT entry, which pushes the relocation index and jumps to the first PLT entry; that entry "
            "calls the dynamic linker's resolver (`_dl_runtime_resolve` in glibc). Other architectures differ "
            "in detail: on ARM64 every slot initially points at the first PLT entry.",
            "Eager binding is requested at link time with `-z now`, recorded as `DF_BIND_NOW` in `DT_FLAGS` or "
            "`DF_1_NOW` in `DT_FLAGS_1`, or at run time with the environment variable `LD_BIND_NOW`. Many "
            "distributions build with `-z now` by default.",
        ],
        pe=[
            "Ordinary imports are always bound when the image is loaded. Lazy behaviour exists only as "
            "*delay-load* imports, a separate table (data directory 13) created by the linker option "
            "`/DELAYLOAD`: the DLL itself is loaded on the first call to one of its functions.",
        ],
        see=[
            see("The pointer section the stubs use: lazy pointers in older files, the GOT in files with chained fixups",
                section(macho=["__la_symbol_ptr", "__got", "__auth_got"]), ["macho"]),
            see("The PLT's pointer table", section(elf=[".got.plt", ".got"]), ["elf"]),
            see("What the hardening view concludes", view("security_audit")),
        ],
        misconceptions=[
            wrong("Lazy binding is always in effect.",
                  "It depends on how the binary was linked. Full RELRO on ELF and chained fixups on Mach-O both mean everything is bound at load."),
            wrong("Windows binds imports lazily.",
                  "Only delay-load imports are deferred. The normal import table is fully bound before the entry point runs."),
        ],
        next=["relro", "dyld-fixups"],
        sources=["ld(1): -z now, -z lazy", "<mach-o/loader.h> (dyld_info_command)"],
    ),
    concept(
        id="dyld-fixups",
        title="Mach-O binding: dyld info and chained fixups",
        level=3,
        summary="Two generations of encoding tell dyld which pointers to rebase and which to bind.",
        body=[
            "dyld needs two lists for every image: the pointers to [[rebase]] (add the [[slide]]) and the "
            "pointers to [[bind]] (store the address of an imported symbol). Mach-O has encoded these lists in "
            "two ways.",
            "*Opcode streams* (`LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`). The command locates up to five blocks in "
            "`__LINKEDIT`: four byte-code programs (rebase, bind, weak bind, lazy bind) and the export "
            "information, which is a [[export-trie|trie]], not a program. Each opcode updates a small state "
            "(current segment and offset, library ordinal, symbol name, pointer type, addend) or performs a "
            "rebase or bind at the current position. Operands are [[leb128|LEB128]] numbers.",
            "*Chained fixups* (`LC_DYLD_CHAINED_FIXUPS`). The location list is not stored separately. Instead, "
            "every pointer slot that needs fixing holds, on disk, a packed value: one bit saying bind or "
            "rebase, the target (an offset into the image, or an index into the imports table), and the "
            "distance to the *next* slot on the same page. The load command's data gives, per segment and per "
            "page, the offset of the first slot. dyld walks each chain and overwrites every slot with the final "
            "pointer.",
            "Chained fixups are smaller, touch each data page once, and leave no reason for the pointer tables "
            "to be writable afterwards. Exported symbols of such binaries are in a separate "
            "[[export-trie|export trie]] named by `LC_DYLD_EXPORTS_TRIE`.",
            "A bind names its library by *ordinal*: the 1-based position of the library among the image's "
            "`LC_LOAD_DYLIB` commands and their variants (weak, re-export, upward). This is the [[two-level-namespace|two-level namespace]]: a symbol is "
            "looked up in one specific library, not in everything that is loaded. A few special ordinals exist "
            "(0 is the image itself; negative values request the main executable, a flat lookup or a weak "
            "lookup).",
        ],
        macho=[
            "In the common 64-bit pointer format (`DYLD_CHAINED_PTR_64` and `DYLD_CHAINED_PTR_64_OFFSET`) the top "
            "bit selects bind or rebase and the 12-bit `next` field counts in 4-byte units. A rebase stores a "
            "36-bit target; a bind stores a 24-bit import ordinal and an 8-bit addend.",
            "On arm64e the formats (`DYLD_CHAINED_PTR_ARM64E` and relatives) add an *auth* bit and, for "
            "authenticated pointers, the key and a 16-bit diversity value, so that dyld can sign the pointer "
            "as it writes it.",
        ],
        elf=[
            "The equivalent information is the relocation tables `.rela.dyn` and `.rela.plt`. The compact "
            "`DT_RELR` encoding for relative relocations is the closest ELF counterpart of a rebase chain.",
        ],
        pe=[
            "Rebases are the base relocation table. Binds are the import tables. There is no equivalent of a "
            "chain stored in the pointers themselves.",
        ],
        see=[
            see("The load command that names the fixup data",
                lc(macho=["LC_DYLD_CHAINED_FIXUPS", "LC_DYLD_INFO_ONLY", "LC_DYLD_INFO"]), ["macho"]),
            see("The decoded fixups, imports and exports", view("dyld_info")),
            see("The first pointer slot that dyld will rewrite", fixup(), ["macho"]),
        ],
        misconceptions=[
            wrong("The 8 bytes in a __got slot on disk are an address.",
                  "With chained fixups they are a packed description of what to write there and where the next fixup is. They become an address only after dyld has processed the chain."),
            wrong("dyld searches every loaded library for each symbol.",
                  "With two-level namespaces each bind names the library to search by ordinal."),
        ],
        next=["process-startup-macos", "relro"],
        sources=["<mach-o/fixup-chains.h>", "<mach-o/loader.h> (dyld_info_command, bind and rebase opcodes)"],
    ),
    concept(
        id="pe-imports",
        title="PE imports and exports",
        level=3,
        summary="The import directory, the lookup and address tables behind it, and the export directory on the other side.",
        body=[
            "Data directory 1 locates the *import directory*: an array of 20-byte `IMAGE_IMPORT_DESCRIPTOR` "
            "structures, one per DLL, ended by an all-zero entry. Each descriptor holds three [[rva|RVAs]] that "
            "matter:",
            ul(
                "`Name`: the DLL's file name as a zero-terminated string.",
                "`OriginalFirstThunk`: the *import lookup table* (ILT, also called the import name table), an "
                "array of pointer-sized entries, one per imported function, ended by zero.",
                "`FirstThunk`: the [[iat|import address table]], an array of the same shape.",
            ),
            "Each lookup entry either has its top bit set, in which case the low 16 bits are an [[ordinal]], or "
            "is the RVA of a *hint/name* entry: a 16-bit hint followed by the function name. On disk the IAT "
            "normally holds a copy of the lookup table. The loader replaces each IAT entry with the address of "
            "the function.",
            "The other side is the *export directory* (data directory 0) of the DLL. It holds three parallel "
            "tables: function addresses (RVAs, indexed by ordinal minus `Base`), names (sorted, so they can be "
            "binary-searched) and, for each name, the index of its address. The hint in an import is the "
            "position where the name was found at link time, tried first as a shortcut.",
            "An export whose address RVA points *inside* the export directory is a [[forwarder]]: the bytes "
            "there are a string such as `NTDLL.RtlAllocateHeap` naming the real implementation in another DLL.",
        ],
        macho=[
            "The counterpart of the import tables is the bind information (see "
            "[[concept:dyld-fixups|Mach-O binding]]); the counterpart of the export directory is the export "
            "trie.",
        ],
        elf=[
            "Imports are undefined symbols in `.dynsym` plus the relocations that refer to them. Exports are the "
            "defined global symbols in `.dynsym`. Lookup uses a hash table instead of a sorted name list.",
        ],
        pe=[
            "Importing by ordinal alone saves the name lookup but ties the importer to one version of the DLL; "
            "system DLLs are imported by name. *Delay-load* imports use a separate descriptor table (data "
            "directory 13) and are bound on first use.",
        ],
        see=[
            see("The import directory entry in the data directories", lc(pe=["DATA_DIR_IMPORT_TABLE"]), ["pe"]),
            see("The IAT directory entry", lc(pe=["DATA_DIR_IAT"]), ["pe"]),
            see("The export directory entry", lc(pe=["DATA_DIR_EXPORT_TABLE"]), ["pe"]),
            see("Imports, exports and relocations decoded", view("dyld_info")),
            see("The IAT slots and their functions", view("dysymtab")),
        ],
        misconceptions=[
            wrong("OriginalFirstThunk and FirstThunk point to the same table.",
                  "They point to two tables with the same initial content. One is kept as the description; the other is overwritten with addresses."),
            wrong("The hint must be correct.",
                  "It is only a starting guess. If the name at that position does not match, the loader searches the name table."),
        ],
        next=["process-startup-windows", "got-plt"],
        sources=["Microsoft PE/COFF specification: the .idata and .edata sections"],
    ),
    concept(
        id="elf-dynamic",
        title="The ELF dynamic section and symbol lookup",
        level=3,
        summary="Everything the ELF dynamic linker needs is reachable from one table of tagged values.",
        body=[
            "The `PT_DYNAMIC` program header locates the `.dynamic` table: an array of (tag, value) pairs ended "
            "by `DT_NULL`. The dynamic linker works entirely from this table. It does not read section headers.",
            table(
                ["Tag", "Value"],
                [
                    ["`DT_NEEDED`", "offset, in the dynamic string table, of the name of a required library"],
                    ["`DT_STRTAB`, `DT_SYMTAB`", "addresses of the dynamic string and symbol tables"],
                    ["`DT_GNU_HASH`, `DT_HASH`", "address of the symbol hash table"],
                    ["`DT_RELA`, `DT_RELASZ`", "address and size of the relocation table"],
                    ["`DT_JMPREL`, `DT_PLTRELSZ`", "address and size of the PLT relocations"],
                    ["`DT_INIT_ARRAY`, `DT_FINI_ARRAY`", "arrays of initialiser and finaliser functions"],
                    ["`DT_RUNPATH`", "library search path of this image"],
                    ["`DT_FLAGS`, `DT_FLAGS_1`", "flags such as `DF_BIND_NOW`, `DF_1_NOW`, `DF_1_PIE`"],
                    ["`DT_SONAME`", "the name under which other images should record this library"],
                ],
            ),
            "Symbol lookup in ELF is *global*. To bind a reference, the dynamic linker searches the executable "
            "first and then every loaded library in load order, and takes the first definition it finds. A "
            "definition in the executable, or in a library named in `LD_PRELOAD`, therefore replaces the "
            "library's own; this is called [[interposition]].",
            "glibc adds *symbol versioning*: a symbol reference can name a version (`puts@GLIBC_2.2.5`), stored "
            "in the sections `.gnu.version` and `.gnu.version_r`, so one library can keep old and new "
            "implementations of the same function.",
        ],
        macho=[
            "Mach-O spreads the same information over several load commands, and binds each symbol to a named "
            "library rather than searching globally.",
        ],
        elf=[
            "In a position-independent executable or a library, the address-valued entries of `.dynamic` are "
            "relative to the load base. The `.dynamic` section is inside the region that "
            "[[relro|RELRO]] makes read-only.",
        ],
        pe=[
            "The data directories play the role of the dynamic table: a fixed array of sixteen (RVA, size) "
            "pairs with an assigned meaning per index, instead of a list of tags.",
        ],
        see=[
            see("The PT_DYNAMIC program header", lc(elf=["PT_DYNAMIC"]), ["elf"]),
            see("The .dynamic section", section(elf=[".dynamic"]), ["elf"]),
            see("The dynamic symbol table", section(elf=[".dynsym"]), ["elf"]),
            see("Dynamic linking information decoded", view("dyld_info")),
        ],
        misconceptions=[
            wrong("The dynamic linker finds .dynsym by its section name.",
                  "It finds it through the `DT_SYMTAB` entry of the dynamic table. Section names and headers are not used at run time."),
            wrong("A symbol is always taken from the library it was linked against.",
                  "ELF records which libraries are needed but not which one provides which symbol. The first definition in the global search order wins."),
        ],
        next=["process-startup-linux", "relro"],
        sources=["System V gABI, chapter 5 (dynamic linking)", "ld.so(8)"],
    ),

    # ------------------------------------------------------------------ loading
    concept(
        id="virtual-memory",
        title="Virtual memory, pages and permissions",
        level=1,
        summary="A process sees its own address space, built from pages that each carry read, write and execute permissions. Loading a program means mapping parts of its file into that space.",
        body=[
            "Every process has its own [[address-space|address space]]. The addresses a program uses are "
            "[[virtual-address|virtual]]: the CPU translates each one, through tables maintained by the kernel, "
            "to a location in physical memory, or to nothing at all.",
            "The unit of translation is the [[page]]: 4 KiB on x86 and x86-64, 16 KiB on Apple silicon, and "
            "4, 16 or 64 KiB on other ARM64 systems depending on the kernel. Each page has "
            "[[page-permissions|permissions]]: readable, writable, executable. An access the permissions do not "
            "allow stops the program with a fault (`SIGSEGV`, or an access violation on Windows).",
            "A loader does not copy the file into memory. It asks the kernel to [[memory-mapping|map]] ranges of "
            "the file at chosen addresses. Pages are read from the file the first time they are touched "
            "([[demand-paging|demand paging]]). Pages that are never written are shared by every process that "
            "maps the same file; a page that is written gets a private copy at that moment.",
            "Two properties of every executable format follow from this:",
            ul(
                "What is mapped together must be laid out in page-sized units, and a byte's position within its "
                "page must be the same in the file and in memory.",
                "A segment may be larger in memory than in the file. The extra part is filled with zeros by the "
                "kernel and takes no space on disk. This is how zero-initialised variables "
                "([[bss|.bss]]) are stored.",
            ),
        ],
        macho=[
            "Each segment command has `vmaddr` and `vmsize` (where and how much in memory), `fileoff` and "
            "`filesize` (which bytes of the file), and `initprot` and `maxprot` (the permissions, and the most "
            "they may ever be raised to). Segments are aligned to 16 KiB in arm64 files and 4 KiB in x86-64 "
            "files.",
        ],
        elf=[
            "Each `PT_LOAD` program header has `p_vaddr` and `p_memsz`, `p_offset` and `p_filesz`, `p_flags` for "
            "permissions and `p_align`. The specification requires `p_vaddr` and `p_offset` to be equal modulo "
            "`p_align`.",
        ],
        pe=[
            "Each section header has `VirtualAddress` and `VirtualSize`, `PointerToRawData` and `SizeOfRawData`, "
            "and permissions in `Characteristics`. PE uses two alignments: `FileAlignment` (often 512 bytes) "
            "for the file and `SectionAlignment` (a page) for memory, so a section's position within the file "
            "is generally not its position within its page in memory. The memory manager handles this when it "
            "maps the file as an image.",
        ],
        see=[
            see("The segments, in file order and in memory order (also shown in the memory map at the top)", view("segments")),
            see("The permissions field of the code segment",
                segment("exec", field={"macho": "initprot", "elf": "p_flags", "pe": "Characteristics"})),
            see("A segment that is larger in memory than in the file", segment("zerofill", part="header"), optional=True),
        ],
        misconceptions=[
            wrong("Loading a program reads the file into RAM.",
                  "The file is mapped. A page is read only when the program first touches it, and many pages never are."),
            wrong("Each section has its own permissions in memory.",
                  "Permissions apply to whole pages. Sections that share a page share its permissions."),
            wrong("A segment's size in memory equals its size in the file.",
                  "It can be larger. The difference is zero-filled memory that is not stored in the file."),
        ],
        next=["addresses", "nx-wx"],
    ),
    concept(
        id="addresses",
        title="File offsets, virtual addresses and RVAs",
        level=1,
        summary="The same byte has a position in the file and an address in memory. Converting between them goes through the segment table.",
        body=[
            "Three coordinate systems are in use, and most confusion in binary analysis comes from mixing them:",
            ul(
                "A [[file-offset|file offset]] is the position of a byte in the file. In a universal Mach-O file "
                "there are two: the offset from the start of the file and the offset from the start of the "
                "[[slice]].",
                "A [[virtual-address|virtual address]] (VA) is where the byte appears in memory, as planned by "
                "the linker.",
                "A [[rva|relative virtual address]] (RVA) is a virtual address minus the address where the image "
                "starts, its [[image-base|image base]].",
            ),
            "The address at run time is the linked address plus the [[slide]]: the difference between where the "
            "image was actually loaded and where it was linked to go. The slide is zero if the image is loaded "
            "at its preferred address.",
            "There is no single constant that converts an address to a file offset. Each segment is mapped "
            "separately, so the conversion is per segment:",
            code("offset_in_file = address - segment.address + segment.file_offset\n"
                 "valid only if    address - segment.address < segment.file_size"),
            "An address in the zero-filled tail of a segment has no file offset at all. The Translate bar does "
            "this lookup in both directions and names the segment it used.",
        ],
        macho=[
            "Headers store absolute virtual addresses; a 64-bit executable is normally linked at `0x100000000`, "
            "above the unmapped `__PAGEZERO` region. `LC_MAIN` is an exception: its `entryoff` is a file offset.",
        ],
        elf=[
            "A fixed-address executable (`ET_EXEC`) stores absolute addresses. A position-independent executable "
            "or shared library (`ET_DYN`) is linked at address zero, so its addresses are in effect offsets from "
            "the load base. `e_entry` is a virtual address in both cases.",
        ],
        pe=[
            "Nearly every address-like field is an RVA; the virtual address is `ImageBase + RVA`. To convert an "
            "RVA to a file offset, find the section whose `VirtualAddress` range contains it and compute "
            "`PointerToRawData + (RVA - VirtualAddress)`.",
            "One field looks like an RVA and is not: the certificate table's data directory entry holds a file "
            "offset, because the signature is not mapped into memory.",
        ],
        differences="PE standardised on RVAs so that almost nothing in the headers depends on the load address. "
                    "ELF reaches the same result for position-independent files by linking them at zero. "
                    "Mach-O keeps absolute addresses and relies on the slide.",
        see=[
            see("The field that stores the entry point", entry_field()),
            see("The bytes that the entry point address refers to", entry()),
            see("The segment that contains them", segment("exec", part="header")),
        ],
        misconceptions=[
            wrong("An address is a file offset plus a constant.",
                  "The difference between the two changes from segment to segment, and some addresses have no file offset."),
            wrong("An RVA is a file offset.",
                  "An RVA is a distance in memory from the image base. In a typical PE file with 512-byte file alignment, only the headers have equal RVAs and file offsets."),
        ],
        next=["process-startup-linux", "process-startup-macos", "process-startup-windows", "pic-pie"],
    ),
    concept(
        id="process-startup-linux",
        title="How Linux starts a program",
        level=2,
        summary="The kernel maps the executable and its interpreter; the dynamic linker loads the libraries and applies relocations; the C runtime calls main.",
        body=[
            ol(
                "A process calls `execve`. The kernel reads the start of the file and offers it to its binary "
                "format handlers; the ELF handler (`load_elf_binary` in `fs/binfmt_elf.c`) accepts files that "
                "start with the ELF magic, have type `ET_EXEC` or `ET_DYN` and are for this machine.",
                "The kernel reads the [[program-header|program headers]]. If there is a `PT_INTERP` header it "
                "reads the path of the [[interpreter]] (the dynamic linker) and opens that file too. "
                "`PT_GNU_STACK` tells it whether the stack must be executable.",
                "The old address space is discarded. Each `PT_LOAD` segment is mapped. For an `ET_DYN` file the "
                "kernel chooses the load base, at random if [[aslr|ASLR]] is enabled. Memory beyond a segment's "
                "file size is zero-filled.",
                "If there is an interpreter, it is mapped the same way.",
                "The kernel builds the initial stack: the argument count, the argument and environment strings, "
                "and the [[auxiliary-vector|auxiliary vector]], a list of values such as `AT_PHDR` (address of "
                "the program headers), `AT_ENTRY` (the program's entry point), `AT_BASE` (where the interpreter "
                "was loaded) and `AT_RANDOM` (the address of sixteen random bytes).",
                "Execution starts in user mode at the interpreter's entry point, or at `e_entry` if the "
                "executable is static.",
                "The dynamic linker relocates itself, loads every `DT_NEEDED` library, applies all relocations, "
                "makes the [[relro|RELRO]] region read-only, runs the initialisers of the libraries, and jumps "
                "to `AT_ENTRY`.",
                "The entry point is `_start`, a few instructions from the C runtime that call "
                "`__libc_start_main`. That function runs the executable's own initialisers and then calls "
                "`main`; when `main` returns, it calls `exit`.",
            ),
            note("This describes glibc on a current kernel. Other C libraries (musl, bionic) follow the same "
                 "outline with different function names."),
        ],
        macho=[
            "On macOS the kernel's part is similar and dyld's part differs; see "
            "[[concept:process-startup-macos|How macOS starts a program]].",
        ],
        elf=[
            "A static executable has no `PT_INTERP`; the kernel jumps straight to `e_entry`. A static "
            "position-independent executable contains its own small relocation routine in the start-up code.",
        ],
        pe=[
            "Windows has no interpreter field: the loader is always the one in `ntdll.dll`; see "
            "[[concept:process-startup-windows|How Windows starts a program]].",
        ],
        see=[
            see("The interpreter path the kernel reads", lc(elf=["PT_INTERP"]), ["elf"]),
            see("A PT_LOAD header the kernel maps", lc(elf=["PT_LOAD"]), ["elf"]),
            see("The entry address in the ELF header", hfield(elf="e_entry"), ["elf"]),
            see("The instructions at the entry point", entry(), ["elf"]),
        ],
        misconceptions=[
            wrong("The kernel links the shared libraries.",
                  "The kernel maps the executable and the dynamic linker. Loading libraries and resolving symbols is done by the dynamic linker, in user mode."),
            wrong("Execution starts at main.",
                  "It starts in the dynamic linker, continues at `_start`, and reaches `main` only after the libraries and the C runtime have been initialised."),
            wrong("'No such file or directory' means the program is missing.",
                  "`execve` returns the same error when the file named by `PT_INTERP` does not exist, which is what happens when a binary built for a different C library is run."),
        ],
        next=["process-startup-macos", "process-startup-windows", "initializers-tls"],
        sources=["Linux: fs/binfmt_elf.c", "execve(2), ld.so(8), getauxval(3)", "glibc: csu/libc-start.c"],
    ),
    concept(
        id="process-startup-macos",
        title="How macOS starts a program",
        level=2,
        summary="XNU picks a slice, maps its segments and dyld, checks the signature and starts dyld; dyld binds the libraries and calls main.",
        body=[
            ol(
                "A process calls `execve` or `posix_spawn`. The kernel tries its image activators in turn: "
                "Mach-O (`exec_mach_imgact`), universal (`exec_fat_imgact`), interpreter script.",
                "For a [[universal-binary|universal]] file, the kernel picks the best [[slice]] for the machine "
                "and continues with it as if it were the whole file. The other slices are never mapped.",
                "The Mach-O must be of type `MH_EXECUTE`. The kernel walks its [[load-command|load commands]] "
                "(`parse_machfile`): each `LC_SEGMENT_64` is mapped with its permissions, shifted by a random "
                "[[slide]] if the header has `MH_PIE`; `LC_MAIN` or `LC_UNIXTHREAD` gives the entry point; "
                "`LC_CODE_SIGNATURE` locates the [[code-signature|signature]], which is loaded and checked "
                "against system policy.",
                "`LC_LOAD_DYLINKER` names the dynamic linker, normally `/usr/lib/dyld`. The kernel maps it as a "
                "second Mach-O file with its own slide.",
                "The kernel builds the stack (arguments, environment, and a further list of strings from the "
                "kernel) and starts the thread at dyld's entry point, passing the address of the executable's "
                "header.",
                "dyld loads the libraries named by `LC_LOAD_DYLIB` commands, recursively. System libraries come "
                "from the [[dyld-shared-cache|shared cache]]. It applies [[fixup|fixups]] to every image, makes "
                "segments flagged `SG_READ_ONLY` (`__DATA_CONST`) read-only, and runs initialisers, "
                "dependencies first.",
                "For an executable with `LC_MAIN`, dyld calls `main` as a function and passes its return value "
                "to `exit`.",
            ),
            note("Kernel function names are from the open-source XNU releases. Details such as which checks run "
                 "in which pass change between releases."),
        ],
        macho=[
            "On Apple silicon the kernel refuses a dynamically linked arm64 main executable that lacks `MH_PIE`, "
            "and all native code must carry a signature. `__PAGEZERO`, a segment with no permissions that "
            "covers the low 4 GiB of a 64-bit process, makes null-pointer dereferences fault.",
            "A file of type `MH_PRELOAD`, like the firmware sample, is not started by this path at all. It is "
            "meant to be placed in memory by a boot loader, which takes the initial register values from "
            "`LC_UNIXTHREAD`.",
        ],
        elf=[
            "The division of work is the same as on Linux: the kernel maps, the user-mode dynamic linker binds. "
            "The largest difference is that dyld, not the C runtime's start-up code, calls `main`.",
        ],
        pe=[
            "Windows also starts every process inside a system-provided loader, but that loader is not named by "
            "the executable.",
        ],
        see=[
            see("The command that names dyld", lc(macho=["LC_LOAD_DYLINKER"]), ["macho"]),
            see("The entry point command", lc(macho=["LC_MAIN", "LC_UNIXTHREAD"]), ["macho"]),
            see("The __PAGEZERO segment", segment("name", name={"macho": "__PAGEZERO"}, part="header"), ["macho"]),
            see("The code signature command", lc(macho=["LC_CODE_SIGNATURE"]), ["macho"]),
            see("The stages for this file", view("loader_lifecycle"), ["macho"]),
        ],
        misconceptions=[
            wrong("dyld is part of the kernel.",
                  "dyld is an ordinary Mach-O file that runs in user mode inside the new process."),
            wrong("A universal binary is loaded whole.",
                  "Only the chosen slice is mapped. Offsets inside it are relative to the start of that slice."),
            wrong("The kernel jumps to main.",
                  "The kernel starts dyld. dyld calls `main` after binding and initialisation."),
        ],
        next=["dyld-fixups", "code-signing", "initializers-tls"],
        sources=["XNU: bsd/kern/kern_exec.c, bsd/kern/mach_loader.c", "dyld(1)", "<mach-o/loader.h>"],
    ),
    concept(
        id="process-startup-windows",
        title="How Windows starts a program",
        level=2,
        summary="The kernel maps the image and ntdll.dll; the loader inside ntdll resolves imports and runs DLL initialisation; the C runtime calls main.",
        body=[
            ol(
                "A program calls `CreateProcess`. The kernel opens the file and creates an *image section* for "
                "it, validating the headers on the way: the `MZ` signature, `e_lfanew`, the `PE\\0\\0` "
                "signature, the machine type and the optional header.",
                "The kernel creates the process and maps the image into it, at `ImageBase` or, when the image "
                "allows [[aslr|ASLR]], at a randomly chosen base. It also maps `ntdll.dll`, which is present in "
                "every process. Any image, then or later, that does not end up at its preferred base has its "
                "[[base-relocation|base relocations]] applied as part of being mapped, before its imports "
                "are resolved.",
                "The kernel creates the first thread, with a stack sized from `SizeOfStackReserve` and "
                "`SizeOfStackCommit`, and the process and thread environment blocks ([[peb|PEB]] and TEB).",
                "The thread begins in the loader code of `ntdll.dll` (`LdrInitializeThunk`), not in the "
                "program. The loader walks the import directory, loads each DLL and its dependencies, and "
                "writes the addresses of the imported functions into the [[iat|IAT]].",
                "The loader calls the entry point of each DLL with `DLL_PROCESS_ATTACH`, dependencies first, "
                "and calls any [[tls-callback|TLS callbacks]].",
                "The thread then runs the image's entry point, `AddressOfEntryPoint`. This is the C runtime's "
                "start-up routine (`mainCRTStartup` and its variants), which initialises the runtime, runs "
                "C++ static constructors and calls `main` or `WinMain`.",
            ),
            note("This is a simplified outline based on Microsoft's documentation and public symbols. The "
                 "internal steps and their names differ between Windows versions."),
        ],
        macho=[
            "Compare `LC_LOAD_DYLINKER`: a Mach-O executable names its loader; a PE file cannot.",
        ],
        elf=[
            "Compare `PT_INTERP`. The Windows equivalent of the auxiliary vector is the PEB, which the loader "
            "and the runtime read for the image base, the command line and the loaded-module list.",
        ],
        pe=[
            "The `Subsystem` field tells the system what environment the program expects: a console is "
            "attached for `IMAGE_SUBSYSTEM_WINDOWS_CUI` and not for `IMAGE_SUBSYSTEM_WINDOWS_GUI`.",
            "TLS callbacks of the executable run before its entry point, which is why they are checked first "
            "when analysing a suspicious file. The PE32 sample has one.",
        ],
        see=[
            see("e_lfanew: the way from the DOS header to the PE headers", lc(pe=["IMAGE_DOS_HEADER"], field="e_lfanew"), ["pe"]),
            see("The entry point field", hfield(pe="OptionalHeader.AddressOfEntryPoint"), ["pe"]),
            see("The preferred base address", hfield(pe="OptionalHeader.ImageBase"), ["pe"]),
            see("The import directory", lc(pe=["DATA_DIR_IMPORT_TABLE"]), ["pe"]),
            see("The TLS directory", lc(pe=["DATA_DIR_TLS_TABLE"]), ["pe"], optional=True),
        ],
        misconceptions=[
            wrong("AddressOfEntryPoint is the address of main.",
                  "It is the address of the runtime start-up code that eventually calls `main`. For a DLL it is the routine the loader calls on attach and detach."),
            wrong("Nothing in the image runs before the entry point.",
                  "TLS callbacks do, and so does the initialisation routine of every DLL the image imports."),
        ],
        next=["pe-imports", "initializers-tls", "aslr"],
        sources=["Microsoft PE/COFF specification", "Microsoft: CreateProcess, DllMain, Dynamic-link library search order",
                 "Windows Internals (Russinovich, Solomon, Ionescu), process creation"],
    ),
    concept(
        id="pic-pie",
        title="Position-independent code and executables",
        level=2,
        summary="Code that refers to things by distance from itself can run at any address; an executable built that way can be loaded anywhere.",
        body=[
            "Code that contains absolute addresses works only when it is loaded exactly where the linker "
            "assumed. [[pic|Position-independent code]] (PIC) avoids absolute addresses: it refers to its own "
            "code and data by their distance from the current instruction, which does not change when the whole "
            "image moves, and reaches other images through the [[got|GOT]].",
            "How cheap that is depends on the CPU:",
            ul(
                "x86-64 can address data relative to the instruction pointer directly "
                "(`lea rax, [rip + 0x1234]`).",
                "ARM64 uses a pair of instructions: `adrp` computes the address of a 4 KiB page relative to the "
                "current one, and a following `add` or `ldr` supplies the offset within the page.",
                "32-bit x86 has no such addressing mode. PIC code there first obtains its own address with a "
                "call to a tiny helper and keeps a register pointing at the GOT, which costs a register and "
                "some speed.",
            ),
            "A [[pie|position-independent executable]] (PIE) is a main program built entirely from PIC, so that "
            "it can be loaded at any address, like a shared library. This is what makes [[aslr|ASLR]] of the "
            "executable possible.",
            "Position independence concerns code. Pointers stored in *data* (tables of function pointers, "
            "pointers to strings) are still absolute, and are corrected at load time by "
            "[[rebase|rebases or relative relocations]].",
        ],
        macho=[
            "An executable is PIE when the header flag `MH_PIE` (`0x200000`) is set. It has been the linker's "
            "default for many years, and arm64 requires it. Dynamic libraries are always position-independent.",
        ],
        elf=[
            "A PIE has type `ET_DYN`, the same type as a shared library; current linkers also set `DF_1_PIE` in "
            "`DT_FLAGS_1` to tell the two apart. A non-PIE executable has type `ET_EXEC` and is linked at a "
            "fixed address (traditionally `0x400000` on x86-64 and `0x8048000` on 32-bit x86).",
        ],
        pe=[
            "A PE image can be moved if it kept its base relocations: the `.reloc` section exists and "
            "`IMAGE_FILE_RELOCS_STRIPPED` is clear in `Characteristics`. It asks to be moved by setting "
            "`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`. 64-bit code is mostly RIP-relative, so few relocations "
            "are needed; 32-bit code relies on them heavily.",
        ],
        differences="ELF has no executable type for PIE: it reuses the shared-object type `ET_DYN`, which is "
                    "why a flag (`DF_1_PIE`) was added later to tell the two apart. Mach-O and PE keep the "
                    "executable type and add a flag.",
        see=[
            see("The field that marks this file position-independent (or not)",
                hfield(macho="flags", elf="e_type", pe="OptionalHeader.DllCharacteristics")),
            see("The code at the entry point: look for RIP-relative or adrp addressing", entry()),
            see("The hardening view's conclusion", view("security_audit")),
        ],
        misconceptions=[
            wrong("PIE and ASLR are the same thing.",
                  "PIE is a property of the file: it can be loaded anywhere. ASLR is a policy of the system: it chooses a random place. The first makes the second possible for the executable."),
            wrong("Position-independent files contain no relocations.",
                  "Their code needs none, but pointers stored in data still do."),
        ],
        next=["aslr", "relocations"],
        sources=["System V psABI for x86-64", "<mach-o/loader.h> (MH_PIE)", "Microsoft PE/COFF specification (DllCharacteristics)"],
    ),
    concept(
        id="aslr",
        title="Address space layout randomisation",
        level=2,
        summary="The system loads images, stacks and heaps at addresses that differ from run to run, so that an attacker cannot know them in advance.",
        body=[
            "Many attacks need the address of something: a function to return to, a buffer that holds injected "
            "data. [[aslr|ASLR]] removes the fixed addresses. The executable, each shared library, the stack, "
            "the heap and other mappings are placed at locations chosen at random.",
            "Three limits are worth knowing:",
            ul(
                "An image moves as a whole. Distances inside it do not change, so one leaked pointer into an "
                "image reveals the address of everything in it.",
                "The randomness is limited by the address space and by page alignment. It is much weaker in "
                "32-bit processes.",
                "An executable takes part only if it is [[pie|position-independent]]. A fixed-address executable "
                "stays where it was linked, even though its libraries move.",
            ),
        ],
        macho=[
            "A main executable with `MH_PIE` receives a random slide at each launch, and so does dyld. The "
            "[[dyld-shared-cache|shared cache]] holding the system libraries is slid once per boot, so system "
            "library addresses are the same in every process until restart.",
        ],
        elf=[
            "On Linux the sysctl `kernel.randomize_va_space` controls ASLR system-wide (2 is the usual value). "
            "At each `execve` the kernel draws separate random offsets for the load base of a PIE, for the "
            "`mmap` area that receives the dynamic linker and the libraries, for the stack and (with the "
            "value 2) for the heap. Libraries are placed next to one another inside the `mmap` area, so "
            "their distances from each other are not random.",
            "A debugger usually turns randomisation off for the program it starts. A PIE then loads at a fixed "
            "default base, `0x555555554000` on x86-64, which is why that address appears in so many tutorials.",
        ],
        pe=[
            "An image opts in with `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (`0x0040`) and must have base "
            "relocations. `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` (`0x0020`) declares that a 64-bit program "
            "copes with addresses above 4 GiB; set on the EXE, it gives the process's heaps, stacks and other "
            "allocations more random bits. How far an image itself is moved depends on whether its `ImageBase` "
            "is above 4 GiB.",
            "Windows chooses the base of a DLL the first time it is loaded after boot and reuses it in other "
            "processes, so that the relocated pages can be shared.",
        ],
        differences="Linux randomises every process independently. macOS and Windows keep system libraries at "
                    "the same address in all processes between reboots, trading some randomness for shared memory.",
        see=[
            see("The flag that allows this file to be moved",
                hfield(macho="flags", elf="e_type", pe="OptionalHeader.DllCharacteristics")),
            see("The address the file was linked for",
                segment("exec", field={"macho": "vmaddr", "elf": "p_vaddr", "pe": "VirtualAddress"})),
            see("The hardening view", view("security_audit")),
        ],
        misconceptions=[
            wrong("ASLR randomises the position of each function.",
                  "It moves whole images. The layout inside an image is fixed at link time."),
            wrong("With ASLR a memory-corruption bug cannot be exploited.",
                  "It forces the attacker to learn an address first, typically through a second bug that leaks one."),
        ],
        next=["mitigations-overview", "pic-pie"],
        sources=["Linux: Documentation/admin-guide/sysctl/kernel.rst (randomize_va_space)", "Microsoft: /DYNAMICBASE, /HIGHENTROPYVA"],
    ),
    concept(
        id="initializers-tls",
        title="Code that runs before main: initialisers and thread-local storage",
        level=3,
        summary="Each format has tables of functions that the loader or the runtime calls before main, and a description of per-thread variables.",
        body=[
            "Some code must run before `main`: constructors of C++ global objects, functions marked "
            "`__attribute__((constructor))`, and the set-up of language runtimes. The compiler emits a pointer "
            "to each such function into a special section; the linker concatenates them into one table; and "
            "something at start-up walks the table and calls each entry.",
            "[[tls|Thread-local storage]] (TLS) is the other piece of pre-`main` machinery. A thread-local "
            "variable needs one copy per thread. The file holds a template with the initial values, and the "
            "runtime copies it for each new thread.",
            "For analysis the point is simple: `main` is not the first code of the image to run, and the entry "
            "point is not the only place to look.",
        ],
        macho=[
            "Initialisers are pointers in a section of type `S_MOD_INIT_FUNC_POINTERS` (`__mod_init_func`), or "
            "32-bit offsets in a section of type `S_INIT_FUNC_OFFSETS` (`__TEXT,__init_offsets`). dyld runs them "
            "image by image, dependencies first. Objective-C `+load` methods run in the same phase.",
            "Thread-local variables are described by `__DATA,__thread_vars`, with initial values in "
            "`__thread_data` and `__thread_bss`; the header flag `MH_HAS_TLV_DESCRIPTORS` announces them.",
        ],
        elf=[
            "The tables are `.preinit_array` (executables only), `.init_array` and `.fini_array`, located at run "
            "time through `DT_INIT_ARRAY` and related tags. The dynamic linker runs the initialisers of shared "
            "libraries before it transfers control; the C library's start-up code runs the executable's own.",
            "The TLS template is the `PT_TLS` segment (sections `.tdata` and `.tbss`). Code reaches a thread's "
            "copy through the thread pointer: the `fs` segment base on x86-64, the register `TPIDR_EL0` on ARM64.",
        ],
        pe=[
            "C and C++ initialisers are pointer tables that the linker merges into read-only data "
            "(`.CRT$XI...` and `.CRT$XC...` in the object files) and that the C runtime's start-up code walks.",
            "Data directory 9 locates the TLS directory: the template's address range, the address of the "
            "module's TLS index, and `AddressOfCallBacks`, a zero-terminated array of function pointers. The "
            "loader calls these *TLS callbacks* when the process starts and when threads start and exit; for "
            "the executable, the first call comes before the entry point. The fields of the TLS directory are "
            "virtual addresses, not RVAs.",
        ],
        see=[
            see("The TLS data directory", lc(pe=["DATA_DIR_TLS_TABLE"]), ["pe"], optional=True),
            see("Thread-local variable descriptors", section(macho=["__thread_vars"]), ["macho"]),
            see("Functions and the entry point", view("function_starts")),
        ],
        misconceptions=[
            wrong("The first code of a program to run is main.",
                  "Initialisers of every loaded library, initialisers of the executable and, in PE, TLS callbacks all run earlier."),
        ],
        next=["stack-and-frames", "entropy-packing"],
        sources=["System V gABI chapter 5 (initialization and termination functions)", "ELF Handling For Thread-Local Storage (Drepper)",
                 "Microsoft PE/COFF specification, the .tls section", "<mach-o/loader.h> (section types)"],
    ),
]
