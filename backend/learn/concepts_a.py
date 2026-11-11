"""Curriculum, part 1: Foundations; From source to executable."""

from .dsl import (code, concept, fat, header, hfield, lc, note, ol, section, see, segment,
                  symbol, table, ul, view, wrong)

MODULES = [
    {
        "id": "foundations",
        "title": "Foundations",
        "summary": "Bytes, byte order, and how a file format lays structures out on disk.",
    },
    {
        "id": "build",
        "title": "From source to executable",
        "summary": "What the compiler, assembler and linker each produce, and what is inside an object file.",
    },
]

CONCEPTS = [
    # ------------------------------------------------------------------ foundations
    concept(
        id="bytes-and-hex",
        title="Bytes, hexadecimal and the hex view",
        level=1,
        summary="A file is a numbered sequence of bytes; hexadecimal is the notation that keeps byte boundaries visible.",
        body=[
            "A file is a sequence of [[byte|bytes]]. A byte is eight [[bit|bits]] and holds a value from 0 to 255. "
            "Nothing inside the file says what a given byte means. Meaning comes from the *format*: an agreement "
            "that, for example, the eight bytes starting at position 24 hold the address where execution begins.",
            "[[hexadecimal|Hexadecimal]] writes every byte as exactly two digits, `00` to `ff`. Each digit stands for "
            "four bits (a [[nibble]]), so bit patterns are easy to read: `0x80` is the top bit alone, `0x0f` is the "
            "low four bits. The prefix `0x` marks a number as hexadecimal; `0x10` is sixteen, not ten.",
            "A [[hex-dump|hex dump]] shows three columns per row: the [[file-offset|offset]] of the first byte in the "
            "row, sixteen bytes in hex, and the same bytes as text where they are printable characters. Offsets "
            "count from zero, so offset `0x10` is the seventeenth byte of the file.",
            "The same bytes can be read as a number, as text or as a machine instruction. Which reading is right "
            "depends on where the bytes are and who reads them. The decoder under the hex view shows several "
            "readings of the bytes at the cursor at once.",
        ],
        macho=[
            "A 64-bit Mach-O file for a little-endian CPU starts with the bytes `cf fa ed fe`. A universal file "
            "starts with `ca fe ba be`.",
        ],
        elf=[
            "Every ELF file starts with `7f 45 4c 46`: the byte `0x7f` followed by the letters `ELF` in ASCII.",
        ],
        pe=[
            "Every PE file starts with `4d 5a`, the letters `MZ`. They belong to the MS-DOS header that still "
            "precedes the real PE headers.",
        ],
        see=[
            see("The first bytes of the file: its magic number",
                hfield(macho="magic", elf="e_ident[EI_MAG]"), ["macho", "elf"]),
            see("The MZ signature at offset 0", lc(pe=["IMAGE_DOS_HEADER"], field="e_magic"), ["pe"]),
        ],
        misconceptions=[
            wrong("A binary file is an unreadable blob.",
                  "It is a set of documented structures. Most of this tool is those structures decoded field by field."),
            wrong("Hexadecimal data is a different kind of data.",
                  "Hex is only a way of writing numbers. The byte `0x41`, the number 65 and the letter `A` are the same eight bits."),
            wrong("Offset 0x10 is the tenth byte.",
                  "`0x10` is 16, and offsets start at zero, so it is the seventeenth byte."),
        ],
        next=["endianness", "structs-on-disk"],
    ),
    concept(
        id="endianness",
        title="Byte order (endianness)",
        level=1,
        summary="A number wider than one byte has to be stored in some order; little-endian puts the least significant byte first.",
        body=[
            "A 32-bit number occupies four bytes, and a format has to say in which order. "
            "[[little-endian|Little-endian]] stores the least significant byte first: `0x12345678` is written as "
            "`78 56 34 12`. [[big-endian|Big-endian]] stores the most significant byte first: `12 34 56 78`.",
            "x86, x86-64 and ARM64 as used by macOS, Linux and Windows are little-endian, so nearly every number you "
            "see in this tool is stored least significant byte first. To read one from the hex view, read its bytes "
            "right to left.",
            "Byte order applies to multi-byte numbers only. Text, and fields defined as arrays of bytes, are stored "
            "in reading order. Bits inside a byte are not reordered either.",
            "A format must tell its reader which order it uses, before the reader can trust any number in it. "
            "The three formats solve this differently (below). The decoder under the hex view has a byte-order "
            "switch so you can compare both readings of the same bytes.",
        ],
        macho=[
            "The [[magic-number|magic]] doubles as the byte-order mark. A reader that loads the first four bytes as "
            "a number in its own byte order and gets `0xfeedfacf` knows the file matches it. If it gets "
            "`0xcffaedfe` (`MH_CIGAM_64`), every header field must be byte-swapped.",
            "Two parts of a Mach-O file are big-endian regardless of the CPU: the [[universal-binary|universal]] "
            "(fat) header, and the [[code-signature|code signature]] blobs.",
        ],
        elf=[
            "Byte 5 of the file, `e_ident[EI_DATA]`, is `1` for little-endian (`ELFDATA2LSB`) or `2` for big-endian "
            "(`ELFDATA2MSB`). The identification bytes are single bytes precisely so that they can be read before "
            "the byte order is known.",
        ],
        pe=[
            "PE is always little-endian. There is no byte-order field.",
        ],
        differences="Mach-O and ELF were designed to describe machines of either byte order, so they must record it. "
                    "PE has only ever targeted little-endian machines.",
        see=[
            see("The magic number, stored least significant byte first", hfield(macho="magic"), ["macho"]),
            see("The byte-order field EI_DATA", hfield(elf="e_ident[EI_DATA]"), ["elf"]),
            see("e_lfanew: a 4-byte little-endian offset", lc(pe=["IMAGE_DOS_HEADER"], field="e_lfanew"), ["pe"]),
            see("The universal header, which is big-endian", fat("nfat_arch"), ["macho"]),
        ],
        misconceptions=[
            wrong("Endianness reverses the bits.", "Only the order of whole bytes changes. Each byte keeps its value."),
            wrong("Strings are stored backwards on little-endian machines.",
                  "Byte order applies to numbers. A string is a sequence of one-byte characters in reading order."),
            wrong("The bytes cf fa ed fe mean the file is big-endian.",
                  "They are the little-endian encoding of `0xfeedfacf`. The value, read in the file's own byte order, is what identifies it."),
        ],
        next=["structs-on-disk"],
        sources=["System V gABI, chapter 4 (ELF identification)", "<mach-o/loader.h>, <mach-o/fat.h>"],
    ),
    concept(
        id="structs-on-disk",
        title="Structures on disk",
        level=1,
        summary="Formats are C structures written to a file: fixed fields at fixed offsets, with counts and offsets that lead to the variable-sized parts.",
        body=[
            "Executable formats are specified as C [[struct|structures]]: a fixed sequence of [[field|fields]], each "
            "with a size and an offset from the start of the structure. Reading a format is reading known offsets. "
            "In a 64-bit ELF header, for example, the entry address is the eight bytes at offset `0x18`.",
            "A fixed-size header cannot contain variable-sized content, so it holds *references* to it: an offset "
            "and a count, sometimes with an entry size. Every loader and every tool navigates the file by following "
            "these references outward from the header.",
            ul(
                "[[magic-number|Magic number]]: the first bytes identify the format before anything else is trusted.",
                "Size fields: structures carry their own size (`cmdsize`, `e_ehsize`, `SizeOfOptionalHeader`) so a "
                "reader can skip what it does not understand and newer versions can grow.",
                "[[bit-flags|Bit flags]]: one integer packs many yes/no properties, one per bit.",
                "Names: either a fixed-size character array padded with zero bytes (a Mach-O segment name is 16 "
                "bytes, a PE section name 8), or an offset into a [[string-table|string table]].",
                "[[alignment|Alignment]] and padding: a structure or table usually starts at a multiple of 4, 8 or "
                "a page size; the gap before it is padding, normally zero bytes.",
            ),
            "The struct tables in this tool show one row per field: where it is, its raw bytes, its decoded value "
            "and what the value means. Selecting a row highlights exactly those bytes in the hex view.",
        ],
        macho=[
            "The file starts with a `mach_header_64` (32 bytes; 28 in the 32-bit form). It is followed directly by "
            "`ncmds` [[load-command|load commands]]. Each one starts with two 4-byte fields, `cmd` and `cmdsize`, "
            "so a reader can step from one command to the next without understanding all of them.",
        ],
        elf=[
            "The file starts with an `Elf64_Ehdr` (64 bytes; 52 for ELF32). It locates two tables with "
            "offset/entry-size/count triples: `e_phoff`, `e_phentsize`, `e_phnum` for the "
            "[[program-header|program headers]], and `e_shoff`, `e_shentsize`, `e_shnum` for the "
            "[[section-header|section headers]].",
        ],
        pe=[
            "The file starts with a 64-byte MS-DOS header whose last field, `e_lfanew` at offset `0x3c`, gives the "
            "offset of the signature `PE\\0\\0`. After the signature come the 20-byte "
            "[[coff-file-header|COFF file header]], the [[optional-header|optional header]] (its size is in "
            "`SizeOfOptionalHeader`), and then `NumberOfSections` section headers of 40 bytes each.",
        ],
        see=[
            see("The file header as a table of fields", header()),
            see("The count of structures that follow the header",
                hfield(macho="ncmds", elf="e_phnum", pe="FileHeader.NumberOfSections")),
            see("The offset that leads to the next structure",
                hfield(elf="e_phoff"), ["elf"]),
            see("e_lfanew, the offset of the PE headers", lc(pe=["IMAGE_DOS_HEADER"], field="e_lfanew"), ["pe"]),
        ],
        misconceptions=[
            wrong("The PE optional header is optional.",
                  "It is required in every executable image. The name comes from COFF object files, which do not have one."),
            wrong("An offset in a header always counts from the start of the file.",
                  "It depends on the field. Inside one architecture of a universal Mach-O file, offsets count from the start of that slice. Many PE fields are RVAs, which are memory offsets, not file offsets."),
        ],
        next=["file-formats-overview", "addresses"],
        sources=["System V gABI, chapter 4", "Microsoft PE/COFF specification", "<mach-o/loader.h>"],
    ),
    concept(
        id="file-formats-overview",
        title="What an executable format has to describe",
        level=1,
        summary="Mach-O, ELF and PE answer the same questions for the operating system, in three different layouts.",
        body=[
            "An executable file must tell the operating system a small number of things:",
            ul(
                "which CPU the code is for;",
                "which ranges of the file to place at which addresses, with which permissions;",
                "where execution starts;",
                "which other libraries are needed, and which names from them;",
                "which stored addresses must be adjusted if the file is loaded somewhere else.",
            ),
            "It usually also carries information for tools rather than for the loader: [[symbol|symbols]], "
            "[[debug-info|debug information]], a build identifier, a [[code-signature|signature]].",
            table(
                ["", "Mach-O", "ELF", "PE"],
                [
                    ["Used by", "macOS, iOS and other Apple systems", "Linux, the BSDs, Solaris, many embedded systems", "Windows, UEFI firmware"],
                    ["Header", "`mach_header_64`", "`Elf64_Ehdr`", "DOS header, then NT headers"],
                    ["What to map", "`LC_SEGMENT_64` load commands", "`PT_LOAD` program headers", "section table"],
                    ["Entry point", "`LC_MAIN`", "`e_entry`", "`AddressOfEntryPoint`"],
                    ["Dependencies", "`LC_LOAD_DYLIB` commands", "`DT_NEEDED` entries", "import directory"],
                    ["Several CPUs in one file", "yes (universal)", "no", "no"],
                ],
            ),
            "Each format is used for more than executables. The same structures describe relocatable "
            "[[object-file|object files]], [[shared-library|shared libraries]] and, in Mach-O and ELF, core dumps. "
            "A field in the header says which kind a file is.",
        ],
        macho=[
            "The header field `filetype` distinguishes `MH_EXECUTE`, `MH_DYLIB`, `MH_OBJECT`, `MH_BUNDLE` and others. "
            "A [[universal-binary|universal]] file wraps several complete Mach-O files, one per CPU type, behind a "
            "small big-endian table; each wrapped file is called a [[slice]].",
        ],
        elf=[
            "`e_type` is `ET_REL` for an object file, `ET_EXEC` for an executable linked at a fixed address, "
            "`ET_DYN` for a shared library or a position-independent executable, and `ET_CORE` for a core dump. "
            "`e_ident[EI_CLASS]` selects the 32-bit or 64-bit layout of every later structure.",
        ],
        pe=[
            "The `Characteristics` field has `IMAGE_FILE_DLL` set for a DLL. The optional header's `Magic` is "
            "`0x10b` for PE32 (32-bit) and `0x20b` for [[pe32-plus|PE32+]] (64-bit). Object files use the same "
            "COFF header and section table without the DOS and optional headers.",
        ],
        differences="The three formats grew up with different loaders. Mach-O expresses everything as a list of "
                    "commands for the kernel and dyld. ELF separates the loader's view (segments) from the linker's "
                    "view (sections) completely. PE keeps one table of sections and adds a fixed array of "
                    "data directories that point at loader tables inside them.",
        see=[
            see("The field that says what kind of file this is",
                hfield(macho="filetype", elf="e_type", pe="FileHeader.Characteristics")),
            see("The field that names the CPU",
                hfield(macho="cputype", elf="e_machine", pe="FileHeader.Machine")),
            see("The universal header and its slices", fat(), ["macho"]),
            see("Overview of this file", view("overview")),
        ],
        misconceptions=[
            wrong("The file extension decides what a file is.",
                  "Loaders look at the header. `.exe`, `.dll`, `.so` and `.dylib` are conventions for people and build tools."),
            wrong("ELF is the Linux format.",
                  "ELF comes from UNIX System V and is used by many systems. The `e_ident[EI_OSABI]` byte and note sections identify the target system where that matters."),
            wrong("A 64-bit Windows executable is a PE64 file.",
                  "The 64-bit variant is called PE32+. Most fields keep their 32-bit sizes; only addresses and a few sizes are widened to 64 bits."),
        ],
        next=["compile-pipeline", "sections-vs-segments"],
    ),

    # ------------------------------------------------------------------ build
    concept(
        id="compile-pipeline",
        title="From source to object file to executable",
        level=1,
        summary="The compiler turns each source file into an object file; the linker combines object files and libraries into one image; the loader finishes the job at run time.",
        body=[
            "Building a program is a chain of separate tools. A command such as `cc` or `cl` is a *driver* that "
            "runs them in order:",
            ol(
                "The [[compiler]] translates one source file (a [[translation-unit|translation unit]]) into assembly "
                "for one CPU.",
                "The [[assembler]] encodes that into machine code and writes an [[object-file|object file]] "
                "(`.o` or `.obj`).",
                "The [[linker]] combines object files and libraries into an executable or a shared library.",
                "At run time the [[loader]] maps the result into memory and connects it to the shared libraries it "
                "needs.",
            ),
            "The stages exist because of what each one can know. The compiler sees one file, so it cannot know "
            "where a function defined in another file will end up; it leaves a named hole (a "
            "[[relocation]]). The linker sees the whole program and can lay it out, but it cannot know at which "
            "address the operating system will place it, or where a system library will be. The loader knows "
            "that, and makes the final adjustments.",
            code("cc -c main.c -o main.o      # compile + assemble: one object file\n"
                 "cc -c util.c -o util.o\n"
                 "cc main.o util.o -o prog    # link: one executable\n"
                 "./prog                      # load and run",
                 "The same steps a build system runs for you"),
            "Every later topic in this curriculum is about what one of these stages writes into the file for the "
            "next one to read.",
        ],
        macho=[
            "Object files are Mach-O files of type `MH_OBJECT`; the linker (`ld`) writes `MH_EXECUTE` or `MH_DYLIB`. "
            "Inspect either with `otool -hlv` and `nm`.",
        ],
        elf=[
            "Object files are ELF files of type `ET_REL`; the linker (GNU `ld`, `gold`, `lld` or `mold`) writes "
            "`ET_EXEC` or `ET_DYN`. Inspect either with `readelf -a` and `nm`.",
        ],
        pe=[
            "Object files are COFF files (`.obj`): the PE file header and section table without the DOS and "
            "optional headers. The linker (`link.exe` or `lld-link`) writes a PE image. Inspect either with "
            "`dumpbin /headers`.",
        ],
        see=[
            see("The file type written by the linker",
                hfield(macho="filetype", elf="e_type", pe="FileHeader.Characteristics")),
        ],
        misconceptions=[
            wrong("The compiler produces the executable.",
                  "The compiler driver runs the compiler, the assembler and the linker. The executable is the linker's output."),
            wrong("An object file is a small executable.",
                  "It has no entry point and no addresses the system could map. Its code still contains holes for the linker to fill."),
            wrong("Linking glues files end to end.",
                  "The linker resolves names across files, merges sections, assigns addresses, patches every reference and generates new tables for the loader."),
        ],
        next=["object-files", "static-linking"],
    ),
    concept(
        id="object-files",
        title="What is inside an object file",
        level=2,
        summary="Sections of code and data, a table of names defined and needed, and a list of places the linker must patch.",
        body=[
            "A relocatable [[object-file|object file]] holds the result of compiling one source file. It has "
            "three kinds of content:",
            ul(
                "[[section|Sections]] of bytes: machine code, initialised data, read-only constants, and a "
                "description of zero-initialised data that takes no space in the file.",
                "A [[symbol-table|symbol table]]: the names this file defines (with the section and offset of "
                "each) and the names it uses but does not define ([[undefined-symbol|undefined symbols]]).",
                "[[relocation|Relocations]]: for every place in a section that depends on an address not yet "
                "known, a record saying where the place is, which symbol it refers to and how the address is to "
                "be encoded there.",
            ),
            "Nothing in an object file has a final address. Each section is laid out as if it started at address "
            "zero. Positions are expressed as section plus offset until the linker assigns real addresses.",
            note("The samples shipped with this tool are linked images, not object files. In a linked image the "
                 "per-section relocation fields described below are zero, because the linker has already "
                 "consumed them."),
        ],
        macho=[
            "An `MH_OBJECT` file has a single `LC_SEGMENT_64` with an empty name that holds every section. Each "
            "section header locates its relocation entries with `reloff` and `nreloc`. Symbols are in the table "
            "named by `LC_SYMTAB`.",
        ],
        elf=[
            "An `ET_REL` file has section headers and no program headers. Relocations for `.text` are in a "
            "section of their own, `.rela.text` (or `.rel.text`). Symbols are in `.symtab`, their names in "
            "`.strtab`.",
        ],
        pe=[
            "A COFF object has a file header, a section table and a COFF symbol table located by "
            "`PointerToSymbolTable` and `NumberOfSymbols`. Each section header locates its relocations with "
            "`PointerToRelocations` and `NumberOfRelocations`. Linked images normally have all four set to zero.",
        ],
        see=[
            see("A section header in this (linked) file",
                section(macho=["__text"], elf=[".text"], pe=[".text", ".rwxcode"], part="header")),
            see("The file type field: this is not an object file",
                hfield(macho="filetype", elf="e_type", pe="FileHeader.Characteristics")),
        ],
        misconceptions=[
            wrong("An object file has an entry point.",
                  "It may define a symbol called `main`, but which address starts the program is decided by the linker."),
            wrong("Addresses in an object file are just smaller versions of the final addresses.",
                  "They are offsets inside a section. Sections from different files are merged and moved, so the final address of anything is unknown until link time."),
        ],
        next=["sections-vs-segments", "symbols", "relocations"],
    ),
    concept(
        id="sections-vs-segments",
        title="Sections and segments",
        level=1,
        summary="Sections are the linker's units; segments are the loader's. A segment is a run of sections that share memory permissions.",
        body=[
            "A [[section]] is a named piece of content that the compiler emits and the linker manipulates: code, "
            "string constants, initialised data, a table of imported functions. There can be dozens.",
            "A [[segment]] is what the loader maps: one contiguous range of the file placed at one range of "
            "addresses with one set of [[page-permissions|permissions]]. There are usually three or four: "
            "readable and executable for code, read-only for constants, readable and writable for data.",
            "The two levels exist because memory protection works on whole [[page|pages]]. A page cannot be "
            "executable in its first half and writable in its second. The linker therefore sorts sections into "
            "groups with compatible permissions and emits each group as one page-aligned segment. The loader "
            "needs only the segments.",
        ],
        macho=[
            "Each `LC_SEGMENT_64` load command describes one segment and is followed directly by the headers of "
            "the sections inside it. Names are written as a pair: `__TEXT,__text`.",
            "The kernel and dyld map segments. A few sections still matter at run time, found by their type or "
            "name: initialiser lists, thread-local variable descriptors, Objective-C metadata. The `__LINKEDIT` "
            "segment has no sections; it holds the tables used by dyld and by tools (symbols, fixups, signature).",
        ],
        elf=[
            "ELF keeps two independent tables that describe the same bytes. [[program-header|Program headers]] "
            "describe segments and are all the kernel and the dynamic linker use. "
            "[[section-header|Section headers]] describe sections and are used by linkers, debuggers and tools.",
            "A program can run with its section header table removed. This tool shows each ELF section under the "
            "`PT_LOAD` segment that covers its bytes.",
        ],
        pe=[
            "PE has one table. Each `IMAGE_SECTION_HEADER` is mapped separately with its own permissions, so a PE "
            "section plays the role that a segment plays in the other two formats. The finer sections of the "
            "object files (`.text$mn`, `.rdata$r`, `.CRT$XCU`) are merged by the linker and leave no trace in "
            "the image.",
            "This tool shows each PE section as a segment containing one section of the same name, plus a "
            "pseudo-segment `HEADERS` for the header pages, which are also mapped.",
        ],
        differences="The Windows loader was designed around mapping sections of a file directly, so the section "
                    "is the mapped unit. ELF and Mach-O assume a linker that groups many sections per mapping.",
        see=[
            see("The segments of this file", view("segments")),
            see("The segment that holds the code", segment("exec", part="header")),
            see("A section inside it", section(macho=["__text"], elf=[".text"], pe=[".text", ".rwxcode"], part="header")),
        ],
        misconceptions=[
            wrong("An ELF program needs its sections to run.",
                  "The kernel and the dynamic linker read program headers only. Section headers can be stripped."),
            wrong(".text is the code segment.",
                  "`.text` is a section. In ELF it sits inside an executable `PT_LOAD` segment together with other read-only executable sections such as `.plt`."),
            wrong("Section names have meaning to the loader.",
                  "Mostly not. The Linux kernel, the ELF dynamic linker and the Windows loader for user-mode programs work from the tables and do not read section names. Mach-O tools and runtimes look some sections up by name, but mapping is by segment."),
        ],
        next=["virtual-memory", "symbols"],
        sources=["System V gABI, chapters 4 and 5", "<mach-o/loader.h>", "Microsoft PE/COFF specification, section table"],
    ),
    concept(
        id="symbols",
        title="Symbols and symbol tables",
        level=2,
        summary="A symbol is a name attached to a location. Symbol tables are how separately built pieces of code find each other.",
        body=[
            "A [[symbol]] is a name with a value, normally an address, and a few attributes: which section it is "
            "in, whether other files may refer to it (global) or not (local), whether it names a function or "
            "data, and whether it is *defined* here or only *referenced* here.",
            "Symbol tables have three readers. The [[linker]] matches each [[undefined-symbol|undefined symbol]] "
            "in one object file to a definition in another. The [[dynamic-linker|dynamic linker]] does the same "
            "between images at load time, using the names an image [[import|imports]] and [[export|exports]]. "
            "Debuggers and people use symbols to put names on addresses.",
            "Names are not stored inside the symbol entries. Each entry holds an offset into a "
            "[[string-table|string table]], a block of zero-terminated strings, so entries stay a fixed size.",
            "Only the names needed for dynamic linking are required at run time. Everything else can be removed "
            "from a shipped binary (see [[concept:stripping|Stripping]]).",
        ],
        macho=[
            "`LC_SYMTAB` locates an array of `nlist_64` entries (`n_strx`, `n_type`, `n_sect`, `n_desc`, "
            "`n_value`) and the string table. `LC_DYSYMTAB` records how that array is ordered: local symbols, "
            "then defined external symbols, then undefined symbols.",
            "Exported names are additionally stored in the [[export-trie|export trie]], which is what dyld "
            "searches. C names carry a leading underscore: the function `main` is the symbol `_main`.",
        ],
        elf=[
            "There can be two tables of `Elf64_Sym` entries. `.dynsym` holds the symbols needed for dynamic "
            "linking; it is part of a loaded segment and cannot be removed. `.symtab` holds everything, including "
            "local names, and exists for linking and debugging only.",
            "`st_info` packs the binding (local, global, weak) and the type (function, object); `st_shndx` is the "
            "section index, or `SHN_UNDEF` (0) for an undefined symbol.",
        ],
        pe=[
            "A PE image normally has no symbol table. Names survive in two places only: the export directory "
            "(functions this image offers) and the import tables (functions it needs). All other names live in "
            "a separate [[pdb|PDB]] file.",
            "The Symbols view for a PE file is assembled from imports, exports and the entry point. It is not a "
            "structure in the file.",
        ],
        differences="ELF and Mach-O descend from systems where the linker's symbol table was left in the "
                    "executable. Microsoft's toolchain moved symbols into a separate debug file early on.",
        see=[
            see("The symbols of this file", view("symtab")),
            see("An undefined symbol: a name this file needs from elsewhere", symbol("undefined")),
            see("Where the symbol table is located",
                lc(macho=["LC_SYMTAB"])  , ["macho"]),
            see("The dynamic symbol table section", section(elf=[".dynsym"], part="header"), ["elf"]),
            see("The import directory, where PE keeps imported names", lc(pe=["DATA_DIR_IMPORT_TABLE"]), ["pe"]),
        ],
        misconceptions=[
            wrong("A stripped binary has no symbols.",
                  "Stripping removes what the loader does not need. Imported and exported names must stay, or dynamic linking could not work."),
            wrong("A symbol's value is always an address.",
                  "For an undefined symbol it is normally zero. It can also be an absolute constant. For a common symbol it is the size in Mach-O and COFF, and the required alignment in ELF (the size is in `st_size`)."),
        ],
        next=["name-mangling", "relocations", "stripping"],
        sources=["<mach-o/nlist.h>", "System V gABI, chapter 4 (symbol table)", "Microsoft PE/COFF specification"],
    ),
    concept(
        id="name-mangling",
        title="Name mangling and decoration",
        level=2,
        summary="Linkers only compare strings, so languages with namespaces and overloading encode that information into the symbol name.",
        body=[
            "To a linker a symbol name is a flat string. C++ allows two functions with the same name and "
            "different parameters, and functions with the same name in different namespaces. To keep them "
            "apart at link time the compiler encodes the namespace, the name and the parameter types into one "
            "string. This is [[name-mangling|name mangling]].",
            "The encoding is defined by the platform's C++ ABI, not by the language standard:",
            table(
                ["Scheme", "Used by", "`foo::bar(int)` becomes"],
                [
                    ["Itanium C++ ABI", "GCC and Clang, on every system except MSVC-compatible Windows targets", "`_ZN3foo3barEi`"],
                    ["Microsoft", "MSVC and compatible compilers", "`?bar@foo@@YAXH@Z` (returning `void`)"],
                ],
            ),
            "In the Itanium scheme `_Z` starts a mangled name, `N...E` encloses a nested name, each component is "
            "prefixed by its length, and the parameter types follow as short codes (`i` int, `m` unsigned long, "
            "`PKh` pointer to const unsigned char). Swift and Rust use the same idea with their own encodings "
            "(Swift names start with `$s`; Rust's current scheme starts with `_R`).",
            "C is not mangled, but some platforms *decorate* C names. Mach-O prefixes every C symbol with an "
            "underscore. 32-bit Windows prefixes an underscore and, for `stdcall` functions, appends `@` and the "
            "size of the arguments (`_Func@8`). 64-bit Windows and ELF leave C names unchanged.",
            "Demangling turns the string back into a readable declaration. The Symbols view has a Demangle "
            "switch; on the command line the tools are `c++filt`, `swift demangle` and `undname`.",
        ],
        macho=[
            "Because of the extra underscore, an Itanium-mangled C++ symbol starts with two: "
            "`__Z14compute_cryptoPKhm` is `compute_crypto(unsigned char const*, unsigned long)`.",
        ],
        elf=[
            "Itanium names appear as specified, with one underscore: `_ZN3foo3barEi`. Versioned symbols add a "
            "suffix such as `@GLIBC_2.2.5`, which is symbol versioning, not mangling.",
        ],
        pe=[
            "MSVC names start with `?`. Exported functions are often declared `extern \"C\"` or listed in a "
            "module-definition file precisely to give them plain names.",
        ],
        see=[
            see("The symbols of this file (use the Demangle switch)", view("symtab")),
        ],
        misconceptions=[
            wrong("Mangled names are a form of obfuscation.",
                  "They are a documented, reversible encoding whose purpose is type-safe linking."),
            wrong("C++ defines how names are mangled.",
                  "The ABI of the platform does. Object files from compilers that follow different ABIs cannot be linked together."),
        ],
        next=["relocations", "static-linking"],
        sources=["Itanium C++ ABI, section 5.1 (mangling)"],
    ),
    concept(
        id="relocations",
        title="Relocations",
        level=2,
        summary="A relocation is an instruction to whoever knows the final addresses: write the address of that thing at this place.",
        body=[
            "Code and data refer to each other by address, and addresses are decided late. A [[relocation]] "
            "records one such pending reference. It says *where* a value must be written, *what* the value "
            "refers to (a symbol, or the image itself), and *how* to compute and encode it (a full 64-bit "
            "address, a 32-bit distance from the instruction, and so on). Some forms carry an [[addend]], a "
            "constant to add.",
            "Relocations are processed at two different times, by two different programs:",
            ul(
                "Link-time relocations live in object files. The static linker applies them when it assigns "
                "addresses, and most of them disappear.",
                "Load-time relocations stay in the linked image for the loader. They come in two kinds. A "
                "[[rebase]] (or relative relocation) marks a stored pointer into the image itself, which must "
                "be increased by the [[slide]] if the image is not loaded at the address it was linked for. A "
                "[[bind]] marks a slot that must receive the address of a symbol from another image.",
            ),
            "This tool uses the word [[fixup]] for a load-time relocation of either kind.",
        ],
        macho=[
            "Object files store 8-byte `relocation_info` entries per section. Linked images use one of two "
            "encodings in `__LINKEDIT`: streams of rebase and bind opcodes named by `LC_DYLD_INFO_ONLY`, or "
            "[[chained-fixups|chained fixups]] named by `LC_DYLD_CHAINED_FIXUPS`, where the pointer slots "
            "themselves hold the information.",
        ],
        elf=[
            "Entries are `Elf64_Rela` records (`r_offset`, `r_info`, `r_addend`); `r_info` combines a symbol "
            "index and a type such as `R_X86_64_RELATIVE` (a rebase), `R_X86_64_GLOB_DAT` or "
            "`R_X86_64_JUMP_SLOT` (binds). In an image they are in `.rela.dyn` and `.rela.plt`, which the "
            "dynamic linker finds through `DT_RELA` and `DT_JMPREL`. ELF32 on x86 uses `Elf32_Rel`, where the "
            "addend is stored at the place being relocated.",
        ],
        pe=[
            "A PE image has [[base-relocation|base relocations]] only, in the `.reloc` section named by data "
            "directory 5. They are grouped in blocks, one per 4 KiB page, of 16-bit entries: a 4-bit type "
            "(`IMAGE_REL_BASED_DIR64`, `IMAGE_REL_BASED_HIGHLOW`) and a 12-bit offset within the page. They "
            "are applied only when the image is not loaded at `ImageBase`.",
            "Imports are not relocations in PE. They are described by the import tables instead.",
        ],
        differences="ELF uses one generic record for both kinds and both stages. Mach-O replaced records with "
                    "compact encodings twice, to shrink them and to touch fewer pages at launch. PE needs "
                    "only rebasing in its relocation table because imports have their own structure.",
        see=[
            see("The load-time fixups of this file", view("dyld_info")),
            see("The first fixup location in the file", {"kind": "fixup"}),
            see("The command or table that locates them",
                lc(macho=["LC_DYLD_CHAINED_FIXUPS", "LC_DYLD_INFO_ONLY", "LC_DYLD_INFO"],
                   elf=["PT_DYNAMIC"], pe=["DATA_DIR_BASE_RELOCATION_TABLE"])),
        ],
        misconceptions=[
            wrong("Relocating moves code.",
                  "The code stays where it was mapped. Relocation patches the address values stored inside it or beside it."),
            wrong("A position-independent executable needs no relocations.",
                  "Its code avoids absolute addresses, but its data still contains pointers (tables of function pointers, pointers to strings) that must be rebased."),
            wrong("The PE .reloc table resolves imports.",
                  "It only adjusts pointers into the image itself. Imports are resolved through the import address table."),
        ],
        next=["static-linking", "got-plt", "dyld-fixups"],
        sources=["System V gABI chapter 4 and the x86-64 psABI (relocation types)", "<mach-o/reloc.h>, <mach-o/fixup-chains.h>",
                 "Microsoft PE/COFF specification, the .reloc section"],
    ),
    concept(
        id="static-linking",
        title="What the linker does",
        level=2,
        summary="Symbol resolution, layout, relocation, and the generation of the tables the loader will need.",
        body=[
            "The static [[linker]] turns a set of object files and libraries into one image. Its work has four "
            "parts:",
            ol(
                "Symbol resolution. Every undefined symbol must be matched to exactly one definition. Two "
                "global definitions of the same name are an error, unless one of them is [[weak-symbol|weak]]. "
                "A name with no definition is the familiar *undefined symbol* error, unless a shared library "
                "exports it, in which case it becomes an [[import]].",
                "Layout. Sections with the same name from all inputs are concatenated, the merged sections are "
                "grouped into [[segment|segments]] by permission, and everything gets an address.",
                "Relocation. With addresses known, the linker patches each reference recorded by a "
                "[[relocation]]. References that cannot be settled until load time are rewritten into "
                "load-time [[fixup|fixups]].",
                "Synthesis. The linker writes content no compiler produced: the file header, the segment "
                "tables, the [[got|GOT]] and the [[stub|stubs]] or [[plt|PLT]], the import and export tables, "
                "and the dynamic symbol table.",
            ),
            "A static library (`.a`, or `.lib`) is an [[archive]] of object files. The linker takes from it only "
            "the members that define a symbol that is still undefined, not the whole archive. Unreferenced "
            "sections can also be dropped (`--gc-sections`, `-dead_strip`, `/OPT:REF`).",
        ],
        macho=[
            "The Apple linker creates `__TEXT,__stubs`, `__DATA_CONST,__got` and the whole `__LINKEDIT` segment. "
            "It records the SDK and tool versions in `LC_BUILD_VERSION`, and on Apple silicon it adds an ad-hoc "
            "[[code-signature|code signature]].",
        ],
        elf=[
            "The assignment of sections to segments follows a linker script (a default one is built in). The "
            "linker creates `.plt`, `.got`, `.dynamic`, `.dynsym`, `.interp` and the hash tables.",
        ],
        pe=[
            "The linker merges COFF sections by the part of the name before `$` and orders them by the part "
            "after it. Imports come from *import libraries*: small `.lib` files that describe a DLL's exports "
            "and make the linker emit import table entries rather than code.",
        ],
        see=[
            see("Linker-generated commands and tables", view("load_commands")),
            see("The toolchain that built this file",
                lc(macho=["LC_BUILD_VERSION"], pe=["IMAGE_RICH_HEADER"]), ["macho", "pe"]),
        ],
        misconceptions=[
            wrong("A static library is linked in as a whole.",
                  "Only the archive members that satisfy an undefined symbol are pulled in."),
            wrong("The order of libraries on the command line never matters.",
                  "Traditional ELF linkers scan archives once, left to right, so a library must come after the objects that need it. The Apple and Microsoft linkers, and `lld`, are more forgiving."),
        ],
        next=["static-vs-dynamic", "got-plt"],
    ),
    concept(
        id="static-vs-dynamic",
        title="Static and dynamic linking",
        level=2,
        summary="Library code can be copied into the executable at link time, or left in a shared library that the loader connects at run time.",
        body=[
            "With *static* linking, the library's code is copied into the executable. The file is "
            "self-contained, and no name lookup happens when it starts.",
            "With *dynamic* linking, the executable records only the name of the "
            "[[shared-library|shared library]] and the symbols it needs. At launch the "
            "[[dynamic-linker|dynamic linker]] maps the library and fills in the addresses.",
            table(
                ["", "Static", "Dynamic"],
                [
                    ["Library code", "inside the executable", "in a separate file, shared between programs"],
                    ["Library update", "requires relinking", "takes effect at next launch"],
                    ["Start-up work", "none", "load libraries, apply fixups"],
                    ["Memory", "each program has its own copy", "read-only pages are shared between processes"],
                    ["Failure mode", "none at load time", "missing library or symbol at launch"],
                ],
            ),
            "How static a program can be depends on the system. On Linux the kernel's system call interface is "
            "stable, so a fully static executable is supported. On macOS and Windows it is not: the stable "
            "interface is the system libraries (`libSystem`, `ntdll.dll` and `kernel32.dll`), which must be "
            "linked dynamically even if everything else is static.",
        ],
        macho=[
            "A dynamically linked executable has an `LC_LOAD_DYLINKER` command and one `LC_LOAD_DYLIB` per "
            "library. A file with neither, starting from an `LC_UNIXTHREAD` register state, is statically "
            "linked; in practice that means the kernel, dyld itself, or firmware (the firmware sample here).",
        ],
        elf=[
            "A dynamically linked executable has a `PT_INTERP` program header naming its dynamic linker and a "
            "`PT_DYNAMIC` header locating the `.dynamic` table with its `DT_NEEDED` entries. A static executable "
            "has neither (the ELF32 sample here).",
        ],
        pe=[
            "Practically every PE image has an import directory, because even a program that links the C runtime "
            "statically (`/MT`) still imports operating system functions from DLLs.",
        ],
        see=[
            see("The command that names the dynamic linker",
                lc(macho=["LC_LOAD_DYLINKER"], elf=["PT_INTERP"]), ["macho", "elf"]),
            see("The record of a required library",
                lc(macho=["LC_LOAD_DYLIB"], elf=["PT_DYNAMIC"], pe=["DATA_DIR_IMPORT_TABLE"])),
            see("Libraries listed in the overview", view("overview")),
        ],
        misconceptions=[
            wrong("A static library is a kind of shared library.",
                  "A static library is an archive of object files consumed at link time. Nothing of it exists as a separate thing at run time."),
            wrong("Calls into shared libraries are slow.",
                  "After binding, a call costs one extra indirect jump. The measurable cost of dynamic linking is at start-up."),
        ],
        next=["shared-libraries", "got-plt"],
    ),
]
