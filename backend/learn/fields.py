"""
Field-level explanations: one entry per field of the main headers and structures
of Mach-O, ELF and PE.

Every entry has four plain-text parts (no markup):
  meaning   what the field holds
  reader    who reads it, and when
  if_wrong  what happens if the value is wrong or is changed
  peers     the corresponding field in the other formats ("None" where there is none)
plus `concept`, the id of the curriculum concept to read for background.

Keys are "<format>.<structure>.<field>", for example "elf.ehdr.e_entry". Fields
whose meaning depends on the command that contains them (Mach-O linkedit_data
commands, PE data directories) have one entry per command, with the command name
after an "@": "pe.data_directory.VirtualAddress@DATA_DIR_IMPORT_TABLE".

`key_for()` maps a field of a parsed document to its key.
"""

import re
from typing import Any, Dict, List, Optional

CATALOG: Dict[str, Dict[str, str]] = {}


def F(key: str, meaning: str, reader: str, if_wrong: str, peers: str, concept: str) -> None:
    fmt, struct, field = key.split(".", 2)
    CATALOG[key] = {
        "key": key, "format": fmt, "struct": struct, "field": field,
        "meaning": meaning, "reader": reader, "if_wrong": if_wrong, "peers": peers, "concept": concept,
    }


# Display names of the structures, in reference order.
STRUCTS: List[Dict[str, str]] = [
    {"id": "macho.fat_header", "title": "fat_header and fat_arch (universal file)"},
    {"id": "macho.mach_header", "title": "mach_header_64"},
    {"id": "macho.load_command", "title": "load_command (common prefix)"},
    {"id": "macho.segment_command", "title": "segment_command_64 (LC_SEGMENT_64)"},
    {"id": "macho.section", "title": "section_64"},
    {"id": "macho.symtab_command", "title": "symtab_command (LC_SYMTAB)"},
    {"id": "macho.dysymtab_command", "title": "dysymtab_command (LC_DYSYMTAB)"},
    {"id": "macho.dyld_info_command", "title": "dyld_info_command (LC_DYLD_INFO_ONLY)"},
    {"id": "macho.linkedit_data_command", "title": "linkedit_data_command"},
    {"id": "macho.chained_fixups_header", "title": "dyld_chained_fixups_header"},
    {"id": "macho.dylinker_command", "title": "dylinker_command (LC_LOAD_DYLINKER)"},
    {"id": "macho.dylib_command", "title": "dylib_command (LC_LOAD_DYLIB and relatives)"},
    {"id": "macho.rpath_command", "title": "rpath_command (LC_RPATH)"},
    {"id": "macho.entry_point_command", "title": "entry_point_command (LC_MAIN)"},
    {"id": "macho.thread_command", "title": "thread_command (LC_UNIXTHREAD)"},
    {"id": "macho.uuid_command", "title": "uuid_command (LC_UUID)"},
    {"id": "macho.build_version_command", "title": "build_version_command (LC_BUILD_VERSION)"},
    {"id": "macho.version_min_command", "title": "version_min_command (LC_VERSION_MIN_*)"},
    {"id": "macho.source_version_command", "title": "source_version_command (LC_SOURCE_VERSION)"},
    {"id": "macho.encryption_info_command", "title": "encryption_info_command_64"},
    {"id": "macho.fileset_entry_command", "title": "fileset_entry_command (LC_FILESET_ENTRY)"},
    {"id": "macho.superblob", "title": "Code signature SuperBlob"},
    {"id": "macho.code_directory", "title": "CodeDirectory"},
    {"id": "elf.ehdr", "title": "Elf64_Ehdr / Elf32_Ehdr (ELF header)"},
    {"id": "elf.phdr", "title": "Elf64_Phdr / Elf32_Phdr (program header)"},
    {"id": "elf.shdr", "title": "Elf64_Shdr / Elf32_Shdr (section header)"},
    {"id": "pe.dos_header", "title": "IMAGE_DOS_HEADER"},
    {"id": "pe.rich_header", "title": "Rich header"},
    {"id": "pe.nt", "title": "IMAGE_NT_HEADERS signature"},
    {"id": "pe.file_header", "title": "IMAGE_FILE_HEADER (COFF file header)"},
    {"id": "pe.optional_header", "title": "IMAGE_OPTIONAL_HEADER"},
    {"id": "pe.data_directory", "title": "IMAGE_DATA_DIRECTORY"},
    {"id": "pe.section_header", "title": "IMAGE_SECTION_HEADER"},
    {"id": "pe.win_certificate", "title": "WIN_CERTIFICATE"},
]

NONE = "None."

# =============================================================================
# Mach-O
# =============================================================================
F("macho.fat_header.magic",
  "0xcafebabe (FAT_MAGIC), or 0xcafebabf (FAT_MAGIC_64) for the variant with 64-bit offsets, which tools read but the kernel does not execute. Stored big-endian, so the bytes on disk are ca fe ba be.",
  "The kernel at exec, when the file is not a plain Mach-O (it accepts only 0xcafebabe); dyld and every tool that opens the file.",
  "The file is no longer recognised as a universal binary. With no other valid magic it is refused with 'exec format error'.",
  "ELF and PE have no multi-architecture container.",
  "endianness")
F("macho.fat_header.nfat_arch",
  "Number of fat_arch entries that follow, one per architecture. Big-endian.",
  "The kernel, to scan the entries for the best match for this machine.",
  "A smaller value hides the later slices. A larger value makes readers interpret whatever follows as slice descriptions; the kernel rejects entries that reach outside the file.",
  NONE,
  "file-formats-overview")
F("macho.fat_header.arch[].cputype",
  "CPU type of this slice, with the same values as the cputype field of a Mach-O header. Big-endian.",
  "The kernel, to choose a slice without reading each one.",
  "The slice is skipped, or chosen for the wrong machine and then refused when its own header disagrees.",
  "ELF e_machine and PE Machine identify the CPU of the single image.",
  "file-formats-overview")
F("macho.fat_header.arch[].cpusubtype",
  "CPU subtype of this slice (for example arm64e), including capability bits in the top byte. Big-endian.",
  "The kernel, to prefer the most specific slice the machine can run.",
  "A less suitable slice may be chosen, or none.",
  NONE,
  "file-formats-overview")
F("macho.fat_header.arch[].offset",
  "File offset at which this slice starts. Every offset inside the slice's own Mach-O structures counts from here. Big-endian.",
  "The kernel and dyld, to find the slice; this tool, to turn slice offsets into file offsets.",
  "The slice is read from the wrong place and fails header validation, or its code signature no longer matches.",
  NONE,
  "addresses")
F("macho.fat_header.arch[].size",
  "Size of this slice in bytes. Big-endian.",
  "The kernel, which checks every range in the slice against it.",
  "If too small, load commands or segments fall outside the slice and the file is rejected as malformed.",
  NONE,
  "file-formats-overview")
F("macho.fat_header.arch[].align",
  "Alignment of the slice's offset, as a power of two (14 means 16 KiB). Slices are page-aligned so that they can be mapped directly.",
  "The tools that build and thin universal files (lipo).",
  "Mostly informational to the loader; a slice whose offset is not page-aligned cannot be mapped.",
  NONE,
  "virtual-memory")

F("macho.mach_header.magic",
  "0xfeedfacf (MH_MAGIC_64) for a 64-bit file, 0xfeedface (MH_MAGIC) for 32-bit, read in the file's own byte order. A byte-swapped value means the file is in the other byte order.",
  "The kernel, as the first step of exec; dyld for every library; every tool.",
  "The kernel does not recognise the file as Mach-O. exec fails with 'exec format error' and a shell may then try to run the file as a script.",
  "ELF: e_ident[EI_MAG]. PE: e_magic ('MZ') and the 'PE\\0\\0' signature.",
  "structs-on-disk")
F("macho.mach_header.cputype",
  "The CPU architecture, for example CPU_TYPE_ARM64 (0x0100000c) or CPU_TYPE_X86_64 (0x01000007). Bit 24 marks a 64-bit ABI.",
  "The kernel at exec; dyld for each library.",
  "exec fails with 'bad CPU type in executable' if the machine cannot run that architecture natively or by translation.",
  "ELF: e_machine. PE: FileHeader.Machine.",
  "file-formats-overview")
F("macho.mach_header.cpusubtype",
  "A refinement of cputype. The low 24 bits select a variant (2 is arm64e); the top byte carries capability bits, such as the pointer-authentication ABI version on arm64e.",
  "The kernel, when choosing a slice and when deciding how to set up pointer authentication for the process.",
  "An arm64e file marked as plain arm64 is loaded without the pointer-authentication set-up its code and fixups assume, and may not run correctly.",
  "ELF: e_flags carries ABI variants. PE: none.",
  "cfi")
F("macho.mach_header.filetype",
  "What kind of Mach-O file this is: MH_EXECUTE (2), MH_DYLIB (6), MH_BUNDLE (8), MH_OBJECT (1), MH_DYLINKER (7), MH_DSYM (10), MH_PRELOAD (5) and others.",
  "The kernel, which starts only MH_EXECUTE files and loads MH_DYLINKER as the dynamic linker; dyld; the static linker.",
  "A dylib marked as an executable, or the reverse, is refused by whichever loader is handed it.",
  "ELF: e_type. PE: FileHeader.Characteristics (IMAGE_FILE_DLL).",
  "file-formats-overview")
F("macho.mach_header.ncmds",
  "Number of load commands that follow the header.",
  "The kernel and dyld, to walk the load commands.",
  "A smaller value hides the trailing commands from every reader. A larger one runs past the real commands; readers stop with an error when the sizes stop adding up.",
  "ELF: e_phnum. PE: NumberOfSections and NumberOfRvaAndSizes.",
  "structs-on-disk")
F("macho.mach_header.sizeofcmds",
  "Total size in bytes of all load commands.",
  "The kernel, which reads that many bytes after the header and checks that every command lies inside them.",
  "The kernel rejects the file as malformed if header plus load commands do not fit in the file, or if the commands do not add up to this size.",
  "ELF: e_phentsize times e_phnum. PE: SizeOfHeaders covers all headers.",
  "structs-on-disk")
F("macho.mach_header.flags",
  "Bit flags for the whole file. Common ones: MH_PIE (0x200000, load at a random address), MH_DYLDLINK (0x4, input to dyld), MH_TWOLEVEL (0x80, two-level namespace), MH_NOUNDEFS (0x1), MH_HAS_TLV_DESCRIPTORS (0x800000), MH_ALLOW_STACK_EXECUTION (0x20000).",
  "The kernel reads MH_PIE and the stack-execution flag at exec; dyld reads the linking flags.",
  "Clearing MH_PIE makes an x86-64 executable load at its linked address every time; an arm64 executable without it is refused. Other flags change how dyld binds symbols.",
  "ELF: e_type and DT_FLAGS_1. PE: Characteristics and DllCharacteristics.",
  "pic-pie")
F("macho.mach_header.reserved",
  "Padding that makes the 64-bit header 32 bytes long. Not used.",
  "Nobody.",
  "Nothing.",
  NONE,
  "structs-on-disk")

F("macho.load_command.cmd",
  "The type of this load command. Types that dyld must understand in order to run the file have the top bit (LC_REQ_DYLD, 0x80000000) set.",
  "The kernel acts on the types it knows (segments, entry point, dynamic linker, signature, UUID) and skips the rest. dyld and tools act on others.",
  "The command is interpreted as a different structure or skipped. dyld refuses a file with an unknown command that has the LC_REQ_DYLD bit.",
  "ELF: p_type of a program header, or d_tag of a dynamic entry. PE: the index of a data directory.",
  "structs-on-disk")
F("macho.load_command.cmdsize",
  "Size of this load command in bytes, including these two fields and any strings at the end. A multiple of 8 in 64-bit files.",
  "Every reader, to step to the next command.",
  "All following commands are read from the wrong place. The kernel rejects a command whose size is too small or runs past sizeofcmds.",
  "ELF: e_phentsize is one size for all entries. PE: structures have fixed sizes.",
  "structs-on-disk")

F("macho.segment_command.segname",
  "Name of the segment, up to 16 bytes, zero-padded: __TEXT, __DATA, __DATA_CONST, __LINKEDIT, __PAGEZERO.",
  "dyld and tools look some segments up by name (__TEXT, __LINKEDIT). The kernel maps by address, not by name.",
  "Tools and dyld that expect a standard name do not find the segment. Mapping is unaffected.",
  "ELF segments have no names. PE: section Name.",
  "sections-vs-segments")
F("macho.segment_command.vmaddr",
  "Virtual address at which the segment is to be mapped, before any slide.",
  "The kernel at exec for the main executable and dyld; dyld for libraries.",
  "The segment is mapped elsewhere than its code expects. Segments must be page-aligned, and dyld rejects address ranges that overlap or are out of order.",
  "ELF: p_vaddr. PE: ImageBase plus the section's VirtualAddress.",
  "addresses")
F("macho.segment_command.vmsize",
  "Size of the segment in memory. May exceed filesize; the rest is zero-filled.",
  "The kernel and dyld, to reserve the address range.",
  "Too small and part of the segment's contents is not mapped. dyld rejects a segment whose filesize exceeds its vmsize.",
  "ELF: p_memsz. PE: VirtualSize.",
  "virtual-memory")
F("macho.segment_command.fileoff",
  "Offset in the file (in the slice, for a universal file) of the first byte of the segment.",
  "The kernel and dyld, to map those bytes.",
  "Different bytes are mapped at the segment's address: the code or data is wrong and, for a signed file, the page hashes fail. The kernel rejects a file offset that is not page-aligned.",
  "ELF: p_offset. PE: PointerToRawData.",
  "addresses")
F("macho.segment_command.filesize",
  "Number of bytes of the file that belong to the segment.",
  "The kernel and dyld.",
  "The kernel rejects the file if fileoff plus filesize reaches beyond the end of the file.",
  "ELF: p_filesz. PE: SizeOfRawData.",
  "virtual-memory")
F("macho.segment_command.maxprot",
  "The most permissive protection the segment's pages may ever be given: read 1, write 2, execute 4.",
  "The kernel's virtual memory system, each time protection is changed.",
  "Raising it allows a later mprotect to make the pages writable or executable. On current systems the kernel also applies its own limits regardless of this field.",
  "ELF and PE have no stored maximum; the current protection can be changed subject to system policy.",
  "virtual-memory")
F("macho.segment_command.initprot",
  "The protection the segment's pages are mapped with: read 1, write 2, execute 4. __TEXT is 5 (r-x), __DATA is 3 (rw-).",
  "The kernel and dyld when mapping.",
  "A code segment without execute permission faults at the first instruction. Adding write permission to code removes the separation between writable and executable memory, where the system allows it at all.",
  "ELF: p_flags. PE: the MEM_ bits of section Characteristics.",
  "virtual-memory")
F("macho.segment_command.nsects",
  "Number of section headers that follow this command.",
  "dyld and tools. The kernel maps whole segments and looks at sections only in special cases.",
  "Section headers are skipped or misread; cmdsize must agree with it.",
  "ELF: e_shnum for the whole file. PE: NumberOfSections.",
  "sections-vs-segments")
F("macho.segment_command.flags",
  "Segment flags. SG_READ_ONLY (0x10) asks dyld to make the segment read-only after fixups (__DATA_CONST); SG_PROTECTED_VERSION_1 (0x8) marks an encrypted segment.",
  "dyld, for SG_READ_ONLY; the kernel, which notes the SG_READ_ONLY range and decrypts SG_PROTECTED_VERSION_1 segments.",
  "Without SG_READ_ONLY, __DATA_CONST stays writable for the life of the process.",
  "ELF: the PT_GNU_RELRO program header. PE: none.",
  "relro")

F("macho.section.sectname",
  "Name of the section, up to 16 bytes, zero-padded: __text, __stubs, __cstring, __got.",
  "The static linker, dyld and runtimes that look sections up by name; debuggers.",
  "Code that looks the section up by name does not find it.",
  "ELF: sh_name (an offset into a string table). PE: Name.",
  "sections-vs-segments")
F("macho.section.segname",
  "Name of the segment this section belongs to.",
  "The static linker, which uses it in object files to decide where a section goes.",
  "Tools show the section under a different segment. Mapping is unaffected.",
  NONE,
  "sections-vs-segments")
F("macho.section.addr",
  "Virtual address of the section, before any slide.",
  "dyld, runtimes and debuggers.",
  "Lookups by address resolve to the wrong section.",
  "ELF: sh_addr. PE: VirtualAddress.",
  "addresses")
F("macho.section.size",
  "Size of the section in bytes.",
  "dyld (for sections it walks, such as initialiser lists), runtimes and tools.",
  "A table section is read too short or too far.",
  "ELF: sh_size. PE: VirtualSize.",
  "sections-vs-segments")
F("macho.section.offset",
  "File offset of the section's contents. Zero for zero-fill sections, which have no contents in the file.",
  "The static linker and tools. At run time contents are reached through the mapped segment.",
  "Tools read the wrong bytes for the section.",
  "ELF: sh_offset. PE: PointerToRawData.",
  "addresses")
F("macho.section.align",
  "Alignment of the section as a power of two (4 means 16 bytes).",
  "The static linker.",
  "Matters when the file is linked again; no effect on a finished image.",
  "ELF: sh_addralign. PE: the alignment bits of Characteristics in object files.",
  "structs-on-disk")
F("macho.section.reloff",
  "File offset of the section's relocation entries. Used in object files; zero in linked images.",
  "The static linker.",
  "In an object file, the linker reads the wrong relocations.",
  "ELF: a separate .rela section. PE: PointerToRelocations.",
  "object-files")
F("macho.section.nreloc",
  "Number of relocation entries for the section. Zero in linked images.",
  "The static linker.",
  "In an object file, relocations are skipped or garbage is read as relocations.",
  "ELF: the size of the .rela section. PE: NumberOfRelocations.",
  "object-files")
F("macho.section.flags",
  "The low byte is the section type (0 regular, 1 zero-fill, 2 C strings, 6 non-lazy pointers, 7 lazy pointers, 8 stubs, 9 initialiser pointers). The upper bits are attributes such as S_ATTR_PURE_INSTRUCTIONS (0x80000000).",
  "The static linker and dyld, which finds stubs, pointer sections and initialiser lists by type.",
  "dyld treats the section as a different kind: initialisers are not run, or pointer slots are not found.",
  "ELF: sh_type and sh_flags. PE: Characteristics.",
  "sections-vs-segments")
F("macho.section.reserved1",
  "For stub and pointer sections, the index of the section's first entry in the indirect symbol table. Otherwise unused.",
  "dyld and tools, to match each stub or pointer slot with a symbol.",
  "Slots are matched with the wrong symbols.",
  NONE,
  "got-plt")
F("macho.section.reserved2",
  "For stub sections, the size in bytes of one stub. Otherwise unused.",
  "Tools, to divide the section into stubs.",
  "Stubs are split at the wrong boundaries.",
  "ELF: sh_entsize.",
  "got-plt")
F("macho.section.reserved3",
  "Unused padding in the 64-bit structure.",
  "Nobody.",
  "Nothing.",
  NONE,
  "structs-on-disk")

F("macho.symtab_command.symoff",
  "File offset of the symbol table: an array of nlist_64 entries in __LINKEDIT.",
  "dyld (for some lookups), debuggers, nm and other tools. Not needed to map or start the program.",
  "Symbols are read from the wrong place; tools show garbage names or none.",
  "ELF: sh_offset of .symtab, or DT_SYMTAB. PE: PointerToSymbolTable (normally zero in images).",
  "symbols")
F("macho.symtab_command.nsyms",
  "Number of entries in the symbol table.",
  "The same readers as symoff.",
  "Symbols are missing, or bytes after the table are read as symbols.",
  "ELF: sh_size divided by sh_entsize. PE: NumberOfSymbols.",
  "symbols")
F("macho.symtab_command.stroff",
  "File offset of the string table that holds the symbol names.",
  "The same readers as symoff.",
  "Every symbol gets a wrong name.",
  "ELF: .strtab / .dynstr, or DT_STRTAB.",
  "symbols")
F("macho.symtab_command.strsize",
  "Size of the string table in bytes.",
  "The same readers as symoff; careful readers refuse name offsets beyond it.",
  "Names near the end are cut off or rejected.",
  "ELF: sh_size of the string table, or DT_STRSZ.",
  "symbols")

F("macho.dysymtab_command.ilocalsym", "Index of the first local symbol in the symbol table.", "The static linker and tools.",
  "Symbols are reported in the wrong group.", "ELF: sh_info of .symtab is the index of the first non-local symbol.", "symbols")
F("macho.dysymtab_command.nlocalsym", "Number of local symbols.", "The static linker and tools.",
  "Symbols are reported in the wrong group.", "ELF: sh_info of .symtab.", "symbols")
F("macho.dysymtab_command.iextdefsym", "Index of the first externally visible symbol defined in this file.", "The static linker and tools.",
  "Symbols are reported in the wrong group.", NONE, "symbols")
F("macho.dysymtab_command.nextdefsym", "Number of externally visible defined symbols.", "The static linker and tools.",
  "Symbols are reported in the wrong group.", NONE, "symbols")
F("macho.dysymtab_command.iundefsym", "Index of the first undefined symbol: the names this file needs from other images.", "The static linker and tools.",
  "Imports are reported incorrectly.", "ELF: undefined symbols are marked individually with st_shndx 0.", "symbols")
F("macho.dysymtab_command.nundefsym", "Number of undefined symbols.", "The static linker and tools.",
  "Imports are reported incorrectly.", NONE, "symbols")
F("macho.dysymtab_command.indirectsymoff",
  "File offset of the indirect symbol table: 32-bit symbol indices, one per stub and pointer slot.",
  "dyld in older binaries (lazy binding), and tools.",
  "Stubs and pointer slots are matched with the wrong symbols.",
  "ELF: the symbol index inside each .rela.plt entry. PE: the import lookup table.",
  "got-plt")
F("macho.dysymtab_command.nindirectsyms", "Number of entries in the indirect symbol table.", "dyld in older binaries, and tools.",
  "Entries are missing or garbage is read.", NONE, "got-plt")

for _what, _name in (("rebase", "the rebase opcodes: which pointers to slide"),
                     ("bind", "the bind opcodes: which pointers receive the addresses of imported symbols at load"),
                     ("weak_bind", "the weak-bind opcodes: symbols that may be overridden across images"),
                     ("lazy_bind", "the lazy-bind opcodes: imports resolved on first call"),
                     ("export", "the export trie: the symbols this image offers")):
    F("macho.dyld_info_command.%s_off" % _what,
      "File offset, in __LINKEDIT, of %s. Zero if there are none." % _name,
      "dyld, at load time.",
      "dyld reads the wrong bytes as opcodes and aborts the launch, or pointers are left unadjusted and the program crashes later.",
      "ELF: DT_RELA and DT_JMPREL (relocations), .dynsym (exports). PE: the base relocation, import and export directories.",
      "dyld-fixups")
    F("macho.dyld_info_command.%s_size" % _what,
      "Size in bytes of %s." % _name.split(":")[0],
      "dyld, at load time.",
      "The stream is cut short or runs into the next one.",
      "ELF: DT_RELASZ, DT_PLTRELSZ. PE: the Size of the directory entry.",
      "dyld-fixups")

LINKEDIT_BLOBS = {
    "LC_DYLD_CHAINED_FIXUPS": ("the chained-fixups data: where each page's chain of pointers starts, and the table of imported symbols", "dyld, at load time", "dyld-fixups",
                               "dyld cannot apply fixups; the launch is aborted or pointers stay unfixed.",
                               "ELF: DT_RELA / DT_RELR. PE: the base relocation and import directories."),
    "LC_DYLD_EXPORTS_TRIE": ("the export trie: the symbols this image offers to others", "dyld, when another image binds to this one", "dyld-fixups",
                             "Other images cannot find this image's symbols.",
                             "ELF: .dynsym with its hash table. PE: the export directory."),
    "LC_FUNCTION_STARTS": ("the list of function start addresses, as ULEB128 distances", "debuggers and analysis tools", "stripping",
                           "Tools place function boundaries wrongly. Execution is unaffected.",
                           "ELF: none (symbols or unwind tables are used). PE: the exception directory lists functions on x64."),
    "LC_DATA_IN_CODE": ("the table of data ranges inside code sections", "disassemblers and the linker", "reading-disassembly",
                        "Disassemblers decode data as instructions. Execution is unaffected.",
                        "None."),
    "LC_CODE_SIGNATURE": ("the code signature SuperBlob", "the kernel at exec and whenever a page is brought in; the system's signature policy", "code-signing",
                          "The signature is not found or does not validate. On systems that enforce signing the process is killed.",
                          "PE: the certificate table data directory. ELF: none."),
    "LC_SEGMENT_SPLIT_INFO": ("information used to split segments when the image is placed in the shared cache", "the shared cache builder", "shared-libraries",
                              "Only matters when building a shared cache.", "None."),
    "LC_DYLIB_CODE_SIGN_DRS": ("code signing requirements of linked libraries", "the linker and signing tools", "code-signing",
                               "Only matters to signing tools.", "None."),
    "LC_LINKER_OPTIMIZATION_HINT": ("hints for the linker about instruction sequences it may simplify (object files)", "the static linker", "static-linking",
                                    "Only matters when linking.", "None."),
}
for _cmd, (_what, _who, _concept, _wrong, _peers) in LINKEDIT_BLOBS.items():
    F("macho.linkedit_data_command.dataoff@" + _cmd,
      "File offset, in __LINKEDIT, of " + _what + ".", _who[0].upper() + _who[1:] + ".", _wrong, _peers, _concept)
    F("macho.linkedit_data_command.datasize@" + _cmd,
      "Size in bytes of " + _what.split(":")[0] + ".", _who[0].upper() + _who[1:] + ".",
      "The data is cut short or bytes beyond it are read.", _peers, _concept)
F("macho.linkedit_data_command.dataoff", "File offset, in __LINKEDIT, of this command's data.", "The tool or loader that understands this command.",
  "The data is read from the wrong place.", NONE, "structs-on-disk")
F("macho.linkedit_data_command.datasize", "Size in bytes of this command's data.", "The tool or loader that understands this command.",
  "The data is cut short or bytes beyond it are read.", NONE, "structs-on-disk")

F("macho.chained_fixups_header.fixups_version", "Version of the chained-fixups format; currently 0.", "dyld.",
  "dyld refuses a version it does not know.", NONE, "dyld-fixups")
F("macho.chained_fixups_header.starts_offset",
  "Offset, from the start of this header, of the table that says for each segment and page where the first fixup is.",
  "dyld (and the kernel, when it applies fixups as pages are brought in).",
  "Chains are started at the wrong places; pointers are corrupted or left unfixed.", "ELF: DT_RELA. PE: the base relocation directory.", "dyld-fixups")
F("macho.chained_fixups_header.imports_offset", "Offset, from the start of this header, of the imports table: one entry per imported symbol.", "dyld.",
  "Binds refer to the wrong symbols.", "ELF: .dynsym. PE: the import lookup tables.", "dyld-fixups")
F("macho.chained_fixups_header.symbols_offset", "Offset, from the start of this header, of the strings holding the imported symbol names.", "dyld.",
  "Imports get wrong names and fail to resolve.", "ELF: .dynstr. PE: the hint/name table.", "dyld-fixups")
F("macho.chained_fixups_header.imports_count", "Number of entries in the imports table.", "dyld.",
  "Bind ordinals beyond the count are rejected; a larger count reads garbage.", NONE, "dyld-fixups")
F("macho.chained_fixups_header.imports_format",
  "Layout of each imports entry: 1 (DYLD_CHAINED_IMPORT, 4 bytes), 2 (with addend), 3 (with 64-bit addend).", "dyld.",
  "Entries are decoded with the wrong layout.", NONE, "dyld-fixups")
F("macho.chained_fixups_header.symbols_format", "0 if the symbol strings are stored as they are, 1 if they are zlib-compressed.", "dyld.",
  "Names are unreadable.", NONE, "dyld-fixups")

F("macho.dylinker_command.name.offset", "Offset, from the start of this load command, of the path string.", "The kernel.",
  "The kernel reads the path from the wrong place and cannot load the dynamic linker.", "ELF: p_offset of PT_INTERP.", "process-startup-macos")
F("macho.dylinker_command.name",
  "Path of the dynamic linker the kernel must load to run this file, normally /usr/lib/dyld.",
  "The kernel at exec.",
  "exec fails. Release kernels accept no path other than /usr/lib/dyld and reject the file as malformed.",
  "ELF: the PT_INTERP string. PE: none; the loader is always the one in ntdll.dll.",
  "process-startup-macos")

F("macho.dylib_command.name.offset", "Offset, from the start of this load command, of the library path string.", "dyld.",
  "dyld reads the wrong path.", NONE, "shared-libraries")
F("macho.dylib_command.name",
  "The library's install name: the path dyld uses to find it, possibly beginning with @rpath, @executable_path or @loader_path.",
  "dyld, at load time; for LC_ID_DYLIB, the static linker, which copies it into images that link against the library.",
  "The launch is aborted with 'Library not loaded' unless the command is a weak one.",
  "ELF: a DT_NEEDED entry. PE: the Name of an import descriptor.",
  "shared-libraries")
F("macho.dylib_command.timestamp", "A build timestamp of the library. A leftover of an older binding scheme; current linkers write a small constant.", "Nobody on current systems.",
  "Nothing.", "PE: TimeDateStamp of an import descriptor, a similar leftover.", "shared-libraries")
F("macho.dylib_command.current_version",
  "Version of the library that this image was linked against, packed as major.minor.patch (16.8.8 bits).",
  "Tools; code that checks library versions at run time.",
  "Version queries report the wrong value. Loading is unaffected.",
  "ELF: symbol versions. PE: none.",
  "shared-libraries")
F("macho.dylib_command.compatibility_version",
  "The oldest library version this image can run with, in the same packing.",
  "The static linker, which copies it from the library. Older versions of dyld compared it with the compatibility version of the library they found; current dyld does not.",
  "Under an older dyld, a value higher than the installed library provides makes the launch fail with 'Incompatible library version'. On current macOS nothing happens.",
  "ELF: the version in the SONAME (libc.so.6).",
  "shared-libraries")

F("macho.rpath_command.path.offset", "Offset, from the start of this load command, of the path string.", "dyld.",
  "dyld reads the wrong string.", NONE, "shared-libraries")
F("macho.rpath_command.path", "A directory to try in place of @rpath when resolving library install names.", "dyld, at load time.",
  "Libraries named with @rpath are not found.", "ELF: DT_RUNPATH. PE: none; the search order is fixed by the system.", "shared-libraries")

F("macho.entry_point_command.entryoff",
  "Offset of main from the start of the Mach-O file (the start of the __TEXT segment). A file offset, not an address.",
  "The kernel records it; dyld adds the load address of the image and calls the result.",
  "Execution starts at a different instruction, usually crashing at once.",
  "ELF: e_entry (an address). PE: AddressOfEntryPoint (an RVA).",
  "process-startup-macos")
F("macho.entry_point_command.stacksize", "Size of the main thread's stack if not zero; zero means the system default.", "The kernel at exec.",
  "A very small value makes the program overflow its stack early.", "PE: SizeOfStackReserve. ELF: none in the file.", "stack-and-frames")

F("macho.thread_command.flavor", "Which register set follows; the values are specific to each CPU (6 is ARM_THREAD_STATE64, 4 is x86_THREAD_STATE64).", "The kernel, or the boot loader for firmware.",
  "The register values are interpreted with the wrong layout.", NONE, "process-startup-macos")
F("macho.thread_command.count", "Size of the register set in 32-bit words.", "The kernel, or the boot loader.",
  "The register set is rejected or read short.", NONE, "process-startup-macos")
F("macho.thread_command.pc", "Initial program counter: the address of the first instruction to execute.", "The kernel, or the boot loader.",
  "Execution starts elsewhere.", "ELF: e_entry. PE: AddressOfEntryPoint. Mach-O LC_MAIN: entryoff.", "process-startup-macos")
F("macho.thread_command.sp", "Initial stack pointer. Usually zero, meaning the loader provides a stack.", "The kernel, or the boot loader.",
  "The program starts with an unusable stack.", NONE, "stack-and-frames")
F("macho.thread_command.lr (x30)", "Initial value of the link register (x30).", "The kernel, or the boot loader.",
  "Normally zero; a return from the entry function would jump to this address.", NONE, "stack-and-frames")
F("macho.thread_command.fp (x29)", "Initial value of the frame pointer (x29). Zero marks the outermost frame for stack walkers.", "The kernel, or the boot loader.",
  "Stack walkers do not stop at the entry frame.", NONE, "stack-and-frames")
F("macho.thread_command.cpsr", "Initial processor status flags.", "The kernel, or the boot loader.",
  "The program starts in an unexpected processor state.", NONE, "process-startup-macos")
F("macho.thread_command.register", "Initial value of a general-purpose register.", "The kernel, or the boot loader.",
  "The entry code receives a different value in that register.", NONE, "process-startup-macos")

F("macho.uuid_command.uuid",
  "A 128-bit identifier of this build, normally derived by the linker from the contents of the file.",
  "Debuggers and crash reporters, to find the matching dSYM; the kernel copies it into crash information.",
  "Debug information and crash logs are no longer matched with this binary. Execution is unaffected.",
  "ELF: the NT_GNU_BUILD_ID note. PE: the GUID and age in the CodeView debug entry.",
  "debug-info")

F("macho.build_version_command.platform", "The platform the file was built for: 1 macOS, 2 iOS, 3 tvOS, 4 watchOS, 6 Mac Catalyst, 7 iOS simulator and others.", "dyld, which refuses a program built for a platform the process cannot run; the kernel, which records the platform and applies policy by it.",
  "The file is refused as built for a different platform.", "ELF: e_ident[EI_OSABI] and the ABI tag note. PE: Subsystem.", "static-linking")
F("macho.build_version_command.minos", "Minimum OS version, packed as major.minor.patch (16.8.8 bits).", "dyld and system frameworks, which adapt behaviour to the version a program was built for. dyld does not refuse a program only because the value is newer than the running system.",
  "Frameworks and dyld choose different compatibility behaviour. A program built for a newer system fails only when a library or symbol it needs is missing; dyld then mentions the version in its error.", "PE: MajorOperatingSystemVersion and MajorSubsystemVersion. ELF: the ABI tag note.", "static-linking")
F("macho.build_version_command.sdk", "Version of the SDK the file was built with, in the same packing.", "System frameworks, which keep old behaviour for programs built with an old SDK.",
  "Frameworks choose different compatibility behaviour.", NONE, "static-linking")
F("macho.build_version_command.ntools", "Number of tool-version entries that follow.", "Tools.",
  "Tool entries are skipped or misread.", NONE, "static-linking")
F("macho.build_version_command.tools[].tool", "A build tool: 1 clang, 2 swift, 3 ld.", "Tools; useful for attributing a binary to a toolchain.",
  "Informational only.", "PE: the Rich header. ELF: the .comment section.", "static-linking")
F("macho.build_version_command.tools[].version", "Version of that tool, packed as major.minor.patch.", "Tools.",
  "Informational only.", "PE: the Rich header.", "static-linking")

F("macho.version_min_command.version", "Minimum OS version, packed as major.minor.patch. The older form of LC_BUILD_VERSION.", "dyld and system frameworks.",
  "Frameworks and dyld choose different compatibility behaviour. The value by itself does not stop a program from starting on an older system.", "PE: MajorOperatingSystemVersion.", "static-linking")
F("macho.version_min_command.sdk", "SDK version the file was built with.", "System frameworks.",
  "Frameworks choose different compatibility behaviour.", NONE, "static-linking")
F("macho.source_version_command.version", "Version of the source the binary was built from, packed as A.B.C.D.E (24.10.10.10.10 bits).", "Tools; informational.",
  "Informational only.", "PE: MajorImageVersion and MinorImageVersion.", "static-linking")

F("macho.encryption_info_command.cryptoff", "File offset of the encrypted range.", "The kernel, which decrypts those pages as they are loaded.",
  "The wrong range is treated as encrypted.", NONE, "entropy-packing")
F("macho.encryption_info_command.cryptsize", "Size of the encrypted range in bytes.", "The kernel.",
  "The wrong range is treated as encrypted.", NONE, "entropy-packing")
F("macho.encryption_info_command.cryptid", "Zero if the range is not encrypted; non-zero identifies the encryption system in use.", "The kernel and dyld.",
  "Setting it to zero on a file that is still encrypted makes the system run the encrypted bytes as code.", NONE, "entropy-packing")

F("macho.fileset_entry_command.vmaddr", "Virtual address of the embedded Mach-O image.", "The loader of the fileset (a boot loader or the kernel).",
  "The embedded image is looked for at the wrong address.", NONE, "file-formats-overview")
F("macho.fileset_entry_command.fileoff", "File offset of the embedded Mach-O image.", "The loader of the fileset.",
  "The embedded image is read from the wrong place.", NONE, "file-formats-overview")
F("macho.fileset_entry_command.entry_id", "Name of the embedded image.", "The loader of the fileset and tools.",
  "The image is not found by name.", NONE, "file-formats-overview")

F("macho.superblob.magic", "0xfade0cc0, the magic of an embedded signature SuperBlob. Big-endian, like every integer in the signature.", "The kernel when it loads the signature; codesign and other tools.",
  "The signature is not recognised and the file counts as unsigned.", "PE: wRevision and wCertificateType of WIN_CERTIFICATE.", "code-signing")
F("macho.superblob.length", "Total length of the SuperBlob in bytes.", "The kernel and tools.",
  "The signature is rejected as malformed.", "PE: dwLength.", "code-signing")
F("macho.superblob.count", "Number of blobs indexed by the SuperBlob.", "The kernel and tools.",
  "Blobs are missed, or garbage is read as index entries.", NONE, "code-signing")
F("macho.superblob.index[].type", "Slot of this blob: 0 CodeDirectory, 2 requirements, 5 entitlements, 7 DER entitlements, 0x1000 and up alternate CodeDirectories, 0x10000 the CMS signature.", "The kernel and tools.",
  "A blob is taken for another kind and fails validation.", NONE, "code-signing")
F("macho.superblob.index[].offset", "Offset of the blob from the start of the SuperBlob.", "The kernel and tools.",
  "The blob is read from the wrong place and fails validation.", NONE, "code-signing")

F("macho.code_directory.magic", "0xfade0c02, the magic of a CodeDirectory.", "The kernel and tools.", "The blob is not accepted as a CodeDirectory.", NONE, "code-signing")
F("macho.code_directory.length", "Length of the CodeDirectory in bytes. The cdhash is computed over exactly these bytes.", "The kernel and tools.", "The cdhash changes and the signature no longer matches.", NONE, "code-signing")
F("macho.code_directory.version", "Format version; newer versions add fields at the end (0x20400 added the executable-segment fields).", "The kernel and tools.", "Fields are read that are not present, or ignored though present.", NONE, "code-signing")
F("macho.code_directory.flags", "Signature flags: 0x2 ad-hoc, 0x10000 hardened runtime, 0x20000 linker-signed, 0x2000 library validation and others.", "The kernel and the signing policy, when the process starts.", "Because the CodeDirectory is itself hashed and signed, any change invalidates the signature.", "PE: DllCharacteristics carries FORCE_INTEGRITY.", "code-signing")
F("macho.code_directory.hashOffset", "Offset, from the start of the CodeDirectory, of the hash of page 0. Special-slot hashes are stored before it.", "The kernel, when checking a page.", "Pages are compared with the wrong hashes and fail.", NONE, "code-signing")
F("macho.code_directory.identOffset", "Offset of the signing identifier string.", "The kernel and policy.", "The program is identified under a different name.", NONE, "code-signing")
F("macho.code_directory.nSpecialSlots", "Number of special-slot hashes (Info.plist, requirements, resources, entitlements and so on).", "The kernel and tools.", "The other parts of the signature are no longer bound to the CodeDirectory.", NONE, "code-signing")
F("macho.code_directory.nCodeSlots", "Number of page hashes.", "The kernel.", "Pages beyond the count have no hash and cannot be validated.", NONE, "code-signing")
F("macho.code_directory.codeLimit", "File offset where the hashed range ends: the start of the signature.", "The kernel and tools.", "Bytes beyond it are not covered by any hash.", NONE, "code-signing")
F("macho.code_directory.hashSize", "Size of each hash in bytes: 20 for SHA-1, 32 for SHA-256.", "The kernel.", "Hash slots are read at the wrong positions.", NONE, "code-signing")
F("macho.code_directory.hashType", "Hash algorithm: 1 SHA-1, 2 SHA-256, 3 SHA-256 truncated to 20 bytes, 4 SHA-384.", "The kernel.", "Pages are hashed with a different algorithm and do not match.", NONE, "code-signing")
F("macho.code_directory.platform", "Non-zero for platform binaries, which are part of the operating system.", "The kernel and policy.", "Only honoured for signatures the system trusts as its own.", NONE, "code-signing")
F("macho.code_directory.pageSize", "Size of the hashed pages as a power of two; 12 means 4096 bytes. It need not equal the CPU's page size.", "The kernel.", "The file is divided into pages differently and no hash matches.", NONE, "code-signing")
F("macho.code_directory.scatterOffset", "Offset of an optional scatter table; zero if there is none.", "The kernel.", "Normally zero.", NONE, "code-signing")
F("macho.code_directory.teamOffset", "Offset of the team identifier string; zero if there is none.", "The signing policy, for example library validation.", "The program is attributed to a different team, or to none.", NONE, "code-signing")
F("macho.code_directory.execSegBase", "File offset of the executable segment.", "The kernel.", "The executable segment's properties are applied to the wrong range.", NONE, "code-signing")
F("macho.code_directory.execSegLimit", "Size of the executable segment.", "The kernel.", "The executable segment's properties are applied to the wrong range.", NONE, "code-signing")
F("macho.code_directory.execSegFlags", "Flags for the executable segment; bit 0 marks a main binary, others record entitlements that affect how it is mapped.", "The kernel.", "The kernel treats the main binary differently.", NONE, "code-signing")

# =============================================================================
# ELF
# =============================================================================
F("elf.ehdr.e_ident[EI_MAG]",
  "The four bytes 7f 45 4c 46: 0x7f followed by 'ELF'.",
  "The kernel's ELF handler at exec; the dynamic linker for every library; every tool.",
  "The kernel does not recognise the file. execve fails with ENOEXEC, and a shell may then try to run the file as a script.",
  "Mach-O: magic. PE: e_magic and the PE signature.",
  "structs-on-disk")
F("elf.ehdr.e_ident[EI_CLASS]",
  "1 for ELF32, 2 for ELF64. It selects the layout of the rest of the header and of every other structure.",
  "Tools, and the dynamic linker for each object it opens. On x86-64 and AArch64 the Linux kernel does not read it: its 64-bit and 32-bit ELF handlers each assume their own layout and check e_machine. Some other architectures do check it.",
  "Tools read all later fields at the wrong offsets and sizes, and glibc refuses the file as a library. Where the kernel does not look at the byte, execve is unaffected.",
  "Mach-O: the two magics. PE: OptionalHeader.Magic.",
  "file-formats-overview")
F("elf.ehdr.e_ident[EI_DATA]",
  "Byte order of the file's multi-byte fields: 1 little-endian, 2 big-endian.",
  "Tools, and the dynamic linker for each object it opens. On x86-64 and AArch64 the Linux kernel does not read it and assumes the byte order it was built for.",
  "Tools byte-swap every number and report nonsense, and glibc refuses the file as a library. Where the kernel does not look at the byte, execve is unaffected.",
  "Mach-O: implied by which form of the magic is found. PE: always little-endian.",
  "endianness")
F("elf.ehdr.e_ident[EI_VERSION]", "ELF identification version; always 1.", "Strict readers check it, among them glibc for each object it opens.",
  "Some tools reject the file, and glibc refuses it as a library. The Linux kernel does not check it.", NONE, "structs-on-disk")
F("elf.ehdr.e_ident[EI_OSABI]",
  "Operating system ABI the file targets: 0 System V (also used by most Linux binaries), 3 GNU/Linux, 9 FreeBSD and others.",
  "The dynamic linker and tools. The Linux kernel does not check it.",
  "Some dynamic linkers and tools refuse or misidentify the file.",
  "Mach-O: the platform in LC_BUILD_VERSION. PE: Subsystem.",
  "file-formats-overview")
F("elf.ehdr.e_ident[EI_ABIVERSION]", "Version of the ABI named by EI_OSABI; normally 0.", "The dynamic linker.",
  "A dynamic linker may refuse a value it does not support.", NONE, "file-formats-overview")
F("elf.ehdr.e_type",
  "Kind of file: 1 ET_REL (object file), 2 ET_EXEC (executable at a fixed address), 3 ET_DYN (shared library or position-independent executable), 4 ET_CORE.",
  "The kernel at exec, which accepts ET_EXEC and ET_DYN and chooses a load address for ET_DYN.",
  "An ET_DYN file changed to ET_EXEC is mapped at its literal addresses near zero, which the system normally refuses, so it does not run.",
  "Mach-O: filetype and MH_PIE. PE: Characteristics and DYNAMIC_BASE.",
  "pic-pie")
F("elf.ehdr.e_machine",
  "CPU architecture: 3 EM_386, 62 EM_X86_64, 183 EM_AARCH64, 40 EM_ARM, 243 EM_RISCV.",
  "The kernel at exec; the dynamic linker for libraries.",
  "execve fails with ENOEXEC unless a handler for foreign binaries is registered.",
  "Mach-O: cputype. PE: FileHeader.Machine.",
  "file-formats-overview")
F("elf.ehdr.e_version", "ELF version; always 1.", "Strict readers check it, among them glibc for each object it opens.", "Some tools reject the file, and glibc refuses it as a library. The Linux kernel does not check it.", NONE, "structs-on-disk")
F("elf.ehdr.e_entry",
  "Virtual address of the first instruction of the program, normally _start. In an ET_DYN file it is relative to the load base.",
  "The kernel. For a static executable it starts there; for a dynamic one it passes the address to the dynamic linker (AT_ENTRY), which jumps to it when it has finished.",
  "Execution starts at a different instruction. If that is not mapped executable memory, the program dies with a segmentation fault.",
  "Mach-O: LC_MAIN entryoff. PE: AddressOfEntryPoint.",
  "process-startup-linux")
F("elf.ehdr.e_phoff",
  "File offset of the program header table.",
  "The kernel at exec; the dynamic linker.",
  "The kernel reads garbage as program headers and refuses the file or maps nonsense.",
  "Mach-O: load commands follow the header directly. PE: the section table follows the optional header.",
  "structs-on-disk")
F("elf.ehdr.e_shoff",
  "File offset of the section header table; zero if there is none.",
  "Linkers, debuggers and tools. Not used to run the program.",
  "Tools see no sections or garbage. The program still runs.",
  "Mach-O: section headers are inside segment commands. PE: the section table, which is required.",
  "sections-vs-segments")
F("elf.ehdr.e_flags", "Processor-specific flags. Zero on x86 and x86-64; on ARM, MIPS and RISC-V they record ABI variants such as the floating-point convention.", "The kernel and the dynamic linker on those architectures.",
  "On architectures that use it, a mismatch makes the loader refuse the file.", "Mach-O: cpusubtype.", "calling-conventions")
F("elf.ehdr.e_ehsize", "Size of this header: 64 for ELF64, 52 for ELF32.", "Strict readers check it.", "Some tools reject the file.", "PE: SizeOfOptionalHeader. Mach-O: fixed by the magic.", "structs-on-disk")
F("elf.ehdr.e_phentsize", "Size of one program header: 56 for ELF64, 32 for ELF32.", "The kernel, which refuses any other value.", "execve fails with ENOEXEC.", "Mach-O: cmdsize of each command.", "structs-on-disk")
F("elf.ehdr.e_phnum", "Number of program headers.", "The kernel at exec; the dynamic linker.",
  "Segments are missed, or bytes after the table are read as program headers.", "Mach-O: ncmds. PE: NumberOfSections.", "structs-on-disk")
F("elf.ehdr.e_shentsize", "Size of one section header: 64 for ELF64, 40 for ELF32.", "Linkers and tools.", "Tools misread the section table.", NONE, "structs-on-disk")
F("elf.ehdr.e_shnum", "Number of section headers; zero if there is no table.", "Linkers and tools.", "Tools see too few sections or read garbage. The program still runs.", "Mach-O: nsects per segment. PE: NumberOfSections.", "sections-vs-segments")
F("elf.ehdr.e_shstrndx", "Index of the section that holds the section names (.shstrtab).", "Linkers and tools.", "Tools show wrong or no section names.", "Mach-O and PE store section names inside the section headers.", "sections-vs-segments")

F("elf.phdr.p_type",
  "What this entry describes: 1 PT_LOAD (map this), 2 PT_DYNAMIC, 3 PT_INTERP, 4 PT_NOTE, 6 PT_PHDR, 7 PT_TLS, and GNU types such as PT_GNU_STACK, PT_GNU_RELRO, PT_GNU_EH_FRAME, PT_GNU_PROPERTY.",
  "The Linux kernel acts on PT_LOAD, PT_INTERP and PT_GNU_STACK, and on AArch64 also PT_GNU_PROPERTY; the dynamic linker on PT_DYNAMIC, PT_TLS and PT_GNU_RELRO, and on PT_LOAD for libraries.",
  "The entry is ignored or treated as something else. Turning PT_GNU_RELRO into PT_NULL, for example, leaves the GOT writable.",
  "Mach-O: the cmd of a load command. PE: the index of a data directory.",
  "sections-vs-segments")
F("elf.phdr.p_flags",
  "Permissions: 1 PF_X (execute), 2 PF_W (write), 4 PF_R (read). For PT_GNU_STACK they describe the stack.",
  "The kernel when mapping PT_LOAD segments and when creating the stack.",
  "A code segment without PF_X faults at once. PF_X on PT_GNU_STACK makes the stack executable.",
  "Mach-O: initprot. PE: the MEM_ bits of section Characteristics.",
  "virtual-memory")
F("elf.phdr.p_offset", "File offset of the first byte of the segment.", "The kernel and the dynamic linker.",
  "Different bytes are mapped at the segment's address. An offset that does not agree with p_vaddr modulo the page size makes mapping fail.", "Mach-O: fileoff. PE: PointerToRawData.", "addresses")
F("elf.phdr.p_vaddr", "Virtual address of the segment. Relative to the load base in an ET_DYN file.", "The kernel and the dynamic linker.",
  "The segment is mapped where its code does not expect it.", "Mach-O: vmaddr. PE: VirtualAddress.", "addresses")
F("elf.phdr.p_paddr", "Physical address, for systems without virtual memory. Ignored by Linux for user programs; linkers set it equal to p_vaddr. Boot loaders and firmware tools do use it.", "Boot loaders and firmware tools.",
  "No effect on a normal program.", NONE, "addresses")
F("elf.phdr.p_filesz", "Number of bytes of the file in the segment.", "The kernel and the dynamic linker.",
  "Too little of the file is mapped, or the mapping reaches past the end of the file.", "Mach-O: filesize. PE: SizeOfRawData.", "virtual-memory")
F("elf.phdr.p_memsz", "Size of the segment in memory. The part beyond p_filesz is zero-filled (.bss).", "The kernel and the dynamic linker.",
  "Zero-initialised variables have no memory, or the segment overlaps the next one.", "Mach-O: vmsize. PE: VirtualSize.", "virtual-memory")
F("elf.phdr.p_align", "Alignment of the segment. For PT_LOAD, the largest page size the file was linked for; p_vaddr and p_offset must be equal modulo this value.", "The kernel, when choosing the load address of an ET_DYN file; the dynamic linker.",
  "A larger power of two makes the loader align the base address more strictly. Linux and current glibc require p_vaddr and p_offset to agree only modulo the system page size; glibc before 2.35 also refused a library in which they disagreed modulo p_align.", "PE: SectionAlignment. Mach-O: implied by the page-aligned vmaddr.", "virtual-memory")
F("elf.phdr.interpreter", "The path stored in the PT_INTERP segment: the dynamic linker to run this program with.", "The kernel at exec.",
  "execve fails with 'No such file or directory' if the path does not exist.", "Mach-O: LC_LOAD_DYLINKER. PE: none.", "process-startup-linux")

F("elf.shdr.sh_name", "Offset of the section's name in the section name string table.", "Linkers and tools.", "The section gets a wrong name; tools that find sections by name fail.", "Mach-O: sectname. PE: Name.", "sections-vs-segments")
F("elf.shdr.sh_type", "Kind of section: 1 SHT_PROGBITS (contents from the file), 2 SHT_SYMTAB, 3 SHT_STRTAB, 4 SHT_RELA, 6 SHT_DYNAMIC, 7 SHT_NOTE, 8 SHT_NOBITS (no contents in the file, .bss), 11 SHT_DYNSYM.", "Linkers and tools.", "Tools interpret the contents as another kind of table.", "Mach-O: the type byte of section flags.", "sections-vs-segments")
F("elf.shdr.sh_flags", "Attributes: 1 SHF_WRITE, 2 SHF_ALLOC (occupies memory at run time), 4 SHF_EXECINSTR, and others for strings, TLS and groups.", "The static linker, which uses them to assign sections to segments.", "Matters when linking; a finished image is mapped by its program headers.", "Mach-O: section attributes. PE: Characteristics.", "sections-vs-segments")
F("elf.shdr.sh_addr", "Virtual address of the section if it is loaded; zero otherwise.", "Debuggers and tools.", "Tools attribute addresses to the wrong section.", "Mach-O: addr. PE: VirtualAddress.", "addresses")
F("elf.shdr.sh_offset", "File offset of the section's contents.", "Linkers and tools.", "Tools read the wrong bytes.", "Mach-O: offset. PE: PointerToRawData.", "addresses")
F("elf.shdr.sh_size", "Size of the section in bytes. For SHT_NOBITS it is the size in memory; nothing is stored in the file.", "Linkers and tools.", "Tables are read short or too far.", "Mach-O: size. PE: SizeOfRawData and VirtualSize.", "sections-vs-segments")
F("elf.shdr.sh_link", "Index of a related section; the meaning depends on the type. For a symbol table it is the string table; for a relocation section, the symbol table.", "Linkers and tools.", "Names or symbols are looked up in the wrong table.", NONE, "symbols")
F("elf.shdr.sh_info", "Extra information that depends on the type. For a symbol table, the index of the first non-local symbol; for a relocation section, the section the relocations apply to.", "Linkers and tools.", "Relocations are applied to the wrong section, or local symbols are confused with global ones.", "Mach-O: the counts in LC_DYSYMTAB.", "symbols")
F("elf.shdr.sh_addralign", "Required alignment of the section's address; 0 or 1 means none.", "The static linker.", "Matters when linking.", "Mach-O: align.", "structs-on-disk")
F("elf.shdr.sh_entsize", "Size of one entry if the section is a table of fixed-size entries (24 for a 64-bit symbol table); zero otherwise.", "Linkers and tools.", "Table entries are split at the wrong boundaries.", "Mach-O: reserved2 for stub sections.", "structs-on-disk")

# =============================================================================
# PE
# =============================================================================
F("pe.dos_header.e_magic",
  "The bytes 4d 5a, 'MZ', which mark an MS-DOS executable.",
  "The Windows loader, as its first check; MS-DOS, historically.",
  "The file is not recognised as an executable.",
  "ELF: e_ident[EI_MAG]. Mach-O: magic.",
  "structs-on-disk")
F("pe.dos_header.e_cblp", "MS-DOS field: bytes used in the last page of the DOS program.", "MS-DOS only.", "No effect on Windows.", NONE, "structs-on-disk")
F("pe.dos_header.e_cp", "MS-DOS field: number of pages in the DOS program.", "MS-DOS only.", "No effect on Windows.", NONE, "structs-on-disk")
F("pe.dos_header.e_lfarlc", "MS-DOS field: file offset of the DOS relocation table. The value 0x40 was a traditional sign that a newer header follows.", "MS-DOS only.", "No effect on Windows.", NONE, "structs-on-disk")
F("pe.dos_header.e_lfanew",
  "File offset of the PE signature. A 4-byte little-endian value at offset 0x3c.",
  "The Windows loader, immediately after checking 'MZ'.",
  "The loader looks for 'PE\\0\\0' in the wrong place and refuses the file as not a valid Win32 application.",
  "None exactly. ELF and Mach-O headers start at offset 0.",
  "structs-on-disk")

F("pe.rich_header.DanS_magic", "Start marker of the Rich header: the text 'DanS' XORed with the key stored at the end.", "Analysis tools. Windows ignores the whole Rich header.", "Tools no longer find or decode the Rich header.", "Mach-O: LC_BUILD_VERSION tool entries. ELF: .comment.", "stripping")
F("pe.rich_header.entry[].comp_id", "Identifies one build tool: a product id and a build number, XORed with the key.", "Analysis tools, to attribute the file to a toolchain.", "Informational only; it can be forged.", "Mach-O: tools[].tool and tools[].version.", "stripping")
F("pe.rich_header.entry[].count", "How many object files in the link were produced by that tool, XORed with the key.", "Analysis tools.", "Informational only.", NONE, "stripping")
F("pe.rich_header.Rich_magic", "The text 'Rich', which ends the list of entries. Stored unencoded.", "Analysis tools, which search for it to find the header.", "Tools no longer find the Rich header.", NONE, "stripping")
F("pe.rich_header.xor_checksum", "The XOR key for the entries. It is also a checksum over the DOS header and the entries, so tools can tell when either was altered.", "Analysis tools.", "A mismatch with the recomputed checksum suggests the header was edited or copied from another file.", NONE, "stripping")

F("pe.nt.Signature",
  "The four bytes 50 45 00 00, 'PE\\0\\0', at the offset given by e_lfanew.",
  "The Windows loader.",
  "The file is refused as not a valid Win32 application.",
  "ELF: e_ident[EI_MAG]. Mach-O: magic.",
  "structs-on-disk")

F("pe.file_header.Machine",
  "CPU architecture: 0x14c x86, 0x8664 x64, 0xaa64 ARM64, 0x1c4 ARM Thumb-2.",
  "The Windows loader when creating the process or loading a DLL.",
  "The image is refused as built for a different machine type.",
  "ELF: e_machine. Mach-O: cputype.",
  "file-formats-overview")
F("pe.file_header.NumberOfSections",
  "Number of entries in the section table. Microsoft's specification gives 96 as the most the Windows loader accepts.",
  "The Windows loader.",
  "Sections are not mapped, or bytes after the table are read as section headers and the image is refused.",
  "ELF: e_phnum (segments) and e_shnum (sections). Mach-O: ncmds and nsects.",
  "structs-on-disk")
F("pe.file_header.TimeDateStamp",
  "Link time as seconds since 1970-01-01 UTC. Reproducible builds store a hash of the contents here instead of a time.",
  "Debuggers and symbol servers, which use it with SizeOfImage to identify an image.",
  "Symbol and image lookups by timestamp fail. Execution is unaffected.",
  "Mach-O: LC_UUID. ELF: the build ID. Neither format stores a link time.",
  "debug-info")
F("pe.file_header.PointerToSymbolTable", "File offset of the COFF symbol table. Zero in images; used in object files.", "The linker, for object files.", "No effect on an image.", "ELF: sh_offset of .symtab. Mach-O: symoff.", "symbols")
F("pe.file_header.NumberOfSymbols", "Number of COFF symbol table entries. Zero in images.", "The linker, for object files.", "No effect on an image.", "Mach-O: nsyms.", "symbols")
F("pe.file_header.SizeOfOptionalHeader",
  "Size of the optional header that follows: normally 224 for PE32 and 240 for PE32+. The section table begins that many bytes after the file header.",
  "The Windows loader, to find the section table.",
  "The section table is read from the wrong place and the image is refused.",
  "ELF: e_ehsize. Mach-O: sizeofcmds.",
  "structs-on-disk")
F("pe.file_header.Characteristics",
  "Flags for the file: 0x0002 executable image, 0x2000 DLL, 0x0020 can use addresses above 2 GiB, 0x0001 relocations stripped, 0x0100 32-bit machine.",
  "The Windows loader.",
  "Without the executable-image flag the file is refused. With relocations-stripped set, the image cannot be moved from ImageBase.",
  "ELF: e_type. Mach-O: filetype and flags.",
  "file-formats-overview")

F("pe.optional_header.Magic", "0x10b for PE32 (32-bit), 0x20b for PE32+ (64-bit). It selects the layout of the rest of the optional header.", "The Windows loader.",
  "The header is read with the wrong layout and the image is refused.", "ELF: e_ident[EI_CLASS]. Mach-O: the magic.", "file-formats-overview")
F("pe.optional_header.LinkerVersion", "Major and minor version of the linker that produced the file.", "Tools; informational.", "Informational only.", "Mach-O: tools[] in LC_BUILD_VERSION. ELF: .comment.", "static-linking")
F("pe.optional_header.SizeOfCode", "Total size of the code sections.", "Tools; the loader does not rely on it.", "Informational only.", NONE, "sections-vs-segments")
F("pe.optional_header.SizeOfInitializedData", "Total size of the initialised data sections.", "Tools.", "Informational only.", NONE, "sections-vs-segments")
F("pe.optional_header.SizeOfUninitializedData", "Total size of the uninitialised data (.bss) sections.", "Tools.", "Informational only.", NONE, "sections-vs-segments")
F("pe.optional_header.AddressOfEntryPoint",
  "RVA of the first instruction of the image. For an executable it is the C runtime's start-up routine; for a DLL, the routine the loader calls on attach and detach; zero means a DLL has none.",
  "The Windows loader, after imports are resolved and DLLs are initialised.",
  "Execution starts at a different instruction. Packers point it at their unpacking routine.",
  "ELF: e_entry. Mach-O: LC_MAIN entryoff.",
  "process-startup-windows")
F("pe.optional_header.BaseOfCode", "RVA of the start of the code section.", "Tools.", "Informational only.", NONE, "sections-vs-segments")
F("pe.optional_header.BaseOfData", "RVA of the start of the data section. Present in PE32 only.", "Tools.", "Informational only.", NONE, "sections-vs-segments")
F("pe.optional_header.ImageBase",
  "Preferred address of the image in memory; a multiple of 64 KiB. The linker's defaults are 0x400000 for 32-bit executables and 0x140000000 for 64-bit ones.",
  "The Windows loader. If the image is placed elsewhere, base relocations are applied with the difference.",
  "If changed without redoing the relocations, absolute addresses in the image are wrong whenever it is loaded at the new base.",
  "Mach-O: vmaddr of __TEXT. ELF: the lowest PT_LOAD p_vaddr.",
  "addresses")
F("pe.optional_header.SectionAlignment", "Alignment of sections in memory; normally the page size, 0x1000.", "The Windows loader.",
  "Section addresses must be multiples of it; an image that violates this is generally refused.", "ELF: p_align. Mach-O: implied by vmaddr.", "virtual-memory")
F("pe.optional_header.FileAlignment", "Alignment of section data in the file; a power of two from 512 to 64 KiB, commonly 0x200.", "The Windows loader.",
  "Section data is located on the assumption that it is aligned to this value; a file that violates it may be refused or misread.", "ELF requires a segment's file offset and address to agree modulo the page size; Mach-O aligns segments to pages in the file.", "virtual-memory")
F("pe.optional_header.MajorOperatingSystemVersion", "Minimum operating system version the image requires.", "The Windows loader.", "Rarely decisive; the subsystem version is the one that is enforced.", "Mach-O: minos.", "static-linking")
F("pe.optional_header.MajorImageVersion", "A version number chosen by the developer.", "Nobody in the system.", "Informational only.", "Mach-O: LC_SOURCE_VERSION.", "static-linking")
F("pe.optional_header.MajorSubsystemVersion", "Minimum version of the subsystem the image requires (6.0 is Windows Vista).", "The Windows loader.", "With a version higher than the running system, the image is refused.", "Mach-O: minos.", "static-linking")
F("pe.optional_header.Win32VersionValue", "Reserved; the specification requires zero. Undocumented: a value other than zero replaces the operating system version numbers recorded for the process.", "Process creation, if the value is not zero.", "Version queries made by the process can report the numbers packed in this field instead of the real ones.", NONE, "structs-on-disk")
F("pe.optional_header.SizeOfImage",
  "Size of the image in memory, from ImageBase to the end of the last section, rounded up to SectionAlignment.",
  "The Windows loader, to reserve the address range.",
  "The image is generally refused if the value is inconsistent with the section table.",
  "ELF and Mach-O: computed from the segments.",
  "virtual-memory")
F("pe.optional_header.SizeOfHeaders", "Combined size of the DOS header and stub, the PE headers and the section table, rounded up to FileAlignment. The first section's data starts at or after it.", "The Windows loader, which maps that many bytes as the header pages.",
  "Too small and the loader does not map all of the headers; the image may be refused.", "Mach-O: header plus sizeofcmds.", "structs-on-disk")
F("pe.optional_header.CheckSum", "A simple checksum of the file. Verified for drivers and for DLLs loaded into certain system processes; zero is common elsewhere.", "The kernel, for the images it verifies.",
  "A driver with a wrong checksum is not loaded. Ordinary programs are unaffected.", NONE, "authenticode")
F("pe.optional_header.Subsystem", "Environment the image runs in: 1 native (drivers), 2 Windows GUI, 3 Windows console, 10 EFI application.", "The kernel and the Windows subsystem at process creation.",
  "A console program marked GUI starts without a console, and the reverse.", "Mach-O: platform. ELF: EI_OSABI.", "process-startup-windows")
F("pe.optional_header.DllCharacteristics",
  "Flags, mostly about mitigations: 0x0020 HIGH_ENTROPY_VA, 0x0040 DYNAMIC_BASE (may be relocated), 0x0080 FORCE_INTEGRITY, 0x0100 NX_COMPAT, 0x0400 NO_SEH, 0x4000 GUARD_CF, 0x8000 TERMINAL_SERVER_AWARE.",
  "The Windows loader and memory manager when the image is mapped.",
  "Clearing DYNAMIC_BASE keeps the image at ImageBase, unless that range is occupied or the system forces relocation (mandatory ASLR). Clearing NX_COMPAT matters for 32-bit processes only; 64-bit processes always have DEP.",
  "Mach-O: header flags (MH_PIE). ELF: e_type, PT_GNU_STACK and GNU property notes.",
  "mitigations-overview")
F("pe.optional_header.SizeOfStackReserve", "Address space to reserve for the first thread's stack (1 MiB by default).", "The kernel at process creation.", "A small value makes deep recursion overflow sooner.", "Mach-O: stacksize in LC_MAIN.", "stack-and-frames")
F("pe.optional_header.SizeOfStackCommit", "Amount of the stack to commit at once; the rest is committed as it is touched.", "The kernel at process creation.", "Little practical effect.", NONE, "stack-and-frames")
F("pe.optional_header.SizeOfHeapReserve", "Address space to reserve for the default process heap.", "The loader in ntdll.", "Little practical effect; the heap grows on demand.", NONE, "virtual-memory")
F("pe.optional_header.SizeOfHeapCommit", "Amount of the default heap to commit at once.", "The loader in ntdll.", "Little practical effect.", NONE, "virtual-memory")
F("pe.optional_header.LoaderFlags", "Reserved; must be zero.", "Nobody.", "Nothing.", NONE, "structs-on-disk")
F("pe.optional_header.NumberOfRvaAndSizes", "Number of data directory entries that follow; normally 16.", "The Windows loader.", "Directories with an index beyond the count are treated as absent.", "Mach-O: ncmds.", "structs-on-disk")

DATA_DIRS = {
    "EXPORT_TABLE": ("the export directory: the functions this image offers", "The loader, when another image imports from this one.", "pe-imports",
                     "Importers fail to find this image's functions.", "ELF: .dynsym. Mach-O: the export trie."),
    "IMPORT_TABLE": ("the import directory: one descriptor per DLL this image needs", "The loader, before the entry point runs.", "pe-imports",
                     "The loader cannot resolve imports; the process fails to start, or starts with an empty IAT and crashes.", "ELF: DT_NEEDED and the PLT relocations. Mach-O: LC_LOAD_DYLIB and the bind information."),
    "RESOURCE_TABLE": ("the resource tree: icons, version information, manifests, dialogs", "Resource APIs and the shell; process creation and the loader read the manifest.", "file-formats-overview",
                       "Icons and version information disappear; a missing manifest can change how the program is run.", "None in ELF. Mach-O keeps resources in the bundle, outside the binary."),
    "EXCEPTION_TABLE": ("the exception directory (.pdata): unwind information for each function on x64 and ARM64", "The exception dispatcher and debuggers, when unwinding the stack.", "stack-and-frames",
                        "Exceptions cannot unwind through the image's functions; the process is terminated when one is raised.", "ELF: .eh_frame. Mach-O: __unwind_info."),
    "CERTIFICATE_TABLE": ("the attribute certificate table, which holds the Authenticode signature", "Signature verification, when requested.", "authenticode",
                          "The signature is not found or is invalid. The program still runs unless policy requires a signature.", "Mach-O: LC_CODE_SIGNATURE. ELF: none."),
    "BASE_RELOCATION_TABLE": ("the base relocation table (.reloc)", "The loader, when the image is not placed at ImageBase.", "relocations",
                              "The image cannot be relocated correctly; at a different base its absolute addresses are wrong.", "ELF: relative relocations in .rela.dyn. Mach-O: rebases."),
    "DEBUG_DIRECTORY": ("the debug directory, including the record that identifies the PDB", "Debuggers and symbol servers.", "debug-info",
                        "Debuggers cannot find the matching PDB. Execution is unaffected.", "ELF: the build ID note. Mach-O: LC_UUID."),
    "ARCHITECTURE": ("nothing; this entry is reserved and must be zero", "Nobody.", "structs-on-disk", "Nothing.", "None."),
    "GLOBAL_PTR": ("the global pointer value on architectures that use one; zero on x86, x64 and ARM64", "Nobody on current architectures.", "structs-on-disk", "Nothing.", "None."),
    "TLS_TABLE": ("the TLS directory: the thread-local storage template and the list of TLS callbacks", "The loader, at process and thread start.", "initializers-tls",
                  "Thread-local variables are not set up, or callbacks are not run (or other code is run as a callback).", "ELF: PT_TLS. Mach-O: __thread_vars."),
    "LOAD_CONFIG_TABLE": ("the load configuration directory: the security cookie address, Control Flow Guard tables and other loader settings", "The loader.", "cfi",
                          "Control Flow Guard and related protections are not applied to the image.", "ELF: GNU property notes. Mach-O: none."),
    "BOUND_IMPORT": ("the bound import table, a leftover of an optimisation that pre-computed import addresses", "The loader, on images that still have one.", "pe-imports",
                     "Stale bound addresses are ignored and normal binding is used.", "Mach-O: prebinding, also obsolete."),
    "IAT": ("the import address tables of all imported DLLs, as one range", "The loader, which makes the range writable while it binds imports.", "got-plt",
            "Binding may fail if the IAT lies in read-only memory and this range does not cover it.", "ELF: .got and .got.plt. Mach-O: __got."),
    "DELAY_IMPORT_DESCRIPTOR": ("the delay-load import descriptors: DLLs loaded on first use", "The delay-load helper linked into the image.", "lazy-binding",
                                "Delay-loaded functions fail on first call.", "ELF: lazy binding through the PLT. Mach-O: lazy symbol pointers (older binaries)."),
    "CLR_RUNTIME_HEADER": ("the .NET (CLR) header, present in managed assemblies", "The .NET runtime.", "file-formats-overview",
                           "The file is not recognised as a .NET assembly.", "None."),
    "RESERVED_DIRECTORY": ("nothing; this entry is reserved and must be zero", "Nobody.", "structs-on-disk", "Nothing.", "None."),
}
for _name, (_what, _who, _concept, _wrong, _peers) in DATA_DIRS.items():
    _is_cert = _name == "CERTIFICATE_TABLE"
    F("pe.data_directory.VirtualAddress@DATA_DIR_" + _name,
      ("File offset (not an RVA: the signature is not mapped into memory) of " if _is_cert else "RVA of ") + _what + ". Zero if absent.",
      _who, _wrong, _peers, _concept)
    F("pe.data_directory.Size@DATA_DIR_" + _name,
      "Size in bytes of " + _what.split(":")[0] + ".",
      _who, "The table is read short, or bytes beyond it are read.", _peers, _concept)
F("pe.data_directory.VirtualAddress", "RVA of the table this directory entry describes. Zero if absent.", "The loader or the component that uses the table.",
  "The table is read from the wrong place.", NONE, "pe-imports")
F("pe.data_directory.Size", "Size in bytes of the table this directory entry describes.", "The loader or the component that uses the table.",
  "The table is read short, or bytes beyond it are read.", NONE, "pe-imports")

F("pe.section_header.Name", "Section name, up to 8 bytes, zero-padded: .text, .rdata, .data, .reloc. For user-mode images names carry no meaning for the loader.", "Tools and people. For drivers, the kernel: a section whose name begins with PAGE is made pageable.",
  "Nothing changes at run time for a user-mode image. Unusual names (UPX0) are a hint about how the file was produced.", "ELF: sh_name. Mach-O: sectname.", "sections-vs-segments")
F("pe.section_header.VirtualSize", "Size of the section in memory. If it exceeds SizeOfRawData, the rest is zero-filled.", "The Windows loader.",
  "Too small and part of the section is not available in memory.", "ELF: p_memsz. Mach-O: vmsize.", "virtual-memory")
F("pe.section_header.VirtualAddress", "RVA of the section in memory; a multiple of SectionAlignment.", "The Windows loader.",
  "The section is mapped where its code and the data directories do not expect it; sections must be in ascending, contiguous order or the image is refused.", "ELF: p_vaddr. Mach-O: vmaddr.", "addresses")
F("pe.section_header.SizeOfRawData", "Size of the section's data in the file; a multiple of FileAlignment. Zero for a section that is entirely uninitialised.", "The Windows loader.",
  "Too little data is read from the file, or the read reaches past the end of the file and the image is refused.", "ELF: p_filesz. Mach-O: filesize.", "virtual-memory")
F("pe.section_header.PointerToRawData", "File offset of the section's data; a multiple of FileAlignment.", "The Windows loader.",
  "Different bytes are mapped as the section's contents.", "ELF: p_offset. Mach-O: fileoff.", "addresses")
F("pe.section_header.PointerToRelocations", "File offset of the section's relocations. Used in object files; zero in images.", "The linker.", "No effect on an image.", "Mach-O: reloff.", "object-files")
F("pe.section_header.NumberOfRelocations", "Number of relocations for the section. Zero in images.", "The linker.", "No effect on an image.", "Mach-O: nreloc.", "object-files")
F("pe.section_header.Characteristics",
  "Flags. Permissions: 0x20000000 MEM_EXECUTE, 0x40000000 MEM_READ, 0x80000000 MEM_WRITE. Content: 0x20 code, 0x40 initialised data, 0x80 uninitialised data. 0x02000000 marks a section that may be discarded after loading (.reloc).",
  "The Windows loader, to set page protection.",
  "A code section without MEM_EXECUTE faults at the first instruction. Adding MEM_WRITE to a code section makes it writable and executable.",
  "ELF: p_flags. Mach-O: initprot.",
  "virtual-memory")

F("pe.win_certificate.dwLength", "Length of this certificate entry in bytes, including this header. Entries are padded to a multiple of 8.", "Signature verification.",
  "The signature is cut short or the next entry is not found.", "Mach-O: the SuperBlob length.", "authenticode")
F("pe.win_certificate.wRevision", "Revision of the structure; 0x0200 is the current one.", "Signature verification.", "The entry is not accepted.", NONE, "authenticode")
F("pe.win_certificate.wCertificateType", "Kind of content: 0x0002 is a PKCS #7 SignedData structure, the form Authenticode uses.", "Signature verification.", "The entry is not treated as an Authenticode signature.", "Mach-O: the blob type in the SuperBlob index.", "authenticode")


# =============================================================================
# Mapping from a parsed field to its catalog key
# =============================================================================
_MACHO_LC_STRUCT = {
    "LC_SEGMENT": "segment_command", "LC_SEGMENT_64": "segment_command",
    "LC_SYMTAB": "symtab_command", "LC_DYSYMTAB": "dysymtab_command",
    "LC_DYLD_INFO": "dyld_info_command", "LC_DYLD_INFO_ONLY": "dyld_info_command",
    "LC_LOAD_DYLINKER": "dylinker_command", "LC_ID_DYLINKER": "dylinker_command", "LC_DYLD_ENVIRONMENT": "dylinker_command",
    "LC_UUID": "uuid_command", "LC_BUILD_VERSION": "build_version_command", "LC_SOURCE_VERSION": "source_version_command",
    "LC_MAIN": "entry_point_command",
    "LC_LOAD_DYLIB": "dylib_command", "LC_ID_DYLIB": "dylib_command", "LC_LOAD_WEAK_DYLIB": "dylib_command",
    "LC_REEXPORT_DYLIB": "dylib_command", "LC_LOAD_UPWARD_DYLIB": "dylib_command", "LC_LAZY_LOAD_DYLIB": "dylib_command",
    "LC_RPATH": "rpath_command", "LC_UNIXTHREAD": "thread_command", "LC_THREAD": "thread_command",
    "LC_ENCRYPTION_INFO": "encryption_info_command", "LC_ENCRYPTION_INFO_64": "encryption_info_command",
    "LC_VERSION_MIN_MACOSX": "version_min_command", "LC_VERSION_MIN_IPHONEOS": "version_min_command",
    "LC_VERSION_MIN_TVOS": "version_min_command", "LC_VERSION_MIN_WATCHOS": "version_min_command",
    "LC_FILESET_ENTRY": "fileset_entry_command",
    "LC_DYLD_CHAINED_FIXUPS": "linkedit_data_command", "LC_DYLD_EXPORTS_TRIE": "linkedit_data_command",
    "LC_FUNCTION_STARTS": "linkedit_data_command", "LC_DATA_IN_CODE": "linkedit_data_command",
    "LC_CODE_SIGNATURE": "linkedit_data_command", "LC_SEGMENT_SPLIT_INFO": "linkedit_data_command",
    "LC_DYLIB_CODE_SIGN_DRS": "linkedit_data_command", "LC_LINKER_OPTIMIZATION_HINT": "linkedit_data_command",
}
_INDEX_RE = re.compile(r"\[\d+\]")
_REGISTER_RE = re.compile(r"^(x\d+|w\d+|r[a-z0-9]+|e[a-z]+)$")


def _norm(name: str) -> str:
    """arch[2].offset -> arch[].offset (but leave e_ident[EI_MAG] alone)."""
    return _INDEX_RE.sub("[]", name)


def key_for(fmt: str, ctx: str, name: str, cmd_name: Optional[str] = None) -> Optional[str]:
    """Catalog key for a field, or None if the catalog has no entry.

    fmt   'MACHO' | 'ELF' | 'PE' (any case)
    ctx   'header' | 'fat' | 'lc' | 'segment' | 'section' | 'chained_fixups' | 'superblob' |
          'code_directory' | 'win_certificate'
    name  the field's `name` as the parser emits it
    cmd_name  for ctx 'lc': the command's `cmd_name`
    """
    fmt = str(fmt).lower()
    name = _norm(str(name))
    candidates: List[str] = []
    if fmt == "macho":
        if ctx == "fat":
            candidates.append("macho.fat_header." + name)
        elif ctx == "header":
            candidates.append("macho.mach_header." + name)
        elif ctx in ("lc", "segment"):
            struct = "segment_command" if ctx == "segment" else _MACHO_LC_STRUCT.get(str(cmd_name), "")
            if struct == "linkedit_data_command":
                candidates.append("macho.linkedit_data_command.%s@%s" % (name, cmd_name))
            if struct:
                candidates.append("macho.%s.%s" % (struct, name))
                if struct == "thread_command" and _REGISTER_RE.match(name):
                    candidates.append("macho.thread_command.register")
            candidates.append("macho.load_command." + name)
        elif ctx == "section":
            candidates.append("macho.section." + name)
        elif ctx == "chained_fixups":
            candidates.append("macho.chained_fixups_header." + name)
        elif ctx == "superblob":
            candidates.append("macho.superblob." + name)
        elif ctx == "code_directory":
            candidates.append("macho.code_directory." + name)
    elif fmt == "elf":
        if ctx == "header":
            candidates.append("elf.ehdr." + name)
        elif ctx in ("lc", "segment"):
            candidates.append("elf.phdr." + name)
        elif ctx == "section":
            candidates.append("elf.shdr." + name)
    elif fmt == "pe":
        if ctx in ("header", "segment") and (name == "Signature" or name.startswith("FileHeader.") or name.startswith("OptionalHeader.")):
            if name == "Signature":
                candidates.append("pe.nt.Signature")
            elif name.startswith("FileHeader."):
                candidates.append("pe.file_header." + name[len("FileHeader."):])
            else:
                candidates.append("pe.optional_header." + name[len("OptionalHeader."):])
        elif ctx == "lc":
            cmd = str(cmd_name)
            if cmd == "IMAGE_DOS_HEADER":
                candidates.append("pe.dos_header." + name)
            elif cmd == "IMAGE_RICH_HEADER":
                candidates.append("pe.rich_header." + name)
            elif cmd.startswith("DATA_DIR_"):
                candidates.append("pe.data_directory.%s@%s" % (name, cmd))
                candidates.append("pe.data_directory." + name)
        elif ctx in ("section", "segment"):
            candidates.append("pe.section_header." + name)
        elif ctx == "win_certificate":
            candidates.append("pe.win_certificate." + name)
        elif ctx == "rich":
            candidates.append("pe.rich_header." + name)
    for key in candidates:
        if key in CATALOG:
            return key
    return None


def explain(key: Optional[str]) -> Optional[Dict[str, str]]:
    return CATALOG.get(key) if key else None


def reference() -> List[Dict[str, Any]]:
    """The catalog grouped by structure, in reference order."""
    out: List[Dict[str, Any]] = []
    for struct in STRUCTS:
        prefix = struct["id"] + "."
        entries = [e for k, e in CATALOG.items() if k.startswith(prefix)]
        fmt = struct["id"].split(".")[0]
        out.append({"id": struct["id"], "format": fmt, "title": struct["title"], "fields": entries})
    return out
