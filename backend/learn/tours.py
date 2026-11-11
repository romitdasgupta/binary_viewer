"""
Guided tours. A tour is a sequence of steps that drive the tool over the open
file: each step may select a tree node and highlight bytes (`show`), and may ask
for something to be done in the tool (`task`).

Step text and task prompts are rich text. A value that differs per format is a
{"macho": …, "elf": …, "pe": …} dict; a step whose text has no entry for the
open file's format is left out, as is a step whose `show` does not exist in the
file. Placeholders in braces ({exec_seg}, {entry_vm}, {answer}, …) are filled
from the document by resolve.facts() and by the task calculators.

Task kinds (all answers are computed from the open document by resolve.compute_task):
  bytes   put the hex cursor on a byte inside one of the expected ranges
  node    select one of the expected tree nodes (a list of segments may be offered)
  value   type a number (decimal or 0x hex)
  choice  pick one option
"""

from typing import Any, Dict, List, Optional

from .dsl import (entry, entry_field, fat, header, hfield, import_slot, lc, section, segment, signature,
                  symbol, view)

DEFAULT_SAMPLES = {"macho": "synthetic_universal", "elf": "synthetic_elf64", "pe": "synthetic_pe64"}
ALL = ["macho", "elf", "pe"]


def step(id: str, title: str, text: Any, show: Optional[Dict[str, Any]] = None, task: Optional[Dict[str, Any]] = None,
         needs_task: bool = False) -> Dict[str, Any]:
    return {"id": id, "title": title, "text": text, "show": show, "task": task, "needs_task": needs_task}


def task(id: str, kind: str, prompt: Any, explain: Any = "", calc: str = "", target: Any = None,
         options: Any = None, correct: Any = None) -> Dict[str, Any]:
    spec: Dict[str, Any] = {"id": id, "kind": kind, "prompt": prompt, "explain": explain}
    if calc:
        spec["calc"] = calc
    if target is not None:
        spec["target"] = target
    if options is not None:
        spec["options"] = options
        spec["correct"] = correct
    return spec


def tour(id: str, title: str, level: int, minutes: int, summary: str, formats: List[str], steps: List[Dict[str, Any]],
         concepts: List[str], requires: Optional[Dict[str, Any]] = None, samples: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    chosen = dict((f, DEFAULT_SAMPLES[f]) for f in formats)
    chosen.update(samples or {})
    return {"id": id, "title": title, "level": level, "minutes": minutes, "summary": summary, "formats": list(formats),
            "steps": steps, "concepts": list(concepts), "requires": requires, "samples": chosen}


# One question about position independence, asked of the header so that it has one answer on
# every file (see resolve._PIE_OPTIONS).
PIE_PROMPT = {
    "macho": "Does the header ask the kernel to load this main executable at a random address (is `MH_PIE` set in `flags`)?",
    "elf": "May the loader choose the address this file is mapped at (is `e_type` `ET_DYN`)?",
    "pe": "Does this image opt in to load-address randomisation (is `DYNAMIC_BASE` set, with its relocations still present)?",
}

MAGIC = {"kind": "field", "where": "header", "name": {"macho": "magic", "elf": "e_ident[EI_MAG]"}}
PE_MZ = lc(pe=["IMAGE_DOS_HEADER"], field="e_magic")
PERMS = {"macho": "initprot", "elf": "p_flags", "pe": "Characteristics"}

TOURS: List[Dict[str, Any]] = [
    # =========================================================================== level 1
    tour(
        "first-contact", "First contact: identify a file from its header", 1, 6,
        "Read the magic number, decode a little-endian field, and find out which CPU and what kind of file this is.",
        ALL, concepts=["bytes-and-hex", "endianness", "structs-on-disk", "file-formats-overview"],
        steps=[
            step("bytes", "A file is bytes",
                 "The hex view shows {file_name} from its first byte. The left column is the offset of each row; the "
                 "middle is sixteen bytes in hexadecimal; the right shows the same bytes as text. The inspector in the "
                 "centre shows the same bytes decoded into the fields of the {header_name}. Selecting a field row "
                 "highlights its bytes.",
                 show=header()),
            step("magic", "The magic number",
                 {"macho": "A format announces itself in its first bytes. A Mach-O file starts with a 4-byte [[magic-number|magic number]].",
                  "elf": "A format announces itself in its first bytes. An ELF file starts with `0x7f` followed by the letters `ELF`.",
                  "pe": "A format announces itself in its first bytes. A PE file starts with the two letters `MZ`, the signature of the MS-DOS header that still comes first."},
                 task=task("magic", "bytes", "In the hex view, click the first byte of the file's magic number.",
                           "The magic is at offset {answer}. Every tool, and the kernel, checks these bytes before trusting anything else in the file.",
                           target=[MAGIC, PE_MZ])),
            step("endian", "Byte order",
                 {"macho": "A file stores numbers wider than one byte either [[little-endian]] or [[big-endian]]. This slice is {byte_order}: {byte_order_rule}. The magic number tells a reader which: read in the wrong order, its bytes come out reversed.",
                  "elf": "The byte at offset 5 of the file (`EI_DATA`) says whether numbers are stored [[little-endian]] or [[big-endian]]. This file is {byte_order}: {byte_order_rule}."},
                 task=task("le", "value",
                           {"macho": "The magic is stored as the bytes `{bytes}`. Read as one {byte_order} number, what is its value? Type it in hexadecimal.",
                            "elf": "The field `e_machine` at offset {offset} is stored as the bytes `{bytes}`. Read as a {byte_order} number, what is its value?"},
                           "The value is {answer}. The decoder under the hex view shows the same number in its u16 or u32 cell when the cursor is on the first byte; its byte-order switch shows what the other order would give.",
                           calc="le_value",
                           target={"kind": "field", "where": "header", "name": {"macho": "magic", "elf": "e_machine"}}),
                 ),
            step("endian-pe", "Byte order",
                 {"pe": "PE is always [[little-endian]]: the least significant byte of a number comes first, so read a number's bytes from right to left. Try it on `e_lfanew`, the DOS header's last field: four bytes at offset `0x3c` that give the offset of the real PE headers."},
                 task=task("le-pe", "value",
                           {"pe": "`e_lfanew` is stored as the bytes `{bytes}`. Read as a little-endian number, what is its value?"},
                           "The value is {answer}: the PE signature is at that file offset.",
                           calc="le_value", target=lc(pe=["IMAGE_DOS_HEADER"], field="e_lfanew")),
                 needs_task=True),
            step("cpu", "Which CPU",
                 {"macho": "`cputype` names the instruction set: this slice is for {arch}. Bit 24 of the value marks a 64-bit ABI, which is why 64-bit types start with `0x01`.",
                  "elf": "`e_machine` names the instruction set: this file is for {arch}. The kernel refuses to start a file for a machine it cannot run.",
                  "pe": "`Machine`, the first field after the `PE\\0\\0` signature, names the instruction set: this file is for {arch}."},
                 show=hfield(macho="cputype", elf="e_machine", pe="FileHeader.Machine")),
            step("count", "What follows the header",
                 {"macho": "The header holds a count and a size: `ncmds` [[load-command|load commands]], `sizeofcmds` bytes in all, follow the header directly. They are the table of contents of the file.",
                  "elf": "The header locates two tables. `e_phoff` and `e_phnum` give the offset and number of [[program-header|program headers]], which describe what to load.",
                  "pe": "`NumberOfSections` says how many section headers follow the optional header. They describe what to map."},
                 task=task("count", "value",
                           {"macho": "How many load commands follow the header? Find the field and type its value.",
                            "elf": "How many program headers does this file have? Find the field and type its value.",
                            "pe": "How many sections does this file have? Find the field and type its value."},
                           "The answer is {answer}, in the field `{field}`. The same number is the badge on the corresponding node of the tree.",
                           target=hfield(macho="ncmds", elf="e_phnum", pe="FileHeader.NumberOfSections"))),
            step("next", "Where to go from here",
                 "You have read a magic number, a little-endian field, the CPU type and a table count: the same four "
                 "things every loader reads first. The next tour, *From file to memory*, follows those tables to see "
                 "how the file is laid out when it runs."),
        ],
    ),
    tour(
        "file-to-memory", "From file to memory", 1, 8,
        "Segments, the difference between a file offset and an address, and how to convert between them.",
        ALL, concepts=["sections-vs-segments", "virtual-memory", "addresses"],
        steps=[
            step("map", "Two layouts of the same bytes",
                 "The memory map at the top has two strips. *File* shows where each part lies on disk. *VM* shows "
                 "where the loader will place it in the process's address space. The parts are [[segment|segments]]: "
                 "this file has {nsegs}. The same list is in the tree under *Segments & sections*.",
                 show=view("segments")),
            step("one", "One segment",
                 "The segment `{exec_seg}` holds the code. Its header says: take the bytes at file offset {exec_off} "
                 "and make them appear at address {exec_vm}, with permissions `{exec_prot}`. Loading is exactly "
                 "this, repeated for each segment.",
                 show=segment("exec", part="header")),
            step("contains", "Which segment holds an address",
                 "Every address in a running program belongs to at most one segment. Finding that segment is the "
                 "first step of any address calculation.",
                 task=task("segment", "node",
                           "{lead} Which segment contains that address? Select it in the tree, or pick it below.",
                           "It is `{answer}`: the address lies between the segment's start and its start plus its size in memory.",
                           calc="segment_for_address")),
            step("translate", "From an address to a file offset",
                 "Within a segment, a byte keeps its distance from the segment's start. So "
                 "`offset = address - segment address + segment file offset`. The Translate bar above the "
                 "inspector does this in both directions.",
                 task=task("offset", "bytes",
                           "A string in this file will be loaded at address {address}. Put the hex cursor on the byte that will be at that address.",
                           "It is at file offset {answer}. Typing the address into *VM address* in the Translate bar gives the same result and names the segment used.",
                           calc="addr_to_offset")),
            step("zerofill", "More memory than file",
                 "A segment can be larger in memory than in the file. The loader fills the rest with zeros. This is "
                 "how zero-initialised variables ([[bss]]) take up no space on disk. In the memory map such a "
                 "segment is wider in the VM strip than in the File strip.",
                 show=segment("zerofill", part="header"),
                 task=task("zerofill", "value",
                           "Look at the sizes of `{seg}` in memory and in the file. How many bytes of it are not stored in the file?",
                           "{answer} bytes: the size in memory minus the size in the file.",
                           calc="zerofill_size")),
            step("rva", "PE: relative virtual addresses",
                 {"pe": "PE headers store [[rva|RVAs]]: addresses relative to the image base. The file offset of an RVA is "
                        "found through the section that contains it: `PointerToRawData + (RVA - VirtualAddress)`."},
                 task=task("rva", "value",
                           {"pe": "`AddressOfEntryPoint` holds the RVA {rva}. What is the file offset of that byte? Use the section table."},
                           "{answer}. The RVA lies in `{seg}`, whose `VirtualAddress` is {va} and whose `PointerToRawData` is {raw}.",
                           calc="rva_to_offset"),
                 needs_task=True),
            step("slide", "At run time",
                 "The addresses in the file are the linker's plan. If the system loads the image somewhere else, "
                 "every address shifts by the same amount, the [[slide]]. Distances inside the image do not change, "
                 "so the calculation you just did stays valid."),
        ],
    ),

    # =========================================================================== level 2
    tour(
        "permissions", "Page permissions and W^X", 2, 6,
        "Read a segment's permissions, work out the value that would change them, and find segments that are writable and executable.",
        ALL, concepts=["virtual-memory", "nx-wx"], samples={"pe": "synthetic_pe32"},
        steps=[
            step("field", "Where permissions are stored",
                 {"macho": "`initprot` holds the [[page-permissions|permissions]] the segment is mapped with, as three bits: read 1, write 2, execute 4. `maxprot` is the most they may ever be raised to.",
                  "elf": "`p_flags` holds the segment's [[page-permissions|permissions]] as three bits: execute 1, write 2, read 4. Note that the bit order differs from Mach-O.",
                  "pe": "The top bits of a section's `Characteristics` are its [[page-permissions|permissions]]: `0x20000000` execute, `0x40000000` read, `0x80000000` write."},
                 show=segment("exec", field=PERMS)),
            step("exec", "Executable segments",
                 "Only pages mapped with execute permission can run as code. Everything else, including the stack and "
                 "the heap, is data to the CPU ([[nx|NX]]).",
                 task=task("exec", "node",
                           "Select a segment of this file whose pages will be executable.",
                           "Executable here: `{answer}`. The tree shows each segment's permissions as a coloured tag.",
                           calc="exec_segments")),
            step("writable", "Changing one bit",
                 "Permissions are [[bit-flags|bit flags]]: to add one, set its bit and leave the others alone.",
                 task=task("writable", "value",
                           "`{seg}` is mapped `{prot}`; its `{field}` field holds {current}. What value would make it writable as well, with every other bit unchanged?",
                           "{answer}: the current value with the write bit ({bit}) set. A code segment changed this way is writable and executable at once, which is exactly what [[w-xor-x|W^X]] forbids.",
                           calc="make_writable")),
            step("rwx", "Writable and executable",
                 "A segment that is both writable and executable lets a program, or an attacker who can write to "
                 "memory, produce bytes and run them. Compilers do not create such segments by default; packers, "
                 "some runtimes and old toolchains do.",
                 task=task("rwx", "node",
                           "This file has a segment that is writable and executable. Select it.",
                           "It is `{answer}`. The memory map draws such segments in the warning colour.",
                           calc="rwx_segments"),
                 needs_task=True),
            step("stack", "The stack",
                 {"elf": "The stack is not a segment of the file, but its permissions come from the file: the `PT_GNU_STACK` "
                         "program header exists only for its `p_flags`. Without `PF_X` (1) the stack is not executable."},
                 show=lc(elf=["PT_GNU_STACK"], field="p_flags")),
            step("audit", "The summary",
                 "The Hardening view lists these checks, and others, for the whole file. It reports what the file "
                 "declares; what a running process actually gets also depends on the system.",
                 show=view("security_audit")),
        ],
    ),
    tour(
        "entry-point", "From the entry point to the first instructions", 2, 7,
        "Find where the entry point is stored, follow it to the code, and read the first function.",
        ALL, concepts=["addresses", "process-startup-linux", "stack-and-frames", "reading-disassembly"],
        steps=[
            step("where", "Where the entry point is stored",
                 {"macho": "A Mach-O executable names its entry point in a load command: `LC_MAIN` for programs started through dyld, `LC_UNIXTHREAD` (a full set of initial register values) for statically linked files.",
                  "elf": "The ELF header's `e_entry` field holds the entry point.",
                  "pe": "The optional header's `AddressOfEntryPoint` field holds the entry point."},
                 task=task("field", "bytes",
                           "In the hex view, click any of the bytes that hold this file's entry point.",
                           "The field is at offset {answer}. Selecting its row in the inspector highlights the same bytes.",
                           target=entry_field())),
            step("kind", "What kind of number it is",
                 "The three formats store the entry point in three different coordinate systems.",
                 task=task("kind", "choice",
                           "How does the {format} format define the value stored in this file's entry point field?",
                           {"macho": "It is defined as {answer}. `LC_MAIN` stores `entryoff`, the offset of `main` from the start of the Mach-O file; `LC_UNIXTHREAD` stores a register value, which is an address.",
                            "elf": "It is defined as {answer}, in the same coordinates as the `p_vaddr` of the segments: `e_entry` is where the program's own code starts. A position-independent file is linked from address 0 and the loader adds its load base to every address, this one included; ELF has no image-base field to add.",
                            "pe": "It is defined as {answer}: add `ImageBase` to get the address, or go through the section table to get the file offset."},
                           calc="entry_kind")),
            step("code", "The code it points to",
                 "The entry point resolves to address {entry_vm}, file offset {entry_off}. *Show* opens the "
                 "disassembly there.",
                 show=entry(),
                 task=task("code", "bytes",
                           "Put the hex cursor on the first byte of the instruction at the entry point ({address}).",
                           "File offset {answer}. Selecting the first row of the disassembly puts the cursor on the same byte.",
                           calc="entry_code")),
            step("prologue", "The first instructions",
                 "The entry of a function usually begins with a [[prologue]]: it saves the caller's "
                 "[[frame-pointer|frame pointer]] and return address and reserves stack space. With Learn mode on, "
                 "the listing labels such sequences, and each mnemonic explains itself on hover or focus.",
                 show=entry(),
                 task=task("arg", "choice",
                           "Code on this platform passes the first integer argument of a function in which register?",
                           "{answer}. The calling convention belongs to the operating system's ABI, which is why the same CPU can have two.",
                           calc="first_arg_register")),
            step("notmain", "Not yet main",
                 {"macho": "With `LC_MAIN`, the address is `main` itself, and dyld calls it once every library is bound and initialised. Initialisers still run before it.",
                  "elf": "`e_entry` is `_start`, start-up code from the C runtime. With glibc it calls `__libc_start_main`, which runs the program's initialisers and then calls `main`.",
                  "pe": "`AddressOfEntryPoint` is the C runtime's start-up routine, which initialises the runtime and then calls `main` or `WinMain`. TLS callbacks, if any, run even earlier."},
                 show=view("function_starts")),
        ],
    ),
    tour(
        "symbols", "Symbols and names", 2, 5,
        "Where names are kept, what an undefined symbol is, and what a mangled name encodes.",
        ALL, concepts=["symbols", "name-mangling", "stripping"],
        steps=[
            step("table", "The symbols of this file",
                 {"macho": "The Symbols view lists the `nlist_64` entries located by `LC_SYMTAB`. *Kind* shows whether a symbol is defined in a section (`SECT`) or undefined (`UNDF`); `ext` marks symbols visible to other images.",
                  "elf": "The Symbols view lists the entries of `.dynsym` and, if present, `.symtab`. *Kind* shows whether a symbol is defined or undefined (`UNDF`).",
                  "pe": "A PE image has no symbol table. The Symbols view is assembled from the import tables, the export directory and the entry point, which are the only names the file contains."},
                 show=view("symtab")),
            step("undef", "Names needed from elsewhere",
                 "An [[undefined-symbol|undefined symbol]] is a name this file uses but does not contain. Each one must "
                 "be supplied by a library at load time. The list of undefined symbols is the most direct statement "
                 "of what a program can do.",
                 show=symbol("undefined")),
            step("where", "Where the table is",
                 {"macho": "`LC_SYMTAB` gives the file offset and count of the symbol entries, and the offset and size of the string table that holds their names. Both live in `__LINKEDIT`.",
                  "pe": "Imported names are reached from the import directory: descriptor, then lookup table, then a hint and a name for each function."},
                 show={"kind": "lc", "cmd": {"macho": ["LC_SYMTAB"], "pe": ["DATA_DIR_IMPORT_TABLE"]}},
                 task=task("nsyms", "value",
                           {"macho": "How many entries does the symbol table have? Read it from `LC_SYMTAB`."},
                           "{answer}, in the field `nsyms`. It matches the badge of the Symbols node.",
                           target=lc(macho=["LC_SYMTAB"], field="nsyms"))),
            step("where-elf", "Where the table is",
                 {"elf": "`.dynsym` is the table the dynamic linker uses. Its section header gives the offset and size; `sh_entsize` is the size of one entry, and `sh_link` names the string table."},
                 show=section(elf=[".dynsym"], part="header")),
            step("mangle", "Mangled names",
                 "C++ and Swift encode namespaces and parameter types into symbol names so that the linker can tell "
                 "overloads apart ([[name-mangling]]). The *Demangle* switch in the Symbols view shows the readable "
                 "form. A name that starts with `_Z` (`__Z` in Mach-O) follows the Itanium C++ ABI; one that starts "
                 "with `?` is Microsoft's scheme.",
                 show=view("symtab")),
        ],
    ),
    tour(
        "loader-walk", "What the loader reads, in order", 2, 8,
        "Walk through the structures the kernel and the dynamic linker consult, in the order they consult them.",
        ALL, concepts=["process-startup-macos", "process-startup-linux", "process-startup-windows"],
        steps=[
            step("slice", "Choosing a slice",
                 {"macho": "The file is [[universal-binary|universal]]: the kernel reads this table first and picks the slice that best matches the machine. Everything after this step happens inside one slice."},
                 show=fat()),
            step("header", "Recognising the file",
                 {"macho": "The kernel checks the magic, the CPU type and the file type (it starts only `MH_EXECUTE`), then reads `sizeofcmds` bytes of load commands.",
                  "elf": "The kernel's ELF handler checks the magic, the type (`ET_EXEC` or `ET_DYN`) and the machine, then reads the program headers that `e_phoff` and `e_phnum` locate.",
                  "pe": "The kernel checks `MZ`, follows `e_lfanew`, and checks the signature `PE\\0\\0`, the machine and the optional header."},
                 show=header()),
            step("pe-lfanew", "The way to the PE headers",
                 {"pe": "`e_lfanew` is the only field of the DOS header that the Windows loader needs besides the magic."},
                 show=lc(pe=["IMAGE_DOS_HEADER"], field="e_lfanew")),
            step("map", "Mapping the segments",
                 {"macho": "Each `LC_SEGMENT_64` is mapped: `filesize` bytes from `fileoff` appear at `vmaddr` (plus the slide), with the permissions in `initprot`.",
                  "elf": "Each `PT_LOAD` program header is mapped: `p_filesz` bytes from `p_offset` appear at `p_vaddr` (plus the load base), with the permissions in `p_flags`; memory up to `p_memsz` is zero-filled.",
                  "pe": "The image is mapped at `ImageBase`, or at another base if it may be relocated. Each section's `SizeOfRawData` bytes from `PointerToRawData` appear at its `VirtualAddress`."},
                 show=segment("exec", part="header"),
                 task=task("pie", "choice",
                           PIE_PROMPT,
                           {"macho": "{answer}: the header flag `MH_PIE` (`0x200000`) decides. Without it an x86-64 program is loaded at its linked address every time; an arm64 kernel goes further and refuses to start a dynamically linked executable without it.",
                            "elf": "{answer}: a file of type `ET_DYN` can be placed anywhere; `ET_EXEC` is tied to its addresses.",
                            "pe": "{answer}: the `DYNAMIC_BASE` bit (`0x0040`) of `DllCharacteristics` opts in, and only an image that still has its base relocations (`IMAGE_FILE_RELOCS_STRIPPED`, `0x0001`, clear in `Characteristics`) can be moved."},
                           calc="is_pie")),
            step("pagezero", "The unmapped low addresses",
                 {"macho": "`__PAGEZERO` has no permissions and no bytes in the file. It reserves the low addresses so that a null pointer dereference faults."},
                 show=segment("name", name={"macho": "__PAGEZERO"}, part="header")),
            step("interp", "Finding the dynamic linker",
                 {"macho": "`LC_LOAD_DYLINKER` names the dynamic linker. The kernel maps it too and starts the process there, not in the program.",
                  "elf": "`PT_INTERP` holds the path of the dynamic linker. The kernel maps it too and starts the process there, not in the program."},
                 show=lc(macho=["LC_LOAD_DYLINKER"], elf=["PT_INTERP"])),
            step("sig", "Checking the signature",
                 {"macho": "`LC_CODE_SIGNATURE` locates the signature. The kernel loads it at exec and validates each page against it when the page is first used."},
                 show=lc(macho=["LC_CODE_SIGNATURE"])),
            step("stack", "Stack permissions",
                 {"elf": "`PT_GNU_STACK` tells the kernel whether the stack must be executable."},
                 show=lc(elf=["PT_GNU_STACK"])),
            step("libs", "Loading the libraries",
                 {"macho": "Now in user mode: dyld reads each `LC_LOAD_DYLIB` and loads that library, then the libraries it needs in turn.",
                  "elf": "Now in user mode: the dynamic linker follows `PT_DYNAMIC` to the dynamic section and loads each `DT_NEEDED` library, then the libraries those need.",
                  "pe": "Now in user mode: the loader in `ntdll.dll` walks the import directory and loads each DLL named there, then the DLLs those import."},
                 show=lc(macho=["LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB"], elf=["PT_DYNAMIC"], pe=["DATA_DIR_IMPORT_TABLE"])),
            step("fixups", "Fixing up pointers",
                 {"macho": "dyld applies the [[fixup|fixups]]: it adds the slide to pointers into the image and writes the addresses of imported symbols into their slots.",
                  "elf": "The dynamic linker applies the relocations: relative ones get the load base added, the others get the address of the symbol they name.",
                  "pe": "If the image is not at `ImageBase`, base relocations are applied. The address of each imported function is written into the import address table."},
                 show=view("dyld_info")),
            step("relro", "Locking the tables",
                 {"macho": "Segments flagged `SG_READ_ONLY`, such as `__DATA_CONST`, are made read-only now that their pointers are final.",
                  "elf": "The range described by `PT_GNU_RELRO` is made read-only now that its pointers are final."},
                 show={"kind": "lc", "cmd": {"elf": ["PT_GNU_RELRO"]}}),
            step("tls", "Callbacks before the entry point",
                 {"pe": "If the image has a TLS directory with callbacks, the loader calls them now, before the entry point."},
                 show=lc(pe=["DATA_DIR_TLS_TABLE"])),
            step("entry", "Transferring control",
                 {"macho": "After initialisers have run, dyld calls the entry point: {entry_vm}.",
                  "elf": "After the libraries' initialisers have run, the dynamic linker jumps to the entry point: {entry_vm}.",
                  "pe": "After every imported DLL has been initialised, the thread runs the entry point: {entry_vm}."},
                 show=entry()),
        ],
    ),
    tour(
        "universal", "Inside a universal binary", 2, 4,
        "The big-endian table at the front of a multi-architecture Mach-O file, and what slice offsets are.",
        ["macho"], concepts=["file-formats-overview", "endianness", "addresses"], requires=fat(),
        steps=[
            step("header", "The universal header",
                 {"macho": "A [[universal-binary|universal]] file starts with the magic `0xcafebabe` and a count, followed by one `fat_arch` entry per architecture. Unlike the rest of the file, this table is [[big-endian]]: read its numbers left to right."},
                 show=fat("nfat_arch"),
                 task=task("count", "value",
                           {"macho": "How many architectures does this file contain? Read the count from the header."},
                           "{answer}, in `nfat_arch`. The bytes are in big-endian order, so the value is at the right-hand end.",
                           target=fat("nfat_arch"))),
            step("offset", "Where a slice starts",
                 {"macho": "Each entry gives the CPU type, and the offset and size of that architecture's complete Mach-O file, its [[slice]]. The active slice here is {arch}."},
                 task=task("offset", "bytes",
                           {"macho": "Click the bytes that hold the file offset of the {arch} slice."},
                           "The field is at offset {answer}. Its value is where the slice's own Mach-O header begins.",
                           target=fat("arch[].offset"))),
            step("slice", "Offsets inside a slice",
                 {"macho": "Inside a slice, every offset counts from the start of the slice, not of the file. That is why this tool shows both a *File offset* and a *Slice offset* column: the first is where the bytes are, the second is what the slice's own headers say."},
                 show=header()),
            step("switch", "Other slices",
                 {"macho": "The *Slice* selector in the toolbar switches to another architecture. Only one slice is ever loaded into a process; the others are ignored at run time."}),
        ],
    ),
    tour(
        "pe-headers", "The PE header chain", 2, 6,
        "DOS header, PE signature, file header, optional header, section table and data directories, in the order a loader walks them.",
        ["pe"], concepts=["structs-on-disk", "addresses", "pe-imports"],
        steps=[
            step("mz", "The DOS header",
                 {"pe": "Every PE file begins with a 64-byte MS-DOS header. Windows uses two of its fields: the magic `MZ`, and `e_lfanew` at offset `0x3c`."},
                 show=PE_MZ),
            step("lfanew", "The pointer to the real headers",
                 {"pe": "`e_lfanew` holds the file offset of the PE signature. Between the DOS header and that offset lies the DOS stub and, in files produced by Microsoft's linker, the Rich header."},
                 task=task("lfanew", "value",
                           {"pe": "`e_lfanew` is stored as the bytes `{bytes}`. What file offset does it give?"},
                           "{answer}. The four bytes `50 45 00 00` are at that offset.",
                           calc="le_value", target=lc(pe=["IMAGE_DOS_HEADER"], field="e_lfanew"))),
            step("sig", "The signature",
                 {"pe": "At that offset: `PE\\0\\0`, then the 20-byte COFF file header."},
                 task=task("sig", "bytes", {"pe": "Click the first byte of the `PE\\0\\0` signature."},
                           "Offset {answer}, the value of `e_lfanew`.",
                           target=hfield(pe="Signature"))),
            step("opt", "The optional header",
                 {"pe": "`Magic` says which layout follows: `0x10b` for PE32, `0x20b` for PE32+. `ImageBase` is the address the image would like to be loaded at; every RVA in the file is relative to it."},
                 show=hfield(pe="OptionalHeader.ImageBase")),
            step("sections", "The section table",
                 {"pe": "After the optional header come the section headers. Each maps `SizeOfRawData` bytes from `PointerToRawData` in the file to `VirtualAddress` (an RVA) in memory."},
                 show=segment("exec", part="header"),
                 task=task("rva", "value",
                           {"pe": "`AddressOfEntryPoint` holds the RVA {rva}. What is the file offset of that byte?"},
                           "{answer}. The RVA lies in `{seg}`: {raw} + ({rva} - {va}).",
                           calc="rva_to_offset")),
            step("dirs", "The data directories",
                 {"pe": "The optional header ends with (RVA, size) pairs, the [[data-directory|data directories]]: `NumberOfRvaAndSizes` of them, normally sixteen. Each index has a fixed meaning; index 1 is the import directory."},
                 show=lc(pe=["DATA_DIR_IMPORT_TABLE"])),
            step("cert", "One directory that is not an RVA",
                 {"pe": "Index 4, the certificate table, holds a file offset instead of an RVA, because the signature at the end of the file is not mapped into memory."},
                 show=lc(pe=["DATA_DIR_CERTIFICATE_TABLE"], field="VirtualAddress")),
        ],
    ),
    tour(
        "elf-two-views", "ELF: the loader's view and the linker's view", 2, 6,
        "Program headers and section headers describe the same bytes for two different readers.",
        ["elf"], concepts=["sections-vs-segments", "elf-dynamic", "process-startup-linux"],
        steps=[
            step("phoff", "The table the kernel reads",
                 {"elf": "`e_phoff` is the file offset of the [[program-header|program header]] table. This table is all the kernel and the dynamic linker need."},
                 show=hfield(elf="e_phoff"),
                 task=task("phoff", "value", {"elf": "At which file offset does the program header table start? Type the value of `e_phoff`."},
                           "{answer}. In a 64-bit file that is normally 64, directly after the header.",
                           target=hfield(elf="e_phoff"))),
            step("load", "A loadable segment",
                 {"elf": "A `PT_LOAD` entry describes one mapping. Compare `p_filesz` and `p_memsz`: where the second is larger, the difference is zero-filled memory."},
                 show=lc(elf=["PT_LOAD"])),
            step("shoff", "The table tools read",
                 {"elf": "`e_shoff` is the file offset of the [[section-header|section header]] table. Linkers and debuggers use it. A program runs without it, and stripped or packed files sometimes have none."},
                 show=hfield(elf="e_shoff")),
            step("text", "A section inside a segment",
                 {"elf": "`.text` is a section. Its bytes lie inside an executable `PT_LOAD` segment; the tree shows it under that segment. The section header's `sh_addr` and `sh_offset` must agree with the segment that covers it."},
                 show=section(elf=[".text"], part="header")),
            step("interp", "Static or dynamic",
                 {"elf": "Whether a dynamic linker is involved is decided by one program header."},
                 task=task("dynamic", "choice", {"elf": "Does this file ask for a dynamic linker?"},
                           "{answer}: an executable that needs a dynamic linker names it in a `PT_INTERP` program header. Statically linked executables have none, and neither do most shared libraries.",
                           calc="is_dynamic")),
            step("dynamic", "The dynamic section",
                 {"elf": "`PT_DYNAMIC` locates the `.dynamic` table. From it the dynamic linker finds the needed libraries, the symbol and string tables and the relocations, without ever reading a section header."},
                 show=lc(elf=["PT_DYNAMIC"])),
        ],
    ),

    # =========================================================================== level 3
    tour(
        "follow-an-import", "Follow an import", 3, 8,
        "From the list of required libraries to the pointer slot that a call goes through.",
        ALL, concepts=["shared-libraries", "got-plt", "lazy-binding", "relro"],
        requires={"kind": "import_slot"},
        steps=[
            step("dynamic", "A dynamically linked file",
                 {"macho": "An executable that uses shared libraries names a dynamic linker to load them.",
                  "elf": "An executable that uses shared libraries names a dynamic linker to load them."},
                 task=task("dynamic", "choice", "Does this file ask for a dynamic linker?",
                           {"macho": "{answer}: an executable asks for one with an `LC_LOAD_DYLINKER` command. A library has none; the dyld of the process that uses it loads it.",
                            "elf": "{answer}: an executable asks for one with a `PT_INTERP` program header. A shared library normally has none; the dynamic linker of the process that uses it loads it."},
                           calc="is_dynamic")),
            step("libs", "The libraries it needs",
                 {"macho": "Each `LC_LOAD_DYLIB` command names one library by its install name. The first is `{first_lib}`.",
                  "elf": "The dynamic section lists one `DT_NEEDED` entry per library. The first is `{first_lib}`.",
                  "pe": "The import directory has one descriptor per DLL. The first is `{first_lib}`."},
                 show=lc(macho=["LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB"], elf=["PT_DYNAMIC"], pe=["DATA_DIR_IMPORT_TABLE"]),
                 task=task("count", "value",
                           "How many libraries does this file ask the loader for? The Overview lists them.",
                           "{answer}. Each of them may need further libraries of its own.",
                           calc="library_count")),
            step("slots", "One slot per import",
                 {"macho": "This view lists the stubs and pointer slots, and the symbol each belongs to. Code calls a stub; the stub jumps through its slot in the [[got|GOT]].",
                  "elf": "This view lists the [[got|GOT]] slots that relocations will fill, and the symbol each belongs to. Code calls a [[plt|PLT]] entry, which jumps through its slot.",
                  "pe": "This view lists the slots of the [[iat|import address table]] and the function each belongs to. Code calls through the slot directly."},
                 show=view("dysymtab")),
            step("slot", "The slot itself",
                 "A slot is one pointer: eight bytes in a 64-bit file, four in a 32-bit one. On disk it does not yet "
                 "hold the function's address. The loader writes the address of the imported function there.",
                 task=task("slot", "bytes",
                           "Click a byte of the first import pointer slot in the hex view. The slots view gives its address; the Translate bar converts it.",
                           "The first slot is at file offset {answer}.",
                           target=import_slot())),
            step("which", "Which library provides it",
                 {"macho": "Mach-O records, for every imported symbol, which library it must come from ([[two-level-namespace|two-level namespace]]).",
                  "elf": "ELF does not record which library provides a symbol; the dynamic linker searches the loaded libraries in order. The one hint in the file is symbol versioning: for a versioned symbol, the version-needs table (`.gnu.version_r`) names the library the linker found that version in. This tool shows that library where it is recorded and leaves the column empty where it is not.",
                  "pe": "PE groups imports by DLL: each import descriptor has its own lookup table and its own run of slots."},
                 task=task("lib", "choice",
                           {"macho": "Which library is `{symbol}` imported from?", "pe": "Which DLL is `{symbol}` imported from?"},
                           "`{answer}`. The Imports tab of the fixups view shows the library for every symbol.",
                           calc="import_library")),
            step("bind", "Filling the slots",
                 {"macho": "The [[fixup|fixups]] say what goes in each slot. With [[chained-fixups|chained fixups]] the slot itself holds, on disk, the index of the import and the distance to the next fixup.",
                  "elf": "The relocations say what goes in each slot: `JUMP_SLOT` for PLT slots, `GLOB_DAT` for other GOT entries.",
                  "pe": "The loader reads the lookup table of each DLL and writes the address of each function into the matching slot of the IAT."},
                 show=view("dyld_info")),
            step("lock", "Locking the table",
                 {"macho": "If the slots are in a segment flagged `SG_READ_ONLY`, dyld makes it read-only when it is done.",
                  "elf": "If the file has `PT_GNU_RELRO` and binds everything at load ([[bind-now|bind now]]), the slots become read-only when the dynamic linker is done.",
                  "pe": "The IAT directory entry tells the loader which range to unprotect while it binds; afterwards the table is as read-only as the section it lies in."},
                 show=view("security_audit")),
        ],
    ),
    tour(
        "hardening-audit", "A hardening audit by hand", 3, 8,
        "Check position independence, non-executable memory, canaries, read-only tables, control-flow protection and the signature yourself, then compare with the tool.",
        ALL, concepts=["mitigations-overview", "aslr", "nx-wx", "stack-canaries", "relro", "cfi", "code-signing"],
        steps=[
            step("pie", "Can it be moved?",
                 {"macho": "Address randomisation of the main program needs a position-independent executable. In Mach-O that is the header flag `MH_PIE` (`0x200000`).",
                  "elf": "Address randomisation of the main program needs a position-independent executable. In ELF that is the file type: `ET_DYN` (3) rather than `ET_EXEC` (2).",
                  "pe": "Address randomisation needs the `DYNAMIC_BASE` bit (`0x0040`) in `DllCharacteristics`, and base relocations to apply."},
                 show=hfield(macho="flags", elf="e_type", pe="OptionalHeader.DllCharacteristics"),
                 task=task("pie", "choice", PIE_PROMPT,
                           {"macho": "{answer}. Read the field: the tool's decoded flags are next to the raw value.",
                            "elf": "{answer}. Read the field: the tool's decoded value is next to the raw one.",
                            "pe": "{answer}. Read `DllCharacteristics` for `DYNAMIC_BASE`, and `Characteristics` in the file header for `IMAGE_FILE_RELOCS_STRIPPED`: an image without relocations cannot be moved."},
                           calc="is_pie")),
            step("nx", "Is any memory writable and executable?",
                 "Check the permissions of every segment. Code should be `r-x`, data `rw-` or `r--`. A segment "
                 "with both `w` and `x` deserves an explanation.",
                 show=view("segments")),
            step("stack", "Is the stack executable?",
                 {"pe": "`NX_COMPAT` (`0x0100`) in `DllCharacteristics` declares a 32-bit image compatible with DEP. 64-bit processes always have it.",
                  "macho": "The header flag `MH_ALLOW_STACK_EXECUTION` (`0x20000`) asks for executable stacks. It is almost never set, and XNU honours it only where code-signing enforcement is off: on Apple silicon it has no effect."},
                 show={"kind": "field", "where": "header", "name": {"macho": "flags", "pe": "OptionalHeader.DllCharacteristics"}}),
            step("stack-elf", "Is the stack executable?",
                 {"elf": "`PT_GNU_STACK` carries the answer in `p_flags`: 6 (`rw-`) is the normal value; 7 would make the stack executable."},
                 show=lc(elf=["PT_GNU_STACK"], field="p_flags")),
            step("canary", "Stack canaries",
                 {"macho": "Filter the symbols for `stack_chk`. An undefined `___stack_chk_fail` or `___stack_chk_guard` means at least one function is protected by a [[stack-canary|canary]].",
                  "elf": "Filter the symbols for `stack_chk`. An undefined `__stack_chk_fail` means at least one function is protected by a [[stack-canary|canary]].",
                  "pe": "MSVC's cookie check is linked statically, so there is no import to look for. The evidence is the load configuration directory, which records the cookie's address."},
                 show=view("symtab")),
            step("relro", "Read-only pointer tables",
                 {"elf": "Look for a `PT_GNU_RELRO` program header. With bind-now as well, the protection is complete (full RELRO).",
                  "pe": "Check which section the IAT lies in: the IAT directory gives its RVA. In `.rdata` it is read-only after loading."},
                 show={"kind": "lc", "cmd": {"elf": ["PT_GNU_RELRO"], "pe": ["DATA_DIR_IAT"]}}),
            step("relro-macho", "Read-only pointer tables",
                 {"macho": "Look for a `__DATA_CONST` segment whose flags include `SG_READ_ONLY` (`0x10`)."},
                 show=segment("name", name={"macho": "__DATA_CONST"}, field={"macho": "flags"})),
            step("cfi", "Control-flow protection",
                 "Look at the first instructions of the entry function. `endbr64` is a landing pad for Intel CET; "
                 "`paciasp` signs the return address (ARM pointer authentication); `bti` is an ARM landing pad. "
                 "Their presence shows what the compiler was asked for, not what the system enforces.",
                 show=entry()),
            step("sig", "The signature",
                 {"macho": "A Mach-O signature is a table of page hashes. Check whether it is ad-hoc (no certificate) and which flags it carries.",
                  "pe": "An Authenticode signature is a PKCS #7 blob at the end of the file. Its presence says who signed the file, not what the file does."},
                 show=signature()),
            step("audit", "Compare",
                 "The Hardening view runs the same checks. Where it and you disagree, look at the bytes again: "
                 "the view states which field each conclusion comes from.",
                 show=view("security_audit")),
        ],
    ),
    tour(
        "signature", "Inside a code signature", 3, 5,
        "Where the signature is, how it is located, and what it covers.",
        ["macho", "pe"], concepts=["code-signing", "authenticode"], requires=signature(),
        steps=[
            step("locate", "How the signature is located",
                 {"macho": "`LC_CODE_SIGNATURE` gives the offset and size of the signature inside `__LINKEDIT`. It is always the last thing in the file, because it covers everything before it.",
                  "pe": "Data directory 4 gives the position and size of the certificate table. Its first field is a file offset, not an RVA: the signature lies outside every section and is not mapped."},
                 show=lc(macho=["LC_CODE_SIGNATURE"], pe=["DATA_DIR_CERTIFICATE_TABLE"])),
            step("blob", "The signature data",
                 {"macho": "The blob starts with the magic `fa de 0c c0`. Every number in it is big-endian, unlike the rest of the file.",
                  "pe": "The table starts with a `WIN_CERTIFICATE` header: a length, a revision and a type, followed by the PKCS #7 data."},
                 task=task("blob", "bytes", "Click the first byte of the signature data in the hex view.",
                           "It starts at file offset {answer}.",
                           target=signature())),
            step("decoded", "What it contains",
                 {"macho": "The CodeDirectory lists one hash per page of the file. Its own hash, the [[cdhash]], identifies this exact build. The entitlements are the privileges the program asks for.",
                  "pe": "The PKCS #7 structure holds the digest of the file, the signer's certificate chain and usually a timestamp."},
                 show=view("code_signature")),
            step("covers", "What it covers",
                 {"macho": "Each page of the file up to the signature has a hash in the CodeDirectory. Change one byte anywhere and that page no longer matches; the file must be signed again before a system that enforces signatures will run it.",
                  "pe": "The digest covers the whole file except the `CheckSum` field, the certificate table's directory entry and the certificate table itself."}),
        ],
    ),
]


def by_id() -> Dict[str, Dict[str, Any]]:
    return {t["id"]: t for t in TOURS}
