"""
Layer 4B: Systems Pedagogy & Interactive Format Learning Engine.
Provides:
1. Interactive 6-Stage OS Loader & Execution Lifecycle Simulator (`loader_lifecycle`)
2. 10-Row Cross-Format Rosetta Stone Comparative Matrix (`rosetta_stone`)
3. Contextual Field Deep-Dive & "What-If" Patching Catalog (`annotate_slice_pedagogy`)
4. 4 Interactive Guided Learning Tours with Live Micro-Challenges (`guided_tours`)
"""

from typing import Any, Dict, List, Optional

FIELD_PEDAGOGY_CATALOG: Dict[str, Dict[str, Any]] = {
    # Mach-O Header & Load Command Fields
    "magic": {
        "why_it_matters": "First 4 bytes read by the OS kernel during execve() to identify the binary format, bitness (32 vs 64), and byte endianness.",
        "loader_behavior": "XNU's exec_mach_imgact() checks for 0xFEEDFACF (64-bit), 0xFEEDFACE (32-bit), or 0xCAFEBABE (Universal Fat).",
        "what_if_modified": "Changing even 1 bit causes the kernel to reject execution immediately with ENOEXEC ('Exec format error').",
        "cross_format_peer": "ELF: e_ident[0..3] (\\x7fELF) • PE: IMAGE_DOS_HEADER.e_magic ('MZ' 0x5A4D) + NT Signature ('PE\\0\\0').",
    },
    "cputype": {
        "why_it_matters": "Specifies the target CPU instruction set architecture (e.g., ARM64, x86_64, ARMv7, PowerPC).",
        "loader_behavior": "The kernel verifies hardware compatibility (or routes x86_64 binaries to Rosetta 2 on Apple Silicon).",
        "what_if_modified": "Setting an unsupported cputype causes execve() to fail with EBADARCH ('Bad CPU type in executable').",
        "cross_format_peer": "ELF: Elf_Ehdr.e_machine (EM_X86_64 / EM_AARCH64) • PE: IMAGE_FILE_HEADER.Machine (0x8664 / 0xAA64).",
    },
    "cpusubtype": {
        "why_it_matters": "Refines the CPU model and ABI security capabilities—most notably ARM64E (0x80000002) for hardware Pointer Authentication (PAC).",
        "loader_behavior": "When ARM64E is set, XNU enables PAC keys (IA/IB/DA/DB) in system registers and dyld verifies signed pointer chains.",
        "what_if_modified": "Downgrading arm64e to arm64 (0x0) on a binary with PAC instructions causes paciasp/retaa or authenticated fixups to fault.",
        "cross_format_peer": "ELF: e_flags + .note.gnu.property (AArch64 PAC/BTI, Intel CET) • PE: DllCharacteristics (GUARD_CF).",
    },
    "filetype": {
        "why_it_matters": "Distinguishes main executables (MH_EXECUTE) from shared libraries (MH_DYLIB), bundles, object files (MH_OBJECT), and standalone firmware (MH_PRELOAD).",
        "loader_behavior": "Only MH_EXECUTE can be launched directly via execve(); MH_DYLIB is mapped by dyld; MH_PRELOAD is loaded by bootloaders/iBoot.",
        "what_if_modified": "Changing MH_EXECUTE (0x2) to MH_DYLIB (0x6) prevents direct execution from the shell.",
        "cross_format_peer": "ELF: e_type (ET_EXEC / ET_DYN / ET_REL) • PE: FileHeader.Characteristics (IMAGE_FILE_EXECUTABLE_IMAGE / IMAGE_FILE_DLL).",
    },
    "ncmds": {
        "why_it_matters": "Count of Load Commands immediately following the Mach-O header that instruct the kernel and dyld how to map and link the binary.",
        "loader_behavior": "The loader loops `ncmds` times starting at offset 32 (64-bit) or 28 (32-bit), bounded by `sizeofcmds`.",
        "what_if_modified": "Decreasing ncmds hides trailing load commands (like LC_CODE_SIGNATURE or LC_SYMTAB) from naive parsers.",
        "cross_format_peer": "ELF: e_phnum (Program Headers count) • PE: FileHeader.NumberOfSections + OptionalHeader.NumberOfRvaAndSizes.",
    },
    "sizeofcmds": {
        "why_it_matters": "Total byte length of all Load Commands following the Mach-O header.",
        "loader_behavior": "XNU verifies that `sizeof(mach_header) + sizeofcmds` does not exceed the first mapped __TEXT segment.",
        "what_if_modified": "Mismatching sizeofcmds and actual load command sizes causes the kernel or dyld to abort with a malformed Mach-O error.",
        "cross_format_peer": "ELF: e_phnum * e_phentsize • PE: OptionalHeader.SizeOfHeaders.",
    },
    "flags": {
        "why_it_matters": "Bitmask controlling ASLR (MH_PIE), two-level symbol namespaces (MH_TWOLEVEL), stack/heap NX, and section flags.",
        "loader_behavior": "The kernel checks MH_PIE to randomize the load slide and MH_ALLOW_STACK_EXECUTION to configure stack page permissions.",
        "what_if_modified": "Clearing MH_PIE (0x200000) disables ASLR so the binary loads at its static preferred vmaddr on every run.",
        "cross_format_peer": "ELF: e_type (ET_DYN) + DT_FLAGS_1 (DF_1_PIE) • PE: OptionalHeader.DllCharacteristics (DYNAMIC_BASE / NX_COMPAT).",
    },
    "vmaddr": {
        "why_it_matters": "Preferred Virtual Memory Address where this segment or section is mapped in the process's address space.",
        "loader_behavior": "The OS adds the random ASLR slide to `vmaddr` and maps the segment pages into the process page tables.",
        "what_if_modified": "Unaligned vmaddr values (not a multiple of 4KB/16KB page size) cause the kernel VM mapper to reject the binary.",
        "cross_format_peer": "ELF: Elf_Phdr.p_vaddr / Elf_Shdr.sh_addr • PE: ImageBase + Section.VirtualAddress.",
    },
    "vmsize": {
        "why_it_matters": "Total bytes reserved in Virtual Memory for this segment (must be >= filesize; any excess is zero-filled .bss memory).",
        "loader_behavior": "Pages beyond `filesize` up to `vmsize` are backed by demand-zero anonymous RAM pages.",
        "what_if_modified": "Setting vmsize < filesize truncates mapped data or triggers a kernel loader validation failure.",
        "cross_format_peer": "ELF: Elf_Phdr.p_memsz • PE: IMAGE_SECTION_HEADER.VirtualSize.",
    },
    "fileoff": {
        "why_it_matters": "Physical byte offset inside the binary file (or Fat slice) where this segment's contents begin on disk.",
        "loader_behavior": "The kernel mmap()s `filesize` bytes starting at `fileoff` into virtual address `vmaddr + slide`.",
        "what_if_modified": "Shifting fileoff causes the CPU to execute wrong bytes or shifts all string/symbol references out of alignment.",
        "cross_format_peer": "ELF: Elf_Phdr.p_offset • PE: IMAGE_SECTION_HEADER.PointerToRawData.",
    },
    "filesize": {
        "why_it_matters": "Number of initialized bytes read from disk for this segment.",
        "loader_behavior": "Defines the exact disk span `[fileoff, fileoff + filesize)` mapped into memory.",
        "what_if_modified": "Increasing filesize past EOF causes a bus error (SIGBUS) or loader rejection.",
        "cross_format_peer": "ELF: Elf_Phdr.p_filesz • PE: IMAGE_SECTION_HEADER.SizeOfRawData.",
    },
    "initprot": {
        "why_it_matters": "Initial virtual memory page permissions (R=1, W=2, X=4) applied when the segment is first mapped.",
        "loader_behavior": "Hardware MMU page table entries are programmed with these R/W/X bits before user code runs.",
        "what_if_modified": "Setting both Write (2) and Execute (4) -> 0x7 (RWX) violates W^X and creates an injectable code region.",
        "cross_format_peer": "ELF: Elf_Phdr.p_flags (PF_R=4, PF_W=2, PF_X=1) • PE: IMAGE_SECTION_HEADER.Characteristics (MEM_READ/WRITE/EXECUTE).",
    },
    "maxprot": {
        "why_it_matters": "Ceiling on virtual memory permissions that userland mprotect() calls are ever allowed to request for this segment.",
        "loader_behavior": "XNU's VM map enforces `requested_prot <= maxprot`; mprotect() cannot add Execute permission if maxprot lacks VM_PROT_EXECUTE.",
        "what_if_modified": "Raising __DATA.maxprot to RWX allows runtime mprotect() to make data pages executable.",
        "cross_format_peer": "ELF: p_flags (controlled by kernel PaX/SELinux) • PE: VirtualProtect() governed by Arbitrary Code Guard (ACG).",
    },
    # ELF Fields
    "e_ident[EI_MAG]": {
        "why_it_matters": "4-byte ELF magic signature (0x7F followed by ASCII 'E', 'L', 'F') identifying an Executable and Linkable Format binary.",
        "loader_behavior": "Linux `fs/binfmt_elf.c` checks `memcmp(e_ident, \"\\x7fELF\", 4) == 0` before parsing Elf_Ehdr.",
        "what_if_modified": "Corrupting these 4 bytes makes the Linux kernel fall back to shell script execution or fail with ENOEXEC.",
        "cross_format_peer": "Mach-O: magic (0xFEEDFACF) • PE: IMAGE_DOS_HEADER.e_magic ('MZ' 0x5A4D).",
    },
    "e_type": {
        "why_it_matters": "Defines whether the ELF file is Relocatable (ET_REL=1), Fixed Executable (ET_EXEC=2), Shared/PIE (ET_DYN=3), or Core Dump (ET_CORE=4).",
        "loader_behavior": "Modern PIE executables use ET_DYN (3) so the kernel can relocate them at a random ASLR base address just like a shared library!",
        "what_if_modified": "Changing ET_DYN (3) to ET_EXEC (2) disables kernel ASLR base randomization.",
        "cross_format_peer": "Mach-O: filetype (MH_EXECUTE + MH_PIE) • PE: Characteristics + DllCharacteristics (DYNAMIC_BASE).",
    },
    "e_entry": {
        "why_it_matters": "Virtual memory address of `_start`, where the C runtime initializes the stack and calls `__libc_start_main(main)`.",
        "loader_behavior": "If PT_INTERP is present, the kernel jumps to `ld-linux.so` first and passes `e_entry` in the auxiliary vector (`AT_ENTRY`).",
        "what_if_modified": "Redirecting e_entry to another function runs custom code before `_start` and `main()`.",
        "cross_format_peer": "Mach-O: LC_MAIN.entryoff / LC_UNIXTHREAD • PE: OptionalHeader.AddressOfEntryPoint.",
    },
    "e_phoff": {
        "why_it_matters": "File offset to the Program Header Table (`Elf_Phdr`), which tells the OS kernel how to map segments into RAM.",
        "loader_behavior": "The Linux kernel ONLY requires `e_phoff` (Program Headers) to execute a binary; Section Headers (`e_shoff`) are completely ignored by the kernel!",
        "what_if_modified": "Corrupting e_phoff breaks execution; whereas zeroing e_shoff leaves the binary runnable while blinding naive debuggers.",
        "cross_format_peer": "Mach-O: Load Commands at offset 32 • PE: Section Table after OptionalHeader.",
    },
    "e_shoff": {
        "why_it_matters": "File offset to the Section Header Table (`Elf_Shdr`), used by linkers (`ld`), debuggers (`gdb`), and static analysis tools.",
        "loader_behavior": "Ignored by the OS kernel during `execve()`, but essential for resolving `.symtab`, `.shstrtab`, and fine-grained sections.",
        "what_if_modified": "Zeroing e_shoff and e_shnum strips section metadata (an anti-reverse-engineering technique) without stopping the program from running.",
        "cross_format_peer": "Mach-O: section_64 structs nested inside LC_SEGMENT_64 • PE: IMAGE_SECTION_HEADER table.",
    },
    "p_type": {
        "why_it_matters": "Identifies the role of an ELF Program Header (`PT_LOAD` maps memory, `PT_INTERP` names ld.so, `PT_GNU_RELRO` locks GOT read-only).",
        "loader_behavior": "The kernel iterates all `PT_LOAD` entries to `mmap()` file ranges and checks `PT_GNU_STACK` to set stack NX.",
        "what_if_modified": "Changing `PT_GNU_RELRO` to `PT_NULL` disables RELRO protection, leaving the GOT writable at runtime.",
        "cross_format_peer": "Mach-O: Load Command `cmd` (LC_SEGMENT_64, LC_LOAD_DYLINKER) • PE: Data Directories & Section Headers.",
    },
    "p_flags": {
        "why_it_matters": "Bitmask of segment memory permissions: PF_X (0x1 Execute), PF_W (0x2 Write), PF_R (0x4 Read).",
        "loader_behavior": "Translated directly into `PROT_READ | PROT_WRITE | PROT_EXEC` when the kernel maps the segment or stack.",
        "what_if_modified": "Setting PF_X (0x1) on `PT_GNU_STACK` makes the entire process stack executable!",
        "cross_format_peer": "Mach-O: initprot / maxprot • PE: IMAGE_SECTION_HEADER.Characteristics.",
    },
    # PE Fields
    "e_lfanew": {
        "why_it_matters": "4-byte file offset at `0x3C` in the MS-DOS header that points past the DOS stub to the modern `IMAGE_NT_HEADERS` (`PE\\0\\0`).",
        "loader_behavior": "Windows `MmCreateSection` reads `MZ` at 0x0, then immediately seeks to `e_lfanew` to validate `PE\\0\\0`.",
        "what_if_modified": "Pointing e_lfanew to 0x10 allows creating ultra-tiny 'folded' PE files where the NT header overlaps the DOS header.",
        "cross_format_peer": "Mach-O: fat_arch.offset (in Universal binaries) • ELF: e_phoff.",
    },
    "OptionalHeader.AddressOfEntryPoint": {
        "why_it_matters": "Relative Virtual Address (RVA) of the binary's entry point (`mainCRTStartup`, `WinMainCRTStartup`, or `DllMain`).",
        "loader_behavior": "After `ntdll!LdrInitializeThunk` resolves imports and runs TLS callbacks, it jumps to `ImageBase + AddressOfEntryPoint`.",
        "what_if_modified": "Packers like UPX redirect AddressOfEntryPoint to a decompression stub at the end of the file.",
        "cross_format_peer": "Mach-O: LC_MAIN.entryoff • ELF: Elf_Ehdr.e_entry.",
    },
    "OptionalHeader.ImageBase": {
        "why_it_matters": "Preferred base virtual address in memory (`0x140000000` for 64-bit EXEs, `0x00400000` for 32-bit EXEs).",
        "loader_behavior": "If ASLR (`DYNAMIC_BASE`) moves the binary to a different base, `ntdll` applies `.reloc` base relocations using `ActualBase - ImageBase`.",
        "what_if_modified": "Changing ImageBase without updating `.reloc` causes absolute pointers to dereference unmapped memory if ASLR is off.",
        "cross_format_peer": "Mach-O: __TEXT.vmaddr (0x100000000) • ELF: First PT_LOAD.p_vaddr (0x400000 or 0x0).",
    },
    "OptionalHeader.DllCharacteristics": {
        "why_it_matters": "Security mitigation bitmask controlling ASLR (`DYNAMIC_BASE`), 64-bit High-Entropy ASLR, DEP (`NX_COMPAT`), and Control Flow Guard (`GUARD_CF`).",
        "loader_behavior": "Inspected by the Windows kernel memory manager when creating the image section and configuring process exploit mitigations.",
        "what_if_modified": "Clearing `0x0040` (`DYNAMIC_BASE`) disables ASLR; clearing `0x0100` (`NX_COMPAT`) disables DEP.",
        "cross_format_peer": "Mach-O: mach_header.flags (MH_PIE) • ELF: DT_FLAGS_1 + PT_GNU_STACK + .note.gnu.property.",
    },
}


def annotate_slice_pedagogy(slice_doc: Dict[str, Any]) -> None:
    """
    Attaches `pedagogy` deep-dive explanations to matching StructFields in header,
    load_commands, and segments/sections.
    """
    field_lists: List[List[Dict[str, Any]]] = [slice_doc.get("header", {}).get("fields", [])]
    for lc in slice_doc.get("load_commands", []):
        field_lists.append(lc.get("fields", []))
    for seg in slice_doc.get("segments", []):
        field_lists.append(seg.get("fields", []))
        for sect in seg.get("sections", []):
            field_lists.append(sect.get("fields", []))

    for flist in field_lists:
        for f_obj in flist:
            fname = f_obj.get("name", "")
            if fname in FIELD_PEDAGOGY_CATALOG:
                f_obj["pedagogy"] = FIELD_PEDAGOGY_CATALOG[fname]


def build_loader_lifecycle(slice_doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Synthesizes a 6-stage interactive OS Loader & Execution Lifecycle walkthrough
    parameterized with the active binary's real addresses, offsets, segments, and symbols.
    """
    fmt = slice_doc.get("format", "macho").lower()
    ov = slice_doc.get("overview", {})
    hdr = slice_doc.get("header", {})
    segs = slice_doc.get("segments", [])
    dylibs = slice_doc.get("dylibs", [])
    ep = slice_doc.get("entry_point", {})
    sec = slice_doc.get("security_posture", {})
    base_off = slice_doc.get("slice_base_offset", 0)

    first_exec_seg = next((s for s in segs if "x" in s.get("initprot", "").lower()), segs[0] if segs else None)
    first_data_seg = next((s for s in segs if "w" in s.get("initprot", "").lower()), segs[-1] if segs else None)
    ep_vm = ep.get("vmaddr", "0x0")
    ep_off = ep.get("abs_offset", base_off)
    fixups_cnt = len((slice_doc.get("dyld_info", {}).get("chained_fixups") or {}).get("fixups", []))
    imports_cnt = len((slice_doc.get("dyld_info", {}).get("chained_fixups") or {}).get("imports", []))

    if fmt == "elf":
        interp = slice_doc.get("elf_metadata", {}).get("interpreter") or "/lib64/ld-linux-x86-64.so.2 (or static)"
        loader_name = f"Linux Kernel (fs/binfmt_elf.c) + {interp}"
        slide_val = "0x0000555555554000" if sec.get("pie") else "0x0 (ET_EXEC Fixed Base)"
        stages = [
            {
                "stage_id": 1,
                "id": "kernel_validation",
                "title": "1. ELF Magic & Kernel Header Handshake",
                "actor": "Linux Kernel • load_elf_binary()",
                "syscall": "execve() -> fs/binfmt_elf.c",
                "summary": f"Kernel verifies \\x7fELF magic at 0x0, confirms {hdr.get('magic_name')} for {ov.get('arch_display')}, and locates {hdr.get('ncmds')} Program Headers at e_phoff.",
                "abs_offset": base_off,
                "size": hdr.get("region", {}).get("size", 64),
                "vmaddr": first_exec_seg["vmaddr"] if first_exec_seg else "0x0",
                "node_id": "mach_header",
                "state_badge": "Ring 0 • Ehdr Validated",
                "what_could_fail": "If e_ident != \\x7fELF or e_machine mismatches the host CPU (without qemu-user/binfmt_misc), execve() returns -ENOEXEC.",
            },
            {
                "stage_id": 2,
                "id": "segment_mapping",
                "title": "2. PT_LOAD Virtual Memory Mapping & .bss Zero-Fill",
                "actor": "Linux Kernel • elf_map()",
                "syscall": "vm_mmap() per PT_LOAD",
                "summary": f"Kernel iterates PT_LOAD program headers and mmap()s {len(segs)} loadable segment(s) into virtual memory (primary code segment {first_exec_seg['segname'] if first_exec_seg else 'LOAD'} @ {first_exec_seg['vmaddr'] if first_exec_seg else '0x0'}).",
                "abs_offset": first_exec_seg["abs_offset"] if first_exec_seg else base_off,
                "size": first_exec_seg["filesize"] if first_exec_seg else 64,
                "vmaddr": first_exec_seg["vmaddr"] if first_exec_seg else "0x0",
                "node_id": "segments",
                "state_badge": f"ASLR Bias: {slide_val}",
                "what_could_fail": "Unaligned p_vaddr != p_offset (mod PAGE_SIZE) or overlapping PT_LOAD ranges cause elf_map() to abort with -EINVAL / SIGKILL.",
            },
            {
                "stage_id": 3,
                "title": "3. Interpreter Bootstrap & Auxiliary Vector (auxv)",
                "id": "loader_bootstrap",
                "actor": f"Dynamic Linker • {interp}",
                "syscall": "load_elf_interp() + create_elf_tables()",
                "summary": f"Kernel maps PT_INTERP ({interp}) into RAM, pushes argc, argv, envp, and the ELF Auxiliary Vector (AT_PHDR, AT_ENTRY={ep_vm}, AT_RANDOM stack canary seed) onto the initial stack.",
                "abs_offset": base_off + 64,
                "size": max(56, hdr.get("sizeofcmds", 64)),
                "vmaddr": ep_vm,
                "node_id": "load_commands",
                "state_badge": f"AT_ENTRY = {ep_vm}",
                "what_could_fail": "If the PT_INTERP path is missing on disk, execve() fails with misleading 'No such file or directory' (ENOENT) even though the executable exists!",
            },
            {
                "stage_id": 4,
                "id": "relocations_binding",
                "title": "4. Dynamic Linking (.dynamic) & GOT/PLT Relocations",
                "actor": "ld-linux.so • _dl_relocate_object()",
                "syscall": "DT_NEEDED + .rela.dyn / .rela.plt",
                "summary": f"Dynamic loader loads {len(dylibs)} DT_NEEDED shared libraries ({', '.join(d['name'] for d in dylibs[:3]) or 'none'}) and processes {fixups_cnt} relocation entries ({imports_cnt} imported symbols) into .got / .got.plt.",
                "abs_offset": first_data_seg["abs_offset"] if first_data_seg else base_off,
                "size": 64,
                "vmaddr": first_data_seg["vmaddr"] if first_data_seg else "0x0",
                "node_id": "dyld_info",
                "state_badge": f"{fixups_cnt} Relocs • {imports_cnt} Imports",
                "what_could_fail": "Missing DT_NEEDED library or unresolved R_*_GLOB_DAT / R_*_JUMP_SLOT symbol aborts startup with 'symbol lookup error'.",
            },
            {
                "stage_id": 5,
                "id": "permission_lockdown",
                "title": "5. PT_GNU_RELRO Lockdown & Stack NX Enforcement",
                "actor": "ld-linux.so • _dl_protect_relro()",
                "syscall": "mprotect(RELRO, PROT_READ)",
                "summary": "After relocations finish, ld.so calls mprotect(PROT_READ) on the PT_GNU_RELRO region so the Global Offset Table (.got) cannot be overwritten at runtime.",
                "abs_offset": base_off,
                "size": 64,
                "vmaddr": first_data_seg["vmaddr"] if first_data_seg else "0x0",
                "node_id": "security_audit",
                "state_badge": "RELRO Locked • Stack RW-",
                "what_could_fail": "Without Full RELRO (PT_GNU_RELRO + DF_BIND_NOW), .got.plt remains writable and vulnerable to GOT overwrite exploits.",
            },
            {
                "stage_id": 6,
                "id": "entry_handoff",
                "title": "6. Constructors (.init_array) & Transfer to e_entry (_start)",
                "actor": "Userland • _start -> __libc_start_main()",
                "syscall": f"jmp {ep_vm}",
                "summary": f"ld.so executes .init_array constructors, clears registers, and jumps to Ehdr.e_entry ({ep_vm} @ file offset 0x{ep_off:x}) to start execution.",
                "abs_offset": ep_off,
                "size": 32,
                "vmaddr": ep_vm,
                "node_id": "disassembly",
                "state_badge": f"PC/RIP = {ep_vm}",
                "what_could_fail": "Jumping to an unmapped or non-executable e_entry triggers an immediate SIGSEGV (SEGV_MAPERR / SEGV_ACCERR).",
            },
        ]
    elif fmt == "pe":
        pe_meta = slice_doc.get("pe_metadata", {})
        img_base = pe_meta.get("image_base", "0x140000000")
        loader_name = "Windows NT Kernel (MmCreateSection) + ntdll.dll!LdrInitializeThunk"
        slide_val = "Randomized High-Entropy Base" if sec.get("pie") else f"Fixed {img_base}"
        stages = [
            {
                "stage_id": 1,
                "id": "kernel_validation",
                "title": "1. DOS 'MZ' Stub Bridge & PE\\0\\0 NT Header Validation",
                "actor": "NT Kernel • MmCreateSection()",
                "syscall": "NtCreateUserProcess -> MmCreateSection",
                "summary": f"Windows kernel verifies 'MZ' (0x5A4D) at 0x0, follows e_lfanew to 0x{hdr.get('region', {}).get('abs_offset', 0x80):x}, and validates 'PE\\0\\0' + {hdr.get('magic_name')} ({ov.get('arch_display')}).",
                "abs_offset": hdr.get("region", {}).get("abs_offset", 0),
                "size": hdr.get("region", {}).get("size", 264),
                "vmaddr": img_base,
                "node_id": "mach_header",
                "state_badge": f"ImageBase = {img_base}",
                "what_could_fail": "Invalid e_lfanew or mismatched Machine / OptionalHeader.Magic aborts process creation with STATUS_INVALID_IMAGE_FORMAT (0xC000007B).",
            },
            {
                "stage_id": 2,
                "id": "segment_mapping",
                "title": "2. Section Alignment Expansion (FileAlignment -> SectionAlignment)",
                "actor": "NT Memory Manager • MiMapViewOfImageSection()",
                "syscall": "NtMapViewOfSection()",
                "summary": f"Kernel reserves SizeOfImage in virtual memory and expands {len(segs) - 1} PE section(s) from compact disk sectors (FileAlignment) to page-aligned virtual memory (SectionAlignment).",
                "abs_offset": first_exec_seg["abs_offset"] if first_exec_seg else 0,
                "size": first_exec_seg["filesize"] if first_exec_seg else 512,
                "vmaddr": first_exec_seg["vmaddr"] if first_exec_seg else img_base,
                "node_id": "segments",
                "state_badge": f"ASLR: {slide_val}",
                "what_could_fail": "Corrupted PointerToRawData or VirtualAddress ordering causes STATUS_INVALID_IMAGE_NOT_MZ / section mapping failure.",
            },
            {
                "stage_id": 3,
                "id": "loader_bootstrap",
                "title": "3. ntdll.dll Mapping, PEB/TEB Creation & Loader APC",
                "actor": "NT Kernel + ntdll.dll!LdrInitializeThunk",
                "syscall": "PspCreateThread -> KiUserApcDispatcher",
                "summary": "Unlike Unix (where the binary specifies its interpreter), Windows kernel always maps ntdll.dll, initializes the Process Environment Block (PEB), and queues an APC to LdrInitializeThunk.",
                "abs_offset": 0,
                "size": 64,
                "vmaddr": img_base,
                "node_id": "load_commands",
                "state_badge": "PEB->Ldr Initialized",
                "what_could_fail": "If ntdll.dll or required subsystem DLLs fail integrity verification, process terminates with STATUS_DLL_INIT_FAILED.",
            },
            {
                "stage_id": 4,
                "id": "relocations_binding",
                "title": "4. Base Relocations (.reloc) & Import Address Table (IAT) Snapping",
                "actor": "ntdll.dll • LdrRelocateImage + LdrpSnapModule",
                "syscall": "DATA_DIR_IMPORT_TABLE + BASE_RELOCATION_TABLE",
                "summary": f"Loader applies {fixups_cnt} base relocation entries for ASLR delta, loads {len(dylibs)} imported DLL(s) ({', '.join(d['name'] for d in dylibs[:3]) or 'none'}), walks OriginalFirstThunk (INT), and writes resolved pointers into FirstThunk (IAT).",
                "abs_offset": first_data_seg["abs_offset"] if first_data_seg else 0,
                "size": 64,
                "vmaddr": first_data_seg["vmaddr"] if first_data_seg else img_base,
                "node_id": "dyld_info",
                "state_badge": f"{imports_cnt} IAT Imports • {fixups_cnt} Relocs",
                "what_could_fail": "Missing DLL or unexported ordinal/function name raises STATUS_DLL_NOT_FOUND (0xC0000135) or STATUS_ENTRYPOINT_NOT_FOUND (0xC0000139).",
            },
            {
                "stage_id": 5,
                "id": "permission_lockdown",
                "title": "5. IAT Read-Only Restore, DEP (NX_COMPAT) & Control Flow Guard",
                "actor": "ntdll.dll • LdrpProtectAndVerifyImage",
                "syscall": "ZwProtectVirtualMemory()",
                "summary": "Loader restores .rdata / IAT pages to PAGE_READONLY, activates hardware DEP (NX_COMPAT), validates the Control Flow Guard (GUARD_CF) bitmap, and initializes the /GS SecurityCookie.",
                "abs_offset": hdr.get("region", {}).get("abs_offset", 0),
                "size": 64,
                "vmaddr": img_base,
                "node_id": "security_audit",
                "state_badge": "IAT Locked • DEP/CFG Active",
                "what_could_fail": "Indirect call to a non-whitelisted target when GUARD_CF is active triggers an immediate __fastfail() crash.",
            },
            {
                "stage_id": 6,
                "id": "entry_handoff",
                "title": "6. Pre-Main TLS Callbacks & Jump to AddressOfEntryPoint",
                "actor": "ntdll.dll -> TLS Callbacks -> AddressOfEntryPoint",
                "syscall": f"call {ep_vm}",
                "summary": f"Loader runs any registered IMAGE_DIRECTORY_ENTRY_TLS callbacks first, invokes DllMain(DLL_PROCESS_ATTACH), and transfers control to AddressOfEntryPoint ({ep_vm} @ file offset 0x{ep_off:x}).",
                "abs_offset": ep_off,
                "size": 32,
                "vmaddr": ep_vm,
                "node_id": "disassembly",
                "state_badge": f"RIP/EIP = {ep_vm}",
                "what_could_fail": "Malware and packers frequently hide anti-debug checks inside TLS Callbacks so they execute before a debugger stops at AddressOfEntryPoint!",
            },
        ]
    else:
        # Mach-O
        is_preload = (ov.get("filetype_name") == "MH_PRELOAD")
        loader_name = "Bare-Metal Firmware Bootloader (iBoot / SecureROM)" if is_preload else "macOS XNU Kernel (exec_mach_imgact) + /usr/lib/dyld"
        slide_val = "0x0 (MH_PRELOAD Fixed Base)" if is_preload else ("0x0000000104a20000 (ASLR Slide)" if sec.get("pie") else "0x0 (No MH_PIE)")
        stages = [
            {
                "stage_id": 1,
                "id": "kernel_validation",
                "title": "1. Universal Fat Slice Selection & mach_header Validation",
                "actor": "XNU Kernel • exec_mach_imgact()",
                "syscall": "execve() -> grade_binary()",
                "summary": f"Kernel selects the best architecture slice ({slice_doc.get('arch_name')}) at slice base 0x{base_off:x}, validates {hdr.get('magic_name')} ({ov.get('filetype_name')}), and checks {hdr.get('ncmds')} Load Commands ({hdr.get('sizeofcmds')} B).",
                "abs_offset": base_off,
                "size": hdr.get("region", {}).get("size", 32),
                "vmaddr": first_exec_seg["vmaddr"] if first_exec_seg else "0x100000000",
                "node_id": "mach_header",
                "state_badge": f"Slice {slice_doc.get('arch_name')} Selected",
                "what_could_fail": "If sizeofcmds overflows the header page or CPU subtype is unsupported, XNU aborts with EBADMACHO or EBADARCH.",
            },
            {
                "stage_id": 2,
                "id": "segment_mapping",
                "title": "2. __PAGEZERO Guard Trap & LC_SEGMENT_64 Virtual Mapping",
                "actor": "XNU Kernel • load_machfile() + load_segment()",
                "syscall": "vm_map_enter()",
                "summary": f"Kernel reserves 4GB unmapped __PAGEZERO guard (0x0..0x100000000) to trap NULL dereferences, applies ASLR slide, and maps {len(segs)} segment(s) with initprot/maxprot.",
                "abs_offset": first_exec_seg["abs_offset"] if first_exec_seg else base_off,
                "size": first_exec_seg["filesize"] if first_exec_seg else 64,
                "vmaddr": first_exec_seg["vmaddr"] if first_exec_seg else "0x100000000",
                "node_id": "segments",
                "state_badge": f"Slide: {slide_val}",
                "what_could_fail": "Any segment requesting initprot > maxprot or RWX without allow-jit entitlement is rejected by XNU VM.",
            },
            {
                "stage_id": 3,
                "id": "loader_bootstrap",
                "title": "3. Dynamic Linker Handoff (LC_LOAD_DYLINKER -> /usr/lib/dyld)",
                "actor": "Bootloader Direct Jump" if is_preload else "XNU -> /usr/lib/dyld (__dyld_start)",
                "syscall": "LC_UNIXTHREAD" if is_preload else "load_dylinker()",
                "summary": (
                    "Standalone MH_PRELOAD firmware skips dyld and initializes CPU registers directly from LC_UNIXTHREAD."
                    if is_preload
                    else f"XNU maps /usr/lib/dyld into the process address space and sets initial PC to dyld's entry point, passing the executable's mach_header ({first_exec_seg['vmaddr'] if first_exec_seg else '0x100000000'}) on the stack."
                ),
                "abs_offset": base_off + 32,
                "size": max(32, hdr.get("sizeofcmds", 128)),
                "vmaddr": first_exec_seg["vmaddr"] if first_exec_seg else "0x100000000",
                "node_id": "load_commands",
                "state_badge": "Firmware Direct" if is_preload else "dyld4 Bootstrapped",
                "what_could_fail": "Restricted binaries (__RESTRICT or CS_RUNTIME) strip DYLD_INSERT_LIBRARIES here to block dylib injection.",
            },
            {
                "stage_id": 4,
                "id": "relocations_binding",
                "title": "4. Chained Fixups, PAC Pointer Signing & Dylib Binding",
                "actor": "dyld4 • JustInTimeLoader",
                "syscall": "LC_DYLD_CHAINED_FIXUPS + LC_DYLD_EXPORTS_TRIE",
                "summary": f"dyld loads {len(dylibs)} dependent dylib(s) and walks {fixups_cnt} Chained Fixup pointer slots ({imports_cnt} imports), resolving symbols via ULEB128 Exports Tries and signing pointers with ARM64e PAC keys (IA/DA).",
                "abs_offset": first_data_seg["abs_offset"] if first_data_seg else base_off,
                "size": 64,
                "vmaddr": first_data_seg["vmaddr"] if first_data_seg else "0x100000000",
                "node_id": "dyld_info",
                "state_badge": f"{fixups_cnt} Fixups • {imports_cnt} Imports",
                "what_could_fail": "Missing dylib or missing symbol in target LC_DYLD_EXPORTS_TRIE triggers abort_with_payload(DYLD_EXIT_REASON_SYMBOL_MISSING).",
            },
            {
                "stage_id": 5,
                "id": "permission_lockdown",
                "title": "5. __DATA_CONST Read-Only Lockdown & CodeSign Page Verification",
                "actor": "dyld4 + XNU CodeSign Pager",
                "syscall": "mprotect(__DATA_CONST, VM_PROT_READ) + CS_CodeDirectory",
                "summary": "After populating __got and __objc_const inside __DATA_CONST, dyld locks __DATA_CONST down from RW- to R--. XNU verifies every 4KB/16KB code page against SHA-256 slots in LC_CODE_SIGNATURE on page fault.",
                "abs_offset": (slice_doc.get("code_signature_detail", {}).get("superblob_region") or {}).get("abs_offset", base_off),
                "size": (slice_doc.get("code_signature_detail", {}).get("superblob_region") or {}).get("size", 64),
                "vmaddr": first_exec_seg["vmaddr"] if first_exec_seg else "0x100000000",
                "node_id": "code_signature",
                "state_badge": "CDHash Verified • __DATA_CONST R--",
                "what_could_fail": "If even 1 byte of __TEXT was modified on disk without re-signing, the page fault handler delivers SIGKILL (Namespace CODESIGNING, Code 0x2 Invalid Page).",
            },
            {
                "stage_id": 6,
                "id": "entry_handoff",
                "title": f"6. Static Initializers & Jump to {ep.get('type', 'LC_MAIN')} ({ep_vm})",
                "actor": f"dyld4 -> {ep.get('type', 'LC_MAIN')}",
                "syscall": f"br / blr -> {ep_vm}",
                "summary": f"dyld runs Objective-C +load methods and C++ __mod_init_func initializers, then jumps to the entry point at {ep_vm} (file offset 0x{ep_off:x}).",
                "abs_offset": ep_off,
                "size": 32,
                "vmaddr": ep_vm,
                "node_id": "disassembly",
                "state_badge": f"PC = {ep_vm}",
                "what_could_fail": "On ARM64e, if the entry or return pointer PAC signature is corrupted, `autiasp` / `retaa` traps with EXC_BAD_ACCESS (PAC Authentication Failure).",
            },
        ]

    for st in stages:
        st["stage"] = st["stage_id"]
        st["binary_state"] = st["state_badge"]
        st["failure_mode"] = st["what_could_fail"]

    return {
        "format": fmt.upper(),
        "os_family": fmt.upper(),
        "os_loader_name": loader_name,
        "loader_name": loader_name,
        "simulated_aslr_slide": slide_val,
        "stages": stages,
    }


def build_rosetta_stone(slice_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Returns the 10-row Cross-Format Rosetta Stone comparative matrix between
    Mach-O, ELF, and Windows PE, enriched with live jump targets for the active binary.
    """
    fmt = slice_doc.get("format", "macho").lower()
    fmt_upper = fmt.upper()
    base_off = slice_doc.get("slice_base_offset", 0)
    hdr_reg = slice_doc.get("header", {}).get("region") or {"abs_offset": base_off, "size": 64}
    ep = slice_doc.get("entry_point", {})
    segs = slice_doc.get("segments", [])
    first_seg = segs[0] if segs else {"abs_offset": base_off, "vmaddr": "0x0"}

    rows = [
        {
            "id": "magic_container",
            "concept": "1. Magic & Container Header",
            "category": "headers",
            "macho": "`mach_header_64` (`0xFEEDFACF`) + optional Universal `fat_header` (`0xCAFEBABE`) wrapping multiple CPU slices.",
            "elf": "`Elf64_Ehdr` (`0x7F 'E' 'L' 'F'`) specifying class (32/64), endianness, OSABI, `e_phoff`, and `e_shoff`.",
            "pe": "`IMAGE_DOS_HEADER` (`MZ` `0x5A4D`) -> `e_lfanew` -> `IMAGE_NT_HEADERS` (`PE\\0\\0` + COFF + OptionalHeader).",
            "why": "Allows the OS kernel to validate file type and CPU architecture in O(1) time before allocating virtual memory.",
            "live_target": {"node_id": "mach_header", "abs_offset": hdr_reg.get("abs_offset", base_off), "label": f"Inspect {fmt.upper()} Header"},
        },
        {
            "id": "segments_vs_sections",
            "concept": "2. Loader Segments vs Linker Sections",
            "category": "headers",
            "macho": "Unified hierarchy: `LC_SEGMENT_64` (`__TEXT`, `__DATA`) directly contains an array of `section_64` structs (`__text`, `__cstring`).",
            "elf": "Dual parallel tables: `Elf_Phdr` (`PT_LOAD` segments used by kernel at runtime) vs `Elf_Shdr` (`.text`, `.rodata` sections used by linkers/debuggers).",
            "pe": "Section-driven: `IMAGE_SECTION_HEADER`s (`.text`, `.rdata`, `.data`) act as both loader segments (`SectionAlignment` 4KB) and disk chunks (`FileAlignment` 512B).",
            "why": "Hardware MMUs enforce R/W/X permissions at page granularity (4KB/16KB), so fine-grained compiler sections with matching permissions are grouped into page-aligned segments.",
            "live_target": {"node_id": "segments", "abs_offset": first_seg.get("abs_offset", base_off), "label": f"View {len(segs)} Mapped Segments"},
        },
        {
            "id": "null_guard_base",
            "concept": "3. Null-Pointer Guard & Preferred Base",
            "category": "headers",
            "macho": "Explicit 4GB `__PAGEZERO` segment (`vmaddr=0x0`, `prot=---`). Default 64-bit base: `0x100000000`.",
            "elf": "Kernel `mmap_min_addr` guard (`0x10000`). Default base: `0x400000` (`ET_EXEC`) or `0x0` + ASLR bias (`ET_DYN` PIE).",
            "pe": "Bottom 64KB (`0x0..0xFFFF`) reserved by NT kernel. Default `ImageBase`: `0x140000000` (PE32+ exe) or `0x00400000` (PE32).",
            "why": "Guarantees that dereferencing a NULL pointer (`0x0`) triggers an immediate hardware page fault (`SIGSEGV` / `STATUS_ACCESS_VIOLATION`).",
            "live_target": {"node_id": "segments", "abs_offset": base_off, "label": "Inspect Virtual Base"},
        },
        {
            "id": "entry_point",
            "concept": "4. Entry Point Specification",
            "category": "headers",
            "macho": "`LC_MAIN` (`entryoff` relative to `__TEXT`) for userland apps; `LC_UNIXTHREAD` (CPU register state) for `MH_PRELOAD` firmware.",
            "elf": "`Elf_Ehdr.e_entry` (Virtual Memory Address of `_start`, which invokes `__libc_start_main`).",
            "pe": "`OptionalHeader.AddressOfEntryPoint` (RVA relative to `ImageBase`, pointing to `mainCRTStartup` or `DllMain`).",
            "why": "Defines the exact instruction address where the OS loader transfers CPU control after memory mapping and dynamic linking complete.",
            "live_target": {"node_id": "disassembly", "abs_offset": ep.get("abs_offset", base_off), "label": f"Disassemble Entry @ {ep.get('vmaddr', '0x0')}"},
        },
        {
            "id": "dynamic_loader",
            "concept": "5. Dynamic Loader & Shared Libraries",
            "category": "linking",
            "macho": "Interpreter: `LC_LOAD_DYLINKER` (`/usr/lib/dyld`). Dependencies: `LC_LOAD_DYLIB`, `LC_RPATH` (`@rpath`).",
            "elf": "Interpreter: `PT_INTERP` (`/lib64/ld-linux-x86-64.so.2`). Dependencies: `.dynamic` `DT_NEEDED` + `DT_RUNPATH`.",
            "pe": "Interpreter: Kernel-mapped `ntdll.dll!LdrInitializeThunk`. Dependencies: `DATA_DIR_IMPORT_TABLE` (`IMAGE_IMPORT_DESCRIPTOR`).",
            "why": "Separates application code from OS libraries so multiple processes can share physical RAM pages for system libraries.",
            "live_target": {"node_id": "load_commands", "abs_offset": base_off, "label": "Inspect Loader Commands"},
        },
        {
            "id": "stubs_got_iat",
            "concept": "6. External Call Trampolines (Stubs / PLT / IAT)",
            "category": "linking",
            "macho": "`__TEXT,__stubs` trampoline -> loads target pointer from `__DATA_CONST,__got` (bound via `LC_DYLD_CHAINED_FIXUPS`).",
            "elf": "`.plt` (Procedure Linkage Table) stub -> jumps through `.got.plt` / `.got` (bound via `.rela.plt` `R_*_JUMP_SLOT`).",
            "pe": "Indirect call `call qword ptr [__imp_Func]` through `FirstThunk` (**IAT**) populated from `OriginalFirstThunk` (**INT**).",
            "why": "Because `.text`/`__TEXT` is mapped Read-Only (`R-X`), runtime-resolved library addresses must be stored in a writable data table (`GOT`/`IAT`).",
            "live_target": {"node_id": "dyld_info", "abs_offset": base_off, "label": "Inspect Imports & Fixups"},
        },
        {
            "id": "aslr_relocations",
            "concept": "7. ASLR & Position-Independent Rebasing",
            "category": "linking",
            "macho": "`MH_PIE` flag + `LC_DYLD_CHAINED_FIXUPS` (`DYLD_CHAINED_PTR_*_REBASE` threaded directly through data pointers).",
            "elf": "`ET_DYN` type + `.rela.dyn` (`R_X86_64_RELATIVE` / `R_AARCH64_RELATIVE` records adding ASLR base).",
            "pe": "`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` + `.reloc` (`IMAGE_BASE_RELOCATION` 4KB page blocks of `DIR64` / `HIGHLOW` offsets).",
            "why": "Shifts hardcoded global pointers by the random ASLR slide when the binary is loaded at a randomized virtual address.",
            "live_target": {"node_id": "dyld_info", "abs_offset": base_off, "label": "View Rebases & Relocations"},
        },
        {
            "id": "relro_data_const",
            "concept": "8. Post-Relocation Read-Only Lockdown",
            "category": "security",
            "macho": "`__DATA_CONST` segment (`SG_READ_ONLY`): mapped `RW-` during `dyld` fixups, then `mprotect()`ed to `R--`.",
            "elf": "`PT_GNU_RELRO` + `DF_BIND_NOW` (Full RELRO): `ld.so` locks `.got`, `.init_array`, and `.dynamic` to `PROT_READ`.",
            "pe": "`IAT` placed inside `.rdata`: `ntdll` temporarily makes IAT pages writable during import snapping, then restores `PAGE_READONLY`.",
            "why": "Prevents GOT/IAT overwrite attacks where a memory corruption bug hijacks a function pointer in `.got` or `IAT`.",
            "live_target": {"node_id": "security_audit", "abs_offset": base_off, "label": "Inspect Hardening Audit"},
        },
        {
            "id": "constructors_tls",
            "concept": "9. Static Constructors & Pre-`main` Hooks",
            "category": "linking",
            "macho": "`__DATA,__mod_init_func` / `__TEXT,__init_offsets` + Objective-C `+load` methods.",
            "elf": "`.preinit_array` and `.init_array` function pointer tables invoked by `__libc_start_main`.",
            "pe": "`IMAGE_DIRECTORY_ENTRY_TLS` (`AddressOfCallBacks` run *before* `AddressOfEntryPoint`!) + CRT `.CRT$XCU` tables.",
            "why": "Initializes C++ global objects, language runtimes, and thread-local state before `main()` begins.",
            "live_target": {"node_id": "function_starts", "abs_offset": ep.get("abs_offset", base_off), "label": "Inspect Entry & Functions"},
        },
        {
            "id": "codesign_debug",
            "concept": "10. Code Signing, Integrity & Debug UUID",
            "category": "security",
            "macho": "`LC_CODE_SIGNATURE` (`CS_SuperBlob` with per-page SHA-256 hashes, Entitlements, CMS certs) + `LC_UUID`.",
            "elf": "`.note.gnu.build-id` (SHA-1/MD5 Build-ID) + `.note.gnu.property` (CET/PAC/BTI) + detached/kernel PKCS#7.",
            "pe": "`DATA_DIR_CERTIFICATE_TABLE` (`WIN_CERTIFICATE` Authenticode PKCS#7) + `DATA_DIR_DEBUG` (`CodeView RSDS` PDB GUID).",
            "why": "Cryptographically verifies binary integrity and links stripped release builds to `.dSYM` / `debuginfod` / `.pdb` symbols.",
            "live_target": {"node_id": "code_signature", "abs_offset": base_off, "label": "Inspect Signature & Trust"},
        },
    ]

    for r in rows:
        r["active_format"] = fmt_upper
        r["pedagogical_note"] = r["why"]
        r["active_target_node"] = r["live_target"]["node_id"]
        r["active_offset"] = r["live_target"]["abs_offset"]

    return rows


def build_guided_tours(slice_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Builds 4 interactive Guided Learning Tours with live micro-challenges tailored
    to the currently loaded binary's real offsets, segments, and security posture.
    """
    fmt = slice_doc.get("format", "macho").lower()
    base_off = slice_doc.get("slice_base_offset", 0)
    hdr_reg = slice_doc.get("header", {}).get("region") or {"abs_offset": base_off, "size": 32}
    segs = slice_doc.get("segments", [])
    ep = slice_doc.get("entry_point", {})
    sec = slice_doc.get("security_posture", {})

    code_seg = next((s for s in segs if "x" in s.get("initprot", "").lower()), segs[0] if segs else None)
    data_seg = next((s for s in segs if "w" in s.get("initprot", "").lower()), segs[-1] if segs else None)
    ep_vm = ep.get("vmaddr", "0x0")
    ep_off = ep.get("abs_offset", base_off)

    code_seg_name = code_seg["segname"] if code_seg else "__TEXT"
    code_seg_vm = code_seg["vmaddr"] if code_seg else "0x100000000"
    code_seg_off = code_seg["abs_offset"] if code_seg else base_off

    tours = [
        {
            "id": "tour_address_translation",
            "title": "Tour 1: File Offset vs. Virtual Memory Address",
            "level": "Fundamentals",
            "duration": "2 min",
            "estimated_time": "2 min",
            "description": "Learn the core equation of binary analysis: how bytes on disk map to virtual memory addresses in RAM, and how .bss zero-fill works.",
            "steps": [
                {
                    "step": 1,
                    "step_number": 1,
                    "title": f"The Disk-to-RAM Mapping Contract ({code_seg_name})",
                    "narrative": f"On disk, this binary is just a flat array of bytes starting at offset 0x0. When launched, the OS maps segment '{code_seg_name}' from file offset 0x{code_seg_off:x} into Virtual Memory at {code_seg_vm} with permissions '{code_seg['initprot'] if code_seg else 'r-x'}'.",
                    "node_id": "segments",
                    "target_node_id": "segments",
                    "abs_offset": code_seg_off,
                    "size": 64,
                    "challenge": {
                        "question": f"In this binary, the entry point at VMAddr {ep_vm} maps to File Offset 0x{ep_off:x}. What happens when a section has VirtualSize (vmsize) > FileSize (filesize)?",
                        "options": [
                            "The OS kernel zero-fills the extra virtual memory pages (.bss) in RAM without storing zeros on disk.",
                            "The binary fails to load with a truncation error.",
                            "The CPU reads random uninitialized disk sectors.",
                        ],
                        "correct_index": 0,
                        "explanation": "Correct! Uninitialized globals (.bss / S_ZEROFILL / SHT_NOBITS) reserve virtual memory (`vmsize`) without wasting space on disk (`filesize = 0`).",
                    },
                },
                {
                    "step": 2,
                    "step_number": 2,
                    "title": f"Locating the Entry Point Instruction ({ep_vm})",
                    "narrative": f"The header says execution starts at Virtual Address {ep_vm} ({ep.get('type', 'Entry')}). Using the formula `FileOff = SegFileOff + (VMAddr - SegVMAddr)`, the Translator bar resolves {ep_vm} to physical File Offset 0x{ep_off:x}!",
                    "node_id": "disassembly",
                    "target_node_id": "disassembly",
                    "abs_offset": ep_off,
                    "size": 16,
                },
                {
                    "step": 3,
                    "step_number": 3,
                    "title": "Visualizing File vs. Virtual Tracks",
                    "narrative": "Notice in the Dual Memory Map how the FILE track is compact while the VM track is aligned to page boundaries (and includes zero-filled .bss sections with 0 file bytes).",
                    "node_id": "overview",
                    "target_node_id": "overview",
                    "abs_offset": base_off,
                    "size": 32,
                },
            ],
        },
        {
            "id": "tour_dynamic_linking",
            "title": "Tour 2: Trace a Dynamic Function Call (Stubs, GOT & IAT)",
            "level": "Intermediate",
            "duration": "3 min",
            "estimated_time": "3 min",
            "description": "Follow how calling an external library function works when the code segment is Read-Only (R-X) and the library address is unknown until runtime.",
            "steps": [
                {
                    "step": 1,
                    "step_number": 1,
                    "title": "Why Code Pages Cannot Be Patched Directly",
                    "narrative": f"Segment '{code_seg_name}' is mapped Read+Execute ('{code_seg['initprot'] if code_seg else 'r-x'}')—not Writable. That means the OS loader cannot patch external function addresses directly into call instructions without breaking code sharing and page hashes.",
                    "node_id": "disassembly",
                    "target_node_id": "disassembly",
                    "abs_offset": ep_off,
                    "size": 32,
                    "challenge": {
                        "question": "How do modern OS loaders prevent attackers from overwriting resolved function pointers in GOT / IAT / __got at runtime?",
                        "options": [
                            "The loader resolves pointers at startup and then calls mprotect() to lock the page Read-Only (__DATA_CONST / Full RELRO / Read-Only IAT).",
                            "The loader encrypts the entire code segment in RAM.",
                            "The CPU disables indirect branches completely.",
                        ],
                        "correct_index": 0,
                        "explanation": "Spot on! Mach-O `__DATA_CONST`, ELF `PT_GNU_RELRO` (Full RELRO), and PE `.rdata` IAT locking all transition the pointer table from RW- to R-- before `main()` runs.",
                    },
                },
                {
                    "step": 2,
                    "step_number": 2,
                    "title": "The Indirection Table (GOT / Chained Fixups / IAT)",
                    "narrative": f"Instead, code calls a small trampoline (Mach-O `__stubs`, ELF `.plt`, or PE `call [IAT]`) which loads an 8-byte function pointer from a data segment ('{data_seg['segname'] if data_seg else 'DATA'}').",
                    "node_id": "dyld_info",
                    "target_node_id": "dyld_info",
                    "abs_offset": data_seg["abs_offset"] if data_seg else base_off,
                    "size": 64,
                },
                {
                    "step": 3,
                    "step_number": 3,
                    "title": "Auditing Post-Relocation Lockdown",
                    "narrative": "Inspect the Security & Hardening Audit view to confirm whether `__DATA_CONST`, `PT_GNU_RELRO`, or Read-Only `IAT` protection is active.",
                    "node_id": "security_audit",
                    "target_node_id": "security_audit",
                    "abs_offset": base_off,
                    "size": 32,
                },
            ],
        },
        {
            "id": "tour_security_posture",
            "title": "Tour 3: 60-Second Binary Security & Hardening Audit",
            "level": "Security & Forensics",
            "duration": "3 min",
            "estimated_time": "3 min",
            "description": "Audit the currently loaded binary for ASLR/PIE, W^X memory hygiene, stack canaries, hardware CFI (PAC/CET/CFG), and cryptographic signatures.",
            "steps": [
                {
                    "step": 1,
                    "step_number": 1,
                    "title": f"Checking ASLR / PIE ({'ENABLED' if sec.get('pie') else 'DISABLED'})",
                    "narrative": f"In this binary, Position-Independent Execution (ASLR) is {'ENABLED' if sec.get('pie') else 'DISABLED'}. When enabled, the OS shifts all virtual addresses by a random slide on every launch.",
                    "node_id": "mach_header",
                    "target_node_id": "mach_header",
                    "abs_offset": hdr_reg.get("abs_offset", base_off),
                    "size": hdr_reg.get("size", 32),
                    "challenge": {
                        "question": "If an executable section (.text / __text) has a Shannon entropy of 7.65 bits/byte (out of 8.00), what does that strongly suggest?",
                        "options": [
                            "The section is compressed, packed (e.g. UPX), or encrypted rather than plain compiled machine instructions.",
                            "The section contains mostly null padding bytes (0x00).",
                            "The section contains plain ASCII C-strings.",
                        ],
                        "correct_index": 0,
                        "explanation": "Exactly! Compiled native code typically has entropy between 4.5 and 6.6 bits/byte. Entropy above 7.15 indicates high randomness from compression or encryption.",
                    },
                },
                {
                    "step": 2,
                    "step_number": 2,
                    "title": f"Auditing W^X Memory Hygiene ({'RWX VIOLATION!' if sec.get('has_rwx_segments') else 'PASS'})",
                    "narrative": (
                        "WARNING: This binary contains a segment with simultaneous Write and Execute (RWX) permissions! Look for the red/amber RWX block in the Memory Map."
                        if sec.get("has_rwx_segments")
                        else "Every segment in this binary strictly separates Write (RW-) from Execute (R-X), enforcing W^X protection."
                    ),
                    "node_id": "security_audit",
                    "target_node_id": "security_audit",
                    "abs_offset": base_off,
                    "size": 64,
                },
                {
                    "step": 3,
                    "step_number": 3,
                    "title": "Entropy, Capabilities & Anomaly Forensics",
                    "narrative": "Switch to the Semantic & Entropy Intelligence view to inspect per-section Shannon entropy (detecting packed/encrypted payloads) and behavioral API capabilities.",
                    "node_id": "semantic_intel",
                    "target_node_id": "semantic_intel",
                    "abs_offset": base_off,
                    "size": 64,
                },
            ],
        },
    ]
    return tours


def build_pedagogy_bundle(slice_doc: Dict[str, Any]) -> Dict[str, Any]:
    annotate_slice_pedagogy(slice_doc)
    return {
        "loader_lifecycle": build_loader_lifecycle(slice_doc),
        "rosetta_stone": build_rosetta_stone(slice_doc),
        "guided_tours": build_guided_tours(slice_doc),
    }
