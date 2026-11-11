"""
Learning annotations attached to a parsed document.

The teaching material itself lives in backend/learn/ and is served through
/api/learn/* (see backend/learn_content.py). This module only adds what belongs
*inside* a document:

1. `annotate_slice_pedagogy` attaches a `pedagogy` explanation to every field of
   the main headers and structures that the field catalog knows. The inspector
   shows it next to the field in Learn mode, and /api/decode returns it for the
   field under the cursor. Shape (kept from the first version of this module so
   that existing clients keep working):

       {"why_it_matters": meaning, "loader_behavior": who reads it and when,
        "what_if_modified": what happens if it is wrong, "cross_format_peer": peers,
        "key": catalog key, "concept": concept id}

2. `build_pedagogy_bundle` returns the per-slice bundle stored as slice["pedagogy"]:
   `loader_lifecycle` (six stages from exec to the entry point, described with this
   file's own values), and the legacy lists `rosetta_stone` and `guided_tours`,
   which are derived from the comparison table and the tours in backend/learn/.

All text here is plain (no markup). Values taken from the document are
attacker-controlled and are passed through `clean()` before they are placed in
sentences.
"""

from typing import Any, Dict, List, Optional

from . import learn_content
from .learn import compare as _compare
from .learn import fields as _fields
from .learn import resolve as _resolve
from .learn.resolve import clean, find_field, find_lc, hexs, to_int

# Upper bound on annotated fields per slice. Ordinary binaries stay far below it;
# it bounds the growth of the document for files with thousands of sections.
FIELD_ANNOTATION_BUDGET = 1500

_LEGACY_CACHE: Dict[str, Dict[str, str]] = {}


def explanation_for(key: Optional[str]) -> Optional[Dict[str, str]]:
    """The `pedagogy` dict for a catalog key (shared between all fields with that key)."""
    if not key:
        return None
    hit = _LEGACY_CACHE.get(key)
    if hit is None:
        entry = _fields.CATALOG.get(key)
        if entry is None:
            return None
        hit = {
            "why_it_matters": entry["meaning"],
            "loader_behavior": entry["reader"],
            "what_if_modified": entry["if_wrong"],
            "cross_format_peer": entry["peers"],
            "key": key,
            "concept": entry["concept"],
        }
        _LEGACY_CACHE[key] = hit
    return hit


def _annotate(fields: Any, fmt: str, ctx: str, cmd_name: Optional[str], budget: List[int]) -> None:
    if not isinstance(fields, list):
        return
    for field in fields:
        if budget[0] <= 0:
            return
        if not isinstance(field, dict):
            continue
        hit = explanation_for(_fields.key_for(fmt, ctx, str(field.get("name", "")), cmd_name))
        if hit is not None:
            field["pedagogy"] = hit
            budget[0] -= 1


def annotate_slice_pedagogy(slice_doc: Dict[str, Any]) -> int:
    """Attach `pedagogy` to the fields of the header, load commands / program headers / data
    directories, segments and sections of one slice. Returns the number of fields annotated."""
    fmt = str(slice_doc.get("format", "macho")).lower()
    budget = [FIELD_ANNOTATION_BUDGET]
    _annotate((slice_doc.get("header") or {}).get("fields"), fmt, "header", None, budget)
    for lc in slice_doc.get("load_commands") or []:
        if isinstance(lc, dict):
            _annotate(lc.get("fields"), fmt, "lc", str(lc.get("cmd_name", "")), budget)
    for seg in slice_doc.get("segments") or []:
        if isinstance(seg, dict):
            _annotate(seg.get("fields"), fmt, "segment", "LC_SEGMENT_64", budget)
    for seg in slice_doc.get("segments") or []:
        if not isinstance(seg, dict):
            continue
        for sect in seg.get("sections") or []:
            if isinstance(sect, dict):
                _annotate(sect.get("fields"), fmt, "section", None, budget)
    signature = slice_doc.get("code_signature_detail") or {}
    if fmt == "macho":
        _annotate(((slice_doc.get("dyld_info") or {}).get("chained_fixups") or {}).get("fields"), fmt, "chained_fixups", None, budget)
        _annotate(signature.get("fields"), fmt, "superblob", None, budget)
        _annotate((signature.get("code_directory") or {}).get("fields"), fmt, "code_directory", None, budget)
    elif fmt == "pe":
        _annotate(signature.get("fields"), fmt, "win_certificate", None, budget)
    return FIELD_ANNOTATION_BUDGET - budget[0]


def annotate_fat_header_pedagogy(fat_header: Any) -> None:
    """Attach `pedagogy` to the fields of a universal (fat) header. Never raises."""
    try:
        if isinstance(fat_header, dict):
            _annotate(fat_header.get("fields"), "macho", "fat", None, [FIELD_ANNOTATION_BUDGET])
    except Exception:  # noqa: BLE001 - annotations must never cost the user the document
        return


# ---------------------------------------------------------------------------
# Loader lifecycle: six stages, described with this file's own values
# ---------------------------------------------------------------------------
def _region_of(obj: Any, fallback: Dict[str, int]) -> Dict[str, int]:
    if isinstance(obj, dict) and isinstance(obj.get("abs_offset"), int) and not isinstance(obj.get("abs_offset"), bool):
        return {"abs_offset": obj["abs_offset"], "size": max(1, to_int(obj.get("size")) or 1)}
    return fallback


def _stage(number: int, stage_id: str, title: str, actor: str, summary: str, state: str, failure: str,
           region: Dict[str, int], node_id: str, vmaddr: str = "") -> Dict[str, Any]:
    return {
        "stage": number, "stage_id": number, "id": stage_id,
        "title": "%d. %s" % (number, title), "actor": actor, "syscall": actor, "summary": summary,
        "abs_offset": region["abs_offset"], "size": region["size"], "vmaddr": vmaddr, "node_id": node_id,
        "binary_state": state, "state_badge": state, "failure_mode": failure, "what_could_fail": failure,
    }


def _names(items: List[Any], key: str = "name", limit: int = 3) -> str:
    names = [clean(i.get(key), 60) for i in items[:limit] if isinstance(i, dict) and i.get(key)]
    more = len(items) - len(names)
    text = ", ".join(names)
    if more > 0 and names:
        text += " and %d more" % more
    return text or "none"


def build_loader_lifecycle(slice_doc: Dict[str, Any]) -> Dict[str, Any]:
    """Six stages from exec to the entry point for this slice, with the bytes each stage reads."""
    fmt = str(slice_doc.get("format", "macho")).lower()
    header = slice_doc.get("header") or {}
    segs = [s for s in (slice_doc.get("segments") or []) if isinstance(s, dict)]
    libs = [d for d in (slice_doc.get("dylibs") or []) if isinstance(d, dict)]
    ep = slice_doc.get("entry_point") or {}
    sec = slice_doc.get("security_posture") or {}
    base_off = to_int(slice_doc.get("slice_base_offset")) or 0
    head = _region_of(header.get("region"), {"abs_offset": base_off, "size": 32})
    ep_vm = clean(ep.get("vmaddr") or "none")
    ep_off = ep.get("abs_offset") if isinstance(ep.get("abs_offset"), int) else head["abs_offset"]
    ep_region = {"abs_offset": ep_off, "size": 16}
    fixups = ((slice_doc.get("dyld_info") or {}).get("chained_fixups") or {})
    n_fixups = len(fixups.get("fixups") or [])
    n_imports = len(fixups.get("imports") or [])
    exec_index = _resolve.pick_segment(slice_doc, "exec")
    exec_seg = segs[exec_index] if exec_index is not None and exec_index < len(segs) else None
    exec_region = _region_of((exec_seg or {}).get("header_region"), head)
    pie = _resolve.is_pie(slice_doc)
    arch = clean(slice_doc.get("arch_name") or "unknown")
    magic = clean(header.get("magic_name") or "")
    filetype = clean(header.get("filetype_name") or "")

    if fmt == "elf":
        interp_lc = find_lc(slice_doc, ["PT_INTERP"])
        interp = clean(((slice_doc.get("elf_metadata") or {}).get("interpreter")) or "", 120)
        dyn_lc = find_lc(slice_doc, ["PT_DYNAMIC"])
        relro_lc = find_lc(slice_doc, ["PT_GNU_RELRO"])
        n_load = sum(1 for lc in slice_doc.get("load_commands") or [] if isinstance(lc, dict) and lc.get("cmd_name") == "PT_LOAD")
        loader_name = "Linux kernel, then %s" % interp if interp else "Linux kernel (statically linked: no dynamic linker)"
        stages = [
            _stage(1, "kernel_validation", "The kernel recognises the file", "Linux kernel: load_elf_binary (fs/binfmt_elf.c)",
                   "execve reads the start of the file. The ELF handler checks the magic bytes, the type (ET_EXEC or ET_DYN) and "
                   "the machine, then reads the %d program headers located by e_phoff." % (to_int(header.get("ncmds")) or 0),
                   "%s, %s, %s" % (magic, filetype, arch),
                   "With a wrong magic, type or machine, execve fails with ENOEXEC ('Exec format error').",
                   head, "mach_header"),
            _stage(2, "segment_mapping", "PT_LOAD segments are mapped", "Linux kernel: load_elf_binary, elf_map",
                   "Each PT_LOAD program header is mapped: p_filesz bytes from p_offset appear at p_vaddr with the permissions in "
                   "p_flags, and memory up to p_memsz is zero-filled. For an ET_DYN file the kernel first chooses the load base, "
                   "at random when address randomisation is on.",
                   "%d PT_LOAD segment(s); position-independent: %s" % (n_load, "yes" if pie else "no"),
                   "A segment that cannot be mapped, for example because p_offset and p_vaddr disagree modulo the page size, makes "
                   "the exec fail. The old program has already been discarded by this stage, so execve cannot return an error: "
                   "the process is killed with SIGSEGV.",
                   exec_region, "segments"),
            _stage(3, "loader_bootstrap", "The interpreter is mapped and the stack is built", "Linux kernel: load_elf_binary, create_elf_tables",
                   ("PT_INTERP names the dynamic linker, %s. The kernel maps it as a second ELF file. " % interp if interp else
                    "This file has no PT_INTERP header: it is statically linked and no dynamic linker is loaded. ") +
                   "The kernel then builds the initial stack: arguments, environment and the auxiliary vector (AT_PHDR, AT_ENTRY, "
                   "AT_BASE, AT_RANDOM and others).",
                   "Interpreter: %s" % interp if interp else "No interpreter (static)",
                   "If the interpreter's path does not exist, execve fails with ENOENT ('No such file or directory'), although "
                   "the program file itself exists.",
                   _region_of((interp_lc or {}).get("region"), head), "load_commands"),
            _stage(4, "relocations_binding", "Libraries are loaded and relocations applied",
                   "Dynamic linker (ld.so)" if interp else "Start-up code of the executable",
                   ("Execution starts in the dynamic linker. It loads each DT_NEEDED library (%s) and applies the relocations: "
                    "relative ones get the load base added, the others receive the address of the symbol they name." % _names(libs)
                    if interp else
                    "There are no libraries to load. A static position-independent executable applies its own relative "
                    "relocations in its start-up code; a fixed-address one needs none."),
                   "%d needed libraries; %d relocations decoded; %d imported symbols" % (len(libs), n_fixups, n_imports),
                   "With glibc, a missing library stops the launch with 'error while loading shared libraries'. A missing symbol "
                   "stops it with 'symbol lookup error': at start-up for data references and with bind-now, otherwise at the "
                   "first call of the function.",
                   _region_of((dyn_lc or {}).get("region"), head), "dyld_info"),
            _stage(5, "permission_lockdown", "The RELRO range is made read-only", "Dynamic linker: _dl_protect_relro (glibc)",
                   "After relocating, the dynamic linker calls mprotect to make the range described by PT_GNU_RELRO read-only. "
                   "With bind-now that includes the slots the PLT jumps through." if relro_lc else
                   "This file has no PT_GNU_RELRO header, so nothing is made read-only after relocation.",
                   "RELRO: %s; stack executable: %s" % (clean(sec.get("relro") or "none"), "no" if sec.get("nx_stack", True) else "yes"),
                   "Without PT_GNU_RELRO the GOT stays writable for the life of the process.",
                   _region_of((relro_lc or {}).get("region"), head), "security_audit"),
            _stage(6, "entry_handoff", "Initialisers run and control reaches the entry point", "Dynamic linker, then _start (C runtime)",
                   "The dynamic linker runs the initialisers of the shared libraries and jumps to e_entry (%s). That is _start, "
                   "which calls __libc_start_main; it runs the executable's own initialisers and then calls main." % ep_vm,
                   "Entry %s at file offset %s" % (ep_vm, hexs(ep_off)),
                   "An entry address that is not mapped, executable memory ends the process with SIGSEGV at the first instruction.",
                   ep_region, "disassembly", ep_vm),
        ]
        family = "ELF"
    elif fmt == "pe":
        meta = slice_doc.get("pe_metadata") or {}
        base = clean(meta.get("image_base") or "0x0")
        imp_lc = find_lc(slice_doc, ["DATA_DIR_IMPORT_TABLE"])
        dos_lc = find_lc(slice_doc, ["IMAGE_DOS_HEADER"])
        chars_field = find_field(header.get("fields"), "OptionalHeader.DllCharacteristics") or {}
        callbacks = len(((meta.get("tls_info") or {}).get("callbacks")) or [])
        n_sections = sum(1 for s in segs if s.get("segname") != "HEADERS")
        loader_name = "Windows kernel, then the loader in ntdll.dll"
        stages = [
            _stage(1, "kernel_validation", "The kernel validates the headers", "Windows kernel (image section creation)",
                   "Process creation opens the file and creates an image section for it. The headers are validated on the way: "
                   "'MZ' at offset 0, e_lfanew, the signature 'PE\\0\\0' at file offset %s, the machine type and the optional header."
                   % hexs(head["abs_offset"]),
                   "%s, %s, ImageBase %s" % (magic, arch, base),
                   "A file that fails these checks is refused as not a valid Win32 application (STATUS_INVALID_IMAGE_FORMAT).",
                   _region_of((dos_lc or {}).get("region"), head), "mach_header"),
            _stage(2, "segment_mapping", "The image is mapped", "Windows memory manager",
                   "The image is mapped at ImageBase (%s), or at another base chosen by the system if the image may be relocated. "
                   "The headers and each section are placed at their RVAs. Section data is aligned to FileAlignment in the file "
                   "and to SectionAlignment in memory." % base,
                   "%d section(s); may be relocated (DYNAMIC_BASE): %s" % (n_sections, "yes" if pie else "no"),
                   "An image without base relocations cannot be moved from ImageBase.",
                   exec_region, "segments", base),
            _stage(3, "loader_bootstrap", "ntdll.dll is mapped and the first thread is created", "Windows kernel",
                   "The kernel maps ntdll.dll into the new process, creates the process and thread environment blocks and the "
                   "first thread's stack (sized by SizeOfStackReserve). The thread starts in the loader inside ntdll.dll "
                   "(LdrInitializeThunk), not in the program.",
                   "Subsystem: %s" % clean(header.get("cpusubtype_name") or "unknown"),
                   "Nothing in the file controls this step. Unlike ELF and Mach-O, a PE file cannot name its loader; every "
                   "process uses the one in ntdll.dll.",
                   head, "load_commands", base),
            _stage(4, "relocations_binding", "Imports are resolved", "Loader in ntdll.dll",
                   ("The loader walks the import directory, loads the DLLs it names (%s) and their dependencies, and writes the "
                    "address of each imported function into the import address table. " % _names(libs) if libs else
                    "This file has no import directory, so there are no DLLs to load and no addresses to bind. ") +
                   "If the image is not at ImageBase, its base relocations are applied.",
                   "%d imported functions from %d DLL(s); %d relocation entries decoded" % (n_imports, len(libs), n_fixups),
                   "A missing DLL stops the launch (STATUS_DLL_NOT_FOUND, 0xC0000135). A function the DLL does not export stops "
                   "it too (STATUS_ENTRYPOINT_NOT_FOUND, 0xC0000139).",
                   _region_of((imp_lc or {}).get("region"), head), "dyld_info", base),
            _stage(5, "permission_lockdown", "Protections take effect", "Loader and memory manager",
                   "Each section's pages get the protection its Characteristics ask for. Where the linker placed the import "
                   "address table in a read-only section, as Microsoft's linker does, the loader makes it writable only while "
                   "it is being filled in. The mitigations declared in DllCharacteristics apply to the image.",
                   "DllCharacteristics %s" % clean(chars_field.get("value") or "not present"),
                   "With Control Flow Guard active, an indirect call to an address that is not a registered call target "
                   "terminates the process.",
                   _region_of(chars_field if chars_field else None, head), "security_audit", base),
            _stage(6, "entry_handoff", "DLL initialisation, TLS callbacks, entry point", "Loader, then the C runtime",
                   "The loader calls the initialisation routine of each DLL, dependencies first, and the image's TLS callbacks if "
                   "it has any (%d here). The thread then runs AddressOfEntryPoint (%s): the C runtime's start-up code, which "
                   "calls main." % (callbacks, ep_vm),
                   "Entry %s at file offset %s; TLS callbacks: %d" % (ep_vm, hexs(ep_off), callbacks),
                   "If a DLL's initialisation routine reports failure, the process ends with STATUS_DLL_INIT_FAILED (0xC0000142).",
                   ep_region, "disassembly", ep_vm),
        ]
        family = "PE"
    else:
        dylinker_lc = find_lc(slice_doc, ["LC_LOAD_DYLINKER"])
        sig_lc = find_lc(slice_doc, ["LC_CODE_SIGNATURE"])
        main_lc = find_lc(slice_doc, ["LC_MAIN", "LC_UNIXTHREAD"])
        dylinker = clean((find_field((dylinker_lc or {}).get("fields"), "name") or {}).get("value") or "/usr/lib/dyld", 120)
        chained = find_lc(slice_doc, ["LC_DYLD_CHAINED_FIXUPS"]) is not None
        signed = bool((slice_doc.get("code_signature_detail") or {}).get("present"))
        adhoc = bool(((sec.get("code_signature") or {}).get("is_adhoc")))
        has_const = any(str(s.get("segname")) == "__DATA_CONST" for s in segs)
        is_exec = to_int(header.get("filetype")) == 2
        entry_cmd = clean((main_lc or {}).get("cmd_name") or "none")
        if not is_exec:
            loader_name = "Not started by the macOS kernel (file type %s)" % filetype
            note = ("This file is of type %s. The macOS kernel starts only MH_EXECUTE files; the stages below describe what "
                    "the structures in this file ask of whatever loads it. " % filetype)
        else:
            loader_name = "XNU kernel, then %s" % dylinker if dylinker_lc else "XNU kernel (no dynamic linker)"
            note = ""
        stages = [
            _stage(1, "kernel_validation", "The kernel picks a slice and checks the header",
                   "XNU: exec_fat_imgact, exec_mach_imgact (bsd/kern/kern_exec.c)",
                   note + "For a universal file the kernel first picks the slice that best suits the machine. It then checks the "
                   "Mach-O magic, the CPU type and that the file type is MH_EXECUTE, and reads the %d load commands (%d bytes)."
                   % (to_int(header.get("ncmds")) or 0, to_int(header.get("sizeofcmds")) or 0),
                   "Slice %s; %s; %s" % (arch, magic, filetype),
                   "No Mach-O magic, or a file type other than MH_EXECUTE: 'exec format error' (ENOEXEC). A CPU type the "
                   "machine cannot run: 'bad CPU type in executable' (EBADARCH). Malformed load commands are found later, "
                   "while the image is loaded: posix_spawn reports 'Malformed Mach-o file' (EBADMACHO), and a process that "
                   "called execve is killed.",
                   head, "mach_header"),
            _stage(2, "segment_mapping", "Segments are mapped", "XNU: parse_machfile, load_segment (bsd/kern/mach_loader.c)",
                   "Each LC_SEGMENT_64 is mapped: filesize bytes from fileoff appear at vmaddr with the protection in initprot. "
                   "If the header has MH_PIE, every address is shifted by a slide chosen at random for this launch. __PAGEZERO "
                   "reserves the lowest addresses with no access.",
                   "%d segment(s); MH_PIE: %s" % (len(segs), "set" if pie else "not set" if pie is not None else "not applicable"),
                   "A segment that reaches beyond the file, or whose file offset is not page-aligned, makes the kernel reject "
                   "the file as malformed. On arm64, a dynamically linked executable without MH_PIE is refused. Failures at "
                   "this stage are returned by posix_spawn as an error; a process that called execve is killed.",
                   exec_region, "segments"),
            _stage(3, "loader_bootstrap", "The dynamic linker is mapped", "XNU: load_dylinker (bsd/kern/mach_loader.c)",
                   ("LC_LOAD_DYLINKER names the dynamic linker, %s. The kernel maps it as a second Mach-O image with its own "
                    "slide, builds the stack, and starts the thread at the dynamic linker's entry point, passing the address of "
                    "this file's header." % dylinker) if dylinker_lc else
                   "This file has no LC_LOAD_DYLINKER command. It is statically linked: its initial register values, including "
                   "the program counter, come from LC_UNIXTHREAD.",
                   "Dynamic linker: %s" % dylinker if dylinker_lc else "No dynamic linker; entry from %s" % entry_cmd,
                   "If the dynamic linker cannot be loaded, the exec fails. Release kernels accept only /usr/lib/dyld as the "
                   "dynamic linker, and on arm64 they do not run statically linked executables at all.",
                   _region_of((dylinker_lc or main_lc or {}).get("region"), head), "load_commands"),
            _stage(4, "relocations_binding", "dyld loads libraries and applies fixups", "dyld",
                   ("dyld loads the libraries named by LC_LOAD_DYLIB commands (%s); system libraries come from the shared cache. "
                    "It then applies the fixups, stored here as %s: rebases add the slide to pointers into the image, binds "
                    "store the addresses of imported symbols." % (_names(libs), "chained fixups" if chained else "rebase and bind opcodes"))
                   if dylinker_lc else "Without a dynamic linker there are no libraries to load and no fixups to apply.",
                   "%d libraries; %d fixups decoded; %d imported symbols" % (len(libs), n_fixups, n_imports),
                   "A missing library ends the launch with 'Library not loaded'; a missing symbol with 'Symbol not found'.",
                   _region_of(fixups.get("region"), head), "dyld_info"),
            _stage(5, "permission_lockdown", "Read-only data is locked; the signature is enforced", "dyld and the XNU kernel",
                   "dyld makes segments flagged SG_READ_ONLY, such as __DATA_CONST, read-only once their pointers are final. "
                   "From the start, whenever a page of the file is first used, the kernel compares its hash with the code "
                   "signature located by LC_CODE_SIGNATURE.",
                   "Signature: %s; __DATA_CONST: %s" % (("ad-hoc" if adhoc else "present") if signed else "none", "present" if has_const else "absent"),
                   "On a system that enforces code signing, a page that does not match its hash gets the process killed. On Apple "
                   "silicon, native code without a signature is not run at all.",
                   _region_of((sig_lc or {}).get("region"), head), "code_signature"),
            _stage(6, "entry_handoff", "Initialisers run and the entry point is called", "dyld" if dylinker_lc else "The loader of this file",
                   ("dyld runs initialisers, dependencies first, and then calls the entry point given by LC_MAIN: %s." % ep_vm)
                   if dylinker_lc else "Execution begins at the program counter given by %s: %s." % (entry_cmd, ep_vm),
                   "Entry %s at file offset %s (%s)" % (ep_vm, hexs(ep_off), entry_cmd),
                   "An entry point that does not lead to code crashes the process at its first instruction.",
                   ep_region, "disassembly", ep_vm),
        ]
        family = "Mach-O"

    return {
        "format": fmt.upper(),
        "os_family": family,
        "os_loader_name": loader_name,
        "loader_name": loader_name,
        "stages": stages,
    }


# ---------------------------------------------------------------------------
# Legacy lists (kept for clients of the first document format)
# ---------------------------------------------------------------------------
def _doc_stub(slice_doc: Dict[str, Any]) -> Dict[str, Any]:
    end = (to_int(slice_doc.get("slice_base_offset")) or 0) + (to_int(slice_doc.get("slice_size")) or 0)
    return {"file_info": {"file_size": end, "fat_header": None}, "slices": [slice_doc]}


def build_rosetta_stone(slice_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Ten rows of the cross-format comparison (the full table is at /api/learn/compare)."""
    fmt_upper = str(slice_doc.get("format", "macho")).upper()
    base_off = to_int(slice_doc.get("slice_base_offset")) or 0
    doc = _doc_stub(slice_doc)
    table = _compare.by_id()
    rows: List[Dict[str, Any]] = []
    for number, row_id in enumerate(_compare.LEGACY_IDS, 1):
        row = table[row_id]
        hit = _resolve.resolve(row["at"], doc, slice_doc)
        node = hit.get("node_id") if hit.get("available") else "overview"
        offset = hit.get("abs_offset") if hit.get("available") and hit.get("abs_offset") is not None else base_off
        why = learn_content.plain(row["why"])
        rows.append({
            "id": row["id"],
            "concept": "%d. %s" % (number, row["title"]),
            "concept_id": row["concept"],
            "macho": learn_content.plain(row["macho"]),
            "elf": learn_content.plain(row["elf"]),
            "pe": learn_content.plain(row["pe"]),
            "why": why,
            "pedagogical_note": why,
            "live_target": {"node_id": node, "abs_offset": offset, "label": "Show in this file"},
            "active_format": fmt_upper,
            "active_target_node": node,
            "active_offset": offset,
        })
    return rows


_LEGACY_TOURS = ("first-contact", "file-to-memory", "hardening-audit")
_LEGACY_LEVELS = {1: "First contact", 2: "Working knowledge", 3: "Advanced"}


def build_guided_tours(slice_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Three tours in the first document format: plain text, with a multiple-choice challenge on the
    first step. The interactive tours are served by /api/learn/tour."""
    base_off = to_int(slice_doc.get("slice_base_offset")) or 0
    doc = _doc_stub(slice_doc)
    pie = _resolve.is_pie(slice_doc)
    challenges = {
        "first-contact": {
            "question": "A 32-bit field is stored as the bytes 78 56 34 12 in a little-endian file. What is its value?",
            "options": ["0x12345678", "0x78563412", "0x87654321"],
            "correct_index": 0,
            "explanation": "Little-endian stores the least significant byte first, so the bytes are read from right to left: 0x12345678.",
        },
        "file-to-memory": {
            "question": "A segment is 0x3000 bytes in memory and 0x1000 bytes in the file. What is in the other 0x2000 bytes at run time?",
            "options": ["Zeros supplied by the kernel; they are not stored in the file.",
                        "The bytes that follow the segment in the file.",
                        "Nothing; reading them faults."],
            "correct_index": 0,
            "explanation": "Memory beyond a segment's file size is zero-filled. This is how zero-initialised variables (.bss) take no space on disk.",
        },
        "hardening-audit": {
            "question": "May the system load this file at a different address on each run?",
            "options": ["Yes. It may be loaded at a different address on each run.", "No. It is loaded at the address it was linked for."],
            "correct_index": 0 if pie else 1,
            "explanation": "This is decided by a header field: the MH_PIE flag in Mach-O, the type ET_DYN in ELF, the DYNAMIC_BASE bit in PE.",
        },
    }
    out: List[Dict[str, Any]] = []
    for tour_id in _LEGACY_TOURS:
        built = learn_content.build_tour(tour_id, doc, slice_doc)
        if not built or not built.get("steps"):
            continue
        steps: List[Dict[str, Any]] = []
        for number, item in enumerate(built["steps"][:4], 1):
            show = item.get("show") or {}
            node = show.get("node_id") or "overview"
            offset = show.get("abs_offset") if show.get("abs_offset") is not None else base_off
            legacy_step: Dict[str, Any] = {
                "step": number, "step_number": number, "title": item["title"],
                "narrative": learn_content.plain(item["text"]),
                "node_id": node, "target_node_id": node, "abs_offset": offset, "size": show.get("size") or 16,
            }
            if number == 1:
                legacy_step["challenge"] = challenges[tour_id]
            steps.append(legacy_step)
        minutes = "%d min" % built["minutes"]
        out.append({
            "id": "tour_" + tour_id.replace("-", "_"), "tour_id": tour_id, "title": built["title"],
            "level": _LEGACY_LEVELS.get(built["level"], ""), "duration": minutes, "estimated_time": minutes,
            "description": built["summary"], "steps": steps,
        })
    return out


def build_pedagogy_bundle(slice_doc: Dict[str, Any]) -> Dict[str, Any]:
    annotate_slice_pedagogy(slice_doc)
    return {
        "loader_lifecycle": build_loader_lifecycle(slice_doc),
        "rosetta_stone": build_rosetta_stone(slice_doc),
        "guided_tours": build_guided_tours(slice_doc),
    }
