"""Curriculum, part 3: Running code; Exploit mitigations and signing; Packing, debug information, stripping."""

from .dsl import (concept, debug_id, entry, hfield, lc, note, section, see, segment, signature,
                  table, ul, view, wrong)

MODULES = [
    {
        "id": "execution",
        "title": "Running code",
        "summary": "The stack, function prologues, calling conventions, system calls, and how to read the disassembly view.",
    },
    {
        "id": "hardening",
        "title": "Exploit mitigations and signing",
        "summary": "What each mitigation prevents and what it does not, and how code signatures are stored and checked.",
    },
    {
        "id": "forensics",
        "title": "Packing, debug information and stripping",
        "summary": "What entropy says about a file, where debug information lives, and what is left after stripping.",
    },
]

CONCEPTS = [
    # ------------------------------------------------------------------ execution
    concept(
        id="stack-and-frames",
        title="The stack and what a function prologue does",
        level=2,
        summary="Each call gets a frame on the stack for its return address, saved registers and local variables. The prologue builds the frame and the epilogue removes it.",
        body=[
            "Each thread has a [[stack]]: a region of memory used last-in, first-out, tracked by the "
            "[[stack-pointer|stack pointer]] register. On x86 and ARM64 it grows toward lower addresses. Every "
            "function call that is in progress owns a [[stack-frame|frame]] on it, holding the "
            "[[return-address|return address]], the registers the function must restore, and its local "
            "variables.",
            "The instructions at the start of a function that build the frame are the [[prologue]]; the ones at "
            "the end that undo it are the [[epilogue]]. They are the most recognisable pattern in disassembly, "
            "and they differ by CPU because the CPUs treat the return address differently.",
            table(
                ["", "x86-64", "ARM64"],
                [
                    ["Call", "`call` pushes the return address on the stack", "`bl` puts the return address in register `x30` (the link register)"],
                    ["Prologue", "`push rbp` / `mov rbp, rsp` / `sub rsp, N`", "`stp x29, x30, [sp, #-N]!` / `mov x29, sp`"],
                    ["Epilogue", "`leave` (or `mov rsp, rbp` / `pop rbp`), then `ret`", "`ldp x29, x30, [sp], #N`, then `ret`"],
                    ["Return", "`ret` pops the address from the stack", "`ret` jumps to the address in `x30`"],
                ],
            ),
            "The saved [[frame-pointer|frame pointer]] of each frame points at the previous one, which lets a "
            "debugger walk the chain of callers. Compilers may omit the frame pointer in optimised code; "
            "unwinding then relies on tables in the file ([[unwind-info|unwind information]]).",
            "The layout matters for security. Local buffers and the saved return address are neighbours in the "
            "same frame, so writing past the end of a buffer can replace the return address. Stack canaries, "
            "shadow stacks and return-address signing all exist to defend that one value.",
        ],
        macho=[
            "The size of the main thread's stack can be set with the `stacksize` field of `LC_MAIN` (zero means "
            "the system default). Unwind tables are in `__TEXT,__unwind_info` and `__TEXT,__eh_frame`.",
        ],
        elf=[
            "The stack's permissions come from `PT_GNU_STACK`; its size limit is a property of the process "
            "(`ulimit -s`), not of the file. Unwind tables are in `.eh_frame`, indexed by `.eh_frame_hdr`.",
        ],
        pe=[
            "The optional header fields `SizeOfStackReserve` and `SizeOfStackCommit` size the first thread's "
            "stack. On x64, unwind data is in `.pdata` and `.xdata` (the exception directory), and every "
            "non-leaf function must have an entry there.",
        ],
        see=[
            see("The instructions at the entry point", entry()),
            see("Unwind information", section(macho=["__unwind_info"], elf=[".eh_frame"], pe=[".pdata"]), optional=True),
        ],
        misconceptions=[
            wrong("The stack grows upward.", "On these CPUs a push decreases the stack pointer. The newest frame has the lowest address."),
            wrong("On ARM64 a call pushes the return address.",
                  "`bl` only sets `x30`. A function that makes calls of its own saves `x30` on the stack in its prologue; a leaf function need not."),
            wrong("Local variables start out as zero.",
                  "A new frame contains whatever earlier calls left in that memory, unless the compiler was asked to initialise it."),
        ],
        next=["calling-conventions", "stack-canaries"],
        sources=["System V psABI for x86-64", "Arm: Procedure Call Standard for the Arm 64-bit Architecture (AAPCS64)",
                 "Microsoft: x64 calling convention, x64 prolog and epilog"],
    ),
    concept(
        id="calling-conventions",
        title="Calling conventions",
        level=2,
        summary="A calling convention fixes where arguments and results go and which registers a function must preserve. It belongs to the operating system's ABI, not to the CPU.",
        body=[
            "For separately compiled functions to call each other, caller and callee must agree on where the "
            "arguments are, where the result goes, which registers the callee may overwrite, and how the stack "
            "is aligned. That agreement is the [[calling-convention|calling convention]], part of the platform's "
            "[[abi|ABI]].",
            table(
                ["", "System V x86-64 (Linux, macOS)", "Windows x64", "ARM64 (AAPCS64)"],
                [
                    ["Integer arguments", "`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`, then stack", "`rcx`, `rdx`, `r8`, `r9`, then stack", "`x0` to `x7`, then stack"],
                    ["Result", "`rax`", "`rax`", "`x0`"],
                    ["Preserved by callee", "`rbx`, `rbp`, `r12` to `r15`", "`rbx`, `rbp`, `rdi`, `rsi`, `r12` to `r15`, `xmm6` to `xmm15`", "`x19` to `x28`, `x29`, the low halves of `v8` to `v15` (`x30` is overwritten by every `bl`)"],
                    ["Stack alignment at a call", "16 bytes", "16 bytes", "16 bytes"],
                    ["Special", "128-byte red zone below `rsp`", "32 bytes of shadow space above the return address", "`x8` indirect result, `x16`/`x17` scratch for stubs, `x18` reserved by some systems"],
                ],
            ),
            "The same CPU therefore has different conventions on different systems: the first argument is in "
            "`rdi` on Linux and macOS and in `rcx` on Windows. Seeing which register is loaded just before a "
            "call is often enough to tell which system a piece of x86-64 code was compiled for.",
            "32-bit x86 has several conventions that pass arguments on the stack and differ in who removes "
            "them: the caller (`cdecl`) or the callee (`stdcall`, used by the Windows API).",
            note("Apple's ARM64 convention differs from AAPCS64 in details, for example in how variadic "
                 "arguments are passed and in reserving `x18`. arm64e additionally signs return addresses and "
                 "code pointers."),
        ],
        macho=[
            "x86-64 code follows the System V convention; ARM64 code follows Apple's variant of AAPCS64.",
        ],
        elf=[
            "The convention is defined by the processor supplement (psABI) for each architecture. The "
            "`e_ident[EI_OSABI]` and `e_flags` fields record ABI variants where an architecture has more than "
            "one.",
        ],
        pe=[
            "x64 has one standard convention (`__vectorcall` is an opt-in variant). The 32 bytes of shadow space explain the `sub rsp, 0x20` (or larger) at the "
            "start of almost every function that calls another.",
        ],
        differences="The conventions were chosen independently by the vendors of each system. Nothing in the CPU "
                    "forces either choice.",
        see=[
            see("The entry code: note which register is loaded before the first call", entry()),
        ],
        misconceptions=[
            wrong("The calling convention is a property of the CPU.",
                  "It is a property of the operating system's ABI. x86-64 has two in common use."),
            wrong("64-bit Windows and Linux pass arguments the same way.",
                  "They use different registers, and only Windows reserves shadow space."),
        ],
        next=["syscalls", "reading-disassembly"],
        sources=["System V psABI for x86-64, section 3.2", "Microsoft: x64 calling convention", "Arm: AAPCS64",
                 "Apple: Writing ARM64 code for Apple platforms"],
    ),
    concept(
        id="syscalls",
        title="System calls",
        level=2,
        summary="A system call is a controlled transfer into the kernel, made with a dedicated instruction and a number that selects the service.",
        body=[
            "User code cannot touch devices, files or other processes directly. It asks the kernel, with a "
            "[[syscall|system call]]: a special instruction switches the CPU to kernel mode at an entry point "
            "the kernel chose, a number in a register selects the service, and other registers carry the "
            "arguments.",
            table(
                ["System", "Instruction", "Number in", "Arguments in"],
                [
                    ["Linux x86-64", "`syscall`", "`rax`", "`rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`"],
                    ["Linux ARM64", "`svc #0`", "`x8`", "`x0` to `x5`"],
                    ["Linux 32-bit x86", "`int 0x80`", "`eax`", "`ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp`"],
                    ["macOS x86-64", "`syscall`", "`eax` (class in the top byte)", "as Linux x86-64 (`r10` in place of `rcx`)"],
                    ["macOS ARM64", "`svc #0x80`", "`x16`", "`x0` onward"],
                ],
            ),
            "Whether programs may issue these instructions themselves depends on the system. Linux guarantees "
            "that system call numbers do not change, so static executables and other C libraries are possible. "
            "macOS and Windows guarantee only the interface of their system libraries; the numbers behind it "
            "change between releases, and programs are expected to call the library (`libSystem`, `ntdll.dll`) "
            "instead.",
            "Most library functions are not system calls. `strlen` never enters the kernel; `printf` does only "
            "when its buffer is flushed; `fopen` wraps `open` with bookkeeping of its own.",
        ],
        macho=[
            "System call instructions normally appear only inside `libsystem_kernel.dylib`. An ordinary "
            "executable that contains `svc` or `syscall` instructions is unusual and worth a look.",
        ],
        elf=[
            "Static executables and the C library contain the instructions directly. Some frequent calls, such "
            "as reading the clock, are served without entering the kernel by the [[vdso|vDSO]], a small shared "
            "library the kernel maps into every process.",
        ],
        pe=[
            "The stubs are in `ntdll.dll` (`NtCreateFile` and so on): load the number into `eax`, execute "
            "`syscall`. Programs reach them through documented APIs in `kernel32.dll` and other DLLs.",
        ],
        differences="Linux treats the kernel interface as the stable boundary. Apple and Microsoft put the "
                    "boundary one level higher, at a system library, and keep the freedom to change what is below.",
        see=[
            see("The code around the entry point (the ELF64 and firmware samples contain a system call instruction)", entry()),
        ],
        misconceptions=[
            wrong("A system call is an ordinary function call.",
                  "It changes the CPU's privilege level and enters the kernel at a fixed point. The 'function' is selected by a number, not an address."),
            wrong("System call numbers are the same everywhere.",
                  "They differ between operating systems, between architectures on the same system, and on macOS and Windows between releases."),
        ],
        next=["reading-disassembly", "mitigations-overview"],
        sources=["syscall(2), syscalls(2), vdso(7)", "System V psABI for x86-64, appendix A.2", "XNU: bsd/kern/syscalls.master"],
    ),
    concept(
        id="reading-disassembly",
        title="Reading the disassembly view",
        level=2,
        summary="An instruction is a mnemonic and its operands. A handful of patterns account for most of what you see.",
        body=[
            "The disassembly view decodes bytes of a code section into [[instruction|instructions]]. Each row "
            "shows the file offset, the address, the raw bytes, the [[mnemonic]] (the operation) and the "
            "[[operand|operands]] (what it works on).",
            ul(
                "x86-64 instructions vary in length from 1 to 15 bytes. The view uses Intel syntax: the "
                "destination comes first, so `mov rbp, rsp` copies `rsp` into `rbp`. Registers have 64-bit names "
                "(`rax`) and 32-bit names for their low halves (`eax`); writing the 32-bit name clears the "
                "upper half.",
                "ARM64 instructions are always 4 bytes. The destination also comes first. `x0` to `x30` are the "
                "64-bit registers and `w0` to `w30` their low halves; `sp` is the stack pointer; `x29` is the "
                "frame pointer and `x30` the link register.",
            ),
            "Things to look for, roughly in this order:",
            ul(
                "Function boundaries: a [[prologue]] at the start, `ret` at the end.",
                "Calls: `call` or `bl` with an address is a direct call; `call` through memory, or `blr`, is an "
                "indirect call, typically through an import slot or a function pointer.",
                "Decisions: `cmp` or `test` sets the flags, and a conditional jump (`je`, `jne`, `b.eq`) acts "
                "on them. ARM64 also has `cbz` and `cbnz`, which test a register for zero and branch in one "
                "instruction.",
                "Address formation: `lea reg, [rip + N]` on x86-64 and the pair `adrp` + `add` on ARM64 produce "
                "the address of a string or a variable.",
            ),
            "With Learn mode on, hovering or focusing a mnemonic explains it, and recognised sequences "
            "(prologue, epilogue, import stub, system call set-up, pointer signing) are labelled in the listing.",
            note("The built-in decoder covers a subset of each instruction set and shows what it cannot decode "
                 "as `.byte` or `.long`. It decodes linearly, so data placed among code is shown as if it were "
                 "instructions. When the tool runs locally and finds `objdump`, that is used instead."),
        ],
        macho=[
            "`LC_FUNCTION_STARTS` lists where functions begin even when symbols are stripped, and "
            "`LC_DATA_IN_CODE` marks ranges inside `__text` that are data.",
        ],
        elf=[
            "Without `.symtab`, function boundaries have to be inferred from the entry point, call targets and "
            "unwind tables.",
        ],
        pe=[
            "On x64 the exception directory (`.pdata`) lists the start and end of every function that has "
            "unwind data, which is a reliable source of function boundaries.",
        ],
        see=[
            see("Disassembly at the entry point", entry()),
            see("Function starts and the entry point", view("function_starts")),
        ],
        misconceptions=[
            wrong("Disassembly recovers the source code.",
                  "It recovers the instructions. Names, types and structure are gone unless debug information is available."),
            wrong("Every byte in a code section is an instruction.",
                  "Compilers place padding, jump tables and constants among the code."),
        ],
        next=["stack-and-frames", "calling-conventions", "mitigations-overview"],
    ),

    # ------------------------------------------------------------------ hardening
    concept(
        id="mitigations-overview",
        title="Exploit mitigations: what each one prevents",
        level=2,
        summary="A mitigation does not fix a bug. It breaks one step of the attack that would turn the bug into control of the program.",
        body=[
            "The classic attack on native code has three steps. A memory-safety bug (a "
            "[[buffer-overflow|buffer overflow]], a use after free) lets the attacker write where they should "
            "not. They use the write to change a value that controls execution: a return address, a function "
            "pointer, a [[got|GOT]] entry. Execution then goes where they choose: to code they injected, or to "
            "existing code used out of context ([[rop|return-oriented programming]]).",
            "Each mitigation targets one step:",
            table(
                ["Mitigation", "Prevents", "Does not prevent"],
                [
                    ["[[nx|NX / DEP]], [[w-xor-x|W^X]]", "running injected data as code", "reusing code that is already executable"],
                    ["[[aslr|ASLR]]", "knowing addresses in advance", "attacks that first leak an address"],
                    ["[[stack-canary|Stack canary]]", "a contiguous overflow reaching the return address unnoticed", "writes that skip the canary; corruption of other data"],
                    ["[[relro|RELRO]], `__DATA_CONST`, read-only IAT", "overwriting the loader's pointer tables", "overwriting other function pointers"],
                    ["[[cfi|CFG, IBT, BTI]]", "indirect jumps to arbitrary addresses", "jumps to other valid targets"],
                    ["[[shadow-stack|Shadow stack]], [[pac|PAC]] return signing", "using a corrupted return address", "corruption of data"],
                    ["[[code-signature|Code signing]]", "running code that was modified or is of unknown origin", "bugs in correctly signed code"],
                ],
            ),
            "A mitigation is a property of three parties together: the binary declares or contains support for "
            "it, the operating system enforces it, and sometimes the CPU must provide a feature. A flag in the "
            "file is therefore evidence, not proof. Some protections apply whatever the file says (64-bit "
            "Windows processes always have DEP), and some flags have no effect unless every loaded module and "
            "the hardware cooperate (CET).",
            "The Hardening view reports what can be read from the file. It cannot observe a running process.",
        ],
        macho=[
            "Read from the file: `MH_PIE`, segment permissions, the stack-protector symbols, the `arm64e` CPU "
            "subtype, the code signature and its flags (hardened runtime) and entitlements.",
        ],
        elf=[
            "Read from the file: `e_type` and `DF_1_PIE`, `PT_GNU_STACK`, `PT_GNU_RELRO` with the bind-now flags, "
            "the stack-protector symbols, and the feature bits in `.note.gnu.property`.",
        ],
        pe=[
            "Read from the file: the `DllCharacteristics` bits (`DYNAMIC_BASE`, `HIGH_ENTROPY_VA`, `NX_COMPAT`, "
            "`GUARD_CF`), section permissions, the load configuration directory, and the Authenticode signature.",
        ],
        see=[
            see("The hardening view for this file", view("security_audit")),
            see("The header field that carries most of the flags",
                hfield(macho="flags", elf="e_type", pe="OptionalHeader.DllCharacteristics")),
        ],
        misconceptions=[
            wrong("A binary that passes every check is secure.",
                  "The checks say that the standard obstacles are in place. They say nothing about whether the code has bugs."),
            wrong("Mitigations fix vulnerabilities.",
                  "The bug remains. A mitigation makes it harder, sometimes impractical, to turn into code execution."),
        ],
        next=["nx-wx", "stack-canaries", "relro", "cfi", "code-signing"],
    ),
    concept(
        id="nx-wx",
        title="Non-executable memory: NX, DEP and W^X",
        level=2,
        summary="Data pages are not executable, and no page is writable and executable at once, so bytes an attacker can write cannot be run.",
        body=[
            "The earliest exploits wrote machine code into a buffer on the stack and redirected execution to "
            "it. The answer is a per-page execute permission, enforced by the CPU: the stack, the heap and data "
            "segments are mapped without it. The feature is called [[nx|NX]] (no-execute) on x86, XN on ARM, "
            "and DEP (data execution prevention) on Windows.",
            "[[w-xor-x|W^X]] (\"write xor execute\") is the stricter rule that a page is never writable and "
            "executable at the same time. Code is mapped read and execute; data read and write. A program that "
            "generates code at run time (a JIT compiler) must switch a page between the two states.",
            "For a file, the questions are whether any segment asks for write and execute together, and whether "
            "the file requests an executable stack. Legitimate cases exist (older toolchains, some JIT designs), "
            "and so do packers, which need writable executable memory to unpack into.",
        ],
        macho=[
            "Segment permissions are `initprot` and `maxprot`. The header flag `MH_ALLOW_STACK_EXECUTION` asks "
            "for executable stacks, and is honoured only on configurations where code signing is not enforced "
            "globally.",
            "On Apple silicon, memory that is both writable and executable exists only as `MAP_JIT` memory, "
            "which each thread toggles between writable and executable; under the hardened runtime, using it "
            "requires an entitlement. The firmware sample has a read-write-execute segment.",
        ],
        elf=[
            "Segment permissions are in `p_flags`. The stack's permissions are taken from the `PT_GNU_STACK` "
            "program header; if `PF_X` is set there, the whole stack is executable. On some architectures a "
            "missing `PT_GNU_STACK` is treated as a request for an executable stack, for compatibility with old "
            "binaries.",
        ],
        pe=[
            "Section permissions are in `Characteristics` (`IMAGE_SCN_MEM_EXECUTE`, `IMAGE_SCN_MEM_WRITE`). "
            "`IMAGE_DLLCHARACTERISTICS_NX_COMPAT` (`0x0100`) declares that a 32-bit image works with DEP; "
            "64-bit processes have DEP regardless of the flag. The PE32 sample has a section that is readable, "
            "writable and executable.",
        ],
        see=[
            see("A segment that is writable and executable, if this file has one", segment("rwx", part="header"), optional=True),
            see("The permissions of the code segment",
                segment("exec", field={"macho": "initprot", "elf": "p_flags", "pe": "Characteristics"})),
            see("The stack permissions header", lc(elf=["PT_GNU_STACK"], field="p_flags"), ["elf"]),
            see("The DllCharacteristics field (NX_COMPAT)", hfield(pe="OptionalHeader.DllCharacteristics"), ["pe"]),
        ],
        misconceptions=[
            wrong("NX prevents buffer overflows.",
                  "The overflow still happens. NX prevents the overwritten memory from being executed, which is why attackers moved to reusing existing code."),
            wrong("A writable and executable section proves the file is malicious.",
                  "It is a strong signal worth explaining, but old compilers, some language runtimes and legitimate packers produce it too."),
        ],
        next=["stack-canaries", "aslr", "entropy-packing"],
        sources=["<mach-o/loader.h> (MH_ALLOW_STACK_EXECUTION)", "XNU: bsd/kern/mach_loader.c", "Linux: fs/binfmt_elf.c (PT_GNU_STACK)",
                 "Microsoft: /NXCOMPAT, Data Execution Prevention", "Apple: Porting just-in-time compilers to Apple silicon"],
    ),
    concept(
        id="stack-canaries",
        title="Stack canaries",
        level=2,
        summary="A secret value placed between a function's local buffers and its return address; if it has changed when the function returns, the program aborts.",
        body=[
            "A [[stack-canary|stack canary]] (stack protector, `/GS` cookie) is compiler-generated code. In the "
            "[[prologue]] of a protected function, a secret value is copied into the frame, between the local "
            "variables and the saved registers and return address. Before returning, the function compares the "
            "copy with the original. A linear overflow that reaches the return address must first overwrite the "
            "canary, the comparison fails, and the program calls a routine that terminates it.",
            "The secret is chosen at process start. The compiler protects only functions it considers at risk: "
            "with `-fstack-protector-strong`, the usual setting, those with arrays or with local variables "
            "whose address is taken.",
            table(
                ["System", "Where the secret is", "Failure routine"],
                [
                    ["Linux x86-64 (glibc)", "per thread, at `fs:0x28`", "`__stack_chk_fail`"],
                    ["Linux 32-bit x86 (glibc)", "per thread, at `gs:0x14`", "`__stack_chk_fail`"],
                    ["macOS", "the global `___stack_chk_guard` in the system library, reached through the GOT", "`___stack_chk_fail`"],
                    ["Windows (MSVC)", "the global `__security_cookie` in each image, combined with the frame address", "`__security_check_cookie`, which ends in a fast-fail"],
                ],
            ),
            "Tools infer the protection from these names: an import of `__stack_chk_fail`, or in PE the security "
            "cookie recorded in the load configuration directory. The inference has limits in both directions. "
            "A program with no arrays on the stack may be compiled with the option and contain no canary; a "
            "program that imports the symbol may still have unprotected functions.",
        ],
        macho=[
            "Look for the undefined symbols `___stack_chk_guard` and `___stack_chk_fail`. In the code, a load "
            "of the guard through the GOT near the start of a function and a compare before `ret` are the "
            "visible signs.",
        ],
        elf=[
            "Look for `__stack_chk_fail` in `.dynsym`. On x86-64 the code reads `fs:0x28` in the prologue.",
        ],
        pe=[
            "The cookie's address is stored in the `SecurityCookie` field of the load configuration directory "
            "(data directory 10). The check is a call to `__security_check_cookie`, which is linked statically "
            "and therefore has no import to look for.",
        ],
        see=[
            see("The symbols of this file (filter for 'stack_chk')", view("symtab")),
            see("The hardening view's canary check", view("security_audit")),
            see("The load configuration directory", lc(pe=["DATA_DIR_LOAD_CONFIG_TABLE"]), ["pe"]),
        ],
        misconceptions=[
            wrong("A canary prevents the overflow.",
                  "It detects one kind of overflow, when the function returns. Until then the corrupted frame is in use."),
            wrong("Every function in a protected binary has a canary.",
                  "Only functions the compiler's heuristic selects, unless the program was built with `-fstack-protector-all`."),
        ],
        next=["relro", "cfi"],
        sources=["GCC: -fstack-protector options", "Microsoft: /GS (Buffer Security Check)", "System V psABI (thread control block layout, glibc)"],
    ),
    concept(
        id="relro",
        title="Read-only pointer tables: RELRO, __DATA_CONST and the IAT",
        level=3,
        summary="Once the loader has filled in the GOT or IAT, the table is made read-only so that a stray write cannot redirect calls.",
        body=[
            "The [[got|GOT]] and the [[iat|IAT]] are tables of code pointers at known positions in every image, "
            "which makes them an obvious target: overwrite one entry and the next call to that function goes "
            "wherever the attacker likes.",
            "The tables need to be writable only while the loader fills them in. All three systems therefore "
            "remap them read-only once binding is finished, on the condition that binding *is* finished, which "
            "excludes lazily bound entries (see [[concept:lazy-binding|Lazy and eager binding]]).",
        ],
        macho=[
            "The linker places pointers that are only written by dyld in the segment `__DATA_CONST` and sets the "
            "segment flag `SG_READ_ONLY` (`0x10`). dyld maps the segment read-write, applies fixups, then makes "
            "it read-only. The permissions stored in the file for `__DATA_CONST` are still read-write; the "
            "flag is what marks it.",
            "Old-style lazy pointers (`__DATA,__la_symbol_ptr`) stay writable. Binaries with chained fixups "
            "have none.",
        ],
        elf=[
            "The `PT_GNU_RELRO` program header describes a range, inside the writable segment, that the "
            "dynamic linker makes read-only after relocation. The linker arranges for `.init_array`, "
            "`.fini_array`, `.dynamic` and `.got` to fall inside it.",
            "*Partial RELRO* is `PT_GNU_RELRO` with lazy binding: `.got.plt`, the table used by the PLT, stays "
            "writable. *Full RELRO* adds bind-now (`DF_BIND_NOW` or `DF_1_NOW`), so every slot is resolved "
            "before the range is locked and the PLT's slots are covered too.",
        ],
        pe=[
            "There is no flag. Current linkers place the IAT in the read-only `.rdata` section. The loader "
            "makes those pages writable while it binds imports and restores the protection afterwards; data "
            "directory 12 tells it which range that is.",
        ],
        differences="ELF expresses the request as a program header and makes the degree of protection depend on "
                    "the binding mode. Mach-O expresses it as a segment. PE relies on where the linker put the "
                    "table.",
        see=[
            see("The structure that requests the read-only remap",
                lc(elf=["PT_GNU_RELRO"]), ["elf"]),
            see("The __DATA_CONST segment and its flags",
                segment("name", name={"macho": "__DATA_CONST"}, field={"macho": "flags"}), ["macho"]),
            see("The IAT range", lc(pe=["DATA_DIR_IAT"]), ["pe"]),
            see("The hardening view's conclusion", view("security_audit")),
        ],
        misconceptions=[
            wrong("Partial RELRO protects the function pointers used by the PLT.",
                  "It protects `.got` but leaves `.got.plt` writable. Only full RELRO covers the PLT's slots."),
            wrong("RELRO is enforced by the kernel when it loads the file.",
                  "The kernel ignores `PT_GNU_RELRO`. The dynamic linker applies it with `mprotect` after it has finished relocating."),
        ],
        next=["cfi", "lazy-binding"],
        sources=["ld(1): -z relro, -z now", "<mach-o/loader.h> (SG_READ_ONLY)", "glibc: elf/dl-reloc.c (_dl_protect_relro)"],
    ),
    concept(
        id="cfi",
        title="Control-flow integrity: CFG, CET, PAC and BTI",
        level=3,
        summary="Even with code pointers corrupted, indirect branches and returns are restricted to legitimate destinations.",
        body=[
            "With injected code ruled out, attacks reuse existing code by corrupting the targets of *indirect* "
            "branches: calls through function pointers (the forward edge) and returns (the backward edge). "
            "[[cfi|Control-flow integrity]] narrows where those branches may go.",
            table(
                ["Mechanism", "Protects", "How", "Needs"],
                [
                    ["Control Flow Guard (Windows)", "indirect calls", "a check before each indirect call against a bitmap of valid function starts", "compiler and OS"],
                    ["Intel CET: indirect branch tracking", "indirect calls and jumps", "the target must begin with `endbr64`", "CPU, OS, all modules"],
                    ["Intel CET: shadow stack", "returns", "the CPU keeps a second, protected copy of each return address and compares on `ret`", "CPU, OS, all modules"],
                    ["ARM pointer authentication (PAC)", "returns; on arm64e, code and data pointers generally", "a keyed signature stored in the unused high bits of a pointer, verified before use", "CPU (ARMv8.3), OS"],
                    ["ARM branch target identification (BTI)", "indirect calls and jumps", "the target must be a `bti` landing pad", "CPU (ARMv8.5), OS"],
                ],
            ),
            "The instructions involved are visible in disassembly. `endbr64` at the top of a function is a "
            "landing pad for indirect branch tracking. `paciasp` at the top and `autiasp` before `ret` (or a "
            "single `retaa`) sign and verify the return address. On CPUs without the feature, `endbr64`, "
            "`paciasp`, `autiasp` and `bti` execute as no-operations, which is what lets one binary run "
            "everywhere.",
            "The presence of these instructions shows that the compiler was asked for them. Whether they are "
            "*enforced* depends on the CPU, on the operating system enabling the feature for the process, and, "
            "for CET, on every loaded library being marked compatible.",
        ],
        macho=[
            "The CPU subtype `arm64e` marks a binary that uses Apple's pointer authentication ABI: return "
            "addresses, function pointers, C++ virtual tables and imported pointers (`__auth_got`) are signed. "
            "Fixups for signed pointers carry the key and a diversity value so that dyld can sign them.",
        ],
        elf=[
            "Support is declared in the `.note.gnu.property` note (located by `PT_GNU_PROPERTY`). On x86 the "
            "property `GNU_PROPERTY_X86_FEATURE_1_AND` has bit 0 for IBT and bit 1 for shadow stack; on ARM64 "
            "`GNU_PROPERTY_AARCH64_FEATURE_1_AND` has bit 0 for BTI and bit 1 for PAC. The linker sets a bit "
            "only if every input object has it.",
            note("Kernel and C library support for the x86 features arrived gradually: user-space shadow stacks "
                 "were added to Linux in version 6.6. Check the state of your distribution rather than assuming "
                 "either way."),
        ],
        pe=[
            "`IMAGE_DLLCHARACTERISTICS_GUARD_CF` (`0x4000`) says the image contains Control Flow Guard checks; "
            "the table of valid call targets is located through the load configuration directory. "
            "Compatibility with CET shadow stacks is recorded in an extended-characteristics entry of the debug "
            "directory (linker option `/CETCOMPAT`).",
        ],
        differences="Windows implemented the forward-edge check in software first, so it works on any CPU. The "
                    "Intel and ARM mechanisms are CPU features that the compiler prepares the code for.",
        see=[
            see("The entry code: look for endbr64, paciasp or bti", entry()),
            see("The field or note that declares support",
                hfield(macho="cpusubtype", pe="OptionalHeader.DllCharacteristics"), ["macho", "pe"]),
            see("Notes, including GNU properties", view("code_signature"), ["elf"]),
            see("The hardening view", view("security_audit")),
        ],
        misconceptions=[
            wrong("endbr64 in the code means CET is active.",
                  "It means the compiler emitted landing pads. Enforcement needs a CPU with CET, an operating system that turns it on for the process, and compatible libraries."),
            wrong("Pointer authentication encrypts pointers.",
                  "It adds a signature to the otherwise unused upper bits. The address itself stays readable."),
            wrong("Control Flow Guard protects return addresses.",
                  "It checks indirect calls only. Returns are protected by shadow stacks."),
        ],
        next=["code-signing", "mitigations-overview"],
        sources=["Microsoft: Control Flow Guard, /CETCOMPAT", "Intel: Control-flow Enforcement Technology specification",
                 "Arm: Armv8.3 pointer authentication, Armv8.5 BTI", "Linux x86-64 psABI and AArch64 ELF ABI (GNU property notes)",
                 "Apple: Preparing your app to work with pointer authentication"],
    ),
    concept(
        id="code-signing",
        title="Mach-O code signatures",
        level=3,
        summary="A signature is a table of page hashes, sealed by one hash, optionally signed by a certificate. The kernel checks pages against it as they are loaded.",
        body=[
            "`LC_CODE_SIGNATURE` locates the signature at the end of `__LINKEDIT`. It is a *SuperBlob* (magic "
            "`0xfade0cc0`): an index of typed blobs. All of its integers are big-endian.",
            ul(
                "The [[code-directory|CodeDirectory]] (magic `0xfade0c02`) holds the identifier, flags, and an "
                "array of hashes: one for each page of the file from the start up to the signature. It also "
                "holds *special slots*, hashes of the other parts of the signature (requirements, entitlements) "
                "and of bundle files (`Info.plist`, the resource seal).",
                "The [[entitlements|entitlements]] blob lists the privileges the program requests, as a property "
                "list (and again in DER form in newer signatures).",
                "The requirements blob holds rules about who may be considered the same program.",
                "The CMS blob is a standard cryptographic signature over the CodeDirectory, with the signer's "
                "certificate chain. In an [[ad-hoc-signature|ad-hoc]] signature it is empty or absent.",
            ),
            "The hash of the CodeDirectory is the [[cdhash]], the identity of that exact build. Trust is a "
            "chain: the certificate (or a system list of trusted cdhashes) vouches for the CodeDirectory; the "
            "CodeDirectory vouches for every page and for the entitlements.",
            "Validation is lazy. When a page of the file is brought into memory, the kernel hashes it and "
            "compares the result with the slot in the CodeDirectory. A page that does not match is not allowed "
            "to stay valid, and where enforcement is on, the process is killed.",
            "On Apple silicon all native code must be signed, at least ad hoc; the linker adds such a signature "
            "automatically. Changing one byte of a signed file therefore breaks it until it is signed again "
            "(`codesign -f -s - file` replaces the signature with a new ad-hoc one).",
        ],
        macho=[
            "Flags in the CodeDirectory record properties such as ad-hoc (`0x2`), hardened runtime (`0x10000`) "
            "and linker-signed (`0x20000`). Notarisation is not part of this structure: it is a separate ticket "
            "that refers to the cdhash.",
        ],
        elf=[
            "ELF has no standard embedded code signature. Integrity is provided around the file: package "
            "signatures, filesystem mechanisms such as fs-verity and IMA, and, for kernel modules, a signature "
            "appended to the file. The [[build-id|build ID]] is an identifier, not a signature.",
        ],
        pe=[
            "The counterpart is Authenticode; see [[concept:authenticode|Authenticode]]. It signs one hash of "
            "the whole file rather than a table of page hashes.",
        ],
        differences="Apple's design hashes page by page so that the kernel can verify code incrementally as it "
                    "is paged in. Authenticode signs one digest of the whole file, checked by whoever asks.",
        see=[
            see("The load command that locates the signature", lc(macho=["LC_CODE_SIGNATURE"]), ["macho"]),
            see("The signature blob itself", signature(), ["macho"]),
            see("The decoded signature", view("code_signature")),
        ],
        misconceptions=[
            wrong("An ad-hoc signature identifies who built the program.",
                  "It contains hashes but no certificate. It establishes that the file is internally consistent, not where it came from."),
            wrong("Code signing encrypts the program.",
                  "The code is unchanged and readable. The signature only allows changes to be detected."),
        ],
        next=["authenticode", "mitigations-overview"],
        sources=["XNU: osfmk/kern/cs_blobs.h", "Apple TN3126: Inside Code Signing: Hashes", "Apple TN3127: Inside Code Signing: Requirements", "codesign(1)"],
    ),
    concept(
        id="authenticode",
        title="Authenticode: PE signatures",
        level=3,
        summary="A PKCS #7 signature appended to the file, covering a hash of everything except itself and two header fields.",
        body=[
            "A signed PE file carries its signature at the end of the file, outside every section. Data "
            "directory 4, the *certificate table*, locates it, and is the one directory whose first field is a "
            "file offset rather than an RVA, because the signature is not mapped into memory.",
            "The table is a sequence of `WIN_CERTIFICATE` entries: a length, a revision (`0x0200`), a type "
            "(`0x0002` for PKCS #7 signed data) and the signature bytes. The PKCS #7 structure contains the "
            "digest of the file, the signer's certificate chain and, usually, a countersignature from a "
            "timestamp authority so that the signature stays valid after the certificate expires.",
            "The digest covers the file with three exclusions: the `CheckSum` field of the optional header, the "
            "certificate table's data directory entry, and the certificate table itself.",
            ul(
                "For ordinary programs a signature is checked when something asks: the download reputation "
                "prompt, an elevation prompt, an application control policy. An unsigned program runs.",
                "For kernel drivers a valid signature is required.",
                "An image with `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` (`0x0080`) is checked at load.",
            ),
            "Files can also be signed without an embedded signature, by listing their hash in a signed "
            "*catalog* file. Many Windows system files are signed this way, so the absence of a certificate "
            "table does not prove a file is unsigned.",
        ],
        macho=[
            "Compare the [[concept:code-signing|Mach-O signature]]: a table of page hashes that the kernel "
            "verifies as pages are loaded, rather than one digest.",
        ],
        elf=[
            "No equivalent structure exists in the ELF format.",
        ],
        pe=[
            "The optional header's `CheckSum` is an unrelated, non-cryptographic checksum. It is verified only "
            "for drivers and a few system-critical DLLs, and many linkers leave it zero.",
        ],
        see=[
            see("The certificate table directory entry", lc(pe=["DATA_DIR_CERTIFICATE_TABLE"]), ["pe"]),
            see("The signature data at the end of the file", signature(), ["pe"]),
            see("The decoded signature", view("code_signature"), ["pe"]),
            see("The CheckSum field", hfield(pe="OptionalHeader.CheckSum"), ["pe"]),
        ],
        misconceptions=[
            wrong("A signed program is a safe program.",
                  "A signature tells you who signed the file and that it has not changed since. It makes no statement about what the program does."),
            wrong("No certificate table means the file is unsigned.",
                  "It may be catalog-signed. That can only be checked on a system that has the catalog."),
            wrong("The CheckSum field protects the file against tampering.",
                  "It is a simple sum that anyone can recompute, and the loader ignores it for ordinary programs."),
        ],
        next=["code-signing", "entropy-packing"],
        sources=["Microsoft PE/COFF specification: The Attribute Certificate Table", "Microsoft: Windows Authenticode Portable Executable Signature Format"],
    ),

    # ------------------------------------------------------------------ forensics
    concept(
        id="entropy-packing",
        title="Entropy and packing",
        level=2,
        summary="Entropy measures how evenly byte values are distributed. Compressed and encrypted data score near the maximum, which is how packed files are noticed.",
        body=[
            "[[entropy|Shannon entropy]], computed over the byte values of a region, ranges from 0 bits per "
            "byte (every byte the same) to 8 (all 256 values equally frequent). It depends only on how often "
            "each value occurs, not on their order.",
            table(
                ["Content", "Typical entropy (bits per byte)"],
                [
                    ["zero padding", "near 0"],
                    ["text, tables of pointers", "about 3 to 5"],
                    ["machine code", "about 5 to 6.5"],
                    ["compressed or encrypted data", "above about 7.2"],
                ],
            ),
            note("These ranges are rules of thumb. They vary with architecture and with the size of the region; "
                 "small regions give unreliable values."),
            "A [[packer]] compresses or encrypts a program and prepends a small routine that restores it in "
            "memory at start-up and then jumps to the original entry point. The file on disk then shows the "
            "packed data, not the program. Typical signs, none conclusive alone:",
            ul(
                "a section with entropy near 8 that is marked executable;",
                "a section with almost no bytes in the file and a large size in memory, writable and executable;",
                "very few imports, often just the functions needed to load libraries and change page protections;",
                "an entry point outside the first code section;",
                "unusual section names (`UPX0`, `UPX1`).",
            ),
            "High entropy has innocent causes too: embedded images and archives, compressed debug sections, "
            "cryptographic tables, and the signature at the end of a signed file.",
        ],
        macho=[
            "iOS apps distributed through the App Store have part of their `__TEXT` segment encrypted on disk; "
            "the `LC_ENCRYPTION_INFO_64` command gives the range, and its `cryptid` field is non-zero while the "
            "range is encrypted. Such a file cannot be disassembled meaningfully until it has been decrypted.",
        ],
        elf=[
            "Packed ELF files often have no section headers and one or two `PT_LOAD` segments, one of them "
            "writable and executable.",
        ],
        pe=[
            "PE is where packing is most common. Compare `SizeOfRawData` with `VirtualSize` for each section, "
            "check the permissions in `Characteristics`, and compare the import count with what a program of "
            "that size would need.",
        ],
        see=[
            see("Entropy per section for this file", view("semantic_intel")),
            see("A writable and executable segment, if there is one", segment("rwx", part="header"), optional=True),
            see("The entry point", view("function_starts")),
        ],
        misconceptions=[
            wrong("High entropy means malware.",
                  "It means the bytes look random. Compression is the usual reason, and it is used by legitimate software as well."),
            wrong("Low entropy means the file is not packed.",
                  "Simple encodings and padding can lower the measured value. Entropy is one signal among several."),
        ],
        next=["debug-info", "stripping"],
    ),
    concept(
        id="debug-info",
        title="Debug information and build identifiers",
        level=2,
        summary="Debug information maps machine code back to source. It usually lives outside the shipped binary and is matched to it by a unique identifier.",
        body=[
            "[[debug-info|Debug information]] is what lets a debugger show source lines, variable names and "
            "types. It records, among other things, which address belongs to which line of which source file, "
            "the layout of every type, and where each variable lives at each point in the code.",
            "It is large, often several times the size of the code, so shipped binaries rarely contain it. It "
            "is kept in a separate file, and the binary carries a unique identifier so that the right file can "
            "be found later, for example when a crash report arrives.",
            table(
                ["", "Mach-O", "ELF", "PE"],
                [
                    ["Format", "[[dwarf|DWARF]]", "DWARF", "[[pdb|PDB]]"],
                    ["Separate file", "`.dSYM` bundle", "`.debug` file", "`.pdb` file"],
                    ["Identifier in the binary", "`LC_UUID`", "`NT_GNU_BUILD_ID` note", "GUID and age in the debug directory"],
                ],
            ),
            "The identifier must match exactly. Rebuilding the same source generally produces a different one "
            "unless the build is reproducible.",
            "[[unwind-info|Unwind tables]] are a different thing. They are needed at run time for exceptions "
            "and stay in the binary.",
        ],
        macho=[
            "The linker does not copy DWARF into the executable. It leaves it in the object files and writes a "
            "*debug map* (symbol table entries of the `N_OSO` kind) that names them. `dsymutil` follows the map "
            "and collects the DWARF into a `.dSYM` bundle, a directory whose payload is a Mach-O file of type "
            "`MH_DSYM` with the same `LC_UUID`.",
        ],
        elf=[
            "DWARF is in sections named `.debug_info`, `.debug_line`, `.debug_str` and so on, either in the "
            "binary or split out into a file found by build ID (conventionally under "
            "`/usr/lib/debug/.build-id/`) or fetched from a `debuginfod` server. The build ID is a note in the "
            "`PT_NOTE` segment.",
        ],
        pe=[
            "Data directory 6 locates the debug directory. Its CodeView entry begins with the signature `RSDS`, "
            "followed by a GUID, an age counter and the path of the PDB as it was on the build machine. Symbol "
            "servers index PDB files by GUID and age.",
        ],
        see=[
            see("The identifier that ties this file to its debug information", debug_id()),
            see("Overview: the identifier and build details", view("overview")),
        ],
        misconceptions=[
            wrong("A release build has no connection to debug information.",
                  "It normally carries the identifier, and the matching debug file is archived by whoever built it."),
            wrong("The PDB path in a PE file is harmless.",
                  "It is a string from the build machine and often reveals a user name, a project name or a directory layout."),
        ],
        next=["stripping", "symbols"],
        sources=["DWARF Debugging Information Format, version 5", "dsymutil(1)", "Microsoft PE/COFF specification: The Debug Section"],
    ),
    concept(
        id="stripping",
        title="Stripping: what can be removed and what cannot",
        level=2,
        summary="Stripping removes the symbols and sections that only tools use. Whatever the loader needs stays, and so do several other sources of names.",
        body=[
            "To [[strip]] a binary is to remove what is not needed to run it: local symbol names and debug "
            "sections. The file gets smaller and harder to read.",
            "What the loader needs cannot be removed. Imported and exported names, the dynamic symbol table, "
            "load-time relocations and the segment table all stay. An analyst working on a stripped file "
            "still has:",
            ul(
                "every imported function name, which says a great deal about what the program does;",
                "exported names, for a library;",
                "strings;",
                "names kept by language runtimes for their own use: Objective-C class and method names, Swift "
                "and C++ type information;",
                "function boundaries, from unwind tables or dedicated tables.",
            ),
        ],
        macho=[
            "`strip` with no options removes local `nlist` entries and the debug map, and with current tools "
            "the entries of defined global symbols too. Undefined (imported) symbols remain, and exported "
            "names remain in the [[export-trie|export trie]]. `LC_FUNCTION_STARTS` still lists where every function begins, as a sequence of ULEB128-encoded "
            "distances, so tools can show unnamed functions at the right addresses.",
        ],
        elf=[
            "`strip` removes `.symtab`, `.strtab` and the `.debug_*` sections. `.dynsym` stays because it is "
            "part of a loaded segment. The section header table itself can be removed by other tools without "
            "affecting execution.",
        ],
        pe=[
            "There is little to strip from an image built with Microsoft's tools, because its symbols went to "
            "the PDB and were never in the image. (Images built with GNU tools can carry a COFF symbol table "
            "and DWARF sections, which `strip` removes.) What can be left out is the debug directory. The `Rich` header that Microsoft's linker inserts "
            "after the DOS stub, recording the tool versions used, also remains unless it is removed "
            "deliberately.",
        ],
        differences="ELF and Mach-O ship symbols in the binary by default and remove them on request. "
                    "Microsoft's toolchain writes them to a separate file from the start.",
        see=[
            see("The symbols that remain in this file", view("symtab")),
            see("Function starts", view("function_starts")),
            see("The function-starts load command", lc(macho=["LC_FUNCTION_STARTS"]), ["macho"]),
            see("The Rich header", lc(pe=["IMAGE_RICH_HEADER"]), ["pe"]),
        ],
        misconceptions=[
            wrong("A stripped binary contains no names.",
                  "It contains at least every name needed for dynamic linking, and usually many strings and runtime metadata."),
            wrong("Stripping protects a program against analysis.",
                  "It removes conveniences. The code, its imports and its control flow are all still there."),
        ],
        next=["debug-info", "reading-disassembly"],
        sources=["strip(1)", "<mach-o/loader.h> (LC_FUNCTION_STARTS)"],
    ),
]
