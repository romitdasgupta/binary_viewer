"""
Instruction-level help for the disassembly view: what each mnemonic does, and
which multi-instruction idioms to label.

Coverage is every mnemonic that the built-in decoder (backend/labs_encoding.py,
used by backend/disasm.py) can emit for x86 / x86-64 and ARM64; tests enumerate
the decoder to check this. Anything else (an external disassembler is used for
x86 in local mode) simply has no help.

MNEMONICS  {arch: {mnemonic: {"title", "text", "concept"} | {"title", "family"}}}
           arch is "x86" (i386 and x86-64) or "arm64". Text is rich (see learn_content).
           Members of a large family carry only a title and the family id.
FAMILIES   {family id: {"title", "text", "concept"}}: the explanation shared by a family.
PREFIXES   {"x86": {prefix: {"title", "text"}}}: prefixes printed before a mnemonic ("lock add").
           `lookup(arch, mnemonic)` merges all three into {"title", "text", "concept"}.
IDIOMS     [{"id", "arch", "title", "text", "concept", "steps": [step, ...]}]
           A step matches one row of the listing:
             mn   mnemonics, any of which matches (lower case, exact; required)
             ops  operand patterns, any of which must match the operands
             txt  patterns, any of which must match "operands ; comment"
             opt  True: the step may be absent
             gap  up to this many unrelated rows may precede the step
           The first step must match the row where the idiom starts. Earlier idioms take
           priority at the same row.

           Patterns are not regular expressions. The text is normalised first (lower case,
           whitespace runs collapsed to one space, no space after a comma: "x29,x30,[sp,#-16]!"),
           and a pattern is a literal string with at most these additions:
             *      at the very start: may match anywhere (search); at the very end: prefix match
             {n}    one or more decimal digits          {hex}  (0x)? then one or more hex digits
             {imm}  0x<hex digits> or <decimal digits>  {w}    one or more of [a-z0-9_]
             {w=}   the same text as the last {w}
           Every token consumes the longest run it can and never backtracks, so a match costs
           at most len(pattern) x len(text) steps. `parse_pattern` rejects anything else.

`annotate()` is the reference implementation of the matcher; static/js/learn.js
carries an equivalent one for the browser (it validates what it receives and never
compiles a regular expression from the wire). Rows that fall inside a reported idiom
do not start another one, and a run of padding is reported once.
"""

from typing import Any, Dict, List, Optional


def _m(title: str, text: str, concept: str = "reading-disassembly") -> Dict[str, str]:
    return {"title": title, "text": text, "concept": concept}


_X86_JCC = {
    "je": "equal (zero flag set)", "jz": "zero (zero flag set)",
    "jne": "not equal (zero flag clear)", "jnz": "not zero (zero flag clear)",
    "jl": "less, signed", "jle": "less or equal, signed", "jg": "greater, signed", "jge": "greater or equal, signed",
    "jb": "below, unsigned (carry set)", "jbe": "below or equal, unsigned", "ja": "above, unsigned", "jae": "above or equal, unsigned (carry clear)",
    "js": "negative (sign flag set)", "jns": "not negative (sign flag clear)",
    "jo": "overflow", "jno": "no overflow", "jp": "parity even", "jnp": "parity odd",
}

X86: Dict[str, Dict[str, str]] = {
    "mov": _m("Copy", "Copies the second operand into the first. `mov rbp, rsp` copies `rsp` into `rbp`. With square brackets an operand is memory: `mov rax, [rbp - 8]` loads eight bytes from the stack."),
    "movabs": _m("Load a 64-bit constant", "Copies a full 64-bit immediate into a register. Ordinary `mov` can carry at most 32 bits of constant."),
    "movzx": _m("Copy with zero extension", "Copies a smaller value into a larger register and fills the upper bits with zeros. Used for unsigned bytes and words."),
    "movsx": _m("Copy with sign extension", "Copies a smaller value into a larger register and fills the upper bits with copies of its sign bit. Used for signed values."),
    "movsxd": _m("Copy with sign extension (32 to 64)", "Sign-extends a 32-bit value into a 64-bit register. Typical for using an `int` as an array index."),
    "lea": _m("Compute an address", "Computes the address its memory operand describes and stores the address, without reading memory. `lea rdi, [rip + N]` is how position-independent code obtains the address of a string or variable. Compilers also use it for arithmetic.", "pic-pie"),
    "push": _m("Push onto the stack", "Decreases the stack pointer by the operand size and stores the operand there.", "stack-and-frames"),
    "pop": _m("Pop from the stack", "Loads the value at the stack pointer into the operand and increases the stack pointer.", "stack-and-frames"),
    "add": _m("Add", "Adds the second operand to the first. `add rsp, N` releases stack space."),
    "sub": _m("Subtract", "Subtracts the second operand from the first. `sub rsp, N` reserves stack space for local variables.", "stack-and-frames"),
    "inc": _m("Increment", "Adds one to the operand."),
    "dec": _m("Decrement", "Subtracts one from the operand."),
    "imul": _m("Signed multiply", "Multiplies. The two- and three-operand forms store the low half of the product in the destination register."),
    "xor": _m("Exclusive or", "Bitwise exclusive or. `xor eax, eax` is the standard way to set a register to zero."),
    "and": _m("Bitwise and", "Clears the bits that are zero in the second operand. `and rsp, -16` aligns the stack pointer to 16 bytes."),
    "or": _m("Bitwise or", "Sets the bits that are one in the second operand."),
    "not": _m("Bitwise not", "Inverts every bit of the operand."),
    "neg": _m("Negate", "Replaces the operand with its two's complement negative."),
    "shl": _m("Shift left", "Shifts bits left; each position multiplies by two."),
    "shr": _m("Shift right (unsigned)", "Shifts bits right and fills with zeros; each position divides an unsigned value by two."),
    "sar": _m("Shift right (signed)", "Shifts bits right and fills with copies of the sign bit; divides a signed value by two per position, rounding down."),
    "cmp": _m("Compare", "Subtracts the second operand from the first, keeps only the flags and discards the result. A conditional jump normally follows."),
    "test": _m("Test bits", "Computes the bitwise and of the operands, keeps only the flags and discards the result. `test rax, rax` checks whether `rax` is zero."),
    "call": _m("Call", "Pushes the address of the next instruction (the return address) and jumps to the target. With a memory operand the target is read from memory: an indirect call, typically through an import slot or a function pointer.", "stack-and-frames"),
    "jmp": _m("Jump", "Continues execution at the target. With a memory operand the target is read from memory; a `jmp` through a pointer slot is what an import stub consists of.", "got-plt"),
    "ret": _m("Return", "Pops the return address from the stack and jumps to it.", "stack-and-frames"),
    "leave": _m("Release the stack frame", "Equivalent to `mov rsp, rbp` followed by `pop rbp`: discards the local variables and restores the caller's frame pointer.", "stack-and-frames"),
    "nop": _m("No operation", "Does nothing. Used as padding so that the next function or loop starts at an aligned address."),
    "int3": _m("Breakpoint", "Raises a breakpoint trap. Debuggers insert it to stop a program; Microsoft's linker also fills the gaps between functions with it, so that stray execution stops at once."),
    "int": _m("Software interrupt", "Enters the kernel through the given interrupt vector. `int 0x80` is the legacy 32-bit Linux system call; `int 0x29` is the Windows fast-fail.", "syscalls"),
    "syscall": _m("System call", "Enters the kernel. The system call number is in `rax`. On Linux the arguments are in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`; the instruction overwrites `rcx` and `r11`.", "syscalls"),
    "endbr64": _m("Indirect branch landing pad", "Marks a place that indirect calls and jumps are allowed to land on, for Intel CET indirect branch tracking. Executes as a no-operation when the feature is not active.", "cfi"),
    "endbr32": _m("Indirect branch landing pad (32-bit)", "The 32-bit form of `endbr64`.", "cfi"),
    "hlt": _m("Halt", "Stops the CPU until the next interrupt. Privileged: in user code it faults, which is why start-up code places it after a call that must not return."),
    "ud2": _m("Undefined instruction", "Guaranteed to raise an invalid-opcode fault. Compilers emit it for paths that must never execute."),
    "cdqe": _m("Sign-extend eax into rax", "Extends the 32-bit value in `eax` to 64 bits in `rax`."),
    "alu": _m("Arithmetic or logic operation (not fully decoded)", "The built-in decoder recognised an arithmetic instruction with an immediate operand but does not name this particular operation."),
    ".byte": _m("Not decoded", "The built-in decoder does not know the instruction that starts with this byte, or the bytes are data. It shows one byte and tries again at the next."),
}
for _name, _cond in _X86_JCC.items():
    X86[_name] = _m("Jump if " + _cond.split(" (")[0].split(",")[0],
                    "Jumps to the target if the flags say: " + _cond + ". The flags come from the last `cmp`, `test` or arithmetic instruction; otherwise execution continues with the next instruction.")

_A64_COND = {
    "eq": "equal", "ne": "not equal", "cs": "carry set (unsigned higher or same)", "hs": "unsigned higher or same",
    "cc": "carry clear (unsigned lower)", "lo": "unsigned lower", "mi": "negative", "pl": "positive or zero",
    "vs": "overflow", "vc": "no overflow", "hi": "unsigned higher", "ls": "unsigned lower or same",
    "ge": "signed greater or equal", "lt": "signed less", "gt": "signed greater", "le": "signed less or equal",
    "al": "always", "nv": "always",
}

ARM64: Dict[str, Dict[str, str]] = {
    "mov": _m("Copy", "Copies a register or a small constant into the first operand. `mov x29, sp` sets the frame pointer."),
    "movz": _m("Load a 16-bit constant", "Sets the register to a 16-bit constant, optionally shifted left by 16, 32 or 48 bits; all other bits become zero."),
    "movk": _m("Insert 16 bits", "Replaces 16 bits of the register with a constant and keeps the rest. A `movz` followed by up to three `movk` builds any 64-bit constant."),
    "movn": _m("Load an inverted constant", "Sets the register to the bitwise inverse of a shifted 16-bit constant. Used for negative numbers."),
    "add": _m("Add", "Adds the last operand to the second and stores the result in the first. After `adrp` it supplies the offset within the page.", "pic-pie"),
    "adds": _m("Add and set flags", "Adds and also updates the condition flags."),
    "sub": _m("Subtract", "Subtracts the last operand from the second. `sub sp, sp, #N` reserves stack space.", "stack-and-frames"),
    "subs": _m("Subtract and set flags", "Subtracts and also updates the condition flags."),
    "cmp": _m("Compare", "Subtracts and keeps only the flags (`subs` with the result discarded). A conditional branch normally follows."),
    "cmn": _m("Compare negative", "Adds and keeps only the flags."),
    "adr": _m("Address relative to here", "Computes an address at a fixed distance (up to 1 MiB) from this instruction.", "pic-pie"),
    "adrp": _m("Page address relative to here", "Computes the address of a 4 KiB page at a fixed distance (up to 4 GiB) from this instruction's page. A following `add` or `ldr` supplies the offset within the page. This pair is how ARM64 code refers to globals, strings and GOT entries.", "pic-pie"),
    "ldr": _m("Load", "Loads a register from memory. `ldr x8, [x8, #0x58]` reads the eight bytes at `x8 + 0x58`."),
    "str": _m("Store", "Stores a register to memory."),
    "ldrb": _m("Load byte", "Loads one byte from memory, zero-extended."),
    "strb": _m("Store byte", "Stores the low byte of a register to memory."),
    "ldrh": _m("Load halfword", "Loads two bytes from memory, zero-extended."),
    "strh": _m("Store halfword", "Stores the low two bytes of a register to memory."),
    "ldp": _m("Load pair", "Loads two registers from adjacent memory. `ldp x29, x30, [sp], #16` restores the frame pointer and return address and releases 16 bytes of stack.", "stack-and-frames"),
    "stp": _m("Store pair", "Stores two registers to adjacent memory. `stp x29, x30, [sp, #-16]!` first lowers `sp` by 16 and then saves the frame pointer and return address there.", "stack-and-frames"),
    "b": _m("Branch", "Continues execution at the target."),
    "bl": _m("Branch with link (call)", "Puts the address of the next instruction in `x30` and jumps to the target. This is a function call; nothing is pushed on the stack.", "stack-and-frames"),
    "br": _m("Branch to register", "Jumps to the address in a register. Import stubs end with `br x16`.", "got-plt"),
    "blr": _m("Call through register", "Puts the return address in `x30` and jumps to the address in a register: an indirect call."),
    "ret": _m("Return", "Jumps to the address in `x30` (or in the named register).", "stack-and-frames"),
    "b.cond": _m("Conditional branch", "Jumps to the target if the condition flags, set by an earlier `cmp`, `subs` or `adds`, satisfy the condition."),
    "cbz": _m("Branch if zero", "Jumps to the target if the register is zero. Compare and branch in one instruction; the flags are not used."),
    "cbnz": _m("Branch if not zero", "Jumps to the target if the register is not zero."),
    "nop": _m("No operation", "Does nothing. Used for padding and as a placeholder that tools may patch."),
    "svc": _m("Supervisor call (system call)", "Enters the kernel. Apple systems use `svc #0x80` with the call number in `x16`; Linux uses `svc #0` with the number in `x8`.", "syscalls"),
    "brk": _m("Breakpoint", "Raises a breakpoint exception. Compilers emit `brk #1` (or another small number) where the program must trap, for example after a failed check."),
    "udf": _m("Undefined instruction", "Permanently undefined: executing it faults. An all-zero word decodes as `udf #0`, so a run of these usually means padding or data, not code."),
    "paciasp": _m("Sign the return address", "Computes a pointer authentication code for `x30` using key A and the stack pointer as context, and stores it in the upper bits of `x30`. Placed at function entry, before `x30` is saved. A no-operation on CPUs without pointer authentication, and in processes for which the system has not enabled the key.", "cfi"),
    "pacibsp": _m("Sign the return address (key B)", "As `paciasp`, with key B.", "cfi"),
    "autiasp": _m("Authenticate the return address", "Checks the authentication code in `x30` against key A and the stack pointer. If it is wrong, `x30` is left invalid, so the following `ret` faults (newer CPUs fault at once). A no-operation on CPUs without pointer authentication, and in processes for which the system has not enabled the key.", "cfi"),
    "autibsp": _m("Authenticate the return address (key B)", "As `autiasp`, with key B.", "cfi"),
    "retaa": _m("Authenticate and return", "`autiasp` and `ret` combined in one instruction. Unlike the separate pair it has no meaning on CPUs without pointer authentication, so it appears only in code built for them, such as arm64e.", "cfi"),
    "retab": _m("Authenticate and return (key B)", "As `retaa`, with key B.", "cfi"),
    "braa": _m("Authenticated branch to register", "Authenticates the pointer in the first register with key A, using the second register as context, and jumps to it. arm64e import stubs end with `braa x16, x17`.", "cfi"),
    "blraa": _m("Authenticated call through register", "Authenticates a function pointer with key A and calls it. How arm64e code calls through function pointers and virtual tables.", "cfi"),
    "bti": _m("Branch target landing pad", "Marks a place that indirect branches may land on, for ARM branch target identification. `bti c` accepts indirect calls (`blr`) and jumps through `x16` or `x17`, `bti j` accepts indirect jumps (`br`), `bti jc` both. A no-operation where the feature is not active.", "cfi"),
    ".long": _m("Not decoded", "The built-in decoder does not know this instruction (it covers a subset of ARM64), or the four bytes are data. The raw word is shown."),
}


# -----------------------------------------------------------------------------
# The wider instruction set of the table-driven decoder (backend/labs_encoding.py).
# Large families share one explanation: a member is {"title", "family"} and
# FAMILIES[family] supplies "text" and "concept". lookup() merges the two.
# -----------------------------------------------------------------------------
def _f(title: str, family: str) -> Dict[str, str]:
    return {"title": title, "family": family}


FAMILIES: Dict[str, Dict[str, str]] = {
    "x86-cmov": _m("Conditional move", "Copies the second operand into the first only if the condition holds, judged from the flags left by the last `cmp`, `test` or arithmetic instruction. Otherwise the destination keeps its value (in 64-bit mode a 32-bit destination still has its upper 32 bits cleared). A memory source is read whether or not the condition holds. Compilers use it to avoid a branch."),
    "x86-setcc": _m("Set byte on condition", "Writes 1 into a byte register or a byte of memory if the condition holds and 0 if it does not. A `movzx` usually follows to widen the result."),
    "x86-sse-arith": _m("SSE floating-point arithmetic", "Floating-point arithmetic on `xmm` registers. The suffix names the operands: `ss` is one single-precision value, `sd` one double-precision value, `ps` four packed single-precision values, `pd` two packed double-precision values. The result replaces the first operand."),
    "x86-sse-logic": _m("SSE bitwise operation", "A bitwise operation on a whole `xmm` register. `xorps xmm0, xmm0` is the usual way to set a floating-point register to zero."),
    "x86-sse-compare": _m("SSE floating-point compare", "`comiss`, `comisd` and the `u` forms compare two scalar values and set the integer flags, so that an ordinary conditional jump can follow. The `cmp...ps/pd/ss/sd` forms write a mask instead: all ones in each element where the comparison holds, all zeros elsewhere."),
    "x86-sse-convert": _m("SSE conversion", "Converts between integers and floating-point values, or between single and double precision. In the name, `si` is an integer in a general register, `dq` packed 32-bit integers, `ss` and `sd` a scalar single or double, `ps` and `pd` packed singles or doubles. A second `t` (`cvtt...`) truncates toward zero instead of using the current rounding mode, which is what a C cast does."),
    "x86-sse-move": _m("SSE move", "Copies data to, from or between `xmm` registers. The `a` forms (`movaps`, `movdqa`) require a memory operand to be 16-byte aligned and fault otherwise; the `u` forms accept any address."),
    "x86-sse-shuffle": _m("SSE shuffle", "Rearranges the elements of `xmm` registers: selects, interleaves or adds neighbouring elements, as directed by the instruction and its immediate operand."),
    "x86-simd-int": _m("SSE2 packed integer operation", "An integer operation applied to every element of an `xmm` register at once. In most names the last letter gives the element size: `b` bytes, `w` 16-bit words, `d` 32-bit doublewords, `q` 64-bit quadwords. Two letters (`packsswb`, `pmuludq`) give the source and result sizes; `pslldq` and `psrldq` shift the whole 128-bit register by bytes."),
    "x86-string": _m("String instruction", "Works on the memory at `[rsi]` (source) and `[rdi]` (destination) and then advances the pointers by the element size, forward or backward according to the direction flag. With a `rep` prefix it repeats `rcx` times, which is how compilers inline small memory copies and fills."),
    "x86-flag": _m("Flag control", "Changes a single flag in the flags register. The carry flag takes part in multi-word arithmetic; the direction flag decides whether string instructions move forward or backward; the interrupt flag can be changed only by privileged code."),
    "x86-extend": _m("Sign-extend the accumulator", "Widens the value in the accumulator by copying its sign bit, either into the upper part of the same register (`cbw`, `cwde`, `cdqe`) or into `dx`/`edx`/`rdx` (`cwd`, `cdq`, `cqo`). The second group prepares the dividend for `idiv`."),
    "a64-csel": _m("Conditional select", "Writes one of two values to the destination depending on the condition flags, without branching. `csel` chooses between two registers; `csinc`, `csinv` and `csneg` increment, invert or negate the second one. `cset`, `csetm`, `cinc`, `cinv` and `cneg` are shorthand forms of these."),
    "a64-bitfield": _m("Bit-field move", "Copies a run of bits from one register to another: extracts a field (`ubfx`, `sbfx`), inserts one (`bfi`, `bfxil`, `ubfiz`, `sbfiz`), clears one (`bfc`), or widens a byte, halfword or word (`sxtb`, `sxth`, `sxtw`, `uxtb`, `uxth`). The `s` forms sign-extend the result; the `u` forms zero-extend it."),
    "a64-muldiv": _m("Multiply or divide", "`madd` and `msub` compute `ra + rn * rm` and `ra - rn * rm`; `mul` and `mneg` are the same with `ra` zero. The `l` forms multiply two 32-bit registers into a 64-bit result (`s` signed, `u` unsigned); `smulh` and `umulh` give the upper 64 bits of a 128-bit product. Division by zero does not trap on ARM64: the result is zero."),
    "a64-atomic": _m("Atomic memory operation", "One instruction that reads a memory location, combines it with a register and writes it back, with no other processor able to intervene (ARMv8.1 LSE). The `ld...` forms return the old value; the `st...` forms discard it. `swp` exchanges, `cas` compares and swaps. A suffix `a`, `l` or `al` adds acquire or release ordering; `b` or `h` selects a byte or halfword."),
    "a64-exclusive": _m("Exclusive load and store", "A load-exclusive marks an address; the matching store-exclusive succeeds only if nothing else has written there in between, and reports 0 for success in its status register. Loops of the two build atomic operations on CPUs without the single-instruction forms. An `a` (load) or `l` (store) in the name adds acquire or release ordering; `p` works on a pair; `b` and `h` on a byte or halfword."),
    "a64-ordered": _m("Load-acquire and store-release", "An ordinary load or store with an ordering guarantee toward other processors: the building block of C++ `memory_order_acquire` and `memory_order_release`."),
    "a64-load-store": _m("Load or store variant", "A form of `ldr`/`str`. `ldur` and `stur` take an unscaled offset; `ldrsb`, `ldrsh`, `ldrsw` and `ldpsw` sign-extend what they load; `ldnp` and `stnp` hint that the data will not be reused soon; `prfm` only asks the cache to fetch the address."),
    "a64-pac": _m("Pointer authentication", "`pac...` computes a pointer authentication code for the pointer in a register and stores it in the pointer's unused upper bits; `aut...` verifies it and restores the plain pointer, or leaves an invalid one if the check fails. The letters name what is signed (`i` for code pointers, `d` for data pointers) and the key (`a` or `b`). `z` uses zero as the modifier, `sp` the stack pointer, `1716` works on `x17` with `x16` as modifier. `xpac...` strips the code without checking it.", "cfi"),
    "a64-pac-branch": _m("Authenticated branch", "Authenticates a code pointer and branches to it in one step: `braa`/`brab` jump, `blraa`/`blrab` call, `retaa`/`retab` return. A trailing `z` uses zero as the modifier. These exist only on CPUs with pointer authentication, so they appear in code built for it, such as arm64e.", "cfi"),
    "a64-fp": _m("Floating-point operation", "Scalar floating-point arithmetic on the `s` (single), `d` (double) or `h` (half) view of a vector register. Plain `fcvt` converts between precisions. `fcvt` followed by two letters converts to an integer; the first letter is the rounding mode (`z` toward zero, `n` to nearest, `a` to nearest with ties away from zero, `p` toward plus infinity, `m` toward minus infinity) and the last letter says signed or unsigned. `scvtf` and `ucvtf` convert an integer to floating point. `frint...` rounds to an integral value in floating-point format."),
    "a64-system": _m("System instruction", "Affects the processor rather than data: a hint (`yield`, `wfe`, `wfi`, `sev`), a barrier that orders memory accesses or instruction fetches (`dmb`, `dsb`, `isb`) or constrains speculation (`csdb`), or access to a system register (`mrs` reads one, `msr` writes one). User code commonly reads the thread pointer: `tpidr_el0` on Linux, `tpidrro_el0` on Apple platforms."),
    "a64-crc": _m("CRC-32 step", "Updates a CRC-32 checksum with one byte, halfword, word or doubleword. The `c` forms use the Castagnoli polynomial (CRC-32C)."),
}

_X86_CC = dict(_X86_JCC)
for _cc, _text in (("c", "carry"), ("nc", "no carry"), ("nae", "below, unsigned"), ("nb", "above or equal, unsigned"),
                   ("na", "below or equal, unsigned"), ("nbe", "above, unsigned"), ("pe", "parity even"), ("po", "parity odd"),
                   ("nge", "less, signed"), ("nl", "greater or equal, signed"), ("ng", "less or equal, signed"), ("nle", "greater, signed")):
    _X86_CC["j" + _cc] = _text
for _name, _cond in _X86_CC.items():
    _short = _cond.split(" (")[0]
    X86["cmov" + _name[1:]] = _f("Move if " + _short, "x86-cmov")
    X86["set" + _name[1:]] = _f("Set byte if " + _short, "x86-setcc")
    if _name not in X86:
        X86[_name] = _m("Jump if " + _short.split(",")[0], "Jumps to the target if the flags say: " + _cond + ". Otherwise execution continues with the next instruction.")

_SSE_KIND = {"ps": "packed single-precision", "pd": "packed double-precision", "ss": "scalar single-precision", "sd": "scalar double-precision"}
for _stem, _what in (("add", "Add"), ("sub", "Subtract"), ("mul", "Multiply"), ("div", "Divide"), ("min", "Minimum of"),
                     ("max", "Maximum of"), ("sqrt", "Square root of")):
    for _suffix, _kind in _SSE_KIND.items():
        X86[_stem + _suffix] = _f("%s %s values" % (_what, _kind), "x86-sse-arith")
for _stem, _what in (("and", "Bitwise and"), ("andn", "Bitwise and-not"), ("or", "Bitwise or"), ("xor", "Bitwise exclusive or")):
    for _suffix in ("ps", "pd"):
        X86[_stem + _suffix] = _f("%s of %s values" % (_what, _SSE_KIND[_suffix]), "x86-sse-logic")
for _name, _title in (("comiss", "Compare scalar singles, set flags"), ("comisd", "Compare scalar doubles, set flags"),
                      ("ucomiss", "Unordered compare of scalar singles, set flags"), ("ucomisd", "Unordered compare of scalar doubles, set flags")):
    X86[_name] = _f(_title, "x86-sse-compare")
for _pred, _what in (("eq", "equal"), ("lt", "less than"), ("le", "less or equal"), ("unord", "unordered"), ("neq", "not equal"),
                     ("nlt", "not less than"), ("nle", "not less or equal"), ("ord", "ordered")):
    for _suffix, _kind in _SSE_KIND.items():
        X86["cmp" + _pred + _suffix] = _f("Compare %s values: %s" % (_kind, _what), "x86-sse-compare")
_CVT_UNIT = {"si": "integer", "dq": "packed 32-bit integers", "ss": "scalar single", "sd": "scalar double", "ps": "packed singles", "pd": "packed doubles"}
for _name in ("cvtsi2ss", "cvtsi2sd", "cvtss2sd", "cvtsd2ss", "cvtss2si", "cvtsd2si", "cvttss2si", "cvttsd2si", "cvtdq2ps", "cvtdq2pd",
              "cvtps2dq", "cvtpd2dq", "cvttps2dq", "cvttpd2dq", "cvtps2pd", "cvtpd2ps"):
    _src, _dst = _name.replace("cvtt", "").replace("cvt", "").split("2")
    X86[_name] = _f("Convert %s to %s%s" % (_CVT_UNIT[_src], _CVT_UNIT[_dst], ", truncating" if _name.startswith("cvtt") else ""), "x86-sse-convert")
for _name, _title in (
        ("movaps", "Move aligned packed singles"), ("movapd", "Move aligned packed doubles"), ("movups", "Move unaligned packed singles"),
        ("movupd", "Move unaligned packed doubles"), ("movdqa", "Move aligned packed integers"), ("movdqu", "Move unaligned packed integers"),
        ("movss", "Move scalar single"), ("movd", "Move 32 bits to or from an xmm register"), ("movq", "Move 64 bits to or from an xmm register"),
        ("movhlps", "Move the high half of one register to the low half of another"), ("movlhps", "Move the low half of one register to the high half of another"),
        ("movhps", "Move the high half (singles)"), ("movhpd", "Move the high half (double)"), ("movlps", "Move the low half (singles)"),
        ("movlpd", "Move the low half (double)"), ("movmskps", "Collect the sign bits of packed singles"), ("movmskpd", "Collect the sign bits of packed doubles")):
    X86[_name] = _f(_title, "x86-sse-move")
for _name, _title in (
        ("shufps", "Shuffle packed singles"), ("shufpd", "Shuffle packed doubles"), ("unpcklps", "Interleave low singles"), ("unpckhps", "Interleave high singles"),
        ("unpcklpd", "Interleave low doubles"), ("unpckhpd", "Interleave high doubles"), ("haddps", "Add neighbouring singles"), ("haddpd", "Add neighbouring doubles"),
        ("pshufd", "Shuffle doublewords"), ("pshufhw", "Shuffle the high words"), ("pshuflw", "Shuffle the low words")):
    X86[_name] = _f(_title, "x86-sse-shuffle")
for _stem, _sizes, _what in (
        ("padd", "bwdq", "Add"), ("psub", "bwdq", "Subtract"), ("padds", "bw", "Add with signed saturation"), ("paddus", "bw", "Add with unsigned saturation"),
        ("psubs", "bw", "Subtract with signed saturation"), ("psubus", "bw", "Subtract with unsigned saturation"),
        ("pcmpeq", "bwd", "Compare for equality"), ("pcmpgt", "bwd", "Compare for greater than, signed"),
        ("psll", "wdq", "Shift left"), ("psrl", "wdq", "Shift right, filling with zeros"), ("psra", "wd", "Shift right, keeping the sign"),
        ("pavg", "bw", "Average, rounding up")):
    for _size in _sizes:
        X86[_stem + _size] = _f("%s (packed %s)" % (_what, {"b": "bytes", "w": "words", "d": "doublewords", "q": "quadwords"}[_size]), "x86-simd-int")
for _name, _title in (
        ("pand", "Bitwise and of 128 bits"), ("pandn", "Bitwise and-not of 128 bits"), ("por", "Bitwise or of 128 bits"), ("pxor", "Bitwise exclusive or of 128 bits"),
        ("pmullw", "Multiply words, keep the low halves"), ("pmulhw", "Multiply signed words, keep the high halves"),
        ("pmulhuw", "Multiply unsigned words, keep the high halves"), ("pmuludq", "Multiply unsigned doublewords to quadwords"),
        ("pmaddwd", "Multiply words and add neighbouring products"), ("pslldq", "Shift the whole register left by bytes"),
        ("psrldq", "Shift the whole register right by bytes"), ("packsswb", "Narrow words to bytes with signed saturation"),
        ("packssdw", "Narrow doublewords to words with signed saturation"), ("packuswb", "Narrow words to bytes with unsigned saturation"),
        ("punpcklbw", "Interleave low bytes"), ("punpcklwd", "Interleave low words"), ("punpckldq", "Interleave low doublewords"),
        ("punpcklqdq", "Interleave low quadwords"), ("punpckhbw", "Interleave high bytes"), ("punpckhwd", "Interleave high words"),
        ("punpckhdq", "Interleave high doublewords"), ("punpckhqdq", "Interleave high quadwords"),
        ("pmaxsw", "Maximum of signed words"), ("pmaxub", "Maximum of unsigned bytes"), ("pminsw", "Minimum of signed words"),
        ("pminub", "Minimum of unsigned bytes"), ("pmovmskb", "Collect the top bit of each byte"), ("psadbw", "Sum of absolute differences of bytes"),
        ("pextrw", "Extract one word into a general register"), ("pinsrw", "Insert one word from a general register")):
    X86[_name] = _f(_title, "x86-simd-int")
for _name, _title in (
        ("movsb", "Copy a byte from [rsi] to [rdi]"), ("movsw", "Copy a word from [rsi] to [rdi]"), ("movsq", "Copy a quadword from [rsi] to [rdi]"),
        ("stosb", "Store al at [rdi]"), ("stosw", "Store ax at [rdi]"), ("stosd", "Store eax at [rdi]"), ("stosq", "Store rax at [rdi]"),
        ("lodsb", "Load al from [rsi]"), ("lodsw", "Load ax from [rsi]"), ("lodsd", "Load eax from [rsi]"), ("lodsq", "Load rax from [rsi]"),
        ("scasb", "Compare al with [rdi]"), ("scasw", "Compare ax with [rdi]"), ("scasd", "Compare eax with [rdi]"), ("scasq", "Compare rax with [rdi]"),
        ("cmpsb", "Compare bytes at [rsi] and [rdi]"), ("cmpsw", "Compare words at [rsi] and [rdi]"), ("cmpsq", "Compare quadwords at [rsi] and [rdi]")):
    X86[_name] = _f(_title, "x86-string")
for _name, _title in (("clc", "Clear the carry flag"), ("stc", "Set the carry flag"), ("cmc", "Complement the carry flag"),
                      ("cld", "Clear the direction flag (string instructions move forward)"), ("std", "Set the direction flag (string instructions move backward)"),
                      ("cli", "Clear the interrupt flag (privileged)"), ("sti", "Set the interrupt flag (privileged)")):
    X86[_name] = _f(_title, "x86-flag")
for _name, _title in (("cbw", "Sign-extend al into ax"), ("cwde", "Sign-extend ax into eax"), ("cdqe", "Sign-extend eax into rax"),
                      ("cwd", "Sign-extend ax into dx:ax"), ("cdq", "Sign-extend eax into edx:eax"), ("cqo", "Sign-extend rax into rdx:rax")):
    X86[_name] = _f(_title, "x86-extend")
X86.update({
    "movsd": _m("Move scalar double, or copy a doubleword", "With `xmm` operands: copies one double-precision value (SSE2). Without operands it is the string instruction that copies four bytes from `[rsi]` to `[rdi]`; with `rep` in front, an inline memory copy."),
    "adc": _m("Add with carry", "Adds the second operand and the carry flag to the first. Numbers wider than a register are added with `add` on the low parts and `adc` on the high parts."),
    "sbb": _m("Subtract with borrow", "Subtracts the second operand and the carry flag from the first. `sbb eax, eax` turns the carry flag into 0 or -1."),
    "mul": _m("Unsigned multiply", "Multiplies the accumulator (`rax`, `eax`, `ax` or `al`) by the operand. The product is twice as wide and is left in `rdx:rax`, `edx:eax` or `dx:ax`; for a byte operand it is left in `ax`."),
    "div": _m("Unsigned divide", "Divides `rdx:rax` by the operand; the quotient is left in `rax` and the remainder in `rdx` (narrower operands use `edx:eax` or `dx:ax`; a byte operand divides `ax`, leaving the quotient in `al` and the remainder in `ah`). A zero divisor, or a quotient that does not fit, raises a divide error."),
    "idiv": _m("Signed divide", "Divides `rdx:rax` by the operand as signed numbers; quotient in `rax`, remainder in `rdx`. Normally preceded by `cdq` or `cqo`, which sign-extends the dividend into `rdx`."),
    "bsf": _m("Bit scan forward", "Finds the index of the lowest set bit of the source. If the source is zero, the zero flag is set and the destination is not defined."),
    "bsr": _m("Bit scan reverse", "Finds the index of the highest set bit of the source. If the source is zero, the zero flag is set and the destination is not defined."),
    "bswap": _m("Byte swap", "Reverses the byte order of a register: the conversion between little-endian and big-endian.", "endianness"),
    "bt": _m("Bit test", "Copies the selected bit of the first operand into the carry flag."),
    "bts": _m("Bit test and set", "Copies the selected bit into the carry flag and then sets it."),
    "btr": _m("Bit test and reset", "Copies the selected bit into the carry flag and then clears it."),
    "btc": _m("Bit test and complement", "Copies the selected bit into the carry flag and then inverts it."),
    "cmpxchg": _m("Compare and exchange", "Compares the accumulator (`rax`) with the destination. If they are equal the source is stored in the destination; otherwise the destination is loaded into the accumulator. With the `lock` prefix this is the atomic compare-and-swap on which locks and lock-free code are built."),
    "xadd": _m("Exchange and add", "Stores the sum in the destination and the destination's previous value in the source. With `lock`: an atomic fetch-and-add."),
    "xchg": _m("Exchange", "Swaps its two operands. When one of them is memory the exchange is atomic even without a `lock` prefix."),
    "cpuid": _m("Processor identification", "Returns identification and feature information about the processor in `eax`, `ebx`, `ecx` and `edx`; the value in `eax` on entry selects which."),
    "rdtsc": _m("Read time-stamp counter", "Loads the processor's time-stamp counter into `edx:eax`. Used for timing, and by some programs to detect that they are being single-stepped."),
    "lzcnt": _m("Count leading zeros", "Counts the zero bits above the highest set bit. On processors without the instruction the same bytes execute as `bsr`, which gives a different result."),
    "tzcnt": _m("Count trailing zeros", "Counts the zero bits below the lowest set bit. On processors without the instruction the same bytes execute as `bsf`."),
    "popcnt": _m("Population count", "Counts the bits that are set in the source."),
    "pause": _m("Spin-loop hint", "Tells the processor that the code is waiting in a busy loop, which saves power and lets the other hardware thread run."),
    "rol": _m("Rotate left", "Rotates the bits of the operand left; bits leaving at the top re-enter at the bottom."),
    "ror": _m("Rotate right", "Rotates the bits of the operand right; bits leaving at the bottom re-enter at the top."),
    "rcl": _m("Rotate left through carry", "Rotates left through the carry flag, treating it as an extra bit."),
    "rcr": _m("Rotate right through carry", "Rotates right through the carry flag, treating it as an extra bit."),
    "shld": _m("Double-precision shift left", "Shifts the first operand left and fills the vacated bits from the top of the second operand."),
    "shrd": _m("Double-precision shift right", "Shifts the first operand right and fills the vacated bits from the bottom of the second operand."),
})

# Prefixes that the decoder prints in front of the mnemonic ("lock add", "rep movsb").
PREFIXES: Dict[str, Dict[str, Dict[str, str]]] = {"x86": {
    "lock": {"title": "atomic", "text": "The `lock` prefix makes the read-modify-write of the memory operand atomic with respect to other processors."},
    "rep": {"title": "repeated", "text": "The `rep` prefix repeats the instruction `rcx` times, decrementing `rcx` each time."},
    "repe": {"title": "repeated while equal", "text": "The `repe` prefix repeats the instruction while `rcx` is not zero and the zero flag is set."},
    "repz": {"title": "repeated while equal", "text": "The `repz` prefix repeats the instruction while `rcx` is not zero and the zero flag is set."},
    "repne": {"title": "repeated while not equal", "text": "The `repne` prefix repeats the instruction while `rcx` is not zero and the zero flag is clear."},
    "repnz": {"title": "repeated while not equal", "text": "The `repnz` prefix repeats the instruction while `rcx` is not zero and the zero flag is clear."},
}}

ARM64.update({
    "and": _m("Bitwise and", "Clears the bits that are zero in the last operand."),
    "ands": _m("Bitwise and, set flags", "Bitwise and that also updates the condition flags."),
    "tst": _m("Test bits", "Bitwise and that keeps only the flags (`ands` with the result discarded). A conditional branch normally follows."),
    "orr": _m("Bitwise or", "Sets the bits that are one in the last operand. With the zero register as first source it is how `mov` between registers is encoded."),
    "orn": _m("Bitwise or-not", "Or with the inverse of the last operand."),
    "eor": _m("Bitwise exclusive or", "Inverts the bits that are one in the last operand."),
    "eon": _m("Bitwise exclusive or-not", "Exclusive or with the inverse of the last operand."),
    "bic": _m("Bit clear", "And with the inverse of the last operand: clears the bits that are one in it."),
    "bics": _m("Bit clear, set flags", "`bic` that also updates the condition flags."),
    "mvn": _m("Bitwise not", "Writes the inverse of the source register."),
    "lsl": _m("Shift left", "Shifts left, filling with zeros; each position multiplies by two."),
    "lsr": _m("Shift right (unsigned)", "Shifts right, filling with zeros."),
    "asr": _m("Shift right (signed)", "Shifts right, filling with copies of the sign bit."),
    "ror": _m("Rotate right", "Rotates the bits right; bits leaving at the bottom re-enter at the top."),
    "adc": _m("Add with carry", "Adds two registers and the carry flag. Used for arithmetic wider than 64 bits."),
    "adcs": _m("Add with carry, set flags", "`adc` that also updates the condition flags."),
    "sbc": _m("Subtract with carry", "Subtracts with borrow, for arithmetic wider than 64 bits."),
    "sbcs": _m("Subtract with carry, set flags", "`sbc` that also updates the condition flags."),
    "ngc": _m("Negate with carry", "`sbc` from zero."),
    "ngcs": _m("Negate with carry, set flags", "`sbcs` from zero."),
    "neg": _m("Negate", "Subtracts the source from zero."),
    "negs": _m("Negate, set flags", "`neg` that also updates the condition flags."),
    "ccmp": _m("Conditional compare", "If the condition holds, compares its two operands and sets the flags from that; otherwise sets the flags to the given constant. It lets a chain such as `a == 1 && b == 2` be evaluated without branches."),
    "ccmn": _m("Conditional compare negative", "As `ccmp`, comparing by addition."),
    "tbz": _m("Test bit and branch if zero", "Jumps to the target if the given bit of the register is zero. The flags are not used."),
    "tbnz": _m("Test bit and branch if not zero", "Jumps to the target if the given bit of the register is one."),
    "clz": _m("Count leading zeros", "Counts the zero bits above the highest set bit."),
    "cls": _m("Count leading sign bits", "Counts how many bits below the sign bit are equal to it."),
    "rbit": _m("Reverse bits", "Reverses the order of the bits of a register."),
    "rev": _m("Reverse bytes", "Reverses the byte order of a register: the conversion between little-endian and big-endian.", "endianness"),
    "rev16": _m("Reverse bytes in each halfword", "Swaps the two bytes of every 16-bit unit.", "endianness"),
    "rev32": _m("Reverse bytes in each word", "Reverses the bytes of every 32-bit unit.", "endianness"),
    "extr": _m("Extract from a register pair", "Takes a register-sized field out of two registers placed side by side. With the same register twice it is a rotate."),
    "hlt": _m("Halt", "Raises a halt exception for a debugger. Not used in ordinary user code."),
    "hvc": _m("Hypervisor call", "Enters the hypervisor. Kernels issue it; user code cannot.", "syscalls"),
    "smc": _m("Secure monitor call", "Enters the secure monitor (firmware). Kernels and hypervisors issue it; user code cannot.", "syscalls"),
    "eret": _m("Exception return", "Returns from an exception to the interrupted code and privilege level. Kernel and firmware code only.", "syscalls"),
    "movi": _m("Load a constant into a vector register", "Sets every element of a vector register to an immediate constant. `movi v0.2d, #0` is the usual way to zero one."),
    "bsl": _m("Bitwise select", "For every bit, chooses between two vector registers according to a mask held in the destination."),
    "bit": _m("Bitwise insert if true", "Copies bits from the source into the destination where the mask is one."),
    "bif": _m("Bitwise insert if false", "Copies bits from the source into the destination where the mask is zero."),
    "ldraa": _f("Load with an authenticated address (key DA)", "a64-pac"),
    "ldrab": _f("Load with an authenticated address (key DB)", "a64-pac"),
    "pacga": _f("Compute a generic authentication code", "a64-pac"),
    "xpaci": _f("Strip the authentication code from a code pointer", "a64-pac"),
    "xpacd": _f("Strip the authentication code from a data pointer", "a64-pac"),
    "xpaclri": _f("Strip the authentication code from x30", "a64-pac"),
})
for _name, _title in (("csel", "Select one of two registers"), ("csinc", "Select, or the second register plus one"), ("csinv", "Select, or the inverse of the second register"),
                      ("csneg", "Select, or the negative of the second register"), ("cset", "Set to 1 if the condition holds, else 0"),
                      ("csetm", "Set to all ones if the condition holds, else 0"), ("cinc", "Increment if the condition holds"),
                      ("cinv", "Invert if the condition holds"), ("cneg", "Negate if the condition holds")):
    ARM64[_name] = _f(_title, "a64-csel")
for _name, _title in (("ubfx", "Extract an unsigned bit field"), ("sbfx", "Extract a signed bit field"), ("ubfiz", "Insert a bit field into zeros"),
                      ("sbfiz", "Insert a bit field, sign-extended"), ("bfi", "Insert a bit field"), ("bfxil", "Extract a bit field and insert it at the bottom"),
                      ("bfc", "Clear a bit field"), ("bfm", "Bit-field move"), ("ubfm", "Unsigned bit-field move"), ("sbfm", "Signed bit-field move"),
                      ("sxtb", "Sign-extend a byte"), ("sxth", "Sign-extend a halfword"), ("sxtw", "Sign-extend a word"),
                      ("uxtb", "Zero-extend a byte"), ("uxth", "Zero-extend a halfword")):
    ARM64[_name] = _f(_title, "a64-bitfield")
for _name, _title in (("madd", "Multiply and add"), ("msub", "Multiply and subtract"), ("mul", "Multiply"), ("mneg", "Multiply and negate"),
                      ("smaddl", "Signed 32-bit multiply, add to 64 bits"), ("smsubl", "Signed 32-bit multiply, subtract from 64 bits"),
                      ("smull", "Signed 32-bit multiply to 64 bits"), ("smnegl", "Signed 32-bit multiply to 64 bits, negated"),
                      ("umaddl", "Unsigned 32-bit multiply, add to 64 bits"), ("umsubl", "Unsigned 32-bit multiply, subtract from 64 bits"),
                      ("umull", "Unsigned 32-bit multiply to 64 bits"), ("umnegl", "Unsigned 32-bit multiply to 64 bits, negated"),
                      ("smulh", "Signed multiply, high 64 bits"), ("umulh", "Unsigned multiply, high 64 bits"),
                      ("sdiv", "Signed divide"), ("udiv", "Unsigned divide")):
    ARM64[_name] = _f(_title, "a64-muldiv")
_ATOMIC_OPS = {"add": "add", "clr": "clear bits", "eor": "exclusive or", "set": "set bits", "smax": "signed maximum", "smin": "signed minimum",
               "umax": "unsigned maximum", "umin": "unsigned minimum"}
for _order in ("", "a", "l", "al"):
    for _size in ("", "b", "h"):
        _tail = _order + _size
        for _op, _what in _ATOMIC_OPS.items():
            ARM64["ld" + _op + _tail] = _f("Atomic %s on memory, returning the old value" % _what, "a64-atomic")
            if _order in ("", "l"):
                ARM64["st" + _op + _tail] = _f("Atomic %s on memory" % _what, "a64-atomic")
        ARM64["swp" + _tail] = _f("Atomic swap with memory", "a64-atomic")
        ARM64["cas" + _tail] = _f("Atomic compare and swap", "a64-atomic")
for _order in ("", "a", "l", "al"):
    ARM64["casp" + _order] = _f("Atomic compare and swap of a pair", "a64-atomic")
for _size in ("", "b", "h"):
    ARM64["ldxr" + _size] = _f("Load exclusive", "a64-exclusive")
    ARM64["ldaxr" + _size] = _f("Load-acquire exclusive", "a64-exclusive")
    ARM64["stxr" + _size] = _f("Store exclusive", "a64-exclusive")
    ARM64["stlxr" + _size] = _f("Store-release exclusive", "a64-exclusive")
    ARM64["ldar" + _size] = _f("Load-acquire", "a64-ordered")
    ARM64["stlr" + _size] = _f("Store-release", "a64-ordered")
    ARM64["ldlar" + _size] = _f("Load-acquire (limited ordering region)", "a64-ordered")
    ARM64["stllr" + _size] = _f("Store-release (limited ordering region)", "a64-ordered")
for _name, _title in (("ldxp", "Load exclusive pair"), ("ldaxp", "Load-acquire exclusive pair"), ("stxp", "Store exclusive pair"),
                      ("stlxp", "Store-release exclusive pair"), ("clrex", "Clear the exclusive mark")):
    ARM64[_name] = _f(_title, "a64-exclusive")
for _name, _title in (("ldur", "Load, unscaled offset"), ("ldurb", "Load byte, unscaled offset"), ("ldurh", "Load halfword, unscaled offset"),
                      ("ldursb", "Load signed byte, unscaled offset"), ("ldursh", "Load signed halfword, unscaled offset"),
                      ("ldursw", "Load signed word, unscaled offset"), ("stur", "Store, unscaled offset"), ("sturb", "Store byte, unscaled offset"),
                      ("sturh", "Store halfword, unscaled offset"), ("ldrsb", "Load signed byte"), ("ldrsh", "Load signed halfword"),
                      ("ldrsw", "Load signed word"), ("ldpsw", "Load a pair of signed words"), ("ldnp", "Load pair, non-temporal"),
                      ("stnp", "Store pair, non-temporal"), ("prfm", "Prefetch memory"), ("prfum", "Prefetch memory, unscaled offset")):
    ARM64[_name] = _f(_title, "a64-load-store")
for _op, _verb in (("pac", "Sign"), ("aut", "Authenticate")):
    for _kind, _what in (("i", "a code pointer"), ("d", "a data pointer")):
        for _key in ("a", "b"):
            ARM64[_op + _kind + _key] = _f("%s %s with key %s%s" % (_verb, _what, _kind.upper(), _key.upper()), "a64-pac")
            ARM64[_op + _kind + "z" + _key] = _f("%s %s with key %s%s, zero modifier" % (_verb, _what, _kind.upper(), _key.upper()), "a64-pac")
    for _key in ("a", "b"):
        ARM64[_op + "i" + _key + "z"] = _f("%s x30 with key I%s, zero modifier" % (_verb, _key.upper()), "a64-pac")
        ARM64[_op + "i" + _key + "1716"] = _f("%s x17 with key I%s, x16 as modifier" % (_verb, _key.upper()), "a64-pac")
for _name, _title in (("brab", "Authenticated branch to register (key B)"), ("braaz", "Authenticated branch, zero modifier (key A)"),
                      ("brabz", "Authenticated branch, zero modifier (key B)"), ("blrab", "Authenticated call through register (key B)"),
                      ("blraaz", "Authenticated call, zero modifier (key A)"), ("blrabz", "Authenticated call, zero modifier (key B)"),
                      ("eretaa", "Authenticated exception return (key A)"), ("eretab", "Authenticated exception return (key B)")):
    ARM64[_name] = _f(_title, "a64-pac-branch")
for _name, _title in (("fadd", "Floating-point add"), ("fsub", "Floating-point subtract"), ("fmul", "Floating-point multiply"), ("fdiv", "Floating-point divide"),
                      ("fnmul", "Floating-point multiply, negated"), ("fmadd", "Floating-point multiply and add"), ("fmsub", "Floating-point multiply and subtract"),
                      ("fnmadd", "Floating-point negated multiply and add"), ("fnmsub", "Floating-point negated multiply and subtract"),
                      ("fmax", "Floating-point maximum"), ("fmin", "Floating-point minimum"), ("fmaxnm", "Floating-point maximum, preferring numbers to NaN"),
                      ("fminnm", "Floating-point minimum, preferring numbers to NaN"), ("fsqrt", "Floating-point square root"), ("fabs", "Floating-point absolute value"),
                      ("fneg", "Floating-point negate"), ("fmov", "Floating-point move"), ("fcmp", "Floating-point compare, set flags"),
                      ("fcmpe", "Floating-point compare, signalling on NaN"), ("fccmp", "Floating-point conditional compare"),
                      ("fccmpe", "Floating-point conditional compare, signalling on NaN"), ("fcsel", "Floating-point conditional select"),
                      ("fcvt", "Convert between floating-point precisions"), ("scvtf", "Convert a signed integer to floating point"),
                      ("ucvtf", "Convert an unsigned integer to floating point")):
    ARM64[_name] = _f(_title, "a64-fp")
for _mode, _how in (("a", "to nearest, ties away from zero"), ("m", "toward minus infinity"), ("n", "to nearest, ties to even"),
                    ("p", "toward plus infinity"), ("z", "toward zero")):
    for _sign, _what in (("s", "signed"), ("u", "unsigned")):
        ARM64["fcvt" + _mode + _sign] = _f("Convert floating point to a %s integer, rounding %s" % (_what, _how), "a64-fp")
for _mode, _how in (("a", "to nearest, ties away from zero"), ("i", "using the current rounding mode"), ("m", "toward minus infinity"),
                    ("n", "to nearest, ties to even"), ("p", "toward plus infinity"), ("x", "using the current mode, signalling inexact"), ("z", "toward zero")):
    ARM64["frint" + _mode] = _f("Round to an integral value, %s" % _how, "a64-fp")
for _name, _title in (("mrs", "Read a system register"), ("msr", "Write a system register"), ("hint", "Hint (no defined effect here)"),
                      ("yield", "Hint: this thread is spinning"), ("wfe", "Wait for event"), ("wfi", "Wait for interrupt"), ("sev", "Send event"),
                      ("sevl", "Send event, local"), ("esb", "Error synchronisation barrier"), ("csdb", "Barrier against speculative use of data"),
                      ("dgh", "Data gathering hint"), ("tsb", "Trace synchronisation barrier"), ("isb", "Instruction synchronisation barrier"),
                      ("dsb", "Data synchronisation barrier"), ("dmb", "Data memory barrier"), ("sys", "System instruction")):
    ARM64[_name] = _f(_title, "a64-system")
for _name in ("crc32b", "crc32h", "crc32w", "crc32x", "crc32cb", "crc32ch", "crc32cw", "crc32cx"):
    ARM64[_name] = _f("CRC-32%s of a %s" % ("C" if "c" in _name[5:] else "", {"b": "byte", "h": "halfword", "w": "word", "x": "doubleword"}[_name[-1]]), "a64-crc")
ARM64["b.cond"] = _m("Conditional branch", "Jumps to the target if the condition flags, set by an earlier `cmp`, `subs`, `adds` or `tst`, satisfy the condition.")

MNEMONICS: Dict[str, Dict[str, Dict[str, str]]] = {"x86": X86, "arm64": ARM64}
CONDITIONS: Dict[str, Dict[str, str]] = {"arm64": _A64_COND}

IDIOMS: List[Dict[str, Any]] = [
    # ------------------------------------------------------------------ x86 / x86-64
    {"id": "x86-win-syscall-stub", "arch": "x86", "concept": "syscalls",
     "title": "Windows system call stub",
     "text": "The shape of the stubs in `ntdll.dll`: the first argument is moved from `rcx` to `r10` (because `syscall` overwrites `rcx`), the system call number is loaded into `eax`, and `syscall` enters the kernel. The numbers change between Windows builds.",
     "steps": [{"mn": ["mov"], "ops": ["r10,rcx"]}, {"mn": ["mov"], "ops": ["eax,{imm}"]}, {"mn": ["syscall"], "gap": 3}]},
    {"id": "x86-syscall", "arch": "x86", "concept": "syscalls",
     "title": "System call set-up",
     "text": "The system call number is loaded into `eax`/`rax`, then `syscall` enters the kernel. On Linux the arguments are in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` and the result comes back in `rax`.",
     "steps": [{"mn": ["mov"], "ops": ["rax,{imm}", "eax,{imm}"]}, {"mn": ["syscall"], "gap": 6}]},
    {"id": "x86-int80", "arch": "x86", "concept": "syscalls",
     "title": "Legacy 32-bit Linux system call",
     "text": "`int 0x80` enters the kernel through the 32-bit system call gate. The number is in `eax`; the arguments are in `ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp`.",
     "steps": [{"mn": ["int"], "ops": ["0x80"]}]},
    {"id": "x86-endbr-prologue", "arch": "x86", "concept": "stack-and-frames",
     "title": "Landing pad and function prologue",
     "text": "`endbr64` marks the function as a valid target for indirect calls (Intel CET). Then the prologue: save the caller's frame pointer, point the frame pointer at the new frame, and reserve space for locals by lowering the stack pointer.",
     "steps": [{"mn": ["endbr64", "endbr32"]}, {"mn": ["push"], "ops": ["rbp", "ebp"]}, {"mn": ["mov"], "ops": ["rbp,rsp", "rbp,esp", "ebp,rsp", "ebp,esp"]}, {"mn": ["sub"], "ops": ["rsp,*", "esp,*"], "opt": True}]},
    {"id": "x86-prologue", "arch": "x86", "concept": "stack-and-frames",
     "title": "Function prologue",
     "text": "Saves the caller's frame pointer (`push rbp`), makes the frame pointer point at the new frame (`mov rbp, rsp`), and reserves space for local variables by lowering the stack pointer (`sub rsp, N`). Locals are then addressed as `[rbp - offset]`.",
     "steps": [{"mn": ["push"], "ops": ["rbp", "ebp"]}, {"mn": ["mov"], "ops": ["rbp,rsp", "rbp,esp", "ebp,rsp", "ebp,esp"]}, {"mn": ["sub"], "ops": ["rsp,*", "esp,*"], "opt": True}]},
    {"id": "x86-endbr", "arch": "x86", "concept": "cfi",
     "title": "Indirect branch landing pad",
     "text": "With Intel CET indirect branch tracking active, an indirect call or jump must land on an `endbr64`; anywhere else faults. Without it the instruction does nothing.",
     "steps": [{"mn": ["endbr64", "endbr32"]}]},
    {"id": "x86-epilogue", "arch": "x86", "concept": "stack-and-frames",
     "title": "Function epilogue",
     "text": "`leave` discards the frame (`mov rsp, rbp` then `pop rbp`), and `ret` pops the return address and jumps to it.",
     "steps": [{"mn": ["leave"]}, {"mn": ["ret"]}]},
    {"id": "x86-epilogue-pop", "arch": "x86", "concept": "stack-and-frames",
     "title": "Function epilogue",
     "text": "Restores the caller's frame pointer and returns.",
     "steps": [{"mn": ["pop"], "ops": ["rbp", "ebp"]}, {"mn": ["ret"]}]},
    # Two different things that both end in "the canary was wrong": the routine GCC and Clang call
    # ONLY on a mismatch, and the routine Microsoft's compiler calls before EVERY return to do the
    # comparison itself. They are separate idioms because a reader must not take the second for
    # a failure path.
    {"id": "x86-canary-fail", "arch": "x86", "concept": "stack-canaries",
     "title": "Stack canary failure path",
     "text": "Reached only when the canary in the frame no longer matches the guard value: the compare just before it jumps here on a mismatch. `__stack_chk_fail` (code built by GCC or Clang) reports the corruption and terminates the program; it does not return. `__report_gsfailure` is the routine in Microsoft's runtime with the same role.",
     "steps": [{"mn": ["call"], "txt": ["*__stack_chk_fail*", "*__report_gsfailure*"]}]},
    {"id": "x86-gs-cookie-check", "arch": "x86", "concept": "stack-canaries",
     "title": "Stack cookie check before return (/GS)",
     "text": "Not a failure path: code built by Microsoft's compiler with `/GS` calls `__security_check_cookie` before every return of a protected function. The frame's copy of the cookie is passed in `rcx` (`ecx` in 32-bit code), after the xor with the stack or frame pointer applied in the prologue has been undone. The routine compares it with `__security_cookie`, returns normally if they are equal, and otherwise calls `__report_gsfailure`, which terminates the process.",
     "steps": [{"mn": ["call"], "txt": ["*__security_check_cookie*"]}]},
    {"id": "x86-canary-load", "arch": "x86", "concept": "stack-canaries",
     "title": "Stack canary: load the guard value",
     "text": "Reads the process's secret guard value: from the thread control block at `fs:0x28` (Linux x86-64 with glibc) or `gs:0x14` (32-bit Linux), or from a global: `__stack_chk_guard`, or `__security_cookie` in Microsoft's runtime. In a prologue it is copied into the frame (Microsoft's compiler first xors it with the stack or frame pointer); before `ret` it is compared with that copy.",
     "steps": [{"mn": ["mov", "sub", "xor", "cmp"], "txt": ["*fs:0x28*", "*fs:[0x28*", "*gs:0x14*", "*gs:[0x14*", "*__stack_chk_guard*", "*__security_cookie*"]}]},
    {"id": "x86-pc-thunk", "arch": "x86", "concept": "pic-pie",
     "title": "Get the current address (32-bit position-independent code)",
     "text": "32-bit x86 cannot address data relative to the instruction pointer. This helper returns its own return address in a register, from which the code computes the address of the GOT.",
     "steps": [{"mn": ["call"], "txt": ["*get_pc_thunk*"]}]},
    {"id": "x86-import-call", "arch": "x86", "concept": "got-plt",
     "title": "Indirect call through a pointer slot",
     "text": "The target address is read from memory and called. When the slot is in the import address table or the GOT, this is a call to a function in another image; the loader filled the slot in.",
     "steps": [{"mn": ["call"], "ops": ["*ptr [rip*", "*ptr [0x*"]}]},
    {"id": "x86-import-stub", "arch": "x86", "concept": "got-plt",
     "title": "Import stub (PLT entry or thunk)",
     "text": "A jump through a pointer slot. Code calls this stub; the stub transfers to wherever the slot points, which after binding is the real function in another image.",
     "steps": [{"mn": ["jmp"], "ops": ["*ptr [rip*", "*ptr [0x*"]}]},
    {"id": "x86-zero-return", "arch": "x86", "concept": "calling-conventions",
     "title": "Return zero",
     "text": "`xor eax, eax` sets the return register to zero (and clears the upper half of `rax`); the function then returns.",
     "steps": [{"mn": ["xor"], "ops": ["eax,eax"]}, {"mn": ["leave", "pop"], "opt": True}, {"mn": ["ret"]}]},
    {"id": "x86-zero", "arch": "x86", "concept": "reading-disassembly",
     "title": "Set a register to zero",
     "text": "A register exclusive-or'ed with itself is zero. This is shorter than loading the constant 0.",
     "steps": [{"mn": ["xor"], "ops": ["{w},{w=}"]}]},
    {"id": "x86-int3-pad", "arch": "x86", "concept": "reading-disassembly",
     "title": "Padding (breakpoints)",
     "text": "A run of `int3` between functions. It fills the gap up to the next aligned address, and stops the program if execution ever strays into it.",
     "steps": [{"mn": ["int3"]}, {"mn": ["int3"]}, {"mn": ["int3"]}]},
    {"id": "x86-nop-pad", "arch": "x86", "concept": "reading-disassembly",
     "title": "Padding",
     "text": "A run of `nop` that fills the gap so that the next function or loop starts at an aligned address. It is never meant to be executed for its effect.",
     "steps": [{"mn": ["nop"]}, {"mn": ["nop"]}, {"mn": ["nop"]}]},

    # ------------------------------------------------------------------ ARM64
    {"id": "a64-stub-auth", "arch": "arm64", "concept": "got-plt",
     "title": "Import stub (authenticated, arm64e)",
     "text": "Computes the address of a slot in `__auth_got`, loads the signed pointer stored there, and branches to it with `braa`, which authenticates the pointer using the slot's address as context.",
     "steps": [{"mn": ["adrp"], "ops": ["x17,*"]}, {"mn": ["add"], "ops": ["x17,x17,*"]}, {"mn": ["ldr"], "ops": ["x16,[x17*"]}, {"mn": ["braa"], "ops": ["x16,x17"]}]},
    {"id": "a64-stub", "arch": "arm64", "concept": "got-plt",
     "title": "Import stub",
     "text": "Loads a pointer from the GOT (`adrp` gives the page, `ldr` reads the slot) and branches to it. `x16` is reserved by the calling convention as scratch for exactly this purpose.",
     "steps": [{"mn": ["adrp"], "ops": ["x16,*"]}, {"mn": ["ldr"], "ops": ["x16,[x16*"]}, {"mn": ["br"], "ops": ["x16"]}]},
    {"id": "a64-pac-prologue", "arch": "arm64", "concept": "cfi",
     "title": "Signed prologue",
     "text": "`paciasp` signs the return address in `x30` before the prologue saves it to the stack. The frame pointer and the signed return address are then stored as a pair and `x29` is pointed at the new frame.",
     "steps": [{"mn": ["paciasp", "pacibsp"]}, {"mn": ["sub"], "ops": ["sp,sp,*"], "opt": True}, {"mn": ["stp"], "ops": ["x29,x30,[sp*"], "gap": 6}, {"mn": ["mov", "add"], "ops": ["x29,sp*"], "opt": True}]},
    {"id": "a64-pac-sign", "arch": "arm64", "concept": "cfi",
     "title": "Sign the return address",
     "text": "Adds a pointer authentication code to `x30`, using the current stack pointer as context. A return address overwritten on the stack will not carry a valid code.",
     "steps": [{"mn": ["paciasp", "pacibsp"]}]},
    {"id": "a64-prologue", "arch": "arm64", "concept": "stack-and-frames",
     "title": "Function prologue",
     "text": "`stp x29, x30, [sp, #-N]!` lowers the stack pointer by N and saves the caller's frame pointer and the return address there. `mov x29, sp` then makes the frame pointer point at the new frame.",
     "steps": [{"mn": ["stp"], "ops": ["x29,x30,[sp,#-{hex}]!"]}, {"mn": ["mov"], "ops": ["x29,sp"], "opt": True}]},
    {"id": "a64-prologue-sub", "arch": "arm64", "concept": "stack-and-frames",
     "title": "Function prologue",
     "text": "The frame is allocated first (`sub sp, sp, #N`). Callee-saved registers are stored in pairs, among them the frame pointer `x29` and the return address `x30` (the last pair stored, at the top of the saved area, in code for Apple platforms; often the first, at the bottom, on Linux). `add x29, sp, #M` or `mov x29, sp` then points the frame pointer at that saved pair.",
     "steps": [{"mn": ["sub"], "ops": ["sp,sp,*"]}, {"mn": ["stp"], "ops": ["x29,x30,[sp*"], "gap": 6}, {"mn": ["add", "mov"], "ops": ["x29,sp*"], "opt": True}]},
    {"id": "a64-epilogue-auth", "arch": "arm64", "concept": "cfi",
     "title": "Epilogue with authenticated return",
     "text": "Restores the frame pointer and the signed return address, then verifies the signature and returns. If the saved return address was overwritten, the verification fails and the return faults.",
     "steps": [{"mn": ["ldp"], "ops": ["x29,x30,[sp*"]}, {"mn": ["add"], "ops": ["sp,sp,*"], "opt": True}, {"mn": ["autiasp", "autibsp"], "opt": True}, {"mn": ["retaa", "retab"]}]},
    {"id": "a64-epilogue-auth2", "arch": "arm64", "concept": "cfi",
     "title": "Epilogue with authenticated return",
     "text": "Restores the frame pointer and the signed return address, verifies the signature with `autiasp`, and returns.",
     "steps": [{"mn": ["ldp"], "ops": ["x29,x30,[sp*"]}, {"mn": ["add"], "ops": ["sp,sp,*"], "opt": True}, {"mn": ["autiasp", "autibsp"]}, {"mn": ["ret"]}]},
    {"id": "a64-epilogue", "arch": "arm64", "concept": "stack-and-frames",
     "title": "Function epilogue",
     "text": "`ldp x29, x30, [sp], #N` reloads the caller's frame pointer and the return address and releases the frame; `ret` jumps to the address in `x30`.",
     "steps": [{"mn": ["ldp"], "ops": ["x29,x30,[sp*"]}, {"mn": ["add"], "ops": ["sp,sp,*"], "opt": True}, {"mn": ["ret"]}]},
    {"id": "a64-auth-return", "arch": "arm64", "concept": "cfi",
     "title": "Authenticated return",
     "text": "Verifies the pointer authentication code of the return address before using it.",
     "steps": [{"mn": ["retaa", "retab", "autiasp", "autibsp"]}]},
    {"id": "a64-syscall-apple", "arch": "arm64", "concept": "syscalls",
     "title": "System call set-up (Apple)",
     "text": "The system call number is loaded into `x16` and `svc #0x80` enters the kernel. Arguments are in `x0` onward. Programs normally leave this to the system library.",
     "steps": [{"mn": ["mov", "movz", "movn"], "ops": ["x16,#*", "w16,#*"]}, {"mn": ["svc"], "ops": ["#0x80"], "gap": 4}]},
    {"id": "a64-syscall-linux", "arch": "arm64", "concept": "syscalls",
     "title": "System call set-up (Linux)",
     "text": "The system call number is loaded into `x8` and `svc #0` enters the kernel. Arguments are in `x0` to `x5`; the result comes back in `x0`.",
     "steps": [{"mn": ["mov", "movz", "movn"], "ops": ["x8,#*", "w8,#*"]}, {"mn": ["svc"], "ops": ["#0x0", "#0"], "gap": 4}]},
    {"id": "a64-svc", "arch": "arm64", "concept": "syscalls",
     "title": "Supervisor call",
     "text": "Raises an exception to the next privilege level: the kernel, or in firmware whatever handles supervisor calls. The registers hold the request; which register carries the call number is a convention of the system.",
     "steps": [{"mn": ["svc"]}]},
    {"id": "a64-canary-fail", "arch": "arm64", "concept": "stack-canaries",
     "title": "Stack canary failure path",
     "text": "Called when the canary in the frame no longer matches the guard value. The routine does not return.",
     "steps": [{"mn": ["bl"], "txt": ["*__stack_chk_fail*"]}]},
    {"id": "a64-got-load", "arch": "arm64", "concept": "pic-pie",
     "title": "Load from a page-relative address",
     "text": "`adrp` computes the address of a page relative to this code; `ldr` reads a pointer at an offset in that page. When the page is in the GOT, the value read is the address of something in another image.",
     "steps": [{"mn": ["adrp"]}, {"mn": ["ldr"], "ops": ["x{n},[x{n}*", "w{n},[x{n}*"]}]},
    {"id": "a64-address", "arch": "arm64", "concept": "pic-pie",
     "title": "Address of a global or string",
     "text": "`adrp` computes the address of the 4 KiB page that holds the target, relative to this code; `add` supplies the offset within the page. Together they produce a full address without any absolute address in the code.",
     "steps": [{"mn": ["adrp"]}, {"mn": ["add"], "ops": ["x{n},x{n},#*"]}]},
    {"id": "a64-const", "arch": "arm64", "concept": "reading-disassembly",
     "title": "Build a constant 16 bits at a time",
     "text": "An instruction is only 32 bits, so a larger constant is assembled in pieces: the first instruction sets one 16-bit field (usually the low one) and clears the rest, and each `movk` replaces another 16-bit field.",
     "steps": [{"mn": ["mov", "movz"], "ops": ["*#*"]}, {"mn": ["movk"]}]},
    {"id": "a64-bti", "arch": "arm64", "concept": "cfi",
     "title": "Branch target landing pad",
     "text": "With branch target identification active, an indirect branch must land on a `bti` instruction (or on `paciasp`, which counts as one for calls).",
     "steps": [{"mn": ["bti"]}]},
    {"id": "a64-trap", "arch": "arm64", "concept": "reading-disassembly",
     "title": "Trap",
     "text": "A deliberate stop: a failed check, an unreachable path, or a breakpoint. Execution does not continue past it in normal operation.",
     "steps": [{"mn": ["brk"]}]},
]


def arch_family(arch_name: Any) -> Optional[str]:
    """'x86' | 'arm64' | None for the `arch_name` of a slice."""
    name = str(arch_name or "").lower()
    if name.startswith("arm64") or name.startswith("aarch64"):
        return "arm64"
    if name in ("x86_64", "i386", "x86", "amd64", "i686") or name.startswith("x86"):
        return "x86"
    return None


def _merged(entry: Dict[str, str]) -> Dict[str, str]:
    """An entry with its family's text and concept filled in."""
    if "family" not in entry:
        return entry
    family = FAMILIES[entry["family"]]
    return {"title": entry["title"], "text": family["text"], "concept": family["concept"]}


def lookup(arch: str, mnemonic: str) -> Optional[Dict[str, str]]:
    """Help for one mnemonic as {"title", "text", "concept"}, or None.

    Handles what the tables do not list literally: ARM64 conditional branches (b.eq, ...), AT&T-style
    `callq`, and x86 prefixes printed in front of the mnemonic ("lock add", "rep movsb")."""
    table = MNEMONICS.get(arch) or {}
    name = " ".join(str(mnemonic or "").strip().lower().split())
    prefix = None
    if arch == "x86" and " " in name:
        head, rest = name.split(" ", 1)
        if head in PREFIXES["x86"]:
            prefix, name = PREFIXES["x86"][head], rest
    entry: Optional[Dict[str, str]] = None
    if name in table:
        entry = _merged(table[name])
    elif arch == "arm64" and name.startswith("b."):
        entry = dict(table["b.cond"])
        cond = _A64_COND.get(name[2:])
        if cond:
            entry["title"] = "Branch if " + cond
    elif arch == "x86" and name == "callq":
        entry = table["call"]
    if entry is None:
        return None
    if prefix is not None:
        entry = {"title": "%s (%s)" % (entry["title"], prefix["title"]), "text": prefix["text"] + " " + entry["text"], "concept": entry["concept"]}
    return entry


_CLASSES = ("{n}", "{hex}", "{imm}", "{w}", "{w=}")
_DIGITS = frozenset("0123456789")
_HEXDIGITS = frozenset("0123456789abcdef")
_WORDCHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")
MAX_PATTERN = 120
_parsed: Dict[str, Any] = {}


def normalise(text: Any) -> str:
    """Text as patterns see it: lower case, single spaces, no space after a comma."""
    return " ".join(str(text or "").lower().split()).replace(", ", ",")


def parse_pattern(pattern: Any) -> Any:
    """(anywhere, prefix, tokens) for a pattern string; ValueError if it is not one."""
    if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_PATTERN or pattern != pattern.lower():
        raise ValueError("bad idiom pattern %r" % (pattern,))
    anywhere = pattern.startswith("*")
    body = pattern[1:] if anywhere else pattern
    prefix = body.endswith("*")
    body = body[:-1] if prefix else body
    tokens: List[str] = []
    i = 0
    while i < len(body):
        if body[i] == "{":
            j = body.find("}", i)
            if j < 0 or body[i:j + 1] not in _CLASSES:
                raise ValueError("bad idiom pattern %r" % (pattern,))
            tokens.append(body[i:j + 1])
            i = j + 1
        elif body[i] in "*}" or body[i].isspace() and (i == 0 or body[i - 1] in ", "):
            raise ValueError("bad idiom pattern %r" % (pattern,))
        else:
            tokens.append(body[i])
            i += 1
    return anywhere, prefix, tokens


def _match_from(tokens: List[str], text: str, pos: int) -> int:
    """End position if the tokens match text at pos, else -1. No backtracking."""
    word = None
    end = len(text)
    for tok in tokens:
        if len(tok) == 1:
            if pos < end and text[pos] == tok:
                pos += 1
                continue
            return -1
        if tok == "{w=}":
            if word is None or not text.startswith(word, pos):
                return -1
            pos += len(word)
            continue
        start = pos
        if tok in ("{hex}", "{imm}") and text.startswith("0x", pos) and pos + 2 < end and text[pos + 2] in _HEXDIGITS:
            pos += 2
            while pos < end and text[pos] in _HEXDIGITS:
                pos += 1
        else:
            allowed = _HEXDIGITS if tok == "{hex}" else _WORDCHARS if tok == "{w}" else _DIGITS
            while pos < end and text[pos] in allowed:
                pos += 1
            if pos == start:
                return -1
        if tok == "{w}":
            word = text[start:pos]
    return pos


def pattern_matches(pattern: str, text: str) -> bool:
    """True if a pattern (see IDIOMS) matches normalised text."""
    parsed = _parsed.get(pattern)
    if parsed is None:
        parsed = _parsed[pattern] = parse_pattern(pattern)
    anywhere, prefix, tokens = parsed
    for start in range(len(text) + 1) if anywhere else (0,):
        stop = _match_from(tokens, text, start)
        if stop >= 0 and (prefix or stop == len(text)):
            return True
    return False


def _step_matches(row: Dict[str, Any], step: Dict[str, Any]) -> bool:
    mnemonic = " ".join(str(row.get("mnemonic") or "").lower().split())
    if mnemonic not in step["mn"]:
        return False
    operands = str(row.get("operands") or "")
    if "ops" in step and not any(pattern_matches(p, normalise(operands)) for p in step["ops"]):
        return False
    if "txt" in step and not any(pattern_matches(p, normalise(operands + " ; " + str(row.get("comment") or ""))) for p in step["txt"]):
        return False
    return True


def match_at(rows: List[Dict[str, Any]], index: int, idiom: Dict[str, Any]) -> int:
    """Number of rows the idiom spans if it starts at rows[index], else 0."""
    pos = index
    first = True
    for step in idiom["steps"]:
        limit = pos + (0 if first else int(step.get("gap", 0)))
        found = -1
        k = pos
        while k <= limit and k < len(rows):
            if _step_matches(rows[k], step):
                found = k
                break
            k += 1
        if found >= 0:
            pos = found + 1
            first = False
        elif step.get("opt") and not first:
            continue
        else:
            return 0
    return pos - index


def annotate(rows: List[Dict[str, Any]], arch: Optional[str]) -> List[Dict[str, Any]]:
    """Idioms found in a listing: [{"index", "span", "id"}], at most one per starting row."""
    out: List[Dict[str, Any]] = []
    if not arch:
        return out
    idioms = [i for i in IDIOMS if i["arch"] == arch]
    busy_until = 0  # rows inside an idiom already reported do not start another one
    for index in range(len(rows)):
        if index < busy_until:
            continue
        for idiom in idioms:
            span = match_at(rows, index, idiom)
            if span:
                if idiom["id"].endswith("-pad"):
                    end = index + span
                    while end < len(rows) and _step_matches(rows[end], idiom["steps"][0]):
                        end += 1
                    span = end - index
                busy_until = index + span
                out.append({"index": index, "span": span, "id": idiom["id"]})
                break
    return out
