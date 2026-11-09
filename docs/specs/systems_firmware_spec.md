# BinaryStudio — Systems Software & Firmware Binary Analysis Engine Specification

**Project Name:** **BinaryStudio** (`binary_viewer.py` / `macho_viewer.py`)
**Author:** Principal Systems Software & Firmware Engineer
**Scope:** Zero-dependency multi-format Mach-O, Universal (Fat), Kernelcache (`MH_FILESET`), Kext, Firmware (`MH_PRELOAD`), Linux ELF32/64, and Windows PE32/PE32+ binary parsing, byte-accurate structure layout mapping, security posture auditing, and reverse-engineering utilities.

---

## 1. Binary Format Coverage

### 1.1 Universal (Fat) Binary Container & Slice Selection
The parser inspects the first 4 bytes (`uint32_t` big-endian on disk) before assuming a thin Mach-O header:

| Magic Constant | Hex Value | Endianness / Layout | Entry Structure |
| :--- | :--- | :--- | :--- |
| `FAT_MAGIC` | `0xcafebabe` | Big-Endian (`>II`) | `fat_arch` (20 bytes: `cputype`, `cpusubtype`, `offset` (u32), `size` (u32), `align` (u32)) |
| `FAT_CIGAM` | `0xbebafeca` | Swapped (`<II`) | `fat_arch` (32-bit offsets) |
| `FAT_MAGIC_64` | `0xcafebabf` | Big-Endian (`>II`) | `fat_arch_64` (32 bytes: `cputype`, `cpusubtype`, `offset` (u64), `size` (u64), `align` (u32), `reserved` (u32)) |
| `FAT_CIGAM_64` | `0xbfbaeca` | Swapped (`<II`) | `fat_arch_64` (64-bit offsets for >4GB slices) |

- **Java Class Disambiguation:** Because `0xcafebabe` is shared with Java `.class` files, validate `nfat_arch <= 32` and verify that each `fat_arch.offset + fat_arch.size <= file_size` and that the target slice starts with a valid Mach-O magic (`MH_MAGIC*`) or embedded archive header (`!<arch>\n`).
- **Slice Addressing Contract:** Every parsed structure inside a Fat slice carries both `slice_offset` (relative to slice start, used by Mach-O `fileoff` fields) and `abs_offset` (`slice_base + slice_offset`, used by the hex viewer and raw byte reader).

### 1.2 Mach-O Header (`mach_header` / `mach_header_64`)
- **Magic Constants:**
  - `MH_MAGIC` (`0xfeedface`, 32-bit native), `MH_CIGAM` (`0xcefaedfe`, 32-bit swapped) — 28-byte header.
  - `MH_MAGIC_64` (`0xfeedfacf`, 64-bit native), `MH_CIGAM_64` (`0xcffaedfe`, 64-bit swapped) — 32-byte header (includes 4-byte `reserved` field at `+0x1C`).
- **CPU Types & Subtypes (`cputype_t`, `cpusubtype_t`):**
  - `CPU_TYPE_ARM64` (`0x0100000C`):
    - `CPU_SUBTYPE_ARM64_ALL` (`0`), `CPU_SUBTYPE_ARM64_V8` (`1`).
    - `CPU_SUBTYPE_ARM64E` (`2`): Mask capability bits (`0xff000000` = `CPU_SUBTYPE_MASK`). Decode PAC (Pointer Authentication) ABI version (`bits 24..31`, e.g., `0x80000002` = kernel/versioned PAC ABI).
  - `CPU_TYPE_ARM64_32` (`0x0200000C`): watchOS ILP32 (`CPU_SUBTYPE_ARM64_32_V8`).
  - `CPU_TYPE_ARM` (`12`): `ARM_V7` (`9`), `ARM_V7S` (`11`), `ARM_V7K` (`12`), `ARM_V7M`/`ARM_V7EM` (microcontroller/coprocessor firmware).
  - `CPU_TYPE_X86_64` (`0x01000007`): `CPU_SUBTYPE_X86_64_ALL` (`3`), `CPU_SUBTYPE_X86_64_H` (`8`, Haswell).
  - `CPU_TYPE_I386` (`7`).
- **File Types (`filetype`):**
  - Userland/Standard: `MH_OBJECT` (`0x1`), `MH_EXECUTE` (`0x2`), `MH_FVMLIB` (`0x3`), `MH_CORE` (`0x4`), `MH_DYLIB` (`0x6`), `MH_DYLINKER` (`0x7`), `MH_BUNDLE` (`0x8`), `MH_DYLIB_STUB` (`0x9`), `MH_DSYM` (`0xA`).
  - Kernel & Firmware:
    - `MH_PRELOAD` (`0x5`): Standalone firmware, bootloader stages, iBoot/SecureROM/SEP payloads, or raw embedded Mach-O images without dyld.
    - `MH_KEXT_BUNDLE` (`0xB`): XNU kernel extensions (`.kext`).
    - `MH_FILESET` (`0xC`): Modern macOS/iOS XNU kernelcache & dyld shared cache layout containing multiple constituent Mach-O entries via `LC_FILESET_ENTRY`.
- **Header Flags (`flags` bitmask):**
  - Decode all 32 bit flags symbolically (`MH_NOUNDEFS`, `MH_INCRLINK`, `MH_DYLDLINK`, `MH_BINDATLOAD`, `MH_PREBOUND`, `MH_SPLIT_SEGS`, `MH_TWOLEVEL`, `MH_FORCE_FLAT`, `MH_ALLOW_STACK_EXECUTION`, `MH_ROOT_SAFE`, `MH_SETUID_SAFE`, `MH_NO_REEXPORTED_DYLIBS`, `MH_PIE`, `MH_DEAD_STRIPPABLE_DYLIB`, `MH_HAS_TLV_DESCRIPTORS`, `MH_NO_HEAP_EXECUTION`, `MH_APP_EXTENSION_SAFE`, `MH_NLIST_OUTOFSORT_WITH_DYLDINFO`, `MH_SIM_SUPPORT`, `MH_DYLIB_IN_CACHE`).

---

## 2. Load Commands & Deep Inspection

Each load command begins with `load_command { uint32_t cmd; uint32_t cmdsize; }`. Unknown `cmd` values must still be surfaced with raw hex bytes and `LC_REQ_DYLD` (`0x80000000`) flag decoding.

### 2.1 Segments, Sections & Firmware Filesets
- **`LC_SEGMENT` (`0x1`) & `LC_SEGMENT_64` (`0x19`):**
  - Fields: `segname[16]`, `vmaddr`, `vmsize`, `fileoff`, `filesize`, `maxprot`, `initprot`, `nsects`, `flags`.
  - Protection bitmask (`vm_prot_t`): `VM_PROT_READ` (`0x1`), `VM_PROT_WRITE` (`0x2`), `VM_PROT_EXECUTE` (`0x4`) rendered as `rwx` strings (e.g., `r-x / rwx`).
  - Segment flags: `SG_HIGHVM` (`0x1`), `SG_FVMLIB` (`0x2`), `SG_NORELOC` (`0x4`), `SG_PROTECTED_VERSION_1` (`0x8`), `SG_READ_ONLY` (`0x10`).
  - Sections (`section` / `section_64`): `sectname[16]`, `segname[16]`, `addr`, `size`, `offset`, `align` ($2^{\text{align}}$), `reloff`, `nreloc`, `flags`, `reserved1`, `reserved2`, (`reserved3`).
    - `SECTION_TYPE` (`flags & 0xff`): `S_REGULAR`, `S_ZEROFILL`, `S_CSTRING_LITERALS`, `S_4BYTE_LITERALS`, `S_8BYTE_LITERALS`, `S_LITERAL_POINTERS`, `S_NON_LAZY_SYMBOL_POINTERS`, `S_LAZY_SYMBOL_POINTERS`, `S_SYMBOL_STUBS`, `S_MOD_INIT_FUNC_POINTERS`, `S_MOD_TERM_FUNC_POINTERS`, `S_THREAD_LOCAL_*`.
    - `SECTION_ATTRIBUTES` (`flags & 0xffffff00`): `S_ATTR_PURE_INSTRUCTIONS`, `S_ATTR_SOME_INSTRUCTIONS`, `S_ATTR_STRIP_STATIC_SYMS`, `S_ATTR_NO_DEAD_STRIP`, `S_ATTR_LIVE_SUPPORT`, `S_ATTR_SELF_MODIFYING_CODE`, `S_ATTR_DEBUG`.
- **`LC_FILESET_ENTRY` (`0x80000035`) for Kernelcaches:**
  - Parses `vmaddr`, `fileoff`, `entry_id` string (e.g., `com.apple.kernel`, `com.apple.driver.AppleSEPManager`), enabling recursive inspection of embedded kext Mach-Os inside an `MH_FILESET` container.

### 2.2 Dynamic Linker, Exports Trie & Chained Fixups
- **Dylibs & RPaths:**
  - `LC_LOAD_DYLIB` (`0xC`), `LC_ID_DYLIB` (`0xD`), `LC_LOAD_WEAK_DYLIB` (`0x80000018`), `LC_REEXPORT_DYLIB` (`0x8000001F`), `LC_LAZY_LOAD_DYLIB` (`0x20`), `LC_LOAD_UPWARD_DYLIB` (`0x80000023`): Extract path string, `timestamp`, `current_version` (`X.Y.Z` packed in `uint32_t`: `major = v >> 16`, `minor = (v >> 8) & 0xff`, `patch = v & 0xff`), and `compatibility_version`.
  - `LC_RPATH` (`0x8000001C`), `LC_LOAD_DYLINKER` (`0xE`), `LC_ID_DYLINKER` (`0xF`), `LC_DYLD_ENVIRONMENT` (`0x27`).
- **Legacy Dyld Info (`LC_DYLD_INFO` `0x22` / `LC_DYLD_INFO_ONLY` `0x80000022`):**
  - Bytecode state machines for `rebase` (`REBASE_OPCODE_*`), `bind` / `weak_bind` / `lazy_bind` (`BIND_OPCODE_*` with SLEB128/ULEB128 operands), and `export` trie.
- **Exports Trie (`LC_DYLD_EXPORTS_TRIE` `0x80000033` or `dyld_info.export_off`):**
  - DAG/Trie traversal with cycle-detection guard (`visited` offset set). Decodes terminal nodes: `flags` (`EXPORT_SYMBOL_FLAGS_KIND_REGULAR`, `WEAK_DEFINITION`, `REEXPORT`, `STUB_AND_RESOLVER`), ULEB128 symbol `address` (offset from `__TEXT`), and optional `import_name`/ordinal.
- **Chained Fixups (`LC_DYLD_CHAINED_FIXUPS` `0x80000034`):**
  - Parses `dyld_chained_fixups_header` -> `dyld_chained_starts_in_image` -> per-segment `dyld_chained_starts_in_segment` (`page_size`, `pointer_format`, `segment_offset`, `page_start[]`).
  - Supports pointer formats crucial for macOS/iOS and XNU/iBoot:
    - `DYLD_CHAINED_PTR_ARM64E`, `DYLD_CHAINED_PTR_ARM64E_KERNEL`, `DYLD_CHAINED_PTR_ARM64E_USERLAND`, `DYLD_CHAINED_PTR_ARM64E_USERLAND24`, `DYLD_CHAINED_PTR_ARM64E_FIRMWARE`: Decodes Auth vs Non-Auth Rebase/Bind, PAC key (`IA`, `IB`, `DA`, `DB`), diversity (`uint16_t`), `addrDiv` flag, target VM offset / bind ordinal.
    - `DYLD_CHAINED_PTR_64`, `DYLD_CHAINED_PTR_64_OFFSET`, `DYLD_CHAINED_PTR_64_KERNEL_CACHE`.
  - Parses import tables (`DYLD_CHAINED_IMPORT`, `DYLD_CHAINED_IMPORT_ADDEND`, `DYLD_CHAINED_IMPORT_ADDEND64`).

### 2.3 Symbol Tables (`LC_SYMTAB` & `LC_DYSYMTAB`)
- **`LC_SYMTAB` (`0x2`):**
  - Parses `nlist` (12 bytes) or `nlist_64` (16 bytes: `n_strx`, `n_type`, `n_sect`, `n_desc`, `n_value`).
  - `n_type` breakdown: `N_STAB` (`0xe0` debug symbols), `N_PEXT` (`0x10` private external), `N_TYPE` (`0x0e`: `N_UNDF`, `N_ABS`, `N_SECT`, `N_PBUD`, `N_INDR`), `N_EXT` (`0x01` external).
  - `n_desc` breakdown: Reference type (`REFERENCE_FLAG_*`), `REFERENCED_DYNAMICALLY`, `N_NO_DEAD_STRIP`, `N_WEAK_REF`, `N_WEAK_DEF`, `N_ARM_THUMB_DEF`, and two-level namespace library ordinal (`GET_LIBRARY_ORDINAL(n_desc)` -> `SELF_LIBRARY_ORDINAL`, `DYNAMIC_LOOKUP_ORDINAL`, `EXECUTABLE_ORDINAL`, or 1-based dylib index).
  - Demangling hints: Detect prefix `_$s` / `_$S` / `_T0` (Swift), `__Z` (Itanium C++), and resolve via system `c++filt` / `swift-demangle` or lightweight built-in demangler fallback.
- **`LC_DYSYMTAB` (`0xB`):**
  - Partition indices: `ilocalsym`/`nlocalsym`, `iextdefsym`/`nextdefsym`, `iundefsym`/`nundefsym`.
  - Indirect symbol table (`indirectsymoff`, `nindirectsyms`): Maps stub and lazy/non-lazy pointer slots (`reserved1` index in `section_64`) to symbol table indices (`INDIRECT_SYMBOL_LOCAL`, `INDIRECT_SYMBOL_ABS`, or `symtab[idx]`).

### 2.4 Entry Points & Thread States
- **`LC_MAIN` (`0x80000028`):** `entryoff` (file offset relative to `__TEXT` segment -> resolved to `VMAddr = __TEXT.vmaddr + entryoff`), `stacksize`.
- **`LC_UNIXTHREAD` (`0x5`) & `LC_THREAD` (`0x4`):** Used by `MH_PRELOAD` firmware, XNU kernels, and older binaries.
  - Parses thread flavor (`ARM_THREAD_STATE64` = `6`, `x86_THREAD_STATE64` = `4`, `ARM_THREAD_STATE` = `1`), `count`, and register state array:
    - ARM64 (`arm_thread_state64_t`): `x0`–`x28`, `fp` (`x29`), `lr` (`x30`), `sp`, `pc` (entry point VMAddr), `cpsr`.
    - x86_64 (`x86_thread_state64_t`): `rax`..`r15`, `rip` (entry point VMAddr), `rflags`, `cs`, `fs`, `gs`.

### 2.5 Identification, Build & Versioning
- **`LC_UUID` (`0x1B`):** 16-byte UUID formatted as canonical `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`.
- **`LC_BUILD_VERSION` (`0x32`):**
  - `platform` (`PLATFORM_MACOS` `1`, `PLATFORM_IOS` `2`, `PLATFORM_TVOS` `3`, `PLATFORM_WATCHOS` `4`, `PLATFORM_BRIDGEOS` `5`, `PLATFORM_MACCATALYST` `6`, `PLATFORM_IOSSIMULATOR` `7`, `PLATFORM_DRIVERKIT` `10`, `PLATFORM_VISIONOS` `11`, `PLATFORM_FIRMWARE` `13`, `PLATFORM_SEPOS` `14`).
  - `minos` and `sdk` (`XXXX.YY.ZZ` nibble-packed `uint32_t`).
  - `ntools` array of `build_tool_version` (`TOOL_CLANG` `1`, `TOOL_SWIFT` `2`, `TOOL_LD` `3`, `TOOL_LLD` `4`).
- **`LC_VERSION_MIN_MACOSX` (`0x24`), `LC_VERSION_MIN_IPHONEOS` (`0x25`), `LC_VERSION_MIN_TVOS` (`0x2F`), `LC_VERSION_MIN_WATCHOS` (`0x30`):** Legacy minimum OS/SDK commands.
- **`LC_SOURCE_VERSION` (`0x2A`):** 64-bit packed version `A.B.C.D.E` (24.10.10.10.10 bits).

### 2.6 Code Signing (`LC_CODE_SIGNATURE` `0x1D`) & Security Posture Engine
Code signature data resides in `__LINKEDIT` and uses **Big-Endian** network byte order (`CS_GenericBlob`, `CS_SuperBlob`, `CS_BlobIndex`).
- **SuperBlob (`CSMAGIC_EMBEDDED_SIGNATURE` `0xfade0cc0`):**
  - Iterates `count` `CS_BlobIndex` entries (`type` slot + `offset` relative to SuperBlob start):
    - **CodeDirectory (`CSMAGIC_CODEDIRECTORY` `0xfade0c02`, slots `0` and `0x1000+`):**
      - Decodes `version` (up to `0x20600` with `execSegBase`, `execSegLimit`, `execSegFlags`, `runtime`, `preEncryptOffset`), `flags` (`CS_VALID`, `CS_HARD`, `CS_KILL`, `CS_ENFORCEMENT`, `CS_REQUIRE_LV`, `CS_RUNTIME`, `CS_LINKER_SIGNED`, `CS_ADHOC`), `hashType` (`CS_HASHTYPE_SHA1`, `SHA256`, `SHA256_TRUNCATED`, `SHA384`), `pageSize` ($2^{\text{pageSize}}$), `identOffset` (Identifier string), `teamOffset` (Team ID string), `nSpecialSlots`, `nCodeSlots`.
      - **Live Hash Verification:** Computes the CDHash (hash of CodeDirectory blob truncated to 20 bytes / full hash) and optionally verifies special slots (`-1` Info.plist, `-2` Requirements, `-3` ResourceDir, `-5` Entitlements, `-7` DER Entitlements) and sample/all code page hashes against actual file bytes.
    - **Entitlements (`CSMAGIC_EMBEDDED_ENTITLEMENTS` `0xfade7171`, slot `5`):** Raw XML plist extraction and key-value parsing (highlighting high-privilege keys like `com.apple.private.*`, `get-task-allow`, `task_for_pid-allow`, `platform-application`).
    - **DER Entitlements (`CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` `0xfade7172`, slot `7`):** ASN.1 DER tree decoder into human-readable key-value dictionary.
    - **Requirements (`CSMAGIC_REQUIREMENTS` `0xfade0c01`, slot `2`):** Requirements blob listing.
    - **CMS Signature (`CSMAGIC_BLOBWRAPPER` `0xfade0b01`, slot `0x10000`):** PKCS#7 / CMS ASN.1 parser extracting signer certificate chain (Subject CN, Organizational Unit, Issuer, Serial, Validity timestamps) or marking as Ad-Hoc if empty.
- **Automated Security Posture Audit:**
  - **PIE (Position Independent Executable):** `MH_PIE` set on `MH_EXECUTE` and no fixed non-zero base without slide capability.
  - **Stack Canary:** Presence of `___stack_chk_fail` or `___stack_chk_guard` in undefined symbols (`LC_SYMTAB`).
  - **ARC (Automatic Reference Counting):** Presence of `_objc_release` / `_objc_retain` / `_objc_storeStrong` in undefined symbols.
  - **PAC (Pointer Authentication):** `CPU_SUBTYPE_ARM64E` or `DYLD_CHAINED_PTR_ARM64E*` fixups + PAC instructions (`paciasp`, `autiasp`, `retaa`, `retab`).
  - **RWX Segments / Sections:** Any segment where `(initprot & 0x7) == 0x7` or `(maxprot & 0x7) == 0x7` (with `MH_ALLOW_STACK_EXECUTION` / `MH_NO_HEAP_EXECUTION` cross-check).
  - **Restrict Segment / Hardened Runtime:** Presence of `__RESTRICT,__restrict` section, `CS_RUNTIME` (`0x10000`), or `CS_REQUIRE_LV` (`0x2000`).
  - **Encrypted Binary:** `LC_ENCRYPTION_INFO` (`0x21`) / `LC_ENCRYPTION_INFO_64` (`0x2C`) with `cryptid != 0` (`cryptoff`, `cryptsize`, `cryptid`).

### 2.7 Function Starts & Data-in-Code
- **`LC_FUNCTION_STARTS` (`0x26`):** Decodes the ULEB128 delta stream starting from `__TEXT.fileoff` (and `__TEXT.vmaddr`), producing an ordered table of function entry addresses (`vmaddr`, `file_offset`, inferred symbol name if unmatched in `LC_SYMTAB`, e.g., `sub_100004120`).
- **`LC_DATA_IN_CODE` (`0x29`):** Array of `data_in_code_entry` (`offset`, `length`, `kind`: `DICE_KIND_DATA`, `DICE_KIND_JUMP_TABLE8`, `JUMP_TABLE16`, `JUMP_TABLE32`, `ABS_JUMP_TABLE32`).

---

## 3. Firmware & Reverse-Engineering Essentials

### 3.1 Exact Byte-Range & Field-Level Layout Tracking
Every parsed node in the AST implements a `ByteRegion` contract so clicking any header, load command, section, symbol, or field in the UI immediately scrolls and highlights those exact bytes in the Hex Viewer (and vice-versa: clicking a byte in the Hex Viewer resolves the deepest enclosing `ByteRegion`).

- **Field-Level Breakdown (`StructField`):**
  Every structure emits an ordered list of fields:
  - `name` (e.g., `"cputype"`)
  - `abs_offset` (`uint64_t` byte offset from start of file)
  - `slice_offset` (`uint64_t` byte offset from start of Mach-O slice)
  - `size` (`uint32_t` in bytes: 1, 2, 4, 8, 16, or variable)
  - `raw_hex` (e.g., `"0c 00 00 01"`)
  - `raw_value` (integer or string)
  - `interpreted` (human-readable decoding, e.g., `"CPU_TYPE_ARM64 (0x0100000C)"`)

### 3.2 Virtual Address (`VMAddr`) <-> File Offset Translator
A dedicated O(log N) interval tree over `LC_SEGMENT` / `LC_SEGMENT_64` (and `LC_FILESET_ENTRY` sub-segments):
- **`vmaddr_to_offset(vmaddr)`:**
  Finds segment $S$ where $S.\text{vmaddr} \le \text{vmaddr} < S.\text{vmaddr} + S.\text{vmsize}$.
  - If $\text{vmaddr} - S.\text{vmaddr} < S.\text{filesize}$: returns `slice_offset = S.fileoff + (vmaddr - S.vmaddr)` and `abs_offset = slice_base + slice_offset`, plus enclosing section (`__TEXT,__text`) and nearest symbol (`_main + 0x24`).
  - If $\text{vmaddr} - S.\text{vmaddr} \ge S.\text{filesize}$ (e.g., `S_ZEROFILL` / `__bss`): marks as `UNMAPPED_ZEROFILL` (valid VM address, no backing file bytes).
- **`offset_to_vmaddr(offset)`:**
  Finds segment $S$ where $S.\text{fileoff} \le \text{offset} < S.\text{fileoff} + S.\text{filesize}$ and returns `vmaddr = S.vmaddr + (offset - S.fileoff)`.

### 3.3 String Extraction Engine
1. **Structured String Sections:** Automatically parses null-terminated UTF-8/ASCII strings from `S_CSTRING_LITERALS` (`__TEXT,__cstring`), Objective-C metadata (`__objc_methname`, `__objc_classname`, `__objc_methtype`), and UTF-16 (`__TEXT,__ustring`) with exact `vmaddr` and `abs_offset`.
2. **Full-Binary Raw String Scanner:** Configurable scan (min length $\ge 4$) across `__DATA_CONST`, `__RODATA`, or entire firmware image (`MH_PRELOAD`) to catch unsectioned strings common in iBoot/SecureROM.

### 3.4 ARM64 / x86_64 Instruction Disassembly Preview
For executable sections (`S_ATTR_PURE_INSTRUCTIONS` / `S_ATTR_SOME_INSTRUCTIONS`, e.g., `__TEXT,__text`, `__TEXT,__stubs`, `__TEXT,__auth_stubs`):
- **Dual-Backend Strategy:**
  1. **Primary (Fast On-Demand Windowed Disassembler):** Invokes macOS native `llvm-objdump --disassemble --macho --start-address=<vmaddr> --stop-address=<end>` (or `otool -tvV`) on requested address windows (e.g., 256–1024 instructions per page/function), OR uses a built-in zero-dependency ARM64 instruction decoder for core A64 instructions (`adrp`, `add`, `bl`, `b`, `ldr`, `str`, `stp`, `ldp`, `pac*`, `aut*`, `ret*`, `svc`, `mrs`, `msr`).
  2. **Symbol & PAC Cross-Referencing:** Resolves `adrp` + `add`/`ldr` pairs and `bl` targets against `LC_SYMTAB`, `LC_FUNCTION_STARTS`, stub targets, and `__cstring` literals so instructions display inline annotations (e.g., `; -> "Hello World" @ 0x100003f50`).

---

## 4. Architecture & Data Contract Recommendation

### 4.1 Layered Engine Design
- **Layer 1: Zero-Copy Byte Cursor (`BinaryBuffer`):** Bounds-checked reader supporting endian-aware primitives (`u8`, `u16`, `u32`, `u64`, `uleb128`, `sleb128`, `fixed_cstr`), automatically emitting `StructField` records as fields are read.
- **Layer 2: Structural Parser (`MachOParser`):** Parses Fat header, Mach-O slices, load commands, symbol tables, chained fixups, and code signatures into an immutable `MachODocument` model.
- **Layer 3: Query & On-Demand Services (`AnalysisService`):** Handles windowed hex slicing (`get_hex_range(abs_offset, length)`), windowed disassembly (`disassemble_range(slice_idx, vmaddr, count)`), and `VMAddr <-> FileOffset` translation without serializing gigabytes of raw hex or instructions upfront.

### 4.2 Canonical JSON Schema (`MachODocument`)
```json
{
  "file_info": {
    "path": "/usr/bin/true",
    "file_size": 101456,
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "is_fat": true,
    "fat_header": {
      "magic": "0xcafebabe",
      "magic_name": "FAT_MAGIC",
      "nfat_arch": 2,
      "region": { "abs_offset": 0, "slice_offset": 0, "size": 48 },
      "fields": [
        {
          "name": "magic",
          "abs_offset": 0,
          "slice_offset": 0,
          "size": 4,
          "raw_hex": "ca fe ba be",
          "raw_value": 3405691582,
          "interpreted": "FAT_MAGIC (Big-Endian 32-bit Universal)"
        }
      ]
    }
  },
  "slices": [
    {
      "slice_index": 0,
      "arch_name": "arm64e",
      "slice_base_offset": 16384,
      "slice_size": 50608,
      "header": {
        "magic": "0xfeedfacf",
        "magic_name": "MH_MAGIC_64",
        "is_64bit": true,
        "little_endian": true,
        "cputype": 16777228,
        "cputype_name": "CPU_TYPE_ARM64",
        "cpusubtype": 2147483650,
        "cpusubtype_name": "CPU_SUBTYPE_ARM64E (PAC v0x80)",
        "filetype": 2,
        "filetype_name": "MH_EXECUTE",
        "ncmds": 19,
        "sizeofcmds": 1528,
        "flags": 2097285,
        "flags_decoded": ["MH_NOUNDEFS", "MH_DYLDLINK", "MH_TWOLEVEL", "MH_PIE"],
        "region": { "abs_offset": 16384, "slice_offset": 0, "size": 32 },
        "fields": []
      },
      "security_posture": {
        "pie": true,
        "arc": false,
        "stack_canary": true,
        "pac_enabled": true,
        "has_rwx_segments": false,
        "has_restrict_segment": false,
        "is_encrypted": false,
        "code_signature": {
          "present": true,
          "is_adhoc": false,
          "hardened_runtime": true,
          "library_validation": false,
          "cdhash": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
          "cdhash_verified": true,
          "identifier": "com.apple.true",
          "team_id": "Software Signing",
          "certificates": ["Software Signing", "Apple Code Signing Certification Authority", "Apple Root CA"]
        }
      },
      "load_commands": [
        {
          "index": 0,
          "cmd": 25,
          "cmd_name": "LC_SEGMENT_64",
          "cmdsize": 72,
          "summary": "__PAGEZERO (vm: 0x0..0x100000000, prot: ---/---)",
          "region": { "abs_offset": 16416, "slice_offset": 32, "size": 72 },
          "fields": [],
          "details": {
            "segname": "__PAGEZERO",
            "vmaddr": "0x0",
            "vmsize": "0x100000000",
            "fileoff": 0,
            "filesize": 0,
            "initprot": "---",
            "maxprot": "---",
            "sections": []
          }
        }
      ],
      "memory_map": [
        {
          "segname": "__TEXT",
          "sectname": "__text",
          "vmaddr": "0x100003f60",
          "vmsize": 144,
          "slice_offset": 16224,
          "abs_offset": 32608,
          "filesize": 144,
          "prot": "r-x",
          "flags_decoded": ["S_REGULAR", "S_ATTR_PURE_INSTRUCTIONS", "S_ATTR_SOME_INSTRUCTIONS"]
        }
      ],
      "dylibs": [],
      "symbols": [],
      "exports": [],
      "chained_fixups": { "pointer_format": "DYLD_CHAINED_PTR_ARM64E", "chains_count": 12, "imports": [] },
      "function_starts": [
        { "vmaddr": "0x100003f60", "slice_offset": 16224, "abs_offset": 32608, "name": "_main" }
      ],
      "code_signature_detail": {
        "superblob_region": { "abs_offset": 51200, "slice_offset": 34816, "size": 15792 },
        "blobs": [],
        "entitlements_xml": "<?xml version=\"1.0\" ...>",
        "entitlements_dict": {}
      },
      "strings": [
        { "section": "__TEXT,__cstring", "vmaddr": "0x100003ff0", "abs_offset": 32752, "length": 12, "value": "usage: true" }
      ]
    }
  ]
}
```

### 4.3 On-Demand RPC / API Endpoints for UI Performance
To ensure instant responsiveness even on 150MB XNU kernelcaches (`MH_FILESET`), the backend exposes 4 lightweight endpoints alongside the initial `MachODocument` load:
1. `parse_file(path) -> MachODocument` (eagerly parses headers, load commands, segments/sections, security posture, code signature metadata, and bounded previews of symbols/strings).
2. `read_hex_slice(abs_offset, length) -> { abs_offset, bytes_hex, ascii, annotations: ByteRegion[] }` (called as the user scrolls the virtualized Hex Viewer).
3. `translate_address(slice_index, query: { vmaddr? | slice_offset? | abs_offset? }) -> { vmaddr, slice_offset, abs_offset, segment, section, symbol, symbol_offset }`.
4. `disassemble(slice_index, vmaddr, instruction_count) -> InstructionRow[]` where each `InstructionRow` contains `{ vmaddr, abs_offset, raw_bytes_hex, mnemonic, operands, comment, branch_target_vmaddr }`.
