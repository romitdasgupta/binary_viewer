# CTO Architecture Decision Record (ADR) & Integration Contract — BinaryStudio

**Document ID:** `ADR-001-BINARYSTUDIO`  
**Status:** **LOCKED / AUTHORITATIVE**  
**Author:** Chief Technology Officer (CTO Agent)  
**Project Name:** **BinaryStudio** (`binary_viewer.py`, with `macho_viewer.py` compatibility wrapper)  
**Audience:** Systems & Firmware Engineering (`sys_firmware_eng`), UI/UX & Frontend Architecture (`ui_ux_expert`), QA & Verification

---

## 1. Executive Summary & Final Architectural Decisions

After reviewing [`systems_firmware_spec.md`](../../docs/specs/systems_firmware_spec.md) and [`ui_ux_spec.md`](../../docs/specs/ui_ux_spec.md) and auditing the target macOS host environment (`Python 3.9.6`, `Apple clang 21.0.0`, `/usr/bin/lipo`, `/usr/bin/codesign`, `/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`, `swift-demangle`, `c++filt`), the following technical decisions are **final and locked**:

### 1.1 Tech Stack Decision: Zero-Dependency Python 3 Stdlib Backend + Vanilla ES6 Desktop Web IDE + CLI
- **Backend Server (`http.server.ThreadingHTTPServer`):**
  - **Decision:** Pure Python 3 Standard Library (`http.server.ThreadingHTTPServer`, `struct`, `json`, `hashlib`, `plistlib`, `urllib.parse`, `subprocess`, `unittest`). **Zero external PyPI dependencies required.**
  - **Rationale:** System Python 3.9.6 does not have `fastapi` or `uvicorn` pre-installed. Using pure Python standard library (`ThreadingHTTPServer`) guarantees 100% deterministic, zero-friction startup (`python3 binary_viewer.py`) with zero virtual environment or network dependency failures, while supporting concurrent API requests for hex range slicing, disassembly, and address conversion.
- **Frontend GUI (`static/index.html`, `static/styles.css`, `static/app.js`):**
  - **Decision:** Self-contained, zero-build-step Vanilla ES6+ Single-Page Application served directly by the Python HTTP server.
  - **Rationale:** Avoids Node/npm/bundler friction while delivering a pixel-accurate, high-density dark-mode IDE (`#0D1117` canvas, tabular monospace typography, dual-track SVG/Canvas memory map ribbon, virtualized 16-byte Hex/ASCII grid, live Data Decoder, real-time VM/File Offset converter bar, and `Cmd+K` global omni-search).
- **Unified Launcher & CLI (`binary_viewer.py` & `macho_viewer.py` compatibility wrapper):**
  - Supports both **Web GUI Server Mode** (`python3 binary_viewer.py [--port 8421] [--file /bin/ls] [--open]`) and **Headless CLI / JSON Inspection Mode** (`python3 binary_viewer.py --cli <path> [--json] [--slice <arch|idx>] [--disasm <vmaddr>] [--translate <addr>]`).

### 1.2 Test Binary & Synthetic Firmware Fixture Strategy
To guarantee comprehensive verification across all Mach-O constructs (even for edge cases not present in `/bin/ls` or `/usr/bin/true`), the project will include an automated fixture generator (`tests/build_fixtures.py` or `backend/fixtures.py`) that compiles deterministic Mach-O binaries into `fixtures/` using macOS `clang`, `lipo`, and `codesign`:

1. **`fixtures/synthetic_universal` (Universal Fat Binary: `arm64` + `x86_64`):**
   - Compiled from C/Objective-C/C++ source with `-arch arm64` and `-arch x86_64` and merged via `/usr/bin/lipo -create`.
   - Includes:
     - Custom segments and sections (`__TEXT,__custom_code`, `__DATA,__custom_data`, `__RODATA,__ firmware_cfg`).
     - Exported functions, C++ mangled symbols (`_Z14compute_cryptoPKhm`), Objective-C classes/selectors (`__objc_classname`, `__objc_methname`), and Thread-Local Variables (`__DATA,__thread_vars`).
     - `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_DYLD_CHAINED_FIXUPS` / `LC_DYLD_EXPORTS_TRIE`, `LC_FUNCTION_STARTS`, `LC_UUID`, `LC_BUILD_VERSION`, `LC_SOURCE_VERSION`, `LC_RPATH` (`@executable_path/../Frameworks`).
     - Ad-hoc code signature (`codesign -s - --entitlements fixtures/entitlements.plist`) embedding a rich XML & DER Entitlements blob (`com.apple.security.get-task-allow`, `com.apple.security.cs.allow-jit`, `com.apple.private.custom-test`).
2. **`fixtures/synthetic_firmware.preload` (`MH_PRELOAD` Standalone Firmware Image):**
   - Constructed/compiled as a standalone `MH_PRELOAD` (`filetype = 0x5`) ARM64 firmware image containing `LC_UNIXTHREAD` (with full `ARM_THREAD_STATE64` initial register state `x0`..`x28`, `fp`, `lr`, `sp`, `pc`, `cpsr`), unsectioned raw firmware version strings, and a custom RWX segment to trigger the Security Posture Audit's `has_rwx_segments` warning.
3. **Real System Binaries (Built-in Presets):**
   - `/bin/ls` (macOS Universal `arm64e` + `x86_64`, PAC-enabled, Apple system code signature, Hardened Runtime).
   - `/usr/bin/true` (Compact macOS Universal `arm64e` + `x86_64` baseline).

---

## 2. Directory & Module Layout

```text
├── binary_viewer.py                # Primary Entrypoint: CLI inspector + HTTP Server launcher
├── macho_viewer.py                 # Backward-compatible CLI & server wrapper
├── README.md                       # Documentation, architecture overview, CLI & GUI usage
├── backend/
│   ├── __init__.py
│   ├── buffer.py                   # Layer 1: BinaryBuffer (bounds-checked cursor, ULEB128/SLEB128, StructField emitter)
│   ├── constants.py                # Mach-O magic numbers, CPU types, LC_* names, flags, VM_PROT, CS_* constants
│   ├── parser.py                   # Layer 2: MachOParser (Fat, Header, Load Commands, Segments, Symtab, Fixups, Strings)
│   ├── codesign.py                 # LC_CODE_SIGNATURE SuperBlob, CodeDirectory CDHash verifier, Entitlements, CMS parser
│   ├── security.py                 # Automated Security Posture & Hardening Audit engine
│   ├── disasm.py                   # Layer 3: ARM64 native decoder + llvm-objdump / otool integration & symbol resolver
│   ├── service.py                  # AnalysisService: caching, hex slicing, interval-tree VMAddr<->FileOffset translator, search
│   ├── fixtures.py                 # Builds synthetic_universal & synthetic_firmware.preload using clang/lipo/codesign
│   └── server.py                   # ThreadingHTTPServer REST API router & static asset server
├── static/
│   ├── index.html                  # App shell: Top bar, Dual Memory Map Ribbon, Converter Bar, 3-Pane Split, Status Bar, Cmd+K Modal
│   ├── styles.css                  # High-contrast dark theme (#0D1117), semantic memory colors, tabular grids, split panes
│   └── app.js                      # State store, Tree Navigator, Memory Map renderer, Inspector views, Virtualized Hex & Decoder
├── fixtures/                       # Generated test binaries & entitlements plist
│   ├── entitlements.plist
│   ├── synthetic_universal
│   └── synthetic_firmware.preload
├── tests/
│   └── test_binary_viewer.py       # End-to-end unit & integration test suite (parser, API endpoints, real & synthetic binaries)
└── docs/
    └── specs/
        ├── systems_firmware_spec.md
        ├── ui_ux_spec.md
        └── cto_architecture_decision.md
```

---

## 3. Unified Byte-Span & Field Schema (Reconciling Backend & Frontend)

To satisfy both `sys_firmware_eng`'s `ByteRegion`/`StructField` model and `ui_ux_expert`'s `span`/`fields` model without translation friction, **every structural object and field** uses these exact keys:

### 3.1 `ByteRegion` Object (`region`)
Attached to `fat_header`, `header`, each `load_command`, each `segment`, each `section`, `code_signature_detail`, etc.:
```json
{
  "abs_offset": 16384,
  "slice_offset": 0,
  "size": 32,
  "vmaddr": "0x100000000",
  "vmsize": 32
}
```
*(Note: `vmaddr` and `vmsize` are optional on file-only structures like `fat_header`, defaulting to `null`.)*

### 3.2 `StructField` Object (`fields[]`)
Used directly by the Center Inspector's **Structure Field Table View** and **Synchronized Hex Highlighter**:
```json
{
  "name": "cputype",
  "type": "uint32",
  "abs_offset": 16388,
  "slice_offset": 4,
  "size": 4,
  "raw_hex": "0c 00 00 01",
  "raw_value": 16777228,
  "value": "0x0100000c",
  "interpreted": "CPU_TYPE_ARM64",
  "description": "64-bit ARM architecture (AArch64)",
  "bit_flags": [
    { "name": "CPU_ARCH_ABI64", "mask": "0x01000000", "set": true }
  ],
  "target_offset": null,
  "target_vmaddr": null
}
```
- `abs_offset` (int): Exact byte offset from the beginning of the file (`0..file_size`). **This is the primary coordinate used by the Hex Viewer.**
- `slice_offset` (int): Byte offset relative to the start of the active Mach-O slice (`abs_offset - slice_base_offset`).
- `size` (int): Field length in bytes.
- `raw_hex` (string): Space-separated lowercase hex bytes in file order (e.g., `"cf fa ed fe"`).
- `value` (string): Formatted hex or scalar value (e.g., `"0xfeedfacf"`).
- `interpreted` (string): Human-readable symbolic decoding (e.g., `"MH_MAGIC_64"` or `"MH_NOUNDEFS | MH_DYLDLINK | MH_PIE"`).
- `bit_flags` (optional array): Present on bitmask fields (`flags`, `initprot`, `maxprot`, `section.flags`) for expandable bitflag pills in the UI.
- `target_offset` / `target_vmaddr` (optional int / hex string): Present on pointer/offset fields (`symoff`, `stroff`, `dataoff`, `entryoff`, `offset`, `addr`) to render clickable `[Jump -> ...]` chips.

---

## 4. Authoritative HTTP REST API Contract

The backend server listens on `127.0.0.1` (default port `8421`, configurable via `--port`). All API responses return `Content-Type: application/json; charset=utf-8` with standard HTTP status codes (`200 OK`, `400 Bad Request`, `404 Not Found`, `500 Internal Server Error` with `{"error": "message"}`).

### 4.1 `GET /api/presets`
Returns the list of built-in one-click sample binaries and recently loaded files.
- **Response (`200 OK`):**
```json
{
  "presets": [
    {
      "id": "synthetic_universal",
      "label": "Synthetic Universal (arm64 + x86_64)",
      "path": "fixtures/synthetic_universal",
      "description": "Multi-arch test binary with custom segments, C++/ObjC symbols, chained fixups & entitlements",
      "exists": true
    },
    {
      "id": "synthetic_firmware",
      "label": "Synthetic Firmware (MH_PRELOAD)",
      "path": "fixtures/synthetic_firmware.preload",
      "description": "Standalone ARM64 firmware image with LC_UNIXTHREAD state and RWX segment warning",
      "exists": true
    },
    {
      "id": "bin_ls",
      "label": "/bin/ls",
      "path": "/bin/ls",
      "description": "macOS Universal system utility (arm64e PAC + x86_64) with Apple Code Signature",
      "exists": true
    },
    {
      "id": "usr_bin_true",
      "label": "/usr/bin/true",
      "path": "/usr/bin/true",
      "description": "Minimal macOS Universal Mach-O executable",
      "exists": true
    }
  ]
}
```

### 4.2 `POST /api/parse` (and `GET /api/parse?path=<urlencoded_path>`)
Parses a local file path on disk, sets it as the active binary in `AnalysisService`, and returns the canonical `MachODocument`.
- **Request (`POST` JSON body or `GET` query param):**
  ```json
  { "path": "/bin/ls" }
  ```
- **Response (`200 OK`):** Returns the full `MachODocument` JSON (schema locked in **Section 5** below).

### 4.3 `POST /api/upload`
Accepts a drag-and-dropped binary file from the browser.
- **Request:**
  - Either `Content-Type: application/octet-stream` with header `X-Filename: my_binary.dylib` (raw binary body), OR JSON `{"filename": "my_binary", "data_base64": "..."}`.
  - Backend saves or caches the buffer in memory/temp, parses it, sets it as active, and returns the exact same `MachODocument` JSON as `/api/parse`.

### 4.4 `GET /api/hex`
Returns a windowed slice of raw bytes for the virtualized Hex/ASCII pane plus structural annotations overlapping that range, and live multi-format data decoding at the start offset.
- **Query Parameters:**
  - `path` (optional string — defaults to currently loaded file)
  - `offset` (int, required — `abs_offset` from start of file, e.g. `16384`)
  - `length` (int, optional — default `4096`, max `65536`)
  - `slice_index` (int, optional — default `0`, used to resolve `vmaddr` and slice-specific annotations)
- **Response (`200 OK`):**
```json
{
  "abs_offset": 16384,
  "length": 64,
  "file_size": 101456,
  "hex_bytes": "cffaedfe0c000001020000800200000013000000f80500008500200000000000...",
  "rows": [
    {
      "abs_offset": 16384,
      "slice_offset": 0,
      "vmaddr": "0x100000000",
      "hex_array": ["cf", "fa", "ed", "fe", "0c", "00", "00", "01", "02", "00", "00", "80", "02", "00", "00", "00"],
      "ascii": "................"
    }
  ],
  "annotations": [
    {
      "id": "header_0",
      "label": "mach_header_64",
      "category": "header",
      "abs_offset": 16384,
      "size": 32
    }
  ]
}
```

### 4.5 `GET /api/decode`
Decodes 1–16 bytes at a specific `abs_offset` for the **Live Byte Inspector / Data Decoder Card** (docked below the Hex Grid) and resolves the structural ownership breadcrumb.
- **Query Parameters:**
  - `offset` (int, required — `abs_offset`)
  - `slice_index` (int, default `0`)
  - `endian` (string, optional — `"little"` or `"big"`, default `"little"`)
  - ` path` (optional string)
- **Response (`200 OK`):**
```json
{
  "abs_offset": 16384,
  "slice_offset": 0,
  "vmaddr": "0x100000000",
  "raw_hex": "cf fa ed fe 0c 00 00 01",
  "breadcrumbs": [
    { "id": "slice_0", "label": "Slice #0 (arm64e)", "abs_offset": 16384, "size": 50608 },
    { "id": "seg___TEXT", "label": "LC_SEGMENT_64 (__TEXT)", "abs_offset": 16384, "size": 16384 },
    { "id": "header_0", "label": "mach_header_64", "abs_offset": 16384, "size": 32 },
    { "id": "field_magic", "label": "magic (MH_MAGIC_64)", "abs_offset": 16384, "size": 4 }
  ],
  "primitives": {
    "uint8": 207,
    "int8": -49,
    "uint16": 64207,
    "int16": -1329,
    "uint32": 4277009103,
    "int32": -17958193,
    "hex32": "0xfeedfacf",
    "uint64": "0x0100000cfeeedfacf",
    "int64": 72057649807620815,
    "float32": -1.581185e+38,
    "float64": 7.291128e-304,
    "uleb128": { "value": 3489056719, "byte_length": 5 },
    "sleb128": { "value": -805910577, "byte_length": 5 },
    "cstring_preview": "....",
    "arm64_insn": "udf #0xfacf"
  }
}
```

### 4.6 `GET /api/translate`
Bidirectional O(log N) address converter between `vmaddr`, `slice_offset`, and `abs_offset` for the **Address / Offset Converter Bar**.
- **Query Parameters:**
  - `slice_index` (int, default `0`)
  - `query` (string, required — hex `0x100003f60` or decimal `16224`, or explicit `vmaddr=...` / `abs_offset=...` / `slice_offset=...`)
  - `mode` (string, optional — `"auto"` (default: treats values `>= __TEXT.vmaddr` as `vmaddr`, smaller values as offset), `"vmaddr"`, `"abs_offset"`, or `"slice_offset"`)
- **Response (`200 OK`):**
```json
{
  "query": "0x100003f60",
  "mode_resolved": "vmaddr",
  "mapped": true,
  "status": "MAPPED",
  "vmaddr": "0x100003f60",
  "rva": "0x3f60",
  "slice_offset": 16224,
  "abs_offset": 32608,
  "segment": {
    "segname": "__TEXT",
    "vmaddr": "0x100000000",
    "vmsize": "0x4000",
    "initprot": "r-x",
    "maxprot": "r-x"
  },
  "section": {
    "sectname": "__text",
    "segname": "__TEXT",
    "vmaddr": "0x100003f60",
    "size": 144,
    "abs_offset": 32608
  },
  "nearest_symbol": {
    "name": "_main",
    "demangled": "main",
    "vmaddr": "0x100003f60",
    "offset_from_symbol": 0,
    "display": "_main + 0x0"
  }
}
```

### 4.7 `GET /api/disassemble`
On-demand instruction disassembly for executable sections (`__TEXT,__text`, `__TEXT,__stubs`, `__TEXT,__auth_stubs`, etc.).
- **Query Parameters:**
  - `slice_index` (int, default `0`)
  - `vmaddr` (string/int, optional — defaults to entry point or first executable section `__TEXT,__text`)
  - `section` (string, optional — e.g. `"__TEXT,__text"`)
  - `count` (int, default `200`, max `1000`)
- **Response (`200 OK`):**
```json
{
  "slice_index": 0,
  "arch_name": "arm64e",
  "section": "__TEXT,__text",
  "start_vmaddr": "0x100003f60",
  "instructions": [
    {
      "vmaddr": "0x100003f60",
      "slice_offset": 16224,
      "abs_offset": 32608,
      "size": 4,
      "raw_hex": "7f 23 03 d5",
      "mnemonic": "paciasp",
      "operands": "",
      "symbol_label": "_main",
      "comment": "PAC Sign LR with SP (Key A)",
      "branch_target_vmaddr": null
    },
    {
      "vmaddr": "0x100003f64",
      "slice_offset": 16228,
      "abs_offset": 32612,
      "size": 4,
      "raw_hex": "fd 7b bf a9",
      "mnemonic": "stp",
      "operands": "x29, x30, [sp, #-0x10]!",
      "symbol_label": null,
      "comment": "Prologue frame setup",
      "branch_target_vmaddr": null
    }
  ]
}
```

### 4.8 `GET /api/search`
Backend-accelerated omni-search (complementing instant client-side search in `Cmd+K`), supporting symbol search, string search, load command search, and **raw hex byte sequence search** across the entire binary.
- **Query Parameters:**
  - `q` (string, required — e.g., `"main"`, `"@objc"`, `"\"usage"`, `"#LC_MAIN"`, or hex bytes `"cf fa ed fe"`)
  - `slice_index` (int, default `0`)
  - `scope` (string, optional — `"all"`, `"symbols"`, `"strings"`, `"structures"`, `"hex"`)
- **Response (`200 OK`):**
```json
{
  "query": "main",
  "results": [
    {
      "category": "symbol",
      "title": "_main",
      "subtitle": "__TEXT,__text • External Defined (SECT)",
      "vmaddr": "0x100003f60",
      "abs_offset": 32608,
      "size": 4,
      "node_id": "symtab"
    }
  ]
}
```

---

## 5. Locked `MachODocument` JSON Schema (`/api/parse`)

Below is the exact top-level and per-slice JSON schema returned by `/api/parse` and `/api/upload`. Both engineers MUST adhere to these exact key names:

```json
{
  "file_info": {
    "path": "/bin/ls",
    "filename": "ls",
    "file_size": 168432,
    "sha256": "8a3f...",
    "md5": "1b2c...",
    "is_fat": true,
    "fat_header": {
      "magic": "0xcafebabe",
      "magic_name": "FAT_MAGIC",
      "is_64bit": false,
      "is_swapped": true,
      "nfat_arch": 2,
      "region": { "abs_offset": 0, "slice_offset": 0, "size": 48, "vmaddr": null, "vmsize": null },
      "fields": [ /* StructField[] */ ],
      "slices_summary": [
        {
          "slice_index": 0,
          "arch_name": "x86_64",
          "cputype": 16777223,
          "cputype_name": "CPU_TYPE_X86_64",
          "cpusubtype": 3,
          "cpusubtype_name": "CPU_SUBTYPE_X86_64_ALL",
          "offset": 16384,
          "size": 69968,
          "align": 14,
          "align_bytes": 16384
        },
        {
          "slice_index": 1,
          "arch_name": "arm64e",
          "cputype": 16777228,
          "cputype_name": "CPU_TYPE_ARM64",
          "cpusubtype": 2147483650,
          "cpusubtype_name": "CPU_SUBTYPE_ARM64E (PAC v0x80)",
          "offset": 98304,
          "size": 70128,
          "align": 14,
          "align_bytes": 16384
        }
      ]
    }
  },
  "slices": [
    {
      "slice_index": 0,
      "arch_name": "arm64e",
      "slice_base_offset": 98304,
      "slice_size": 70128,
      "overview": {
        "filetype_name": "MH_EXECUTE",
        "filetype_desc": "Demand Paged Executable File",
        "arch_display": "ARM64e (Pointer Authentication ABI v0x80)",
        "endianness": "Little-Endian",
        "is_64bit": true,
        "uuid": "A1B2C3D4-E5F6-...",
        "platform": "macOS",
        "minos": "15.0.0",
        "sdk": "15.2.0",
        "source_version": "650.100.2.0.0",
        "entry_point_vmaddr": "0x100003f60",
        "entry_point_abs_offset": 114528,
        "entry_point_type": "LC_MAIN",
        "ncmds": 19,
        "sizeofcmds": 1528,
        "segments_count": 4,
        "sections_count": 9,
        "symbols_count": 124,
        "strings_count": 198,
        "dylibs_count": 3
      },
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
        "flags_hex": "0x00200085",
        "flags_decoded": ["MH_NOUNDEFS", "MH_DYLDLINK", "MH_TWOLEVEL", "MH_PIE"],
        "region": { "abs_offset": 98304, "slice_offset": 0, "size": 32, "vmaddr": "0x100000000", "vmsize": 32 },
        "fields": [ /* StructField[] */ ]
      },
      "load_commands": [
        {
          "index": 0,
          "cmd": 25,
          "cmd_hex": "0x19",
          "cmd_name": "LC_SEGMENT_64",
          "cmdsize": 72,
          "req_dyld": false,
          "summary": "__PAGEZERO (vm: 0x0..0x100000000, prot: ---/---)",
          "region": { "abs_offset": 98336, "slice_offset": 32, "size": 72, "vmaddr": "0x100000020", "vmsize": 72 },
          "fields": [ /* StructField[] */ ],
          "details": { /* command-specific parsed dictionary */ }
        }
      ],
      "segments": [
        {
          "index": 0,
          "segname": "__TEXT",
          "vmaddr": "0x100000000",
          "vmaddr_int": 4294967296,
          "vmsize": "0x4000",
          "vmsize_int": 16384,
          "fileoff": 0,
          "filesize": 16384,
          "abs_offset": 98304,
          "initprot": "r-x",
          "maxprot": "r-x",
          "initprot_raw": 5,
          "maxprot_raw": 5,
          "nsects": 4,
          "flags": 0,
          "flags_decoded": [],
          "region": { "abs_offset": 98304, "slice_offset": 0, "size": 16384, "vmaddr": "0x100000000", "vmsize": 16384 },
          "header_region": { "abs_offset": 98408, "slice_offset": 104, "size": 392, "vmaddr": "0x100000068", "vmsize": 392 },
          "fields": [ /* StructField[] for segment_command_64 */ ],
          "sections": [
            {
              "index": 0,
              "sectname": "__text",
              "segname": "__TEXT",
              "vmaddr": "0x100003f60",
              "vmaddr_int": 4294983520,
              "size": 144,
              "slice_offset": 16224,
              "abs_offset": 114528,
              "align": 2,
              "align_bytes": 4,
              "reloff": 0,
              "nreloc": 0,
              "flags": 2147484672,
              " flags_hex": "0x80000400",
              "section_type": "S_REGULAR",
              "attributes_decoded": ["S_ATTR_PURE_INSTRUCTIONS", "S_ATTR_SOME_INSTRUCTIONS"],
              "is_executable": true,
              "prot": "r-x",
              "region": { "abs_offset": 114528, "slice_offset": 16224, "size": 144, "vmaddr": "0x100003f60", "vmsize": 144 },
              "header_region": { "abs_offset": 98480, "slice_offset": 176, "size": 80, "vmaddr": "0x1000000b0", "vmsize": 80 },
              "fields": [ /* StructField[] for section_64 header */ ]
            }
          ]
        }
      ],
      "memory_map": [
        /* Flattened array of segment & section descriptors for the Top Dual Memory Map Ribbon */
      ],
      "dylibs": [
        {
          "index": 0,
          "cmd_name": "LC_LOAD_DYLIB",
          "name": "/usr/lib/libSystem.B.dylib",
          "timestamp": 2,
          "current_version": "1351.0.0",
          "compatibility_version": "1.0.0",
          "abs_offset": 99120,
          "size": 56
        }
      ],
      "rpaths": [
        { "path": "@executable_path/../Frameworks", "abs_offset": 99200, "size": 48 }
      ],
      "entry_point": {
        "type": "LC_MAIN",
        "entryoff": 16224,
        "vmaddr": "0x100003f60",
        "abs_offset": 114528,
        "stacksize": 0,
        "thread_flavor": null,
        "registers": {}
      },
      "dyld_info": {
        "has_dyld_info": false,
        "has_chained_fixups": true,
        "has_exports_trie": true,
        "chained_fixups": {
          "fixups_version": 0,
          "pointer_format": "DYLD_CHAINED_PTR_ARM64E",
          "imports_format": "DYLD_CHAINED_IMPORT",
          "imports_count": 42,
          "chains_count": 48,
          "segments": [],
          "imports": [
            { "index": 0, "name": "_printf", "lib_ordinal": 1, "lib_name": "/usr/lib/libSystem.B.dylib", "weak_import": false }
          ],
          "fixups": [
            { "vmaddr": "0x100004000", "abs_offset": 114688, "type": "AUTH_BIND", "ordinal": 0, "symbol": "_printf", "pac_key": "IA", "diversity": 0, "addr_div": true }
          ],
          "region": { "abs_offset": 131072, "slice_offset": 32768, "size": 512, "vmaddr": null, "vmsize": null },
          "fields": []
        },
        "exports": [
          { "name": "__mh_execute_header", "vmaddr": "0x100000000", "offset": 0, "flags": 0, "flags_decoded": ["EXPORT_SYMBOL_FLAGS_KIND_REGULAR"] }
        ],
        "rebases": [],
        "binds": []
      },
      "symbols": [
        {
          "index": 0,
          "name": "_main",
          "demangled": "main",
          "n_strx": 4,
          "n_type": 15,
          "n_type_hex": "0x0f",
          "type_name": "SECT",
          "is_external": true,
          "is_private_external": false,
          "is_stab": false,
          "n_sect": 1,
          "section_name": "__TEXT,__text",
          "n_desc": 0,
          "library_ordinal": 0,
          "library_name": "SELF",
          "n_value": "0x100003f60",
          "n_value_int": 4294983520,
          "abs_offset": 132000,
          "slice_offset": 33696,
          "size": 16,
          "target_abs_offset": 114528
        }
      ],
      "dysymtab": {
        "present": true,
        "ilocalsym": 0,
        "nlocalsym": 12,
        "iextdefsym": 12,
        "nextdefsym": 4,
        "iundefsym": 16,
        "nundefsym": 42,
        "indirect_symbols": [
          { "index": 0, "section": "__TEXT,__auth_stubs", "slot_vmaddr": "0x100003f90", "symtab_index": 16, "symbol_name": "_printf" }
        ],
        "fields": []
      },
      "function_starts": [
        { "index": 0, "vmaddr": "0x100003f60", "slice_offset": 16224, "abs_offset": 114528, "name": "_main" }
      ],
      "strings": [
        {
          "index": 0,
          "source": "__TEXT,__cstring",
          "vmaddr": "0x100003ff0",
          "slice_offset": 16368,
          "abs_offset": 114672,
          "length": 12,
          "encoding": "UTF-8",
          "value": "usage: ls [-ABCFGHLOPRSTUWabcdefghiklmnopqrstuwx1]"
        }
      ],
      "objc_metadata": {
        "present": false,
        "classes": [],
        "selectors": [],
        "protocols": []
      },
      "fileset_entries": [
        /* Populated for MH_FILESET kernelcaches: { entry_id, vmaddr, fileoff, abs_offset } */
      ],
      "code_signature_detail": {
        "present": true,
        "superblob_region": { "abs_offset": 149504, "slice_offset": 51200, "size": 18928, "vmaddr": null, "vmsize": null },
        "magic": "0xfade0cc0",
        "length": 18928,
        "blob_count": 5,
        "fields": [ /* StructField[] for CS_SuperBlob & CS_BlobIndex */ ],
        "blobs": [
          { "index": 0, "type": 0, "type_name": "CSSLOT_CODEDIRECTORY", "magic": "0xfade0c02", "magic_name": "CSMAGIC_CODEDIRECTORY", "abs_offset": 149548, "size": 652 }
        ],
        "code_directory": {
          "version": "0x20400",
          "flags": "0x00010002",
          "flags_decoded": ["CS_ADHOC", "CS_RUNTIME"],
          "hash_type": "SHA-256 (2)",
          "page_size": 4096,
          "identifier": "com.apple.ls",
          "team_id": "",
          "cdhash": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
          "cdhash_full": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
          "cdhash_verified": true,
          "n_special_slots": 7,
          "n_code_slots": 13,
          "exec_seg_base": 0,
          "exec_seg_limit": 16384,
          "exec_seg_flags": 1,
          "special_slots": [
            { "slot": -1, "name": "Info.plist", "hash": "0000...", "present": false },
            { "slot": -5, "name": "Entitlements (XML)", "hash": "9f8e...", "present": true, "verified": true },
            { "slot": -7, "name": "Entitlements (DER)", "hash": "3c4d...", "present": true, "verified": true }
          ],
          "code_slots_preview": [
            { "page_index": 0, "file_offset": 0, "expected_hash": "8a1b...", "actual_hash": "8a1b...", "verified": true }
          ],
          "fields": [ /* StructField[] */ ]
        },
        "entitlements_xml": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>...",
        "entitlements_dict": {
          "com.apple.security.get-task-allow": true
        },
        "entitlements_entries": [
          { "key": "com.apple.security.get-task-allow", "value": true, "type": "boolean", "risk": "HIGH", "reason": "Allows debugger attachment / task_for_pid" }
        ],
        "cms_signature": {
          "present": true,
          "is_adhoc": false,
          "size": 4412,
          "certificates": [
            { "subject_cn": "Software Signing", "issuer_cn": "Apple Code Signing Certification Authority", "org": "Apple Inc." }
          ]
        }
      },
      "security_posture": {
        "pie": true,
        "arc": false,
        "stack_canary": true,
        "pac_enabled": true,
        "has_rwx_segments": false,
        "has_restrict_segment": false,
        "is_encrypted": false,
        "stripped_symbols": false,
        "code_signature": {
          "present": true,
          "is_adhoc": false,
          "hardened_runtime": true,
          "library_validation": false,
          "cdhash": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
          "cdhash_verified": true,
          "identifier": "com.apple.ls",
          "team_id": "Software Signing",
          "certificates": ["Software Signing", "Apple Code Signing Certification Authority", "Apple Root CA"]
        },
        "checks": [
          {
            "id": "pie",
            "title": "Position Independent Executable (MH_PIE)",
            "status": "PASS",
            "value": "Enabled",
            "detail": "ASLR slide enabled via MH_PIE flag (0x200000) in mach_header_64."
          },
          {
            "id": "stack_canary",
            "title": "Stack Smashing Protection",
            "status": "PASS",
            "value": "Present (___stack_chk_guard / ___stack_chk_fail)",
            "detail": "Stack canary symbols found in symbol table."
          },
          {
            "id": "pac",
            "title": "Pointer Authentication (ARM64e PAC)",
            "status": "PASS",
            "value": "ARM64e + Chained Fixups",
            "detail": "Binary uses CPU_SUBTYPE_ARM64E and authenticated pointer fixups."
          },
          {
            "id": "rwx",
            "title": "W^X Memory Protection Hygiene",
            "status": "PASS",
            "value": "No RWX Segments",
            "detail": "No segments have simultaneous Write and Execute permissions."
          },
          {
            "id": "codesign",
            "title": "Code Signature & CDHash Integrity",
            "status": "PASS",
            "value": "Verified (SHA-256)",
            "detail": "LC_CODE_SIGNATURE CodeDirectory hashes match on-disk binary pages."
          }
        ]
      }
    }
  ]
}
```

---

## 6. Parallel Execution & Integration Responsibilities

### 6.1 Systems & Firmware Engineer (`sys_firmware_eng`)
- Implement `backend/` modules (`buffer.py`, `constants.py`, `parser.py`, `elf_parser.py`, `pe_parser.py`, `codesign.py`, `security.py`, `semantics.py`, `pedagogy.py`, `disasm.py`, `service.py`, `fixtures.py`, `server.py`) and `binary_viewer.py` + `tests/test_binary_viewer.py`.
- Generate `fixtures/synthetic_universal` and `fixtures/synthetic_firmware.preload` automatically when `fixtures.ensure_fixtures()` runs (or at server startup / test run).
- Guarantee 100% conformance to the JSON schemas and HTTP endpoints in Sections 3, 4, and 5.

### 6.2 UI/UX & Frontend Architect (`ui_ux_expert`)
- Implement `static/index.html`, `static/styles.css`, and `static/app.js`.
- Consume `/api/presets`, `/api/parse`, `/api/upload`, `/api/hex`, `/api/decode`, `/api/translate`, `/api/disassemble`, and `/api/search`.
- Implement all interactive features specified in [`ui_ux_spec.md`](../../docs/specs/ui_ux_spec.md):
  - Top bar with file picker, path input, one-click presets (`Synthetic Universal`, `Synthetic Firmware`, `/bin/ls`, `/usr/bin/true`), architecture slice switcher, and `Cmd+K` omni-search button.
  - Dual-Track Visual Memory Map Ribbon (File Offset Track + Virtual Memory Track, Compressed/Linear scale toggle, hover tooltips, live cursor playhead, click-to-jump).
  - Real-Time Address / Offset Converter Bar (`File Offset <-> VM Address <-> RVA` + resolved segment/section/symbol pill).
  - Left Sidebar Structure Tree with inline filter and badge counts.
  - Context-Sensitive Center Inspector (Overview & Security Dashboard, Structure Field Table with expandable bitflags & jump links, Virtualized Symbols & Strings tables with C++/Swift demangle toggle & filters, Disassembly view, Code Signature & Entitlements XML/Key-Value tabs, Security & Hardening Scorecard).
  - Synchronized Virtualized Hex & ASCII Pane + Live Byte Data Decoder (`int8..64`, `float32/64`, `ULEB128/SLEB128`, string, ARM64 instruction, and reverse-lookup structural breadcrumbs).
