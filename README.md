# MachOStudio — High-Density Mach-O, Universal Binary & Firmware Inspector

**MachOStudio** (`macho_viewer`) is a zero-dependency macOS reverse-engineering, binary verification, and firmware inspection suite for **Mach-O** (`MH_EXECUTE`, `MH_DYLIB`, `MH_BUNDLE`, `MH_OBJECT`, `MH_KEXT_BUNDLE`, `MH_FILESET`, `MH_PRELOAD`) and **Universal (Fat) 32/64-bit** binaries.

Inspired by **MachOView**, **ImHex**, **Binary Ninja**, and **Xcode Instruments**, MachOStudio combines a byte-accurate Python 3 standard-library binary analysis engine with a high-density desktop-class Web IDE and a scriptable CLI.

> 📖 **Deep Technical Reference:** For a byte-level walkthrough of the Mach-O specification, Universal header disambiguation, `ARM64E` PAC encodings, `LC_DYLD_EXPORTS_TRIE` ULEB128 prefix trees, `LC_DYLD_CHAINED_FIXUPS` pointer chains, `LC_CODE_SIGNATURE` live SHA-256 page verification, and the viewer's $O(\log N)$ interval architecture, see **[`docs/INNER_WORKINGS.md`](./docs/INNER_WORKINGS.md)**.

---

## Key Capabilities & Feature Matrix

| Category | Capabilities |
| :--- | :--- |
| **Binary Formats** | Universal (Fat) 32-bit (`0xCAFEBABE`) & 64-bit (`0xCAFEBABF`) with Java `.class` disambiguation; 32-bit & 64-bit Mach-O (`0xFEEDFACE`, `0xFEEDFACF`); Little-Endian & Big-Endian support; Userland (`MH_EXECUTE`, `MH_DYLIB`, `MH_BUNDLE`, `MH_OBJECT`, `MH_DYLINKER`, `MH_DSYM`) and Kernel/Firmware (`MH_PRELOAD`, `MH_KEXT_BUNDLE`, `MH_FILESET`). |
| **Ground-Truth Byte Tracking** | Every header, load command, segment, section, symbol, and code-signature blob emits exact `abs_offset`, `slice_offset`, `size`, `raw_hex`, and expandable `bit_flags`. Clicking any field highlights its exact bytes in the Hex Viewer; clicking any byte in the Hex Viewer resolves its owning structural hierarchy. |
| **Dual-Track Visual Memory Map** | Synchronized **Physical File Offset** and **Virtual Memory (`VMAddr`)** ribbons with semantic permission color-coding (`R-X` Cyan, `RW-` Amber, `R--` Emerald, `Hdr` Violet, `Sign` Pink), **Square-Root Compressed vs. Linear** scale toggle (preserving legibility alongside 4 GB `__PAGEZERO`), hover tooltips, and a live cursor playhead. |
| **Real-Time Address Translator** | Instant $O(\log N)$ bidirectional conversion between **File Offset** $\leftrightarrow$ **Slice Offset** $\leftrightarrow$ **Virtual Address (`VMAddr`)** $\leftrightarrow$ **RVA**, automatically resolving the enclosing segment, section (`S_ZEROFILL` aware), and nearest symbol (`_main + 0x14`). |
| **Dynamic Linker & PAC Fixups** | Full decoding of `LC_DYLD_CHAINED_FIXUPS` (`DYLD_CHAINED_PTR_ARM64E*`, `DYLD_CHAINED_PTR_64*`, PAC keys `IA`/`IB`/`DA`/`DB`, diversity, `addrDiv`), `LC_DYLD_EXPORTS_TRIE` DAG prefix traversal, `LC_SYMTAB` (`nlist_64` bitfields + C++/Swift demangling), `LC_DYSYMTAB` indirect stub resolution, and `LC_FUNCTION_STARTS`. |
| **Live Code Signature Verifier** | Big-Endian `CS_SuperBlob` (`0xFADE0CC0`) & `CS_CodeDirectory` (`0xFADE0C02`) parser with **live on-disk SHA-256 verification** of the `CDHash`, negative special slots (`-1` Info.plist, `-2` Requirements, `-5` XML Entitlements, `-7` ASN.1 DER Entitlements), and code page slots (`0..N`), plus CMS/PKCS#7 X.509 certificate chain extraction. |
| **9-Point Security Posture Audit** | Automated binary hardening scorecard checking **PIE (ASLR)**, **Stack Canary**, **ARM64e PAC**, **$\text{W}\oplus\text{X}$ (`RWX` segments)**, **Objective-C/Swift ARC**, **`__RESTRICT` / Hardened Runtime (`CS_RUNTIME`)**, **`@rpath` hygiene**, **Code Signature integrity**, and **FairPlay Encryption (`LC_ENCRYPTION_INFO`)**. |
| **On-Demand Disassembly** | Hybrid ARM64 / x86_64 instruction disassembler combining macOS `llvm-objdump` / `otool` with a built-in zero-dependency ARM64 A64 instruction decoder (`paciasp`, `autiasp`, `retaa`, `stp`, `ldp`, `adrp`, `bl`, `b`, `svc`, `mrs`, `msr`) and automatic branch/symbol/string annotations. |
| **Global Omni-Search (`⌘K`)** | Instant spotlight search across `@symbols`, `"strings`, `#load_commands & sections`, and raw `0x` hex byte sequences or virtual addresses. |

---

## Quick Start

MachOStudio uses **100% pure Python 3 Standard Library** on the backend and **Vanilla ES6+ HTML/CSS/JS** on the frontend. **No `pip install`, `npm install`, or virtual environment is required.**

### 1. Launch the Interactive Desktop Web IDE

```bash
cd macho_viewer
python3 macho_viewer.py
```

By default, the server starts on `http://127.0.0.1:8421` (and automatically builds the deterministic synthetic test fixtures in `fixtures/` if not already present).

- **Auto-open in your default browser on launch:**
  ```bash
  python3 macho_viewer.py --open
  ```
- **Launch on a custom port with a specific initial binary pre-loaded:**
  ```bash
  python3 macho_viewer.py --port 8421 --file /bin/ls --open
  ```

### 2. Built-In Sample Presets in the UI
Once the UI is open, click any of the four built-in preset pills in the top toolbar (or drag-and-drop any binary file onto the window):
1. **Synthetic Universal (`fixtures/synthetic_universal`):** Multi-arch (`arm64` + `x86_64`) test binary compiled with custom segments/sections, C++ and Objective-C symbols, chained fixups, and high-risk XML/DER entitlements (`get-task-allow`, `allow-jit`).
2. **Firmware (`MH_PRELOAD`) (`fixtures/synthetic_firmware.preload`):** Standalone ARM64 firmware image featuring an `LC_UNIXTHREAD` (`ARM_THREAD_STATE64`) entry state, raw firmware strings, and an intentional `RWX` segment that triggers the Security Posture Audit warning.
3. **`/bin/ls`:** Real macOS Universal (`arm64e` PAC + `x86_64`) system utility signed by Apple (`Software Signing`) with Hardened Runtime.
4. **`/usr/bin/true`:** Minimal macOS Universal executable ideal for clean structural inspection.

---

## Headless CLI Usage (`--cli`)

MachOStudio includes a full-featured command-line interface for terminal inspection, automated verification, and JSON pipeline integration:

```bash
# 1. Human-readable executive summary of a Universal or Thin Mach-O binary
python3 macho_viewer.py --cli /bin/ls

# 2. Inspect a specific architecture slice (by arch name or slice index)
python3 macho_viewer.py --cli /bin/ls --slice arm64e
python3 macho_viewer.py --cli /bin/ls --slice 0

# 3. Translate a Virtual Memory Address (VMAddr) or File Offset to Segment/Section/Symbol
python3 macho_viewer.py --cli /bin/ls --slice arm64e --translate 0x100003f60

# 4. Disassemble instructions starting at the entry point or a specific VMAddr
python3 macho_viewer.py --cli /bin/ls --slice arm64e --disasm 0x100003f60

# 5. Emit the complete canonical MachODocument JSON schema for scripting / jq
python3 macho_viewer.py --cli /usr/bin/true --json | python3 -m json.tool | head -n 50
```

---

## Keyboard Shortcuts (Web IDE)

| Shortcut | Action |
| :--- | :--- |
| `Cmd + K` or `/` | Open Global Omni-Search Modal (`@symbols`, `"strings`, `#structures`, `0x` hex/addr) |
| `G` | Focus the Real-Time Address / Offset Translator (`File Off ⇄ Slice Off ⇄ VM Addr ⇄ RVA`) |
| `H` | Toggle the Hex Viewer's left column between **File Offset** and **Virtual Memory Address** |
| `[` / `]` | Navigate **Back** / **Forward** in selection and jump history |
| `Esc` | Close active modal (`Cmd+K` search) |

---

## REST API Reference

The local HTTP server (`backend/server.py`) exposes a clean JSON REST API that powers the Web IDE and can be queried directly via `curl` or external scripts:

| Method & Endpoint | Query / Body Parameters | Description |
| :--- | :--- | :--- |
| `GET /api/presets` | *(none)* | Lists built-in sample binaries (`synthetic_universal`, `synthetic_firmware`, `/bin/ls`, `/usr/bin/true`) and their on-disk availability. |
| `GET /api/parse` | `?path=/bin/ls` | Parses a local file on disk, sets it as active, and returns the full `MachODocument` JSON. |
| `POST /api/parse` | `{"path": "/bin/ls"}` | Same as `GET /api/parse` via JSON POST body. |
| `POST /api/upload` | Raw binary (`application/octet-stream` + `X-Filename` header) or JSON `{"filename", "data_base64"}` | Parses an uploaded or drag-and-dropped binary buffer and returns the `MachODocument` JSON. |
| `GET /api/hex` | `?offset=16384&length=4096&slice_index=0` | Returns windowed 16-byte hex/ASCII rows and overlapping structural `ByteRegion` annotations for the virtualized Hex Viewer. |
| `GET /api/decode` | `?offset=16384&slice_index=0&endian=little` | Decodes 1–16 bytes at `offset` into `int8..64`, `uint8..64`, `float32/64`, `ULEB128`, `SLEB128`, C-string, ARM64 instruction, and structural ownership breadcrumbs. |
| `GET /api/translate` | `?query=0x100003f60&slice_index=0&mode=auto` | Bidirectional $O(\log N)$ translator between `vmaddr`, `rva`, `slice_offset`, and `abs_offset`, returning the enclosing segment, section, and nearest symbol. |
| `GET /api/disassemble` | `?slice_index=0&vmaddr=0x100003f60&count=200` | Disassembles instructions in an executable section with resolved branch targets, stub symbols, and C-string literal comments. |
| `GET /api/search` | `?q=main&slice_index=0&scope=all` | Searches across symbols, strings, load commands/sections, or raw hex byte sequences (`scope`: `all`, `symbols`, `strings`, `structures`, `hex`). |

---

## Project Architecture & Directory Layout

```text

├── macho_viewer.py                 # Unified CLI inspector & ThreadingHTTPServer launcher
├── README.md                       # Project guide, quick start, CLI & REST API reference
├── backend/
│   ├── __init__.py
│   ├── buffer.py                   # Layer 1: BinaryBuffer (bounds-checked cursor, ULEB128/SLEB128, StructField emitter)
│   ├── constants.py                # Mach-O magics, CPU/PAC subtypes, LC_* names, VM_PROT, nlist, Chained Fixup & CS_* constants
│   ├── parser.py                   # Layer 2: MachOParser (Fat 32/64, Headers, Load Commands, Symtab, Exports Trie, Chained Fixups)
│   ├── codesign.py                 # Big-Endian CS_SuperBlob, CodeDirectory live SHA-256 verifier, XML/DER Entitlements, CMS parser
│   ├── security.py                 # 9-point automated Security Posture & Hardening Audit engine
│   ├── disasm.py                   # Layer 3: Hybrid llvm-objdump + native ARM64 A64 decoder & symbol/string cross-referencer
│   ├── service.py                  # AnalysisService: document cache, hex slicing, O(log N) address translator, omni-search
│   ├── fixtures.py                 # Deterministic generator for synthetic_universal & synthetic_firmware.preload
│   └── server.py                   # Zero-dependency ThreadingHTTPServer REST API router & static file server
├── static/
│   ├── index.html                  # Desktop Web IDE shell (Toolbar, Dual Memory Map, Translator, 3-Pane Split, Cmd+K Modal)
│   ├── styles.css                  # High-contrast dark theme (#0D1117), semantic memory colors, tabular monospace layout
│   └── app.js                      # Reactive state store, SVG/DOM Memory Map, Virtualized Hex/Symbol grids, Live Byte Decoder
├── fixtures/                       # Auto-generated synthetic test binaries & entitlements
│   ├── entitlements.plist
│   ├── synthetic_universal
│   └── synthetic_firmware.preload
├── tests/
│   └── test_macho_viewer.py        # Automated unit & integration verification suite
└── docs/
    ├── INNER_WORKINGS.md           # Deep technical guide to Mach-O internals & viewer architecture
    └── specs/
        ├── systems_firmware_spec.md
        ├── ui_ux_spec.md
        └── cto_architecture_decision.md
```

---

## Verification & Automated Test Suite

The automated test suite in [`tests/test_macho_viewer.py`](./tests/test_macho_viewer.py) executes 10 comprehensive end-to-end verification tests covering synthetic fixtures, real Apple system binaries, ground-truth cross-validation against `/usr/bin/otool` and `/usr/bin/codesign`, negative/malformed binary handling, HTTP REST endpoints, and CLI modes:

```bash
python3 -m unittest discover -s tests -v
```

| Test Case | Verification Scope |
| :--- | :--- |
| [`test_01_fixtures_built`](./tests/test_macho_viewer.py#L42-L46) | Builds deterministic `fixtures/synthetic_universal` (`arm64` + `x86_64`) and `fixtures/synthetic_firmware.preload` (`MH_PRELOAD`) via [`ensure_fixtures`](./backend/fixtures.py#L470-L483). |
| [`test_02_parse_synthetic_universal`](./tests/test_macho_viewer.py#L48-L100) | Verifies Universal Fat header, custom segments/sections (`__TEXT,__custom_code`, `__RODATA,__firmware_cfg`), C++ demangling, `@rpath`, XML/DER entitlements, and SHA-256 `CDHash` verification. |
| [`test_03_parse_synthetic_firmware_preload`](./tests/test_macho_viewer.py#L102-L137) | Verifies standalone `MH_PRELOAD` firmware parsing, `LC_UNIXTHREAD` (`ARM_THREAD_STATE64`) register extraction (`sp`, `pc`), `RWX` segment security failure detection, and ARM64 disassembly with inline `ADRP+ADD` string cross-referencing. |
| [`test_04_parse_real_system_binaries`](./tests/test_macho_viewer.py#L139-L157) | Verifies `/bin/ls` and `/usr/bin/true` Universal `arm64e` + `x86_64` slices, `LC_DYLD_CHAINED_FIXUPS`, CMS certificate chains, and live page hash verification. |
| [`test_05_translate_hex_decode_search`](./tests/test_macho_viewer.py#L159-L182) | Verifies $O(\log N)$ `VMAddr <-> File Offset` translation ([`translate_address`](./backend/service.py#L112-L263)), `S_ZEROFILL` (`__bss`) detection, live multi-format byte decoding ([`decode_bytes_at`](./backend/service.py#L339-L452)), and omni-search ([`search`](./backend/service.py#L519-L650)). |
| [`test_06_http_api_endpoints`](./tests/test_macho_viewer.py#L184-L258) | Spins up `ThreadingHTTPServer` ([`create_server`](./backend/server.py#L237-L263)) and exercises `/api/presets`, `/api/parse`, `/api/hex`, `/api/decode`, `/api/translate`, `/api/disassemble`, `/api/search`, and `/api/upload`. |
| [`test_07_cli_modes`](./tests/test_macho_viewer.py#L260-L270) | Verifies `python3 macho_viewer.py --cli` executive report and disassembly output. |
| [`test_08_cross_validate_against_otool_and_codesign`](./tests/test_macho_viewer.py#L272-L361) | Cross-validates parsed `cputype`, `filetype`, `ncmds`, `sizeofcmds`, `flags`, `LC_UUID`, every `LC_SEGMENT_64` (`vmaddr`, `vmsize`, `fileoff`, `filesize`), `CDHash`, and `Identifier` against macOS `/usr/bin/otool -hl` and `/usr/bin/codesign -dvvv`. |
| [`test_09_java_class_disambiguation_and_malformed_inputs`](./tests/test_macho_viewer.py#L363-L398) | Verifies rejection of Java `.class` files (`0xCAFEBABE` with class version `55 > 32`) and graceful handling of truncated/out-of-bounds Mach-O buffers. |
| [`test_10_32bit_and_big_endian_macho_parsing`](./tests/test_macho_viewer.py#L400-L492) | Verifies 32-bit Little-Endian (`MH_MAGIC` ARMv7 with `LC_SEGMENT` and 12-byte `nlist`) and 32-bit Big-Endian (`MH_CIGAM` PowerPC) Mach-O parsing. |
