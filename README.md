# MachOStudio — Multi-Format Binary Inspector, Semantic Intelligence & Systems Learning Suite (`Mach-O` • `ELF32/64` • `Windows PE32/PE32+`)

**MachOStudio** (`macho_viewer`) is a zero-dependency cross-platform reverse-engineering, binary security verification, semantic intelligence, and interactive systems pedagogy suite supporting:
1. **Apple Mach-O & Universal (Fat) 32/64-bit Binaries:** Userland (`MH_EXECUTE`, `MH_DYLIB`, `MH_BUNDLE`, `MH_OBJECT`, `MH_DYLINKER`, `MH_DSYM`) and Kernel/Firmware (`MH_PRELOAD`, `MH_KEXT_BUNDLE`, `MH_FILESET`), with live SHA-256 `LC_CODE_SIGNATURE` verification and `ARM64E` PAC Chained Fixups.
2. **Linux / SVR4 ELF32 & ELF64 Binaries:** `ET_EXEC`, `ET_DYN` (PIE & `.so`), `ET_REL`, `ET_CORE`, Program Headers (`PT_LOAD`, `PT_DYNAMIC`, `PT_INTERP`, `PT_NOTE`, `PT_GNU_STACK`, `PT_GNU_RELRO`), Section Headers, `.dynamic` tags, PLT/GOT relocations, and GNU Notes (`Build-ID`, `ABI-tag`, Intel CET `IBT/SHSTK`, ARM64 `PAC/BTI`).
3. **Windows PE32 (32-bit) & PE32+ (64-bit) Binaries:** `.exe`, `.dll`, `.sys` kernel drivers, MS-DOS stub, XOR-decrypted **Rich Header** (`DanS`/`Rich` `@comp.id` toolchain fingerprint), COFF & Optional Headers, 16 Data Directories, Import Lookup/Address Tables (`ILT`/`IAT`), Export Directory + Forwarders, Base Relocations (`.reloc`), CodeView `RSDS` PDB GUID/path, TLS Callbacks, Load Config (`/GS` cookie & `GUARD_CF`), and `WIN_CERTIFICATE` Authenticode PKCS#7 signatures.

Inspired by **MachOView**, **ImHex**, **DIE (Detect It Easy)**, **PE-bear**, **Binary Ninja**, and **Godbolt Compiler Explorer**, MachOStudio pairs a 100% Python 3 standard-library analysis engine with a desktop-class Web IDE and a scriptable CLI.

> 📖 **Deep Technical References:**
> - **[`docs/INNER_WORKINGS.md`](./docs/INNER_WORKINGS.md):** Byte-level specification and architectural walkthrough of Mach-O, ELF32/64, Windows PE32/PE32+, the 4 Semantic Intelligence layers, and the Interactive Pedagogy engine.
> - **[`docs/WEB_HOSTING_AND_MONETIZATION.md`](./docs/WEB_HOSTING_AND_MONETIZATION.md):** Production architecture blueprint for zero-trust WebAssembly/microVM cloud hosting, viral shareable permalinks, and freemium/B2B SaaS monetization (planned for the next sprint).

---

## Key Capabilities & Feature Matrix

| Category | Capabilities |
| :--- | :--- |
| **Multi-Format Support** | **Mach-O** (Universal Fat 32/64 with Java `.class` disambiguation, Thin 32/64, Little/Big-Endian, `MH_PRELOAD` firmware); **ELF** (`ELF32` & `ELF64`, LSB/MSB, `x86_64`, `i386`, `AArch64`, `ARM`, `RISC-V`); **Windows PE** (`PE32` & `PE32+`, `x86_64`, `i386`, `ARM64`). |
| **Ground-Truth Byte Tracking** | Every header, load command, program header, data directory, segment, section, symbol, and signature blob emits exact `abs_offset`, `slice_offset`, `size`, `raw_hex`, and expandable `bit_flags`. Clicking any field highlights its exact bytes in the Hex Viewer; clicking any byte in the Hex Viewer resolves its owning structural hierarchy. |
| **Semantic Intelligence Layers** | **1. Shannon Entropy & Byte Class Heatmap:** Per-section and 96-window sliding entropy sparkline ($0.0\text{–}8.0$ bits/byte) + 4-bucket byte distribution (Null, ASCII, Control, High-Bit) to spot packed/encrypted payloads.<br/>**2. Behavioral Capability Taxonomy:** Maps imported APIs, symbols, and strings into Process/Thread, Virtual Memory/Injection, File I/O, Network, Crypto, Dynamic Loading, Anti-Analysis, and IPC/System capabilities with 1-click evidence chips.<br/>**3. Toolchain & Build Provenance:** Extracts compiler/linker versions, PE XOR-decrypted Rich Header `@comp.id` objects, ELF `.comment` & `Build-ID`, CodeView `RSDS` PDB paths, and source languages.<br/>**4. Structural Anomaly Forensics:** Detects `RWX` violations, high-entropy code sections, pre-main PE TLS callbacks, and unusual entry points. |
| **Interactive Pedagogy & Learning** | **1. 6-Stage OS Loader Lifecycle Simulator:** Step-by-step interactive walkthrough of how **macOS XNU + `dyld`**, **Linux `binfmt_elf.c` + `ld-linux.so`**, or **Windows NT Kernel + `ntdll.dll`** maps and launches the active binary.<br/>**2. Cross-Format "Rosetta Stone" Matrix:** 10-row side-by-side structural comparison (`Mach-O ⇄ ELF ⇄ PE`) with live jump buttons into the active binary.<br/>**3. Contextual Field Deep-Dives:** Inline callouts on struct fields explaining *"Why This Field Matters"*, *"OS Loader Behavior"*, *"What Breaks If Patched"*, and *"Cross-Format Peer"*.<br/>**4. Guided Learning Tours & Micro-Challenges:** 3 interactive tracks with live hex/inspector synchronization and multiple-choice verification quizzes. |
| **Dual-Track Visual Memory Map** | Synchronized **Physical File Offset** and **Virtual Memory (`VMAddr`)** ribbons with semantic permission color-coding (`R-X` Cyan, `RW-` Amber, `R--` Emerald, `Hdr` Violet, `Sign` Pink), **Square-Root Compressed vs. Linear** scale toggle, hover tooltips, and a live cursor playhead. |
| **Real-Time Address Translator** | Instant $O(\log N)$ bidirectional conversion between **File Offset** $\leftrightarrow$ **Slice Offset** $\leftrightarrow$ **Virtual Address (`VMAddr`)** $\leftrightarrow$ **RVA**, automatically resolving the enclosing segment, section (`S_ZEROFILL` / `SHT_NOBITS` / `.bss` aware), and nearest symbol. |
| **9-Point Format-Aware Security Audit** | Automated binary hardening scorecard tailored to each format: **Mach-O** (`MH_PIE`, Canary, ARM64e PAC, $\text{W}\oplus\text{X}$, ARC, `__RESTRICT`/`CS_RUNTIME`, `@rpath`, `CDHash`, Encryption); **ELF** (`PIE`, `Full/Partial RELRO`, `PT_GNU_STACK` NX, Canary, Intel CET `IBT/SHSTK` & ARM64 `PAC/BTI`, $\text{W}\oplus\text{X}$ / `DT_TEXTREL`, `_FORTIFY_SOURCE`, `RPATH/RUNPATH`, `Build-ID`); **Windows PE** (`DYNAMIC_BASE` ASLR, `HIGH_ENTROPY_VA`, `NX_COMPAT` DEP, `GUARD_CF` CFG, `SafeSEH`/`.pdata`, `/GS` SecurityCookie, $\text{W}\oplus\text{X}$, `FORCE_INTEGRITY`/TLS Callbacks, Authenticode `WIN_CERTIFICATE`). |
| **Pure-Python ARM64 & x86/x86_64 Disassembler** | Hybrid disassembler combining system `llvm-objdump` / `objdump` / `otool` with built-in zero-dependency **ARM64 A64** (`paciasp`, `autiasp`, `retaa`, `adrp`, `bl`, `svc`) and **x86 / x86_64** (`endbr64`, `push`, `mov`, `lea`, `call`, `jmp`, `syscall`, `ret`) decoders and automatic RIP/PC-relative symbol & string cross-referencing. |

---

## Quick Start

MachOStudio uses **100% pure Python 3 Standard Library** on the backend and **Vanilla ES6+ HTML/CSS/JS** on the frontend. **No `pip install`, `npm install`, or virtual environment is required.**

### 1. Launch the Interactive Desktop Web IDE

```bash
cd macho_viewer
python3 macho_viewer.py
```

By default, the server starts on `http://127.0.0.1:8421` and automatically builds all 6 deterministic synthetic test fixtures in `fixtures/` (`synthetic_universal`, `synthetic_firmware.preload`, `synthetic_elf64`, `synthetic_elf32`, `synthetic_pe64.exe`, `synthetic_pe32.exe`).

- **Auto-open in your default browser on launch:**
  ```bash
  python3 macho_viewer.py --open
  ```
- **Launch on a custom port with a specific Mach-O, ELF, or PE binary pre-loaded:**
  ```bash
  python3 macho_viewer.py --port 8421 --file fixtures/synthetic_pe64.exe --open
  ```

### 2. Built-In Sample Presets in the UI
Click any of the built-in preset pills in the top toolbar (or drag-and-drop any Mach-O, ELF, or Windows PE binary onto the window):
1. **Universal Mach-O (`fixtures/synthetic_universal`):** Multi-arch (`arm64` + `x86_64`) Mach-O with custom segments, C++/ObjC symbols, chained fixups, and XML/DER entitlements (`get-task-allow`, `allow-jit`).
2. **Firmware (`MH_PRELOAD`) (`fixtures/synthetic_firmware.preload`):** Standalone ARM64 firmware image with `LC_UNIXTHREAD` registers, firmware strings, and an intentional `RWX` segment.
3. **Linux ELF64 (PIE + CET) (`fixtures/synthetic_elf64`):** 64-bit `x86_64` `ET_DYN` PIE executable with Full RELRO (`PT_GNU_RELRO` + `DF_BIND_NOW`), NX stack, Intel CET (`IBT | SHSTK`), GNU `Build-ID`, PLT/GOT relocations, and C++/C symbols.
4. **Linux ELF32 (Legacy) (`fixtures/synthetic_elf32`):** 32-bit `i386` `ET_EXEC` binary with an executable stack (`PT_GNU_STACK` `RWE`) that triggers security posture warnings.
5. **Windows PE32+ (Signed) (`fixtures/synthetic_pe64.exe`):** 64-bit `x86_64` Windows executable with XOR-encoded Rich Header, ASLR (`HIGH_ENTROPY_VA`), DEP, Control Flow Guard (`GUARD_CF`), `/GS` cookie, `KERNEL32.dll`/`WS2_32.dll` imports, forwarded exports, CodeView `RSDS` PDB path, and `WIN_CERTIFICATE` Authenticode signature.
6. **Windows PE32 (TLS + RWX) (`fixtures/synthetic_pe32.exe`):** 32-bit `i386` Windows executable containing a pre-main `IMAGE_DIRECTORY_ENTRY_TLS` callback and an `RWX` section (`.rwxcode`) to demonstrate anomaly forensics.
7. **`/bin/ls` & `/usr/bin/true`:** Real host system binaries (Universal Mach-O on macOS or ELF64 on Linux).

---

## Headless CLI Usage (`--cli`)

MachOStudio includes a full-featured command-line interface for terminal inspection across Mach-O, ELF, and PE files:

```bash
# 1. Human-readable executive summary (Overview, Segments, Security Scorecard, Entropy, Capabilities & Anomalies)
python3 macho_viewer.py --cli fixtures/synthetic_pe64.exe
python3 macho_viewer.py --cli fixtures/synthetic_elf64
python3 macho_viewer.py --cli fixtures/synthetic_universal

# 2. Translate a Virtual Memory Address (VMAddr) or File Offset to Segment/Section/Symbol
python3 macho_viewer.py --cli fixtures/synthetic_pe64.exe --translate 0x140001000

# 3. Disassemble ARM64 or x86/x86_64 instructions at the entry point or a specific VMAddr
python3 macho_viewer.py --cli fixtures/synthetic_elf64 --disasm 0x1040

# 4. Emit the complete canonical Document JSON schema (including semantic_layers & pedagogy)
python3 macho_viewer.py --cli fixtures/synthetic_pe64.exe --json | python3 -m json.tool | head -n 50
```

---

## Project Architecture & Directory Layout

```text
├── macho_viewer.py                 # Unified CLI inspector & ThreadingHTTPServer launcher
├── README.md                       # Project guide, quick start, CLI & REST API reference
├── backend/
│   ├── __init__.py
│   ├── buffer.py                   # Layer 1: BinaryBuffer (bounds-checked cursor, ULEB128/SLEB128, StructField emitter)
│   ├── constants.py                # Mach-O magics, CPU/PAC subtypes, LC_* names, VM_PROT, Chained Fixup & CS_* constants
│   ├── parser.py                   # Layer 2A: Multi-format dispatcher & Mach-O / Universal Fat 32/64 parser
│   ├── elf_parser.py               # Layer 2B: ELF32/ELF64 parser (Ehdr, Phdr, Shdr, .dynamic, Notes, Relocs) & 9-point ELF audit
│   ├── pe_parser.py                # Layer 2C: Windows PE32/PE32+ parser (DOS, Rich, NT/Optional, DataDirs, IAT, Exports, PDB, TLS, Authenticode) & 9-point PE audit
│   ├── codesign.py                 # Big-Endian CS_SuperBlob, CodeDirectory live SHA-256 verifier, XML/DER Entitlements, CMS/PKCS#7 X.509 parser
│   ├── security.py                 # 9-point Mach-O Security Posture & Hardening Audit engine
│   ├── disasm.py                   # Layer 3: Hybrid llvm-objdump/objdump + pure-Python ARM64 & x86/x86_64 decoders
│   ├── semantics.py                # Layer 4A: Shannon Entropy, Byte Class Distribution, Behavioral Capability Taxonomy, Provenance & Anomaly Forensics
│   ├── pedagogy.py                 # Layer 4B: 6-Stage OS Loader Simulator, 10-Row Rosetta Stone Matrix, Field Deep-Dives & Guided Learning Tours
│   ├── service.py                  # AnalysisService: document cache, hex slicing, O(log N) address translator, omni-search
│   ├── fixtures.py                 # Deterministic generator for all 6 synthetic Mach-O, ELF32/64, and PE32/PE32+ binaries
│   └── server.py                   # Zero-dependency ThreadingHTTPServer REST API router & static file server
├── static/
│   ├── index.html                  # Desktop Web IDE shell (Toolbar, Format Badge, Learn Button, Dual Memory Map, 3-Pane Split)
│   ├── styles.css                  # High-contrast dark theme (#0D1117), semantic memory colors, entropy sparklines & tour cards
│   └── app.js                      # Format-adaptive tree, Semantic/Entropy Inspector, OS Loader Simulator, Rosetta Matrix & Guided Tours
├── fixtures/                       # Auto-generated synthetic test binaries (Mach-O, ELF32/64, PE32/PE32+)
├── tests/
│   └── test_macho_viewer.py        # 15 end-to-end automated unit & integration verification tests
└── docs/
    ├── INNER_WORKINGS.md           # Deep technical guide to Mach-O, ELF, PE, Semantic Layers & Pedagogy
    ├── WEB_HOSTING_AND_MONETIZATION.md # Cloud sandboxing, WebAssembly architecture & SaaS monetization blueprint
    └── specs/
        ├── systems_firmware_spec.md
        ├── ui_ux_spec.md
        └── cto_architecture_decision.md
```

---

## Verification & Automated Test Suite

Run all 15 end-to-end verification tests in [`tests/test_macho_viewer.py`](./tests/test_macho_viewer.py):

```bash
python3 -m unittest discover -s tests -v
```

| Test Case | Verification Scope |
| :--- | :--- |
| [`test_01_fixtures_built`](./tests/test_macho_viewer.py#L46-L52) | Builds all 6 deterministic Mach-O, ELF32/64, and PE32/PE32+ fixtures via [`ensure_fixtures`](./backend/fixtures.py#L1217-L1242). |
| [`test_02_parse_synthetic_universal`](./tests/test_macho_viewer.py#L54-L106) | Verifies Universal Fat header, custom segments/sections, C++ demangling, `@rpath`, XML/DER entitlements, and SHA-256 `CDHash` verification. |
| [`test_03_parse_synthetic_firmware_preload`](./tests/test_macho_viewer.py#L108-L143) | Verifies standalone `MH_PRELOAD` firmware parsing, `LC_UNIXTHREAD` registers, `RWX` detection, and ARM64 disassembly. |
| [`test_04_parse_real_system_binaries`](./tests/test_macho_viewer.py#L145-L174) | Verifies host `/bin/ls` and `/usr/bin/true` binaries across macOS (Universal Mach-O) and Linux (ELF64). |
| [`test_05_translate_hex_decode_search`](./tests/test_macho_viewer.py#L175-L199) | Verifies $O(\log N)$ `VMAddr <-> File Offset` translation, `S_ZEROFILL` detection, live byte decoding, and omni-search. |
| [`test_06_http_api_endpoints`](./tests/test_macho_viewer.py#L200-L274) | Spins up `ThreadingHTTPServer` and exercises `/api/presets`, `/api/parse`, `/api/hex`, `/api/decode`, `/api/translate`, `/api/disassemble`, `/api/search`, and `/api/upload`. |
| [`test_07_cli_modes`](./tests/test_macho_viewer.py#L276-L286) | Verifies `python3 macho_viewer.py --cli` executive report (including Semantic & Anomaly summary) and disassembly output. |
| [`test_08_cross_validate_against_otool_and_codesign`](./tests/test_macho_viewer.py#L288-L389) | Cross-validates Mach-O headers, segments, and `CDHash` against macOS `/usr/bin/otool` and `/usr/bin/codesign`. |
| [`test_09_java_class_disambiguation_and_malformed_inputs`](./tests/test_macho_viewer.py#L390-L426) | Verifies rejection of Java `.class` files (`0xCAFEBABE`) and graceful handling of truncated/malformed buffers. |
| [`test_10_32bit_and_big_endian_macho_parsing`](./tests/test_macho_viewer.py#L427-L518) | Verifies 32-bit Little-Endian (`MH_MAGIC` ARMv7) and 32-bit Big-Endian (`MH_CIGAM` PowerPC) Mach-O parsing. |
| [`test_11_parse_synthetic_elf64_and_elf32`](./tests/test_macho_viewer.py#L519-L581) | Verifies ELF64 & ELF32 parsing, Program/Section headers, `.dynamic`, GNU Notes (`Build-ID`, `ABI-tag`, Intel CET `IBT/SHSTK`), PLT/GOT relocations, x86_64 disassembly, and 9-point ELF security posture. |
| [`test_12_parse_synthetic_pe64_and_pe32`](./tests/test_macho_viewer.py#L582-L645) | Verifies PE32+ & PE32 parsing, XOR-decrypted Rich Header, Data Directories, Imports (name & ordinal), Exports + Forwarders, `.reloc`, CodeView `RSDS` PDB, `/GS` cookie, `WIN_CERTIFICATE` Authenticode, and TLS/RWX audit. |
| [`test_13_semantic_layers_and_entropy_intelligence`](./tests/test_macho_viewer.py#L646-L683) | Verifies Shannon entropy & 4-bucket byte distribution, Behavioral Capability Taxonomy, Toolchain Provenance, and Structural Anomaly Forensics (`rwx_memory`, `pe_tls_callbacks`). |
| [`test_14_pedagogy_loader_lifecycle_rosetta_and_tours`](./tests/test_macho_viewer.py#L684-L729) | Verifies the 6-Stage OS Loader Lifecycle Simulator, 10-Row Rosetta Stone Matrix, Header Field Pedagogy Annotations, and Guided Learning Tours with Micro-Challenges across Mach-O, ELF, and PE. |
| [`test_15_cross_validate_elf_against_readelf_and_multi_format_api`](./tests/test_macho_viewer.py#L730-L769) | Cross-validates ELF64 against `/usr/bin/readelf` (when on Linux) and tests `/api/decode` field pedagogy and `/api/translate` on ELF64 and PE32+. |
