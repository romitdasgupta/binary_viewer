"""
Layer 4A: Multi-Format Semantic Intelligence Engine (Mach-O, ELF32/64, Windows PE32/PE32+).
Provides:
1. Shannon Entropy & 4-Bucket Byte Distribution Heatmap (`entropy_analysis`)
2. 8-Category Behavioral Capability & API Taxonomy (`capabilities`)
3. Compiler, Toolchain & ABI Provenance Fingerprint (`provenance`)
4. Structural Anomaly & Heuristic Forensics (`anomalies`)
"""

import math
import re
from typing import Any, Dict, List, Tuple


def compute_entropy_and_classes(data: bytes) -> Dict[str, Any]:
    """
    Computes Shannon entropy H in [0.0, 8.0] bits/byte and 4-bucket byte distribution
    in a single pass over `data`.
    """
    n = len(data)
    if n == 0:
        return {
            "entropy": 0.0,
            "null_pct": 100.0,
            "ascii_pct": 0.0,
            "control_pct": 0.0,
            "high_pct": 0.0,
        }

    # Sample up to 256 KB if very large to keep latency < 5ms
    if n > 262144:
        step = max(1, n // 131072)
        sample = data[::step]
    else:
        sample = data

    total = len(sample)
    counts = [0] * 256
    for b in sample:
        counts[b] += 1

    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)

    null_cnt = counts[0]
    ascii_cnt = sum(counts[0x20:0x7F]) + counts[0x09] + counts[0x0A] + counts[0x0D]
    high_cnt = sum(counts[0x80:0x100])
    ctrl_cnt = max(0, total - null_cnt - ascii_cnt - high_cnt)

    return {
        "entropy": round(entropy, 2),
        "null_pct": round((null_cnt / total) * 100.0, 1),
        "ascii_pct": round((ascii_cnt / total) * 100.0, 1),
        "control_pct": round((ctrl_cnt / total) * 100.0, 1),
        "high_pct": round((high_cnt / total) * 100.0, 1),
    }


def classify_region_semantics(
    entropy: float,
    null_pct: float,
    ascii_pct: float,
    is_executable: bool,
    is_zerofill: bool,
    size: int,
) -> Tuple[str, str, str]:
    """
    Returns (classification_label, badge_color_class, explanation).
    """
    if is_zerofill or size == 0 or entropy < 1.0 or null_pct >= 75.0:
        return (
            "Sparse / Zero-Padded",
            "badge-slate",
            "Region is predominantly null bytes or uninitialized zero-fill (.bss) memory.",
        )
    if entropy >= 7.15:
        return (
            "Compressed / Packed / Encrypted",
            "badge-danger",
            "High randomness (>= 7.15 bits/byte) typical of compressed streams, packed stubs, or cryptographic material.",
        )
    if entropy > 6.80:
        return (
            "High-Density / Possible Packing",
            "badge-amber",
            "Elevated entropy (6.80 - 7.15 bits/byte); dense machine code, lookup tables, or compressed blobs.",
        )
    if ascii_pct >= 58.0 and entropy < 5.9:
        return (
            "Plaintext / Strings / Metadata",
            "badge-emerald",
            "High concentration of printable ASCII characters (C-strings, XML/plist manifests, or symbol names).",
        )
    if is_executable:
        return (
            "Compiled Native Code",
            "badge-cyan",
            "Standard instruction stream entropy (4.2 - 6.8 bits/byte) for compiled native machine code.",
        )
    return (
        "Structured Binary Data",
        "badge-purple",
        "Structured headers, pointer tables, relocations, or initialized program constants.",
    )


def build_entropy_analysis(slice_doc: Dict[str, Any], raw_slice_bytes: bytes) -> Dict[str, Any]:
    slice_base = slice_doc.get("slice_base_offset", 0)
    slice_len = len(raw_slice_bytes)
    overall = compute_entropy_and_classes(raw_slice_bytes)

    # Compute per-section entropy & attach to section objects as well
    section_profiles: List[Dict[str, Any]] = []
    for seg in slice_doc.get("segments", []):
        for sect in seg.get("sections", []):
            is_zf = bool(sect.get("is_zerofill"))
            s_off = sect.get("slice_offset", 0)
            s_sz = sect.get("raw_size", sect.get("size", 0))
            if is_zf or s_sz <= 0 or s_off < 0 or s_off >= slice_len:
                stats = {
                    "entropy": 0.0,
                    "null_pct": 100.0,
                    "ascii_pct": 0.0,
                    "control_pct": 0.0,
                    "high_pct": 0.0,
                }
            else:
                chunk = raw_slice_bytes[s_off : min(slice_len, s_off + s_sz)]
                stats = compute_entropy_and_classes(chunk)

            label, badge_cls, reason = classify_region_semantics(
                entropy=stats["entropy"],
                null_pct=stats["null_pct"],
                ascii_pct=stats["ascii_pct"],
                is_executable=bool(sect.get("is_executable")),
                is_zerofill=is_zf,
                size=s_sz,
            )
            sect["entropy"] = stats["entropy"]
            sect["semantic_class"] = label
            sect["semantic_badge"] = badge_cls

            section_profiles.append({
                "name": f"{sect.get('segname', '')},{sect.get('sectname', '')}".strip(","),
                "segname": sect.get("segname", ""),
                "sectname": sect.get("sectname", ""),
                "vmaddr": sect.get("vmaddr", "0x0"),
                "abs_offset": sect.get("abs_offset", slice_base + s_off),
                "size": sect.get("size", 0),
                "prot": sect.get("prot", seg.get("initprot", "---")),
                "is_executable": bool(sect.get("is_executable")),
                "is_zerofill": is_zf,
                "entropy": stats["entropy"],
                "null_pct": stats["null_pct"],
                "ascii_pct": stats["ascii_pct"],
                "control_pct": stats["control_pct"],
                "high_pct": stats["high_pct"],
                "byte_classes": stats,
                "classification": label,
                "badge_class": badge_cls,
                "explanation": reason,
            })

    # Compute 96-window sliding sparkline across the slice
    windows: List[Dict[str, Any]] = []
    if slice_len > 0:
        num_wins = min(96, max(8, slice_len // 128))
        win_sz = max(16, slice_len // num_wins)
        for i in range(num_wins):
            w_start = i * win_sz
            if w_start >= slice_len:
                break
            w_end = slice_len if i == num_wins - 1 else min(slice_len, w_start + win_sz)
            w_chunk = raw_slice_bytes[w_start:w_end]
            w_stats = compute_entropy_and_classes(w_chunk)
            dom = "structured"
            if w_stats["null_pct"] >= 70.0:
                dom = "null"
            elif w_stats["entropy"] >= 7.0:
                dom = "packed"
            elif w_stats["ascii_pct"] >= 55.0:
                dom = "ascii"
            elif w_stats["entropy"] >= 4.5:
                dom = "code"
            windows.append({
                "index": i,
                "abs_offset": slice_base + w_start,
                "slice_offset": w_start,
                "size": w_end - w_start,
                "entropy": w_stats["entropy"],
                "dominant_class": dom,
                "null_pct": w_stats["null_pct"],
                "ascii_pct": w_stats["ascii_pct"],
                "high_pct": w_stats["high_pct"],
            })

    ov_label, ov_badge, ov_reason = classify_region_semantics(
        entropy=overall["entropy"],
        null_pct=overall["null_pct"],
        ascii_pct=overall["ascii_pct"],
        is_executable=True,
        is_zerofill=False,
        size=slice_len,
    )

    byte_dist = {
        "null_pct": overall["null_pct"],
        "ascii_pct": overall["ascii_pct"],
        "control_pct": overall["control_pct"],
        "high_pct": overall["high_pct"],
    }
    max_win_ent = max((w["entropy"] for w in windows), default=overall["entropy"])

    return {
        "overall_entropy": overall["entropy"],
        "max_window_entropy": max_win_ent,
        "overall_classification": ov_label,
        "overall_badge": ov_badge,
        "overall_explanation": ov_reason,
        "packing_assessment": ov_reason,
        "byte_distribution": byte_dist,
        "byte_class_distribution": byte_dist,
        "sections": section_profiles,
        "section_metrics": section_profiles,
        "windows": windows,
        "sliding_windows": windows,
    }


CAPABILITY_RULES = [
    {
        "id": "process",
        "title": "Process & Thread Execution",
        "icon": "EXEC",
        "badge_class": "badge-amber",
        "summary": "Spawns child processes, executes shell commands, or manages execution threads.",
        "keywords": (
            "posix_spawn", "fork", "vfork", "execve", "execvp", "execl", "system", "popen",
            "pthread_create", "nstask", "createprocess", "shellexecute", "winexec",
            "createthread", "createremotethread", "ntcreatethread", "exitprocess",
            "getcurrentprocess",
        ),
    },
    {
        "id": "memory_injection",
        "title": "Virtual Memory & Code Loading",
        "icon": "MEM",
        "badge_class": "badge-danger",
        "summary": "Allocates virtual memory pages, alters page protections (W^X / JIT), or accesses process memory.",
        "keywords": (
            "mmap", "mprotect", "mremap", "mach_vm_allocate", "mach_vm_protect", "mach_vm_write",
            "task_for_pid", "virtualalloc", "virtualprotect", "writeprocessmemory",
            "readprocessmemory", "mapviewoffile", "ntmapviewofsection", "rtlallocateheap",
            "allow-jit",
        ),
    },
    {
        "id": "filesystem",
        "title": "File System & Stream I/O",
        "icon": "FILE",
        "badge_class": "badge-cyan",
        "summary": "Opens, reads, writes, formats, or enumerates files, streams, and directories.",
        "keywords": (
            "fopen", "openat", "fread", "fwrite", "unlink", "rename", "chmod", "chown",
            "stat", "opendir", "readdir", "nsfilemanager", "createfile", "readfile",
            "writefile", "deletefile", "copyfile", "findfirstfile", "gettemppath",
            "printf", "puts", "snprintf", "fprintf",
        ),
    },
    {
        "id": "network",
        "title": "Network & Socket Communications",
        "icon": "NET",
        "badge_class": "badge-purple",
        "summary": "Creates network sockets, resolves DNS hosts, or performs HTTP/TLS transfers.",
        "keywords": (
            "socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom",
            "getaddrinfo", "nsurlsession", "cfnetwork", "wsastartup", "internetopen",
            "httpsendrequest", "winhttp", "urldownloadtofile", "curl_",
        ),
    },
    {
        "id": "crypto",
        "title": "Cryptography, Hashing & Trust",
        "icon": "CRYP",
        "badge_class": "badge-emerald",
        "summary": "Computes cryptographic hashes, encrypts/decrypts buffers, or validates certificates/keys.",
        "keywords": (
            "cccrypt", "cc_sha", "seckey", "secitem", "commoncrypto", "evp_encrypt",
            "aes_", "sha256", "ssl_", "tls", "cryptacquire", "cryptencrypt", "bcrypt",
            "crypthash", "certopen", "compute_crypto", "pe_crypto_transform", "trustcache",
        ),
    },
    {
        "id": "dynamic_loading",
        "title": "Dynamic Linking & Runtime Reflection",
        "icon": "DYN",
        "badge_class": "badge-cyan",
        "summary": "Resolves shared library symbols dynamically at runtime or dispatches via Objective-C/late binding.",
        "keywords": (
            "dlopen", "dlsym", "dladdr", "objc_msgsend", "nsclassfromstring",
            "dyld_get_image", "loadlibrary", "getprocaddress", "getmodulehandle",
            "ldrloaddll",
        ),
    },
    {
        "id": "anti_analysis",
        "title": "Debugging, Tracing & Fault Traps",
        "icon": "DBG",
        "badge_class": "badge-danger",
        "summary": "Checks debugger attachment, sets anti-trace restrictions, or invokes breakpoint/panic traps.",
        "keywords": (
            "ptrace", "sysctl", "task_get_exception", "isdebuggerpresent",
            "checkremotedebugger", "ntqueryinformationprocess", "outputdebugstring",
            "setunhandledexception", "panic_trap", "get-task-allow", "__restrict",
        ),
    },
    {
        "id": "ipc_system",
        "title": "IPC, Kernel Syscalls & System UI",
        "icon": "SYS",
        "badge_class": "badge-purple",
        "summary": "Interacts with OS IPC channels (Mach ports, XPC, Mailbox, Registry, or Win32 GUI/Services).",
        "keywords": (
            "xpc_connection", "mach_msg", "bootstrap_look_up", "sep_mailbox", "iboot",
            "ioctl", "prctl", "regopenkey", "regsetvalue", "openprocesstoken",
            "adjusttokenprivileges", "messagebox", "createservice",
        ),
    },
]


def build_capabilities_and_strings(slice_doc: Dict[str, Any]) -> Dict[str, Any]:
    symbols = slice_doc.get("symbols", [])
    imports = (slice_doc.get("dyld_info", {}).get("chained_fixups") or {}).get("imports", [])
    exports = slice_doc.get("dyld_info", {}).get("exports", [])
    entitlements = slice_doc.get("code_signature_detail", {}).get("entitlements_dict", {})
    strings = slice_doc.get("strings", [])

    # Collect searchable symbol/entitlement candidates
    candidates: List[Dict[str, Any]] = []
    seen_names = set()
    for sym in symbols:
        nm = sym.get("name", "")
        if nm and nm not in seen_names:
            seen_names.add(nm)
            candidates.append({
                "name": sym.get("demangled") or nm,
                "raw": nm.lower(),
                "kind": "symbol",
                "abs_offset": sym.get("target_abs_offset") or sym.get("abs_offset", 0),
                "vmaddr": sym.get("n_value"),
            })
    for imp in imports:
        nm = imp.get("name", "")
        if nm and nm not in seen_names:
            seen_names.add(nm)
            candidates.append({
                "name": f"{nm} ({imp.get('lib_name', '')})",
                "raw": nm.lower(),
                "kind": "import",
                "abs_offset": slice_doc.get("slice_base_offset", 0),
                "vmaddr": None,
            })
    for ex in exports:
        nm = ex.get("name", "")
        if nm and nm not in seen_names:
            seen_names.add(nm)
            candidates.append({
                "name": nm,
                "raw": nm.lower(),
                "kind": "export",
                "abs_offset": ex.get("offset", 0),
                "vmaddr": ex.get("vmaddr"),
            })
    for ent_k, ent_v in entitlements.items():
        if ent_v:
            candidates.append({
                "name": f"entitlement:{ent_k}",
                "raw": ent_k.lower(),
                "kind": "entitlement",
                "abs_offset": slice_doc.get("slice_base_offset", 0),
                "vmaddr": None,
            })

    cards: List[Dict[str, Any]] = []
    active_count = 0
    total_matched = 0
    for rule in CAPABILITY_RULES:
        matched_evidence: List[Dict[str, Any]] = []
        for cand in candidates:
            if any(kw in cand["raw"] for kw in rule["keywords"]):
                matched_evidence.append({
                    "label": cand["name"],
                    "indicator": cand["name"],
                    "value": cand["name"],
                    "kind": cand["kind"],
                    "abs_offset": cand["abs_offset"],
                    "vmaddr": cand["vmaddr"],
                })
                if len(matched_evidence) >= 12:
                    break

        detected = len(matched_evidence) > 0
        if detected:
            active_count += 1
            total_matched += len(matched_evidence)
        cards.append({
            "id": rule["id"],
            "title": rule["title"],
            "icon": rule["icon"],
            "risk": "HIGH" if rule["badge_class"] == "badge-danger" else "INFO",
            "badge_class": rule["badge_class"] if detected else "badge-slate",
            "detected": detected,
            "count": len(matched_evidence),
            "match_count": len(matched_evidence),
            "summary": rule["summary"],
            "description": rule["summary"],
            "evidence": matched_evidence,
        })

    # Classify strings into semantic categories
    str_categories: Dict[str, List[Dict[str, Any]]] = {
        "paths_and_libs": [],
        "file_paths": [],
        "urls": [],
        "registry_keys": [],
        "crypto_and_security": [],
        "diagnostics_and_banners": [],
    }
    for st in strings:
        val = st.get("value", "")
        v_low = val.lower()
        item = {
            "value": val[:80],
            "source": st.get("source", ""),
            "vmaddr": st.get("vmaddr", "0x0"),
            "abs_offset": st.get("abs_offset", 0),
        }
        if "http://" in v_low or "https://" in v_low or "://" in v_low:
            if len(str_categories["urls"]) < 25:
                str_categories["urls"].append(item)
        if "software\\" in v_low or "hkey_" in v_low or "hkcu\\" in v_low or "hklm\\" in v_low or "currentversion\\run" in v_low:
            if len(str_categories["registry_keys"]) < 25:
                str_categories["registry_keys"].append(item)
        if (
            "/" in val
            or "\\" in val
            or ".dylib" in v_low
            or ".so" in v_low
            or ".dll" in v_low
            or ".pdb" in v_low
            or "@rpath" in v_low
        ):
            if len(str_categories["paths_and_libs"]) < 25:
                str_categories["paths_and_libs"].append(item)
                str_categories["file_paths"].append(item)
        elif any(k in v_low for k in ("pac", "auth", "crypt", "sha", "cert", "relro", "cet", "trust", "key", "security")):
            if len(str_categories["crypto_and_security"]) < 25:
                str_categories["crypto_and_security"].append(item)
        elif any(k in v_low for k in ("panic", "error", "fail", "warn", "version", "iboot", "firmware", "synthetic", "gcc", "clang")):
            if len(str_categories["diagnostics_and_banners"]) < 25:
                str_categories["diagnostics_and_banners"].append(item)

    detected_categories = [c for c in cards if c["detected"]]
    return {
        "active_categories_count": active_count,
        "total_categories": len(CAPABILITY_RULES),
        "total_matched_indicators": total_matched,
        "cards": cards,
        "categories": detected_categories,
        "string_intelligence": str_categories,
    }


def build_provenance_profile(slice_doc: Dict[str, Any]) -> Dict[str, Any]:
    fmt = slice_doc.get("format", "macho").lower()
    ov = slice_doc.get("overview", {})
    syms = slice_doc.get("symbols", [])
    dylibs = slice_doc.get("dylibs", [])

    # Infer primary source languages
    languages: List[str] = []
    sym_names = [s.get("name", "") for s in syms]
    lib_names = [d.get("name", "").lower() for d in dylibs]

    if slice_doc.get("objc_metadata", {}).get("present") or any("foundation" in l or "libobjc" in l for l in lib_names):
        languages.append("Objective-C")
    if any(n.startswith("_$s") or n.startswith("$s") for n in sym_names) or any("swift" in l for l in lib_names):
        languages.append("Swift")
    if any(n.startswith("__Z") or n.startswith("_Z") or "?" in n for n in sym_names) or any("libc++" in l or "stdc++" in l or "msvcp" in l for l in lib_names):
        languages.append("C++")
    if any("rust_eh_personality" in n for n in sym_names):
        languages.append("Rust")
    if any("gopclntab" in s.get("sectname", "") for seg in slice_doc.get("segments", []) for s in seg.get("sections", [])):
        languages.append("Go")
    if ov.get("filetype_name") == "MH_PRELOAD":
        languages.append("ARM64 Bare-Metal / Firmware Assembly")
    if not languages:
        languages.append("C / Native System ABI")

    compiler_chain = ov.get("sdk") or "System Native Toolchain"
    debug_artifact = ov.get("source_version") or "None"
    rich_tools: List[Dict[str, Any]] = []

    if fmt == "pe":
        pe_meta = slice_doc.get("pe_metadata", {})
        compiler_chain = f"MSVC Linker {pe_meta.get('linker_version', '')} ({pe_meta.get('timestamp_utc', '')})"
        debug_artifact = pe_meta.get("pdb_path") or "No RSDS PDB Path"
        if pe_meta.get("rich_header"):
            rich_tools = pe_meta["rich_header"].get("entries", [])
    elif fmt == "elf":
        elf_meta = slice_doc.get("elf_metadata", {})
        comments = elf_meta.get("compiler_comments", [])
        if comments:
            compiler_chain = comments[0]
        debug_artifact = elf_meta.get("interpreter") or "Static / No PT_INTERP"

    strip_lvl = "Stripped (Dynamic Only)" if slice_doc.get("security_posture", {}).get("stripped_symbols") else "Unstripped (Full Symbols)"
    abi_str = f"{ov.get('platform', 'OS')} ({ov.get('minos') or 'Standard ABI'})"

    return {
        "format_family": fmt.upper(),
        "os_and_abi": abi_str,
        "abi": abi_str,
        "architecture": f"{ov.get('arch_display', slice_doc.get('arch_name', ''))} ({ov.get('endianness', 'Little-Endian')})",
        "compiler_toolchain": compiler_chain,
        "compiler_family": compiler_chain,
        "linker_info": [compiler_chain],
        "source_languages": languages,
        "inferred_languages": languages,
        "strip_level": strip_lvl,
        "build_id_or_uuid": ov.get("uuid") or "Not Embedded",
        "debug_or_source_artifact": debug_artifact,
        "debug_artifacts": [debug_artifact] if debug_artifact and debug_artifact != "None" else [],
        "rich_header_tools": rich_tools,
    }


def build_structural_anomalies(slice_doc: Dict[str, Any], file_size: int) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    segs = slice_doc.get("segments", [])
    ep_off = slice_doc.get("entry_point", {}).get("abs_offset", 0)
    ep_vm_str = slice_doc.get("entry_point", {}).get("vmaddr", "0x0")
    try:
        ep_vm = int(ep_vm_str, 16) if ep_vm_str.startswith("0x") else int(ep_vm_str or 0)
    except ValueError:
        ep_vm = 0

    # 1. W^X Violation check
    for seg in segs:
        p = seg.get("initprot", "").lower()
        if "w" in p and "x" in p:
            anomalies.append({
                "id": "rwx_memory",
                "severity": "WARN",
                "title": f"Simultaneous Write + Execute (RWX) Region: {seg['segname']}",
                "detail": f"Segment {seg['segname']} @ {seg['vmaddr']} has permissions '{seg['initprot']}', violating W^X memory isolation and allowing direct shellcode modification.",
                "abs_offset": seg.get("abs_offset", 0),
                "vmaddr": seg.get("vmaddr"),
            })

    # 2. High-Entropy Executable Section (Packer / Encryption heuristic)
    for seg in segs:
        for sect in seg.get("sections", []):
            ent = sect.get("entropy", 0.0)
            sname = sect.get("sectname", "")
            if sect.get("is_executable") and ent >= 6.85:
                anomalies.append({
                    "id": "high_entropy_code",
                    "severity": "WARN" if ent >= 7.15 else "INFO",
                    "title": f"High-Entropy Executable Section: {sname} ({ent:.2f} bits/byte)",
                    "detail": f"Executable section {sname} exhibits unusually high byte randomness ({ent:.2f}/8.00), indicative of packed, compressed, or encrypted code.",
                    "abs_offset": sect.get("abs_offset", 0),
                    "vmaddr": sect.get("vmaddr"),
                })
            if any(pk in sname.lower() for pk in ("upx", "aspack", "vmp", "themida", "mpress")):
                anomalies.append({
                    "id": "packer_section_name",
                    "severity": "WARN",
                    "title": f"Packer Signature Section Name: {sname}",
                    "detail": f"Section '{sname}' matches a known executable packer or protector signature.",
                    "abs_offset": sect.get("abs_offset", 0),
                    "vmaddr": sect.get("vmaddr"),
                })

    # 3. Entry Point Validation
    if ep_vm > 0:
        in_exec_seg = False
        for seg in segs:
            s_vm = seg.get("vmaddr_int", 0)
            s_sz = seg.get("vmsize_int", 0)
            if s_vm <= ep_vm < s_vm + s_sz and "x" in seg.get("initprot", "").lower():
                in_exec_seg = True
                break
        if not in_exec_seg and segs:
            anomalies.append({
                "id": "ep_outside_exec_segment",
                "severity": "WARN",
                "title": f"Entry Point ({ep_vm_str}) Outside Standard Executable Segment",
                "detail": "The initial instruction pointer does not fall inside a standard R-X code segment.",
                "abs_offset": ep_off,
                "vmaddr": ep_vm_str,
            })

    # 4. PE Pre-Main TLS Callbacks
    pe_tls = slice_doc.get("pe_metadata", {}).get("tls_callbacks", [])
    if pe_tls:
        anomalies.append({
            "id": "pe_tls_callbacks",
            "severity": "WARN",
            "title": f"Pre-Entry TLS Callbacks Registered ({len(pe_tls)})",
            "detail": f"IMAGE_DIRECTORY_ENTRY_TLS executes {', '.join(pe_tls)} before AddressOfEntryPoint—commonly used for custom runtime init or anti-debug checks.",
            "abs_offset": ep_off,
            "vmaddr": pe_tls[0],
        })

    # 5. High-Risk Entitlements (Mach-O)
    for ent in slice_doc.get("code_signature_detail", {}).get("entitlements_entries", []):
        if ent.get("risk") == "HIGH":
            anomalies.append({
                "id": "high_risk_entitlement",
                "severity": "INFO",
                "title": f"Privileged / Debug Entitlement: {ent['key']}",
                "detail": ent.get("reason", "Grants elevated debugging or code-signing exceptions."),
                "abs_offset": slice_doc.get("code_signature_detail", {}).get("superblob_region", {}).get("abs_offset", 0) if slice_doc.get("code_signature_detail", {}).get("superblob_region") else 0,
                "vmaddr": None,
            })

    return anomalies


def build_semantic_layers(slice_doc: Dict[str, Any], raw_slice_bytes: bytes, total_file_size: int) -> Dict[str, Any]:
    entropy_info = build_entropy_analysis(slice_doc, raw_slice_bytes)
    capabilities_info = build_capabilities_and_strings(slice_doc)
    provenance_info = build_provenance_profile(slice_doc)
    anomalies_list = build_structural_anomalies(slice_doc, total_file_size)

    return {
        "entropy_analysis": entropy_info,
        "capabilities": capabilities_info,
        "provenance": provenance_info,
        "anomalies": {
            "total_count": len(anomalies_list),
            "high_severity_count": sum(1 for a in anomalies_list if a["severity"] in ("HIGH", "WARN")),
            "findings": anomalies_list,
        },
    }
