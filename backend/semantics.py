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
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from . import runtime
from .constants import ANALYSIS_LIMITS


def compute_entropy_and_classes(
    data: bytes, start: int = 0, end: Optional[int] = None, max_sample: int = 131072
) -> Dict[str, Any]:
    """
    Computes Shannon entropy H in [0.0, 8.0] bits/byte and 4-bucket byte distribution
    over data[start:end], sampling with a fixed stride when the range is larger
    than ~2 * max_sample bytes. The range is never copied in full, so profiling
    many (possibly overlapping) large sections costs O(sample), not O(size).
    """
    if end is None:
        end = len(data)
    start = max(0, start)
    end = min(len(data), end)
    n = max(0, end - start)
    if n == 0:
        return {
            "entropy": 0.0,
            "null_pct": 100.0,
            "ascii_pct": 0.0,
            "control_pct": 0.0,
            "high_pct": 0.0,
        }

    # Sample large ranges with a fixed stride (deterministic).
    if n > 2 * max_sample:
        step = max(1, n // max_sample)
        sample = data[start:end:step]
    else:
        sample = data[start:end] if (start or end != len(data)) else data

    total = len(sample)
    counts = [0] * 256
    for b, c in Counter(sample).items():
        counts[b] = c

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
            "High randomness (>= 7.15 bits/byte), typical of compressed or encrypted data. Embedded archives, images and key material look the same; entropy alone does not show packing.",
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
            "Executable section with entropy below the 6.8 bits/byte threshold used here; compiled machine code usually measures roughly 5.5 to 6.7.",
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

    # Compute per-section entropy & attach to section objects as well. The total
    # number of sampled bytes is bounded, so thousands of sections (or many
    # sections aliasing one huge range) cannot multiply the work.
    all_sects = [sect for seg in slice_doc.get("segments", []) for sect in seg.get("sections", [])]
    per_section_sample = max(4096, min(131072, ANALYSIS_LIMITS["entropy_sample_total"] // max(1, len(all_sects))))
    section_profiles: List[Dict[str, Any]] = []
    for seg in slice_doc.get("segments", []):
        for sect in seg.get("sections", []):
            runtime.check_deadline()
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
                stats = compute_entropy_and_classes(
                    raw_slice_bytes, s_off, min(slice_len, s_off + s_sz), max_sample=per_section_sample // 2
                )

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
            w_stats = compute_entropy_and_classes(raw_slice_bytes, w_start, w_end, max_sample=32768)
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


# ---------------------------------------------------------------------------
# Capabilities: which operating-system services the image refers to
# ---------------------------------------------------------------------------
# Matching is on WHOLE symbol names, never on substrings: "system" must be the C
# library function `system`, not part of `_ZNSt6system...` or `GetSystemInfo`.
#
#   names     exact names of C / POSIX / Mach functions (after `canonical_api_names`
#             has removed the decorations a format adds to a symbol)
#   win       Win32 / NT API names without the ANSI / wide suffix: `CreateFile` also
#             matches `CreateFileA` and `CreateFileW`, and nothing else
#   families  documented name prefixes of one library's API (`curl_`, `EVP_`,
#             `BCrypt...`): a prefix ending in "_" matches any continuation, any
#             other prefix must be followed by an upper-case letter, digit, "_" or "$"
#   classes   Objective-C classes, matched against `_OBJC_CLASS_$_<name>` references
#   entitlements  exact entitlement keys that declare the capability
#
# Evidence has a strength, and the kinds are never mixed:
#   import       an undefined symbol / import-table entry (the image calls it)
#   defined      a symbol of that name defined in the image (a statically linked copy)
#   entitlement  the code signature declares it
#   string       (weak) the API name merely appears as a string in the file, which is
#                how names passed to dlsym / GetProcAddress look, but also how text looks
def _nt(*names: str) -> Tuple[str, ...]:
    return tuple(prefix + n for n in names for prefix in ("Nt", "Zw"))


CAPABILITY_RULES = [
    {
        "id": "process",
        "title": "Process & Thread Execution",
        "icon": "EXEC",
        "badge_class": "badge-amber",
        "summary": "References APIs that create processes, run shell commands, or start threads.",
        "names": (
            "fork", "vfork", "execve", "execv", "execvp", "execvpe", "execl", "execlp", "execle", "fexecve",
            "posix_spawn", "posix_spawnp", "system", "popen", "pthread_create", "clone", "clone3", "daemon",
        ) + _nt("CreateThreadEx", "CreateUserProcess", "CreateProcess", "CreateProcessEx"),
        "win": (
            "CreateProcess", "CreateProcessAsUser", "CreateProcessWithLogon", "CreateProcessWithToken",
            "ShellExecute", "ShellExecuteEx", "WinExec", "CreateThread", "CreateRemoteThread",
            "CreateRemoteThreadEx", "RtlCreateUserThread", "OpenProcess",
        ),
        "classes": ("NSTask",),
    },
    {
        "id": "memory_injection",
        "title": "Virtual Memory & Code Loading",
        "icon": "MEM",
        "badge_class": "badge-danger",
        "summary": "References APIs that map memory, change page protections, or read and write another process's memory. Ordinary allocators and JITs use the same calls.",
        "names": (
            "mmap", "mmap64", "mprotect", "mremap", "memfd_create", "process_vm_readv", "process_vm_writev",
            "vm_allocate", "vm_protect", "vm_write", "vm_read", "vm_remap",
            "mach_vm_allocate", "mach_vm_protect", "mach_vm_write", "mach_vm_read", "mach_vm_read_overwrite",
            "mach_vm_map", "mach_vm_remap", "task_for_pid", "pthread_jit_write_protect_np",
        ) + _nt("MapViewOfSection", "AllocateVirtualMemory", "ProtectVirtualMemory", "WriteVirtualMemory", "ReadVirtualMemory"),
        "win": (
            "VirtualAlloc", "VirtualAllocEx", "VirtualAlloc2", "VirtualProtect", "VirtualProtectEx",
            "WriteProcessMemory", "ReadProcessMemory", "MapViewOfFile", "MapViewOfFileEx", "MapViewOfFile2",
            "MapViewOfFile3", "CreateFileMapping",
        ),
        "entitlements": (
            "com.apple.security.cs.allow-jit", "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.disable-executable-page-protection", "dynamic-codesigning",
            "task_for_pid-allow", "com.apple.system-task-ports",
        ),
    },
    {
        "id": "filesystem",
        "title": "File System & Stream I/O",
        "icon": "FILE",
        "badge_class": "badge-cyan",
        "summary": "References APIs that open, read, write or enumerate files and directories, or write formatted output to streams.",
        "names": (
            "fopen", "fopen64", "open", "open64", "openat", "openat64", "creat", "fread", "fwrite", "read", "write",
            "pread", "pwrite", "unlink", "unlinkat", "remove", "rename", "renameat", "chmod", "fchmod", "chown",
            "fchown", "stat", "stat64", "lstat", "lstat64", "fstat", "fstat64", "fstatat", "__xstat", "__lxstat",
            "__fxstat", "opendir", "readdir", "readdir64", "readdir_r", "mkdir", "rmdir", "truncate", "ftruncate",
            "printf", "fprintf", "vprintf", "vfprintf", "puts", "fputs", "putchar", "fputc", "perror",
            "_wfopen", "fopen_s",
        ) + _nt("CreateFile", "OpenFile", "ReadFile", "WriteFile"),
        "win": (
            "CreateFile", "CreateFile2", "ReadFile", "WriteFile", "DeleteFile", "CopyFile", "CopyFileEx", "MoveFile",
            "MoveFileEx", "FindFirstFile", "FindFirstFileEx", "FindNextFile", "GetTempPath", "GetTempFileName",
        ),
        "classes": ("NSFileManager", "NSFileHandle"),
    },
    {
        "id": "network",
        "title": "Network & Socket Communications",
        "icon": "NET",
        "badge_class": "badge-purple",
        "summary": "References APIs that create sockets, resolve host names, or perform HTTP transfers.",
        "names": (
            "socket", "connect", "bind", "listen", "accept", "accept4", "send", "sendto", "sendmsg", "recv",
            "recvfrom", "recvmsg", "getaddrinfo", "getnameinfo", "gethostbyname", "gethostbyname2",
            "WSAStartup", "WSAConnect", "WSASend", "WSARecv", "WSASendTo", "WSARecvFrom",
        ),
        "win": (
            "WSASocket", "InternetOpen", "InternetOpenUrl", "InternetConnect", "InternetReadFile", "HttpOpenRequest",
            "HttpSendRequest", "HttpSendRequestEx", "URLDownloadToFile", "URLDownloadToCacheFile",
        ),
        "families": ("curl_", "WinHttp", "nw_connection_", "CFHTTPMessage", "CFSocket"),
        "classes": ("NSURLSession", "NSURLConnection"),
    },
    {
        "id": "crypto",
        "title": "Cryptography, Hashing & Trust",
        "icon": "CRYP",
        "badge_class": "badge-emerald",
        "summary": "References APIs that hash, encrypt or decrypt data, or handle keys and certificates.",
        "names": (
            "CCCrypt", "CCKeyDerivationPBKDF", "SecItemAdd", "SecItemCopyMatching", "SecItemUpdate", "SecItemDelete",
            "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "MD5", "AES_encrypt", "AES_decrypt",
            "AES_set_encrypt_key", "AES_set_decrypt_key", "AES_cbc_encrypt",
            "CertOpenStore", "CertOpenSystemStoreA", "CertOpenSystemStoreW", "CertCloseStore",
            "CertFindCertificateInStore", "CertEnumCertificatesInStore", "CertGetCertificateChain",
            "CertVerifyCertificateChainPolicy", "CertFreeCertificateContext",
        ),
        "families": (
            "CC_SHA", "CC_MD5", "CCCryptor", "CCHmac", "SecKey", "SecCertificate", "SecTrust", "SecIdentity",
            "EVP_", "SSL_", "HMAC_", "RSA_", "EC_KEY_", "SHA1_", "SHA256_", "SHA512_", "MD5_",
            "gnutls_", "mbedtls_", "wolfSSL_", "crypto_", "BCrypt", "NCrypt", "Crypt",
        ),
    },
    {
        "id": "dynamic_loading",
        "title": "Dynamic Linking & Runtime Reflection",
        "icon": "DYN",
        "badge_class": "badge-cyan",
        "summary": "References APIs that load libraries or look up symbols at run time, or the Objective-C message dispatcher.",
        "names": (
            "dlopen", "dlsym", "dlvsym", "dlmopen", "dladdr", "NSClassFromString", "NSSelectorFromString",
            "objc_getClass", "objc_lookUpClass", "class_getMethodImplementation", "method_exchangeImplementations",
            "_dyld_image_count", "_dyld_get_image_name", "_dyld_get_image_header", "_dyld_get_image_vmaddr_slide",
            "_dyld_register_func_for_add_image", "LdrLoadDll", "LdrGetProcedureAddress",
        ),
        "win": ("LoadLibrary", "LoadLibraryEx", "GetProcAddress", "GetModuleHandle", "GetModuleHandleEx"),
        "families": ("objc_msgSend",),
    },
    {
        "id": "anti_analysis",
        "title": "Debugging, Tracing & Fault Traps",
        "icon": "DBG",
        "badge_class": "badge-danger",
        "summary": "References APIs that can detect or block a debugger (ptrace, sysctl, IsDebuggerPresent). The same calls have ordinary uses.",
        "names": (
            "ptrace", "sysctl", "sysctlbyname", "task_get_exception_ports", "task_set_exception_ports",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "SetUnhandledExceptionFilter", "DebugActiveProcess",
        ) + _nt("QueryInformationProcess", "SetInformationThread"),
        "win": ("OutputDebugString",),
        "entitlements": ("get-task-allow", "com.apple.security.get-task-allow"),
    },
    {
        "id": "ipc_system",
        "title": "IPC, Kernel Syscalls & System UI",
        "icon": "SYS",
        "badge_class": "badge-purple",
        "summary": "References OS inter-process and system interfaces: Mach messages and XPC, ioctl / prctl, or the Windows registry, tokens, services and message boxes.",
        "names": (
            "mach_msg", "mach_msg_overwrite", "mach_msg2", "bootstrap_look_up", "bootstrap_check_in", "ioctl", "prctl",
            "OpenProcessToken", "AdjustTokenPrivileges",
        ),
        "win": (
            "RegOpenKey", "RegOpenKeyEx", "RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx",
            "RegQueryValueEx", "RegDeleteKey", "RegDeleteValue", "MessageBox", "MessageBoxEx", "CreateService",
            "OpenSCManager", "StartService", "CreateNamedPipe",
        ),
        "families": ("xpc_connection_",),
    },
]

# Suffixes Apple's libc adds to a symbol name to select a variant of the same function.
_DARWIN_VARIANT = re.compile(r"\$(UNIX2003|INODE64|NOCANCEL|DARWIN_EXTSN|1050|NOCANCEL\$UNIX2003|INODE64\$UNIX2003)$")
_STDCALL = re.compile(r"^_([A-Za-z][A-Za-z0-9_]*)@\d+$")
_FORTIFIED = re.compile(r"^__([a-z][a-z0-9_]*?)_chk$")
_C_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_OBJC_CLASS_PREFIXES = ("OBJC_CLASS_$_", "_OBJC_CLASS_$_")


def canonical_api_names(raw: str, fmt: str = "") -> Tuple[List[str], Optional[str]]:
    """(candidate API names, Objective-C class name or None) for one symbol name.

    Removes, deliberately and only, the decorations a format or toolchain adds:
      ELF      `name@VERSION` / `name@@VERSION`; `__name_chk` (the _FORTIFY_SOURCE variant)
      Mach-O   the single leading underscore of every C symbol; `$UNIX2003`-style variants;
               `_OBJC_CLASS_$_Name` is returned as the class `Name`
      PE/COFF  `__imp_` (import thunk), `_name@N` (32-bit stdcall)
    The ANSI / wide suffix of Win32 names is handled by the rule's `win` set, not here.
    A name that is not a plain C identifier afterwards (C++, Swift, Rust mangling) yields
    no candidates: mangled names are never matched.
    """
    name = str(raw or "")
    for prefix in _OBJC_CLASS_PREFIXES:
        if name.startswith(prefix):
            cls = name[len(prefix):]
            return ([], cls) if _C_IDENTIFIER.match(cls) else ([], None)
    name = name.split("@@", 1)[0]
    stdcall = _STDCALL.match(name)
    if stdcall:
        name = stdcall.group(1)
    else:
        name = name.split("@", 1)[0]
    for prefix in ("__imp__", "__imp_"):
        if name.startswith(prefix) and len(name) > len(prefix):
            name = name[len(prefix):]
            break
    name = _DARWIN_VARIANT.sub("", name)
    if not _C_IDENTIFIER.match(name):
        return ([], None)
    out = [name]
    if fmt == "macho" and name.startswith("_") and len(name) > 1:
        out = [name[1:]]          # every C symbol in Mach-O carries one leading underscore
    for item in list(out):
        fortified = _FORTIFIED.match(item)
        if fortified:
            out.append(fortified.group(1))
    return (out, None)


def _family_match(name: str, families: Tuple[str, ...]) -> bool:
    for prefix in families:
        if not name.startswith(prefix):
            continue
        if prefix.endswith("_"):
            if len(name) > len(prefix):
                return True
        elif len(name) == len(prefix) or not name[len(prefix)].islower():
            return True
    return False


# Set forms of each rule's name lists, so that matching one symbol against one rule is a
# couple of hash look-ups however long the lists are (a file may carry 20,000 symbols).
_RULE_SETS: Dict[str, Tuple[frozenset, frozenset, frozenset]] = {
    rule["id"]: (frozenset(rule.get("names", ())), frozenset(rule.get("win", ())), frozenset(rule.get("classes", ())))
    for rule in CAPABILITY_RULES
}


def match_api(rule: Dict[str, Any], names: List[str], objc_class: Optional[str] = None) -> Optional[str]:
    """The API name of `rule` that one symbol refers to, or None. Whole names only."""
    exact, win, classes = _RULE_SETS[rule["id"]]
    if objc_class is not None:
        return objc_class if objc_class in classes else None
    families = rule.get("families", ())
    for name in names:
        if name in exact or name in win:
            return name
        if len(name) > 1 and name[-1] in "AW" and name[:-1] in win:
            return name
        if families and _family_match(name, families):
            return name
    return None


def _distinctive(text: str) -> bool:
    """True if a string that equals an API name is unlikely to be ordinary text."""
    return len(text) >= 8 or any(ch.isupper() or ch.isdigit() or ch == "_" for ch in text)


def build_capabilities_and_strings(slice_doc: Dict[str, Any]) -> Dict[str, Any]:
    fmt = str(slice_doc.get("format", "macho")).lower()
    symbols = slice_doc.get("symbols", [])
    imports = (slice_doc.get("dyld_info", {}).get("chained_fixups") or {}).get("imports", [])
    exports = slice_doc.get("dyld_info", {}).get("exports", [])
    entitlements = slice_doc.get("code_signature_detail", {}).get("entitlements_dict", {})
    strings = slice_doc.get("strings", [])
    base_off = slice_doc.get("slice_base_offset", 0)

    # Symbol-based candidates: (raw name, kind, shown name, abs_offset, vmaddr, library).
    # An import-table entry and an undefined symbol are "import"; a symbol the image
    # itself defines (or exports) is "defined".
    candidates: List[Tuple[str, str, str, Any, Any, str]] = []
    seen_names = set()
    for imp in imports:
        nm = imp.get("name", "")
        if nm and (nm, "import") not in seen_names:
            seen_names.add((nm, "import"))
            lib = str(imp.get("lib_name") or "")
            candidates.append((nm, "import", f"{nm} ({lib})" if lib else nm, base_off, None, lib))
    for sym in symbols:
        nm = sym.get("name", "")
        if not nm or sym.get("is_stab"):
            continue
        kind = "import" if sym.get("type_name") == "UNDF" else ("defined" if sym.get("type_name") == "SECT" else "")
        if not kind or (nm, kind) in seen_names:
            continue
        seen_names.add((nm, kind))
        candidates.append((nm, kind, sym.get("demangled") or nm, sym.get("target_abs_offset") or sym.get("abs_offset", 0),
                           sym.get("n_value"), str(sym.get("library_name") or "") if kind == "import" else ""))
    for ex in exports:
        nm = ex.get("name", "")
        if nm and (nm, "defined") not in seen_names:
            seen_names.add((nm, "defined"))
            candidates.append((nm, "defined", nm, ex.get("offset", 0), ex.get("vmaddr"), ""))
    resolved = [(canonical_api_names(raw, fmt), kind, shown, off, vm, lib) for raw, kind, shown, off, vm, lib in candidates]

    cards: List[Dict[str, Any]] = []
    active_count = 0
    total_matched = 0
    total_weak = 0
    for rule in CAPABILITY_RULES:
        runtime.check_deadline()
        strong: List[Dict[str, Any]] = []
        strong_seen = set()
        matched_apis = set()
        for (names, objc_class), kind, shown, off, vm, lib in resolved:
            api = match_api(rule, names, objc_class)
            if api is None:
                continue
            if (api, kind) in strong_seen:
                continue          # .dynsym and .symtab (or an import and its symbol) name the same API
            strong_seen.add((api, kind))
            matched_apis.add(api)
            strong.append({
                "label": shown, "indicator": shown, "value": shown, "api": api, "kind": kind,
                "library": lib, "abs_offset": off, "vmaddr": vm,
            })
        for ent_k, ent_v in entitlements.items():
            if ent_v and str(ent_k) in rule.get("entitlements", ()):
                strong.append({
                    "label": f"entitlement:{ent_k}", "indicator": f"entitlement:{ent_k}", "value": f"entitlement:{ent_k}",
                    "api": str(ent_k), "kind": "entitlement", "library": "", "abs_offset": base_off, "vmaddr": None,
                })
        strong.sort(key=lambda ev: {"import": 0, "entitlement": 1, "defined": 2}.get(ev["kind"], 3))
        strong_total = len(strong)
        del strong[12:]

        # Weak evidence: a string that IS an API name of this rule (and is not ordinary text),
        # for APIs not already established above. Never a substring of a longer string.
        weak: List[Dict[str, Any]] = []
        weak_seen = set()
        for st in strings:
            val = st.get("value", "")
            if not (3 <= len(val) <= 64) or val in weak_seen or not _C_IDENTIFIER.match(val) or not _distinctive(val):
                continue
            api = match_api(rule, [val])
            if api is None or api in matched_apis:
                continue
            weak_seen.add(val)
            if len(weak) < 12:
                weak.append({
                    "label": val, "indicator": val, "value": val, "api": api, "kind": "string",
                    "library": "", "abs_offset": st.get("abs_offset", 0), "vmaddr": st.get("vmaddr"),
                })

        detected = strong_total > 0
        kinds = {ev["kind"] for ev in strong}
        strength = ("import" if "import" in kinds else "entitlement" if "entitlement" in kinds else "defined") if detected \
            else ("strings" if weak else "none")
        if detected:
            active_count += 1
            total_matched += strong_total
        total_weak += len(weak_seen)
        cards.append({
            "id": rule["id"],
            "title": rule["title"],
            "icon": rule["icon"],
            "risk": "HIGH" if rule["badge_class"] == "badge-danger" else "INFO",
            "badge_class": rule["badge_class"] if detected else "badge-slate",
            "detected": detected,
            "strength": strength,
            "count": strong_total,
            "match_count": strong_total,
            "summary": rule["summary"],
            "description": rule["summary"],
            "evidence": strong,
            "weak_evidence": weak,
            "weak_count": len(weak_seen),
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
        "total_weak_indicators": total_weak,
        "cards": cards,
        "categories": detected_categories,
        # Areas for which the only evidence is an API name appearing as a string.
        "weak_categories": [c for c in cards if not c["detected"] and c["weak_evidence"]],
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
        languages.append("Bare-Metal / Firmware (MH_PRELOAD)")
    if not languages:
        languages.append("C / Native System ABI")

    compiler_chain = ov.get("sdk") or "System Native Toolchain"
    debug_artifact = ov.get("source_version") or "None"
    rich_tools: List[Dict[str, Any]] = []

    if fmt == "pe":
        pe_meta = slice_doc.get("pe_metadata", {})
        compiler_chain = f"Linker version {pe_meta.get('linker_version', '')} ({pe_meta.get('timestamp_utc', '')})"
        debug_artifact = pe_meta.get("pdb_path") or "No RSDS PDB Path"
        if pe_meta.get("rich_header"):
            rich_tools = pe_meta["rich_header"].get("entries", [])
    elif fmt == "elf":
        elf_meta = slice_doc.get("elf_metadata", {})
        comments = elf_meta.get("compiler_comments", [])
        if comments:
            compiler_chain = comments[0]
        debug_artifact = elf_meta.get("interpreter") or "Static / No PT_INTERP"

    posture = slice_doc.get("security_posture", {})
    if posture.get("symbols_state"):
        # PE: the parser says exactly what is and is not in the image (COFF symbol table,
        # debug directory / PDB reference, *_STRIPPED characteristics).
        strip_lvl = str(posture["symbols_state"])
    else:
        strip_lvl = "Stripped (Dynamic Only)" if posture.get("stripped_symbols") else "Unstripped (Full Symbols)"
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

    # 1. W^X Violation check. Not for Mach-O relocatable objects and dSYM files: their
    #    segment protections are not mapping requests (see security.evaluate_security_posture).
    not_mapped = slice_doc.get("format", "macho").lower() == "macho" and \
        (slice_doc.get("header") or {}).get("filetype_name") in ("MH_OBJECT", "MH_DSYM")
    for seg in ([] if not_mapped else segs):
        p = seg.get("initprot", "").lower()
        if "w" in p and "x" in p:
            anomalies.append({
                "id": "rwx_memory",
                "severity": "WARN",
                "title": f"Simultaneous Write + Execute (RWX) Region: {seg['segname']}",
                "detail": f"Segment {seg['segname']} @ {seg['vmaddr']} has permissions '{seg['initprot']}': it is writable and executable at once, so bytes written there at run time can be executed. Loaders may refuse or downgrade such a mapping.",
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
                    "detail": f"Executable section {sname} has unusually high byte randomness ({ent:.2f}/8.00) for machine code, which can indicate packed, compressed or encrypted content (or large data tables placed in a code section).",
                    "abs_offset": sect.get("abs_offset", 0),
                    "vmaddr": sect.get("vmaddr"),
                })
            if any(pk in sname.lower() for pk in ("upx", "aspack", "vmp", "themida", "mpress")):
                anomalies.append({
                    "id": "packer_section_name",
                    "severity": "WARN",
                    "title": f"Packer Signature Section Name: {sname}",
                    "detail": f"Section name '{sname}' contains a string used by a known packer or protector (UPX, ASPack, VMProtect, Themida, MPRESS). Names are easy to change, so this is a hint only.",
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
                "title": f"Entry Point ({ep_vm_str}) Outside Any Executable Segment",
                "detail": "The entry point address recorded in the file does not fall inside a segment that is mapped executable.",
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
            "detail": f"The TLS directory (IMAGE_DIRECTORY_ENTRY_TLS) lists {', '.join(pe_tls)}; the loader calls these before AddressOfEntryPoint. Language runtimes use TLS callbacks for thread-local set-up; they are also a common place for anti-debugging code.",
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

    limit = ANALYSIS_LIMITS["anomalies"]
    if len(anomalies) > limit:
        del anomalies[limit:]
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
