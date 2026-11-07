"""
Automated Security Posture & Firmware Hardening Scorecard Engine.
"""

from typing import Any, Dict, List
from .constants import (
    CPU_TYPE_ARM64,
    MH_ALLOW_STACK_EXECUTION,
    MH_DYLIB,
    MH_EXECUTE,
    MH_KEXT_BUNDLE,
    MH_NO_HEAP_EXECUTION,
    MH_PRELOAD,
    VM_PROT_EXECUTE,
    VM_PROT_WRITE,
)


def evaluate_security_posture(
    header: Dict[str, Any],
    segments: List[Dict[str, Any]],
    symbols: List[Dict[str, Any]],
    rpaths: List[Dict[str, Any]],
    dyld_info: Dict[str, Any],
    code_sig_detail: Dict[str, Any],
    encryption_info: Dict[str, Any],
) -> Dict[str, Any]:
    flags = header.get("flags", 0)
    filetype = header.get("filetype", 0)
    cputype = header.get("cputype", 0)
    cpusubtype = header.get("cpusubtype", 0)

    # 1. PIE (Position Independent Executable)
    has_pie_flag = bool(flags & 0x00200000)
    is_pie = has_pie_flag or filetype in (MH_DYLIB, MH_KEXT_BUNDLE)

    # 2. Symbol-based mitigations: Stack Canary & ARC
    sym_names = {s.get("name", "") for s in symbols}
    has_canary = bool(
        {"___stack_chk_fail", "___stack_chk_guard", "__stack_chk_fail", "__stack_chk_guard"}
        & sym_names
    )
    has_arc = bool(
        {
            "_objc_release",
            "_objc_retain",
            "_objc_storeStrong",
            "_objc_autoreleaseReturnValue",
            "_objc_retainAutoreleasedReturnValue",
        }
        & sym_names
    )

    local_or_ext_defined = [
        s for s in symbols if s.get("type_name") == "SECT" and not s.get("is_stab")
    ]
    stripped_symbols = len(local_or_ext_defined) == 0

    # 3. PAC (Pointer Authentication / ARM64e)
    is_arm64e = (cputype == CPU_TYPE_ARM64) and ((cpusubtype & 0xFF) == 2)
    chained_ptr_fmt = (
        dyld_info.get("chained_fixups", {}).get("pointer_format", "")
        if dyld_info.get("chained_fixups")
        else ""
    )
    has_arm64e_chains = "ARM64E" in chained_ptr_fmt
    pac_enabled = is_arm64e or has_arm64e_chains

    # 4. RWX Segments & __RESTRICT Check
    rwx_segments: List[str] = []
    has_restrict_segment = False
    for seg in segments:
        segname = seg.get("segname", "")
        init_raw = seg.get("initprot_raw", 0)
        max_raw = seg.get("maxprot_raw", 0)
        if ((init_raw & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) or (
            (max_raw & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)
            and (init_raw & (VM_PROT_WRITE | VM_PROT_EXECUTE)) != 0
        ):
            rwx_segments.append(f"{segname} ({seg.get('initprot')}/{seg.get('maxprot')})")
        if segname == "__RESTRICT":
            has_restrict_segment = True
        for sect in seg.get("sections", []):
            if sect.get("segname") == "__RESTRICT" or sect.get("sectname") == "__restrict":
                has_restrict_segment = True

    if flags & MH_ALLOW_STACK_EXECUTION:
        rwx_segments.append("STACK (MH_ALLOW_STACK_EXECUTION)")

    has_rwx = len(rwx_segments) > 0

    # 5. Encryption Check
    is_encrypted = bool(encryption_info and encryption_info.get("cryptid", 0) != 0)

    # 6. Code Signature Summary
    cs_present = bool(code_sig_detail and code_sig_detail.get("present"))
    cd = code_sig_detail.get("code_directory") if cs_present else None
    cd_flags = cd.get("flags_int", 0) if cd else 0
    cms = code_sig_detail.get("cms_signature", {}) if cs_present else {}
    certs_objs = cms.get("certificates", []) if cms else []
    cert_names = [c.get("subject_cn", "") for c in certs_objs if c.get("subject_cn")]

    is_adhoc = bool(cd_flags & 0x00000002) or (cs_present and len(cert_names) == 0)
    hardened_runtime = bool(cd_flags & 0x00010000)
    library_validation = bool(cd_flags & 0x00002000) or bool(cd_flags & 0x00000010)
    cs_restrict = bool(cd_flags & 0x00000800)

    if cs_restrict or hardened_runtime:
        has_restrict_segment = has_restrict_segment or cs_restrict

    cs_summary = {
        "present": cs_present,
        "is_adhoc": is_adhoc,
        "hardened_runtime": hardened_runtime,
        "library_validation": library_validation,
        "cdhash": cd.get("cdhash", "") if cd else "",
        "cdhash_verified": bool(cd.get("cdhash_verified")) if cd else False,
        "identifier": cd.get("identifier", "") if cd else "",
        "team_id": (cd.get("team_id") or (cert_names[0] if cert_names else "")) if cd else "",
        "certificates": cert_names,
    }

    # Build Detailed Checks Array
    checks: List[Dict[str, Any]] = []

    # Check 1: PIE
    if filetype == MH_PRELOAD:
        checks.append({
            "id": "pie",
            "title": "Position Independent Executable (MH_PIE)",
            "status": "INFO",
            "value": "MH_PRELOAD (Fixed Base Firmware)",
            "detail": "Standalone firmware image linked at fixed physical/virtual base address.",
        })
    elif is_pie:
        checks.append({
            "id": "pie",
            "title": "Position Independent Executable (MH_PIE)",
            "status": "PASS",
            "value": "Enabled",
            "detail": "ASLR random slide enabled via MH_PIE (0x200000) or shared library semantics.",
        })
    else:
        checks.append({
            "id": "pie",
            "title": "Position Independent Executable (MH_PIE)",
            "status": "FAIL",
            "value": "Disabled (Fixed Address)",
            "detail": "MH_PIE flag is not set; binary loads at a predictable virtual address without ASLR.",
        })

    # Check 2: Stack Canary
    if has_canary:
        checks.append({
            "id": "stack_canary",
            "title": "Stack Smashing Protection (Canary)",
            "status": "PASS",
            "value": "Present (___stack_chk_guard)",
            "detail": "Compiler stack buffer overflow canary verification symbols are linked.",
        })
    else:
        checks.append({
            "id": "stack_canary",
            "title": "Stack Smashing Protection (Canary)",
            "status": "INFO" if filetype != MH_PRELOAD else "WARN",
            "value": "Not Detected",
            "detail": "No ___stack_chk_fail / ___stack_chk_guard reference found (leaf functions or -fno-stack-protector).",
        })

    # Check 3: PAC / ARM64e
    if pac_enabled:
        checks.append({
            "id": "pac",
            "title": "Pointer Authentication (ARM64e PAC)",
            "status": "PASS",
            "value": f"ARM64e ({chained_ptr_fmt or 'Hardware PAC'})",
            "detail": "Uses ARMv8.3-A Pointer Authentication instructions and/or authenticated chained fixups.",
        })
    elif cputype == CPU_TYPE_ARM64:
        checks.append({
            "id": "pac",
            "title": "Pointer Authentication (ARM64e PAC)",
            "status": "INFO",
            "value": "Standard ARM64 (No PAC)",
            "detail": "Compiled for baseline ARM64 ABI without arm64e pointer signing.",
        })
    else:
        checks.append({
            "id": "pac",
            "title": "Pointer Authentication (ARM64e PAC)",
            "status": "INFO",
            "value": "N/A (Non-ARM64)",
            "detail": "Pointer Authentication is specific to Apple Silicon ARM64e.",
        })

    # Check 4: W^X / RWX Memory Hygiene
    if has_rwx:
        checks.append({
            "id": "rwx",
            "title": "W^X Memory Protection Hygiene",
            "status": "FAIL",
            "value": f"RWX Detected: {', '.join(rwx_segments)}",
            "detail": "One or more segments allow simultaneous Write and Execute permissions, enabling shellcode injection.",
        })
    else:
        checks.append({
            "id": "rwx",
            "title": "W^X Memory Protection Hygiene",
            "status": "PASS",
            "value": "Strict W^X Enforced",
            "detail": "No segments have simultaneous Write (VM_PROT_WRITE) and Execute (VM_PROT_EXECUTE) permissions.",
        })

    # Check 5: ARC (Objective-C / Swift Memory Management)
    if has_arc:
        checks.append({
            "id": "arc",
            "title": "Automatic Reference Counting (ARC)",
            "status": "PASS",
            "value": "Enabled (_objc_retain / _objc_release)",
            "detail": "Objective-C/Swift Automatic Reference Counting runtime primitives detected.",
        })
    else:
        checks.append({
            "id": "arc",
            "title": "Automatic Reference Counting (ARC)",
            "status": "INFO",
            "value": "Pure C/C++ or Manual Memory",
            "detail": "No Objective-C ARC retain/release symbols imported.",
        })

    # Check 6: Dyld Injection Hardening (__RESTRICT / Hardened Runtime)
    if has_restrict_segment or hardened_runtime or library_validation:
        modes = []
        if hardened_runtime:
            modes.append("CS_RUNTIME")
        if library_validation:
            modes.append("Library Validation")
        if has_restrict_segment:
            modes.append("__RESTRICT")
        checks.append({
            "id": "restrict",
            "title": "Dyld Environment & Injection Hardening",
            "status": "PASS",
            "value": " | ".join(modes),
            "detail": "Protected against untrusted DYLD_INSERT_LIBRARIES and dylib hijacking.",
        })
    else:
        checks.append({
            "id": "restrict",
            "title": "Dyld Environment & Injection Hardening",
            "status": "WARN",
            "value": "No __RESTRICT / CS_RUNTIME",
            "detail": "Neither __RESTRICT,__restrict nor Hardened Runtime (CS_RUNTIME) is active.",
        })

    # Check 7: RPATH Hygiene
    if not rpaths:
        checks.append({
            "id": "rpath",
            "title": "Dynamic Runpath (@rpath) Hygiene",
            "status": "PASS",
            "value": "No LC_RPATH entries",
            "detail": "All dynamic libraries use absolute paths without relative @rpath search directories.",
        })
    else:
        rp_list = [r.get("path", "") for r in rpaths]
        risky_rpaths = [
            p for p in rp_list if p.startswith(".") or p.startswith("/tmp") or p.startswith("/var/tmp")
        ]
        checks.append({
            "id": "rpath",
            "title": "Dynamic Runpath (@rpath) Hygiene",
            "status": "FAIL" if risky_rpaths else "INFO",
            "value": f"{len(rp_list)} RPATH(s): {', '.join(rp_list[:2])}",
            "detail": (
                f"Relative/world-writable RPATH detected ({', '.join(risky_rpaths)})"
                if risky_rpaths
                else f"Configured LC_RPATH entries: {', '.join(rp_list)}"
            ),
        })

    # Check 8: Code Signature & CDHash Integrity
    if cs_present and cd:
        verified = cd.get("cdhash_verified", False)
        sig_type = "Ad-Hoc Signed" if is_adhoc else f"Signed ({cert_names[0] if cert_names else 'CMS'})"
        checks.append({
            "id": "codesign",
            "title": "Code Signature & CDHash Integrity",
            "status": "PASS" if verified else "WARN",
            "value": f"{sig_type} • {'Verified' if verified else 'Unverified'} ({cd.get('hash_type', 'SHA-256')})",
            "detail": (
                f"CDHash {cd.get('cdhash')} matches on-disk code pages ({cd.get('n_code_slots')} slots)."
                if verified
                else f"CodeDirectory present ({cd.get('cdhash')}) but one or more page hashes did not verify."
            ),
        })
    else:
        checks.append({
            "id": "codesign",
            "title": "Code Signature & CDHash Integrity",
            "status": "FAIL" if filetype == MH_EXECUTE else "INFO",
            "value": "Unsigned (No LC_CODE_SIGNATURE)",
            "detail": "Binary does not contain an embedded LC_CODE_SIGNATURE SuperBlob.",
        })

    # Check 9: FairPlay / Binary Encryption
    if is_encrypted:
        checks.append({
            "id": "encryption",
            "title": "Binary Segment Encryption (LC_ENCRYPTION_INFO)",
            "status": "WARN",
            "value": f"Encrypted (cryptid={encryption_info.get('cryptid')})",
            "detail": f"Range 0x{encryption_info.get('cryptoff', 0):x}..+0x{encryption_info.get('cryptsize', 0):x} is encrypted.",
        })
    else:
        checks.append({
            "id": "encryption",
            "title": "Binary Segment Encryption (LC_ENCRYPTION_INFO)",
            "status": "PASS",
            "value": "Unencrypted (Cleartext Code)",
            "detail": "Executable pages are unencrypted and directly inspectable.",
        })

    return {
        "pie": is_pie,
        "arc": has_arc,
        "stack_canary": has_canary,
        "pac_enabled": pac_enabled,
        "has_rwx_segments": has_rwx,
        "has_restrict_segment": has_restrict_segment,
        "is_encrypted": is_encrypted,
        "stripped_symbols": stripped_symbols,
        "code_signature": cs_summary,
        "checks": checks,
    }
