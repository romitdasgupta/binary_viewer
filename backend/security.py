"""
Automated Security Posture & Firmware Hardening Scorecard Engine.
"""

from typing import Any, Dict, List
from .constants import (
    CPU_TYPE_ARM64,
    MH_ALLOW_STACK_EXECUTION,
    MH_BUNDLE,
    MH_DYLIB,
    MH_DYLINKER,
    MH_EXECUTE,
    FILETYPE_INFO,
    MH_KEXT_BUNDLE,
    MH_DSYM,
    MH_NO_HEAP_EXECUTION,
    MH_OBJECT,
    MH_PIE,
    MH_PRELOAD,
    VM_PROT_EXECUTE,
    VM_PROT_WRITE,
    is_arm64e_subtype,
)

_WX = VM_PROT_WRITE | VM_PROT_EXECUTE

# File types whose images are always loaded at an address the loader chooses, so
# MH_PIE (a main-executable flag) says nothing about them:
#   MH_DYLIB / MH_BUNDLE  dyld maps them wherever there is room;
#   MH_DYLINKER           XNU slides dyld itself unconditionally ("For PIE and dyld,
#                         slide everything by the ASLR offset", mach_loader.c);
#   MH_KEXT_BUNDLE        relocated by the kernel's linker.
_ALWAYS_RELOCATED = {
    MH_DYLIB: "a dylib is mapped by dyld at an address dyld chooses",
    MH_BUNDLE: "a bundle is mapped by dyld at an address dyld chooses",
    MH_DYLINKER: "the kernel slides the dynamic linker on every exec, whatever its flags",
    MH_KEXT_BUNDLE: "a kernel extension is relocated by the kernel's linker",
}


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

    # 1. PIE (Position Independent Executable). MH_PIE is read by the kernel for
    #    MH_EXECUTE only; for every other file type the check does not apply.
    has_pie_flag = bool(flags & MH_PIE)
    pie_applicable = filetype == MH_EXECUTE
    is_pie = has_pie_flag if pie_applicable else filetype in _ALWAYS_RELOCATED

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
    is_arm64e = (cputype == CPU_TYPE_ARM64) and is_arm64e_subtype(cpusubtype)
    chained_ptr_fmt = (
        dyld_info.get("chained_fixups", {}).get("pointer_format", "")
        if dyld_info.get("chained_fixups")
        else ""
    )
    has_arm64e_chains = "ARM64E" in chained_ptr_fmt
    pac_enabled = is_arm64e or has_arm64e_chains

    # 4. RWX Segments & __RESTRICT Check
    #    initprot is what the segment is mapped with; maxprot is only a ceiling for
    #    later vm_protect calls. A segment is "writable and executable" when initprot
    #    has both bits. maxprot alone permitting both (the default for __TEXT in
    #    Intel binaries from older linkers) is reported as a note, not a failure:
    #    such a segment is mapped r-x and runs normally.
    rwx_segments: List[str] = []
    rwx_maxprot_only: List[str] = []
    has_restrict_segment = False
    for seg in segments:
        segname = seg.get("segname", "")
        init_raw = seg.get("initprot_raw", 0)
        max_raw = seg.get("maxprot_raw", 0)
        if (init_raw & _WX) == _WX:
            rwx_segments.append(f"{segname} ({seg.get('initprot')}/{seg.get('maxprot')})")
        elif (max_raw & _WX) == _WX:
            rwx_maxprot_only.append(f"{segname} ({seg.get('initprot')}/{seg.get('maxprot')})")
        if segname == "__RESTRICT":
            has_restrict_segment = True
        for sect in seg.get("sections", []):
            if sect.get("segname") == "__RESTRICT" or sect.get("sectname") == "__restrict":
                has_restrict_segment = True

    if flags & MH_ALLOW_STACK_EXECUTION:
        rwx_segments.append("STACK (MH_ALLOW_STACK_EXECUTION)")

    # A relocatable object keeps everything in one unnamed segment that the compiler
    # marks rwx, and a dSYM's segments have no contents; neither is ever mapped as-is,
    # so their protection fields are not mapping requests.
    prot_applicable = filetype not in (MH_OBJECT, MH_DSYM)
    if not prot_applicable:
        rwx_segments, rwx_maxprot_only = [], []

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
    ft_name = FILETYPE_INFO.get(filetype, (f"file type 0x{filetype:x}", ""))[0]
    pie_title = "Position Independent Executable (MH_PIE)"
    if filetype == MH_PRELOAD:
        checks.append({
            "id": "pie",
            "title": pie_title,
            "status": "INFO",
            "value": "MH_PRELOAD (Fixed Base Firmware)",
            "detail": "Standalone firmware image linked at fixed physical/virtual base address.",
        })
    elif not pie_applicable:
        why = _ALWAYS_RELOCATED.get(filetype)
        checks.append({
            "id": "pie",
            "title": pie_title,
            "status": "INFO",
            "value": f"Not applicable ({ft_name})",
            "detail": (
                f"MH_PIE is a flag of main executables (MH_EXECUTE); it has no meaning for {ft_name}: {why}."
                if why
                else f"MH_PIE is a flag of main executables (MH_EXECUTE). {ft_name} is not an image that the kernel "
                     "or dyld loads as a program, so load-address randomisation does not apply to this file."
            ),
        })
    elif is_pie:
        checks.append({
            "id": "pie",
            "title": pie_title,
            "status": "PASS",
            "value": "Enabled",
            "detail": "MH_PIE (0x200000) is set, so the kernel loads the main executable at a random slide.",
        })
    else:
        checks.append({
            "id": "pie",
            "title": pie_title,
            "status": "FAIL",
            "value": "Disabled (Fixed Address)",
            "detail": "MH_PIE flag is not set; the main executable is mapped at its linked address with no ASLR slide (dyld and system libraries are still slid). XNU does not run a dynamically linked arm64 executable without MH_PIE.",
        })

    # Check 2: Stack Canary
    if has_canary:
        checks.append({
            "id": "stack_canary",
            "title": "Stack Smashing Protection (Canary)",
            "status": "PASS",
            "value": "Present (___stack_chk_guard)",
            "detail": "The image references the stack-protector symbols, so at least one function checks a stack canary before returning. Functions the compiler judged not to need one are not instrumented.",
        })
    else:
        checks.append({
            "id": "stack_canary",
            "title": "Stack Smashing Protection (Canary)",
            "status": "INFO" if filetype != MH_PRELOAD else "WARN",
            "value": "Not Detected",
            "detail": "No ___stack_chk_fail / ___stack_chk_guard reference found: built with -fno-stack-protector, no function has the local arrays that trigger instrumentation, or the symbol names are gone (stripped static or firmware image).",
        })

    # Check 3: PAC / ARM64e
    if pac_enabled:
        checks.append({
            "id": "pac",
            "title": "Pointer Authentication (ARM64e PAC)",
            "status": "PASS",
            "value": f"ARM64e ({chained_ptr_fmt or 'Hardware PAC'})",
            "detail": "arm64e slice: return addresses and code pointers are signed with ARMv8.3-A pointer authentication, and pointers in data are signed through authenticated chained fixups.",
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
            "detail": "Pointer authentication is an AArch64 (ARMv8.3-A) feature; on Apple platforms it is used by the arm64e ABI.",
        })

    # Check 4: W^X / RWX Memory Hygiene
    if not prot_applicable:
        checks.append({
            "id": "rwx",
            "title": "W^X Memory Protection Hygiene",
            "status": "INFO",
            "value": f"Not applicable ({ft_name})",
            "detail": (
                "A relocatable object file holds all its sections in one unnamed segment whose protection the compiler sets to rwx. "
                "The static linker redistributes those sections into the output's segments; this segment is never mapped."
                if filetype == MH_OBJECT
                else "A dSYM companion file repeats the segment layout of the binary it describes but carries only debug "
                     "information; it is not mapped for execution."
            ),
        })
    elif has_rwx:
        checks.append({
            "id": "rwx",
            "title": "W^X Memory Protection Hygiene",
            "status": "FAIL",
            "value": f"RWX Detected: {', '.join(rwx_segments)}",
            "detail": "A segment asks to be mapped writable and executable at once (both bits in initprot), or the header requests an executable stack. Bytes written to such memory can be run as code if the kernel grants the mapping."
            + (f" In addition, maxprot allows both for: {', '.join(rwx_maxprot_only)}." if rwx_maxprot_only else ""),
        })
    elif rwx_maxprot_only:
        checks.append({
            "id": "rwx",
            "title": "W^X Memory Protection Hygiene",
            "status": "INFO",
            "value": f"No W+X mapping requested; maxprot allows it for {', '.join(rwx_maxprot_only)}",
            "detail": "No segment is mapped writable and executable (initprot). For the segments listed, maxprot contains both bits: that is only the ceiling a later vm_protect / mprotect call may raise the protection to, and was the linker default for __TEXT in older Intel binaries. The segment itself is mapped as initprot says.",
        })
    else:
        checks.append({
            "id": "rwx",
            "title": "W^X Memory Protection Hygiene",
            "status": "PASS",
            "value": "No W+X segment requested",
            "detail": "No segment combines VM_PROT_WRITE and VM_PROT_EXECUTE in initprot or maxprot, and MH_ALLOW_STACK_EXECUTION is clear.",
        })

    # Check 5: ARC (Objective-C / Swift Memory Management)
    if has_arc:
        checks.append({
            "id": "arc",
            "title": "Automatic Reference Counting (ARC)",
            "status": "PASS",
            "value": "ARC runtime calls present",
            "detail": "References Objective-C retain/release runtime entry points. objc_storeStrong and objc_retainAutoreleasedReturnValue indicate ARC; objc_retain/objc_release alone can also come from manual retain/release code. This is not an exploit mitigation.",
        })
    else:
        checks.append({
            "id": "arc",
            "title": "Automatic Reference Counting (ARC)",
            "status": "INFO",
            "value": "No ARC runtime calls",
            "detail": "No Objective-C ARC retain/release symbols referenced (C, C++, pure Swift, or manual retain/release through objc_msgSend).",
        })

    # Check 6: Dyld Injection Hardening (__RESTRICT / Hardened Runtime)
    # dyld takes these decisions from the main executable of the process (its
    # __RESTRICT section and its code-signing flags); the absence of the markers in
    # any other kind of image is not a weakness of that image.
    if filetype != MH_EXECUTE and not (has_restrict_segment or hardened_runtime or library_validation):
        checks.append({
            "id": "restrict",
            "title": "Dyld Environment & Injection Hardening",
            "status": "INFO",
            "value": f"Not applicable ({ft_name})",
            "detail": "Whether dyld honours DYLD_* environment variables and whether library validation applies is decided by the main executable of the process (its __RESTRICT,__restrict section and the flags of its code signature), not by this image.",
        })
    elif has_restrict_segment or hardened_runtime or library_validation:
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
            "detail": "Hardened runtime, CS_RESTRICT and a __RESTRICT,__restrict section make dyld ignore DYLD_* environment variables; library validation makes the kernel refuse dylibs not signed by Apple or the same team. Entitlements (allow-dyld-environment-variables, disable-library-validation) can switch these off and are not considered here.",
        })
    else:
        checks.append({
            "id": "restrict",
            "title": "Dyld Environment & Injection Hardening",
            "status": "WARN",
            "value": "No __RESTRICT / CS_RUNTIME / library validation",
            "detail": "No __RESTRICT,__restrict section, and the signature sets none of CS_RUNTIME, CS_RESTRICT or library validation, so DYLD_INSERT_LIBRARIES is honoured unless something else restricts the process (setuid, SIP-protected platform binary).",
        })

    # Check 7: RPATH Hygiene
    if not rpaths:
        checks.append({
            "id": "rpath",
            "title": "Dynamic Runpath (@rpath) Hygiene",
            "status": "PASS",
            "value": "No LC_RPATH entries",
            "detail": "This image adds no run-path search directories. Its dependencies can still be named relative to @executable_path or @loader_path, or use @rpath resolved through the LC_RPATHs of the images that loaded it.",
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
                f"The code-page hashes checked against the CodeDirectory match the file ({cd.get('n_code_slots')} code slots); CDHash {cd.get('cdhash')}. The CMS signature and certificate chain are not evaluated here."
                if verified
                else f"CodeDirectory present (CDHash {cd.get('cdhash')}) but one or more code-page hashes do not match the file; where code-signing enforcement applies (all code on Apple silicon and iOS) the kernel kills the process when such a page is faulted in."
            ),
        })
    else:
        checks.append({
            "id": "codesign",
            "title": "Code Signature & CDHash Integrity",
            "status": "FAIL" if filetype == MH_EXECUTE else "INFO",
            "value": "Unsigned (No LC_CODE_SIGNATURE)",
            "detail": "No LC_CODE_SIGNATURE load command. Apple silicon macOS refuses to run native arm64 code that is not at least ad hoc signed; iOS requires a signature for all code.",
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
        "pie_applicable": pie_applicable,
        "rwx_maxprot_only": rwx_maxprot_only,
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
