#!/usr/bin/env python3
"""
Mach-O File Viewer & Systems/Firmware Analysis Engine.
Unified CLI Inspector & Desktop Web IDE Server Launcher.
"""

import argparse
import json
import os
import sys
import webbrowser
from typing import Any, Dict

from backend.fixtures import ensure_fixtures
from backend.server import create_server
from backend.service import AnalysisService


def _resolve_slice_index(doc: Dict[str, Any], slice_arg: str) -> int:
    slices = doc.get("slices", [])
    if not slices:
        return 0
    if slice_arg.isdigit():
        idx = int(slice_arg)
        return max(0, min(idx, len(slices) - 1))
    s_lower = slice_arg.lower()
    for i, sl in enumerate(slices):
        if sl.get("arch_name", "").lower() == s_lower or s_lower in sl.get("arch_name", "").lower():
            return i
    return 0


def _print_cli_summary(
    service: AnalysisService,
    doc: Dict[str, Any],
    slice_idx: int,
    disasm_addr: str = None,
    translate_addr: str = None,
) -> None:
    fi = doc["file_info"]
    sl = doc["slices"][slice_idx]
    ov = sl["overview"]
    sec = sl["security_posture"]
    sem = sl.get("semantic_layers", {})
    fmt_display = fi.get("format_display") or sl.get("format_display") or "Mach-O"

    print("=" * 78)
    print(f"Mach-O / ELF / PE Binary Analysis Report [{fmt_display}]: {fi['path']}")
    print("=" * 78)
    print(f"  Format      : {fmt_display} ({fi.get('format', 'MACHO')})")
    print(f"  File Size   : {fi['file_size']:,} bytes")
    print(f"  SHA-256     : {fi['sha256']}")
    print(f"  Container   : {'Universal (Fat) Binary' if fi['is_fat'] else f'Single-Architecture {fmt_display}'}")
    if fi["is_fat"] and fi["fat_header"]:
        archs_str = ", ".join(
            f"#{s['slice_index']} {s['arch_name']} (off=0x{s['offset']:x}, sz={s['size']:,})"
            for s in fi["fat_header"]["slices_summary"]
        )
        print(f"  Fat Slices  : {archs_str}")

    print("-" * 78)
    print(f"  Active Slice: #{slice_idx} [{sl['arch_name']}] — {ov['arch_display']}")
    print(f"  File Type   : {ov['filetype_name']} ({ov['filetype_desc']})")
    print(f"  Header Flags: {', '.join(sl['header']['flags_decoded']) or '0x0'}")
    print(f"  UUID / ID   : {ov['uuid'] or 'None'}")
    print(f"  Platform    : {ov['platform']} (minOS: {ov['minos'] or 'N/A'}, SDK: {ov['sdk'] or 'N/A'})")
    print(f"  Entry Point : {ov['entry_point_vmaddr']} (abs offset 0x{ov['entry_point_abs_offset']:x}, via {ov['entry_point_type']})")
    print(
        f"  Counts      : {ov['segments_count']} segments, {ov['sections_count']} sections, "
        f"{ov['symbols_count']} symbols, {ov['strings_count']} strings, {ov['dylibs_count']} dylibs"
    )

    if sem:
        ent = sem.get("entropy_analysis", {})
        caps = sem.get("capabilities", {})
        prov = sem.get("provenance", {})
        anom = sem.get("anomalies", {})
        print("-" * 78)
        print("  Semantic Intelligence & Provenance:")
        print(
            f"    Overall Entropy : {ent.get('overall_entropy', 0.0):.2f} bits/byte "
            f"[{ent.get('overall_classification', 'N/A')}] — {ent.get('packing_assessment', '')}"
        )
        print(
            f"    Provenance      : {prov.get('compiler_family', 'Unknown')} | "
            f"Lang: {', '.join(prov.get('source_languages', []))} | Strip: {prov.get('strip_level', 'Unknown')}"
        )
        active_caps = [c["title"] for c in caps.get("categories", [])]
        print(f"    Capabilities    : {', '.join(active_caps) if active_caps else 'Minimal / Standard Runtime Only'}")
        print(f"    Anomalies       : {anom.get('total_count', 0)} structural findings")

    print("-" * 78)
    print("  Segments & Sections:")
    for seg in sl["segments"]:
        print(
            f"    [{seg['segname']:<15}] VM {seg['vmaddr']:<14} + {seg['vmsize']:<10} | "
            f"File 0x{seg['fileoff']:06x} + 0x{seg['filesize']:06x} | Prot {seg['initprot']}/{seg['maxprot']}"
        )
        for sect in seg["sections"]:
            print(
                f"      └─ {sect['sectname']:<16} VM {sect['vmaddr']:<14} sz={sect['size']:<8} "
                f"off=0x{sect['slice_offset']:06x} ({sect['section_type']})"
            )

    print("-" * 78)
    print("  Security & Firmware Hardening Scorecard:")
    for chk in sec["checks"]:
        print(f"    [{chk['status']:<4}] {chk['title']:<44}: {chk['value']}")

    if translate_addr:
        print("-" * 78)
        tr = service.translate_address(slice_index=slice_idx, query=translate_addr, mode="auto")
        print(f"  Address Translation ({translate_addr}):")
        print(f"    Status      : {tr['status']} (resolved mode: {tr['mode_resolved']})")
        print(f"    VMAddr / RVA: {tr['vmaddr']} (RVA {tr['rva']})")
        print(f"    File Offsets: slice_offset={tr['slice_offset']}, abs_offset={tr['abs_offset']}")
        if tr["segment"]:
            print(f"    Segment     : {tr['segment']['segname']} ({tr['segment']['initprot']})")
        if tr["section"]:
            print(f"    Section     : {tr['section']['segname']},{tr['section']['sectname']}")
        if tr["nearest_symbol"]:
            print(f"    Symbol      : {tr['nearest_symbol']['display']}")

    if disasm_addr is not None:
        print("-" * 78)
        vm_arg = None if disasm_addr in ("", "entry", "default") else disasm_addr
        dis = service.disassemble(slice_index=slice_idx, vmaddr=vm_arg, count=32)
        print(f"  Disassembly Preview ({dis['section']} @ {dis['start_vmaddr']}):")
        for ins in dis["instructions"]:
            if ins.get("symbol_label"):
                print(f"\n  {ins['symbol_label']}:")
            cmt = f"  ; {ins['comment']}" if ins.get("comment") else ""
            print(
                f"    {ins['vmaddr']}:  {ins['raw_hex']:<14}  {ins['mnemonic']:<8} {ins['operands']:<28}{cmt}"
            )
    print("=" * 78)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mach-O File Viewer & Firmware Binary Analysis Engine"
    )
    parser.add_argument(
        "--cli",
        metavar="FILE",
        help="Run in headless CLI inspection mode on the given Mach-O file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output canonical MachODocument JSON in --cli mode",
    )
    parser.add_argument(
        "--slice",
        default="0",
        help="Select architecture slice by index (0, 1) or arch name (arm64, arm64e, x86_64)",
    )
    parser.add_argument(
        "--disasm",
        nargs="?",
        const="entry",
        default=None,
        help="Disassemble instructions at entry point or specified VMAddr in --cli mode",
    )
    parser.add_argument(
        "--translate",
        default=None,
        help="Translate a VMAddr or File Offset in --cli mode",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP server bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8421,
        help="HTTP server port (default: 8421)",
    )
    parser.add_argument(
        "--file",
        default=None,
        help="Preload a specific Mach-O binary when starting the web server",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Automatically open the Web IDE in the default browser",
    )

    args = parser.parse_args()
    workspace_root = os.path.dirname(os.path.abspath(__file__))

    if args.cli:
        ensure_fixtures(workspace_root)
        service = AnalysisService(workspace_root)
        doc = service.load_file(args.cli)
        slice_idx = _resolve_slice_index(doc, args.slice)

        if args.json:
            if args.translate:
                out = service.translate_address(slice_index=slice_idx, query=args.translate)
            elif args.disasm is not None:
                vm_arg = None if args.disasm in ("", "entry", "default") else args.disasm
                out = service.disassemble(slice_index=slice_idx, vmaddr=vm_arg, count=64)
            else:
                out = doc
            print(json.dumps(out, indent=2))
        else:
            _print_cli_summary(
                service,
                doc,
                slice_idx=slice_idx,
                disasm_addr=args.disasm,
                translate_addr=args.translate,
            )
        return 0

    # Web IDE Server Mode
    server = create_server(
        workspace_root=workspace_root,
        host=args.host,
        port=args.port,
        initial_file=args.file,
    )
    url = f"http://{args.host}:{args.port}"
    print(f"Mach-O Viewer Server listening on {url}")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Mach-O Viewer Server.")
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
