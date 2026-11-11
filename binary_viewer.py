#!/usr/bin/env python3
"""
BinaryStudio — Multi-Format Binary Inspector, Semantic Intelligence & Systems Learning Suite.
Supports Apple Mach-O (32/64 & Universal Fat), Linux ELF32/64, and Windows PE32/PE32+ Binaries.
Unified CLI Inspector & Web IDE Server Launcher.

  python3 binary_viewer.py                       local web UI on http://127.0.0.1:8421
  python3 binary_viewer.py --cli FILE [--json]   inspect a file in the terminal
  python3 binary_viewer.py --public ...          host it for other people (see --help)
"""

import argparse
import json
import os
import signal
import sys
import webbrowser
from typing import Any, Dict, List, Optional

from backend import runtime
from backend.api import LOG, is_loopback_host
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
    print(f"BinaryStudio — Multi-Format Binary Analysis Report [{fmt_display}]: {fi['path']}")
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


def _env_help() -> str:
    lines = [
        "environment variables (a command-line flag wins over its variable):",
    ]
    for name, _attr, _convert, text in runtime.ENV_VARS:
        lines.append(f"  {name}")
        lines.append(f"      {text}")
    lines += [
        "",
        "modes:",
        "  local (default)  One trusted user on this machine. Can open any file this user can",
        "                   read and may run objdump / c++filt. Listens on loopback only.",
        "  public (--public) For hosting on a network. No access to server files, no external",
        "                   tools, uploads addressed by unguessable ids and dropped when idle,",
        "                   rate limits and bounded memory. Serves plain HTTP: put a TLS reverse",
        "                   proxy in front, name your domain with --allowed-host and, when the",
        "                   proxy sets X-Forwarded-For, pass --trust-proxy. See deploy/.",
    ]
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BinaryStudio — Multi-Format Binary Inspector & Disassembler (Mach-O, ELF32/64, Windows PE32/PE32+)",
        epilog=_env_help(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    cli = parser.add_argument_group("command-line inspection")
    cli.add_argument(
        "--cli",
        metavar="FILE",
        help="Run in headless CLI inspection mode on the given Mach-O, ELF32/64, or Windows PE binary",
    )
    cli.add_argument(
        "--json",
        action="store_true",
        help="Output canonical BinaryDocument JSON in --cli mode",
    )
    cli.add_argument(
        "--slice",
        default="0",
        help="Select architecture slice by index (0, 1) or arch name (arm64, arm64e, x86_64)",
    )
    cli.add_argument(
        "--disasm",
        nargs="?",
        const="entry",
        default=None,
        help="Disassemble instructions at entry point or specified VMAddr in --cli mode",
    )
    cli.add_argument(
        "--translate",
        default=None,
        help="Translate a VMAddr or File Offset in --cli mode",
    )

    web = parser.add_argument_group("web server")
    web.add_argument(
        "--host",
        default=None,
        help="HTTP server bind address (default: 127.0.0.1)",
    )
    web.add_argument(
        "--port",
        type=int,
        default=None,
        help="HTTP server port (default: 8421; 0 picks a free port)",
    )
    web.add_argument(
        "--file",
        default=None,
        help="Preload a specific Mach-O, ELF, or PE binary when starting the web server (local mode)",
    )
    web.add_argument(
        "--open",
        action="store_true",
        help="Automatically open BinaryStudio Web IDE in the default browser",
    )
    web.add_argument(
        "--debug",
        action="store_true",
        help="Local mode only: include Python tracebacks in error responses",
    )
    web.add_argument(
        "--access-log",
        action="store_true",
        default=None,
        help="Log one line per request to stderr (always on with --public)",
    )
    web.add_argument(
        "--i-know-this-is-unsafe",
        dest="unsafe_bind",
        action="store_true",
        help="Allow local mode on a non-loopback --host. Everyone who can reach the port can then "
             "read every file you can. You almost certainly want --public instead",
    )

    public = parser.add_argument_group("public hosting")
    public.add_argument(
        "--public",
        action="store_true",
        help="Run in public mode: safe to expose behind a TLS reverse proxy (see 'modes' below)",
    )
    public.add_argument(
        "--allowed-host",
        action="append",
        default=None,
        metavar="NAME",
        help="A Host name this server answers to, e.g. binarystudio.example.com; repeat for more. "
             "A leading dot matches subdomains; '*' accepts any. Loopback names are always accepted",
    )
    public.add_argument(
        "--trust-proxy",
        action="store_true",
        default=None,
        help="Take each client's address from the last X-Forwarded-For entry. Only for use behind "
             "a reverse proxy that sets it; the port must not be reachable any other way",
    )
    public.add_argument(
        "--max-upload-mb",
        type=float,
        default=None,
        metavar="N",
        help="Largest accepted upload in MiB (default: 32 public, 256 local)",
    )
    public.add_argument(
        "--csp-extra",
        default=None,
        metavar="POLICY",
        help="Sources to add to the page Content-Security-Policy, e.g. "
             "\"script-src 'wasm-unsafe-eval'; frame-src https://ads.example\"",
    )
    return parser


def _run_cli(args: argparse.Namespace, workspace_root: str) -> int:
    ensure_fixtures(workspace_root)
    service = AnalysisService(workspace_root, runtime.RuntimeConfig("local"))
    try:
        doc = service.load_file(args.cli)
    except (runtime.ApiError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
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


def _display_url(host: str, port: int) -> str:
    shown = "127.0.0.1" if host in ("0.0.0.0", "") else ("[::1]" if host == "::" else host)
    if ":" in shown and not shown.startswith("["):
        shown = f"[{shown}]"
    return f"http://{shown}:{port}"


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    workspace_root = os.path.dirname(os.path.abspath(__file__))

    if args.cli:
        return _run_cli(args, workspace_root)

    # Web IDE Server Mode
    env = os.environ
    env_mode = (env.get("BINARYSTUDIO_MODE") or "local").strip().lower()
    if env_mode not in ("local", "public"):
        parser.error(f"BINARYSTUDIO_MODE must be 'local' or 'public', not {env_mode!r}")
    mode = "public" if args.public else env_mode

    overrides: Dict[str, Any] = {}
    if args.max_upload_mb is not None:
        if args.max_upload_mb <= 0:
            parser.error("--max-upload-mb must be greater than zero")
        overrides["max_upload_bytes"] = int(args.max_upload_mb * 1024 * 1024)
    if args.trust_proxy:
        overrides["trust_proxy_headers"] = True
    if args.allowed_host:
        overrides["allowed_hosts"] = list(args.allowed_host)
    if args.access_log:
        overrides["access_log"] = True
    if args.csp_extra is not None:
        overrides["csp_extra"] = args.csp_extra
    if args.unsafe_bind:
        overrides["allow_unsafe_bind"] = True
    if args.debug:
        if mode != "local":
            parser.error("--debug is only available in local mode")
        overrides["debug_errors"] = True
    if args.file and mode != "local":
        parser.error("--file is only available in local mode; public mode never opens server files")

    try:
        config = runtime.RuntimeConfig.from_env(mode, dict(env), **overrides)
    except ValueError as exc:
        parser.error(str(exc))
    runtime.set_config(config)

    host = args.host or (env.get("BINARYSTUDIO_HOST") or "").strip() or "127.0.0.1"
    port = args.port
    if port is None:
        try:
            port = int(env.get("BINARYSTUDIO_PORT") or 8421)
        except ValueError:
            parser.error("BINARYSTUDIO_PORT must be an integer")
    if not (0 <= port <= 65535):
        parser.error("--port must be between 0 and 65535")

    try:
        server = create_server(
            workspace_root=workspace_root,
            host=host,
            port=port,
            initial_file=args.file,
            config=config,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot listen on {host}:{port}: {exc}", file=sys.stderr)
        return 1

    port = server.server_address[1]
    url = _display_url(host, port)
    print(f"BinaryStudio Server listening on {url}", flush=True)
    if config.access_log:
        LOG.write(
            "info", "startup", mode=config.mode, host=host, port=port,
            allowed_hosts=server.app.allowed_hosts, trust_proxy=config.trust_proxy_headers,
            max_upload_bytes=config.max_upload_bytes, rate_limit_per_minute=config.rate_limit_per_minute,
            upload_rate_limit_per_minute=config.upload_rate_limit_per_minute,
            max_concurrent_parses=config.max_concurrent_parses, doc_ttl_seconds=config.doc_ttl_seconds,
            cache_max_docs=config.cache_max_docs, cache_max_bytes=config.cache_max_bytes,
            parse_workers=config.parse_worker_count(), parse_worker_memory_bytes=config.parse_worker_memory_bytes,
        )
    # Analyses run in worker processes when configured (the default with --public);
    # start them now rather than on the first upload.
    server.prewarm_workers()
    if config.mode == "public":
        if not config.allowed_hosts:
            LOG.write("warn", "config", message="No --allowed-host given: only loopback Host names are "
                      "accepted, so requests for your domain will get 403 until you add it.")
        if not is_loopback_host(host) and not config.trust_proxy_headers:
            LOG.write("warn", "config", message="Listening on a non-loopback address without --trust-proxy: "
                      "this server speaks plain HTTP. Put a TLS reverse proxy in front (see deploy/).")
    elif not is_loopback_host(host):
        LOG.write("warn", "config", message="LOCAL MODE ON A NETWORK ADDRESS: anyone who can reach this "
                  "port can read any file this user can read.")

    def _terminate(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, _terminate)
    except (ValueError, OSError, AttributeError):
        pass

    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down BinaryStudio Server.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
