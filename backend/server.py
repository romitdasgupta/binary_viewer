"""
ThreadingHTTPServer REST API Router & Static Web IDE Asset Server.
Implements all locked endpoints in ADR-001-MACHO-VIEWER Section 4.
"""

import base64
import json
import mimetypes
import os
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from .fixtures import ensure_fixtures
from .service import AnalysisService


def _first_param(qs: Dict[str, Any], key: str, default: Optional[str] = None) -> Optional[str]:
    vals = qs.get(key)
    if vals and len(vals) > 0:
        return vals[0]
    return default


def _int_param(qs: Dict[str, Any], key: str, default: int = 0) -> int:
    raw = _first_param(qs, key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw, 16) if raw.lower().startswith("0x") else int(raw, 0)
    except ValueError:
        return default


class BinaryStudioRequestHandler(BaseHTTPRequestHandler):
    service: AnalysisService = None  # Attached by create_server()
    static_dir: str = ""

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy per-request console logs unless error
        pass

    def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Filename")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Filename")
        self.end_headers()

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        route = parsed_url.path
        qs = parse_qs(parsed_url.query)

        try:
            if route == "/api/presets":
                self._send_json(200, {"presets": self.service.get_presets()})
                return

            elif route == "/api/parse":
                path = _first_param(qs, "path")
                if not path:
                    self._send_json(400, {"error": "Missing required 'path' query parameter."})
                    return
                doc = self.service.load_file(path)
                self._send_json(200, doc)
                return

            elif route == "/api/hex":
                offset = _int_param(qs, "offset", 0)
                length = _int_param(qs, "length", 4096)
                slice_index = _int_param(qs, "slice_index", 0)
                path = _first_param(qs, "path")
                res = self.service.get_hex_slice(
                    offset=offset, length=length, slice_index=slice_index, path=path
                )
                self._send_json(200, res)
                return

            elif route == "/api/decode":
                offset = _int_param(qs, "offset", 0)
                slice_index = _int_param(qs, "slice_index", 0)
                endian = _first_param(qs, "endian", "little") or "little"
                path = _first_param(qs, "path")
                res = self.service.decode_bytes_at(
                    offset=offset, slice_index=slice_index, endian=endian, path=path
                )
                self._send_json(200, res)
                return

            elif route == "/api/translate":
                slice_index = _int_param(qs, "slice_index", 0)
                mode = _first_param(qs, "mode", "auto") or "auto"
                query = (
                    _first_param(qs, "query")
                    or _first_param(qs, "vmaddr")
                    or _first_param(qs, "abs_offset")
                    or _first_param(qs, "slice_offset")
                    or "0"
                )
                if _first_param(qs, "vmaddr") is not None and mode == "auto":
                    mode = "vmaddr"
                elif _first_param(qs, "abs_offset") is not None and mode == "auto":
                    mode = "abs_offset"
                elif _first_param(qs, "slice_offset") is not None and mode == "auto":
                    mode = "slice_offset"

                path = _first_param(qs, "path")
                res = self.service.translate_address(
                    slice_index=slice_index, query=query, mode=mode, path=path
                )
                self._send_json(200, res)
                return

            elif route == "/api/disassemble":
                slice_index = _int_param(qs, "slice_index", 0)
                vmaddr = _first_param(qs, "vmaddr")
                section = _first_param(qs, "section")
                count = _int_param(qs, "count", 200)
                path = _first_param(qs, "path")
                res = self.service.disassemble(
                    slice_index=slice_index,
                    vmaddr=vmaddr,
                    section=section,
                    count=count,
                    path=path,
                )
                self._send_json(200, res)
                return

            elif route == "/api/search":
                q = _first_param(qs, "q", "") or ""
                slice_index = _int_param(qs, "slice_index", 0)
                scope = _first_param(qs, "scope", "all") or "all"
                path = _first_param(qs, "path")
                res = self.service.search(
                    query=q, slice_index=slice_index, scope=scope, path=path
                )
                self._send_json(200, res)
                return

            # Static asset serving
            self._serve_static(route)

        except FileNotFoundError as e:
            self._send_json(404, {"error": str(e)})
        except ValueError as e:
            self._send_json(400, {"error": str(e)})
        except Exception as e:
            self._send_json(500, {"error": str(e), "trace": traceback.format_exc()})

    def do_POST(self) -> None:
        parsed_url = urlparse(self.path)
        route = parsed_url.path

        try:
            content_len = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_len) if content_len > 0 else b""

            if route == "/api/parse":
                body_json = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                path = body_json.get("path", "")
                if not path:
                    self._send_json(400, {"error": "Missing 'path' in JSON body."})
                    return
                doc = self.service.load_file(path)
                self._send_json(200, doc)
                return

            elif route == "/api/upload":
                content_type = self.headers.get("Content-Type", "")
                filename = self.headers.get("X-Filename", "uploaded_binary")
                if "application/json" in content_type:
                    body_json = json.loads(raw_body.decode("utf-8"))
                    filename = body_json.get("filename", filename)
                    b64_str = body_json.get("data_base64", "")
                    file_bytes = base64.b64decode(b64_str)
                else:
                    file_bytes = raw_body

                if not file_bytes:
                    self._send_json(400, {"error": "Empty binary upload payload."})
                    return
                doc = self.service.load_uploaded_bytes(filename, file_bytes)
                self._send_json(200, doc)
                return

            else:
                self._send_json(404, {"error": f"Unknown POST endpoint: {route}"})

        except FileNotFoundError as e:
            self._send_json(404, {"error": str(e)})
        except ValueError as e:
            self._send_json(400, {"error": str(e)})
        except Exception as e:
            self._send_json(500, {"error": str(e), "trace": traceback.format_exc()})

    def _serve_static(self, route: str) -> None:
        rel_path = "index.html" if route in ("/", "/index.html") else route.lstrip("/")
        if rel_path.startswith("static/"):
            rel_path = rel_path[len("static/"):]
        safe_path = os.path.normpath(os.path.join(self.static_dir, rel_path))
        if not safe_path.startswith(os.path.abspath(self.static_dir)) or not os.path.isfile(safe_path):
            self._send_json(404, {"error": f"Asset not found: {route}"})
            return

        ctype, _ = mimetypes.guess_type(safe_path)
        if not ctype:
            ctype = "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"

        with open(safe_path, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)


MachOViewerRequestHandler = BinaryStudioRequestHandler


def create_server(
    workspace_root: str,
    host: str = "127.0.0.1",
    port: int = 8421,
    initial_file: Optional[str] = None,
) -> ThreadingHTTPServer:
    ensure_fixtures(workspace_root)
    service = AnalysisService(workspace_root)
    if initial_file and os.path.isfile(initial_file):
        service.load_file(initial_file)

    static_dir = os.path.join(os.path.abspath(workspace_root), "static")

    class BoundHandler(BinaryStudioRequestHandler):
        pass

    BoundHandler.service = service
    BoundHandler.static_dir = static_dir

    server = ThreadingHTTPServer((host, port), BoundHandler)
    return server
