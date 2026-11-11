"""
Tests for the patch / experiment / builder / compare labs (backend/labs_patch.py).

What is pinned down here:

  * patch application: order, overlap, bounds, the byte and entry limits
  * the original document is never altered, derived ids are capabilities of
    their own, and one upload's derived copy cannot reach another upload
  * the structural diff: every guided experiment, applied to the fixture it
    belongs to, produces exactly the audit / field / consequence changes in
    EXPECTED (and nothing else in those categories)
  * a patched file that no longer parses still yields a document and says what broke
  * checksums and hashes recomputed from bytes (PE checksum against an
    independent implementation; Authenticode exclusions; Mach-O page hashes)
  * the minimal-ELF builder, read back by the project's parser and by an
    independent struct decode, field by field (and by `file` / llvm-readobj when present)
  * abuse of /api/patch: huge, negative, overflowing, non-hex, thousands of entries, random junk

Nothing here executes a binary.
"""

import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from http.client import HTTPConnection

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKSPACE_ROOT)

from backend import labs_patch
from backend.api import ApiRequest, EventLog, build_router
from backend.fixtures import ensure_fixtures
from backend.parser import parse_macho_bytes
from backend.runtime import RuntimeConfig
from backend.server import create_server
from backend.service import AnalysisService

FIXTURES = ensure_fixtures(WORKSPACE_ROOT)
PRESETS = ["synthetic_elf64", "synthetic_elf32", "synthetic_pe64", "synthetic_pe32", "synthetic_universal", "synthetic_firmware"]


def fixture_bytes(preset: str) -> bytes:
    with open(FIXTURES[preset], "rb") as handle:
        return handle.read()


class _Null:
    def write(self, _text: str) -> None:
        pass

    def flush(self) -> None:
        pass


def make_router(mode: str = "local", **overrides):
    config = RuntimeConfig(mode, **overrides)
    service = AnalysisService(WORKSPACE_ROOT, config)
    return build_router(service, config, log=EventLog(stream=_Null())), service, config


def call(router, method, route, query=None, body=None, raw=None, client="198.51.100.9", headers=None):
    hdrs = dict(headers or {})
    payload = b""
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        hdrs.setdefault("content-type", "application/json")
    if raw is not None:
        payload = raw
    resp = router.handle(ApiRequest(method, route, query or {}, payload, hdrs, client))
    data = None
    if resp.content_type.startswith("application/json") and resp.body:
        data = json.loads(resp.body.decode("utf-8"))
    return resp, data


def upload(router, data: bytes, name: str = "sample.bin", client="198.51.100.9") -> str:
    resp, doc = call(router, "POST", "/api/upload", raw=data, client=client,
                     headers={"content-type": "application/octet-stream", "x-filename": name})
    assert resp.status == 200, (resp.status, doc)
    return doc["doc_id"]


def patch(router, doc, patches, **extra):
    return call(router, "POST", "/api/patch", body=dict({"doc": doc, "patches": patches}, **extra))


def download(router, doc) -> bytes:
    resp, _ = call(router, "GET", "/api/download", {"doc": doc})
    assert resp.status == 200, resp.status
    return resp.body


# (preset, slice index, experiment id) -> None when the experiment does not apply to that
# fixture, else exactly: the bytes it changes (offset, before, after), whether the result
# parses, every hardening check that changes (before status, after status), every decoded field
# whose bytes change, anomalies that appear, the consequence notes in order, Mach-O code pages
# that stop matching their hash, and the status of each slice.
EXPECTED = {('synthetic_elf64', 0, 'elf.code-writable'): {'patch': [(236, '05', '07')],
                                               'parse_ok': True,
                                               'security': {'rwx': ('PASS', 'FAIL')},
                                               'fields': [('Program header #3 PT_LOAD', 'p_flags')],
                                               'anomalies': ['rwx_memory'],
                                               'notes': ['elf.segment_wx'],
                                               'pages': [],
                                               'slices': [('x86_64', 'changed')]},
 ('synthetic_elf64', 0, 'elf.exec-stack'): {'patch': [(460, '06', '07')],
                                            'parse_ok': True,
                                            'security': {'nx_stack': ('PASS', 'FAIL')},
                                            'fields': [('Program header #7 PT_GNU_STACK', 'p_flags')],
                                            'anomalies': [],
                                            'notes': ['elf.stack_exec'],
                                            'pages': [],
                                            'slices': [('x86_64', 'changed')]},
 ('synthetic_elf64', 0, 'elf.no-pie'): {'patch': [(16, '03', '02')],
                                        'parse_ok': True,
                                        'security': {'pie': ('PASS', 'FAIL')},
                                        'fields': [('ELF header', 'e_type')],
                                        'anomalies': [],
                                        'notes': ['elf.et_exec', 'elf.et_exec_low'],
                                        'pages': [],
                                        'slices': [('x86_64', 'changed')]},
 ('synthetic_elf64', 0, 'elf.no-relro'): {'patch': [(512, '52e57464', '00000000')],
                                          'parse_ok': True,
                                          'security': {'relro': ('PASS', 'FAIL')},
                                          'fields': [('Program header #8 PT_GNU_RELRO', 'p_type')],
                                          'anomalies': [],
                                          'notes': ['elf.relro_gone'],
                                          'pages': [],
                                          'slices': [('x86_64', 'changed')]},
 ('synthetic_elf64', 0, 'elf.entry'): {'patch': [(24, '4010', '0020')],
                                       'parse_ok': True,
                                       'security': {},
                                       'fields': [('ELF header', 'e_entry')],
                                       'anomalies': ['ep_outside_exec_segment'],
                                       'notes': ['elf.entry', 'entry.not_executable'],
                                       'pages': [],
                                       'slices': [('x86_64', 'changed')]},
 ('synthetic_elf64', 0, 'elf.interp'): {'patch': [(602, '32', '58')],
                                        'parse_ok': True,
                                        'security': {},
                                        'fields': [('Program header #1 PT_INTERP', 'interpreter')],
                                        'anomalies': [],
                                        'notes': ['elf.interp_path'],
                                        'pages': [],
                                        'slices': [('x86_64', 'changed')]},
 ('synthetic_elf64', 0, 'elf.magic'): {'patch': [(1, '45', '00')],
                                       'parse_ok': False,
                                       'security': {},
                                       'fields': [('ELF header', 'e_ident[EI_MAG]')],
                                       'anomalies': [],
                                       'notes': ['parse.failed', 'elf.magic'],
                                       'pages': [],
                                       'slices': [('x86_64', 'unparsed')]},
 ('synthetic_elf64', 0, 'elf.endian'): {'patch': [(5, '01', '02')],
                                        'parse_ok': True,
                                        'security': {'pie': ('PASS', 'INFO'),
                                                     'relro': ('PASS', 'INFO'),
                                                     'nx_stack': ('PASS', 'INFO'),
                                                     'stack_canary': ('PASS', 'INFO'),
                                                     'cfi_cet_pac': ('PASS', 'INFO'),
                                                     'rpath': ('INFO', 'PASS'),
                                                     'build_id_symbols': ('PASS', 'INFO')},
                                        'fields': [('ELF header', 'e_ident[EI_DATA]')],
                                        'anomalies': [],
                                        'notes': ['elf.ei_data', 'entry.unmapped'],
                                        'pages': [],
                                        'slices': [('x86_64', 'changed')]},
 ('synthetic_elf64', 0, 'elf.section-bounds'): {'patch': [(9824, '40000000', 'f0ffff7f')],
                                                'parse_ok': True,
                                                'security': {},
                                                'fields': [('Section .text', 'sh_size')],
                                                'anomalies': [],
                                                'notes': ['elf.sections'],
                                                'pages': [],
                                                'slices': [('x86_64', 'changed')]},
 ('synthetic_elf32', 0, 'elf.code-writable'): {'patch': [(76, '05', '07')],
                                               'parse_ok': True,
                                               'security': {'rwx': ('PASS', 'FAIL')},
                                               'fields': [('Program header #0 PT_LOAD', 'p_flags')],
                                               'anomalies': ['rwx_memory'],
                                               'notes': ['elf.segment_wx'],
                                               'pages': [],
                                               'slices': [('i386', 'changed')]},
 ('synthetic_elf32', 0, 'elf.exec-stack'): None,
 ('synthetic_elf32', 0, 'elf.no-pie'): None,
 ('synthetic_elf32', 0, 'elf.no-relro'): None,
 ('synthetic_elf32', 0, 'elf.entry'): {'patch': [(24, '00', '01')],
                                       'parse_ok': True,
                                       'security': {},
                                       'fields': [('ELF header', 'e_entry')],
                                       'anomalies': [],
                                       'notes': ['elf.entry', 'entry.moved'],
                                       'pages': [],
                                       'slices': [('i386', 'changed')]},
 ('synthetic_elf32', 0, 'elf.interp'): None,
 ('synthetic_elf32', 0, 'elf.magic'): {'patch': [(1, '45', '00')],
                                       'parse_ok': False,
                                       'security': {},
                                       'fields': [('ELF header', 'e_ident[EI_MAG]')],
                                       'anomalies': [],
                                       'notes': ['parse.failed', 'elf.magic'],
                                       'pages': [],
                                       'slices': [('i386', 'unparsed')]},
 ('synthetic_elf32', 0, 'elf.endian'): {'patch': [(5, '01', '02')],
                                        'parse_ok': True,
                                        'security': {'pie': ('FAIL', 'INFO'),
                                                     'relro': ('FAIL', 'INFO'),
                                                     'nx_stack': ('FAIL', 'INFO'),
                                                     'build_id_symbols': ('INFO', 'INFO')},
                                        'fields': [('ELF header', 'e_ident[EI_DATA]')],
                                        'anomalies': [],
                                        'notes': ['elf.ei_data', 'entry.unmapped'],
                                        'pages': [],
                                        'slices': [('i386', 'changed')]},
 ('synthetic_elf32', 0, 'elf.section-bounds'): {'patch': [(2108, '20000000', 'f0ffff7f')],
                                                'parse_ok': True,
                                                'security': {},
                                                'fields': [('Section .text', 'sh_size')],
                                                'anomalies': [],
                                                'notes': ['elf.sections'],
                                                'pages': [],
                                                'slices': [('i386', 'changed')]},
 ('synthetic_pe64', 0, 'pe.no-aslr'): {'patch': [(350, '60', '20')],
                                       'parse_ok': True,
                                       'security': {'pie': ('PASS', 'FAIL'), 'high_entropy_va': ('PASS', 'WARN'), 'codesign': ('PASS', 'WARN')},
                                       'fields': [('PE headers', 'OptionalHeader.DllCharacteristics')],
                                       'anomalies': [],
                                       'notes': ['pe.dynamic_base_off', 'pe.checksum', 'pe.authenticode'],
                                       'pages': [],
                                       'slices': [('x86_64', 'changed')]},
 ('synthetic_pe64', 0, 'pe.no-nx'): {'patch': [(351, '41', '40')],
                                     'parse_ok': True,
                                     'security': {'dep_nx': ('PASS', 'INFO'), 'codesign': ('PASS', 'WARN')},
                                     'fields': [('PE headers', 'OptionalHeader.DllCharacteristics')],
                                     'anomalies': [],
                                     'notes': ['pe.nx_off', 'pe.checksum', 'pe.authenticode'],
                                     'pages': [],
                                     'slices': [('x86_64', 'changed')]},
 ('synthetic_pe64', 0, 'pe.no-cfg'): {'patch': [(351, '41', '01')],
                                      'parse_ok': True,
                                      'security': {'cfg': ('PASS', 'INFO'), 'codesign': ('PASS', 'WARN')},
                                      'fields': [('PE headers', 'OptionalHeader.DllCharacteristics')],
                                      'anomalies': [],
                                      'notes': ['pe.cfg_off', 'pe.checksum', 'pe.authenticode'],
                                      'pages': [],
                                      'slices': [('x86_64', 'changed')]},
 ('synthetic_pe64', 0, 'pe.section-writable'): {'patch': [(559, '60', 'e0')],
                                                'parse_ok': True,
                                                'security': {'rwx': ('PASS', 'FAIL'), 'codesign': ('PASS', 'WARN')},
                                                'fields': [('Segment .text', 'Characteristics')],
                                                'anomalies': ['rwx_memory'],
                                                'notes': ['pe.section_wx', 'pe.checksum', 'pe.authenticode'],
                                                'pages': [],
                                                'slices': [('x86_64', 'changed')]},
 ('synthetic_pe64', 0, 'pe.entry'): {'patch': [(297, '10', '20')],
                                     'parse_ok': True,
                                     'security': {'codesign': ('PASS', 'WARN')},
                                     'fields': [('PE headers', 'OptionalHeader.AddressOfEntryPoint')],
                                     'anomalies': ['ep_outside_exec_segment'],
                                     'notes': ['pe.entry', 'entry.not_executable', 'pe.checksum', 'pe.authenticode'],
                                     'pages': [],
                                     'slices': [('x86_64', 'changed')]},
 ('synthetic_pe64', 0, 'pe.tamper-signed'): {'patch': [(1536, '00', 'ff')],
                                             'parse_ok': True,
                                             'security': {'codesign': ('PASS', 'WARN')},
                                             'fields': [],
                                             'anomalies': [],
                                             'notes': ['pe.checksum', 'pe.authenticode'],
                                             'pages': [],
                                             'slices': [('x86_64', 'changed')]},
 ('synthetic_pe64', 0, 'pe.magic'): {'patch': [(0, '4d', '00')],
                                     'parse_ok': False,
                                     'security': {},
                                     'fields': [('Header #0 IMAGE_DOS_HEADER', 'e_magic')],
                                     'anomalies': [],
                                     'notes': ['parse.failed', 'pe.magic'],
                                     'pages': [],
                                     'slices': [('x86_64', 'unparsed')]},
 ('synthetic_pe64', 0, 'pe.section-bounds'): {'patch': [(617, '04', '53')],
                                              'parse_ok': True,
                                              'security': {'codesign': ('PASS', 'WARN')},
                                              'fields': [('Segment .reloc', 'SizeOfRawData')],
                                              'anomalies': [],
                                              'notes': ['pe.section_bounds', 'pe.checksum', 'pe.authenticode'],
                                              'pages': [],
                                              'slices': [('x86_64', 'changed')]},
 ('synthetic_pe32', 0, 'pe.no-aslr'): None,
 ('synthetic_pe32', 0, 'pe.no-nx'): None,
 ('synthetic_pe32', 0, 'pe.no-cfg'): None,
 ('synthetic_pe32', 0, 'pe.section-writable'): None,
 ('synthetic_pe32', 0, 'pe.entry'): {'patch': [(169, '10', '20')],
                                     'parse_ok': True,
                                     'security': {},
                                     'fields': [('PE headers', 'OptionalHeader.AddressOfEntryPoint')],
                                     'anomalies': ['ep_outside_exec_segment'],
                                     'notes': ['pe.entry', 'entry.not_executable', 'pe.checksum_never'],
                                     'pages': [],
                                     'slices': [('i386', 'changed')]},
 ('synthetic_pe32', 0, 'pe.tamper-signed'): {'patch': [(768, '00', 'ff')],
                                             'parse_ok': True,
                                             'security': {},
                                             'fields': [],
                                             'anomalies': [],
                                             'notes': ['pe.checksum_never'],
                                             'pages': [],
                                             'slices': [('i386', 'same')]},
 ('synthetic_pe32', 0, 'pe.magic'): {'patch': [(0, '4d', '00')],
                                     'parse_ok': False,
                                     'security': {},
                                     'fields': [('Header #0 IMAGE_DOS_HEADER', 'e_magic')],
                                     'anomalies': [],
                                     'notes': ['parse.failed', 'pe.magic'],
                                     'pages': [],
                                     'slices': [('i386', 'unparsed')]},
 ('synthetic_pe32', 0, 'pe.section-bounds'): {'patch': [(433, '02', '30')],
                                              'parse_ok': True,
                                              'security': {},
                                              'fields': [('Segment .rdata', 'SizeOfRawData')],
                                              'anomalies': [],
                                              'notes': ['pe.section_bounds', 'pe.checksum_never'],
                                              'pages': [],
                                              'slices': [('i386', 'changed')]},
 ('synthetic_universal', 0, 'macho.code-writable'): {'patch': [(16544, '05', '07'), (16548, '05', '07')],
                                                     'parse_ok': True,
                                                     'security': {'rwx': ('PASS', 'FAIL'), 'codesign': ('PASS', 'WARN')},
                                                     'fields': [('Load command #1 LC_SEGMENT_64', 'maxprot'), ('Load command #1 LC_SEGMENT_64', 'initprot')],
                                                     'anomalies': ['rwx_memory'],
                                                     'notes': ['macho.segment_wx', 'macho.dyld_segment_perms', 'macho.signature_pages'],
                                                     'pages': [('x86_64', [0])],
                                                     'slices': [('x86_64', 'changed'), ('arm64', 'same')]},
 ('synthetic_universal', 0, 'macho.no-pie'): {'patch': [(16410, 'a1', '81')],
                                              'parse_ok': True,
                                              'security': {'pie': ('PASS', 'FAIL'), 'codesign': ('PASS', 'WARN')},
                                              'fields': [('Mach-O header', 'flags')],
                                              'anomalies': [],
                                              'notes': ['macho.pie_off', 'macho.signature_pages'],
                                              'pages': [('x86_64', [0])],
                                              'slices': [('x86_64', 'changed'), ('arm64', 'same')]},
 ('synthetic_universal', 0, 'macho.entry'): {'patch': [(18216, 'b009', '0010')],
                                             'parse_ok': True,
                                             'security': {'codesign': ('PASS', 'WARN')},
                                             'fields': [('Load command #14 LC_MAIN', 'entryoff')],
                                             'anomalies': ['ep_outside_exec_segment'],
                                             'notes': ['macho.entry_main', 'entry.not_executable', 'macho.signature_pages'],
                                             'pages': [('x86_64', [0])],
                                             'slices': [('x86_64', 'changed'), ('arm64', 'same')]},
 ('synthetic_universal', 0, 'macho.tamper-page'): {'patch': [(18933, '45', 'ba')],
                                                   'parse_ok': True,
                                                   'security': {'codesign': ('PASS', 'WARN')},
                                                   'fields': [],
                                                   'anomalies': [],
                                                   'notes': ['macho.signature_pages'],
                                                   'pages': [('x86_64', [0])],
                                                   'slices': [('x86_64', 'changed'), ('arm64', 'same')]},
 ('synthetic_universal', 0, 'macho.magic'): {'patch': [(16384, 'cf', '30')],
                                             'parse_ok': True,
                                             'security': {},
                                             'fields': [('Mach-O header', 'magic')],
                                             'anomalies': [],
                                             'notes': ['macho.magic_slice'],
                                             'pages': [],
                                             'slices': [('x86_64', 'removed'), ('arm64', 'same')]},
 ('synthetic_universal', 0, 'macho.segment-bounds'): {'patch': [(17944, 'c00b', '80d7')],
                                                      'parse_ok': True,
                                                      'security': {'codesign': ('PASS', 'WARN')},
                                                      'fields': [('Load command #5 LC_SEGMENT_64', 'filesize')],
                                                      'anomalies': [],
                                                      'notes': ['macho.segment_bounds', 'macho.signature_pages'],
                                                      'pages': [('x86_64', [0])],
                                                      'slices': [('x86_64', 'changed'), ('arm64', 'same')]},
 ('synthetic_universal', 1, 'macho.code-writable'): {'patch': [(49312, '05', '07'), (49316, '05', '07')],
                                                     'parse_ok': True,
                                                     'security': {'rwx': ('PASS', 'FAIL'), 'codesign': ('PASS', 'WARN')},
                                                     'fields': [('Load command #1 LC_SEGMENT_64', 'maxprot'), ('Load command #1 LC_SEGMENT_64', 'initprot')],
                                                     'anomalies': ['rwx_memory'],
                                                     'notes': ['macho.segment_wx', 'macho.dyld_segment_perms', 'macho.signature_pages'],
                                                     'pages': [('arm64', [0])],
                                                     'slices': [('x86_64', 'same'), ('arm64', 'changed')]},
 ('synthetic_universal', 1, 'macho.no-pie'): {'patch': [(49178, 'a1', '81')],
                                              'parse_ok': True,
                                              'security': {'pie': ('PASS', 'FAIL'), 'codesign': ('PASS', 'WARN')},
                                              'fields': [('Mach-O header', 'flags')],
                                              'anomalies': [],
                                              'notes': ['macho.pie_off', 'macho.signature_pages'],
                                              'pages': [('arm64', [0])],
                                              'slices': [('x86_64', 'same'), ('arm64', 'changed')]},
 ('synthetic_universal', 1, 'macho.entry'): {'patch': [(51064, 'fc09', '0040')],
                                             'parse_ok': True,
                                             'security': {'codesign': ('PASS', 'WARN')},
                                             'fields': [('Load command #14 LC_MAIN', 'entryoff')],
                                             'anomalies': ['ep_outside_exec_segment'],
                                             'notes': ['macho.entry_main', 'entry.not_executable', 'macho.signature_pages'],
                                             'pages': [('arm64', [0])],
                                             'slices': [('x86_64', 'same'), ('arm64', 'changed')]},
 ('synthetic_universal', 1, 'macho.tamper-page'): {'patch': [(51758, '00', 'ff')],
                                                   'parse_ok': True,
                                                   'security': {'codesign': ('PASS', 'WARN')},
                                                   'fields': [],
                                                   'anomalies': [],
                                                   'notes': ['macho.signature_pages'],
                                                   'pages': [('arm64', [0])],
                                                   'slices': [('x86_64', 'same'), ('arm64', 'changed')]},
 ('synthetic_universal', 1, 'macho.magic'): {'patch': [(49152, 'cf', '30')],
                                             'parse_ok': True,
                                             'security': {},
                                             'fields': [('Mach-O header', 'magic')],
                                             'anomalies': [],
                                             'notes': ['macho.magic_slice'],
                                             'pages': [],
                                             'slices': [('x86_64', 'same'), ('arm64', 'removed')]},
 ('synthetic_universal', 1, 'macho.segment-bounds'): {'patch': [(50792, '200c00', '405802')],
                                                      'parse_ok': True,
                                                      'security': {'codesign': ('PASS', 'WARN')},
                                                      'fields': [('Load command #5 LC_SEGMENT_64', 'filesize')],
                                                      'anomalies': [],
                                                      'notes': ['macho.segment_bounds', 'macho.signature_pages'],
                                                      'pages': [('arm64', [0])],
                                                      'slices': [('x86_64', 'same'), ('arm64', 'changed')]},
 ('synthetic_firmware', 0, 'macho.code-writable'): {'patch': [(88, '05', '07'), (92, '05', '07')],
                                                    'parse_ok': True,
                                                    'security': {'rwx': ('FAIL', 'FAIL')},
                                                    'fields': [('Load command #0 LC_SEGMENT_64', 'maxprot'), ('Load command #0 LC_SEGMENT_64', 'initprot')],
                                                    'anomalies': ['rwx_memory'],
                                                    'notes': ['macho.standalone'],
                                                    'pages': [],
                                                    'slices': [('arm64e', 'changed')]},
 ('synthetic_firmware', 0, 'macho.no-pie'): None,
 ('synthetic_firmware', 0, 'macho.entry'): {'patch': [(768, '00', '04')],
                                            'parse_ok': True,
                                            'security': {},
                                            'fields': [('Load command #2 LC_UNIXTHREAD', 'pc')],
                                            'anomalies': [],
                                            'notes': ['macho.standalone', 'macho.entry_thread', 'entry.moved'],
                                            'pages': [],
                                            'slices': [('arm64e', 'changed')]},
 ('synthetic_firmware', 0, 'macho.tamper-page'): None,
 ('synthetic_firmware', 0, 'macho.magic'): {'patch': [(0, 'cf', '30')],
                                            'parse_ok': False,
                                            'security': {},
                                            'fields': [('Mach-O header', 'magic')],
                                            'anomalies': [],
                                            'notes': ['parse.failed', 'macho.standalone'],
                                            'pages': [],
                                            'slices': [('arm64e', 'unparsed')]},
 ('synthetic_firmware', 0, 'macho.segment-bounds'): {'patch': [(313, '10', 'a0')],
                                                     'parse_ok': True,
                                                     'security': {},
                                                     'fields': [('Load command #1 LC_SEGMENT_64', 'filesize')],
                                                     'anomalies': [],
                                                     'notes': ['macho.standalone'],
                                                     'pages': [],
                                                     'slices': [('arm64e', 'changed')]}}


class PatchSetTests(unittest.TestCase):
    """parse_patches / apply_patches in isolation."""

    def test_apply_in_order_later_wins(self) -> None:
        data = bytes(range(16))
        patches = labs_patch.parse_patches(
            [{"offset": 2, "hex": "aabbcc"}, {"offset": 3, "hex": "11"}, {"offset": 15, "hex": "ff"}], len(data), 64)
        out = labs_patch.apply_patches(data, patches)
        self.assertEqual(out, bytes([0, 1, 0xAA, 0x11, 0xCC]) + bytes(range(5, 15)) + b"\xff")
        self.assertEqual(data, bytes(range(16)), "the input buffer is not modified")
        self.assertEqual(len(out), len(data))

    def test_hex_forms(self) -> None:
        got = labs_patch.parse_patches([{"offset": "0x4", "hex": "DE ad\nBE\tef"}], 16, 64)
        self.assertEqual((got[0]["offset"], got[0]["data"]), (4, b"\xde\xad\xbe\xef"))

    def test_rejections(self) -> None:
        size = 32
        bad = [
            ("not a list", {"offset": 0, "hex": "00"}),
            ("entry not an object", ["00"]),
            ("missing offset", [{"hex": "00"}]),
            ("float offset", [{"offset": 1.5, "hex": "00"}]),
            ("bool offset", [{"offset": True, "hex": "00"}]),
            ("null offset", [{"offset": None, "hex": "00"}]),
            ("negative offset", [{"offset": -1, "hex": "00"}]),
            ("offset at end", [{"offset": size, "hex": "00"}]),
            ("runs past end", [{"offset": size - 1, "hex": "0000"}]),
            ("huge offset", [{"offset": 1 << 70, "hex": "00"}]),
            ("huge negative offset", [{"offset": -(1 << 70), "hex": "00"}]),
            ("odd digits", [{"offset": 0, "hex": "abc"}]),
            ("non-hex", [{"offset": 0, "hex": "zz"}]),
            ("unicode digits", [{"offset": 0, "hex": "٠١"}]),
            ("empty hex", [{"offset": 0, "hex": "  "}]),
            ("hex not a string", [{"offset": 0, "hex": 255}]),
            ("hex is a list", [{"offset": 0, "hex": ["00"]}]),
            ("offset is text", [{"offset": "twelve", "hex": "00"}]),
        ]
        for label, raw in bad:
            with self.subTest(label):
                with self.assertRaises(labs_patch.BadRequest):
                    labs_patch.parse_patches(raw, size, 16)

    def test_byte_limit_is_exact(self) -> None:
        size = 4096
        ok = labs_patch.parse_patches([{"offset": 0, "hex": "00" * 64}], size, 64)
        self.assertEqual(len(ok[0]["data"]), 64)
        with self.assertRaises(labs_patch.TooLarge):
            labs_patch.parse_patches([{"offset": 0, "hex": "00" * 65}], size, 64)
        # The limit is on the sum, overlapping or not.
        with self.assertRaises(labs_patch.TooLarge):
            labs_patch.parse_patches([{"offset": 0, "hex": "00" * 40}, {"offset": 0, "hex": "00" * 40}], size, 64)

    def test_entry_limit(self) -> None:
        many = [{"offset": 0, "hex": "00"}] * (labs_patch.MAX_PATCHES + 1)
        with self.assertRaises(labs_patch.TooLarge):
            labs_patch.parse_patches(many, 16, 1 << 20)
        self.assertEqual(len(labs_patch.parse_patches(many[:-1], 16, 1 << 20)), labs_patch.MAX_PATCHES)

    def test_labels_are_reduced_to_one_printable_line(self) -> None:
        got = labs_patch.parse_patches([{"offset": 0, "hex": "00", "label": "a\r\nb\x00<c>" + "x" * 500}], 4, 4)
        self.assertNotIn("\n", got[0]["label"])
        self.assertNotIn("\x00", got[0]["label"])
        self.assertLessEqual(len(got[0]["label"]), labs_patch.MAX_LABEL_CHARS)

    def test_derived_filenames(self) -> None:
        self.assertEqual(labs_patch._derived_filename("a.exe"), "a.patched.exe")
        self.assertEqual(labs_patch._derived_filename("ls"), "ls.patched")
        self.assertEqual(labs_patch._derived_filename("a.patched.exe"), "a.patched.exe")


class PatchApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router, self.service, self.config = make_router("public")

    def test_patch_download_round_trip_and_parent_untouched(self) -> None:
        original = fixture_bytes("synthetic_elf64")
        doc = upload(self.router, original, "prog.elf")
        before_parse = call(self.router, "GET", "/api/parse", {"doc": doc})[1]
        resp, out = patch(self.router, doc, [{"offset": 16, "hex": "02", "label": "e_type"}, {"offset": 0x100, "hex": "deadbeef"}])
        self.assertEqual(resp.status, 200, out)
        self.assertRegex(out["doc_id"], r"^p_[0-9a-f]{32}$")
        self.assertEqual(out["parent"], doc)
        self.assertEqual(out["document"]["doc_id"], out["doc_id"])
        self.assertEqual(out["document"]["file_info"]["filename"], "prog.patched.elf")
        self.assertEqual(out["patches"][0], {"offset": 16, "hex": "02", "label": "e_type", "before": "03"})
        expected = bytearray(original)
        expected[16] = 2
        expected[0x100:0x104] = b"\xde\xad\xbe\xef"
        self.assertEqual(download(self.router, out["doc_id"]), bytes(expected))
        self.assertEqual(out["document"]["file_info"]["sha256"], hashlib.sha256(bytes(expected)).hexdigest())
        # The parent: same bytes, same analysis, same id.
        self.assertEqual(download(self.router, doc), original)
        self.assertEqual(call(self.router, "GET", "/api/parse", {"doc": doc})[1], before_parse)
        self.assertEqual(self.service.get_entry(doc=doc).data, original)

    def test_download_headers(self) -> None:
        doc = upload(self.router, fixture_bytes("synthetic_pe32"), 'ev"il\r\n.exe')
        resp, _ = call(self.router, "GET", "/api/download", {"doc": doc})
        self.assertEqual(resp.content_type, "application/octet-stream")
        disposition = resp.headers["Content-Disposition"]
        self.assertTrue(disposition.startswith("attachment;"))
        self.assertNotIn("\r", disposition)
        self.assertNotIn("\n", disposition)
        self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("sandbox", resp.headers["Content-Security-Policy"])

    def test_preset_can_be_patched_and_stays_pristine(self) -> None:
        original = fixture_bytes("synthetic_pe64")
        resp, out = patch(self.router, "preset:synthetic_pe64", [{"offset": 350, "hex": "20"}])
        self.assertEqual(resp.status, 200)
        self.assertNotEqual(download(self.router, out["doc_id"]), original)
        self.assertEqual(download(self.router, "preset:synthetic_pe64"), original)
        again = call(self.router, "GET", "/api/parse", {"doc": "preset:synthetic_pe64"})[1]
        self.assertEqual(again["file_info"]["sha256"], hashlib.sha256(original).hexdigest())

    def test_patches_that_change_nothing_return_the_parent(self) -> None:
        resp, out = patch(self.router, "preset:synthetic_elf64", [{"offset": 0, "hex": "7f454c46"}])
        self.assertEqual(resp.status, 200)
        self.assertTrue(out["identical"])
        self.assertEqual(out["doc_id"], "preset:synthetic_elf64")
        self.assertEqual(out["diff"]["summary"]["bytes"], 0)
        self.assertEqual(self.service.store.stats()["docs"], 0, "no derived document is stored for a no-op")
        resp, out = patch(self.router, "preset:synthetic_elf64", [])
        self.assertTrue(out["identical"])

    def test_a_derived_document_can_be_patched_again(self) -> None:
        _, first = patch(self.router, "preset:synthetic_elf64", [{"offset": 16, "hex": "02"}])
        _, second = patch(self.router, first["doc_id"], [{"offset": 460, "hex": "07"}])
        data = download(self.router, second["doc_id"])
        self.assertEqual((data[16], data[460]), (2, 7))
        self.assertEqual(download(self.router, first["doc_id"])[460], 6, "the intermediate copy is not altered either")

    def test_replace_drops_only_the_named_derived_copy(self) -> None:
        doc = upload(self.router, fixture_bytes("synthetic_elf64"))
        other = upload(self.router, fixture_bytes("synthetic_elf32"))
        _, first = patch(self.router, doc, [{"offset": 16, "hex": "02"}])
        _, second = patch(self.router, doc, [{"offset": 16, "hex": "01"}], replace=first["doc_id"])
        resp, err = call(self.router, "GET", "/api/parse", {"doc": first["doc_id"]})
        self.assertEqual((resp.status, err["code"]), (410, "doc_expired"))
        self.assertEqual(call(self.router, "GET", "/api/parse", {"doc": second["doc_id"]})[0].status, 200)
        # `replace` can never drop an upload, a preset, or anything that is not a derived id.
        for target in (other, doc, "preset:synthetic_elf32", "p_zz", "p_" + "0" * 32, 17, ["x"], {"a": 1}):
            resp, _ = patch(self.router, doc, [{"offset": 16, "hex": "00"}], replace=target)
            self.assertEqual(resp.status, 200)
        self.assertEqual(download(self.router, other), fixture_bytes("synthetic_elf32"))
        self.assertEqual(download(self.router, doc), fixture_bytes("synthetic_elf64"))

    def test_derived_documents_are_isolated_from_other_uploads(self) -> None:
        a = upload(self.router, fixture_bytes("synthetic_elf64"), "a.elf", client="203.0.113.1")
        b = upload(self.router, fixture_bytes("synthetic_pe64"), "b.exe", client="203.0.113.2")
        resp, out = call(self.router, "POST", "/api/patch", body={"doc": a, "patches": [{"offset": 16, "hex": "02"}]}, client="203.0.113.1")
        derived = out["doc_id"]
        # The derived copy holds A's bytes only; nothing in the response mentions B.
        self.assertEqual(download(self.router, derived)[:4], b"\x7fELF")
        self.assertNotIn(b, json.dumps(out))
        # B is exactly as uploaded, and its id is the only way to it.
        self.assertEqual(download(self.router, b), fixture_bytes("synthetic_pe64"))
        # An offset valid for B (larger than nothing in A is assumed) is still checked against A.
        resp, err = patch(self.router, derived, [{"offset": len(fixture_bytes("synthetic_elf64")), "hex": "00"}])
        self.assertEqual(resp.status, 400)
        # Derived ids cannot be guessed or forged from the parent id.
        for forged in ("p_" + a[2:], "p_" + b[2:], derived[:-1] + ("0" if derived[-1] != "0" else "1"), "p_" + "f" * 32):
            resp, err = call(self.router, "GET", "/api/download", {"doc": forged})
            self.assertEqual((resp.status, err["code"]), (410, "doc_expired"), forged)
        # Comparing needs both capabilities.
        resp, err = call(self.router, "GET", "/api/labs/compare", {"a": derived, "b": "u_" + "0" * 32})
        self.assertEqual(resp.status, 410)
        resp, err = call(self.router, "GET", "/api/labs/compare", {"a": derived})
        self.assertEqual(resp.status, 400)

    def test_errors_are_clean(self) -> None:
        cases = [
            ({"patches": [{"offset": 0, "hex": "00"}]}, 400),
            ({"doc": 5, "patches": []}, 400),
            ({"doc": "u_" + "0" * 32, "patches": [{"offset": 0, "hex": "00"}]}, 410),
            ({"doc": "preset:nope", "patches": []}, 404),
            ({"doc": "preset:synthetic_elf64", "patches": "00"}, 400),
            ({"doc": "preset:synthetic_elf64", "patches": [{"offset": 1 << 40, "hex": "00"}]}, 400),
            ({"doc": "preset:synthetic_elf64", "patches": [{"offset": 0, "hex": "0"}]}, 400),
            ({"doc": "path:/etc/passwd", "patches": [{"offset": 0, "hex": "00"}]}, 403),
        ]
        for body, status in cases:
            with self.subTest(body=str(body)[:60]):
                resp, err = call(self.router, "POST", "/api/patch", body=body)
                self.assertEqual(resp.status, status, err)
                self.assertEqual(set(err), {"error", "code"})
                self.assertNotIn("Traceback", err["error"])
        resp, err = call(self.router, "POST", "/api/patch", raw=b"[1,2,3]", headers={"content-type": "application/json"})
        self.assertEqual(resp.status, 400)
        resp, err = call(self.router, "POST", "/api/patch", raw=b"doc=x", headers={"content-type": "text/plain"})
        self.assertEqual(resp.status, 415)
        resp, err = call(self.router, "GET", "/api/patch")
        self.assertEqual(resp.status, 405)
        resp, err = call(self.router, "GET", "/api/download", {"path": "/etc/passwd"})
        self.assertEqual(resp.status, 403)
        resp, err = call(self.router, "GET", "/api/download", {})
        self.assertEqual(resp.status, 400)

    def test_limits_over_the_api(self) -> None:
        limit = self.config.max_patch_bytes
        size = len(fixture_bytes("synthetic_universal"))
        self.assertGreater(size, limit)
        resp, out = patch(self.router, "preset:synthetic_universal", [{"offset": 40000, "hex": "00" * limit}])
        self.assertEqual(resp.status, 200, "exactly the limit is accepted")
        resp, err = patch(self.router, "preset:synthetic_universal", [{"offset": 40000, "hex": "00" * (limit + 1)}])
        self.assertEqual((resp.status, err["code"]), (413, "too_large"))
        resp, err = patch(self.router, "preset:synthetic_universal", [{"offset": 0, "hex": "00"}] * (labs_patch.MAX_PATCHES + 1))
        self.assertEqual((resp.status, err["code"]), (413, "too_large"))
        huge = b'{"doc":"preset:synthetic_universal","patches":[{"offset":0,"hex":"' + b"00" * (self.config.max_json_body_bytes) + b'"}]}'
        resp, err = call(self.router, "POST", "/api/patch", raw=huge, headers={"content-type": "application/json"})
        self.assertEqual((resp.status, err["code"]), (413, "too_large"))

    def test_features_can_be_switched_off(self) -> None:
        router, _service, _config = make_router("public", allow_patch=False, allow_download=False)
        resp, err = patch(router, "preset:synthetic_elf64", [{"offset": 0, "hex": "00"}])
        self.assertEqual((resp.status, err["code"]), (403, "forbidden"))
        resp, err = call(router, "POST", "/api/labs/resolve", body={"doc": "preset:synthetic_elf64", "op": {"kind": "fill", "offset": 0, "size": 1, "byte": 0}})
        self.assertEqual(resp.status, 403)
        resp, err = call(router, "GET", "/api/download", {"doc": "preset:synthetic_elf64"})
        self.assertEqual((resp.status, err["code"]), (403, "forbidden"))

    def test_dead_entries_are_squashed_without_changing_the_result(self) -> None:
        original = fixture_bytes("synthetic_elf64")
        patches = [
            {"offset": 460, "hex": "07", "label": "set"},          # overwritten by the next one
            {"offset": 460, "hex": "06", "label": "back"},         # equals the original: dead
            {"offset": 0x4F0, "hex": "aabbcc", "label": "wide"},
            {"offset": 0x4F1, "hex": "bb", "label": "inside"},     # no-op against the patch before it, but not against the file
            {"offset": 0x4F8, "hex": "01020304", "label": "old"},
            {"offset": 0x4F6, "hex": "ffffffffffffffff", "label": "covers old"},
            {"offset": 16, "hex": "0300", "label": "same as file"},
        ]
        resp, out = patch(self.router, "preset:synthetic_elf64", patches)
        self.assertEqual([p["label"] for p in out["patches"]], ["wide", "inside", "covers old"])
        expected = bytearray(original)
        for p in patches:
            expected[p["offset"]:p["offset"] + len(p["hex"]) // 2] = bytes.fromhex(p["hex"])
        self.assertEqual(download(self.router, out["doc_id"]), bytes(expected))
        # Replaying the squashed list gives the same file.
        resp, again = patch(self.router, "preset:synthetic_elf64", [{"offset": p["offset"], "hex": p["hex"]} for p in out["patches"]])
        self.assertEqual(download(self.router, again["doc_id"]), bytes(expected))
        # Random lists: squashing never changes the bytes.
        rng = random.Random(5)
        for _ in range(200):
            raw = [{"offset": rng.randrange(0, 40), "hex": bytes(rng.choice((0, 0, 1, 2)) for _ in range(rng.randrange(1, 6))).hex()} for _ in range(rng.randrange(1, 9))]
            data = bytes(rng.choice((0, 0, 1)) for _ in range(48))
            parsed = labs_patch.parse_patches(raw, len(data), 1 << 16)
            self.assertEqual(labs_patch.apply_patches(data, labs_patch.squash_patches(data, parsed)), labs_patch.apply_patches(data, parsed), raw)

    def test_patch_rate_limit(self) -> None:
        router, _service, config = make_router("public", upload_rate_limit_per_minute=1, rate_limit_per_minute=0)
        burst = int(1 * labs_patch.PATCH_RATE_FACTOR / 2)
        statuses = []
        for i in range(burst + 3):
            resp, _ = patch(router, "preset:synthetic_elf32", [{"offset": 0x200 + i, "hex": "ff"}])
            statuses.append(resp.status)
        self.assertEqual(statuses[:burst], [200] * burst)
        self.assertEqual(statuses[burst:], [429] * 3)
        resp, err = patch(router, "preset:synthetic_elf32", [{"offset": 0x300, "hex": "ff"}])
        self.assertEqual(err["code"], "rate_limited")
        self.assertIn("Retry-After", resp.headers)
        # Another client is not affected.
        resp, _ = call(router, "POST", "/api/patch", body={"doc": "preset:synthetic_elf32", "patches": [{"offset": 0x300, "hex": "ff"}]}, client="192.0.2.77")
        self.assertEqual(resp.status, 200)

    def test_derived_documents_count_against_the_cache(self) -> None:
        router, service, _config = make_router("public", cache_max_docs=6, cache_client_share=0.0, upload_rate_limit_per_minute=0)
        ids = []
        for i in range(12):
            _, out = patch(router, "preset:synthetic_elf32", [{"offset": 0x200, "hex": "%02x" % (i + 1)}])
            ids.append(out["doc_id"])
        self.assertLessEqual(service.store.stats()["docs"], 6)
        resp, err = call(router, "GET", "/api/parse", {"doc": ids[0]})
        self.assertEqual((resp.status, err["code"]), (410, "doc_expired"), "the oldest derived copy was evicted like any upload")
        self.assertEqual(call(router, "GET", "/api/parse", {"doc": ids[-1]})[0].status, 200)
        # With `replace` a long editing session holds one derived copy.
        router, service, _config = make_router("public", upload_rate_limit_per_minute=0)
        previous = None
        for i in range(10):
            _, out = patch(router, "preset:synthetic_elf32", [{"offset": 0x200, "hex": "%02x" % (i + 1)}], **({"replace": previous} if previous else {}))
            previous = out["doc_id"]
        self.assertEqual(service.store.stats()["docs"], 1)

    def test_per_client_share_applies_to_derived_documents(self) -> None:
        router, service, _config = make_router("public", cache_max_docs=20, cache_client_share=0.2, upload_rate_limit_per_minute=0)
        victim = upload(router, fixture_bytes("synthetic_elf64"), client="192.0.2.1")
        for i in range(30):
            call(router, "POST", "/api/patch", body={"doc": "preset:synthetic_elf32", "patches": [{"offset": 0x200, "hex": "%02x" % (i + 1)}]}, client="192.0.2.2")
        self.assertEqual(call(router, "GET", "/api/parse", {"doc": victim})[0].status, 200, "one client's patches do not evict another client's upload")


class ExperimentTests(unittest.TestCase):
    """Every guided experiment against every fixture: exact patches and exact structural consequences."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.router, cls.service, cls.config = make_router("local")

    def observed(self, preset: str, slice_index: int):
        resp, catalogue = call(self.router, "GET", "/api/labs/experiments", {"doc": "preset:" + preset, "slice_index": str(slice_index)})
        self.assertEqual(resp.status, 200)
        return catalogue

    def test_every_experiment_on_every_fixture(self) -> None:
        seen = set()
        for preset in PRESETS:
            for slice_index in ((0, 1) if preset == "synthetic_universal" else (0,)):
                catalogue = self.observed(preset, slice_index)
                for exp in catalogue["experiments"]:
                    if exp["format"] != catalogue["format"]:
                        self.assertFalse(exp["applicable"])
                        self.assertIn("Needs a", exp["reason"])
                        continue
                    key = (preset, slice_index, exp["id"])
                    seen.add(key)
                    want = EXPECTED[key]
                    with self.subTest(key=key):
                        if want is None:
                            self.assertFalse(exp["applicable"])
                            self.assertTrue(exp["reason"])
                            continue
                        self.assertTrue(exp["applicable"], exp["reason"])
                        self.assertEqual([(c["offset"], c["before_hex"], c["hex"]) for c in exp["changes"]], want["patch"])
                        original = fixture_bytes(preset)
                        for offset, before_hex, _after in want["patch"]:
                            self.assertEqual(original[offset:offset + len(before_hex) // 2].hex(), before_hex)
                        resp, out = patch(self.router, "preset:" + preset, [{"offset": c["offset"], "hex": c["hex"], "label": c["label"]} for c in exp["changes"]])
                        self.assertEqual(resp.status, 200, out)
                        diff = out["diff"]
                        security, fields, anomalies = {}, [], []
                        for part in diff["slices"]:
                            for check in part.get("security", []):
                                security[check["id"]] = (check["before"]["status"] if check["before"] else None,
                                                         check["after"]["status"] if check["after"] else None)
                            fields += [(f["struct"], f["name"]) for f in part.get("fields", []) if f["kind"] == "bytes"]
                            anomalies += [a["id"] for a in part.get("anomalies", {}).get("added", [])]
                        pages = [(i["slice"], [p["page"] for p in i["pages"] if not p["after_ok"]])
                                 for i in diff["integrity"] if i["kind"] == "macho_pages"]
                        self.assertEqual(diff["parse"]["ok"], want["parse_ok"])
                        self.assertEqual(security, want["security"])
                        self.assertEqual(fields, want["fields"])
                        self.assertEqual(anomalies, want["anomalies"])
                        self.assertEqual([n["id"] for n in diff["consequences"]], want["notes"])
                        self.assertEqual(pages, want["pages"])
                        self.assertEqual([(p["label"], p["status"]) for p in diff["slices"]], want["slices"])
                        self.assertEqual(diff["bytes"]["changed"], sum(len(a) // 2 for _o, _b, a in want["patch"]))
                        # Resolving through the op endpoint gives the same bytes.
                        resp, resolved = call(self.router, "POST", "/api/labs/resolve",
                                              body={"doc": "preset:" + preset, "slice_index": slice_index, "op": {"kind": "experiment", "id": exp["id"]}})
                        self.assertEqual([(p["offset"], p["hex"]) for p in resolved["patches"]], [(o, a) for o, _b, a in want["patch"]])
        self.assertEqual(seen, set(EXPECTED), "EXPECTED lists experiments or fixtures that no longer exist")

    def test_every_experiment_has_a_fixture_it_applies_to(self) -> None:
        applicable = {key[2] for key, want in EXPECTED.items() if want is not None}
        self.assertEqual(applicable, {exp["id"] for exp in labs_patch.EXPERIMENTS})
        presets = {p["id"] for p in self.service.get_presets()}
        for exp in labs_patch.EXPERIMENTS:
            self.assertIn(exp["sample"], presets)
            self.assertIsNotNone(next((w for (p, _s, e), w in EXPECTED.items() if e == exp["id"] and p == exp["sample"] and w), None),
                                 f"{exp['id']} does not apply to its own sample")

    def test_catalogue_text_is_complete_and_calm(self) -> None:
        resp, catalogue = call(self.router, "GET", "/api/labs/experiments")
        self.assertEqual(resp.status, 200)
        self.assertIsNone(catalogue["format"])
        for exp in catalogue["experiments"]:
            self.assertFalse(exp["applicable"])
            self.assertGreater(len(exp["setup"]), 60)
            self.assertTrue(exp["look"])
            self.assertTrue(exp["loader"])
            for note in exp["loader"]:
                self.assertNotIn("{", note["text"], "unfilled placeholder")
                self.assertTrue(note["basis"])
            for text in [exp["title"], exp["setup"]] + [n["text"] for n in exp["loader"]]:
                self.assertNotIn("!", text.replace("#!", ""))
        for key, entry in labs_patch.TEXT.items():
            self.assertNotIn("!", entry["text"].replace("#!", ""), key)
            self.assertTrue(entry["basis"], key)

    def test_an_applied_experiment_is_no_longer_offered(self) -> None:
        _, out = patch(self.router, "preset:synthetic_elf64", [{"offset": 460, "hex": "07"}])
        resp, catalogue = call(self.router, "GET", "/api/labs/experiments", {"doc": out["doc_id"]})
        item = next(e for e in catalogue["experiments"] if e["id"] == "elf.exec-stack")
        self.assertFalse(item["applicable"])
        self.assertIn("already set", item["reason"])
        resp, answer = call(self.router, "POST", "/api/labs/resolve", body={"doc": out["doc_id"], "op": {"kind": "experiment", "id": "elf.exec-stack"}})
        self.assertEqual((resp.status, answer["ok"], answer["patches"]), (200, False, []))
        self.assertIn("already set", answer["error"])

    def test_standalone_macho_gets_a_caveat(self) -> None:
        self.assertIn("MH_PRELOAD", self.observed("synthetic_firmware", 0)["caveat"])
        self.assertEqual(self.observed("synthetic_universal", 0)["caveat"], "")


class DiffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.router, cls.service, cls.config = make_router("local")

    def test_a_document_does_not_differ_from_itself(self) -> None:
        for preset in PRESETS:
            with self.subTest(preset):
                entry = self.service.get_entry(doc="preset:" + preset)
                for mode in ("patch", "compare"):
                    diff = labs_patch.diff_documents(entry.doc, entry.data, entry.doc, entry.data, mode, [] if mode == "patch" else None)
                    self.assertTrue(all(v == 0 for v in diff["summary"].values()), diff["summary"])
                    self.assertTrue(all(part["status"] == "same" for part in diff["slices"]))
                    self.assertEqual(diff["consequences"], [])

    def test_a_byte_outside_every_structure_changes_only_bytes(self) -> None:
        # 0x4f0 is padding at the end of the first segment of the ELF64 fixture.
        _, out = patch(self.router, "preset:synthetic_elf64", [{"offset": 0x4F0, "hex": "ab"}])
        summary = out["diff"]["summary"]
        self.assertEqual(summary["bytes"], 1)
        self.assertEqual(summary["fields"], 0)
        self.assertEqual(summary["security"], 0)
        self.assertEqual(out["diff"]["bytes"]["ranges"], [{"offset": 0x4F0, "size": 1, "before": "00", "after": "ab",
                                                           "where": out["diff"]["bytes"]["ranges"][0]["where"], "node": None}])
        self.assertEqual(out["diff"]["consequences"], [])

    def test_byte_runs_report_only_bytes_that_differ(self) -> None:
        original = fixture_bytes("synthetic_elf64")
        same = original[0x100:0x108].hex()
        _, out = patch(self.router, "preset:synthetic_elf64", [{"offset": 0x100, "hex": same}, {"offset": 0x4F0, "hex": "0102"}, {"offset": 0x4F3, "hex": "03"}])
        self.assertEqual([(r["offset"], r["size"]) for r in out["diff"]["bytes"]["ranges"]], [(0x4F0, 2), (0x4F3, 1)])
        self.assertEqual(out["diff"]["bytes"]["changed"], 3)

    def test_field_record_carries_flag_delta_and_values(self) -> None:
        _, out = patch(self.router, "preset:synthetic_elf64", [{"offset": 460, "hex": "07"}])
        (field,) = out["diff"]["slices"][0]["fields"]
        self.assertEqual((field["struct"], field["name"], field["abs_offset"], field["size"], field["kind"]),
                         ("Program header #7 PT_GNU_STACK", "p_flags", 460, 4, "bytes"))
        self.assertEqual(field["before"]["raw_hex"], "06 00 00 00")
        self.assertEqual(field["after"]["raw_hex"], "07 00 00 00")
        self.assertEqual(field["flags_set"], [{"name": "PF_X", "mask": "0x1"}])
        self.assertEqual(field["flags_cleared"], [])
        self.assertEqual((field["before_int"], field["after_int"]), (6, 7))
        self.assertEqual(field["node"], "lc_7")

    def test_segment_and_entry_changes(self) -> None:
        _, out = patch(self.router, "preset:synthetic_elf64", [{"offset": 236, "hex": "06"}])  # code segment: r-x -> rw-
        part = out["diff"]["slices"][0]
        seg = part["segments"]["changed"][0]
        self.assertEqual(seg["node"], "seg_1")
        self.assertIn({"prop": "initprot", "before": "r-x", "after": "rw-"}, seg["changes"])
        # The parser names ELF segments after their permissions, so the name follows the flags.
        self.assertIn({"prop": "segname", "before": "LOAD_1_TEXT", "after": "LOAD_1_DATA"}, seg["changes"])
        self.assertEqual(part["entry"]["before"]["executable"], True)
        self.assertEqual(part["entry"]["after"]["executable"], False)
        notes = [n["id"] for n in out["diff"]["consequences"]]
        self.assertEqual(notes, ["elf.segment_prot", "entry.not_executable"])
        note = out["diff"]["consequences"][1]
        self.assertIn("0x1040", note["text"])
        self.assertIn("LOAD_1_DATA", note["text"])
        self.assertIn("rw-", note["text"])

    def test_universal_slices_are_paired_by_position_in_the_file(self) -> None:
        # Break the first slice's magic: it disappears, and the arm64 slice (now index 0) is still "same".
        _, out = patch(self.router, "preset:synthetic_universal", [{"offset": 16384, "hex": "00"}])
        self.assertTrue(out["diff"]["parse"]["ok"])
        self.assertEqual([(p["label"], p["status"], p["before_index"], p["after_index"]) for p in out["diff"]["slices"]],
                         [("x86_64", "removed", 0, None), ("arm64", "same", 1, 0)])
        self.assertEqual(len(out["diff"]["file_warnings"]["added"]), 1)
        self.assertEqual(len(out["document"]["slices"]), 1)

    def test_fat_header_fields_are_reported_at_file_level(self) -> None:
        _, out = patch(self.router, "preset:synthetic_universal", [{"offset": 7, "hex": "01"}])  # nfat_arch 2 -> 1
        names = [(f["struct"], f["name"], f["before"]["value"], f["after"]["value"]) for f in out["diff"]["file_fields"] if f["kind"] == "bytes"]
        self.assertEqual(names, [("Fat header", "nfat_arch", "2", "1")])

    def test_compare_two_fixtures(self) -> None:
        resp, out = call(self.router, "GET", "/api/labs/compare", {"a": "preset:synthetic_elf64", "b": "preset:synthetic_elf32"})
        self.assertEqual(resp.status, 200)
        diff = out["diff"]
        self.assertEqual(diff["mode"], "compare")
        self.assertEqual(diff["consequences"], [], "consequences are only stated for in-place patches")
        part = diff["slices"][0]
        self.assertEqual(part["status"], "changed")
        self.assertEqual(part["label"], "x86_64 / i386")
        by_name = {(f["struct"], f["name"]): f for f in part["fields"]}
        self.assertTrue(by_name[("ELF header", "e_type")]["before"]["interpreted"].startswith("ET_DYN"))
        self.assertTrue(by_name[("ELF header", "e_type")]["after"]["interpreted"].startswith("ET_EXEC"))
        checks = {c["id"]: (c["before"]["status"], c["after"]["status"]) for c in part["security"]}
        self.assertEqual(checks["pie"], ("PASS", "FAIL"))
        self.assertEqual(checks["nx_stack"], ("PASS", "FAIL"))
        self.assertIn("libc.so.6", part["libraries"]["removed"])
        self.assertGreater(part["symbols"]["removed_count"], 0)
        self.assertIn(".dynamic", [r["label"] for r in part["sections"]["removed"]])
        self.assertFalse(diff["bytes"]["comparable"])
        self.assertEqual(diff["bytes"]["why_not"], "size")
        self.assertIn({"prop": "file_size", "before": 12288, "after": len(fixture_bytes("synthetic_elf32"))}, diff["file"])

    def test_compare_same_document_and_patched_copy(self) -> None:
        resp, out = call(self.router, "GET", "/api/labs/compare", {"a": "preset:synthetic_pe64", "b": "preset:synthetic_pe64"})
        self.assertTrue(out["diff"]["identical"])
        _, patched = patch(self.router, "preset:synthetic_pe64", [{"offset": 350, "hex": "20"}])
        resp, out = call(self.router, "GET", "/api/labs/compare", {"a": "preset:synthetic_pe64", "b": patched["doc_id"]})
        part = out["diff"]["slices"][0]
        # ASLR and its dependent check change; and the signature's digest no longer matches the file.
        self.assertEqual({c["id"] for c in part["security"]}, {"pie", "high_entropy_va", "codesign"})
        self.assertEqual(out["diff"]["bytes"]["changed"], 1)
        # Across formats nothing pairs up, and nothing crashes.
        resp, out = call(self.router, "GET", "/api/labs/compare", {"a": "preset:synthetic_pe64", "b": "preset:synthetic_universal"})
        self.assertEqual(resp.status, 200)


class FieldOpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.router, cls.service, cls.config = make_router("local")

    def resolve(self, doc, op, slice_index=0):
        return call(self.router, "POST", "/api/labs/resolve", body={"doc": doc, "slice_index": slice_index, "op": op})

    def test_little_endian_field(self) -> None:
        resp, out = self.resolve("preset:synthetic_elf64", {"kind": "field", "offset": 24, "size": 8, "value": "0x2000"})
        self.assertEqual(resp.status, 200, out)
        self.assertEqual([(p["offset"], p["hex"]) for p in out["patches"]], [(24, "0020")])  # only the bytes that change
        self.assertEqual(out["changes"][0]["before_hex"], "4010")

    def test_big_endian_fields_keep_their_byte_order(self) -> None:
        # Fat header (big-endian): nfat_arch at offset 4.
        resp, out = self.resolve("preset:synthetic_universal", {"kind": "field", "offset": 4, "size": 4, "value": "0x01020304"})
        self.assertEqual((out["patches"][0]["offset"], out["patches"][0]["hex"]), (4, "01020304"))
        # CodeDirectory fields are big-endian inside a little-endian Mach-O slice.
        entry = self.service.get_entry(doc="preset:synthetic_universal")
        cd = entry.doc["slices"][0]["code_signature_detail"]["code_directory"]["fields"]
        flags = next(f for f in cd if f["name"] == "flags")
        resp, out = self.resolve("preset:synthetic_universal", {"kind": "field", "offset": flags["abs_offset"], "size": 4, "value": "0x10002"})
        self.assertEqual((out["patches"][0]["offset"], out["patches"][0]["hex"]), (flags["abs_offset"] + 1, "01"))
        # A zero-valued field has no byte order of its own; it takes its siblings'.
        spare = next(f for f in cd if f["raw_value"] == 0 and f["size"] == 4)
        resp, out = self.resolve("preset:synthetic_universal", {"kind": "field", "offset": spare["abs_offset"], "size": 4, "value": "1"})
        self.assertEqual((out["patches"][0]["offset"], out["patches"][0]["hex"]), (spare["abs_offset"] + 3, "01"))

    def test_flag_toggle_set_and_clear(self) -> None:
        resp, out = self.resolve("preset:synthetic_pe64", {"kind": "flag", "offset": 350, "size": 2, "flag": "IMAGE_DLLCHARACTERISTICS_GUARD_CF", "set": False})
        self.assertEqual([(p["offset"], p["hex"]) for p in out["patches"]], [(351, "01")])
        resp, out = self.resolve("preset:synthetic_pe64", {"kind": "flag", "offset": 350, "size": 2, "flag": "IMAGE_DLLCHARACTERISTICS_GUARD_CF", "set": True})
        self.assertEqual(out["patches"], [], "already set: nothing to change")
        resp, out = self.resolve("preset:synthetic_pe64", {"kind": "flag", "offset": 350, "size": 2, "flag": "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"})
        self.assertEqual([(p["offset"], p["hex"]) for p in out["patches"]], [(350, "e0")], "no 'set' means toggle")
        resp, answer = self.resolve("preset:synthetic_pe64", {"kind": "flag", "offset": 350, "size": 2, "flag": "NO_SUCH_FLAG"})
        self.assertEqual((resp.status, answer["ok"]), (200, False))

    def test_text_field_and_raw_bytes(self) -> None:
        entry = self.service.get_entry(doc="preset:synthetic_universal")
        seg = entry.doc["slices"][0]["segments"][1]
        name = next(f for f in seg["fields"] if f["name"] == "segname")
        resp, out = self.resolve("preset:synthetic_universal", {"kind": "field", "offset": name["abs_offset"], "size": 16, "value": "__TEXT2"})
        self.assertEqual((out["patches"][0]["offset"], out["patches"][0]["hex"]), (name["abs_offset"] + 6, "32"))
        resp, answer = self.resolve("preset:synthetic_universal", {"kind": "field", "offset": name["abs_offset"], "size": 16, "value": "x" * 17})
        self.assertEqual((answer["ok"], answer["patches"]), (False, []))
        self.assertIn("17 bytes", answer["error"])
        resp, out = self.resolve("preset:synthetic_elf64", {"kind": "field", "offset": 0, "size": 4, "value": "hex: 7f 45 4c 00"})
        self.assertEqual([(p["offset"], p["hex"]) for p in out["patches"]], [(3, "00")])
        resp, answer = self.resolve("preset:synthetic_elf64", {"kind": "field", "offset": 0, "size": 4, "value": "hex:7f45"})
        self.assertFalse(answer["ok"])

    def test_values_that_do_not_fit_or_fields_that_do_not_exist(self) -> None:
        for op in (
            {"kind": "field", "offset": 16, "size": 2, "value": "0x10000"},
            {"kind": "field", "offset": 16, "size": 2, "value": "banana"},
            {"kind": "field", "offset": 16, "size": 2, "value": None},
            {"kind": "field", "offset": 17, "size": 2, "value": "1"},
            {"kind": "field", "offset": 1 << 50, "size": 2, "value": "1"},
            {"kind": "field", "size": 2, "value": "1"},
            {"kind": "fill", "offset": 0, "size": 0, "byte": 0},
            {"kind": "fill", "offset": 0, "size": 4, "byte": 256},
            {"kind": "fill", "offset": 12280, "size": 64, "byte": 0},
            {"kind": "fill", "offset": 0, "size": 1 << 30, "byte": 0},
        ):
            with self.subTest(op=op):
                resp, answer = self.resolve("preset:synthetic_elf64", op)
                self.assertEqual(resp.status, 200, "an edit that cannot be made is an answer, not an HTTP error")
                self.assertEqual((answer["ok"], answer["patches"], answer["changes"]), (False, [], []))
                self.assertTrue(answer["error"])
        for op in ({"kind": "experiment", "id": "no.such"}, {"kind": "launch"}, "field", None):
            with self.subTest(op=op):
                resp, err = self.resolve("preset:synthetic_elf64", op)
                self.assertEqual(resp.status, 400, err)
                self.assertEqual(set(err), {"error", "code"})
        resp, out = self.resolve("preset:synthetic_elf64", {"kind": "field", "offset": 16, "size": 2, "value": "-1"})
        self.assertEqual(out["patches"][0]["hex"], "ffff", "negative numbers are two's complement")

    def test_fill(self) -> None:
        resp, out = self.resolve("preset:synthetic_elf64", {"kind": "fill", "offset": 0x1040, "size": 8, "byte": "0x90"})
        self.assertEqual([(p["offset"], p["hex"]) for p in out["patches"]], [(0x1040, "90" * 8)])

    def test_field_endianness_helper(self) -> None:
        data = bytes.fromhex("00000001" "00000000" "01000000")
        big = {"abs_offset": 0, "size": 4, "raw_value": 1}
        zero = {"abs_offset": 4, "size": 4, "raw_value": 0}
        little = {"abs_offset": 8, "size": 4, "raw_value": 1}
        self.assertEqual(labs_patch.field_endianness(big, [big, zero], data), "big")
        self.assertEqual(labs_patch.field_endianness(little, [little], data), "little")
        self.assertEqual(labs_patch.field_endianness(zero, [big, zero], data), "big")
        self.assertEqual(labs_patch.field_endianness(zero, [zero], data, default_little=True), "little")
        self.assertIsNone(labs_patch.field_endianness({"abs_offset": 0, "size": 4, "raw_value": 77}, [], data))
        self.assertIsNone(labs_patch.field_endianness({"abs_offset": 0, "size": 16, "raw_value": "text"}, [], data))


class UnparsedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router, self.service, self.config = make_router("public")

    def test_unparsed_result_is_a_document_with_the_reason(self) -> None:
        resp, out = patch(self.router, "preset:synthetic_elf64", [{"offset": 0, "hex": "00000000", "label": "zero the magic"}])
        self.assertEqual(resp.status, 200, "a file that stops parsing is a result, not an error")
        parse = out["diff"]["parse"]
        self.assertFalse(parse["ok"])
        self.assertIn("magic", parse["error"].lower())
        self.assertEqual(parse["culprit"]["patch_index"], 0)
        self.assertEqual(parse["culprit"]["structures"][0]["label"], "ELF header · e_ident[EI_MAG]")
        self.assertEqual(parse["culprit"]["structures"][0]["node"], "mach_header")
        doc = out["document"]
        self.assertTrue(doc["file_info"]["unparsed"])
        self.assertEqual(doc["file_info"]["file_size"], 12288)
        self.assertEqual(len(doc["slices"]), 1)
        derived = out["doc_id"]
        expected = b"\0\0\0\0" + fixture_bytes("synthetic_elf64")[4:]
        self.assertEqual(download(self.router, derived), expected)
        # Every document endpoint still answers for it.
        for route, query in (("/api/parse", {}), ("/api/hex", {"offset": "0", "length": "64"}), ("/api/decode", {"offset": "5"}),
                             ("/api/translate", {"query": "0x10"}), ("/api/disassemble", {}), ("/api/search", {"q": "7f45"}),
                             ("/api/labs/experiments", {})):
            with self.subTest(route):
                resp, body = call(self.router, "GET", route, dict(query, doc=derived))
                self.assertEqual(resp.status, 200, body)
        hexed = call(self.router, "GET", "/api/hex", {"doc": derived, "offset": "0", "length": "16"})[1]
        self.assertEqual(hexed["hex_bytes"][:8], "00000000")
        # Experiments say why they cannot be applied; undoing is a patch from the root again.
        catalogue = call(self.router, "GET", "/api/labs/experiments", {"doc": derived})[1]
        self.assertTrue(all(not e["applicable"] for e in catalogue["experiments"]))
        # Patching the unparsed copy back to health works.
        resp, healed = patch(self.router, derived, [{"offset": 0, "hex": "7f454c46"}])
        self.assertTrue(healed["diff"]["parse"]["ok"])
        self.assertFalse(healed["diff"]["parse"]["before_ok"])
        self.assertEqual(download(self.router, healed["doc_id"]), fixture_bytes("synthetic_elf64"))

    def test_the_first_breaking_patch_is_isolated(self) -> None:
        patches = [{"offset": 0x4F0, "hex": "aa"}, {"offset": 460, "hex": "07"}, {"offset": 1, "hex": "00", "label": "break"}, {"offset": 0x4F1, "hex": "bb"}]
        _, out = patch(self.router, "preset:synthetic_elf64", patches)
        culprit = out["diff"]["parse"]["culprit"]
        self.assertEqual((culprit["patch_index"], culprit["offset"], culprit["label"], culprit["isolated"]), (2, 1, "break", True))
        notes = [n["id"] for n in out["diff"]["consequences"]]
        self.assertEqual(notes[0], "parse.failed")
        self.assertIn("elf.magic", notes)
        self.assertIn("elf.stack_exec", notes, "consequences of the other patches are still explained from the bytes")

    def test_unparsed_copies_of_every_format(self) -> None:
        for preset, offset in (("synthetic_pe64", 0), ("synthetic_pe32", 0), ("synthetic_firmware", 0), ("synthetic_elf32", 0), ("synthetic_universal", 0)):
            with self.subTest(preset):
                resp, out = patch(self.router, "preset:" + preset, [{"offset": offset, "hex": "00000000"}])
                self.assertEqual(resp.status, 200)
                self.assertFalse(out["diff"]["parse"]["ok"])
                self.assertTrue(out["diff"]["parse"]["culprit"]["structures"])
                self.assertEqual(call(self.router, "GET", "/api/hex", {"doc": out["doc_id"]})[0].status, 200)

    def test_partial_failures_surface_as_warnings(self) -> None:
        router, _service, _config = make_router("local")
        _, out = patch(router, "preset:synthetic_elf64", [{"offset": 40, "hex": "ffffffffffff0000"}])  # e_shoff past the end
        self.assertTrue(out["diff"]["parse"]["ok"])
        part = out["diff"]["slices"][0]
        self.assertEqual([w["code"] for w in part["warnings"]["added"]], ["section_headers_past_eof"])
        self.assertEqual(len(part["sections"]["removed"]), 13)
        self.assertEqual([n["id"] for n in out["diff"]["consequences"]], ["elf.sections"])


def reference_pe_checksum(data: bytes, checksum_offset: int) -> int:
    """The widely used 32-bit formulation (as in pefile), written independently of labs_patch."""
    padded = data + b"\0" * (-len(data) % 4)
    checksum = 0
    for i in range(0, len(padded), 4):
        if i == checksum_offset:
            continue
        dword = struct.unpack_from("<I", padded, i)[0]
        checksum = (checksum & 0xFFFFFFFF) + dword + (checksum >> 32)
        if checksum > 0xFFFFFFFF:
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = checksum + (checksum >> 16)
    return (checksum & 0xFFFF) + len(data)


class IntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.router, cls.service, cls.config = make_router("local")

    def test_pe_checksum_matches_reference_implementation(self) -> None:
        for preset in ("synthetic_pe64", "synthetic_pe32"):
            data = fixture_bytes(preset)
            layout = labs_patch._pe_layout(data)
            self.assertEqual(layout["checksum_off"] % 4, 0)
            self.assertEqual(labs_patch.pe_checksum(data, layout["checksum_off"]), reference_pe_checksum(data, layout["checksum_off"]))
        rng = random.Random(7)
        for length in (64, 65, 66, 67, 4096, 70001):
            blob = bytes(rng.getrandbits(8) for _ in range(length))
            self.assertEqual(labs_patch.pe_checksum(blob, 16), reference_pe_checksum(blob, 16), length)
        self.assertEqual(labs_patch.pe_checksum(b"\xff" * 8, 0), reference_pe_checksum(b"\xff" * 8, 0))

    def test_writing_the_computed_checksum_makes_it_match(self) -> None:
        data = fixture_bytes("synthetic_pe64")
        info = labs_patch.pe_integrity(data)
        self.assertTrue(info["checksum_ok"], "the synthetic fixture carries the checksum of its own bytes")
        self.assertTrue(info["embedded_hash_matches"], "and a signature that holds its Authenticode hash")
        # Any change makes a checksum that matched go stale ...
        _, stale = patch(self.router, "preset:synthetic_pe64", [{"offset": 0x600, "hex": "ff"}])
        self.assertEqual([n["id"] for n in stale["diff"]["consequences"]], ["pe.checksum", "pe.authenticode"])
        broken = next(i for i in stale["diff"]["integrity"] if i["kind"] == "pe_checksum")
        self.assertTrue(broken["before"]["checksum_ok"])
        self.assertFalse(broken["after"]["checksum_ok"])
        self.assertTrue(broken["before"]["embedded_hash_matches"])
        self.assertFalse(broken["after"]["embedded_hash_matches"])
        # ... and writing the value computed over the changed file makes it match again.
        fixed = int(broken["after"]["checksum_computed"], 16).to_bytes(4, "little").hex()
        _, out = patch(self.router, stale["doc_id"], [{"offset": info["checksum_offset"], "hex": fixed}])
        item = next(i for i in out["diff"]["integrity"] if i["kind"] == "pe_checksum")
        self.assertTrue(item["after"]["checksum_ok"])
        self.assertEqual(item["after"]["checksum_computed"], broken["after"]["checksum_computed"], "the field itself is not part of the sum")
        self.assertEqual([n["id"] for n in out["diff"]["consequences"]], ["pe.checksum_ok"])
        self.assertEqual(item["after"]["image_hash_sha256"], item["before"]["image_hash_sha256"],
                         "CheckSum is excluded from the Authenticode hash")
        self.assertFalse(item["after"]["embedded_hash_matches"], "a correct checksum does not repair the signature")

    def test_authenticode_hash_exclusions(self) -> None:
        data = bytearray(fixture_bytes("synthetic_pe64"))
        layout = labs_patch._pe_layout(bytes(data))
        base = labs_patch.authenticode_digest(bytes(data), layout)

        def digest_with(offset: int) -> str:
            changed = bytearray(data)
            changed[offset] ^= 0xFF
            return labs_patch.authenticode_digest(bytes(changed), labs_patch._pe_layout(bytes(changed)) or layout)

        self.assertEqual(digest_with(layout["checksum_off"]), base, "CheckSum")
        self.assertEqual(digest_with(layout["cert_off"] + 16), base, "inside the certificate table")
        self.assertNotEqual(digest_with(layout["checksum_off"] - 1), base, "the byte before CheckSum")
        self.assertNotEqual(digest_with(layout["checksum_off"] + 4), base, "the byte after CheckSum")
        self.assertNotEqual(digest_with(layout["cert_dir_off"] - 1), base)
        self.assertNotEqual(digest_with(layout["cert_dir_off"] + 8), base)
        self.assertNotEqual(digest_with(0x600), base, "code")
        self.assertNotEqual(digest_with(2), base, "DOS header")
        # An embedded digest is recognised: plant the real hash in the certificate blob.
        planted = bytearray(data)
        planted[layout["cert_off"] + 64:layout["cert_off"] + 96] = bytes.fromhex(base)
        info = labs_patch.pe_integrity(bytes(planted))
        self.assertTrue(info["embedded_hash_matches"])
        self.assertEqual(info["embedded_hash_algorithm"], "sha256")
        planted[0x600] ^= 0xFF
        self.assertFalse(labs_patch.pe_integrity(bytes(planted))["embedded_hash_matches"])

    def test_macho_page_hashes(self) -> None:
        entry = self.service.get_entry(doc="preset:synthetic_universal")
        for index, sl in enumerate(entry.doc["slices"]):
            summary = labs_patch.macho_failing_pages(sl, entry.data)
            self.assertEqual(summary["failing_count"], 0)
            self.assertEqual(summary["checked"], summary["pages"])
            params = labs_patch._cd_params(sl)
            # Corrupt the last byte of each signed page in turn: exactly that page fails.
            for page in range(params["nCodeSlots"]):
                end = min((page + 1) * params["page"], params["codeLimit"])
                data = bytearray(entry.data)
                data[params["base"] + end - 1] ^= 0x01
                failing = labs_patch.macho_failing_pages(sl, bytes(data))["failing"]
                self.assertEqual(failing, [page], (index, page))
        # The parser agrees for the pages it samples.
        preview = entry.doc["slices"][0]["code_signature_detail"]["code_directory"]["code_slots_preview"]
        status = labs_patch.macho_page_status(entry.data, labs_patch._cd_params(entry.doc["slices"][0]), range(len(preview)))
        for slot in preview:
            self.assertEqual(status[slot["page_index"]]["expected"], slot["expected_hash"])
            self.assertEqual(status[slot["page_index"]]["actual"], slot["actual_hash"])

    def test_a_patch_past_the_signed_range_breaks_no_page(self) -> None:
        entry = self.service.get_entry(doc="preset:synthetic_universal")
        sl = entry.doc["slices"][0]
        params = labs_patch._cd_params(sl)
        outside = params["cd_offset"] + params["cd_size"] + 4  # inside the signature area, after the CodeDirectory
        _, out = patch(self.router, "preset:synthetic_universal", [{"offset": outside, "hex": "%02x" % (entry.data[outside] ^ 0xFF)}])
        self.assertEqual([i for i in out["diff"]["integrity"] if i["kind"] == "macho_pages"], [])

    def test_editing_the_code_directory_reports_every_page_it_breaks(self) -> None:
        entry = self.service.get_entry(doc="preset:synthetic_universal")
        params = labs_patch._cd_params(entry.doc["slices"][0])
        slot2 = params["cd_offset"] + params["hashOffset"] + 2 * params["hashSize"]
        _, out = patch(self.router, "preset:synthetic_universal", [{"offset": slot2, "hex": "%02x" % (entry.data[slot2] ^ 0xFF)}])
        item = next(i for i in out["diff"]["integrity"] if i["kind"] == "macho_pages")
        self.assertEqual([p["page"] for p in item["pages"]], [2])
        self.assertTrue(item["code_directory_touched"])
        self.assertEqual([n["id"] for n in out["diff"]["consequences"]], ["macho.signature_pages", "macho.cdhash"])
        # Restoring a hash is reported as a page that matches again.
        _, broken = patch(self.router, "preset:synthetic_universal", [{"offset": 18933, "hex": "ba"}])
        _, healed = patch(self.router, broken["doc_id"], [{"offset": 18933, "hex": "45"}])
        self.assertEqual([n["id"] for n in healed["diff"]["consequences"]], ["macho.signature_pages_fixed"])


class BuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.router, cls.service, cls.config = make_router("public", rate_limit_per_minute=0, upload_rate_limit_per_minute=0)
        cls.options = call(cls.router, "GET", "/api/labs/build/options")[1]

    def build(self, **spec):
        return call(self.router, "POST", "/api/labs/build", body=spec)

    def every_variant(self):
        for arch in self.options["arches"]:
            for payload in arch["payloads"]:
                for type_id, base in (("exec", "0x400000"), ("dyn", "0x0"), ("exec", "0x7f0000000000")):
                    for flags in ("rx", "rwx", "r", ""):
                        for gnu_stack, stack_exec in ((True, False), (True, True), (False, False)):
                            yield dict(arch=arch["id"], payload=payload["id"], type=type_id, base=base, flags=flags,
                                       gnu_stack=gnu_stack, stack_exec=stack_exec)

    def test_layout_is_complete_and_matches_an_independent_decode(self) -> None:
        count = 0
        for spec in self.every_variant():
            count += 1
            with self.subTest(spec=spec):
                resp, out = self.build(**spec)
                self.assertEqual(resp.status, 200, out)
                data = bytes.fromhex(out["hex"])
                self.assertEqual(len(data), out["size"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), out["sha256"])
                # Regions tile the file exactly: no gap, no overlap, bytes as stated.
                cursor = 0
                for region in out["regions"]:
                    self.assertEqual(region["offset"], cursor)
                    self.assertEqual(bytes.fromhex(region["hex"]), data[cursor:cursor + region["size"]])
                    cursor += region["size"]
                self.assertEqual(cursor, len(data))
                self.assertEqual(sum(g["size"] for g in out["groups"]), len(data))
                # Independent decode with the ELF64 struct layouts from the gABI.
                ident = data[:16]
                self.assertEqual(ident, b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8)
                (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
                 e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
                phnum = 2 if spec["gnu_stack"] else 1
                payload_off = 64 + 56 * phnum
                base = int(spec["base"], 16)
                self.assertEqual(e_type, 2 if spec["type"] == "exec" else 3)
                self.assertEqual(e_machine, 62 if spec["arch"] == "x86_64" else 183)
                self.assertEqual((e_version, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shnum, e_shstrndx),
                                 (1, 64, 0, 0, 64, 56, phnum, 0, 0))
                self.assertEqual(e_shentsize, 64)
                self.assertEqual(e_entry, base + payload_off)
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", data, 64)
                want_flags = (4 if "r" in spec["flags"] else 0) | (2 if "w" in spec["flags"] else 0) | (1 if "x" in spec["flags"] else 0)
                self.assertEqual((p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz),
                                 (1, want_flags, 0, base, base, len(data), len(data)))
                self.assertEqual(p_align, 0x1000 if spec["arch"] == "x86_64" else 0x10000)
                self.assertEqual((p_vaddr - p_offset) % p_align, 0, "gABI: p_vaddr and p_offset congruent modulo p_align")
                self.assertTrue(p_vaddr <= e_entry < p_vaddr + p_memsz)
                if spec["gnu_stack"]:
                    s_type, s_flags, s_offset, s_vaddr, s_paddr, s_filesz, s_memsz, s_align = struct.unpack_from("<IIQQQQQQ", data, 120)
                    self.assertEqual((s_type, s_flags, s_offset, s_vaddr, s_paddr, s_filesz, s_memsz, s_align),
                                     (0x6474E551, 7 if spec["stack_exec"] else 6, 0, 0, 0, 0, 0, 16))
                # Read back by the project's parser, field by field.
                self.assertTrue(out["verify"]["ok"], out["verify"])
                doc = parse_macho_bytes(data, path=out["filename"])
                sl = doc["slices"][0]
                header = {f["name"]: f for f in sl["header"]["fields"]}
                self.assertEqual(header["e_type"]["raw_value"], e_type)
                self.assertEqual(header["e_machine"]["raw_value"], e_machine)
                self.assertEqual(header["e_entry"]["raw_value"], e_entry)
                self.assertEqual(header["e_phoff"]["raw_value"], 64)
                self.assertEqual(header["e_phnum"]["raw_value"], phnum)
                self.assertEqual(header["e_shnum"]["raw_value"], 0)
                self.assertEqual(header["e_ident[EI_CLASS]"]["raw_value"], 2)
                self.assertEqual(header["e_ident[EI_DATA]"]["raw_value"], 1)
                self.assertEqual(sl["arch_name"], "x86_64" if spec["arch"] == "x86_64" else "arm64")
                self.assertEqual([lc["cmd_name"] for lc in sl["load_commands"]], ["PT_LOAD", "PT_GNU_STACK"][:phnum])
                load = {f["name"]: f["raw_value"] for f in sl["load_commands"][0]["fields"]}
                self.assertEqual(load, {"p_type": 1, "p_flags": want_flags, "p_offset": 0, "p_vaddr": base, "p_paddr": base,
                                        "p_filesz": len(data), "p_memsz": len(data), "p_align": p_align})
                (seg,) = sl["segments"]
                self.assertEqual((seg["vmaddr_int"], seg["filesize"], seg["fileoff"]), (base, len(data), 0))
                self.assertEqual(seg["initprot"], "".join(c if c in spec["flags"] else "-" for c in "rwx"))
                self.assertEqual(int(sl["entry_point"]["vmaddr"], 16), e_entry)
                self.assertEqual(sl["entry_point"]["abs_offset"], payload_off)
                self.assertEqual(sl["warnings"], [])
                checks = {c["id"]: c["status"] for c in sl["security_posture"]["checks"]}
                self.assertEqual(checks["pie"], "PASS" if spec["type"] == "dyn" else "FAIL")
                self.assertEqual(checks["rwx"], "FAIL" if {"w", "x"} <= set(spec["flags"]) else "PASS")
                if spec["gnu_stack"]:
                    self.assertEqual(checks["nx_stack"], "FAIL" if spec["stack_exec"] else "PASS")
                # The payload is exactly the published snippet, in the stated order.
                snippet = b"".join(bytes.fromhex(code) for code, _text in labs_patch._PAYLOADS[spec["arch"]][spec["payload"]]["code"])
                self.assertEqual(data[payload_off:], snippet)
        self.assertEqual(count, 2 * 4 * 3 * 4 * 3)

    def test_payload_encodings(self) -> None:
        """The snippets, checked against hand-derived encodings (Intel SDM / Arm ARM)."""
        x86 = {c: t for c, t in labs_patch._PAYLOADS["x86_64"]["exit42"]["code"]}
        self.assertEqual(x86, {"bf2a000000": "mov edi, 42", "b83c000000": "mov eax, 60", "0f05": "syscall"})
        def movz(reg: int, imm: int) -> str:  # MOVZ Xd, #imm16 : 1 10 100101 00 imm16 Rd
            return struct.pack("<I", 0xD2800000 | (imm << 5) | reg).hex()
        a64 = [c for c, _ in labs_patch._PAYLOADS["aarch64"]["exit42"]["code"]]
        self.assertEqual(a64, [movz(0, 42), movz(8, 93), struct.pack("<I", 0xD4000001).hex()])
        hello = labs_patch._PAYLOADS["aarch64"]["hello"]["code"]
        self.assertEqual([c for c, _ in hello][:8], [movz(0, 1), struct.pack("<I", 0x10000000 | ((28 >> 2) << 5) | 1).hex(), movz(2, 3), movz(8, 64),
                                                     "010000d4", movz(0, 0), movz(8, 93), "010000d4"])
        # adr x1 is the second instruction (offset 4) and the string follows 8 instructions: 32 - 4 = 28.
        self.assertEqual(sum(len(c) // 2 for c, _ in hello[:8]) - 4, 28)
        x86_hello = labs_patch._PAYLOADS["x86_64"]["hello"]["code"]
        lea_end = sum(len(c) // 2 for c, _ in x86_hello[:3])
        string_at = sum(len(c) // 2 for c, _ in x86_hello[:8])
        self.assertEqual(string_at - lea_end, 0x10, "rip-relative displacement of the lea")
        self.assertEqual(bytes.fromhex(x86_hello[8][0]), b"hi\n")
        # The project's own decoders read the same instructions.
        from backend.disasm import decode_single_arm64_preview, decode_x86_64_insn
        code = b"".join(bytes.fromhex(c) for c, _ in labs_patch._PAYLOADS["x86_64"]["exit42"]["code"])
        pos, seen = 0, []
        while pos < len(code):
            length, mnemonic, operands, _a, _b = decode_x86_64_insn(code[pos:pos + 15], 0, 0x4000B0 + pos, is_64=True)
            self.assertGreater(length, 0)
            seen.append((mnemonic, operands.replace(" ", "")))
            pos += length
        self.assertEqual([m for m, _ in seen], ["mov", "mov", "syscall"])
        self.assertIn("0x2a", seen[0][1])
        self.assertIn("svc", decode_single_arm64_preview(bytes.fromhex("010000d4"), 0).lower())

    def test_notes_reflect_the_form(self) -> None:
        def notes(**spec):
            return " ".join(n["text"] for n in self.build(**spec)[1]["notes"] if n["level"] == "warn")
        self.assertEqual(notes(arch="x86_64"), "")
        self.assertIn("not executable", notes(flags="rw"))
        self.assertIn("writable and executable", notes(flags="rwx"))
        self.assertIn("mmap_min_addr", notes(base="0x1000"))
        self.assertIn("outside the only segment", notes(entry="0x10"))
        self.assertIn("not at the payload", notes(entry="0x400000"))
        self.assertIn("stack with execute permission", notes(stack_exec=True))
        self.assertNotIn("stack with execute permission", notes(stack_exec=True, gnu_stack=False))

    def test_custom_entry_and_rejections(self) -> None:
        _, out = self.build(entry="0x400123")
        self.assertEqual(struct.unpack_from("<Q", bytes.fromhex(out["hex"]), 24)[0], 0x400123)
        for spec in (dict(arch="mips"), dict(type="core"), dict(payload="rm -rf"), dict(flags="rwxz"), dict(base="0x400001"),
                     dict(base="-4096"), dict(base="0x1000000000000"), dict(base="zzz"), dict(entry="q"), dict(entry=str(1 << 70)),
                     dict(arch="aarch64", base="0x401000")):
            with self.subTest(spec=spec):
                resp, answer = self.build(**spec)
                self.assertEqual(resp.status, 200)
                self.assertEqual(set(answer), {"ok", "error"}, "a form value the builder cannot use is explained, and nothing is built")
                self.assertFalse(answer["ok"])
        resp, err = self.build(format="pe")
        self.assertEqual((resp.status, set(err)), (400, {"error", "code"}))
        resp, err = call(self.router, "POST", "/api/labs/build", raw=b"x" * 20000, headers={"content-type": "application/json"})
        self.assertEqual(resp.status, 413)

    def test_built_file_opens_like_any_upload_and_can_be_patched(self) -> None:
        _, out = self.build(arch="aarch64", payload="hello")
        doc = upload(self.router, bytes.fromhex(out["hex"]), out["filename"])
        resp, catalogue = call(self.router, "GET", "/api/labs/experiments", {"doc": doc})
        usable = {e["id"] for e in catalogue["experiments"] if e["applicable"]}
        self.assertEqual(usable, {"elf.code-writable", "elf.exec-stack", "elf.entry", "elf.magic", "elf.endian"})
        self.assertEqual(download(self.router, doc), bytes.fromhex(out["hex"]))

    @unittest.skipUnless(shutil.which("file"), "file(1) not available")
    def test_file_utility_recognises_the_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for arch, word in (("x86_64", "x86-64"), ("aarch64", "aarch64")):
                for type_id, kind in (("exec", "executable"), ("dyn", "shared object")):
                    _, out = self.build(arch=arch, type=type_id, base="0x400000" if type_id == "exec" else "0")
                    path = os.path.join(tmp, f"{arch}-{type_id}.elf")
                    with open(path, "wb") as handle:
                        handle.write(bytes.fromhex(out["hex"]))
                    text = subprocess.run(["file", "-b", path], capture_output=True, text=True, timeout=20).stdout
                    self.assertIn("ELF 64-bit LSB", text)
                    self.assertIn(word, text)
                    self.assertIn(kind, text.replace("pie executable", "shared object"))
                    self.assertIn("statically linked", text)

    def test_llvm_readobj_agrees(self) -> None:
        tool = shutil.which("llvm-readobj") or next((p for p in ("/opt/homebrew/opt/llvm/bin/llvm-readobj", "/usr/local/opt/llvm/bin/llvm-readobj")
                                                    if os.path.exists(p)), None)
        if not tool:
            self.skipTest("llvm-readobj not available")
        with tempfile.TemporaryDirectory() as tmp:
            _, out = self.build(arch="aarch64", payload="hello", flags="rx", stack_exec=True)
            path = os.path.join(tmp, "a.elf")
            with open(path, "wb") as handle:
                handle.write(bytes.fromhex(out["hex"]))
            run = subprocess.run([tool, "--file-headers", "--program-headers", path], capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertNotIn("warning", (run.stdout + run.stderr).lower())
            self.assertNotIn("error", (run.stdout + run.stderr).lower())
            for needle in ("Format: elf64-littleaarch64", "Type: Executable (0x2)", "Machine: EM_AARCH64", "Entry: 0x4000B0", "ProgramHeaderCount: 2",
                           "SectionHeaderCount: 0", "Type: PT_LOAD (0x1)", "VirtualAddress: 0x400000", f"FileSize: {out['size']}", f"MemSize: {out['size']}",
                           "Alignment: 65536", "Type: PT_GNU_STACK (0x6474E551)", "PF_X (0x1)"):
                self.assertIn(needle, run.stdout)


class AbuseTests(unittest.TestCase):
    """Fuzz-style: whatever is posted, the answer is a diff or a clean 4xx — never a 500, never a changed parent."""

    def setUp(self) -> None:
        self.router, self.service, self.config = make_router("public", upload_rate_limit_per_minute=0, rate_limit_per_minute=0)

    def assert_clean(self, resp, data, context) -> None:
        self.assertIn(resp.status, (200, 400, 404, 410, 413, 415, 422), (context, resp.status, data))
        if resp.status != 200:
            self.assertEqual(set(data), {"error", "code"}, context)
            self.assertNotIn("Traceback", data["error"])
            self.assertNotIn(WORKSPACE_ROOT, data["error"])

    def test_malformed_bodies(self) -> None:
        bodies = [
            b"", b"{", b"null", b"[]", b"0", b'"x"', b"{}", b'{"doc":null}', b'{"doc":[]}', b'{"doc":{}}',
            b'{"doc":"preset:synthetic_elf64"}', b'{"doc":"preset:synthetic_elf64","patches":null}',
            b'{"doc":"preset:synthetic_elf64","patches":{}}', b'{"doc":"preset:synthetic_elf64","patches":[null]}',
            b'{"doc":"preset:synthetic_elf64","patches":[[]]}', b'{"doc":"preset:synthetic_elf64","patches":[{}]}',
            b'{"doc":"preset:synthetic_elf64","patches":[{"offset":1e400,"hex":"00"}]}',
            b'{"doc":"preset:synthetic_elf64","patches":[{"offset":NaN,"hex":"00"}]}',
            b'{"doc":"preset:synthetic_elf64","patches":[{"offset":' + b"9" * 39 + b',"hex":"00"}]}',
            b'{"doc":"preset:synthetic_elf64","patches":[{"offset":' + b"9" * 400 + b',"hex":"00"}]}',
            b'{"doc":"preset:synthetic_elf64","patches":[{"offset":"0x' + b"f" * 200 + b'","hex":"00"}]}',
            b'{"doc":"preset:synthetic_elf64","patches":[{"offset":0,"hex":"' + b"\xc3\x28" + b'"}]}',
            b'{"doc":"preset:synthetic_elf64","patches":[{"offset":0,"hex":"00","label":{"a":[1,2,3]}}]}',
            b'{"doc":"' + b"A" * 5000 + b'","patches":[]}',
            b'{"doc":"preset:../../etc/passwd","patches":[]}',
            b'{"doc":"p_' + b"0" * 32 + b'\\u0000","patches":[]}',
            b"[" * 5000 + b"]" * 5000,
            b'{"doc":"preset:synthetic_elf64","patches":' + b"[" * 3000 + b"]" * 3000 + b"}",
        ]
        before = fixture_bytes("synthetic_elf64")
        for body in bodies:
            resp, data = call(self.router, "POST", "/api/patch", raw=body, headers={"content-type": "application/json"})
            self.assert_clean(resp, data, body[:60])
            for route in ("/api/labs/resolve", "/api/labs/build"):
                resp, data = call(self.router, "POST", route, raw=body[:16000], headers={"content-type": "application/json"})
                self.assert_clean(resp, data, (route, body[:60]))
        self.assertEqual(download(self.router, "preset:synthetic_elf64"), before)

    def test_thousands_of_tiny_patches(self) -> None:
        size = len(fixture_bytes("synthetic_universal"))
        rng = random.Random(11)
        patches = [{"offset": rng.randrange(60000, size), "hex": "%02x" % rng.getrandbits(8)} for _ in range(labs_patch.MAX_PATCHES)]
        resp, out = patch(self.router, "preset:synthetic_universal", patches)
        self.assertEqual(resp.status, 200)
        self.assertLessEqual(len(out["diff"]["bytes"]["ranges"]), labs_patch.MAX_BYTE_RANGES)
        self.assertGreater(out["diff"]["bytes"]["truncated"], 0)
        expected = bytearray(fixture_bytes("synthetic_universal"))
        for p in patches:
            expected[p["offset"]] = int(p["hex"], 16)
        self.assertEqual(download(self.router, out["doc_id"]), bytes(expected))
        resp, err = patch(self.router, "preset:synthetic_universal", patches + [{"offset": 0, "hex": "00"}])
        self.assertEqual(resp.status, 413)

    def test_random_patch_sets_on_every_fixture(self) -> None:
        rng = random.Random(20261109)
        for preset in PRESETS:
            original = fixture_bytes(preset)
            for round_index in range(40):
                patches = []
                for _ in range(rng.randrange(1, 6)):
                    # Bias towards headers, where a random byte does the most damage.
                    offset = rng.randrange(0, min(len(original), 1024)) if rng.random() < 0.7 else rng.randrange(0, len(original))
                    length = min(rng.choice((1, 1, 2, 4, 8, 64)), len(original) - offset)
                    patches.append({"offset": offset, "hex": bytes(rng.getrandbits(8) for _ in range(length)).hex()})
                resp, out = patch(self.router, "preset:" + preset, patches)
                self.assert_clean(resp, out, (preset, round_index, patches))
                if resp.status != 200:
                    continue
                expected = bytearray(original)
                for p in patches:
                    expected[p["offset"]:p["offset"] + len(p["hex"]) // 2] = bytes.fromhex(p["hex"])
                self.assertEqual(download(self.router, out["doc_id"]), bytes(expected), (preset, patches))
                diff = out["diff"]
                self.assertEqual(diff["bytes"]["changed"], sum(1 for a, b in zip(original, expected) if a != b))
                if not diff["parse"]["ok"]:
                    self.assertTrue(diff["parse"]["error"])
                json.dumps(out)  # the whole response is serialisable
            self.assertEqual(download(self.router, "preset:" + preset), original, "the preset survived every patch")

    def test_no_route_of_this_module_reads_the_filesystem_in_public_mode(self) -> None:
        for route, query in (("/api/download", {"doc": "path:/etc/hosts"}), ("/api/labs/compare", {"a": "path:/etc/hosts", "b": "preset:synthetic_elf64"}),
                             ("/api/labs/experiments", {"doc": "path:/etc/hosts"})):
            resp, err = call(self.router, "GET", route, query)
            self.assertEqual((resp.status, err["code"]), (403, "forbidden"), route)
        for route in ("/api/patch", "/api/labs/resolve"):
            resp, err = call(self.router, "POST", route, body={"doc": "path:/etc/hosts", "patches": [], "op": {"kind": "fill", "offset": 0, "size": 1, "byte": 0}})
            self.assertEqual((resp.status, err["code"]), (403, "forbidden"), route)


class HttpTests(unittest.TestCase):
    """The same endpoints through the real HTTP adapter, on an ephemeral port."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server(WORKSPACE_ROOT, host="127.0.0.1", port=0, config=RuntimeConfig("public"), log=EventLog(stream=_Null()))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(5)

    def request(self, method, path, body=None, headers=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
        finally:
            conn.close()

    def test_patch_then_download_over_http(self) -> None:
        body = json.dumps({"doc": "preset:synthetic_elf64", "patches": [{"offset": 16, "hex": "02"}]})
        status, headers, raw = self.request("POST", "/api/patch", body, {"Content-Type": "application/json"})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(headers["cache-control"], "no-store")
        out = json.loads(raw)
        status, headers, data = self.request("GET", "/api/download?doc=" + out["doc_id"])
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/octet-stream")
        self.assertIn("attachment", headers["content-disposition"])
        self.assertIn("synthetic_elf64.patched", headers["content-disposition"])
        expected = bytearray(fixture_bytes("synthetic_elf64"))
        expected[16] = 2
        self.assertEqual(data, bytes(expected))
        self.assertEqual(int(headers["content-length"]), len(expected))

    def test_cross_site_and_form_posts_are_refused(self) -> None:
        body = json.dumps({"doc": "preset:synthetic_elf64", "patches": [{"offset": 16, "hex": "02"}]})
        status, _h, _b = self.request("POST", "/api/patch", body, {"Content-Type": "application/json", "Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        status, _h, _b = self.request("POST", "/api/patch", body, {"Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_static_assets_are_served(self) -> None:
        for path, kind in (("/static/js/labs-patch.js", "text/javascript"), ("/static/css/labs-patch.css", "text/css")):
            status, headers, data = self.request("GET", path)
            self.assertEqual(status, 200, path)
            self.assertTrue(headers["content-type"].startswith(kind))
            self.assertGreater(len(data), 1000)


class FrontendSourceTests(unittest.TestCase):
    """Static rules the feature's own files must keep (the browser run checks behaviour)."""

    def read(self, *parts: str) -> str:
        with open(os.path.join(WORKSPACE_ROOT, *parts), encoding="utf-8") as handle:
            return handle.read()

    def test_no_inline_styles_handlers_or_dynamic_code(self) -> None:
        source = self.read("static", "js", "labs-patch.js")
        for needle in ("style=", ".style.", "onclick=", "onload=", "eval(", "new Function", "javascript:", "innerHTML +=", "document.write",
                       "http://", "https://", "localStorage"):
            self.assertNotIn(needle, source, needle)
        # Every innerHTML assignment is the result of the escaping html`` tag.
        for line in source.splitlines():
            if ".innerHTML =" in line:
                self.assertRegex(line, r"\.innerHTML = (html`|\w+Markup\(\)|buildFormMarkup\(\)|compareResultMarkup\(\))", line.strip())

    def test_css_uses_theme_variables_only(self) -> None:
        css = self.read("static", "css", "labs-patch.css")
        import re
        self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b", css), [])
        self.assertEqual(re.findall(r"\brgba?\(", css), [])
        self.assertNotIn("@import", css)
        self.assertNotIn("url(", css)

    def test_registered_once_in_router_and_page(self) -> None:
        api = self.read("backend", "api.py")
        self.assertEqual(api.count("register_labs_patch_routes(router)"), 1)
        page = self.read("static", "index.html")
        self.assertEqual(page.count('src="static/js/labs-patch.js"'), 1)
        self.assertEqual(page.count('href="static/css/labs-patch.css"'), 1)


if __name__ == "__main__":
    unittest.main()
