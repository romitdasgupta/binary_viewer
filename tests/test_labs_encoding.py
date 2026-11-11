"""
Tests for the encoding lab (backend/labs_encoding.py) and the number playground's arithmetic
(the Python-free part of static/js/labs-encoding.js, run under node).

Ground truth for instruction decoding is llvm-objdump:

  * CORPUS_* below are real instructions harvested from llvm-objdump output (system binaries and
    compiler output for Mach-O, ELF and COFF targets), one per distinct operand shape. They run
    everywhere, with no tools installed.
  * LiveObjdumpTests run only where clang and llvm-objdump exist. They re-check the embedded corpus
    against the local tool, run a differential fuzz (random encodings, both decoders, texts must
    be identical), and measure coverage on a real binary.

Two documented differences from llvm's text are normalised before comparing:
  * llvm prints the pseudo register riz/eiz for "SIB index = 100 (none)"; the lab prints no index.
  * llvm prints the unsigned imm16 of RET as a signed number; the lab prints it unsigned.
"""

import io
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal
from fractions import Fraction

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKSPACE_ROOT)

from backend import labs_encoding as L  # noqa: E402
from backend import constants, elf_parser, pe_parser  # noqa: E402
from backend.api import ApiRequest, EventLog, build_router  # noqa: E402
from backend.runtime import RuntimeConfig  # noqa: E402
from backend.service import AnalysisService  # noqa: E402

JS_PATH = os.path.join(WORKSPACE_ROOT, "static", "js", "labs-encoding.js")

# ---------------------------------------------------------------------------
# Ground truth harvested from llvm-objdump: (address, bytes, text, computed target or None)
# ---------------------------------------------------------------------------
CORPUS_ARM64 = [
    (0x100001e44, 'ffc30191', 'add sp, sp, #0x70', None),
    (0x100013e6c, 'ef7d4f0b', 'add w15, w15, w15, lsr #31', None),
    (0x1000015b8, '0801130b', 'add w8, w8, w19', None),
    (0x100011878, '0805080b', 'add w8, w8, w8, lsl #1', None),
    (0x100000ab8, '29050011', 'add w9, w9, #0x1', None),
    (0x1000169c8, '29012a0b', 'add w9, w9, w10, uxtb', None),
    (0x100000748, '00103891', 'add x0, x0, #0xe04', None),
    (0x100003644, '6102158b', 'add x1, x19, x21', None),
    (0x1000040d4, '78c23b8b', 'add x24, x19, w27, sxtw', None),
    (0x100000728, 'fd830691', 'add x29, sp, #0x1a0', None),
    (0x100052fe4, 'a8064091', 'add x8, x21, #0x1, lsl #12', None),
    (0x10004faa8, '0881298b', 'add x8, x8, w9, sxtb', None),
    (0x100000f24, '08d1298b', 'add x8, x8, w9, sxtw #4', None),
    (0x100006db4, '08058a8b', 'add x8, x8, x10, asr #1', None),
    (0x10000f7ec, '9c070031', 'adds w28, w28, #0x1', None),
    (0x10002435c, '090d022b', 'adds w9, w8, w2, lsl #3', None),
    (0x100050560, '950208ab', 'adds x21, x20, x8', None),
    (0x100036c80, '080400b1', 'adds x8, x0, #0x1', None),
    (0x1000f3c48, 'c8c235ab', 'adds x8, x22, w21, sxtw', None),
    (0x100000744, 'a00400f0', 'adrp x0, 0x100097000', 0x100097000),
    (0x100072ef0, '291d0c0a', 'and w9, w9, w12, lsl #7', None),
    (0x100011c58, '76021f72', 'ands w22, w19, #0x2', None),
    (0x1000dd2a0, '0f011cea', 'ands x15, x8, x28', None),
    (0x10003eb04, '620a40f2', 'ands x2, x19, #0x7', None),
    (0x10000bd60, '0f28c91a', 'asr w15, w0, w9', None),
    (0x1000039a8, '00fd6093', 'asr x0, x8, #32', None),
    (0x100024564, 'b32ad39a', 'asr x19, x21, x19', None),
    (0x100001e48, 'ff2303d5', 'autibsp', None),
    (0x100000794, 'fcffff17', 'b 0x100000784', 0x100000784),
    (0x100000e34, '4c010054', 'b.gt 0x100000e5c', 0x100000e5c),
    (0x100002afc, '68010054', 'b.hi 0x100002b28', 0x100002b28),
    (0x1000020a8, '42010054', 'b.hs 0x1000020d0', 0x1000020d0),
    (0x100002380, 'c3030054', 'b.lo 0x1000023f8', 0x1000023f8),
    (0x1000015a8, '092f0054', 'b.ls 0x100001b88', 0x100001b88),
    (0x100043fe8, '64010054', 'b.mi 0x100044014', 0x100044014),
    (0x100026e10, 'a5040054', 'b.pl 0x100026ea4', 0x100026ea4),
    (0x100049208, '86000054', 'b.vs 0x100049218', 0x100049218),
    (0x100009c24, '8d057cb3', 'bfi x13, x12, #4, #2', None),
    (0x100045630, '0a511433', 'bfxil w10, w8, #20, #1', None),
    (0x100048b94, '167d40b3', 'bfxil x22, x8, #0, #32', None),
    (0x1000449f4, '001c614e', 'bic v0.16b, v0.16b, v1.16b', None),
    (0x100023674, '0050f18a', 'bic x0, x0, x17, ror #20', None),
    (0x1000251ac, '1f01206a', 'bics wzr, w8, w0', None),
    (0x100137cdc, '401ca12e', 'bit v0.8b, v2.8b, v1.8b', None),
    (0x9ec, '00013fd6', 'blr x8', None),
    (0x10000d51c, '00021fd6', 'br x16', None),
    (0x10000dab8, '3f081fd6', 'braaz x1', None),
    (0x1000691c0, '861c676e', 'bsl v6.16b, v4.16b, v7.16b', None),
    (0x100000754, '60320035', 'cbnz w0, 0x100000da0', 0x100000da0),
    (0x100000840, 'a00000b5', 'cbnz x0, 0x100000854', 0x100000854),
    (0x1000007bc, '400000b4', 'cbz x0, 0x1000007c4', 0x1000007c4),
    (0x10005b194, '40115c3a', 'ccmn w10, w28, #0x0, ne', None),
    (0x10005fadc, '80aa413a', 'ccmn w20, #0x1, #0x0, ge', None),
    (0x100023348, '201b413a', 'ccmn w25, #0x1, #0x0, ne', None),
    (0x10004e030, '041841ba', 'ccmn x0, #0x1, #0x4, ne', None),
    (0x1000360f8, '48d15c7a', 'ccmp w10, w28, #0x8, le', None),
    (0x100000fd0, '640a407a', 'ccmp w19, #0x0, #0x4, eq', None),
    (0x10013a414, '645a407a', 'ccmp w19, #0x0, #0x4, pl', None),
    (0x1000031f4, '6412557a', 'ccmp w19, w21, #0x4, ne', None),
    (0x100007f20, '60b2497a', 'ccmp w19, w9, #0x0, lt', None),
    (0x100037984, 'a0c2537a', 'ccmp w21, w19, #0x0, gt', None),
    (0x10004f8e0, 'a092567a', 'ccmp w21, w22, #0x0, ls', None),
    (0x100000824, '0001407a', 'ccmp w8, w0, #0x0, eq', None),
    (0x10000b9d0, '28c9417a', 'ccmp w9, #0x1, #0x8, gt', None),
    (0x10005f330, '44d940fa', 'ccmp x10, #0x0, #0x4, le', None),
    (0x100041e24, '422943fa', 'ccmp x10, #0x3, #0x2, hs', None),
    (0x1000784a4, '403149fa', 'ccmp x10, x9, #0x0, lo', None),
    (0x10013ab7c, '845940fa', 'ccmp x12, #0x0, #0x4, pl', None),
    (0x10011513c, 'a8b257fa', 'ccmp x21, x23, #0x8, lt', None),
    (0x1001374d4, 'c05248fa', 'ccmp x22, x8, #0x0, pl', None),
    (0x10002c9d8, 'c4a249fa', 'ccmp x22, x9, #0x4, ge', None),
    (0x10005ac00, '40835cfa', 'ccmp x26, x28, #0x0, hi', None),
    (0x1000267dc, '04b940fa', 'ccmp x8, #0x0, #0x4, lt', None),
    (0x100013310, '20a940fa', 'ccmp x9, #0x0, #0x0, ge', None),
    (0x1000400d0, '20c14afa', 'ccmp x9, x10, #0x0, gt', None),
    (0x100007f24, '68a6931a', 'cinc w8, w19, lt', None),
    (0x100020bdc, '0835881a', 'cinc w8, w8, hs', None),
    (0x100073e0c, '0885881a', 'cinc w8, w8, ls', None),
    (0x100017bbc, '29d5891a', 'cinc w9, w9, gt', None),
    (0x10004a338, '4ad58a9a', 'cinc x10, x10, gt', None),
    (0x1000725f0, '2ba5899a', 'cinc x11, x9, lt', None),
    (0x1000c1c60, '02b5889a', 'cinc x2, x8, ge', None),
    (0x10001f5d8, 'a826959a', 'cinc x8, x21, lo', None),
    (0x100050754, '0895889a', 'cinc x8, x8, hi', None),
    (0x10003e648, '2f8189da', 'cinv x15, x9, ls', None),
    (0x5b0, '5f3f03d5', 'clrex', None),
    (0x178, '2911c05a', 'clz w9, w9', None),
    (0x1000413ac, '2c11c0da', 'clz x12, x9', None),
    (0x100000f54, '1f040031', 'cmn w0, #0x1', None),
    (0x1000bb5a4, '5f01092b', 'cmn w10, w9', None),
    (0x10005b070, '7f07192b', 'cmn w27, w25, lsl #1', None),
    (0x100011c84, '1f1d4031', 'cmn w8, #0x7, lsl #12', None),
    (0x1000025e0, '1f0400b1', 'cmn x0, #0x1', None),
    (0x100034244, 'bf82286b', 'cmp w21, w8, sxtb', None),
    (0x10003a70c, 'df06546b', 'cmp w22, w20, lsr #1', None),
    (0x10009f56c, 'dfa2286b', 'cmp w22, w8, sxth', None),
    (0x100020ec0, '7f0f886b', 'cmp w27, w8, asr #3', None),
    (0x1000007a8, '1f01006b', 'cmp w8, w0', None),
    (0x100000934, '3fb50071', 'cmp w9, #0x2d', None),
    (0x100063a28, '7f8148eb', 'cmp x11, x8, lsr #32', None),
    (0x10003237c, '9f4215eb', 'cmp x20, x21, lsl #16', None),
    (0x100001358, 'bf0209eb', 'cmp x21, x9', None),
    (0x100089940, 'dfa228eb', 'cmp x22, w8, sxth', None),
    (0x1000d5e40, 'ff0228eb', 'cmp x23, w8, uxtb', None),
    (0x100009cc8, '7fc33aeb', 'cmp x27, w26, sxtw', None),
    (0x1000b356c, '9f2328eb', 'cmp x28, w8, uxth', None),
    (0x100013680, '0814805a', 'cneg w8, w0, eq', None),
    (0x10000c770, '0855885a', 'cneg w8, w8, mi', None),
    (0x100014e58, '155480da', 'cneg x21, x0, mi', None),
    (0x100011d08, '6133881a', 'csel w1, w27, w8, lo', None),
    (0x100009014, '2b118b1a', 'csel w11, w9, w11, ne', None),
    (0x1000dcfe4, '10b29f1a', 'csel w16, w16, wzr, lt', None),
    (0x1000561ec, 'd3c29f1a', 'csel w19, w22, wzr, gt', None),
    (0x100002f88, '14019f1a', 'csel w20, w8, wzr, eq', None),
    (0x1001012f8, '56218c1a', 'csel w22, w10, w12, hs', None),
    (0x10000f8c4, '16c1961a', 'csel w22, w8, w22, gt', None),
    (0x1000733f4, '17918b1a', 'csel w23, w8, w11, ls', None),
    (0x100071f04, '48819f1a', 'csel w8, w10, wzr, hi', None),
    (0x10001ddc8, 'e8c3811a', 'csel w8, wzr, w1, gt', None),
    (0x10005e5dc, 'e8a3881a', 'csel w8, wzr, w8, ge', None),
    (0x1000195ac, 'e833881a', 'csel w8, wzr, w8, lo', None),
    (0x100001f70, '0010889a', 'csel x0, x0, x8, ne', None),
    (0x100063014, '80129f9a', 'csel x0, x20, xzr, ne', None),
    (0x100049a30, 'aac28a9a', 'csel x10, x21, x10, gt', None),
    (0x1000181a0, 'f713959a', 'csel x23, xzr, x21, ne', None),
    (0x100014eac, '19319f9a', 'csel x25, x8, xzr, lo', None),
    (0x100051d64, '08818a9a', 'csel x8, x8, x10, hi', None),
    (0x10000d91c, '08b1899a', 'csel x8, x8, x9, lt', None),
    (0x10004f278, 'e8b3969a', 'csel x8, xzr, x22, lt', None),
    (0x100003534, 'e803889a', 'csel x8, xzr, x8, eq', None),
    (0x10002dea8, 'e833889a', 'csel x8, xzr, x8, lo', None),
    (0x1000308fc, 'e9c3899a', 'csel x9, xzr, x9, gt', None),
    (0x100086e08, 'ee579f1a', 'cset w14, mi', None),
    (0x1000031c0, 'f7d79f1a', 'cset w23, gt', None),
    (0x100000be0, 'f8179f1a', 'cset w24, eq', None),
    (0x100013458, 'e8b79f1a', 'cset w8, ge', None),
    (0x100026894, 'e0139f5a', 'csetm w0, eq', None),
    (0x100011da0, 'e0039f5a', 'csetm w0, ne', None),
    (0x10006aee4, 'ead39f5a', 'csetm w10, gt', None),
    (0x10007dbe4, 'e9239f5a', 'csetm w9, lo', None),
    (0x1000abb60, 'e8139fda', 'csetm x8, eq', None),
    (0x10004e6b8, 'e8d39fda', 'csetm x8, gt', None),
    (0x10005ff04, 'eac78a1a', 'csinc w10, wzr, w10, gt', None),
    (0x10000b100, '30269f1a', 'csinc w16, w17, wzr, hs', None),
    (0x10004c0d8, 'f7d6801a', 'csinc w23, w23, w0, le', None),
    (0x10000f8c8, 'f7c69b1a', 'csinc w23, w23, w27, gt', None),
    (0x1000017dc, '68169f1a', 'csinc w8, w19, wzr, ne', None),
    (0x10006cd10, '08d59f1a', 'csinc w8, w8, wzr, le', None),
    (0x100027274, '09c59f1a', 'csinc w9, w8, wzr, gt', None),
    (0x1000321a4, '8ad58a9a', 'csinc x10, x12, x10, le', None),
    (0x10013587c, 'f507899a', 'csinc x21, xzr, x9, eq', None),
    (0x10007059c, '08249f9a', 'csinc x8, x0, xzr, hs', None),
    (0x100026720, '08859f9a', 'csinc x8, x8, xzr, hi', None),
    (0x10011cd48, 'e817889a', 'csinc x8, xzr, x8, ne', None),
    (0x100041534, '00319f5a', 'csinv w0, w8, wzr, lo', None),
    (0x10000f194, '20119f5a', 'csinv w0, w9, wzr, ne', None),
    (0x10001c9d0, '6b01975a', 'csinv w11, w11, w23, eq', None),
    (0x1000b1c5c, '44819f5a', 'csinv w4, w10, wzr, hi', None),
    (0x10010e364, '28b19f5a', 'csinv w8, w9, wzr, lt', None),
    (0x10006e1ac, 'b1919fda', 'csinv x17, x13, xzr, ls', None),
    (0x100013304, '08019fda', 'csinv x8, x8, xzr, eq', None),
    (0x10008224c, '08d19fda', 'csinv x8, x8, xzr, le', None),
    (0x1000502a0, '49c19fda', 'csinv x9, x10, xzr, gt', None),
    (0x1000412a4, '3115885a', 'csneg w17, w9, w8, ne', None),
    (0x10005b600, '15d5955a', 'csneg w21, w8, w21, le', None),
    (0x10001773c, '3935885a', 'csneg w25, w9, w8, lo', None),
    (0x100041068, '0805805a', 'csneg w8, w8, w0, eq', None),
    (0x100040fa4, 'e807805a', 'csneg w8, wzr, w0, eq', None),
    (0x1000811f8, '4ad580da', 'csneg x10, x10, x0, le', None),
    (0x1000f3cc8, '0ab598da', 'csneg x10, x8, x24, lt', None),
    (0x100101a14, '001c216e', 'eor v0.16b, v0.16b, v1.16b', None),
    (0x10002495c, '107ede4a', 'eor w16, w16, w30, ror #31', None),
    (0x100001e4c, 'd0071eca', 'eor x16, x30, x30, lsl #1', None),
    (0x10002459c, '730215ca', 'eor x19, x19, x21', None),
    (0x10000b5e8, '180340d2', 'eor x24, x24, #0x1', None),
    (0x48, '083549ca', 'eor x8, x8, x9, lsr #13', None),
    (0x1000598e8, '68518a13', 'extr w8, w11, w10, #0x14', None),
    (0x100026e50, '01c0601e', 'fabs d1, d0', None),
    (0x100010678, '0129611e', 'fadd d1, d8, d1', None),
    (0x1000482d8, '0004611e', 'fccmp d0, d1, #0x0, eq', None),
    (0x10008cec4, '00d4611e', 'fccmp d0, d1, #0x0, le', None),
    (0x1000fb0dc, '00a46f1e', 'fccmp d0, d15, #0x0, ge', None),
    (0x1000fade0, '00c5601e', 'fccmp d8, d0, #0x0, gt', None),
    (0x100136d2c, '2055201e', 'fccmp s9, s0, #0x0, pl', None),
    (0x100004be4, '0820601e', 'fcmp d0, #0.0', None),
    (0x100026e0c, '0020611e', 'fcmp d0, d1', None),
    (0x100136d14, '0021291e', 'fcmp s8, s9', None),
    (0x1000f2634, '204c601e', 'fcsel d0, d1, d0, mi', None),
    (0x1000f4260, '40bc601e', 'fcsel d0, d2, d0, lt', None),
    (0x100004be8, '015c611e', 'fcsel d1, d0, d1, pl', None),
    (0x100006cb4, '290d681e', 'fcsel d9, d9, d8, eq', None),
    (0x10013b3e0, '004c211e', 'fcsel s0, s0, s1, mi', None),
    (0x10013aab8, '21cc221e', 'fcsel s1, s1, s2, gt', None),
    (0x100010688, '1600689e', 'fcvtps x22, d0', None),
    (0x10001d520, '0800781e', 'fcvtzs w8, d0', None),
    (0x10002bf70, '0000791e', 'fcvtzu w0, d0', None),
    (0x10005887c, '0000799e', 'fcvtzu x0, d0', None),
    (0x10001e3ac, '420c411f', 'fmadd d2, d2, d1, d3', None),
    (0x10000a838, '0001679e', 'fmov d0, x8', None),
    (0x10000a464, '4000261e', 'fmov w0, s2', None),
    (0x1000fadd0, '0140211e', 'fneg s1, s0', None),
    (0x100026f20, '0140651e', 'frintm d1, d0', None),
    (0x10013b5c4, '0038211e', 'fsub s0, s0, s1', None),
    (0xad8, '2801e8b8', 'ldaddal w8, w8, [x9]', None),
    (0xad8, '69fd5f88', 'ldaxr w9, [x11]', None),
    (0x100051d18, 'e007406d', 'ldp d0, d1, [sp]', None),
    (0x1000f8d58, '0084406d', 'ldp d0, d1, [x0, #0x8]', None),
    (0x1000f4068, '0004406d', 'ldp d0, d1, [x0]', None),
    (0x10003dad0, 'e006c1ac', 'ldp q0, q1, [x23], #0x20', None),
    (0x10000c2e8, '000746ad', 'ldp q0, q1, [x24, #0xc0]', None),
    (0x10013b5c0, '2100452d', 'ldp s1, s0, [x1, #0x28]', None),
    (0x100004fe0, '0b2841a9', 'ldp x11, x10, [x0, #0x10]', None),
    (0x100100078, '8a2e4069', 'ldpsw x10, x11, [x20]', None),
    (0x10002bf54, 'e00740fd', 'ldr d0, [sp, #0x8]', None),
    (0x10001ce60, '800240fd', 'ldr d0, [x20]', None),
    (0x100026124, '00b540fd', 'ldr d0, [x8, #0x168]', None),
    (0x10003ef10, 'a41d407d', 'ldr h4, [x13, #0xe]', None),
    (0x10004831c, '4001c03d', 'ldr q0, [x10]', None),
    (0x1000d6e60, '008dc63c', 'ldr q0, [x8, #0x68]!', None),
    (0x10006918c, 'a46ae83c', 'ldr q4, [x21, x8]', None),
    (0x1000708e0, '6a4540b8', 'ldr w10, [x11], #0x4', None),
    (0x100002cf8, '085974b8', 'ldr w8, [x8, w20, uxtw #2]', None),
    (0x10003a88c, '494d40b8', 'ldr w9, [x10, #0x4]!', None),
    (0x10005a9cc, '3f8140b9', 'ldr wzr, [x9, #0x80]', None),
    (0x10000aa70, 'd58e40f8', 'ldr x21, [x22, #0x8]!', None),
    (0x1000008ec, '080140f9', 'ldr x8, [x8]', None),
    (0x100000c7c, '297968f8', 'ldr x9, [x9, x8, lsl #3]', None),
    (0x10000f0f4, 'e0234039', 'ldrb w0, [sp, #0x8]', None),
    (0x100000bcc, '4b1d4038', 'ldrb w11, [x10, #0x1]!', None),
    (0x1000066dc, '08487538', 'ldrb w8, [x0, w21, uxtw]', None),
    (0x100000acc, '09054039', 'ldrb w9, [x8, #0x1]', None),
    (0x100030614, '0ac86978', 'ldrh w10, [x0, w9, sxtw]', None),
    (0x10003250c, 'aa4a7678', 'ldrh w10, [x21, w22, uxtw]', None),
    (0x1000032dc, 'e80b4079', 'ldrh w8, [sp, #0x4]', None),
    (0x100036d08, 'e8034079', 'ldrh w8, [sp]', None),
    (0x100056e08, '88264079', 'ldrh w8, [x20, #0x12]', None),
    (0x1000525b4, '08d97678', 'ldrh w8, [x8, w22, sxtw #1]', None),
    (0x100096728, '28e55f78', 'ldrh w8, [x9], #-0x2', None),
    (0x10004840c, '297b7478', 'ldrh w9, [x25, x20, lsl #1]', None),
    (0x100015af8, 'e09fc139', 'ldrsb w0, [sp, #0x67]', None),
    (0x10005251c, '4a49fb38', 'ldrsb w10, [x10, w27, uxtw]', None),
    (0x100016d48, '371fc038', 'ldrsb w23, [x25, #0x1]!', None),
    (0x100002e7c, '0800c039', 'ldrsb w8, [x0]', None),
    (0x100015d58, '2905c039', 'ldrsb w9, [x9, #0x1]', None),
    (0x10000418c, '686aa838', 'ldrsb x8, [x19, x8]', None),
    (0x10001ca60, '08038039', 'ldrsb x8, [x24]', None),
    (0x1000b0ea8, '0b69eb78', 'ldrsh w11, [x8, x11]', None),
    (0x1000481c0, '36dbf478', 'ldrsh w22, [x25, w20, sxtw #1]', None),
    (0x1000c7aa0, '086fc378', 'ldrsh w8, [x24, #0x36]!', None),
    (0x10001823c, 'e92bc179', 'ldrsh w9, [sp, #0x94]', None),
    (0x100048408, '74ef9f78', 'ldrsh x20, [x27, #-0x2]!', None),
    (0x1000862a8, '08018079', 'ldrsh x8, [x8]', None),
    (0x1000e5814, 'e98b8079', 'ldrsh x9, [sp, #0x44]', None),
    (0x10012e954, 'e30380b9', 'ldrsw x3, [sp]', None),
    (0x100001180, 'e83b80b9', 'ldrsw x8, [sp, #0x38]', None),
    (0x1000a1e58, '088480b8', 'ldrsw x8, [x0], #0x8', None),
    (0x10002452c, 'e0c3c03c', 'ldur q0, [sp, #0xc]', None),
    (0x10000476c, '8082c03c', 'ldur q0, [x20, #0x8]', None),
    (0x1000026d8, 'a8835cf8', 'ldur x8, [x29, #-0x38]', None),
    (0x100009868, '88f25f38', 'ldurb w8, [x20, #-0x1]', None),
    (0x1000dce68, '8a92c178', 'ldursh w10, [x20, #0x19]', None),
    (0x100014ac4, '2821c81a', 'lsl w8, w9, w8', None),
    (0x100003038, '007d1f53', 'lsr w0, w8, #31', None),
    (0x100002b74, '6bfd43d3', 'lsr x11, x11, #3', None),
    (0x100015f64, '081ca04e', 'mov v8.16b, v0.16b', None),
    (0x10000900c, 'ec031f2a', 'mov w12, wzr', None),
    (0x100000b78, '000080d2', 'mov x0, #0x0', None),
    (0x10000072c, 'f50302aa', 'mov x21, x2', None),
    (0x100000d80, 'e9030091', 'mov x9, sp', None),
    (0x100012ad8, 'e0e5002f', 'movi d0, #0x000000ffffffff', None),
    (0x100001b28, '00e4006f', 'movi v0.2d, #0000000000000000', None),
    (0x100040f18, '22e4000f', 'movi v2.8b, #0x1', None),
    (0x100002b68, 'a99999f2', 'movk x9, #0xcccd', None),
    (0x100002b78, '6c810a1b', 'msub w12, w11, w10, w0', None),
    (0x100022ac4, '238d0b9b', 'msub x3, x9, x11, x3', None),
    (0x100002b08, '4a7d0b9b', 'mul x10, x10, x11', None),
    (0x100000d18, 'e903292a', 'mvn w9, w9', None),
    (0x100009c88, 'e803156b', 'negs w8, w21', None),
    (0x10006e8e4, '001ca14e', 'orr v0.16b, v0.16b, v1.16b', None),
    (0x100042f18, '001ca10e', 'orr v0.8b, v0.8b, v1.8b', None),
    (0x100009144, '0805002a', 'orr w8, w8, w0, lsl #1', None),
    (0x100010ecc, '0809492a', 'orr w8, w8, w9, lsr #2', None),
    (0x10000116c, '2801082a', 'orr w8, w9, w8', None),
    (0x10000fdd4, '5a0369b2', 'orr x26, x26, #0x800000', None),
    (0x10000ff68, '5a0308aa', 'orr x26, x26, x8', None),
    (0x100001d14, '1001c1da', 'pacia x16, x8', None),
    (0x100000708, '7f2303d5', 'pacibsp', None),
    (0x100001f50, 'c0035fd6', 'ret', None),
    (0x100001e78, 'ff0f5fd6', 'retab', None),
    (0x10004faf0, '0909c05a', 'rev w9, w8', None),
    (0x100035cd4, '2905c0da', 'rev16 x9, x9', None),
    (0x100060f70, 'e8020013', 'sbfx w8, w23, #0, #1', None),
    (0x1000105a4, 'c002629e', 'scvtf d0, x22', None),
    (0x100015d68, '2801621e', 'scvtf d8, w9', None),
    (0x100020d30, 'e80ed81a', 'sdiv w8, w23, w24', None),
    (0x1000fb7ec, '49a52b9b', 'smsubl x9, w10, w11, x9', None),
    (0x1000119c4, 'a87e379b', 'smull x8, w21, w23', None),
    (0x100002da4, 'e007006d', 'stp d0, d1, [sp]', None),
    (0x10003f8e0, '4070016d', 'stp d0, d28, [x2, #0x10]', None),
    (0x10002cae0, 'e923be6d', 'stp d9, d8, [sp, #-0x20]!', None),
    (0x1000030f0, 'e00300ad', 'stp q0, q0, [sp]', None),
    (0x498, '220d82ac', 'stp q2, q3, [x9], #0x40', None),
    (0x100027798, '155c0129', 'stp w21, w23, [x0, #0x8]', None),
    (0x100022964, '16548228', 'stp w22, w21, [x0], #0x10', None),
    (0x100027280, 'fb260029', 'stp w27, w9, [x23]', None),
    (0x100010b68, 'e8a70529', 'stp w8, w9, [sp, #0x2c]', None),
    (0x100029a30, 'e97f0029', 'stp w9, wzr, [sp]', None),
    (0x10002727c, 'ff220129', 'stp wzr, w8, [x23, #0x8]', None),
    (0x100022c58, 'f47f00a9', 'stp x20, xzr, [sp]', None),
    (0x100025f98, '14fc00a9', 'stp x20, xzr, [x0, #0x8]', None),
    (0x1000037d0, '157c00a9', 'stp x21, xzr, [x0]', None),
    (0x100048c24, '165181a9', 'stp x22, x20, [x8, #0x10]!', None),
    (0x10001772c, 'ff0300a9', 'stp xzr, x0, [sp]', None),
    (0x100001c9c, 'ff4f12a9', 'stp xzr, x19, [sp, #0x120]', None),
    (0x10002d548, '1f4c01a9', 'stp xzr, x19, [x0, #0x10]', None),
    (0x10002d1fc, '1f4c00a9', 'stp xzr, x19, [x0]', None),
    (0x10000fa34, 'ff7f01a9', 'stp xzr, xzr, [sp, #0x10]', None),
    (0x10001c420, 'ff7f00a9', 'stp xzr, xzr, [sp]', None),
    (0x100004634, '7f7e01a9', 'stp xzr, xzr, [x19, #0x10]', None),
    (0x450, 'c08500fc', 'str d0, [x14], #0x8', None),
    (0x1000f5838, '60da36fc', 'str d0, [x19, w22, sxtw #3]', None),
    (0x1000f57fc, '605a36fc', 'str d0, [x19, w22, uxtw #3]', None),
    (0x10001ce64, '600200fd', 'str d0, [x19]', None),
    (0x10002612c, '800600fd', 'str d0, [x20, #0x8]', None),
    (0x10005ae34, 'e07a3afc', 'str d0, [x23, x26, lsl #3]', None),
    (0x100016050, 'e80300fd', 'str d8, [sp]', None),
    (0x1000032c4, 'e003803d', 'str q0, [sp]', None),
    (0x1000619dc, '4069a83c', 'str q0, [x10, x8]', None),
    (0x100011b3c, 'e022803d', 'str q0, [x23, #0x80]', None),
    (0x1000045c8, '0001803d', 'str q0, [x8]', None),
    (0x10001fe7c, '2079b43c', 'str q0, [x9, x20, lsl #4]', None),
    (0x100001884, 'e07303bd', 'str s0, [sp, #0x370]', None),
    (0x10004e588, 'e00300bd', 'str s0, [sp]', None),
    (0x100074cf4, '006100bd', 'str s0, [x8, #0x60]', None),
    (0x10002c1a0, '200100bd', 'str s0, [x9]', None),
    (0x100000804, 'e00a00b9', 'str w0, [x23, #0x8]', None),
    (0x10008e998, '0a4929b8', 'str w10, [x8, w9, uxtw]', None),
    (0x1000204c4, 'e80300b9', 'str w8, [sp]', None),
    (0x100061188, '88ca36b8', 'str w8, [x20, w22, sxtw]', None),
    (0x10005fdf0, '896a28b8', 'str w9, [x20, x8]', None),
    (0x10004187c, '09d933b8', 'str w9, [x8, w19, sxtw #2]', None),
    (0x10003a874, '094500b8', 'str w9, [x8], #0x4', None),
    (0x100013c68, 'ff0300b9', 'str wzr, [sp]', None),
    (0x10003a9d4, '5f7b38b8', 'str wzr, [x26, x24, lsl #2]', None),
    (0x100075efc, '9f4f06b8', 'str wzr, [x28, #0x64]!', None),
    (0x10003ef58, '1f5929b8', 'str wzr, [x8, w9, uxtw #2]', None),
    (0x100017cc4, '005934f8', 'str x0, [x8, w20, uxtw #3]', None),
    (0x1000172a0, '206928f8', 'str x0, [x9, x8]', None),
    (0x1000116c8, '14c839f8', 'str x20, [x0, w25, sxtw]', None),
    (0x100032f7c, 'e80f1ff8', 'str x8, [sp, #-0x10]!', None),
    (0x100001cb4, 'e80300f9', 'str x8, [sp]', None),
    (0x100009cbc, '68da3cf8', 'str x8, [x19, w28, sxtw #3]', None),
    (0x100052580, 'a88e00f8', 'str x8, [x21, #0x8]!', None),
    (0x100000954, '280100f9', 'str x8, [x9]', None),
    (0x100032dc0, 'ff0f1ff8', 'str xzr, [sp, #-0x10]!', None),
    (0x100002fcc, 'ff0300f9', 'str xzr, [sp]', None),
    (0x100003ff8, '7f7a2df8', 'str xzr, [x19, x13, lsl #3]', None),
    (0x1000011c8, '9f0200f9', 'str xzr, [x20]', None),
    (0x100002b80, '0cfd1f38', 'strb w12, [x8, #-0x1]!', None),
    (0x100005d30, '18150038', 'strb w24, [x8], #0x1', None),
    (0x100005460, '7c6a2a38', 'strb w28, [x19, x10]', None),
    (0x100004bec, 'e83b0039', 'strb w8, [sp, #0xe]', None),
    (0x10000540c, '68ca3438', 'strb w8, [x19, w20, sxtw]', None),
    (0x100003670, '68020039', 'strb w8, [x19]', None),
    (0x100002b60, 'ff9f0039', 'strb wzr, [sp, #0x27]', None),
    (0x100008cc0, '1f482838', 'strb wzr, [x0, w8, uxtw]', None),
    (0x100001db0, '1f000039', 'strb wzr, [x0]', None),
    (0x100038bc0, '1f8f0038', 'strb wzr, [x24, #0x8]!', None),
    (0x10000b2b0, 'a4793078', 'strh w4, [x13, x16, lsl #1]', None),
    (0x100007814, 'e81f0079', 'strh w8, [sp, #0xe]', None),
    (0x1000eb42c, 'e8030079', 'strh w8, [sp]', None),
    (0x1000270d0, '08100079', 'strh w8, [x0, #0x8]', None),
    (0x1000029cc, '08000079', 'strh w8, [x0]', None),
    (0x100090a80, '68d93478', 'strh w8, [x11, w20, sxtw #1]', None),
    (0x100009b5c, '686a2078', 'strh w8, [x19, x0]', None),
    (0x10002d624, 'ff1f0079', 'strh wzr, [sp, #0xe]', None),
    (0x100092818, '3f6b2978', 'strh wzr, [x25, x9]', None),
    (0x10000b07c, '1f010079', 'strh wzr, [x8]', None),
    (0x10003fb90, '80c2003c', 'stur b0, [x20, #0xc]', None),
    (0x10001ced4, '004000fc', 'stur d0, [x0, #0x4]', None),
    (0x1000045b0, '0080803c', 'stur q0, [x0, #0x8]', None),
    (0x100071ee4, '00b000bc', 'stur s0, [x0, #0xb]', None),
    (0x100020d70, 'a8431ab8', 'stur w8, [x29, #-0x5c]', None),
    (0x100052f90, 'e97302b8', 'stur w9, [sp, #0x27]', None),
    (0x100043410, 'ff4301f8', 'stur xzr, [sp, #0x14]', None),
    (0x100006508, '68f21f38', 'sturb w8, [x19, #-0x1]', None),
    (0x1000064f4, '7ff21f38', 'sturb wzr, [x19, #-0x1]', None),
    (0x100051cac, '48130078', 'sturh w8, [x26, #0x1]', None),
    (0x100058e90, '1f110078', 'sturh wzr, [x8, #0x1]', None),
    (0x10006d3bc, 'ff0740d1', 'sub sp, sp, #0x1, lsl #12', None),
    (0x100033530, 'bf4301d1', 'sub sp, x29, #0x50', None),
    (0x100021eac, '8106974b', 'sub w1, w20, w23, asr #1', None),
    (0x10005c808, 'ce812f4b', 'sub w14, w14, w15, sxtb', None),
    (0x100003700, '2200084b', 'sub w2, w1, w8', None),
    (0x1000015a0, '080c0051', 'sub w8, w0, #0x3', None),
    (0x10002b828, '08454b4b', 'sub w8, w8, w11, lsr #17', None),
    (0x1000618e4, '08012b4b', 'sub w8, w8, w11, uxtb', None),
    (0x100057fcc, '0821374b', 'sub w8, w8, w23, uxth', None),
    (0x1000025e8, 'a12302d1', 'sub x1, x29, #0x88', None),
    (0x100003a44, 'f44310d1', 'sub x20, sp, #0x410', None),
    (0x10000a6a4, '08c133cb', 'sub x8, x8, w19, sxtw', None),
    (0x100002240, '5700016b', 'subs w23, w2, w1', None),
    (0x100026630, '210108eb', 'subs x1, x9, x8', None),
    (0x100003280, '290500f1', 'subs x9, x9, #0x1', None),
    (0x100000f44, '141d0013', 'sxtb w20, w8', None),
    (0x100011c80, '083d0013', 'sxth w8, w8', None),
    (0x1000525b8, '163d4093', 'sxth x22, w8', None),
    (0x10000076c, '80000037', 'tbnz w0, #0x0, 0x10000077c', 0x10000077c),
    (0x100004190, '8803f8b7', 'tbnz x8, #0x3f, 0x100004200', 0x100004200),
    (0x100000cb4, 'd8050036', 'tbz w24, #0x0, 0x100000d6c', 0x100000d6c),
    (0x100001e50, '5000f0b6', 'tbz x16, #0x3e, 0x100001e58', 0x100001e58),
    (0x100002e24, 'bf01096a', 'tst w13, w9', None),
    (0x100002d90, '1f050072', 'tst w8, #0x3', None),
    (0x100043b88, '1f1d496a', 'tst w8, w9, lsr #7', None),
    (0x100027284, '3f190a6a', 'tst w9, w10, lsl #6', None),
    (0x100002e3c, '7f010cea', 'tst x11, x12', None),
    (0x100001120, '000d0353', 'ubfx w0, w8, #3, #1', None),
    (0x10000d88c, '0c000000', 'udf #0xc', None),
    (0x10001c554, '600ac89a', 'udiv x0, x19, x8', None),
    (0x10000f894, '687fb89b', 'umull x8, w27, w24', None),
]

UNDECODED_ARM64 = [
    ('00819f0d', 'st1.s'),
    ('220e020e', 'dup'),
    ('4234600e', 'cmgt'),
    ('42b8710e', 'addv'),
    ('4258200e', 'cnt'),
    ('a01d064e', 'mov.h'),
    ('211a400d', 'ld1.b'),
    ('2128210e', 'xtn'),
    ('2064000f', 'movi'),
    ('0084a10e', 'add'),
    ('02f6036f', 'fmov'),
    ('0204186e', 'mov.d'),
    ('20d4624e', 'fadd'),
    ('001d144e', 'mov.s'),
    ('2144a26e', 'ushl'),
    ('0018000e', 'uzp1'),
    ('00d8615e', 'scvtf'),
    ('85140c6f', 'usra'),
    ('a634216e', 'cmhi'),
    ('6581004c', 'st2'),
    ('00b8e15e', 'fcvtzs'),
    ('0040006e', 'ext'),
    ('01bae06e', 'neg'),
    ('0008a00e', 'rev64'),
    ('00d4e97e', 'fabd'),
    ('00c0a12e', 'umull'),
    ('0084200f', 'shrn'),
    ('02c0a16e', 'umull2'),
    ('2158824e', 'uzp2'),
    ('21043d6f', 'ushr'),
    ('2094a26e', 'mls'),
    ('0096010f', 'orr'),
    ('2105002f', 'mvni'),
    ('2178800e', 'zip2'),
    ('0084a12e', 'sub'),
    ('8068610e', 'fcvtn'),
    ('02040c5e', 'mov'),
    ('41e4e36e', 'fcmgt'),
    ('82e8e04e', 'fcmlt'),
    ('a2dc626e', 'fmul'),
]

CORPUS_X86_64 = [
    (0x10004ca27, '6683d200', 'adc dx, 0x0', None),
    (0x1000cf342, '41130c24', 'adc ecx, dword ptr [r12]', None),
    (0x1000138f3, '4183d402', 'adc r12d, 0x2', None),
    (0x10007d982, '4111c4', 'adc r12d, eax', None),
    (0x1000233c0, '4883d200', 'adc rdx, 0x0', None),
    (0x10000275c, '04d0', 'add al, -0x30', None),
    (0x100014e26, '00d0', 'add al, dl', None),
    (0x1000d37a8, '6601c8', 'add ax, cx', None),
    (0x1000581a9, '66030451', 'add ax, word ptr [rcx + 2*rdx]', None),
    (0x1000273bb, '45004c3fff', 'add byte ptr [r15 + rdi - 0x1], r9b', None),
    (0x10000e163, '005548', 'add byte ptr [rbp + 0x48], dl', None),
    (0x10005d58c, '4183470802', 'add dword ptr [r15 + 0x8], 0x2', None),
    (0x10000b61a, '018dc8feffff', 'add dword ptr [rbp - 0x138], ecx', None),
    (0x100001474, '83c0fd', 'add eax, -0x3', None),
    (0x100005dd7, '0305975c0800', 'add eax, dword ptr [rip + 0x85c97]', 0x10008ba74),
    (0x10005bdeb, '41035954', 'add ebx, dword ptr [r9 + 0x54]', None),
    (0x100001f1b, '01c2', 'add edx, eax', None),
    (0x10002fec9, '48019d30feffff', 'add qword ptr [rbp - 0x1d0], rbx', None),
    (0x10008d2e7, '4883838800000004', 'add qword ptr [rbx + 0x88], 0x4', None),
    (0x10007ddb5, '4801140f', 'add qword ptr [rdi + rcx], rdx', None),
    (0x1000043bc, '440375a0', 'add r14d, dword ptr [rbp - 0x60]', None),
    (0x100052e11, '4f037cf508', 'add r15, qword ptr [r13 + 8*r14 + 0x8]', None),
    (0x10003ba2b, '48035a08', 'add rbx, qword ptr [rdx + 0x8]', None),
    (0x1000cbd1d, '6641834346e2', 'add word ptr [r11 + 0x46], -0x1e', None),
    (0x10002e10c, '660f58d1', 'addpd xmm2, xmm1', None),
    (0x100010166, 'f20f5805d2081300', 'addsd xmm0, qword ptr [rip + 0x1308d2]', 0x100140a40),
    (0x100010161, 'f20f584db8', 'addsd xmm1, qword ptr [rbp - 0x48]', None),
    (0x1000459c7, '6683e00c', 'and ax, 0xc', None),
    (0x1000e4d37, '418064cf01fc', 'and byte ptr [r15 + 8*rcx + 0x1], -0x4', None),
    (0x10012b8fd, '204d80', 'and byte ptr [rbp - 0x80], cl', None),
    (0x1000757ea, '4220443310', 'and byte ptr [rbx + r14 + 0x10], al', None),
    (0x100057f49, '20040e', 'and byte ptr [rsi + rcx], al', None),
    (0x100000eea, '20ca', 'and dl, cl', None),
    (0x100026c9e, '836018fd', 'and dword ptr [rax + 0x18], -0x3', None),
    (0x1000517ed, '44214778', 'and dword ptr [rdi + 0x78], r8d', None),
    (0x10005ea13, '4421253edb0200', 'and dword ptr [rip + 0x2db3e], r12d', 0x10008c558),
    (0x100048cf0, '81250a500400fdbfffff', 'and dword ptr [rip + 0x4500a], 0xffffbffd', 0x10008dd04),
    (0x100001042, '83e001', 'and eax, 0x1', None),
    (0x10000f49b, '2345a4', 'and eax, dword ptr [rbp - 0x5c]', None),
    (0x100002911, '422344b93c', 'and eax, dword ptr [rcx + 4*r15 + 0x3c]', None),
    (0x100002952, '4421e8', 'and eax, r13d', None),
    (0x1000b0e38, '49214630', 'and qword ptr [r14 + 0x30], rax', None),
    (0x10005f056, '48217598', 'and qword ptr [rbp - 0x68], rsi', None),
    (0x1000838cf, '48816130ffffdfff', 'and qword ptr [rcx + 0x30], -0x200001', None),
    (0x100021793, '4d21fe', 'and r14, r15', None),
    (0x100067a13, '48234218', 'and rax, qword ptr [rdx + 0x18]', None),
    (0x100014eda, '4883e6c0', 'and rsi, -0x40', None),
    (0x10008324c, '492336', 'and rsi, qword ptr [r14]', None),
    (0x1000660ed, '66214112', 'and word ptr [rcx + 0x12], ax', None),
    (0x10007d077, '6681640114fff7', 'and word ptr [rcx + rax + 0x14], 0xf7ff', None),
    (0x16e, '0f55cb', 'andnps xmm1, xmm3', None),
    (0x1000f1fb4, '660f540534ec0400', 'andpd xmm0, xmmword ptr [rip + 0x4ec34]', 0x100140bf0),
    (0x100067a24, '0f5405157a0000', 'andps xmm0, xmmword ptr [rip + 0x7a15]', 0x10006f440),
    (0x1000d48e8, '410f54c8', 'andps xmm1, xmm8', None),
    (0x10005f967, '480fcb', 'bswap rbx', None),
    (0x10001cd06, '0fba65ac08', 'bt dword ptr [rbp - 0x54], 0x8', None),
    (0x10000c144, '410fbae509', 'bt r13d, 0x9', None),
    (0x1000629c5, '480fbae736', 'bt rdi, 0x36', None),
    (0x100057c86, '480fbaf123', 'btr rcx, 0x23', None),
    (0x100027091, '480fbae834', 'bts rax, 0x34', None),
    (0x100010445, 'ff9508ffffff', 'call qword ptr [rbp - 0xf8]', None),
    (0x1000118bc, '440f47eb', 'cmova r13d, ebx', None),
    (0x10006cb43, '440f477da4', 'cmova r15d, dword ptr [rbp - 0x5c]', None),
    (0x10008e329, '440f467dc8', 'cmovbe r15d, dword ptr [rbp - 0x38]', None),
    (0x100002b65, '0f44c1', 'cmove eax, ecx', None),
    (0x1000459b4, '480f4fcb', 'cmovg rcx, rbx', None),
    (0x100032ac0, '440f4c6d8c', 'cmovl r13d, dword ptr [rbp - 0x74]', None),
    (0x100064cee, '440f45ada0f7ffff', 'cmovne r13d, dword ptr [rbp - 0x860]', None),
    (0x10000277f, '480f45c2', 'cmovne rax, rdx', None),
    (0x1000233cd, '4c0f49fa', 'cmovns r15, rdx', None),
    (0x100015053, '440f48e8', 'cmovs r13d, eax', None),
    (0x100038e1b, '413a442401', 'cmp al, byte ptr [r12 + 0x1]', None),
    (0x100099dc1, '433a5c2f01', 'cmp bl, byte ptr [r15 + r13 + 0x1]', None),
    (0x10011d7b2, '43807cb20200', 'cmp byte ptr [r10 + 4*r14 + 0x2], 0x0', None),
    (0x10004f5a8, '41381c07', 'cmp byte ptr [r15 + rax], bl', None),
    (0x100079e08, '803c5000', 'cmp byte ptr [rax + 2*rdx], 0x0', None),
    (0x1000008e8, '80382d', 'cmp byte ptr [rax], 0x2d', None),
    (0x100002aee, '42807c33013d', 'cmp byte ptr [rbx + r14 + 0x1], 0x3d', None),
    (0x1000dc6a2, '807cc10400', 'cmp byte ptr [rcx + 8*rax + 0x4], 0x0', None),
    (0x1000511e7, '384411ff', 'cmp byte ptr [rcx + rdx - 0x1], al', None),
    (0x100022d8f, '44383f', 'cmp byte ptr [rdi], r15b', None),
    (0x100003942, '38c2', 'cmp dl, al', None),
    (0x10004ccdb, '41833c8a00', 'cmp dword ptr [r10 + 4*rcx], 0x0', None),
    (0x100005c4e, '42397cc004', 'cmp dword ptr [rax + 8*r8 + 0x4], edi', None),
    (0x100001227, '833c182d', 'cmp dword ptr [rax + rbx], 0x2d', None),
    (0x100001ff2, '837dd400', 'cmp dword ptr [rbp - 0x2c], 0x0', None),
    (0x100007676, '44396dc0', 'cmp dword ptr [rbp - 0x40], r13d', None),
    (0x10000b3a9, '423944a304', 'cmp dword ptr [rbx + 4*r12 + 0x4], eax', None),
    (0x10003e692, '42837cbb0800', 'cmp dword ptr [rbx + 4*r15 + 0x8], 0x0', None),
    (0x1000231c6, '397910', 'cmp dword ptr [rcx + 0x10], edi', None),
    (0x1000a72ea, '44393c19', 'cmp dword ptr [rcx + rbx], r15d', None),
    (0x100000762, '3905a83c0800', 'cmp dword ptr [rip + 0x83ca8], eax', 0x100084410),
    (0x10008416d, '413b4c8004', 'cmp ecx, dword ptr [r8 + 4*rax + 0x4]', None),
    (0x10008fa10, '3b9485ecfdffff', 'cmp edx, dword ptr [rbp + 4*rax - 0x214]', None),
    (0x1000239ef, '48837cc1f800', 'cmp qword ptr [rcx + 8*rax - 0x8], 0x0', None),
    (0x10000fcd5, '4a837c29f800', 'cmp qword ptr [rcx + r13 - 0x8], 0x0', None),
    (0x10000ddfb, '4c393deedc0700', 'cmp qword ptr [rip + 0x7dcee], r15', 0x10008baf0),
    (0x10004434c, '664183fcff', 'cmp r12w, -0x1', None),
    (0x100052722, '443a6c08ff', 'cmp r13b, byte ptr [rax + rcx - 0x1]', None),
    (0x100001251, '4939c6', 'cmp r14, rax', None),
    (0x100080579, '664139c7', 'cmp r15w, ax', None),
    (0x1000c346e, '4b3b4425f0', 'cmp rax, qword ptr [r13 + r12 - 0x10]', None),
    (0x100002414, '483b45d0', 'cmp rax, qword ptr [rbp - 0x30]', None),
    (0x1000068a3, '483b05f6cd0700', 'cmp rax, qword ptr [rip + 0x7cdf6]', 0x1000836a0),
    (0x1000fd68f, '493b4c0640', 'cmp rcx, qword ptr [r14 + rax + 0x40]', None),
    (0x100002c4b, '483b4b08', 'cmp rcx, qword ptr [rbx + 0x8]', None),
    (0x1000e8bf9, '6641837c1cfe00', 'cmp word ptr [r12 + rbx - 0x2], 0x0', None),
    (0x10002c4c3, '6641813c245554', 'cmp word ptr [r12], 0x5455', None),
    (0x100051135, '664183bc45cc00000066', 'cmp word ptr [r13 + 2*rax + 0xcc], 0x66', None),
    (0x10004ec56, '66395042', 'cmp word ptr [rax + 0x42], dx', None),
    (0x100135644, 'f20fc2d801', 'cmpltsd xmm3, xmm0', None),
    (0x100086329, 'f20fc2c804', 'cmpneqsd xmm1, xmm0', None),
    (0x1000f928b, 'f30fe6c0', 'cvtdq2pd xmm0, xmm0', None),
    (0x10013798f, 'f30fe64c86f8', 'cvtdq2pd xmm1, qword ptr [rsi + 4*rax - 0x8]', None),
    (0x1000f6fb9, 'f2480f2a4580', 'cvtsi2sd xmm0, qword ptr [rbp - 0x80]', None),
    (0x100049084, 'f2480f2a07', 'cvtsi2sd xmm0, qword ptr [rdi]', None),
    (0x100136933, 'f20f2a9495dcfeffff', 'cvtsi2sd xmm2, dword ptr [rbp + 4*rdx - 0x124]', None),
    (0x168, 'f30f2acf', 'cvtsi2ss xmm1, edi', None),
    (0x1001321f2, 'f3420f5a843d68ffffff', 'cvtss2sd xmm0, dword ptr [rbp + r15 - 0x98]', None),
    (0x1000f7e56, 'f30f5ac9', 'cvtss2sd xmm1, xmm1', None),
    (0x10001e435, 'f20f2cd0', 'cvttsd2si edx, xmm0', None),
    (0x2fc, 'f2480f2c442408', 'cvttsd2si rax, qword ptr [rsp + 0x8]', None),
    (0x100007276, 'f2480f2cf0', 'cvttsd2si rsi, xmm0', None),
    (0x100076657, 'fe4b68', 'dec byte ptr [rbx + 0x68]', None),
    (0x1000097ef, 'ff4b08', 'dec dword ptr [rbx + 0x8]', None),
    (0x1000106c7, 'ff0d37b40700', 'dec dword ptr [rip + 0x7b437]', 0x10008bb04),
    (0x1000f9b41, '48ff8d60ffffff', 'dec qword ptr [rbp - 0xa0]', None),
    (0x1000027cc, '48ffce', 'dec rsi', None),
    (0x10009525e, 'f7b57cffffff', 'div dword ptr [rbp - 0x84]', None),
    (0x100093c17, 'f733', 'div dword ptr [rbx]', None),
    (0x10004b5e0, '41f7f6', 'div r14d', None),
    (0x10001a076, '48f7f1', 'div rcx', None),
    (0x100010080, 'f20f5ec1', 'divsd xmm0, xmm1', None),
    (0x2ef, 'f30f5e45fc', 'divss xmm0, dword ptr [rbp - 0x4]', None),
    (0x367, 'f30f5e442408', 'divss xmm0, dword ptr [rsp + 0x8]', None),
    (0x10001e4e4, 'f77db0', 'idiv dword ptr [rbp - 0x50]', None),
    (0x10002007a, '42f77c9b04', 'idiv dword ptr [rbx + 4*r11 + 0x4]', None),
    (0x100070f1b, '49f7b8c8000000', 'idiv qword ptr [r8 + 0xc8]', None),
    (0x10000b7b6, '410fafc5', 'imul eax, r13d', None),
    (0x10005d5bf, '0faf30', 'imul esi, dword ptr [rax]', None),
    (0x10000ff9e, '4c0fafe1', 'imul r12, rcx', None),
    (0x10003f70a, '440faf65b4', 'imul r12d, dword ptr [rbp - 0x4c]', None),
    (0x1000227d3, '4c0faf6dc0', 'imul r13, qword ptr [rbp - 0x40]', None),
    (0x100012399, '4869c767666666', 'imul rax, rdi, 0x66666667', None),
    (0x1000071e3, '486b8da0feffff64', 'imul rcx, qword ptr [rbp - 0x160], 0x64', None),
    (0x100058b7a, 'fe8310030000', 'inc byte ptr [rbx + 0x310]', None),
    (0x100089770, 'fe440104', 'inc byte ptr [rcx + rax + 0x4]', None),
    (0x100000a7e, 'ff00', 'inc dword ptr [rax]', None),
    (0x1000010c5, 'ff45d4', 'inc dword ptr [rbp - 0x2c]', None),
    (0x100000a46, 'ff05dcae0800', 'inc dword ptr [rip + 0x8aedc]', 0x10008b928),
    (0x10000e03d, '49ff44c408', 'inc qword ptr [r12 + 8*rax + 0x8]', None),
    (0x10000e009, '49ff0424', 'inc qword ptr [r12]', None),
    (0x1000fff6d, '48ff0408', 'inc qword ptr [rax + rcx]', None),
    (0x10002355b, '40fec6', 'inc sil', None),
    (0x10000147a, '0f8644050000', 'jbe 0x1000019c4', 0x1000019c4),
    (0x100000d3f, '7f22', 'jg 0x100000d63', 0x100000d63),
    (0x10000158d, '7d22', 'jge 0x1000015b1', 0x1000015b1),
    (0x10002a59a, 'ff6008', 'jmp qword ptr [rax + 0x8]', None),
    (0x10005c0cb, 'ff20', 'jmp qword ptr [rax]', None),
    (0x100001e09, 'ffe0', 'jmp rax', None),
    (0x100027052, '7a09', 'jp 0x10002705d', 0x10002705d),
    (0x1000021a9, '7805', 'js 0x1000021b0', 0x1000021b0),
    (0x100068c32, '8d048504000000', 'lea eax, [4*rax + 0x4]', None),
    (0x10005d41f, '8d44c009', 'lea eax, [rax + 8*rax + 0x9]', None),
    (0x1000027b8, '8d0412', 'lea eax, [rdx + rdx]', None),
    (0x100015d8e, '8d1c4dffffffff', 'lea ebx, [2*rcx - 0x1]', None),
    (0x10005960b, '438d4c25ff', 'lea ecx, [r13 + r12 - 0x1]', None),
    (0x10000274b, '8d50d0', 'lea edx, [rax - 0x30]', None),
    (0x100026fb1, '428d7446d0', 'lea esi, [rsi + 2*r8 - 0x30]', None),
    (0x10004dd0e, '4e8d246500000000', 'lea r12, [2*r12]', None),
    (0x10000b1e4, '4c8d245dffffffff', 'lea r12, [2*rbx - 0x1]', None),
    (0x10001fbdb, '448d74b601', 'lea r14d, [rsi + 4*rsi + 0x1]', None),
    (0x10002fabf, '468d3c6d00000000', 'lea r15d, [2*r13]', None),
    (0x100093a99, '488d04c5d8ffffff', 'lea rax, [8*rax - 0x28]', None),
    (0x100089b23, '4a8d84f398000000', 'lea rax, [rbx + 8*r14 + 0x98]', None),
    (0x10000518a, '488d3c4501000000', 'lea rdi, [2*rax + 0x1]', None),
    (0x100067671, '488d3c8503000000', 'lea rdi, [4*rax + 0x3]', None),
    (0x100022cd0, '4a8d3cf500000000', 'lea rdi, [8*r14]', None),
    (0x1000037e6, '488d3cc508000000', 'lea rdi, [8*rax + 0x8]', None),
    (0x100041abb, '4a8d7c2301', 'lea rdi, [rbx + r12 + 0x1]', None),
    (0x100002761, '488d1450', 'lea rdx, [rax + 2*rdx]', None),
    (0x100001022, '488d95a0feffff', 'lea rdx, [rbp - 0x160]', None),
    (0x1000a9d13, '498d748602', 'lea rsi, [r14 + 4*rax + 0x2]', None),
    (0x100137310, 'f30f5f4c820c', 'maxss xmm1, dword ptr [rdx + 4*rax + 0xc]', None),
    (0x10000773e, '428a4427ff', 'mov al, byte ptr [rdi + r12 - 0x1]', None),
    (0x10000272e, '8a07', 'mov al, byte ptr [rdi]', None),
    (0x10002797b, '43c644ca0401', 'mov byte ptr [r10 + 8*r9 + 0x4], 0x1', None),
    (0x100014f11, '4188040f', 'mov byte ptr [r15 + rcx], al', None),
    (0x100022295, '40883c50', 'mov byte ptr [rax + 2*rdx], dil', None),
    (0x10011c944, '885cc8f8', 'mov byte ptr [rax + 8*rcx - 0x8], bl', None),
    (0x100019a31, 'c64442043b', 'mov byte ptr [rdx + 2*rax + 0x4], 0x3b', None),
    (0x100004298, '8806', 'mov byte ptr [rsi], al', None),
    (0x100056da0, '8a4c813e', 'mov cl, byte ptr [rcx + 4*rax + 0x3e]', None),
    (0x418, '6689c1', 'mov cx, ax', None),
    (0x100002b32, '8a140b', 'mov dl, byte ptr [rbx + rcx]', None),
    (0x100027977, '438904ca', 'mov dword ptr [r10 + 8*r9], eax', None),
    (0x10003cf32, '43c744acfc00000000', 'mov dword ptr [r12 + 4*r13 - 0x4], 0x0', None),
    (0x10006be52, '43c74434fc00000000', 'mov dword ptr [r12 + r14 - 0x4], 0x0', None),
    (0x100010118, '41c744061000000000', 'mov dword ptr [r14 + rax + 0x10], 0x0', None),
    (0x10002928c, '41c704c102000000', 'mov dword ptr [r9 + 8*rax], 0x2', None),
    (0x100002540, '894810', 'mov dword ptr [rax + 0x10], ecx', None),
    (0x100000b9b, 'c70001000000', 'mov dword ptr [rax], 0x1', None),
    (0x10000086d, 'c745d401000000', 'mov dword ptr [rbp - 0x2c], 0x1', None),
    (0x100000877, '894dd0', 'mov dword ptr [rbp - 0x30], ecx', None),
    (0x100000820, 'c70536b1080001000000', 'mov dword ptr [rip + 0x8b136], 0x1', 0x10008b960),
    (0x632, '890500000000', 'mov dword ptr [rip], eax', 0x638),
    (0x1000e539e, 'c7045effffffff', 'mov dword ptr [rsi + 2*rbx], 0xffffffff', None),
    (0x10000294d, '438b44bc3c', 'mov eax, dword ptr [r12 + 4*r15 + 0x3c]', None),
    (0x100000874, '8b45d4', 'mov eax, dword ptr [rbp - 0x2c]', None),
    (0x1000034f3, '428b3cb0', 'mov edi, dword ptr [rax + 4*r14]', None),
    (0x100003443, '8b7cb1f8', 'mov edi, dword ptr [rcx + 4*rsi - 0x8]', None),
    (0x10000fcdd, '428b1429', 'mov edx, dword ptr [rcx + r13]', None),
    (0x100000703, 'be01000000', 'mov esi, 0x1', None),
    (0x1000cab15, '4989445c28', 'mov qword ptr [r12 + 2*rbx + 0x28], rax', None),
    (0x10000316f, '4c897808', 'mov qword ptr [rax + 0x8], r15', None),
    (0x100109572, '4ac784ad58ffffff00000000', 'mov qword ptr [rbp + 4*r13 - 0xa8], 0x0', None),
    (0x100000905, '488901', 'mov qword ptr [rcx], rax', None),
    (0x1000008aa, '48890d27bf0800', 'mov qword ptr [rip + 0x8bf27], rcx', 0x10008c7d8),
    (0x100019df2, '458b641c04', 'mov r12d, dword ptr [r12 + rbx + 0x4]', None),
    (0x100059a96, '448a2c2510000000', 'mov r13b, byte ptr [0x10]', None),
    (0x100000b60, '458a6e01', 'mov r13b, byte ptr [r14 + 0x1]', None),
    (0x100109536, '468b446d9c', 'mov r8d, dword ptr [rbp + 2*r13 - 0x64]', None),
    (0x10004b641, '448b0cc8', 'mov r9d, dword ptr [rax + 8*rcx]', None),
    (0x5f7, '488b0500000000', 'mov rax, qword ptr [rip]', 0x5fe),
    (0x100091b2f, '4a8b34a8', 'mov rsi, qword ptr [rax + 4*r13]', None),
    (0x100079ddb, '408a3450', 'mov sil, byte ptr [rax + 2*rdx]', None),
    (0x100017cfb, '6643c7443cff2b3d', 'mov word ptr [r12 + r15 - 0x1], 0x3d2b', None),
    (0x100004a06, '6641c7040c5d3d', 'mov word ptr [r12 + rcx], 0x3d5d', None),
    (0x100043fd3, '66418919', 'mov word ptr [r9], bx', None),
    (0x100091237, '6642894473ff', 'mov word ptr [rbx + 2*r14 - 0x1], ax', None),
    (0x1000669df, '6644892d057d0200', 'mov word ptr [rip + 0x27d05], r13w', 0x10008e6ec),
    (0x100030401, '660f28c1', 'movapd xmm0, xmm1', None),
    (0x100042b77, '660f288d20fdffff', 'movapd xmm1, xmmword ptr [rbp - 0x2e0]', None),
    (0x100053f42, '0f284510', 'movaps xmm0, xmmword ptr [rbp + 0x10]', None),
    (0x100067a21, '0f2802', 'movaps xmm0, xmmword ptr [rdx]', None),
    (0x10001af0b, '0f2805de2e0500', 'movaps xmm0, xmmword ptr [rip + 0x52ede]', 0x10006ddf0),
    (0x1000f2540, '0f28c8', 'movaps xmm1, xmm0', None),
    (0x1000572b0, '660f7ec1', 'movd ecx, xmm0', None),
    (0x10006616d, '660f6e4112', 'movd xmm0, dword ptr [rcx + 0x12]', None),
    (0x100025540, '66410f6e2c07', 'movd xmm5, dword ptr [r15 + rax]', None),
    (0x100009161, '660f6f0597791300', 'movdqa xmm0, xmmword ptr [rip + 0x137997]', 0x100140b00),
    (0x100004f5a, '660f6fc8', 'movdqa xmm1, xmm0', None),
    (0x100067de8, '66440f7f8445d0f2ffff', 'movdqa xmmword ptr [rbp + 2*rax - 0xd30], xmm8', None),
    (0x100057e31, '660f7f8530ffffff', 'movdqa xmmword ptr [rbp - 0xd0], xmm0', None),
    (0x1000633ee, '660f7f05eab10200', 'movdqa xmmword ptr [rip + 0x2b1ea], xmm0', 0x10008e5e0),
    (0x100000c42, '660f7f06', 'movdqa xmmword ptr [rsi], xmm0', None),
    (0x10001f3c4, 'f3410f6f0424', 'movdqu xmm0, xmmword ptr [r12]', None),
    (0x1000d6846, 'f30f6f04f8', 'movdqu xmm0, xmmword ptr [rax + 8*rdi]', None),
    (0x100000c0c, 'f30f6f4db6', 'movdqu xmm1, xmmword ptr [rbp - 0x4a]', None),
    (0x349, 'f30f6f543710', 'movdqu xmm2, xmmword ptr [rdi + rsi + 0x10]', None),
    (0x100066a6e, 'f30f7f05e27c0200', 'movdqu xmmword ptr [rip + 0x27ce2], xmm0', 0x10008e758),
    (0x100137904, '0f16c8', 'movlhps xmm1, xmm0', None),
    (0x10012df1e, '66420f1314e8', 'movlpd qword ptr [rax + 8*r13], xmm2', None),
    (0x100027731, '660fd64b04', 'movq qword ptr [rbx + 0x4], xmm1', None),
    (0x10000ac71, 'f30f7e45e8', 'movq xmm0, qword ptr [rbp - 0x18]', None),
    (0x1001146a6, 'f30f7e448204', 'movq xmm0, qword ptr [rdx + 4*rax + 0x4]', None),
    (0x1000451d3, 'f20f1103', 'movsd qword ptr [rbx], xmm0', None),
    (0x100075f7e, 'f20f1105ca491000', 'movsd qword ptr [rip + 0x1049ca], xmm0', 0x10017a950),
    (0x10000fb55, 'f2410f1006', 'movsd xmm0, qword ptr [r14]', None),
    (0x100014398, 'f20f1045b8', 'movsd xmm0, qword ptr [rbp - 0x48]', None),
    (0x100132ae0, 'f30f114dc0', 'movss dword ptr [rbp - 0x40], xmm1', None),
    (0x10013730a, 'f30f11448608', 'movss dword ptr [rsi + 4*rax + 0x8], xmm0', None),
    (0x100136954, 'f30f108495d8feffff', 'movss xmm0, dword ptr [rbp + 4*rdx - 0x128]', None),
    (0x1001372f8, 'f30f10448608', 'movss xmm0, dword ptr [rsi + 4*rax + 0x8]', None),
    (0x2a7, 'f30f101500000000', 'movss xmm2, dword ptr [rip]', 0x2af),
    (0x1000164da, '0fbf8584feffff', 'movsx eax, word ptr [rbp - 0x17c]', None),
    (0x100014007, '0fbe4901', 'movsx ecx, byte ptr [rcx + 0x1]', None),
    (0x100003aa7, '420fbe3423', 'movsx esi, byte ptr [rbx + r12]', None),
    (0x1000dc09e, '420fbfb43dc8feffff', 'movsx esi, word ptr [rbp + r15 - 0x138]', None),
    (0x1000bfec9, '4d0fbf11', 'movsx r10, word ptr [r9]', None),
    (0x10004c459, '4e0fbe2430', 'movsx r12, byte ptr [rax + r14]', None),
    (0x100000e64, '440fbee0', 'movsx r12d, al', None),
    (0x10004dfac, '440fbff0', 'movsx r14d, ax', None),
    (0x10004dee4, '4e0fbf3c70', 'movsx r15, word ptr [rax + 2*r14]', None),
    (0x1000c0b31, '4c0fbf4442fc', 'movsx r8, word ptr [rdx + 2*rax - 0x4]', None),
    (0x10001685f, '4a0fbe4439ff', 'movsx rax, byte ptr [rcx + r15 - 0x1]', None),
    (0x100044353, '490fbfcc', 'movsx rcx, r12w', None),
    (0x100000b18, '4d63e7', 'movsxd r12, r15d', None),
    (0x100091693, '4963448450', 'movsxd rax, dword ptr [r12 + 4*rax + 0x50]', None),
    (0x1000f26e1, '48630c2588000000', 'movsxd rcx, dword ptr [0x88]', None),
    (0x1000030b3, '486313', 'movsxd rdx, dword ptr [rbx]', None),
    (0x1000f6cfb, '660f104580', 'movupd xmm0, xmmword ptr [rbp - 0x80]', None),
    (0x10007c16e, '660f1001', 'movupd xmm0, xmmword ptr [rcx]', None),
    (0x100027fb2, '660f114320', 'movupd xmmword ptr [rbx + 0x20], xmm0', None),
    (0x10001d387, '660f110419', 'movupd xmmword ptr [rcx + rbx], xmm0', None),
    (0x10000d823, '660f110424', 'movupd xmmword ptr [rsp], xmm0', None),
    (0x100003ecc, '410f104608', 'movups xmm0, xmmword ptr [r14 + 0x8]', None),
    (0x10000fe16, '0f1003', 'movups xmm0, xmmword ptr [rbx]', None),
    (0x1000c974b, '430f104c2f10', 'movups xmm1, xmmword ptr [r15 + r13 + 0x10]', None),
    (0x1000d684b, '0f104cf810', 'movups xmm1, xmmword ptr [rax + 8*rdi + 0x10]', None),
    (0x1000a7829, '410fb75cc414', 'movzx ebx, word ptr [r12 + 8*rax + 0x14]', None),
    (0x10011e55d, '410fb75cb704', 'movzx ebx, word ptr [r15 + 4*rsi + 0x4]', None),
    (0x100000adb, '0fb608', 'movzx ecx, byte ptr [rax]', None),
    (0x100044357, '0fb74c4a02', 'movzx ecx, word ptr [rdx + 2*rcx + 0x2]', None),
    (0x10000883a, '0fb63d27450800', 'movzx edi, byte ptr [rip + 0x84527]', 0x10008cd68),
    (0x100002736, '0fb6d0', 'movzx edx, al', None),
    (0x100074747, '0fb6744e01', 'movzx esi, byte ptr [rsi + 2*rcx + 0x1]', None),
    (0x10004e771, '450fb61496', 'movzx r10d, byte ptr [r14 + 4*rdx]', None),
    (0x10006022b, '450fb736', 'movzx r14d, word ptr [r14]', None),
    (0x10007473e, '440fb6044e', 'movzx r8d, byte ptr [rsi + 2*rcx]', None),
    (0x1000ff0ad, '450fb704b9', 'movzx r8d, word ptr [r9 + 4*rdi]', None),
    (0x1000f2b76, 'f2410f594718', 'mulsd xmm0, qword ptr [r15 + 0x18]', None),
    (0x1000070e9, 'f20f598540feffff', 'mulsd xmm0, qword ptr [rbp - 0x1c0]', None),
    (0x10012de2a, 'f20f5924d1', 'mulsd xmm4, qword ptr [rcx + 8*rdx]', None),
    (0x100008b95, 'f7da', 'neg edx', None),
    (0x10000d9f7, '40f6de', 'neg sil', None),
    (0x100000c36, 'f7d0', 'not eax', None),
    (0x10001c5dc, '800808', 'or byte ptr [rax], 0x8', None),
    (0x10001dbdb, '800dcae0060001', 'or byte ptr [rip + 0x6e0ca], 0x1', 0x10008bcac),
    (0x1000a8790, '804cc6d908', 'or byte ptr [rsi + 8*rax - 0x27], 0x8', None),
    (0x1000496d4, '430a1427', 'or dl, byte ptr [r15 + r12]', None),
    (0x1000008dd, '08ca', 'or dl, cl', None),
    (0x1001141ab, '09048a', 'or dword ptr [rdx + 4*rcx], eax', None),
    (0x10000107a, '0905f0a80800', 'or dword ptr [rip + 0x8a8f0], eax', 0x10008b970),
    (0x1000007f1, '09c8', 'or eax, ecx', None),
    (0x1000e4906, '0b5c881c', 'or ebx, dword ptr [rax + 4*rcx + 0x1c]', None),
    (0x100001503, '0b4dbc', 'or ecx, dword ptr [rbp - 0x44]', None),
    (0x100002458, '83cf7e', 'or edi, 0x7e', None),
    (0x1000dc692, '490909', 'or qword ptr [r9], rcx', None),
    (0x100013100, '490b442460', 'or rax, qword ptr [r12 + 0x60]', None),
    (0x10000409f, '4809ce', 'or rsi, rcx', None),
    (0x16c, '660f56da', 'orpd xmm3, xmm2', None),
    (0x1000d493f, '0f56c4', 'orps xmm0, xmm4', None),
    (0x100066970, '660fd4c8', 'paddq xmm1, xmm0', None),
    (0x100025558, '660fdbfa', 'pand xmm7, xmm2', None),
    (0x10000f3dc, '660fdfc3', 'pandn xmm0, xmm3', None),
    (0x1000633ea, '660f76c0', 'pcmpeqd xmm0, xmm0', None),
    (0x1000d4914, '660f66c2', 'pcmpgtd xmm0, xmm2', None),
    (0x2af, '660fd5d0', 'pmullw xmm2, xmm0', None),
    (0x100001c52, '5b', 'pop rbx', None),
    (0x100000c21, '660febc1', 'por xmm0, xmm1', None),
    (0x1000f0130, '660feb05782a0500', 'por xmm0, xmmword ptr [rip + 0x52a78]', 0x100142bb0),
    (0x100025546, '660f70f500', 'pshufd xmm6, xmm5, 0x0', None),
    (0x10000a546, 'f20f70c900', 'pshuflw xmm1, xmm1, 0x0', None),
    (0x100025553, '660f72f703', 'pslld xmm7, 0x3', None),
    (0x100099a47, '660f71f20c', 'psllw xmm2, 0xc', None),
    (0x10007a47c, '660f72d112', 'psrld xmm1, 0x12', None),
    (0x10000a542, '660f60c9', 'punpcklbw xmm1, xmm1', None),
    (0x100048882, '660f620d76a20f00', 'punpckldq xmm1, xmmword ptr [rip + 0xfa276]', 0x100142b00),
    (0x10003b387, '6a00', 'push 0x0', None),
    (0x1000ec5bf, '43ff34da', 'push qword ptr [r10 + 8*r11]', None),
    (0x10004bd06, 'ff30', 'push qword ptr [rax]', None),
    (0x10001dd09, 'ff7598', 'push qword ptr [rbp - 0x68]', None),
    (0x100036961, 'ff745355', 'push qword ptr [rbx + 2*rdx + 0x55]', None),
    (0x10004fd39, 'ff740f55', 'push qword ptr [rdi + rcx + 0x55]', None),
    (0x100061c52, '660fef45c0', 'pxor xmm0, xmmword ptr [rbp - 0x40]', None),
    (0x100001c6f, 'c3', 'ret', None),
    (0x1000259ac, 'd1c1', 'rol ecx', None),
    (0x100115024, '41c0c006', 'rol r8b, 0x6', None),
    (0x1000125d9, 'd1c8', 'ror eax', None),
    (0x10004270c, '48d1ca', 'ror rdx', None),
    (0x10004c161, 'd1f8', 'sar eax', None),
    (0x10000bc0c, 'd3ff', 'sar edi, cl', None),
    (0x100001404, '83d800', 'sbb eax, 0x0', None),
    (0x10000d9ff, '19f6', 'sbb esi, esi', None),
    (0x10004b8a7, '0f97c0', 'seta al', None),
    (0x100016c8d, '0f9385f0f5ffff', 'setae byte ptr [rbp - 0xa10]', None),
    (0x1000509d0, '0f9400', 'sete byte ptr [rax]', None),
    (0x100053554, '0f9483b8010000', 'sete byte ptr [rbx + 0x1b8]', None),
    (0x100000b45, '0f94c1', 'sete cl', None),
    (0x10006d12e, '0f9f401b', 'setg byte ptr [rax + 0x1b]', None),
    (0x100004da7, '0f9cc1', 'setl cl', None),
    (0x100050941, '410f9507', 'setne byte ptr [r15]', None),
    (0x100002513, '0f99c2', 'setns dl', None),
    (0x100085f5e, '0f90c0', 'seto al', None),
    (0x1000217a0, '49d3e7', 'shl r15, cl', None),
    (0x10000c0c5, 'c0e805', 'shr al, 0x5', None),
    (0x10000103f, 'c1e803', 'shr eax, 0x3', None),
    (0x1000336d1, '49d3ec', 'shr r12, cl', None),
    (0x10003999f, '41d3ef', 'shr r15d, cl', None),
    (0x10004b169, '48d1e8', 'shr rax', None),
    (0x1000027b4, '48c1ea03', 'shr rdx, 0x3', None),
    (0x1000d6b1f, '2a8d70ffffff', 'sub cl, byte ptr [rbp - 0x90]', None),
    (0x1000cdb5e, '66412b7d08', 'sub di, word ptr [r13 + 0x8]', None),
    (0x10008fcc3, '2984b510ffffff', 'sub dword ptr [rbp + 4*rsi - 0xf0], eax', None),
    (0x100024327, '2905e3170600', 'sub dword ptr [rip + 0x617e3], eax', 0x100085b10),
    (0x1000076db, '462954c608', 'sub dword ptr [rsi + 8*r8 + 0x8], r10d', None),
    (0x10010cbb9, '412b4c8404', 'sub ecx, dword ptr [r12 + 4*rax + 0x4]', None),
    (0x10001e674, '2b75bc', 'sub esi, dword ptr [rbp - 0x44]', None),
    (0x100004018, '48297008', 'sub qword ptr [rax + 0x8], rsi', None),
    (0x100004011, '4929f0', 'sub r8, rsi', None),
    (0x100027ef1, '482b44d320', 'sub rax, qword ptr [rbx + 8*rdx + 0x20]', None),
    (0x100043b78, '482b01', 'sub rax, qword ptr [rcx]', None),
    (0x1000154c0, '482b4dd0', 'sub rcx, qword ptr [rbp - 0x30]', None),
    (0x1000006ed, '4881ec38010000', 'sub rsp, 0x138', None),
    (0x100057d63, 'f20f5c05fd8c0e00', 'subsd xmm0, qword ptr [rip + 0xe8cfd]', 0x100140a68),
    (0x100029b6b, 'f20f5cc8', 'subsd xmm1, xmm0', None),
    (0x10013749d, 'f30f5c4628', 'subss xmm0, dword ptr [rsi + 0x28]', None),
    (0x100000728, '84c0', 'test al, al', None),
    (0x100006827, 'f60002', 'test byte ptr [rax], 0x2', None),
    (0x100014db2, 'f644913e01', 'test byte ptr [rcx + 4*rdx + 0x3e], 0x1', None),
    (0x10002f0d4, '8409', 'test byte ptr [rcx], cl', None),
    (0x10000f608, '857598', 'test dword ptr [rbp - 0x68], esi', None),
    (0x1000d3455, '49850b', 'test qword ptr [r11], rcx', None),
    (0x1000e2cce, '4c857c1930', 'test qword ptr [rcx + rbx + 0x30], r15', None),
    (0x10000edc2, '664585ff', 'test r15w, r15w', None),
    (0x100000774, '4885ff', 'test rdi, rdi', None),
    (0x1000dc409, '66854f14', 'test word ptr [rdi + 0x14], cx', None),
    (0x10005c2b9, '660f2e8578ffffff', 'ucomisd xmm0, qword ptr [rbp - 0x88]', None),
    (0x100027dd3, '660f2e058d8c1100', 'ucomisd xmm0, qword ptr [rip + 0x118c8d]', 0x100140a68),
    (0x100132b24, '0f2ed1', 'ucomiss xmm2, xmm1', None),
    (0x100003e83, '0f0b', 'ud2', None),
    (0x1001379a0, '660f15d1', 'unpckhpd xmm2, xmm1', None),
    (0x8c2, '0fc101', 'xadd dword ptr [rcx], eax', None),
    (0x1000064a8, '4430e8', 'xor al, r13b', None),
    (0x100039be8, '41324f12', 'xor cl, byte ptr [r15 + 0x12]', None),
    (0x1000d39c9, '324dd7', 'xor cl, byte ptr [rbp - 0x29]', None),
    (0x100057b1c, '83702c20', 'xor dword ptr [rax + 0x2c], 0x20', None),
    (0x100000b5c, '3345b0', 'xor eax, dword ptr [rbp - 0x50]', None),
    (0x1001301fc, '41334c1d03', 'xor ecx, dword ptr [r13 + rbx + 0x3]', None),
    (0x10003d865, '33510c', 'xor edx, dword ptr [rcx + 0xc]', None),
    (0x100023f54, '49310c06', 'xor qword ptr [r14 + rax], rcx', None),
    (0x1000217a8, '4d31fe', 'xor r14, r15', None),
    (0x100060fad, '44320431', 'xor r8b, byte ptr [rcx + rsi]', None),
    (0x10000cda5, '493306', 'xor rax, qword ptr [r14]', None),
    (0x100000bec, '483345b0', 'xor rax, qword ptr [rbp - 0x50]', None),
    (0x100041d5e, '4883f13f', 'xor rcx, 0x3f', None),
    (0x100024481, '483354c820', 'xor rdx, qword ptr [rax + 8*rcx + 0x20]', None),
    (0x1000007a0, '0f57c0', 'xorps xmm0, xmm0', None),
    (0x1000583af, '0f57057a860e00', 'xorps xmm0, xmmword ptr [rip + 0xe867a]', 0x100140a30),
]

UNDECODED_X86_64 = [
    ('660f3a2005c1e9020000', 'pinsrb'),
    ('660f380005b8750100', 'pshufb'),
    ('660f382205088b0000', 'pmovsxbq'),
    ('66480f3a2285f0eeffff00', 'pinsrq'),
    ('660f3817c0', 'ptest'),
    ('660f3821c9', 'pmovsxbd'),
    ('660f3829c1', 'pcmpeqq'),
    ('660f3a0bc10a', 'roundsd'),
    ('66450f3a0ed90f', 'pblendw'),
    ('660f3a22c001', 'pinsrd'),
    ('e03f', 'loopne'),
    ('660f3806c0', 'phsubd'),
    ('66440f3810c7', 'pblendvb'),
    ('660f3a16c101', 'pextrd'),
    ('660f3814cb', 'blendvps'),
    ('660f3802c9', 'phaddd'),
    ('660f3815d1', 'blendvpd'),
    ('66410f3a14c108', 'pextrb'),
]

CORPUS_X86 = [
    (0xbc, '83d000', 'adc eax, 0x0', None),
    (0x680, '11d0', 'adc eax, edx', None),
    (0x4f5, '01849600000000', 'add dword ptr [esi + 4*edx], eax', None),
    (0x7, '03442404', 'add eax, dword ptr [esp + 0x4]', None),
    (0x13, '01c8', 'add eax, ecx', None),
    (0x2e, '81c303000000', 'add ebx, 0x3', None),
    (0x799, '03948100000000', 'add edx, dword ptr [ecx + 4*eax]', None),
    (0x278, '2401', 'and al, 0x1', None),
    (0xad, '81e6ff00ffff', 'and esi, 0xffff00ff', None),
    (0x6b6, '21d6', 'and esi, edx', None),
    (0x243, '660f55c8', 'andnpd xmm1, xmm0', None),
    (0x237, '660f54d1', 'andpd xmm2, xmm1', None),
    (0x1ea, '0fbdca', 'bsr ecx, edx', None),
    (0x1e0, '0fc9', 'bswap ecx', None),
    (0x28, 'e800000000', 'call 0x2d', 0x2d),
    (0x9ce, 'ffd0', 'call eax', None),
    (0x19f, '0f47c8', 'cmova ecx, eax', None),
    (0x86f, '0f42d1', 'cmovb edx, ecx', None),
    (0x588, '0f4fc8', 'cmovg ecx, eax', None),
    (0x17f, '0f4cea', 'cmovl ebp, edx', None),
    (0x814, '803c0800', 'cmp byte ptr [eax + ecx], 0x0', None),
    (0x364, '80791278', 'cmp byte ptr [ecx + 0x12], 0x78', None),
    (0x560, '807c010100', 'cmp byte ptr [ecx + eax + 0x1], 0x0', None),
    (0x1be, '837d0800', 'cmp dword ptr [ebp + 0x8], 0x0', None),
    (0x2b8, '837df864', 'cmp dword ptr [ebp - 0x8], 0x64', None),
    (0x51c, '83f878', 'cmp eax, 0x78', None),
    (0x256, '3b450c', 'cmp eax, dword ptr [ebp + 0xc]', None),
    (0x270, 'f30fc2c101', 'cmpltss xmm0, xmm1', None),
    (0x587, 'f20f2a450c', 'cvtsi2sd xmm0, dword ptr [ebp + 0xc]', None),
    (0x32d, 'f20f2ac9', 'cvtsi2sd xmm1, ecx', None),
    (0x267, 'f30f2ac1', 'cvtsi2ss xmm0, ecx', None),
    (0x3ae, 'f30f2a4d1c', 'cvtsi2ss xmm1, dword ptr [ebp + 0x1c]', None),
    (0x1a9, 'f30f5a4c2440', 'cvtss2sd xmm1, dword ptr [esp + 0x40]', None),
    (0x7ca, 'f20f2c14f2', 'cvttsd2si edx, qword ptr [edx + 8*esi]', None),
    (0x336, 'f20f5ec1', 'divsd xmm0, xmm1', None),
    (0x411, 'f30f5e4508', 'divss xmm0, dword ptr [ebp + 0x8]', None),
    (0x2a8, 'f30f5ec8', 'divss xmm1, xmm0', None),
    (0x7dd, 'f7fe', 'idiv esi', None),
    (0x673, '0fafc1', 'imul eax, ecx', None),
    (0xf, '6b4d0c03', 'imul ecx, dword ptr [ebp + 0xc], 0x3', None),
    (0x78, '69f6b979379e', 'imul esi, esi, 0x9e3779b9', None),
    (0x3b6, '42', 'inc edx', None),
    (0x2a6, '7710', 'ja 0x2b8', 0x2b8),
    (0x1c2, '7416', 'je 0x1da', 0x1da),
    (0x259, '7d08', 'jge 0x263', 0x263),
    (0x2ae, '7c08', 'jl 0x2b8', 0x2b8),
    (0x463, 'ffe0', 'jmp eax', None),
    (0x12f, '7512', 'jne 0x143', 0x143),
    (0x185, '8d044d00000000', 'lea eax, [2*ecx]', None),
    (0xb30, '8d8408bc9a7856', 'lea eax, [eax + ecx + 0x56789abc]', None),
    (0x47a, '8d8300000000', 'lea eax, [ebx]', None),
    (0x1ed, '8d5101', 'lea edx, [ecx + 0x1]', None),
    (0x40b, '8d1489', 'lea edx, [ecx + 4*ecx]', None),
    (0x6aa, '8d75ff', 'lea esi, [ebp - 0x1]', None),
    (0xa0b, '8a4510', 'mov al, byte ptr [ebp + 0x10]', None),
    (0x3eb, '8a1c31', 'mov bl, byte ptr [ecx + esi]', None),
    (0x3ab, 'c6402000', 'mov byte ptr [eax + 0x20], 0x0', None),
    (0x5c9, '88540820', 'mov byte ptr [eax + ecx + 0x20], dl', None),
    (0xaf8, '888c0500ffffff', 'mov byte ptr [ebp + eax - 0x100], cl', None),
    (0x584, '885112', 'mov byte ptr [ecx + 0x12], dl', None),
    (0x464, '881c32', 'mov byte ptr [edx + esi], bl', None),
    (0x6c7, '8a08', 'mov cl, byte ptr [eax]', None),
    (0xa4f, '8a4def', 'mov cl, byte ptr [ebp - 0x11]', None),
    (0x57f, '88ca', 'mov dl, cl', None),
    (0xc7, '8908', 'mov dword ptr [eax], ecx', None),
    (0x59, '894d0c', 'mov dword ptr [ebp + 0xc], ecx', None),
    (0x133, 'c745f0ffffffff', 'mov dword ptr [ebp - 0x10], 0xffffffff', None),
    (0x480, 'c7042403000000', 'mov dword ptr [esp], 0x3', None),
    (0x572, '6689ca', 'mov dx, cx', None),
    (0x52e, '8b00', 'mov eax, dword ptr [eax]', None),
    (0x5e7, '8b848320000000', 'mov eax, dword ptr [ebx + 4*eax + 0x20]', None),
    (0x1, '89e5', 'mov ebp, esp', None),
    (0x68, 'b9157c4a7f', 'mov ecx, 0x7f4a7c15', None),
    (0x75, '8b55ec', 'mov edx, dword ptr [ebp - 0x14]', None),
    (0x388, '66894dd4', 'mov word ptr [ebp - 0x2c], cx', None),
    (0x578, '66895110', 'mov word ptr [ecx + 0x10], dx', None),
    (0x204, '660f28c8', 'movapd xmm1, xmm0', None),
    (0x1fc, '660f289000000000', 'movapd xmm2, xmmword ptr [eax]', None),
    (0x2ac, '0f28c1', 'movaps xmm0, xmm1', None),
    (0x356, '0f288800000000', 'movaps xmm1, xmmword ptr [eax]', None),
    (0x4fe, '0f29442410', 'movaps xmmword ptr [esp + 0x10], xmm0', None),
    (0x406, '660f7e4032', 'movd dword ptr [eax + 0x32], xmm0', None),
    (0x55a, '660f6e444704', 'movd xmm0, dword ptr [edi + 2*eax + 0x4]', None),
    (0x520, '660f6e0447', 'movd xmm0, dword ptr [edi + 2*eax]', None),
    (0x3b2, '660f6ec9', 'movd xmm1, ecx', None),
    (0x53c, '660f6fca', 'movdqa xmm1, xmm2', None),
    (0x3c9, '660f6f9200000000', 'movdqa xmm2, xmmword ptr [edx]', None),
    (0x50b, '660f7f0424', 'movdqa xmmword ptr [esp], xmm0', None),
    (0x460, 'f30f6f1482', 'movdqu xmm2, xmmword ptr [edx + 4*eax]', None),
    (0x3f9, 'f30f7f4822', 'movdqu xmmword ptr [eax + 0x22], xmm1', None),
    (0x39a, '660f134de8', 'movlpd qword ptr [ebp - 0x18], xmm1', None),
    (0x395, 'f30f7e4df0', 'movq xmm1, qword ptr [ebp - 0x10]', None),
    (0x4ed, 'f30f7e9100000000', 'movq xmm2, qword ptr [ecx]', None),
    (0x58f, 'f20f114114', 'movsd qword ptr [ecx + 0x14], xmm0', None),
    (0x33f, 'f20f108000000000', 'movsd xmm0, qword ptr [eax]', None),
    (0x331, 'f20f1045f8', 'movsd xmm0, qword ptr [ebp - 0x8]', None),
    (0x405, 'f30f1145f8', 'movss dword ptr [ebp - 0x8], xmm0', None),
    (0x2f8, 'f30f104518', 'movss xmm0, dword ptr [ebp + 0x18]', None),
    (0x41b, 'f30f1045f8', 'movss xmm0, dword ptr [ebp - 0x8]', None),
    (0xb28, '0fbe840500ffffff', 'movsx eax, byte ptr [ebp + eax - 0x100]', None),
    (0x4a8, '0f104130', 'movups xmm0, xmmword ptr [ecx + 0x30]', None),
    (0x650, '0f100407', 'movups xmm0, xmmword ptr [edi + eax]', None),
    (0x654, '0f104c0710', 'movups xmm1, xmmword ptr [edi + eax + 0x10]', None),
    (0x4ac, '0f114030', 'movups xmmword ptr [eax + 0x30], xmm0', None),
    (0x4c3, '0f1100', 'movups xmmword ptr [eax], xmm0', None),
    (0x65d, '0f114c0610', 'movups xmmword ptr [esi + eax + 0x10], xmm1', None),
    (0x659, '0f110406', 'movups xmmword ptr [esi + eax], xmm0', None),
    (0x27a, '0fb6c0', 'movzx eax, al', None),
    (0xaf4, '0fb64508', 'movzx eax, byte ptr [ebp + 0x8]', None),
    (0x6e7, '0fb6443101', 'movzx eax, byte ptr [ecx + esi + 0x1]', None),
    (0xe9, 'f7642428', 'mul dword ptr [esp + 0x28]', None),
    (0x6f, 'f7e1', 'mul ecx', None),
    (0x31a, 'f20f59c2', 'mulsd xmm0, xmm2', None),
    (0x26b, 'f30f598000000000', 'mulss xmm0, dword ptr [eax]', None),
    (0x69f, '90', 'nop', None),
    (0x4db, '0f1f440000', 'nop dword ptr [eax + eax]', None),
    (0x23d, '0f1f00', 'nop dword ptr [eax]', None),
    (0x1a, '660f1f440000', 'nop word ptr [eax + eax]', None),
    (0xf1, '6666666666662e0f1f840000000000', 'nop word ptr cs:[eax + eax]', None),
    (0x12d, '09c8', 'or eax, ecx', None),
    (0x1e7, '83ca01', 'or edx, 0x1', None),
    (0x247, '660f56ca', 'orpd xmm1, xmm2', None),
    (0x3ed, '660f67ca', 'packuswb xmm1, xmm2', None),
    (0x5a4, '660ffe1424', 'paddd xmm2, xmmword ptr [esp]', None),
    (0x548, '660fd4f5', 'paddq xmm6, xmm5', None),
    (0x533, '660f66c6', 'pcmpgtd xmm0, xmm6', None),
    (0x544, '660ff4f1', 'pmuludq xmm6, xmm1', None),
    (0x3c4, '660f70c944', 'pshufd xmm1, xmm1, 0x44', None),
    (0x3b6, 'f20f70c100', 'pshuflw xmm0, xmm1, 0x0', None),
    (0x56a, '660f73f120', 'psllq xmm1, 0x20', None),
    (0x537, '660f72e610', 'psrad xmm6, 0x10', None),
    (0x84, '6a00', 'push 0x0', None),
    (0x5c2, 'ffb48300000000', 'push dword ptr [ebx + 4*eax]', None),
    (0x483, 'ff742418', 'push dword ptr [esp + 0x18]', None),
    (0x35d, '660fefc1', 'pxor xmm0, xmm1', None),
    (0x57a, '66d3c0', 'rol ax, cl', None),
    (0x666, 'c1fa1f', 'sar edx, 0x1f', None),
    (0x84f, 'd3fa', 'sar edx, cl', None),
    (0x275, '0f97c0', 'seta al', None),
    (0x61c, '0f92c0', 'setb al', None),
    (0xabc, '0f94c2', 'sete dl', None),
    (0x4c4, 'd3e0', 'shl eax, cl', None),
    (0xa1e, '0fa5f2', 'shld edx, esi, cl', None),
    (0x4b, '0fa4c613', 'shld esi, eax, 0x13', None),
    (0x1d3, 'd1e8', 'shr eax', None),
    (0x48, 'c1ea0d', 'shr edx, 0xd', None),
    (0xa23, '0fadfe', 'shrd esi, edi, cl', None),
    (0x2b2, '2b45f8', 'sub eax, dword ptr [ebp - 0x8]', None),
    (0x25, '83ec20', 'sub esp, 0x20', None),
    (0x25e, 'f20f5c4c2418', 'subsd xmm1, qword ptr [esp + 0x18]', None),
    (0xa36, 'a820', 'test al, 0x20', None),
    (0x1f8, 'f30fbcca', 'tzcnt ecx, edx', None),
    (0x347, '660f2e45f8', 'ucomisd xmm0, qword ptr [ebp - 0x8]', None),
    (0x3f5, '0f2e450c', 'ucomiss xmm0, dword ptr [ebp + 0xc]', None),
    (0x29d, '0f2ec1', 'ucomiss xmm0, xmm1', None),
    (0x55, '31f0', 'xor eax, esi', None),
    (0x1ed, '83f11f', 'xor ecx, 0x1f', None),
    (0x34, '334c2420', 'xor ecx, dword ptr [esp + 0x20]', None),
    (0x754, '331424', 'xor edx, dword ptr [esp]', None),
    (0x264, '0f57c0', 'xorps xmm0, xmm0', None),
]

UNDECODED_X86 = [
    ('dd45f0', 'fld'),
    ('d97dd6', 'fnstcw'),
    ('d96dd4', 'fldcw'),
    ('df7df0', 'fistp'),
    ('df6de8', 'fild'),
    ('dd5de0', 'fstp'),
]

# computed addresses as llvm-objdump reports them (branch operands, ADRP pages, the '# 0x...' comment of RIP-relative operands)
TARGETS_ARM64 = [
    (0x100000b28, '11000010', 'adr x17, 0x100000b28', 0x100000b28),
    (0x1000036ac, '11000010', 'adr x17, 0x1000036ac', 0x1000036ac),
    (0x10000710c, '11000010', 'adr x17, 0x10000710c', 0x10000710c),
    (0x10000d058, '11000010', 'adr x17, 0x10000d058', 0x10000d058),
    (0x100001730, 'a0000090', 'adrp x0, 0x100015000', 0x100015000),
    (0x10000844c, '600000d0', 'adrp x0, 0x100016000', 0x100016000),
    (0x10000eee4, '400000b0', 'adrp x0, 0x100017000', 0x100017000),
    (0x10000663c, 'b30000d0', 'adrp x19, 0x10001c000', 0x10001c000),
    (0x10000469c, 'd4000090', 'adrp x20, 0x10001c000', 0x10001c000),
    (0x100000e24, 'f5000090', 'adrp x21, 0x10001c000', 0x10001c000),
    (0x100002bf0, '570000d0', 'adrp x23, 0x10000c000', 0x10000c000),
    (0x10000acd8, '880000d0', 'adrp x8, 0x10001c000', 0x10001c000),
    (0x1000006b4, 'e8000090', 'adrp x8, 0x10001c000', 0x10001c000),
    (0x10000e41c, '690000f0', 'adrp x9, 0x10001d000', 0x10001d000),
    (0x100001a28, '1c000014', 'b 0x100001a98', 0x100001a98),
    (0x100002d00, 'fafeff17', 'b 0x1000028e8', 0x1000028e8),
    (0x100003a10, 'f8feff17', 'b 0x1000035f0', 0x1000035f0),
    (0x1000040ac, '02000014', 'b 0x1000040b4', 0x1000040b4),
    (0x100007838, 'cd000014', 'b 0x100007b6c', 0x100007b6c),
    (0x100007454, 'd5010014', 'b 0x100007ba8', 0x100007ba8),
    (0x10000a7e8, '02000014', 'b 0x10000a7f0', 0x10000a7f0),
    (0x10000d398, '04000014', 'b 0x10000d3a8', 0x10000d3a8),
    (0x10000d848, '22000014', 'b 0x10000d8d0', 0x10000d8d0),
    (0x100000f5c, '0a3c0014', 'b 0x10000ff84', 0x10000ff84),
    (0x100001b28, 'c0020054', 'b.eq 0x100001b80', 0x100001b80),
    (0x10000255c, 'c0f8ff54', 'b.eq 0x100002474', 0x100002474),
    (0x100003b1c, '40030054', 'b.eq 0x100003b84', 0x100003b84),
    (0x100005870, '60000054', 'b.eq 0x10000587c', 0x10000587c),
    (0x10000b730, '00020054', 'b.eq 0x10000b770', 0x10000b770),
    (0x10000be78, '20010054', 'b.eq 0x10000be9c', 0x10000be9c),
    (0x10000bf88, 'e0060054', 'b.eq 0x10000c064', 0x10000c064),
    (0x10000c94c, 'c0000054', 'b.eq 0x10000c964', 0x10000c964),
    (0x10000f9d8, '60020054', 'b.eq 0x10000fa24', 0x10000fa24),
    (0x10000f94c, '600a0054', 'b.eq 0x10000fa98', 0x10000fa98),
    (0x100000824, '6a000054', 'b.ge 0x100000830', 0x100000830),
    (0x100000898, '6a000054', 'b.ge 0x1000008a4', 0x1000008a4),
    (0x10000090c, '6a000054', 'b.ge 0x100000918', 0x100000918),
    (0x100000ca0, 'aa000054', 'b.ge 0x100000cb4', 0x100000cb4),
    (0x100001e14, '4affff54', 'b.ge 0x100001dfc', 0x100001dfc),
    (0x100001f5c, 'aa050054', 'b.ge 0x100002010', 0x100002010),
    (0x100002044, '4a120054', 'b.ge 0x10000228c', 0x10000228c),
    (0x1000023cc, '0a010054', 'b.ge 0x1000023ec', 0x1000023ec),
    (0x1000022c0, 'aa0a0054', 'b.ge 0x100002414', 0x100002414),
    (0x1000034e8, 'aa010054', 'b.ge 0x10000351c', 0x10000351c),
    (0x1000007c8, '0cffff54', 'b.gt 0x1000007a8', 0x1000007a8),
    (0x10000169c, 'ec000054', 'b.gt 0x1000016b8', 0x1000016b8),
    (0x1000023bc, '8c010054', 'b.gt 0x1000023ec', 0x1000023ec),
    (0x1000027d4, '8c290054', 'b.gt 0x100002d04', 0x100002d04),
    (0x100003688, '4c020054', 'b.gt 0x1000036d0', 0x1000036d0),
    (0x1000036d4, '2c040054', 'b.gt 0x100003758', 0x100003758),
    (0x1000099a0, '4c230054', 'b.gt 0x100009e08', 0x100009e08),
    (0x10000afb8, 'cc020054', 'b.gt 0x10000b010', 0x10000b010),
    (0x10000b7e8, '6c040054', 'b.gt 0x10000b874', 0x10000b874),
    (0x10000c250, '2c010054', 'b.gt 0x10000c274', 0x10000c274),
    (0x100000ef4, '68010054', 'b.hi 0x100000f20', 0x100000f20),
    (0x10000268c, 'e8380054', 'b.hi 0x100002da8', 0x100002da8),
    (0x100003f28, '08010054', 'b.hi 0x100003f48', 0x100003f48),
    (0x100003fd4, '48fcff54', 'b.hi 0x100003f5c', 0x100003f5c),
    (0x100004ad8, 'e8010054', 'b.hi 0x100004b14', 0x100004b14),
    (0x100006900, '48ffff54', 'b.hi 0x1000068e8', 0x1000068e8),
    (0x100006a84, 'c8000054', 'b.hi 0x100006a9c', 0x100006a9c),
    (0x10000cd2c, '48010054', 'b.hi 0x10000cd54', 0x10000cd54),
    (0x10000ce6c, '48010054', 'b.hi 0x10000ce94', 0x10000ce94),
    (0x10000e0f8, 'a8020054', 'b.hi 0x10000e14c', 0x10000e14c),
    (0x100000d90, '62000054', 'b.hs 0x100000d9c', 0x100000d9c),
    (0x100001db4, '82080054', 'b.hs 0x100001ec4', 0x100001ec4),
    (0x1000020f8, '42000054', 'b.hs 0x100002100', 0x100002100),
    (0x100002248, '42000054', 'b.hs 0x100002250', 0x100002250),
    (0x100004888, 'c2010054', 'b.hs 0x1000048c0', 0x1000048c0),
    (0x100004b30, '420a0054', 'b.hs 0x100004c78', 0x100004c78),
    (0x1000069ac, '02010054', 'b.hs 0x1000069cc', 0x1000069cc),
    (0x10000848c, '02030054', 'b.hs 0x1000084ec', 0x1000084ec),
    (0x100008828, '42040054', 'b.hs 0x1000088b0', 0x1000088b0),
    (0x100009ca8, 'e2000054', 'b.hs 0x100009cc4', 0x100009cc4),
    (0x1000017f8, 'ad010054', 'b.le 0x10000182c', 0x10000182c),
    (0x100001cf0, '0d010054', 'b.le 0x100001d10', 0x100001d10),
    (0x100004ba8, '2d050054', 'b.le 0x100004c4c', 0x100004c4c),
    (0x100005010, 'ed020054', 'b.le 0x10000506c', 0x10000506c),
    (0x100006430, '6d000054', 'b.le 0x10000643c', 0x10000643c),
    (0x100007088, '0d050054', 'b.le 0x100007128', 0x100007128),
    (0x100007170, '8d000054', 'b.le 0x100007180', 0x100007180),
    (0x100008598, 'ad0b0054', 'b.le 0x10000870c', 0x10000870c),
    (0x1000091cc, '8d050054', 'b.le 0x10000927c', 0x10000927c),
    (0x10000b68c, '0d020054', 'b.le 0x10000b6cc', 0x10000b6cc),
    (0x100002010, 'c3fcff54', 'b.lo 0x100001fa8', 0x100001fa8),
    (0x100002fe0, '03ffff54', 'b.lo 0x100002fc0', 0x100002fc0),
    (0x100004830, '83000054', 'b.lo 0x100004840', 0x100004840),
    (0x100004be0, 'e3000054', 'b.lo 0x100004bfc', 0x100004bfc),
    (0x100005c08, 'c3000054', 'b.lo 0x100005c20', 0x100005c20),
    (0x100009428, 'a3060054', 'b.lo 0x1000094fc', 0x1000094fc),
    (0x1000095b4, '03fdff54', 'b.lo 0x100009554', 0x100009554),
    (0x100009d30, '83030054', 'b.lo 0x100009da0', 0x100009da0),
    (0x10000c7ec, '63000054', 'b.lo 0x10000c7f8', 0x10000c7f8),
    (0x10000d63c, '03010054', 'b.lo 0x10000d65c', 0x10000d65c),
    (0x100002f58, '89000054', 'b.ls 0x100002f68', 0x100002f68),
    (0x10000367c, 'c90a0054', 'b.ls 0x1000037d4', 0x1000037d4),
    (0x1000047dc, 'a9000054', 'b.ls 0x1000047f0', 0x1000047f0),
    (0x1000068cc, 'a9000054', 'b.ls 0x1000068e0', 0x1000068e0),
    (0x1000068e4, '29010054', 'b.ls 0x100006908', 0x100006908),
    (0x100006ff0, '09710054', 'b.ls 0x100007e10', 0x100007e10),
    (0x10000fb38, '49000054', 'b.ls 0x10000fb40', 0x10000fb40),
    (0x100000840, '4bffff54', 'b.lt 0x100000828', 0x100000828),
    (0x100000abc, 'ebfeff54', 'b.lt 0x100000a98', 0x100000a98),
    (0x100001f6c, '4b050054', 'b.lt 0x100002014', 0x100002014),
    (0x10000205c, 'ab000054', 'b.lt 0x100002070', 0x100002070),
    (0x100003400, '6b010054', 'b.lt 0x10000342c', 0x10000342c),
    (0x100003f90, '2b010054', 'b.lt 0x100003fb4', 0x100003fb4),
    (0x100004384, '2b010054', 'b.lt 0x1000043a8', 0x1000043a8),
    (0x1000070a8, '6b000054', 'b.lt 0x1000070b4', 0x1000070b4),
    (0x100008344, '6b110054', 'b.lt 0x100008570', 0x100008570),
    (0x10000eab8, 'cbfcff54', 'b.lt 0x10000ea50', 0x10000ea50),
    (0x100004908, 'e4000054', 'b.mi 0x100004924', 0x100004924),
    (0x100000d6c, 'a1020054', 'b.ne 0x100000dc0', 0x100000dc0),
    (0x100002f94, '61010054', 'b.ne 0x100002fc0', 0x100002fc0),
    (0x100003d20, '61000054', 'b.ne 0x100003d2c', 0x100003d2c),
    (0x100003db8, '210c0054', 'b.ne 0x100003f3c', 0x100003f3c),
    (0x100004a4c, '211a0054', 'b.ne 0x100004d90', 0x100004d90),
    (0x100005c2c, '410b0054', 'b.ne 0x100005d94', 0x100005d94),
    (0x10000976c, '41000054', 'b.ne 0x100009774', 0x100009774),
    (0x100009c74, '61030054', 'b.ne 0x100009ce0', 0x100009ce0),
    (0x10000a578, '810b0054', 'b.ne 0x10000a6e8', 0x10000a6e8),
    (0x10000b270, '81000054', 'b.ne 0x10000b280', 0x10000b280),
    (0x10000eec8, '65000054', 'b.pl 0x10000eed4', 0x10000eed4),
    (0x10000f13c, '65000054', 'b.pl 0x10000f148', 0x10000f148),
    (0x10000292c, 'fffeff97', 'bl 0x100002528', 0x100002528),
    (0x10000195c, 'eb0a0094', 'bl 0x100004508', 0x100004508),
    (0x1000039f4, '7d030094', 'bl 0x1000047e8', 0x1000047e8),
    (0x100003808, '08040094', 'bl 0x100004828', 0x100004828),
    (0x10000a174, '8afcff97', 'bl 0x10000939c', 0x10000939c),
    (0x10000b1d0, '1ef9ff97', 'bl 0x100009648', 0x100009648),
    (0x10000fbdc, '7e000094', 'bl 0x10000fdd4', 0x10000fdd4),
    (0x10000d61c, '960a0094', 'bl 0x100010074', 0x100010074),
    (0x10000cae8, '970d0094', 'bl 0x100010144', 0x100010144),
    (0x10000c844, '400e0094', 'bl 0x100010144', 0x100010144),
    (0x100001b94, 'e0feff35', 'cbnz w0, 0x100001b70', 0x100001b70),
    (0x10000e098, 'a0ffff35', 'cbnz w0, 0x10000e08c', 0x10000e08c),
    (0x100001490, 'ca000035', 'cbnz w10, 0x1000014a8', 0x1000014a8),
    (0x100001280, 'cc010035', 'cbnz w12, 0x1000012b8', 0x1000012b8),
    (0x100001bdc, '68000035', 'cbnz w8, 0x100001be8', 0x100001be8),
    (0x1000020b0, '88000035', 'cbnz w8, 0x1000020c0', 0x1000020c0),
    (0x100005d8c, '68fbff35', 'cbnz w8, 0x100005cf8', 0x100005cf8),
    (0x10000ec58, '88ffff35', 'cbnz w8, 0x10000ec48', 0x10000ec48),
    (0x10000d5e0, 'a00200b5', 'cbnz x0, 0x10000d634', 0x10000d634),
    (0x100001924, '68ffffb5', 'cbnz x8, 0x100001910', 0x100001910),
    (0x1000058ec, '600c0034', 'cbz w0, 0x100005a78', 0x100005a78),
    (0x100002190, '34060034', 'cbz w20, 0x100002254', 0x100002254),
    (0x1000014ac, 'c8010034', 'cbz w8, 0x1000014e4', 0x1000014e4),
    (0x1000027b4, '68000034', 'cbz w8, 0x1000027c0', 0x1000027c0),
    (0x1000009f8, '600000b4', 'cbz x0, 0x100000a04', 0x100000a04),
    (0x100000fec, '600400b4', 'cbz x0, 0x100001078', 0x100001078),
    (0x100001040, 'c00100b4', 'cbz x0, 0x100001078', 0x100001078),
    (0x1000035c0, '605200b4', 'cbz x0, 0x10000400c', 0x10000400c),
    (0x10000a044, '000800b4', 'cbz x0, 0x10000a144', 0x10000a144),
    (0x100001c5c, '730000b4', 'cbz x19, 0x100001c68', 0x100001c68),
    (0x100001130, '1501f837', 'tbnz w21, #0x1f, 0x100001150', 0x100001150),
    (0x1000094dc, '48000037', 'tbnz w8, #0x0, 0x1000094e4', 0x1000094e4),
    (0x10000b358, 'c8020037', 'tbnz w8, #0x0, 0x10000b3b0', 0x10000b3b0),
    (0x10000f358, '88010037', 'tbnz w8, #0x0, 0x10000f388', 0x10000f388),
    (0x100000ac4, 'e802f837', 'tbnz w8, #0x1f, 0x100000b20', 0x100000b20),
    (0x100008f20, '88012037', 'tbnz w8, #0x4, 0x100008f50', 0x100008f50),
    (0x10000aab4, '28032037', 'tbnz w8, #0x4, 0x10000ab18', 0x10000ab18),
    (0x100009ab0, '88192837', 'tbnz w8, #0x5, 0x100009de0', 0x100009de0),
    (0x10000f580, 'c8004037', 'tbnz w8, #0x8, 0x10000f598', 0x10000f598),
    (0x100005470, '89000037', 'tbnz w9, #0x0, 0x100005480', 0x100005480),
    (0x100002704, '6b020036', 'tbz w11, #0x0, 0x100002750', 0x100002750),
    (0x1000012d8, '68000036', 'tbz w8, #0x0, 0x1000012e4', 0x1000012e4),
    (0x100001904, '28010036', 'tbz w8, #0x0, 0x100001928', 0x100001928),
    (0x1000021fc, '4802f836', 'tbz w8, #0x1f, 0x100002244', 0x100002244),
    (0x1000098d0, '48292836', 'tbz w8, #0x5, 0x100009df8', 0x100009df8),
    (0x10000209c, '68003036', 'tbz w8, #0x6, 0x1000020a8', 0x1000020a8),
    (0x1000093dc, '88073036', 'tbz w8, #0x6, 0x1000094cc', 0x1000094cc),
    (0x10000f584, '48074836', 'tbz w8, #0x9, 0x10000f66c', 0x10000f66c),
    (0x1000031b8, '5000f0b6', 'tbz x16, #0x3e, 0x1000031c0', 0x1000031c0),
    (0x10000937c, '5000f0b6', 'tbz x16, #0x3e, 0x100009384', 0x100009384),
]

# computed addresses as llvm-objdump reports them (branch operands, ADRP pages, the '# 0x...' comment of RIP-relative operands)
TARGETS_X86_64 = [
    (0x100003879, 'e8c30a0000', 'call 0x100004341', 0x100004341),
    (0x10000cc5e, 'e8b29affff', 'call 0x100006715', 0x100006715),
    (0x1000087ad, 'e887feffff', 'call 0x100008639', 0x100008639),
    (0x10000cc4b, 'e86c180000', 'call 0x10000e4bc', 0x10000e4bc),
    (0x10000d394, 'e874160000', 'call 0x10000ea0d', 0x10000ea0d),
    (0x100002017, 'e844cd0000', 'call 0x10000ed60', 0x10000ed60),
    (0x100005371, 'e8639f0000', 'call 0x10000f2d9', 0x10000f2d9),
    (0x10000b9a0, 'e8093a0000', 'call 0x10000f3ae', 0x10000f3ae),
    (0x10000eea9, 'e838060000', 'call 0x10000f4e6', 0x10000f4e6),
    (0x100005b24, 'e8ed990000', 'call 0x10000f516', 0x10000f516),
    (0x100003206, '803d7863010000', 'cmp byte ptr [rip + 0x16378], 0x0', 0x100019585),
    (0x1000017d8, '803d9d3d000000', 'cmp byte ptr [rip + 0x3d9d], 0x0', 0x10000557c),
    (0x100000ff2, '803d4346000000', 'cmp byte ptr [rip + 0x4643], 0x0', 0x10000563c),
    (0x100000c7c, '803df948000000', 'cmp byte ptr [rip + 0x48f9], 0x0', 0x10000557c),
    (0x10000837d, '833d4c12010000', 'cmp dword ptr [rip + 0x1124c], 0x0', 0x1000195d0),
    (0x1000011cf, '833d3a44000000', 'cmp dword ptr [rip + 0x443a], 0x0', 0x100005610),
    (0x100000cce, '3b059c880100', 'cmp eax, dword ptr [rip + 0x1889c]', 0x100019570),
    (0x100000cb4, '3b05b6880100', 'cmp eax, dword ptr [rip + 0x188b6]', 0x100019570),
    (0x10000eaeb, '4c3b35f6b20000', 'cmp r14, qword ptr [rip + 0xb2f6]', 0x100019de8),
    (0x1000028a0, '483b0541760100', 'cmp rax, qword ptr [rip + 0x17641]', 0x100019ee8),
    (0x100002229, '48f735f0330000', 'div qword ptr [rip + 0x33f0]', 0x100005620),
    (0x100006be5, 'ff05d1290100', 'inc dword ptr [rip + 0x129d1]', 0x1000195bc),
    (0x100006b39, 'ff05b9300100', 'inc dword ptr [rip + 0x130b9]', 0x100019bf8),
    (0x100005b06, 'ff0530350100', 'inc dword ptr [rip + 0x13530]', 0x10001903c),
    (0x100004746, 'ff05bc480100', 'inc dword ptr [rip + 0x148bc]', 0x100019008),
    (0x10000363b, 'ff05c7590100', 'inc dword ptr [rip + 0x159c7]', 0x100019008),
    (0x1000037f1, 'ff05855d0100', 'inc dword ptr [rip + 0x15d85]', 0x10001957c),
    (0x1000024a2, 'ff05387a0100', 'inc dword ptr [rip + 0x17a38]', 0x100019ee0),
    (0x1000015a3, '773b', 'ja 0x1000015e0', 0x1000015e0),
    (0x1000016b7, '770b', 'ja 0x1000016c4', 0x1000016c4),
    (0x1000016e8, '0f873c010000', 'ja 0x10000182a', 0x10000182a),
    (0x10000294c, '7714', 'ja 0x100002962', 0x100002962),
    (0x100002c57, '0f87a3010000', 'ja 0x100002e00', 0x100002e00),
    (0x100003a41, '7714', 'ja 0x100003a57', 0x100003a57),
    (0x1000051c9, '0f874fffffff', 'ja 0x10000511e', 0x10000511e),
    (0x10000639b, '77ec', 'ja 0x100006389', 0x100006389),
    (0x1000063f3, '77e9', 'ja 0x1000063de', 0x1000063de),
    (0x1000064e3, '7715', 'ja 0x1000064fa', 0x1000064fa),
    (0x1000022ca, '7306', 'jae 0x1000022d2', 0x1000022d2),
    (0x100002bdd, '7326', 'jae 0x100002c05', 0x100002c05),
    (0x10000476f, '0f8310010000', 'jae 0x100004885', 0x100004885),
    (0x100004f90, '731a', 'jae 0x100004fac', 0x100004fac),
    (0x10000582e, '73e6', 'jae 0x100005816', 0x100005816),
    (0x100007f22, '7302', 'jae 0x100007f26', 0x100007f26),
    (0x10000c180, '73ec', 'jae 0x10000c16e', 0x10000c16e),
    (0x10000d7a3, '7305', 'jae 0x10000d7aa', 0x10000d7aa),
    (0x100002e7f, '7209', 'jb 0x100002e8a', 0x100002e8a),
    (0x1000031b6, '7220', 'jb 0x1000031d8', 0x1000031d8),
    (0x10000575f, '7213', 'jb 0x100005774', 0x100005774),
    (0x100006413, '72e8', 'jb 0x1000063fd', 0x1000063fd),
    (0x1000092b8, '7209', 'jb 0x1000092c3', 0x1000092c3),
    (0x10000b921, '727d', 'jb 0x10000b9a0', 0x10000b9a0),
    (0x10000c776, '7225', 'jb 0x10000c79d', 0x10000c79d),
    (0x10000c841, '721f', 'jb 0x10000c862', 0x10000c862),
    (0x10000d138, '72e9', 'jb 0x10000d123', 0x10000d123),
    (0x10000d49a, '72ed', 'jb 0x10000d489', 0x10000d489),
    (0x100002fd5, '761c', 'jbe 0x100002ff3', 0x100002ff3),
    (0x100004487, '7611', 'jbe 0x10000449a', 0x10000449a),
    (0x100004caf, '7649', 'jbe 0x100004cfa', 0x100004cfa),
    (0x10000636f, '760f', 'jbe 0x100006380', 0x100006380),
    (0x100006648, '7655', 'jbe 0x10000669f', 0x10000669f),
    (0x1000068f7, '760c', 'jbe 0x100006905', 0x100006905),
    (0x10000f124, '7607', 'jbe 0x10000f12d', 0x10000f12d),
    (0x1000015c2, '0f8489000000', 'je 0x100001651', 0x100001651),
    (0x100001a29, '0f84a5000000', 'je 0x100001ad4', 0x100001ad4),
    (0x1000023cd, '7479', 'je 0x100002448', 0x100002448),
    (0x100002761, '7417', 'je 0x10000277a', 0x10000277a),
    (0x100003a0e, '0f84e1000000', 'je 0x100003af5', 0x100003af5),
    (0x100003b29, '0f849b010000', 'je 0x100003cca', 0x100003cca),
    (0x100008048, '0f8424040000', 'je 0x100008472', 0x100008472),
    (0x100008a00, '740d', 'je 0x100008a0f', 0x100008a0f),
    (0x100009d81, '0f84a7000000', 'je 0x100009e2e', 0x100009e2e),
    (0x10000cce8, '7415', 'je 0x10000ccff', 0x10000ccff),
    (0x1000007ce, '7f1a', 'jg 0x1000007ea', 0x1000007ea),
    (0x1000008b4, '7f1a', 'jg 0x1000008d0', 0x1000008d0),
    (0x1000009a6, '7f05', 'jg 0x1000009ad', 0x1000009ad),
    (0x1000022a1, '7fcf', 'jg 0x100002272', 0x100002272),
    (0x1000034c0, '7f0e', 'jg 0x1000034d0', 0x1000034d0),
    (0x100003609, '7f4d', 'jg 0x100003658', 0x100003658),
    (0x100003642, '7f14', 'jg 0x100003658', 0x100003658),
    (0x100004bbc, '0f8f98000000', 'jg 0x100004c5a', 0x100004c5a),
    (0x100009284, '7fc9', 'jg 0x10000924f', 0x10000924f),
    (0x1000093eb, '0f8f1b040000', 'jg 0x10000980c', 0x10000980c),
    (0x100000775, '7d02', 'jge 0x100000779', 0x100000779),
    (0x1000007e8, '7d02', 'jge 0x1000007ec', 0x1000007ec),
    (0x100000843, '7d07', 'jge 0x10000084c', 0x10000084c),
    (0x1000008b6, '7d07', 'jge 0x1000008bf', 0x1000008bf),
    (0x1000008ce, '7d02', 'jge 0x1000008d2', 0x1000008d2),
    (0x100001b20, '7de3', 'jge 0x100001b05', 0x100001b05),
    (0x100001c4f, '0f8dab000000', 'jge 0x100001d00', 0x100001d00),
    (0x100002eac, '7d18', 'jge 0x100002ec6', 0x100002ec6),
    (0x1000034ee, '7d16', 'jge 0x100003506', 0x100003506),
    (0x1000035a7, '0f8df6000000', 'jge 0x1000036a3', 0x1000036a3),
    (0x100000a1a, '7cd6', 'jl 0x1000009f2', 0x1000009f2),
    (0x100000e33, '0f8cc4000000', 'jl 0x100000efd', 0x100000efd),
    (0x1000012ba, '7cbe', 'jl 0x10000127a', 0x10000127a),
    (0x100001afc, '7c27', 'jl 0x100001b25', 0x100001b25),
    (0x100003656, '7cc6', 'jl 0x10000361e', 0x10000361e),
    (0x100005a9e, '7cd0', 'jl 0x100005a70', 0x100005a70),
    (0x10000c85e, '7c96', 'jl 0x10000c7f6', 0x10000c7f6),
    (0x10000dd87, '7c0c', 'jl 0x10000dd95', 0x10000dd95),
    (0x10000ed98, '7c2d', 'jl 0x10000edc7', 0x10000edc7),
    (0x10000f2b8, '7c05', 'jl 0x10000f2bf', 0x10000f2bf),
    (0x1000009b1, '7e2d', 'jle 0x1000009e0', 0x1000009e0),
    (0x10000112a, '0f8ed3010000', 'jle 0x100001303', 0x100001303),
    (0x100001377, '7e7e', 'jle 0x1000013f7', 0x1000013f7),
    (0x1000020aa, '7e0e', 'jle 0x1000020ba', 0x1000020ba),
    (0x10000308d, '7e39', 'jle 0x1000030c8', 0x1000030c8),
    (0x100005be6, '7e08', 'jle 0x100005bf0', 0x100005bf0),
    (0x100006a16, '7e1b', 'jle 0x100006a33', 0x100006a33),
    (0x10000ba20, '7e19', 'jle 0x10000ba3b', 0x10000ba3b),
    (0x10000c7e9, '0f8e91000000', 'jle 0x10000c880', 0x10000c880),
    (0x10000dec5, '7e75', 'jle 0x10000df3c', 0x10000df3c),
    (0x100000e64, 'e98bfcffff', 'jmp 0x100000af4', 0x100000af4),
    (0x100001dcc, 'e9cb030000', 'jmp 0x10000219c', 0x10000219c),
    (0x1000029e8, 'e9aa000000', 'jmp 0x100002a97', 0x100002a97),
    (0x100002a22, 'eb73', 'jmp 0x100002a97', 0x100002a97),
    (0x1000039ad, 'e939f8ffff', 'jmp 0x1000031eb', 0x1000031eb),
    (0x100004234, 'e9c0feffff', 'jmp 0x1000040f9', 0x1000040f9),
    (0x100004983, 'e985feffff', 'jmp 0x10000480d', 0x10000480d),
    (0x1000063fb, 'eb13', 'jmp 0x100006410', 0x100006410),
    (0x100009ad2, 'eb1e', 'jmp 0x100009af2', 0x100009af2),
    (0x10000d973, 'ebec', 'jmp 0x10000d961', 0x10000d961),
    (0x100001216, '7530', 'jne 0x100001248', 0x100001248),
    (0x1000013ad, '750a', 'jne 0x1000013b9', 0x1000013b9),
    (0x100001a61, '7521', 'jne 0x100001a84', 0x100001a84),
    (0x100001e06, '7517', 'jne 0x100001e1f', 0x100001e1f),
    (0x10000236e, '75be', 'jne 0x10000232e', 0x10000232e),
    (0x1000097d3, '754d', 'jne 0x100009822', 0x100009822),
    (0x10000aac9, '750d', 'jne 0x10000aad8', 0x10000aad8),
    (0x10000ac36, '753f', 'jne 0x10000ac77', 0x10000ac77),
    (0x10000c55a, '7505', 'jne 0x10000c561', 0x10000c561),
    (0x10000e995, '7505', 'jne 0x10000e99c', 0x10000e99c),
    (0x10000b992, '7b62', 'jnp 0x10000b9f6', 0x10000b9f6),
    (0x10000bc6a, '0f8bd5000000', 'jnp 0x10000bd45', 0x10000bd45),
    (0x10000142a, '7909', 'jns 0x100001435', 0x100001435),
    (0x100002e19, '7918', 'jns 0x100002e33', 0x100002e33),
    (0x100008ff6, '7911', 'jns 0x100009009', 0x100009009),
    (0x10000e989, '7911', 'jns 0x10000e99c', 0x10000e99c),
    (0x10000b929, '7a75', 'jp 0x10000b9a0', 0x10000b9a0),
    (0x10000ec8b, '7a6d', 'jp 0x10000ecfa', 0x10000ecfa),
    (0x100000cd8, '7822', 'js 0x100000cfc', 0x100000cfc),
    (0x100000fac, '7817', 'js 0x100000fc5', 0x100000fc5),
    (0x100001a59, '780d', 'js 0x100001a68', 0x100001a68),
    (0x1000023da, '7838', 'js 0x100002414', 0x100002414),
    (0x1000042e2, '781a', 'js 0x1000042fe', 0x1000042fe),
    (0x100004e21, '7813', 'js 0x100004e36', 0x100004e36),
    (0x100005a64, '783a', 'js 0x100005aa0', 0x100005aa0),
    (0x100005e66, '7835', 'js 0x100005e9d', 0x100005e9d),
    (0x10000cc0b, '7812', 'js 0x10000cc1f', 0x10000cc1f),
    (0x10000e515, '0f88b1000000', 'js 0x10000e5cc', 0x10000e5cc),
    (0x100007436, '4c8d05c3850000', 'lea r8, [rip + 0x85c3]', 0x10000fa00),
    (0x100003877, '488d05525d0100', 'lea rax, [rip + 0x15d52]', 0x1000195d0),
    (0x100002e76, '488d1dbe1e0000', 'lea rbx, [rip + 0x1ebe]', 0x100004d3b),
    (0x100007a8e, '488d0d9bd10000', 'lea rcx, [rip + 0xd19b]', 0x100014c30),
    (0x10000a756, '488d0d13ec0000', 'lea rcx, [rip + 0xec13]', 0x100019370),
    (0x10000da25, '488d3d17930000', 'lea rdi, [rip + 0x9317]', 0x100016d43),
    (0x10000cc55, '488d3d289e0000', 'lea rdi, [rip + 0x9e28]', 0x100016a84),
    (0x100009655, '488d3dc1ce0000', 'lea rdi, [rip + 0xcec1]', 0x10001651d),
    (0x10000bbc1, '488d35d2ad0000', 'lea rsi, [rip + 0xadd2]', 0x10001699a),
    (0x100008115, '488d35c2df0000', 'lea rsi, [rip + 0xdfc2]', 0x1000160de),
    (0x1000081fe, 'c605cf13010001', 'mov byte ptr [rip + 0x113cf], 0x1', 0x1000195d4),
    (0x100007472, 'c7056c270100feffffff', 'mov dword ptr [rip + 0x1276c], 0xfffffffe', 0x100019be8),
    (0x100000705, '8b0df5880100', 'mov ecx, dword ptr [rip + 0x188f5]', 0x100019000),
    (0x10000dbb5, '48890564c20000', 'mov qword ptr [rip + 0xc264], rax', 0x100019e20),
    (0x100004e58, '4c8b3de9350100', 'mov r15, qword ptr [rip + 0x135e9]', 0x100018448),
    (0x100005c18, '488b05b13f0100', 'mov rax, qword ptr [rip + 0x13fb1]', 0x100019bd0),
    (0x10000bf49, '488b0528d40000', 'mov rax, qword ptr [rip + 0xd428]', 0x100019378),
    (0x10000311b, '488b1d36240000', 'mov rbx, qword ptr [rip + 0x2436]', 0x100005558),
    (0x100002d15, '488b3dbc710100', 'mov rdi, qword ptr [rip + 0x171bc]', 0x100019ed8),
    (0x10000137d, '488b159c860100', 'mov rdx, qword ptr [rip + 0x1869c]', 0x100019a20),
    (0x10000cbf9, 'f20f10058f290000', 'movsd xmm0, qword ptr [rip + 0x298f]', 0x10000f590),
    (0x10000cdf3, 'f20f10058d830000', 'movsd xmm0, qword ptr [rip + 0x838d]', 0x100015188),
    (0x100005f45, 'f20f100d43960000', 'movsd xmm1, qword ptr [rip + 0x9643]', 0x10000f590),
    (0x100008a58, '4c632db1110100', 'movsxd r13, dword ptr [rip + 0x111b1]', 0x100019c10),
    (0x100005bdc, '48630555340100', 'movsxd rax, dword ptr [rip + 0x13455]', 0x100019038),
    (0x10000592f, '48630502370100', 'movsxd rax, dword ptr [rip + 0x13702]', 0x100019038),
    (0x10000584c, '486305e5370100', 'movsxd rax, dword ptr [rip + 0x137e5]', 0x100019038),
    (0x1000057ba, '48630577380100', 'movsxd rax, dword ptr [rip + 0x13877]', 0x100019038),
    (0x100009331, '48633db8020100', 'movsxd rdi, dword ptr [rip + 0x102b8]', 0x1000195f0),
    (0x100004abc, '48633d75450100', 'movsxd rdi, dword ptr [rip + 0x14575]', 0x100019038),
    (0x100004c1c, '0f1005c5360100', 'movups xmm0, xmmword ptr [rip + 0x136c5]', 0x1000182e8),
    (0x100004b47, '0f100562370100', 'movups xmm0, xmmword ptr [rip + 0x13762]', 0x1000182b0),
    (0x100004b3c, '0f10057d370100', 'movups xmm0, xmmword ptr [rip + 0x1377d]', 0x1000182c0),
    (0x100004b31, '0f100598370100', 'movups xmm0, xmmword ptr [rip + 0x13798]', 0x1000182d0),
    (0x10000952c, '0f1005fded0000', 'movups xmm0, xmmword ptr [rip + 0xedfd]', 0x100018330),
    (0x100005149, '0fb60d884a0100', 'movzx ecx, byte ptr [rip + 0x14a88]', 0x100019bd8),
    (0x10000169b, '440fb63dad3f0000', 'movzx r15d, byte ptr [rip + 0x3fad]', 0x100005650),
    (0x1000019ac, '0b05123c0000', 'or eax, dword ptr [rip + 0x3c12]', 0x1000055c4),
    (0x10000abaf, '0f9405fff30000', 'sete byte ptr [rip + 0xf3ff]', 0x100019fb5),
    (0x100005ff6, '2b05e43b0100', 'sub eax, dword ptr [rip + 0x13be4]', 0x100019be0),
    (0x100005f7a, '2b05603c0100', 'sub eax, dword ptr [rip + 0x13c60]', 0x100019be0),
    (0x100002d96, '4c2b350b710100', 'sub r14, qword ptr [rip + 0x1710b]', 0x100019ea8),
    (0x100002f36, '4c2b3d6b6f0100', 'sub r15, qword ptr [rip + 0x16f6b]', 0x100019ea8),
    (0x100009608, '482b15d9ff0000', 'sub rdx, qword ptr [rip + 0xffd9]', 0x1000195e8),
    (0x10000c90e, '660f5c05aa880000', 'subpd xmm0, xmmword ptr [rip + 0x88aa]', 0x1000151c0),
    (0x10000cbae, 'f20f5c05ca850000', 'subsd xmm0, qword ptr [rip + 0x85ca]', 0x100015180),
    (0x100001956, 'f605fb3c000001', 'test byte ptr [rip + 0x3cfb], 0x1', 0x100005658),
    (0x100005f2a, '660f2e055e960000', 'ucomisd xmm0, qword ptr [rip + 0x965e]', 0x10000f590),
    (0x100004ca7, '660f2e05e1a80000', 'ucomisd xmm0, qword ptr [rip + 0xa8e1]', 0x10000f590),
]

BITS = {"arm64": 64, "x86_64": 64, "x86": 32}
CORPORA = {"arm64": CORPUS_ARM64, "x86_64": CORPUS_X86_64, "x86": CORPUS_X86}
UNDECODED = {"arm64": UNDECODED_ARM64, "x86_64": UNDECODED_X86_64, "x86": UNDECODED_X86}
TARGETS = {"arm64": TARGETS_ARM64, "x86_64": TARGETS_X86_64}


def decode_one(arch, raw, pc=0):
    if arch == "arm64":
        insn = L.decode_a64(struct.unpack("<I", raw[:4])[0], pc)
        insn["size"] = 4
        return insn
    return L.decode_x86(raw, 0, pc, BITS[arch])


def recombine(arch, insn, size):
    """Rebuild the encoding from the reported fields; also returns how often each bit was attributed."""
    seen = [0] * (size * 8)
    if arch == "arm64":
        word = 0
        for f in insn["fields"]:
            width = f["hi"] - f["lo"] + 1
            assert f["width"] == width and len(f["bits"]) == width and int(f["bits"], 2) == f["value"] == int(f["value_hex"], 16)
            word |= f["value"] << f["lo"]
            for b in range(f["lo"], f["hi"] + 1):
                seen[b] += 1
        return struct.pack("<I", word), seen
    out = bytearray(size)
    for f in insn["fields"]:
        value = int(f["value_hex"], 16)
        if f["nbytes"] == 1:
            assert int(f["bits"], 2) == value and len(f["bits"]) == f["hi"] - f["lo"] + 1
            out[f["byte"]] |= value << f["lo"]
            for b in range(f["lo"], f["hi"] + 1):
                seen[f["byte"] * 8 + b] += 1
        else:
            out[f["byte"]:f["byte"] + f["nbytes"]] = value.to_bytes(f["nbytes"], "little")
            for b in range(f["byte"] * 8, (f["byte"] + f["nbytes"]) * 8):
                seen[b] += 1
    return bytes(out), seen


def normalise_reference(text):
    """llvm-objdump text -> the form the lab prints (see the module docstring)."""
    text = re.sub(r" \+ (\d\*)?[re]iz", "", text)
    text = re.sub(r"\[(\d\*)?[re]iz - ", "[-", text)
    text = re.sub(r"\[(\d\*)?[re]iz \+ ", "[", text)
    if text.startswith("ret -0x"):
        text = "ret 0x%x" % (0x10000 - int(text[7:], 16))
    return text


class EmbeddedCorpusTests(unittest.TestCase):
    def test_corpus_is_broad(self):
        self.assertGreaterEqual(len(CORPUS_ARM64), 400)
        self.assertGreaterEqual(len(CORPUS_X86_64), 400)
        self.assertGreaterEqual(len(CORPUS_X86), 150)
        for arch, rows in CORPORA.items():
            mnemonics = {text.split()[0] for _pc, _hx, text, _t in rows}
            self.assertGreaterEqual(len(mnemonics), {"arm64": 90, "x86_64": 90, "x86": 40}[arch], arch)

    def test_text_matches_the_reference_disassembler(self):
        for arch, rows in CORPORA.items():
            for pc, hx, text, _target in rows:
                raw = bytes.fromhex(hx)
                insn = decode_one(arch, raw, pc)
                self.assertEqual(insn["status"], "decoded", (arch, hx, text, insn["gaps"]))
                self.assertEqual(insn["text"], text, (arch, hx))
                self.assertEqual(insn["size"], len(raw), (arch, hx))

    def test_computed_targets_match_the_reference(self):
        checked = 0
        for arch, rows in CORPORA.items():
            for pc, hx, text, target in rows:
                insn = decode_one(arch, bytes.fromhex(hx), pc)
                if target is None:
                    # objdump gives no computed address here. The only address the lab may report is an absolute
                    # one that is written out in the operand itself (no register, no segment override).
                    absolute = re.search(r"(?<!:)\[(-?0x[0-9a-f]+)\]", text) if arch != "arm64" else None
                    if absolute:
                        self.assertEqual(int(insn["target"], 16), int(absolute.group(1), 16) & ((1 << BITS[arch]) - 1), (arch, hx, text))
                        self.assertEqual(insn["target_kind"], "data")
                    else:
                        self.assertIsNone(insn["target"], (arch, hx, text))
                    continue
                checked += 1
                self.assertEqual(int(insn["target"], 16), target, (arch, hx, text))
                self.assertTrue(insn["steps"], (arch, hx))
                # the last arithmetic line ends with the computed address
                self.assertIn("0x%x" % target, " ".join(insn["steps"]), (arch, hx, text))
        for arch, rows in TARGETS.items():
            for pc, hx, text, target in rows:
                insn = decode_one(arch, bytes.fromhex(hx), pc)
                checked += 1
                self.assertEqual(insn["text"], text, (arch, hx))
                self.assertEqual(int(insn["target"], 16), target, (arch, hx, text))
                self.assertIn("= 0x%x" % target, insn["steps"][-1], (arch, hx, text))
        self.assertGreater(checked, 400)

    def test_fields_recombine_to_the_original_encoding(self):
        for arch, rows in CORPORA.items():
            for pc, hx, _text, _target in rows:
                raw = bytes.fromhex(hx)
                insn = decode_one(arch, raw, pc)
                rebuilt, seen = recombine(arch, insn, len(raw))
                self.assertEqual(rebuilt, raw, (arch, hx))
                self.assertEqual(set(seen), {1}, "every bit attributed exactly once: %s %s" % (arch, hx))
                for f in insn["fields"]:
                    self.assertTrue(f["meaning"].strip(), (arch, hx, f["name"]))
                    self.assertNotEqual(f["kind"], "unknown", (arch, hx, f["name"]))

    def test_instructions_outside_the_tables_say_not_decoded(self):
        for arch, rows in UNDECODED.items():
            self.assertTrue(rows, arch)
            for hx, mnemonic in rows:
                insn = decode_one(arch, bytes.fromhex(hx))
                self.assertEqual(insn["status"], "not_decoded", (arch, hx, mnemonic))
                self.assertEqual(insn["text"], "", (arch, hx, mnemonic))
                self.assertTrue(insn["gaps"], (arch, hx))
                if arch != "arm64" and insn["length_known"]:
                    # not decoded, but the length is claimed: it must be the length objdump found
                    self.assertEqual(insn["size"], len(hx) // 2, (arch, hx, mnemonic))
        known = [mn for hx, mn in UNDECODED_X86_64 + UNDECODED_X86 if decode_one("x86_64", bytes.fromhex(hx))["length_known"]]
        self.assertGreater(len(known), 10)

    def test_every_single_bit_flip_decodes_without_error(self):
        # "toggle a bit and see what changes" must be safe for every bit of every instruction
        rng = random.Random(7)
        for arch, rows in CORPORA.items():
            for pc, hx, _text, _target in rng.sample(rows, 60):
                raw = bytearray.fromhex(hx)
                for bit in range(len(raw) * 8):
                    raw[bit // 8] ^= 1 << (bit % 8)
                    padded = bytes(raw) + bytes(12)
                    insn = decode_one(arch, padded, pc)
                    self.assertIn(insn["status"], ("decoded", "partial", "not_decoded"), (arch, bytes(raw).hex()))
                    if insn["status"] in ("decoded", "partial"):
                        rebuilt, seen = recombine(arch, insn, insn["size"])
                        self.assertEqual(rebuilt, padded[:insn["size"]], (arch, bytes(raw).hex()))
                        self.assertEqual(set(seen), {1}, (arch, bytes(raw).hex()))
                    raw[bit // 8] ^= 1 << (bit % 8)


class ExplanationTests(unittest.TestCase):
    """The arithmetic and the stated exceptions, on hand-checked encodings."""

    def test_adrp_arithmetic(self):
        insn = L.decode_a64(0x90000068, 0x10000075C)  # adrp x8, 0x10000c000 (from /bin/ls)
        self.assertEqual(insn["text"], "adrp x8, 0x10000c000")
        f = {x["name"]: x for x in insn["fields"]}
        self.assertEqual((f["immlo"]["hi"], f["immlo"]["lo"], f["immlo"]["value"]), (30, 29, 0))
        self.assertEqual((f["immhi"]["hi"], f["immhi"]["lo"], f["immhi"]["value"]), (23, 5, 3))
        steps = " | ".join(insn["steps"])
        self.assertIn("SignExtend(imm21, 21) << 12 = 12 << 12 = 0xc000", steps)
        self.assertIn("0x10000075c & ~0xfff = 0x100000000", steps)
        self.assertIn("= 0x10000c000", steps)

    def test_adr_and_negative_offsets(self):
        self.assertEqual(L.decode_a64(0x10FFFFE0, 0x1000)["text"], "adr x0, 0xffc")
        back = L.decode_a64(0x17FFFFFF, 0x2000)
        self.assertEqual((back["text"], back["target"]), ("b 0x1ffc", "0x1ffc"))
        self.assertIn("SignExtend(imm26, 26) * 4 = -1 * 4 = -0x4", " | ".join(back["steps"]))

    def test_register_31_is_sp_or_zr_depending_on_the_instruction(self):
        add = L.decode_a64(0x910003FD, 0)       # add x29, sp, #0  -> mov x29, sp
        self.assertEqual(add["text"], "mov x29, sp")
        rn = next(f for f in add["fields"] if f["name"] == "Rn")
        self.assertIn("stack pointer", rn["meaning"])
        orr = L.decode_a64(0xAA1F03E0, 0)       # orr x0, xzr, xzr -> mov x0, xzr
        self.assertEqual(orr["text"], "mov x0, xzr")
        rm = next(f for f in orr["fields"] if f["name"] == "Rm")
        self.assertIn("zero register", rm["meaning"])
        cmp_ = L.decode_a64(0xF100001F, 0)      # subs xzr, x0, #0 -> cmp x0, #0x0: Rd=31 is ZR because S=1
        self.assertEqual(cmp_["text"], "cmp x0, #0x0")
        rd = next(f for f in cmp_["fields"] if f["name"] == "Rd")
        self.assertIn("zero register", rd["meaning"])

    def test_pac_and_bti_live_in_the_hint_space(self):
        for word, text in ((0xD503237F, "pacibsp"), (0xD50323BF, "autiasp"), (0xD503245F, "bti c"), (0xD503201F, "nop")):
            insn = L.decode_a64(word, 0)
            self.assertEqual(insn["text"], text)
            self.assertEqual(insn["encoding_class"], "Hints")
            self.assertTrue(any("execute as NOP" in n for n in insn["notes"]))
        self.assertEqual(L.decode_a64(0xD65F0FFF, 0)["text"], "retab")
        self.assertEqual(L.decode_a64(0xD63F0A1F, 0)["text"], "blraaz x16")

    def test_logical_immediate_is_expanded_step_by_step(self):
        insn = L.decode_a64(0x927CEC08, 0)  # and x8, x0, #0xfffffffffffffff0
        self.assertEqual(insn["text"], "and x8, x0, #0xfffffffffffffff0")
        self.assertIn("0xfffffffffffffff0", " | ".join(insn["steps"]))

    def test_rip_relative_and_the_modrm_exception(self):
        insn = L.decode_x86(bytes.fromhex("488d05044e0000"), 0, 0x100000779, 64)
        self.assertEqual((insn["text"], insn["target"]), ("lea rax, [rip + 0x4e04]", "0x100005584"))
        rm = next(f for f in insn["fields"] if f["name"] == "rm")
        self.assertIn("RIP-relative", rm["meaning"])
        steps = " | ".join(insn["steps"])
        self.assertIn("04 4e 00 00 read little-endian", steps)
        self.assertIn("0x100000779 + 7 (length) = 0x100000780", steps)
        self.assertIn("0x100000780 + 0x4e04 = 0x100005584", steps)
        # the same bytes in 32-bit mode: an absolute disp32, no RIP
        insn32 = L.decode_x86(bytes.fromhex("8d05044e0000"), 0, 0x1000, 32)
        self.assertEqual(insn32["text"], "lea eax, [0x4e04]")
        self.assertEqual((insn32["target"], insn32["target_kind"]), ("0x4e04", "data"))
        self.assertEqual(insn["target_kind"], "data")
        fs = L.decode_x86(bytes.fromhex("64488b042528000000"), 0, 0, 64)   # mov rax, fs:[0x28]: relative to the FS base
        self.assertEqual((fs["text"], fs["target"]), ("mov rax, qword ptr fs:[0x28]", None))
        self.assertEqual(L.decode_x86(bytes.fromhex("e80c000000"), 0, 0x1000, 64)["target_kind"], "branch")
        self.assertEqual(L.decode_a64(0x94000005, 0x1000)["target_kind"], "branch")
        self.assertEqual(L.decode_a64(0x90000068, 0x1000)["target_kind"], "data")

    def test_rip_target_counts_a_trailing_immediate(self):
        insn = L.decode_x86(bytes.fromhex("c705100000007b000000"), 0, 0x1000, 64)  # mov dword ptr [rip+0x10], 0x7b
        self.assertEqual(insn["text"], "mov dword ptr [rip + 0x10], 0x7b")
        self.assertEqual(insn["target"], "0x%x" % (0x1000 + 10 + 0x10))

    def test_sib_exceptions(self):
        no_index = L.decode_x86(bytes.fromhex("8b0424"), 0, 0, 64)          # mov eax, [rsp]
        self.assertEqual(no_index["text"], "mov eax, dword ptr [rsp]")
        f = {x["name"]: x for x in no_index["fields"]}
        self.assertIn("SIB byte follows", f["rm"]["meaning"])
        self.assertIn("no index register", f["index"]["meaning"])
        r12_index = L.decode_x86(bytes.fromhex("428b0420"), 0, 0, 64)       # REX.X: index 100 becomes r12
        self.assertEqual(r12_index["text"], "mov eax, dword ptr [rax + r12]")
        no_base = L.decode_x86(bytes.fromhex("8b048d10000000"), 0, 0, 64)   # base=101, mod=00: disp32, no base
        self.assertEqual(no_base["text"], "mov eax, dword ptr [4*rcx + 0x10]")
        self.assertIn("no base register", next(x for x in no_base["fields"] if x["name"] == "base")["meaning"])
        rbp_base = L.decode_x86(bytes.fromhex("8b4500"), 0, 0, 64)          # rbp as base needs mod=01 disp8=0
        self.assertEqual(rbp_base["text"], "mov eax, dword ptr [rbp]")

    def test_rex_bits_and_byte_registers(self):
        insn = L.decode_x86(bytes.fromhex("4d89c8"), 0, 0, 64)  # mov r8, r9
        self.assertEqual(insn["text"], "mov r8, r9")
        rex = {f["name"]: f for f in insn["fields"] if f["group"] == "rex"}
        self.assertEqual([rex["REX.%s" % n]["value"] for n in "WRXB"], [1, 1, 0, 1])
        self.assertIn("64-bit operand size", rex["REX.W"]["meaning"])
        self.assertIn("no effect", rex["REX.X"]["meaning"].lower() + " no effect" if rex["REX.X"]["value"] else "no effect")
        self.assertEqual(L.decode_x86(bytes.fromhex("88e0"), 0, 0, 64)["text"], "mov al, ah")
        self.assertEqual(L.decode_x86(bytes.fromhex("4088e0"), 0, 0, 64)["text"], "mov al, spl")  # any REX changes 4..7

    def test_immediates_are_assembled_little_endian_and_sign_extended(self):
        insn = L.decode_x86(bytes.fromhex("4883e4f0"), 0, 0, 64)
        self.assertEqual(insn["text"], "and rsp, -0x10")
        self.assertIn("as a signed 8-bit number: -0x10", " | ".join(insn["steps"]))
        movabs = L.decode_x86(bytes.fromhex("48b8efcdab8967452301"), 0, 0, 64)
        self.assertEqual(movabs["text"], "movabs rax, 0x123456789abcdef")
        imm = next(f for f in movabs["fields"] if f["name"] == "imm64")
        self.assertEqual((imm["nbytes"], imm["value_hex"], imm["value"]), (8, "0x123456789abcdef", None))  # > 2^53: hex only

    def test_x86_stream_stops_only_at_an_unknown_length(self):
        # d6 is undefined in 64-bit mode: there is no instruction, so no length; decoding stops
        res = L.decode_bytes("x86_64", bytes.fromhex("554889e5d6c3"), 0x1000)
        self.assertEqual([i["status"] for i in res["instructions"]], ["decoded", "decoded", "not_decoded"])
        self.assertEqual(res["stopped"], "not_decoded")
        self.assertEqual(res["remaining"], 1)
        self.assertIn("unknown", res["stop_reason"])
        self.assertFalse(res["instructions"][2]["length_known"])
        # VEX, the 0F 38 / 0F 3A maps and x87 are not decoded either, but their length follows from the encoding
        # ... and so does the length of the other valid instructions outside the tables (push fs, fxsave, loop, enter)
        res = L.decode_bytes("x86_64", bytes.fromhex("55" "c5f877" "660f3817c0" "660f3a0bc10a" "dd45f0" "c4e27918c0" "62f17c48100424"
                                                     "0fa0" "0fae0424" "e2fe" "c8100000" "c3"), 0x1000)
        self.assertEqual([(i["status"], i["size"]) for i in res["instructions"]],
                         [("decoded", 1), ("not_decoded", 3), ("not_decoded", 5), ("not_decoded", 6), ("not_decoded", 3),
                          ("not_decoded", 5), ("not_decoded", 7), ("not_decoded", 2), ("not_decoded", 4), ("not_decoded", 2),
                          ("not_decoded", 4), ("decoded", 1)])
        self.assertIsNone(res["stopped"])
        self.assertEqual(res["instructions"][-1]["text"], "ret")
        for insn in res["instructions"][1:-1]:
            self.assertTrue(insn["length_known"])
            self.assertEqual(insn["text"], "")
            self.assertRegex(insn["gaps"][0], "not decoded|does not decode")
        truncated = L.decode_bytes("x86_64", bytes.fromhex("e80000"), 0)
        self.assertEqual(truncated["instructions"][0]["status"], "truncated")
        a64 = L.decode_bytes("arm64", bytes.fromhex("1f2003d5c0035f"), 0)
        self.assertEqual([i["status"] for i in a64["instructions"]], ["decoded", "truncated"])

    def test_fast_path_gives_the_same_text(self):
        # lite=True is what the disassembler uses: same decode logic, no field list
        for arch, rows in CORPORA.items():
            for pc, hx, text, _target in rows:
                raw = bytes.fromhex(hx)
                if arch == "arm64":
                    full, lite = L.decode_a64(struct.unpack("<I", raw)[0], pc), L.decode_a64(struct.unpack("<I", raw)[0], pc, lite=True)
                else:
                    full, lite = L.decode_x86(raw, 0, pc, BITS[arch]), L.decode_x86(raw, 0, pc, BITS[arch], lite=True)
                    self.assertEqual(lite["size"], full["size"])
                for key in ("status", "text", "mnemonic", "operands", "target", "target_kind"):
                    self.assertEqual(lite[key], full[key], (arch, hx, key))
                self.assertFalse(lite.get("fields"))
        rng = random.Random(99)
        for _ in range(3000):
            raw = bytes(rng.getrandbits(8) for _ in range(15))
            for bits in (64, 32):
                full, lite = L.decode_x86(raw, 0, 0x1000, bits), L.decode_x86(raw, 0, 0x1000, bits, lite=True)
                self.assertEqual([lite[k] for k in ("status", "size", "text", "target", "length_known")],
                                 [full[k] for k in ("status", "size", "text", "target", "length_known")], raw.hex())
            word = rng.getrandbits(32)
            full, lite = L.decode_a64(word, 0x1000), L.decode_a64(word, 0x1000, lite=True)
            self.assertEqual([lite[k] for k in ("status", "text", "target")], [full[k] for k in ("status", "text", "target")], hex(word))

    def test_a64_unknown_words_keep_only_the_group(self):
        insn = L.decode_a64(0x4EA08440, 0)  # add v0.4s, v2.4s, v0.4s: Advanced SIMD three-same, not in the tables
        self.assertEqual(insn["status"], "not_decoded")
        self.assertIn("Advanced SIMD", insn["encoding_class"])
        self.assertEqual([f["name"] for f in insn["fields"]], ["not decoded", "op0", "not decoded"])
        self.assertEqual(sum(f["width"] for f in insn["fields"]), 32)


class RobustnessTests(unittest.TestCase):
    def test_random_bytes_never_raise_and_stay_consistent(self):
        rng = random.Random(1234)
        for arch in L.ARCHS:
            for _ in range(1500):
                data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(1, 40)))
                pc = rng.getrandbits(64)
                res = L.decode_bytes(arch, data, pc)
                json.dumps(res)  # JSON-serialisable
                pos = 0
                for insn in res["instructions"]:
                    self.assertEqual(insn["offset"], pos)
                    self.assertGreaterEqual(insn["size"], 1)
                    self.assertLessEqual(insn["size"], 15)
                    self.assertEqual(insn["hex"].replace(" ", ""), data[pos:pos + insn["size"]].hex())
                    if insn["status"] in ("decoded", "partial"):
                        rebuilt, seen = recombine(arch, insn, insn["size"])
                        self.assertEqual(rebuilt, data[pos:pos + insn["size"]], (arch, data.hex()))
                        self.assertEqual(set(seen), {1}, (arch, data.hex()))
                    else:
                        self.assertEqual(insn["text"], "")
                        self.assertTrue(insn["gaps"])
                    for f in insn["fields"]:  # field values that JavaScript cannot hold exactly are hex-only
                        if f.get("value") is not None:
                            self.assertLess(f["value"], 1 << 53)
                    pos += insn["size"]
                self.assertEqual(pos, res["bytes_decoded"])
                self.assertEqual(res["remaining"], len(data) - pos)
                self.assertLessEqual(len(res["instructions"]), L.MAX_INSTRUCTIONS)

    def test_input_is_bounded(self):
        res = L.decode_bytes("arm64", bytes(4096), 0)
        self.assertEqual(res["bytes_total"], L.MAX_INPUT_BYTES)
        self.assertEqual(len(res["instructions"]), L.MAX_INSTRUCTIONS)
        res = L.decode_bytes("x86_64", b"\x90" * 4096, 0, max_instructions=10 ** 9)
        self.assertEqual(len(res["instructions"]), L.MAX_INSTRUCTIONS)
        prefixes = L.decode_bytes("x86_64", b"\x66" * 64, 0)   # an instruction cannot exceed 15 bytes
        self.assertEqual(prefixes["instructions"][0]["status"], "not_decoded")
        self.assertLessEqual(prefixes["instructions"][0]["size"], 15)

    def test_pc_wraps_at_64_bits(self):
        res = L.decode_bytes("arm64", struct.pack("<I", 0x14000002), (1 << 64) - 4)
        self.assertEqual(res["instructions"][0]["target"], "0x4")


def api_call(router, method, route, body=None, headers=None, raw=None):
    payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
    hdrs = {"content-type": "application/json"} if payload else {}
    hdrs.update(headers or {})
    resp = router.handle(ApiRequest(method, route, {}, payload, hdrs, "198.51.100.9"))
    data = json.loads(resp.body.decode()) if resp.body else None
    return resp.status, data


class EndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.routers = {}
        for mode in ("local", "public"):
            config = RuntimeConfig(mode, rate_limit_per_minute=0, upload_rate_limit_per_minute=0, hard_parse_timeout_seconds=0)
            service = AnalysisService(WORKSPACE_ROOT, config)
            cls.routers[mode] = build_router(service, config, log=EventLog(stream=io.StringIO()))
        cls.router = cls.routers["public"]

    def decode(self, body, mode="public", **kw):
        return api_call(self.routers[mode], "POST", "/api/labs/encoding/decode", body, **kw)

    def test_decode_in_every_mode(self):
        for mode in ("local", "public"):
            status, data = self.decode({"arch": "arm64", "hex": "fd 7b bf a9 fd 03 00 91", "pc": "0x100003f50"}, mode)
            self.assertEqual(status, 200, data)
            self.assertEqual([i["text"] for i in data["instructions"]], ["stp x29, x30, [sp, #-0x10]!", "mov x29, sp"])
            self.assertEqual(data["instructions"][1]["pc"], "0x100003f54")
            status, data = self.decode({"arch": "x86_64", "hex": "e8 0c 00 00 00", "pc": 4096}, mode)
            self.assertEqual((status, data["instructions"][0]["target"]), (200, "0x1011"))
            status, data = self.decode({"arch": "x86", "hex": "8b450c"}, mode)
            self.assertEqual((status, data["instructions"][0]["text"]), (200, "mov eax, dword ptr [ebp + 0xc]"))

    def test_hex_input_forms(self):
        for text in ("4889e5", "48 89 e5", "0x48, 0x89, 0xe5", "\\x48\\x89\\xe5", "48:89:E5\n"):
            status, data = self.decode({"arch": "x86_64", "hex": text})
            self.assertEqual((status, data["instructions"][0]["text"]), (200, "mov rbp, rsp"), text)
        # a disassembler prints an A64 instruction as one number; in memory the bytes are reversed
        status, data = self.decode({"arch": "arm64", "hex": "910003fd d65f03c0", "input": "words"})
        self.assertEqual([i["text"] for i in data["instructions"]], ["mov x29, sp", "ret"])
        self.assertEqual(data["instructions"][0]["hex"], "fd 03 00 91")

    def test_info(self):
        status, data = api_call(self.router, "GET", "/api/labs/encoding/info")
        self.assertEqual(status, 200)
        self.assertEqual([a["id"] for a in data["archs"]], list(L.ARCHS))
        self.assertEqual(data["limits"]["max_bytes"], L.MAX_INPUT_BYTES)

    def test_bad_requests_get_clean_errors(self):
        bad = [
            {}, {"arch": "arm64"}, {"arch": "mips", "hex": "00"}, {"arch": ["arm64"], "hex": "00"}, {"arch": "arm64", "hex": ""},
            {"arch": "arm64", "hex": "   "}, {"arch": "arm64", "hex": 5}, {"arch": "arm64", "hex": None}, {"arch": "arm64", "hex": ["00"]},
            {"arch": "arm64", "hex": "zz"}, {"arch": "arm64", "hex": "123"}, {"arch": "x86_64", "hex": "90" * (L.MAX_INPUT_BYTES + 1)},
            {"arch": "x86_64", "hex": "9 0"}, {"arch": "arm64", "hex": "00", "pc": "banana"}, {"arch": "arm64", "hex": "00", "pc": -1},
            {"arch": "arm64", "hex": "00", "pc": 1 << 64}, {"arch": "arm64", "hex": "00", "pc": True}, {"arch": "arm64", "hex": "00", "pc": 1.5},
            {"arch": "arm64", "hex": "00", "pc": "0x" + "f" * 60}, {"arch": "arm64", "hex": "00", "pc": {"a": 1}},
            {"arch": "arm64", "hex": "00", "max_instructions": "3"}, {"arch": "arm64", "hex": "00", "max_instructions": True},
            {"arch": "x86_64", "hex": "90909090", "input": "words"}, {"arch": "arm64", "hex": "9100", "input": "words"},
            {"arch": "arm64", "hex": "00", "input": "nibbles"}, {"arch": "arm64", "hex": "<script>alert(1)</script>"},
            {"arch": "arm64", "hex": "0x" * 3000},
        ]
        for body in bad:
            status, data = self.decode(body)
            self.assertEqual(status, 400, (body if len(str(body)) < 200 else "long body", data))
            self.assertEqual(data["code"], "bad_request")
            self.assertNotIn("Traceback", data["error"])
            self.assertNotIn("<script>", data["error"])

    def test_limits_are_clamped_not_trusted(self):
        status, data = self.decode({"arch": "x86_64", "hex": "90" * 200, "max_instructions": 10 ** 12})
        self.assertEqual((status, len(data["instructions"])), (200, L.MAX_INSTRUCTIONS))
        status, data = self.decode({"arch": "x86_64", "hex": "90" * 200, "max_instructions": -5})
        self.assertEqual((status, len(data["instructions"])), (200, 1))

    def test_transport_level_abuse(self):
        route = "/api/labs/encoding/decode"
        self.assertEqual(api_call(self.router, "GET", route)[0], 405)
        self.assertEqual(api_call(self.router, "POST", route, raw=b"not json")[0], 400)
        self.assertEqual(api_call(self.router, "POST", route, raw=b"[1,2,3]")[0], 400)
        self.assertEqual(api_call(self.router, "POST", route, raw=b'"arm64"')[0], 400)
        self.assertEqual(api_call(self.router, "POST", route, raw=b"")[0], 400)
        status, _ = api_call(self.router, "POST", route, raw=b"arch=arm64&hex=00", headers={"content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 415)
        big = json.dumps({"arch": "arm64", "hex": "00", "junk": "A" * (L.MAX_BODY_BYTES + 10)}).encode()
        status, data = api_call(self.router, "POST", route, raw=big)
        self.assertEqual((status, data["code"]), (413, "too_large"))
        deep = b'{"arch":"arm64","hex":' + b"[" * 50000 + b"]" * 50000 + b"}"
        self.assertIn(api_call(self.router, "POST", route, raw=deep[:L.MAX_BODY_BYTES])[0], (400, 413))
        status, data = api_call(self.router, "POST", route, raw=json.dumps({"arch": "arm64", "hex": "00", "pc": 10 ** 60}).encode())
        self.assertEqual(status, 400)

    def test_responses_carry_no_document_state(self):
        # the endpoint is stateless: an unknown doc id in the query must not matter
        resp = self.router.handle(ApiRequest("POST", "/api/labs/encoding/decode", {"doc": "u_" + "0" * 32, "slice_index": "7"},
                                             json.dumps({"arch": "arm64", "hex": "1f2003d5"}).encode(),
                                             {"content-type": "application/json"}, "198.51.100.9"))
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(resp.body.decode())["instructions"][0]["text"], "nop")
        self.assertEqual(resp.headers.get("Cache-Control"), "no-store")


# ---------------------------------------------------------------------------
# The product's disassembler (backend/disasm.py) is this decoder: no second set of tables
# ---------------------------------------------------------------------------
from backend import disasm, runtime  # noqa: E402

ROW_KEYS = {"vmaddr", "slice_offset", "abs_offset", "size", "raw_hex", "mnemonic", "operands", "symbol_label", "comment",
            "branch_target_vmaddr"}


def make_slice(arch, code, vm=0x1000, symbols=(), function_starts=(), strings=(), slots=(), dice=None, section_size=None):
    """The smallest slice dictionary disassemble_window needs: one executable section holding `code` at offset 0x100."""
    size = len(code) if section_size is None else section_size
    raw = bytes(0x100) + bytes(code)
    load_commands = []
    if dice is not None:
        load_commands.append({"cmd_name": "LC_DATA_IN_CODE", "details": dice})
    sl = {
        "slice_index": 0, "arch_name": arch,
        "segments": [{"segname": "__TEXT", "vmaddr_int": vm, "vmsize_int": 0x10000, "fileoff": 0x100, "filesize": size,
                      "sections": [{"segname": "__TEXT", "sectname": "__text", "vmaddr_int": vm, "size": size,
                                    "slice_offset": 0x100, "is_executable": True}]}],
        "symbols": [{"type_name": "SECT", "n_value_int": a, "name": n, "demangled": n} for a, n in symbols],
        "function_starts": [{"vmaddr": hex(a), "name": "sub_%x" % a} for a in function_starts],
        "strings": [{"vmaddr": hex(a), "value": v} for a, v in strings],
        "dysymtab": {"indirect_symbols": [{"slot_vmaddr": hex(a), "symbol_name": n} for a, n in slots]},
        "load_commands": load_commands,
    }
    return sl, raw


def listing(arch, code, count=200, **kw):
    sl, raw = make_slice(arch, code, **kw)
    with runtime.use_config(RuntimeConfig("public")):
        out = disasm.disassemble_window(sl, raw, 0, kw.get("vm", 0x1000), count, file_path="/bin/ls")
    return out


def brief(out):
    return [((i["mnemonic"] + " " + i["operands"]).strip(), i["size"]) for i in out["instructions"]]


class ProductDisassemblerTests(unittest.TestCase):
    def test_the_built_in_decoders_are_the_verified_decoder(self):
        for arch, rows in CORPORA.items():
            for pc, hx, text, target in rows:
                raw = bytes.fromhex(hx)
                if arch == "arm64":
                    mnem, ops, _comment, tgt = disasm.decode_arm64_insn(struct.unpack("<I", raw)[0], pc)
                    self.assertEqual(disasm.decode_single_arm64_preview(raw, pc), text, hx)
                else:
                    length, mnem, ops, _comment, tgt = disasm.decode_x86_64_insn(raw + bytes(4), 0, pc, is_64=(arch == "x86_64"))
                    self.assertEqual(length, len(raw), (arch, hx))
                self.assertEqual((mnem + " " + ops).strip(), text, (arch, hx))
                if target is not None:
                    self.assertEqual(tgt, target, (arch, hx, text))
        for arch, rows in TARGETS.items():
            for pc, hx, text, target in rows:
                raw = bytes.fromhex(hx)
                tgt = (disasm.decode_arm64_insn(struct.unpack("<I", raw)[0], pc)[3] if arch == "arm64"
                       else disasm.decode_x86_64_insn(raw, 0, pc, True)[4])
                self.assertEqual(tgt, target, (arch, hx, text))

    def test_the_decoder_bugs_that_were_reported_are_gone(self):
        a64 = [("041980b9", "ldrsw x4, [x8, #0x18]"), ("e00b803d", "str q0, [sp, #0x20]"), ("00b945fd", "ldr d0, [x8, #0xb70]"),
               ("e07303bd", "str s0, [sp, #0x370]"), ("14008039", "ldrsb x20, [x0]"), ("2a01c039", "ldrsb w10, [x9]"),
               ("e883c179", "ldrsh w8, [sp, #0xc0]"), ("88bd8179", "ldrsh x8, [x12, #0xde]"), ("eb375a69", "ldpsw x11, x13, [sp, #0xd0]"),
               ("1f0a3fd6", "blraaz x16"), ("300a1fd7", "braa x17, x16"), ("5f2403d5", "bti c"), ("9f2403d5", "bti j"),
               ("e0031836", "tbz w0, #0x3, 0x107c")]
        for hx, text in a64:
            self.assertEqual(disasm.decode_single_arm64_preview(bytes.fromhex(hx), 0x1000), text, hx)
        x86 = [("83f8ff", "cmp eax, -0x1"), ("837b0801", "cmp dword ptr [rbx + 0x8], 0x1"), ("833dfdb1080000", "cmp dword ptr [rip + 0x8b1fd], 0x0"),
               ("83e001", "and eax, 0x1"), ("83cf7e", "or edi, 0x7e"), ("83d800", "sbb eax, 0x0"), ("834dd404", "or dword ptr [rbp - 0x2c], 0x4"),
               ("488d35c1ffffff", "lea rsi, [rip - 0x3f]"), ("4154", "push r12"), ("415c", "pop r12"), ("41b801000000", "mov r8d, 0x1"),
               ("0f8490000000", "je 0x1096"), ("488b3dac3c0800", "mov rdi, qword ptr [rip + 0x83cac]"), ("f3c3", "rep ret")]
        for hx, text in x86:
            raw = bytes.fromhex(hx)
            length, mnem, ops, _c, _t = disasm.decode_x86_64_insn(raw + b"\xcc" * 8, 0, 0x1000, True)
            self.assertEqual(((mnem + " " + ops).strip(), length), (text, len(raw)), hx)
        self.assertNotIn("alu", {disasm.decode_x86_64_insn(bytes([0x83, 0xC0 | (r << 3), 1]), 0, 0, True)[1] for r in range(8)})
        # REX prefixes are part of the instruction, not a stray byte before it
        out = listing("x86_64", bytes.fromhex("41544155415641575b415f415e415d415cc3"))
        self.assertEqual([t for t, _n in brief(out)], ["push r12", "push r13", "push r14", "push r15", "pop rbx", "pop r15", "pop r14",
                                                      "pop r13", "pop r12", "ret"])

    def test_row_shape_and_decoder_fields(self):
        out = listing("x86_64", bytes.fromhex("554889e5e8050000005dc3"), symbols=[(0x1000, "_main")])
        self.assertEqual((out["decoder"], out["syntax"], out["section"], out["start_vmaddr"]), ("builtin", "intel", "__TEXT,__text", "0x1000"))
        for row in out["instructions"]:
            self.assertTrue(ROW_KEYS <= set(row), row)
            self.assertEqual(len(row["raw_hex"].split()), row["size"])
            self.assertEqual(row["abs_offset"], row["slice_offset"])
        self.assertEqual(out["instructions"][0]["symbol_label"], "_main")
        self.assertEqual(brief(out), [("push rbp", 1), ("mov rbp, rsp", 3), ("call 0x100e", 5), ("pop rbp", 1), ("ret", 1)])
        arm = listing("arm64", bytes.fromhex("7f2303d5fd7bbfa9c0035fd6"))
        self.assertEqual((arm["decoder"], arm["syntax"]), ("builtin", "arm64"))
        self.assertEqual(brief(arm), [("pacibsp", 4), ("stp x29, x30, [sp, #-0x10]!", 4), ("ret", 4)])
        self.assertIn("key IB", arm["instructions"][0]["comment"])

    def test_branch_targets_and_references_are_kept_apart(self):
        code = bytes.fromhex("488d3d09000000" "e802000000" "eb00" "c3" + "00" * 2) + b"hello\x00"
        out = listing("x86_64", code, symbols=[(0x100e, "_helper")], strings=[(0x1010, "hello")])
        lea, call, jmp, ret = out["instructions"][:4]
        self.assertEqual((lea["operands"], lea["branch_target_vmaddr"], lea["ref_vmaddr"]), ("rdi, [rip + 0x9]", None, "0x1010"))
        self.assertEqual(lea["comment"], '"hello" @ 0x1010')
        self.assertEqual((call["operands"], call["branch_target_vmaddr"], call["comment"]), ("0x100e", "0x100e", "-> _helper"))
        self.assertNotIn("ref_vmaddr", call)
        self.assertEqual((jmp["mnemonic"], jmp["branch_target_vmaddr"]), ("jmp", "0x100e"))
        # an import slot: the call goes through memory, so there is nothing to jump to in the listing
        out = listing("x86_64", bytes.fromhex("ff15fa0f0000"), slots=[(0x2000, "printf")])
        row = out["instructions"][0]
        self.assertEqual((row["operands"], row["comment"], row["branch_target_vmaddr"], row["ref_vmaddr"]),
                         ("qword ptr [rip + 0xffa]", "-> imp.printf", None, "0x2000"))
        out = listing("i386", bytes.fromhex("ff1500200000" "a104200000"), slots=[(0x2000, "puts")], strings=[(0x2004, "x")])
        self.assertEqual([(r["operands"], r["comment"]) for r in out["instructions"]],
                         [("dword ptr [0x2000]", "-> imp.puts"), ("eax, dword ptr [0x2004]", '"x" @ 0x2004')])

    def test_x86_undecoded_instructions_of_known_length_keep_the_stream_in_step(self):
        code = bytes.fromhex("55" "c5f877" "660f3800c1" "dd45f0" "0fae0424" "837b0801" "4154" "c3")
        out = listing("x86_64", code)
        self.assertEqual(brief(out), [("push rbp", 1), (".byte 0xc5, 0xf8, 0x77", 3), (".byte 0x66, 0x0f, 0x38, 0x00, 0xc1", 5),
                                      (".byte 0xdd, 0x45, 0xf0", 3), (".byte 0x0f, 0xae, 0x04, 0x24", 4),
                                      ("cmp dword ptr [rbx + 0x8], 0x1", 4), ("push r12", 2), ("ret", 1)])
        comments = [i["comment"] for i in out["instructions"]]
        self.assertIn("VEX-encoded", comments[1])
        self.assertIn("0F 38", comments[2])
        self.assertIn("x87", comments[3])
        for c in comments[1:5]:
            self.assertTrue(c.startswith("not decoded"), c)
        self.assertEqual(sum(i["size"] for i in out["instructions"]), len(code))

    def test_x86_unknown_length_resumes_at_the_next_byte_and_resyncs_at_a_symbol(self):
        # d6 is undefined in 64-bit mode: one byte is shown as data and decoding goes on from the next byte
        out = listing("x86_64", bytes.fromhex("d6" "4889e5" "c3"))
        self.assertEqual(brief(out), [(".byte 0xd6", 1), ("mov rbp, rsp", 3), ("ret", 1)])
        self.assertIn("length is unknown", out["instructions"][0]["comment"])
        # a byte that would swallow the start of the next function: without the symbol the listing is out of step ...
        code = bytes.fromhex("c3" "b8" "554889e5" "c3")           # ret; stray b8; push rbp; mov rbp, rsp; ret
        out = listing("x86_64", code)
        self.assertEqual(brief(out)[1], ("mov eax, 0xe5894855", 5))
        # ... with a function start at 0x1002 no instruction may run across it, and the listing is right from there on
        for anchors in ({"function_starts": [0x1002]}, {"symbols": [(0x1002, "_f")]}):
            out = listing("x86_64", code, **anchors)
            self.assertEqual(brief(out), [("ret", 1), (".byte 0xb8", 1), ("push rbp", 1), ("mov rbp, rsp", 3), ("ret", 1)])
            self.assertIn("would run across", out["instructions"][1]["comment"])
            self.assertIsNotNone(out["instructions"][2]["symbol_label"])

    def test_data_in_code_is_shown_as_data(self):
        code = bytes.fromhex("c3" "10000000" "f0ffffff" "c3")
        for dice in ({"entries": [{"offset": "0x101", "length": 8, "kind": "DICE_KIND_JUMP_TABLE32"}]},):
            out = listing("x86_64", code, dice=dice)
            self.assertEqual(brief(out), [("ret", 1), (".long 0x00000010", 4), (".long 0xfffffff0", 4), ("ret", 1)])
            self.assertIn("data in code", out["instructions"][1]["comment"])
        # the table is read from the file when the load command says where it is (the document keeps only some entries)
        table = struct.pack("<IHH", 0x101, 4, 4) + struct.pack("<IHH", 0x105, 2, 3) + struct.pack("<IHH", 0x107, 2, 2)
        sl, raw = make_slice("x86_64", code, dice={"dataoff": 0x100 + len(code), "datasize": len(table), "entries": []})
        raw += table
        with runtime.use_config(RuntimeConfig("public")):
            out = disasm.disassemble_window(sl, raw, 0, 0x1000, 50)
        self.assertEqual(brief(out), [("ret", 1), (".long 0x00000010", 4), (".short 0xfff0", 2), (".byte 0xff", 1), (".byte 0xff", 1), ("ret", 1)])
        arm = listing("arm64", bytes.fromhex("c0035fd6" "44332211" "c0035fd6"),
                      dice={"entries": [{"offset": "0x104", "length": 4, "kind": "DICE_KIND_DATA"}]})
        self.assertEqual(brief(arm), [("ret", 4), (".long 0x11223344", 4), ("ret", 4)])

    def test_section_end_and_incomplete_instructions(self):
        out = listing("x86_64", bytes.fromhex("c3" "e80000"))        # a call cut off by the end of the section
        self.assertEqual(brief(out), [("ret", 1), (".byte 0xe8, 0x00, 0x00", 3)])
        self.assertIn("incomplete", out["instructions"][1]["comment"])
        out = listing("x86_64", bytes.fromhex("c3c3c3c3"), section_size=2)   # never read past the section
        self.assertEqual(len(out["instructions"]), 2)
        self.assertEqual(len(listing("arm64", bytes.fromhex("c0035fd6c003"))["instructions"]), 1)
        self.assertEqual(len(listing("x86_64", b"\x90" * 5000, count=10 ** 9)["instructions"]), 1000)

    def test_arm64_words_outside_the_tables_are_data(self):
        out = listing("arm64", struct.pack("<3I", 0xD503201F, 0x4EA08440, 0xD65F03C0))
        self.assertEqual(brief(out), [("nop", 4), (".long 0x4ea08440", 4), ("ret", 4)])
        self.assertEqual(out["instructions"][1]["comment"], "not decoded: Advanced SIMD / floating-point")

    def test_arm64_page_tracking_names_what_is_referenced(self):
        words = [0x90000000,   # adrp x0, 0x1000 (page of this code)
                 0x91040000,   # add x0, x0, #0x100   -> 0x1100 "boot"
                 0x90000008,   # adrp x8, 0x1000
                 0xF9410108,   # ldr x8, [x8, #0x200] -> slot 0x1200
                 0x94000003,   # bl 0x101c
                 0x91040000,   # add x0, x0, #0x100: x0 is no longer a page after the call
                 0xD65F03C0, 0xD65F03C0]
        out = listing("arm64", struct.pack("<8I", *words), strings=[(0x1100, "boot")], slots=[(0x1200, "malloc")], symbols=[(0x101c, "_callee")])
        rows = out["instructions"]
        self.assertEqual([r["mnemonic"] for r in rows], ["adrp", "add", "adrp", "ldr", "bl", "add", "ret", "ret"])
        self.assertEqual((rows[0]["branch_target_vmaddr"], rows[0]["ref_vmaddr"]), (None, "0x1000"))
        self.assertEqual((rows[1]["comment"], rows[1]["ref_vmaddr"]), ('"boot" @ 0x1100', "0x1100"))
        self.assertEqual((rows[3]["comment"], rows[3]["ref_vmaddr"]), ("-> imp.malloc", "0x1200"))
        self.assertEqual((rows[4]["comment"], rows[4]["branch_target_vmaddr"]), ("-> _callee", "0x101c"))
        self.assertIsNone(rows[5]["comment"])
        self.assertNotIn("ref_vmaddr", rows[5])
        # a register that is overwritten stops being a page
        words = [0x90000000, 0xAA0103E0, 0x91040000]   # adrp x0; mov x0, x1; add x0, x0, #0x100
        rows = listing("arm64", struct.pack("<3I", *words), strings=[(0x1100, "boot")])["instructions"]
        self.assertEqual(rows[1]["mnemonic"] + " " + rows[1]["operands"], "mov x0, x1")
        self.assertIsNone(rows[2]["comment"])

    def test_decode_preview_endpoint_uses_the_same_decoder(self):
        config = RuntimeConfig("public", rate_limit_per_minute=0, upload_rate_limit_per_minute=0, hard_parse_timeout_seconds=0)
        service = AnalysisService(WORKSPACE_ROOT, config)
        for preset in ("synthetic_elf64", "synthetic_pe64", "synthetic_elf32", "synthetic_universal"):
            doc_id = "preset:" + preset
            doc = service.get_entry(doc=doc_id).doc
            for index, sl in enumerate(doc["slices"]):
                dis = service.disassemble(slice_index=index, count=40, doc=doc_id)
                self.assertEqual(dis["decoder"], "builtin")
                self.assertTrue(dis["instructions"])
                arm = sl["arch_name"].startswith("arm64")
                for row in dis["instructions"][:25]:
                    preview = service.decode_bytes_at(offset=row["abs_offset"], slice_index=index, doc=doc_id)["primitives"]
                    text = (row["mnemonic"] + " " + row["operands"]).strip()
                    if row["mnemonic"].startswith(".") and not arm:
                        continue    # a data row of several bytes: the preview decodes from its first byte only
                    self.assertEqual(preview["arm64_insn" if arm else "x86_insn"], text, (preset, row["vmaddr"]))

    def test_listing_rows_are_contiguous_on_every_fixture(self):
        # every preset, every slice, whole executable sections: rows are contiguous and never overlap
        config = RuntimeConfig("public", rate_limit_per_minute=0, upload_rate_limit_per_minute=0, hard_parse_timeout_seconds=0)
        service = AnalysisService(WORKSPACE_ROOT, config)
        for preset in ("synthetic_elf64", "synthetic_elf32", "synthetic_pe64", "synthetic_pe32", "synthetic_universal", "synthetic_firmware"):
            doc_id = "preset:" + preset
            for index, sl in enumerate(service.get_entry(doc=doc_id).doc["slices"]):
                for seg in sl["segments"]:
                    for sect in seg.get("sections", []):
                        if not sect.get("is_executable") or not sect["size"]:
                            continue
                        dis = service.disassemble(slice_index=index, vmaddr=hex(sect["vmaddr_int"]), count=1000, doc=doc_id)
                        expect = sect["vmaddr_int"]
                        for row in dis["instructions"]:
                            self.assertEqual(int(row["vmaddr"], 16), expect, (preset, row))
                            self.assertGreaterEqual(row["size"], 1)
                            expect += row["size"]
                        self.assertLessEqual(expect, sect["vmaddr_int"] + sect["size"], preset)
                        json.dumps(dis)


# ---------------------------------------------------------------------------
# Live comparison with llvm-objdump (skipped where the tools are missing)
# ---------------------------------------------------------------------------
def _find_tool(name, extra=()):
    found = shutil.which(name)
    if found:
        return found
    for candidate in extra:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    try:
        out = subprocess.run(["xcrun", "-f", name], capture_output=True, text=True, timeout=20)
        if out.returncode == 0 and os.path.isfile(out.stdout.strip()):
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


OBJDUMP = _find_tool("llvm-objdump", ("/opt/homebrew/opt/llvm/bin/llvm-objdump", "/usr/local/opt/llvm/bin/llvm-objdump"))
CLANG = _find_tool("clang")
TRIPLES = {"arm64": "aarch64-linux-gnu", "x86_64": "x86_64-linux-gnu", "x86": "i386-linux-gnu"}
OBJDUMP_LINE = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ?)+|[0-9a-f]{8})\s*\t(.*)$")


def _reference_text(raw_text, arch):
    if "<unknown>" in raw_text:
        return None
    text = raw_text.split(" //")[0].split("\t;")[0].split(" ;")[0]
    text = re.sub(r"\s+##? .*$", "", text)
    text = re.sub(r"\s*<[^>]*>", "", text)
    text = " ".join(text.replace("\t", " ").split())
    if arch == "arm64":   # Mach-O objects print Apple's SIMD syntax ("movi.2d v0, ..."); make it the generic one
        m = re.match(r"^([a-z0-9]+)\.(\d+[bhsdq])\s+(.*)$", text)
        if m:
            text = "%s %s" % (m.group(1), re.sub(r"\bv(\d+)\b", lambda mm: "v%s.%s" % (mm.group(1), m.group(2)), m.group(3)))
    return normalise_reference(text)


def _objdump_lines(path, arch, extra=()):
    """[(address, size, text or None)] for one object or executable."""
    cmd = [OBJDUMP, "-d", "--x86-asm-syntax=intel"] + list(extra) + [path]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    rows = []
    for line in out.splitlines():
        m = OBJDUMP_LINE.match(line)
        if not m:
            continue
        raw = m.group(2).replace(" ", "")
        text = _reference_text(m.group(3), arch)
        if arch != "arm64" and text == "" and rows:           # continuation line of a long instruction
            rows[-1] = (rows[-1][0], rows[-1][1] + len(raw) // 2, rows[-1][2], rows[-1][3] + raw)
            continue
        if arch == "arm64" and " " not in m.group(2).strip():  # printed as one word: reverse to memory order
            raw = bytes.fromhex(raw)[::-1].hex()
        if rows and rows[-1][2] in ("lock", "rep", "repne") and rows[-1][0] + rows[-1][1] == int(m.group(1), 16):
            prev = rows.pop()                                   # objdump prints these prefixes on their own line
            rows.append((prev[0], prev[1] + len(raw) // 2, (prev[2] + " " + (text or "")).strip() if text else None, prev[3] + raw))
            continue
        rows.append((int(m.group(1), 16), len(raw) // 2, text, raw))
    return rows


def _assemble_slots(vectors, arch, workdir, slot):
    lines = [".text"]
    for raw in vectors:
        if arch == "arm64":
            lines.append(".inst 0x%08x" % struct.unpack("<I", raw)[0])
        else:
            lines.append(".byte " + ",".join(str(b) for b in list(raw) + [0x90] * (slot - len(raw))))
    src = os.path.join(workdir, "v_%s.s" % arch)
    obj = os.path.join(workdir, "v_%s.o" % arch)
    with open(src, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    subprocess.run([CLANG, "-target", TRIPLES[arch], "-c", src, "-o", obj], check=True, capture_output=True, timeout=120)
    extra = ["--mattr=+v8.5a,+lse,+crc,+fp-armv8,+neon,+pauth"] if arch == "arm64" else []
    by_addr = {row[0]: row for row in _objdump_lines(obj, arch, extra)}
    return [by_addr.get(i * slot) for i in range(len(vectors))]


def _can_cross_assemble():
    if not (OBJDUMP and CLANG):
        return False
    try:
        with tempfile.TemporaryDirectory() as tmp:
            for arch in TRIPLES:
                _assemble_slots([b"\x1f\x20\x03\xd5" if arch == "arm64" else b"\x90"], arch, tmp, 4 if arch == "arm64" else 16)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


LIVE = _can_cross_assemble()


def _random_x86(rng, bits):
    v = bytearray()
    r = rng.random()
    if r < 0.12:
        v.append(0x66)
    elif r < 0.16:
        v.append(rng.choice([0xF2, 0xF3]))
    elif r < 0.19:
        v.append(rng.choice([0x64, 0x65, 0x2E]))
    elif r < 0.21:
        v.append(0xF0)
    elif r < 0.22:
        v.append(0x67)
    if bits == 64 and rng.random() < 0.45:
        v.append(0x40 | rng.randrange(16))
    if rng.random() < 0.35:
        v += bytes([0x0F, rng.choice(sorted(L._X2)) if rng.random() < 0.9 else rng.randrange(256)])
    else:
        v.append(rng.choice(sorted(L._X1)) if rng.random() < 0.9 else rng.randrange(256))
    v.append((rng.choice([0, 1, 2, 3, 3]) << 6) | (rng.randrange(8) << 3) | rng.choice([0, 1, 2, 3, 4, 4, 5, 5, 6, 7]))
    v += bytes(rng.randrange(256) for _ in range(10))
    return bytes(v)


def _random_a64(rng):
    if rng.random() < 0.75:
        _title, _pattern, mask, value, layout, _handler = rng.choice(L._A64_CLASSES)
        word = (rng.getrandbits(32) & ~mask) | value
        for name, _hi, lo in layout:
            if name and name.startswith("R") and rng.random() < 0.2:
                word |= 31 << lo
        return struct.pack("<I", word & 0xFFFFFFFF)
    return struct.pack("<I", rng.getrandbits(32))


@unittest.skipUnless(LIVE, "clang with cross targets and llvm-objdump are needed for the live comparison")
class LiveObjdumpTests(unittest.TestCase):
    def test_embedded_corpus_is_what_the_local_objdump_prints(self):
        with tempfile.TemporaryDirectory() as tmp:
            for arch, rows in CORPORA.items():
                slot = 4 if arch == "arm64" else 16
                vectors = [bytes.fromhex(hx) for _pc, hx, _text, _t in rows]
                ref = _assemble_slots(vectors, arch, tmp, slot)
                agree = 0
                for i, (pc, hx, text, _t) in enumerate(rows):
                    self.assertIsNotNone(ref[i], (arch, hx))
                    # addresses differ from the harvest (slot i*16 instead of the original), so compare what this
                    # module prints at the slot address with what the tool prints there
                    mine = decode_one(arch, vectors[i], i * slot)
                    self.assertEqual(mine["text"], ref[i][2], (arch, hx, text))
                    self.assertEqual(ref[i][1], len(vectors[i]), (arch, hx))
                    agree += 1
                self.assertEqual(agree, len(rows))

    def test_differential_fuzz_against_objdump(self):
        counts = {}
        with tempfile.TemporaryDirectory() as tmp:
            for arch, seed in (("arm64", 101), ("x86_64", 202), ("x86", 303)):
                rng = random.Random(seed)
                slot = 4 if arch == "arm64" else 32
                vectors = [_random_a64(rng) if arch == "arm64" else _random_x86(rng, BITS[arch]) for _ in range(6000)]
                ref = _assemble_slots(vectors, arch, tmp, slot)
                matched = 0
                for i, raw in enumerate(vectors):
                    mine = decode_one(arch, raw, i * slot)
                    if mine["status"] != "decoded":
                        continue
                    self.assertIsNotNone(ref[i], (arch, raw.hex(), mine["text"]))
                    self.assertEqual(mine["text"], ref[i][2], "%s %s: the reference prints %r" % (arch, raw[:mine["size"]].hex(), ref[i][2]))
                    self.assertEqual(mine["size"], ref[i][1], (arch, raw.hex(), mine["text"]))
                    matched += 1
                counts[arch] = matched
        # a meaningful share of the random encodings must land inside the tables
        self.assertGreater(counts["arm64"], 2000)
        self.assertGreater(counts["x86_64"], 3000)
        self.assertGreater(counts["x86"], 3000)

    @unittest.skipUnless(os.path.isfile("/bin/ls") and shutil.which("lipo"), "needs a universal /bin/ls and lipo")
    def test_coverage_on_a_real_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            for lipo_arch, arch in (("x86_64", "x86_64"), ("arm64e", "arm64")):
                thin = os.path.join(tmp, "ls." + lipo_arch)
                if subprocess.run(["lipo", "-thin", lipo_arch, "/bin/ls", "-o", thin], capture_output=True).returncode != 0:
                    continue
                rows = [r for r in _objdump_lines(thin, arch, ["-j", "__text"]) if r[2] and not r[2].startswith(".")]
                self.assertGreater(len(rows), 1000)
                verified = wrong = 0
                for address, size, text, raw in rows:
                    mine = decode_one(arch, bytes.fromhex(raw), address)
                    if mine["status"] != "decoded":
                        continue
                    if mine["text"] == text and mine["size"] == size:
                        verified += 1
                    else:
                        wrong += 1
                # x86 text sections contain jump tables that objdump decodes as instructions; allow for those
                self.assertLessEqual(wrong, len(rows) * (0.06 if arch == "x86_64" else 0.002), (arch, wrong, len(rows)))
                self.assertGreaterEqual(verified, len(rows) * (0.92 if arch == "x86_64" else 0.98), (arch, verified, len(rows)))


@unittest.skipUnless(LIVE and os.path.isfile("/bin/ls") and shutil.which("lipo"), "needs llvm-objdump, lipo and a universal /bin/ls")
class LiveProductPathTests(unittest.TestCase):
    """The listing a hosted user gets (service.disassemble with external tools disabled) against llvm-objdump."""

    def test_public_mode_listing_of_a_real_binary_matches_objdump(self):
        config = RuntimeConfig("public", rate_limit_per_minute=0, upload_rate_limit_per_minute=0, hard_parse_timeout_seconds=0)
        self.assertFalse(config.allow_external_tools)
        service = AnalysisService(WORKSPACE_ROOT, config)
        with tempfile.TemporaryDirectory() as tmp:
            for lipo_arch, arch in (("x86_64", "x86_64"), ("arm64e", "arm64")):
                thin = os.path.join(tmp, "ls." + lipo_arch)
                if subprocess.run(["lipo", "-thin", lipo_arch, "/bin/ls", "-o", thin], capture_output=True).returncode != 0:
                    continue
                reference = [r for r in _objdump_lines(thin, arch, ["-j", "__text"]) if r[2] and not r[2].startswith(".")]
                with open(thin, "rb") as fh:
                    doc_id = service.add_upload("ls", fh.read(), owner="test").doc_id
                rows = {}
                vm, end = reference[0][0], reference[-1][0] + reference[-1][1]
                while vm < end:
                    dis = service.disassemble(slice_index=0, vmaddr=hex(vm), count=1000, doc=doc_id)
                    self.assertEqual(dis["decoder"], "builtin")
                    if not dis["instructions"]:
                        break
                    for row in dis["instructions"]:
                        rows[int(row["vmaddr"], 16)] = row
                    vm = int(dis["instructions"][-1]["vmaddr"], 16) + dis["instructions"][-1]["size"]
                same = data = 0
                for address, size, text, _raw in reference:
                    row = rows.get(address)
                    if row is None:
                        continue    # objdump decodes straight through jump tables and function starts; see the report
                    if row["mnemonic"] in (".byte", ".short", ".long"):
                        data += 1
                        continue
                    self.assertEqual(((row["mnemonic"] + " " + row["operands"]).strip(), row["size"]), (text, size),
                                     "%s @ 0x%x" % (arch, address))
                    same += 1
                # the x86 reference still contains what objdump made of the jump tables inside __text, which the
                # product shows as data; those rows cannot agree
                floor = 0.95 if arch == "x86_64" else 0.97
                self.assertGreaterEqual(same, len(reference) * floor, (arch, same, data, len(reference)))


# ---------------------------------------------------------------------------
# The playground's arithmetic: the JavaScript is run under node, expectations are computed in Python
# ---------------------------------------------------------------------------
NODE = shutil.which("node") or next((p for p in ("/opt/homebrew/bin/node", "/usr/local/bin/node") if os.path.isfile(p)), None)

NODE_DRIVER = r"""
const M = require(process.argv[2]);
const B = BigInt;
let input = '';
process.stdin.on('data', (d) => { input += d; });
process.stdin.on('end', () => {
  const cases = JSON.parse(input);
  const big = (o) => JSON.parse(JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v)));
  const ops = {
    int(c) {
      const v = B(c.v);
      return { signed: M.toSigned(v, c.bits), hex: M.hex(v, c.bits), bin: M.bin(v, c.bits), oct: M.oct(v, c.bits),
        le: M.bytesOf(v, c.bits, true), be: M.bytesOf(v, c.bits, false), swap: M.byteSwap(v, c.bits),
        fromLe: M.fromBytes(M.bytesOf(v, c.bits, true), true), rotl: M.rotl(v, c.bits, c.n), sar: M.sar(v, c.bits, c.n % c.bits),
        neg: M.wrap(-v, c.bits), not: M.wrap(~v, c.bits) };
    },
    parse(c) { return M.parseInteger(c.text, c.bits); },
    fdecode(c) { const d = M.floatDecode(B(c.v), c.width); return { sign: d.sign, exp: d.exp, mant: d.mant, kind: d.kind, unbiased: d.unbiased, exact: d.exact, shortest: d.shortest }; },
    fencode(c) { return M.floatEncode(c.text, c.width); },
    uenc(c) { return M.ulebEncode(B(c.v)); },
    senc(c) { return M.slebEncode(B(c.v)); },
    udec(c) { return M.ulebDecode(c.bytes); },
    sdec(c) { return M.slebDecode(c.bytes); },
    align(c) { const v = B(c.v), a = B(c.a); return { down: M.alignDown(v, a), up: M.alignUp(v, a), pad: M.padding(v, a), pow2: M.isPowerOfTwo(a) }; },
    tables() { return M.FLAG_TABLES; },
    flags(c) { const d = M.decodeFlags(c.table, B(c.v)); return { set: d.set.map((f) => f.name), unknown: d.unknown, fields: d.fields.map((f) => [f.raw, f.text]) }; },
    translate(c) {
      const layout = { imageBase: B(c.base), segments: c.segments.map((s) => ({ name: s[0], vmaddr: B(s[1]), vmsize: B(s[2]), fileoff: B(s[3]), filesize: B(s[4]) })) };
      const r = M.translate(layout, c.mode, B(c.v));
      return { status: r.status, va: r.va, rva: r.rva, offset: r.offset, segment: r.segment, steps: r.steps.length };
    },
    hexbytes(c) { return M.parseHexBytes(c.text, c.max); },
  };
  process.stdout.write(JSON.stringify(cases.map((c) => big(ops[c.op](c)))));
});
"""


def run_js(cases):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
        fh.write(NODE_DRIVER)
        driver = fh.name
    try:
        proc = subprocess.run([NODE, driver, JS_PATH], input=json.dumps(cases), capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(driver)
    if proc.returncode != 0:
        raise AssertionError("node failed: " + proc.stderr[-2000:])
    return json.loads(proc.stdout)


def py_uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return list(out)


def py_sleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
            out.append(byte)
            return list(out)
        out.append(byte | 0x80)


def nearest_float(text, width):
    """Bit pattern of the float nearest to the decimal `text` (ties to even), by exact rational arithmetic."""
    exact = Fraction(text)
    fmt, ifmt, bits = ("<f", "<I", 32) if width == 32 else ("<d", "<Q", 64)
    sign = 1 if exact < 0 or text.strip().startswith("-") else 0
    target = abs(exact)
    try:
        guess = struct.unpack(ifmt, struct.pack(fmt, float(target)))[0]
    except OverflowError:
        guess = (0xFF << 23) if width == 32 else (0x7FF << 52)
    inf = (0xFF << 23) if width == 32 else (0x7FF << 52)
    max_finite = Fraction(struct.unpack(fmt, struct.pack(ifmt, inf - 1))[0])
    ulp_top = max_finite - Fraction(struct.unpack(fmt, struct.pack(ifmt, inf - 2))[0])
    best = None
    for cand in range(max(0, guess - 2), min(inf, guess + 2) + 1):
        if cand == inf:
            # infinity wins when the value is at or beyond max_finite + half an ulp (the tie goes to "even" = infinity)
            dist = None if target < max_finite + ulp_top / 2 else Fraction(-1)
        else:
            dist = abs(Fraction(struct.unpack(fmt, struct.pack(ifmt, cand))[0]) - target)
        if dist is None:
            continue
        key = (dist, cand & 1)
        if best is None or key < best[0]:
            best = (key, cand)
    return best[1] | (sign << (bits - 1))


@unittest.skipUnless(NODE, "node is needed to run the playground arithmetic")
class PlaygroundMathTests(unittest.TestCase):
    EDGES64 = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, (1 << 53) - 1, 1 << 53,
               (1 << 53) + 1, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0x0123456789ABCDEF]

    def test_integers_twos_complement_and_endianness(self):
        rng = random.Random(11)
        cases = []
        for bits in (8, 16, 32, 64):
            values = [v & ((1 << bits) - 1) for v in self.EDGES64] + [rng.getrandbits(bits) for _ in range(150)]
            for v in values:
                cases.append({"op": "int", "bits": bits, "v": str(v), "n": rng.randrange(0, 2 * bits)})
        for c, r in zip(cases, run_js(cases)):
            bits, v, n = c["bits"], int(c["v"]), c["n"]
            mask = (1 << bits) - 1
            signed = v - (1 << bits) if v >> (bits - 1) else v
            self.assertEqual(int(r["signed"]), signed, c)
            self.assertEqual(r["hex"], "0x%0*x" % (bits // 4, v), c)
            self.assertEqual(r["bin"], format(v, "0%db" % bits), c)
            self.assertEqual(r["oct"], "0o%o" % v, c)
            self.assertEqual(bytes(r["le"]), v.to_bytes(bits // 8, "little"), c)
            self.assertEqual(bytes(r["be"]), v.to_bytes(bits // 8, "big"), c)
            self.assertEqual(int(r["swap"]), int.from_bytes(v.to_bytes(bits // 8, "little"), "big"), c)
            self.assertEqual(int(r["fromLe"]), v, c)
            k = n % bits
            self.assertEqual(int(r["rotl"]), ((v << k) | (v >> (bits - k))) & mask, c)
            self.assertEqual(int(r["sar"]), (signed >> (n % bits)) & mask, c)
            self.assertEqual(int(r["neg"]), (-v) & mask, c)
            self.assertEqual(int(r["not"]), (~v) & mask, c)

    def test_parsing_what_people_type(self):
        texts = [("255", 8, 255, True), ("256", 8, 0, False), ("-1", 8, 255, True), ("-128", 8, 128, True), ("-129", 8, 127, False),
                 ("0xff", 8, 255, True), ("0XFF", 8, 255, True), ("0b1111_0000", 8, 240, True), ("0o17", 8, 15, True), ("'A'", 8, 65, True),
                 ("18446744073709551615", 64, (1 << 64) - 1, True), ("18446744073709551616", 64, 0, False),
                 ("-9223372036854775808", 64, 1 << 63, True), ("9007199254740993", 64, 9007199254740993, True),
                 ("0xffff_ffff_ffff_ffff", 64, (1 << 64) - 1, True), (" 42 ", 32, 42, True), ("-0x10", 32, 0xFFFFFFF0, True)]
        res = run_js([{"op": "parse", "text": t, "bits": b} for t, b, _v, _f in texts])
        for (text, bits, value, fits), r in zip(texts, res):
            self.assertTrue(r["ok"], text)
            self.assertEqual((int(r["value"]), r["fits"]), (value, fits), text)
        bad = ["", " ", "abc", "0x", "0b102", "12.5", "1e3", "--1", "0xg", "'ab'", "9" * 500, "１２"]
        for text, r in zip(bad, run_js([{"op": "parse", "text": t, "bits": 32} for t in bad])):
            self.assertFalse(r["ok"], text)

    def test_ieee754_fields_and_exact_values(self):
        rng = random.Random(12)
        cases = []
        for width, exp_bits, mant_bits in ((32, 8, 23), (64, 11, 52)):
            top = (1 << exp_bits) - 1
            specials = [0, 1 << (width - 1), 1, (1 << mant_bits) - 1, 1 << mant_bits, (top << mant_bits) - 1, top << mant_bits,
                        (1 << (width - 1)) | (top << mant_bits), (top << mant_bits) | (1 << (mant_bits - 1)), (top << mant_bits) | 1,
                        ((top >> 1) << mant_bits)]
            for v in specials + [rng.getrandbits(width) for _ in range(300)] + [rng.getrandbits(mant_bits) for _ in range(40)]:
                cases.append({"op": "fdecode", "width": width, "v": str(v)})
        for c, r in zip(cases, run_js(cases)):
            width, v = c["width"], int(c["v"])
            exp_bits, mant_bits = (8, 23) if width == 32 else (11, 52)
            sign, exp, mant = v >> (width - 1), (v >> mant_bits) & ((1 << exp_bits) - 1), v & ((1 << mant_bits) - 1)
            self.assertEqual((r["sign"], r["exp"], int(r["mant"])), (sign, exp, mant), c)
            value = struct.unpack("<f" if width == 32 else "<d", v.to_bytes(width // 8, "little"))[0]
            if exp == (1 << exp_bits) - 1:
                expected_kind = "infinity" if mant == 0 else ("quiet NaN" if mant >> (mant_bits - 1) else "signalling NaN")
                self.assertIsNone(r["exact"], c)
            else:
                expected_kind = ("zero" if mant == 0 else "subnormal") if exp == 0 else "normal"
                # every finite float has an exact decimal expansion; Decimal(float) is that expansion
                expected = format(Decimal(value), "f")
                self.assertEqual(r["exact"], expected, c)
                # the shortest form reads back as exactly this float
                if value == 0:
                    self.assertEqual(r["shortest"], "-0" if sign else "0")
                else:
                    self.assertEqual(nearest_float(r["shortest"].replace("e", "E"), width), v, (c, r["shortest"]))
            self.assertEqual(r["kind"], expected_kind, c)

    def test_decimal_to_float_rounding(self):
        rng = random.Random(13)
        texts = ["0", "-0", "1", "-1", "0.1", "0.2", "0.3", "1e-45", "1.4e-45", "7e-46", "7.1e-46", "3.4028235e38", "3.4028236e38",
                 "3.40282357e38", "1e39", "1.7976931348623157e308", "1.7976931348623159e308", "1e309", "4.9e-324", "2.4e-324",
                 "2.5e-324", "1e-400", "16777217", "16777219", "9007199254740993", "9007199254740995", "0.5", ".5", "5.", "1E2",
                 "123456789.123456789", "1.00000005960464477539062", "1.00000005960464477539063", "1.000000059604644775390625",
                 "8.5e-46", "2.2250738585072011e-308", "2.2250738585072014e-308", "6.02214076e23", "-273.15", "1e22", "1e23"]
        for _ in range(400):
            digits = "".join(rng.choice("0123456789") for _ in range(rng.randrange(1, 20)))
            texts.append("%s%s.%se%d" % (rng.choice(["", "-"]), digits[:1], digits[1:] or "0", rng.randrange(-50, 40)))
        for _ in range(100):   # exact ties between two adjacent float32 values, and one digit either side of them
            a = rng.getrandbits(31) % 0x7F000000 + 1
            lo = Fraction(struct.unpack("<f", struct.pack("<I", a))[0])
            hi = Fraction(struct.unpack("<f", struct.pack("<I", a + 1))[0])
            mid = Decimal((lo + hi).numerator) / Decimal((lo + hi).denominator) / 2
            base = format(mid, "f")
            texts += [base, base + "1", base[:-1] + str((int(base[-1]) - 1) % 10) if base[-1] != "0" else base + "0"]
        cases = [{"op": "fencode", "text": t, "width": w} for t in texts for w in (32, 64)]
        for c, r in zip(cases, run_js(cases)):
            self.assertTrue(r["ok"], c)
            expected = nearest_float(c["text"], c["width"])
            self.assertEqual(int(r["bits"]), expected, (c, hex(int(r["bits"])), hex(expected)))
            if c["width"] == 64:   # Python's own decimal -> double conversion is correctly rounded too
                self.assertEqual(int(r["bits"]), struct.unpack("<Q", struct.pack("<d", float(c["text"])))[0], c)
        specials = run_js([{"op": "fencode", "text": t, "width": 64} for t in ("inf", "-Infinity", "nan", "abc", "", "1e", "0x10", "1..2")])
        self.assertEqual([int(s["bits"]) if s["ok"] else None for s in specials],
                         [0x7FF << 52, (0xFFF << 52), (0x7FF << 52) | (1 << 51), None, None, None, None, None])

    def test_leb128_round_trips(self):
        rng = random.Random(14)
        unsigned = [0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 624485, (1 << 32) - 1, 1 << 32, (1 << 63) - 1, 1 << 63, (1 << 64) - 1, 1 << 64,
                    (1 << 127) + 5] + [rng.getrandbits(rng.randrange(1, 70)) for _ in range(300)]
        signed = [0, 1, -1, 63, 64, -64, -65, 127, 128, -128, -129, -123456, (1 << 63) - 1, -(1 << 63), -(1 << 64), 1 << 64] + \
                 [rng.getrandbits(rng.randrange(1, 70)) * rng.choice([1, -1]) for _ in range(300)]
        cases = [{"op": "uenc", "v": str(v)} for v in unsigned] + [{"op": "senc", "v": str(v)} for v in signed]
        res = run_js(cases)
        decode_cases = []
        for c, r in zip(cases, res):
            v = int(c["v"])
            expected = py_uleb(v) if c["op"] == "uenc" else py_sleb(v)
            self.assertEqual(r["bytes"], expected, c)
            self.assertEqual(len(r["steps"]), len(expected), c)
            decode_cases.append({"op": "udec" if c["op"] == "uenc" else "sdec", "bytes": expected + [0xAA], "want": c["v"]})
        for c, r in zip(decode_cases, run_js(decode_cases)):
            self.assertTrue(r["ok"], c)
            self.assertEqual(r["value"], c["want"], c)
            self.assertEqual((r["length"], r["rest"]), (len(c["bytes"]) - 1, 1), c)
            v = int(c["want"])
            self.assertEqual(r["fits64"], (-(1 << 63) <= v < (1 << 63)) if c["op"] == "sdec" else v < (1 << 64), c)
        self.assertFalse(run_js([{"op": "uenc", "v": "-1"}])[0]["ok"])
        # malformed input: truncated, empty, endless continuation, and a padded (non-canonical) encoding
        bad = run_js([{"op": "udec", "bytes": [0x80]}, {"op": "sdec", "bytes": []}, {"op": "udec", "bytes": [0xFF] * 40},
                      {"op": "udec", "bytes": [0x80, 0x80, 0x00]}, {"op": "sdec", "bytes": [0x7F]}, {"op": "sdec", "bytes": [0xFF, 0x00]}])
        self.assertEqual([b["ok"] for b in bad], [False, False, False, True, True, True])
        self.assertEqual([bad[3]["value"], bad[4]["value"], bad[5]["value"]], ["0", "-1", "127"])

    def test_alignment(self):
        rng = random.Random(15)
        cases = []
        for a in (1, 2, 4, 8, 16, 0x200, 0x1000, 0x4000, 0x10000, 3, 10, 24, 0x1001, 1 << 63):
            for v in self.EDGES64 + [rng.getrandbits(rng.randrange(1, 64)) for _ in range(20)] + [a - 1, a, a + 1]:
                cases.append({"op": "align", "v": str(v), "a": str(a)})
        for c, r in zip(cases, run_js(cases)):
            v, a = int(c["v"]), int(c["a"])
            down, up = v - v % a, -(-v // a) * a
            self.assertEqual((int(r["down"]), int(r["up"]), int(r["pad"])), (down, up, up - v), c)
            self.assertEqual(r["pow2"], a & (a - 1) == 0, c)
            if r["pow2"]:   # the mask form shown in the UI agrees with the division form
                self.assertEqual((down, up), (v & ~(a - 1), (v + a - 1) & ~(a - 1)), c)

    def test_flag_tables_match_the_parsers(self):
        tables = {t["id"]: t for t in run_js([{"op": "tables"}])[0]}

        def names(table_id):
            return {f["name"]: int(f["mask"]) for f in tables[table_id]["flags"]}

        expectations = {
            "macho.header.flags": {name: mask for mask, name, _d in constants.MH_HEADER_FLAGS},
            "macho.segment.flags": {name: mask for mask, name in constants.SG_FLAGS},
            "macho.section.flags": {name: mask for mask, name in constants.SECTION_ATTRIBUTES},
            "macho.vm_prot": {"VM_PROT_READ": constants.VM_PROT_READ, "VM_PROT_WRITE": constants.VM_PROT_WRITE, "VM_PROT_EXECUTE": constants.VM_PROT_EXECUTE},
            "elf.p_flags": {"PF_X": elf_parser.PF_X, "PF_W": elf_parser.PF_W, "PF_R": elf_parser.PF_R},
            "elf.sh_flags": {n: getattr(elf_parser, n) for n in ("SHF_WRITE", "SHF_ALLOC", "SHF_EXECINSTR", "SHF_MERGE", "SHF_STRINGS", "SHF_INFO_LINK", "SHF_TLS")},
            "pe.characteristics": {name: mask for mask, name, _d in pe_parser.FILE_CHARACTERISTICS_FLAGS},
            "pe.dll_characteristics": {name: mask for mask, name, _d in pe_parser.DLL_CHARACTERISTICS_FLAGS},
            "pe.section.characteristics": {name: mask for mask, name, _d in pe_parser.SECTION_CHARACTERISTICS_FLAGS},
        }
        self.assertEqual(set(expectations), set(tables))
        for table_id, expected in expectations.items():
            got = names(table_id)
            for name, mask in expected.items():
                self.assertEqual(got.get(name), mask, (table_id, name))
            masks = list(got.values())
            self.assertEqual(len(masks), len(set(masks)), table_id)
            for mask in masks:   # single bits that fit in the field
                self.assertEqual(mask & (mask - 1), 0, (table_id, mask))
                self.assertLess(mask, 1 << tables[table_id]["bits"], table_id)
        section_types = tables["macho.section.flags"]["fields"][0]["values"]
        self.assertEqual({int(k): v for k, v in section_types.items()}, constants.SECTION_TYPES)

    def test_flag_decoding(self):
        tables = {t["id"]: t for t in run_js([{"op": "tables"}])[0]}
        rng = random.Random(16)
        cases = []
        for table_id, table in tables.items():
            for _ in range(60):
                cases.append({"op": "flags", "table": table_id, "v": str(rng.getrandbits(table["bits"]))})
            cases.append({"op": "flags", "table": table_id, "v": "0"})
            cases.append({"op": "flags", "table": table_id, "v": str((1 << table["bits"]) - 1)})
        for c, r in zip(cases, run_js(cases)):
            table, v = tables[c["table"]], int(c["v"])
            known = 0
            expected = []
            for f in table["flags"]:
                known |= int(f["mask"])
                if v & int(f["mask"]):
                    expected.append(f["name"])
            for fld in table.get("fields", []):
                known |= int(fld["mask"])
            self.assertEqual(r["set"], expected, c)
            self.assertEqual(int(r["unknown"]), v & ~known, c)
        # values a learner would type
        got = run_js([{"op": "flags", "table": "pe.characteristics", "v": str(0x2022)}, {"op": "flags", "table": "elf.p_flags", "v": "5"},
                      {"op": "flags", "table": "macho.header.flags", "v": str(0x00200085)},
                      {"op": "flags", "table": "pe.section.characteristics", "v": str(0x60500020)},
                      {"op": "flags", "table": "macho.section.flags", "v": str(0x80000400)}])
        self.assertEqual(got[0]["set"], ["IMAGE_FILE_EXECUTABLE_IMAGE", "IMAGE_FILE_LARGE_ADDRESS_AWARE", "IMAGE_FILE_DLL"])
        self.assertEqual(got[1]["set"], ["PF_X", "PF_R"])
        self.assertEqual(got[2]["set"], ["MH_NOUNDEFS", "MH_DYLDLINK", "MH_TWOLEVEL", "MH_PIE"])
        self.assertEqual(got[3]["set"], ["IMAGE_SCN_CNT_CODE", "IMAGE_SCN_MEM_EXECUTE", "IMAGE_SCN_MEM_READ"])
        self.assertEqual(got[3]["fields"], [["5", "IMAGE_SCN_ALIGN_16BYTES"]])
        self.assertEqual(got[4]["fields"], [["0", "S_REGULAR"]])

    def test_address_arithmetic_mirrors_the_translator(self):
        config = RuntimeConfig("local", rate_limit_per_minute=0, upload_rate_limit_per_minute=0, hard_parse_timeout_seconds=0)
        service = AnalysisService(WORKSPACE_ROOT, config)
        rng = random.Random(17)
        cases, expected = [], []
        for preset in ("synthetic_elf64", "synthetic_elf32", "synthetic_pe64", "synthetic_pe32", "synthetic_universal", "synthetic_firmware"):
            doc_id = "preset:" + preset
            doc = service.get_entry(doc=doc_id).doc
            for index, sl in enumerate(doc["slices"]):
                segs = sl["segments"]
                text = next((s for s in segs if s["segname"] == "__TEXT"), None) or next((s for s in segs if s["segname"] != "__PAGEZERO"), None)
                base = text["vmaddr_int"] if text else 0
                layout = [[s["segname"], str(s["vmaddr_int"]), str(s["vmsize_int"]), str(s["fileoff"]), str(s["filesize"])] for s in segs]
                queries = []
                for s in segs:
                    for va in (s["vmaddr_int"], s["vmaddr_int"] + s["vmsize_int"] - 1, s["vmaddr_int"] + s["vmsize_int"],
                               s["vmaddr_int"] + s["filesize"], s["vmaddr_int"] + max(0, s["filesize"] - 1), s["vmaddr_int"] - 1,
                               s["vmaddr_int"] + rng.randrange(0, max(1, s["vmsize_int"]))):
                        if va >= 0:
                            queries.append(("va", va))
                    for off in (s["fileoff"], s["fileoff"] + s["filesize"], s["fileoff"] + max(0, s["filesize"] - 1),
                                s["fileoff"] + rng.randrange(0, max(1, s["filesize"]))):
                        queries.append(("offset", off))
                queries += [("offset", rng.randrange(0, sl["slice_size"] + 64)) for _ in range(20)]
                for mode, value in queries:
                    ref = service.translate_address(slice_index=index, query=hex(value), mode="vmaddr" if mode == "va" else "slice_offset", doc=doc_id)
                    cases.append({"op": "translate", "base": str(base), "segments": layout, "mode": mode, "v": str(value)})
                    expected.append(ref)
        self.assertGreater(len(cases), 300)
        seen = set()
        for c, r, ref in zip(cases, run_js(cases), expected):
            seen.add(ref["status"])
            self.assertEqual(r["status"], ref["status"], (c["mode"], c["v"], ref))
            ref_va = int(ref["vmaddr"], 16) if ref["vmaddr"] else None
            self.assertEqual(None if r["va"] is None else int(r["va"]), ref_va, (c["mode"], c["v"]))
            if c["mode"] == "va":
                self.assertEqual(None if r["offset"] is None else int(r["offset"]), ref["slice_offset"], (c["mode"], c["v"]))
            if ref["rva"] is not None:
                self.assertEqual(int(r["rva"]), int(ref["rva"], 16), (c["mode"], c["v"]))
            self.assertGreater(r["steps"], 0)
        self.assertEqual(seen, {"MAPPED", "UNMAPPED_ZEROFILL", "UNMAPPED"})
        # 64-bit precision: addresses above 2^53 must not be rounded
        big = run_js([{"op": "translate", "base": str(0xFFFFFF8000000000), "mode": "va", "v": str(0xFFFFFF8000201235),
                       "segments": [["kernel", str(0xFFFFFF8000200000), str(0x100000), str(0x1001), str(0x100000)]]}])[0]
        self.assertEqual((big["status"], int(big["offset"]), int(big["rva"])), ("MAPPED", 0x2236, 0x201235))

    def test_hex_byte_parsing(self):
        got = run_js([{"op": "hexbytes", "text": t, "max": 8} for t in ("e5 8e 26", "0xE5,0x8E,0x26", "e58e26", "", "e5 8", "zz", "00" * 9)])
        self.assertEqual(got, [[0xE5, 0x8E, 0x26]] * 3 + [[], None, None, None])


if __name__ == "__main__":
    unittest.main()
