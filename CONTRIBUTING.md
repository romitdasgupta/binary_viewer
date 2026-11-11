# Contributing

## Ground rules

These matter more here than in most projects, because the program's whole job is to read hostile input.

- **Standard library only.** The backend is Python 3.9 standard library: no packages, nothing that needs a compiler, nothing that would not import inside Pyodide. Code under `backend/` must not open sockets, start threads or run subprocesses, except in `server.py`, in `workers.py` and `parse_worker.py` (the public server's analysis worker pool; both are left out of the static build), and in local-mode paths that check `runtime.get_config().allow_external_tools`. The frontend is plain JavaScript with no dependencies and no build step.
- **Never execute what users open.** Not on the server, not in the browser, not in a lab. Labs edit or build bytes and analyse the result; they offer a download for people to run on their own machines.
- **Every number in a file is hostile.** Never use a count, offset or size from a file directly as a loop bound or allocation size: clamp it to `ANALYSIS_LIMITS` (`backend/constants.py`) and to the bytes present, record a warning with `add_warning(...)` when you truncate, call `runtime.check_deadline()` inside loops that can run long, and raise `BinaryFormatError` for input you reject. A plain `ValueError`, an `IndexError` or a hang is a bug (the fuzz harness reports it as one).
- **Strings from files are attacker-controlled.** Names, strings, paths, entitlements, file names and server error messages must never be treated as markup. In JavaScript, build DOM with `textContent` / `createElement`, or with `BS.util.html` (which escapes every interpolated value); always quote attributes; `BS.ui.modal` takes a DOM node (`bodyEl`) or plain `text`, never an HTML string. Document ids are capabilities: pass them to `BS.api` as the `doc` parameter (it sends them as `X-BS-Doc` headers) and never build them into a URL or put them, or file bytes, in browser storage. In Python, error messages must not contain server paths or file bytes in public mode, and values placed in sentences go through `clean()` (see `backend/learn/resolve.py`).
- **No inline script, handlers or styles.** No `onclick=`, no inline `<script>`, no `eval` / `new Function`, no `javascript:` URLs, no `style=""` attributes (set `element.style` from code instead), no requests to other origins. The page CSP (`script-src 'self'; style-src 'self'`) enforces the script rules and blocks `style` attributes and `<style>` elements; the tests check the rest (`tests/test_audit_logic.py` fails on an inline style in `static/` or in the generated pages).
- **Features use the extension API.** New frontend features go in `static/js/<feature>.js` and talk to the core only through `window.BinaryStudio`, documented in the header of `static/app.js`. See [docs/architecture.md](docs/architecture.md#extending) for adding endpoints, views, labs and learning content.

## Running the tests

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

On 2026-11-11 this ran 508 tests in 46.8 s (as reported by unittest) on macOS with Python 3.9.6, all passing, with nothing skipped because every optional tool below was present. Per module, run one at a time on the same day:

| Module | Tests | Time | What it covers |
|---|---|---|---|
| `tests.test_binary_viewer` | 16 | 1 s | parsers on the samples, CLI, core endpoints |
| `tests.test_api_security` | 80 | 7 s | router, document store and HTTP adapter abuse cases over real sockets |
| `tests.test_security_regressions` | 54 | 9 s | one class per finding of the November 2026 security review: worker processes killed on overrun, response and upload budgets, document ids in headers, cache accounting, response size against the rate limit, strict header parsing and the Origin scheme |
| `tests.test_robustness` | 26 | 5 s | a fixed slice of the fuzz corpus plus one regression per bug class found |
| `tests.test_audit_logic` | 112 | 2 s | one class per analysis statement that was found to be wrong: signatures, import attribution, each hardening check, capabilities, unsupported architectures, the PE64 fixture, no inline styles |
| `tests.test_learn` | 44 | 1 s | learning content integrity, resolution against samples, tour answers |
| `tests.test_labs_patch` | 69 | 4 s | patching, diffs, experiments, checksums, the ELF builder, `/api/patch` abuse |
| `tests.test_labs_encoding` | 55 | 4 s | the instruction decoder against an embedded `llvm-objdump` corpus; the number lab's arithmetic under node |
| `tests.test_static_build` | 24 | 10 s | the static build: bundle, output, headers, engine parity, headless Chrome |
| `tests.test_site` | 28 | 2 s | generated learning pages, site files, escaping, ads validation and CSP per provider, server and static-build integration |

Several tests start servers on loopback ports and measure time. On a machine that is busy with another run a timing test can fail; rerun that module alone before treating it as a regression. The worker-pool tests run on macOS, where the workers' address-space limit is not enforced, so they do not show that the limit works on Linux.

```sh
python3 -m unittest tests.test_api_security
python3 -m unittest tests.test_static_build -v
```

Optional tools. Tests that need them are skipped, with a message, when they are missing:

- `node` (used: v26.12.0; no minimum version is enforced): the number-lab arithmetic and the Pyodide parity leg.
- Google Chrome (`/Applications/Google Chrome.app` on macOS): the static build's browser test.
- `clang` with cross targets and `llvm-objdump` (on macOS, Homebrew's `llvm`), plus `lipo` and a universal `/bin/ls`: the live disassembler comparisons.
- The Pyodide archive in the build cache (see below): everything in `test_static_build` that needs the runtime.

A skipped test is not a passing test. Before a change that touches what a skipped test covers, install the tool and run it.

## The fuzz harness

`tests/fuzz_harness.py` mutates the samples (and, unless `--no-host`, some binaries from the host) in format-aware ways and runs each case through the whole client-facing pipeline (parse, semantic layers, learning annotations, strict JSON encoding, then hex, decode, translate, disassemble and search) in supervised worker processes. Every case is determined by the seed and its index.

```sh
python3 tests/fuzz_harness.py --iterations 300 --seed 1 --workers 4
```

That run took 7.0 s on 2026-11-11 and ended `ok=276 rejected=24 bugs=0`. "Rejected" is a deliberate `BinaryFormatError` or deadline; "BUG" is anything else: another exception type, a non-serialisable document, a case slower than `--slow` CPU seconds, a hang (killed after `--hard-timeout`), or memory growth past `--mem-mb`. For a longer run, use the header's example (`--iterations 20000 --workers 8`) and `--out report.json`.

To reproduce a finding in-process with its traceback, or run one file:

```sh
python3 tests/fuzz_harness.py --repro-case 1234 --seed 1 --traceback
python3 tests/fuzz_harness.py --repro-case 1234 --seed 1 --dump case.bin
python3 tests/fuzz_harness.py --repro-file crash.bin
```

When you fix a parser bug, add a small hand-made file that triggers it to `tests/test_robustness.py`.

## Disassembler checks

The decoder tables in `backend/labs_encoding.py` are the only instruction decoder. `tests/test_labs_encoding.py` checks them three ways:

- an embedded corpus of instructions harvested from `llvm-objdump` output (runs everywhere);
- with `clang` and `llvm-objdump` installed: the corpus re-checked against the local tool, a differential fuzz of 6,000 random encodings per architecture (AArch64, x86-64, x86) requiring identical text and length for everything the lab claims to decode, and coverage on the `__text` of `/bin/ls`;
- the product path: the public-mode listing of `/bin/ls` (built-in decoder only) against `llvm-objdump`.

Two documented differences from llvm's text are normalised before comparing (`riz`/`eiz` and the sign of `ret imm16`); see the module docstring. A decoder change must keep all three passing. If you add an encoding, add corpus rows for it.

## Browser checks

There is no browser automation in the repository other than `tests/test_static_build.py`'s `BrowserTests`, which loads the static build in headless Chrome over the DevTools protocol (no dependencies) and checks that it boots, opens a sample and an upload, reports no CSP violation, makes no request to another origin and never sends the uploaded bytes anywhere.

For interface changes, at minimum:

- open each sample and walk the tree with the keyboard, in both themes;
- open a hostile file name (for example `"><img src=x onerror=alert(1)>.bin`) and check that it is shown as text everywhere it appears;
- check the browser console for CSP violations and errors;
- check a narrow window (the hex pane docks to the bottom) and that nothing scrolls horizontally.

Only desktop Chrome has been used so far. Testing in Firefox and Safari is welcome.

## Static build and parity

```sh
python3 tools/build_static.py --out dist/          # the first build downloads Pyodide into the cache
python3 tools/build_static.py --out dist/ --offline
python3 tools/build_static.py --serve dist/        # http://127.0.0.1:8000 with dist/_headers applied
```

`dist/` and `.pyodide-cache/` are in `.gitignore`; never commit either. The build refuses to overwrite a directory that is not a previous build.

The parity report runs the same plan of requests (about 1,300) through CPython, through the shipped Pyodide under node, and through the Python server, and compares the responses:

```sh
python3 tests/test_static_build.py --parity --dist dist/
```

Rebuild `dist/` from the current tree first: the Pyodide and CPython legs use the build's engine bundle, the server leg uses the working tree, so a stale build shows every source change since as a difference. On 2026-11-11, against a fresh build, the report showed 0 differences between Pyodide and CPython and 0 between the server and CPython, over 1,284 steps. The command exits with status 1 whenever any leg differs. Against a build 30 minutes older than the tree it reported 47 server differences, all learning text edited after the build.

## Before you send a change

- The test suite passes, and you ran the skipped tests your change affects.
- For parser changes, a fuzz run of a few thousand cases shows `bugs=0`.
- For frontend changes, the browser checks above.
- If you changed behaviour that a document describes (a flag, a default, a limit, a shortcut, an endpoint, what a check reports), update the document in the same change. `python3 binary_viewer.py --help` and `docs/hosting.md#settings-reference` must agree.
