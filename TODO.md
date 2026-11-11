# TODO

Open items as of 2026-11-11, after the v2 rework (Learn, Labs, hardened public server, static WASM build, site layer). Nothing here blocks local use. Items under "Before going public" should be closed before the site is put on the internet.

## Before going public

### Owner decisions and placeholders
- [ ] Fill the placeholders in `static/privacy.html`, `static/terms.html`, `static/about.html`: operator name, contact, jurisdiction, log retention period, security contact, licence.
- [ ] Have a lawyer check the liability clause in the terms.
- [ ] Choose a licence for the repository.
- [ ] `SECURITY.md` says the project "has not had an external security audit". The reviews so far were automated, in-session. Decide whether to commission an outside review and update the sentence either way.
- [ ] EthicalAds: the integration renders their JSON API response first-party. Get their permission for self-rendering and try it against the live service. The `frame` provider is also untried.

### Deployment, never run
- [ ] Build and run the `Dockerfile` and `deploy/docker-compose.yml`.
- [ ] Run `deploy/Caddyfile` and `deploy/nginx.conf` behind real TLS; confirm doc-id log redaction, `X-Forwarded-For` / `X-Forwarded-Proto`, and that a browser upload over HTTPS succeeds.
- [ ] Run `deploy/binarystudio.service` on a Linux host (`OOMPolicy=continue`, the `setrlimit` / `prlimit64` allowances).
- [ ] Verify the Linux-only worker limits: `RLIMIT_AS`, per-job CPU limit, `oom_score_adj`.
- [ ] Measure worst-case memory on Linux with 4 concurrent hostile parses. On a host under about 4 GiB, lower `BINARYSTUDIO_PARSE_WORKER_MEMORY_MB` (default 1024).
- [ ] Deploy `dist/` to a real static host and check `_headers` (CSP, duplicate-header merging on Netlify) and the service-worker update path between two builds.

### Security follow-ups (low severity)
- [ ] Behind `--trust-proxy`, a proxy that sends no `X-Forwarded-Proto` makes the Origin scheme comparison fall back to host and port only (`backend/api.py`, `request_scheme` / `cross_site_reason`). Consider refusing when the scheme is unknown.
- [ ] Derived (patched) documents hold a full copy of the file bytes; share bytes with the parent.
- [ ] Not covered by the re-review: deep fuzzing for new slow inputs, multi-minute sustained load, connection exhaustion at the cap, the WASM build path.
- [ ] Windows: the worker pool should fall back to in-thread analysis; untested.

## Frontend

- [ ] **First:** at the default 1440px layout, struct tables are wider than the inspector (Mach-O header by 54px, some load commands by 245px), so in Learn mode the "Meaning" column needs a sideways scroll.
- [ ] Command palette matches a single substring: multi-word queries ("open sample mach") find nothing, and "main" ranks loosely related commands above the `_main` symbol.
- [ ] Hex pane shows blank rows and stale decoder values with no message when the public server rate-limits; the inspector does explain.
- [ ] Focus drops to `<body>` after "Apply it" in an experiment navigates to the patch lab.
- [ ] Cosmetic: compare view wraps "x86_64" mid-word; slice picker chevron touches long option text; sidebar filter focus indicator is a 1px underline.
- [ ] Optional: remember each document's `ETag` and send `If-None-Match` when re-requesting it.
- [ ] Test in Safari and Firefox, on real phones, and with a screen reader. Only headless desktop Chrome has been used.

## Analysis

- [ ] Verify the PE verdicts (DEP, SafeSEH, Control Flow Guard) on a Windows machine; they follow the PE specification only. Test with genuine Windows PE files and non-SHA-256 Authenticode digests.
- [ ] Capability rules were trimmed (fixture-specific keywords and start-up boilerplate removed), so the firmware sample now shows no capabilities. Decide which rules to restore.
- [ ] The throwaway RSA key that signs `fixtures/synthetic_pe64.exe` is in `backend/fixtures.py` as integers. Decide whether to ship a precomputed blob instead.
- [ ] Patch-lab diff attributes PE section fields to "Segment .text".
- [ ] The PE fixture's `/GS` cookie sits in `.rdata`.
- [ ] i386 DLLs without `NX_COMPAT` FAIL like EXEs; decide whether that is right.
- [ ] dyld segment-permission wording is taken from dyld source and observed only on macOS 27; Intel Mac behaviour is from source only.
- [ ] No disassembly for architectures other than x86, x86-64 and AArch64 (by design for now; revisit if 32-bit ARM matters).

## Tooling

- [ ] `tools/build_static.py --serve` answers unknown paths with a bare 404 instead of `404.html`.
- [ ] `--security-contact` accepts `tel:` but the help text mentions only `mailto:` and `https:`.
- [ ] `backend/server.py` comment says workers are "started on first use"; `binary_viewer.py` prewarms them at boot.
- [ ] The headless-Chrome harness (verify / real / hostile / e2e suites) is not in the repository. A copy is at `../binary_viewer-browser-harness/` on the development machine; it has the repository path hard-coded in `lib.mjs`, `e2e.mjs`, `real.mjs` and `serve.py`. Port it to `tests/browser/` with relative paths.
- [ ] Timing-sensitive tests (entropy 2 s limit in `tests/test_robustness.py`, the static-build browser test) can flake on a loaded machine.
