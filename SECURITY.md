# Security

BinaryStudio reads untrusted files by design. This document states what each way of running it protects against, what it does not, and the risks that remain. It describes version 2.0.0 as of 2026-11-11. It has not had an external security audit.

## Reporting a vulnerability

Please report vulnerabilities privately to **`<SECURITY CONTACT: owner to fill in>`**, not in a public issue. Include the mode (local, public server, static build), the version (`GET /api/config` or `backend/runtime.py`), and a file or request that reproduces the problem if you have one. Parser problems can usually be reproduced with `python3 tests/fuzz_harness.py --repro-file FILE`.

Response time and disclosure policy: **`<owner to fill in>`**.

Operators of a public deployment should publish their own contact with `BINARYSTUDIO_SECURITY_CONTACT` (server) or `--security-contact` (static build), which serves it as `/.well-known/security.txt`.

## What every mode guarantees

- **Nothing is executed.** No mode runs, loads or emulates an opened file, on the server or in the browser. The labs edit and build bytes and then analyse them; they never run them.
- **Parsers treat every count, offset and size in a file as hostile.** They are pure Python, clamp loops and allocations to the caps in `ANALYSIS_LIMITS` (`backend/constants.py`) and to the bytes actually present, check a per-analysis deadline, and reject what they cannot parse with `BinaryFormatError` rather than crashing. When a cap truncates output the document says so. A structure-aware fuzz harness (`tests/fuzz_harness.py`) and a regression suite (`tests/test_robustness.py`) exercise this.
- **Strings from files are data, never markup.** Symbol, section, library and file names, strings, paths and server error messages are escaped or inserted as text. The page is served with a CSP that allows scripts and stylesheets only from its own origin, with no inline script and no inline style (`script-src 'self'; style-src 'self'`), so an escaping bug cannot load or run outside code.

## Local mode (default)

**Intended use:** one person on their own computer.

**Trusted:** the user, and everything else that can connect to the machine's loopback interface. Local mode can open any path the account can read, run `objdump`/`llvm-objdump` and `c++filt` on files, and show Python tracebacks with `--debug`.

**Defended against:**

- *Other machines.* It listens on loopback only and refuses to start on any other address unless given `--i-know-this-is-unsafe`.
- *Web pages in your browser.* A malicious page cannot use the local server: requests whose `Sec-Fetch-Site` or `Origin` say they come from another site or origin are refused; form-style content types are refused; no CORS headers are ever sent; the `Host` header must be a loopback name, which defeats DNS rebinding. A link can still name a file (`?file=/some/path` or `#doc=path:/some/path`): the interface does not read a path that arrived in a URL until you confirm it in the open panel. That check is in the page's JavaScript, not in the server.
- *Hostile files,* as above, with longer limits (256 MiB, 120 s).

**Not defended against:**

- **Other users and processes on the same machine.** There is no authentication. Anything that can connect to `127.0.0.1:8421` can read every file your account can read (`/api/parse?path=...`, `/api/hex`, `/api/download`). Do not run local mode on a shared machine, a jump host, or anywhere untrusted code runs as another user.
- **Bugs in external tools.** In local mode, x86 disassembly of a file on disk may be done by `llvm-objdump` or GNU `objdump`, and C++ names are passed to `c++filt`. A vulnerability in those tools applies.

## Public mode (`--public`)

**Intended use:** an Internet-facing service behind a TLS reverse proxy, used anonymously.

**Trusted:** the operator, the host, and the reverse proxy (only if `--trust-proxy` is set).

**Guaranteed by design (and by tests in `tests/test_api_security.py`):**

- **No access to server files.** Loading by path, host samples and external tools are off and cannot be re-enabled by any other option. Static files are served only from `static/`, after refusing dot segments, hidden files, backslashes, NULs and colons and resolving symlinks.
- **Uploads are isolated.** Each upload gets an id of 128 random bits (`u_` + 32 hex digits from `secrets`); a patched copy gets its own (`p_`). There is no listing of documents and no "current document". An id is not written to the app's logs (only its kind is). The interface sends ids in request headers (`X-BS-Doc`, and `X-BS-Doc-A` / `X-BS-Doc-B` for a comparison), not in request URLs, and never puts an upload's id in a page URL or in browser storage; the file's bytes are kept in the tab's memory only, never in browser storage. Unknown, expired and evicted ids all return the same `410`.
- **Bounded resources.** Upload size, request bodies in flight (in total and per client, reserved as the bytes arrive rather than when they are announced), response bodies in flight (in total and per client), connections in total and per client, request head size and time, cut-offs for slow senders and for readers that stop reading, per-client request, upload and patch rates, concurrent analyses, analysis time, document size and cache size are all capped (see [docs/hosting.md](docs/hosting.md#settings-reference)). A response also costs rate-limit tokens by size (one per 256 KiB), so a small request cannot buy unlimited egress. Once one client's uploads hold 30% of the cache, its own oldest documents are evicted first, not other people's.
- **Uploads are analysed outside the server process.** Public mode parses each upload in one of a small pool of worker processes (`backend/workers.py`, `backend/parse_worker.py`). A worker still running at the analysis deadline (20 s) plus a 3 s grace is killed and replaced, and that request gets `422 timeout`; a worker that crashes or runs out of memory fails only its own request. The server process and every cached document are unaffected. Workers return JSON, never pickled objects. If no worker process can be started at all, the server logs `parse_workers_unavailable` once and analyses in its own threads, where the old last resort applies: an analysis still running after the hard timeout (80 s) makes the process exit for its supervisor to restart.
- **Request hygiene.** `Transfer-Encoding` is refused, exactly one `Content-Length` and one `Host` are required, header lines that are folded, have whitespace around the name or do not end in CRLF (a bare LF) are refused with 400, and bodies over a limit are refused from the headers before being read.
- **Cross-site requests are refused, scheme included.** As in local mode, `/api/` requests that `Sec-Fetch-Site` or `Origin` mark as coming from elsewhere get 403. An `Origin` whose scheme differs from the one the request arrived over counts as another origin. The server itself only speaks plain HTTP, so behind a TLS proxy it must be told the real scheme: start it with `--trust-proxy` and have the proxy send `X-Forwarded-Proto`. Without `--trust-proxy`, every browser request that carries an `https://` Origin (uploads and patches among them) gets 403.
- **Nothing internal in responses.** Errors carry a message and a code; internal errors carry only a reference that appears in the log. Exception messages, which can quote file bytes, are not logged in public mode.

**Not guaranteed:**

- **Confidentiality from the operator.** Uploaded files are in the server's memory and the operator can read them. Say so in your privacy policy.
- **Confidentiality from anyone who obtains an id.** An upload id is a bearer capability: whoever has it can read the file until it expires (30 minutes idle by default). The interface sends it in the `X-BS-Doc`, `X-BS-Doc-A` and `X-BS-Doc-B` request headers (percent-encoded), and patch requests carry it in a JSON body, so it is not in URLs the interface requests. The server still accepts the query form (`?doc=`, `?a=`, `?b=`) from other clients and hand-written URLs. A reverse proxy, CDN or log pipeline that records request headers, or full URLs for clients that use the query form, will record the id. The examples in `deploy/` drop those headers and redact those parameters (Caddy's log filter; nginx's `log_format`, with `error_log` at `crit` because nginx's error log quotes the full request line); your own setup must too.
- **Availability under attack.** It is one server process with a few analysis workers. Rate limits are per client address (IPv6 per /64), so an attacker with many addresses can still exhaust CPU, the analysis slots or the cache. Documents live only in the server process's memory: anything that restarts it (a crash, the kernel's memory limit, or the hard-timeout exit when workers are off) drops every user's documents at once. Put a CDN or proxy with its own limits in front if availability matters.
- **TLS.** The app speaks plain HTTP. Transport security is entirely the reverse proxy's job.
- **Correct client addresses without a correct proxy.** With `--trust-proxy` the app believes the last `X-Forwarded-For` entry, and the last `X-Forwarded-Proto` value, from any loopback or private-network peer. If the app's port is reachable by anyone other than the proxy, rate limits can be evaded and logs falsified.

## Static build (WebAssembly)

**Intended use:** a public site with no server-side code. The same engine runs in each visitor's browser in a Web Worker.

**Guaranteed by design (and by `tests/test_static_build.py`):**

- **Files stay on the device.** Opened files are analysed in the tab; the transport answers every API call inside the browser. The browser test checks that no request goes to another origin and that the uploaded bytes never appear in any request.
- **No server to attack.** The host serves fixed files.
- **Pinned runtime.** Pyodide is fetched at build time, checked against a pinned SHA-256 and served from the site's own origin. Nothing is loaded from a CDN at run time.

**Not guaranteed:**

- **Headers on hosts that cannot send them.** On GitHub Pages or a plain S3 bucket only the `<meta>` CSP applies; it cannot forbid framing and does not cover the worker. See [docs/hosting.md](docs/hosting.md#deploy).
- **Integrity of what the host serves.** If the host or anyone who can deploy to it is compromised, visitors get whatever it serves. The worker checks the engine bundle's SHA-256 against the value in the build's manifest (in a secure context), but the manifest is served by the same host, so this catches corruption, not tampering. The Pyodide hash check happens at build time only.
- **Resource limits.** A hostile file can still exhaust the tab's memory or CPU. The page can stop the engine and start a new one, and the engine's per-analysis deadline still applies, but the effect is on the visitor's own machine.

## Known residual risks

Stated plainly, in no particular order:

1. Local mode has no authentication; any local user or process can read the running user's files through it.
2. Parsers are memory-safe Python, but they rely on CPython's standard library (for example `plistlib`, which uses expat, for XML entitlements). A flaw there would apply. Entitlement XML with entity declarations is refused and nesting is capped before parsing.
3. The analysis deadline is cooperative: parsers check it as they go, and Python cannot interrupt a thread. In public mode this no longer matters for uploads, because they are analysed in worker processes that the server kills at the deadline plus a 3 s grace. It still matters wherever analysis runs in-thread: local mode, the CLI, the static build (where the page's watchdog replaces the engine worker instead), public mode with `BINARYSTUDIO_PARSE_WORKERS=0`, and public mode on a system where no worker process can be started. In the last two cases a stuck analysis is ended only by the hard timeout, which exits the whole server and loses every cached document.
4. The per-worker memory limit (`BINARYSTUDIO_PARSE_WORKER_MEMORY_MB`, 1024 MiB) is an address-space limit (`RLIMIT_AS`) that each worker sets on itself. Linux enforces it; macOS does not, and Windows has no such limit. All development and testing was on macOS, so the limit has never been seen to take effect. Where it is not enforced, a worker's memory is bounded only by the analysis deadline and by the supervisor's limit on the whole service.
5. The memory charged for cached documents is an estimate (the file's size plus five times its JSON size), not a measurement. Memory use above the estimate is bounded only by the process limit set by the supervisor.
6. Worst-case memory can exceed the 2 GiB limit in the deploy files. With the defaults the server may hold a full cache (512 MiB by estimate) and 128 MiB of request bodies while four workers each analyse a maximum-size file, and each worker is allowed up to 1 GiB. The intended outcome is that the kernel then kills a worker (workers mark themselves as the preferred victim, and the systemd unit sets `OOMPolicy=continue`), so one upload fails. That behaviour has not been tested; if the server process is killed instead, every document is lost and the supervisor restarts it.
7. A derived document (a patched copy from the patch lab) holds a full copy of the file's bytes and its own analysis, not a delta against its original. Both are charged to the cache, and a patched copy and its original are kept together even past the client's cache share, so patching large files uses the cache twice as fast as uploading them.
8. Rate limiting and the per-client cache share are keyed by IP address and are weak against distributed clients.
9. Only desktop Chrome has been used to test the interface and the static build.
10. Nothing in `deploy/` has ever been run: not the Docker image, the compose file, the systemd unit (including `OOMPolicy=continue` and the `setrlimit` / `prlimit64` allowances in its system-call filter that the workers' limits depend on), the Caddyfile or `nginx.conf` (including their log redaction). Their hardening is untested. No Linux or Windows host has been used at all, so worker processes under Linux limits, and the fallback to in-thread analysis where workers cannot start (expected on Windows), are untested too.
11. Ads (off by default) never load third-party script, but enabling the `ethicalads` provider in the in-app footer slot adds a third-party origin to the app's `connect-src` and `img-src`, and the `house` and `frame` providers can add image or frame origins. See [docs/monetisation.md](docs/monetisation.md). The ads layer has not been tested against a live provider.
