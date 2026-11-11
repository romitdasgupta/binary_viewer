# Hosting guide

There are two ways to put BinaryStudio on the web. This guide covers both, lists every setting with its default, and ends with a pre-launch checklist and an honest account of what has been tested.

- [Choosing](#choosing)
- [Option A: the static build](#option-a-the-static-build)
- [Option B: the Python server in public mode](#option-b-the-python-server-in-public-mode)
- [Settings reference](#settings-reference)
- [Operations](#operations)
- [Pre-launch checklist](#pre-launch-checklist)
- [What has and has not been tested](#what-has-and-has-not-been-tested)

Before either, read [SECURITY.md](../SECURITY.md) for what each mode protects against and what it does not. Never expose local mode (the default) to a network: it can read every file the account running it can read. It refuses to bind to a non-loopback address unless you pass `--i-know-this-is-unsafe`; do not.

## Choosing

| | Static build | Python server (`--public`) |
|---|---|---|
| Where files are analysed | In the visitor's browser (WebAssembly) | On your server |
| Do visitors' files reach you? | No | Yes, held in memory until idle or evicted |
| Server-side code to attack | None (any static host) | A Python HTTP server parsing hostile input |
| First visit download | About 6.9 MB compressed (measured below) | About 0.7 MB of HTML, CSS and JavaScript (about 0.17 MB gzip-compressed), then each document as JSON |
| Works on weak devices | Needs a desktop-class browser for large files | Yes; the server does the work |
| Largest file | 512 MiB (set in `tools/build_static.py`) | 32 MiB by default, configurable |
| Operational work | Upload files; set headers | Process supervision, memory limits, TLS proxy, logs |

**Recommendation:** use the static build for public hosting unless you need to serve devices that cannot run it. It removes the server as a target and visitors' files never leave their machines. Run the Python server when you need server-side analysis, and then treat it as a service that parses hostile input.

## Option A: the static build

### Build

Requirements: Python 3.9 or newer, standard library only. The first build needs network access once.

```sh
python3 tools/build_static.py --out dist/
```

The build downloads the pinned Pyodide release (`pyodide-core-314.0.7.tar.bz2`, CPython 3.14.2 compiled to WebAssembly, about 6.8 MB) into a cache outside the repository, checks its SHA-256 against the value pinned in `tools/build_static.py` and aborts on a mismatch. The cache is `$BINARYSTUDIO_PYODIDE_CACHE` if set, else `$XDG_CACHE_HOME/binarystudio/pyodide`, else `~/.cache/binarystudio/pyodide`; `--pyodide-cache DIR` overrides it. Pyodide is never committed, and the site never fetches it from a CDN at run time. Once the cache is filled, `--offline` guarantees no network access:

```sh
python3 tools/build_static.py --out dist/ --offline
```

The build then bundles `backend/` (without `server.py`, `fixtures.py`, `workers.py` and `parse_worker.py`) and the six samples into a zip, runs that bundle on its own in an isolated interpreter as a smoke test, rewrites `index.html` to reference content-hashed assets, and writes `dist/_headers`. It refuses to delete an existing output directory that is not a previous build. On 2026-11-09 the build took 17.5 s and reported:

```
everything shipped            28 files    15.21 MB raw     7.04 MB gzip
engine (Pyodide + bundle)      6 files    13.80 MB raw     6.69 MB gzip
first visit downloads         18 files    14.53 MB raw     6.87 MB gzip
routes: 20   engine modules: 28   upload limit: 536.87 MB
```

(Sizes in decimal megabytes; the upload limit is 512 MiB.) A later build the same day, after the generated learning pages and site files were added, shipped 43 files, 15.28 MB raw and 7.08 MB gzip, with the first-visit download unchanged at 6.88 MB gzip. `dist/build-info.json` records the file list, sizes, Pyodide version and hash, the routes and the CSP of each build.

### Try it locally

```sh
python3 tools/build_static.py --serve dist/
```

This serves `dist/` on `http://127.0.0.1:8000` with the headers from `dist/_headers` applied, the way Cloudflare Pages or Netlify would. It is a test server, not for production.

### Deploy

Upload the contents of `dist/` to any static host, at the root of a domain or subdomain. (Serving from a sub-path such as `https://example.com/tools/binarystudio/` has not been tested.)

**Headers.** The host must send these on every response. `dist/_headers` contains them in the format Cloudflare Pages and Netlify read:

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: accelerometer=(), autoplay=(), browsing-topics=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), hid=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()
Strict-Transport-Security: max-age=31536000
```

and, for `/assets/*` only, `Cache-Control: public, max-age=31536000, immutable`. Everything else must be revalidated (the host's default). The CSP is the Python server's page policy with `'wasm-unsafe-eval'` added to `script-src` so the browser may compile the engine; `tests/test_static_build.py` checks that this is the only difference. Copy the headers from your own `dist/_headers`, not from this page, after every build.

Content types: `.mjs` files must be served as JavaScript (browsers refuse module scripts otherwise) and `.wasm` as `application/wasm`. Common hosts do this by default; check it.

**Hosts that ignore `_headers`** (GitHub Pages, a plain S3 bucket) cannot send these headers. `index.html` carries the CSP as a `<meta>` tag as a fallback, but a meta CSP cannot express `frame-ancestors` (so the page can be framed by other sites), does not apply to the engine's worker script, and the other headers are missing entirely. On GitHub Pages there is no way to fix this. On S3, put a CDN in front that adds response headers (for example a CloudFront response headers policy) and copy the values from `dist/_headers`.

**Updates.** Each build has its own id. A service worker (`sw.js`) precaches the build for offline use after the engine has started once. Pages are fetched network-first, so visitors get a new deployment on their next load; a tab that is already open keeps using its own build until every tab of it is closed.

**Configuration.** The static build has no runtime settings: everything is decided when you build. Limits come from `WASM_OVERRIDES` in `tools/build_static.py` (512 MiB largest file, 6 documents and 768 MiB in the engine's cache), and the answer to `/api/config` is generated at build time. Three build options (each also read from an environment variable) configure the site layer in `tools/site_pages.py`:

| Option | Variable | Effect |
|---|---|---|
| `--site-url URL` | `BINARYSTUDIO_SITE_URL` | Absolute site URL, for canonical links and `sitemap.xml` (no sitemap without it) |
| `--ads JSON` or `--ads @file.json` | `BINARYSTUDIO_ADS` | Ads configuration; see [monetisation.md](monetisation.md) |
| `--security-contact URI` | `BINARYSTUDIO_SECURITY_CONTACT` | `mailto:`, `https://` or `tel:` contact published as `/.well-known/security.txt` (not generated without it) |

The build also generates static learning pages under `learn/` (one article per concept, the glossary, the comparison and the field reference) and `robots.txt`, and copies `privacy.html`, `terms.html`, `about.html`, `404.html` and the favicons from `static/` to the site root. Footer links to the privacy, terms and about pages appear only for pages that exist in `static/` when you build.

**Upgrading Pyodide.** Change the four `PYODIDE_*` constants together in `tools/build_static.py`, build once with network access, then run `tests/test_static_build.py` and the parity check described in [CONTRIBUTING.md](../CONTRIBUTING.md#static-build-and-parity).

## Option B: the Python server in public mode

### What public mode changes

`--public` (or `BINARYSTUDIO_MODE=public`) turns off, and makes impossible to turn back on by any other setting: opening server files by path, the host samples (`/bin/ls`), external tools (`objdump`, `c++filt`) and tracebacks in errors. Uploads are addressed by random ids and dropped when idle. Rate limits, a concurrency cap, parse deadlines and memory bounds are on by default. Uploads are analysed in a pool of worker processes rather than in the server's own threads (see [Operations](#operations)). `--file` and `--debug` are refused.

The server speaks plain HTTP/1.1. It must sit behind a reverse proxy that terminates TLS, and behind such a proxy it must be started with `--trust-proxy` (see [What the reverse proxy must do](#what-the-reverse-proxy-must-do)).

### Requirements

- Python 3.9 or newer (developed and tested on 3.9.6). No packages.
- A process supervisor that restarts it (systemd, Docker, or similar), and permission for the server to start child processes of its own interpreter (the analysis workers). An overrunning analysis costs one worker, not the server; the server exits on purpose only when workers are off or unavailable and an analysis cannot be stopped. See [Operations](#operations).
- A reverse proxy with TLS: Caddy and nginx examples are in `deploy/`.
- About 2 GiB of memory with the default limits; the worst case is higher (see [Memory](#memory)).

### Step by step: systemd and Caddy on one host

These steps follow the comments in `deploy/binarystudio.service` and `deploy/Caddyfile`. They have not been run end to end (see the last section).

1. Copy the application. It needs `binary_viewer.py`, `macho_viewer.py`, `backend/`, `static/`, `fixtures/` and `tools/site_pages.py` (the generated learning pages, `robots.txt`, `security.txt` and the ads layer; without it the server runs, those pages are missing and ads are forced off). The same commands are in the comment at the top of `deploy/binarystudio.service`:

   ```sh
   sudo mkdir -p /opt/binarystudio/tools
   sudo cp -r binary_viewer.py macho_viewer.py backend static fixtures /opt/binarystudio/
   sudo cp tools/site_pages.py /opt/binarystudio/tools/
   sudo chown -R root:root /opt/binarystudio && sudo chmod -R a+rX,go-w /opt/binarystudio
   ```

2. Install the unit, set your domain in `Environment=BINARYSTUDIO_ALLOWED_HOSTS=...`, and start it. The unit already sets `BINARYSTUDIO_TRUST_PROXY=1`; keep it:

   ```sh
   sudo cp deploy/binarystudio.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now binarystudio
   ```

   The unit runs `binary_viewer.py --public --host 127.0.0.1 --port 8421` as a throwaway user (`DynamicUser=yes`) with a read-only filesystem, no capabilities, a system-call filter, `MemoryMax=2G`, `OOMPolicy=continue` and `Restart=always`. The filter removes the `@resources` group and then allows `setrlimit` and `prlimit64` again, because each analysis worker lowers its own limits when it starts; if those calls are refused anyway the workers still run, without their own kernel limits. `OOMPolicy=continue` is there so that when the kernel kills a worker for memory, systemd does not stop the whole unit. None of this has been run. `systemd-analyze security binarystudio` reviews the hardening.

3. Check it locally: `curl -s http://127.0.0.1:8421/healthz` prints `ok`.

4. Install Caddy 2, copy `deploy/Caddyfile` to `/etc/caddy/Caddyfile`, and set `BINARYSTUDIO_DOMAIN` to your domain in Caddy's environment (or replace `binarystudio.example.com` in the file). Caddy obtains the certificate itself. The file keeps document ids (the capability of an upload) out of Caddy's access log: it deletes the `X-BS-Doc`, `X-BS-Doc-A`, `X-BS-Doc-B`, `X-Filename` and `Referer` request headers from log entries and redacts the `doc`, `a`, `b` and `path` query parameters. Caddy sets `X-Forwarded-For` and `X-Forwarded-Proto` by default, which is what `--trust-proxy` reads.

5. Open `https://<your domain>/`, open a sample and upload a small file. Then work through the [checklist](#pre-launch-checklist).

To use nginx instead, follow the comments in `deploy/nginx.conf`. Three lines in it are required: `proxy_set_header Host $host;` (otherwise every request is refused by the Host allowlist), `proxy_set_header X-Forwarded-For $remote_addr;` (overwrite, never append, because the app trusts the last entry) and `proxy_set_header X-Forwarded-Proto $scheme;` (so the app knows the browser used HTTPS). The file logs `$uri` instead of the request line, so query strings are not in the access log, and sets `error_log ... crit`: nginx's error log quotes the full request line, query string included, at level `error` and below, and that cannot be reformatted. nginx does not log request headers.

### Step by step: Docker Compose

`Dockerfile` builds an image that runs public mode as uid 10001 on port 8421 with `/healthz` as its health check; `deploy/docker-compose.yml` runs it with a read-only root filesystem, no capabilities, `mem_limit: 2g`, `pids_limit: 512`, no published port, `BINARYSTUDIO_TRUST_PROXY=1`, and Caddy in front. The analysis workers run inside the app container.

```sh
cd deploy
BINARYSTUDIO_DOMAIN=binarystudio.example.com docker compose up -d --build
```

**Not run.** Docker was not available on the development machine: the image has never been built and the compose file has never been started. Expect to debug both. The image uses `python:3.13-slim` while the code is tested on 3.9; the `Dockerfile` header shows how to run `tests.test_api_security` inside the image to check it.

### What the reverse proxy must do

- Pass the original `Host` header unchanged. The app answers only to the names in `--allowed-host` (plus loopback names), and compares each request's `Origin` with its `Host`.
- Be trusted: start the app with `--trust-proxy` (or `BINARYSTUDIO_TRUST_PROXY=1`). This is required behind a TLS proxy, not optional. The app listens on plain HTTP, so without it every request counts as having arrived over `http`, and a browser request whose `Origin` is `https://...` (every upload and patch) is refused with 403 as cross-origin; the log line is `cross_site_rejected` with the reason "Origin is https but the request arrived over plain http".
- Send `X-Forwarded-Proto` with the scheme the browser used (`https`). With `--trust-proxy` the app compares it with the scheme of `Origin`; the last value counts. If a trusted proxy sends no `X-Forwarded-Proto`, the scheme comparison is skipped and only host and port are compared.
- Set `X-Forwarded-For` so that its last entry is the address the proxy saw. The app takes the client address from the last entry only, and only when the connection comes from a loopback or private address (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, ::1, fc00::/7, fe80::/10). The app's port must not be reachable by anything except the proxy.
- Allow request bodies a little above the app's upload limit (both examples use 33 MiB for the default 32 MiB) so the user sees the app's error message for a file that is slightly too large. Raise it when you raise `--max-upload-mb`.
- Allow response times above the parse timeout plus the 3 s kill grace (23 s by default); both examples use 90 s.
- Keep document ids out of its logs: an upload's id is the only thing needed to read it while it is held. The web interface sends ids in the `X-BS-Doc`, `X-BS-Doc-A` and `X-BS-Doc-B` request headers; other clients may still use the query parameters `doc`, `a` and `b`, which the server accepts. So do not log those headers, and do not log query strings (or redact those parameters), in access logs and in error logs.
- Send header lines that end in CRLF. The app refuses with 400 any request whose header block has a line ending in a bare LF, a folded line or whitespace around a header name. Caddy and nginx send well-formed headers.
- Compression is optional. The app gzips JSON itself for clients that accept it (`BINARYSTUDIO_GZIP`, on by default) and marks the response `Content-Encoding: gzip`; set `BINARYSTUDIO_GZIP=0` to leave compression to the proxy.
- Terminate TLS and send `Strict-Transport-Security` (both examples do). The app can send it too with `BINARYSTUDIO_HSTS_SECONDS`, but only set that when every request reaches users over HTTPS.

## Settings reference

A command-line flag wins over its environment variable. `python3 binary_viewer.py --help` prints the same list. The defaults below were generated from `backend/runtime.py` (`RuntimeConfig` and `ENV_VARS`).

| Variable | Flag | Local default | Public default | Meaning |
|---|---|---|---|---|
| `BINARYSTUDIO_MODE` | `--public` | `local` | `public` | `local` or `public` |
| `BINARYSTUDIO_HOST` | `--host` | 127.0.0.1 | 127.0.0.1 | bind address (the Docker image sets 0.0.0.0) |
| `BINARYSTUDIO_PORT` | `--port` | 8421 | 8421 | bind port; 0 picks a free one |
| `BINARYSTUDIO_ALLOWED_HOSTS` | `--allowed-host` (repeatable) | loopback names | loopback names | Host names to accept, comma separated. A leading dot matches subdomains; `*` accepts any |
| `BINARYSTUDIO_TRUST_PROXY` | `--trust-proxy` | 0 | 0 | 1 = take the client address from the last `X-Forwarded-For` entry and the request scheme from `X-Forwarded-Proto`. Required behind a TLS proxy |
| `BINARYSTUDIO_MAX_UPLOAD_MB` | `--max-upload-mb` | 256 | 32 | largest accepted upload, MiB |
| `BINARYSTUDIO_RATE_LIMIT` | | 0 | 240 | requests per client per minute; 0 = unlimited |
| `BINARYSTUDIO_UPLOAD_RATE_LIMIT` | | 0 | 12 | uploads per client per minute; 0 = unlimited |
| `BINARYSTUDIO_MAX_CONCURRENT_PARSES` | | 0 | 4 | analyses running at once; 0 = unlimited |
| `BINARYSTUDIO_PARSE_TIMEOUT` | | 120 | 20 | seconds one analysis may take; 0 = unlimited |
| `BINARYSTUDIO_HARD_PARSE_TIMEOUT` | | 0 | 80 | last resort when analyses run inside the server process (workers off or unavailable): seconds after which a stuck one makes the server exit for its supervisor to restart; 0 = never. Never reached with workers |
| `BINARYSTUDIO_PARSE_WORKERS` | | 0 | 1 | 1 = analyse uploads in worker processes that are killed when they overrun; 0 = inside the server process. The pool has one worker per concurrent analysis (4 when `BINARYSTUDIO_MAX_CONCURRENT_PARSES` is 0) |
| `BINARYSTUDIO_PARSE_WORKER_MEMORY_MB` | | 0 (none) | 1024 | address-space limit (`RLIMIT_AS`) of one analysis worker, MiB; 0 = none. Enforced on Linux only |
| `BINARYSTUDIO_MAX_INFLIGHT_RESPONSE_MB` | | 0 | 256 | response bodies being written at once, MiB; one client may hold a quarter of it. Past either, a large response gets `503 busy`. 0 = unlimited |
| `BINARYSTUDIO_GZIP` | | 1 | 1 | 1 = gzip JSON and text API responses for clients that accept it; 0 = leave compression to the proxy |
| `BINARYSTUDIO_DOC_TTL` | | 0 | 1800 | seconds an idle document stays in memory; 0 = until evicted |
| `BINARYSTUDIO_CACHE_MAX_DOCS` | | 32 | 64 | documents kept in memory |
| `BINARYSTUDIO_CACHE_MAX_MB` | | 512 | 512 | estimated memory for cached documents, MiB |
| `BINARYSTUDIO_CACHE_CLIENT_SHARE` | | 0 | 0.3 | fraction of the cache one client may fill before its own oldest documents are evicted; 0 = no bound |
| `BINARYSTUDIO_MAX_DOCUMENT_MB` | | 0 (none) | 24 | largest analysis result (serialized JSON), MiB |
| `BINARYSTUDIO_MAX_CONNECTIONS` | | 256 | 128 | open connections; 0 = unlimited |
| `BINARYSTUDIO_MAX_CONNECTIONS_PER_CLIENT` | | 0 | 24 | open connections per client address; 0 = unlimited. With `--trust-proxy` every connection comes from the proxy, so the same number caps the requests in progress per forwarded client address instead (`503 busy` past it) |
| `BINARYSTUDIO_REQUEST_TIMEOUT` | | 30 | 15 | seconds to receive a complete request head |
| `BINARYSTUDIO_ACCESS_LOG` | `--access-log` | 0 | 1 | one log line per request |
| `BINARYSTUDIO_STATIC_MAX_AGE` | | 0 | 300 | `Cache-Control` max-age for static assets other than HTML |
| `BINARYSTUDIO_CSP_EXTRA` | `--csp-extra` | none | none | sources merged into the page CSP, e.g. `frame-src https://ads.example` |
| `BINARYSTUDIO_CSP` | | built in | built in | replace the page CSP entirely |
| `BINARYSTUDIO_PERMISSIONS_POLICY` | | built in | built in | replace the `Permissions-Policy` header |
| `BINARYSTUDIO_HSTS_SECONDS` | | 0 | 0 | send `Strict-Transport-Security` with this max-age; 0 = not sent |
| `BINARYSTUDIO_ADS` | | off | off | ads configuration (JSON), validated at start-up; see [monetisation.md](monetisation.md) |
| `BINARYSTUDIO_SOURCE_URL` | | none | none | http(s) URL of the source code, shown in the UI |
| `BINARYSTUDIO_SITE_URL` | | none | none | absolute site URL, for canonical links and `sitemap.xml` |
| `BINARYSTUDIO_SECURITY_CONTACT` | | none | none | `mailto:` or `https:` contact; enables `/.well-known/security.txt` |

Booleans accept `1/0`, `true/false`, `yes/no`, `on/off`. An invalid value stops the server at start-up with a message naming the variable.

Fixed limits (not configurable from the environment; set in `backend/runtime.py`, `backend/api.py`, `backend/labs_patch.py`, `backend/labs_encoding.py`, `backend/service.py`):

| Limit | Value |
|---|---|
| JSON request body | 1 MiB (16 KiB for `/api/labs/encoding/decode` and `/api/labs/build`, 64 KiB for `/api/labs/resolve`) |
| Bytes changed by one patch set / entries | 64 KiB / 4,096 |
| Patch requests | 10 per allowed upload per minute, per client (120/min in public mode), on top of the request limit |
| Request line / request head | 8,192 / 16,384 bytes |
| Keep-alive idle time | 15 s local, 5 s public |
| Requests per connection | 200 |
| Slowest accepted transfer | 64 KiB/s |
| Request body: first byte | must start arriving within 5 s (public) or 30 s (local), then keep up with the minimum rate |
| Reader that accepts nothing | cut off after 15 s (public) or 60 s (local) |
| Request bodies buffered at once | 4 x the upload limit in public mode (128 MiB by default), half of that per client; unlimited locally. Reserved as the bytes arrive, not when a `Content-Length` announces them |
| Response size charged to the rate limit | one extra token per 256 KiB of response body |
| Responses counted against the in-flight cap | those of 256 KiB or more |
| Wait for an analysis slot | 2 s, then `503 busy` |
| Worker kill grace | 3 s past the parse timeout |
| Worker recycling | after 200 analyses, or after one that took its peak memory past 128 MiB |
| Rate-limit burst | half the per-minute rate |
| Clients remembered by the rate limiter | 20,000 (least recently seen forgotten) |
| Search query / results | 256 characters / 200 |
| Hex window per request | 64 KiB |
| Disassembly per request | 1,000 instructions |

Rate limits are per client address; IPv6 clients are grouped by /64.

### Security headers

Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin` and the `Permissions-Policy` above. HTML and static files get the page CSP:

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'
```

Content pages (the generated `/learn/` pages, generated once from the engine's own learning data and served from memory) get the same policy plus whatever sources an enabled ads provider needs; the app shell gets those sources only if the in-app footer slot is configured ([monetisation.md](monetisation.md#providers)). JSON and downloads get `default-src 'none'; frame-ancestors 'none'; sandbox` and `Cache-Control: no-store`. Documents, downloads and any `GET` answer of 4 KiB or more also carry an `ETag`, and a `GET` whose `If-None-Match` names it gets `304` with no body; because of `no-store` nothing is written to a browser cache, so this only helps a client that still holds the answer. JSON and text answers of 1 KiB or more are gzipped for clients that accept it (unless `BINARYSTUDIO_GZIP=0`). No `Access-Control-*` header is ever sent. `--csp-extra` merges sources into a directive (adding sources to a `'none'` directive replaces the `'none'`); `BINARYSTUDIO_CSP` replaces the whole policy, and you then own it.

## Operations

### One server process and its analysis workers

The server is one Python process with one thread per connection (`ThreadingHTTPServer`, capped by `BINARYSTUDIO_MAX_CONNECTIONS`). In public mode it does not parse uploads in those threads. It keeps a pool of worker processes (`backend/workers.py`; each runs `backend/parse_worker.py` under the same interpreter with `-I -B`), one per concurrent analysis, so four by default. Workers are started in the background when the server starts, started again on demand, and reused. The server hands a worker the file over a pipe and waits for the document as JSON. Local mode, the CLI and the static build analyse in-thread and start no processes; the bundled samples are parsed in the server process at start-up.

What happens to an analysis that misbehaves:

- **It runs too long.** The parsers check a deadline (`BINARYSTUDIO_PARSE_TIMEOUT`) as they go and normally answer with a clean error themselves. A worker still running 3 s after the deadline is killed and replaced; the server logs `parse_worker_killed` and the request gets `422` with code `timeout`.
- **It needs too much memory.** On Linux the worker's address-space limit (`BINARYSTUDIO_PARSE_WORKER_MEMORY_MB`) makes the allocation fail; the worker reports it and exits, the server logs `parse_worker_memory`, and the request gets `422 parse_failed`. This limit is not enforced on macOS, does not exist on Windows, and has not been tested on Linux.
- **It crashes the worker.** The server logs `parse_worker_died` and the request gets `422 parse_failed`.

In each case only that request fails; the server and every cached document are untouched, and the next upload gets a new worker.

If no worker can be started at all (no permission to create processes, or a platform the pool does not support), the server logs `parse_workers_unavailable` once and analyses in its own threads, as it does with `BINARYSTUDIO_PARSE_WORKERS=0`. A Python thread cannot be killed, so in that configuration the last resort applies: if an analysis is still running `BINARYSTUDIO_HARD_PARSE_TIMEOUT` seconds after it started, the housekeeping thread (every 15 s) logs `parse_stuck` and the process exits with status 70. The supervisor must restart it, and browsers re-upload their open documents after the resulting `410 doc_expired`. This fallback is what a Windows host is expected to get; it has not been tried.

Documents are held only in the server process. There is no shared state between server processes, so you cannot run several behind a load balancer without sticky sessions: a document id is only known to the process that created it. (A client whose document is unknown re-uploads it, so this degrades rather than breaks, but it has not been tried.)

`GET /healthz` answers `ok` for any Host, is not rate limited and is not logged when it succeeds. `SIGTERM` stops the server.

### Memory

Budget for, at least:

- the document cache (`BINARYSTUDIO_CACHE_MAX_MB`, 512 MiB). This is an estimate: each document is charged as the file's size plus five times its JSON size. A patched copy made in the patch lab is a whole document with its own full copy of the file's bytes, charged like an upload;
- request bodies in flight (128 MiB by default);
- the analysis workers. `deploy/binarystudio.service` records about 35 MiB for an idle worker and about 200 MiB for one analysing a file that yields a 20 MiB document; a worker whose peak passed 128 MiB is replaced after that analysis, because CPython does not return freed memory. Each worker may grow to its own limit (1 GiB by default) where that limit is enforced.

Large responses are written from the cached buffers, not copied per request, so the 256 MiB response cap bounds how much is being sent at once rather than adding memory.

The worst case is above the 2 GiB limit in the deploy files: a full cache, 128 MiB of uploads in flight and four workers each analysing a maximum-size file can ask for more than that, since four workers alone are allowed 4 GiB between them. The deploy files are written so that the kernel then kills a worker and one upload fails (workers set their own `oom_score_adj` to 1000, and the unit has `OOMPolicy=continue`). Neither that nor the 1 GiB limit has been exercised: it is Linux behaviour, and everything was run on macOS. If you need a firm bound, lower `BINARYSTUDIO_MAX_CONCURRENT_PARSES`, `BINARYSTUDIO_PARSE_WORKER_MEMORY_MB` or `BINARYSTUDIO_CACHE_MAX_MB`, or raise the service's limit.

For a sense of scale, measured on 2026-11-09 on macOS (Python 3.9.6, public-mode config), one analysis per process, before analyses moved into workers:

| File | Size | Analysis | JSON | Charged to cache | Peak RSS |
|---|---|---|---|---|---|
| `/usr/lib/dyld` | 3.9 MiB | 0.58 s | 10.6 MiB | 57 MiB | 96 MiB |
| Calculator.app binary | 3.3 MiB | 0.40 s | 7.2 MiB | 39 MiB | 72 MiB |

So the default cache holds on the order of ten documents of that size. Peak memory for a 32 MiB upload, or for many simultaneous ones, has not been measured.

### Logs

Logs are JSON lines on stderr: `startup` (the effective limits), `request` (one per request when the access log is on, which it is in public mode), `host_rejected`, `cross_site_rejected`, `request_rejected`, `connection_rejected`, `internal_error`, `parse_worker_killed`, `parse_worker_died`, `parse_worker_memory`, `parse_workers_unavailable`, `parse_stuck` and a few others. A request line holds the time, client address (from `X-Forwarded-For` with `--trust-proxy`), method, path without the query string, status, duration, bytes in and out, the kind of document (`preset:<name>`, `u_*`, `p_*` or `path:*`, never the id itself) and the error code. Uploaded bytes and file names are never logged; in public mode exception messages are not logged either, because they can quote bytes of the file. Repeated refusals are throttled so a flood of rejected requests cannot fill the disk.

Client IP addresses are personal data in many jurisdictions. Decide how long you keep them and say so in your privacy policy.

### Error responses

Errors have one shape, `{"error": "<message for the user>", "code": "<machine code>"}`. Codes: `bad_request` (400, also 411/414/415/431), `forbidden` (403), `not_found` (404), `method_not_allowed` (405), `timeout` (408, or 422 when an analysis ran past its deadline or its worker was killed for overrunning), `doc_expired` (410), `too_large` (413), `parse_failed` (422), `rate_limited` (429, with `Retry-After`), `internal` (500, with a reference that also appears in the log), `busy` (503: no analysis slot within 2 s, too many response bytes in flight, or too many requests in progress from one address). The static build adds `out_of_memory` (507) when the in-browser engine runs out of memory.

## Pre-launch checklist

For both options:

- [ ] The placeholders in `static/privacy.html`, `static/terms.html` and `static/about.html` are filled in (`grep -n 'class="fill"' static/*.html` lists them; see [monetisation.md](monetisation.md#placeholders-in-the-site-pages)) and the pages are accurate for your deployment, including what happens to uploaded files and to logs. The terms need a lawyer for the liability clause.
- [ ] `BINARYSTUDIO_SECURITY_CONTACT` / `--security-contact` is set, so `/.well-known/security.txt` exists, and `BINARYSTUDIO_SITE_URL` / `--site-url` is set for canonical links and the sitemap.
- [ ] `BINARYSTUDIO_SOURCE_URL` (server) points at the published source, if you publish it.
- [ ] The security headers above arrive in a browser: check the response headers of `/`, of a file under `/assets/` (static) or `/static/` (server), and of an API call.
- [ ] A test from a network outside your own: open a sample, upload a file, open the Learn and Labs views.
- [ ] Ads are off, or you have read [monetisation.md](monetisation.md) and had the legal items reviewed.
- [ ] The vulnerability contact in [SECURITY.md](../SECURITY.md) is filled in.

Static build:

- [ ] Built from a clean checkout with `--offline` after the first download; `tests/test_static_build.py` passes on the build machine.
- [ ] The host honours `_headers` (or equivalent headers are configured); `frame-ancestors 'none'` is in the response header, not only in the meta tag.

Python server:

- [ ] `--public` is in effect: `GET /api/config` shows `"mode":"public"` and `"path_load":false`.
- [ ] `--allowed-host` names your domain; a request with another Host gets 403.
- [ ] `--trust-proxy` is set, and the app's port is reachable from the proxy alone (bind to 127.0.0.1 or a private network; check with a port scan from outside). The proxy sends `X-Forwarded-Proto`. An upload from a browser over HTTPS succeeds; a 403 there means the app does not know the request came over HTTPS.
- [ ] The supervisor restarts the process: kill it and watch it come back.
- [ ] Analysis workers start: shortly after start-up the server has child processes, and the log has no `parse_workers_unavailable` line. Kill a worker and check the server stays up.
- [ ] A memory limit is set (2 GiB in the deploy files), the host has room for it, and you have read [Memory](#memory) on the worst case.
- [ ] The proxy's body limit is above the upload limit; its timeout is above the parse timeout plus 3 s.
- [ ] Access and error logs of both the proxy and the app contain no document ids: no `X-BS-Doc` header values and no `doc=`, `a=` or `b=` query values.
- [ ] Log retention is decided.

## What has and has not been tested

As of 2026-11-11.

Tested on the development machine (macOS, Python 3.9.6, desktop Chrome):

- The test suite, 508 tests, including the API security tests against real sockets (Host allowlist, cross-site refusal, slow requests, connection caps, oversize bodies, rate limits), the worker pool on macOS (a worker that overruns is killed and the request gets `timeout`), and, where the tools exist, comparisons against `llvm-objdump`.
- The static build end to end: building, serving with `--serve`, the in-browser engine in headless Chrome under the exact `_headers` (boots, opens a sample and an upload, no CSP violations, no request to another origin, the uploaded bytes never appear in a request), and response-by-response parity between CPython and the shipped Pyodide.
- Public mode started locally with the flags shown in this guide.

Not tested:

- The Docker image (never built) and `deploy/docker-compose.yml` (never started). Docker is not installed on the development machine.
- `deploy/binarystudio.service` under systemd, and `deploy/Caddyfile` and `deploy/nginx.conf` with real certificates. They were written from the documentation of each tool. That includes the unit's `OOMPolicy=continue`, its system-call filter with the `setrlimit` / `prlimit64` allowances the workers need, and both proxies' log redaction.
- The analysis workers' kernel limits. The address-space limit (`RLIMIT_AS`), the CPU-time limit and `oom_score_adj` are Linux behaviour and have never been seen to take effect; macOS does not enforce `RLIMIT_AS`.
- The fallback to in-thread analysis where worker processes cannot be started, which is what a Windows host is expected to get.
- Any real CDN or static host. Whether Cloudflare Pages, Netlify or others apply `dist/_headers` exactly as `--serve` does has not been checked, including how they combine two `Content-Security-Policy` rules for one path (which the build emits when ads widen the content pages' policy).
- Any live ad provider. No real ad has been loaded.
- Browsers other than desktop Chrome: no Firefox, Safari, Edge or mobile browser.
- Python versions other than 3.9.6 for the server (the in-browser engine runs CPython 3.14.2 from Pyodide).
- Linux and Windows hosts. Everything was run on macOS.
- Load: no test of many concurrent users, large uploads under load, or long uptimes.
- Serving the static build from a sub-path.
