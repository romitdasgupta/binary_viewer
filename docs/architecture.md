# Architecture

How BinaryStudio is put together, as of version 2.0.0, and how to extend it. For the on-disk formats themselves see [format-internals.md](format-internals.md).

- [Module map](#module-map)
- [The Document model](#the-document-model)
- [Runtime modes and configuration](#runtime-modes-and-configuration)
- [The request path](#the-request-path)
- [Document ids as capabilities](#document-ids-as-capabilities)
- [The frontend and its extension API](#the-frontend-and-its-extension-api)
- [How the static build reuses the router](#how-the-static-build-reuses-the-router)
- [Extending](#extending)

## Module map

```
binary_viewer.py         CLI and server launcher (macho_viewer.py: old name, same program)
backend/
  runtime.py             modes, RuntimeConfig, BINARYSTUDIO_* variables, error types, CSP, parse deadlines
  api.py                 transport-agnostic router: routing, errors, rate limits, body limits,
                         security headers, Host / cross-site checks, structured log, core endpoints
  server.py              HTTP adapter over the router + static file server (never used in the browser)
  workers.py             pool of analysis worker processes (public mode; imported only by server.py)
  parse_worker.py        the worker process itself: reads a file from a pipe, analyses it, answers in JSON
  service.py             AnalysisService: document store, hex windows, byte decoder, translator,
                         disassembly and search entry points
  parser.py              entry point for parsing (parse_macho_bytes) and the Mach-O parser;
                         dispatches ELF to elf_parser.py and PE to pe_parser.py
  elf_parser.py, pe_parser.py, codesign.py, security.py
  buffer.py              BinaryBuffer (bounds-checked reads that record field positions),
                         BinaryFormatError, add_warning
  constants.py           format constants and ANALYSIS_LIMITS
  semantics.py           entropy, capabilities, provenance, anomalies (slice["semantic_layers"])
  pedagogy.py            learning annotations stored inside a document (slice["pedagogy"], field "pedagogy")
  disasm.py              listing for AArch64 and x86/x86-64 over the decoder in labs_encoding.py;
                         other architectures get no listing and an explanation
  labs_encoding.py       the instruction decoder tables and the encoding lab endpoints
  labs_patch.py          patch, experiments, ELF builder, compare, download endpoints
  learn_content.py       public interface and /api/learn/* routes for the content in backend/learn/
  learn/                 the learning content as Python data (see its __init__.py)
  fixtures.py            builds the sample binaries (local mode, only when they are missing)
static/
  index.html, app.js, styles.css     the core shell
  js/<feature>.js, css/<feature>.css learn, labs-patch, labs-encoding
  wasm/                  transport.js, engine-worker.js, sw.js, bs_wasm_glue.py, wasm.css (static build only)
static/*.html            privacy, terms, about, 404 (owner-fill placeholders); static/js/ads.js ad renderer
tools/build_static.py    builds dist/ (the static site) and serves it for testing
tools/site_pages.py      the site layer: generated learning pages under /learn/, robots.txt, sitemap.xml,
                         ads.txt, security.txt, and ads validation and CSP. Loaded by the server
                         (optional: without it there are no generated pages and ads stay off) and by the build
deploy/                  Caddyfile, nginx.conf, docker-compose.yml, binarystudio.service (untested)
tests/                   see CONTRIBUTING.md
```

Everything under `backend/` except `server.py`, `workers.py`, `parse_worker.py` and `fixtures.py` is importable inside Pyodide: standard library only, no sockets, no threads started, no subprocesses outside the local-mode code paths that are switched off by configuration. Those four files are left out of the static build's engine bundle. Process control and `resource` limits live only in `workers.py` and `parse_worker.py`.

## The Document model

Parsing a file produces one JSON-serialisable dict, the Document. It is what `/api/parse` and `/api/upload` return and what `--cli --json` prints.

```
{ "doc_id": "preset:synthetic_elf64",
  "file_info": { path, filename, file_size, sha256, md5, format, format_display, is_fat, fat_header, warnings },
  "slices": [ { slice_index, format, arch_name, slice_base_offset, slice_size, is_64, format_display,
                overview, header, load_commands, segments, memory_map, dylibs, rpaths, entry_point,
                dyld_info, symbols, dysymtab, function_starts, strings, objc_metadata, fileset_entries,
                code_signature_detail, security_posture, intervals, warnings, truncated,
                semantic_layers, pedagogy, ... } ] }
```

Points worth knowing:

- **One slice per architecture.** A universal Mach-O has one slice per `fat_arch`; every other file has one slice.
- **The schema is Mach-O shaped.** ELF and PE map onto the same keys: program headers appear under `load_commands`, the ELF and PE headers under `header` (tree id `mach_header`), program-header segments and PE sections under `segments`. Format-specific extras sit in their own keys (for example `elf_metadata`).
- **Fields carry their position.** Structures carry a `region` and a list of `fields`; each field has `name`, `type`, `abs_offset` (from the start of the file), `slice_offset`, `size`, `raw_hex`, `value`, `interpreted`, `description`, `bit_flags`, optional `target_offset` / `target_vmaddr` cross-references, and in Learn mode a `pedagogy` explanation. `BinaryBuffer.record_field` fills these as the parser reads, so values and positions come from the same read.
- **`intervals`** lists `{id, label, category, abs_offset, size, vmaddr}` for every structure; the frontend uses it to map a byte to the structures that contain it.
- **Truncation is explicit.** When an `ANALYSIS_LIMITS` cap cuts something short, the slice gets a `warnings` entry `{code, message, limit, total}` and `truncated: true`.
- **Strings are hostile.** Every name and string in a Document came from the file. Nothing that renders a Document may treat them as markup.

The service keeps the Document, its encoded JSON (so every response for it shares one buffer), that JSON as one deflate segment (so every gzip response shares one compressed buffer) and the file's bytes in a `DocEntry`; hex, decode, translate, disassembly, search and the labs work from those bytes.

## Runtime modes and configuration

`backend/runtime.py` defines three modes: `local`, `public` and `wasm`. A `RuntimeConfig` holds capabilities (`allow_path_load`, `allow_host_presets`, `allow_external_tools`, upload, patch, download), limits and header settings. In any mode other than `local`, `validate()` forces the first three capabilities and `debug_errors` off whatever overrides were passed.

Parsers and the disassembler do not take a config argument; they call `runtime.get_config()`. That returns the config the router or service has scoped to the current thread with `use_config(...)`, or the process-wide one. This is why several servers with different modes can share one process in the tests without one loosening another.

`RuntimeConfig.from_env()` reads the `ENV_VARS` table; `binary_viewer.py --help` prints the same table, and [hosting.md](hosting.md#settings-reference) lists it with defaults. Add a new setting to `RuntimeConfig.__init__` and, if it should be configurable, to `ENV_VARS`; both the help text and the validation follow.

Deadlines: `with parse_deadline(seconds):` sets a per-thread deadline (nested deadlines never extend an outer one); hot loops call `check_deadline()`, which reads the clock on every call and raises `ParseBudgetExceeded` at the first call after the deadline. Work that cannot be interrupted once started (a plist parse, a regex scan, a hash) is bounded instead by byte budgets shared by the whole analysis of one file: `work_budgets()` and `spend_budget()`.

## The request path

Over HTTP (Python server):

1. `server.py` reads the request head with an absolute deadline and a byte budget. The header block is read strictly: a line that does not end in CRLF, a folded line or whitespace around a name is a 400. It then checks, in order: `/healthz`; method; with `trust_proxy_headers`, the cap on requests in progress per forwarded client; exactly one allowed `Host`; no `Transfer-Encoding`, one valid `Content-Length`; then for `/api/` paths the cross-site check (`Sec-Fetch-Site`, and `Origin` against `Host` and against the request's scheme, which is `http` unless a trusted proxy's `X-Forwarded-Proto` says otherwise). Other paths go to the static file server, which answers with an `ETag` and honours `If-None-Match`.
2. `ApiRouter.preflight()` decides everything that can be decided before the body is read: rate limit, route and method, form-style content types, body size, the upload rate limit for routes registered with `bucket="upload"`. Only then is the body read (and `100 Continue` sent if the client asked). The body must start within a first-byte deadline and keep a minimum rate, and its memory is reserved from the in-flight upload budget as the bytes arrive.
3. `ApiRouter.handle()` first moves document ids sent as headers (`X-BS-Doc`, `X-BS-Doc-A`, `X-BS-Doc-B`, percent-encoded) into the query parameters `doc`, `a` and `b`, where handlers look for them; a header wins over the query form. It then runs the handler inside `use_config(config)` and `parse_deadline(config.parse_timeout_seconds)`. It never raises: `ApiError` subclasses become `{"error", "code"}` with their status, `ParseBudgetExceeded` becomes `422 timeout`, `ValueError` becomes `400` (with its message only in local mode), anything else becomes `500 internal` with a reference that is logged. `_finalize` adds `Cache-Control: no-store` and the API security headers, and for a `200` outside the static build negotiates the representation: an `ETag` on documents, downloads and `GET` answers of 4 KiB or more (`304` when `If-None-Match` names it) and gzip for JSON and text when the client accepts it. Afterwards the response's size is charged to the client's rate limit, one token per 256 KiB.
4. Handlers call `AnalysisService`. `get_entry(doc=..., path=...)` resolves a document id (below); a new upload goes through `add_upload`, which acquires an analysis slot (or answers `503 busy` after 2 s), analyses, checks `max_document_bytes`, and stores the `DocEntry` in the bounded LRU `DocumentStore`. Every analysis of bytes, including the patch lab's, goes through `AnalysisService._analyse`.
5. Where the analysis runs depends on whether the service has an executor. In public mode `server.py` gives it a `WorkerPool` (`service.set_executor`), and `_analyse` hands the file to a worker process over a pipe with what is left of the deadline; a worker that has not answered by then plus `parse_kill_grace_seconds` is killed and replaced, and the caller gets the same `ParseBudgetExceeded`. The answer is the document's JSON and its deflate segment, parsed as JSON and never unpickled. Without an executor (local mode, the CLI, the static build, tests that build a bare `AnalysisService`, or a pool that could not start a worker) `analyse_document` runs in the calling thread.
6. `server.py` writes the response from the shared buffers. Bodies of 256 KiB or more are counted against the in-flight response budget, in total and per client (`503 busy` past it), and a reader that accepts nothing for `response_stall_seconds` is cut off.

A background thread runs `router.housekeeping()` every 15 s (expire documents, prune rate-limit tables) and enforces the hard parse timeout, which can only be reached by an analysis running in a server thread.

## Document ids as capabilities

| Id | Meaning | Available |
|---|---|---|
| `preset:<id>` | a bundled sample; the id is looked up in a fixed list, never used as a path | all modes |
| `u_<32 hex>` | an upload; 128 random bits from `secrets` | all modes |
| `p_<32 hex>` | a document derived from another (a patched copy) | all modes |
| `path:<absolute path>` | a file on the machine | local mode only |

Holding a `u_` or `p_` id is the only way to reach its bytes: there is no listing, ids are not logged (`redact_doc_id` logs only the kind), and the frontend never puts them in a URL or in storage. `BS.api` sends a request's `doc` (and a comparison's `a` and `b`) as the headers `X-BS-Doc`, `X-BS-Doc-A` and `X-BS-Doc-B`, percent-encoded, so ids do not appear in request URLs and proxy logs; the server still accepts the query form. Unknown, expired and evicted ids all raise `DocExpired` (410), and the frontend re-uploads from the bytes it holds in memory (it does not keep file bytes in browser storage). In local mode there is also an implicit "active document" used when a call names none; it does not exist in other modes.

The store is bounded by document count, by estimated memory (the file's size plus five times its JSON size, `DOC_COST_FACTOR`), by idle time, and per client by `cache_client_share`: when one client's uploads exceed its share, its own oldest are evicted first. A derived document holds its own full copy of the bytes and is charged in full; the store never evicts its original to make room for it.

## The frontend and its extension API

`static/app.js` is the core: state, API client, tree, inspector views, hex pane, palette, history and deep links. It is plain ES2020 in one IIFE with no build step. Features live in `static/js/*.js`, loaded with `<script defer>` after `app.js`, and talk to the core only through `window.BinaryStudio` (alias `window.BS`).

The extension API is documented in the header comment of `static/app.js`; that comment is the reference and is not repeated here. It covers `BS.api` (requests, automatic `doc` and `slice_index`, error codes, transparent re-upload on `410`, `setTransport`), events (`ready`, `doc:loaded`, `view:rendered`, ...), `registerView`, `registerCommand` (palette entries and shortcuts), `BS.nav`, `BS.loadDocument` / `loadBytes` / `openPreset`, `BS.hex` (bytes, decoration layers, byte activation), `BS.ui` (toasts, modals that take a DOM node `bodyEl` or plain `text`, toolbar buttons, the `footer` slot), `BS.learn`, `BS.util` (escaping and the `html` tagged template) and `BS.storage`. It ends with the security rules for feature code.

## How the static build reuses the router

`tools/build_static.py` packs `backend/` (minus `server.py`, `fixtures.py`, `workers.py` and `parse_worker.py`), `static/wasm/bs_wasm_glue.py` and the six samples into a zip, and injects `static/wasm/transport.js` into `index.html` right after `app.js`.

In the browser:

1. `transport.js` calls `BS.api.setTransport(fn)`. From then on every request the core and the features make goes to `fn` instead of `fetch`. `/api/config` and `/api/presets` are answered at once from a manifest computed at build time; everything else is queued for the worker, one request at a time.
2. `engine-worker.js` (a module worker) loads Pyodide from the site's own origin, checks the bundle's SHA-256, unpacks it, and calls `bs_wasm_glue.init()`, which builds a `RuntimeConfig("wasm", ...)`, an `AnalysisService` and the router from `build_router`, exactly as the server does, but with no worker pool: the engine analyses in the browser's worker thread.
3. Each request becomes `bs_wasm_glue.handle(method, route, query, headers, body)`, which builds an `ApiRequest` and calls `router.handle()`. The response goes back to the page unchanged in shape.

So a new endpoint registered in `build_router` works in the static build with no change to the transport. The glue adds one thing the router cannot: a `MemoryError` becomes `507 out_of_memory` and the worker is replaced, because a WebAssembly heap never shrinks. If the worker dies or exceeds the page's watchdog, the request in flight fails with a normal error, a new worker starts, and documents come back through the `410` re-upload path.

## Extending

### Adding an endpoint

1. Write a handler that takes an `ApiRequest` and returns a dict (sent as JSON), an `ApiResponse` (`ApiResponse.binary(data, filename)` for downloads), or `None` (204). Fail by raising a type from `runtime` (`BadRequest`, `Forbidden`, `NotFound`, `TooLarge`, `ParseFailed`, `RateLimited`, `Busy`, `DocExpired`). Never put server paths or file bytes in a message.
2. Register it in `build_router` in `backend/api.py`, or in a `register_<area>_routes(router)` that `build_router` calls: `router.register("GET", "/api/thing", handler, max_body=..., bucket=...)`. A route ending in `/*` matches by prefix. The default body limit is 1 MiB; pass `max_body` to lower it.
3. Resolve documents with `doc_params(req, config)` and `service.get_entry(...)`, so path loading stays refused outside local mode.
4. Check capabilities in the handler (`config.allow_patch`, etc.) rather than assuming them.
5. Add tests: router-level ones need no socket (`router.handle(ApiRequest(...))`); add the route to the parity plan if its output should be compared between CPython and Pyodide (see `tests/test_static_build.py`).

### Adding a view

1. Create `static/js/<feature>.js` (and `static/css/<feature>.css`) and add `<script defer src="static/js/<feature>.js"></script>` and the stylesheet link at the marked FEATURE slots in `static/index.html`. The static build rewrites those references to hashed assets automatically; `tests/test_static_build.py` fails if a reference does not resolve.
2. In the script, call `BS.registerView({id: '<feature>.<name>', title, group, render})` and, if useful, `BS.registerCommand(...)`. Prefix ids with the feature name; the id becomes the deep link `#view=<id>`.
3. Follow the security rules in the `app.js` header: build DOM with `textContent` or `BS.util.html`, no inline handlers or `style=""` attributes, no requests to other origins.

### Adding a lab

A lab is a backend module plus a view. Put byte and Document logic in `backend/labs_<name>.py` with a `register_..._routes(router)` function called from `build_router`, keep the JavaScript to presentation, and never execute anything. Derived bytes go through `service.add_derived(...)` so they get a `p_` id, count against the cache and expire like uploads. Enforce size and count limits in the backend; the patch lab's constants in `backend/labs_patch.py` are the model.

### Adding learning content

Content is data in `backend/learn/`, written with the constructors in `backend/learn/dsl.py`; the format (rich text, blocks, concepts, terms, fields, comparisons, tours, locators) is documented at the top of `backend/learn_content.py`.

- **A concept** goes into `concepts_a.py`, `concepts_b.py` or `concepts_c.py`. Its module is assigned by position: `backend/learn/__init__.py` slices each file's `CONCEPTS` list into modules with fixed indexes (`_BY_MODULE`). Adding or removing a concept means adjusting those slices.
- **A glossary term** goes into `glossary.py`; its `match` strings are underlined in Learn mode.
- **A field explanation** goes into `fields.py`, keyed like `elf.ehdr.e_entry`; `pedagogy.py` attaches it to matching fields in Documents.
- **A tour** goes into `tours.py`. Questions are computed against the open file by `resolve.py`, never stored as answers.

`tests/test_learn.py` checks ids, cross-references and shape, resolves every "see it in this file" action and tour step against the samples, and compares tour answers with values read independently from the fixtures' bytes. Run it after any content change.
