# Monetisation

BinaryStudio has an optional advertising mechanism. It is off by default and nothing in the repository turns it on. This page explains the placement policy and why, how the mechanism works, how to enable each provider, what each one does to the Content-Security-Policy, and what needs legal review.

The mechanism lives in `tools/site_pages.py` (validation, CSP, generated pages) and `static/js/ads.js` (rendering). This page was checked against both on 2026-11-11; the module docstring of `tools/site_pages.py` is the reference for the configuration format.

## The placement policy, and why

**No third-party code ever runs in the origin that serves the tool.** No provider `<script>` is loaded by any page; providers are rendered by BinaryStudio's own `static/js/ads.js` as inert DOM (text, a link with `rel="sponsored noopener"`, an image), or placed in a sandboxed cross-origin iframe.

The reason is what the tool's origin holds:

- **Users' binaries.** In the static build, every file a visitor opens is in that tab's memory and the engine answers any script in the page. On the Python server an upload's id is the capability to read it, and the page holds it. Any script in the page can read both.
- **The CSP is the safety net against hostile files.** Names and strings from binaries are rendered into the page. `script-src 'self'` and `connect-src 'self'` mean that even a rendering bug cannot load code or send data elsewhere. Conventional ad networks need their script in the page and broad `script-src` / `connect-src`, which would remove that net for every visitor. They are therefore not offered.

**Ads go on content pages by default, not in the workspace.** The generated learning articles, glossary, comparison and field reference pages never hold a user's file. The in-app footer strip is a separate, explicit opt-in (`slots.footer`), and the docs recommend against using it with a provider that needs network access (see the CSP table below).

## How it works

Configuration is one JSON object, the `ads` part of `GET /api/config`:

```json
{"enabled": true,
 "provider": "house" | "ethicalads" | "frame",
 "slots": {"content": {"height": 150}, "footer": {"height": 90}},
 "options": {...}}
```

- **Python server:** `BINARYSTUDIO_ADS='<json>'`. The server validates it at start-up through `tools/site_pages.py` (`normalize_ads`) and refuses to start on an invalid value. If `tools/site_pages.py` is not installed next to the server, ads are forced off and a `ads_disabled` warning is logged.
- **Static build:** `python3 tools/build_static.py --ads '<json>'` (or `--ads @file.json`, or `BINARYSTUDIO_ADS`). The validated object is built into the app's `/api/config` answer and into the generated pages.

`slots` names where ads may appear: `content` (the generated content pages; the default when `slots` is omitted) and/or `footer` (a strip under the app's status bar). Heights are integers from 60 to 250 pixels (defaults 150 and 90), rounded to tens; the space is reserved before anything loads so the layout does not move, and the slot collapses to nothing when the ad is blocked, refused, fails or is unfilled (6 s timeout).

Common `options`: `label` (`Advertisement`, `Sponsored`, `Sponsor` or `Ad`; default `Advertisement`), `respect_dnt` (default true: no network request when Do Not Track or Global Privacy Control is on), `consent` (default false, true for `frame`: show a prompt and load nothing until the visitor answers; the answer is kept in local storage as `binarystudio:ads.consent`, and "Ads: change ad choice" in the palette or a footer button resets it), `consent_text`, and `ads_txt` (lines published as `/ads.txt`).

`static/js/ads.js` is only fetched by the app when `ads.enabled` and `slots.footer` are both set, and only included in content pages when a provider other than `house` is enabled for `content`.

## Providers

| Provider | What happens | Extra CSP |
|---|---|---|
| `house` | Units written in the configuration (`options.units`: 1 to 20 of `{title, text, url, image?, image_alt?, image_width?, image_height?, sponsor?}`), rendered as text, link and optional image. On content pages they are written into the HTML at generation time, with no script at all. | `img-src` for the origin of any image hosted elsewhere; none otherwise |
| `ethicalads` | `ads.js` fetches one ad decision as JSON from EthicalAds' API and renders it as text, link and image; their script is never loaded. A view is counted with their view pixel once half the unit is on screen. Options: `publisher` (required), `ad_type` (`image` or `text`), `keywords`, `campaign_types`, `api`, `media`. | `connect-src https://server.ethicalads.io`; `img-src https://server.ethicalads.io https://media.ethicalads.io` |
| `frame` | A sandboxed iframe of `options.src`, which must be https on another origin than the site (the build refuses the site's own origin when `--site-url` is given). Sandbox: `allow-scripts allow-popups allow-popups-to-escape-sandbox`, never `allow-same-origin`, so the frame has an opaque origin and cannot reach the page, its storage or the API. Use it for a network or sponsor tag you host on a separate domain. Consent is on by default. | `frame-src <origin of src>` |

The extra sources are added to the CSP of **content pages** only, unless `slots.footer` is configured, in which case they are added to the **app shell's** CSP as well. `python3 tools/site_pages.py --csp --ads '<json>'` prints both policies for a configuration; the table above was produced that way.

Note what this means for the app: `frame` and `house` add nothing that lets a script in the app send data elsewhere. `ethicalads` in the `footer` slot adds `connect-src https://server.ethicalads.io` to the app shell, so the tool's own origin may then send requests to a third party. That does not run their code, but it weakens the safety net described above. Prefer `content` placement.

## Enabling each provider

These commands were run on 2026-11-09 with the server listening locally; they started, `/api/config` reported the normalised object, and the CSPs were as stated. On 2026-11-11 the CSPs in the table above were printed again with `tools/site_pages.py --csp`; the servers were not started again. The examples are for a local try over plain HTTP: a real deployment behind a TLS proxy also needs `--trust-proxy` (see the [hosting guide](hosting.md#what-the-reverse-proxy-must-do)).

House ads on content pages, Python server:

```sh
BINARYSTUDIO_ADS='{"enabled":true,"provider":"house","options":{"units":[{"title":"Our book","text":"A short read","url":"/about.html"}]}}' \
python3 binary_viewer.py --public --allowed-host binarystudio.example.com
```

A framed ad on content pages (consent prompt on by default):

```sh
BINARYSTUDIO_ADS='{"enabled":true,"provider":"frame","slots":{"content":{"height":150}},"options":{"src":"https://ads.example.net/slot.html"}}' \
python3 binary_viewer.py --public --allowed-host binarystudio.example.com
```

With this configuration `/learn/` was served with `frame-src https://ads.example.net` and `/` (the app) without it.

EthicalAds in the static build:

```sh
python3 tools/build_static.py --out dist/ --site-url https://binarystudio.example \
  --ads '{"enabled":true,"provider":"ethicalads","options":{"publisher":"<your publisher id>"}}'
```

The `frame` variant of this build was run; the `ethicalads` build command was only checked through `tools/site_pages.py --csp`. No provider has been tested against a live ad service: no EthicalAds account was used and no real ad was ever loaded.

**Static hosts and the two policies.** When content pages need a wider CSP than the app, `dist/_headers` sends the content policy on `/*` and repeats the app policy on the app's own paths (`/`, `/index.html`, `/sw.js`, `/assets/*`). Cloudflare Pages joins the two headers with a comma, and a browser then enforces both, whose intersection is the app policy. A host that keeps only one of them would give the app the wider content policy; `index.html` also carries the app policy in a `<meta>` tag, which still holds the app document to it. How Netlify or other hosts treat the duplicate has not been checked.

Checks before going live with any provider:

- [ ] `python3 tools/site_pages.py --csp --ads ...` shows no change to the app shell's `script-src`, and no change to its `connect-src` unless you accept the footer trade-off above.
- [ ] In the browser's network panel, opening and analysing a file causes no request to the provider from the app.
- [ ] With Global Privacy Control on, no request to the provider happens at all.
- [ ] With `consent` on, nothing loads until the visitor agrees, and "change ad choice" works.

## What needs legal review

This is a list of questions, not advice.

- **Consent.** The `frame` provider asks for consent by default; the others do not. Whether a prompt is needed for EthicalAds' decision request and view pixel, and whether the prompt's wording (`consent_text`, or the default sentence in `ads.js`) is adequate in your jurisdictions, needs review. The prompt is per site and per provider, stored in local storage.
- **The privacy policy.** `static/privacy.html` has placeholders for the ad network and its policy, the operator, the hosting provider, log retention and more (listed in the final section of this page). It must name the provider and describe what it receives (at least the visitor's IP address and the page).
- **Terms.** `static/terms.html` contains `[LIMITATION OF LIABILITY CLAUSE: TO BE WRITTEN OR APPROVED BY A LAWYER FOR YOUR JURISDICTION]` and a jurisdiction placeholder.
- **Minors.** Learning content may attract students, some under 18; targeting rules for minors may apply.
- **Provider terms.** Some providers forbid rendering their ads without their script, or forbid iframing. If a provider's terms conflict with the placement policy, the answer is not to use that provider.
- **Statements on the site.** "Files never leave your browser" and similar copy must stay true with ads enabled; check it in the network panel.

## Placeholders in the site pages

`static/privacy.html`, `static/terms.html` and `static/about.html` contain these markers (rendered highlighted) for the operator to fill: `[OPERATOR NAME]`, `[CONTACT EMAIL]`, `[DATE]`, `[JURISDICTION]`, `[HOSTING PROVIDER / WHO STORES LOGS]`, `[PROXY OR CDN, AND WHAT IT LOGS]`, `[LOG RETENTION PERIOD]`, `[30 MINUTES, OR THE VALUE OF BINARYSTUDIO_DOC_TTL]`, `[OFF / ON: NAME THE PROVIDER]`, `[NETWORK AND LINK TO ITS POLICY]`, `[SECURITY CONTACT, ALSO IN /.well-known/security.txt]`, `[SOURCE REPOSITORY URL]`, `[LICENCE NAME AND LINK]`, and the limitation-of-liability clause above. Find them with `grep -n 'class="fill"' static/*.html`.

## Appendix: ideas not implemented

Recorded from an earlier planning document (removed; see `git log`). None of this exists and nothing here is planned work.

- Shareable links that include an uploaded file, which would require storing files or analysis results server-side.
- A gallery of annotated specimen binaries (smallest valid ELF, tiny PE, packed vs unpacked).
- A CI check that fails a build when hardening regresses between two versions, built on the structural diff the compare lab already computes.
- Exportable reports (JSON, SARIF) of the hardening checklist.
