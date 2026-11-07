# Trufflehog Intelligence v7.19.0 — Universal Sniffer + Product & Asset Relationships

Trufflehog is a **generic, passive, local Chrome extension** for observing network and asset-delivery evidence on websites you are authorised to inspect. It does not require recognising a CMS, DAM or photography agency. It does not bypass access controls, use credentials, brute-force URLs, or probe endpoints.

## Install on Windows

1. Extract the complete ZIP to a permanent folder (do not run the extension inside the ZIP).
2. Open the `Trufflehog-Intelligence` folder and double-click `run.bat`.
3. Choose **1** to open `chrome://extensions`; turn on **Developer mode**, then **Load unpacked** and select the folder containing `manifest.json`.
4. If replacing an older unpacked Trufflehog extension, reload that installed folder or remove/disable the older copy to avoid duplicate capture. Chrome may ask you to approve the **expanded all-sites permission**. Allow it only if you want passive automatic collection across ordinary sites.
5. In Chrome's extension **Details → Site access**, make sure access is set to **On all sites**. Chrome's own restrictions and protected browser pages still apply.

## How automatic capture works

**No Start Capture click is required.** On permitted HTTP/HTTPS websites, Trufflehog attempts to create a tab-specific session as soon as Chrome reports the main-frame navigation request. Network requests and response metadata are observed as the page loads. Once the page is ready, its visible DOM resource references can be inventoried. New origins create separate capture sessions; previously saved investigations are retained where the evidence vault is available.

All available capture switches for newly started sessions default **on**:

- Network and API observation and passive secret-pattern alerts.
- Download lifecycle observer (request/response headers and allowed field **names**, never values).
- JSON schema and asset-licensing interpretation.
- Viewer manifests and image evidence/dimension checks.
- Visual and metadata verification flags.

**Chrome limitation:** JSON response bodies, already-delivered image bytes, and DevTools-only source scans still require **F12 to be open on the inspected tab**. The extension does not use `chrome.debugger`, collect full request bodies or replay web requests. It cannot inspect a website before Chrome initiates the request, and it cannot guarantee observing every early event during worker startup. These are runtime limits, not disabled settings.

The observer **does not actively search/fetch URLs ahead of browsing**; it analyses browser-observed resources. Some optional, user-triggered modules retain their own explicit user controls. Chrome browser-internal pages, extension pages and other protected locations cannot be captured.

## Product & Asset Relationships and hybrid workflow evidence (v7.16)

In **Dashboard → Network & APIs**, open **Product & Asset Relationships** for generic, vendor-neutral interpretation of product records, variants, categories, localisation, channels, prices and explicitly referenced media. **Hybrid workflow stages** inventories browser-observed documents, API operations, file responses and download states without inventing causality or asserting a specific backend.

For response-body details, open **F12 on the website tab before the response arrives**, with JSON shapes enabled (new auto-capture sessions default on). Reload the source page and browse normally. Product/media linking only uses exact shared asset or URL references observed within that same DevTools lifetime; no missing requests are generated, and internal URLs or signed-URL values are not guessed. A matched image HTTP response does **not** verify a native-resolution master or authorised download.

Older saved captures continue to load. New PIM fields are initialised empty if absent. Under heavy sessions, PIM observations roll into the existing vault segment process alongside earlier event families. JSON/CSV views contain anonymous references and counts rather than credentials. All-site automatic capture is broad; use global pause and Chrome permissions to limit it.

## Import privacy preflight

Under **Security → Import privacy preflight**, choose a local HAR, cURL or PowerShell capture (12 MB limit) to receive a category/count warning about possible cookies, login data, signatures, account fields and request bodies. The source is scanned in memory and not modified, saved, reissued or exported. A clean result is not a guarantee that no secret exists. This protects both the original full-fidelity file and the credentials it may contain.

## Global pause / resume

Click the Trufflehog icon and untick **Automatically capture all permitted websites (global pause)**. Current recordings are stopped and archived, and no new automatic capture will be started. Tick it again to resume and inspect already-open permitted tabs. The setting persists across restarts. `Stop capture` only stops the current tab; the next normal navigation may restart it while global auto-capture is enabled.

To restrict access to specific sites, use **Chrome → Extensions → Trufflehog → Details → Site access**. Changing Chrome site-access preferences is stronger than pausing inside the extension.

## Quick local acceptance test

1. Launch `run.bat` and choose **2**. Node.js is required *only* for the local synthetic test server.
2. Open `http://127.0.0.1:4317/` (the launcher opens it for you). On a fresh page navigation, the popup should say **Automatic recording** without clicking Start.
3. Click **Run all test requests** and check Diagnostics; the recorded request count should increase.
4. For JSON/licensing evidence, open **F12 on the localhost test tab**, run the requests again, then inspect the **Asset Licensing & Delivery Intelligence** dashboard. An advertised original-size option is **not** a verified original file.
5. Check Chrome `chrome://extensions` → Trufflehog → **Errors**. Capture should not show a missing `webRequest` host permission when Chrome granted all-sites access.

## Privacy and limitations

- This update requests **`http://*/*` and `https://*/*` host permissions**, materially broader than v7.14's per-site grants. Chrome informs you about that change. Incognito sessions are not covered unless you separately allow the extension in Incognito.
- Only existing bounded, sanitized capture data is stored locally; credential, cookie, token and signing **values** are not exported. Saved network evidence may contain site names or redacted path context; keep your local evidence vault private.
- Download attribution stays conservative when multiple tabs could have initiated one download.
- A 200 response, a signed URL, or an API-advertised original size does not establish entitlement, master-file delivery, or a security vulnerability.
- Live Windows Chrome startup tests are still necessary before calling this fully production-verified.

See `RELEASE-v7.16.md` for release details. Historical v5.0 and later workflows and release notes are retained.

## Developer regression tests

Inside the extracted extension folder, run `node --test --test-concurrency=2 tests/*.cjs` (Node.js required). Independent JavaScript syntax and ZIP integrity checks are part of release packaging.


## v7.17 — Evidence integrity and runtime recovery

- **Backup/import:** recognised capture arrays now include `pimObservations`, `pimMediaObservations`, `licensingObservations`, `downloadEvents`, `frameCoverage`, and `workerScripts`. Known coverage counters are retained. Import remains a *sanitised metadata import*: raw bodies, authorization material and arbitrary unknown fields are not accepted. It is not a byte-for-byte original-file vault.
- **Product & Asset Relationships:** a shared media ID or URL pathname is now an **asset-family association**, never an exact rendition match. A **matching rendition descriptor** requires the same path plus comparable transformation parameters. Unknown query parameters prevent this stronger match. This is still not cryptographic proof of identical bytes, master resolution, purchase entitlement or an actual browser download.
- **Navigation attribution:** the MV3 worker now tracks a bounded in-memory navigation generation at request start and excludes late completions from preceding navigations. When a request-start cannot be proven (e.g. after a worker restart), only same-origin or documented-origin traffic is attributed. Some otherwise legitimate cross-origin traffic may remain unassigned rather than falsely reported.
- **Download recovery:** the browser-download observer keeps a bounded, short-lived link between Chrome's download ID and the local anonymous download reference in `chrome.storage.session`. This survives ordinary service-worker suspension, not a complete browser restart. It clears the reference on complete/interrupted observations. It does not store signed download URLs or credentials in the checkpoint.
- **Windows validation:** run `run.bat`, open the local fixture, keep DevTools open before running the tests if you need JSON-response interpretation, then check the dashboard. This extension still requests broad HTTP/HTTPS site access. Use the popup to pause capture, and Chrome settings to restrict access.

**Remaining:** real Windows Chrome acceptance, archive/storage throughput under long high-traffic sessions, encrypted full-fidelity evidence storage with deliberate opt-in, and simplified dashboard navigation.


## v7.18 — Passive Security Intelligence (first implementation)

Open **Dashboard → Security → Security Intelligence** while visiting an authorised, permitted site. The new generic engine evaluates metadata the browser already observed and records **review indicators** (not confirmed vulnerabilities) for:

- credential- or session-like URL parameter names, without storing values;
- AWS/GCS/Azure-style signed-link markers and *declared* duration classes where observable;
- suspicious cross-origin `Referer` and authentication-code redirects, where corresponding headers/events are browser-visible;
- wildcard/credentialed and null-origin CORS policy combinations, without asserting browser bypass;
- sensitive POST/PUT/PATCH/DELETE endpoint shapes and a fixed vocabulary of form **field names only**;
- session-like cookie attribute problems where the `Set-Cookie` header is available.

The **Offline HAR security review** control reads a user-selected HAR locally (maximum 12 MB and the first 3,000 entries), displays classified counts, and allows a safe JSON export. It examines credential-named headers, redirect query names and embedded textual request/response bodies in bounded memory. Neither raw HAR traffic, query values, credential-bearing headers, POST contents nor response bodies are persisted. Existing JavaScript secret indicators and import privacy preflight remain separate.

**Important limits:** Passive observation cannot validate authorization, BOLA/IDOR, SSRF, CSRF, code execution, token privileges, file access, payment entitlement, or exploitation of any CVE. CORS wildcard with credentials is normally *blocked by browsers*, rather than a proven data exposure. Allowlisted SSO redirects and publishable API keys can be legitimate. Chrome may not expose `Referer`, `Cookie`, or `Set-Cookie` to `webRequest` without the optional `extraHeaders` mode; this release does **not** enable that costly permission mode globally. The security engine requires the same permitted HTTP(S) site capture as the existing extension. No active probes, payloads, bypasses, replays or automatic credential tests are added.

To test, use `run.bat` option 2 and the local synthetic fixture. It adds harmless CORS, URL marker and form-field requests; examine **Security Intelligence** after clicking Run all test requests. For offline review, select `tests/security-intelligence-synthetic.har`. The synthetic fixtures use `.invalid` domains and non-working placeholder tokens.

**Not yet included:** encrypted raw evidence vault, component/version-to-CVE matching, response bodies unavailable to the existing DevTools inspector, full `extraHeaders` coverage, authentication anomaly aggregation, and real Windows Chrome acceptance. These require separate implementation and testing.

## v7.20 — Passive secret-exposure coverage (NEW)

The existing opt-in DevTools inspector now recognises additional credential formats in already-loaded JavaScript, HTML, JSON and textual API responses. The web-request layer records only credential header names and redirect/query classifications. Local HAR review can derive redacted findings from embedded textual request and response bodies, including API, GraphQL and telemetry payloads. None of these paths replay requests, validate credentials, fetch unobserved resources or retain matched values/source excerpts. See `RELEASE-v7.20.md` for exact limits and validation instructions.

Source references: OWASP API Top 10 and REST/Logging cheat sheets, Chrome `webRequest` and storage documentation, and cloud providers' signed URL guidance. See `RELEASE-v7.18.md` for links and scope.


## v7.19 — Durable incremental live capture (NEW)

**Storage model:** For browsers exposing standard IndexedDB APIs, the background
service worker now commits a compact *delta* transaction for each changed capture
record. Unchanged updates are not written. Every 96 committed deltas, the journal
atomically stores a full checkpoint and discards prior deltas. Every 48 changes,
a backwards-compatible `chrome.storage.local` checkpoint is updated; that mirror
is **not authoritative**. The journal is authoritative during live recording,
including after a Manifest V3 service-worker suspension.

When upgrading from a pre-v7.19 build, the existing `record:<tab>` local record
remains readable. The journal migrates a record on its next write; opening a new
capture initializes a fresh journal checkpoint. Archived session data remains in
the existing **TrufflehogEvidenceVault** database, unaffected by this migration.

**Find it:** Dashboard → Capture diagnostics. The new fields show journal mode,
checkpoint revision, uncompacted transactions, a browser-wide storage estimate
when available, and responses deliberately left unattributed. The unattributed
counts are **only since the current background worker started**; zero does not
establish complete traffic coverage. Storage estimates are browser-provided,
not a promise of remaining capacity for the extension.

**Important limitations:** This release still assembles complete in-memory records
for analysis and the UI. It reduces full-record writes but is not yet an
out-of-core streaming system. High-load benchmarks of 100,000+ events across many
tabs and actual Chrome storage-quota exhaustion have not been completed. No live
Windows Chrome acceptance was performed in this environment. If IndexedDB is
unavailable, isolated/legacy test environments retain the old local-record
behaviour; Chrome with IndexedDB errors reports a storage error instead of
quietly returning an obsolete mirror. Archive and local-mirror failures need
manual attention as indicated by the extension.

**Verification:** Run `node --test --test-concurrency=2 tests/*.cjs` in the
extracted folder. Tests include simulated journal checkpoints, worker restarts,
redaction and archive recovery. This synthetic IndexedDB model is not a
substitute for a real browser acceptance run.
