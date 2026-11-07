# Trufflehog Intelligence v7.1 — Offline DAM Stage Timeline

**24 October 2026 · Chrome MV3 · local-only file analysis · no additional browser permissions**

## New functionality

**Overview → Independent HAR coverage** now includes a third local step: **3. Reconstruct observed stage sequence (offline)**, available after an explicit HAR privacy preflight even with **no saved Trufflehog investigation**. The existing HAR reconciliation becomes step 4.

The timeline inspects the selected HAR (up to **12 MB**, **12,000 entries**) and presents at most **240 classified stage events**, with total and suppressed counts so truncation is visible. It detects (as observable indications only):

- POST/PUT export-preparation request **path clues** and GET job/status **path clues**.
- Attachment `Content-Disposition` headers, redirects, 401/403 denials, 206 responses, image/media MIME and JSON API response types.
- S3 presigned/multipart form **field-name** and generic resumable-upload **header-name/query-name** indicators.
- Recognised service-host **categories**, HTTP method and status **classes**.
- Relative time **bands** measured from the first valid HAR timestamp; original timestamps are never output.
- Possible ordered **export → status → attachment** patterns within 40 HAR entries, carefully labelled as proximity-only clues rather than proven causality.

## Privacy and interpretation

The new report has only hard-coded text labels and bounded numeric values. It does **not** contain HAR-supplied URLs, domains, paths, query strings/values, filenames, local paths, auth tokens, cookies, AWS signing data, headers, request IDs, trace IDs, response body bytes, exact timestamps or arbitrary strings. Only reports in the new **offline stage timeline** and its JSON/CSV exports have this strict fixed-label guarantee; earlier Evidence Vault export formats have different retention designs.

All original HAR data is examined **locally and transiently**, without any extension-initiated site requests. A preflight warning count of zero does **not** make the original HAR safe to share. Never share the raw HAR or actual downloaded files unless you have separately reviewed them and have permission.

**Limits:** HAR entry order may differ from actual event timing; relative time bands are a coarse display only. Sequences do not prove the same asset, a successful download, permission/access level, authenticated master entitlement, or that a POST caused a later attachment. The browser may omit requests/responses. The first 240 relevant events are displayed, and excluded count is disclosed; this is not a complete chronology for large captures.

## Use on Windows

1. Back up your Evidence Vault records. Extract v7.1 **over the same unpacked extension directory**, then click **Reload** at `chrome://extensions` (uninstalling first may lose local data).
2. Open **Overview → Independent HAR coverage**.
3. Choose a local `.har` / `.json` HAR file (maximum 12 MB). Prefer Chrome's sanitised HAR export and keep the original private.
4. Click **1. Inspect HAR privacy locally**.
5. Optional: click **2. Analyse DAM workflow (offline)** for vendor/service/stage **counts**.
6. Click **3. Reconstruct observed stage sequence (offline)** to inspect ordered categorical evidence and two adjacency-pattern counts. Export **redacted JSON** or **redacted CSV** only if needed.
7. Optional: with a saved capture group, click **4. Reconcile reviewed HAR with capture** to compare capture coverage.

A changed HAR selection requires another local privacy preflight before stage analysis or reconciliation.

## Test commands

```bat
node tests\test_v71_har_sequence.cjs
node tests\test_v71_wiring.cjs
node tests\v71_har_sequence_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

Fixture: `tests/v71-stage-timeline.har` (entirely fictional hosts, synthetic metadata and dummy signing placeholders). Synthetic event payloads are never used as live HTTP requests.

**Verification performed:** 121 of 121 Node.js suites passed, 66 top-level JavaScript files passed syntax checks, offline demo passed, ZIP integrity and MV3 manifest checked. **Real installed-Chrome interaction, UI, DevTools and IndexedDB workflow are still not verified** in this container: test on Windows before treating it as production-ready.

No protected files are retrieved, no signing keys tested, no private endpoints scanned and no remote requests replayed.
