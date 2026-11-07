# Trufflehog Intelligence v6.0 — Deterministic Local Capture Benchmark

**24 October 2026 · Chrome Manifest V3 · no additional browser permissions**

## Why this release exists

Across v5.0–v5.9, the individual modules passed Node.js tests but the complete installed extension + Chrome DevTools + IndexedDB capture path could not be verified in the development environment (Chromium timed out on `about:blank`). v6.0 provides a **deterministic loopback-only fixture** and a dedicated dashboard report showing which expected, harmless network events Chrome actually captured. It does not claim to have passed the Windows installed-Chrome test for you.

## New overview screen: Local capture benchmark

The **Overview → Local capture benchmark** section compares the current live/saved session against these specific synthetic steps:

1. HTML document delivered (`200`)
2. JavaScript resource delivered (`200`)
3. Stylesheet delivered (`200`)
4. JSON fetch delivered (`200`)
5. SVG image delivered (`200`)
6. POST export-job request completed (`202`)
7. Job-status fetch delivered (`200`)
8. Attachment response delivered (`200` with attachment disposition)
9. A known fixture resource was actually inspected by the DevTools response-body scanner (matching SHA-256 digest recorded)
10. The opt-in Download Observer recorded a POST initiation stage for the local site
11. Capture retention reported no local record drops in the active segment

Each item has **pass**, **warn**, or **not-tested** status. The assessment is `not-run` when a qualifying localhost fixture was not observed; this is not interpreted as success. The browser's download-completion event, stored-session readback and Windows notification visibility still have separate limits/checks (existing Capture acceptance view).

## Run the actual fixture on Windows

1. Back up important Evidence Vault investigations (older full backups may contain sensitive data). Keep the *same unpacked extension directory* to preserve extension identity and existing site storage.
2. Extract v6.0 files over your current unpacked folder. In Chrome open `chrome://extensions` and click **Reload** on Trufflehog Intelligence.
3. Open Command Prompt inside the extension folder and run:

   ```bat
   py tests\v60_benchmark.py
   ```

4. Open **http://127.0.0.1:8770/v60-lab.html** in Chrome. Grant the extension permission for this local origin only.
5. **Start capture** for this tab; **enable Download Observer**.
6. Open DevTools (F12) *on the fixture tab* before reloading. Reload the fixture to trigger HTML/CSS/JS/JSON/SVG requests while the scanner is active.
7. Select **Run synthetic export**. It creates a harmless local POST, status request, redirect and attachment file with no media and no credentials.
8. Open the Trufflehog dashboard with the **fixture tab selected**. Choose **Overview → Local capture benchmark**, then **Refresh evidence**. Review any warnings and export the redacted JSON benchmark.
9. **Stop capture**, open **Overview → Capture acceptance**, and verify the saved Evidence Vault session was read back. Manually test desktop notification visibility separately.
10. Stop the Python fixture server with Ctrl+C. All fixture traffic stays on `127.0.0.1:8770`; the server does not contact external services.

## Privacy and security

- The evaluator runs locally on the browser's already-saved observations and **makes no network requests**.
- It refuses to evaluate other sites: the origin must be the loopback hostname `127.0.0.1` or `localhost`, using HTTP port `8770`.
- Exported results consist of **fixed safe labels, statuses and bounded counts**. They contain no request/response bodies, raw URLs, query parameters, POST values, credentials, tokens, identifiers, signature headers, local filenames or downloaded file bytes.
- No credential testing, bypasses, undocumented endpoint probes or third-party DAM access is introduced.
- A 200 attachment response is not proof that Chrome associated a `DownloadItem` with the preceding POST. A passing local fixture cannot guarantee complete capture on other sites.

## Developer verification

From the extracted extension root:

```bat
node tests\test_v60_benchmark.cjs
node tests\test_v60_wiring.cjs
for %f in (tests\test*.cjs) do @node "%f"
node --check dashboard.js
```

For this packaged build, **99 Node.js suites passed**, **55 top-level JavaScript files passed syntax checks**, and the Python localhost fixture passed HTTP functional checks for the full synthetic flow and oversized POST rejection. ZIP integrity and manifest were checked before distribution.

**Not yet verified:** the complete installed-Chrome workflow and Windows notification display. Those require performing the steps above on the user's installed Chrome. The test outcomes only establish what was run in this development environment.

All v5.9 functionality is retained, including DAM specialist profiles, case dossier and encrypted dossier export, case-change comparison, Evidence Vault, authenticated download observation, upload protocol intelligence, CDN image-quality tools, redacted secret alerts and browser permissions.
