# Trufflehog Intelligence v6.1 — Capture Repair & Evidence Readiness

**24 October 2026 | Chrome Manifest V3 | no additional permissions**

## Why this release

v6.0 introduced a deterministic localhost benchmark and reported captured evidence stages, but left users to interpret which Chrome settings or timing issues might have caused a missing stage. v6.1 introduces a new **Overview → Capture repair guide** to turn those existing observations into ranked, safe troubleshooting instructions, without collecting additional network data.

## Features

- Uses the **Capture acceptance** report, where available, and existing v6.0 **Local capture benchmark** evidence.
- Explains **Not tested**, **Needs review**, and **observed stages passed with limits** separately. An unrun fixture does not get treated as a failed capture.
- Prioritises fixes for: exact-origin host permission, capture activation, content-inspector response, network metadata, DevTools response-body scanning, Download Observer POST evidence, final attachment response, dropped records and Evidence Vault readback.
- Lists manual Windows notification validation separately. The Chrome notifications API cannot prove a Windows desktop banner appeared.
- Displays a **fixed-text step-by-step repair plan** for each diagnostic; export a privacy-safe JSON copy.
- No live network requests, page reloads, permission changes, credential validation, raw trace IDs, signature values, upload bodies, endpoints or file paths are performed by the guide.

### Important distinctions

The report is **not proof of the root cause**. A missing resource may be due to Chrome caching, the user not triggering a fixture action, missing permission, a stale DevTools session or other causes. A successful local benchmark is not proof of completeness on third-party DAM websites. The extension has not passed a complete installed Chrome acceptance run in this build environment.

## Windows installation

1. Back up any existing investigation data, including the Evidence Vault. Older full vault backups may contain sensitive artifacts.
2. Extract the v6.1 ZIP into the same unpacked extension directory, overwriting the previous files. Keep the extension's identity to preserve local storage.
3. Select **Reload** at `chrome://extensions`.
4. Run the existing v6.0 local fixture: `py tests\v60_benchmark.py`.
5. Open `http://127.0.0.1:8770/v60-lab.html`, grant site access, start capture and enable Download Observer.
6. Open DevTools (F12) **on the fixture tab**, reload it, select **Run synthetic export** and wait for the browser's normal response.
7. Open **Overview → Capture repair guide**, choose **Re-run diagnostics**, and review the action list. You can also review the underlying **Local capture benchmark** and **Capture acceptance** screens.
8. Stop capture, check saved Evidence Vault readback, and manually verify any Windows notification test.
9. Export the redacted capture-repair report if you need help diagnosing a failure.

Fixture traffic stays on loopback only (port 8770). Do not run the fixture against live agency websites.

## Build verification

101 Node.js suites passed, 56 top-level JavaScript files passed syntax checks, and the preserved Python localhost fixture compiled successfully. ZIP integrity and the manifest were checked. Live Chrome extension/DevTools/Windows notification integration is still unverified.

## Testing

From the unpacked extension directory on Windows:

```bat
node tests\test_v61_capture_repair.cjs
node tests\test_v61_wiring.cjs
for %f in (tests\test*.cjs) do @node "%f"
node --check dashboard.js
```

All v6.0 capabilities are preserved (DAM specialists, investigation dossier/encrypted dossier export, cross-capture case review, local fixture, automated masked findings, download observation, AWS upload patterns, rendition quality analysis and Evidence Vault). **Installed-Chrome end-to-end operation remains unverified** until the user runs the lab on their PC.
