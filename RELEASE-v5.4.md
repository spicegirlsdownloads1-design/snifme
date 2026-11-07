# Trufflehog Intelligence 5.4.0 — Workflow Intelligence

## Scope

An offline correlation and coverage layer over already-redacted, opted-in HTTP/download observations. No extra network requests, request replay, credential testing, private file retrieval, background polling or cross-site capture.

## New

- **Network & APIs → Download workflows** reconstructs HTTP lifecycles grouped internally by the actual browser request ID, without exporting that ID.
- Candidate download/export POSTs are associated with later observed GETs and attachment evidence. A `202 Accepted` followed by plausible same-host GET activity is labelled **possible async export**, not a verified job.
- Associations are graded by shared session-local trace labels, redirect-host clues, same-host timing, or unambiguous download referrer/timing. None proves cross-request causality.
- Ambiguous downloads remain standalone rather than being attributed to an arbitrary POST.
- Download starts and completion events have per-capture generated `DL...` labels. Chrome's raw download IDs, paths and filenames are never stored. Labels can become unpaired after an MV3 worker restart.
- **Overview → Workflow coverage** reports starts without completions, completions without starts, unpaired downloads, dropped events, DevTools coverage and past observer opt-in state. Older saved sessions may have no opt-in marker.
- Sanitised offline JSON export combines the workflow and coverage reports.
- Includes local `tests/workflow_lab.py` demonstration of synthetic POST→202→status GET→download.

## Windows test

1. Export your current Evidence Vault investigations before updating.
2. Extract the ZIP and copy the entire `Trufflehog-Intelligence` folder contents into the existing unpacked extension directory; reload at `chrome://extensions`.
3. Open Command Prompt in the unpacked extension directory and run `py tests\workflow_lab.py`.
4. Open `http://127.0.0.1:8767/` in Chrome, grant site access, start capture, then enable Download observer **before** interacting with the fixture. DevTools is optional for this test.
5. Click **Prepare synthetic export**, then **Download harmless ZIP**. Open **Download workflows** and **Workflow coverage**.
6. Test an ambiguous case by clicking **Prepare** twice before downloading; it should not assert a unique POST→download link.
7. Stop capture and use the Evidence Vault saved-session view to review the archived events.

## Evidence and limitations

Chrome download events have no reliable initiating tab ID, and the MV3 service worker may restart. Existing referrer-origin correlation requires exactly one opted-in capture. Separate requests are at most correlations, not proof they share server-side jobs. The sample lab uses local dummy values; it does not test real signing or any private DAM.

Automated Node.js tests and syntax checks cannot establish that the extension starts and operates correctly in a full installed Windows Chrome. The full Chrome acceptance test remains outstanding.
