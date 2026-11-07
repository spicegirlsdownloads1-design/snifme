# Trufflehog Intelligence v5.0 — Capture Acceptance

## Scope

This release adds a **Capture acceptance** diagnostic in Overview and a popup shortcut. It verifies pieces of the real capture-to-report pipeline using already recorded local evidence and Chrome's runtime state. No third-party URL probing, extra content fetching or credential validation is introduced.

### Reported stages

- Extension background response.
- Current tab's site permission and capture state.
- Content-inspector handshake from the selected authorised page.
- Recorded network metadata count.
- DevTools resource-scanner completeness, separated from whole-page coverage.
- Current record's dropped-event counters.
- IndexedDB readback of a completed saved session (after stopping capture).
- Masked findings count, *not* raw strings.
- Windows notification visibility explicitly marked **Not tested** until checked by the person using Chrome.

Each stage is `pass`, `warn` or `not-tested`. The report's overall classification is `needs-review`, `incomplete`, or `observed-tests-pass` (the latter is only possible if all stages were affirmatively verified). A network response recorded by DevTools does not prove the entire website was scanned, and a user-visible notification cannot be verified from the extension API alone.

### How to exercise the installed extension on Windows

1. In `chrome://extensions`, load or reload the unpacked `Trufflehog-Intelligence` directory. Keep its existing directory when upgrading to retain local extension storage.
2. Open Command Prompt **inside the unpacked extension directory** and run `py tests\windows_acceptance_lab.py` (use `python` instead of `py` if needed).
3. In Chrome, visit `http://127.0.0.1:8765/acceptance-lab.html`. The server binds only to 127.0.0.1, with no external services, external requests or real credentials.
4. Click the extension icon, grant access to this localhost site, and start capture.
5. Open **DevTools on the local page**, not on the Trufflehog dashboard. Reload the lab page; the HTML, stylesheet, JavaScript and JSON should be observed. Click **Add synthetic asset**.
6. Open **Overview → Capture acceptance**. Use **Re-run acceptance checks**. The content inspector and request stages should pass if the connection is working. Resource scanning should show its actual status; no full-site guarantee is implied.
7. Stop capture and re-run the acceptance check to verify IndexedDB saved-session readback. Close and reopen Chrome to test persistence separately.
8. Use **Send test notification** in the popup and visually confirm the Windows desktop banner; the acceptance report intentionally does not mark this step as a programmatic pass.
9. Export the **acceptance JSON** and check for unexpected `warn` and `not-tested` classifications. You may copy the report for troubleshooting; it contains counts and classifications only.

### Safety and limitations

- The diagnostic action is callable **only from the extension UI**, never a page script.
- It does not fetch images, scan arbitrary URLs, validate secrets or attempt protected downloads.
- Reports exclude file contents, source URLs, matched strings, session IDs, cookies and token-bearing headers.
- DevTools must be open in time for the browser to expose response content. Files loaded before it opens can be missed.
- Unit and isolated worker tests do **not** certify installed-Chrome behaviour.
- Do not clear the extension or reinstall under a different unpacked path without backing up the Evidence Vault first.

## Verification summary

Automated Node.js test suites, syntax checks, and ZIP integrity are run as part of packaging. Full installed Chrome + Windows desktop notification behaviour must be verified on the user's Windows machine. Chromium has timed out in this container on `about:blank` even with no extension loaded in previous attempts.
