# v7.15.0 — Automatic Generic Capture

- Declared required Chrome host permissions for normal HTTP and HTTPS sites; **the user must approve the expanded all-sites access in Chrome**.
- New navigation-time passive capture bootstrap using `chrome.webRequest.onBeforeRequest`, with per-tab serialization to avoid duplicate starts and to keep early response metadata.
- Every new capture and active captures upgraded from older releases enable existing response schema, image/visual/metadata, viewer-manifest, secret and download observation flags. DevTools is still needed for inspected response body/image bytes and will not open itself.
- Cross-origin navigation starts a new session instead of joining two sites; older sessions are archived using the existing evidence vault.
- Added a global automatic-capture pause/resume switch in the popup. A pause stops ongoing capture and prevents new automatic sessions.
- New installations default alert preferences on without overriding an existing user's explicit off choice.
- Preserved generic analysis, local processing, masked/redacted reports, no debugger permission, no request replay, no privileged endpoint guessing and no watermark alteration.
- Added `tests/test_v715_auto_all_sites.cjs`; updated historical version/permission expectations affected by the intentional opt-in-to-all-sites change.

**Limits:** Chrome only supplies navigation requests once they start, and DevTools-only inspection requires the DevTools window. All-sites host permission requires a browser-granted access setting. Unpacked Chrome extension live Windows acceptance remains pending.
