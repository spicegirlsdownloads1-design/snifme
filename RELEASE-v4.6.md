# Trufflehog Intelligence v4.6.0 — Secret Change & Alert Intelligence

**Local, passive Chrome Manifest V3 investigation extension.** Builds on v4.5. All existing DAM/CMS detection, image/CDN analysis, Evidence Vault, offline HAR/file inspector, scan coverage, site-permission controls and masked secret notifications are retained.

## What's new

- **Locally keyed HMAC-SHA-256 fingerprints:** When Chrome DevTools sees a pattern-matching candidate in a previously delivered text response, Trufflehog can compute a keyed fingerprint in the extension's DevTools context. The original candidate is never sent to the background worker, written to storage or included in exports.
- **Same-origin comparison:** The HMAC input is scoped by source origin and finding type, reducing unintentional cross-site correlation. The installation-specific 256-bit random key stays in trusted extension storage, is not included in Evidence Vault backups and is never sent to a website. The public 16-hex-digit key ID detects key changes without exporting the key itself.
- **Four evidence states:** `new`, `unchanged`, `changed` and `unverified`. `changed` requires two fingerprints created using the same local key at the same resource/offset/type; `unverified` means no comparable fingerprint exists. No state is proof a credential is active or exploitable.
- **Changed-indicator notifications:** Changes can raise the familiar red badge and Chrome desktop notice. In **Security → Exposure history**, switch *Changed-secret notifications* off without disabling newly observed potential-secret alerts or the finding records. The master secret-notification setting remains independent.
- **Review audit trail:** Mark a finding New / Reviewing / False positive / Resolved. A bounded local history records status transitions and timestamps (no free-text notes or source content).
- **Exposure history:** Inspect saved masked findings for the currently selected site, including observations across archived capture segments. This is strictly offline and has JSON/CSV export of redacted metadata.

## Install on Windows (Chrome)

1. Back up existing Evidence Vault data, capture-group backups and custom DAM profiles. The per-installation HMAC key is intentionally **not** contained in these exports.
2. Extract the ZIP. Copy the **contents of `Trufflehog-Intelligence`** into your existing unpacked extension folder (retaining its path) and reload at `chrome://extensions`.
3. Open a permitted website and click **Grant site access & start capture**. Open its DevTools (`F12`) **before** the JavaScript or other text response loads, then reload the website.
4. Under **Security → Masked indicators**, check the `Value evidence` classification and review-state dropdown. Under **Security → Exposure history**, refresh archived observations and adjust changed-indicator desktop notifications.
5. For a local-only test, import `tests/offline-demo.har` through the offline inspector; note that **offline file imports do not generate persistent keyed HMAC fingerprints** or save findings to the Evidence Vault.
6. Stop capture, repeat the capture of the same site, and compare findings. Only responses actually inspected while DevTools was open can be classified by fingerprint.

## Privacy, limitations and interpretation

- No credential validation, active enumeration, protected-file retrieval, outbound telemetry or automated API requests have been added.
- The original candidate is transiently available in DevTools memory to calculate its HMAC. It is **never sent to the service worker**. The service worker receives only the masked type, location, and an HMAC digest/key ID. No raw response bodies or authentication headers are saved.
- A new browser installation, removed storage, simultaneous first-time key initialisation, or imported evidence from another installation can make comparisons **unverified**. Fingerprints are not portable without the private key; never share or export that key.
- The existing site-local legacy location history remains, preserving the v3.9 repeat-alert behaviour where no HMAC evidence is available. A repeated mask is not treated as proof the value is unchanged.
- A match of a *private-key header* does not fingerprint the key content and is therefore excluded from unchanged-value claims.
- Findings are heuristic; source line/column may move with minification. If the location changes, Trufflehog may show a new location rather than infer a rotated credential.
- DevTools body inspection **still requires F12**. The tool cannot claim whole-site scanning, and the Evidence Vault contains only what was actually observed.
- Importing a prior record with an HMAC string is not authenticated proof that the fingerprint came from the same browser; imported history is classified unverified.
- The extension's full live Chrome MV3 / Windows notification / IndexedDB operation was **not verified in this build environment**. Its local test suites are not a substitute for installed-Chrome acceptance testing.

## Verification and local tests

From the extracted `Trufflehog-Intelligence` directory run Node.js tests:

```bat
for %f in (tests\*.cjs) do @node "%f"
```

(The command above is for Command Prompt; use `%%f` inside a `.bat` file.) Check locally in Chrome using `tests\windows_capture_smoke.py` or `tests\windows_diagnostic_runner.py` as documented in previous releases.

See the inherited README for broader v4.5 and earlier functionality, installation limits and supported DAM systems.
