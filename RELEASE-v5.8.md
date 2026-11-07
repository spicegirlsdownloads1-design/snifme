# Trufflehog Intelligence v5.8.0 — Investigation Workspace

**24 October 2026 · Chrome Manifest V3 · offline report generation · no new permissions**

## Release overview

This release builds on v5.7 DAM Platform Specialists and v5.6 upload and API schema analysis. It adds an **Evidence Vault → Investigation dossier** workflow that combines recorded segments from **one capture group** into a privacy-safe report.

### New capabilities

1. **Grouped case dossiers:** Select a saved capture group (including automatically rolled segments), and build a report from records already in IndexedDB. The module does not visit websites or create requests.
2. **Evidence statements:** Eight fixed categories separate **Observed**, **Inferred**, and **Unverified**. No category label grants a security clearance or indicates access to original photos.
3. **Coverage diagnostics:** Missing numbered segments, unfinalized captures, reported retention drops and DevTools coverage gaps are identified. Absence of a reported drop or gap does not prove complete coverage.
4. **DAM specialist indications:** Approved vendor names and strength of indications are drawn from the existing passive v5.7 detector; external service traffic is never evidence of DAM ownership or compromised permissions.
5. **Coarse event timeline:** Timestamp and safe event type (HTTP, masked indicator, verified file, download) only. No request paths, tokens, referrers, download filenames or raw evidence identifiers.
6. **Redacted dossier exports:** Compact JSON case envelope with a SHA-256 integrity digest, and CSV evidence summaries. The digest detects incidental modification but **does not authenticate a person, device or website**.
7. **Optional encrypted case export:** PBKDF2-HMAC-SHA256 (250,000 iterations, random salt) derives an AES-256-GCM key from a passphrase of at least 12 characters. A fresh 96-bit IV is used per export. **The passphrase is neither saved nor recoverable**, and no data is sent to servers.
8. **Case-file verification:** Import a `.json` or encrypted case export to check decryption and the SHA-256 digest; the case file is **not** merged into Evidence Vault. For safety, arbitrary imported note fields are never displayed.

**Encryption scope:** This encrypts the **redacted case dossier**, not the full original Evidence Vault records, raw network traffic, or unencrypted existing group backups. Existing Evidence Vault backups have their own privacy properties. Do not assume every data export is encrypted.

### Privacy and limitations

The new case exporter uses a strict static allowlist. It intentionally omits request bodies, asset IDs, session and group IDs, source-code snippets, credentials, signed URLs, POST values, full HTTP routes, external hostnames, local download paths, raw trace IDs and pixel-image data. The selected site's **origin hostname** is retained to identify the case.

Timeline and counts are based only on saved events. Browser capture can omit requests because of host permissions, Chrome caching, DevTools start time, worker restarts or other causes. A complete dossier is **not** proof of complete capture, license entitlement or repository ownership.

### Windows installation

1. Export any important Evidence Vault investigations before upgrading.
2. Extract the new ZIP into the **same unpacked extension folder** and overwrite the old files. Do not uninstall the extension first if you need existing IndexedDB records.
3. Open `chrome://extensions`, enable Developer mode, find Trufflehog Intelligence and choose **Reload**.
4. Open its dashboard and go to **Evidence Vault → Investigation dossier**.
5. Click **Refresh saved groups**, choose one group, then **Build local dossier**.
6. Review coverage warnings, observed evidence and vendor inferences; export JSON or CSV. To encrypt, enter a strong passphrase and select **Export encrypted case**.
7. To check an exported file, enter its passphrase if encrypted and click **Verify encrypted/JSON case file**. Verification is not proof of the observations' origin.

### Developer test commands

```
for %f in (tests\test*.cjs) do @node "%f"
node --check case_intel.js
node --check case_crypto.js
node --check dashboard.js
node tests\case_dossier_demo.cjs
```

### Existing modules retained

DAM specialist profiles (Capture, ResourceSpace, PhotoShelter, Bynder, Cloudinary, Canto and FotoWare), DAM policies and risk prompts, opt-in secret and image scanning, frame and worker observations, Download Observer, AWS DAM patterns, upload protocols, API schema comparisons, asset quality, cross-archive analysis and Evidence Vault backup/import functionality.

### Known outstanding verification

Automated Node.js tests and static packaging verification do **not** prove the Chrome MV3 worker, Windows desktop notifications, DevTools body capture or end-to-end dashboard behaviour work in an installed browser. This was not established in the current runtime and requires manual Chrome verification.
