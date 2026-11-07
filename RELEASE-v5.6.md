# Trufflehog Intelligence v5.6.0 — Advanced API & Upload Intelligence

**Read-only analysis · Chrome Manifest V3 · 24 October 2026**

This release extends the v5.5 Authenticated Download Observer with **multipart/resumable upload protocol classifications** and adds an **offline diff of JSON field-name/type shapes** from two captured sessions of the same website.

## New functionality

### Network & APIs → Upload protocols

After the user starts a site-specific capture and explicitly enables **Download Observer**, Trufflehog analyses **only observed browser requests** for:

| Family | Passive evidence | Example stage labels |
|---|---|---|
| S3-compatible multipart | `uploads`, `uploadId`, `partNumber` query **names**, with S3 hostname classification where available | Initiate, part transfer, commit request |
| Azure Blob-compatible | `comp=block` or `comp=blocklist` enumerated **operation**; recognised Blob host where available | Block transfer, commit request |
| Google Cloud Storage-compatible | `uploadType=resumable`, session-ID parameter **presence**, recognised GCS host or standard headers | Initiate, resumable transfer |
| tus-compatible | `Tus-Resumable`, `Upload-Offset`, `Upload-Length`, `Upload-Checksum` and `Upload-Metadata` header **names** | Initiate, offset check, resumable transfer |
| Generic multipart form | Recognised upload field **names** or multipart MIME type and an upload-labelled path | Single-form upload |

**No request generation, upload submission, test upload to cloud storage, endpoint guessing or authorisation probing is performed.** Headers and query/form values are evaluated only as needed to recognise a known field/operation and are never stored in the new reports. Raw bodies are neither decoded nor retained by the new module. Storage provider names are presented as *compatible patterns*, not verified operators.

The upload report groups HTTP lifecycle stages by Chrome's in-memory request ID but exports only generated local references `UP1`, `UP2`, etc. It records timestamps, hostnames, methods, bounded HTTP statuses, fixed indicator labels, capture-stage coverage and explicit uncertainties. Upload session IDs, AWS credential scopes, policy documents, bucket names, object paths, Azure block IDs, signing material and raw browser request IDs are not included in the **new upload report**.

**Interpretation:** A 200/201/204, or a commit operation, confirms only the browser-observed HTTP step. It does not certify that a DAM generated a derivative, indexed the asset, or completed its backend processing. Because reusable upload identities are not retained, related requests are not asserted to belong to the same uploaded asset.

### Network & APIs → API schema changes

A local comparison of two *saved* opt-in JSON-shape captures. For each same-origin, method-and-route match, Trufflehog counts:

- JSON field-name additions/removals in observed response structures;
- Differences in primitive/container field types;
- Newly observed endpoints and endpoints not observed in the current capture;
- Evidence limitations when a response or endpoint was not seen by DevTools.

Route paths and query values are **not exported**. Endpoint matching uses only transient in-memory normalised route strings and emits labels such as `API1`, `API2`. The report contains hostnames, route categories, field counts and difference counts, **not the field names or actual JSON values**. Only captures of exactly the same origin may be compared. Different responses caused by filters, content, permissions, or browsing can look like a schema change; no backend deployment is assumed.

This feature **requires JSON shapes to have been explicitly enabled while DevTools was open during both captures**. The original Chrome JSON-shape scanner's 256 KiB response limit and privacy filters still apply. Historic sessions with no JSON shapes may be selected but will produce unpaired/empty results; that is not evidence an endpoint has disappeared.

## Upgrade

1. Export important Evidence Vault investigation groups before upgrading.
2. Extract `Trufflehog-Intelligence-v5.6.0.zip` and replace the contents of the **existing unpacked extension directory**; preserve your Chrome extension ID and saved profile. Do not uninstall/clear extension storage.
3. Reload at `chrome://extensions` and open the dashboard.
4. Browse only a site where you have authorisation to observe workflows. Start capture and explicitly select **Enable Download Observer**.
5. Use **Network & APIs → Upload protocols** after a normal upload or a synthetic localhost test.
6. To compare JSON shapes, open F12 **before page loading**, enable the **JSON shapes** toggle, capture the original site twice, stop each capture to archive the session, then use **Network & APIs → API schema changes** and choose a saved baseline.

## Windows localhost test

From Command Prompt in the extension's top-level folder:

```bat
py tests\protocol_lab.py
```

Open `http://127.0.0.1:8769/` in Chrome, grant that origin, start capture and enable Download Observer. Click the four buttons for simulated protocol stages. They send only inert dummy requests to localhost, not to AWS/Azure/GCS. The **Upload protocols** view should show S3-compatible, Azure-compatible, GCS-compatible and tus-compatible patterns with provider confidence qualified. The storage-provider tests use recognised URL parameter/header shapes, not actual storage hostnames.

For JSON shape comparison, open Chrome DevTools and explicitly enable JSON shapes before clicking **JSON schema A**. Stop capture and archive. Start a separate capture on the same localhost origin with DevTools and JSON shapes active, click **JSON schema B**, and stop/archive. Open **API schema changes**, compare with the earlier saved session and inspect observed type/addition counts. Results require response contents to be available to DevTools and may be affected by DevTools caching.

## Security & limitations

- **No additional Chrome permissions**; no debugger, cookies, webRequestBlocking or arbitrary network probing.
- The original event recorder retains its existing request-ID lifecycle linkage and conservative bounded storage; the **new exported reports** do not expose IDs or credential-bearing URLs.
- No request body values, multipart file data, signing policies, cookies, bearer tokens, AWS temporary credentials, signed URL query values, Azure block identifiers or local paths are included in the new analysis.
- The browser cannot see private backend worker states, unseen requests, data written directly by another service, or all cross-origin activity. Service Worker restarts and host permissions can cause gaps.
- This build's unit/integration simulations and localhost fixture are **not equivalent to a verified installed-Chrome acceptance test**; Chrome extension startup, DevTools integration, Windows notifications and production-site capture still need local validation.

## Validation

- **87 Node.js test suites passed**, including v5.6 protocol detection, privacy-safe schema diff, background opt-in storage and UI wiring.
- **50 JavaScript source syntax checks passed** (`node --check`).
- Local fixture checked for synthetic protocol responses and two different JSON structures.
- ZIP integrity and manifest version checked before delivery.

From the extension directory, run the Node tests (on Windows Command Prompt):

```bat
for %f in (tests\test*.cjs) do @node "%f"
```

In a `.bat` file, use `%%f` instead of `%f`.

## References

- Amazon S3 multipart uploads: https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
- Microsoft Azure Put Block List: https://learn.microsoft.com/en-us/rest/api/storageservices/put-block-list
- Google Cloud Storage resumable uploads: https://docs.cloud.google.com/storage/docs/resumable-uploads
- tus resumable upload protocol: https://github.com/tus/tus-resumable-upload-protocol/blob/main/protocol.md
