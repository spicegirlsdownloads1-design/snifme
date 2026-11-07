# Trufflehog Intelligence v5.2 — DAM Telemetry & Trace Correlation

This release implements the browser-observable portions of the user-provided **Architectural Design and Telemetry Framework for Digital Asset Management Systems** and retains all v5.1 features.

## New in v5.2

- **W3C `traceparent` indicator:** validates the header's version/ID/flags shape and identifies its sampled bit. Its opaque trace ID is held only in a bounded in-memory service-worker map and replaced with capture-local `Trace N` labels *before* storing any event. `tracestate` values are NEVER retained. Labels are not stable across worker restarts or sessions.
- **Authentication mechanism classification:** `Bearer`, `Basic`, `AWS SigV4`, cookie-present or other authorization, plus presence of HMAC/signature headers. Credential scopes, prefixes, raw signatures, API keys, tokens, cookies and POST values are not stored.
- **CDN and observability headers:** indicates whether known CloudFront, Cloudflare, proxy and request-ID headers are present. CDN header values, edge request identifiers, `tracestate` contents and vendor tokens are excluded.
- **Transfer and cache evidence:** observed Content-Length, ETag/Last-Modified *presence*, cache-policy category and bounded max-age. Missing Content-Length is recorded as unknown, not zero.
- **Browser download diagnostics:** optional received/total byte counts, percent and resumability where Chrome provides them; failed downloads are grouped as network/server/filesystem/user/browser errors without exposing raw messages or filenames. On completion/interruption the observer requests the DownloadItem by ID when available, discarding all fields except approved numerical/status data.
- **DAM upload/ingestion field dictionary:** recognises field-name *categories* such as `public_id`, `upload_preset`, `resource_type`, `structured_metadata`, and `transformation` if provided as form fields; no values, uploaded files or private API calls are inspected.
- **Local CloudEvents 1.0-style JSON export** from the Download telemetry view. Events are explicitly identified as `com.trufflehog.observation.download.step`, not server-side DAM events. Only whitelisted observation metadata is included.

## Deliberate omissions

No `chrome.downloads.onDeterminingFilename` modifications, no cURL/request replay, no cryptographic signature verification, no token-age computation, no impersonation of server-side CloudEvents, no private bucket or admin discovery, no file-content acquisition, and no external webhooks. The uploaded document's examples of trace propagation are architectural guidance: a browser extension **cannot establish end-to-end backend trace propagation** from one visible `traceparent` header.

## Key limitations

- The download observer is explicitly opted in after capture starts. It uses read-only `webRequest` listeners plus Chrome downloads events and does not require DevTools for request/transfer metadata; response-body scanning still needs DevTools.
- Cross-origin CDN requests can be missing without separate host permissions. Protected request headers may also be unavailable. `Not observed` is **not** evidence a header or credential is absent.
- Chrome's `downloads.DownloadItem` has no dependable originating tab ID; matching is restricted to a **unique opted-in referrer-origin**, and any association is a clue, not proof of a particular POST causing a download.
- Manifest V3 worker suspension can reset the in-memory trace map and download event association. Trace labels are valid only within a continuous observed worker context. The 450-event segment cap and Evidence Vault rollover rules remain.
- CloudEvents are generated **locally** during export and do not carry `traceparent` or `tracestate` values. The Event `source` names the extension, not the DAM website.
- Exports have no credential values, signatures, original filenames, raw request headers, full signed URLs, or absolute local paths.
- Chrome end-to-end behaviour must still be verified in your Windows installation; automated test mocks do not establish browser-event coverage.

## Upgrade / Windows smoke test

1. Back up the Evidence Vault and extract into your **existing unpacked folder**; reload from `chrome://extensions`.
2. Start the local fixture in Command Prompt from inside the unpacked `Trufflehog-Intelligence` folder:

   ```bat
   py tests\download_lab.py
   ```
3. Open `http://127.0.0.1:8765/download-lab.html`, grant permission, start capture, then enable the **Download telemetry** observer.
4. Click **Generate harmless sample download**. Under **Network & APIs → Download telemetry**, inspect POST field categories, a 303 redirect, header evidence, cache policy and delivery evidence. Download events may be omitted if the browser doesn't expose an acceptable referrer.
5. Select **Export local CloudEvents JSON**. The event `source` should be `/trufflehog/local-download-observer`, with no raw headers or secrets.
6. Run the automated suite (Node.js required): `for %f in (tests\test*.cjs) do @node "%f"`.

No genuine DAM credentials or remote servers are needed for the local fixture.

## Standards / API references

- W3C Trace Context: https://www.w3.org/TR/trace-context/
- CNCF CloudEvents: https://cloudevents.io/
- Chrome `webRequest`: https://developer.chrome.com/docs/extensions/reference/api/webRequest
- Chrome `downloads`: https://developer.chrome.com/docs/extensions/reference/api/downloads
