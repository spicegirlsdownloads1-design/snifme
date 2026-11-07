# Trufflehog Intelligence v5.1 — Authenticated Download Observer

v5.1 extends v5.0 with an explicitly enabled, per-capture, **read-only download lifecycle observer**.

## New capabilities

- Records selected POST/PUT/PATCH and download-related request stages using Chrome `webRequest`: method, host, request ID (for lifecycle grouping), status, recognised POST field *categories*, and recognised request header *names*. It **never** stores body values or header values.
- Classifies the presence of signing/expiry/credential query parameters without retaining their values, raw URL paths, or redirect URLs. Redirect hosts are recorded.
- Recognises attachment response flags and bounded MIME classifications.
- Observes Chrome download start and completion events **only when a unique opted-in referrer-origin match exists**. Chrome `DownloadItem` supplies no reliable originating `tabId`; resulting events are explicitly *correlated*, not linked to an individual POST.
- Provides **Network & APIs → Download observer**, a per-capture on/off button, CSV/JSON results, and Evidence Vault compatibility. All earlier modules remain present.
- A local Python fixture in `tests/download_lab.py` demonstrates an ordinary POST → 303 → attachment workflow using a harmless text file.

## Deliberate exclusions

No request replay, cURL reconstruction, hidden URL guessing, signing-key recovery, signature-value capture, private asset access or credential validation. The observer saves no POST values, cookies, bearer tokens, API secrets, CSRF values, usable signatures, raw response bodies, filenames, or complete signed URLs. JSON request-body field names are not parsed; they are classified as **opaque body not inspected**.

## Known limits

- Enable the observer **after** starting capture; earlier lifecycle events are not available. The `webRequest` listener only sees requests Chrome permits under the selected site's permissions; cross-origin CDNs can be partially or completely unobserved. Chrome may omit protected headers, and we do not request the privileged `extraHeaders` option. Thus *not observed* never means *absent*.
- Chrome `downloads` has no originating tab ID in `DownloadItem`; download lifecycle evidence is included only for a single unique capture on the exact referrer origin. Missing/empty referrers or multiple simultaneous captures prevent attribution.
- Events are limited to 450 per active segment, with a rollover boundary at 410. Capture segments remain in the Evidence Vault. Browser download-event correlation after a Manifest V3 service-worker restart may be incomplete.
- Background webRequest listeners remain passive. The extension does not record request body text or parse arbitrary JSON POST bodies. Matching a redirect chain uses request IDs; matching download events to a preceding POST is **not verified**.
- Installed Chrome / Windows end-to-end verification is still required. Isolated Node.js tests do not prove Chrome's operating system download notifications or every webRequest field is available.

## Upgrade

1. Export existing Evidence Vault backups.
2. Extract the ZIP, copy the `Trufflehog-Intelligence` contents into **the same** unpacked extension directory, then select **Reload** at `chrome://extensions`.
3. Open a website you are permitted to inspect. Click the extension and grant site access/start capture.
4. Open its dashboard under **Network & APIs → Download observer**, select **Enable download observer**, then carry out a normal authorised download.
5. Review request lifecycle records. Use Export CSV/JSON; neither export contains raw secrets from this observer.
6. Disable the observer or stop capture when done.

### Local acceptance fixture

In a Command Prompt opened in the extension folder, run:

```bat
py tests\download_lab.py
```

Open `http://127.0.0.1:8765/download-lab.html`, grant site access, start capture, enable **Download observer**, and press **Generate harmless sample download**. Expect a POST, a 303 redirect to the same local host, and an attachment delivery. A download event may be absent if Chrome supplies no referrer; this is a documented limitation, not a claim of a missing download.

## Security and privacy

Use only for systems/accounts you own or are explicitly permitted to assess. Never use observed material to bypass account access, replay signed requests, or retrieve content outside your permissions. Everything is processed locally; secrets are discarded before records are written.
