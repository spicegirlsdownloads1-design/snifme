# Trufflehog Intelligence v7.0 — Offline DAM Workflow Inventory

**24 October 2026 · Manifest V3 · preserves v6.9 modules · no new Chrome permissions**

## What this release adds

The **Overview → Independent HAR coverage** page now includes **2. Analyse DAM workflow (offline)**, following the mandatory HAR privacy preflight introduced in v6.9. Unlike HAR reconciliation, this inventory **does not need a saved Trufflehog capture**.

It analyses a user-selected, locally parsed HAR file (maximum 12 MB / 12,000 entries) for:

- Observed DAM vendor-service hostname signals (Capture, ResourceSpace, PhotoShelter, Bynder, Cloudinary, Canto, FotoWare), AWS API Gateway, Amazon S3, CloudFront, Azure Blob, Google Cloud Storage and Cloudflare edge-header presence.
- Broad HTTP request/response stages: API/JSON, media responses, attachment headers, download/rendition path clues, POST export-job clues, GET status-check clues, upload structures, redirects, HTTP 206 partial responses and HTTP 401/403 denials.
- **Structural** auth and delivery indicators: authorization/cookie/CSRF header presence, SigV4 structure, signed/credential-like query field names, S3 form-policy field names, multipart/GCS/Azure/tus protocol fields, edge/trace headers, cache-control policy presence and missing image body content.
- Request methods and HTTP status classes; excluded/non-HTTP and missing header evidence.
- Fixed category/count exports in standalone JSON or CSV, never complete HAR records.

### Observational limits

These are **service-use clues**, not definitive platform identification or proof of DAM ownership, account scope, security defects or licence entitlements. A `Content-Disposition` attachment header is **not** proof that the browser finished downloading a file. A request containing `/export/` is not proof that a background job ran. HTTP `200/206` responses may be authenticated. An HTTP `403` is an observed denial, not a vulnerability. No remote URLs are constructed, fetched, probed or replayed.

The inventory does **not** reconstruct causal download chains from HAR alone. It does not download media, test signing material, inspect protected masters, or retain request identities to connect activity across sites.

### Privacy model

- Original HAR remains selected locally in the dashboard memory only; it is **not** uploaded, saved to IndexedDB or inserted into the Evidence Vault.
- The new exported report is built solely from hard-coded labels and bounded integer counts. It contains **no source-derived hostnames, URLs, paths, parameters, trace IDs, request IDs, filenames, credentials, headers, bodies, values or free-text**.
- The preflight is structural, not a comprehensive secret scanner. Even a zero-warning HAR should be treated as private; do not share original HARs without separate authorisation/review.
- Earlier, unrelated Evidence Vault exports have their own different data-retention model and are **not** covered by the new report's allowlist guarantee.

## Windows Chrome installation

1. Back up any Evidence Vault investigations before upgrading.
2. Extract v7.0 **over the same previously loaded unpacked extension folder** to keep Chrome's existing local extension data. In `chrome://extensions`, choose **Reload**.
3. In Chrome DevTools, open **Network** before a normal authorised browse and export a HAR, preferably using Chrome's sanitised export where supported. Preserve the original file privately.
4. Open Trufflehog dashboard → **Overview → Independent HAR coverage**, select `.har` or `.json` (up to 12 MB).
5. Click **1. Inspect HAR privacy locally**. Review what the structural preflight can and cannot detect.
6. Click **2. Analyse DAM workflow (offline)**, inspect the summary and optionally export the **redacted** JSON/CSV counts. **No saved capture is required.**
7. Existing **3. Reconcile reviewed HAR with capture** remains available when you have a matching Evidence Vault group.

## Tests and known limitation

```bat
node tests\test_v70_har_dam.cjs
node tests\test_v70_wiring.cjs
node tests\v70_har_dam_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

Synthetic input: `tests\v70-dam-workflow.har` (fictional domains, dummy credential strings). You can import it directly to exercise the offline report.

The new offline engine is tested in Node.js, and all inherited suites are rerun. **Actual installed-Chrome UI/DevTools/IndexedDB integration remains unverified in this environment**; use the supplied Windows local acceptance tools if you need evidence of the complete live workflow.

The included demo HAR intentionally contains a fake bearer string and fake signing values to prove that these **values never appear** in the offline inventory. It should not be mistaken for a real agency trace.
