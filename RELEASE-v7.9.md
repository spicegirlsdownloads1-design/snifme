# Trufflehog Intelligence v7.9 — Offline Image Content Negotiation Evidence

**24 October 2026 · Chrome MV3 · additive upgrade from v7.8 · no additional permissions.**

## New offline analysis

Under **Overview → Independent HAR coverage**, choose a locally saved HAR and run **1. Inspect HAR privacy locally**, then **2g. Inspect image negotiation (offline)**. The existing 12 MiB file / 12,000 entry limits apply.

- Counts successfully observed image `200`/`206` representations reported as JPEG, PNG, WebP, AVIF, GIF, SVG, or another image type. A HAR media label is **not image-byte verification**; it cannot establish dimensions or master quality.
- Counts request `Accept` format preferences (`image/avif`, `image/webp`, `image/jpeg`, image wildcard). A preference is not proof that a variant exists.
- Summarises response `Vary` hints (`Accept`, `Accept-Encoding`, `Accept-Language`, permitted image sizing hint names, Cookie/Authorization **presence only**, wildcard); `Accept-CH` image-sizing hint names; observed request width/DPR/client hints; and `Content-Encoding` categories.
- Separates **media-related 304** cache-validation observations from delivered image responses and treats file-suffix-only cases as unverified clues.
- Generates a category-only redacted JSON or CSV report with no request URLs, headers, dynamic values, file names, auth material, ETags or timestamps.
- After **independent privacy reviews of both files**, and answering the five context-comparability declarations, **5. Compare two reviewed HARs (offline)** additionally produces an **Offline image negotiation comparison**, counts and rates per 1,000 observed HTTP entries. It cannot attribute observed changes to actual server-side policy or image quality changes.

**All calculations are local on user-selected HARs.** No fetch, request replay, probing, binary inspection, URL variation, credential validation or downloads are performed. No HAR is newly stored in IndexedDB or Chrome storage by this module. Existing other app functions retain their own data contracts.

## Windows installation

1. Back up your Evidence Vault investigations before updating.
2. Extract the package contents **over the same unpacked Chrome extension folder**, keeping its path and extension ID stable; do **not** uninstall the old extension if you need its local storage.
3. Open `chrome://extensions` and click **Reload**.
4. Open the Trufflehog dashboard, **Overview → Independent HAR coverage**.
5. Import `tests/v79-negotiation-baseline.har` and use **1. Inspect HAR privacy locally** then **2g. Inspect image negotiation (offline)**.
6. For the comparison demonstration, import `tests/v79-negotiation-comparison.har` into the second file picker; complete **4. Inspect second HAR privacy locally**, declare all five comparability answers as **yes**, then **5. Compare two reviewed HARs (offline)**. Review **Offline image negotiation comparison**.
7. The fixtures use fictional `.invalid` domains and dummy data; **do not visit their URLs**. For your own HARs, never share the original raw file without independent sanitisation: HARs may contain live cookies, authorisation data, personal information and signed URLs.

Run from Command Prompt in the extension folder:

```bat
node tests\test_v79_image_negotiation.cjs
node tests\test_v79_wiring.cjs
node tests\v79_negotiation_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

## Caveats

- `Vary` describes response-selection criteria and possible cache-key behaviour under HTTP semantics; not proof of a security issue. Absence of `Vary` alone is not a vulnerability.
- Client Hints are browser- and permission-dependent. Differences may reflect device/browser/viewport choices, not the repository's master file or transfer entitlement.
- HAR's `mimeType` and server `Content-Type` may disagree, be missing, or represent metadata inferred by the exporter. Image dimensions, quality, rights and byte integrity are not checked here.
- The new module explicitly excludes 304 responses from newly delivered images.
- Comparisons count response characteristics within two independently collected sessions. They do not prove shared asset identity, availability of an alternate rendition, origin master resolution, public access, licence bypass or revocation failure.
- **Complete installed-Chrome operation is still unverified in this container.** Node tests and syntax checks are not a substitute for the dashboard's actual browser smoke test.

HTTP technical grounding: [RFC 9110 §12.5 (Accept and Vary)](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5), [MDN Content Negotiation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Content_negotiation), [Chromium Client Hints](https://chromium.googlesource.com/chromium/src/+/main/docs/client_hints/).
