# Trufflehog Intelligence v7.7 — Offline Byte-Range Evidence

**24 October 2026 · Chrome Manifest V3 · additive upgrade from v7.6 · no new Chrome permissions.**

This release adds **byte-range transfer observations** to **Overview → Independent HAR coverage**, extending existing offline HAR privacy, DAM/CDN classification, access-evidence, delivery-policy and redirect-boundary analysis. This is a metadata inspection feature, not a downloader or media reconstruction tool.

## New analysis

- **2e. Inspect byte-range evidence (offline):** requires the privacy preflight on the *exact same* local `.har` file and rechecks the HAR before analysis.
- Classifies observed `Range`, `If-Range`, `Accept-Ranges`, `206 Partial Content`, `416 Range Not Satisfiable`, `Content-Range`, `Content-Length` and `multipart/byteranges` response metadata.
- Checks whether single-part `206` headers contain syntactically valid `bytes first-last/total` values; flags invalid/missing content ranges and suspicious `Content-Length` differences.
- Groups *only previously recorded header claims*, and **only** where the source URL string, **strong ETag**, content encoding, and declared complete length match within one HAR. No URLs, ETags, byte offsets, or identifiers are included in its reports.
- Summarises what fraction of a representation's byte range **headers claim** was described by the observed responses, in coarse `0–24%`, `25–49%`, `50–74%`, `75–99%`, and `100%` buckets. These are **NOT receipt, integrity, entitlement, quality or download-completion measurements**. Repeated or overlapping ranges are noted separately.
- **Two-HAR comparison:** after two independent privacy preflights and five user-declared comparability questions, compares fixed-category counts and rates per 1,000 observed HTTP 206 responses.
- Adds export buttons for fixed-label, count-only redacted JSON and CSV, for both single-HAR and comparison reports.

The new module never requests, replays, reassembles, downloads, validates credentials, decodes binary payloads, constructs alternate media URLs, or attempts to access originals. A `206` response is not an indication that a more complete file is available outside the permitted session.

This interpretation follows [RFC 9110 §14.4 and §15.3.7](https://www.rfc-editor.org/rfc/rfc9110): `Content-Range` describes part of a selected HTTP representation, while `Content-Length` on a partial response typically describes the partial message. Multipart responses carry a separate content range for each part; the new analyser intentionally does not inspect their bodies.

## Windows upgrade and test

1. Back up important Evidence Vault captures. Extract the v7.7 ZIP over your **existing unpacked extension folder**, keeping the folder path and extension ID stable. Do not uninstall/re-add when preserving local storage.
2. Go to `chrome://extensions` and **Reload** the extension.
3. Open the Trufflehog dashboard → **Overview → Independent HAR coverage**.
4. Choose a HAR exported from your **own authorised browsing session** (up to **12 MiB / 12,000 entries**). Raw HAR files may contain cookies, credentials, complete signed URLs and private request bodies; store them securely.
5. Click **1. Inspect HAR privacy locally**, then **2e. Inspect byte-range evidence (offline)**. Review the response classifications and declared-span buckets.
6. For comparisons, choose a second HAR and run **4. Inspect second HAR privacy locally**, declare the five context fields, then **5. Compare two reviewed HARs (offline)**. Scroll to **Offline byte-range evidence comparison**.
7. Optionally export the redacted fixed-label JSON/CSV. The original HAR is not persisted by this new analysis module.

Test with bundled offline synthetic fixtures:

- `tests/v77-range-baseline.har` — fictional 206 range requests with complementary header spans and a 416 response.
- `tests/v77-range-comparison.har` — fictional partial coverage and a 200 response to a Range request.

Both use `.invalid` hostnames, fake signing strings and nonfunctional values. They are for the **local offline inspector only**: do not open the fictional URLs or use them to test a live service.

From Command Prompt in the unpacked extension directory:

```bat
node tests\test_v77_range_evidence.cjs
node tests\test_v77_wiring.cjs
node tests\v77_range_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

## Privacy model and limitations

- HAR contents are parsed in local memory. New JSON/CSV reports contain **only fixed labels, bounded numeric counts, normalised rates and explicit yes/no/unknown context declarations**.
- The new analysis never outputs request/response URLs, hostnames, paths, filenames, signed parameter values, cookies, bearer tokens, request/trace IDs, ETags, byte offsets, POST data, downloaded binary content or exact timestamps.
- The privacy preflight checks the data structure, **not** whether the original HAR is safe to share. Treat raw HARs as sensitive regardless of preflight results. Other pre-existing full-session exports have separate privacy contracts.
- Strong ETag grouping is a conservative identity clue for the same requested representation **within a single HAR**, not proof of object identity, validated content, access rights or availability of a master file. Missing ETags, different signed URLs and different content encodings reduce grouping coverage.
- `100%` means **100% of the declared byte span appears in the observed response *headers***. It does *not* mean that 100% of bytes were captured, received or written to disk.
- Chrom(e/ium) HARs may lack requests due to cache, open DevTools timing, redirects, workers, privacy sanitisation and partial capture.
- Differences between captures are purely observational; actual delivery, revocation, quality, exposure, or security posture requires corroborating evidence and an owner-authorised assessment.

## Verification scope

The local Node.js regression suite, JavaScript syntax checks and ZIP integrity are checked during packaging. **Complete installed-Chrome startup, dashboard interaction, background/DevTools capture, Windows notifications and Evidence Vault persistence remain unverified in this environment.** Use the bundled fictional HARs on your Windows installation before relying on the interface.
