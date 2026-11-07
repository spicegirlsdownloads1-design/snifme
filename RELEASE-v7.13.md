# Trufflehog Intelligence v7.13.0 — Universal Delivery Boundary Review

25 October 2026 · Chrome MV3 · generic-first, opt-in passive observation

## Source research and scope

This update incorporates the reusable browser-observable patterns from the user-supplied report, *Enterprise Digital Asset Management Security: Server Exploitation Mechanisms and Asset Exposure Vectors* (2026-10-25). It is **not** an exploit scanner and is **not** limited to DAM products.

The report discusses server-side XXE, path traversal, code execution, document parsing, media delegates, S3-style signed URLs, cloud IAM, cache policies, and distributed asset architecture. A passive browser trace cannot verify server-side execution, vulnerable library versions, patch status, IAM privileges or anonymous access. The new functionality confines itself to observable HTTP evidence and marks these limits explicitly.

For numeric SigV4-style expiry conventions, the code uses official published signing-query fields. A query duration reflects the *declared* window only; underlying credentials and service policy may shorten or invalidate it. Other signing protocols retain an 'unknown' duration rather than guessing.

Reference documentation:
- https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html

## New features

- New **Security → Universal delivery boundaries** dashboard for any website, including custom/unrecognised backends.
- At capture time, `scanner.js` classifies explicit signing-parameter presence and bounded numeric expiry-duration bands for `X-Amz-*` and `X-Goog-*` signature fields. It never stores signature values, credential scope, expiration timestamps or URL query values for the new analysis.
- New `generic_boundary_review.js` analyses only the browser's recorded requests and optionally enabled download-observer events.
- Fixed-label, count-only indications include different-origin signed delivery, signed + public-cache policy, >=24-hour public cache directives, declared signing windows, observed redirect boundaries, attachment disposition, 202 API write responses, 206 partial content, 401/403 denied outcomes, and 5xx responses.
- Old captures with only the ambiguous `signedQuery` field are *not* promoted to confirmed signature observations. They receive a separate 'metadata unavailable' tally.
- Dedicated redacted JSON/CSV exports list category names, counts, evidence class and interpretation limits. Their output never includes hostnames, URLs, paths, IDs, cookies, signatures, expiry values or header/body contents. Counts are capped and capture gaps produce warnings.
- No new extension permissions and no active website requests, replay, brute-force checks, endpoint enumeration, or cross-origin escalation.

## Using the view

1. Back up locally saved Evidence Vault data before updating the unpacked extension.
2. Extract the ZIP to your existing unpacked extension folder, preserving its location, then reload from `chrome://extensions`.
3. Explicitly enable capture on an authorised tab and browse normally. The optional download observer must be independently enabled for redirect-stage evidence.
4. Open **Security → Universal delivery boundaries** and review fixed labels and coverage warnings. The analysis performs no network I/O.
5. Export the dedicated redacted report as JSON/CSV for owner review if needed. The redaction guarantee here does **not** extend to all previous whole-session export formats.

## Interpretation limitations

- An observed signed query is not proof a signature is valid or that asset access is unrestricted.
- A 24h-to-7d signing window is a protocol declaration, not a guaranteed effective validity period; some services cap windows at shorter durations.
- A public cache directive does not prove anonymous or unauthorised access, a cache-hit, or missing withdrawal policy.
- Redirect observations show traffic stages, not entitlements, original files or server-to-server operations.
- 202/206/401/403/5xx statuses are not proof of a security weakness.
- Server-side XXE, path traversal, RCE, parser CVEs and cloud IAM cannot be established from this feature and are never asserted.
- Historical captures without new signature classification retain limited coverage. Missing browser events and worker restarts can hide activity.

## Validation

- `node --test --test-concurrency=4 tests/*.cjs` — 166 tests passed including 2 new tests.
- `node --check *.js` — 78 JavaScript syntax checks passed.
- Chrome/DevTools end-to-end behaviour on Windows remains unverified.
