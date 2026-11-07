# Trufflehog Intelligence v7.5 — Offline Access Evidence Matrix

**24 October 2026 — local-only, read-only HAR analysis; no new Chrome permissions.**

## Changes

The existing **Overview → Independent HAR coverage** workspace now provides:

- **2c. Inspect access evidence (offline)**: after a local privacy preflight for the exact selected HAR, cross-tabulates request-side authentication/signing indicators with observed media/attachment response outcomes and cache directives.
- **Offline access-indicator comparison**: compares the same fixed categories between independently preflighted HARs after completing the existing five context-declaration questions.
- Redacted JSON and CSV export for both the single-HAR and two-HAR reports, with only fixed category labels and aggregate counts/rates.

The analyser distinguishes **signed URL name**, **Authorization header present**, **Cookie header present**, **mixed indicators**, **none observed**, and **request headers unavailable**. These are not proof of authorisation/anonymous access. Outcome categories distinguish 2xx MIME-confirmed media/attachment, 206, 401/403, 3xx and inconclusive responses. Cache categories distinguish `public`, `private/no-store`, `no-cache`, other directive and absent header.

**Important:** Chrome's sanitised HAR export can remove authentication and cookie headers. **No indicator observed does not mean the request was anonymous or unauthenticated.** A header was observed only where the HAR explicitly includes it. These reports cannot establish licensing, access-control failure, public original image availability, cache revocation failure or actual disk download completion.

## Run on Windows

1. Back up Evidence Vault captures. Extract v7.5 over the existing unpacked extension directory; reload on `chrome://extensions` without removing and re-adding the extension.
2. From the dashboard go to **Overview → Independent HAR coverage**, and select a local `.har` file (12 MB and 12,000 entries maximum).
3. Click **1. Inspect HAR privacy locally**, then **2c. Inspect access evidence (offline)**; review count matrices and warnings, and optionally export the fixed-label report.
4. To compare, select a second HAR, run **4. Inspect second HAR privacy locally**, declare the five comparability factors, then click **5. Compare two reviewed HARs (offline)**. Review **Offline access-indicator comparison**.
5. Import the bundled fixtures `tests\v75-access-baseline.har` and `tests\v75-access-comparison.har` to exercise these steps using only invented request data. Both files contain deliberately non-functional signing/cookie strings and the `.invalid` reserved domain.

```bat
node tests\test_v75_access_matrix.cjs
node tests\test_v75_wiring.cjs
node tests\v75_access_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

## Privacy and limitations

The new module never fetches or replays requests and never stores or exports original HAR files, hosts, paths, query values, POST data, response bodies, session cookies, credentials, signature values, trace IDs, request identifiers, filenames, asset IDs, or exact timestamps. The local browser must temporarily parse original HAR values to classify them. Reports contain only hard-coded labels, bounded counts and context declarations. **Other pre-existing screens and exports have different privacy contracts.** Always handle raw HAR files as sensitive.

A HAR from an authenticated session can show a 2xx media response without proving that an anonymous user could receive it. Missing headers, different workflows, disk-cache effects, omitted requests and sample sizes distort comparisons. Although unit tests and static wiring checks verify these code paths, this build has **not been validated as a complete installed Chrome extension** in this environment. Use the local fixtures and your approved site captures to verify UI behaviour on Windows.
