# Trufflehog Intelligence v7.6 — Offline Redirect Boundary Evidence

**24 October 2026 · Chrome Manifest V3 · additive upgrade from v7.5 · no new Chrome permissions.**

This update extends the existing **Overview → Independent HAR coverage** workspace to distinguish **actual redirect evidence** from mere temporal proximity. The extension remains a local-only, read-only investigator. It does not test authorisation, reconstruct protected download URLs, request image masters, replay signed links, or authenticate using detected credentials.

## Additions

- **2d. Inspect redirect boundaries (offline)**. After a successful privacy preflight on the exact selected HAR, classify HTTP 301/302/303/307/308 responses. The analyser examines a `Location` header or HAR `response.redirectURL`, resolves the destination in local memory, then looks for exactly one later request for the same absolute destination in the already-imported HAR.
- **Boundary evidence counts** distinguish uniquely matched same-origin/cross-origin destinations, missing target captures, repeated ambiguous targets, invalid/non-HTTP destinations and redirects without destination metadata.
- **Target indicator counts** for matched cross-origin requests: observed `Authorization`/API-key header names, cookie header name, signing query-parameter *names*, absent or unavailable header evidence, HTTPS-to-HTTP destinations, MIME-confirmed media 2xx, attachment 2xx and 401/403 denials.
- **Two-HAR boundary comparison** in the existing comparison workflow, with fixed-category counts and per-1,000-redirect rates. The existing five user-declared comparability questions and independent HAR privacy preflights remain mandatory.
- **Redacted JSON/CSV exports** for the single-HAR report and two-HAR comparison. Only fixed labels, bounded counts, rates and explicit yes/no/unknown context answers are output.
- Two wholly synthetic `.har` test fixtures and automated tests for ambiguous targets, unmatched targets, cross-origin evidence, missing auth headers and privacy.

## Install on Windows

1. Back up any important Evidence Vault investigations first.
2. Extract `Trufflehog-Intelligence-v7.6.0.zip` over your existing **unpacked extension directory** (preserve the Chrome extension ID by reloading rather than removing/re-adding it).
3. In `chrome://extensions`, click **Reload**.
4. Open the Trufflehog dashboard → **Overview → Independent HAR coverage**.
5. Choose a local HAR file from a normal authorised browsing session. Maximum size is **12 MiB / 12,000 entries**.
6. Click **1. Inspect HAR privacy locally**. Next click **2d. Inspect redirect boundaries (offline)**. Review the non-conclusive, fixed-category findings.
7. To compare captures: select a second HAR; click **4. Inspect second HAR privacy locally**, declare the five comparability factors, then click **5. Compare two reviewed HARs (offline)**. Scroll to **Offline redirect-boundary comparison**.
8. You can download redacted JSON and CSV reports. Your original HAR file is not persisted by the new analyser.

Use the included `tests\v76-redirect-baseline.har` and `tests\v76-redirect-comparison.har` for demonstration. They use fictional `.invalid` domains and non-functional signing strings.

## Automated tests

From the unpacked extension root:

```bat
node tests\test_v76_redirect_boundaries.cjs
node tests\test_v76_wiring.cjs
node tests\v76_redirect_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

**Local results:** 131/131 Node.js suites passed, 71/71 top-level JavaScript files passed `node --check`, and the synthetic two-HAR demonstration reported the expected fixed-category comparison. The ZIP's checksum/integrity and manifest version are checked during packaging.

## Privacy and interpretation

URLs and header values from the selected local HAR are inspected **transiently in memory** to resolve redirect matches. They are **never output** in the new report. This includes source/destination hostnames, paths, query values, signatures, cookies, bearer tokens, asset IDs, filenames, request IDs, traces, exact timestamps, POST values and response bodies. The original HAR could nevertheless contain sensitive information; keep it private and use Chrome's sanitised export where appropriate.

This analysis can **link a redirect response to a unique later HAR request with the same destination**, but cannot prove the browser navigation was causally triggered by that redirect, verify CDN configuration, establish public access, infer a user's permissions, prove a media original is accessible, or establish a disk download completed. If the HAR omits, sanitises, coalesces or reorders requests, the link may be missing or ambiguous. Some browsers strip `Authorization` and `Cookie` fields from HAR exports: **"No authentication indicator observed" does not mean unauthenticated**.

The HTTPS→HTTP category flags an observable scheme change requiring contextual review; it does not establish credential transmission or exploitation. Differences between HARs are not evidence of a vulnerability, revocation failure or delivery-policy change unless collection contexts are comparable and corroborating owner-side tests are available.

All previous v7.5 HAR access, media policy and workflow analyses; v5.7 platform-specialist recognition; capture diagnostics; download observer; secret redaction; Evidence Vault and imaging modules remain packaged.

**Not verified:** complete installed-Chrome startup, dashboard interaction, live worker/DevTools capture, Evidence Vault persistence and Windows desktop notifications in this environment. Verify the new page locally with the synthetic HARs before applying to production archives.
