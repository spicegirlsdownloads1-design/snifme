# Trufflehog Intelligence v6.9 — HAR Privacy Preflight

**24 October 2026 · Chrome Manifest V3 · local inspection only · no new permissions**

## What changed

The **Overview → Independent HAR coverage** view now adds a mandatory local privacy preflight before a HAR can be reconciled with saved Trufflehog capture evidence.

- Detects the **presence**, not the values, of credential-related header names, cookies, URL query strings, signature-like parameter names, URL userinfo, request forms/bodies, response body text, redirect headers, trace/request correlation fields and HAR page metadata.
- Returns **fixed category labels and numerical counts**. It never includes a source-derived URL, hostname, header value, cookie, trace identifier, signature, original body, filename, post field name or source string in the **new v6.9 preflight report**.
- Supports privacy preflight even with **no Evidence Vault capture saved yet**.
- Requires a review of the **selected** HAR before reconciling it with a saved capture; changing the file resets that review. The reconciliation action separately re-parses and re-audits the file before processing.
- Exports numerical **privacy-report JSON** and **privacy counts CSV**, alongside the existing v6.7/6.8 coverage and triage reports.
- Bounded to 12 MB file selection and 12,000 HAR entries; excludes non-HTTP entries and reports malformed entries.
- Does not read unrelated files, contact sites, replay requests, fetch credentials or store imported HARs in the Evidence Vault.

## Use on Windows Chrome

1. Make an Evidence Vault backup before upgrading. Keep the **same unpacked extension folder** to preserve Chrome extension local storage and extension identity. Extract v6.9 over it and click **Reload** at `chrome://extensions`.
2. For a browser-network comparison, record an authorised browsing session. Open DevTools **before** navigation and use Network → Export HAR (sanitised), where offered.
3. In the dashboard open **Overview → Independent HAR coverage**, select the HAR, and click **1. Inspect HAR privacy locally**. A saved capture is **not** required for this check.
4. Review the numeric counts and cautions. Keep the original HAR private.
5. If you have a saved capture, select the matching group and click **2. Reconcile reviewed HAR with capture**.
6. Review **Same-site versus external-origin coverage** and the older **Run offline coverage triage** results as needed.
7. Export the numeric report if useful. **Never assume the original HAR is safe to share based on a zero-count or Chrome's default sanitisation.**

## Tests

From inside the unpacked `Trufflehog-Intelligence` folder:

```bat
node tests\test_v69_har_privacy.cjs
node tests\test_v69_wiring.cjs
node tests\v69_har_privacy_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

**Validation performed here:** 117 of 117 Node.js test suites passed; 64 top-level JavaScript syntax checks passed; synthetic privacy-report demo passed; ZIP manifest and archive checked.

**Important remaining limitation:** full installed Chrome MV3 service-worker, DevTools, dashboard/UI, local Evidence Vault and Windows notification integration have *not* been successfully verified in this build environment. A packaged working test suite is not proof of a complete browser workflow.

## Interpretation and security limitations

- The preflight checks **structures** and known field-name categories, not sensitive text within arbitrary bodies, header values or filenames. A negative result does not certify a HAR as shareable.
- The selected HAR is parsed in browser memory and is not written to the Evidence Vault or report export, but its input File handle remains available to the browser until changed or the dashboard closes.
- Legacy full Evidence Vault exports and third-party HAR files have **different privacy characteristics**. The strict redaction guarantee here applies only to **new v6.9 privacy preflight exports**.
- HAR reconciliation compares sanitised URL/method/status identities and can conflate distinct requests; neither observer has complete coverage.
- This update preserves the previously packaged DAM specialists, authenticated-download observer, AWS DAM intelligence, asset-quality ledger, upload protocol observations, comparison readiness and reporting tools.
