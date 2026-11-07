# Trufflehog Intelligence v7.2 — Offline HAR Workflow Comparison

**24 October 2026 · Chrome Manifest V3 · no extra permissions · local file analysis**

This release builds on the v7.1 bounded HAR timeline. It adds **two-HAR stage difference analysis** using independently privacy-reviewed HARs. A saved Trufflehog capture is **not required**. Both HAR files stay in the local dashboard's memory; no upload, request replay, protected file access or credential validation occurs.

## New workflow: Overview → Independent HAR coverage

1. Select a first exported `.har` file (limit 12 MB / 12,000 entries). Run **1. Inspect HAR privacy locally**.
2. Optionally run the earlier single-HAR inventory (step 2) and timeline (step 3).
3. Select a **second HAR** file and run **4. Inspect second HAR privacy locally**.
4. Declare whether the HARs concern the same website, account/role, browsing actions, gallery/asset scope and equivalent DevTools/browser capture conditions. Each answer defaults to **Not confirmed**. These are user declarations, not browser-verified facts.
5. Run **5. Compare two reviewed HARs (offline)** and review stage counts, rates per 1,000 inspected HTTP entries, limited adjacency pattern counts and coverage warnings.
6. Export the bounded redacted JSON/CSV if useful. The existing **6. Reconcile reviewed HAR with capture** feature still works with a saved capture.

## Evidence limits

- Stage counts cover all eligible HTTP entries in each bounded HAR; display timelines and adjacency-pattern counts are limited to the **first 240 classified events**. The report warns when that limit was reached.
- A difference in recorded HTTP stages is **not evidence by itself** of DAM policy drift, a vulnerability, a real asset identity match, changed user permissions or a completed download.
- Comparability is downgraded for unknown or differing declared contexts, small sample sizes, missing/out-of-order HAR timestamps, excluded records, mismatched request volumes or timeline truncation.
- Exported stage reports include only fixed categorical labels, numeric counts/rates, predefined interpretations, and fixed guidance. No original site hosts, URLs, paths, headers, cookies, auth tokens, signing fields/values, timestamps, trace IDs or HAR-supplied strings appear in the **new comparison report**.
- Privacy preflight only reports risk categories and counts. **Never assume the raw HAR is safe to share**, even if preflight warnings are absent. Earlier extension exports have their own retention contracts.
- No extra Chrome permissions, new network requests or request bodies are collected for this feature.

## Offline test commands (Windows Command Prompt)

```bat
node tests\test_v72_har_compare.cjs
node tests\test_v72_wiring.cjs
node tests\v72_har_compare_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

Fixtures use fictional `.example` hostnames, dummy credentials and synthetic HTTP events. Test outcomes do not prove full installed-Chrome/DevTools/IndexedDB integration, which remains unverified in the available container.

Back up Evidence Vault data, extract over the existing unpacked extension folder, and reload using `chrome://extensions` instead of uninstalling the extension.
