# Trufflehog Intelligence v6.4 — DAM Capture Comparison Readiness

24 October 2026 · Chrome Manifest V3 · no additional permissions · no network requests for comparison

## What this fixes

v6.3 provides same-site DAM/CDN delivery policy comparisons, but **two captures from the same origin do not automatically represent the same account privileges, gallery/asset scope, browser permissions or workflow**. This release adds a dedicated context and coverage gate to help prevent misleading security conclusions when interpreting cross-capture changes.

## New dashboard: Security → Comparison readiness

1. Capture and save two sessions as separate Evidence Vault groups, preferably after repeating an equivalent set of approved browsing actions.
2. Go to **Security → Comparison readiness**. Select the baseline and comparison capture groups from the saved groups.
3. Use five fixed-choice, **operator-declared** questions: (a) same role/account context, (b) same browsing or download actions, (c) same asset/gallery/filter/search scope, (d) same Chrome site/CDN grants, and (e) whether DevTools was already open before load in *both* captures. “Not confirmed” is valid; the tool does not assume yes.
4. Click **Assess comparison readiness**. The analyzer compares the already-saved requests, media/API request mixes, capture-group segmentation and retention gaps. It does not compare asset identifiers, raw API paths or secret values.
5. Interpret the classification **Do not compare as equivalent**, **Limited descriptive comparison**, or **Operator-declared matching context**. Even the latter is **not a verified security-policy comparison**.
6. Export the **strictly redacted JSON** report or the fixed-choice context CSV, then, if appropriate, open **Security → DAM policy comparison**. That existing view now includes a shortcut to readiness assessment.

## Logic and evidence boundaries

- Rejects different site origins or two selections of the same saved capture group.
- Operator-reported role/workflow/gallery/host-grant differences and missing early DevTools coverage **block equivalent-context interpretations**; unknown answers are limitations.
- Flags blank request lists, fewer than 20 requests in a group, request-volume differences exceeding 3×, large (over 25 percentage point) differences in API/media composition, dropped records, truncated segment sampling, missing sequence numbers and unfinalised sessions.
- Request similarity is only one clue; the tool cannot determine whether two accounts truly have the same role, whether the same assets appeared, or whether cache or access policies changed.
- No free-form identity or account notes, credentials, asset IDs, source URLs, tokens, trace IDs, full hostnames or request bodies enter the **new reports**. Context answers are held in dashboard memory only, not Chrome storage or Evidence Vault.
- Existing Evidence Vault and older general-purpose exports retain their own established privacy characteristics; the strict allowlist guarantee applies to the **new** comparison-readiness report.

## Windows installation

1. Back up important Evidence Vault investigations (legacy full backups can contain sensitive URLs and other captured metadata).
2. Extract the ZIP into the **same already-installed unpacked extension directory** and overwrite the existing files. Uninstalling first can change extension identity and lose local data.
3. Go to `chrome://extensions` and click **Reload**.
4. Capture two ordinary, authorised sessions and save them. Open **Security → Comparison readiness** and follow the steps above.
5. Use **Refresh saved groups** if the two captures do not appear. Only comparable same-origin groups pass the comparison engine.

## Offline verification

```bat
node tests\test_v64_readiness.cjs
node tests\test_v64_wiring.cjs
node tests\v64_readiness_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

No new Chrome permissions or active probing are introduced. The pre-existing DevTools scanning, masked alerts, browser download observer, upload protocol analysis, DAM specialists, image rendition comparisons and case features remain installed.

**Known limitation:** The complete Windows installed-Chrome/DevTools/IndexedDB integration workflow has not been verified from the development environment. Offline test passes and a loadable ZIP cannot certify operational capture or Windows desktop notification delivery.
