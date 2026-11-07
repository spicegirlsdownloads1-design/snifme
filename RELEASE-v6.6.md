# Trufflehog Intelligence v6.6 — Evidence-Weighted DAM Review

**24 October 2026 · Chrome Manifest V3 · entirely offline synthesis · no additional permissions**

## What this release adds

The new **Security → Evidence-weighted review** combines the three distinct comparison layers already available in v6.3–v6.5:

1. **v6.4 comparison readiness:** five fixed operator-declared context questions (account/role context; browser actions; gallery/asset/search scope; Chrome host grants; early DevTools visibility).
2. **v6.5 observed workflow patterns:** HTTP request-category compositions, four approximate completion-order quarters, sampling and chronological gaps.
3. **v6.3 DAM delivery-policy comparison:** per-1,000 observed media/API/overall request rates for 2xx media, 401/403 media, signed-delivery clues, long public cache TTL, attachment responses and credential-like API query-key classes.

This is a *review prioritisation aid*, not a scanner claiming policy breaches. The default interpretation remains strictly descriptive.

### Context and coverage gates

- Operator-declared differences or an empty capture **block comparisons as equivalent**.
- Material differences in observed HTTP request composition **block attributing recorded policy differences** to a change in access controls.
- Incomplete saved segments, dropped events, unknown comparison context, fewer than 40 captured requests or incomplete HTTP timestamps are explicitly surfaced.
- A difference of **100 per 1,000 observations** (10 percentage points) may be flagged for owner review if the relevant metric has at least **20 observations in each denominator**. This is a pragmatic triage threshold, **not a statistical-significance test** and not proof that a security rule changed.
- Even an operator-declared matching context and identical coarse HTTP patterns do not prove identical account privileges, licences, browsing actions, assets or server-side policy.
- Any changed setting or capture selection immediately invalidates the previous displayed report.

## Privacy and operation

The new synthesis reads **only previously saved Evidence Vault captures**, creates **zero web requests**, and does not inspect private endpoints or test protected downloads. It returns fixed category/status labels, operator fixed-choice status, numeric aggregate counts/rates, qualitative limitations, and fixed owner-review suggestions. Its standalone JSON/CSV reports do **not** include site origins, hostnames, asset identifiers, request IDs, trace IDs, complete URLs, tokens, signatures, POST values or image contents.

No operator free-text is accepted or persisted in this module. Answers exist in the current dashboard instance and are not saved to Chrome storage.

**Important:** Existing full Evidence Vault archives and legacy general-purpose exports retain their prior formats and may include URL metadata. The strict new-export guarantee applies to *this* dedicated v6.6 report, not to all legacy export functions.

## How to use on Windows

1. Back up saved investigations. Unzip the new release over the **same unpacked extension directory**; do not uninstall the previous build. Click **Reload** in `chrome://extensions`.
2. Record and stop **two separate authorised browsing sessions from exactly the same site origin**. Make the browsing actions as comparable as practicable.
3. Open the dashboard and choose **Security → Evidence-weighted review**.
4. Select the baseline and comparison Evidence Vault groups. Answer the five context questions; **Not confirmed** is a valid answer and lowers interpretability.
5. Click **Run evidence-weighted review**. Read the overall classification, six DAM observation indicators, context declarations, and limitations. Export the dedicated redacted JSON or CSV if useful.
6. Verify apparent changes using authorised administrative records or owner-approved tests. A suspicious finding is *not* proof of a leaked high-resolution file, invalid authentication, or a breached licence boundary.

## Offline validation

Run from inside `Trufflehog-Intelligence`:

```bat
node tests\test_v66_synthesis.cjs
node tests\test_v66_wiring.cjs
node tests\v66_synthesis_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

Inside a `.bat` file, use `%%f` rather than `%f`.

**Known limitation:** full installed-Chrome MV3/DevTools/IndexedDB integration and desktop notifications have not been validated in this build environment. Node.js unit tests and static source checks do not certify complete real-browser operation.
