# Trufflehog Intelligence v6.5 — Observed Workflow Pattern Comparison

24 October 2026 · Chrome Manifest V3 · **no new permissions or outbound requests**.

## Why this release

Two saved captures of the same DAM or gallery can have different browsing actions, browser caching, filters and visible API requests. v6.4 asks the user to state whether the contexts were comparable; **v6.5 adds an independent, browser-observed coarse HTTP-traffic pattern comparison**. It does not claim to prove the same account, licence permissions, asset set, or user workflow.

## New view: Security → Observed workflow patterns

1. Record and stop two separate, normal authorised browser sessions from the same website origin.
2. Open **Security → Observed workflow patterns** in the extension dashboard.
3. Select baseline and comparison Evidence Vault capture groups.
4. Click **Compare observed patterns** to examine request categories, category shares, and four sequential phases based on HTTP completion times (or record order if timestamps are incomplete).
5. Review the percentage-point shifts, capture gaps and warnings. An exact match is only a match of *observed request categories*, not proof that the same workflow or access controls were applied.
6. Export strictly allowlisted redacted JSON/CSV reports, or open **Security → Comparison readiness**. That older v6.4 view now shows the coarse pattern assessment and cautions if materially different traffic was observed.

### Bounded evidence model

- Distinguishes Documents, Scripts, Styles, API reads, API writes, Images, Other media, Downloads and Other request categories.
- Measures distribution differences as percent distance. Four approximate chronological quarters are based on request **completion** timestamps; time order is not causation or a reconstruction of user clicks.
- Comparisons with under 40 observations per capture show *Insufficient captured observations*.
- Reports incomplete timestamps, missing segments, dropped records, unfinished captures, insufficient samples and analysis caps. A missing request is never evidence that a request did not happen.
- Does **not** read request or response bodies, access credentials, query strings, cookies, filenames, API routes, image bytes, trace IDs, account information or full hostnames. Only fixed category labels and numeric totals leave the new module. Raw legacy Evidence Vault backups have their own privacy characteristics.
- No extra requests, role testing, credential validation, master-image access attempts, access-control checks or Chrome permissions are added.

## Windows installation

Back up important investigations. Unzip over the **same existing unpacked extension folder**; do not uninstall, as this can lose the stored extension ID and its IndexedDB data. Reload through `chrome://extensions`.

## Test commands

```bat
node tests\test_v65_patterns.cjs
node tests\test_v65_wiring.cjs
node tests\v65_pattern_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

The new analysis runs entirely on previously saved sessions. It needs no live website fixture.

**Known limitation:** Chrome MV3 background/DevTools integration and Windows notification delivery have not been end-to-end validated in this development environment. Passing Node.js suites cannot prove installed-Chrome operation.
