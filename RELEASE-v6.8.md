# Trufflehog Intelligence v6.8 — Independent HAR Gap Triage

**24 October 2026 · Chrome Manifest V3 · local and passive · no additional permissions**

## Purpose

v6.7 compared saved Trufflehog network observations with a separately exported Chrome DevTools HAR, but reported mostly counts. v6.8 helps an investigator identify **what to check next** when those limited data sources disagree. The analysis **cannot establish actual server activity, security vulnerabilities, or total network completeness**.

## Changes

- **Origin-scope comparison:** HAR-only and capture-only observations are counted separately for the selected site's own origin and for external origins (including observed CDN/API services), without exporting any origin or hostnames in the HAR reconciliation report.
- **Repeated request identity warning:** repeated method/sanitised-URL keys are counted to highlight ambiguous 1:1 matching; no raw URLs, query values, cookies or signatures are persisted.
- **Gap triage:** fixed labels and suggested follow-up checks for incomplete sessions, dropped records, disjoint timestamps, statuses that differ, missing external-origin observations, repeated identities and the five most affected request categories.
- **Optional context questions:** whether the traces describe the same session/actions, DevTools was opened before navigation, Preserve log was enabled and the same website access/host permissions applied. All questions default to **Not confirmed**; declarations are not treated as browser verification.
- **Strictly redacted report export:** separate triage JSON and CSV output with only fixed category/status labels, numeric counts and fixed advice. The imported HAR remains in dashboard memory only during comparison.
- **No new permissions or background requests.** Prior features from v2.x–v6.7 are preserved.

## Windows usage

1. Back up important existing Evidence Vault investigations. Extract v6.8 over the **same** previously loaded unpacked extension directory and select **Reload** in `chrome://extensions`. Replacing files in place helps preserve existing local storage and extension identity; removing the extension can delete its local data.
2. On a site you are authorised to inspect, open Chrome DevTools > Network **before** navigating to the target page. Consider enabling **Preserve log**, and make the relevant Chrome site/CDN permissions explicit.
3. Start Trufflehog's normal site capture and perform the browsing or permitted download workflow, then stop and save the capture.
4. In Chrome DevTools, **Export HAR (sanitized)**. Chrome's default sanitisation excludes some sensitive headers, but a HAR can still contain sensitive URL parameters, request/response bodies or filenames; treat even sanitised HAR files as private.
5. Open the dashboard **Overview → Independent HAR coverage**. Select the saved capture group and HAR file and click **Reconcile HAR with capture**.
6. Inspect **Same-site versus external-origin coverage**, fill in the context questions you can actually verify, then choose **Run offline coverage triage**. Use the resulting recommended checks to improve the next authorised capture.
7. Export numerical comparison or triage reports if needed. Do not share the original HAR or the legacy unredacted archive unless separately reviewed for sensitive contents.

## Demonstration without third-party traffic

Run the existing deterministic fixture:

```bat
py tests\v60_benchmark.py
```

Visit `http://127.0.0.1:8770/v60-lab.html` in Chrome, grant localhost site permission, open DevTools Network before reload, start capture and enable Download Observer. Follow the local fixture actions. Stop and save a Trufflehog capture, export a sanitised HAR from DevTools, then reconcile and triage as above. The fixture binds **127.0.0.1 only**.

A standalone deterministic offline demo can also be run with:

```bat
node tests\v68_triage_demo.cjs
```

## Implementation/test details

- Source modules: `har_coverage.js` (scope totals and repeated-identity counts), `har_triage.js` (categorical fixed-text recommendation engine), and the dashboard interface.
- Automated checks: `node tests\test_v68_triage.cjs` and `node tests\test_v68_wiring.cjs`; plus the full inherited `tests/test*.cjs` suite.
- Limits inherited from v6.7: maximum **12 MB** HAR import, **12,000** HAR entries, **12,000** compared saved requests, **40** saved segments. Reported counts are bounded.
- **No full installed Chrome integration test was completed in this build environment.** Local fixture, Node.js and syntax checks cannot substitute for the Windows browser acceptance run.

## Interpretation limits

- An unmatched HAR request isn't proof Trufflehog malfunctioned; DevTools and extension listeners see different subsets of browser activity.
- An unmatched saved capture isn't proof the HAR was exported incorrectly: differences in timestamps, cache, Network panel filters and recording windows matter.
- Matching redacted method/URL/status triples can conflate different requests, especially pagination, signed URLs and repeats. Matching does **not** prove causal linkage or permission equivalence.
- Operator answers are self-declared. Missing fields and host permissions can reduce visibility.
- The triage report doesn't read third-party servers, retrieve media masters, replay request signatures, or validate credentials.
