# Trufflehog Intelligence v6.7 — Independent HAR Coverage Reconciliation

**24 October 2026 · Chrome Manifest V3 · entirely offline · no new permissions**

## Why this release exists

Earlier releases introduced a deterministic localhost capture benchmark and several evidence-comparison modules. However, a full installed-Chrome acceptance run remains unverified in this environment. v6.7 adds an **independent browser HAR cross-check** so investigators can see when the extension's saved capture disagrees with Chrome DevTools' separately exported network log. Both have visibility limits.

## New workspace: Overview → Independent HAR coverage

1. Record and stop one **authorised** browsing session in Trufflehog. Open DevTools before the site reload so both observers have an opportunity to see the same traffic.
2. In Chrome DevTools **Network**, preserve the network log as appropriate, perform normal browsing, then save the session as a **sanitised HAR** where Chrome offers that option. HAR files can contain credentials and request bodies. Keep them private.
3. Open the extension dashboard, select **Overview → Independent HAR coverage**, select the saved capture group, and choose the corresponding HAR.
4. Click **Reconcile HAR with capture**. The tool checks method + sanitised URL + HTTP status, then performs a weaker status-different match on method + sanitised URL.
5. Inspect HAR-only, capture-only, and status-different observations by coarse type (Documents, Scripts, Styles, API reads/writes, Images, Other media, Downloads, Other). Export the dedicated strictly redacted JSON/CSV as needed.

**Limitations:** URL sanitisation can merge distinct signed URLs or cursor requests; URL matching cannot prove event identity, request cause or total network coverage. HAR may omit browser cache hits and requests outside the DevTools window, and this extension may omit browser-internal requests or requests without granted permissions. Timestamps can differ because HAR stores request initiation whereas extension requests are generally observed on completion. A high match rate therefore does **not** prove capture completeness.

## Privacy and safety

- The imported file is parsed locally in dashboard memory and is **not** uploaded, stored in IndexedDB, included in JSON/CSV exports, or transmitted to remote services.
- Maximum 12 MB HAR file at the file selector; up to 12,000 HAR entries, 12,000 saved request entries, and 40 saved segments. Exceeding those limits is reported.
- The tool ignores HAR request/response bodies, raw headers, cookies, local download paths, credential values, and trace identifiers. It compares method + sanitized URL + status only transiently, then outputs **fixed categorical labels and numeric totals**.
- Raw captured evidence, legacy full Evidence Vault archives and original HAR files have different privacy characteristics; this guarantee applies only to the new HAR reconciliation report.
- The module uses no new Chrome permissions and makes **zero requests** to investigated websites. It cannot validate authentication, test private downloads or retrieve protected assets.

## Windows local test

1. Back up Evidence Vault before extracting the new ZIP **over the same unpacked extension directory**; reload on `chrome://extensions`.
2. Start the existing safe loopback lab: `py tests\v60_benchmark.py`. Open `http://127.0.0.1:8770/v60-lab.html` with DevTools Network open; record a session and save the HAR.
3. Stop and save the Trufflehog capture, then run the new reconciliation view against the saved HAR. Compare results and review warnings.
4. Stop the fixture with Ctrl+C. No outside systems are contacted.

## Offline regression tests

```bat
node tests\test_v67_har_coverage.cjs
node tests\test_v67_wiring.cjs
node tests\v67_har_reconciliation_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

**Remaining limitation:** A full Windows installed-Chrome capture + DevTools + vault save/readback + notification acceptance run still needs to be performed locally. Node.js tests do not substitute for that run.
