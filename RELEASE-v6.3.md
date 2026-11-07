# Trufflehog Intelligence v6.3 — DAM Delivery Policy Comparison

**24 October 2026 · passive/offline · Chrome Manifest V3 · no new permissions**

## What changed

- **Security → DAM policy comparison** compares two separate saved Evidence Vault capture groups from the **same exact origin**.
- Reads **already-observed request metadata** only; never issues a new request, guesses a URL, verifies a signature, repeats a download, or tests an access-control boundary.
- Compares six categories: successful media delivery; 401/403 media responses; signed-media indicators; publicly cacheable media with a TTL of at least 24 hours; successful downloadable attachments; and API query-parameter classes associated with possible credentials.
- Includes raw counts and rates **per 1,000 relevant recorded requests** (media, API or all requests) so differently sized captures are not compared solely through absolute counts.
- Distinguishes **small samples** (fewer than 20 relevant requests in either session), **no sample**, and **descriptive rates**. Differences are observations, never proof of a vulnerability, permission change, public original, licensed download, or CDN revocation failure.
- Flags bounded capture records, missing segment indices, unfinalized segments, dropped-event counters and missing request lists. Ignores carried-forward request records to avoid double-counting them.
- Dedicated **redacted JSON export** and built-in CSV for this new view. The new reports contain fixed labels and numeric summaries; no raw source URLs, hostnames, token-bearing queries, asset IDs, session IDs, signing values or file contents.
- Retains the previously built **DAM specialists (v5.7)**, **case dossier/encrypted backups (v5.8)**, **same-site case changes (v5.9)**, **local benchmark (v6.0)**, **capture repair (v6.1)** and **DAM security matrix (v6.2)**.

## Windows installation

1. Export existing Evidence Vault investigations.
2. Extract ZIP contents over the current unpacked extension files without uninstalling the extension, then reload at `chrome://extensions`.
3. Capture two normal browsing sessions on the same approved website. Save the two investigations as separate groups using Evidence Vault.
4. Open **Security → DAM policy comparison**; click **Refresh saved groups** if necessary.
5. Select baseline and comparison groups, then **Compare DAM policy evidence**.
6. Review sample denominators and coverage warnings **before** interpreting any difference. Export JSON or CSV for offline operator review.

## Offline tests

Run in the extracted `Trufflehog-Intelligence` directory:

```bat
node tests\test_v63_policy_drift.cjs
node tests\test_v63_wiring.cjs
node tests\v63_policy_drift_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

For the full JavaScript syntax check in a Unix-like shell: `for f in *.js; do node --check "$f"; done`.

## Important limits

- Passively observed `2xx`/`403` statuses apply only to the logged-in browsing context that made those requests. They do not establish anonymous accessibility, actual entitlement or master-file quality.
- Matching site origins do not prove that the user visited the same gallery, filtered the same assets or used the same account/role in both sessions.
- The analysis cannot confirm whether cache invalidation works, whether an expired link is unusable, or whether backing storage enforces access controls.
- Existing broader session exports may contain normal metadata according to their established semantics; the **new v6.3 report** is intentionally more restrictive.
- Full installed-Chrome, DevTools and Windows-notification integration still requires local testing; Node regression tests alone do not certify it.
