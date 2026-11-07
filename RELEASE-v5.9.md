# Trufflehog Intelligence 5.9.0 — Case Change Review

**24 October 2026 · read-only/offline comparison · no new Chrome permissions**

## Purpose

Add evidence-based comparison of **two separately saved capture groups of the same website origin**. v5.8 already generates individual case dossiers and optional encrypted exports; v5.9 builds an offline cross-capture review while retaining every earlier workspace, scan and alert.

## New dashboard: Evidence Vault → Case change review

1. Stop and save two separate investigation groups on the same site. Reload the Dashboard and select the new **Case change review** tab.
2. Choose a reference group and a comparison group. **Compare saved case evidence** reads them from local IndexedDB; it does not contact the sites.
3. Review numeric changes in recorded 2xx, 4xx and 5xx responses; masked findings (including locally flagged changed indicators); completed/interrupted browser downloads; media responses; signed-query indicators; public-cache media response observations with TTL ≥ 24 hours; and image-byte verifications.
4. Review DAM platform confidence shifts, such as **newly observed** or **not observed later; absence unverified**. The engine uses the current fixed v5.7 DAM specialist definitions; it never proves ownership or platform removal.
5. Look at the capture-coverage warnings for incomplete DevTools scan coverage, missing numbered segments, records dropped, unfinalized captures or capped CDN-policy analysis.
6. Export a **redacted JSON comparison with SHA-256 integrity digest** or a **redacted metrics CSV**. The digest detects modifications, **not source authenticity**.

## Privacy and scope

- No request or response bodies, credentials, cookies, authentication/signature values, API response field values, asset IDs, local filenames, request identifiers, private CDN hostnames or complete URLs are included in the new comparison report.
- The **site origin hostname** is retained solely to identify the site being compared.
- Comparisons are strictly **same-origin** and **different saved capture-group**; different-origin comparisons are rejected rather than misrepresented as site configuration changes.
- Every exported difference is a numeric count or a predefined safe observation label. No custom profile strings or private response-field names enter the new exports.
- Media policy analysis uses a maximum of 4,000 recorded requests per segment; rolled-over `carriedFromSegment` entries are excluded from policy counts to avoid double counting. Truncated coverage receives a warning.
- Presence of a signed query or a 2xx browser delivery **does not** prove that a download is publicly available or that a protected original is accessible.
- Fewer recorded findings does not prove remediation, and more 4xx responses does not imply an authorisation defect. Different navigation, session state, cache, host permissions and DevTools start time can all change recorded counts.
- The Case Change Review does **not** request URLs, inspect other users' assets, test credentials, replay downloads, remove watermarks, create new media variants or change server-side permissions.

## Offline developer checks

From the extracted extension folder:

```bat
node tests\test_v59_case_compare.cjs
node tests\test_v59_wiring.cjs
node tests\case_drift_demo.cjs
```

Run every regression suite:

```bat
for %f in (tests\test*.cjs) do @node "%f"
```

The new module is `case_compare.js`. Dependencies are loaded in order in `dashboard.html`: `dam_delivery_policy.js`, `dam_specialists.js`, `case_intel.js`, `case_crypto.js`, `case_compare.js`, `dashboard.js`.

## Windows installation

1. Back up important Evidence Vault investigations; existing backups can contain sensitive URLs or asset references, so handle them appropriately.
2. Unzip into the **same unpacked Chrome extension directory**, overwriting old files; **do not uninstall** the extension if preserving its existing IndexedDB data.
3. Select **Reload** in `chrome://extensions`. Open the dashboard → Evidence Vault → **Case change review**.
4. Capture two normal browsing sessions on the same site where you have authorisation, then stop/save and compare. A capture from a different site should be rejected.
5. Export JSON and CSV and inspect them to confirm their intended redaction and count-based conclusions.

## Known limitations

The results of offline Node.js suites, static syntax checks and ZIP integrity do **not** demonstrate that the Chrome MV3 worker, DevTools forwarding, IndexedDB persistence, the dashboard UI or Windows notifications work in an installed Chrome browser. **Full installed-Chrome acceptance remains unverified**. The next practical step is using the included v5.0 Windows acceptance fixture and inspecting failures before relying on unattended capture.
