# Trufflehog Intelligence v7.4 — Offline Asset Delivery Policy Comparison

**24 October 2026 · Chrome Manifest V3 · local-only / read-only HAR analysis · no new Chrome permissions**

## What is new

The existing **Overview → Independent HAR coverage** workspace gains:

1. **2b. Inspect delivery policies (offline)** — analyse a single locally selected HAR, but only after **1. Inspect HAR privacy locally** has been run for the exact selected file.
2. **Observed delivery policy and signing differences** — a policy comparison panel displayed by the existing **5. Compare two reviewed HARs (offline)**, after both HARs have passed separate local privacy preflights.
3. Redacted JSON exports for the individual inventory and two-HAR comparison, plus a redacted delivery-comparison CSV.

The new analysis distinguishes observed media MIME responses from attachments and media-looking request paths used only to classify 401/403 errors or redirects. It records only fixed-label counts for:

- Image/media response MIME, attachments, inline disposition, partial `206`, denied `401/403` and media redirect `3xx`.
- Presence of signing-parameter **names**, AWS/Google signing scheme names, expiry-field names, authentication and cookie headers **without retaining values**.
- Response cache directives (`public`, `private`, `no-store`, `no-cache`, `immutable`), broad `max-age` / `s-maxage` duration bins, CDN cache `HIT` / `MISS` / `BYPASS` / `DYNAMIC`, and relevant header gaps.
- **Owner-review combinations** where a delivered media/attachment response has `Cache-Control: public` alongside a signing-name clue, `Authorization` header or session cookie in the request. These are **not vulnerability claims**.
- Two-HAR counts and normalised rates per 1,000 HTTP entries and per 1,000 delivery-relevant entries. The two-HAR workflow retains the five explicit comparability declarations from v7.2.

Every metric is a count of things *observed in the supplied HAR*. A response observed in an authenticated browser does not prove anonymous/public file access, improper entitlement, leaked original, CDN revocation failure, or successful disk download. No alternate URLs, unauthorised GETs or replayable signatures are generated.

## Privacy contract

Original HAR files are sensitive, even when Chrome offers a sanitised export. In the new analysis, the original content stays in local browser memory during the operation. **The new reports contain fixed labels and numbers only.** They exclude source hosts, URLs, query/POST values, path segments, image IDs, file names, response bodies, tokens, cookies, signatures, exact timestamps, trace IDs and request IDs. The structural preflight is not a guarantee that any original HAR is safe to share.

Other legacy views and full-session exports have separate privacy semantics; this contract covers only the new v7.4 inventory and comparison reports.

## Upgrade steps (Windows / Chrome)

1. Export/back up any investigations saved in Evidence Vault.
2. Extract `Trufflehog-Intelligence-v7.4.0.zip` over the **same unpacked extension directory** used for v7.3. Do not uninstall/re-add the extension when you want its current local storage to remain associated with the same extension ID.
3. Open `chrome://extensions` and click **Reload** for Trufflehog Intelligence.
4. Open the Trufflehog dashboard → **Overview → Independent HAR coverage**.
5. Choose a HAR (12 MB and 12,000 entries maximum) from authorised browsing, and click **1. Inspect HAR privacy locally**.
6. Click **2b. Inspect delivery policies (offline)**. Review fixed-label counts and the non-conclusive owner-review combinations; export redacted JSON if useful.
7. For changes across two HARs, select a second HAR, run **4. Inspect second HAR privacy locally**, complete the existing five context questions, and click **5. Compare two reviewed HARs (offline)**. Scroll to **Observed delivery policy and signing differences**. Use the new redacted JSON/CSV exports if needed.

Changing either selected HAR invalidates its review. Nothing about this mode requires a new host permission, API credential, download entitlement, external API access or a saved Evidence Vault capture.

## Offline test and demonstration

In Command Prompt, from inside the unpacked `Trufflehog-Intelligence` folder:

```bat
node tests\test_v74_delivery_posture.cjs
node tests\test_v74_wiring.cjs
node tests\v74_delivery_demo.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

Import the included `tests\v74-delivery-baseline.har` and `tests\v74-delivery-comparison.har` via the dashboard to check the review gates and comparison UI. The HARs contain **fictional hostnames and deliberately fake signing strings**; neither points to any actual agency or S3 bucket.

**Automated verification:** 127 / 127 Node.js suites passed; 69 / 69 top-level JavaScript source files passed `node --check`. The signed URL/caching/attachment/denial comparison tests, privacy tests and ZIP integrity checks passed. Full installed-Chrome dashboard interaction, background-worker capture, DevTools scanning, Windows notifications and Evidence Vault persistence **remain unverified** in this environment. These tests establish local component behaviour, not complete installed-extension operation.

## Evidence limitations and false positives

- Cache directives are response metadata; CDN-specific infrastructure may interpret or override them. Client-observed responses do not establish origin or revocation controls.
- `public` cache control alongside a signed query *name*, `Authorization` or `Cookie` can be intentional and secure; classify as **owner-side review**, not exposure.
- Some 401/403 and redirect responses use HTML/no MIME. Recognising a media filename suffix in the request helps classify their HTTP status, but does not prove that a media file exists or was accessible.
- Browser HARs may omit response bodies, in-memory cached requests, worker activity, redirects or download-completion events. Missing or changed counts are not proof of increased/decreased security.
- Custom CDN and DAM domains are not reliably identifiable by hostname. Cross-HAR comparison still requires matching site, account, actions, asset scope and browser capture conditions.
