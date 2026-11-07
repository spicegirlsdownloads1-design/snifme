# Trufflehog Intelligence v7.8 — Offline Cache Revalidation Evidence

**24 October 2026 | Chrome Manifest V3 | additive upgrade from v7.7 | no additional Chrome permissions**

v7.8 adds a local, passive HTTP-cache validation observer to **Overview → Independent HAR coverage**. It builds on v7.7 byte-range, v7.6 redirect boundaries, v7.5 access evidence, v7.4 delivery policy, DAM-specialist profiles, the Download Observer, Evidence Vault, and all previous functionality.

## What's new

**2f. Inspect cache revalidation (offline)** recognises patterns in an *already-exported HAR*:

- `If-None-Match`, `If-Modified-Since`, and their concurrent presence, with the HTTP-standard precedence noted.
- Separately labels `If-Match`, `If-Unmodified-Since` and `If-Range` so upload/write preconditions and range requests aren't incorrectly classified as cache revalidation.
- `304 Not Modified`, `200` and `206` statuses when a conditional safe request is visible; `412 Precondition Failed` observations.
- ETag and weak ETag **presence**, `Last-Modified`, `Vary`, `Vary: *`, `Cache-Control`, `Age`, and observed HIT/MISS/BYPASS/DYNAMIC header categories.
- Counts 304 responses with a conditional request visible separately from 304 entries whose request headers are missing or do not show that condition.
- Reports the presence of `Age` beyond declared `s-maxage` or `max-age` as a *header-only review clue*, not a finding of misconfigured caching.
- Separately counts `304` for media MIME or file-suffix *clues* without interpreting the 304 as a downloaded image.
- Fixed-label redacted local JSON/CSV exports, with no URLs, hosts, IDs, time values, validators, ETags or header values.

**Two-HAR comparison:** run separate privacy preflights on both original files, declare the five comparability questions, then select **5. Compare two reviewed HARs (offline)**. The **Offline cache revalidation comparison** shows count/rate changes from the two reviewed captures. The two-HAR export is privacy-limited and carries no request-level identities.

## Windows testing

1. Back up your existing Evidence Vault data. Unzip v7.8 over the *same unpacked extension folder*, retaining Chrome's extension ID and local database. Do **not** uninstall the extension unless you have separately exported anything you need.
2. Visit `chrome://extensions`, use **Reload**, and open the dashboard.
3. Choose **Overview → Independent HAR coverage**.
4. Import a Chrome DevTools HAR from your own authorised activity, under **12 MiB**, with no more than **12,000 entries**. **Raw HARs can contain live authentication cookies, signed URLs, personal information and POST bodies. Never distribute them without an independent sanitisation process.**
5. Run **1. Inspect HAR privacy locally**, followed by **2f. Inspect cache revalidation (offline)**. Review the fixed-category results and export redacted JSON/CSV if useful.
6. For an offline demonstration, use `tests/v78-cache-baseline.har` and `tests/v78-cache-comparison.har`. They use fictional `.invalid` hosts and dummy query/header values. Do **not** open their URLs.
7. To compare, import the second HAR, run its own privacy check (**4**), answer the five comparability questions, then select **5**. Scroll to **Offline cache revalidation comparison**.

Run automated tests from the unpacked extension root in Command Prompt:

```bat
node tests\test_v78_cache_revalidation.cjs
node tests\test_v78_wiring.cjs
for %f in (tests\test*.cjs) do @node "%f"
```

## Security and interpretation boundaries

- All computations are local and on user-selected, already-captured HAR data. The module performs **no fetch, replay, probing, file download, credential test or URL construction**.
- The analyser examines no response bodies except for noting the *presence* of body text in an anomalous `304` HAR entry, whose content is never read or included.
- It does not save imported HAR files to IndexedDB, Chrome storage, the Evidence Vault or remote servers. Temporary raw data exists only while the dashboard processes the selected file. Existing other export features may have different privacy contracts.
- All output labels come from an internal allowlist, plus bounded counts, normalised rates, and exact three-valued comparison declarations (`yes`/`no`/`unknown`).
- `304` means the server (or a cache) validated a representation so a full response need not be retransmitted. **It is not evidence that bytes arrived**, an original is retrievable, a signed URL is still valid, a revoked asset remains accessible, or a licence was bypassed.
- Source HAR headers may be missing or sanitised; browser cache and service workers can make complete visibility impossible. Observed difference is not proof of different backend policy or exposure. The operator declarations control the interpretation of comparisons, not server actions.
- `Vary`, `ETag`, `Age` and CDN status flags are observed headers, not proof of cache configuration compliance. For HTTP semantics, see [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html), [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) and [MDN 304](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/304).

## Verification limitation

Node tests, syntax checks and ZIP integrity are run during release packaging. **Full installed-Chrome startup, actual DevTools capture, dashboard interaction, Windows notification delivery and IndexedDB persistence are not verified in this container**. Perform the installed-Chrome tests above before using the results operationally.
