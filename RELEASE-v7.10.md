# Trufflehog Intelligence v7.10.0 — Universal Traffic Anatomy

24 October 2026 · Chrome Manifest V3 · generic-first, passive, local-only

## Universal sniffer, not a service-specific detector

The sniffer works on unknown and custom websites without identifying a DAM, CMS, gallery or CDN vendor. Platform recognition is an optional separate evidence view; no brand signature is required for the new generic analysis.

- **Network & APIs → Universal traffic anatomy** summarises the current permitted capture using 23 fixed categories: document, script, API read/write, media, cross-origin, HTTP status, signing-presence, cache, attachment and other already-observed clues.
- **Universal Research** is the default investigation recipe for new users; saved profile preferences remain unchanged. Gallery, DAM, CDN and Cross-Archive recipes remain available.
- The new aggregate report can be exported as JSON or CSV with fixed labels, bounded counts, caveats and no observed URLs, hosts, IDs, filenames, header or query values, request bodies or response contents.
- The report incorporates optional Download observer header-name and lifecycle *presence* indications. It distinguishes absence of evidence from a disabled or incomplete observer.
- Download workflow summaries additionally pair only genuinely matching opt-in start and terminal records. Lost or ambiguous lifecycle segments remain unlinked.
- Existing v7.9 offline HAR image content negotiation, v7.8 cache revalidation, privacy preflight, role-flow, sequence, byte-range and redirect-boundary tools are retained, along with earlier DAM specialist modules.

## Limits

- Only existing captured records are analysed: no additional network calls, endpoint guesses, key tests, signature replay, access-control circumvention, original-file retrieval or new Chrome permissions.
- Classification is descriptive. It does not prove a vulnerability, accessible source/master file, licence rights, security exposure, complete site inventory, causal linkage or server-side policy.
- The report samples up to 3,000 retained HTTP observations and 3,000 optional lifecycle events, warning on sample limits and existing dropped records. Earlier browser capture limits may be lower.
- Previous session/Vault exports retain their existing legacy data model; the strict redaction guarantee applies to this **new generic aggregate export**, not retroactively to all old backup formats.
- Native MV3/background service-worker, browser download attribution and Windows notification behaviour still require real Chrome verification.

## Install and use

1. Back up important local Evidence Vault material before upgrading.
2. Extract the full ZIP to your current unpacked extension folder and reload it from `chrome://extensions`; retaining the extension installation preserves its local Chrome storage.
3. Open a site you are authorised to inspect and start a capture. Browse normally; the inspector does not generate browsing traffic.
4. Select **Network & APIs → Universal traffic anatomy**. No service-specific identification is required.
5. For optional header-name and browser-download lifecycle observations, deliberately opt in to Download observer before repeating a permitted workflow.
6. Export the dedicated redacted JSON/CSV aggregate report if required.

## Development checks

Run `node --test tests/*.cjs` in the unpacked extension folder. New tests `test_v710_generic.cjs` and `test_v710_wiring.cjs` verify unknown-platform classification, redaction, bounds, fixed export categories, recipe defaults and no new permissions; `test_v573_download_lifecycle.cjs` verifies terminal-download matching.
