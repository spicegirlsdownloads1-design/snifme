# Trufflehog Intelligence v6.2 — DAM Security Review Matrix

**24 October 2026 | Chrome Manifest V3 | no new permissions**

## What changed

- New **Security → DAM security matrix**, combining recognised platform clues with passive HTTP evidence.
- Site-wide auth-query indicators, signed media, 401/403 media responses, public cache TTL of 24 hours or more, and download attachments are counted separately.
- Explicit separation of **site-wide observations** from **vendor-associated host traffic** prevents falsely attributing CDN/request behaviours to a named DAM.
- Recognised Capture, ResourceSpace, PhotoShelter, Bynder, Cloudinary, Canto and FotoWare clues receive fixed, platform-specific owner-review checklists.
- Every row shows sample size, evidence scope, limitations and next verification step. **Not observed** never means secure or absent.
- Bounded, redacted JSON and CSV reports. No source URLs, endpoints, POST values, tokens, account IDs, hostnames, signed URLs or media contents included in this *new matrix report*.
- Uses existing saved capture data only; no network calls, host permission changes, replay or download operations.

## Use in Windows Chrome

1. Back up Evidence Vault; replace your existing unpacked extension files with this release without removing the extension, then reload at `chrome://extensions`.
2. Record an authorised site normally. Opening DevTools before page load helps existing optional response-shape/secret scanning, but the new matrix uses saved HTTP metadata.
3. Open **Security → DAM security matrix** and distinguish the site-wide rows from vendor-specific findings.
4. Export the dedicated **security matrix (redacted JSON)** or use the current-view **CSV** export.
5. Verify relevant settings using administrative access to your *own* DAM system; the tool cannot establish actual authorisation, original file availability, CDN origin restrictions or software patch status.

## Testing and limitations

`node tests\test_v62_dam_review.cjs` and `node tests\test_v62_wiring.cjs`. Run the offline demonstration with `node tests\v62_dam_review_demo.cjs` (no network traffic). Run all tests using `for %f in (tests\test*.cjs) do @node "%f"` from Command Prompt.

Tests are simulated. Full installed-Chrome capture and notification behaviour remains **unverified** until tested on the user's Windows system. Existing broader exports may contain URL metadata; the new standalone matrix has stronger output restrictions.
