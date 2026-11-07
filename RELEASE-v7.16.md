# v7.16.0 — Generic Product / Asset Correlation and Hybrid Workflows

Built on v7.15.0 with no additional Chrome permissions.

- Added `product_asset_intel.js`: bounded vendor-agnostic product, category, variant, price, publishing/localisation and explicit media reference classification. Inspects only permitted DevTools-observed JSON (max 256KB); captures no response bodies or credential values.
- Added `PIM_MEDIA_OBSERVATION`: captures anonymous media-reference matches only when DevTools actually observes a media HTTP response. Exact ID and path linkages are bounded and scoped to one DevTools session, not inferred by time proximity.
- Added `hybrid_workflow_intel.js`: strictly offline inventory of document, API-like, accepted-job, redirect, media, attachment and download stages. It does not infer server topology, exploitability, original-resolution masters or download entitlements.
- Added Security → Import privacy preflight for explicitly selected HAR/cURL/PowerShell files, with local-only pattern counts and no source-file persistence.
- Added two dashboard views under Network & APIs: Product & Asset Relationships and Hybrid workflow stages. Added redacted structured JSON/CSV exports with spreadsheet formula sanitisation.
- Added safe synthetic PIM routes to the localhost acceptance fixture and refreshed setup instructions for automatic v7.15+ capture.
- Added regression tests for exact matching, mismatched IDs, commerce false positives, truncation, cyclic objects, denied media, privacy and dashboard wiring. Historical test version pins updated non-destructively.
- Existing captures, exports, settings, run.bat and global pause remain supported. No new network requests, credential replay, endpoint enumeration or platform-specific rules.

## Remaining verification

Live Windows Chrome extension installation, runtime messages, auto-capture on initial navigation, DevTools open/close, session rollover, browser restart/recovery, signed-link boundaries and export privacy require user-machine verification. Automatic all-site capture does **not** enable automatic response-body inspection without DevTools; storing raw passwords/cookies from every site has not been implemented.
