# Trufflehog Intelligence v5.5.0 — Asset Quality Intelligence

## Implemented

- **Images & DAM → Asset quality ledger**: bounded offline rendition family grouping from observed image URLs and DevTools byte-verifications. Reports the largest *verified encoded pixel size* per family and separately labels browser-reported dimensions. The best observed rendition is NOT a claim about the original or master.
- **Exact received-byte duplicate groups**: SHA-256 equality from existing opt-in verification, reported with anonymous D1/D2 group labels and aggregate host counts; no image URLs or digest strings in this quality export.
- **Images & DAM → Transfer integrity**: browser-completed/interrupted downloads and download MIME categories without asserting a download-to-image relationship. Records the numeric presence of range-request headers and safe `Content-Range` values (`206 Partial Content` is not automatically a failure).
- **New redacted reports**: quality and transfer JSON exports exclude URLs, path IDs, image content, filename, signing fields and raw credential values. These reports contain only aggregate measured facts and evidence limitations.
- Synthetic localhost image-size and byte-range test: `py tests\quality_lab.py` (port 8768).
- No new Chrome permissions. No background fetching, guessed URLs, restricted file access, image reconstruction or watermark alteration.

## Local Windows acceptance instructions

1. Back up significant saved Evidence Vault records before replacing files; reload the unpacked extension at `chrome://extensions`.
2. In Command Prompt inside the extension root run `py tests\quality_lab.py`.
3. Open `http://127.0.0.1:8768/` in a fresh tab and grant the requested localhost site access.
4. Start capture; **enable Verify image bytes** and optionally Enable visual fingerprints. Open DevTools (F12) on the inspected page BEFORE reloading the page so DevTools sees image responses. Disable DevTools cache if necessary.
5. Refresh the fixture and visit **Images & DAM → Asset quality ledger**. The same-host 300×200 and 1200×800 PNGs should appear in one family, with 1200×800 as the largest verified received size. The duplicate preview should share exact received bytes with the 300×200 rendition.
6. Enable Download observer, click **Fetch a harmless partial-response sample** followed by **Download a locally generated test file**. View **Transfer integrity**. The observer is opt-in and its normal path classifications apply.
7. Stop capture and verify saved reports/exports contain only metadata, not file content or local path.

## Caveats

Encoded image-byte verification is capped by the existing 4 MiB per-response, 160-image DevTools inspection policy and depends on Chrome actually providing response content. Missing dimensions are not guessed from filenames. Browser-reported pixel sizes are not proof of encoded size. Asset families are same-host path heuristics, so could group unrelated images. SHA-256 confirms only identical received bytes; it cannot establish ownership, rights, licences, or publicly reachable masters. Browser downloads are deliberately not linked to asset rows on MIME/size/timing alone. `Content-Range` is a browser-observed field and is not a complete transfer integrity guarantee. Some requests or downloads may be absent due to Chrome permission/visibility/worker constraints. Full installed-Chrome acceptance has not been validated in this build environment.
