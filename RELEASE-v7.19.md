# Trufflehog Intelligence v7.19.0 — Capture Journal & Diagnostics

Date: 2026-11-07

## New and changed

- `capture_journal.js`: Transactional IndexedDB change journal for live capture
  records. Commits append or replace deltas, snapshots every 96 changes and
  reconstructs the latest state across service-worker restarts. No HTTP requests
  are made by the module.
- `background.js`: Uses the journal for active capture records on real Chromium;
  older local records migrate on first changed write. Keeps a local compatibility
  checkpoint every 48 committed changes and on capture archive/rollover.
- Dashboard → Capture diagnostics: Shows persistence backend, checkpoint revision,
  pending compacted/uncompacted changes, available browser-wide storage estimate
  and origin-attribution exclusions counted since the current worker started.
- Existing passive security rules, rendition-aware matching, download recovery,
  HAR processing and evidence-vault format are retained.

## Boundaries

- No new host permissions, script injection, active endpoint testing, credential
  replay, arbitrary URL guessing or secret-value persistence.
- `storage.local` checkpoint count is lower; this is *not* a full out-of-core
  event-stream architecture. Record analysis still operates on bounded arrays.
- Browser-wide quota estimates are indicative and cannot certify free capacity.
- Captures from old releases are kept; the journal is a new internal storage DB.
- Existing Evidence Vault archives are unaffected.
- Import/export still use sanitized metadata, not an encrypted raw evidence vault.

## Verification

- The automated regression suite covers legacy behaviour and new simulated
  journal operations, including compaction and recovery after a worker restart.
- Independent browser/Windows acceptance remains outstanding. In particular,
  direct Chrome IndexedDB transaction behaviour and long-session quota exhaustion
  require real-browser testing.

## Windows acceptance: recommended

1. Install or reload the unpacked v7.19 extension in Chrome (disable any older copy).
2. Visit the bundled localhost test page, then open Capture diagnostics.
3. Trigger test requests; verify IndexedDB journal mode and recorded counts.
4. Suspend/restart only the extension service worker; check that the live record
   reconstructs with the same session ID and request count.
5. Browse across two site origins and confirm no cross-navigation contamination.
6. Stop capture and compare saved Evidence Vault session with the live record.
7. Inspect chrome://extensions → Errors and Chrome profile storage health.

See README.md, OPEN-TASKS.txt and WINDOWS-CHROME-TEST-CHECKLIST.txt.
