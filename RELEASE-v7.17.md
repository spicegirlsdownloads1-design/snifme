# Trufflehog Intelligence v7.17.0 — Evidence Integrity & Recovery

Date: 2026-11-06

## Fixed

1. Vault session reimports preserve all recognised v7.16 evidence families (generic PIM, licensing, downloads, frame/worker observations) and known non-secret dropped-event counters. Metadata-only import still filters secrets and unknown objects.
2. Matching URL path or asset identifier is **asset-family evidence**, not exact rendition evidence. Transformation-aware matches are classified separately; no master-resolution or file-byte claim is inferred.
3. Requests that started before a subsequent navigation cannot contaminate the new site's capture after completing late. Ambiguous requests lacking a start or document-origin context are conservatively excluded.
4. Pending browser-download correlation now uses chrome.storage.session, scoped to the original local capture session, to survive Chrome MV3 service-worker suspension. Clear after terminal completion or interruption.
5. The older installation-version marker is corrected; the local guided test now includes two different rendition descriptors and updated instructions.

## Scope and privacy

Passive HTTP(S) observation only; no active probing, request replay, authorization bypass, credential validation or automatic third-party access. Site access must be approved in Chrome, and the global pause remains available.

A short-lived, internal numerical Chrome download ID is held in chrome.storage.session for recovery. No signature, session cookie, auth header or download filename is retained there. The pre-existing anonymous metadata export is unchanged except for preserving additional field families on import.

## Validation and limitations

See TEST-RESULTS.txt for the current automated-test count. Tests cover rendition false positives, import round-trip, stale network events and a simulated worker restart. Real Windows Chrome behavior and high-load multi-tab persistence have not been independently verified. DevTools is still required for JSON response-body analysis; opening it late cannot recover already-finished responses.
