# Trufflehog Intelligence v7.18.0 — Passive Security Intelligence

Release status: **offline regression-tested; Windows Chrome acceptance not yet completed**.

## New

- `security_intelligence.js`: pure, vendor-neutral, no-network security-condition analyser.
- MV3 wiring in `background.js`: inspect events already observed at request start, request-header, response-header and redirect stages, with active-tab origin/epoch guards.
- Strict persistence: host, curated route vocabulary, recognised rule names and categorical markers only; no token/header/cookie/body values, no raw signed URLs.
- Bounded, deduplicated security observation list and independent dropped-observation counter; stored/archived/imported alongside other supported capture families.
- Security Intelligence dashboard with totals, rule summaries, per-location observations, safe JSON/CSV exports and offline HAR inspection.
- Synthetic localhost security fixtures and Node regression/unit/worker integration tests.

## Principle

**A passive indicator is not proof of a vulnerability.** Observed `Origin`, CORS or signed URL metadata does not imply server compromise. No probing, replay, access-bypass checks, exploit payloads, intrusive enumeration or credential validation.

## Related published guidance

- OWASP API Security Project: https://owasp.org/projects/api-security-project
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- MDN CORS guidance: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CORS
- Chrome webRequest: https://developer.chrome.com/docs/extensions/reference/api/webRequest
- AWS signed URL guardrails: https://docs.aws.amazon.com/prescriptive-guidance/latest/presigned-url-best-practices/additional-guardrails.html
- Azure SAS: https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview
- Google signed URLs: https://docs.cloud.google.com/storage/docs/access-control/signed-urls

## Open engineering tasks

1. Perform live Windows Chrome acceptance, including capture on restart, site navigation, multi-tab and normal browsing.
2. Implement incremental event storage and high-volume tests instead of repeated whole-live-record writes.
3. Extend explicit opt-in body/header inspection without silently escalating global capture permissions.
4. Add security posture and detection-coverage diagnostics; quantify missing header/body visibility.
5. Design and test an encrypted, user-controlled full-fidelity evidence vault distinct from ordinary local records.
6. Introduce CVE-aware version matching with publisher advisories only where version/build evidence is independently grounded; never conclude exploitability from matching routes.
7. Calibrate rule false positives with authorised, sanitised examples and site-context exclusions.
