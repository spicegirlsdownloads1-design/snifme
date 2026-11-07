# Proposed Trufflehog Intelligence v7.20 changes (v7.19-compatible branch)

## Passive secret-exposure intelligence

This review branch builds on v7.19 without replacing the incremental capture journal or existing detectors. The manifest remains at 7.19.0 until maintainers choose a release version.

- Expands already-loaded JavaScript, HTML, JSON and text scanning for npm, PyPI, Hugging Face, Azure Storage connection strings, credential-bearing database URLs and HTTP user-info.
- Classifies credential-bearing request and response header names without retaining header values.
- Detects credential-like query parameters in same-origin and cross-origin redirect targets without retaining redirect URLs or values.
- Reviews embedded HAR request/response bodies in bounded memory and exports only rule identifiers, redacted marker classes and safe provenance.
- Preserves the existing DevTools-only response-body boundary: the extension does not fetch, replay or probe resources to obtain bodies.

## Privacy boundaries

- No credential validation, replay, endpoint probing or automatic source-map fetching.
- No raw token, cookie, header value, request body, response body or matching source excerpt is stored in security observations.
- Body analysis is capped at 2 MiB per item and 80 derived indicator classes.
- HAR analysis remains local, bounded to 12 MiB / 3,000 entries, and never modifies the source file.
- API-key-shaped browser identifiers remain review findings, not proof of a private or exploitable credential.

## Validation

Run all Node regression tests from the extension root:

```powershell
Get-ChildItem tests/test_*.cjs | ForEach-Object { node $_.FullName }
```

The focused v7.20 suite is `tests/test_v720_secret_exposure.cjs`.
