# Trufflehog Intelligence 5.7.0 — DAM Platform Specialists

**Read-only analysis · Chrome Manifest V3 · 24 October 2026**

This release adds a platform-specific interpretation layer on top of **v5.6's existing technology recognition and already-recorded request/JSON-shape data**. It does not fetch URLs, query vendor APIs, test credentials, generate image variants, download protected media, or alter authentication state.

## New workspace: Images & DAM → DAM specialist profiles

The specialist dashboard classifies evidence into **Strong indication**, **Moderate indication**, or **Weak clue**, and explains the relationship of each observed service to the captured site. It treats an external vendor-owned script or media host as **service observed**, not proof that the website's central DAM or repository belongs to that vendor.

| Specialist | Read-only patterns recognised | Key caveat |
| --- | --- | --- |
| Capture DAM | API host `api.captureweb.net`, `captureweb.net` vendor domain, existing `idasset`/`org_filename` schema clues | Field pairs are not exclusive to Capture; Capture's WordPress-connected site is not necessarily the only DAM service involved |
| ResourceSpace | Signed `/api/index.php` request field **names** `user`, `function`, `sign`, and `authmode` indicators | Self-hosted use is common; those names alone are only **weak** evidence and the signatures/keys are not stored |
| PhotoShelter | Observed PhotoShelter-associated host; prior validated technology clues | An embedded gallery is not proof that the site's main library is PhotoShelter |
| Bynder | Vendor-associated host plus documented `/api/v4/media/` and media-version download-location route patterns | The media download-location API requires access rights; an observed route does not prove access or entitlement |
| Cloudinary | Recognised media-delivery URL **type** (`upload`, `private`, `authenticated`) and upload API path | A URL type is an access-policy clue, not a test; `private` derivatives can be public depending on settings |
| Canto | Vendor-associated host or prior verified static hints | No claims about client-secret validity or tenant permissions |
| FotoWare / FotoWeb | Vendor-associated host or prior verified static hints | No claims about backend role, account role or sharing permissions |

The tool reports **fixed, approved labels and explanations** only. It does not persist raw request/response bodies, complete URLs, resource IDs, query values, account identifiers, token-bearing request headers, discovered passwords or other credential material in the **new specialist analysis/export**. Any permission or security assessment must be conducted by the system owner.

### Analysis method and confidence

- **Strong indication**: Documented vendor-specific path/API/delivery structure combined with recognised vendor-associated traffic (or strong previously validated recognition).
- **Moderate indication**: Vendor-associated traffic or validated recognition without enough independent workflow evidence to assign the specific application role.
- **Weak clue**: Common or self-hosted field-name/path patterns, or a weak static code hint.
- **Source relationship**: Current site-origin observation, external-service observation, or code/schema-only unconfirmed evidence.
- Only the latest 1,300 recorded request metadata entries, 160 JSON shape summaries and bounded recognition evidence are considered. Matching more traffic is *not* proof of coverage.
- Third-party URL paths, signatures, tokens, resource IDs and credentials are inspected only transiently, where required for allowlisted structural matching, never exported in specialist reports.

### New redacted exports

Use **Export specialist report (redacted JSON)** for a platform-specific standalone JSON analysis or the regular **CSV** export for the active view. The full capture export includes `damSpecialists`, a validated report containing only bounded approved labels and counts. **Other legacy full-session exports have their own existing data fields and privacy policy**; the specialist report makes no new claims about those formats.

### Offline demonstration

From Command Prompt in the extension folder, run:

```bat
node tests\dam_specialists_demo.cjs
```

The demo loads `tests/dam_specialists_demo.json` and produces a local interpretation without any network access or API calls. Hostnames and resource IDs in the fixture are illustrative, not findings about existing sites.

### Windows Chrome acceptance check

1. Back up saved Evidence Vault investigations first.
2. Extract the ZIP into your **existing unpacked extension directory** and reload at `chrome://extensions` without uninstalling it.
3. Start capture on a website you are authorised to inspect, then browse normally. DevTools may be needed for JSON response shapes and other existing scanners, but the specialist engine itself consumes already-recorded metadata.
4. Open **Images & DAM → DAM specialist profiles**. Check platform confidence, network-supported candidate count, role classification and explanation.
5. Export the specialist JSON. Verify no sensitive URLs, token values, POST payloads or signature material are included.
6. For real browser acceptance, verify the current session can be archived and reopened through Evidence Vault. Compare the specialist report with the current network capture and check there are no erroneous platform conclusions.

There are **no new Chrome permissions** and **no automatic requests**. Test-suite success does not establish functioning installed-Chrome capture, service worker lifecycle, DevTools forwarding or Windows notifications: those remain **unverified** in this environment.

#The companion [`RESEARCH-DAM-2026-10-24.md`](RESEARCH-DAM-2026-10-24.md) records the detailed vendor-specific risks, owner-side review steps and official references.

## Documented evidence sources

- Capture official UK public service disclosure (API, WordPress integration, permissions): https://www.applytosupply.digitalmarketplace.service.gov.uk/g-cloud/services/388233230371905
- ResourceSpace API signing, `authmode` and CSRF: https://www.resourcespace.com/knowledge-base/api/
- Bynder retrieve media endpoint: https://api.bynder.com/reference/get_api-v4-media
- Bynder media-version download roles: https://api.bynder.com/reference/get_api-v4-media-id-version-download
- Bynder hosted/custom portals: https://support.bynder.com/hc/en-us/articles/360013875240-How-To-Create-A-Portal-Custom-URL
- Cloudinary public/private/authenticated delivery: https://cloudinary.com/documentation/image_trans_flags_delivery_types
- PhotoShelter API v4 overview: https://engineering.photoshelter.com/

## Developer verification

```bat
for %f in (tests\test*.cjs) do @node "%f"
node --check dam_specialists.js
node --check dashboard.js
```

The release retains all prior detection modules, Evidence Vault storage, the offline inspector, secure alerts, optional DevTools body scanning, Upload/Download Observers, image-quality analysis and API schema comparison. No source changes to live Chrome request handling are required for this release.
