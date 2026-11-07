# DAM and Photographic Archive Security: evidence-led research

**Date:** 24 October 2026  
**Companion:** Trufflehog Intelligence 5.7 — DAM Platform Specialists  
**Scope:** Capture DAM, ResourceSpace, PhotoShelter, Bynder, Cloudinary, Canto, and FotoWare / FotoWeb; browser-observable evidence and risks requiring owner verification.

## Executive assessment

The main systemic risk is *permission drift across components*: a DAM's gallery visibility, API authentication, item-level entitlement, public-share settings, image derivative delivery and CDN caching may each behave differently. A successfully loaded image, observed API request or recognised vendor product is **not** proof that an unauthenticated person can obtain the file or that a security defect exists. The browser can record evidence and generate review questions; permission enforcement must be evaluated by the system's authorised owner.

## Highest-priority risks for archive owners

| Risk | Why it matters | Read-only Trufflehog indication | What owners must confirm |
| --- | --- | --- | --- |
| Broken object- or function-level authorisation | Asset IDs or API functions could receive inconsistent entitlement checks | Presence of per-asset API and download-location patterns | Test role boundaries using explicitly approved test accounts; compare server logs and policies |
| Overprivileged integration credentials | CMS plugins, batch processes or browser apps could hold overly broad API permissions | Auth scheme and redacted potentially confidential code indicators | Credential scope, custody, rotation and audit history |
| Public-original versus public-derivative assumptions | A `private` original does not imply all previews and transforms are private | Observed delivery type and actually delivered rendition class | Platform delivery policy and transformation rules |
| Search/visibility/download permission mismatches | Searchability, view access, licensing and download size may be independently configurable | Search fields, observed preview/download workflow and asset states | Gallery inheritance, licensing and download permission configuration |
| CDN caching and revocation delays | Withdrawing an asset may not remove cached copies immediately | Response cache metadata and public-share delivery type *when observed* | Cache invalidation, origin access and revocation requirements |
| Long-lived or leak-prone request authorisation | URLs or JavaScript may contain credentials or signatures | Scheme/parameter-name presence; redacted secret indicators | Actual token lifecycle, secret custody and revocation |
| Media ingestion, conversion and export | Untrusted inputs pass through parsers and asynchronous jobs | Upload protocol, processing-job and export/download stage hints | Patch level, scanning, processing isolation and review of failed jobs |

**Baseline:** OWASP's API Security Top 10 (2023) includes broken object-level authorisation (API1), broken authentication (API2), property-level authorisation (API3) and function-level authorisation (API5). These are general classes of risk, **not accusations about the vendors below**. Source: https://api-security.owasp.org/editions/2023/en/0x11-t10/

## Platform-specific observations and review points

### Capture DAM (Capture Ltd; do not confuse with similarly named products)

- **Verified:** Capture's UK public-sector service listing describes a WordPress-connected front end, a published API, layered permissions, licensing and download workflow features. Official Capture API documentation describes an administrative asset endpoint authenticated by `X-Api-Key` and identifies `idasset` / `org_filename` as data fields.
- **Review:** Verify that front-end and administrative API permissions are separated, that WordPress integration secrets are not exposed, and that licensing/download permissions are checked server-side. An asset schema clue alone provides only weak vendor attribution.
- **Passive observation:** Requests to `api.captureweb.net`, vendor-associated hosts, and distinctive API/response structure names. No API credentials should be exercised.
- **Sources:** https://www.applytosupply.digitalmarketplace.service.gov.uk/g-cloud/services/388233230371905 ; https://api.captureweb.net/

### ResourceSpace

- **Verified:** Its REST API supports GET and POST and signs requests using an API key; `user`, `function`, `sign` and `authmode` parameter names are documented. Version 10.2 limits native browser-auth API functions and requires CSRF tokens for native state-changing operations. ResourceSpace 11.1 adds external API logging with a default 14-day retention period.
- **Review:** API-key handling, user-specific scope, CSRF configuration for native requests, patch levels and log availability. Self-hosted deployments are frequently not on vendor hostnames; a matching parameter-name pattern on its own is weak attribution.
- **Passive observation:** Names of signing/auth-mode parameters, API pattern, and pre-existing technology clues. Do not store values, derive valid signatures or test access to other resources.
- **Source:** https://www.resourcespace.com/knowledge-base/api/

### PhotoShelter

- **Verified:** Gallery *visibility*, *searchability* and *download permission* are separately configurable. Download policies can distinguish anonymous, password-based and named-user access as well as allowed download sizes. Child collections/galleries can inherit permissions.
- **Review:** Listed/unlisted and public settings, inherited view/download permissions, password/link lifetime and entitlement to large images.
- **Passive observation:** PhotoShelter-associated service traffic, gallery visibility metadata and download outcomes already visible during a consented session. A public gallery is not evidence that full-size downloads are public.
- **Sources:** https://support.photoshelter.com/hc/en-us/articles/203374470-Managing-Visibility-and-Download-Permissions ; https://support.photoshelter.com/hc/en-us/articles/203374400-Gallery-Collection-Access-Who-Can-Download-Your-Images

### Bynder

- **Verified:** Its documented media-version download-location API requires MEDIAHIGHRES and additional roles for archived, watermarked or limited-use assets. Bynder separately documents public-asset links and CDN caching: some public URLs may continue to work until their cache expires; default AWS CDN expiry is documented as 24 hours.
- **Review:** Role- and asset-level download policy, archived/limited usage status, public link configurations and cache invalidation. An observed response containing a download location does not prove anonymous access.
- **Passive observation:** Recognised media APIs, version/download-location path shapes, public delivery/cache hints and user-observed download lifecycle; never fetch alternate assets or retry denied endpoints.
- **Sources:** https://api.bynder.com/reference/get_api-v4-media-id-version-download ; https://support.bynder.com/hc/en-us/articles/360013870200-Understanding-And-Enabling-Public-Assets

### Cloudinary

- **Verified:** For the `private` delivery type, the original requires signed access but transformed derivatives can be publicly available. For `authenticated`, originals and derivatives require authorised delivery. Strict Transformations is a separate configuration dimension.
- **Review:** Delivery type, signed original-versus-derivative policy, transformation rules, expiring links and cache configuration.
- **Passive observation:** Only recognised `upload`/`private`/`authenticated` URL structure of actually observed requests; this must **not** be interpreted as proof that signing is enforced, bypassable or misconfigured.
- **Sources:** https://cloudinary.com/documentation/image_trans_flags_delivery_types ; https://cloudinary.com/documentation/upload_parameters

### Canto

- **Verified:** Its API uses OAuth 2.0 and supports authorization-code and client-credentials flows. Canto warns against client-credential flows in JavaScript applications and recommends minimum required scopes.
- **Review:** App-secret exposure, credential rotation, service-user scope, account permissions and webhook/export privileges.
- **Passive observation:** Recognised Canto service hosts and redacted OAuth scheme indicators. Do not collect or replay token values.
- **Sources:** https://api.canto.com/ ; https://support.canto.com/hc/en-us/articles/23002380063505-Guideline-for-integrating-Canto-with-a-third-party-system

### FotoWare / FotoWeb

- **Verified:** FotoWare documents OAuth 2.0 application access tokens sent as bearer authorization for FotoWeb API requests; its documentation also describes a query-string token option but does not recommend it for routine API calls.
- **Review:** Prefer secure header-based handling where supported, role-aware download access, link exposure and log hygiene.
- **Passive observation:** Service-host recognition and redacted auth-mechanism indicators. Presence of a token parameter name is not evidence that token contents or credentials are compromised.
- **Source:** https://learn.fotoware.com/using-application-access-tokens-for-oauth-20-authorization

## Historic advisories: distinguish confirmed CVEs from speculative exposure

- **CVE-2024-12706:** NVD describes an authenticated SQL injection vulnerability in *OpenText Digital Asset Management* through version 24.4. This is not evidence that unrelated DAM products or instances are affected. Source: https://nvd.nist.gov/vuln/detail/CVE-2024-12706
- **CVE-2019-25693:** NVD identifies a historical ResourceSpace 8.6 issue involving CSRF/SQL injection. The CVE identifier reflects its original year; publication and metadata changes can occur later. It must **not** be treated as an alert for current or unversioned ResourceSpace installations. Source: https://nvd.nist.gov/vuln/detail/CVE-2019-25693

## Implementation decisions for Trufflehog 5.7

1. **Passive and on the captured evidence only:** no active endpoint enumeration, API calls, signed URL generation, credential validation or protected-image retrieval.
2. **Evidence-rated identification:** vendor-specific host and documented path structures support stronger indications; generic field patterns remain weak clues.
3. **No unproven access claims:** distinguish "service observed", "site hosted", "possible vendor technology" and "download permission unverified".
4. **Redacted outputs:** specialist export stores only allowlisted platform labels, static reviewed explanations, counts and confidence. It must not include asset identifiers, secret values, raw trace IDs, complete URLs, POST bodies or private file paths.
5. **Owner-review guidance, not automated vulnerability verdicts:** a detected service or weak field-pattern match cannot establish that a site has a known CVE or insecure permissions.
6. **Existing legacy exports are separate:** the new specialist report is privacy-bounded; users should continue to review legacy full-session export contents before sharing.
7. **Limitations:** absence of evidence may reflect missing browser permissions, a closed DevTools session, caching, unobserved server-to-server operations or unavailable response bodies.

**Verification status:** The v5.7 offline/static regression suite passes, but installed-Chrome runtime capture, DevTools forwarding, real download attribution and Windows desktop alerts have not been validated by those tests.
