# Trufflehog Intelligence v4.9 — DAM Access & CDN Policy Intelligence

- **Security → DAM access states:** delivered/denied HTTP responses, path-labelled preview/original/derivative, attachment delivery and JSON metadata field categories.
- **Images & DAM → CDN delivery policies:** recorded cache scope and duration bands, signed URL presence and owner-side revocation checks.
- **Privacy:** no new active network calls or permissions. Background captures only the presence of a Content-Disposition attachment header, never the filename or raw header. Reports contain host, broad role, counts and interpretation.
- **Important:** a file delivered while logged in is not necessarily public, an original path is not necessarily the master, public cache is not proof of a leak, and denied requests cannot be assumed bypassable.
- **Verification:** 69 automated Node suites and 43 JS syntax checks passed. Installed-Chrome end-to-end remains unverified.
