# Release v4.7.0

- Added passive frame/worker context inventory, strict origin sanitization, and worker-context evidence labels.
- Added offline cross-site host/role correlations over saved capture groups and redacted JSON/CSV exports.
- No new permissions or network probes. Existing extension functions retained.
- 63 Node.js tests passed. Local Chromium itself timed out on `about:blank`; installed extension remains unverified.
