# Trufflehog Intelligence v4.8 — Same-Origin Frame Coverage

Adds bounded same-origin iframe inline-script inspection and external script inventory during approved top-level captures, DOM-mutation refreshes for reachable frame documents, service-worker controller-script references (not content), and a Frame Coverage table. Cross-origin frames are never read. No network fetch or active credential tests. Inherited DAM, gallery, media, and secret-alert features retained.

Verification: run `node --test tests/*.cjs` and `node --check` for JS files. Live installed-Chrome validation is required.
