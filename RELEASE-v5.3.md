# Trufflehog Intelligence v5.3 — AWS DAM Ingestion & Workflow Evidence

This update builds on **v5.2** and implements browser-observable parts of the user-supplied **AWS-Hosted Digital Asset Management Architectures: API Protocols, Ingestion Mechanisms, and Metadata Schema Frameworks**. It preserves the v5.2 Download Observer, read-only DAM/CDN analysis, masked-key alerts, Evidence Vault, the offline inspector and the prior gallery analysis modules.

## What's new

- **New Network & APIs → AWS DAM ingestion** dashboard. Displays evidence from already observed requests; no additional URLs are fetched.
- Recognises common **S3 endpoint**, **API Gateway `execute-api`** and **CloudFront** hostname patterns. This is evidence about the contacted hostname, not proof of the platform's overall architecture or account ownership.
- Classifies **AWS-style presigned S3 POST form fields**: `policy`, `x-amz-credential`, `x-amz-signature`, `x-amz-date`, `x-amz-security-token`, `key`, `acl`, and response-code fields. Values are never stored. Policy content is **never decoded** or checked.
- Distinguishes an **observed POST to an S3 endpoint** from a **presigned POST field pattern on an unverified host**, and neither from a completed upload.
- Recognises request-host patterns consistent with an **API Gateway** asset/workflow service. The example `/demo/assets` route from the document is illustrative, not a universal endpoint, and the extension never probes it.
- Optional **DevTools JSON field-name inspection** interprets observed field names such as `executionArn`, `overallStatus`, `schemaVersion`, `aimlResults`, `customMetadata`, `dataClassification`, and `NextToken` without retaining their values. This cannot establish that Step Functions executed or that AWS hosts the server.
- Adds privacy-safe **CSV and JSON** exports of classifications and HTTP outcomes. The new JSON export contains only fixed labels, sanitised hostnames, status codes, timestamps and recognised metadata categories. Imported or malformed event fields are revalidated before rendering or export.
- A local **synthetic AWS-style upload lab**, port 8766, demonstrates form-field recognition and JSON schema clues with dummy values and no AWS access.

## Important boundaries

- **Opt-in:** the new network evidence uses the existing **Enable download observer** toggle on a site you are authorised to inspect. It now also recognises upload-related requests without sending them. It does not collect traffic from arbitrary unrelated tabs.
- **No sensitive material:** no AWS access key ID or scope, secret access key, session token, policy value, S3 bucket name from a POST body, object key, user file, signed URL, JWT, private workflow payload, response body, local file path or signature value is retained by this module.
- **No privileged activity:** no bucket enumeration, API endpoint guessing, request replay, credential validation, permission tests, upload/download initiation, private metadata access or backend tracing.
- **Response schemas require DevTools:** enable **JSON shapes** and open DevTools before the response arrives to collect permitted response field names. Raw JSON values remain excluded.
- **Permissions matter:** cross-host requests may be invisible without suitable user-approved host access. Missing sightings do **not** prove that a service or a signing field is absent.
- **Classification is not vulnerability testing:** S3 presigned POST and API Gateway are legitimate mechanisms. Even a successful HTTP response does not prove an upload was authorised for a broader audience or that a file exists or is retrievable publicly.

## Installation

1. Export important Evidence Vault investigations.
2. Extract the ZIP **over the same existing unpacked extension folder** to preserve Chrome extension identity and local storage. Do not install a second copy alongside the original.
3. Open `chrome://extensions` and select **Reload** for Trufflehog.
4. On an approved gallery, start capture and select **Enable download observer**. Choose **Network & APIs → AWS DAM ingestion** to inspect observed request classifications.
5. For JSON field-name clues, also enable **JSON shapes** and open DevTools on the original page *before* loading the relevant response.

## Synthetic Windows acceptance lab

From Command Prompt in the unpacked `Trufflehog-Intelligence` folder:

```bat
py tests\aws_dam_lab.py
```

Open `http://127.0.0.1:8766/aws-dam-lab.html`. Grant the local site permission and begin capture. Enable Download Observer, click **Simulate presigned POST field structure**, then open **AWS DAM ingestion**. On localhost, the expected classification is **Presigned POST field pattern; service unverified**, not an S3 endpoint. Turn on JSON shapes, open F12 on the local page, then visit `/demo/assets` and reload to see the optional synthetic workflow field names.

To run the tests with Node.js installed:

```bat
for %f in (tests\test*.cjs) do @node "%f"
```

The synthetic lab never connects to AWS, processes real assets or sends real credentials.

## Verification limits

The release has passed source syntax, unit/regression and simulated background-worker tests, plus an independent local fixture HTTP test. **End-to-end installed Chrome MV3, cross-origin network observation, DevTools behaviour and Windows notifications remain unverified in this container** and require the local acceptance procedure.
