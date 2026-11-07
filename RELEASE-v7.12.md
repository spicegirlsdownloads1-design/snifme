# Trufflehog Intelligence v7.12.0 — Universal Relationship Evidence Confidence

25 October 2026 · Chrome MV3 · passive, generic-first, offline evidence analysis

## What changed

- **Network & APIs → Relationship confidence**: new universal relationship grading dashboard, based entirely on the selected local capture. Platform identity is never required.
- **Exact lifecycle** reports local browser request IDs with both a start and terminal stage, and local browser download references with start and terminal outcomes. HTTP and download groups are separate: they are **not** paired to each other.
- **Structural context** counts uniquely ordered, adjacent HTTP completion records (within 30 seconds) with the same private document, frame and initiator context. This supports a shared browsing context, **not** a proven data dependency.
- **Timing clues** count adjacent HTTP completion records with strictly ordered, unique timestamps within 30 seconds where no complete common document/frame/initiator context is demonstrated. These are weak proximity clues, never dependencies.
- Equal-time completions and affected neighbouring pairs are excluded; intervals over 30 seconds are excluded. Missing frame/document data and incomplete observer lifecycles are reported as coverage limits.
- Separate **redacted JSON / CSV** export contains only fixed signal labels, qualification text and bounded counts. No URL, host, document path, request or download ID, filename, secret value, header value, body or private grouping key appears in this report.
- All prior v7.11 analyses, HAR comparisons and existing platform research panels are retained. No added permissions or active traffic.

## How to use

1. Back up Evidence Vault material before replacing extension files.
2. Unzip into the existing unpacked extension directory, preserving its installation path, then reload from `chrome://extensions`.
3. Start capture explicitly on an authorised tab and browse normally.
4. Open **Network & APIs → Relationship confidence**. The new analysis itself never requests the site.
5. To record optional HTTP/download lifecycle stages, enable the Download observer independently before the authorised action. Disabled or incomplete observation must not be read as zero activity.
6. Export dedicated redacted relationship JSON/CSV from this view as needed. The redaction statement applies only to **this new export**; older whole-session exports have different content models.

## Scope, privacy and caveats

- Exact local IDs only pair stages of one HTTP request or one browser download; no response-to-response causality is inferred.
- Same document/frame/initiator is browser context evidence. Same origin/host alone does not qualify as structural evidence.
- Timing-only observations are strictly weaker and are not causal.
- Exact group counts and HTTP response-pair counts have different denominators: do not add them or treat them as a probability or security confidence score.
- Raw grouping keys remain in volatile analysis structures and are discarded before export. The original capture retains its pre-existing session data model.
- A worker restart, missing DevTools observation, capped buffers or truncated events can hide stages. The app does not replay, re-request, test credentials or probe permissions.

## Validation

- `node --test tests/*.cjs` — regression fixtures, including `test_v712_relationships.cjs` and `test_v712_wiring.cjs`.
- `node --check *.js` — syntax verification.
- Native Windows Chrome/DevTools behaviour remains to be verified.
