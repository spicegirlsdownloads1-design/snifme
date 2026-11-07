# Trufflehog Intelligence v7.11.0 — Universal Traffic Transitions

24 October 2026 · Chrome Manifest V3 · read-only, generic-first

## Changes

- New **Network & APIs → Traffic transitions & lifecycles** dashboard panel.
- A 7-by-7 matrix of fixed, vendor-neutral HTTP response categories indicates which kinds of already-recorded responses appeared consecutively, only when completion timestamps have a reliable strictly increasing order and are no more than 30 seconds apart. Tied timestamps, missing dates and longer gaps are counted as limitations; there is no invented ordering.
- Generic lifecycle coverage counts distinct HTTP request labels and optional Chrome download labels, pairing only exact IDs **internally** to separate start-and-terminal, missing-start, missing-terminal, redirect, header-observation, completion and interruption cases.
- The new view provides fully redacted aggregate JSON/CSV exports using fixed labels and bounded numeric counts. It does not export URLs, hostnames, query values, credentials, request IDs, download IDs, filenames, script data or response contents.
- Existing **Universal traffic anatomy** and its default Universal Research recipe are unchanged. All legacy platform specialists, downloadable HAR tools, privacy preflights, workflows and saved evidence remain available.
- No added Chrome permissions, active requests, signature replay, endpoint guessing, authentication checks or asset retrieval.

## How to interpret

The transition table shows **temporal adjacency of browser-recorded HTTP completions**, not network causality or a confirmed server workflow. A recorded `API write → API read` transition does not establish that the read polls a job created by the write; an `API read → Image/media` transition does not establish the API supplied the image URL. A paired browser request ID confirms only local stages belonging to the same request. Chrome download attribution is incomplete if the browser worker restarted or a download had no unambiguous origin match.

An incomplete or disabled observer leaves unknown coverage, even if an aggregate count is zero. Missing, dropped and truncated capture records affect conclusions. Strict redaction applies to the **new transition report**, not retroactively to older whole-session exports.

## Windows upgrade

1. Save any important Evidence Vault exports.
2. Extract this complete extension ZIP into the existing unpacked Chrome extension folder and reload it at `chrome://extensions` to preserve the installed extension's local data.
3. Start an explicitly authorised site capture and browse normally.
4. Open **Network & APIs → Traffic transitions & lifecycles**.
5. For optional header and download stage evidence, independently enable the Download observer before an authorised interaction. The viewer does not generate requests.

## Validation

Run `node --test tests/*.cjs` in the extracted extension folder. `test_v711_sequence.cjs` checks chronology, exact stage grouping, ambiguity warnings, unknown browsers, redaction, immutability and caps; `test_v711_wiring.cjs` checks UI and unchanged permissions. Native Windows Chrome integration testing is still pending.
