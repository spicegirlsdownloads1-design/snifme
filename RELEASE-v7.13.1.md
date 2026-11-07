# v7.13.1 — Local test compatibility and guided onboarding

- Declares only `http://127.0.0.1/*` as required host access, to satisfy Chrome webRequest listener registration at startup. Other sites remain opt-in via `optional_host_permissions`.
- Replaces the six-button fixture with a three-step guided test and one-click synthetic requests.
- Clarifies synthetic HTTP success versus actual capture in the Trufflehog dashboard.
- Preserves existing application logic and privacy-bound recording guard.
- Chrome may allow access to all 127.0.0.1 ports under that match pattern; capture still requires explicit user opt-in.
- This is a candidate build; live Windows Chrome confirmation is pending.
