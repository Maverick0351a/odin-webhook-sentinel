# Copilot Operating Guide — ODIN Webhook Sentinel

> Purpose: Help me evolve this service safely. Always run tests after edits.

## Repo Map (important)

- `services/sentinel/main.py`  — FastAPI app & routes
- `sentinel/verify.py`         — Signature verification (generic, GitHub, Stripe)
- `sentinel/crypto.py`         — Canonical JSON, CID, Ed25519 signing, JWKS
- `sentinel/odin_client.py`    — Minimal ODIN envelope builder + forwarder
- `tests/`                     — Pytest suite (keep green)

## Prompt 1 — Align envelope schema with my Gateway
```
Read services/sentinel/main.py and sentinel/odin_client.py.
Modify `build_envelope()` to match the ODIN Gateway schema in my other repo:
- field names
- header names
- path for posting (/v1/odin/envelope)
Keep signing message format: "{cid}|{trace_id}|{ts}".
Update tests to reflect the schema if necessary.
Run: pytest -q
```
Tip: If my gateway requires API key + MAC (X-ODIN-API-Key/MAC), add it to `forward_to_gateway()`.

## Prompt 2 — Add provider: Twilio (X-Twilio-Signature)
```
Implement verify_twilio() in sentinel/verify.py:
- Header: X-Twilio-Signature (base64)
- Signed string = full URL + sorted form-encoded params
- HMAC-SHA1(secret) base64, compare to header
Add route /hooks/twilio that calls it. Add tests.
```
Note: Use official docs for the exact base string; write minimal deterministic unit tests.

## Prompt 3 — Add persistence (JSONL then Firestore)
```
Add optional write-ahead log:
- If SENTINEL_LOG_JSONL is set, append {ts,cid,verified,source,ip} to that file.
Add Firestore (optional): if FIRESTORE_PROJECT set, write a doc per event:
  collection 'sentinel_events', docId = {trace_id}-{hop?}, include verify meta.
Expose /healthz with {storage:"jsonl"/"firestore", ok:true}.
Add tests for the JSONL path (Firestone mocked off).
```

## Prompt 4 — Harden Stripe verification
```
Enforce timestamp tolerance (SENTINEL_STRIPE_TOLERANCE, default 300s).
Support multiple v1 signatures in header; accept if any matches.
Return reason codes on failure.
Extend tests: old timestamp -> fail; wrong secret -> fail.
```

## Prompt 5 — Docker & GitHub Action
```
Create .github/workflows/ci.yml: run pytest on 3.11/3.12.
Ensure Dockerfile uses non-root user and only copies what is required.
Add hadolint and basic security checks later.
```

## Guardrails
- Never log secrets.
- Always verify using the raw body, parse JSON only *after* signature passes.
- Keep canonical JSON stable: sort keys, no extra spaces.
- Reject bodies > 2MB by default (configurable).

Thank you!
