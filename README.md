# ODIN Webhook Sentinel

![CI](https://github.com/Maverick0351a/odin-webhook-sentinel/actions/workflows/ci.yml/badge.svg)
![CodeQL](https://github.com/Maverick0351a/odin-webhook-sentinel/actions/workflows/codeql.yml/badge.svg)
![Release](https://img.shields.io/github/v/tag/Maverick0351a/odin-webhook-sentinel?label=release)
![License](https://img.shields.io/github/license/Maverick0351a/odin-webhook-sentinel)
![Helm OCI](https://img.shields.io/badge/helm-oci--charts-blue)

Verify inbound webhooks (HMAC/Stripe/GitHub), produce tamper-evident metadata (CID, canonical JSON),
and optionally forward a signed ODIN envelope to your Gateway. Built with FastAPI.

**Why this exists**: Make inbound webhook handling *provable* and *portable*. Sentinel verifies signatures,
computes a canonical JSON hash (CID), and can re-sign + forward to ODIN Gateway so downstream systems
rely on receipts instead of trust.

---

## ✨ Features

- ✅ Signature verification:
  - Generic HMAC-SHA256 (`X-Signature-256: sha256=<hex>`)
  - GitHub (`X-Hub-Signature-256` → `sha256=<hex>`)
  - Stripe (`Stripe-Signature`: `t=..,v1=..` with timestamp tolerance)
- 🔒 Cryptographic metadata: canonical JSON + CID (`sha256:<hex>`)
- 📨 (Optional) Forward to ODIN Gateway as a signed envelope (Ed25519)
- 📦 Dockerfile, tests, CI (GitHub Actions) + CodeQL + Dependabot
- 🧱 Optional JSONL + Firestore persistence
- 🧪 Local smoke script to send a signed test webhook
- 🛡️ Simple in-memory rate limiting (env configurable)
- 📊 Structured JSON logging (toggle with `SENTINEL_STRUCT_LOG`)
 - 📈 Optional Prometheus `/metrics` (install `prometheus-client`)

---

## Quick start (PowerShell)

```powershell
# 1) Create venv & install
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
pip install -r dev-requirements.txt

# 2) Configure env (copy .env.example → .env and edit secrets)
copy .env.example .env

# 3) Run the service (http://127.0.0.1:8787)
uvicorn services.sentinel.main:app --host 127.0.0.1 --port 8787 --reload

# 4) Send a signed test webhook
python scripts\dev_send_webhook.py
```

### Bash

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
pip install -r dev-requirements.txt

cp .env.example .env
uvicorn services.sentinel.main:app --host 127.0.0.1 --port 8787 --reload

python scripts/dev_send_webhook.py
```

---

## Endpoints

- `POST /hooks/generic` — Generic HMAC (`X-Signature-256: sha256=<hex>`)
- `POST /hooks/github`  — GitHub HMAC (`X-Hub-Signature-256`)
- `POST /hooks/stripe`  — Stripe (`Stripe-Signature`; tolerance by env)
- `GET  /healthz`       — Liveness
- `GET  /.well-known/jwks.json` — JWKS for your **sender** key (if configured)

Response JSON includes `verified`, `cid`, and normalised metadata.
If ODIN forwarding is enabled (see env vars), response also includes `gateway_forwarded` and `trace_id`.

---

## Environment

Copy `.env.example` to `.env` and set values:

See `.env.example` for the full list. Key variables:

| Purpose | Vars |
|---------|------|
| Generic HMAC | `SENTINEL_GENERIC_SECRET`, `SENTINEL_GENERIC_HEADER` |
| GitHub | `SENTINEL_GITHUB_SECRET` |
| Stripe | `SENTINEL_STRIPE_SECRET`, `SENTINEL_STRIPE_TOLERANCE` |
| Twilio | `TWILIO_AUTH_TOKEN` |
| ODIN Forwarding | `ODIN_GATEWAY_URL`, `ODIN_SENDER_PRIV_B64`, `ODIN_SENDER_KID`, `ODIN_API_KEY`, `ODIN_API_SECRET` |
| Persistence | `SENTINEL_LOG_JSONL`, `FIRESTORE_PROJECT` |
| Limits/Logging | `SENTINEL_MAX_BODY_BYTES`, `SENTINEL_RATE_LIMIT`, `SENTINEL_RATE_WINDOW`, `SENTINEL_RATE_BUCKET_CAP`, `SENTINEL_STRUCT_LOG` |

Rate limiting: enable with `SENTINEL_RATE_LIMIT` (requests/window). Window length via `SENTINEL_RATE_WINDOW` (seconds). Cap tracked IPs with `SENTINEL_RATE_BUCKET_CAP` (LRU eviction).
Metrics: install dev extras (`pip install .[dev]`) to expose `/metrics`.
Structured logging: disable with `SENTINEL_STRUCT_LOG=0`.

---

## ODIN Forwarding (optional)

If `ODIN_GATEWAY_URL` and `ODIN_SENDER_PRIV_B64` are set, the Sentinel will construct an ODIN envelope:
- CID over canonical JSON of the payload
- Message to sign: `{cid}|{trace_id}|{ts}` (Ed25519; base64url signature)
- Envelope fields: `payload`, `payload_type`, `target_type`, `trace_id`, `ts`, `signature`, `kid`, `sender_jwk`

> ⚠️ Your ODIN Gateway might expect slightly different field names.
> See `AGENT.md` for a ready Copilot prompt to align the envelope schema to your gateway.

---

## Tests

```bash
pytest -q
```

---

## Docker

```bash
docker build -t odin-webhook-sentinel:dev .
docker run --rm -p 8787:8787 --env-file .env odin-webhook-sentinel:dev
```

## Deployment

### Container Image
After tagging (e.g. `git tag v1.0.0 && git push --tags`), the release workflow builds and publishes an image (example: GHCR) with tags: `1.0.0`, `1.0`, `1`, `latest`.

Pin by digest in production:
```
docker pull ghcr.io/Maverick0351a/odin-webhook-sentinel@sha256:<digest>
```

### Helm (Kubernetes)

```bash
helm install sentinel ./charts/sentinel \
  --set env.SENTINEL_GENERIC_SECRET=changeme \
  --set env.SENTINEL_RATE_LIMIT=60
```

Enable ServiceMonitor (Prometheus Operator):
```bash
helm upgrade --install sentinel ./charts/sentinel \
  --set metrics.serviceMonitor.enabled=true
```

### Change Log & Security
See `CHANGELOG.md` and `SECURITY.md`.

### Signing & SBOM (optional)
```
cosign sign ghcr.io/Maverick0351a/odin-webhook-sentinel:1.0.0
syft ghcr.io/Maverick0351a/odin-webhook-sentinel:1.0.0 -o spdx-json > SBOM.spdx.json
```

---

## Makefile shortcuts

```bash
make dev        # install + dev deps
make lint       # ruff lint
make fmt        # format
make coverage   # run coverage suite
make docker     # build image
```

## Copilot: start here

Open **AGENT.md** in VS Code and run the first prompt in Copilot Chat.
It contains small, safe tasks (add providers, tweak envelope, wire Firestore) you can apply incrementally.

---

## License

Apache-2.0 © 2025 ODIN
