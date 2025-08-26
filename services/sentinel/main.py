import asyncio
import json
import os
import pathlib
import time
import logging
from collections import defaultdict, deque, OrderedDict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import JSONResponse
import uuid
from pydantic import BaseModel

from sentinel import verify as V
from sentinel.config import Settings
from sentinel.crypto import canonical_json, jwks_from_seed, sha256_cid
from sentinel.odin_client import build_envelope, forward_to_gateway

load_dotenv()

logger = logging.getLogger("sentinel")
if not logger.handlers:
    handler = logging.StreamHandler()
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

app = FastAPI(title="ODIN Webhook Sentinel", version="0.1.0")

# In-memory rate limit buckets {ip: deque[timestamps]}
class _LRUBuckets:
    def __init__(self, cap: int):
        self.cap = cap
        self.data: OrderedDict[str, deque[float]] = OrderedDict()

    def get(self, key: str) -> deque[float]:
        dq = self.data.get(key)
        if dq is None:
            if self.cap and len(self.data) >= self.cap:
                # evict oldest
                self.data.popitem(last=False)
            dq = deque()
            self.data[key] = dq
        else:
            # move to end (recent use)
            self.data.move_to_end(key, last=True)
        return dq

_rl_buckets = None  # placeholder until Settings created

try:  # optional prometheus_client
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
except Exception:  # pragma: no cover
    Counter = None  # type: ignore
    Histogram = None  # type: ignore

if Counter:  # pragma: no cover (metrics wiring itself not critical)
    try:
        METRIC_REQUESTS = Counter(
            "sentinel_requests_total", "Total HTTP requests", ["source", "verified"]
        )
        METRIC_RATE_LIMITED = Counter(
            "sentinel_rate_limited_total", "Rate limited responses"
        )
        METRIC_LATENCY = Histogram(
            "sentinel_request_latency_seconds",
            "Latency of webhook processing",
            buckets=(0.01,0.025,0.05,0.1,0.25,0.5,1,2,5),
            labelnames=("source","verified"),
        ) if 'Histogram' in globals() else None
    except ValueError:
        # Already registered (e.g., module reload in tests)
        METRIC_REQUESTS = None
        METRIC_RATE_LIMITED = None
        METRIC_LATENCY = None
else:
    METRIC_REQUESTS = None
    METRIC_RATE_LIMITED = None
    METRIC_LATENCY = None


@app.middleware("http")
async def rate_limit_middleware(request, call_next):  # type: ignore
    if SET.rate_limit_per_window and SET.rate_limit_per_window > 0:
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        bucket = _rl_buckets.get(ip)  # type: ignore
        window_start = now - SET.rate_limit_window_seconds
        while bucket and bucket[0] < window_start:
            bucket.popleft()
        if len(bucket) >= SET.rate_limit_per_window:
            if METRIC_RATE_LIMITED:
                METRIC_RATE_LIMITED.inc()
            return Response(
                content=json.dumps({"detail": "rate_limited"}),
                media_type="application/json",
                status_code=429,
            )
        bucket.append(now)
    # Add request id
    req_id = str(uuid.uuid4())
    request.state.request_id = req_id
    start = time.time()
    resp = await call_next(request)
    duration = time.time() - start
    try:
        if METRIC_LATENCY and request.url.path.startswith("/hooks/"):
            # source is last part
            parts = request.url.path.split("/")
            source = parts[-1] if parts else "unknown"
            verified_label = resp.status_code == 200
            METRIC_LATENCY.labels(source=source, verified=str(verified_label).lower()).observe(duration)
    except Exception:
        pass
    resp.headers["X-Request-ID"] = req_id
    return resp

SET = Settings(
    generic_secret=os.getenv("SENTINEL_GENERIC_SECRET"),
    generic_header=os.getenv("SENTINEL_GENERIC_HEADER", "X-Signature-256"),
    github_secret=os.getenv("SENTINEL_GITHUB_SECRET"),
    stripe_secret=os.getenv("SENTINEL_STRIPE_SECRET"),
    stripe_tolerance=int(os.getenv("SENTINEL_STRIPE_TOLERANCE", "300") or "300"),
    twilio_auth_token=os.getenv("TWILIO_AUTH_TOKEN"),
    odin_gateway_url=os.getenv("ODIN_GATEWAY_URL"),
    odin_sender_priv_b64=os.getenv("ODIN_SENDER_PRIV_B64"),
    odin_sender_kid=os.getenv("ODIN_SENDER_KID"),
    odin_api_key=os.getenv("ODIN_API_KEY"),
    odin_api_secret=os.getenv("ODIN_API_SECRET"),
    max_body_bytes=int(os.getenv("SENTINEL_MAX_BODY_BYTES", "2000000")),
    log_jsonl_path=os.getenv("SENTINEL_LOG_JSONL"),
    firestore_project=os.getenv("FIRESTORE_PROJECT"),
    structured_logging=os.getenv("SENTINEL_STRUCT_LOG", "1") != "0",
    auth_token=os.getenv("SENTINEL_AUTH_TOKEN"),
)

# now instantiate buckets with cap
if _rl_buckets is None:
    _rl_buckets = _LRUBuckets(cap=SET.rate_limit_bucket_cap)


class VerifyResult(BaseModel):
    source: str
    verified: bool
    method: str
    reason: str | None = None
    cid: str | None = None
    gateway_forwarded: bool = False
    trace_id: str | None = None
    request_id: str | None = None


@app.get("/healthz")
def healthz():
    storage: str | None = None
    firestore_project = SET.firestore_project or os.getenv("FIRESTORE_PROJECT")
    log_path = SET.log_jsonl_path or os.getenv("SENTINEL_LOG_JSONL")
    if firestore_project:
        storage = "firestore"
    elif log_path:
        storage = "jsonl"
    return {
        "ok": True,
        "gateway": bool(SET.odin_gateway_url),
        "providers": {
            "generic": bool(SET.generic_secret),
            "github": bool(SET.github_secret),
            "stripe": bool(SET.stripe_secret),
            "twilio": bool(SET.twilio_auth_token),
        },
        "storage": storage,
    }


@app.get("/readyz")
def readyz():
    # Basic readiness: required config validation
    required_ok = True
    # For now just returns ok; could add downstream checks (e.g., Firestore) later
    return {"ok": required_ok}


def require_auth(request: Request):
    if SET.auth_token:
        auth = request.headers.get("Authorization")
        if not auth or auth != f"Bearer {SET.auth_token}":
            raise HTTPException(status_code=401, detail="unauthorized")
    return True


@app.get("/.well-known/jwks.json")
def jwks():
    if SET.odin_sender_priv_b64 and SET.odin_sender_kid:
        return jwks_from_seed(SET.odin_sender_priv_b64, SET.odin_sender_kid)
    return {"keys": []}


async def _verify_and_optionally_forward(
    source: str, body: bytes, headers: dict[str, str], request_id: str
) -> VerifyResult:
    verified = False
    reason = "not_configured"
    method = "unknown"

    if len(body) > SET.max_body_bytes:
        raise HTTPException(status_code=413, detail="payload too large")

    if source == "generic":
        method = "hmac-sha256"
        sig = headers.get(SET.generic_header) or headers.get(SET.generic_header.lower())
        generic_secret = SET.generic_secret or os.getenv("SENTINEL_GENERIC_SECRET")
        if generic_secret:
            verified, reason = V.verify_generic_hmac_sha256(generic_secret, sig or "", body)
        else:
            reason = "generic_secret_not_set"
    elif source == "github":
        method = "github-hmac-sha256"
        sig = headers.get("X-Hub-Signature-256") or headers.get("x-hub-signature-256")
        github_secret = SET.github_secret or os.getenv("SENTINEL_GITHUB_SECRET")
        if github_secret:
            verified, reason = V.verify_github(github_secret, sig or "", body)
        else:
            reason = "github_secret_not_set"
    elif source == "stripe":
        method = "stripe-signature"
        sig = headers.get("Stripe-Signature") or headers.get("stripe-signature")
        stripe_secret = SET.stripe_secret or os.getenv("SENTINEL_STRIPE_SECRET")
        if stripe_secret:
            verified, reason = V.verify_stripe(stripe_secret, sig or "", body, SET.stripe_tolerance)
        else:
            reason = "stripe_secret_not_set"
    elif source == "twilio":
        method = "twilio-hmac-sha1"
        sig = headers.get("X-Twilio-Signature") or headers.get("x-twilio-signature")
        twilio_auth = SET.twilio_auth_token or os.getenv("TWILIO_AUTH_TOKEN")
        if twilio_auth:
            # For Twilio we must reconstruct full URL + sorted form params. We only accept form-encoded.
            # Since we already consumed body, parse if form.
            from urllib.parse import parse_qsl

            content_type = headers.get("Content-Type", "")
            if "application/x-www-form-urlencoded" in content_type or body:
                # attempt parse regardless if body present
                try:
                    form_params = dict(parse_qsl(body.decode("utf-8")))
                except Exception:
                    form_params = {}
            else:
                verified, reason = False, "unsupported_content_type"
                form_params = {}
            # Need request URL: assume headers forwarded host + path
            proto = headers.get("X-Forwarded-Proto") or "https"
            host = headers.get("X-Forwarded-Host") or headers.get("host") or headers.get("Host")
            path = headers.get("X-Original-Uri") or f"/hooks/{source}"  # fallback
            if not host:
                verified, reason = False, "missing_host"
            else:
                full_url = f"{proto}://{host}{path}"
                verified, reason = V.verify_twilio(twilio_auth, sig or "", full_url, form_params)
        else:
            reason = "twilio_auth_token_not_set"
    else:
        raise HTTPException(status_code=404, detail="unknown source")

    # Prepare response
    result = VerifyResult(
        source=source, verified=verified, method=method, reason=None if verified else reason, request_id=request_id
    )
    if verified:
        try:
            # Note: verify using raw body; only parse after verification succeeds
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                payload = {"raw": body.decode("utf-8", "ignore")}
            cid = sha256_cid(canonical_json(payload))
            result.cid = cid

            # optional: forward to ODIN Gateway
            if SET.odin_gateway_url and SET.odin_sender_priv_b64 and SET.odin_sender_kid:
                env, cid2 = build_envelope(
                    payload=payload,
                    payload_type=f"{source}.webhook.v1",
                    target_type="webhook.normalized.v1",
                    sender_seed_b64=SET.odin_sender_priv_b64,
                    sender_kid=SET.odin_sender_kid,
                )
                # In the envelope, cid2 equals cid (since built from same canonical payload)
                resp = await forward_to_gateway(
                    SET.odin_gateway_url,
                    env,
                    cid2,
                    api_key=SET.odin_api_key,
                    api_secret=SET.odin_api_secret,
                )
                result.gateway_forwarded = (resp.status_code // 100) == 2
                try:
                    bodyj = resp.json()
                    result.trace_id = bodyj.get("trace_id") or bodyj.get("receipt", {}).get(
                        "trace_id"
                    )
                except Exception:
                    pass
        except Exception as e:
            result.reason = f"post_verify_error:{e}"
    return result


@app.post("/hooks/{source}")
async def receive(source: str, request: Request, _: bool = Depends(require_auth)):
    headers = {k: v for k, v in request.headers.items()}
    body = await request.body()
    res = await _verify_and_optionally_forward(source, body, headers, getattr(request.state, 'request_id', 'na'))
    code = 200 if res.verified else 400
    # Persistence (JSONL first, Firestore optional)
    try:
        log_path = SET.log_jsonl_path or os.getenv("SENTINEL_LOG_JSONL")
        if log_path:
            # Prepare log entry
            client_ip = request.client.host if request.client else None
            log_entry = {
                "ts": int(time.time()),
                "cid": res.cid,
                "verified": res.verified,
                "source": res.source,
                "ip": client_ip,
            }
            p = pathlib.Path(log_path)
            p.parent.mkdir(parents=True, exist_ok=True)

            def _write_log():  # executed in thread
                with p.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(log_entry, separators=(",", ":")) + "\n")

            async def _append():
                await asyncio.to_thread(_write_log)

            await _append()
        # Firestore (optional) -- only if configured; lazy import
        firestore_project = SET.firestore_project or os.getenv("FIRESTORE_PROJECT")
        if firestore_project:
            try:
                from google.cloud import firestore  # type: ignore

                db = firestore.Client(project=firestore_project)  # pragma: no cover
                doc_id = f"{res.trace_id or 'na'}"
                meta = res.model_dump()
                db.collection("sentinel_events").document(doc_id).set(meta)  # pragma: no cover
            except Exception:
                pass  # Do not block response
    except Exception:
        pass
    if METRIC_REQUESTS:
        try:
            METRIC_REQUESTS.labels(source=res.source, verified=str(res.verified).lower()).inc()
        except Exception:
            pass
    if SET.structured_logging:
        try:
            logger.info(
                json.dumps(
                    {
                        "event": "webhook_result",
                        "source": res.source,
                        "verified": res.verified,
                        "reason": res.reason,
                        "cid": res.cid,
                        "gateway_forwarded": res.gateway_forwarded,
                        "trace_id": res.trace_id,
                        "request_id": res.request_id,
                        "status_code": code,
                        "latency_ms": int((time.time() - start_ts) * 1000) if (start_ts := getattr(request.state,'_start_time',None)) else None,
                    }
                )
            )
        except Exception:
            pass
    return Response(content=res.model_dump_json(), media_type="application/json", status_code=code)


@app.get("/metrics")
def metrics():  # pragma: no cover
    if not Counter:
        return Response(status_code=404, content="prometheus_client not installed")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def main():
    # Convenience CLI entrypoint: `odin-webhook-sentinel`
    import os

    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8787"))
    uvicorn.run("services.sentinel.main:app", host=host, port=port, reload=False)
