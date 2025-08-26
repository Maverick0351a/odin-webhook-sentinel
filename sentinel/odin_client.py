import hashlib
import hmac
import json
import uuid
from typing import Any

import httpx

from .crypto import canonical_json, now_iso, public_jwk_from_seed, sha256_cid, sign_ed25519


def build_envelope(
    payload: Any,
    payload_type: str,
    target_type: str,
    sender_seed_b64: str,
    sender_kid: str,
    trace_id: str | None = None,
    ts: str | None = None,
) -> tuple[dict[str, Any], str]:
    trace_id = trace_id or str(uuid.uuid4())
    ts = ts or now_iso()
    cid = sha256_cid(canonical_json(payload))
    message = f"{cid}|{trace_id}|{ts}".encode()
    signature = sign_ed25519(sender_seed_b64, message)
    sender_jwk = public_jwk_from_seed(sender_seed_b64, sender_kid)
    env = {
        "payload": payload,
        "payload_type": payload_type,
        "target_type": target_type,
        "trace_id": trace_id,
        "ts": ts,
        "signature": signature,
        "kid": sender_kid,
        "sender_jwk": sender_jwk,
    }
    return env, cid


def _mac(api_secret: str, message: str) -> str:
    dig = hmac.new(api_secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
    import base64

    return base64.urlsafe_b64encode(dig).decode("ascii").rstrip("=")


async def forward_to_gateway(
    gateway_url: str,
    envelope: dict[str, Any],
    cid: str,
    api_key: str | None = None,
    api_secret: str | None = None,
) -> httpx.Response:
    url = gateway_url.rstrip("/") + "/v1/odin/envelope"
    headers = {"Content-Type": "application/json"}
    if api_key and api_secret:
        # sign the same message context
        msg = f"{cid}|{envelope['trace_id']}|{envelope['ts']}"
        headers["X-ODIN-API-Key"] = api_key
        headers["X-ODIN-API-MAC"] = _mac(api_secret, msg)
    async with httpx.AsyncClient(timeout=10) as client:
        return await client.post(url, headers=headers, content=json.dumps(envelope))
