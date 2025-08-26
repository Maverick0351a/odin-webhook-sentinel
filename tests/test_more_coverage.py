import base64
import importlib
import json
import os
import time
from typing import Any

import hmac
import hashlib
import pytest

from sentinel import crypto
from sentinel import verify as V


def test_crypto_roundtrip_and_signing():
    obj = {"b": 2, "a": 1}
    cj = crypto.canonical_json(obj)
    # keys sorted, no spaces
    assert cj == b'{"a":1,"b":2}'
    cid = crypto.sha256_cid(cj)
    assert cid.startswith("sha256:") and len(cid) == 7 + 64
    # 32 raw bytes seed
    raw = b"a" * 32
    seed_b64u = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    sk = crypto.ed25519_from_seed_b64(seed_b64u)
    sig1 = crypto.sign_ed25519(seed_b64u, b"test-message")
    sig2 = crypto.sign_ed25519(seed_b64u, b"test-message")
    # deterministic (Ed25519 deterministic signature)
    assert sig1 == sig2
    jwk = crypto.public_jwk_from_seed(seed_b64u, "kid1")
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and jwk["kid"] == "kid1"
    jwks = crypto.jwks_from_seed(seed_b64u, "kid1")
    assert jwks == {"keys": [jwk]}
    # now_iso returns UTC offset
    assert crypto.now_iso().endswith("+00:00")


def test_crypto_invalid_seed():
    with pytest.raises(ValueError):
        crypto.ed25519_from_seed_b64("short")


def test_build_envelope_and_mac_forward(monkeypatch):
    # Configure env BEFORE import reload so globals pick up
    seed = base64.urlsafe_b64encode(b"b" * 32).decode().rstrip("=")
    monkeypatch.setenv("ODIN_SENDER_PRIV_B64", seed)
    monkeypatch.setenv("ODIN_SENDER_KID", "kidX")
    monkeypatch.setenv("ODIN_GATEWAY_URL", "https://odin.example")
    monkeypatch.setenv("ODIN_API_KEY", "k")
    monkeypatch.setenv("ODIN_API_SECRET", "s")
    monkeypatch.setenv("SENTINEL_GENERIC_SECRET", "gsecret")

    # Reload main to rebuild Settings with new env
    from services.sentinel import main as main_mod

    importlib.reload(main_mod)
    app = main_mod.app

    # Stub AsyncClient
    class DummyClient:
        def __init__(self, *a, **k):
            self.captured: dict[str, Any] | None = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, headers, content):
            self.captured = {"url": url, "headers": headers, "content": content}
            from httpx import Response

            return Response(200, json={"trace_id": "t123"})

    monkeypatch.setattr("sentinel.odin_client.httpx.AsyncClient", DummyClient)

    from fastapi.testclient import TestClient

    client = TestClient(app)
    body = b'{"k":1}'
    sig_hex = hmac.new(b"gsecret", body, hashlib.sha256).hexdigest()
    r = client.post("/hooks/generic", data=body, headers={"X-Signature-256": f"sha256={sig_hex}"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["verified"] is True and j["gateway_forwarded"] is True and j["trace_id"] == "t123"


def test_verify_missing_header_and_plain_hex():
    ok, reason = V.verify_generic_hmac_sha256("sec", "", b"{}")
    assert not ok and reason == "missing_header"
    body = b"{}"
    mac = hmac.new(b"sec", body, hashlib.sha256).hexdigest()
    ok2, reason2 = V.verify_generic_hmac_sha256("sec", mac, body)  # plain hex path
    assert ok2 and reason2 == "ok"


def test_stripe_missing_header_and_missing_v1():
    ok, reason = V.verify_stripe("secret", "", b"{}")
    assert not ok and reason == "missing_header"
    ok2, reason2 = V.verify_stripe("secret", "t=123", b"{}")
    assert not ok2 and reason2 == "missing_v1"


def test_twilio_missing_header():
    ok, reason = V.verify_twilio("tk", "", "https://x", {})
    assert not ok and reason == "missing_header"


def test_main_jwks_empty_and_configured(monkeypatch):
    # Unconfigured path: reload without keys
    monkeypatch.delenv("ODIN_SENDER_PRIV_B64", raising=False)
    monkeypatch.delenv("ODIN_SENDER_KID", raising=False)
    from services.sentinel import main as main_mod

    importlib.reload(main_mod)
    from fastapi.testclient import TestClient

    client = TestClient(main_mod.app)
    assert client.get("/.well-known/jwks.json").json() == {"keys": []}

    # Configure and reload
    seed = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    monkeypatch.setenv("ODIN_SENDER_PRIV_B64", seed)
    monkeypatch.setenv("ODIN_SENDER_KID", "kidZ")
    importlib.reload(main_mod)
    client2 = TestClient(main_mod.app)
    data = client2.get("/.well-known/jwks.json").json()
    assert data["keys"] and data["keys"][0]["kid"] == "kidZ"


def test_main_size_limit_and_unknown_source(monkeypatch):
    from services.sentinel import main as main_mod

    main_mod.SET.max_body_bytes = 5
    from fastapi.testclient import TestClient

    client = TestClient(main_mod.app)
    # Oversize
    r = client.post("/hooks/generic", data=b"123456")
    assert r.status_code == 413
    # Unknown source
    r2 = client.post("/hooks/unknown", data=b"{}")
    assert r2.status_code == 404


def test_twilio_missing_host_and_unsupported_content_type(monkeypatch):
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "tok")
    from services.sentinel import main as main_mod

    importlib.reload(main_mod)
    from fastapi.testclient import TestClient

    client = TestClient(main_mod.app)
    # Build signature using placeholder URL that won't matter because host missing triggers early reason
    url = "https://example/hooks/twilio"
    mac = hmac.new(b"tok", url.encode(), hashlib.sha1).digest()
    sig = base64.b64encode(mac).decode()
    r2 = client.post(
        "/hooks/twilio",
        data=b"",
        headers={
            "X-Twilio-Signature": sig,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Forwarded-Proto": "https",
            "X-Original-Uri": "/hooks/twilio",
            "Host": "",  # force empty host so code path sets missing_host
        },
    )
    assert r2.status_code == 400 and r2.json()["reason"] == "missing_host"
