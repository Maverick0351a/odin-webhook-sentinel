import base64
import hashlib
import hmac
import time

from fastapi.testclient import TestClient

from services.sentinel.main import app


def test_app_generic_hmac(monkeypatch):
    monkeypatch.setenv("SENTINEL_GENERIC_SECRET", "s3cr3t")
    client = TestClient(app)
    # set auth token if configured
    monkeypatch.setenv("SENTINEL_AUTH_TOKEN", "token")
    app.dependency_overrides = {}  # ensure fresh dependencies
    headers_common = {"Authorization": "Bearer token"}
    body = b'{"hello":"world"}'
    import hashlib
    import hmac

    sig = hmac.new(b"s3cr3t", body, hashlib.sha256).hexdigest()
    headers = {"X-Signature-256": f"sha256={sig}"}
    headers.update(headers_common)
    r = client.post("/hooks/generic", data=body, headers=headers)
    assert r.status_code == 200
    j = r.json()
    assert j["verified"] is True
    assert j["cid"].startswith("sha256:")


def test_app_twilio(monkeypatch):
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "twilio_token")
    client = TestClient(app)
    monkeypatch.setenv("SENTINEL_AUTH_TOKEN", "token")
    headers_common = {"Authorization": "Bearer token"}
    url = "https://test.local/hooks/twilio"
    params = {"Alpha": "10", "Beta": "20"}
    # Construct signature per Twilio: full URL + concatenated values by sorted key
    pieces = [url] + [params[k] for k in sorted(params.keys())]
    data = "".join(pieces).encode()
    mac = hmac.new(b"twilio_token", data, hashlib.sha1).digest()
    sig = base64.b64encode(mac).decode()
    body = "&".join([f"{k}={v}" for k, v in params.items()])
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Twilio-Signature": sig,
        "Host": "test.local",
        "X-Forwarded-Proto": "https",
        "X-Original-Uri": "/hooks/twilio",
    }
    headers.update(headers_common)
    r = client.post("/hooks/twilio", data=body, headers=headers)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["verified"] is True


def test_app_stripe_old_timestamp(monkeypatch):
    # Provide secret and send old timestamp to ensure 400
    monkeypatch.setenv("SENTINEL_STRIPE_SECRET", "whsec_app")
    client = TestClient(app)
    monkeypatch.setenv("SENTINEL_AUTH_TOKEN", "token")
    headers_common = {"Authorization": "Bearer token"}
    body = b"{\"k\":1}"
    t = int(time.time()) - 1000
    signed = f"{t}.".encode() + body
    mac = hmac.new(b"whsec_app", signed, hashlib.sha256).hexdigest()
    header = f"t={t},v1={mac}"
    r = client.post("/hooks/stripe", data=body, headers={"Stripe-Signature": header, **headers_common})
    assert r.status_code == 400
    assert r.json()["reason"] == "timestamp_out_of_tolerance"


def test_jsonl_logging(monkeypatch, tmp_path):
    log_file = tmp_path / "events.jsonl"
    monkeypatch.setenv("SENTINEL_GENERIC_SECRET", "s3cr3t")
    monkeypatch.setenv("SENTINEL_LOG_JSONL", str(log_file))
    client = TestClient(app)
    monkeypatch.setenv("SENTINEL_AUTH_TOKEN", "token")
    headers_common = {"Authorization": "Bearer token"}
    body = b"{}"
    sig = hmac.new(b"s3cr3t", body, hashlib.sha256).hexdigest()
    headers = {"X-Signature-256": f"sha256={sig}"}
    headers.update(headers_common)
    r = client.post("/hooks/generic", data=body, headers=headers)
    assert r.status_code == 200
    # File should exist with one line
    data = log_file.read_text().strip().splitlines()
    assert len(data) == 1
    import json as _json

    entry = _json.loads(data[0])
    assert entry["verified"] is True and entry["source"] == "generic"
    # Health endpoint should show storage jsonl
    h = client.get("/healthz")
    assert h.json().get("storage") == "jsonl"
    # readiness
    rdz = client.get("/readyz")
    assert rdz.status_code == 200 and rdz.json().get("ok") is True
