import base64
import hashlib
import hmac
import importlib
import sys
import types

from fastapi.testclient import TestClient


def test_post_verify_error_reason(monkeypatch):
    # Configure env for generic verification + forwarding
    seed = base64.urlsafe_b64encode(b"d" * 32).decode().rstrip("=")
    monkeypatch.setenv("SENTINEL_GENERIC_SECRET", "gsecret2")
    monkeypatch.setenv("ODIN_SENDER_PRIV_B64", seed)
    monkeypatch.setenv("ODIN_SENDER_KID", "kidErr")
    monkeypatch.setenv("ODIN_GATEWAY_URL", "https://gw.example")
    # induce error in forward_to_gateway
    import sentinel.odin_client as oc

    async def boom(*a, **k):  # noqa: D401
        raise RuntimeError("boom")

    monkeypatch.setattr(oc, "forward_to_gateway", boom)
    # Reload main to ensure settings pick up odin vars
    from services.sentinel import main as main_mod

    importlib.reload(main_mod)
    client = TestClient(main_mod.app)
    body = b'{"k":1}'
    sig = hmac.new(b"gsecret2", body, hashlib.sha256).hexdigest()
    r = client.post("/hooks/generic", data=body, headers={"X-Signature-256": f"sha256={sig}"})
    assert r.status_code == 200
    j = r.json()
    assert j["verified"] is True and j["reason"].startswith("post_verify_error:")


def test_firestore_branch(monkeypatch):
    monkeypatch.setenv("FIRESTORE_PROJECT", "proj-123")
    monkeypatch.setenv("SENTINEL_GENERIC_SECRET", "gsecret3")
    captured = {}

    class Client:  # pragma: no cover (executed via test but internal lines not critical)
        def __init__(self, project):
            captured["project"] = project

        # Firestore chainable stubs
        def collection(self, name):
            captured["collection"] = name
            return self

        def document(self, doc_id):
            captured["doc_id"] = doc_id
            return self

        def set(self, meta):
            captured["meta"] = meta
            return None

    import types
    import sys
    google_mod = types.ModuleType("google")
    cloud_mod = types.ModuleType("google.cloud")
    firestore_mod = types.ModuleType("google.cloud.firestore")
    firestore_mod.Client = Client
    sys.modules["google"] = google_mod
    sys.modules["google.cloud"] = cloud_mod
    sys.modules["google.cloud.firestore"] = firestore_mod
    import importlib
    from services.sentinel import main as main_mod
    importlib.reload(main_mod)  # ensure SET picks up env
    client = TestClient(main_mod.app)
    body = b"{}"
    sig = hmac.new(b"gsecret3", body, hashlib.sha256).hexdigest()
    r = client.post("/hooks/generic", data=body, headers={"X-Signature-256": f"sha256={sig}"})
    assert r.status_code == 200
    assert captured.get("project") == "proj-123"
    assert captured.get("collection") == "sentinel_events"
    assert "meta" in captured and captured["meta"]["verified"] is True


def test_twilio_parse_exception(monkeypatch):
    # Configure Twilio token
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "tokP")
    from services.sentinel import main as main_mod
    import importlib
    importlib.reload(main_mod)
    from fastapi.testclient import TestClient
    client = TestClient(main_mod.app)
    url = "https://ex.local/hooks/twilio"
    import hmac, base64
    mac = hmac.new(b"tokP", url.encode(), __import__("hashlib").sha1).digest()
    sig = base64.b64encode(mac).decode()
    # Body with invalid UTF-8 to trigger parse exception path
    body = b"\xff\xfe\xfd"
    r = client.post(
        "/hooks/twilio",
        data=body,
        headers={
            "X-Twilio-Signature": sig,
            "Host": "ex.local",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Forwarded-Proto": "https",
            "X-Original-Uri": "/hooks/twilio",
        },
    )
    # Should still verify (empty params) and hit parse-exception branch
    assert r.status_code == 200 and r.json()["verified"] is True


def test_firestore_exception_path(monkeypatch):
    monkeypatch.setenv("FIRESTORE_PROJECT", "proj-err")
    monkeypatch.setenv("SENTINEL_GENERIC_SECRET", "gsecretX")
    captured = {"collection_called": False}
    class Client:
        def __init__(self, project):
            pass
        def collection(self, name):
            captured["collection_called"] = True
            raise RuntimeError("boomfs")
    import types, sys
    google_mod = types.ModuleType("google")
    cloud_mod = types.ModuleType("google.cloud")
    firestore_mod = types.ModuleType("google.cloud.firestore")
    firestore_mod.Client = Client
    sys.modules["google"] = google_mod
    sys.modules["google.cloud"] = cloud_mod
    sys.modules["google.cloud.firestore"] = firestore_mod
    import importlib
    from services.sentinel import main as main_mod
    importlib.reload(main_mod)
    from fastapi.testclient import TestClient
    client = TestClient(main_mod.app)
    body = b"{}"
    import hashlib, hmac
    sig = hmac.new(b"gsecretX", body, hashlib.sha256).hexdigest()
    r = client.post("/hooks/generic", data=body, headers={"X-Signature-256": f"sha256={sig}"})
    assert r.status_code == 200 and captured["collection_called"] is True
