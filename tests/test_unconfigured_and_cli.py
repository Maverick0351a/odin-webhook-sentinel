import importlib
import os

from fastapi.testclient import TestClient


def _reload_main_clear():
    # Clear provider secrets
    for k in [
        "SENTINEL_GENERIC_SECRET",
        "SENTINEL_GITHUB_SECRET",
        "SENTINEL_STRIPE_SECRET",
        "TWILIO_AUTH_TOKEN",
        "ODIN_SENDER_PRIV_B64",
        "ODIN_SENDER_KID",
        "ODIN_GATEWAY_URL",
        "ODIN_API_KEY",
        "ODIN_API_SECRET",
        "SENTINEL_LOG_JSONL",
    ]:
        os.environ.pop(k, None)
    from services.sentinel import main as main_mod

    importlib.reload(main_mod)
    return main_mod


def test_unconfigured_generic_reason():
    main_mod = _reload_main_clear()
    client = TestClient(main_mod.app)
    r = client.post("/hooks/generic", data=b"{}")
    assert r.status_code == 400
    assert r.json()["reason"] == "generic_secret_not_set"


def test_unconfigured_github_reason():
    main_mod = _reload_main_clear()
    client = TestClient(main_mod.app)
    r = client.post("/hooks/github", data=b"{}")
    assert r.status_code == 400
    assert r.json()["reason"] == "github_secret_not_set"


def test_unconfigured_stripe_reason():
    main_mod = _reload_main_clear()
    client = TestClient(main_mod.app)
    r = client.post("/hooks/stripe", data=b"{}")
    assert r.status_code == 400
    assert r.json()["reason"] == "stripe_secret_not_set"


def test_unconfigured_twilio_reason():
    main_mod = _reload_main_clear()
    client = TestClient(main_mod.app)
    r = client.post("/hooks/twilio", data=b"A=1&B=2")
    assert r.status_code == 400
    assert r.json()["reason"] == "twilio_auth_token_not_set"


def test_cli_main_invokes_uvicorn(monkeypatch):
    # Ensure host/port env applied
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.setenv("PORT", "9999")
    called = {}

    def fake_run(app_path, host, port, reload):  # signature from main.main
        called["app_path"] = app_path
        called["host"] = host
        called["port"] = port
        called["reload"] = reload

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    from services.sentinel import main as main_mod

    importlib.reload(main_mod)
    main_mod.main()  # call CLI entrypoint
    assert called == {
        "app_path": "services.sentinel.main:app",
        "host": "127.0.0.1",
        "port": 9999,
        "reload": False,
    }
