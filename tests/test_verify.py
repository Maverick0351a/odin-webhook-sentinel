import base64
import hashlib
import hmac
import time

from sentinel import verify as V


def test_generic_hmac():
    secret = "topsecret"
    body = b'{"x":1}'
    mac = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    ok, reason = V.verify_generic_hmac_sha256(secret, f"sha256={mac}", body)
    assert ok and reason == "ok"


def test_stripe_ok_and_window():
    secret = "whsec_abc"
    body = b'{"y":2}'
    t = int(time.time())
    signed = f"{t}.".encode() + body
    mac = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    header = f"t={t},v1={mac}"
    ok, reason = V.verify_stripe(secret, header, body, tolerance=300)
    assert ok


def test_stripe_bad_sig():
    body = b"{}"
    ok, reason = V.verify_stripe("wh", "t=1,v1=deadbeef", body, tolerance=300)
    assert ok is False


def test_stripe_old_timestamp():
    secret = "whsec_old"
    body = b"{\"o\":1}"
    t = int(time.time()) - 1000  # beyond 300s default
    signed = f"{t}.".encode() + body
    mac = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    header = f"t={t},v1={mac}"
    ok, reason = V.verify_stripe(secret, header, body, tolerance=300)
    assert not ok and reason == "timestamp_out_of_tolerance"


def test_stripe_wrong_secret():
    good_secret = "good"
    bad_secret = "bad"
    body = b"{\"z\":9}"
    t = int(time.time())
    signed = f"{t}.".encode() + body
    mac = hmac.new(good_secret.encode(), signed, hashlib.sha256).hexdigest()
    header = f"t={t},v1={mac}"
    ok, reason = V.verify_stripe(bad_secret, header, body, tolerance=300)
    assert not ok and reason == "mismatch"


def test_stripe_multiple_v1_accept_any():
    secret = "whsec_multi"
    body = b"{\"multi\":true}"
    t = int(time.time())
    signed = f"{t}.".encode() + body
    mac_good = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    mac_bad = "deadbeef" * 8  # 64 hex chars
    header = f"t={t},v1={mac_bad},v1={mac_good}"
    ok, reason = V.verify_stripe(secret, header, body, tolerance=300)
    assert ok and reason == "ok"


def test_twilio_verify_function():
    token = "twilio_token"
    url = "https://example.com/hooks/twilio"
    params = {"A": "1", "B": "2"}
    # Build expected signature
    pieces = [url] + [params[k] for k in sorted(params.keys())]
    data = "".join(pieces).encode()
    mac = hmac.new(token.encode(), data, hashlib.sha1).digest()
    sig = base64.b64encode(mac).decode()
    ok, reason = V.verify_twilio(token, sig, url, params)
    assert ok and reason == "ok"
