import base64
import hashlib
import hmac
import time
from collections.abc import Mapping


def _cteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def verify_generic_hmac_sha256(secret: str, header_value: str, body: bytes) -> tuple[bool, str]:
    # header_value format: 'sha256=<hex>'
    try:
        if not header_value:
            return False, "missing_header"
        if header_value.startswith("sha256="):
            provided = header_value.split("=", 1)[1].strip()
        else:
            # allow plain hex
            provided = header_value.strip()
        mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        return (_cteq(mac, provided), "ok" if _cteq(mac, provided) else "mismatch")
    except Exception as e:
        return False, f"error:{e}"


def verify_github(secret: str, header_value: str, body: bytes) -> tuple[bool, str]:
    # GitHub: X-Hub-Signature-256: 'sha256=<hex>'
    return verify_generic_hmac_sha256(secret, header_value, body)


def _parse_stripe_sig_header(header: str) -> dict[str, str]:
    parts = {}
    for chunk in header.split(","):
        if "=" in chunk:
            k, v = chunk.strip().split("=", 1)
            parts.setdefault(k, []).append(v)
    # flatten singletons for convenience; keep list for v1
    out = {}
    for k, vals in parts.items():
        if k == "v1":
            out[k] = vals
        else:
            out[k] = vals[0]
    return out


def verify_stripe(
    secret: str, stripe_sig_header: str, body: bytes, tolerance: int = 300
) -> tuple[bool, str]:
    # Signed payload = f"{t}.{body}"; compare HMAC-SHA256(secret) hex to any v1
    if not stripe_sig_header:
        return False, "missing_header"
    try:
        parts = _parse_stripe_sig_header(stripe_sig_header)
        t = int(parts.get("t", "0"))
        v1_list = parts.get("v1", [])
        if not v1_list:
            return False, "missing_v1"
        now = int(time.time())
        if tolerance and abs(now - t) > tolerance:
            return False, "timestamp_out_of_tolerance"
        signed = f"{t}.".encode() + body
        mac = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
        for v in v1_list:
            if _cteq(mac, v):
                return True, "ok"
        return False, "mismatch"
    except Exception as e:
        return False, f"error:{e}"


def verify_twilio(
    auth_token: str, twilio_signature: str, full_url: str, form_params: Mapping[str, str]
) -> tuple[bool, str]:
    """Verify Twilio webhook per docs:
    - Construct string: full URL + concatenated parameter values ordered by param name (lexicographically) of the POST form (application/x-www-form-urlencoded)
    - Compute HMAC-SHA1 with auth_token, base64 encode
    - Compare to X-Twilio-Signature
    """
    try:
        if not twilio_signature:
            return False, "missing_header"
        # Sort parameters by name, concatenate values only
        pieces = [full_url]
        for k in sorted(form_params.keys()):
            pieces.append(str(form_params[k]))
        data = "".join(pieces).encode("utf-8")
        mac = hmac.new(auth_token.encode("utf-8"), data, hashlib.sha1).digest()
        expected = base64.b64encode(mac).decode("ascii")
        return (
            _cteq(expected, twilio_signature),
            "ok" if _cteq(expected, twilio_signature) else "mismatch",
        )
    except Exception as e:
        return False, f"error:{e}"
