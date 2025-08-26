import base64
import datetime
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_cid(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s or "") + pad)


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def ed25519_from_seed_b64(seed_b64: str) -> Ed25519PrivateKey:
    seed = b64u_decode(seed_b64)
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes (base64url)")
    return Ed25519PrivateKey.from_private_bytes(seed)


def sign_ed25519(seed_b64: str, message: bytes) -> str:
    sk = ed25519_from_seed_b64(seed_b64)
    sig = sk.sign(message)
    return b64u(sig)


def public_jwk_from_seed(seed_b64: str, kid: str) -> dict[str, str]:
    sk = ed25519_from_seed_b64(seed_b64)
    pk: Ed25519PublicKey = sk.public_key()
    pub_raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub_raw), "kid": kid}


def jwks_from_seed(seed_b64: str, kid: str) -> dict[str, Any]:
    return {"keys": [public_jwk_from_seed(seed_b64, kid)]}
