# Send a signed 'generic' webhook to localhost:8787
import hashlib
import hmac
import json
import os

import httpx

body = {"event": "demo", "amount": 123}
b = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
secret = os.getenv("SENTINEL_GENERIC_SECRET", "change-me")
mac = hmac.new(secret.encode("utf-8"), b, hashlib.sha256).hexdigest()

headers = {"X-Signature-256": f"sha256={mac}", "Content-Type": "application/json"}
url = "http://127.0.0.1:8787/hooks/generic"

print("POST", url, "headers:", headers)
r = httpx.post(url, headers=headers, content=b, timeout=10)
print(r.status_code, r.text)
