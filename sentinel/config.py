from pydantic import BaseModel


class Settings(BaseModel):
    # generic
    generic_secret: str | None = None
    generic_header: str = "X-Signature-256"

    # github
    github_secret: str | None = None

    # stripe
    stripe_secret: str | None = None
    stripe_tolerance: int = 300

    # forwarding
    odin_gateway_url: str | None = None
    odin_sender_priv_b64: str | None = None
    odin_sender_kid: str | None = None
    odin_api_key: str | None = None
    odin_api_secret: str | None = None

    max_body_bytes: int = 2_000_000  # 2MB

    # twilio
    twilio_auth_token: str | None = None  # Twilio Auth Token for webhook signature verification

    # persistence
    log_jsonl_path: str | None = None  # SENTINEL_LOG_JSONL
    firestore_project: str | None = None  # FIRESTORE_PROJECT

    # rate limiting (optional)
    rate_limit_per_window: int | None = None  # SENTINEL_RATE_LIMIT (requests)
    rate_limit_window_seconds: int = 60  # SENTINEL_RATE_WINDOW (seconds)
    rate_limit_bucket_cap: int = 10000  # SENTINEL_RATE_BUCKET_CAP (max tracked IPs)

    # structured logging toggle
    structured_logging: bool = True  # SENTINEL_STRUCT_LOG ("0" to disable)

    # simple bearer auth token for protected endpoints
    auth_token: str | None = None  # SENTINEL_AUTH_TOKEN
