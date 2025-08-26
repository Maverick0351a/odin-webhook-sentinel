## syntax=docker/dockerfile:1
# Multi-stage for cleaner final image
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
        PYTHONUNBUFFERED=1 \
        PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy only project metadata first (enable layer caching)
COPY pyproject.toml README.md /app/
RUN pip install --upgrade pip && pip wheel --no-deps --wheel-dir /wheels .

# Copy source for runtime stage
FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="odin-webhook-sentinel" \
        org.opencontainers.image.description="Verify & forward webhooks with cryptographic attestations" \
        org.opencontainers.image.source="https://github.com/Maverick0351a/odin-webhook-sentinel" \
        org.opencontainers.image.licenses="Apache-2.0" \
        org.opencontainers.image.vendor="ODIN" \
        org.opencontainers.image.version="1.0.0"
ENV PYTHONDONTWRITEBYTECODE=1 \
        PYTHONUNBUFFERED=1 \
        PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
COPY sentinel /app/sentinel
COPY services /app/services

# Create non-root user
RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8787
ENV PORT=8787
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import sys,urllib.request,json;\
    import os;\
    url=f'http://127.0.0.1:{os.environ.get("PORT","8787")}/healthz';\
    r=json.loads(urllib.request.urlopen(url, timeout=2).read() or '{}');\
    sys.exit(0 if r.get('ok') else 1)" || exit 1

CMD ["uvicorn", "services.sentinel.main:app", "--host", "0.0.0.0", "--port", "8787"]
