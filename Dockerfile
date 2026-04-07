# ── Build Stage ──────────────────────────────────────────
FROM python:3.9-alpine3.19 AS builder

# Install build-time dependencies only
RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev mariadb-dev

WORKDIR /app

# Copy and install dependencies first (better layer caching)
COPY Backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime Stage ─────────────────────────────────────────
FROM python:3.9-alpine3.19

# Install only runtime libs needed (not full dev packages)
RUN apk add --no-cache libstdc++ mariadb-connector-c \
    && adduser -D appuser

WORKDIR /app

# Copy installed packages from builder (with ownership in one step)
COPY --from=builder --chown=appuser:appuser /install /usr/local
COPY --chown=appuser:appuser Backend/ Backend/

USER appuser

EXPOSE 8000

CMD ["uvicorn", "Backend.main:app", "--host", "0.0.0.0", "--port", "8000"]