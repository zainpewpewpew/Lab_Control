#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export $(grep -v '^#' .env | xargs -0 2>/dev/null || cat .env | grep -v '^#' | tr '\n' ' ')
# Export line above: awk fallback for POSIX portability.
set -a; source ./.env; set +a
HOST="${CS_HOST:-0.0.0.0}"
PORT="${CS_PORT:-8443}"
exec ./venv/bin/uvicorn server:app \
  --host "$HOST" --port "$PORT" \
  --ssl-keyfile state/key.pem --ssl-certfile state/cert.pem \
  --log-level info
