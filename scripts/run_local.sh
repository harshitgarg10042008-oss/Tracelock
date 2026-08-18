#!/usr/bin/env bash
set -euo pipefail

ROLE="${TRACELOCK_SERVICE_ROLE:-gateway}"
NAME="${TRACELOCK_SERVICE_NAME:-tracelock-${ROLE}}"
PORT="${TRACELOCK_PORT:-8000}"

export TRACELOCK_SERVICE_ROLE="$ROLE"
export TRACELOCK_SERVICE_NAME="$NAME"
export TRACELOCK_ENVIRONMENT="${TRACELOCK_ENVIRONMENT:-local}"

exec uvicorn tracelock_services.app:app --host "${TRACELOCK_HOST:-127.0.0.1}" --port "$PORT"
