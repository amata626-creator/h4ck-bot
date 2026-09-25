#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/backend"
# Load .env so H4CK_BOT_ADMIN_TOKEN is in the environment
set -a
[[ -f ../.env ]] && source ../.env
set +a
exec /home/ubuntu/h4ck-bot/.venv/bin/uvicorn api.main:app \
  --host 0.0.0.0 --port 8080 "$@"
