#!/usr/bin/env bash
# Start the H4CK-B0T API bound to loopback only.
# Reach it from your laptop with an SSH tunnel:
#   ssh -L 8080:127.0.0.1:8080 ubuntu@51.77.137.181
# Then browse to http://127.0.0.1:8080/
#
# To bind publicly (NOT recommended - only for a demo where you
# accept the exposure), pass --public:
set -euo pipefail
cd "$(dirname "$0")/backend"
set -a
[[ -f ../.env ]] && source ../.env
set +a
HOST="127.0.0.1"
if [[ "${1:-}" == "--public" ]]; then
  HOST="0.0.0.0"
  shift
fi
exec /home/ubuntu/h4ck-bot/.venv/bin/uvicorn api.main:app \
  --host "$HOST" --port 8080 "$@"
