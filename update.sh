#!/usr/bin/env bash
#
# One-command update for a deployed H4CK-B0T box:  ./update.sh
# Pulls latest code, runs the idempotent installer, restarts the service.
# Never touches scope.yaml or .env (authorization + admin token preserved).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

say() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }

say "Pulling latest code"
git pull --ff-only

say "Running installer (idempotent)"
./install.sh

say "Restarting service"
# `systemctl cat` finds the unit whether or not it has a persistent unit
# file (list-unit-files misses runtime/transient units).
if systemctl cat h4ckbot >/dev/null 2>&1; then
  sudo systemctl restart h4ckbot
  sleep 3
  systemctl is-active h4ckbot
  say "Done — h4ckbot restarted on the latest code."
else
  say "No 'h4ckbot' systemd service found. Start the API manually:"
  echo "    source .venv/bin/activate && cd backend && uvicorn api.main:app --host 127.0.0.1 --port 8080"
fi
