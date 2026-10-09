#!/usr/bin/env bash
#
# H4CK-B0T installer / bootstrap.
#
# Idempotent: safe to run repeatedly. It never overwrites an existing
# .env or scope.yaml, and never scans anything — it only sets up the
# environment. Run it from the repo root after `git clone` / `git pull`:
#
#     ./install.sh
#
# Then edit scope.yaml to list targets you are AUTHORIZED to test, and
# start the API with the command printed at the end.

set -euo pipefail

# ── Resolve repo root (the dir this script lives in) ────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m   %s\n' "$*"; }

# ── 1. Python version check (need 3.11+) ───────────────────────────
say "Checking Python"
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install Python 3.11+ and re-run." >&2
  exit 1
fi
PYVER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
"$PY" - <<'PYEOF' || { echo "ERROR: Python 3.11+ required (found $PYVER)." >&2; exit 1; }
import sys
sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)
PYEOF
ok "Python $PYVER"

# ── 2. Virtualenv ──────────────────────────────────────────────────
say "Setting up virtualenv (.venv)"
if [[ ! -d .venv ]]; then
  "$PY" -m venv .venv
  ok "created .venv"
else
  ok ".venv already exists"
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip

# ── 3. Python dependencies ─────────────────────────────────────────
say "Installing Python dependencies (requirements.txt)"
python -m pip install --quiet -r requirements.txt
ok "dependencies installed"

# ── 4. Playwright browser (for screenshot evidence) ────────────────
say "Installing Playwright Chromium (screenshot evidence)"
# The Python package is installed above; this fetches the browser binary.
# --with-deps needs root for OS libraries; try it, fall back gracefully.
if python -m playwright install --with-deps chromium 2>/dev/null; then
  ok "Chromium + OS deps installed"
elif python -m playwright install chromium; then
  ok "Chromium installed (OS deps not auto-installed)"
  warn "If screenshots fail, install system libs: sudo python -m playwright install-deps chromium"
else
  warn "Playwright Chromium install failed. Screenshots will be skipped at scan"
  warn "time (findings still generate; the evidence layer degrades gracefully)."
fi

# ── 5. Admin token (.env) ──────────────────────────────────────────
say "Admin token (.env)"
if [[ -f .env ]] && grep -q '^H4CK_BOT_ADMIN_TOKEN=.\+' .env \
   && ! grep -q 'replace-me' .env; then
  ok ".env already has an admin token — leaving it untouched"
else
  TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
  # Preserve any other lines already in .env; only (re)set the token line.
  if [[ -f .env ]]; then
    grep -v '^H4CK_BOT_ADMIN_TOKEN=' .env > .env.tmp || true
    mv .env.tmp .env
  fi
  echo "H4CK_BOT_ADMIN_TOKEN=$TOKEN" >> .env
  chmod 600 .env
  ok "generated a new admin token in .env (kept private, chmod 600)"
fi

# ── 5b. Dashboard session secret (for the login page) ──────────────
say "Dashboard session secret (.env)"
if [[ -f .env ]] && grep -q '^H4CK_BOT_SESSION_SECRET=.\+' .env; then
  ok ".env already has a session secret — leaving it untouched"
else
  SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
  echo "H4CK_BOT_SESSION_SECRET=$SECRET" >> .env
  chmod 600 .env
  ok "generated a dashboard session secret"
fi
# The login gate turns on only once an admin PASSWORD is set. Nudge if not.
if ! { [[ -f .env ]] && grep -q '^H4CK_BOT_ADMIN_PASSWORD_HASH=.\+' .env; }; then
  warn "No dashboard password set yet — the login page is INACTIVE until you run:"
  warn "    python backend/api/auth.py set-password admin"
  warn "    sudo systemctl restart h4ckbot"
fi

# ── 6. Scope file (authorization boundary) ─────────────────────────
say "Scope file (scope.yaml)"
if [[ -f scope.yaml ]]; then
  ok "scope.yaml already exists — leaving it untouched"
else
  cp scope.yaml.example scope.yaml
  warn "created scope.yaml from the example. IT CONTAINS NO REAL TARGETS."
  warn "Edit it to list only hosts you are AUTHORIZED to test before scanning."
fi

# ── 7. Data dir (SQLite + evidence artifacts) ──────────────────────
mkdir -p data/evidence
ok "data/ ready (SQLite db + evidence artifacts live here)"

# ── 8. Ollama check (optional — local LLM validation layer) ────────
say "Checking Ollama (local LLM, optional)"
OLLAMA_URL="${OLLAMA_BASE_URL:-http://localhost:11434}"
OLLAMA_MODEL="${H4CK_BOT_LLM_MODEL:-qwen2.5:3b}"
if curl -fsS "$OLLAMA_URL/api/tags" >/dev/null 2>&1; then
  ok "Ollama is reachable at $OLLAMA_URL"
  if curl -fsS "$OLLAMA_URL/api/tags" | grep -q "\"$OLLAMA_MODEL"; then
    ok "model '$OLLAMA_MODEL' is available"
  else
    warn "model '$OLLAMA_MODEL' not pulled yet. Pull it with:"
    warn "    ollama pull $OLLAMA_MODEL"
    warn "(Without it, the AI-assisted validation layer reports 'unavailable'"
    warn " and the other validation layers still run.)"
  fi
else
  warn "Ollama not reachable at $OLLAMA_URL — the AI-assisted validation layer"
  warn "will be skipped. Install from https://ollama.com, run 'ollama serve',"
  warn "then 'ollama pull $OLLAMA_MODEL'. Everything else works without it."
fi

# ── 9. Nuclei check (optional — template/CVE detection engine) ─────
say "Checking Nuclei (detection engine, optional)"
if command -v nuclei >/dev/null 2>&1; then
  ok "nuclei found: $(nuclei -version 2>&1 | head -1)"
  if nuclei -update-templates -silent >/dev/null 2>&1; then
    ok "nuclei templates updated"
  else
    warn "could not update nuclei templates (offline?) — existing templates still used"
  fi
else
  warn "nuclei not installed — the 'nuclei' module will no-op (scans still run)."
  warn "Install it to add CVE/exposure/misconfig coverage, e.g.:"
  warn "    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  warn "  or download a release binary from https://github.com/projectdiscovery/nuclei/releases"
  warn "  then: nuclei -update-templates"
fi

# ── Done ───────────────────────────────────────────────────────────
cat <<EOF

$(ok "Install complete.")

Next steps:
  1. Edit scope.yaml — list ONLY targets you are authorized to test.
  2. Start the API (bound to loopback):

       source .venv/bin/activate
       cd backend && uvicorn api.main:app --host 127.0.0.1 --port 8080

     Then open http://127.0.0.1:8080/  (tunnel in with
     'ssh -L 8080:127.0.0.1:8080 <user>@<host>' if it's on a server).

  3. The admin token for POST /api/assessments/run is in .env
     (H4CK_BOT_ADMIN_TOKEN). Send it as:  Authorization: Bearer <token>

EOF
