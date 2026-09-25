#!/usr/bin/env bash
# Promote a pending scope proposal into the authoritative scope.yaml.
#
# Usage:
#   scope_promote.sh                          # list pending proposals
#   scope_promote.sh <proposal_id>            # promote one
#   scope_promote.sh --reject <proposal_id>   # reject one
#
# After promotion, restart the API so the new scope is loaded:
#   pkill -f "uvicorn api.main:app"
#   /home/ubuntu/h4ck-bot/run.sh
set -euo pipefail

ROOT="/home/ubuntu/h4ck-bot"
PROPOSED="${ROOT}/scope.proposed.yaml"
SCOPE="${ROOT}/scope.yaml"
VENV_PY="${ROOT}/.venv/bin/python"

if [[ ! -f "$PROPOSED" ]]; then
  echo "No proposals file at $PROPOSED"
  exit 0
fi

# ── Argument parsing ────────────────────────────────────────────────
# Accept three forms:
#   (no args)                 -> list
#   <uuid>                    -> promote that proposal
#   --reject <uuid>           -> reject that proposal
ACTION=""
TARGET_ID=""
case "${1:-}" in
  ""|list)          ACTION="list" ;;
  --reject)         ACTION="reject"; TARGET_ID="${2:-}" ;;
  --promote)        ACTION="promote"; TARGET_ID="${2:-}" ;;
  *)                ACTION="promote"; TARGET_ID="$1" ;;   # bare uuid
esac

"$VENV_PY" - "$ACTION" "$PROPOSED" "$SCOPE" "$TARGET_ID" << 'PYEOF'
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path

action = sys.argv[1]
proposed_path = Path(sys.argv[2])
scope_path = Path(sys.argv[3])
target_id = sys.argv[4] if len(sys.argv) > 4 else ""

data = yaml.safe_load(proposed_path.read_text()) or {"proposals": []}
proposals = data.get("proposals", [])
pending = [p for p in proposals if p.get("status") == "pending"]

if action == "list":
    if not pending:
        print("No pending proposals.")
        sys.exit(0)
    print(f"{len(pending)} pending proposal(s):\n")
    for p in pending:
        print(f"  id:       {p['proposal_id']}")
        print(f"  host:     {p['host']}")
        print(f"  note:     {p.get('note','')}")
        print(f"  authref:  {p.get('authorization_ref','')}")
        print(f"  from:     {p.get('proposed_from_ip','')} at {p.get('proposed_at','')}")
        print()
    print("To promote:  scope_promote.sh <proposal_id>")
    print("To reject:   scope_promote.sh --reject <proposal_id>")
    sys.exit(0)

if not target_id:
    print(f"ERROR: proposal id required for {action}", file=sys.stderr)
    sys.exit(1)

match = next((p for p in pending if p["proposal_id"] == target_id), None)
if not match:
    print(f"ERROR: no pending proposal with id {target_id}", file=sys.stderr)
    print()
    print("Pending proposals:", file=sys.stderr)
    for p in pending:
        print(f"  {p['proposal_id']}  ({p['host']})", file=sys.stderr)
    sys.exit(1)

if action == "reject":
    match["status"] = "rejected"
    match["decided_at"] = datetime.now(timezone.utc).isoformat()
    proposed_path.write_text(yaml.safe_dump({"proposals": proposals}, sort_keys=False))
    print(f"Rejected {match['host']}.")
    sys.exit(0)

# action == "promote"
scope = yaml.safe_load(scope_path.read_text()) or {}
targets = scope.get("targets", [])
if any(t.get("host") == match["host"] for t in targets):
    print(f"NOTE: {match['host']} is already in scope.yaml - marking promoted anyway")
else:
    targets.append({
        "host": match["host"],
        "note": match.get("note", ""),
        "permitted_techniques": match.get("permitted_techniques", ["passive_recon","port_scan","misconfig_check"]),
        "active_testing_permitted": match.get("active_testing_permitted", False),
        "destructive_actions_allowed": match.get("destructive_actions_allowed", False),
    })
    scope["targets"] = targets
    scope_path.write_text(yaml.safe_dump(scope, sort_keys=False))
    print(f"Promoted {match['host']} into scope.yaml.")

match["status"] = "promoted"
match["decided_at"] = datetime.now(timezone.utc).isoformat()
proposed_path.write_text(yaml.safe_dump({"proposals": proposals}, sort_keys=False))

print()
print("Now restart the API for the new scope to take effect:")
print("  pkill -f 'uvicorn api.main:app'")
print("  /home/ubuntu/h4ck-bot/run.sh")
PYEOF
