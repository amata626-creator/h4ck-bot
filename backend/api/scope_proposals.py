"""
Proposal store for scope changes.

The authoritative scope.yaml is NEVER written by the API. This module
lets an authenticated operator *propose* additions to scope, which land
in scope.proposed.yaml. Promotion into the real scope is a manual,
out-of-band action (see scripts/scope_promote.sh) that requires shell
access to the server.

Security model:
  - Every write requires H4CK_BOT_ADMIN_TOKEN, a secret set in the
    server environment. If unset, the API refuses to start rather than
    silently allowing anonymous writes.
  - Every proposal is appended to scope_audit.log with the timestamp
    and the client IP, so there's a record of who tried to add what.
  - Nothing the API writes is scannable until an admin promotes it by
    hand. The worst a leaked token gets you is polluting the proposal
    queue, which an admin reviews before anything takes effect.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

logger = logging.getLogger("h4ck-bot.scope_proposals")


@dataclass
class Proposal:
    proposal_id: str
    host: str
    note: str
    authorization_ref: str
    permitted_techniques: list[str] = field(default_factory=lambda: [
        "passive_recon", "port_scan", "misconfig_check",
    ])
    active_testing_permitted: bool = False
    destructive_actions_allowed: bool = False
    proposed_at: str = ""
    proposed_from_ip: str = ""
    status: str = "pending"          # "pending" | "promoted" | "rejected"
    decided_at: str = ""


def _token() -> str:
    tok = os.environ.get("H4CK_BOT_ADMIN_TOKEN", "")
    if not tok:
        raise RuntimeError(
            "H4CK_BOT_ADMIN_TOKEN is not set. The API will not start "
            "without it. Generate one with:\n"
            "  python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"\n"
            "and put it in /home/ubuntu/h4ck-bot/.env, then restart with:\n"
            "  set -a; source /home/ubuntu/h4ck-bot/.env; set +a\n"
            "  uvicorn api.main:app --host 0.0.0.0 --port 8080"
        )
    return tok


def verify_token(presented: str | None) -> bool:
    """Constant-time comparison against the configured token."""
    if not presented:
        return False
    try:
        expected = _token()
    except RuntimeError:
        return False
    return hmac.compare_digest(presented, expected)


class ProposalStore:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.path = base_dir / "scope.proposed.yaml"
        self.audit_path = base_dir / "scope_audit.log"
        self._ensure()

    def _ensure(self) -> None:
        if not self.path.exists():
            self.path.write_text("proposals: []\n")
        if not self.audit_path.exists():
            self.audit_path.touch(mode=0o600)

    def _load(self) -> list[Proposal]:
        raw = yaml.safe_load(self.path.read_text()) or {}
        return [Proposal(**p) for p in raw.get("proposals", [])]

    def _save(self, proposals: list[Proposal]) -> None:
        self.path.write_text(yaml.safe_dump(
            {"proposals": [asdict(p) for p in proposals]},
            sort_keys=False,
        ))

    def _audit(self, action: str, host: str, ip: str, note: str = "") -> None:
        line = json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "host": host,
            "ip": ip,
            "note": note,
        })
        with self.audit_path.open("a") as f:
            f.write(line + "\n")

    def propose(self, host: str, note: str, authorization_ref: str,
                ip: str) -> Proposal:
        host = host.strip().lower()
        if not host:
            raise ValueError("host must not be empty")
        if len(host) > 253:
            raise ValueError("host too long")
        if not authorization_ref.strip():
            raise ValueError(
                "authorization_ref is required - state why you are "
                "authorized to scan this target (engagement ref, bug "
                "bounty program, 'my own infrastructure', etc.)"
            )

        proposals = self._load()
        # Refuse if already pending or already in the file
        for p in proposals:
            if p.host == host and p.status == "pending":
                raise ValueError(f"'{host}' is already proposed (pending review)")

        prop = Proposal(
            proposal_id=str(uuid.uuid4()),
            host=host,
            note=note.strip(),
            authorization_ref=authorization_ref.strip(),
            proposed_at=datetime.now(timezone.utc).isoformat(),
            proposed_from_ip=ip,
        )
        proposals.append(prop)
        self._save(proposals)
        self._audit("propose", host, ip, note)
        logger.info("proposed target %s from %s", host, ip)
        return prop

    def list_pending(self) -> list[Proposal]:
        return [p for p in self._load() if p.status == "pending"]

    def reject(self, proposal_id: str, ip: str) -> bool:
        proposals = self._load()
        for p in proposals:
            if p.proposal_id == proposal_id and p.status == "pending":
                p.status = "rejected"
                p.decided_at = datetime.now(timezone.utc).isoformat()
                self._save(proposals)
                self._audit("reject", p.host, ip)
                return True
        return False
