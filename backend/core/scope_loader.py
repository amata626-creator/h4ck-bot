"""
Loads and enforces the authorized-scope file (scope.yaml).

This is the authorization boundary. The API refuses any assessment
whose target is not in the loaded scope file. There is deliberately no
API or UI path to add a target - scope changes are made by editing the
file on the server, by the operator, with the authorization reference
documented alongside.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass(frozen=True)
class ScopeEntry:
    host: str
    note: str = ""
    permitted_techniques: tuple[str, ...] = ("passive_recon", "port_scan")
    active_testing_permitted: bool = False
    destructive_actions_allowed: bool = False


@dataclass(frozen=True)
class Scope:
    authorized_by: str
    authorization_ref: str
    targets: tuple[ScopeEntry, ...] = field(default_factory=tuple)

    def find(self, target: str) -> Optional[ScopeEntry]:
        """Exact host match, or subdomain match against a listed apex.

        'scanme.nmap.org' matches an entry for 'scanme.nmap.org'.
        'api.acme.com' matches an entry for 'acme.com' (suffix match).
        A bare IP only matches itself.
        """
        target = target.strip().lower()
        for entry in self.targets:
            h = entry.host.lower()
            if target == h:
                return entry
            if target.endswith("." + h):
                return entry
        return None

    def is_authorized(self, target: str) -> bool:
        return self.find(target) is not None


class ScopeError(RuntimeError):
    """Raised when a target is not covered by the loaded scope."""


def load_scope(path: Path | str) -> Scope:
    p = Path(path)
    if not p.is_file():
        raise ScopeError(
            f"scope file not found at {p.resolve()} - refusing to start. "
            "Create scope.yaml listing every authorized target before running."
        )
    raw = yaml.safe_load(p.read_text()) or {}

    entries = []
    for t in raw.get("targets", []):
        entries.append(ScopeEntry(
            host=str(t["host"]),
            note=str(t.get("note", "")),
            permitted_techniques=tuple(t.get("permitted_techniques", ["passive_recon", "port_scan"])),
            active_testing_permitted=bool(t.get("active_testing_permitted", False)),
            destructive_actions_allowed=bool(t.get("destructive_actions_allowed", False)),
        ))

    if not entries:
        raise ScopeError(
            f"scope file at {p.resolve()} lists no targets - refusing to start. "
            "Add at least one target, or you have no authorized scope to run against."
        )

    return Scope(
        authorized_by=str(raw.get("authorized_by", "")),
        authorization_ref=str(raw.get("authorization_ref", "")),
        targets=tuple(entries),
    )


def build_roe(assessment_id: str, target: str, scope: Scope):
    """Build a RulesOfEngagement for a specific target, using the scope
    file's per-target permissions. Raises ScopeError if the target is
    not authorized."""
    from datetime import datetime, timedelta, timezone
    from core.rules_of_engagement import RulesOfEngagement

    entry = scope.find(target)
    if entry is None:
        raise ScopeError(
            f"target '{target}' is not in the authorized scope. "
            f"Authorized targets: {[e.host for e in scope.targets]}. "
            "Add it to scope.yaml with a real authorization reference first."
        )

    now = datetime.now(timezone.utc)
    return RulesOfEngagement(
        assessment_id=assessment_id,
        authorized_by=scope.authorized_by,
        authorized_targets=[entry.host],
        testing_window_start=now - timedelta(minutes=1),
        testing_window_end=now + timedelta(hours=4),
        permitted_techniques=list(entry.permitted_techniques),
        active_testing_permitted=entry.active_testing_permitted,
        destructive_actions_allowed=entry.destructive_actions_allowed,
    )
