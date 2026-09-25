"""
Rules of Engagement (RoE) - the authorization envelope for an assessment.
An assessment cannot run without an explicit RoE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class RulesOfEngagement:
    assessment_id: str
    authorized_by: str
    authorized_targets: list[str]
    testing_window_start: datetime
    testing_window_end: datetime
    permitted_techniques: list[str]
    restricted_techniques: list[str] = field(default_factory=list)
    active_testing_permitted: bool = True
    destructive_actions_allowed: bool = False
    emergency_contact: str = ""
    stop_conditions: list[str] = field(default_factory=list)

    def is_active_now(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.testing_window_start <= now <= self.testing_window_end

    def permits(self, technique: str) -> bool:
        if technique in self.restricted_techniques:
            return False
        return technique in self.permitted_techniques

    def target_authorized(self, target: str) -> bool:
        return any(target == t or target.endswith(f".{t}") for t in self.authorized_targets)
