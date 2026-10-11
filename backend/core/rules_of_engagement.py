"""
Rules of Engagement (RoE) - the authorization envelope for an assessment.
An assessment cannot run without an explicit RoE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

# "active_testing" is an UMBRELLA authorization token: it grants the family of
# non-destructive, active web/API techniques below. The universal one-click
# authorization grants "active_testing" (the operator attests they may actively
# test the target), so without this umbrella every specific active technique
# (injection_testing, xss_testing, ...) would be skipped despite that explicit
# grant. Destructive actions are NOT in this family — they are gated separately
# by destructive_actions_allowed and always require human approval.
ACTIVE_TESTING_FAMILY = frozenset({
    "authz_testing", "auth_testing", "injection_testing", "xss_testing", "api_testing",
})


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
            return False          # an explicit restriction always wins
        if technique in self.permitted_techniques:
            return True
        # Umbrella: granting "active_testing" authorizes the non-destructive
        # active technique family (how universal authorization is expressed).
        if "active_testing" in self.permitted_techniques and technique in ACTIVE_TESTING_FAMILY:
            return True
        return False

    def target_authorized(self, target: str) -> bool:
        return any(target == t or target.endswith(f".{t}") for t in self.authorized_targets)
