"""
Planner — turns prioritized hypotheses into a gated, auditable assessment plan.

This is where "autonomous" is kept honest. Every hypothesis is checked against
the Rules of Engagement before it can run:

  - technique must be in the RoE's permitted_techniques, or it is SKIPPED;
  - active testing requires roe.active_testing_permitted, or SKIPPED;
  - destructive actions require roe.destructive_actions_allowed, and even then
    always wait for a human (PENDING_APPROVAL) — the engine never destroys on
    its own;
  - outside the testing window, nothing runs.

Then the automation level decides auto vs. approval:
  - assisted:        every step waits for approval;
  - semi_autonomous: non-destructive passive checks run; anything that actively
                     touches the target waits for approval;   <-- the default
  - autonomous:      everything the RoE permits runs (destructive still waits).

The planner executes nothing. It produces the plan; the orchestrator runs the
AUTO steps through the existing scanner modules + validation pipeline.
"""

from __future__ import annotations

import logging

from core.rules_of_engagement import RulesOfEngagement
from redteam.types import (
    AssessmentPlan, Hypothesis, PlanDecision, PlannedStep,
)

logger = logging.getLogger("h4ck-bot.redteam")

_VALID_LEVELS = {"assisted", "semi_autonomous", "autonomous"}


class Planner:
    def plan(
        self,
        hypotheses: list[Hypothesis],
        roe: RulesOfEngagement,
        automation_level: str = "semi_autonomous",
        target: str = "",
    ) -> AssessmentPlan:
        level = automation_level if automation_level in _VALID_LEVELS else "semi_autonomous"
        plan = AssessmentPlan(target=target or roe.authorized_targets[:1] and roe.authorized_targets[0] or "",
                              automation_level=level)

        window_open = roe.is_active_now()

        for h in hypotheses:
            decision, reason = self._decide(h, roe, level, window_open)
            plan.steps.append(PlannedStep(hypothesis=h, decision=decision, reason=reason))

        logger.info(
            "redteam plan for %s [%s]: %d auto, %d pending, %d skipped",
            plan.target, level, len(plan.auto), len(plan.pending), len(plan.skipped),
        )
        return plan

    def _decide(
        self,
        h: Hypothesis,
        roe: RulesOfEngagement,
        level: str,
        window_open: bool,
    ) -> tuple[PlanDecision, str]:
        tech = h.suggested_technique.value

        if not window_open:
            return PlanDecision.SKIPPED, "outside the RoE testing window"

        if not roe.permits(tech):
            return (PlanDecision.SKIPPED,
                    f"technique '{tech}' is not in the RoE permitted_techniques")

        if h.destructive and not roe.destructive_actions_allowed:
            return (PlanDecision.SKIPPED,
                    "destructive action, and the RoE does not allow destructive actions")

        if h.requires_active_testing and not roe.active_testing_permitted:
            return (PlanDecision.SKIPPED,
                    "requires active testing, which this RoE does not permit (safe-mode only)")

        # Permitted and allowed — now gate by autonomy + risk.
        if h.destructive:
            return (PlanDecision.PENDING_APPROVAL,
                    "destructive action always requires explicit human approval")

        if level == "assisted":
            return (PlanDecision.PENDING_APPROVAL,
                    "assisted mode: analyst approves every action")

        if level == "semi_autonomous":
            if h.requires_active_testing:
                return (PlanDecision.PENDING_APPROVAL,
                        "active test in semi-autonomous mode waits for approval")
            return (PlanDecision.AUTO,
                    "non-destructive passive check, permitted by the RoE")

        # autonomous
        return (PlanDecision.AUTO, f"permitted by the RoE under autonomous mode")
