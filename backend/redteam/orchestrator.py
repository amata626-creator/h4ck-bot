"""
RedTeamOrchestrator — the capstone that runs the whole loop:

    recon  +  semantic model  ->  hypotheses  ->  gated plan
        ->  run AUTO (and later, approved) steps through executors
        ->  validation pipeline  ->  findings

Design choice: all I/O lives OUTSIDE this class. The caller supplies the already
built ReconResult and SemanticModel, plus an `exec_factory` that turns a
hypothesis into an ExecContext (with a live HTTP fetcher). That keeps the
orchestration logic pure and unit-testable offline, while the API layer wires
the real recon module, Ollama, and httpx.

Semi-autonomous by default: only the plan's AUTO steps run during assess();
PENDING (active) steps are returned for a human to approve, and approve_step()
runs one on demand. Nothing here bypasses the planner's RoE gating.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from core.rules_of_engagement import RulesOfEngagement
from core.schema import Finding
from recon.types import ReconResult
from semantic.types import SemanticModel
from redteam.executors import ExecContext, ExecutorRegistry
from redteam.hypotheses import HypothesisGenerator
from redteam.planner import Planner
from redteam.types import AssessmentPlan, Hypothesis, PlannedStep

logger = logging.getLogger("h4ck-bot.redteam.orch")

# Builds the per-hypothesis execution context (live HTTP fetcher, owner field,
# candidate ids). Supplied by the caller so the orchestrator stays I/O-free.
ExecFactory = Callable[[Hypothesis], ExecContext]


@dataclass
class RedTeamResult:
    assessment_id: str
    target: str
    plan: AssessmentPlan
    findings: list[Finding] = field(default_factory=list)   # executed + validated

    def summary(self) -> dict:
        return {
            "assessment_id": self.assessment_id,
            "target": self.target,
            "plan": self.plan.summary(),
            "findings_executed": len(self.findings),
        }


class RedTeamOrchestrator:
    def __init__(
        self,
        registry: ExecutorRegistry,
        validation_pipeline,
        generator: HypothesisGenerator | None = None,
        planner: Planner | None = None,
    ):
        self.registry = registry
        self.validation_pipeline = validation_pipeline
        self.generator = generator or HypothesisGenerator()
        self.planner = planner or Planner()

    async def assess(
        self,
        *,
        assessment_id: str,
        target: str,
        roe: RulesOfEngagement,
        automation_level: str,
        recon: ReconResult,
        semantic: SemanticModel,
        exec_factory: ExecFactory,
    ) -> RedTeamResult:
        hyps = self.generator.generate(semantic, recon)
        plan = self.planner.plan(hyps, roe, automation_level, target)
        logger.info("redteam assess %s: %d auto, %d pending, %d skipped",
                    target, len(plan.auto), len(plan.pending), len(plan.skipped))

        findings: list[Finding] = []
        for step in plan.auto:
            findings.extend(await self._run_step(step, exec_factory))

        return RedTeamResult(assessment_id=assessment_id, target=target,
                             plan=plan, findings=findings)

    async def approve_step(self, step: PlannedStep, exec_factory: ExecFactory) -> list[Finding]:
        """Run one PENDING step after a human approves it."""
        logger.info("redteam: approved step %s (%s)",
                    step.hypothesis.hypothesis_id, step.hypothesis.kind.value)
        return await self._run_step(step, exec_factory)

    async def _run_step(self, step: PlannedStep, exec_factory: ExecFactory) -> list[Finding]:
        ex = self.registry.for_hypothesis(step.hypothesis)
        if ex is None:
            # No dedicated executor yet (e.g. injection/XSS are handled by the
            # owasp_top10 module in the classic scan path, not here). Honest
            # no-op rather than a fabricated result.
            logger.info("redteam: no executor for %s (%s) - left for module path",
                        step.hypothesis.hypothesis_id, step.hypothesis.kind.value)
            return []
        ctx = exec_factory(step.hypothesis)
        raw = await ex.execute(step.hypothesis, ctx)
        out: list[Finding] = []
        for f in raw:
            f.validation = await self.validation_pipeline.validate(f)
            f.status = f.validation.status           # keep status in lockstep
            out.append(f)
        return out
