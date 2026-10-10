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
from typing import Awaitable, Callable, Optional

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

# How many adaptive rounds the AI loop may run, and how many new hypotheses it
# may add per round. Bounds keep an eager model from looping or flooding.
_MAX_ADAPTIVE_ROUNDS = 3
_MAX_NEW_PER_ROUND = 8


@dataclass
class StrategyContext:
    """What the AI strategist sees to decide the NEXT round of probes: the real
    observed surface, everything confirmed so far, and what's already been
    tried. It never sees anything that would let it invent a target."""
    target: str
    recon: ReconResult
    semantic: SemanticModel
    findings_so_far: list[Finding]
    round_index: int
    already_tried: set[tuple]          # {(kind, endpoint)} pairs already probed


# The strategist proposes the next round of hypotheses from what's been learned.
# Async + injected so the orchestrator stays I/O-free; the orchestrator GROUNDS
# and de-dups whatever it returns, so a hallucinated target cannot survive.
Strategist = Callable[[StrategyContext], Awaitable[list[Hypothesis]]]


def observed_surface(recon: ReconResult) -> tuple[set[str], set[str]]:
    """The endpoints and params recon actually saw — the only things a proposed
    hypothesis is allowed to reference."""
    paths: set[str] = set()
    params: set[str] = set()
    for ep in recon.endpoints:
        paths.add(ep.path)
        params |= set(ep.params or [])
    return paths, params


def _needs_params(hyp: Hypothesis) -> bool:
    from redteam.types import HypothesisKind
    return hyp.kind in {HypothesisKind.INJECTION, HypothesisKind.XSS, HypothesisKind.SSRF,
                        HypothesisKind.XXE, HypothesisKind.SSTI, HypothesisKind.OPEN_REDIRECT}


def ground_hypotheses(hyps: list[Hypothesis], recon: ReconResult) -> list[Hypothesis]:
    """Constrain proposed hypotheses to the observed surface. Any endpoint recon
    never saw is dropped; a hypothesis left with no real endpoint (an invented
    target) is discarded entirely. This is the anti-hallucination gate: the AI
    may reason freely about WHAT to test, but only against surface that actually
    exists."""
    paths, params = observed_surface(recon)
    out: list[Hypothesis] = []
    for h in hyps:
        eps = [e for e in (h.target_endpoints or []) if e in paths]
        if not eps:
            logger.info("strategist: dropping hypothesis %s - endpoints %s not in observed surface",
                        getattr(h, "hypothesis_id", "?"), h.target_endpoints)
            continue
        h.target_endpoints = eps
        if h.target_params:
            kept = [p for p in h.target_params if p in params]
            if not kept and _needs_params(h):
                logger.info("strategist: dropping %s - no observed param among %s",
                            getattr(h, "hypothesis_id", "?"), h.target_params)
                continue
            h.target_params = kept
        out.append(h)
    return out


def _tried_keys(hyp: Hypothesis) -> set[tuple]:
    return {(hyp.kind.value, ep) for ep in (hyp.target_endpoints or [])}


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
        strategist: Optional[Strategist] = None,
    ) -> RedTeamResult:
        # Round 0: the deterministic seed hypotheses (pattern-matched from the
        # semantic model). This is the floor - it runs with or without an AI
        # strategist, so the engine never regresses below its rule-based baseline.
        hyps = self.generator.generate(semantic, recon)
        plan = self.planner.plan(hyps, roe, automation_level, target)
        logger.info("redteam assess %s: seed plan - %d auto, %d pending, %d skipped",
                    target, len(plan.auto), len(plan.pending), len(plan.skipped))

        findings: list[Finding] = []
        tried: set[tuple] = set()
        for step in plan.auto:
            findings.extend(await self._run_step(step, exec_factory))
            tried |= _tried_keys(step.hypothesis)

        # Adaptive rounds: the AI strategist reasons over what we've CONFIRMED so
        # far and proposes the next grounded probes - observe, hypothesize, test,
        # pivot - which is what makes this a pentester and not a one-shot scanner.
        # Grounded + de-duped + RoE-gated + bounded, so the model steers but can
        # neither invent targets nor act unsafely nor loop forever.
        if strategist is not None:
            for rnd in range(1, _MAX_ADAPTIVE_ROUNDS + 1):
                sctx = StrategyContext(
                    target=target, recon=recon, semantic=semantic,
                    findings_so_far=list(findings), round_index=rnd, already_tried=set(tried),
                )
                try:
                    proposed = await strategist(sctx)
                except Exception as exc:  # noqa: BLE001 - AI is best-effort, never fatal
                    logger.info("strategist round %d failed (keeping prior findings): %s", rnd, exc)
                    break
                grounded = ground_hypotheses(proposed or [], recon)
                # drop anything whose (kind, endpoint) pairs were all tried already
                fresh = [h for h in grounded if not _tried_keys(h).issubset(tried)][:_MAX_NEW_PER_ROUND]
                if not fresh:
                    logger.info("strategist round %d: no new grounded hypotheses - loop converged", rnd)
                    break
                rplan = self.planner.plan(fresh, roe, automation_level, target)
                logger.info("strategist round %d: %d proposed -> %d grounded-fresh -> %d auto",
                            rnd, len(proposed or []), len(fresh), len(rplan.auto))
                for step in rplan.auto:
                    findings.extend(await self._run_step(step, exec_factory))
                    tried |= _tried_keys(step.hypothesis)
                # fold newly-planned steps into the overall plan for reporting
                # (auto/pending/skipped are computed from .steps)
                plan.steps.extend(rplan.steps)

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
            # No dedicated executor for this hypothesis kind yet (BOLA/IDOR,
            # injection, and reflected XSS have one; others are left to the
            # module path). Honest no-op rather than a fabricated result.
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
