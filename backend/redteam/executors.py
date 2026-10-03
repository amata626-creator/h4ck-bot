"""
Red-team executors — the safe checks that confirm or refute a hypothesis.

Phase 1b ships the executor the platform was missing: a real IDOR/BOLA check
(the web_api module was a stub). Everything here is bounded by hard safety
rules, because this is the part that actually touches a target:

  - GET only. No writes, no destructive methods, ever.
  - In-scope only. The target host must be authorized by the RoE.
  - Bounded + paced. A small, capped number of probes with a delay between
    them — never an enumeration flood.
  - Evidence in, verdict out as POTENTIAL. The executor never self-certifies a
    finding; it collects evidence and hands a POTENTIAL finding to the existing
    validation pipeline, which decides.

The HTTP layer is injected (a `Fetcher`), so the detection logic is unit-tested
offline with crafted responses — no live target needed to prove correctness.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional, Protocol

from core.rules_of_engagement import RulesOfEngagement
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding, FindingKind,
    KillChainPhase, MitreTechnique, WeaknessRef,
)
from redteam.types import Hypothesis, HypothesisKind

logger = logging.getLogger("h4ck-bot.redteam.exec")


@dataclass
class FetchResult:
    url: str
    status: int
    text: str = ""
    headers: dict = field(default_factory=dict)

    def json(self) -> Optional[dict]:
        try:
            v = json.loads(self.text)
            return v if isinstance(v, dict) else None
        except Exception:
            return None


# A Fetcher performs ONE safe GET and returns a FetchResult. Injected so tests
# can supply crafted responses and production supplies a real httpx client.
Fetcher = Callable[[str], Awaitable[FetchResult]]


class Executor(Protocol):
    async def execute(self, hyp: Hypothesis, ctx: "ExecContext") -> list[Finding]: ...


@dataclass
class ExecContext:
    target_host: str
    roe: RulesOfEngagement
    fetch: Fetcher
    # object ids to probe for IDOR/BOLA (from recon/known objects); kept small.
    candidate_ids: list[str] = field(default_factory=lambda: ["1", "2", "3"])
    owner_field: str = ""          # from the semantic model, if known
    max_probes: int = 5
    pace_seconds: float = 0.3
    base_url: str = ""             # e.g. "https://host"


def _fill_id(path_template: str, oid: str) -> str:
    """Substitute an object id into an endpoint template: /x/{id} or /x/:id."""
    import re
    if "{" in path_template:
        return re.sub(r"\{[^}]+\}", oid, path_template, count=1)
    if "/:" in path_template:
        return re.sub(r"/:\w+", "/" + oid, path_template, count=1)
    # path ending in a numeric segment -> swap it
    if re.search(r"/\d+/?$", path_template):
        return re.sub(r"/\d+(/?)$", "/" + oid + r"\1", path_template)
    # otherwise append as a path id
    return path_template.rstrip("/") + "/" + oid


class BolaExecutor:
    """Horizontal object-access (IDOR/BOLA) check.

    For an instance-scoped endpoint, request several distinct object ids with
    the SAME (or no) identity. If multiple ids each return a 200 carrying a
    distinct object — and, when known, distinct owner-field values — then the
    endpoint is not scoping objects to the caller: a classic IDOR/BOLA. If the
    other ids return 401/403/404, there is no finding.
    """

    handles = {HypothesisKind.BOLA, HypothesisKind.IDOR}

    async def execute(self, hyp: Hypothesis, ctx: ExecContext) -> list[Finding]:
        # Safety gate: never touch a host the RoE didn't authorize.
        if not ctx.roe.target_authorized(ctx.target_host):
            logger.warning("bola: %s not authorized by RoE - skipping", ctx.target_host)
            return []

        findings: list[Finding] = []
        base = ctx.base_url or f"https://{ctx.target_host}"

        for template in hyp.target_endpoints:
            probes: list[FetchResult] = []
            for oid in ctx.candidate_ids[: ctx.max_probes]:
                url = base.rstrip("/") + _fill_id(template, oid)
                try:
                    res = await ctx.fetch(url)          # GET only (the Fetcher enforces it)
                except Exception as e:                   # noqa: BLE001
                    logger.info("bola: fetch failed %s: %s", url, e)
                    continue
                probes.append(res)
                await asyncio.sleep(ctx.pace_seconds)    # paced, never a flood

            finding = self._evaluate(hyp, template, base, probes, ctx)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate(self, hyp, template, base, probes, ctx) -> Optional[Finding]:
        ok = [p for p in probes if p.status == 200 and p.text.strip()]
        if len(ok) < 2:
            return None  # need >=2 distinct objects readable to claim horizontal access

        # Distinct bodies, and (if we know the owner field) distinct owners.
        bodies = {p.text.strip() for p in ok}
        owners = set()
        if ctx.owner_field:
            for p in ok:
                j = p.json() or {}
                if ctx.owner_field in j:
                    owners.add(str(j[ctx.owner_field]))
        distinct_objects = len(bodies) >= 2
        distinct_owners = len(owners) >= 2
        if not distinct_objects:
            return None

        asset = Asset(asset_id="a0", name=ctx.target_host, asset_type="api",
                      scope_approved=True, metadata={"exposure": "internet"})
        # Confidence/severity nudge when owner fields prove cross-tenant access.
        base_score = 8.1 if distinct_owners else 6.5
        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Possible IDOR/BOLA on {template}",
            description=(
                f"{len(ok)} distinct object ids returned 200 with distinct content on "
                f"{template} using a single (or no) identity"
                + (f"; the owner field '{ctx.owner_field}' differed across responses "
                   f"({sorted(owners)[:3]}), indicating cross-owner access"
                   if distinct_owners else "")
                + ". The endpoint does not appear to scope objects to the caller. "
                "Checked read-only (GET); no modification attempted."
            ),
            asset=asset,
            module_source="bola_executor",
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(base_score=base_score,
                           vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
            cwe=WeaknessRef(cwe_id="CWE-639",
                            name="Authorization Bypass Through User-Controlled Key"),
            mitre_techniques=[MitreTechnique(technique_id="T1190", tactic="initial-access",
                                             name="Exploit Public-Facing Application")],
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            remediation=(
                "Enforce per-object authorization server-side: verify the authenticated "
                "principal owns (or may access) the requested object before returning it. "
                "Do not rely on unguessable ids."
            ),
            business_impact="An attacker could read other users'/tenants' records by changing the object id.",
        )
        # Attach the probe transactions as evidence (two independent items so the
        # evidence-correlation layer has something real to weigh).
        for p in ok[:4]:
            preview = f"GET {p.url}\nstatus: {p.status}\nbody: {p.text[:200]}"
            finding.add_evidence(Evidence.new(
                evidence_type=EvidenceType.HTTP_TRANSACTION,
                raw_bytes=preview.encode(),
                storage_ref=f"mem://bola/{uuid.uuid4().hex[:8]}",
                description=f"IDOR probe response for {p.url}",
                metadata={"preview": preview},
            ))
        logger.info("bola: potential finding on %s (%d readable ids, distinct_owners=%s)",
                    template, len(ok), distinct_owners)
        return finding


class ExecutorRegistry:
    """Maps a hypothesis to the executor that can safely check it. Techniques
    without a real executor yet (injection/xss are handled by the owasp module,
    not here) return None so the caller can report honest coverage."""

    def __init__(self):
        self._executors: list[Executor] = [BolaExecutor()]

    def for_hypothesis(self, hyp: Hypothesis) -> Optional[Executor]:
        for ex in self._executors:
            if hyp.kind in getattr(ex, "handles", set()):
                return ex
        return None
