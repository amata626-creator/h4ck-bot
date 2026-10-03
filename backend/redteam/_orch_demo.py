"""
Offline self-check for RedTeamOrchestrator with fully faked I/O:
synthetic recon + semantic, a stub validation pipeline, and a mock fetcher.
Proves the loop runs, gates correctly, and executes/validates a BOLA finding.

Run:  python -m redteam._orch_demo
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from core.rules_of_engagement import RulesOfEngagement
from core.schema import ValidationLayerResult, ValidationResult
from recon.types import AuthHints, Endpoint, ReconResult, TechStack
from semantic.types import Resource, SemanticModel
from redteam.executors import ExecContext, ExecutorRegistry, FetchResult
from redteam.orchestrator import RedTeamOrchestrator


def _recon() -> ReconResult:
    r = ReconResult(target="demo.local", base_urls=["https://demo.local"],
                    tech=TechStack(framework="express"))
    r.endpoints = [Endpoint(path="/api/v2/invoices/{id}", methods=["GET"], params=["id"],
                            content_type="application/json")]
    r.auth = AuthHints()
    return r


def _semantic() -> SemanticModel:
    return SemanticModel(target="demo.local", resources=[
        Resource(name="invoice", endpoints=["/api/v2/invoices/{id}"],
                 identifier_field="invoice_id", owner_field="user_id", sensitivity="high"),
    ])


def _roe() -> RulesOfEngagement:
    now = datetime.now(timezone.utc)
    return RulesOfEngagement(
        assessment_id="orch", authorized_by="demo", authorized_targets=["demo.local"],
        testing_window_start=now - timedelta(minutes=1),
        testing_window_end=now + timedelta(hours=1),
        permitted_techniques=["authz_testing", "api_testing"], active_testing_permitted=True,
    )


class StubPipeline:
    async def validate(self, finding):
        return ValidationResult(layers=[
            ValidationLayerResult(layer_name="stub", passed=True, confidence=0.9),
        ])


def _vuln_fetch():
    async def fetch(url: str) -> FetchResult:
        oid = url.rstrip("/").split("/")[-1]
        return FetchResult(url=url, status=200,
                           text=f'{{"invoice_id": {oid}, "user_id": "u{oid}"}}')
    return fetch


def _exec_factory(roe):
    def factory(hyp):
        return ExecContext(target_host="demo.local", roe=roe, fetch=_vuln_fetch(),
                           candidate_ids=["1", "2", "3"], owner_field="user_id",
                           base_url="https://demo.local", pace_seconds=0)
    return factory


async def main():
    roe = _roe()
    orch = RedTeamOrchestrator(ExecutorRegistry(), StubPipeline())

    # autonomous: active BOLA runs during assess()
    res = await orch.assess(
        assessment_id="A1", target="demo.local", roe=roe,
        automation_level="autonomous", recon=_recon(), semantic=_semantic(),
        exec_factory=_exec_factory(roe),
    )
    print("plan:", res.plan.summary()["counts"])
    print("executed findings:", len(res.findings))
    bola = [f for f in res.findings if f.cwe and f.cwe.cwe_id == "CWE-639"]
    assert bola, "autonomous assess should have run the BOLA executor"
    assert bola[0].status.value == "validated", f"stub pipeline should validate; got {bola[0].status}"
    print(f"  -> {bola[0].title}  status={bola[0].status.value}  cvss={bola[0].cvss.base_score}")
    print("[check] autonomous: BOLA executed + validated  OK")

    # semi-autonomous: BOLA is active -> pending, not auto-run; approve runs it
    res2 = await orch.assess(
        assessment_id="A2", target="demo.local", roe=roe,
        automation_level="semi_autonomous", recon=_recon(), semantic=_semantic(),
        exec_factory=_exec_factory(roe),
    )
    assert not res2.findings, "semi-auto must not auto-run active BOLA"
    pend = [s for s in res2.plan.pending if s.hypothesis.kind.value.startswith("broken_object")]
    assert pend, "BOLA should be queued for approval"
    print(f"\nsemi-auto: {len(res2.plan.pending)} pending, {len(res2.findings)} auto-run")
    approved = await orch.approve_step(pend[0], _exec_factory(roe))
    assert approved and approved[0].cwe.cwe_id == "CWE-639", "approval should run the BOLA check"
    print(f"[check] semi-auto: BOLA held, then ran on approval -> {approved[0].title}  OK")

    print("\nORCHESTRATOR CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
