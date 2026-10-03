"""
End-to-end demo + self-check for the red-team reasoning loop, on synthetic
recon + semantic input (no network, no LLM). Proves three things:

  1. the generator produces grounded hypotheses (no target outside recon),
  2. hypotheses are prioritized by plausibility x impact,
  3. the planner gates them correctly under semi-autonomous mode
     (passive -> auto, active -> pending, not-permitted -> skipped).

Run:  python -m redteam._demo
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.rules_of_engagement import RulesOfEngagement
from recon.types import AuthHints, Endpoint, ReconResult, TechStack
from semantic.types import Resource, RoleHint, SemanticModel
from redteam.hypotheses import HypothesisGenerator
from redteam.planner import Planner
from redteam.types import PlanDecision


def _synthetic_recon() -> ReconResult:
    r = ReconResult(target="demo.local",
                    base_urls=["https://demo.local"],
                    tech=TechStack(server="nginx", framework="express", language="node"))
    r.endpoints = [
        Endpoint(path="/api/v2/invoices/{id}", methods=["GET", "PUT"],
                 params=["id"], content_type="application/json",
                 sample_response_keys=["invoice_id", "user_id", "amount"]),
        Endpoint(path="/api/v2/users/{id}", methods=["GET"], params=["id"],
                 content_type="application/json"),
        Endpoint(path="/search", methods=["GET"], params=["query"],
                 content_type="text/html"),
        Endpoint(path="/login", methods=["GET", "POST"], params=["username", "password"],
                 content_type="text/html"),
        Endpoint(path="/about", methods=["GET"], content_type="text/html"),
    ]
    r.auth = AuthHints(login_paths=["/login"], cookie_names=["session"], csrf_param_names=[])
    return r


def _synthetic_semantic() -> SemanticModel:
    return SemanticModel(
        target="demo.local",
        app_purpose="Invoicing SaaS",
        product_category="finance",
        roles=[RoleHint(name="user"), RoleHint(name="admin")],
        resources=[
            Resource(name="invoice", endpoints=["/api/v2/invoices/{id}"],
                     identifier_field="invoice_id", owner_field="user_id",
                     sensitivity="high"),
            Resource(name="user", endpoints=["/api/v2/users/{id}"],
                     identifier_field="id", owner_field="", sensitivity="medium"),
        ],
    )


def _roe(active=True, permitted=None) -> RulesOfEngagement:
    now = datetime.now(timezone.utc)
    return RulesOfEngagement(
        assessment_id="demo",
        authorized_by="CISO, demo",
        authorized_targets=["demo.local"],
        testing_window_start=now - timedelta(minutes=1),
        testing_window_end=now + timedelta(hours=1),
        permitted_techniques=permitted or [
            "passive_recon", "authz_testing", "injection_testing",
            "xss_testing", "auth_testing", "api_testing",
        ],
        active_testing_permitted=active,
    )


def main() -> None:
    recon = _synthetic_recon()
    semantic = _synthetic_semantic()
    discovered = {e.path for e in recon.endpoints}

    hyps = HypothesisGenerator().generate(semantic, recon)
    print(f"\n{len(hyps)} hypotheses (highest priority first):\n")
    for h in hyps:
        print(f"  [{h.priority():.2f}] {h.kind.value:34s} {h.suggested_technique.value:17s} "
              f"{'ACTIVE' if h.requires_active_testing else 'passive'}  -> {h.target_endpoints}")

    # 1. grounding
    for h in hyps:
        for p in h.target_endpoints:
            assert p in discovered, f"UNGROUNDED target {p} in {h.hypothesis_id}"
    print("\n[check] every hypothesis target was discovered by recon  OK")

    # 2. prioritized
    assert [h.priority() for h in hyps] == sorted((h.priority() for h in hyps), reverse=True)
    print("[check] hypotheses sorted by priority  OK")

    # 3a. semi-autonomous gating
    plan = Planner().plan(hyps, _roe(), automation_level="semi_autonomous", target="demo.local")
    s = plan.summary()
    print(f"\nsemi-autonomous plan: {s['counts']}")
    for st in plan.steps:
        print(f"  {st.decision.value:16s} {st.hypothesis.kind.value:34s} {st.reason}")
    for st in plan.steps:
        if st.hypothesis.requires_active_testing:
            assert st.decision == PlanDecision.PENDING_APPROVAL, "active must wait for approval"
        else:
            assert st.decision == PlanDecision.AUTO, "passive permitted should auto-run"
    print("[check] semi-autonomous: active->pending, passive->auto  OK")

    # 3b. RoE forbids active -> those skip
    plan2 = Planner().plan(hyps, _roe(active=False), automation_level="semi_autonomous")
    assert all(st.decision == PlanDecision.SKIPPED
               for st in plan2.steps if st.hypothesis.requires_active_testing)
    print("[check] active_testing_permitted=False -> active hypotheses skipped  OK")

    # 3c. technique not permitted -> skip
    plan3 = Planner().plan(hyps, _roe(permitted=["passive_recon", "api_testing"]),
                           automation_level="autonomous")
    for st in plan3.steps:
        if st.hypothesis.suggested_technique.value not in ("passive_recon", "api_testing"):
            assert st.decision == PlanDecision.SKIPPED
    print("[check] techniques outside permitted_techniques skipped  OK")

    print("\nALL RED-TEAM PHASE-1 CHECKS PASSED")


if __name__ == "__main__":
    main()
