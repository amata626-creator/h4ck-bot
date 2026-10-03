"""
Offline self-check for the BOLA/IDOR executor using a mock HTTP layer.
Proves the detection logic without touching any real target.

Run:  python -m redteam._bola_demo
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from core.rules_of_engagement import RulesOfEngagement
from redteam.executors import BolaExecutor, ExecContext, FetchResult
from redteam.types import Hypothesis, HypothesisKind, Technique


def _roe(target="demo.local") -> RulesOfEngagement:
    now = datetime.now(timezone.utc)
    return RulesOfEngagement(
        assessment_id="t", authorized_by="demo", authorized_targets=[target],
        testing_window_start=now - timedelta(minutes=1),
        testing_window_end=now + timedelta(hours=1),
        permitted_techniques=["authz_testing"], active_testing_permitted=True,
    )


def _hyp() -> Hypothesis:
    return Hypothesis(
        hypothesis_id="h1", kind=HypothesisKind.BOLA,
        title="BOLA on invoices", target_endpoints=["/api/v2/invoices/{id}"],
        rationale="owner field present", suggested_technique=Technique.AUTHZ_TESTING,
    )


def make_fetch(mode: str):
    async def fetch(url: str) -> FetchResult:
        oid = url.rstrip("/").split("/")[-1]
        if mode == "vulnerable":
            # every id returns a distinct object owned by a different user
            return FetchResult(url=url, status=200,
                               text=f'{{"invoice_id": {oid}, "user_id": "u{oid}", "amount": 100}}')
        if mode == "safe":
            # only your own object (id 1) is readable; others are forbidden
            if oid == "1":
                return FetchResult(url=url, status=200,
                                   text='{"invoice_id": 1, "user_id": "u1"}')
            return FetchResult(url=url, status=403, text="forbidden")
        return FetchResult(url=url, status=404, text="")
    return fetch


async def main():
    ex = BolaExecutor()

    # 1. vulnerable: distinct owners readable -> one high-confidence finding
    ctx = ExecContext(target_host="demo.local", roe=_roe(), fetch=make_fetch("vulnerable"),
                      candidate_ids=["1", "2", "3"], owner_field="user_id",
                      base_url="https://demo.local", pace_seconds=0)
    f = await ex.execute(_hyp(), ctx)
    assert len(f) == 1, f"expected 1 finding, got {len(f)}"
    assert f[0].cvss.base_score == 8.1, "cross-owner access -> higher severity"
    assert len(f[0].evidence) >= 2, "needs >=2 evidence items"
    print(f"[vulnerable] flagged: {f[0].title}  cvss={f[0].cvss.base_score}  "
          f"evidence={len(f[0].evidence)}")

    # 2. safe: only own object readable -> no finding
    ctx2 = ExecContext(target_host="demo.local", roe=_roe(), fetch=make_fetch("safe"),
                       candidate_ids=["1", "2", "3"], owner_field="user_id",
                       base_url="https://demo.local", pace_seconds=0)
    f2 = await ex.execute(_hyp(), ctx2)
    assert f2 == [], "properly-scoped endpoint must not be flagged"
    print("[safe] correctly not flagged (others return 403)")

    # 3. out of scope: RoE does not authorize this host -> nothing runs
    ctx3 = ExecContext(target_host="evil.example", roe=_roe("demo.local"),
                       fetch=make_fetch("vulnerable"), candidate_ids=["1", "2", "3"],
                       owner_field="user_id", base_url="https://evil.example", pace_seconds=0)
    f3 = await ex.execute(_hyp(), ctx3)
    assert f3 == [], "must refuse a host the RoE did not authorize"
    print("[scope] correctly refused an unauthorized host")

    print("\nBOLA EXECUTOR CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
