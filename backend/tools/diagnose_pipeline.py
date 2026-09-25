"""Layer-by-layer breakdown of the validation pipeline for a single
synthetic BOLA finding. Run: python3 -m tools.diagnose_pipeline

Shows which layers passed, failed, or were non-applicable, and how the
overall confidence and status are derived.
"""

import asyncio

from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding, FindingKind, WeaknessRef,
)
from evidence.validation_pipeline import default_pipeline


def _make_evidence() -> tuple[Evidence, Evidence]:
    return (
        Evidence.new(
            EvidenceType.HTTP_TRANSACTION,
            b'{"invoice_id":10421,"account_id":"9931-A"}',
            "mem://x",
            "cross-tenant response body",
            metadata={"preview": 'status: 200 body: {"invoice_id":10421,"account_id":"9931-A"}'},
        ),
        Evidence.new(
            EvidenceType.RESPONSE_HEADERS,
            b"X-Tenant-Id: 9931-A\r\n",
            "mem://y",
            "response headers echo foreign tenant id",
            metadata={"preview": "status: 200 headers: X-Tenant-Id: 9931-A"},
        ),
    )


async def main():
    asset = Asset(
        asset_id="a1", name="api.acme-corp.com",
        asset_type="api", scope_approved=True,
        metadata={"framework": "express", "exposure": "internet"},
    )
    finding = Finding(
        finding_id="f1",
        title="Broken object-level authorization on /api/v2/invoices/{id}",
        description="A low-priv identity received another tenant's invoice.",
        asset=asset,
        module_source="web_api_scanner",
        finding_kind=FindingKind.VULNERABILITY,
        cvss=CvssScore(base_score=9.1,
                       vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
        cwe=WeaknessRef(cwe_id="CWE-639", name="Authorization Bypass"),
    )
    for e in _make_evidence():
        finding.add_evidence(e)

    # A sibling finding on the same asset, same CWE class - gives the
    # contextual layer something to correlate against.
    sibling = Finding(
        finding_id="f0",
        title="Broken object-level authorization on /api/v2/users/{id}",
        description="Same class, different endpoint.",
        asset=asset,
        module_source="web_api_scanner",
        finding_kind=FindingKind.VULNERABILITY,
        cvss=CvssScore(base_score=8.1,
                       vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
        cwe=WeaknessRef(cwe_id="CWE-639", name="Authorization Bypass"),
    )

    pipe = default_pipeline(prior_findings=[sibling])
    result = await pipe.validate(finding)

    print(f"{'layer':<28} {'appl':<6} {'pass':<6} {'conf':<6} notes")
    print("-" * 100)
    for l in result.layers:
        print(f"{l.layer_name:<28} {str(l.applicable):<6} {str(l.passed):<6} {l.confidence:<6.2f} {l.notes}")
    print("-" * 100)
    print(f"applicable layers:  {len(result.applicable_layers)} of {len(result.layers)}")
    print(f"overall_confidence: {result.overall_confidence:.2f}")
    print(f"status:             {result.status.value}")


if __name__ == "__main__":
    asyncio.run(main())
