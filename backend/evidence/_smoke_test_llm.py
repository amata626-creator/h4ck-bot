"""Run directly to sanity-check the Ollama wiring against a live local
model: `python3 -m evidence._smoke_test_llm`

Set H4CK_BOT_LLM_MODEL to override the default. Recommended models
(capable of grounded JSON on this schema):
    llama3.1          (~4.7 GB, best all-round)
    qwen2.5:7b        (~4.7 GB, strong structured output)
    phi3:mini         (~2.3 GB, smallest usable)

Do NOT use sub-1B models for this layer - they will reliably fail the
grounding requirement in llm_client._parse_verdict and be discounted
to confidence <= 0.2, which is the system working as designed but not a
useful smoke test.
"""

import asyncio
import os

from core.schema import Asset, CvssScore, Evidence, EvidenceType, Finding, WeaknessRef
from evidence.ai_analysis_layer import LocalLlmAnalysisLayer
from evidence.llm_client import OllamaClient


DEFAULT_MODEL = os.environ.get("H4CK_BOT_LLM_MODEL", "llama3.1")


async def main():
    asset = Asset(asset_id="a1", name="api.acme-corp.com", asset_type="api", scope_approved=True)
    finding = Finding(
        finding_id="f1",
        title="Broken object-level authorization on /api/v2/invoices/{id}",
        description="A low-priv identity received another tenant's invoice.",
        asset=asset,
        module_source="web_api_scanner",
        cvss=CvssScore(base_score=9.1, vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
        cwe=WeaknessRef(cwe_id="CWE-639", name="Authorization Bypass Through User-Controlled Key"),
    )
    finding.add_evidence(Evidence.new(
        evidence_type=EvidenceType.HTTP_TRANSACTION,
        raw_bytes=b'{"invoice_id":10421,"account_id":"9931-A"}',
        storage_ref="mem://demo",
        description="200 OK returned for invoice belonging to a different tenant account, "
                    "using a low-privilege bearer token",
    ))

    client = OllamaClient(model=DEFAULT_MODEL)
    print(f"using model: {DEFAULT_MODEL}  (override with H4CK_BOT_LLM_MODEL)")
    layer = LocalLlmAnalysisLayer(client)
    result = await layer.evaluate(finding)
    print("passed:", result.passed)
    print("confidence:", result.confidence)
    print("notes:", result.notes)


if __name__ == "__main__":
    asyncio.run(main())
