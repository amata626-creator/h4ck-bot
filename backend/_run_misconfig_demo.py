import asyncio
from datetime import datetime, timedelta, timezone

from core.orchestrator import Orchestrator
from core.rules_of_engagement import RulesOfEngagement
from core.schema import Asset, FindingKind
from evidence.validation_pipeline import default_pipeline
from evidence.llm_client import OllamaClient
from modules.misconfig_module import MisconfigModule


async def main():
    roe = RulesOfEngagement(
        assessment_id="scanme-misconfig-demo",
        authorized_by="self - scanme.nmap.org is explicitly open for testing",
        authorized_targets=["scanme.nmap.org"],
        testing_window_start=datetime.now(timezone.utc) - timedelta(minutes=1),
        testing_window_end=datetime.now(timezone.utc) + timedelta(hours=1),
        permitted_techniques=["passive_recon", "port_scan", "misconfig_check"],
        active_testing_permitted=True,
        destructive_actions_allowed=False,
    )

    assets = [Asset(asset_id="scanme-1", name="scanme.nmap.org", asset_type="host", scope_approved=True)]

    orchestrator = Orchestrator(
        validation_pipeline=default_pipeline(llm_client=OllamaClient(model="llama3.2:3b"))
    )

    async for finding in orchestrator.run(
        roe, assets, modules=[MisconfigModule()], automation_level="assisted"
    ):
        print(f"- {finding.title}")
        print(f"  CVSS: {finding.cvss.base_score} ({finding.severity.value})  CWE: {finding.cwe.cwe_id}")
        if finding.finding_kind == FindingKind.INFORMATIONAL:
            print(f"  kind: informational")
        else:
            print(f"  status: {finding.status.value}  confidence: {finding.validation.overall_confidence:.2f}")


if __name__ == "__main__":
    asyncio.run(main())
