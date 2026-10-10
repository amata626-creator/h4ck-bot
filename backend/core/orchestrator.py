"""
Assessment orchestrator - routing, gating, streaming. Kept thin on
purpose: security logic lives in modules/, FP logic in evidence/.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import AsyncIterator

from core.module_interface import ModuleRunContext, OutOfScopeError, ScannerModule
from core.rules_of_engagement import RulesOfEngagement
from core.schema import Asset, Evidence, EvidenceType, Finding, FindingKind
from evidence.screenshot_capture import screenshot_findings
from evidence.validation_pipeline import ValidationPipeline

logger = logging.getLogger("h4ck-bot.orchestrator")


@dataclass
class AssessmentRun:
    assessment_id: str
    roe: RulesOfEngagement
    assets: list[Asset]
    modules: list[ScannerModule]
    automation_level: str
    findings: list[Finding] = field(default_factory=list)
    audit_log: list[str] = field(default_factory=list)
    auth: dict = field(default_factory=dict)

    def _log(self, msg: str) -> None:
        logger.info(msg)
        self.audit_log.append(msg)


class Orchestrator:
    def __init__(self, validation_pipeline: ValidationPipeline):
        self.validation_pipeline = validation_pipeline

    async def run(
        self,
        assessment_id: str,
        roe: RulesOfEngagement,
        assets: list[Asset],
        modules: list[ScannerModule],
        automation_level: str = "assisted",
        auth: dict | None = None,
    ) -> AsyncIterator[Finding]:
        # assessment_id is the caller's id (the one already stored in the
        # database) - NOT generated here. Generating our own id here was
        # a long-standing bug: every log line, evidence storage_ref, and
        # screenshot path referenced a phantom id that was never written
        # to the assessments table, so it could never be looked up again.
        run = AssessmentRun(
            assessment_id=assessment_id,
            roe=roe,
            assets=assets,
            modules=modules,
            automation_level=automation_level,
        )
        run.auth = auth or {}
        run._log(f"assessment {run.assessment_id} starting - "
                 f"{len(assets)} assets, {len(modules)} modules, "
                 f"automation={automation_level}")

        for module in modules:
            eligible = [a for a in assets
                        if a.asset_type in module.capabilities.supported_asset_types]
            if not eligible:
                continue

            ctx = ModuleRunContext(
                assessment_id=run.assessment_id,
                assets=eligible,
                roe=roe,
                automation_level=automation_level,
                config={"auth": run.auth or {}},
            )
            run._log(f"module {module.capabilities.module_id} running against "
                     f"{len(eligible)} asset(s)")

            try:
                async for raw in module.run(ctx):
                    yield await self._validate_and_record(run, raw)
            except OutOfScopeError as e:
                run._log(f"module {module.capabilities.module_id} stopped - out of scope: {e}")
                continue
            except NotImplementedError as e:
                run._log(f"module {module.capabilities.module_id} skipped - not implemented: {e}")
                continue

        await self._capture_and_attach_screenshots(run)

        run._log(f"assessment {run.assessment_id} complete - {len(run.findings)} findings")

    async def _validate_and_record(self, run: AssessmentRun, finding: Finding) -> Finding:
        # Informational findings (open ports, discovered assets, tech
        # fingerprints) are not vulnerability claims - there is nothing
        # for the 5-layer FP-reduction pipeline to validate or reject.
        # Record them as-is; they still become available as sibling
        # context for ContextualCorrelationLayer on later findings, since
        # they're appended to run.findings either way.
        if finding.finding_kind == FindingKind.INFORMATIONAL:
            run.findings.append(finding)
            run._log(f"finding {finding.finding_id} [{finding.title}] -> "
                     f"recorded (informational, not run through validation)")
            return finding

        # Feed accumulated findings to the contextual layer, if present,
        # so it can correlate this finding against earlier ones on the
        # same asset within this run.
        for layer in self.validation_pipeline.layers:
            setter = getattr(layer, "set_prior_findings", None)
            if callable(setter):
                setter(run.findings)

        result = await self.validation_pipeline.validate(finding)
        finding.validation = result
        finding.status = result.status
        run.findings.append(finding)
        run._log(f"finding {finding.finding_id} [{finding.title}] -> "
                 f"{finding.status.value} (confidence={result.overall_confidence:.2f})")
        return finding

    async def _capture_and_attach_screenshots(self, run: AssessmentRun) -> None:
        """
        Capture a screenshot of each finding's OWN url (deduped), carrying the
        assessment's session when one was supplied, and attach it to the
        finding(s) at that url. A finding whose url isn't web-facing (a mobile
        app, a bare non-web asset) gets no screenshot. Best-effort and
        non-destructive — logged, never faked.
        """
        await screenshot_findings(
            run.findings, run.assessment_id, auth=run.auth, log=run._log
        )


async def _example():
    from datetime import datetime, timedelta, timezone
    from evidence.validation_pipeline import default_pipeline
    from modules.example_web_api_module import WebApiScannerModule

    roe = RulesOfEngagement(
        assessment_id="demo",
        authorized_by="CISO, VAPTIX AI Cyber",
        authorized_targets=["vaptix-ai-cyber.com"],
        testing_window_start=datetime.now(timezone.utc) - timedelta(minutes=1),
        testing_window_end=datetime.now(timezone.utc) + timedelta(days=7),
        permitted_techniques=["passive_recon", "auth_testing", "api_testing"],
    )
    assets = [Asset(asset_id="a1", name="api.vaptix-ai-cyber.com",
                    asset_type="api", scope_approved=True,
                    metadata={"framework": "express", "exposure": "internet"})]

    orch = Orchestrator(validation_pipeline=default_pipeline())
    async for f in orch.run(str(uuid.uuid4()), roe, assets, modules=[WebApiScannerModule()]):
        print(f.finding_id, f.title, f.status.value, f.severity.value)


if __name__ == "__main__":
    asyncio.run(_example())
