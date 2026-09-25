"""
Reference ScannerModule. Copy this pattern for cloud / web3 / AI-LLM
modules. HTTP interaction is stubbed - this shows structure only.
"""

from __future__ import annotations

import uuid
from typing import AsyncIterator

from core.module_interface import ModuleCapabilities, ModuleRunContext, ScannerModule
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding, FindingKind,
    KillChainPhase, MitreTechnique, WeaknessRef,
)


class WebApiScannerModule(ScannerModule):
    @property
    def capabilities(self) -> ModuleCapabilities:
        return ModuleCapabilities(
            module_id="web_api_scanner",
            display_name="Web & API security scanner",
            supported_asset_types=["host", "web_app", "api"],
            kill_chain_phases=["exploitation"],
            requires_active_testing=True,
            max_automation_level="semi_autonomous",
        )

    async def run(self, ctx: ModuleRunContext) -> AsyncIterator[Finding]:
        for asset in ctx.assets:
            self.assert_in_scope(asset, ctx)
            finding = await self._check_bola(asset, ctx)
            if finding is not None:
                yield finding

    async def _check_bola(self, asset: Asset, ctx: ModuleRunContext) -> Finding | None:
        raise NotImplementedError(
            "Real BOLA check not implemented. This module produces no "
            "findings until it does. A real implementation requires: "
            "endpoint discovery (OpenAPI or path enumeration), two "
            "authenticated identities, and a cross-tenant response "
            "comparison."
        )
