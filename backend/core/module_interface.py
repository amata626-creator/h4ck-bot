"""
The plugin contract. Every scanner implements ScannerModule; the
orchestrator picks it up without any other changes.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import AsyncIterator

from core.schema import Asset, Finding
from core.rules_of_engagement import RulesOfEngagement


@dataclass
class ModuleCapabilities:
    module_id: str
    display_name: str
    supported_asset_types: list[str]
    kill_chain_phases: list[str]
    requires_active_testing: bool = True
    max_automation_level: str = "assisted"


@dataclass
class ModuleRunContext:
    assessment_id: str
    assets: list[Asset]
    roe: RulesOfEngagement
    automation_level: str
    config: dict = field(default_factory=dict)


class OutOfScopeError(RuntimeError):
    """Raised when a module attempts an action outside authorized scope."""


class ScannerModule(abc.ABC):
    @property
    @abc.abstractmethod
    def capabilities(self) -> ModuleCapabilities:
        ...

    @abc.abstractmethod
    async def run(self, ctx: ModuleRunContext) -> AsyncIterator[Finding]:
        """Yield Findings (status POTENTIAL) as produced; validation happens downstream."""
        ...

    def assert_in_scope(self, asset: Asset, ctx: ModuleRunContext) -> None:
        if not asset.scope_approved:
            raise OutOfScopeError(f"{asset.name} is not scope-approved")
        if not ctx.roe.is_active_now():
            raise OutOfScopeError("current time is outside the RoE testing window")
        if self.capabilities.requires_active_testing and not ctx.roe.active_testing_permitted:
            raise OutOfScopeError(
                f"{self.capabilities.module_id} requires active testing, "
                "which this RoE does not permit (safe-mode only)"
            )
