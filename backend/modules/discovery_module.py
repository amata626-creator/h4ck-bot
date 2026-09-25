"""
Real discovery/fingerprinting module - TCP port scanning + HTTP service
fingerprinting. This is the first module in the pipeline that actually
touches a network target, so it enforces scope checking hardest of all
the modules: assert_in_scope() runs per-asset before any socket opens,
and additionally refuses to run at all unless the target hostname is
listed in ctx.roe.authorized_targets (belt-and-suspenders on top of the
base class check).

What this does:
  - TCP connect scan across a configurable port list (default: common
    service ports, not a full 1-65535 sweep - keep scans fast and polite)
  - For open HTTP(S) ports, fetches headers and a small response sample
    to fingerprint the web server / framework
  - Produces Finding objects only for INFORMATIONAL discovery results
    (open port + service banner), status POTENTIAL - these feed later
    modules (misconfig checker, CVE matcher), they are not vulnerability
    claims themselves

What this does NOT do:
  - No UDP scanning, no OS fingerprinting, no service version brute-force
  - No exploitation of anything found - discovery only
"""

from __future__ import annotations

import asyncio
import socket
import uuid
from typing import AsyncIterator

import httpx

from core.module_interface import ModuleCapabilities, ModuleRunContext, ScannerModule, OutOfScopeError
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding, FindingKind,
    KillChainPhase, WeaknessRef,
)

# Common service ports - deliberately small and polite, not a full sweep.
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

CONNECT_TIMEOUT = 2.0


class DiscoveryModule(ScannerModule):
    @property
    def capabilities(self) -> ModuleCapabilities:
        return ModuleCapabilities(
            module_id="discovery_scanner",
            display_name="Network & service discovery",
            supported_asset_types=["web_app", "api", "cloud_resource", "host"],
            kill_chain_phases=["reconnaissance"],
            requires_active_testing=True,
            max_automation_level="semi_autonomous",
        )

    async def run(self, ctx: ModuleRunContext) -> AsyncIterator[Finding]:
        for asset in ctx.assets:
            # base-class scope/RoE check
            self.assert_in_scope(asset, ctx)

            # extra check specific to this module: target must be
            # explicitly named in authorized_targets, not just
            # scope_approved=True on the Asset object. Discovery is the
            # first thing to touch the wire, so it double-checks.
            if not ctx.roe.target_authorized(asset.name):
                raise OutOfScopeError(
                    f"{asset.name} is not in RulesOfEngagement.authorized_targets "
                    "- discovery module refuses to scan it"
                )

            ports = ctx.config.get("ports", DEFAULT_PORTS)
            open_ports = await self._scan_ports(asset.name, ports)

            for port, banner in open_ports:
                finding = await self._build_discovery_finding(asset, ctx, port, banner)
                if finding is not None:
                    yield finding

    async def _scan_ports(self, host: str, ports: list[int]) -> list[tuple[int, str]]:
        """TCP connect scan. Returns list of (port, banner_or_empty)."""
        results = []
        sem = asyncio.Semaphore(50)  # bound concurrency, be polite

        async def check_port(port: int):
            async with sem:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
                    )
                    banner = ""
                    if port in (80, 8080, 443, 8443):
                        banner = "http"
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    results.append((port, banner))
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError, socket.gaierror):
                    pass  # closed/filtered - not a finding

        await asyncio.gather(*(check_port(p) for p in ports))
        return sorted(results)

    async def _build_discovery_finding(
        self, asset: Asset, ctx: ModuleRunContext, port: int, banner: str
    ) -> Finding | None:
        http_evidence_bytes = b""
        server_header = ""

        if banner == "http":
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{asset.name}:{port}/"
            try:
                async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
                    resp = await client.get(url)
                    server_header = resp.headers.get("server", "")
                    http_evidence_bytes = (
                        f"GET {url}\nstatus: {resp.status_code}\n"
                        f"headers: {dict(resp.headers)}\n"
                    ).encode()
            except Exception as exc:
                http_evidence_bytes = f"GET {url} failed: {exc}".encode()

        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Open port {port}/tcp on {asset.name}" + (f" ({server_header})" if server_header else ""),
            description=(
                f"TCP connect scan found port {port} open on {asset.name}. "
                "This is a discovery result, not a vulnerability claim - it "
                "feeds the misconfig/CVE-matching modules downstream."
            ),
            asset=asset,
            module_source=self.capabilities.module_id,
            # Informational severity - discovery findings carry no CVSS
            # claim of their own; downstream modules assign real scores
            # once they check the service for actual weaknesses.
            cvss=CvssScore(base_score=0.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            cwe=WeaknessRef(cwe_id="CWE-200", name="Exposure of Sensitive Information (informational - open service)"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            finding_kind=FindingKind.INFORMATIONAL,
        )

        if http_evidence_bytes:
            finding.add_evidence(Evidence.new(
                evidence_type=EvidenceType.HTTP_TRANSACTION,
                raw_bytes=http_evidence_bytes,
                storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/http.txt",
                description=f"HTTP response headers from port {port}",
            ))
        else:
            finding.add_evidence(Evidence.new(
                evidence_type=EvidenceType.RAW_OUTPUT,
                raw_bytes=f"TCP connect succeeded on port {port}".encode(),
                storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/tcp.txt",
                description="TCP connect scan result",
            ))

        return finding
