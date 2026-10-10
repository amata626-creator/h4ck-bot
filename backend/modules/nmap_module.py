"""
nmap integration — real service/version detection, then offline CVE correlation.

This is what makes "infrastructure VAPT" honest: nmap -sV identifies the
service, product, version and CPE on each open port; we then correlate the CPE
against a LOCAL NVD index (modules.cve_index) to surface candidate CVEs.

Honesty / ethos:
  - Non-destructive: TCP connect scan (-sT, no raw sockets/root needed) plus
    version detection (-sV). No intrusive NSE scripts, no exploitation.
  - Scope-gated (assert_in_scope).
  - Graceful: no-op if the `nmap` binary is absent; still reports the service
    inventory if the CVE index hasn't been synced yet.
  - A version->CVE match is INFERENCE (backported patches don't bump the
    version), so those findings are left to land as NEEDS_REVIEW by the
    validation pipeline (requires_corroboration=True, one evidence type) — a
    'potential, confirm it' signal, not a false 'validated'. The elegant next
    step is Nuclei confirming the exploitable subset -> validated.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import AsyncIterator

from core.module_interface import ModuleCapabilities, ModuleRunContext, ScannerModule
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding,
    FindingKind, KillChainPhase, VulnerabilityRef, WeaknessRef,
)
from modules.cve_index import load_index, correlate

logger = logging.getLogger("h4ck-bot.nmap")

_RUN_TIMEOUT_S = 300.0
_SEV_SCORE = {"low": 3.1, "medium": 5.5, "high": 7.5, "critical": 9.5}


@dataclass
class ServiceInfo:
    port: int
    proto: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    cpes: list[str] = field(default_factory=list)

    def banner(self) -> str:
        bits = [self.name, self.product, self.version]
        return " ".join(b for b in bits if b).strip() or self.name or "unknown"


def parse_nmap_xml(xml_bytes: bytes) -> list[ServiceInfo]:
    """Parse `nmap -oX` output into the open services it found. Robust to the
    usual partial/!DOCTYPE'd nmap XML."""
    out: list[ServiceInfo] = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return out
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue
            svc = port.find("service")
            si = ServiceInfo(
                port=int(port.get("portid", "0") or 0),
                proto=port.get("protocol", "tcp"),
                state=state,
            )
            if svc is not None:
                si.name = svc.get("name", "")
                si.product = svc.get("product", "")
                si.version = svc.get("version", "")
                si.cpes = [c.text for c in svc.findall("cpe") if c.text]
            out.append(si)
    return out


def _cpe_parts(cpe: str) -> tuple[str, str, str, str]:
    """(part, vendor, product, version) from a CPE 2.2 (cpe:/a:v:p:ver) or 2.3
    (cpe:2.3:a:v:p:ver:...) string. `part` is 'a' (application), 'o' (OS) or
    'h' (hardware). Missing fields come back empty."""
    s = cpe
    if s.startswith("cpe:2.3:"):
        f = s.split(":")
        # cpe:2.3:part:vendor:product:version:...
        part = f[2] if len(f) > 2 else ""
        vendor = f[3] if len(f) > 3 else ""
        product = f[4] if len(f) > 4 else ""
        version = f[5] if len(f) > 5 and f[5] not in ("*", "-") else ""
        return part, vendor, product, version
    if s.startswith("cpe:/"):
        f = s[len("cpe:/"):].split(":")
        # part:vendor:product:version
        part = f[0] if len(f) > 0 else ""
        vendor = f[1] if len(f) > 1 else ""
        product = f[2] if len(f) > 2 else ""
        version = f[3] if len(f) > 3 else ""
        return part, vendor, product, version
    return "", "", "", ""


class NmapModule(ScannerModule):
    @property
    def capabilities(self) -> ModuleCapabilities:
        return ModuleCapabilities(
            module_id="nmap_cve",
            display_name="nmap service/version + offline CVE correlation",
            supported_asset_types=["host", "web_app", "api"],
            kill_chain_phases=["reconnaissance"],
            requires_active_testing=True,
            max_automation_level="autonomous",
        )

    async def run(self, ctx: ModuleRunContext) -> AsyncIterator[Finding]:
        if shutil.which("nmap") is None:
            logger.info("nmap binary not found on PATH - skipping (install nmap to enable service/CVE scanning)")
            return
        index = load_index()
        if not index:
            logger.info("CVE index not found/empty (run tools/sync_nvd.py) - reporting service inventory only")

        for asset in ctx.assets:
            if asset.asset_type not in self.capabilities.supported_asset_types:
                continue
            self.assert_in_scope(asset, ctx)
            host = asset.name.split("://", 1)[-1].split("/", 1)[0]  # strip scheme/path
            services = await self._scan(host)
            for finding in self._to_findings(asset, host, services, index):
                yield finding

    async def _scan(self, host: str) -> list[ServiceInfo]:
        # -sT connect scan (no root), -sV version detection, -Pn skip host
        # discovery, -oX - XML to stdout, --version-light for speed.
        cmd = ["nmap", "-sT", "-sV", "-Pn", "--version-light", "-oX", "-", host]
        logger.info("nmap: scanning %s", host)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=_RUN_TIMEOUT_S)
        except asyncio.TimeoutError:
            logger.warning("nmap timed out on %s", host)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return []
        except (FileNotFoundError, OSError) as exc:
            logger.warning("nmap failed to launch: %s", exc)
            return []
        services = parse_nmap_xml(stdout)
        logger.info("nmap: %d open service(s) on %s", len(services), host)
        return services

    def _to_findings(self, asset: Asset, host: str, services: list[ServiceInfo], index: dict):
        for si in services:
            # 1. Service inventory — informational / Recorded context.
            yield self._service_finding(asset, host, si)

            # 2. CVE correlation per CPE (needs a concrete version).
            if not index:
                continue
            seen_cves: set[str] = set()
            for cpe in si.cpes:
                part, vendor, product, version = _cpe_parts(cpe)
                # Only APPLICATION CPEs carry this service's CVEs. nmap also
                # reports an OS CPE (e.g. cpe:/o:canonical:ubuntu_linux) for the
                # host; correlating that would pin the entire distro/kernel CVE
                # list onto, say, the SSH service - a flood of false positives.
                if part and part != "a":
                    continue
                version = version or si.version
                if not product or not version:
                    continue
                for m in correlate(vendor, product, version, index):
                    if m.cve in seen_cves:
                        continue
                    seen_cves.add(m.cve)
                    yield self._cve_finding(asset, host, si, cpe, m)

    def _service_finding(self, asset: Asset, host: str, si: ServiceInfo) -> Finding:
        f = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Open service {si.port}/{si.proto} on {host} ({si.banner()})",
            description=(
                f"nmap -sV identified {si.banner()} on {host}:{si.port}/{si.proto}."
                + (f" CPE: {', '.join(si.cpes)}." if si.cpes else "")
            ),
            asset=asset, module_source=self.capabilities.module_id,
            finding_kind=FindingKind.INFORMATIONAL,
            cvss=CvssScore(base_score=0.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            cwe=WeaknessRef(cwe_id="CWE-0", name="Service inventory (informational)"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            requires_corroboration=False,
        )
        preview = (f"nmap -sV\nhost: {host}\nport: {si.port}/{si.proto} ({si.state})\n"
                   f"service: {si.banner()}\ncpe: {', '.join(si.cpes) or '(none)'}\n")
        f.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RAW_OUTPUT, raw_bytes=preview.encode(),
            storage_ref=f"mem://nmap/{f.finding_id}", description="nmap service detection",
            metadata={"preview": preview, "source": "nmap"},
        ))
        return f

    def _cve_finding(self, asset: Asset, host: str, si: ServiceInfo, cpe: str, m) -> Finding:
        score = m.score or _SEV_SCORE.get(m.severity, 5.0)
        f = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Potential {m.cve} in {si.banner()} on {host}:{si.port} (version-inferred)",
            description=(
                f"{si.banner()} on {host}:{si.port} matches the affected-version range for "
                f"{m.cve}. {m.description[:300]} "
                "NOTE: this is inferred from the reported version and is NOT confirmed exploitable — "
                "distributions often backport fixes without changing the version. Confirm with a "
                "targeted check (e.g. a Nuclei template for this CVE) before treating it as validated."
            ),
            asset=asset, module_source=self.capabilities.module_id,
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(base_score=round(float(score), 1), vector=m.vector),
            cwe=WeaknessRef(cwe_id="CWE-1035", name="Using Components with Known Vulnerabilities (version-inferred)"),
            cve_refs=[VulnerabilityRef(cve_id=m.cve)],
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            remediation=f"Upgrade {si.product or si.name} to a fixed version, or confirm the backported patch status.",
            business_impact=f"If unpatched, {m.cve} ({m.severity or 'see CVSS'}) may be exploitable against this service.",
            # Version inference needs independent corroboration -> pipeline
            # lands this as NEEDS_REVIEW, which is the honest verdict.
            requires_corroboration=True,
        )
        preview = (f"version-inferred CVE correlation (local NVD index)\n"
                   f"host: {host}:{si.port}\nservice: {si.banner()}\ncpe: {cpe}\n"
                   f"cve: {m.cve}  cvss: {score} ({m.severity})\nvector: {m.vector}\n")
        f.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RAW_OUTPUT, raw_bytes=preview.encode(),
            storage_ref=f"mem://nmap-cve/{f.finding_id}", description=f"Version match for {m.cve}",
            metadata={"preview": preview, "source": "nmap_cve", "cve": m.cve},
        ))
        return f
