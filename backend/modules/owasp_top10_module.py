"""
OWASP Top 10 (2021) detection module.

Covers categories not already handled elsewhere in this codebase:
  - A03:2021 Injection          -> error-based SQLi signature detection
  - A06:2021 Vulnerable/Outdated Components -> version fingerprint match
  - A07:2021 Identification & Authentication Failures -> username enumeration

Already covered by other modules (not duplicated here):
  - A01:2021 Broken Access Control      -> modules/example_web_api_module.py (BOLA)
  - A02:2021 Cryptographic Failures     -> modules/misconfig_module.py (TLS check)
  - A05:2021 Security Misconfiguration  -> modules/misconfig_module.py (headers, exposed paths)

Detection boundary, on purpose: every check here is a single, standard,
non-destructive probe (a marker string, a quote character, a version
fingerprint) - the same class of technique OWASP ZAP/Nikto/Burp's
passive+light-active scanning uses. Nothing here chains payloads,
attempts real credential bypass, or extracts data. It answers "is this
present" with evidence, not "here is a working exploit."
"""

from __future__ import annotations

import re
import uuid
from typing import AsyncIterator

import httpx

from core.module_interface import ModuleCapabilities, ModuleRunContext, ScannerModule, OutOfScopeError
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding,
    FindingKind, KillChainPhase, WeaknessRef,
)

CONNECT_TIMEOUT = 6.0

# Common DB error signatures - standard, publicly documented strings
# every DB engine emits on malformed queries. Recognizing these is
# detection, not exploitation.
SQLI_ERROR_SIGNATURES = {
    "you have an error in your sql syntax": "MySQL",
    "warning: mysql_": "MySQL",
    "unclosed quotation mark after the character string": "Microsoft SQL Server",
    "quoted string not properly terminated": "Oracle",
    "org.postgresql.util.psqlexception": "PostgreSQL",
    "sqlite3.operationalerror": "SQLite",
    "pg_query(): query failed": "PostgreSQL",
}

# Probe params to try injection/reflection against. Real coverage would
# discover these from crawling; this is a fixed, minimal starting set.
COMMON_PARAMS = ["id", "q", "search", "query", "page", "category", "user"]

# server/framework -> (known-vulnerable version ceiling, CVE-style note).
# Minimal illustrative table - a real deployment should pull this from
# an actual CVE/NVD feed (see the CVE/NVD matching module we discussed
# earlier), not a hardcoded dict.
KNOWN_VULNERABLE_VERSIONS = {
    "apache": {"max_safe": "2.4.54", "note": "Apache HTTP Server versions before 2.4.54 have multiple known CVEs"},
    "nginx": {"max_safe": "1.24.0", "note": "nginx versions before 1.24.0 have known CVEs in some modules"},
    "php": {"max_safe": "8.1.0", "note": "PHP versions before 8.1 are past or nearing end-of-life with known CVEs"},
}


class OwaspTop10Module(ScannerModule):
    @property
    def capabilities(self) -> ModuleCapabilities:
        return ModuleCapabilities(
            module_id="owasp_top10",
            display_name="OWASP Top 10 (2021) detection",
            supported_asset_types=["web_app", "api", "host"],
            kill_chain_phases=["reconnaissance", "exploitation"],
            requires_active_testing=True,
            max_automation_level="assisted",
        )

    async def run(self, ctx: ModuleRunContext) -> AsyncIterator[Finding]:
        for asset in ctx.assets:
            self.assert_in_scope(asset, ctx)
            if not ctx.roe.target_authorized(asset.name):
                raise OutOfScopeError(f"{asset.name} is not in authorized_targets")

            ports = ctx.config.get("http_ports", [80, 443])
            for port in ports:
                scheme = "https" if port in (443, 8443) else "http"
                base_url = f"{scheme}://{asset.name}:{port}"

                if not await self._is_reachable(base_url):
                    continue

                async for finding in self._check_injection(asset, ctx, base_url):
                    yield finding

                async for finding in self._check_reflected_xss(asset, ctx, base_url):
                    yield finding

                finding = await self._check_vulnerable_components(asset, ctx, base_url)
                if finding is not None:
                    yield finding

                async for finding in self._check_username_enumeration(asset, ctx, base_url):
                    yield finding

    async def _is_reachable(self, base_url: str) -> bool:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT) as client:
                await client.get(base_url)
            return True
        except Exception:
            return False

    # -- A03: Injection (error-based SQLi detection) ------------------------

    async def _check_injection(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        probe = "'"  # single quote - standard SQLi syntax-error probe, no payload
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT) as client:
            for param in COMMON_PARAMS:
                url = f"{base_url}/?{param}={probe}"
                try:
                    resp = await client.get(url)
                except Exception:
                    continue

                body_lower = resp.text.lower()
                matched_engine = None
                for sig, engine in SQLI_ERROR_SIGNATURES.items():
                    if sig in body_lower:
                        matched_engine = engine
                        break

                if matched_engine is None:
                    continue

                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Possible SQL injection via '{param}' parameter on {asset.name}",
                    description=(
                        f"A single-quote probe on the '{param}' parameter triggered a "
                        f"{matched_engine} database error in the response, suggesting "
                        f"unsanitized input reaches a SQL query. This is a detection "
                        f"signal, not confirmed exploitation - no data was extracted."
                    ),
                    asset=asset,
                    module_source=self.capabilities.module_id,
                    finding_kind=FindingKind.VULNERABILITY,
                    owasp_category="A03:2021-Injection",
                    cvss=CvssScore(base_score=8.6, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
                    cwe=WeaknessRef(cwe_id="CWE-89", name="SQL Injection"),
                    kill_chain_phase=KillChainPhase.EXPLOITATION,
                    remediation="Use parameterized queries / prepared statements for all user input reaching SQL. Never concatenate raw input into query strings.",
                    business_impact="Unsanitized input reaching the database can allow data disclosure, modification, or deletion depending on the query context.",
                )
                finding.add_evidence(Evidence.new(
                    evidence_type=EvidenceType.HTTP_TRANSACTION,
                    raw_bytes=f"GET {url}\nstatus: {resp.status_code}\nmatched_engine: {matched_engine}\nbody_excerpt: {resp.text[:400]}".encode(),
                    storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/sqli_probe.txt",
                    description=f"Response body containing a {matched_engine} error signature after single-quote probe",
                    metadata={"preview": f"GET {url}\nstatus: {resp.status_code}\nmatched_engine: {matched_engine}"},
                ))
                yield finding

    # -- A03: Injection (reflected XSS detection) ----------------------------

    async def _check_reflected_xss(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        marker = f"h4ckbot_{uuid.uuid4().hex[:8]}"
        probe = f"<{marker}>"  # inert marker - not a working script tag
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT) as client:
            for param in COMMON_PARAMS:
                url = f"{base_url}/?{param}={probe}"
                try:
                    resp = await client.get(url)
                except Exception:
                    continue

                # Reflection detection only: does our exact unescaped marker
                # come back in the HTML? We do not execute anything or use
                # a headless browser to confirm actual script execution -
                # that would be a step toward exploitation, not detection.
                if probe not in resp.text:
                    continue

                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Possible reflected XSS via '{param}' parameter on {asset.name}",
                    description=(
                        f"An inert HTML-like marker submitted in the '{param}' parameter "
                        f"was reflected back unescaped in the response body, indicating "
                        f"the application does not encode this input before rendering it. "
                        f"This is a detection signal - no script execution was attempted "
                        f"or confirmed."
                    ),
                    asset=asset,
                    module_source=self.capabilities.module_id,
                    finding_kind=FindingKind.VULNERABILITY,
                    owasp_category="A03:2021-Injection",
                    cvss=CvssScore(base_score=6.1, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
                    cwe=WeaknessRef(cwe_id="CWE-79", name="Cross-Site Scripting (Reflected)"),
                    kill_chain_phase=KillChainPhase.EXPLOITATION,
                    remediation="HTML-encode all user input before rendering it into a response. Use your framework's auto-escaping templates rather than manual string concatenation.",
                    business_impact="Unescaped reflected input can allow an attacker to run script in a victim's browser session if a crafted link is followed.",
                )
                finding.add_evidence(Evidence.new(
                    evidence_type=EvidenceType.HTTP_TRANSACTION,
                    raw_bytes=f"GET {url}\nstatus: {resp.status_code}\nmarker_reflected_unescaped: true\nbody_excerpt: {resp.text[:400]}".encode(),
                    storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/xss_probe.txt",
                    description="Response body showing the unescaped marker reflected",
                    metadata={"preview": f"GET {url}\nstatus: {resp.status_code}\nmarker_reflected_unescaped: true"},
                ))
                yield finding

    # -- A06: Vulnerable and Outdated Components -----------------------------

    async def _check_vulnerable_components(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> Finding | None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT) as client:
                resp = await client.get(base_url)
        except Exception:
            return None

        server_header = resp.headers.get("server", "")
        x_powered_by = resp.headers.get("x-powered-by", "")
        combined = f"{server_header} {x_powered_by}".lower()

        for product, info in KNOWN_VULNERABLE_VERSIONS.items():
            match = re.search(rf"{product}[/\s]([\d.]+)", combined)
            if not match:
                continue
            version_str = match.group(1)
            if self._version_lt(version_str, info["max_safe"]):
                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Outdated {product} version detected on {asset.name}: {version_str}",
                    description=f"{info['note']}. Detected version: {version_str} (fix version: {info['max_safe']}+).",
                    asset=asset,
                    module_source=self.capabilities.module_id,
                    finding_kind=FindingKind.VULNERABILITY,
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    cvss=CvssScore(base_score=6.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
                    cwe=WeaknessRef(cwe_id="CWE-1104", name="Use of Unmaintained Third Party Components"),
                    kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                    remediation=f"Upgrade {product} to {info['max_safe']} or later. Check vendor advisories for the specific CVEs affecting the detected version.",
                    business_impact="Outdated software components carry publicly known, often weaponized vulnerabilities.",
                )
                finding.add_evidence(Evidence.new(
                    evidence_type=EvidenceType.RESPONSE_HEADERS,
                    raw_bytes=f"Server: {server_header}\nX-Powered-By: {x_powered_by}".encode(),
                    storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/version_fingerprint.txt",
                    description="Version-revealing response headers",
                    metadata={"preview": f"Server: {server_header}\nX-Powered-By: {x_powered_by}"},
                ))
                return finding
        return None

    @staticmethod
    def _version_lt(a: str, b: str) -> bool:
        def parts(v: str) -> list[int]:
            return [int(x) for x in re.findall(r"\d+", v)]
        pa, pb = parts(a), parts(b)
        return pa < pb

    # -- A07: Identification and Authentication Failures ---------------------

    async def _check_username_enumeration(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        login_paths = ["/login", "/signin", "/user/login", "/account/login"]
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            login_url = None
            for path in login_paths:
                try:
                    resp = await client.get(base_url + path)
                except Exception:
                    continue
                if resp.status_code == 200 and "password" in resp.text.lower():
                    login_url = base_url + path
                    break
            if login_url is None:
                return

            # Two generic, non-real probe usernames - not a credential
            # guessing attack, just comparing error message shape.
            try:
                resp_a = await client.post(login_url, data={"username": "h4ckbot_probe_a", "password": "x"})
                resp_b = await client.post(login_url, data={"username": "h4ckbot_probe_b", "password": "x"})
            except Exception:
                return

            if resp_a.status_code != resp_b.status_code and abs(len(resp_a.text) - len(resp_b.text)) < 50:
                return  # status differs but bodies are similar length - inconclusive, don't report

            # Look for a differentiating error message pattern between
            # the two arbitrary usernames (both are fake, so any
            # difference is purely about response shape, not real data).
            if resp_a.text.strip() == resp_b.text.strip() and resp_a.status_code == resp_b.status_code:
                return  # identical responses - good, no enumeration signal

            finding = Finding(
                finding_id=str(uuid.uuid4()),
                title=f"Possible username enumeration on {login_url}",
                description=(
                    "Two different, fabricated usernames produced different "
                    "response status codes or bodies at the login endpoint, "
                    "which can let an attacker distinguish valid from invalid "
                    "usernames without knowing any real credentials."
                ),
                asset=asset,
                module_source=self.capabilities.module_id,
                finding_kind=FindingKind.VULNERABILITY,
                owasp_category="A07:2021-Identification and Authentication Failures",
                cvss=CvssScore(base_score=5.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                cwe=WeaknessRef(cwe_id="CWE-204", name="Observable Response Discrepancy"),
                kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                remediation="Return an identical, generic error message and response time for both valid and invalid usernames on login failure.",
                business_impact="Enables username enumeration, which narrows the search space for credential-stuffing or password-spray attacks.",
            )
            finding.add_evidence(Evidence.new(
                evidence_type=EvidenceType.BEHAVIORAL_DIFF,
                raw_bytes=(
                    f"probe_a status={resp_a.status_code} len={len(resp_a.text)}\n"
                    f"probe_b status={resp_b.status_code} len={len(resp_b.text)}"
                ).encode(),
                storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/enum_diff.txt",
                description="Response comparison between two fabricated usernames",
                metadata={"preview": f"probe_a status={resp_a.status_code} len={len(resp_a.text)}; probe_b status={resp_b.status_code} len={len(resp_b.text)}"},
            ))
            yield finding
