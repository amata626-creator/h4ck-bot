"""
Real misconfiguration checker.

Runs independent checks against HTTP(S) services:
  1. Missing/weak security headers (HSTS, CSP, X-Frame-Options, etc.)
  2. Weak TLS configuration (protocol version, expired/self-signed cert)
  3. Exposed default/debug pages (common paths that shouldn't be reachable)
  4. Insecure cookie flags (session/auth cookies missing HttpOnly/Secure/SameSite)
  5. Permissive CORS (Origin reflection, or wildcard with credentials)
  6. Technology/version disclosure (Server, X-Powered-By, X-AspNet-Version, …)

All checks are GET-only and non-destructive. Cookie inspection reports on
flags only and never captures a cookie value. Each produces a single
authoritative observation, so requires_corroboration is False.

Each check produces a real vulnerability-kind Finding with a real CVSS
score computed from actual observed conditions (not hardcoded), CWE
mapping, and evidence. These are the first non-informational findings
in the codebase - they're meant to flow through the full 5-layer
validation pipeline once layers 1-3 are implemented.
"""

from __future__ import annotations

import socket
import ssl
import uuid
from datetime import datetime, timezone
from typing import AsyncIterator

import httpx

from core.module_interface import ModuleCapabilities, ModuleRunContext, ScannerModule, OutOfScopeError
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding,
    FindingKind, KillChainPhase, WeaknessRef,
)

CONNECT_TIMEOUT = 5.0

# header -> (CWE, base severity contribution if missing)
SECURITY_HEADERS = {
    "strict-transport-security": ("CWE-319", "Missing HSTS allows protocol downgrade / SSL-stripping attacks"),
    "content-security-policy": ("CWE-693", "Missing CSP increases XSS/injection impact"),
    "x-frame-options": ("CWE-1021", "Missing X-Frame-Options allows clickjacking"),
    "x-content-type-options": ("CWE-693", "Missing X-Content-Type-Options allows MIME-sniffing attacks"),
}

DEFAULT_PAGE_PATHS = [
    "/.git/config",
    "/.env",
    "/wp-admin/",
    "/phpinfo.php",
    "/server-status",
    "/.well-known/security.txt",  # not a vuln by itself, used as a control check
    "/admin/",
    "/actuator/health",
]

# paths that indicate a real exposure if they return 200 with matching content
SENSITIVE_PATH_SIGNATURES = {
    "/.git/config": "[core]",
    "/.env": "DB_",
    "/phpinfo.php": "phpinfo()",
    "/server-status": "Apache Server Status",
    "/actuator/health": '"status"',
}

# Cookies whose theft actually matters (session / auth). A missing flag on
# one of these is the finding; analytics cookies are not chased.
SESSION_COOKIE_HINTS = ("sess", "sid", "auth", "token", "jsessionid", "aspxauth", "csrf")

# Response headers that leak stack/framework/version detail. 'server' is
# handled separately — only flagged when it carries a version number, since a
# bare 'Server: Apache' is not itself a disclosure worth reporting.
DISCLOSURE_HEADERS = (
    "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime",
    "x-generator", "x-drupal-dynamic-cache", "x-version", "x-backend-server",
)

# A sentinel Origin the target could never legitimately trust. If it comes
# back reflected in Access-Control-Allow-Origin, the CORS policy echoes
# arbitrary origins — the real misconfiguration.
CORS_PROBE_ORIGIN = "https://h4ckbot-cors-probe.invalid"


class MisconfigModule(ScannerModule):
    @property
    def capabilities(self) -> ModuleCapabilities:
        return ModuleCapabilities(
            module_id="misconfig_checker",
            display_name="Security misconfiguration checker",
            supported_asset_types=["web_app", "api", "host"],
            kill_chain_phases=["reconnaissance", "exploitation"],
            requires_active_testing=True,
            max_automation_level="semi_autonomous",
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

                reachable = await self._is_reachable(base_url)
                if not reachable:
                    continue

                async for finding in self._check_headers(asset, ctx, base_url):
                    yield finding

                async for finding in self._check_cookies(asset, ctx, base_url):
                    yield finding

                async for finding in self._check_cors(asset, ctx, base_url):
                    yield finding

                async for finding in self._check_info_disclosure(asset, ctx, base_url):
                    yield finding

                if scheme == "https":
                    finding = await self._check_tls(asset, ctx, asset.name, port)
                    if finding is not None:
                        yield finding

                async for finding in self._check_default_pages(asset, ctx, base_url):
                    yield finding

    async def _is_reachable(self, base_url: str) -> bool:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT) as client:
                await client.get(base_url)
            return True
        except Exception:
            return False

    # -- Check 1: security headers -----------------------------------------

    async def _check_headers(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(base_url)
        except Exception:
            return

        response_headers = {k.lower(): v for k, v in resp.headers.items()}
        missing = [h for h in SECURITY_HEADERS if h not in response_headers]

        if not missing:
            return  # nothing to report - all present

        # CVSS scales with how many are missing and whether it's HTTPS
        # (missing HSTS on plain HTTP is worse than on an already-HTTP-only site)
        severity_score = min(3.1 + (len(missing) * 1.2), 6.5)

        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Missing security headers on {base_url}",
            description=(
                f"{len(missing)} of {len(SECURITY_HEADERS)} recommended security headers "
                f"are absent: {', '.join(missing)}."
            ),
            asset=asset,
            module_source=self.capabilities.module_id,
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(
                base_score=round(severity_score, 1),
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            ),
            cwe=WeaknessRef(cwe_id="CWE-693", name="Protection Mechanism Failure (missing security headers)"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            remediation=(
                "Add the missing headers: " +
                "; ".join(f"{h} ({SECURITY_HEADERS[h][1]})" for h in missing)
            ),
            business_impact="Increases exploitability of client-side attacks (XSS, clickjacking, downgrade).",
            # A header is literally present or absent in the captured
            # response - one authoritative observation is dispositive.
            requires_corroboration=False,
        )

        raw = (
            f"GET {base_url}\nstatus: {resp.status_code}\n"
            f"present_headers: {list(response_headers.keys())}\n"
            f"missing_headers: {missing}\n"
        ).encode()

        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RESPONSE_HEADERS,
            raw_bytes=raw,
            storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/headers.txt",
            description="Full response header set from target",
            metadata={"preview": raw.decode()},
        ))

        yield finding

    # -- Check 2: TLS configuration ------------------------------------------

    async def _check_tls(self, asset: Asset, ctx: ModuleRunContext, host: str, port: int) -> Finding | None:
        issues = []
        cert_info = {}

        try:
            ctx_ssl = ssl.create_default_context()
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cert_info["negotiated_protocol"] = ssock.version()

                    # protocol version check
                    if ssock.version() in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        issues.append(f"weak protocol negotiated: {ssock.version()}")

                    # cert expiry check - need real cert data, re-fetch with verification off but parsing on
        except Exception as exc:
            return None  # TLS connection failed entirely - handled as availability, not a misconfig finding here

        # separately fetch cert details (subject/expiry) via a verified-off context
        try:
            with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
                ctx_ssl2 = ssl.create_default_context()
                ctx_ssl2.check_hostname = False
                ctx_ssl2.verify_mode = ssl.CERT_NONE
                with ctx_ssl2.wrap_socket(sock, server_hostname=host) as ssock2:
                    der = ssock2.getpeercert(binary_form=True)
                    import cryptography.x509 as x509
                    from cryptography.hazmat.backends import default_backend

                    parsed = x509.load_der_x509_certificate(der, default_backend())
                    not_after = parsed.not_valid_after_utc
                    cert_info["not_after"] = not_after.isoformat()
                    cert_info["subject"] = parsed.subject.rfc4514_string()
                    cert_info["issuer"] = parsed.issuer.rfc4514_string()

                    if not_after < datetime.now(timezone.utc):
                        issues.append(f"certificate expired on {not_after.isoformat()}")

                    if parsed.subject == parsed.issuer:
                        issues.append("certificate appears self-signed (subject == issuer)")
        except Exception:
            pass  # cert parsing failed - report protocol-version issues only if any

        if not issues:
            return None

        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"TLS configuration issue on {host}:{port}",
            description="; ".join(issues),
            asset=asset,
            module_source=self.capabilities.module_id,
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(
                base_score=5.9 if any("expired" in i or "weak protocol" in i for i in issues) else 4.3,
                vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            ),
            cwe=WeaknessRef(cwe_id="CWE-295", name="Improper Certificate Validation / Weak Transport Security"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            remediation="Renew/replace the certificate with a CA-signed cert and disable TLS versions below 1.2.",
            business_impact="Weakens confidentiality/integrity guarantees of transport encryption; may enable MITM.",
            # Negotiated TLS version / cert validity are observed facts of
            # the handshake - a single authoritative observation.
            requires_corroboration=False,
        )

        raw = f"TLS check on {host}:{port}\n{cert_info}\nissues: {issues}\n".encode()
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RAW_OUTPUT,
            raw_bytes=raw,
            storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/tls.txt",
            description="TLS handshake details and certificate inspection",
            metadata={"preview": raw.decode()},
        ))

        return finding

    # -- Check 4: insecure cookie flags --------------------------------------

    @staticmethod
    def _parse_set_cookie(raw: str) -> tuple[str, set[str], str | None]:
        """Return (name, lowercased-attribute-names, samesite-value). The
        cookie VALUE is deliberately never returned — we report on flags, not
        secrets, so a live session token never reaches a finding or report."""
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip() if parts else ""
        attrs: set[str] = set()
        samesite: str | None = None
        for p in parts[1:]:
            key = p.split("=", 1)[0].strip().lower()
            attrs.add(key)
            if key == "samesite":
                samesite = (p.split("=", 1)[1].strip().lower() if "=" in p else "")
        return name, attrs, samesite

    async def _check_cookies(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(base_url)
        except Exception:
            return

        raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not raw_cookies:
            return

        is_https = base_url.startswith("https")
        flagged: list[str] = []          # human-readable, value-redacted lines
        issue_types: set[str] = set()
        touches_session = False

        for raw in raw_cookies:
            name, attrs, samesite = self._parse_set_cookie(raw)
            if not name:
                continue
            problems = []
            if "httponly" not in attrs:
                problems.append("HttpOnly")
                issue_types.add("HttpOnly")
            if is_https and "secure" not in attrs:
                problems.append("Secure")
                issue_types.add("Secure")
            if samesite is None:
                problems.append("SameSite")
                issue_types.add("SameSite")
            if not problems:
                continue
            session_like = any(h in name.lower() for h in SESSION_COOKIE_HINTS)
            touches_session = touches_session or session_like
            # Reconstruct a redacted Set-Cookie for evidence: name + attributes
            # only, never the value.
            present_attrs = ", ".join(sorted(attrs)) or "(none)"
            flagged.append(
                f"{name}{' [session]' if session_like else ''}: "
                f"missing {', '.join(problems)}  (present attrs: {present_attrs})"
            )

        # Report only when a flag is actually missing — and treat missing
        # SameSite ALONE as too low-signal to raise on its own (browsers
        # default to Lax), so require at least one HttpOnly/Secure gap.
        if not flagged or issue_types <= {"SameSite"}:
            return

        base = min(3.1 + 1.1 * len(issue_types) + (1.0 if touches_session else 0.0), 6.1)
        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Insecure cookie flags on {base_url}",
            description=(
                f"{len(flagged)} cookie(s) are set without recommended security flags. "
                + ("A session/auth cookie is affected, so this is directly exploitable "
                   "via XSS or transport interception. " if touches_session else "")
                + "Missing flags: " + ", ".join(sorted(issue_types)) + "."
            ),
            asset=asset,
            module_source=self.capabilities.module_id,
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(
                base_score=round(base, 1),
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            ),
            cwe=WeaknessRef(cwe_id="CWE-1004",
                            name="Sensitive Cookie Without 'HttpOnly' Flag (see also CWE-614 Secure, CWE-1275 SameSite)"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            remediation=(
                "Set HttpOnly and Secure on session/auth cookies, and an explicit "
                "SameSite (Lax or Strict). Serve cookies only over HTTPS."
            ),
            business_impact="A session cookie reachable from script or sent in clear can be stolen, enabling session hijacking.",
            requires_corroboration=False,
        )
        raw_ev = (f"GET {base_url}\nstatus: {resp.status_code}\n"
                  "cookies with missing flags (values redacted):\n  "
                  + "\n  ".join(flagged) + "\n").encode()
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RESPONSE_HEADERS,
            raw_bytes=raw_ev,
            storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/cookies.txt",
            description="Set-Cookie flag inspection (cookie values redacted)",
            metadata={"preview": raw_ev.decode()},
        ))
        yield finding

    # -- Check 5: permissive CORS --------------------------------------------

    async def _check_cors(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(base_url, headers={"Origin": CORS_PROBE_ORIGIN})
        except Exception:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        acao = headers.get("access-control-allow-origin")
        if not acao:
            return
        acac = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        reflected = acao.strip() == CORS_PROBE_ORIGIN
        wildcard = acao.strip() == "*"

        # A fixed ACAO naming some specific legitimate origin is NOT a finding.
        # Only our reflected sentinel, or wildcard-with-credentials, is.
        if not (reflected or (wildcard and acac)):
            return

        if reflected and acac:
            base, detail = 7.5, ("The server reflects an arbitrary Origin AND allows credentials — any site "
                                 "can read authenticated responses on the victim's behalf.")
        elif reflected:
            base, detail = 5.3, ("The server reflects an arbitrary Origin into Access-Control-Allow-Origin, "
                                 "trusting any site to read cross-origin responses.")
        else:  # wildcard and acac
            base, detail = 4.3, ("Access-Control-Allow-Origin is '*' together with Allow-Credentials: true, "
                                 "an invalid, permissive combination.")

        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Permissive CORS policy on {base_url}",
            description=detail,
            asset=asset,
            module_source=self.capabilities.module_id,
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(
                base_score=base,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N" if (reflected and acac)
                else "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
            ),
            cwe=WeaknessRef(cwe_id="CWE-942", name="Permissive Cross-domain Policy with Untrusted Domains"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            remediation=(
                "Do not reflect the Origin header. Allow only an explicit allowlist of trusted origins, "
                "and never combine Access-Control-Allow-Credentials: true with a wildcard or reflected origin."
            ),
            business_impact="Allows malicious sites to read authenticated responses, exposing user data cross-origin.",
            requires_corroboration=False,
        )
        raw_ev = (f"GET {base_url}\nsent  Origin: {CORS_PROBE_ORIGIN}\n"
                  f"recv  Access-Control-Allow-Origin: {acao}\n"
                  f"recv  Access-Control-Allow-Credentials: {headers.get('access-control-allow-credentials', '(absent)')}\n"
                  f"reflected_sentinel: {reflected}\n").encode()
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.HTTP_TRANSACTION,
            raw_bytes=raw_ev,
            storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/cors.txt",
            description="CORS reflection probe (sentinel Origin vs returned ACAO/ACAC)",
            metadata={"preview": raw_ev.decode()},
        ))
        yield finding

    # -- Check 6: version / stack information disclosure ----------------------

    async def _check_info_disclosure(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(base_url)
        except Exception:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        leaks: list[str] = []
        for h in DISCLOSURE_HEADERS:
            if h in headers and headers[h].strip():
                leaks.append(f"{h}: {headers[h]}")
        # 'Server' only counts as a disclosure when it carries a version number.
        server = headers.get("server", "")
        if server and any(c.isdigit() for c in server):
            leaks.append(f"server: {server}")

        if not leaks:
            return

        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Technology/version disclosure on {base_url}",
            description=(
                "Response headers reveal server/framework version detail that helps an attacker "
                "fingerprint the stack and target known CVEs: " + "; ".join(leaks) + "."
            ),
            asset=asset,
            module_source=self.capabilities.module_id,
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(
                base_score=3.1,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            ),
            cwe=WeaknessRef(cwe_id="CWE-200", name="Exposure of Sensitive Information (version/stack disclosure)"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            remediation="Suppress or genericize version-bearing headers (Server, X-Powered-By, X-AspNet-Version, etc.).",
            business_impact="Speeds up targeted attacks by disclosing the exact stack and version to fingerprint.",
            requires_corroboration=False,
        )
        raw_ev = (f"GET {base_url}\nstatus: {resp.status_code}\n"
                  "disclosure headers:\n  " + "\n  ".join(leaks) + "\n").encode()
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RESPONSE_HEADERS,
            raw_bytes=raw_ev,
            storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/disclosure.txt",
            description="Version/stack disclosure headers",
            metadata={"preview": raw_ev.decode()},
        ))
        yield finding

    # -- Check 3: exposed default/debug pages --------------------------------

    async def _check_default_pages(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=False) as client:
            for path in DEFAULT_PAGE_PATHS:
                url = base_url + path
                try:
                    resp = await client.get(url)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                signature = SENSITIVE_PATH_SIGNATURES.get(path)
                if signature and signature not in resp.text:
                    continue  # 200 but doesn't match expected content - likely a custom 404 page, skip

                if path == "/.well-known/security.txt":
                    continue  # this one is a GOOD thing to have, not a finding

                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Exposed sensitive path: {path} on {asset.name}",
                    description=f"{url} returned HTTP 200 with content matching a sensitive-file signature.",
                    asset=asset,
                    module_source=self.capabilities.module_id,
                    finding_kind=FindingKind.VULNERABILITY,
                    cvss=CvssScore(
                        base_score=7.5 if path in ("/.env", "/.git/config") else 5.3,
                        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    ),
                    cwe=WeaknessRef(cwe_id="CWE-538", name="Insertion of Sensitive Information into Externally-Accessible File"),
                    kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                    remediation=f"Remove or restrict access to {path}; ensure it is not served by the web root.",
                    business_impact="May disclose credentials, source code structure, or internal service state.",
                )

                _exposed_raw = f"GET {url}\nstatus: {resp.status_code}\nbody_preview: {resp.text[:300]}"
                finding.add_evidence(Evidence.new(
                    evidence_type=EvidenceType.HTTP_TRANSACTION,
                    raw_bytes=_exposed_raw.encode(),
                    storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/exposed_path.txt",
                    description=f"Response body from {path}",
                    metadata={"preview": _exposed_raw},
                ))

                yield finding
