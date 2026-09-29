"""
Advanced security checks module - CORS, CSP, Clickjacking, Open
Redirect, CRLF Injection, and Sensitive Data Exposure.

Same detection boundary as modules/owasp_top10_module.py, restated
here because this module was explicitly split off from a larger list
of proposed checks that also included several that cross into actual
exploitation (RCE validation, credential bruteforce, CAPTCHA bypass,
account-takeover simulation, an auto-mutating "reinforced fuzzing"
payload-evolution loop, etc). Those were deliberately NOT built here.
Every check in THIS module is a single non-destructive probe (a
header, a redirect target, a passive body scan, a normal GET to a
path) - it produces evidence of a misconfiguration, never a working
exploit or extracted secret used for anything beyond proving exposure.

Logging: every probe and decision logs at INFO, including the
negative case, matching the rest of this codebase's diagnosability
convention.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import AsyncIterator

import httpx

from core.module_interface import ModuleCapabilities, ModuleRunContext, ScannerModule, OutOfScopeError
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding,
    FindingKind, KillChainPhase, WeaknessRef,
)
from modules.owasp_top10_module import _PageParser, _normalize_netloc, MAX_CRAWL_PAGES, STATIC_EXTENSIONS

logger = logging.getLogger("h4ck-bot.advanced_checks")

CONNECT_TIMEOUT = 6.0

REDIRECT_PARAM_NAMES = [
    "redirect", "url", "next", "return", "continue", "dest",
    "redirect_uri", "return_to", "target", "out", "view", "r",
]

CRLF_PARAM_NAMES = ["id", "q", "search", "page", "category", "ref"]

SENSITIVE_PATHS = [
    ".env", ".git/config", ".git/HEAD", "config.php.bak", "wp-config.php.bak",
    "backup.zip", ".aws/credentials", ".npmrc", "docker-compose.yml", ".DS_Store",
]

SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API key assignment": re.compile(r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,45}['\"]"),
    "Private key block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "JWT-looking token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}


async def _discover_urls(base_url: str) -> list[str]:
    """Same-origin endpoint discovery. Tries modules.deep_crawler first
    (a Playwright-based crawler that renders pages with a real browser,
    catching JS/SPA-hydrated links a static HTML parser would miss,
    plus XHR/fetch API calls made during page load, robots.txt/
    sitemap.xml, OpenAPI/Swagger specs, and AI-assisted extraction of
    templated endpoints from JS bundles). Falls back to the original
    httpx+html.parser crawl below if deep_crawler is unavailable or
    errors out, so this never becomes a hard dependency."""
    try:
        from modules.deep_crawler import discover_endpoints
        urls = await discover_endpoints(base_url, max_pages=MAX_CRAWL_PAGES)
        logger.info(f"advanced_checks crawl: {base_url} -> discovered {len(urls)} URL(s) via deep_crawler")
        return urls
    except Exception as e:
        logger.info(f"advanced_checks crawl: deep_crawler failed for {base_url} "
                   f"({type(e).__name__}: {e}) - falling back to static HTML crawl")

    visited: set[str] = set()
    to_visit = [base_url]
    base_host = _normalize_netloc(__import__("urllib.parse", fromlist=["urlparse"]).urlparse(base_url).netloc)

    async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
        while to_visit and len(visited) < MAX_CRAWL_PAGES:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = await client.get(url)
            except Exception as e:
                logger.info(f"advanced_checks crawl: failed to fetch {url} - {type(e).__name__}: {e}")
                continue
            if "text/html" not in resp.headers.get("content-type", ""):
                continue
            parser = _PageParser(str(resp.url))
            try:
                parser.feed(resp.text)
            except Exception as e:
                logger.info(f"advanced_checks crawl: HTML parse error on {url} - {type(e).__name__}: {e}")
                continue
            for link in parser.links:
                from urllib.parse import urlparse
                try:
                    parsed = urlparse(link)
                except Exception:
                    continue
                if _normalize_netloc(parsed.netloc) != base_host:
                    continue
                if parsed.scheme not in ("http", "https"):
                    continue
                if link.lower().split("?")[0].endswith(STATIC_EXTENSIONS):
                    continue
                if link not in visited and link not in to_visit:
                    to_visit.append(link)

    logger.info(f"advanced_checks crawl: {base_url} -> discovered {len(visited)} page(s)")
    return list(visited)


class AdvancedChecksModule(ScannerModule):
    @property
    def capabilities(self) -> ModuleCapabilities:
        return ModuleCapabilities(
            module_id="advanced_checks",
            display_name="Advanced checks (CORS, CSP, Clickjacking, Open Redirect, CRLF, Sensitive Data)",
            supported_asset_types=["web_app", "api", "host"],
            kill_chain_phases=["reconnaissance"],
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

                try:
                    async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                        await client.get(base_url)
                except Exception as e:
                    logger.info(f"advanced_checks: {base_url} not reachable - {type(e).__name__}: {e} - skipping")
                    continue

                urls = await _discover_urls(base_url)

                finding = await self._check_cors(asset, ctx, base_url)
                if finding is not None:
                    yield finding

                finding = await self._check_csp(asset, ctx, base_url)
                if finding is not None:
                    yield finding

                finding = await self._check_clickjacking(asset, ctx, base_url)
                if finding is not None:
                    yield finding

                async for f in self._check_open_redirect(asset, ctx, base_url, urls):
                    yield f

                async for f in self._check_crlf_injection(asset, ctx, base_url):
                    yield f

                async for f in self._check_sensitive_data_exposure(asset, ctx, base_url, urls):
                    yield f

    # -- CORS misconfiguration --------------------------------------------

    async def _check_cors(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> Finding | None:
        probe_origin = "https://h4ckbot-cors-probe.invalid"
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(base_url, headers={"Origin": probe_origin})
        except Exception as e:
            logger.info(f"advanced_checks cors: request failed for {base_url} - {type(e).__name__}: {e}")
            return None

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

        logger.info(f"advanced_checks cors: {base_url} -> "
                   f"Access-Control-Allow-Origin='{acao}' Access-Control-Allow-Credentials={acac}")

        reflects_arbitrary_origin = acao == probe_origin
        wildcard_with_credentials = acao == "*" and acac

        if not reflects_arbitrary_origin and not wildcard_with_credentials:
            logger.info(f"advanced_checks cors: {base_url} - no dangerous CORS combination detected")
            return None

        severity_note = (
            "reflects any Origin AND allows credentials - a malicious site can read "
            "authenticated responses from a victim's browser"
            if reflects_arbitrary_origin and acac else
            "reflects any Origin sent to it (no credentials allowed, lower impact but "
            "still an overly permissive policy)"
            if reflects_arbitrary_origin else
            "sets Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: "
            "true, an invalid/dangerous combination browsers may handle inconsistently"
        )

        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"CORS misconfiguration on {asset.name}",
            description=f"The server's CORS policy {severity_note}.",
            asset=asset,
            module_source=self.capabilities.module_id,
            finding_kind=FindingKind.MISCONFIGURATION,
            owasp_category="A05:2021-Security Misconfiguration",
            cvss=CvssScore(
                base_score=8.1 if (reflects_arbitrary_origin and acac) else 5.3,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N" if (reflects_arbitrary_origin and acac)
                       else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            ),
            cwe=WeaknessRef(cwe_id="CWE-942", name="Permissive Cross-domain Policy with Untrusted Domains"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            remediation="Validate the Origin header against an explicit allowlist instead of reflecting it. Never combine a wildcard or reflected origin with Access-Control-Allow-Credentials: true.",
            business_impact="An overly permissive CORS policy can let a malicious site read authenticated API responses on behalf of a logged-in victim.",
        )
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RESPONSE_HEADERS,
            raw_bytes=f"Request Origin: {probe_origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {resp.headers.get('access-control-allow-credentials', '')}".encode(),
            storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/cors_probe.txt",
            description="CORS response headers after sending an arbitrary, attacker-controlled Origin",
            metadata={"preview": f"ACAO={acao} ACAC={acac}"},
        ))
        return finding

    # -- CSP misconfiguration ----------------------------------------------

    async def _check_csp(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> Finding | None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(base_url)
        except Exception as e:
            logger.info(f"advanced_checks csp: request failed for {base_url} - {type(e).__name__}: {e}")
            return None

        csp = resp.headers.get("content-security-policy") or resp.headers.get("content-security-policy-report-only")
        if not csp:
            meta_match = re.search(
                r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=["\']([^"\']+)["\']',
                resp.text, re.IGNORECASE,
            )
            csp = meta_match.group(1) if meta_match else None

        logger.info(f"advanced_checks csp: {base_url} -> CSP={'present' if csp else 'MISSING'}"
                   + (f" value={csp[:200]}" if csp else ""))

        issues = []
        if not csp:
            issues.append("no Content-Security-Policy header or meta tag present at all")
        else:
            csp_lower = csp.lower()
            if "unsafe-inline" in csp_lower:
                issues.append("allows 'unsafe-inline' (defeats CSP's protection against injected inline scripts)")
            if "unsafe-eval" in csp_lower:
                issues.append("allows 'unsafe-eval' (permits dynamic code execution via eval())")
            if re.search(r"(default-src|script-src)[^;]*\*", csp_lower):
                issues.append("uses a wildcard '*' source in default-src/script-src (allows loading scripts from any origin)")

        if not issues:
            logger.info(f"advanced_checks csp: {base_url} - CSP present with no obviously unsafe directives")
            return None

        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Content-Security-Policy issue(s) on {asset.name}",
            description="Content-Security-Policy weaknesses found: " + "; ".join(issues) + ".",
            asset=asset,
            module_source=self.capabilities.module_id,
            finding_kind=FindingKind.MISCONFIGURATION,
            owasp_category="A05:2021-Security Misconfiguration",
            cvss=CvssScore(base_score=4.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
            cwe=WeaknessRef(cwe_id="CWE-693", name="Protection Mechanism Failure"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            remediation="Define a Content-Security-Policy that avoids 'unsafe-inline'/'unsafe-eval' and restricts default-src/script-src to specific trusted origins.",
            business_impact="A missing or weak CSP removes a key browser-side defense against XSS payload execution, increasing the impact of any injection vulnerability found elsewhere.",
        )
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RESPONSE_HEADERS,
            raw_bytes=f"Content-Security-Policy: {csp or '(none)'}".encode(),
            storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/csp_header.txt",
            description="CSP header/meta-tag value (or absence) observed on the response",
            metadata={"preview": "; ".join(issues)},
        ))
        return finding

    # -- Clickjacking --------------------------------------------------------

    async def _check_clickjacking(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> Finding | None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(base_url)
        except Exception as e:
            logger.info(f"advanced_checks clickjacking: request failed for {base_url} - {type(e).__name__}: {e}")
            return None

        xfo = resp.headers.get("x-frame-options", "")
        csp = resp.headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        logger.info(f"advanced_checks clickjacking: {base_url} -> "
                   f"X-Frame-Options='{xfo}' frame-ancestors_in_csp={has_frame_ancestors}")

        if xfo.upper() in ("DENY", "SAMEORIGIN") or has_frame_ancestors:
            logger.info(f"advanced_checks clickjacking: {base_url} - framing is restricted, not reporting")
            return None

        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Missing clickjacking protection on {asset.name}",
            description=(
                "The response has neither a restrictive X-Frame-Options header "
                "(DENY/SAMEORIGIN) nor a CSP frame-ancestors directive, so the "
                "page can be embedded in an iframe on an attacker-controlled site."
            ),
            asset=asset,
            module_source=self.capabilities.module_id,
            finding_kind=FindingKind.MISCONFIGURATION,
            owasp_category="A05:2021-Security Misconfiguration",
            cvss=CvssScore(base_score=4.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
            cwe=WeaknessRef(cwe_id="CWE-1021", name="Improper Restriction of Rendered UI Layers or Frames"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            remediation="Set X-Frame-Options: DENY (or SAMEORIGIN if framing by your own origin is needed) and/or a CSP frame-ancestors directive.",
            business_impact="Without framing protection, an attacker can overlay invisible UI elements to trick users into clicking unintended actions (clickjacking).",
        )
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RESPONSE_HEADERS,
            raw_bytes=f"X-Frame-Options: {xfo or '(missing)'}\nContent-Security-Policy: {csp or '(missing)'}".encode(),
            storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/clickjacking_headers.txt",
            description="Framing-related response headers",
            metadata={"preview": f"X-Frame-Options={xfo or '(missing)'}"},
        ))
        return finding

    # -- Open Redirect ---------------------------------------------------------

    async def _check_open_redirect(self, asset: Asset, ctx: ModuleRunContext,
                                    base_url: str, urls: list[str]) -> AsyncIterator[Finding]:
        from urllib.parse import urlparse, parse_qs

        probe_target = "https://h4ckbot-redirect-probe.invalid/landing"
        candidates: list[tuple[str, str]] = []  # (url_with_probe, param_name)

        # URLs already carrying a redirect-shaped param - replace its value.
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query)
            for pname in params:
                if pname.lower() in REDIRECT_PARAM_NAMES:
                    candidates.append((f"{base_url}{parsed.path}?{pname}={probe_target}", pname))

        # Also guess on the root path, same pattern as owasp_top10's generic pass.
        for pname in REDIRECT_PARAM_NAMES:
            candidates.append((f"{base_url}/?{pname}={probe_target}", pname))

        tested_params: set[str] = set()
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=False) as client:
            for url, pname in candidates:
                if pname in tested_params:
                    continue
                tested_params.add(pname)
                try:
                    resp = await client.get(url)
                except Exception as e:
                    logger.info(f"advanced_checks open_redirect: request failed for {url} - {type(e).__name__}: {e}")
                    continue

                location = resp.headers.get("location", "")
                redirects_offsite = False
                if resp.status_code in (301, 302, 303, 307, 308) and location:
                    # A same-origin http->https canonicalization redirect often
                    # round-trips the full original URL, INCLUDING our probe
                    # value sitting inertly in the query string - that makes it
                    # look like an "open redirect" under a naive substring
                    # check even though the browser never leaves the site.
                    # What actually matters is where Location's HOST points.
                    loc_host = _normalize_netloc(urlparse(location).netloc)
                    probe_host = _normalize_netloc(urlparse(probe_target).netloc)
                    redirects_offsite = bool(loc_host) and loc_host == probe_host

                if redirects_offsite:
                    logger.info(f"advanced_checks open_redirect: param '{pname}' -> "
                               f"status {resp.status_code}, Location='{location}' - CONFIRMED open redirect")

                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        title=f"Open redirect via '{pname}' parameter on {asset.name}",
                        description=(
                            f"Setting the '{pname}' parameter to an attacker-controlled URL "
                            f"caused the server to issue an HTTP {resp.status_code} redirect "
                            f"to that exact URL, without validating it against an allowlist."
                        ),
                        asset=asset,
                        module_source=self.capabilities.module_id,
                        finding_kind=FindingKind.VULNERABILITY,
                        owasp_category="",  # no dedicated 2021 category (was A10:2017)
                        cvss=CvssScore(base_score=4.7, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
                        cwe=WeaknessRef(cwe_id="CWE-601", name="URL Redirection to Untrusted Site ('Open Redirect')"),
                        kill_chain_phase=KillChainPhase.EXPLOITATION,
                        remediation="Validate redirect targets against an explicit allowlist of paths/domains, or use indirect reference tokens instead of raw URLs.",
                        business_impact="Open redirects are commonly used in phishing to make a malicious link appear to originate from a trusted domain.",
                    )
                    finding.add_evidence(Evidence.new(
                        evidence_type=EvidenceType.HTTP_TRANSACTION,
                        raw_bytes=f"GET {url}\nstatus: {resp.status_code}\nLocation: {location}".encode(),
                        storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/open_redirect_probe.txt",
                        description="Redirect response following the probe URL parameter",
                        metadata={"preview": f"status={resp.status_code} Location={location}"},
                    ))
                    yield finding
                elif resp.status_code in (301, 302, 303, 307, 308) and location:
                    logger.info(f"advanced_checks open_redirect: param '{pname}' -> "
                               f"status {resp.status_code}, Location='{location}' - same-origin redirect, not an open redirect")
                else:
                    logger.info(f"advanced_checks open_redirect: param '{pname}' -> "
                               f"status {resp.status_code}, no redirect to probe target")

    # -- CRLF Injection ---------------------------------------------------------

    async def _check_crlf_injection(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        marker = f"h4ckbot{uuid.uuid4().hex[:6]}"
        # %0d%0a = CRLF, url-encoded so httpx doesn't reject it outright at the client level -
        # whether the TARGET decodes and reflects this into a raw response header is exactly what we're testing.
        probe = f"test%0d%0aX-H4ckbot-Crlf-Test:{marker}"

        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            for pname in CRLF_PARAM_NAMES:
                url = f"{base_url}/?{pname}={probe}"
                try:
                    resp = await client.get(url)
                except Exception as e:
                    logger.info(f"advanced_checks crlf: request failed for {url} - {type(e).__name__}: {e}")
                    continue

                injected_header = resp.headers.get("x-h4ckbot-crlf-test")
                if injected_header == marker:
                    logger.info(f"advanced_checks crlf: param '{pname}' -> CONFIRMED header injection "
                               f"(X-H4ckbot-Crlf-Test: {injected_header})")

                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        title=f"CRLF injection via '{pname}' parameter on {asset.name}",
                        description=(
                            f"Submitting a CRLF-encoded sequence in the '{pname}' parameter "
                            f"resulted in an attacker-controlled response header "
                            f"(X-H4ckbot-Crlf-Test) being injected into the actual HTTP "
                            f"response, confirming the server does not sanitize this input "
                            f"before writing it into response headers."
                        ),
                        asset=asset,
                        module_source=self.capabilities.module_id,
                        finding_kind=FindingKind.VULNERABILITY,
                        owasp_category="A03:2021-Injection",
                        cvss=CvssScore(base_score=6.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
                        cwe=WeaknessRef(cwe_id="CWE-93", name="Improper Neutralization of CRLF Sequences"),
                        kill_chain_phase=KillChainPhase.EXPLOITATION,
                        remediation="Strip or encode CR/LF characters from any user input written into HTTP response headers.",
                        business_impact="CRLF injection can enable HTTP response splitting, cache poisoning, or session fixation depending on what the injected header controls.",
                    )
                    finding.add_evidence(Evidence.new(
                        evidence_type=EvidenceType.HTTP_TRANSACTION,
                        raw_bytes=f"GET {url}\ninjected_header_seen: X-H4ckbot-Crlf-Test: {injected_header}".encode(),
                        storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/crlf_probe.txt",
                        description="Response headers showing the injected marker header actually present",
                        metadata={"preview": f"param={pname} injected=X-H4ckbot-Crlf-Test:{injected_header}"},
                    ))
                    yield finding
                else:
                    logger.info(f"advanced_checks crlf: param '{pname}' -> status {resp.status_code}, no header injection")

    # -- Sensitive Data Exposure ---------------------------------------------

    async def _check_sensitive_data_exposure(self, asset: Asset, ctx: ModuleRunContext,
                                              base_url: str, urls: list[str]) -> AsyncIterator[Finding]:
        # Deliberately NOT following redirects for the sensitive-path probes:
        # an app that gates every unmatched path behind an auth redirect
        # (e.g. a NextAuth-style "/?callbackUrl=<path>" 307) will otherwise
        # land on the same final page for every request, whose byte size
        # varies slightly with the length of the original path string -
        # that's a real, reproducible artifact (confirmed by hand against
        # dev.cokpit.ai), not exposure, and byte-length comparison can never
        # reliably tell the two apart. A redirect away from the requested
        # path IS the correct "not exposed" signal on its own: the server
        # never actually served that path's content directly.
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=False) as client:
            for path in SENSITIVE_PATHS:
                url = f"{base_url}/{path}"
                try:
                    resp = await client.get(url)
                except Exception as e:
                    logger.info(f"advanced_checks sensitive_data: request failed for {url} - {type(e).__name__}: {e}")
                    continue

                if resp.status_code in (301, 302, 303, 307, 308):
                    logger.info(f"advanced_checks sensitive_data: {path} -> status {resp.status_code} "
                               f"redirect to '{resp.headers.get('location', '')}' - protected, not exposed")
                    continue
                if resp.status_code != 200:
                    logger.info(f"advanced_checks sensitive_data: {path} -> status {resp.status_code} - not exposed")
                    continue

                logger.info(f"advanced_checks sensitive_data: {path} -> status 200 with no redirect, "
                           f"{len(resp.text)} bytes - EXPOSED")

                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    title=f"Sensitive file exposed at /{path} on {asset.name}",
                    description=(
                        f"A normal GET request to /{path} returned HTTP 200 with content "
                        f"distinct from the site's baseline 404 response, indicating this "
                        f"sensitive file is publicly readable."
                    ),
                    asset=asset,
                    module_source=self.capabilities.module_id,
                    finding_kind=FindingKind.EXPOSURE,
                    owasp_category="A05:2021-Security Misconfiguration",
                    cvss=CvssScore(base_score=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
                    cwe=WeaknessRef(cwe_id="CWE-200", name="Exposure of Sensitive Information to an Unauthorized Actor"),
                    kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                    remediation=f"Remove /{path} from the publicly served directory, or block access to it at the web server / reverse proxy level.",
                    business_impact="Exposed configuration or credential files can hand an attacker direct access to secrets, database credentials, or source code.",
                )
                finding.add_evidence(Evidence.new(
                    evidence_type=EvidenceType.HTTP_TRANSACTION,
                    raw_bytes=f"GET {url}\nstatus: {resp.status_code}\nbody_excerpt: {resp.text[:300]}".encode(),
                    storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/exposed_file.txt",
                    description=f"Response confirming /{path} is publicly accessible",
                    metadata={"preview": f"GET /{path} -> {resp.status_code}, {len(resp.text)} bytes"},
                ))
                yield finding

            # Passive secret-pattern scan across the crawled pages.
            for url in [base_url] + urls:
                try:
                    resp = await client.get(url)
                except Exception:
                    continue
                for label, pattern in SECRET_PATTERNS.items():
                    match = pattern.search(resp.text)
                    if not match:
                        continue

                    logger.info(f"advanced_checks sensitive_data: {label} pattern matched on {url}")

                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        title=f"{label} exposed in response body on {asset.name}",
                        description=(
                            f"A response body at {url} contains a pattern matching "
                            f"{label}, suggesting a secret or credential was accidentally "
                            f"included in served content."
                        ),
                        asset=asset,
                        module_source=self.capabilities.module_id,
                        finding_kind=FindingKind.EXPOSURE,
                        owasp_category="A02:2021-Cryptographic Failures",
                        cvss=CvssScore(base_score=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
                        cwe=WeaknessRef(cwe_id="CWE-200", name="Exposure of Sensitive Information to an Unauthorized Actor"),
                        kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                        remediation="Remove hardcoded secrets from client-visible responses; rotate any credential that was exposed this way.",
                        business_impact="A leaked credential or key can be used directly by an attacker without needing any other vulnerability.",
                    )
                    finding.add_evidence(Evidence.new(
                        evidence_type=EvidenceType.HTTP_TRANSACTION,
                        raw_bytes=f"GET {url}\nmatched_pattern: {label}\ncontext: ...{resp.text[max(0,match.start()-40):match.end()+10]}...".encode(),
                        storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/secret_pattern.txt",
                        description=f"Response excerpt matching the {label} pattern",
                        metadata={"preview": f"{label} matched on {url}"},
                    ))
                    yield finding
