"""
Advanced security checks, batch 2 - Subdomain Takeover, Cookie/Session
Security, GraphQL Introspection Exposure, WebSocket Auth Inspection,
Supply-Chain (outdated JS library) Fingerprinting, and SSRF Candidate
Detection.

Same detection-only boundary as modules/advanced_checks_module.py.
Two checks here deserve an explicit note on where the line was drawn:

- SSRF candidate detection sends a probe pointing at the AWS/GCP/Azure
  metadata IP (169.254.169.254) ONLY to measure a response-timing
  differential against a control probe pointing at a nonexistent host.
  It NEVER inspects, parses, stores, or reports the response body from
  that probe - a positive result is reported purely as a timing
  differential ("candidate, needs manual follow-up"), never as
  confirmed credential exposure. Actually retrieving and reporting
  real cloud credentials from a metadata service is real credential
  theft and is explicitly NOT built here or anywhere in this module.

- WebSocket auth inspection only opens a connection and observes
  whether the handshake completes with no auth header/token supplied.
  It does not send any application-level messages after connecting.

Logging: every probe and decision logs at INFO, including the
negative case, matching the rest of this codebase's convention.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import time
import uuid
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs

import httpx

from core.module_interface import ModuleCapabilities, ModuleRunContext, ScannerModule, OutOfScopeError
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding,
    FindingKind, KillChainPhase, WeaknessRef,
)
from modules.advanced_checks_module import _discover_urls, CONNECT_TIMEOUT

logger = logging.getLogger("h4ck-bot.advanced_checks2")

SUBDOMAIN_WORDLIST = [
    "www", "api", "dev", "staging", "stage", "test", "beta", "admin", "portal",
    "app", "mail", "ftp", "cdn", "static", "assets", "blog", "shop", "store",
    "vpn", "remote", "docs", "help", "support", "status", "monitor", "grafana",
    "jenkins", "gitlab", "git", "jira", "confluence", "wiki", "demo", "sandbox",
]

# (cname_domain_suffix, unclaimed-resource fingerprint substring)
TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": ("github.io", "there isn't a github pages site here"),
    "AWS S3": ("s3.amazonaws.com", "nosuchbucket"),
    "Heroku": ("herokuapp.com", "no such app"),
    "Shopify": ("myshopify.com", "sorry, this shop is currently unavailable"),
    "Fastly": ("fastly.net", "fastly error: unknown domain"),
    "Azure Web Apps": ("azurewebsites.net", "404 web site not found"),
    "Bitbucket": ("bitbucket.io", "repository not found"),
    "Tumblr": ("domains.tumblr.com", "whatever you were looking for doesn't currently exist"),
    "Unbounce": ("unbouncepages.com", "the requested url was not found on this server"),
    "Pantheon": ("pantheonsite.io", "the gods are wise"),
    "Zendesk": ("zendesk.com", "help center closed"),
    "WordPress.com": ("wordpress.com", "do you want to register"),
}

GRAPHQL_PATHS = ["/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/query"]
INTROSPECTION_QUERY = {
    "query": "query IntrospectionQuery { __schema { queryType { name } types { name kind } } }"
}

WS_PATHS = ["/ws", "/websocket", "/socket", "/socket.io/?EIO=4&transport=websocket"]

# (library label, version-extraction regex, minimum safe version tuple, why it matters)
JS_LIBRARY_PATTERNS = [
    ("jQuery", re.compile(r"jquery[/@-](\d+\.\d+\.\d+)", re.I), (3, 5, 0),
     "XSS via jQuery.htmlPrefilter() in versions before 3.5.0 (CVE-2020-11022/11023)"),
    ("Lodash", re.compile(r"lodash[.@/-](\d+\.\d+\.\d+)", re.I), (4, 17, 21),
     "Prototype pollution in versions before 4.17.21 (CVE-2020-8203/28500)"),
    ("Moment.js", re.compile(r"moment[.@/-](\d+\.\d+\.\d+)", re.I), (2, 29, 4),
     "ReDoS in versions before 2.29.4 (CVE-2022-31129)"),
    ("Bootstrap", re.compile(r"bootstrap[.@/-](\d+\.\d+\.\d+)", re.I), (4, 3, 1),
     "XSS in tooltip/popover data-* attributes before 4.3.1 (CVE-2019-8331)"),
]

SSRF_PARAM_NAMES = [
    "url", "uri", "link", "src", "source", "fetch", "callback", "webhook",
    "target", "endpoint", "image", "avatar", "proxy", "dest", "site", "feed", "load",
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


class AdvancedChecks2Module(ScannerModule):
    @property
    def capabilities(self) -> ModuleCapabilities:
        return ModuleCapabilities(
            module_id="advanced_checks2",
            display_name="Advanced checks batch 2 (Subdomain Takeover, Cookie Security, GraphQL Introspection, WebSocket Auth, Supply Chain, SSRF Candidates)",
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

            # DNS-based, once per asset - not tied to a specific port/scheme.
            async for f in self._check_subdomain_takeover(asset, ctx):
                yield f

            ports = ctx.config.get("http_ports", [80, 443])
            for port in ports:
                scheme = "https" if port in (443, 8443) else "http"
                base_url = f"{scheme}://{asset.name}:{port}"

                try:
                    async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                        await client.get(base_url)
                except Exception as e:
                    logger.info(f"advanced_checks2: {base_url} not reachable - {type(e).__name__}: {e} - skipping")
                    continue

                urls = await _discover_urls(base_url)

                async for f in self._check_cookie_security(asset, ctx, base_url):
                    yield f

                async for f in self._check_graphql_introspection(asset, ctx, base_url):
                    yield f

                async for f in self._check_websocket_auth(asset, ctx, base_url):
                    yield f

                async for f in self._check_supply_chain_js(asset, ctx, base_url, urls):
                    yield f

                async for f in self._check_ssrf_candidates(asset, ctx, base_url, urls):
                    yield f

    # -- Subdomain Takeover ---------------------------------------------------

    async def _check_subdomain_takeover(self, asset: Asset, ctx: ModuleRunContext) -> AsyncIterator[Finding]:
        import dns.resolver
        import dns.exception

        resolver = dns.resolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 4

        logger.info(f"advanced_checks2 subdomain_takeover: {asset.name} - checking {len(SUBDOMAIN_WORDLIST)} candidate subdomain(s)")
        cname_count = 0
        matched_count = 0

        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            for sub in SUBDOMAIN_WORDLIST:
                fqdn = f"{sub}.{asset.name}"
                try:
                    answers = await asyncio.to_thread(resolver.resolve, fqdn, "CNAME")
                    cname = str(answers[0].target).rstrip(".")
                    cname_count += 1
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    logger.info(f"advanced_checks2 subdomain_takeover: {fqdn} - NXDOMAIN/no CNAME")
                    continue
                except Exception as e:
                    logger.info(f"advanced_checks2 subdomain_takeover: {fqdn} - DNS lookup failed - {type(e).__name__}: {e}")
                    continue

                logger.info(f"advanced_checks2 subdomain_takeover: {fqdn} -> CNAME {cname}")

                matched = None
                for service_name, (domain_suffix, fingerprint) in TAKEOVER_FINGERPRINTS.items():
                    if domain_suffix in cname.lower():
                        matched = (service_name, fingerprint)
                        break
                if not matched:
                    continue

                service_name, fingerprint = matched
                try:
                    resp = await client.get(f"http://{fqdn}/")
                except Exception as e:
                    logger.info(f"advanced_checks2 subdomain_takeover: {fqdn} - request to CNAME target failed - {type(e).__name__}: {e}")
                    continue

                if fingerprint in resp.text.lower():
                    logger.info(f"advanced_checks2 subdomain_takeover: {fqdn} -> CONFIRMED unclaimed {service_name} resource")

                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        title=f"Dangling DNS / possible subdomain takeover: {fqdn}",
                        description=(
                            f"{fqdn} has a CNAME pointing to {cname}, a {service_name} "
                            f"resource. The response body matches {service_name}'s "
                            f"'unclaimed resource' page, meaning this subdomain "
                            f"points at a third-party service resource that is not "
                            f"currently registered/claimed by anyone - an attacker "
                            f"could register it there and serve content under "
                            f"{fqdn}'s trusted name."
                        ),
                        asset=asset,
                        module_source=self.capabilities.module_id,
                        finding_kind=FindingKind.MISCONFIGURATION,
                        owasp_category="A05:2021-Security Misconfiguration",
                        cvss=CvssScore(base_score=8.1, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N"),
                        cwe=WeaknessRef(cwe_id="CWE-284", name="Improper Access Control"),
                        kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                        remediation=f"Remove the dangling CNAME record for {fqdn}, or (re)claim the {service_name} resource it points to.",
                        business_impact="A dangling subdomain can be claimed by an attacker to host phishing pages, steal cookies scoped to the parent domain, or bypass CSP/CORS allowlists that trust the parent domain.",
                    )
                    finding.add_evidence(Evidence.new(
                        evidence_type=EvidenceType.HTTP_TRANSACTION,
                        raw_bytes=f"{fqdn} CNAME {cname}\nGET http://{fqdn}/\nmatched_fingerprint: {fingerprint}".encode(),
                        storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/subdomain_takeover.txt",
                        description=f"CNAME record and fingerprint match confirming {fqdn} is an unclaimed {service_name} resource",
                        metadata={"preview": f"{fqdn} -> {cname} ({service_name}, unclaimed)"},
                    ))
                    yield finding
                else:
                    matched_count += 1
                    logger.info(f"advanced_checks2 subdomain_takeover: {fqdn} -> CNAME points to {service_name} but resource appears claimed")

        logger.info(f"advanced_checks2 subdomain_takeover: {asset.name} - done: "
                   f"{cname_count} subdomain(s) had a CNAME, {matched_count} matched a known third-party service and were checked for takeover")

    # -- Cookie / Session Security -------------------------------------------

    async def _check_cookie_security(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(base_url)
        except Exception as e:
            logger.info(f"advanced_checks2 cookie_security: request failed for {base_url} - {type(e).__name__}: {e}")
            return

        raw_cookies = resp.headers.get_list("set-cookie")
        if not raw_cookies:
            logger.info(f"advanced_checks2 cookie_security: {base_url} - no Set-Cookie headers present")
            return

        is_https = base_url.startswith("https")
        flag_issues: list[str] = []
        entropy_issues: list[str] = []

        for raw in raw_cookies:
            parts = [p.strip() for p in raw.split(";")]
            name = parts[0].split("=", 1)[0]
            value = parts[0].split("=", 1)[1] if "=" in parts[0] else ""
            attrs_lower = [p.lower() for p in parts[1:]]

            has_secure = any(a == "secure" for a in attrs_lower)
            has_httponly = any(a == "httponly" for a in attrs_lower)
            has_samesite = any(a.startswith("samesite") for a in attrs_lower)

            looks_sensitive = bool(re.search(r"(sess|sid|auth|token|jwt|login)", name, re.I))

            logger.info(f"advanced_checks2 cookie_security: {base_url} cookie='{name}' "
                       f"secure={has_secure} httponly={has_httponly} samesite={has_samesite} "
                       f"looks_sensitive={looks_sensitive}")

            if looks_sensitive or True:  # check flags on every cookie, note sensitivity in the text
                if is_https and not has_secure:
                    flag_issues.append(f"'{name}' missing Secure flag (site is HTTPS)")
                if not has_httponly:
                    flag_issues.append(f"'{name}' missing HttpOnly flag")
                if not has_samesite:
                    flag_issues.append(f"'{name}' missing SameSite attribute")

            if looks_sensitive and value:
                entropy = _shannon_entropy(value)
                logger.info(f"advanced_checks2 cookie_security: {base_url} cookie='{name}' "
                           f"value_len={len(value)} entropy_bits_per_char={entropy:.2f}")
                if len(value) < 16 or entropy < 2.5:
                    entropy_issues.append(
                        f"'{name}' looks like a session/auth token but has low entropy "
                        f"(length={len(value)}, ~{entropy:.2f} bits/char) - may be predictable"
                    )

        if flag_issues:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                title=f"Cookie security attribute issue(s) on {asset.name}",
                description="Cookies set without recommended security attributes: " + "; ".join(flag_issues) + ".",
                asset=asset,
                module_source=self.capabilities.module_id,
                finding_kind=FindingKind.MISCONFIGURATION,
                owasp_category="A05:2021-Security Misconfiguration",
                cvss=CvssScore(base_score=4.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
                cwe=WeaknessRef(cwe_id="CWE-614", name="Sensitive Cookie Without 'Secure' Attribute"),
                kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                remediation="Set Secure, HttpOnly, and SameSite=Lax/Strict on all session/auth cookies.",
                business_impact="Missing cookie flags increase exposure to session hijacking via XSS (missing HttpOnly), network interception (missing Secure), or CSRF (missing SameSite).",
            )
            finding.add_evidence(Evidence.new(
                evidence_type=EvidenceType.RESPONSE_HEADERS,
                raw_bytes=("\n".join(raw_cookies)).encode(),
                storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/cookie_flags.txt",
                description="Raw Set-Cookie headers observed",
                metadata={"preview": "; ".join(flag_issues)},
            ))
            yield finding

        if entropy_issues:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                title=f"Low-entropy session/auth token on {asset.name}",
                description="Session/auth-looking cookie value(s) with low randomness: " + "; ".join(entropy_issues) + ".",
                asset=asset,
                module_source=self.capabilities.module_id,
                finding_kind=FindingKind.VULNERABILITY,
                owasp_category="A02:2021-Cryptographic Failures",
                cvss=CvssScore(base_score=6.5, vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
                cwe=WeaknessRef(cwe_id="CWE-330", name="Use of Insufficiently Random Values"),
                kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                remediation="Generate session/auth tokens using a cryptographically secure random generator with at least 128 bits of entropy.",
                business_impact="A predictable session token can let an attacker guess or brute-force valid sessions without needing credentials.",
            )
            finding.add_evidence(Evidence.new(
                evidence_type=EvidenceType.RESPONSE_HEADERS,
                raw_bytes=("\n".join(raw_cookies)).encode(),
                storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/cookie_entropy.txt",
                description="Raw Set-Cookie headers used for entropy analysis",
                metadata={"preview": "; ".join(entropy_issues)},
            ))
            yield finding

        if not flag_issues and not entropy_issues:
            logger.info(f"advanced_checks2 cookie_security: {base_url} - no cookie security issues found")

    # -- GraphQL Introspection Exposure ---------------------------------------

    async def _check_graphql_introspection(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            for path in GRAPHQL_PATHS:
                url = f"{base_url}{path}"
                try:
                    resp = await client.post(url, json=INTROSPECTION_QUERY, headers={"Content-Type": "application/json"})
                except Exception as e:
                    logger.info(f"advanced_checks2 graphql: request failed for {url} - {type(e).__name__}: {e}")
                    continue

                if resp.status_code != 200:
                    logger.info(f"advanced_checks2 graphql: {url} -> status {resp.status_code}, not a live GraphQL endpoint")
                    continue

                try:
                    data = resp.json()
                except Exception:
                    logger.info(f"advanced_checks2 graphql: {url} -> non-JSON response, skipping")
                    continue

                schema = (data.get("data") or {}).get("__schema") if isinstance(data, dict) else None
                type_count = len(schema.get("types", [])) if schema else 0

                if schema and type_count:
                    logger.info(f"advanced_checks2 graphql: {url} -> CONFIRMED introspection enabled, {type_count} types exposed")

                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        title=f"GraphQL introspection enabled on {asset.name}",
                        description=(
                            f"A standard introspection query against {path} returned the "
                            f"full schema ({type_count} types), letting anyone enumerate "
                            f"every query, mutation, and type the API exposes without "
                            f"needing any documentation."
                        ),
                        asset=asset,
                        module_source=self.capabilities.module_id,
                        finding_kind=FindingKind.EXPOSURE,
                        owasp_category="A05:2021-Security Misconfiguration",
                        cvss=CvssScore(base_score=5.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                        cwe=WeaknessRef(cwe_id="CWE-200", name="Exposure of Sensitive Information to an Unauthorized Actor"),
                        kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                        remediation="Disable introspection in production, or gate it behind authentication.",
                        business_impact="A fully enumerable schema hands an attacker a complete map of the API's attack surface, including internal-only fields/mutations that were never meant to be discoverable.",
                    )
                    finding.add_evidence(Evidence.new(
                        evidence_type=EvidenceType.HTTP_TRANSACTION,
                        raw_bytes=f"POST {url}\nquery: {INTROSPECTION_QUERY['query']}\ntypes_returned: {type_count}".encode(),
                        storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/graphql_introspection.txt",
                        description="Introspection query response confirming schema exposure",
                        metadata={"preview": f"{path} -> {type_count} types exposed"},
                    ))
                    yield finding
                    return
                else:
                    logger.info(f"advanced_checks2 graphql: {url} -> introspection returned no schema (disabled, or not a GraphQL endpoint)")

    # -- WebSocket Auth Inspection --------------------------------------------

    async def _check_websocket_auth(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        import websockets

        ws_scheme = "wss" if base_url.startswith("https") else "ws"
        host_port = base_url.split("://", 1)[1]

        for path in WS_PATHS:
            url = f"{ws_scheme}://{host_port}{path}"
            try:
                async with websockets.connect(url, open_timeout=CONNECT_TIMEOUT, close_timeout=3):
                    logger.info(f"advanced_checks2 websocket: {url} -> handshake ACCEPTED with no auth header/token supplied")

                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        title=f"Unauthenticated WebSocket endpoint on {asset.name}",
                        description=(
                            f"A WebSocket handshake to {path} succeeded without any "
                            f"Authorization header, cookie, or token being supplied, "
                            f"suggesting this endpoint does not authenticate connections "
                            f"at the handshake level. No application data was sent after "
                            f"connecting - this only confirms the connection itself was "
                            f"accepted anonymously."
                        ),
                        asset=asset,
                        module_source=self.capabilities.module_id,
                        finding_kind=FindingKind.MISCONFIGURATION,
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        cvss=CvssScore(base_score=5.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                        cwe=WeaknessRef(cwe_id="CWE-306", name="Missing Authentication for Critical Function"),
                        kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                        remediation="Require an auth token/cookie to be validated during the WebSocket handshake (or immediately after, before accepting any messages).",
                        business_impact="An unauthenticated WebSocket endpoint may allow anyone to receive real-time data streams or send messages intended only for authenticated clients.",
                    )
                    finding.add_evidence(Evidence.new(
                        evidence_type=EvidenceType.HTTP_TRANSACTION,
                        raw_bytes=f"WS connect {url}\nauth_header_sent: none\nresult: handshake accepted".encode(),
                        storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/websocket_auth.txt",
                        description="Confirmation that the WebSocket handshake succeeded with no auth supplied",
                        metadata={"preview": f"{path} -> accepted with no auth"},
                    ))
                    yield finding
            except Exception as e:
                logger.info(f"advanced_checks2 websocket: {url} -> connection failed/rejected - {type(e).__name__}: {e}")
                continue

    # -- Supply Chain (outdated JS libraries) ---------------------------------

    async def _check_supply_chain_js(self, asset: Asset, ctx: ModuleRunContext,
                                      base_url: str, urls: list[str]) -> AsyncIterator[Finding]:
        checked: set[tuple[str, str]] = set()
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            for url in [base_url] + urls:
                try:
                    resp = await client.get(url)
                except Exception:
                    continue

                for lib_name, pattern, safe_version, desc in JS_LIBRARY_PATTERNS:
                    match = pattern.search(resp.text)
                    if not match:
                        continue
                    version_str = match.group(1)
                    key = (lib_name, version_str)
                    if key in checked:
                        continue
                    checked.add(key)

                    try:
                        version_tuple = _version_tuple(version_str)
                    except Exception:
                        continue

                    logger.info(f"advanced_checks2 supply_chain: found {lib_name} v{version_str} on {url}")

                    if version_tuple >= safe_version:
                        logger.info(f"advanced_checks2 supply_chain: {lib_name} v{version_str} is current enough, not flagging")
                        continue

                    logger.info(f"advanced_checks2 supply_chain: {lib_name} v{version_str} < "
                               f"{'.'.join(map(str, safe_version))} - OUTDATED")

                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        title=f"Outdated {lib_name} (v{version_str}) on {asset.name}",
                        description=f"{lib_name} version {version_str} was detected, which is older than {'.'.join(map(str, safe_version))}. {desc}",
                        asset=asset,
                        module_source=self.capabilities.module_id,
                        finding_kind=FindingKind.VULNERABILITY,
                        owasp_category="A06:2021-Vulnerable and Outdated Components",
                        cvss=CvssScore(base_score=5.4, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
                        cwe=WeaknessRef(cwe_id="CWE-1104", name="Use of Unmaintained Third Party Components"),
                        kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                        remediation=f"Upgrade {lib_name} to {'.'.join(map(str, safe_version))} or later.",
                        business_impact="Outdated front-end libraries with known CVEs give attackers documented, off-the-shelf exploitation techniques against the application.",
                    )
                    finding.add_evidence(Evidence.new(
                        evidence_type=EvidenceType.HTTP_TRANSACTION,
                        raw_bytes=f"GET {url}\nmatched: {lib_name} v{version_str}".encode(),
                        storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/supply_chain.txt",
                        description=f"Response excerpt showing {lib_name} v{version_str} reference",
                        metadata={"preview": f"{lib_name} v{version_str} found on {url}"},
                    ))
                    yield finding

    # -- SSRF Candidate Detection ---------------------------------------------

    async def _check_ssrf_candidates(self, asset: Asset, ctx: ModuleRunContext,
                                      base_url: str, urls: list[str]) -> AsyncIterator[Finding]:
        candidates: list[tuple[str, str]] = []
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query)
            for pname in params:
                if pname.lower() in SSRF_PARAM_NAMES:
                    candidates.append((parsed.path, pname))

        if not candidates:
            logger.info(f"advanced_checks2 ssrf: {base_url} - no URL-accepting parameters discovered, nothing to test")
            return

        internal_probe = "http://169.254.169.254/latest/meta-data/"
        control_probe = "http://h4ckbot-ssrf-control-nonexistent.invalid/"

        tested: set[str] = set()
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            for path, pname in candidates:
                if pname in tested:
                    continue
                tested.add(pname)

                t_internal = None
                t_control = None
                try:
                    t0 = time.monotonic()
                    await client.get(f"{base_url}{path}", params={pname: internal_probe})
                    t_internal = time.monotonic() - t0
                except Exception as e:
                    logger.info(f"advanced_checks2 ssrf: internal-range probe for '{pname}' errored - {type(e).__name__}: {e}")

                try:
                    t0 = time.monotonic()
                    await client.get(f"{base_url}{path}", params={pname: control_probe})
                    t_control = time.monotonic() - t0
                except Exception as e:
                    logger.info(f"advanced_checks2 ssrf: control probe for '{pname}' errored - {type(e).__name__}: {e}")

                logger.info(f"advanced_checks2 ssrf: param '{pname}' on {path} -> "
                           f"internal_probe_time={t_internal} control_probe_time={t_control}")

                if t_internal is None or t_control is None:
                    continue

                if t_internal > (t_control + 2.0):
                    logger.info(f"advanced_checks2 ssrf: CANDIDATE - significant timing differential for param '{pname}'")

                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        title=f"Possible SSRF candidate via '{pname}' parameter on {asset.name}",
                        description=(
                            f"Setting '{pname}' to a cloud-metadata-range URL took "
                            f"{t_internal:.2f}s to respond, versus {t_control:.2f}s for "
                            f"an unreachable control URL - a meaningful timing "
                            f"differential that suggests the server may be making an "
                            f"outbound request using this parameter. This is a "
                            f"CANDIDATE signal only: response content was never "
                            f"inspected or reported, and this does NOT confirm SSRF or "
                            f"any data exposure. Manual follow-up is required to confirm "
                            f"or rule this out."
                        ),
                        asset=asset,
                        module_source=self.capabilities.module_id,
                        finding_kind=FindingKind.VULNERABILITY,
                        owasp_category="A10:2021-Server-Side Request Forgery",
                        cvss=CvssScore(base_score=4.0, vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                        cwe=WeaknessRef(cwe_id="CWE-918", name="Server-Side Request Forgery (SSRF)"),
                        kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                        remediation="Manually verify whether this parameter triggers a server-side outbound request; if so, restrict it to an allowlist of destinations and block requests to link-local/metadata ranges.",
                        business_impact="If confirmed, SSRF can let an attacker pivot the server into making requests against internal-only services, including cloud metadata endpoints that expose credentials.",
                        status="needs_review",
                    )
                    finding.add_evidence(Evidence.new(
                        evidence_type=EvidenceType.HTTP_TRANSACTION,
                        raw_bytes=f"param={pname} path={path}\ninternal_probe_time={t_internal:.3f}s\ncontrol_probe_time={t_control:.3f}s".encode(),
                        storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/ssrf_timing.txt",
                        description="Timing differential between an internal-range probe and a control probe (response bodies never inspected)",
                        metadata={"preview": f"param={pname}: internal={t_internal:.2f}s control={t_control:.2f}s"},
                    ))
                    yield finding
                else:
                    logger.info(f"advanced_checks2 ssrf: no meaningful timing differential for param '{pname}', not flagging")
