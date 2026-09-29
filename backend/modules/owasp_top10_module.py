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

Two passes run per port:
  1. Generic root-path probing (COMMON_PARAMS on "/") - cheap, catches
     simple cases, kept as-is from the original version of this module.
  2. Crawl-and-form-discovery - fetches the homepage and a handful of
     same-origin pages, extracts real <form> elements (action, method,
     field names, whether a field is type="password"), and submits the
     same probes into the REAL field names via the form's REAL method
     and action, instead of guessing generic query params on the root
     path. This catches injection points a generic root-path probe
     structurally cannot reach (a login form's POST fields, a search
     form at a non-root path, etc).

Known limitation, stated plainly rather than hidden: this crawler only
parses the initial HTML response. It cannot see forms or links injected
by client-side JavaScript (a React/Next.js/Vue app that renders its
login form after page load, for example). That is a real gap for
modern SPA targets - closing it would require a headless-browser-based
crawl (we already have Playwright wired in for screenshots, so it's a
plausible future extension), not something this module currently does.

Logging: every probe and every crawl step logs its outcome at INFO
level (this app logs root at INFO - see api/main.py), including the
negative case, so a scan that produces zero findings in a category is
diagnosable from the server log instead of silent.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field as dataclass_field
from html.parser import HTMLParser
from typing import AsyncIterator
from urllib.parse import urljoin, urlparse

import httpx

from core.module_interface import ModuleCapabilities, ModuleRunContext, ScannerModule, OutOfScopeError
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding,
    FindingKind, KillChainPhase, WeaknessRef,
)

logger = logging.getLogger("h4ck-bot.owasp_top10")

CONNECT_TIMEOUT = 6.0
MAX_CRAWL_PAGES = 40

STATIC_EXTENSIONS = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".webm",
)

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

# Probe params to try injection/reflection against on the generic
# root-path pass. Real coverage of non-root-path forms comes from the
# crawl-and-form-discovery pass below.
COMMON_PARAMS = ["id", "q", "search", "query", "page", "category", "user"]

# server/framework -> (known-vulnerable version ceiling, CVE-style note).
# Minimal illustrative table - a real deployment should pull this from
# an actual CVE/NVD feed, not a hardcoded dict.
KNOWN_VULNERABLE_VERSIONS = {
    "apache": {"max_safe": "2.4.54", "note": "Apache HTTP Server versions before 2.4.54 have multiple known CVEs"},
    "nginx": {"max_safe": "1.24.0", "note": "nginx versions before 1.24.0 have known CVEs in some modules"},
    "php": {"max_safe": "8.1.0", "note": "PHP versions before 8.1 are past or nearing end-of-life with known CVEs"},
}


@dataclass
class DiscoveredForm:
    action: str
    method: str  # "get" or "post"
    fields: list[str] = dataclass_field(default_factory=list)
    has_password: bool = False
    source_page: str = ""


def _normalize_netloc(netloc: str) -> str:
    """
    Strip default ports (80 for http, 443 for https) so an explicitly-
    ported base URL like "testfire.net:80" compares equal to a link
    resolved against a response whose httpx-normalized URL dropped the
    default port ("testfire.net"). Without this, every same-origin link
    on a default-port site is wrongly treated as off-site and the crawl
    never advances past the first page.
    """
    if netloc.endswith(":80") or netloc.endswith(":443"):
        return netloc.rsplit(":", 1)[0]
    return netloc


class _PageParser(HTMLParser):
    """
    Minimal same-page extractor: links and forms, from the initial HTML
    response only - no JavaScript execution. This is a detection tool
    finding the SHAPE of forms and links on a page, not a browser.
    """

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[DiscoveredForm] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag, attrs):
        attrs_d = {k: v for k, v in attrs if v is not None}
        tag_lower = tag.lower()

        if tag_lower == "a" and attrs_d.get("href"):
            try:
                self.links.append(urljoin(self.base_url, attrs_d["href"]))
            except Exception:
                pass

        elif tag_lower == "form":
            action_raw = attrs_d.get("action") or self.base_url
            try:
                action = urljoin(self.base_url, action_raw)
            except Exception:
                action = self.base_url
            method = (attrs_d.get("method") or "get").lower()
            if method not in ("get", "post"):
                method = "get"
            self._current_form = {"action": action, "method": method, "fields": [], "has_password": False}

        elif tag_lower in ("input", "textarea", "select") and self._current_form is not None:
            name = attrs_d.get("name")
            if name and name not in self._current_form["fields"]:
                self._current_form["fields"].append(name)
            if tag_lower == "input" and (attrs_d.get("type") or "").lower() == "password":
                self._current_form["has_password"] = True

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(DiscoveredForm(
                action=self._current_form["action"],
                method=self._current_form["method"],
                fields=self._current_form["fields"],
                has_password=self._current_form["has_password"],
                source_page=self.base_url,
            ))
            self._current_form = None


def _filler_value(field_name: str) -> str:
    """A plausible, harmless value for a form field we are NOT injecting
    into this request, so the submission looks realistic instead of
    tripping basic required-field validation."""
    name = field_name.lower()
    if "email" in name:
        return "test@example.com"
    if "pass" in name:
        return "x"
    if "phone" in name or "tel" in name:
        return "5555555555"
    return "test"


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
                    logger.info(f"owasp_top10: {base_url} not reachable - skipping all checks for this port")
                    continue

                logger.info(f"owasp_top10: {base_url} reachable - running checks")

                # -- Pass 1: generic root-path probing (cheap, original coverage) --
                async for finding in self._check_injection(asset, ctx, base_url):
                    yield finding

                async for finding in self._check_reflected_xss(asset, ctx, base_url):
                    yield finding

                finding = await self._check_vulnerable_components(asset, ctx, base_url)
                if finding is not None:
                    yield finding

                # -- Pass 2: crawl and test real discovered forms --
                forms = await self._crawl_forms(base_url)

                async for finding in self._check_form_injection(asset, ctx, forms):
                    yield finding

                login_forms = [f for f in forms if f.has_password]
                if login_forms:
                    async for finding in self._check_login_form_enumeration(asset, ctx, login_forms[0]):
                        yield finding
                else:
                    logger.info(f"owasp_top10: {base_url} - crawl found no form with a password field, "
                               f"falling back to hardcoded login-path guesses")
                    async for finding in self._check_username_enumeration(asset, ctx, base_url):
                        yield finding

    async def _is_reachable(self, base_url: str) -> bool:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                await client.get(base_url)
            return True
        except Exception as e:
            logger.info(f"owasp_top10: reachability check failed for {base_url} - {type(e).__name__}: {e}")
            return False

    # -- Crawl: discover links and forms from the initial HTML only -----------

    async def _crawl_forms(self, base_url: str) -> list[DiscoveredForm]:
        visited: set[str] = set()
        to_visit = [base_url]
        all_forms: list[DiscoveredForm] = []
        base_host = _normalize_netloc(urlparse(base_url).netloc)

        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            while to_visit and len(visited) < MAX_CRAWL_PAGES:
                url = to_visit.pop(0)
                if url in visited:
                    continue
                visited.add(url)

                try:
                    resp = await client.get(url)
                except Exception as e:
                    logger.info(f"owasp_top10 crawl: failed to fetch {url} - {type(e).__name__}: {e}")
                    continue

                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type:
                    logger.info(f"owasp_top10 crawl: {url} -> content-type '{content_type}', skipping (not HTML)")
                    continue

                parser = _PageParser(str(resp.url))
                try:
                    parser.feed(resp.text)
                except Exception as e:
                    logger.info(f"owasp_top10 crawl: HTML parse error on {url} - {type(e).__name__}: {e}")
                    continue

                for form in parser.forms:
                    sig = (form.action, form.method, tuple(form.fields))
                    already_have = any(
                        (f.action, f.method, tuple(f.fields)) == sig for f in all_forms
                    )
                    if not already_have:
                        all_forms.append(form)
                        logger.info(f"owasp_top10 crawl: found form on {url} -> "
                                   f"action={form.action} method={form.method.upper()} "
                                   f"fields={form.fields} has_password={form.has_password}")

                for link in parser.links:
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

        logger.info(f"owasp_top10 crawl: {base_url} -> visited {len(visited)} page(s), "
                   f"discovered {len(all_forms)} unique form(s)")
        return all_forms

    async def _submit_form(self, client: httpx.AsyncClient, form: DiscoveredForm,
                            field_under_test: str, probe_value: str) -> httpx.Response:
        data = {
            f: (probe_value if f == field_under_test else _filler_value(f))
            for f in form.fields
        }
        if form.method == "post":
            return await client.post(form.action, data=data)
        return await client.get(form.action, params=data)

    # -- A03: Injection, against REAL discovered forms -------------------------

    async def _check_form_injection(self, asset: Asset, ctx: ModuleRunContext,
                                     forms: list[DiscoveredForm]) -> AsyncIterator[Finding]:
        if not forms:
            logger.info("owasp_top10 form-injection: no forms discovered by the crawl, nothing to test")
            return

        marker = f"h4ckbot_{uuid.uuid4().hex[:8]}"
        xss_probe = f"<{marker}>"
        sqli_probe = "'"

        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            for form in forms:
                testable_fields = [f for f in form.fields if "pass" not in f.lower()]
                if not testable_fields:
                    logger.info(f"owasp_top10 form-injection: form at {form.action} has no non-password "
                               f"fields to test - skipping")
                    continue

                for target_field in testable_fields:
                    # SQLi probe
                    try:
                        resp = await self._submit_form(client, form, target_field, sqli_probe)
                    except Exception as e:
                        logger.info(f"owasp_top10 form-injection sqli: request failed - "
                                   f"{form.method.upper()} {form.action} field='{target_field}' - "
                                   f"{type(e).__name__}: {e}")
                    else:
                        body_lower = resp.text.lower()
                        matched_engine = next(
                            (eng for sig, eng in SQLI_ERROR_SIGNATURES.items() if sig in body_lower), None
                        )
                        if matched_engine is None:
                            logger.info(f"owasp_top10 form-injection sqli: {form.method.upper()} {form.action} "
                                       f"field='{target_field}' -> status {resp.status_code}, no signature match")
                        else:
                            logger.info(f"owasp_top10 form-injection sqli: {form.method.upper()} {form.action} "
                                       f"field='{target_field}' -> matched {matched_engine}")
                            finding = Finding(
                                finding_id=str(uuid.uuid4()),
                                title=f"Possible SQL injection via '{target_field}' field on form at {form.action}",
                                description=(
                                    f"A single-quote probe submitted into the '{target_field}' field of a "
                                    f"real {form.method.upper()} form discovered by crawling {asset.name} "
                                    f"triggered a {matched_engine} database error in the response, suggesting "
                                    f"unsanitized input reaches a SQL query. This is a detection signal, not "
                                    f"confirmed exploitation - no data was extracted."
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
                                raw_bytes=(
                                    f"{form.method.upper()} {form.action}\nfield: {target_field}\n"
                                    f"status: {resp.status_code}\nmatched_engine: {matched_engine}\n"
                                    f"body_excerpt: {resp.text[:400]}"
                                ).encode(),
                                storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/form_sqli_probe.txt",
                                description=f"Response from discovered form showing a {matched_engine} error signature",
                                metadata={"preview": f"{form.method.upper()} {form.action} field={target_field} status={resp.status_code}"},
                            ))
                            yield finding

                    # XSS probe
                    try:
                        resp2 = await self._submit_form(client, form, target_field, xss_probe)
                    except Exception as e:
                        logger.info(f"owasp_top10 form-injection xss: request failed - "
                                   f"{form.method.upper()} {form.action} field='{target_field}' - "
                                   f"{type(e).__name__}: {e}")
                        continue

                    if xss_probe not in resp2.text:
                        logger.info(f"owasp_top10 form-injection xss: {form.method.upper()} {form.action} "
                                   f"field='{target_field}' -> status {resp2.status_code}, marker not reflected")
                        continue

                    logger.info(f"owasp_top10 form-injection xss: {form.method.upper()} {form.action} "
                               f"field='{target_field}' -> marker reflected unescaped")
                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        title=f"Possible reflected XSS via '{target_field}' field on form at {form.action}",
                        description=(
                            f"An inert HTML-like marker submitted into the '{target_field}' field of a real "
                            f"{form.method.upper()} form discovered by crawling {asset.name} was reflected "
                            f"back unescaped in the response body. This is a detection signal - no script "
                            f"execution was attempted or confirmed."
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
                        raw_bytes=(
                            f"{form.method.upper()} {form.action}\nfield: {target_field}\n"
                            f"status: {resp2.status_code}\nmarker_reflected_unescaped: true\n"
                            f"body_excerpt: {resp2.text[:400]}"
                        ).encode(),
                        storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/form_xss_probe.txt",
                        description="Response from discovered form showing the unescaped marker reflected",
                        metadata={"preview": f"{form.method.upper()} {form.action} field={target_field} status={resp2.status_code}"},
                    ))
                    yield finding

    # -- A07: enumeration against a REAL discovered login form -----------------

    async def _check_login_form_enumeration(self, asset: Asset, ctx: ModuleRunContext,
                                             form: DiscoveredForm) -> AsyncIterator[Finding]:
        password_field = next((f for f in form.fields if "pass" in f.lower()), None)
        if password_field is None:
            logger.info(f"owasp_top10 enum: form at {form.action} flagged has_password but no "
                       f"password-like field name found - skipping")
            return

        identity_field = next(
            (f for f in form.fields
             if f != password_field and any(k in f.lower() for k in ("user", "email", "login", "uid", "name"))),
            None,
        )
        if identity_field is None:
            identity_field = next((f for f in form.fields if f != password_field), None)
        if identity_field is None:
            logger.info(f"owasp_top10 enum: login form at {form.action} has no identifiable username field "
                       f"besides '{password_field}' - skipping")
            return

        logger.info(f"owasp_top10 enum: testing discovered login form at {form.action} "
                   f"(method={form.method.upper()}, identity_field='{identity_field}', password_field='{password_field}')")

        def build(username_value: str) -> dict:
            data = {f: _filler_value(f) for f in form.fields}
            data[identity_field] = username_value
            data[password_field] = "x"
            return data

        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            try:
                if form.method == "post":
                    baseline_1 = await client.post(form.action, data=build("h4ckbot_probe_a"))
                    baseline_2 = await client.post(form.action, data=build("h4ckbot_probe_a"))
                    resp_b = await client.post(form.action, data=build("h4ckbot_probe_b"))
                else:
                    baseline_1 = await client.get(form.action, params=build("h4ckbot_probe_a"))
                    baseline_2 = await client.get(form.action, params=build("h4ckbot_probe_a"))
                    resp_b = await client.get(form.action, params=build("h4ckbot_probe_b"))
            except Exception as e:
                logger.info(f"owasp_top10 enum: probe request failed against {form.action} - {type(e).__name__}: {e}")
                return

            resp_a = baseline_1
            baseline_len_diff = abs(len(baseline_1.text) - len(baseline_2.text))
            cross_len_diff = abs(len(resp_a.text) - len(resp_b.text))

            logger.info(f"owasp_top10 enum: {form.action} -> baseline (same identity twice) "
                       f"len_diff={baseline_len_diff}; cross (different identities) "
                       f"status_a={resp_a.status_code} len_a={len(resp_a.text)}, "
                       f"status_b={resp_b.status_code} len_b={len(resp_b.text)}, "
                       f"cross_len_diff={cross_len_diff}")

            if baseline_1.status_code == baseline_2.status_code == resp_b.status_code:
                noise_floor = max(baseline_len_diff, 10)
                if cross_len_diff <= noise_floor:
                    logger.info(f"owasp_top10 enum: {form.action} - cross-identity diff "
                               f"({cross_len_diff} bytes) is within baseline noise "
                               f"({baseline_len_diff} bytes) - not reporting, avoided a likely false positive")
                    return

            logger.info(f"owasp_top10 enum: {form.action} - difference exceeds baseline noise - reporting")

            finding = Finding(
                finding_id=str(uuid.uuid4()),
                title=f"Possible username enumeration on discovered login form at {form.action}",
                description=(
                    f"Two different, fabricated values in the '{identity_field}' field of a real login "
                    f"form discovered by crawling {asset.name} produced different response status codes "
                    f"or bodies (beyond same-value baseline noise), which can let an attacker distinguish "
                    f"valid from invalid identities without knowing any real credentials."
                ),
                asset=asset,
                module_source=self.capabilities.module_id,
                finding_kind=FindingKind.VULNERABILITY,
                owasp_category="A07:2021-Identification and Authentication Failures",
                cvss=CvssScore(base_score=5.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                cwe=WeaknessRef(cwe_id="CWE-204", name="Observable Response Discrepancy"),
                kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                remediation="Return an identical, generic error message and response time regardless of whether the submitted identity exists.",
                business_impact="Enables username enumeration, which narrows the search space for credential-stuffing or password-spray attacks.",
            )
            finding.add_evidence(Evidence.new(
                evidence_type=EvidenceType.BEHAVIORAL_DIFF,
                raw_bytes=(
                    f"form: {form.method.upper()} {form.action}\n"
                    f"identity_field={identity_field} password_field={password_field}\n"
                    f"baseline (same identity twice): len_diff={baseline_len_diff}\n"
                    f"probe_a status={resp_a.status_code} len={len(resp_a.text)}\n"
                    f"probe_b status={resp_b.status_code} len={len(resp_b.text)}\n"
                    f"cross_len_diff={cross_len_diff}"
                ).encode(),
                storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/form_enum_diff.txt",
                description="Response comparison between two fabricated identities on a discovered login form, with a same-identity baseline",
                metadata={"preview": f"form={form.action}; baseline_len_diff={baseline_len_diff}; cross_len_diff={cross_len_diff}"},
            ))
            yield finding

    # -- A03: Injection (generic root-path probing - original coverage) -------

    async def _check_injection(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        probe = "'"
        matched_any = False
        request_errors = 0
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            for param in COMMON_PARAMS:
                url = f"{base_url}/?{param}={probe}"
                try:
                    resp = await client.get(url)
                except Exception as e:
                    request_errors += 1
                    logger.info(f"owasp_top10 sqli: request failed for {url} - {type(e).__name__}: {e}")
                    continue

                body_lower = resp.text.lower()
                matched_engine = None
                for sig, engine in SQLI_ERROR_SIGNATURES.items():
                    if sig in body_lower:
                        matched_engine = engine
                        break

                if matched_engine is None:
                    logger.info(f"owasp_top10 sqli: param '{param}' -> status {resp.status_code}, "
                               f"no known DB error signature in {len(resp.text)}-byte body")
                    continue

                matched_any = True
                logger.info(f"owasp_top10 sqli: param '{param}' -> matched {matched_engine} error signature")

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

        if not matched_any:
            logger.info(f"owasp_top10 sqli: {base_url} - no signature match across "
                       f"{len(COMMON_PARAMS)} param(s), {request_errors} request error(s) - "
                       f"true negative or the app doesn't surface raw DB errors")

    # -- A03: Injection (generic root-path reflected XSS - original coverage) --

    async def _check_reflected_xss(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        marker = f"h4ckbot_{uuid.uuid4().hex[:8]}"
        probe = f"<{marker}>"
        reflected_any = False
        request_errors = 0
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            for param in COMMON_PARAMS:
                url = f"{base_url}/?{param}={probe}"
                try:
                    resp = await client.get(url)
                except Exception as e:
                    request_errors += 1
                    logger.info(f"owasp_top10 xss: request failed for {url} - {type(e).__name__}: {e}")
                    continue

                if probe not in resp.text:
                    logger.info(f"owasp_top10 xss: param '{param}' -> status {resp.status_code}, "
                               f"marker not reflected unescaped in {len(resp.text)}-byte body")
                    continue

                reflected_any = True
                logger.info(f"owasp_top10 xss: param '{param}' -> marker reflected unescaped")

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

        if not reflected_any:
            logger.info(f"owasp_top10 xss: {base_url} - marker never reflected unescaped across "
                       f"{len(COMMON_PARAMS)} param(s), {request_errors} request error(s) - "
                       f"true negative or params aren't actually rendered into the page")

    # -- A06: Vulnerable and Outdated Components -----------------------------

    async def _check_vulnerable_components(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> Finding | None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(base_url)
        except Exception as e:
            logger.info(f"owasp_top10 components: request failed for {base_url} - {type(e).__name__}: {e}")
            return None

        server_header = resp.headers.get("server", "")
        x_powered_by = resp.headers.get("x-powered-by", "")
        combined = f"{server_header} {x_powered_by}".lower()

        logger.info(f"owasp_top10 components: {base_url} -> Server='{server_header}' "
                   f"X-Powered-By='{x_powered_by}'")

        if not combined.strip():
            logger.info(f"owasp_top10 components: {base_url} - no Server/X-Powered-By header at all, "
                       f"nothing to fingerprint against (app may suppress version headers - a good sign)")
            return None

        for product, info in KNOWN_VULNERABLE_VERSIONS.items():
            match = re.search(rf"{product}[/\s]([\d.]+)", combined)
            if not match:
                continue
            version_str = match.group(1)
            if self._version_lt(version_str, info["max_safe"]):
                logger.info(f"owasp_top10 components: matched {product} {version_str} "
                           f"(< safe floor {info['max_safe']})")
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

        logger.info(f"owasp_top10 components: {base_url} - headers present but no product/version "
                   f"in {list(KNOWN_VULNERABLE_VERSIONS.keys())} matched the regex, or version was "
                   f"newer than the known-safe floor")
        return None

    @staticmethod
    def _version_lt(a: str, b: str) -> bool:
        def parts(v: str) -> list[int]:
            return [int(x) for x in re.findall(r"\d+", v)]
        pa, pb = parts(a), parts(b)
        return pa < pb

    # -- A07: fallback hardcoded-path enumeration (used only if the crawl -----
    # -- found no password-bearing form) --------------------------------------

    async def _check_username_enumeration(self, asset: Asset, ctx: ModuleRunContext, base_url: str) -> AsyncIterator[Finding]:
        login_paths = ["/login", "/signin", "/user/login", "/account/login"]
        async with httpx.AsyncClient(verify=False, timeout=CONNECT_TIMEOUT, follow_redirects=True) as client:
            login_url = None
            for path in login_paths:
                try:
                    resp = await client.get(base_url + path)
                except Exception as e:
                    logger.info(f"owasp_top10 enum: request failed for {base_url + path} - {type(e).__name__}: {e}")
                    continue
                if resp.status_code == 200 and "password" in resp.text.lower():
                    login_url = base_url + path
                    logger.info(f"owasp_top10 enum: login page found at {login_url}")
                    break
                else:
                    logger.info(f"owasp_top10 enum: {base_url + path} -> status {resp.status_code}, "
                               f"'password' {'found' if 'password' in resp.text.lower() else 'not found'} in body")
            if login_url is None:
                logger.info(f"owasp_top10 enum: {base_url} - no login page found among "
                           f"{login_paths} either - giving up on enumeration for this port")
                return

            try:
                baseline_1 = await client.post(login_url, data={"username": "h4ckbot_probe_a", "password": "x"})
                baseline_2 = await client.post(login_url, data={"username": "h4ckbot_probe_a", "password": "x"})
                resp_b = await client.post(login_url, data={"username": "h4ckbot_probe_b", "password": "x"})
            except Exception as e:
                logger.info(f"owasp_top10 enum: probe POST failed against {login_url} - {type(e).__name__}: {e}")
                return

            resp_a = baseline_1
            baseline_len_diff = abs(len(baseline_1.text) - len(baseline_2.text))
            cross_len_diff = abs(len(resp_a.text) - len(resp_b.text))

            logger.info(f"owasp_top10 enum: {login_url} -> baseline (same username twice) "
                       f"len_diff={baseline_len_diff}; cross (different usernames) "
                       f"status_a={resp_a.status_code} len_a={len(resp_a.text)}, "
                       f"status_b={resp_b.status_code} len_b={len(resp_b.text)}, "
                       f"cross_len_diff={cross_len_diff}")

            if baseline_1.status_code == baseline_2.status_code == resp_b.status_code:
                noise_floor = max(baseline_len_diff, 10)
                if cross_len_diff <= noise_floor:
                    logger.info(f"owasp_top10 enum: {login_url} - cross-username diff "
                               f"({cross_len_diff} bytes) is within same-username baseline "
                               f"noise ({baseline_len_diff} bytes) - not reporting, "
                               f"avoided a likely false positive from dynamic page content")
                    return

            logger.info(f"owasp_top10 enum: {login_url} - difference exceeds baseline noise - reporting enumeration finding")

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
                    f"baseline (same username 'h4ckbot_probe_a' twice): len_diff={baseline_len_diff}\n"
                    f"probe_a status={resp_a.status_code} len={len(resp_a.text)}\n"
                    f"probe_b status={resp_b.status_code} len={len(resp_b.text)}\n"
                    f"cross_len_diff={cross_len_diff}"
                ).encode(),
                storage_ref=f"evidence/{ctx.assessment_id}/{finding.finding_id}/enum_diff.txt",
                description="Response comparison between two fabricated usernames, with a same-username baseline to rule out dynamic-content noise",
                metadata={"preview": f"baseline_len_diff={baseline_len_diff}; probe_a status={resp_a.status_code} len={len(resp_a.text)}; probe_b status={resp_b.status_code} len={len(resp_b.text)}"},
            ))
            yield finding
