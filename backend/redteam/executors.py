"""
Red-team executors — the safe checks that confirm or refute a hypothesis.

Phase 1b shipped the first real executor (IDOR/BOLA). Phase 1d adds the two
input-level ones - reflected XSS and SQL injection - so the red-team loop can
CONFIRM web findings itself, each producing two independent evidence types.
Everything here is bounded by hard safety rules, because this is the part that
actually touches a target:

  - GET only. No writes, no destructive methods, ever.
  - In-scope only. The target host must be authorized by the RoE.
  - Bounded + paced. A small, capped number of probes with a delay between
    them — never an enumeration flood.
  - Evidence in, verdict out as POTENTIAL. The executor never self-certifies a
    finding; it collects evidence and hands a POTENTIAL finding to the existing
    validation pipeline, which decides.

The HTTP layer is injected (a `Fetcher`), so the detection logic is unit-tested
offline with crafted responses — no live target needed to prove correctness.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional, Protocol
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from core.rules_of_engagement import RulesOfEngagement
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding, FindingKind,
    KillChainPhase, MitreTechnique, WeaknessRef,
)
from redteam.types import Hypothesis, HypothesisKind

logger = logging.getLogger("h4ck-bot.redteam.exec")


@dataclass
class FetchResult:
    url: str
    status: int
    text: str = ""
    headers: dict = field(default_factory=dict)

    def json(self) -> Optional[dict]:
        try:
            v = json.loads(self.text)
            return v if isinstance(v, dict) else None
        except Exception:
            return None


# A Fetcher performs ONE safe GET and returns a FetchResult. Injected so tests
# can supply crafted responses and production supplies a real httpx client.
Fetcher = Callable[[str], Awaitable[FetchResult]]
# A Poster performs ONE body POST (url, body, content_type) -> FetchResult.
# Injected like Fetcher; only the XXE executor needs it, and only for an inert,
# detection-only XML payload. None when posting isn't wired.
Poster = Callable[[str, bytes, str], Awaitable[FetchResult]]


class Executor(Protocol):
    async def execute(self, hyp: Hypothesis, ctx: "ExecContext") -> list[Finding]: ...


@dataclass
class ExecContext:
    target_host: str
    roe: RulesOfEngagement
    fetch: Fetcher
    # object ids to probe for IDOR/BOLA (from recon/known objects); kept small.
    candidate_ids: list[str] = field(default_factory=lambda: ["1", "2", "3"])
    owner_field: str = ""          # from the semantic model, if known
    max_probes: int = 5
    pace_seconds: float = 0.3
    base_url: str = ""             # e.g. "https://host"
    oob_base_url: str = ""         # public callback base for OOB detection (SSRF/XXE)
    post: "Optional[Poster]" = None  # body POST, for XXE's inert XML detection payload


# Parameter names that commonly carry a URL/host the server fetches — the
# candidates for SSRF. Used by the SSRF hypothesis and the OOB executor.
URL_PARAM_HINTS = {
    "url", "uri", "link", "next", "redirect", "redirect_url", "redirecturl",
    "dest", "destination", "continue", "return", "returnurl", "return_url",
    "callback", "webhook", "image", "imageurl", "img", "src", "source", "feed",
    "host", "domain", "site", "page", "path", "file", "fileurl", "load",
    "fetch", "proxy", "open", "to", "out", "view", "data", "u", "q", "target",
}


def _fill_id(path_template: str, oid: str) -> str:
    """Substitute an object id into an endpoint template: /x/{id} or /x/:id."""
    import re
    if "{" in path_template:
        return re.sub(r"\{[^}]+\}", oid, path_template, count=1)
    if "/:" in path_template:
        return re.sub(r"/:\w+", "/" + oid, path_template, count=1)
    # path ending in a numeric segment -> swap it
    if re.search(r"/\d+/?$", path_template):
        return re.sub(r"/\d+(/?)$", "/" + oid + r"\1", path_template)
    # otherwise append as a path id
    return path_template.rstrip("/") + "/" + oid


def _with_param(base: str, path: str, param: str, value: str) -> str:
    """Build a GET URL for `path` under `base` with `param` set to `value`,
    preserving any other query params already on the path. Used by the
    input-level executors (injection/XSS) to place one inert probe value."""
    full = base.rstrip("/") + "/" + path.lstrip("/")
    parts = urlsplit(full)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _snippet(body: str, needle: str, pad: int = 60) -> str:
    """A short window of `body` around the first occurrence of `needle`, for
    evidence previews - never the whole response."""
    i = body.find(needle)
    if i < 0:
        return body[:120]
    start = max(0, i - pad)
    end = min(len(body), i + len(needle) + pad)
    return ("..." if start else "") + body[start:end] + ("..." if end < len(body) else "")


class BolaExecutor:
    """Horizontal object-access (IDOR/BOLA) check.

    For an instance-scoped endpoint, request several distinct object ids with
    the SAME (or no) identity. If multiple ids each return a 200 carrying a
    distinct object — and, when known, distinct owner-field values — then the
    endpoint is not scoping objects to the caller: a classic IDOR/BOLA. If the
    other ids return 401/403/404, there is no finding.
    """

    handles = {HypothesisKind.BOLA, HypothesisKind.IDOR}

    async def execute(self, hyp: Hypothesis, ctx: ExecContext) -> list[Finding]:
        # Safety gate: never touch a host the RoE didn't authorize.
        if not ctx.roe.target_authorized(ctx.target_host):
            logger.warning("bola: %s not authorized by RoE - skipping", ctx.target_host)
            return []

        findings: list[Finding] = []
        base = ctx.base_url or f"https://{ctx.target_host}"

        for template in hyp.target_endpoints:
            probes: list[FetchResult] = []
            for oid in ctx.candidate_ids[: ctx.max_probes]:
                url = base.rstrip("/") + _fill_id(template, oid)
                try:
                    res = await ctx.fetch(url)          # GET only (the Fetcher enforces it)
                except Exception as e:                   # noqa: BLE001
                    logger.info("bola: fetch failed %s: %s", url, e)
                    continue
                probes.append(res)
                await asyncio.sleep(ctx.pace_seconds)    # paced, never a flood

            finding = self._evaluate(hyp, template, base, probes, ctx)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate(self, hyp, template, base, probes, ctx) -> Optional[Finding]:
        ok = [p for p in probes if p.status == 200 and p.text.strip()]
        if len(ok) < 2:
            return None  # need >=2 distinct objects readable to claim horizontal access

        # Distinct bodies, and (if we know the owner field) distinct owners.
        bodies = {p.text.strip() for p in ok}
        owners = set()
        if ctx.owner_field:
            for p in ok:
                j = p.json() or {}
                if ctx.owner_field in j:
                    owners.add(str(j[ctx.owner_field]))
        distinct_objects = len(bodies) >= 2
        distinct_owners = len(owners) >= 2
        if not distinct_objects:
            return None

        asset = Asset(asset_id="a0", name=ctx.target_host, asset_type="api",
                      scope_approved=True, metadata={"exposure": "internet"})
        # Confidence/severity nudge when owner fields prove cross-tenant access.
        base_score = 8.1 if distinct_owners else 6.5
        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Possible IDOR/BOLA on {template}",
            description=(
                f"{len(ok)} distinct object ids returned 200 with distinct content on "
                f"{template} using a single (or no) identity"
                + (f"; the owner field '{ctx.owner_field}' differed across responses "
                   f"({sorted(owners)[:3]}), indicating cross-owner access"
                   if distinct_owners else "")
                + ". The endpoint does not appear to scope objects to the caller. "
                "Checked read-only (GET); no modification attempted."
            ),
            asset=asset,
            module_source="bola_executor",
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(base_score=base_score,
                           vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
            cwe=WeaknessRef(cwe_id="CWE-639",
                            name="Authorization Bypass Through User-Controlled Key"),
            mitre_techniques=[MitreTechnique(technique_id="T1190", tactic="initial-access",
                                             name="Exploit Public-Facing Application")],
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            remediation=(
                "Enforce per-object authorization server-side: verify the authenticated "
                "principal owns (or may access) the requested object before returning it. "
                "Do not rely on unguessable ids."
            ),
            business_impact="An attacker could read other users'/tenants' records by changing the object id.",
        )
        # Evidence, type 1: the raw probe transactions.
        for p in ok[:4]:
            preview = f"GET {p.url}\nstatus: {p.status}\nbody: {p.text[:200]}"
            finding.add_evidence(Evidence.new(
                evidence_type=EvidenceType.HTTP_TRANSACTION,
                raw_bytes=preview.encode(),
                storage_ref=f"mem://bola/{uuid.uuid4().hex[:8]}",
                description=f"IDOR probe response for {p.url}",
                metadata={"preview": preview},
            ))
        # Evidence, type 2: the behavioral difference across object ids under one
        # identity. A distinct, independent evidence TYPE (not another HTTP log),
        # so evidence-correlation has two real signals to weigh for a confirmed
        # finding - the raw transactions AND the cross-object behavior they show.
        diff_lines = [f"  id-probe {p.url} -> {p.status}, body[:60]={p.text[:60]!r}" for p in ok[:4]]
        diff = (
            "Horizontal access behavior - one (or no) identity, distinct object ids:\n"
            + "\n".join(diff_lines)
            + (f"\nowner field '{ctx.owner_field}' differed across responses: {sorted(owners)[:4]}"
               if distinct_owners else "\n(no owner field known; distinct bodies observed)")
        )
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.BEHAVIORAL_DIFF,
            raw_bytes=diff.encode(),
            storage_ref=f"mem://bola-diff/{uuid.uuid4().hex[:8]}",
            description="Cross-object access behavior under a single identity",
            metadata={"preview": diff},
        ))
        logger.info("bola: potential finding on %s (%d readable ids, distinct_owners=%s)",
                    template, len(ok), distinct_owners)
        return finding


class XssReflectionExecutor:
    """Reflected-XSS confirmation (CWE-79).

    For each recon-observed parameter on an HTML endpoint, submit an INERT,
    unique, angle-bracketed marker - an unknown tag like `<h4ckb0t9f1c>`, which
    no browser executes - and compare the response to a bracket-free baseline.
    If the marker comes back with its `<` and `>` UNESCAPED, attacker-controlled
    markup reaches the HTML sink: the reflected-XSS condition, demonstrated
    without ever submitting a script or an event handler. If it is reflected
    only encoded (`&lt;...&gt;`) or not reflected, there is no finding - the
    input is being sanitized.

    Two independent evidence TYPES are attached (the transaction showing the
    unescaped reflection, and the baseline-vs-probe behavioral diff), so a
    confirmed vector satisfies evidence-correlation honestly.
    """

    handles = {HypothesisKind.XSS}

    async def execute(self, hyp: Hypothesis, ctx: "ExecContext") -> list[Finding]:
        if not ctx.roe.target_authorized(ctx.target_host):
            logger.warning("xss: %s not authorized by RoE - skipping", ctx.target_host)
            return []

        base = ctx.base_url or f"https://{ctx.target_host}"
        findings: list[Finding] = []
        probed = 0
        for path in hyp.target_endpoints:
            for param in hyp.target_params:
                if probed >= ctx.max_probes:
                    break
                token = "h4ckb0t" + uuid.uuid4().hex[:8]
                raw_marker = f"<{token}>"            # inert unknown tag, never executes
                enc_marker = f"&lt;{token}&gt;"
                probe_url = _with_param(base, path, param, token + raw_marker)
                baseline_url = _with_param(base, path, param, token)   # same token, no brackets
                try:
                    baseline = await ctx.fetch(baseline_url)
                    await asyncio.sleep(ctx.pace_seconds)
                    probe = await ctx.fetch(probe_url)
                except Exception as e:  # noqa: BLE001
                    logger.info("xss: fetch failed %s: %s", probe_url, e)
                    continue
                probed += 1
                await asyncio.sleep(ctx.pace_seconds)
                f = self._evaluate(path, param, raw_marker, enc_marker, baseline, probe, ctx)
                if f is not None:
                    findings.append(f)
        return findings

    def _evaluate(self, path, param, raw_marker, enc_marker, baseline, probe, ctx) -> Optional[Finding]:
        body = probe.text or ""
        if raw_marker not in body:
            # Not reflected, or reflected only encoded/sanitized -> no XSS vector.
            return None

        asset = Asset(asset_id="a0", name=ctx.target_host, asset_type="web",
                      scope_approved=True, metadata={"exposure": "internet"})
        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Reflected XSS via '{param}' on {path}",
            description=(
                f"Parameter '{param}' on {path} is reflected into the HTML response with its "
                f"'<' and '>' unescaped (inert marker {raw_marker} returned verbatim). "
                "Attacker-controlled markup reaches the page sink, the reflected-XSS condition. "
                "Confirmed read-only (GET) with a non-executing unknown-tag marker; no script "
                "or event handler was submitted."
            ),
            asset=asset,
            module_source="xss_executor",
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(base_score=6.1,
                           vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            cwe=WeaknessRef(cwe_id="CWE-79", name="Improper Neutralization of Input (Reflected XSS)"),
            mitre_techniques=[MitreTechnique(technique_id="T1059.007", tactic="execution",
                                             name="JavaScript")],
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            remediation=(
                "Context-encode user input on output (HTML-entity encode < > \" ' &), and apply a "
                "Content-Security-Policy. Prefer framework auto-escaping over manual sanitization."
            ),
            business_impact="An attacker could run script in a victim's session (session theft, defacement, phishing).",
        )
        tx = (f"GET {probe.url}\nstatus: {probe.status}\n"
              f"unescaped reflection of {raw_marker}:\n{_snippet(body, raw_marker)}")
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.HTTP_TRANSACTION,
            raw_bytes=tx.encode(),
            storage_ref=f"mem://xss/{uuid.uuid4().hex[:8]}",
            description=f"Unescaped reflection of inert marker on {path}?{param}",
            metadata={"preview": tx},
        ))
        base_has = raw_marker in (baseline.text or "")
        diff = (
            f"Reflection behavior for parameter '{param}' on {path}:\n"
            f"  baseline (no brackets)  -> unescaped marker present: {base_has}\n"
            f"  probe (bracketed marker)-> unescaped marker present: True\n"
            f"  encoded form ({enc_marker}) present in probe: {enc_marker in body}\n"
            "The endpoint reflects the parameter into HTML without encoding < and >."
        )
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.BEHAVIORAL_DIFF,
            raw_bytes=diff.encode(),
            storage_ref=f"mem://xss-diff/{uuid.uuid4().hex[:8]}",
            description="Baseline-vs-probe reflection difference",
            metadata={"preview": diff},
        ))
        logger.info("xss: potential finding on %s?%s (unescaped reflection)", path, param)
        return finding


# DB error signatures that indicate input reached a SQL interpreter. Matched
# case-insensitively, and ONLY counted when they appear after an inert quote
# probe but NOT in the benign baseline (a behavioral difference, not a page
# that merely always contains the word "sql").
_SQL_ERROR_SIGNS = (
    "you have an error in your sql syntax", "sql syntax", "sqlstate",
    "unclosed quotation mark", "quoted string not properly terminated",
    "ora-0", "odbc", "mysql_fetch", "mysqli", "pg::", "psql:",
    "syntax error at or near", "sqlite error", "sqlite3::",
    "microsoft ole db provider", "jdbc", "warning: mysql",
)


class InjectionProbeExecutor:
    """Injection confirmation via differential error-signature (CWE-89 family).

    For each recon-observed injectable parameter, send a benign baseline value
    and then the same value with a single appended quote ("'") - an inert,
    non-destructive, GET-only probe. If a database error signature appears in
    the quoted response but NOT in the baseline, the input is reaching a SQL
    interpreter unsanitized: a confirmed injection point, shown by behavior, not
    by a guessed payload. No UNION/stacked/boolean exfiltration is attempted and
    nothing state-changing is sent.
    """

    handles = {HypothesisKind.INJECTION}

    async def execute(self, hyp: Hypothesis, ctx: "ExecContext") -> list[Finding]:
        if not ctx.roe.target_authorized(ctx.target_host):
            logger.warning("injection: %s not authorized by RoE - skipping", ctx.target_host)
            return []

        base = ctx.base_url or f"https://{ctx.target_host}"
        findings: list[Finding] = []
        probed = 0
        for path in hyp.target_endpoints:
            for param in hyp.target_params:
                if probed >= ctx.max_probes:
                    break
                token = "h4ckb0t" + uuid.uuid4().hex[:8]
                baseline_url = _with_param(base, path, param, token)        # benign
                probe_url = _with_param(base, path, param, token + "'")     # one inert quote
                try:
                    baseline = await ctx.fetch(baseline_url)
                    await asyncio.sleep(ctx.pace_seconds)
                    probe = await ctx.fetch(probe_url)
                except Exception as e:  # noqa: BLE001
                    logger.info("injection: fetch failed %s: %s", probe_url, e)
                    continue
                probed += 1
                await asyncio.sleep(ctx.pace_seconds)
                f = self._evaluate(path, param, baseline, probe, ctx)
                if f is not None:
                    findings.append(f)
        return findings

    def _evaluate(self, path, param, baseline, probe, ctx) -> Optional[Finding]:
        pb = (probe.text or "").lower()
        bb = (baseline.text or "").lower()
        hit = next((s for s in _SQL_ERROR_SIGNS if s in pb and s not in bb), None)
        if hit is None:
            # No new error surfaced from the quote -> no evidence of a SQL sink.
            return None

        asset = Asset(asset_id="a0", name=ctx.target_host, asset_type="web",
                      scope_approved=True, metadata={"exposure": "internet"})
        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"SQL injection via '{param}' on {path}",
            description=(
                f"Appending a single quote to parameter '{param}' on {path} produced a database "
                f"error ('{hit}') that the benign baseline did not. Input is reaching a SQL "
                "interpreter without proper parameterization. Confirmed with an inert quote probe "
                "(GET, read-only); no data-exfiltration or state-changing payload was sent."
            ),
            asset=asset,
            module_source="injection_executor",
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(base_score=8.6,
                           vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
            cwe=WeaknessRef(cwe_id="CWE-89", name="SQL Injection"),
            mitre_techniques=[MitreTechnique(technique_id="T1190", tactic="initial-access",
                                             name="Exploit Public-Facing Application")],
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            remediation=(
                "Use parameterized queries / prepared statements; never concatenate user input into "
                "SQL. Add least-privilege DB accounts and suppress verbose error output."
            ),
            business_impact="An attacker could read or alter database contents, potentially exfiltrating all records.",
        )
        tx = (f"GET {probe.url}\nstatus: {probe.status}\n"
              f"DB error signature '{hit}' surfaced:\n{_snippet(pb, hit)}")
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.HTTP_TRANSACTION,
            raw_bytes=tx.encode(),
            storage_ref=f"mem://inj/{uuid.uuid4().hex[:8]}",
            description=f"Quote probe eliciting DB error on {path}?{param}",
            metadata={"preview": tx},
        ))
        diff = (
            f"Error-signature behavior for parameter '{param}' on {path}:\n"
            f"  baseline (benign value) -> '{hit}' present: False\n"
            f"  probe (value + \"'\")     -> '{hit}' present: True\n"
            "A DB error appeared only when the quote was added, indicating unsanitized SQL interpolation."
        )
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.BEHAVIORAL_DIFF,
            raw_bytes=diff.encode(),
            storage_ref=f"mem://inj-diff/{uuid.uuid4().hex[:8]}",
            description="Baseline-vs-probe error-signature difference",
            metadata={"preview": diff},
        ))
        logger.info("injection: potential finding on %s?%s (signature '%s')", path, param, hit)
        return finding


class SsrfOobExecutor:
    """Out-of-band SSRF confirmation (CWE-918).

    For each URL-like parameter, inject a UNIQUE, INERT callback URL pointing at
    our own listener (e.g. http://scan.vaptix.com/oob/<token>) and make the
    request. If the target's back end fetches that URL, our listener records an
    interaction tagged with the token — direct proof the server made a
    server-side request to an attacker-supplied destination (the SSRF
    condition), even though the HTTP response gave nothing away. This is the
    canonical non-destructive SSRF test: a benign URL in a parameter, GET-only,
    no exploit payload. The callback itself is the proof, so a confirmed finding
    is VALIDATED, not inferred.

    Two independent evidence TYPES are attached — the probe transaction (we
    injected the callback) and the OOB interaction record (the server called
    back) — so evidence-correlation is satisfied honestly. Skips cleanly when no
    public callback base is configured (H4CK_BOT_OOB_BASE)."""

    handles = {HypothesisKind.SSRF}

    async def execute(self, hyp: Hypothesis, ctx: "ExecContext") -> list[Finding]:
        if not ctx.roe.target_authorized(ctx.target_host):
            logger.warning("ssrf: %s not authorized by RoE - skipping", ctx.target_host)
            return []
        if not ctx.oob_base_url:
            logger.info("ssrf: no OOB callback base (H4CK_BOT_OOB_BASE) configured - skipping OOB detection")
            return []

        from oob.listener import store, callback_url
        st = store()
        base = ctx.base_url or f"https://{ctx.target_host}"
        findings: list[Finding] = []
        probed = 0
        for path in hyp.target_endpoints:
            # prefer URL-like params, fall back to all params the hypothesis named
            params = [p for p in hyp.target_params if p.lower() in URL_PARAM_HINTS] or list(hyp.target_params)
            for param in params:
                if probed >= ctx.max_probes:
                    break
                token = st.new_token()
                cb = callback_url(token, ctx.oob_base_url)
                probe_url = _with_param(base, path, param, cb)
                try:
                    probe = await ctx.fetch(probe_url)
                except Exception as e:  # noqa: BLE001
                    logger.info("ssrf: fetch failed %s: %s", probe_url, e)
                    continue
                probed += 1
                # Wait for an out-of-band callback (back-end fetch can lag).
                interactions = []
                for _ in range(4):
                    await asyncio.sleep(1.5)
                    interactions = st.poll(token)
                    if interactions:
                        break
                if interactions:
                    findings.append(self._finding(path, param, cb, probe, interactions, ctx))
        return findings

    def _finding(self, path, param, cb, probe, interactions, ctx) -> Finding:
        asset = Asset(asset_id="a0", name=ctx.target_host, asset_type="web",
                      scope_approved=True, metadata={"exposure": "internet"})
        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Server-Side Request Forgery (SSRF) via '{param}' on {path}",
            description=(
                f"Parameter '{param}' on {path} caused the server to make an outbound request to an "
                f"attacker-supplied URL. A unique inert callback ({cb}) was injected, and the target's "
                f"back end fetched it — recorded out-of-band by our listener ({len(interactions)} "
                "interaction(s)). This is the SSRF condition, confirmed directly by the callback. "
                "Non-destructive: only a benign URL was supplied; no exploit payload was used."
            ),
            asset=asset,
            module_source="ssrf_oob_executor",
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(base_score=7.5,
                           vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            cwe=WeaknessRef(cwe_id="CWE-918", name="Server-Side Request Forgery (SSRF)"),
            mitre_techniques=[MitreTechnique(technique_id="T1190", tactic="initial-access",
                                             name="Exploit Public-Facing Application")],
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            remediation=(
                "Do not fetch user-supplied URLs server-side. If unavoidable, enforce a strict "
                "allowlist of hosts/schemes, block internal/link-local ranges, and disable redirects."
            ),
            business_impact="SSRF can reach internal services and cloud metadata, leading to data exposure or pivoting.",
            requires_corroboration=True,
        )
        tx = (f"GET {probe.url}\nstatus: {probe.status}\n"
              f"injected callback into '{param}': {cb}")
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.HTTP_TRANSACTION, raw_bytes=tx.encode(),
            storage_ref=f"mem://ssrf/{finding.finding_id}",
            description=f"SSRF probe injecting an OOB callback on {path}?{param}",
            metadata={"preview": tx},
        ))
        oob_text = ("Out-of-band callback received — proof the server fetched the injected URL:\n\n"
                    + "\n\n".join(i.summary() for i in interactions[:5]))
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RAW_OUTPUT, raw_bytes=oob_text.encode(),
            storage_ref=f"mem://ssrf-oob/{finding.finding_id}",
            description="Out-of-band interaction(s) recorded by the listener",
            metadata={"preview": oob_text, "source": "oob_listener"},
        ))
        logger.info("ssrf: CONFIRMED on %s?%s (%d OOB interaction(s))", path, param, len(interactions))
        return finding


class XxeOobExecutor:
    """Out-of-band blind-XXE confirmation (CWE-611).

    Submits an INERT, DETECTION-ONLY XML document whose external entity points
    at a unique callback URL on our listener:

        <!DOCTYPE t [ <!ENTITY x SYSTEM "http://<listener>/oob/<token>/xxe"> ]>
        <t>&x;</t>

    If the server's XML parser resolves external entities, it fetches that URL,
    and our listener records the interaction — direct proof of blind XXE, with
    no change in the HTTP response. This is the standard non-destructive XXE
    detection test. It deliberately does NOT use file:// or parameter-entity
    exfiltration (the weaponized variant): the entity only triggers an HTTP
    callback, which is the proof. POST-only (XXE lives in the request body);
    no data is modified.

    Two independent evidence types are attached (the probe + the OOB
    interaction). Skips cleanly without an OOB base or a POST capability."""

    handles = {HypothesisKind.XXE}

    _XML_CT = "application/xml"

    async def execute(self, hyp: Hypothesis, ctx: "ExecContext") -> list[Finding]:
        if not ctx.roe.target_authorized(ctx.target_host):
            logger.warning("xxe: %s not authorized by RoE - skipping", ctx.target_host)
            return []
        if not ctx.oob_base_url:
            logger.info("xxe: no OOB callback base configured - skipping")
            return []
        if ctx.post is None:
            logger.info("xxe: no POST capability wired - skipping")
            return []

        from oob.listener import store, callback_url
        st = store()
        base = ctx.base_url or f"https://{ctx.target_host}"
        findings: list[Finding] = []
        probed = 0
        for path in hyp.target_endpoints:
            if probed >= ctx.max_probes:
                break
            token = st.new_token()
            cb = callback_url(token, ctx.oob_base_url) + "/xxe"
            body = self._payload(cb)
            url = base.rstrip("/") + "/" + path.lstrip("/")
            try:
                probe = await ctx.post(url, body.encode(), self._XML_CT)
            except Exception as e:  # noqa: BLE001
                logger.info("xxe: post failed %s: %s", url, e)
                continue
            probed += 1
            interactions = []
            for _ in range(4):
                await asyncio.sleep(1.5)
                interactions = st.poll(token)
                if interactions:
                    break
            if interactions:
                findings.append(self._finding(path, cb, url, probe, interactions, ctx))
        return findings

    @staticmethod
    def _payload(cb: str) -> str:
        # Detection-only: external entity triggers an HTTP callback. No file://,
        # no parameter entities, nothing exfiltrated.
        ent = "h4ckxxe"
        return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE probe [ <!ENTITY {ent} SYSTEM "{cb}"> ]>\n'
                f'<probe>&{ent};</probe>')

    def _finding(self, path, cb, url, probe, interactions, ctx) -> Finding:
        asset = Asset(asset_id="a0", name=ctx.target_host, asset_type="web",
                      scope_approved=True, metadata={"exposure": "internet"})
        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"Blind XML External Entity (XXE) on {path}",
            description=(
                f"The XML parser at {path} resolved an external entity pointing to a unique inert "
                f"callback ({cb}); the server fetched it, recorded out-of-band by our listener "
                f"({len(interactions)} interaction(s)). This confirms blind XXE — the parser processes "
                "external entities from untrusted input. Detection-only: the entity triggered an HTTP "
                "callback; no file was read and nothing was exfiltrated."
            ),
            asset=asset,
            module_source="xxe_oob_executor",
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(base_score=7.1,
                           vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L"),
            cwe=WeaknessRef(cwe_id="CWE-611", name="Improper Restriction of XML External Entity Reference (XXE)"),
            mitre_techniques=[MitreTechnique(technique_id="T1190", tactic="initial-access",
                                             name="Exploit Public-Facing Application")],
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            remediation=(
                "Disable external entity and DTD processing in the XML parser (set FEATURE_SECURE_PROCESSING, "
                "disallow-doctype-decl). Prefer a parser hardened against XXE by default."
            ),
            business_impact="XXE can read internal files, perform SSRF to internal services, and exfiltrate data.",
            requires_corroboration=True,
        )
        tx = (f"POST {url}\nContent-Type: {self._XML_CT}\nstatus: {probe.status}\n"
              f"injected detection-only external entity -> {cb}")
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.HTTP_TRANSACTION, raw_bytes=tx.encode(),
            storage_ref=f"mem://xxe/{finding.finding_id}",
            description=f"XXE probe (inert external entity) on {path}",
            metadata={"preview": tx},
        ))
        oob_text = ("Out-of-band callback received — proof the XML parser fetched the entity URL:\n\n"
                    + "\n\n".join(i.summary() for i in interactions[:5]))
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RAW_OUTPUT, raw_bytes=oob_text.encode(),
            storage_ref=f"mem://xxe-oob/{finding.finding_id}",
            description="Out-of-band interaction(s) recorded by the listener",
            metadata={"preview": oob_text, "source": "oob_listener"},
        ))
        logger.info("xxe: CONFIRMED on %s (%d OOB interaction(s))", path, len(interactions))
        return finding


class ExecutorRegistry:
    """Maps a hypothesis to the executor that can safely check it. Each executor
    is non-destructive (GET-only, inert probes), scope-gated against the RoE, and
    emits POTENTIAL findings for the validation pipeline to adjudicate - it never
    self-certifies. Kinds with no executor yet return None, so the orchestrator
    reports honest coverage instead of a fabricated result."""

    def __init__(self):
        self._executors: list[Executor] = [
            BolaExecutor(),
            XssReflectionExecutor(),
            InjectionProbeExecutor(),
            SsrfOobExecutor(),
            XxeOobExecutor(),
        ]

    def for_hypothesis(self, hyp: Hypothesis) -> Optional[Executor]:
        for ex in self._executors:
            if hyp.kind in getattr(ex, "handles", set()):
                return ex
        return None
