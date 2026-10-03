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
        ]

    def for_hypothesis(self, hyp: Hypothesis) -> Optional[Executor]:
        for ex in self._executors:
            if hyp.kind in getattr(ex, "handles", set()):
                return ex
        return None
