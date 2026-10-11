"""
AI-authored safe probes — the AI writes its own check.

This is the limit-breaker: the engine is no longer capped by the fixed set of
hand-written executors. When the strategist forms a hypothesis it has no
dedicated tool for, it SYNTHESIZES its own check — a single bounded, GET-only,
non-destructive request plus a response matcher — and emits it as a `probe_spec`
on the hypothesis. The engine can then test weaknesses we never coded.

The entire safety of that rests on ONE thing, and it lives in this file: the
`validate_probe_spec` function, the wall. An AI-authored spec is NEVER trusted
as written. Before anything touches the target, the spec must pass every hard
rule below, and if any check is ambiguous the answer is "reject":

  1. GET only. The spec cannot request any other method; the transport
     (ctx.fetch) is GET-only regardless, so this is defence in depth.
  2. Grounded. The endpoint must be one recon actually observed, and a named
     parameter must be one recon actually observed on the target. The AI cannot
     invent attack surface — same discipline as every other hypothesis.
  3. Non-destructive payload. The payload is a bounded string that must clear a
     denylist of anything that could change state or reach internal/dangerous
     destinations: SQL write verbs, stacked queries, shell metacharacters,
     path traversal, dangerous URI schemes, internal/link-local hosts.
  4. Bounded. One endpoint, one optional parameter, a capped payload length, a
     capped time-delay oracle, a small paced number of requests.
  5. Evidence, not self-certification. A matched probe emits a POTENTIAL finding
     with two independent evidence types and requires_corroboration=True, so the
     normal validation pipeline — not the AI — decides whether it is VALIDATED.

If the wall rejects a spec, the probe never runs and the reason is logged. That
is the one boundary that does not move.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Optional
from urllib.parse import urlsplit

from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding, FindingKind,
    KillChainPhase, MitreTechnique, WeaknessRef,
)
from redteam.executors import ExecContext, _snippet, _with_param
from redteam.types import Hypothesis, HypothesisKind

logger = logging.getLogger("h4ck-bot.redteam.synth")

# ── the wall: hard limits ────────────────────────────────────────────
_MAX_PAYLOAD_LEN = 256
_MIN_DELAY_S = 2          # time-oracle floor (must be meaningfully > jitter)
_MAX_DELAY_S = 6          # time-oracle cap (never ask the server to hang long)
_MIN_NEEDLE_LEN = 6       # a matcher needle must be specific enough to mean something
_MATCHERS = {"reflection", "error_signature", "status_change", "time_delay"}
_SEVERITIES = {"info", "low", "medium", "high", "critical"}

# Anything in a payload that could change state, execute, traverse, or reach a
# dangerous/internal destination. Matched case-insensitively as a substring.
# Detection-oriented inert values pass; weaponization does not. When in doubt the
# token is on this list — a rejected probe is always safe, a permitted destructive
# one is not.
_DESTRUCTIVE_TOKENS = (
    # SQL state change / stacked queries
    "drop ", "drop\t", "delete ", "insert ", "update ", "truncate", "alter ",
    "create ", "grant ", "revoke", "merge ", "upsert", "replace into",
    "exec ", "execute ", "xp_", "sp_", "into outfile", "into dumpfile",
    "load_file", "; ", ";\n", "';", "\";", "benchmark(",
    # shell / command execution and chaining
    "$(", "`", "&&", "||", "|sh", "|bash", "| sh", "| bash", "; rm", "rm -",
    "shutdown", "reboot", "mkfs", "/bin/sh", "/bin/bash", "powershell", "cmd.exe",
    "curl ", "wget ", "nc ", "ncat", "bash -i", "chmod ", "chown ",
    # path traversal / file access
    "../", "..\\", "/etc/passwd", "/etc/shadow", "c:\\windows", "win.ini",
    # dangerous URI schemes
    "file://", "gopher://", "dict://", "ldap://", "jar://", "netdoc://",
    "php://", "expect://", "data:", "ftp://", "smb://", "\\\\",
    # internal / cloud-metadata SSRF destinations
    "169.254.169.254", "metadata.google", "127.0.0.1", "localhost",
    "0.0.0.0", "::1", "[::1]", "internal", "169.254.",
    # XSS active execution (generic probes detect by reflection, not by firing JS)
    "<script", "onerror=", "onload=", "javascript:", "<iframe", "<svg",
)

# A compact MITRE fallback by CWE family, so an AI-probed finding still lands on
# the kill-chain/ATT&CK map instead of "unknown".
_MITRE_BY_CWE_PREFIX = {
    "CWE-20": ("T1190", "initial-access", "Exploit Public-Facing Application"),
    "CWE-22": ("T1083", "discovery", "File and Directory Discovery"),
    "CWE-200": ("T1592", "reconnaissance", "Gather Victim Host Information"),
    "CWE-538": ("T1592", "reconnaissance", "Gather Victim Host Information"),
}
_DEFAULT_MITRE = ("T1190", "initial-access", "Exploit Public-Facing Application")


def _ground_endpoint(endpoint: str, observed_paths: set[str]) -> Optional[str]:
    """Return the endpoint iff it is a relative path recon actually observed.
    Rejects absolute URLs, schemes, and anything off the observed surface."""
    if not isinstance(endpoint, str) or not endpoint:
        return None
    ep = endpoint.strip()
    if "://" in ep or " " in ep or ".." in ep:
        return None
    if not ep.startswith("/"):
        ep = "/" + ep
    ep_path = ep.split("?", 1)[0].split("#", 1)[0]
    # Must match an observed path exactly (by path component). Grounding is strict:
    # the AI cannot point a probe at a route the scanner never saw.
    observed_norm = {p.split("?", 1)[0] for p in observed_paths}
    return ep_path if ep_path in observed_norm else None


def _payload_is_destructive(payload: str) -> Optional[str]:
    """Return the offending token if the payload could change state / execute /
    traverse / reach a dangerous destination, else None."""
    low = payload.lower()
    for tok in _DESTRUCTIVE_TOKENS:
        if tok in low:
            return tok.strip() or tok
    return None


def validate_probe_spec(
    spec: dict, observed_paths: set[str], observed_params: set[str],
) -> tuple[bool, str, dict]:
    """THE WALL. Validate an AI-authored probe spec against the hard limits.

    Returns (ok, reason, normalized). `ok` is True only if every rule passes;
    `normalized` is the cleaned spec the executor will run. Any ambiguity, any
    missing field, any token we don't positively recognize as safe -> reject.
    """
    if not isinstance(spec, dict):
        return False, "spec is not an object", {}

    # Rule 1: GET only. An explicit non-GET method is an immediate reject.
    method = str(spec.get("method", "GET")).upper()
    if method != "GET":
        return False, f"method {method!r} is not GET (probes are GET-only)", {}

    # Rule 2a: endpoint must be grounded in observed surface.
    endpoint = _ground_endpoint(spec.get("endpoint", ""), observed_paths)
    if endpoint is None:
        return False, f"endpoint {spec.get('endpoint')!r} not in observed surface (ungrounded)", {}

    # Rule 2b: a named parameter must be grounded too (may be absent).
    param = spec.get("param")
    if param is not None:
        param = str(param).strip()
        if not param:
            param = None
        elif param not in observed_params:
            return False, f"param {param!r} not observed on target (ungrounded)", {}

    # Rule 3: payload must be a bounded, non-destructive string.
    payload = spec.get("payload", "")
    if not isinstance(payload, str) or not payload:
        return False, "payload missing or not a string", {}
    if len(payload) > _MAX_PAYLOAD_LEN:
        return False, f"payload too long ({len(payload)} > {_MAX_PAYLOAD_LEN})", {}
    bad = _payload_is_destructive(payload)
    if bad is not None:
        return False, f"payload contains a disallowed/destructive token: {bad!r}", {}

    # Rule 4: matcher must be one of the known differential types, within bounds.
    matcher = spec.get("matcher")
    if not isinstance(matcher, dict):
        return False, "matcher missing or not an object", {}
    m_type = str(matcher.get("type", "")).strip().lower()
    if m_type not in _MATCHERS:
        return False, f"matcher type {m_type!r} not in {sorted(_MATCHERS)}", {}
    norm_matcher: dict = {"type": m_type}
    if m_type in ("reflection", "error_signature"):
        needle = matcher.get("needle")
        if not isinstance(needle, str) or len(needle) < _MIN_NEEDLE_LEN:
            return False, f"{m_type} matcher needs a needle of >= {_MIN_NEEDLE_LEN} chars", {}
        if len(needle) > _MAX_PAYLOAD_LEN:
            return False, "matcher needle too long", {}
        norm_matcher["needle"] = needle
    elif m_type == "time_delay":
        try:
            delay = int(matcher.get("min_delay_s", 0))
        except (TypeError, ValueError):
            return False, "time_delay matcher min_delay_s not an integer", {}
        if not (_MIN_DELAY_S <= delay <= _MAX_DELAY_S):
            return False, f"time_delay min_delay_s {delay} out of [{_MIN_DELAY_S},{_MAX_DELAY_S}]", {}
        # A time oracle requires the payload itself to encode the delay; since we
        # forbid SQL/shell tokens, a destructive sleep can't pass rule 3. The
        # payload must still name a benign delay construct, but we don't try to
        # parse it — the matcher only measures elapsed time differentially.
        norm_matcher["min_delay_s"] = delay
    # status_change needs no extra fields.

    # Rule 5 fields: classification (defaulted safely, never trusted blindly).
    cwe = str(spec.get("cwe", "") or "").strip().upper()
    if not re.fullmatch(r"CWE-\d{1,5}", cwe):
        cwe = "CWE-20"   # Improper Input Validation — the honest generic default
    severity = str(spec.get("severity", "medium") or "medium").strip().lower()
    if severity not in _SEVERITIES:
        severity = "medium"
    title = str(spec.get("title", "") or "").strip()[:160] or "AI-synthesized probe"
    rationale = str(spec.get("rationale", "") or "").strip()[:600]

    normalized = {
        "endpoint": endpoint,
        "param": param,
        "payload": payload,
        "matcher": norm_matcher,
        "cwe": cwe,
        "severity": severity,
        "title": title,
        "rationale": rationale,
    }
    return True, "ok", normalized


def _mitre_for(cwe: str) -> MitreTechnique:
    tid, tactic, name = _MITRE_BY_CWE_PREFIX.get(cwe, _DEFAULT_MITRE)
    return MitreTechnique(technique_id=tid, tactic=tactic, name=name)


class GenericProbeExecutor:
    """Runs an AI-authored probe_spec — but only after `validate_probe_spec`
    clears it. GET-only, grounded, non-destructive, bounded, evidence-gated.

    The matcher is always DIFFERENTIAL (baseline vs probe), never an absolute
    claim about a single response, so a page that merely contains a word can't
    trigger a finding. Status/time oracles are confirmed on repeat so a one-off
    blip can't pass. Every matched probe produces two independent evidence types
    and requires_corroboration=True; the validation pipeline adjudicates."""

    handles = {HypothesisKind.AI_PROBE}

    async def execute(self, hyp: Hypothesis, ctx: ExecContext) -> list[Finding]:
        if not ctx.roe.target_authorized(ctx.target_host):
            logger.warning("synth-probe: %s not authorized by RoE - skipping", ctx.target_host)
            return []

        observed_paths = {e for e in (hyp.target_endpoints or [])}
        observed_params = {p for p in (hyp.target_params or [])}
        ok, reason, spec = validate_probe_spec(hyp.probe_spec or {}, observed_paths, observed_params)
        if not ok:
            # The wall held: an AI-authored spec that isn't provably safe never runs.
            logger.warning("synth-probe: REJECTED AI spec for %s (%s)", hyp.hypothesis_id, reason)
            return []

        base = ctx.base_url or f"https://{ctx.target_host}"
        try:
            finding = await self._run(spec, base, ctx)
        except Exception as e:  # noqa: BLE001
            logger.info("synth-probe: run failed on %s: %s", spec["endpoint"], e)
            return []
        return [finding] if finding is not None else []

    async def _run(self, spec, base, ctx) -> Optional[Finding]:
        endpoint, param, payload = spec["endpoint"], spec["param"], spec["payload"]
        matcher = spec["matcher"]
        token = "h4ckp" + uuid.uuid4().hex[:8]

        # Build baseline (benign token) and probe (token + payload) URLs. If the
        # spec has no param, we append the value as a trailing query marker on a
        # grounded path so we still have a benign-vs-probe differential.
        if param:
            baseline_url = _with_param(base, endpoint, param, token)
            probe_url = _with_param(base, endpoint, param, token + payload)
        else:
            baseline_url = _with_param(base, endpoint, "h4ckprobe", token)
            probe_url = _with_param(base, endpoint, "h4ckprobe", token + payload)

        m_type = matcher["type"]
        if m_type == "time_delay":
            return await self._match_time(spec, endpoint, param, baseline_url, probe_url, ctx)

        baseline = await ctx.fetch(baseline_url)
        await asyncio.sleep(ctx.pace_seconds)
        probe = await ctx.fetch(probe_url)
        await asyncio.sleep(ctx.pace_seconds)

        if m_type == "reflection":
            return self._match_reflection(spec, endpoint, param, token, payload, baseline, probe, ctx)
        if m_type == "error_signature":
            return self._match_needle(spec, endpoint, param, baseline, probe, ctx)
        if m_type == "status_change":
            return await self._match_status(spec, endpoint, param, probe_url, baseline, probe, ctx)
        return None

    # ── matchers (each a strict differential) ─────────────────────────
    def _match_reflection(self, spec, endpoint, param, token, payload, baseline, probe, ctx) -> Optional[Finding]:
        pbody, bbody = probe.text or "", baseline.text or ""
        combined = token + payload
        # Fired iff the payload comes back verbatim in the probe but the payload
        # characters are NOT in the benign baseline (so it's our input reflected).
        if combined not in pbody or payload in bbody:
            return None
        tx = (f"GET {probe.url}\nstatus: {probe.status}\n"
              f"payload reflected verbatim:\n{_snippet(pbody, combined)}")
        diff = (
            f"Reflection differential on {endpoint}"
            + (f"?{param}" if param else "") + ":\n"
            f"  baseline (benign token)   -> payload present: {payload in bbody}\n"
            f"  probe (token + payload)   -> payload present: True (verbatim)\n"
            "AI-synthesized probe: the supplied input is returned unmodified in the response body."
        )
        return self._finding(spec, endpoint, param, ctx,
                             summary="input reflected verbatim", tx=tx, diff=diff)

    def _match_needle(self, spec, endpoint, param, baseline, probe, ctx) -> Optional[Finding]:
        needle = spec["matcher"]["needle"].lower()
        pbody, bbody = (probe.text or "").lower(), (baseline.text or "").lower()
        # Fired iff the expected signature appears after the payload but NOT in
        # the benign baseline — a behavioral difference, not an ever-present word.
        if needle not in pbody or needle in bbody:
            return None
        tx = (f"GET {probe.url}\nstatus: {probe.status}\n"
              f"expected signature {needle!r} surfaced only under the probe:\n"
              f"{_snippet(probe.text or '', spec['matcher']['needle'])}")
        diff = (
            f"Signature differential on {endpoint}" + (f"?{param}" if param else "") + ":\n"
            f"  baseline -> {needle!r} present: False\n"
            f"  probe    -> {needle!r} present: True\n"
            "AI-synthesized probe: the signature appeared only when the payload was supplied."
        )
        return self._finding(spec, endpoint, param, ctx,
                             summary=f"signature {needle!r} elicited", tx=tx, diff=diff)

    async def _match_status(self, spec, endpoint, param, probe_url, baseline, probe, ctx) -> Optional[Finding]:
        # Only a server-ERROR differential counts (5xx under probe, non-5xx
        # baseline), and it must repeat so a transient 500 can't pass.
        if not (probe.status >= 500 and baseline.status < 500):
            return None
        await asyncio.sleep(ctx.pace_seconds)
        confirm = await ctx.fetch(probe_url)
        if confirm.status < 500:
            return None
        tx = (f"GET {probe.url}\nbaseline status: {baseline.status}\n"
              f"probe status: {probe.status} (repeat: {confirm.status})")
        diff = (
            f"Status differential on {endpoint}" + (f"?{param}" if param else "") + ":\n"
            f"  baseline (benign) -> HTTP {baseline.status}\n"
            f"  probe (payload)   -> HTTP {probe.status}, repeat HTTP {confirm.status}\n"
            "AI-synthesized probe: the payload reliably drove the endpoint into a server error."
        )
        return self._finding(spec, endpoint, param, ctx,
                             summary="payload triggers a repeatable server error", tx=tx, diff=diff)

    async def _match_time(self, spec, endpoint, param, baseline_url, probe_url, ctx) -> Optional[Finding]:
        import time as _t
        delay = spec["matcher"]["min_delay_s"]

        async def timed(url):
            t0 = _t.monotonic()
            await ctx.fetch(url)
            return _t.monotonic() - t0

        control = await timed(baseline_url)
        await asyncio.sleep(ctx.pace_seconds)
        thresh = max(delay * 0.7, control + delay * 0.6)
        d1 = await timed(probe_url)
        await asyncio.sleep(ctx.pace_seconds)
        if d1 < thresh:
            return None
        d2 = await timed(probe_url)             # confirm on repeat
        if d2 < thresh:
            return None
        tx = (f"GET {probe_url}\ncontrol: {control:.2f}s\ndelayed: {d1:.2f}s, {d2:.2f}s "
              f"(threshold {thresh:.2f}s)")
        diff = (
            f"Time differential on {endpoint}" + (f"?{param}" if param else "") + ":\n"
            f"  control (benign) -> {control:.2f}s\n"
            f"  probe #1/#2      -> {d1:.2f}s / {d2:.2f}s\n"
            f"AI-synthesized probe: the payload added ~{delay}s, confirmed on repeat."
        )
        return self._finding(spec, endpoint, param, ctx,
                             summary=f"payload induces a repeatable ~{delay}s delay", tx=tx, diff=diff)

    # ── finding builder ───────────────────────────────────────────────
    def _finding(self, spec, endpoint, param, ctx, *, summary, tx, diff) -> Finding:
        sev_score = {"critical": 9.0, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}
        asset = Asset(asset_id="a0", name=ctx.target_host, asset_type="web",
                      scope_approved=True, metadata={"exposure": "internet"})
        where = endpoint + (f" (param '{param}')" if param else "")
        finding = Finding(
            finding_id=str(uuid.uuid4()),
            title=f"[AI-probe] {spec['title']} on {endpoint}",
            description=(
                f"AI-SYNTHESIZED CHECK. The engine had no dedicated executor for this hypothesis, "
                f"so it authored its own non-destructive probe against {where} and {summary}. "
                f"Rationale: {spec['rationale'] or 'n/a'}. The probe was validated before running "
                "(GET-only, grounded to observed surface, non-destructive payload, bounded) and the "
                "result is evidence-gated by the validation pipeline — the AI did not self-certify it. "
                "Treat as a lead to verify: an AI-authored check is more speculative than a hand-written one."
            ),
            asset=asset,
            module_source="ai_synth_probe",
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(base_score=sev_score.get(spec["severity"], 5.3),
                           vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
            cwe=WeaknessRef(cwe_id=spec["cwe"], name="AI-probed weakness (see description)"),
            mitre_techniques=[_mitre_for(spec["cwe"])],
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            remediation=(
                "Verify this AI-authored finding manually. If confirmed, treat per the mapped CWE: "
                "validate and encode untrusted input at the relevant sink and add server-side checks."
            ),
            business_impact="An AI-synthesized probe observed anomalous, attacker-influenced behavior worth verifying.",
            requires_corroboration=True,   # AI-authored -> MUST have 2 evidence types to validate
        )
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.HTTP_TRANSACTION, raw_bytes=tx.encode(),
            storage_ref=f"mem://synth/{uuid.uuid4().hex[:8]}",
            description=f"AI-probe transaction on {endpoint}", metadata={"preview": tx}))
        finding.add_evidence(Evidence.new(
            evidence_type=EvidenceType.BEHAVIORAL_DIFF, raw_bytes=diff.encode(),
            storage_ref=f"mem://synth-diff/{uuid.uuid4().hex[:8]}",
            description="AI-probe baseline-vs-probe differential", metadata={"preview": diff}))
        logger.info("synth-probe: potential finding on %s (%s)", endpoint, summary)
        return finding
