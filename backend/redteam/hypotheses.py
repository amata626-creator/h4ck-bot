"""
Hypothesis generator — the red-team engine's reasoning core (Phase 1: Web/API).

Turns a SemanticModel + ReconResult into grounded, prioritized vulnerability
hypotheses. The deterministic rules below are the reliable engine: every
hypothesis they emit references an endpoint recon actually discovered, so there
are no hallucinated targets. An optional LLM pass can enrich rationale and
re-rank, but it can only annotate hypotheses the deterministic layer already
grounded — it can never invent a new target. (Same "LLM proposes, deterministic
constrains" discipline the semantic layer uses.)

Nothing here executes a check. It produces questions; the planner decides which
may be asked, under the Rules of Engagement.
"""

from __future__ import annotations

import logging
import re
import uuid

from core.schema import KillChainPhase, MitreTechnique, Severity, WeaknessRef
from recon.types import ReconResult
from semantic.types import SemanticModel
from redteam.types import Hypothesis, HypothesisKind, Technique

logger = logging.getLogger("h4ck-bot.redteam")

# Params whose names suggest injectable sinks (weak prior, raises confidence).
_INJECTABLE_HINTS = ("id", "search", "q", "query", "filter", "sort", "order",
                     "name", "email", "user", "file", "path", "url", "redirect")
# Path segments that imply privileged / admin functionality.
_PRIVILEGED_HINTS = ("admin", "internal", "manage", "config", "debug", "actuator")
_ID_PATH = re.compile(r"\{[^}]+\}|/:\w+|/\d+(?:/|$)")   # /users/{id}, /:id, /42


def _sev_from_sensitivity(sensitivity: str, base: Severity) -> Severity:
    if sensitivity == "high":
        return Severity.HIGH if base.value != "critical" else Severity.CRITICAL
    if sensitivity == "low":
        return Severity.LOW
    return base


class HypothesisGenerator:
    def generate(self, semantic: SemanticModel, recon: ReconResult) -> list[Hypothesis]:
        discovered = {ep.path for ep in recon.endpoints}
        by_path = {ep.path: ep for ep in recon.endpoints}
        out: list[Hypothesis] = []

        def new_id() -> str:
            return "hyp_" + uuid.uuid4().hex[:10]

        def ground(paths: list[str]) -> list[str]:
            """Keep only paths recon actually saw — the anti-hallucination gate."""
            return [p for p in paths if p in discovered]

        # ── 1. BOLA / IDOR on owned, instance-scoped resources ───────────
        # The strongest Web/API signal and the one the semantic model is built
        # to surface: a resource with an owner field + endpoints that address a
        # single instance is a textbook broken-object-level-authorization test.
        for res in semantic.resources_with_ownership():
            eps = ground(res.endpoints)
            instance_eps = [p for p in eps if _ID_PATH.search(p) or res.identifier_field]
            if not instance_eps:
                continue
            sev = _sev_from_sensitivity(res.sensitivity, Severity.HIGH)
            out.append(Hypothesis(
                hypothesis_id=new_id(),
                kind=HypothesisKind.BOLA,
                title=f"Broken object-level authorization on '{res.name}' resource",
                target_endpoints=instance_eps,
                rationale=(
                    f"Resource '{res.name}' exposes an owner field "
                    f"('{res.owner_field or 'inferred from name'}') and is addressed per-instance "
                    f"via {instance_eps[:3]}. A low-privilege identity may be able to read or "
                    f"modify another tenant's '{res.name}' by changing the object id."
                ),
                evidence_refs=[f"semantic.resource:{res.name}", f"recon.endpoints:{instance_eps[:3]}"],
                cwe=WeaknessRef(cwe_id="CWE-639", name="Authorization Bypass Through User-Controlled Key"),
                mitre=MitreTechnique(technique_id="T1190", tactic="initial-access",
                                     name="Exploit Public-Facing Application"),
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                estimated_severity=sev,
                prior_confidence=0.6 if res.owner_field else 0.45,
                suggested_technique=Technique.AUTHZ_TESTING,
                requires_active_testing=True,
            ))

        # ── 2. Injection candidates on parameterized endpoints ───────────
        for ep in recon.endpoints:
            if not ep.params:
                continue
            risky = [p for p in ep.params if any(h in p.lower() for h in _INJECTABLE_HINTS)]
            if not risky:
                continue
            out.append(Hypothesis(
                hypothesis_id=new_id(),
                kind=HypothesisKind.INJECTION,
                title=f"Injection candidate via {risky[:3]} on {ep.path}",
                target_endpoints=[ep.path],
                rationale=(
                    f"Endpoint {ep.path} accepts parameter(s) {risky[:3]} that commonly reach a "
                    f"query, command, or filter sink. Safe injection probes (inert markers, no "
                    f"destructive payloads) would show whether input is interpolated unsafely."
                ),
                evidence_refs=[f"recon.endpoint:{ep.signature}", f"params:{risky[:3]}"],
                cwe=WeaknessRef(cwe_id="CWE-89", name="SQL Injection (and related injection)"),
                mitre=MitreTechnique(technique_id="T1190", tactic="initial-access",
                                     name="Exploit Public-Facing Application"),
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                estimated_severity=Severity.HIGH,
                prior_confidence=0.4,
                suggested_technique=Technique.INJECTION_TESTING,
                requires_active_testing=True,
            ))

        # ── 3. Reflected XSS on HTML endpoints that take input ───────────
        for ep in recon.endpoints:
            is_html = "html" in (ep.content_type or "").lower()
            if not (ep.params and (is_html or "GET" in (ep.methods or []))):
                continue
            out.append(Hypothesis(
                hypothesis_id=new_id(),
                kind=HypothesisKind.XSS,
                title=f"Reflected XSS candidate via {ep.params[:3]} on {ep.path}",
                target_endpoints=[ep.path],
                rationale=(
                    f"{ep.path} renders with input parameter(s) {ep.params[:3]}. An inert HTML-like "
                    f"marker submitted and observed un-escaped in the response would indicate "
                    f"reflected XSS. No script execution is attempted."
                ),
                evidence_refs=[f"recon.endpoint:{ep.signature}"],
                cwe=WeaknessRef(cwe_id="CWE-79", name="Cross-Site Scripting (Reflected)"),
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                estimated_severity=Severity.MEDIUM,
                prior_confidence=0.35,
                suggested_technique=Technique.XSS_TESTING,
                requires_active_testing=True,
            ))

        # ── 4. Broken authentication around the login surface ────────────
        if recon.auth.login_paths:
            login = ground(recon.auth.login_paths) or recon.auth.login_paths[:2]
            no_csrf = not recon.auth.csrf_param_names
            out.append(Hypothesis(
                hypothesis_id=new_id(),
                kind=HypothesisKind.BROKEN_AUTH,
                title="Authentication weaknesses on the login flow",
                target_endpoints=login,
                rationale=(
                    f"Login surface observed at {login}. Candidate checks: username enumeration via "
                    f"differential responses, missing rate-limiting / lockout"
                    + (", and no CSRF token was observed on the auth form" if no_csrf else "")
                    + ". All non-destructive and bounded."
                ),
                evidence_refs=[f"recon.auth.login_paths:{login}"],
                cwe=WeaknessRef(cwe_id="CWE-287", name="Improper Authentication"),
                mitre=MitreTechnique(technique_id="T1110", tactic="credential-access",
                                     name="Brute Force"),
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                estimated_severity=Severity.HIGH,
                prior_confidence=0.5,
                suggested_technique=Technique.AUTH_TESTING,
                requires_active_testing=True,
            ))

        # ── 5. Excessive data exposure on sensitive resources ────────────
        for res in semantic.resources:
            if res.sensitivity != "high":
                continue
            eps = ground(res.endpoints)
            if not eps:
                continue
            out.append(Hypothesis(
                hypothesis_id=new_id(),
                kind=HypothesisKind.SENSITIVE_DATA_EXPOSURE,
                title=f"Excessive data exposure on '{res.name}'",
                target_endpoints=eps,
                rationale=(
                    f"'{res.name}' is high-sensitivity and served by {eps[:3]}. A read of the "
                    f"response (passive, no mutation) would show whether it returns more fields "
                    f"than a client needs (tokens, PII, internal ids)."
                ),
                evidence_refs=[f"semantic.resource:{res.name}"],
                cwe=WeaknessRef(cwe_id="CWE-213", name="Exposure of Sensitive Information"),
                kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                estimated_severity=Severity.MEDIUM,
                prior_confidence=0.45,
                suggested_technique=Technique.API_TESTING,
                requires_active_testing=False,   # observing a response is passive
            ))

        # ── 6. Mass assignment on writable resources ─────────────────────
        for res in semantic.resources_with_ownership():
            write_eps = ground([
                ep.path for ep in recon.endpoints
                if ep.path in res.endpoints
                and any(m in ("POST", "PUT", "PATCH") for m in (ep.methods or []))
            ])
            if not write_eps:
                continue
            out.append(Hypothesis(
                hypothesis_id=new_id(),
                kind=HypothesisKind.MASS_ASSIGNMENT,
                title=f"Mass assignment candidate on '{res.name}'",
                target_endpoints=write_eps,
                rationale=(
                    f"'{res.name}' accepts writes at {write_eps[:3]} and has an owner/privilege "
                    f"field. Submitting extra fields (e.g. role, owner_id, is_admin) would show "
                    f"whether the binding is over-permissive."
                ),
                evidence_refs=[f"semantic.resource:{res.name}"],
                cwe=WeaknessRef(cwe_id="CWE-915", name="Improperly Controlled Modification of Attributes"),
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                estimated_severity=Severity.HIGH,
                prior_confidence=0.35,
                suggested_technique=Technique.API_TESTING,
                requires_active_testing=True,
            ))

        out.sort(key=lambda h: h.priority(), reverse=True)
        logger.info("redteam: generated %d grounded hypotheses for %s",
                    len(out), semantic.target)
        return out
