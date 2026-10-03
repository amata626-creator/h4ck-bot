"""
Red-team reasoning layer — data model.

A Hypothesis is the unit of red-team reasoning: "I believe <target> may have
<weakness>, because <evidence I actually observed>, and here is the safe check
that would confirm or refute it." It sits between the semantic model (what the
app IS) and the scanner modules (what the platform can safely DO).

Design rules, inherited from the semantic layer's discipline:
  - Every hypothesis must be GROUNDED: its target_endpoints must be endpoints
    that recon actually discovered. A hypothesis that references something not
    observed is a hallucination and is dropped.
  - A hypothesis is a QUESTION, not a finding. It carries a prior confidence
    (how plausible before testing), never a verdict. Only the validation
    pipeline turns a confirmed hypothesis into a Finding.
  - Nothing here executes anything. The planner decides what may run, under
    the Rules of Engagement; this module only reasons.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from core.schema import KillChainPhase, MitreTechnique, Severity, WeaknessRef


class HypothesisKind(str, Enum):
    """The class of weakness a hypothesis is about. Web/API focused for
    Phase 1; extend as new attack-surface modules land."""
    BOLA = "broken_object_level_authorization"      # CWE-639
    IDOR = "insecure_direct_object_reference"        # CWE-639
    BROKEN_AUTHZ = "broken_function_level_authz"     # CWE-285
    BROKEN_AUTH = "broken_authentication"            # CWE-287
    INJECTION = "injection"                          # CWE-89 / CWE-77
    XSS = "cross_site_scripting"                     # CWE-79
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"  # CWE-213
    MASS_ASSIGNMENT = "mass_assignment"              # CWE-915
    CSRF = "cross_site_request_forgery"              # CWE-352
    SSRF = "server_side_request_forgery"             # CWE-918
    SECURITY_MISCONFIG = "security_misconfiguration"  # CWE-16


# Technique vocabulary — these strings are what Rules of Engagement list in
# `permitted_techniques`, so the planner can gate a hypothesis by matching its
# technique against the RoE. Keep them aligned with scope.yaml's vocabulary.
class Technique(str, Enum):
    PASSIVE_RECON = "passive_recon"
    PORT_SCAN = "port_scan"
    MISCONFIG_CHECK = "misconfig_check"
    AUTHZ_TESTING = "authz_testing"
    AUTH_TESTING = "auth_testing"
    INJECTION_TESTING = "injection_testing"
    XSS_TESTING = "xss_testing"
    API_TESTING = "api_testing"


@dataclass
class Hypothesis:
    hypothesis_id: str
    kind: HypothesisKind
    title: str

    # Grounding: every path here MUST exist in the ReconResult it came from.
    target_endpoints: list[str]

    # Why the red-team engine believes this, in terms of observed evidence.
    rationale: str
    evidence_refs: list[str] = field(default_factory=list)

    # Grounding for input-level checks (injection/XSS): the specific request
    # parameter names recon observed on the target endpoint(s). An executor
    # only ever probes a parameter that appears here, so it cannot invent an
    # injection point the scanner never saw.
    target_params: list[str] = field(default_factory=list)

    # Classification / scoring.
    cwe: Optional[WeaknessRef] = None
    mitre: Optional[MitreTechnique] = None
    kill_chain_phase: Optional[KillChainPhase] = None
    estimated_severity: Severity = Severity.MEDIUM
    prior_confidence: float = 0.5          # plausibility BEFORE testing, 0..1

    # How the platform would safely check this.
    suggested_technique: Technique = Technique.PASSIVE_RECON
    requires_active_testing: bool = True
    destructive: bool = False

    source: str = "deterministic"          # "deterministic" | "llm"

    def priority(self) -> float:
        """Ranking score: plausibility weighted by impact. Higher runs first."""
        sev_weight = {
            Severity.CRITICAL: 1.0, Severity.HIGH: 0.8, Severity.MEDIUM: 0.55,
            Severity.LOW: 0.3, Severity.INFO: 0.1,
        }[self.estimated_severity]
        return round(self.prior_confidence * sev_weight, 4)


class PlanDecision(str, Enum):
    AUTO = "auto"                      # safe + permitted: the engine runs it
    PENDING_APPROVAL = "pending_approval"  # permitted but needs a human OK
    SKIPPED = "skipped"               # not permitted by the RoE


@dataclass
class PlannedStep:
    hypothesis: Hypothesis
    decision: PlanDecision
    reason: str

    def to_summary(self) -> dict:
        h = self.hypothesis
        return {
            "hypothesis_id": h.hypothesis_id,
            "kind": h.kind.value,
            "title": h.title,
            "targets": h.target_endpoints,
            "technique": h.suggested_technique.value,
            "requires_active_testing": h.requires_active_testing,
            "priority": h.priority(),
            "prior_confidence": h.prior_confidence,
            "estimated_severity": h.estimated_severity.value,
            "decision": self.decision.value,
            "reason": self.reason,
            "rationale": h.rationale,
        }


@dataclass
class AssessmentPlan:
    """The ordered, gated output of a red-team reasoning pass: what the engine
    will run now, what is waiting for approval, and what the RoE ruled out."""
    target: str
    automation_level: str
    steps: list[PlannedStep] = field(default_factory=list)

    @property
    def auto(self) -> list[PlannedStep]:
        return [s for s in self.steps if s.decision == PlanDecision.AUTO]

    @property
    def pending(self) -> list[PlannedStep]:
        return [s for s in self.steps if s.decision == PlanDecision.PENDING_APPROVAL]

    @property
    def skipped(self) -> list[PlannedStep]:
        return [s for s in self.steps if s.decision == PlanDecision.SKIPPED]

    def summary(self) -> dict:
        return {
            "target": self.target,
            "automation_level": self.automation_level,
            "counts": {
                "auto": len(self.auto),
                "pending_approval": len(self.pending),
                "skipped": len(self.skipped),
                "total": len(self.steps),
            },
            "steps": [s.to_summary() for s in self.steps],
        }
