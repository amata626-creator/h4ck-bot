"""
Core data model for H4CK-B0T.

Every scanner module, the validation pipeline, and the report generator
speak this schema and nothing else.
"""

from __future__ import annotations

import uuid
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class FindingKind(str, Enum):
    """
    High-level category of a finding. Independent of severity: a finding
    can be INFORMATIONAL and still severity=INFO, or a VULNERABILITY at
    CRITICAL. Used for grouping in reports/UI and for filtering in
    demo runners.

    Modules should set this explicitly at construction. Scanner modules
    that report an exploitable flaw use VULNERABILITY; recon/exposure
    modules that report "this exists" without a flaw use INFORMATIONAL.
    """
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    EXPOSURE = "exposure"
    WEAKNESS = "weakness"
    INFORMATIONAL = "informational"


class FindingStatus(str, Enum):
    POTENTIAL = "potential"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class KillChainPhase(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class AutomationLevel(str, Enum):
    ASSISTED = "assisted"
    SEMI_AUTONOMOUS = "semi_autonomous"
    AUTONOMOUS = "autonomous"


@dataclass(frozen=True)
class CvssScore:
    """Compute base_score with a real CVSS library (`pip install cvss`), don't hand-roll it."""
    base_score: float
    vector: str
    version: str = "3.1"

    @property
    def severity(self) -> Severity:
        return Severity.from_cvss(self.base_score)


@dataclass(frozen=True)
class WeaknessRef:
    cwe_id: str
    name: str


@dataclass(frozen=True)
class VulnerabilityRef:
    cve_id: str
    description: Optional[str] = None


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    tactic: str
    name: str


class EvidenceType(str, Enum):
    SCREENSHOT = "screenshot"
    HTTP_TRANSACTION = "http_transaction"
    RESPONSE_HEADERS = "response_headers"
    BEHAVIORAL_DIFF = "behavioral_diff"
    POC_REFERENCE = "poc_reference"
    RAW_OUTPUT = "raw_output"


@dataclass
class Evidence:
    evidence_id: str
    evidence_type: EvidenceType
    captured_at: datetime
    content_hash: str
    storage_ref: str
    description: str = ""
    metadata: dict = field(default_factory=dict)

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def new(
        cls,
        evidence_type: EvidenceType,
        raw_bytes: bytes,
        storage_ref: str,
        description: str = "",
        metadata: Optional[dict] = None,
    ) -> "Evidence":
        return cls(
            evidence_id=str(uuid.uuid4()),
            evidence_type=evidence_type,
            captured_at=datetime.now(timezone.utc),
            content_hash=cls.hash_bytes(raw_bytes),
            storage_ref=storage_ref,
            description=description,
            metadata=metadata or {},
        )


@dataclass
class ValidationLayerResult:
    """
    Result from a single validation layer.

    `applicable` distinguishes "this layer has nothing to say about this
    finding type" from "this layer evaluated and the finding failed".
    Non-applicable layers are excluded from the overall confidence mean
    and from the all-passed / all-failed gates that determine status.

    Layers MUST set applicable=False explicitly when they have no check
    for the finding type. The default is True (a layer that ran a check
    and produced a verdict is, by definition, applicable).

    `advisory` marks a layer whose verdict INFORMS but does not GATE: it
    is shown in the report and can lower confidence, but it cannot by
    itself block a VALIDATED status or force a FALSE_POSITIVE. The
    non-deterministic AI layer is advisory, so a flaky LLM opinion can't
    veto a finding that every deterministic layer confirms.
    """
    layer_name: str
    passed: bool
    confidence: float
    notes: str = ""
    applicable: bool = True
    advisory: bool = False


@dataclass
class ValidationResult:
    layers: list[ValidationLayerResult] = field(default_factory=list)

    @property
    def applicable_layers(self) -> list[ValidationLayerResult]:
        return [l for l in self.layers if l.applicable]

    @property
    def gating_layers(self) -> list[ValidationLayerResult]:
        """Applicable layers that actually decide status - deterministic
        layers only. Advisory (e.g. AI) layers are excluded from the gate."""
        return [l for l in self.layers if l.applicable and not l.advisory]

    @property
    def overall_confidence(self) -> float:
        # Confidence that drives the VALIDATED threshold: the gating
        # (deterministic) layers. Falls back to applicable layers only if
        # there are no gating layers at all, so display is never empty.
        basis = self.gating_layers or self.applicable_layers
        if not basis:
            return 0.0
        return sum(l.confidence for l in basis) / len(basis)

    @property
    def status(self) -> FindingStatus:
        if not self.layers:
            return FindingStatus.POTENTIAL

        if not self.applicable_layers:
            # Nothing could evaluate this finding - not validated, but not a
            # false positive either.
            return FindingStatus.POTENTIAL

        gating = self.gating_layers
        if not gating:
            # Only advisory opinions exist; no deterministic layer gated it.
            return FindingStatus.NEEDS_REVIEW

        passed = [l for l in gating if l.passed]
        failed = [l for l in gating if not l.passed]

        if len(passed) == len(gating) and self.overall_confidence >= 0.85:
            return FindingStatus.VALIDATED
        if len(failed) == len(gating):
            return FindingStatus.FALSE_POSITIVE
        return FindingStatus.NEEDS_REVIEW


@dataclass
class Asset:
    asset_id: str
    name: str
    asset_type: str
    scope_approved: bool
    metadata: dict = field(default_factory=dict)


@dataclass
class Finding:
    finding_id: str
    title: str
    description: str
    asset: Asset
    module_source: str

    finding_kind: FindingKind
    cvss: CvssScore
    cwe: WeaknessRef
    cve_refs: list[VulnerabilityRef] = field(default_factory=list)
    mitre_techniques: list[MitreTechnique] = field(default_factory=list)
    kill_chain_phase: Optional[KillChainPhase] = None

    status: FindingStatus = FindingStatus.POTENTIAL
    validation: ValidationResult = field(default_factory=ValidationResult)
    evidence: list[Evidence] = field(default_factory=list)

    remediation: str = ""
    business_impact: str = ""
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    attack_path_id: Optional[str] = None
    owasp_category: str = ""  # e.g. "A03:2021-Injection" - empty if not OWASP-mapped

    # Whether this finding's claim needs independent corroboration (>=2
    # distinct evidence types) to be VALIDATED. True by default - most
    # findings are inferential and benefit from a second signal. A module
    # sets this False only when a SINGLE authoritative observation is
    # dispositive on its own: a security header is literally present or
    # absent in the captured response, a negotiated TLS version is a fact,
    # an open port is observed directly. For those, evidence_correlation
    # has nothing meaningful to cross-check and should not gate the finding.
    # Inferential findings (BOLA/IDOR, injection, "possible reflected XSS")
    # keep this True: a single 200 or a single reflection could be
    # coincidence, so corroboration genuinely matters.
    requires_corroboration: bool = True

    @property
    def severity(self) -> Severity:
        return self.cvss.severity

    def add_evidence(self, evidence: Evidence) -> None:
        self.evidence.append(evidence)

    def is_reportable(self) -> bool:
        """Only validated / needs-review findings WITH evidence reach a report."""
        if self.status == FindingStatus.FALSE_POSITIVE:
            return False
        if self.status == FindingStatus.POTENTIAL:
            return False
        return len(self.evidence) > 0


@dataclass
class AttackPath:
    attack_path_id: str
    title: str
    finding_ids: list[str]
    kill_chain_phases: list[KillChainPhase]
    narrative: str
    overall_severity: Severity
