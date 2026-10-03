"""
Real implementation of Layer 3 - contextual correlation.

Cross-references the finding against the asset it was found on and
against other findings already recorded on the same asset in this
assessment run. The idea: a finding that contradicts everything else we
know about the asset is more likely to be a false positive; a finding
that fits the pattern (same class of bug elsewhere on the same asset,
same framework, same misconfiguration family) is more likely real.

This layer deliberately does NOT re-fetch anything. It correlates
against:
  - finding.asset.metadata (populated by discovery_module: framework,
    server, tech stack, etc.)
  - the assessment's existing finding list (passed in at construction -
    see ContextualCorrelationLayer.__init__)

If neither source has anything to say about this finding type, the
layer returns applicable=False rather than guessing.

This replaces the ContextualCorrelationLayer stub in validation_pipeline.py.
"""

from __future__ import annotations

from core.schema import Asset, Finding, ValidationLayerResult
from evidence.validation_pipeline import ValidationLayer


# Framework -> whether object-level authorization is expected to be
# handled by the framework or has to be written by hand. Used only as a
# weak prior: a hand-rolled authz layer in a framework that doesn't do
# it for you is a more plausible BOLA/IDOR target than one where the
# framework enforces it. This is a heuristic, not a verdict.
FRAMEWORK_AUTHZ_DEFAULT = {
    "django": "framework_handles",        # Django ORM + permissions are opt-in but pervasive
    "rails": "framework_handles",         # strong params + cancan/pundit common
    "laravel": "framework_handles",
    "spring": "framework_handles",        # @PreAuthorize etc.
    "express": "hand_rolled",             # no built-in authz
    "flask": "hand_rolled",
    "fastapi": "hand_rolled",
    "gin": "hand_rolled",
    "aspnet": "framework_handles",
}


class ContextualCorrelationLayer(ValidationLayer):
    """
    Correlates a finding against other findings on the same asset.

    `prior_findings` is the list of findings already validated in this
    assessment run, on any asset. The layer picks out the ones on the
    same asset (by asset_id) and uses them as context.

    ADVISORY: this layer produces a supportive, not-decisive signal
    (capped at 0.8 by design), so its result is marked advisory=True -
    it informs the report and nudges confidence but is EXCLUDED from the
    status gate. A weak contextual prior can neither validate a finding
    on its own nor block one the dispositive deterministic layers
    (fingerprinting, response-analysis, evidence-correlation) confirm.
    """

    name = "contextual_correlation"

    def __init__(self, prior_findings: list[Finding] | None = None):
        self.prior_findings = prior_findings or []

    def set_prior_findings(self, findings: list[Finding]) -> None:
        """The orchestrator calls this as findings accumulate, so later
        findings in a run can correlate against earlier ones."""
        self.prior_findings = findings

    async def evaluate(self, finding: Finding) -> ValidationLayerResult:
        asset = finding.asset
        same_asset = [
            f for f in self.prior_findings
            if f.asset.asset_id == asset.asset_id and f.finding_id != finding.finding_id
        ]

        notes: list[str] = []
        signals: list[float] = []  # each signal is a confidence contribution in [0, 1]

        # Signal 1: sibling findings of the same weakness class on the
        # same asset. If the same CWE shows up more than once on one
        # asset, the second occurrence is more likely real (patterns
        # repeat) - but only a weak prior.
        same_cwe_siblings = [f for f in same_asset if f.cwe.cwe_id == finding.cwe.cwe_id]
        if same_cwe_siblings:
            signals.append(0.75)
            notes.append(
                f"{len(same_cwe_siblings)} sibling finding(s) with the same {finding.cwe.cwe_id} "
                f"on this asset - consistent pattern"
            )

        # Signal 2: sibling findings in the same kill-chain phase on the
        # same asset. A BOLA + an IDOR + an auth bypass on one asset is a
        # coherent story; a lone finding with no neighbours is weaker.
        if finding.kill_chain_phase is not None:
            same_phase = [f for f in same_asset if f.kill_chain_phase == finding.kill_chain_phase]
            if same_phase:
                signals.append(0.65)
                notes.append(
                    f"{len(same_phase)} sibling finding(s) in kill-chain phase "
                    f"'{finding.kill_chain_phase.value}' on this asset"
                )

        # Signal 3: framework authz expectation from asset metadata.
        # Only meaningful for authz-class CWEs (BOLA/IDOR/broken access).
        authz_cwes = {"CWE-639", "CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-566"}
        framework = (asset.metadata or {}).get("framework", "").lower().strip()
        if finding.cwe.cwe_id in authz_cwes and framework:
            expectation = FRAMEWORK_AUTHZ_DEFAULT.get(framework)
            if expectation == "hand_rolled":
                signals.append(0.7)
                notes.append(
                    f"asset framework '{framework}' has no built-in object-level authz - "
                    f"a {finding.cwe.cwe_id} here is plausible"
                )
            elif expectation == "framework_handles":
                signals.append(0.4)
                notes.append(
                    f"asset framework '{framework}' normally handles object-level authz - "
                    f"a {finding.cwe.cwe_id} here would be a misconfiguration, less common but possible"
                )

        # Signal 4: asset is internet-facing (metadata flag from discovery).
        exposure = (asset.metadata or {}).get("exposure", "").lower()
        if exposure in ("internet", "public"):
            signals.append(0.6)
            notes.append("asset is internet-facing - matches expected exposure for this finding class")

        if not signals:
            # Nothing in our context store speaks to this finding. Be
            # honest - don't force a pass or a fail.
            return ValidationLayerResult(
                layer_name=self.name,
                passed=True,
                confidence=0.0,
                notes="no contextual signal available for this finding type / asset",
                applicable=False,
                advisory=True,
            )

        confidence = sum(signals) / len(signals)
        # Correlated context is supportive, not decisive: cap at 0.8 so a
        # single strong signal can't push a finding to VALIDATED on its
        # own (the 0.85 threshold in ValidationResult.status still
        # requires the other applicable layers to agree).
        confidence = min(confidence, 0.8)
        passed = confidence >= 0.5

        return ValidationLayerResult(
            layer_name=self.name,
            passed=passed,
            confidence=confidence,
            notes="; ".join(notes),
            applicable=True,
            advisory=True,
        )
