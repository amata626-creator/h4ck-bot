"""
False-positive reduction pipeline (5 layers). Framed as MEASURED
reduction, not elimination.

Layers report `applicable=False` when they have no check for a given
finding type - such layers are excluded from the confidence mean and
from the all-passed/all-failed status gates. "I have nothing to say" is
different from "I checked and it failed."
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from core.schema import EvidenceType, Finding, ValidationLayerResult, ValidationResult


class ValidationLayer(abc.ABC):
    name: str

    @abc.abstractmethod
    async def evaluate(self, finding: Finding) -> ValidationLayerResult:
        ...


class ContextualCorrelationLayer(ValidationLayer):
    """Layer 3 stub - see evidence/contextual_correlation_layer.py for
    the real implementation, which default_pipeline() wires in."""
    name = "contextual_correlation"

    async def evaluate(self, finding: Finding) -> ValidationLayerResult:
        raise NotImplementedError(
            "Use evidence.contextual_correlation_layer.ContextualCorrelationLayer"
        )


class EvidenceCorrelationLayer(ValidationLayer):
    """Layer 5 - require multiple independent evidence types."""
    name = "evidence_correlation"
    MIN_INDEPENDENT_EVIDENCE = 2
    # Documentary evidence records CONTEXT but is not an independent *detection*
    # of the vulnerability, so it must never count toward corroboration. A
    # full-page screenshot of the web root is attached to every web-facing
    # finding after the scan; without this exclusion that homepage photo would
    # silently satisfy the 2-evidence requirement and promote version-inferred
    # CVEs (and other single-signal findings) from NEEDS_REVIEW to VALIDATED -
    # exactly the false-positive inflation this layer exists to prevent.
    _DOCUMENTARY_EVIDENCE = frozenset({EvidenceType.SCREENSHOT})

    async def evaluate(self, finding: Finding) -> ValidationLayerResult:
        distinct_types = {
            e.evidence_type for e in finding.evidence
            if e.evidence_type not in self._DOCUMENTARY_EVIDENCE
        }

        # Deterministic, single-observation findings (missing headers, TLS
        # version, open port) are proven by one authoritative evidence item;
        # there is nothing to cross-correlate. This layer abstains rather
        # than failing them for lacking a second, redundant signal.
        if not finding.requires_corroboration:
            return ValidationLayerResult(
                layer_name=self.name,
                passed=True,
                confidence=1.0,
                notes=(
                    f"{len(distinct_types)} authoritative evidence type(s); "
                    "single-observation finding - independent corroboration not required"
                ),
                applicable=False,
            )

        passed = len(distinct_types) >= self.MIN_INDEPENDENT_EVIDENCE
        confidence = min(1.0, len(distinct_types) / self.MIN_INDEPENDENT_EVIDENCE)
        return ValidationLayerResult(
            layer_name=self.name,
            passed=passed,
            confidence=confidence,
            notes=f"{len(distinct_types)} distinct evidence type(s) present",
            applicable=True,
        )


@dataclass
class ValidationPipeline:
    layers: list[ValidationLayer] = field(default_factory=list)

    async def validate(self, finding: Finding) -> ValidationResult:
        results: list[ValidationLayerResult] = []
        for layer in self.layers:
            try:
                results.append(await layer.evaluate(finding))
            except NotImplementedError:
                results.append(
                    ValidationLayerResult(
                        layer_name=layer.name,
                        passed=False,
                        confidence=0.0,
                        notes="layer not implemented",
                        applicable=True,
                    )
                )
        return ValidationResult(layers=results)


def default_pipeline(llm_client=None, prior_findings=None) -> ValidationPipeline:
    # Lazy imports: avoids circular import at module-load time, since
    # each layer module imports ValidationLayer from this file.
    from evidence.ai_analysis_layer import LocalLlmAnalysisLayer
    from evidence.contextual_correlation_layer import ContextualCorrelationLayer as RealContextualCorrelationLayer
    from evidence.fingerprinting_layer import RealApplicationFingerprintingLayer
    from evidence.response_analysis_layer import RealResponseAnalysisLayer
    from evidence.static_analysis_layer import RealStaticAnalysisLayer

    return ValidationPipeline(
        layers=[
            RealApplicationFingerprintingLayer(),
            RealResponseAnalysisLayer(),
            RealStaticAnalysisLayer(),
            RealContextualCorrelationLayer(prior_findings=prior_findings or []),
            LocalLlmAnalysisLayer(llm_client),
            EvidenceCorrelationLayer(),
        ]
    )
