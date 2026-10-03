"""
Wires OllamaClient into the ValidationLayer interface from
validation_pipeline.py. This replaces the AiAssistedAnalysisLayer stub -
import this one instead of the NotImplementedError version once you have
Ollama running locally.
"""

from __future__ import annotations

from core.schema import Finding, ValidationLayerResult
from evidence.llm_client import OllamaClient
from evidence.validation_pipeline import ValidationLayer


class LocalLlmAnalysisLayer(ValidationLayer):
    """Layer 4 of the FP-reduction pipeline - local LLM review of
    already-collected evidence. Advisory only: this layer's confidence
    feeds the aggregate score, but ValidationResult.status still requires
    every layer to pass before a finding reaches VALIDATED, so a single
    LLM opinion can never validate a finding alone."""

    name = "ai_assisted_analysis"

    def __init__(self, client: OllamaClient | None = None):
        self.client = client or OllamaClient()

    async def evaluate(self, finding: Finding) -> ValidationLayerResult:
        if not finding.evidence:
            return ValidationLayerResult(
                layer_name=self.name,
                passed=False,
                confidence=0.0,
                notes="no evidence attached to review",
            )

        evidence_summaries = [
            {
                "evidence_id": e.evidence_id,
                "evidence_type": e.evidence_type.value,
                "description": e.description,
                "content_preview": e.metadata.get("preview", e.description),
            }
            for e in finding.evidence
        ]

        try:
            verdict = await self.client.analyze_evidence(
                finding_title=finding.title,
                finding_description=finding.description,
                evidence_summaries=evidence_summaries,
            )
        except Exception as exc:  # noqa: BLE001 - Ollama down, network, etc.
            return ValidationLayerResult(
                layer_name=self.name,
                passed=False,
                confidence=0.0,
                notes=f"LLM analysis unavailable: {exc}",
            )

        note = verdict.reasoning
        if not verdict.grounded:
            note = f"[ungrounded - discounted] {note}"

        return ValidationLayerResult(
            layer_name=self.name,
            passed=verdict.supported and verdict.grounded,
            confidence=verdict.confidence,
            notes=note,
        )
