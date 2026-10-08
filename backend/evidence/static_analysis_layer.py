"""
Gating layer for static-analysis findings (mobile APK/IPA, and any other
at-rest artifact inspection).

A static finding is proven by one authoritative observation: the manifest
literally declares `android:debuggable="true"`, the Info.plist literally sets
`NSAllowsArbitraryLoads = true`, a secret literally appears in a packaged
file. There is no HTTP response to analyse, so the HTTP-oriented layers
abstain. This layer provides the deterministic gate those findings need: it
confirms the collected evidence actually contains the exact fact the finding
asserts.

Contract: a static finding tags each substantiating evidence item with
`metadata["static_claim"] = "<exact token that must appear in the preview>"`.
This layer is applicable only to findings that carry at least one such
tagged evidence item; for everything else (all the web findings) it returns
applicable=False and therefore does not affect their verdict.
"""

from __future__ import annotations

from core.schema import Finding, ValidationLayerResult
from evidence.validation_pipeline import ValidationLayer


class RealStaticAnalysisLayer(ValidationLayer):
    name = "static_analysis"

    async def evaluate(self, finding: Finding) -> ValidationLayerResult:
        tagged = [
            e for e in finding.evidence
            if (e.metadata or {}).get("static_claim")
        ]
        if not tagged:
            # Not a static finding — no opinion, abstain.
            return ValidationLayerResult(
                layer_name=self.name,
                passed=True,
                confidence=0.0,
                notes="no static-analysis evidence on this finding",
                applicable=False,
            )

        substantiated = 0
        notes = []
        for e in tagged:
            claim = str(e.metadata.get("static_claim", ""))
            preview = e.metadata.get("preview", e.description) or ""
            if claim and claim in preview:
                substantiated += 1
            else:
                notes.append(f"claim not found in its evidence: {claim!r}")

        passed = substantiated == len(tagged)
        confidence = substantiated / len(tagged) if tagged else 0.0
        if passed:
            notes.append(
                f"{substantiated}/{len(tagged)} claim(s) literally substantiated by the packaged artifact"
            )
        return ValidationLayerResult(
            layer_name=self.name,
            passed=passed,
            confidence=confidence,
            notes="; ".join(notes),
            applicable=True,
        )
