"""
Real implementation of Layer 2 - response analysis.

Checks that the evidence actually, internally, supports the claim the
finding is making - status codes, header presence/absence, and content
signatures match what the finding's title/description assert. This is
deliberately narrow: it does NOT decide whether the underlying issue is
"bad" (that's a severity/policy question, already encoded in CVSS at
finding-creation time) - it only checks that the evidence is internally
consistent and not contradicting itself.

When this layer has no check for a finding type, it returns
applicable=False (not passed=False) so it doesn't drag down the overall
confidence or force a FALSE_POSITIVE verdict. "I have nothing to say"
is different from "I checked and it failed."

This replaces the ResponseAnalysisLayer stub in validation_pipeline.py.
"""

from __future__ import annotations

import re

from core.schema import EvidenceType, Finding, ValidationLayerResult
from evidence.validation_pipeline import ValidationLayer


class RealResponseAnalysisLayer(ValidationLayer):
    name = "response_analysis"

    async def evaluate(self, finding: Finding) -> ValidationLayerResult:
        relevant = [
            e for e in finding.evidence
            if e.evidence_type in (EvidenceType.RESPONSE_HEADERS, EvidenceType.HTTP_TRANSACTION, EvidenceType.RAW_OUTPUT)
        ]
        if not relevant:
            return ValidationLayerResult(
                layer_name=self.name,
                passed=False,
                confidence=0.0,
                notes="no HTTP/response evidence attached to analyze",
                applicable=True,
            )

        # We don't have the raw bytes here (Evidence only stores a hash +
        # storage_ref by design - the actual content lives in the evidence
        # store). For this reference implementation, we rely on
        # Evidence.description and metadata['preview'], which the modules
        # populate with human-readable summaries. A production evidence
        # store would let this layer fetch storage_ref and re-parse the
        # real bytes for a stronger check.
        checks_run = 0
        checks_passed = 0
        notes = []

        for e in relevant:
            preview = e.metadata.get("preview", e.description) or ""

            if "missing security header" in finding.title.lower() or finding.cwe.cwe_id in ("CWE-319", "CWE-1021", "CWE-16"):
                checks_run += 1
                status_match = re.search(r"status:\s*(\d+)", preview)
                if status_match and status_match.group(1) == "200" and "missing_headers" in preview:
                    checks_passed += 1
                    notes.append("response succeeded (200) and evidence explicitly lists missing headers")
                else:
                    notes.append("could not confirm 200 status + explicit missing-header list in evidence")

            elif "exposed sensitive path" in finding.title.lower() or finding.cwe.cwe_id == "CWE-538":
                checks_run += 1
                status_match = re.search(r"status:\s*(\d+)", preview)
                if status_match and status_match.group(1) == "200":
                    checks_passed += 1
                    notes.append("path returned 200 as claimed")
                else:
                    notes.append("evidence does not confirm a 200 response for the claimed exposed path")

            elif finding.cwe.cwe_id == "CWE-295":
                checks_run += 1
                if "issues:" in preview and "[]" not in preview:
                    checks_passed += 1
                    notes.append("TLS evidence contains a non-empty issues list matching the claim")
                else:
                    notes.append("TLS evidence does not clearly list the claimed issue(s)")

            else:
                # No specific check written for this finding type yet.
                continue

        if checks_run == 0:
            # Not a failure - this layer simply has no opinion on this
            # finding type. Mark non-applicable so it's excluded from the
            # confidence mean and the all-passed/all-failed gates.
            return ValidationLayerResult(
                layer_name=self.name,
                passed=True,
                confidence=0.0,
                notes="no response-analysis check implemented for this finding type",
                applicable=False,
            )

        passed = checks_passed == checks_run
        confidence = checks_passed / checks_run

        return ValidationLayerResult(
            layer_name=self.name,
            passed=passed,
            confidence=confidence,
            notes="; ".join(notes),
            applicable=True,
        )
