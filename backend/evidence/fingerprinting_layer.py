"""
Real implementation of Layer 1 - application fingerprinting.

Checks whether the response evidence looks like genuine, direct
application behavior, or whether it's actually a WAF block page, a CDN
edge response, or a SPA's generic fallback route masquerading as a hit.
A finding built on top of a WAF interstitial or a client-side-routed
"page not found" is a classic source of false positives - this layer
exists specifically to catch that before a finding is trusted.

This replaces the ApplicationFingerprintingLayer stub in
validation_pipeline.py. Like RealResponseAnalysisLayer, it reads from
Evidence.metadata['preview'] (populated by scanner modules) rather than
re-fetching the target - this layer judges the evidence already
collected, it does not make new network calls.
"""

from __future__ import annotations

import re

from core.schema import EvidenceType, Finding, ValidationLayerResult
from evidence.validation_pipeline import ValidationLayer

# Header/body signatures that indicate the response came from a WAF/CDN
# edge, not the origin application directly. Not exhaustive - extend as
# your team encounters more.
WAF_CDN_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri WAF",
    "x-akamai-transformed": "Akamai",
    "server: cloudflare": "Cloudflare",
    "server: akamaighost": "Akamai",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-iinfo": "Incapsula",
    "x-cdn": "generic CDN",
}

# Body-content signatures for WAF block pages / generic error pages that
# often return HTTP 200 or a misleading status while not reflecting real
# application state.
GENERIC_PAGE_SIGNATURES = [
    "access denied",
    "request blocked",
    "attention required",  # common Cloudflare interstitial phrase
    "this website is using a security service",
    "404 not found",  # if this appears in a body claimed to be a real hit, that's a contradiction
]


class RealApplicationFingerprintingLayer(ValidationLayer):
    name = "fingerprinting"

    async def evaluate(self, finding: Finding) -> ValidationLayerResult:
        # Static-analysis findings aren't HTTP responses — WAF/CDN
        # fingerprinting is meaningless for a manifest fact. Abstain and let
        # the static_analysis layer gate them.
        if any((e.metadata or {}).get("static_claim") for e in finding.evidence):
            return ValidationLayerResult(
                layer_name=self.name, passed=True, confidence=0.0,
                notes="static finding - not an HTTP response to fingerprint", applicable=False,
            )
        relevant = [
            e for e in finding.evidence
            if e.evidence_type in (EvidenceType.RESPONSE_HEADERS, EvidenceType.HTTP_TRANSACTION, EvidenceType.RAW_OUTPUT)
        ]
        if not relevant:
            return ValidationLayerResult(
                layer_name=self.name,
                passed=False,
                confidence=0.0,
                notes="no response evidence available to fingerprint",
                applicable=True,
            )

        notes = []
        waf_cdn_hit = None
        generic_page_hit = None

        for e in relevant:
            preview = (e.metadata.get("preview", e.description) or "").lower()

            for sig, provider in WAF_CDN_SIGNATURES.items():
                if sig in preview:
                    waf_cdn_hit = provider
                    break

            for phrase in GENERIC_PAGE_SIGNATURES:
                if phrase in preview:
                    generic_page_hit = phrase
                    break

            if waf_cdn_hit or generic_page_hit:
                break

        if waf_cdn_hit:
            notes.append(
                f"response appears to pass through {waf_cdn_hit} - "
                "headers/behavior may reflect the edge, not the origin app"
            )
            # Not an automatic fail - a WAF being present doesn't invalidate
            # a finding, but it lowers confidence since we can't be certain
            # we observed origin behavior directly.
            return ValidationLayerResult(
                layer_name=self.name,
                passed=True,
                confidence=0.5,
                notes="; ".join(notes),
            )

        if generic_page_hit:
            notes.append(f"response body matches a generic/block-page signature: '{generic_page_hit}'")
            return ValidationLayerResult(
                layer_name=self.name,
                passed=False,
                confidence=0.1,
                notes="; ".join(notes),
            )

        # No WAF/CDN signature and no generic-page signature - evidence
        # looks like direct, genuine application response.
        notes.append("no WAF/CDN signature or generic-page pattern detected - response appears to be direct application behavior")
        return ValidationLayerResult(
            layer_name=self.name,
            passed=True,
            confidence=0.9,
            notes="; ".join(notes),
        )
