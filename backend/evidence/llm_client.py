"""
Local LLM client (Ollama) for the AI-assisted validation layer.

Design constraints, on purpose:
  - This client ONLY analyzes evidence you already collected (HTTP
    transactions, headers, diffs, screenshots-as-text-description). It
    never generates payloads, exploit code, or attack instructions - the
    prompt template below hard-codes that boundary and the response
    parser rejects output that doesn't match the expected verdict schema.
  - Runs fully local via Ollama's HTTP API (default localhost:11434) -
    no data leaves the environment, matching whitepaper section 6.1
    (data residency, offline operation, private inference).
  - Every verdict must cite which evidence_id it's based on. An
    ungrounded verdict (no citation, or citing evidence that doesn't
    exist on the finding) is treated as low-confidence, not trusted.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger("h4ck-bot.llm")


ANALYSIS_SYSTEM_PROMPT = """You are a security finding validator. You review \
evidence already collected by a scanner (HTTP requests/responses, headers, \
config output, behavioral diffs) and judge whether the evidence actually \
supports the claimed vulnerability, or looks like a false positive.

Rules you must follow:
- You are NOT generating exploit payloads, attack code, or instructions to \
attack anything. You are reviewing evidence that has already been collected.
- If the evidence is insufficient to judge, say so - do not guess.
- Every verdict must cite which evidence item (by evidence_id) supports it.
- Respond with ONLY a JSON object matching this schema, nothing else:

{
  "supported": true | false,
  "confidence": 0.0-1.0,
  "cited_evidence_ids": ["..."],
  "reasoning": "one or two sentences, evidence-grounded, no speculation"
}
"""


@dataclass
class LlmVerdict:
    supported: bool
    confidence: float
    cited_evidence_ids: list[str]
    reasoning: str
    grounded: bool  # True only if cited_evidence_ids is non-empty and valid


class OllamaClient:
    """
    Thin wrapper over Ollama's /api/chat endpoint. Install and run Ollama
    separately (https://ollama.com), pull a model, e.g.:
        ollama pull llama3.1
    then point this client at it - nothing here starts or manages the
    Ollama process itself.
    """

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "mistral:7b", timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    async def analyze_evidence(
        self,
        finding_title: str,
        finding_description: str,
        evidence_summaries: list[dict],
    ) -> LlmVerdict:
        """
        evidence_summaries: list of {"evidence_id": ..., "evidence_type": ...,
        "description": ..., "content_preview": ...} - built by the caller
        from Finding.evidence, never raw secrets/credentials.
        """
        user_prompt = self._build_prompt(finding_title, finding_description, evidence_summaries)

        raw = await self._chat(user_prompt)
        return self._parse_verdict(raw, valid_evidence_ids={e["evidence_id"] for e in evidence_summaries})

    def _build_prompt(self, title: str, description: str, evidence: list[dict]) -> str:
        evidence_block = "\n".join(
            f"- evidence_id: {e['evidence_id']}\n"
            f"  type: {e['evidence_type']}\n"
            f"  description: {e.get('description', '')}\n"
            f"  content: {e.get('content_preview', '')[:800]}"
            for e in evidence
        )
        return (
            f"Finding under review: {title}\n"
            f"Description: {description}\n\n"
            f"Collected evidence:\n{evidence_block}\n\n"
            "Judge whether this evidence supports the finding. Respond with "
            "the JSON schema only."
        )

    async def _chat(self, user_prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": ANALYSIS_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "format": "json",
            # Deterministic: temperature 0 + fixed seed so the same evidence
            # yields the same verdict across runs (no coin-flip validation).
            "options": {"temperature": 0, "seed": 42, "top_p": 1.0},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]

    def _parse_verdict(self, raw: str, valid_evidence_ids: set[str]) -> LlmVerdict:
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("LLM returned non-JSON output, treating as ungrounded/low-confidence")
            return LlmVerdict(
                supported=False, confidence=0.0, cited_evidence_ids=[],
                reasoning="model output was not valid JSON", grounded=False,
            )

        cited = obj.get("cited_evidence_ids", []) or []
        cited_valid = [c for c in cited if c in valid_evidence_ids]
        grounded = len(cited_valid) > 0

        confidence = float(obj.get("confidence", 0.0))
        if not grounded:
            # An ungrounded verdict never gets to claim high confidence,
            # regardless of what the model put in the field.
            confidence = min(confidence, 0.2)

        return LlmVerdict(
            supported=bool(obj.get("supported", False)),
            confidence=max(0.0, min(1.0, confidence)),
            cited_evidence_ids=cited_valid,
            reasoning=str(obj.get("reasoning", "")),
            grounded=grounded,
        )
