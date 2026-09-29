"""
SemanticModelBuilder — turn a ReconResult into a SemanticModel.

Uses the local Ollama instance via OllamaClient (from evidence/llm_client.py
so the same local-first constraint applies: nothing leaves the machine).

Three things this file is careful about:

  1. JSON-schema-validated output. The LLM is asked for a specific
     JSON shape, and the response is parsed and validated against it.
     Anything non-conforming is rejected and retried once, then the
     step fails cleanly. No silent fallbacks to "assume it's fine."

  2. Hallucination containment. Every resource the LLM names must
     reference endpoints that appear in the input. A resource that
     names an endpoint the recon didn't discover is dropped (not
     reported as a finding), and the drop is recorded in the model's
     unknowns. This is the same discipline as the validation pipeline:
     the LLM proposes, the deterministic layer constrains.

  3. Explicit unknowns. The prompt asks the model for its unknowns,
     and we keep them on the model so downstream components know what
     the LLM didn't figure out.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from recon.types import ReconResult
from semantic.prompt import build_prompt
from semantic.types import Resource, RoleHint, SemanticModel, Workflow

logger = logging.getLogger("h4ck-bot.semantic")


SYSTEM_PROMPT = """You are a security analyst describing a web application \
so that vulnerability hypotheses can be generated against it.

You will receive:
  - A list of HTTP endpoints the application exposes
  - A sample of HTTP responses (trimmed) so you can see the app's shape
  - Technology and authentication hints gathered during reconnaissance

Your job is to describe what the application IS: what business purpose it \
serves, what resources it manages, what workflows a user goes through, \
what roles exist, and where authorization boundaries likely are.

CRITICAL RULES:
  - Do NOT invent endpoints. Every endpoint you reference must appear \
in the input. If you want to reference an endpoint, quote its path \
exactly as it appeared.
  - If you cannot determine something from the input, say "unknown" or \
leave the field empty. Do NOT guess.
  - Every claim you make must be grounded in something you saw in the \
input. Do not draw on general knowledge about apps like this.
  - Respond with ONLY a JSON object matching the schema below. No prose \
before or after.

Schema:
{
  "app_purpose": "one-paragraph description of what this app does",
  "product_category": "e-commerce | SaaS | social | finance | dev-tools | productivity | other",
  "roles": [
    {"name": "anonymous | user | admin | ...", "evidence": "what in the input suggests this role exists"}
  ],
  "resources": [
    {
      "name": "singular lowercase noun, e.g. 'order'",
      "endpoints": ["exact paths from the input that operate on this resource"],
      "identifier_field": "the field name used to identify a specific instance, e.g. 'id' or 'order_id'",
      "owner_field": "the field name in responses that names the owner, e.g. 'user_id' or 'account_id'; empty if unknown",
      "sensitivity": "low | medium | high | unknown",
      "notes": "brief reasoning for the sensitivity rating"
    }
  ],
  "workflows": [
    {
      "name": "e.g. 'user signup'",
      "steps": ["ordered list of exact endpoint paths"],
      "involves_payment": true | false,
      "notes": "brief"
    }
  ],
  "trust_boundaries": [
    "short description, e.g. 'only authenticated users may read /api/v1/orders/{id}'"
  ],
  "auth_flow_notes": "how authentication appears to work, based on the hints",
  "unknowns": [
    "things you could not determine from the input"
  ]
}
"""


class SemanticModelBuilder:
    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        model: str = "llama3.1",
        timeout: float = 300.0,
        allow_cloud: bool = False,
    ):
        self.base_url = ollama_base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.allow_cloud = allow_cloud

        # A ":cloud" suffix in Ollama's model name means the request is
        # proxied to a hosted provider. That's a real data flow: the
        # recon (endpoint names, response shapes) leaves this machine.
        # Refuse unless the caller explicitly opted in.
        self._is_cloud = ":cloud" in model.lower() or model.endswith("-cloud")
        if self._is_cloud and not allow_cloud:
            raise ValueError(
                f"model '{model}' routes to an external provider, but "
                f"allow_cloud is False. Re-run with --allow-cloud if you "
                f"have confirmed that sending recon data for this target "
                f"to a third-party is acceptable."
            )
        if self._is_cloud:
            logger.warning(
                "semantic: model %s is a CLOUD model - recon data for this "
                "target will be sent to an external provider", model,
            )

    async def build(self, recon: ReconResult) -> SemanticModel:
        user_prompt = build_prompt(recon)
        est_tokens = len(user_prompt) // 4
        logger.info(
            "semantic: prompt is %d chars (~%d tokens), model=%s, timeout=%ss",
            len(user_prompt), est_tokens, self.model, self.timeout,
        )

        raw = await self._chat(SYSTEM_PROMPT, user_prompt)
        parsed = self._parse_json(raw)

        if parsed is None:
            # Retry once with an explicit error message
            logger.warning("semantic: first response was not valid JSON, retrying once")
            raw = await self._chat(
                SYSTEM_PROMPT,
                user_prompt + "\n\nYour previous response was not valid JSON. "
                "Respond with ONLY a JSON object. No prose, no markdown fences.",
            )
            parsed = self._parse_json(raw)

        if parsed is None:
            raise RuntimeError(
                "semantic model: LLM did not produce valid JSON after retry. "
                f"First 500 chars of last response: {raw[:500]!r}"
            )

        model = self._to_model(recon, parsed, raw)
        self._validate_against_recon(model, recon)
        return model

    async def _chat(self, system: str, user: str) -> str:
        import time
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "stream": False,
            "format": "json",
            "keep_alive": "10m",
            "options": {"temperature": 0.1, "num_ctx": 8192},
        }
        t0 = time.monotonic()
        logger.info(
            "semantic: sending to %s (model=%s, timeout=%ss, is_cloud=%s)",
            self.base_url, self.model, self.timeout, self._is_cloud,
        )
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.ReadTimeout:
            elapsed = time.monotonic() - t0
            raise RuntimeError(
                f"LLM call timed out after {elapsed:.0f}s. Model '{self.model}' "
                f"did not finish within {self.timeout:.0f}s. "
                f"This usually means the model is too slow for this prompt on "
                f"this hardware. Try: (a) a smaller model such as "
                f"'qwen2.5:3b', (b) --allow-cloud with a ':cloud' model, or "
                f"(c) raise --timeout if you know the model needs longer."
            )
        except httpx.ConnectError as e:
            raise RuntimeError(
                f"Could not connect to Ollama at {self.base_url}. "
                f"Is 'ollama serve' running? ({e!r})"
            )
        elapsed = time.monotonic() - t0
        logger.info("semantic: model responded in %.1fs", elapsed)
        return data["message"]["content"]

    def _parse_json(self, raw: str) -> dict[str, Any] | None:
        """LLMs sometimes wrap JSON in fences. Try strict, then lenient."""
        text = raw.strip()
        try:
            obj = json.loads(text)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass
        # Strip common fence shapes
        m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        # Last resort: first { to last }
        a, b = text.find("{"), text.rfind("}")
        if 0 <= a < b:
            try:
                return json.loads(text[a : b + 1])
            except json.JSONDecodeError:
                pass
        return None

    def _to_model(self, recon: ReconResult, parsed: dict, raw: str) -> SemanticModel:
        def s(v: Any, default: str = "") -> str:
            return str(v) if isinstance(v, (str, int, float)) else default

        def ls(v: Any) -> list[str]:
            if isinstance(v, list):
                return [str(x) for x in v if isinstance(x, (str, int, float))]
            return []

        roles: list[RoleHint] = []
        for r in parsed.get("roles", []) or []:
            if isinstance(r, dict) and r.get("name"):
                roles.append(RoleHint(
                    name=s(r.get("name")),
                    evidence=s(r.get("evidence")),
                ))

        resources: list[Resource] = []
        for r in parsed.get("resources", []) or []:
            if not isinstance(r, dict) or not r.get("name"):
                continue
            resources.append(Resource(
                name=s(r.get("name")).lower(),
                endpoints=ls(r.get("endpoints")),
                identifier_field=s(r.get("identifier_field")),
                owner_field=s(r.get("owner_field")),
                sensitivity=s(r.get("sensitivity"), "unknown"),
                notes=s(r.get("notes")),
            ))

        workflows: list[Workflow] = []
        for w in parsed.get("workflows", []) or []:
            if not isinstance(w, dict) or not w.get("name"):
                continue
            workflows.append(Workflow(
                name=s(w.get("name")),
                steps=ls(w.get("steps")),
                involves_payment=bool(w.get("involves_payment", False)),
                notes=s(w.get("notes")),
            ))

        return SemanticModel(
            target=recon.target,
            app_purpose=s(parsed.get("app_purpose")),
            product_category=s(parsed.get("product_category")),
            roles=roles,
            resources=resources,
            workflows=workflows,
            trust_boundaries=ls(parsed.get("trust_boundaries")),
            auth_flow_notes=s(parsed.get("auth_flow_notes")),
            unknowns=ls(parsed.get("unknowns")),
            model_name=self.model,
            prompt_tokens_estimate=len(raw),  # rough; only for display
            raw_response=raw,
        )

    def _validate_against_recon(self, model: SemanticModel, recon: ReconResult) -> None:
        """
        Drop resources/workflows that reference endpoints the recon
        didn't actually discover. Record the drops as new unknowns so
        the LLM's hallucination is visible rather than silently removed.
        """
        discovered = {ep.path for ep in recon.endpoints}
        dropped: list[str] = []

        for r in model.resources:
            valid_eps = [e for e in r.endpoints if e in discovered]
            invalid = [e for e in r.endpoints if e not in discovered]
            if invalid:
                dropped.append(
                    f"resource '{r.name}': endpoint(s) not in recon: {invalid}"
                )
            r.endpoints = valid_eps

        for w in model.workflows:
            valid_steps = [s for s in w.steps if s in discovered]
            invalid = [s for s in w.steps if s not in discovered]
            if invalid:
                dropped.append(
                    f"workflow '{w.name}': step(s) not in recon: {invalid}"
                )
            w.steps = valid_steps

        # Drop resources that ended up with no valid endpoints at all
        before = len(model.resources)
        model.resources = [r for r in model.resources if r.endpoints]
        after = len(model.resources)
        if before != after:
            dropped.append(
                f"dropped {before - after} resource(s) with no endpoints in recon"
            )

        model.unknowns.extend(f"[auto] {d}" for d in dropped)

        if dropped:
            logger.info(
                "semantic: dropped %d hallucinated references", len(dropped)
            )
