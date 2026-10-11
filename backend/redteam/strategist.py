"""
LlmStrategist — the reasoning brain of the adaptive red-team loop.

After each round of probes, the orchestrator hands the strategist what has been
CONFIRMED so far, the real observed surface, and what has already been tried.
The strategist (a local LLM) reasons like a pentester deciding the next move —
"BOLA worked on /invoices, try the same ownership pattern on /statements";
"that error-based SQLi parameter is worth a blind check on the sibling endpoint"
— and returns the next batch of hypotheses to test.

Safety is structural, not trusted-to-the-model:
  - The model may ONLY reference endpoints/params from the observed surface we
    give it; the orchestrator re-grounds its output and drops anything invented.
  - It may only choose from the kinds we have safe, non-destructive executors
    for; it cannot author a raw request or a destructive action.
  - Output is strict JSON; anything unparseable yields no hypotheses (the loop
    just ends). Any LLM/connection error is swallowed — the engine keeps the
    findings it already has.
So the AI decides WHAT to look at next, while evidence and the deterministic
executors remain the only things that can ever produce a finding.
"""

from __future__ import annotations

import json
import logging
import uuid

import httpx

from recon.types import ReconResult
from redteam.orchestrator import StrategyContext, observed_surface
from redteam.types import Hypothesis, HypothesisKind, Severity, Technique

logger = logging.getLogger("h4ck-bot.redteam.strategist")

# Only kinds with a safe, non-destructive executor. The model picks from these;
# it cannot invent an action type.
_KIND_BY_NAME = {
    "bola": HypothesisKind.BOLA,
    "idor": HypothesisKind.IDOR,
    "injection": HypothesisKind.INJECTION,
    "sqli": HypothesisKind.INJECTION,
    "xss": HypothesisKind.XSS,
    "ssrf": HypothesisKind.SSRF,
    "xxe": HypothesisKind.XXE,
    "ssti": HypothesisKind.SSTI,
    "template": HypothesisKind.SSTI,
    "template_injection": HypothesisKind.SSTI,
    "open_redirect": HypothesisKind.OPEN_REDIRECT,
    "open-redirect": HypothesisKind.OPEN_REDIRECT,
    "redirect": HypothesisKind.OPEN_REDIRECT,
    # AI writes its own check: when no dedicated kind fits, the model authors a
    # bounded, non-destructive probe (validated before it runs — see synth_probe).
    "ai_probe": HypothesisKind.AI_PROBE,
    "probe": HypothesisKind.AI_PROBE,
    "custom": HypothesisKind.AI_PROBE,
    "custom_probe": HypothesisKind.AI_PROBE,
}
_TECH_BY_KIND = {
    HypothesisKind.BOLA: Technique.AUTHZ_TESTING,
    HypothesisKind.IDOR: Technique.AUTHZ_TESTING,
    HypothesisKind.INJECTION: Technique.INJECTION_TESTING,
    HypothesisKind.XSS: Technique.XSS_TESTING,
    HypothesisKind.SSRF: Technique.API_TESTING,
    HypothesisKind.XXE: Technique.API_TESTING,
    HypothesisKind.SSTI: Technique.INJECTION_TESTING,
    HypothesisKind.OPEN_REDIRECT: Technique.API_TESTING,
    HypothesisKind.AI_PROBE: Technique.API_TESTING,
}

_SYSTEM = (
    "You are the planning brain of an AUTHORIZED, strictly non-destructive web "
    "penetration test. Your job is to choose the next checks to run, reasoning "
    "like a pentester about what the confirmed findings and the observed "
    "attack surface imply. Hard rules you must obey:\n"
    "1. You may ONLY name endpoints and parameters that appear in the OBSERVED "
    "SURFACE provided. Never invent a path or a parameter.\n"
    "2. For a standard check, choose 'kind' from: bola, idor, injection, xss, "
    "ssrf, xxe, ssti, open_redirect.\n"
    "3. When you suspect a weakness NONE of those standard kinds covers, you may "
    "AUTHOR YOUR OWN CHECK with kind 'ai_probe'. You then supply a 'probe' object "
    "describing a SINGLE, bounded, NON-DESTRUCTIVE GET request and how to read the "
    "response:\n"
    '   \"probe\": {\"payload\": \"<inert value to put in the param>\", '
    '\"matcher\": {\"type\": \"reflection|error_signature|status_change|time_delay\", '
    '\"needle\": \"<expected string, for reflection/error_signature>\", '
    '\"min_delay_s\": <2-6, for time_delay>}, \"cwe\": \"CWE-XX\", '
    '\"severity\": \"low|medium|high\", \"title\": \"<short>\"}\n'
    "   The payload MUST be inert: NO SQL write verbs (drop/delete/insert/update), "
    "NO stacked queries or ';', NO shell metacharacters ($ ` | & ), NO path "
    "traversal '../', NO file://gopher://etc schemes, NO internal/metadata hosts "
    "(127.0.0.1, localhost, 169.254.169.254), NO <script>. The check is a DETECTOR, "
    "not an exploit. Any probe that breaks these is rejected before it runs.\n"
    "4. Do not repeat anything in ALREADY TRIED.\n"
    "5. Prefer pivots justified by a confirmed finding (same bug class on a "
    "sibling endpoint; chaining two findings).\n"
    "Respond with STRICT JSON only: "
    '{\"next\": [{\"kind\": \"...\", \"endpoint\": \"/path\", \"param\": \"name_or_empty\", '
    '\"why\": \"one sentence grounded in the evidence\", \"probe\": {...only for ai_probe...}}]}'
)


class LlmStrategist:
    def __init__(self, model: str, ollama_base_url: str = "http://localhost:11434",
                 timeout: float = 60.0, max_items: int = 8):
        self.model = model
        self.base_url = ollama_base_url.rstrip("/")
        self.timeout = timeout
        self.max_items = max_items

    async def __call__(self, ctx: StrategyContext) -> list[Hypothesis]:
        paths, params = observed_surface(ctx.recon)
        if not paths:
            return []
        user = self._build_prompt(ctx, sorted(paths), sorted(params))
        try:
            raw = await self._chat(_SYSTEM, user)
        except Exception as exc:  # noqa: BLE001 - best-effort; loop ends on failure
            logger.info("strategist LLM call failed round %d [model=%s, timeout=%ss]: %s: %s",
                        ctx.round_index, self.model, self.timeout,
                        type(exc).__name__, exc or "(no message - likely a timeout)")
            return []
        return self._parse(raw, paths, params)

    def _build_prompt(self, ctx: StrategyContext, paths: list[str], params: list[str]) -> str:
        confirmed = [
            f"- {f.title} [{getattr(f.status, 'value', f.status)}]"
            for f in ctx.findings_so_far
        ][:25] or ["(none confirmed yet)"]
        tried = sorted(f"{k}:{e}" for (k, e) in ctx.already_tried)[:40] or ["(none)"]
        return (
            f"TARGET: {ctx.target}\nROUND: {ctx.round_index}\n\n"
            "OBSERVED SURFACE (the ONLY endpoints/params you may use):\n"
            f"  endpoints: {json.dumps(paths)}\n"
            f"  parameters: {json.dumps(params)}\n\n"
            "CONFIRMED / OBSERVED SO FAR:\n" + "\n".join(confirmed) + "\n\n"
            "ALREADY TRIED (kind:endpoint — do not repeat):\n" + "\n".join(tried) + "\n\n"
            f"Propose up to {self.max_items} NEW checks as JSON per the system instructions. "
            "If nothing new is worth testing, return {\"next\": []}."
        )

    def _parse(self, raw: str, paths: set[str], params: set[str]) -> list[Hypothesis]:
        try:
            obj = json.loads(raw)
            items = obj.get("next", []) if isinstance(obj, dict) else []
        except (json.JSONDecodeError, AttributeError):
            logger.info("strategist: response was not valid JSON - no hypotheses this round")
            return []
        out: list[Hypothesis] = []
        for it in items[: self.max_items]:
            if not isinstance(it, dict):
                continue
            kind = _KIND_BY_NAME.get(str(it.get("kind", "")).strip().lower())
            endpoint = str(it.get("endpoint", "")).strip()
            param = str(it.get("param", "")).strip()
            if kind is None or endpoint not in paths:
                continue  # unknown kind or invented endpoint -> reject here too
            tparams = [param] if (param and param in params) else []

            probe_spec: dict = {}
            if kind is HypothesisKind.AI_PROBE:
                # AI-authored check: build the spec, grounded to this endpoint/param.
                # The spec is NOT trusted here — synth_probe.validate_probe_spec
                # re-checks GET-only / grounding / non-destructive / bounds before
                # it ever runs. We just assemble what the model proposed.
                probe_spec = self._build_probe_spec(it.get("probe"), endpoint, param, tparams)
                if probe_spec is None:
                    logger.info("strategist: dropping ai_probe on %s - no usable probe spec", endpoint)
                    continue

            title = (f"AI-authored probe on {endpoint}" if kind is HypothesisKind.AI_PROBE
                     else f"{kind.value} on {endpoint}") + (f" via '{param}'" if tparams else "")
            out.append(Hypothesis(
                hypothesis_id=f"llm-{uuid.uuid4().hex[:8]}",
                kind=kind,
                title=title,
                target_endpoints=[endpoint],
                target_params=tparams,
                rationale=str(it.get("why", ""))[:300] or "AI strategist pivot from confirmed surface",
                evidence_refs=["strategist.round"],
                suggested_technique=_TECH_BY_KIND.get(kind, Technique.API_TESTING),
                requires_active_testing=True,
                destructive=False,
                estimated_severity=Severity.MEDIUM,
                prior_confidence=0.5,
                source="llm",
                probe_spec=probe_spec,
            ))
        logger.info("strategist: parsed %d grounded hypothesis(es) from LLM", len(out))
        return out

    def _build_probe_spec(self, probe, endpoint: str, param: str, tparams: list) -> dict | None:
        """Assemble an AI-authored probe spec from the model's 'probe' object,
        pinned to the grounded endpoint/param. Returns None if the essentials
        (a payload and a matcher) are absent. This does NOT enforce safety — that
        is synth_probe.validate_probe_spec's job, run again at execution time."""
        if not isinstance(probe, dict):
            return None
        payload = probe.get("payload")
        matcher = probe.get("matcher")
        if not isinstance(payload, str) or not payload.strip() or not isinstance(matcher, dict):
            return None
        spec = {
            "endpoint": endpoint,
            "param": (param if (param and param in tparams) else None),
            "payload": payload,
            "matcher": matcher,
            "cwe": str(probe.get("cwe", "") or ""),
            "severity": str(probe.get("severity", "medium") or "medium"),
            "title": str(probe.get("title", "") or "")[:160],
            "rationale": str(probe.get("rationale", "") or "")[:600],
        }
        return spec

    async def _chat(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": "json",
            "keep_alive": "10m",
            "options": {"temperature": 0.2, "num_ctx": 8192},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
        return (data.get("message") or {}).get("content", "") or ""
