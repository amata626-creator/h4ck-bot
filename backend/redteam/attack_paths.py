"""
AI attack-path chaining — compose confirmed findings into exploit chains.

A flat list of findings is a scanner's output. A pentester's output is a
narrative: "this XSS, plus the missing SameSite on the session cookie, plus the
state-changing GET on the transfer endpoint, chain into account takeover." This
pass asks the LLM to reason over the CONFIRMED findings and propose such chains.

Honesty / grounding (same discipline as the strategist):
  - A chain may ONLY reference finding_ids that actually exist in this
    assessment; any invented id is dropped, and a chain left with fewer than two
    real, distinct findings is discarded (a "chain" of one is just the finding).
  - The LLM supplies the narrative and a title; the SEVERITY is derived
    deterministically from the member findings (max member severity), never
    taken on the model's word - so a chain can't inflate its own rating.
  - Best-effort: any LLM/parse/connection failure yields no chains; the findings
    stand on their own. Nothing here can create or validate a finding.
"""

from __future__ import annotations

import json
import logging
import uuid

import httpx

from core.schema import AttackPath, Finding, FindingStatus, KillChainPhase, Severity

logger = logging.getLogger("h4ck-bot.redteam.chains")

_SEV_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}

# Findings worth chaining: confirmed or needs-review vulnerabilities, not raw
# informational observations (open ports etc.).
_CHAINABLE_STATUS = {FindingStatus.VALIDATED, FindingStatus.NEEDS_REVIEW}

_SYSTEM = (
    "You are a penetration tester writing the attack-narrative section of a "
    "report. You are given a list of CONFIRMED findings, each with an id. Your "
    "job is to identify ATTACK PATHS: ways two or more of these findings chain "
    "together into a higher-impact outcome (e.g. reflected XSS + missing "
    "SameSite cookie + a state-changing GET -> account takeover). Hard rules:\n"
    "1. Reference ONLY the finding ids provided. Never invent a finding.\n"
    "2. Every path must chain at least TWO distinct findings.\n"
    "3. Only assert a chain the listed findings actually support; if nothing "
    "chains, return an empty list. Do not pad.\n"
    "Respond with STRICT JSON only: "
    '{\"paths\": [{\"title\": \"...\", \"finding_ids\": [\"...\",\"...\"], '
    '\"narrative\": \"how the chain works, step by step, grounded in the findings\"}]}'
)


class AttackPathChainer:
    def __init__(self, model: str, ollama_base_url: str = "http://localhost:11434",
                 timeout: float = 60.0, max_paths: int = 6):
        self.model = model
        self.base_url = ollama_base_url.rstrip("/")
        self.timeout = timeout
        self.max_paths = max_paths

    async def __call__(self, findings: list[Finding]) -> list[AttackPath]:
        eligible = {f.finding_id: f for f in findings
                    if f.status in _CHAINABLE_STATUS and f.finding_kind.value != "informational"}
        if len(eligible) < 2:
            return []   # nothing to chain
        try:
            raw = await self._chat(_SYSTEM, self._prompt(eligible))
        except Exception as exc:  # noqa: BLE001 - best-effort
            logger.info("attack-path chaining LLM call failed [model=%s, timeout=%ss]: %s: %s",
                        self.model, self.timeout, type(exc).__name__,
                        exc or "(no message - likely a timeout)")
            return []
        return self._parse(raw, eligible)

    def _prompt(self, eligible: dict[str, Finding]) -> str:
        lines = []
        for fid, f in eligible.items():
            cwe = getattr(f.cwe, "cwe_id", "") if f.cwe else ""
            lines.append(f'  {{"id": "{fid}", "title": {json.dumps(f.title)}, '
                         f'"cwe": "{cwe}", "severity": "{f.severity.value}", '
                         f'"asset": {json.dumps(getattr(f.asset, "name", ""))}}}')
        return ("CONFIRMED FINDINGS:\n[\n" + ",\n".join(lines) + "\n]\n\n"
                f"Identify up to {self.max_paths} attack paths per the system rules. "
                "If none chain, return {\"paths\": []}.")

    def _parse(self, raw: str, eligible: dict[str, Finding]) -> list[AttackPath]:
        try:
            obj = json.loads(raw)
            items = obj.get("paths", []) if isinstance(obj, dict) else []
        except (json.JSONDecodeError, AttributeError):
            logger.info("attack-path: response was not valid JSON - no chains")
            return []
        out: list[AttackPath] = []
        seen_sets: set[frozenset] = set()
        for it in items[: self.max_paths]:
            if not isinstance(it, dict):
                continue
            ids = [str(i) for i in (it.get("finding_ids") or []) if str(i) in eligible]
            ids = list(dict.fromkeys(ids))   # dedupe, preserve order
            if len(ids) < 2:
                continue  # invented ids stripped it below a real chain
            key = frozenset(ids)
            if key in seen_sets:
                continue
            seen_sets.add(key)
            members = [eligible[i] for i in ids]
            # severity is derived from members, never trusted to the model
            sev = _RANK_SEV[max(_SEV_RANK[m.severity] for m in members)]
            phases: list[KillChainPhase] = []
            for m in members:
                if m.kill_chain_phase and m.kill_chain_phase not in phases:
                    phases.append(m.kill_chain_phase)
            out.append(AttackPath(
                attack_path_id=f"ap-{uuid.uuid4().hex[:8]}",
                title=str(it.get("title", "")).strip()[:160] or "Chained attack path",
                finding_ids=ids,
                kill_chain_phases=phases,
                narrative=str(it.get("narrative", "")).strip()[:1200]
                or "Chain of the listed findings.",
                overall_severity=sev,
            ))
        logger.info("attack-path: composed %d grounded chain(s)", len(out))
        return out

    async def _chat(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "stream": False, "format": "json", "keep_alive": "10m",
            "options": {"temperature": 0.2, "num_ctx": 8192},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
        return (data.get("message") or {}).get("content", "") or ""


def attack_path_to_dict(ap: AttackPath) -> dict:
    return {
        "attack_path_id": ap.attack_path_id,
        "title": ap.title,
        "finding_ids": list(ap.finding_ids),
        "kill_chain_phases": [p.value for p in ap.kill_chain_phases],
        "narrative": ap.narrative,
        "overall_severity": ap.overall_severity.value,
    }
