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
    "job is to identify genuine ATTACK PATHS: a CAUSAL chain where one finding "
    "ENABLES the next, escalating to a higher-impact outcome.\n"
    "A real path reads 'A lets the attacker do X, which makes B exploitable, "
    "leading to <concrete impact>' — e.g. exposed .git leaks source -> hardcoded "
    "DB creds -> auth bypass -> account takeover.\n"
    "What is NOT an attack path (do NOT output these):\n"
    "  - Two unrelated weaknesses that merely sit on the same host (e.g. 'weak "
    "TLS ciphers + reflected XSS' — the cipher does not enable the XSS).\n"
    "  - Two instances of the SAME bug (e.g. 'XSS on /a and XSS on /b').\n"
    "  - A list of passive hardening gaps (missing headers + weak ciphers + "
    "expired cert) — those are independent findings, not a chain.\n"
    "Hard rules:\n"
    "1. Reference ONLY the finding ids provided. Never invent a finding.\n"
    "2. Every path chains at least TWO distinct findings of DIFFERENT kinds, and "
    "the narrative MUST state how the earlier finding ENABLES the later one.\n"
    "3. Only assert a chain the findings actually support. If nothing genuinely "
    "chains, return an empty list. An empty list is the correct, expected answer "
    "when findings are independent. NEVER pad.\n"
    "Respond with STRICT JSON only: "
    '{\"paths\": [{\"title\": \"...\", \"finding_ids\": [\"...\",\"...\"], '
    '\"narrative\": \"how A enables B ... -> concrete impact, grounded in the findings\"}]}'
)

# Sources/classes that represent an ACTIVELY EXPLOITABLE weakness (an attacker
# can DO something with it), as opposed to a passive hardening gap. A genuine
# attack path must be anchored on at least one of these — a chain built purely
# from missing-header / weak-cipher / expired-cert / open-port observations is a
# findings list, not a path.
_EXPLOITABLE_SOURCES = (
    "bola_executor", "xss_executor", "injection_executor", "ssrf_oob_executor",
    "xxe_oob_executor", "ssti_executor", "open_redirect_executor",
    "cors_executor", "config_exposure_executor", "ai_synth_probe",
)


def _is_exploitable(f: Finding) -> bool:
    """True if the finding is an actively-exploitable weakness (an executor
    confirmed it, or it is a HIGH/CRITICAL vuln) rather than a passive hardening
    gap. A chain must contain at least one of these to be a real attack path."""
    src = (f.module_source or "").lower()
    if any(src.startswith(s) for s in _EXPLOITABLE_SOURCES):
        return True
    return f.severity in (Severity.HIGH, Severity.CRITICAL)


def _same_class(members: list[Finding]) -> bool:
    """True if the members are all the same class of issue (one CWE AND one
    source) — e.g. 'XSS on /a' + 'XSS on /b'. That is duplicate findings, not a
    chain, so it is rejected."""
    cwes = {getattr(m.cwe, "cwe_id", "") for m in members if getattr(m.cwe, "cwe_id", "")}
    srcs = {(m.module_source or "") for m in members}
    return len(cwes) < 2 and len(srcs) < 2


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
            members = [eligible[i] for i in ids]
            # Deterministic quality gates — the model (esp. a small one) will
            # group co-occurring findings and call it a chain; reject the two
            # clearest non-chains regardless of what it claims.
            if _same_class(members):
                logger.info("attack-path: dropping same-class grouping %s (not a chain)", ids)
                continue
            if not any(_is_exploitable(m) for m in members):
                logger.info("attack-path: dropping all-passive grouping %s (no exploitable anchor)", ids)
                continue
            seen_sets.add(key)
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
            "stream": False, "format": "json", "keep_alive": "30m",
            # Bounded for CPU hosts (see strategist): cap output + shrink context
            # so chaining completes instead of ReadTimeout'ing on an open-ended
            # JSON generation.
            "options": {"temperature": 0.2, "num_ctx": 4096, "num_predict": 1024},
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
