"""
AI-powered content/endpoint fuzzing.

A static wordlist fuzzer tries the same paths against every target. This instead
asks the LLM for CONTEXT-AWARE candidates from the observed tech stack — a Spring
app suggests /actuator/env and /v3/api-docs; WordPress suggests /wp-json and
/wp-login.php; IIS/ASP.NET suggests /elmah.axd and /trace.axd — then PROBES each
one and keeps only those that actually respond. So the AI guesses, the HTTP
response confirms, and only real endpoints expand the attack surface the rest of
the engine (strategist + executors) then works on. No hallucinated endpoints: a
candidate that 404s is discarded.

Safety: GET-only, bounded (capped candidates, paced), carries the auth session,
skips destructive-sounding paths (logout/delete), and calibrates against a random
path so a soft-404 'everything returns 200' app can't produce phantom hits.
Best-effort: any LLM/HTTP failure yields no endpoints and recon continues.
"""

from __future__ import annotations

import asyncio
import difflib
import json
import logging
import os
import uuid

import httpx

from recon.types import Endpoint

logger = logging.getLogger("h4ck-bot.recon.aifuzz")

_MAX_CANDIDATES = 40
_PACE_S = 0.15
# Status codes that mean "this path is real / notable" (not a plain 404).
_INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}
# Never probe paths that could change state or end the session.
_SKIP_SUBSTR = ("logout", "signout", "sign-out", "logoff", "delete", "destroy",
                "remove", "shutdown", "reboot", "drop")

_SYSTEM = (
    "You are the content-discovery brain of an AUTHORIZED, non-destructive web "
    "pentest. Given a target's detected technology and some known paths, propose "
    "additional URL PATHS that commonly exist on THAT stack and are worth probing "
    "- admin consoles, API roots and docs, config/debug/actuator endpoints, "
    "backup/status/health paths, framework defaults. Rules: relative paths only "
    "(start with '/'), no hostnames, no schemes, no query strings, no wildcards. "
    "Prefer paths specific to the detected stack over generic guesses. Respond "
    'with STRICT JSON only: {"paths": ["/path1", "/path2", ...]}'
)


def _reasoning_model() -> str:
    return (os.environ.get("H4CK_BOT_REASONING_MODEL", "").strip()
            or os.environ.get("H4CK_BOT_LLM_MODEL", "").strip()
            or "qwen2.5:3b")


def _ollama_base() -> str:
    return os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")


def _sanitize(paths, known: set[str]) -> list[str]:
    out, seen = [], set()
    for p in paths:
        if not isinstance(p, str):
            continue
        p = p.strip().split("?", 1)[0].split("#", 1)[0]
        if not p.startswith("/") or " " in p or "://" in p or len(p) > 120:
            continue
        low = p.lower()
        if any(s in low for s in _SKIP_SUBSTR):
            continue
        if p in known or p in seen:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= _MAX_CANDIDATES:
            break
    return out


async def _propose_paths(tech_summary: str, known_paths: list[str], timeout: float) -> list[str]:
    user = (
        f"Detected technology: {tech_summary or 'unknown'}\n"
        f"Known paths: {json.dumps(known_paths[:30])}\n"
        f"Propose up to {_MAX_CANDIDATES} additional likely paths for this stack. JSON only."
    )
    payload = {
        "model": _reasoning_model(),
        "messages": [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}],
        "stream": False, "format": "json", "keep_alive": "10m",
        "options": {"temperature": 0.3, "num_ctx": 8192},
    }
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post(f"{_ollama_base()}/api/chat", json=payload)
        r.raise_for_status()
        content = (r.json().get("message") or {}).get("content", "") or ""
    try:
        obj = json.loads(content)
        return obj.get("paths", []) if isinstance(obj, dict) else []
    except (json.JSONDecodeError, AttributeError):
        return []


async def discover(client: "httpx.AsyncClient", base_url: str, tech_summary: str,
                   known_paths: list[str], timeout: float = 60.0, log=None) -> list[Endpoint]:
    """Return endpoints confirmed to exist from AI-proposed, context-aware
    candidates. `client` is the recon httpx client (carries the auth session)."""
    def _log(m):
        (log or logger.info)(m)
    try:
        raw = await _propose_paths(tech_summary, known_paths, timeout)
    except Exception as exc:  # noqa: BLE001 - best-effort
        _log(f"ai-fuzz: path proposal failed ({type(exc).__name__}: {exc or 'timeout'})")
        return []
    candidates = _sanitize(raw, set(known_paths))
    if not candidates:
        return []

    base = base_url.rstrip("/")
    # Soft-404 calibration: a random nonsense path. If the app answers it with a
    # 200, it soft-404s, so we won't trust 200s whose body matches this baseline.
    soft404_body = None
    try:
        b = await client.get(f"{base}/h4ckfuzz-{uuid.uuid4().hex}")
        if b.status_code == 200:
            soft404_body = b.text or ""
    except Exception:  # noqa: BLE001
        pass

    found: list[Endpoint] = []
    for p in candidates:
        try:
            r = await client.get(base + p)
        except Exception:  # noqa: BLE001
            continue
        await asyncio.sleep(_PACE_S)
        st = r.status_code
        if st not in _INTERESTING:
            continue
        if st == 200 and soft404_body is not None:
            # too similar to the random-path response -> it's a soft 404, skip
            if difflib.SequenceMatcher(None, (r.text or "")[:4000], soft404_body[:4000]).ratio() > 0.95:
                continue
        ctype = (r.headers.get("content-type") or "").split(";", 1)[0]
        found.append(Endpoint(path=p, methods=["GET"], discovered_from="ai-fuzz",
                              content_type=ctype, auth_required=(st in (401, 403)),
                              notes=f"AI-fuzzed; HTTP {st}"))
    _log(f"ai-fuzz: {len(found)} endpoint(s) confirmed from {len(candidates)} AI candidate(s)")
    return found
