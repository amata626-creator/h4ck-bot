"""
Prompt construction for the semantic model.

Hard constraints (driven by hardware reality, not preference):
  - The prompt MUST stay under ~800 tokens. Anything larger times out
    llama3.1 on CPU-only hosts. The compress_endpoints() helper groups
    paths by prefix so that 21 raw paths become 6-8 lines.
  - We do NOT send response bodies. We send JSON top-level keys only,
    because that's where the ownership signal lives ("owner_id",
    "user_id") and the body itself adds noise and secrets.
  - Absence is expressible. The prompt repeatedly tells the model to
    say "unknown" rather than guess.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from recon.types import HttpTrace, ReconResult


# ── Endpoint compression ────────────────────────────────────────────

def compress_endpoints(recon: ReconResult, max_lines: int = 10) -> list[str]:
    """
    Group endpoints by their first two path components so 21 paths
    collapse to ~6 lines. Returns a list of one-line descriptions.
    """
    groups: dict[str, list[Any]] = {}
    for ep in recon.endpoints:
        parts = [p for p in ep.path.split("/") if p]
        if len(parts) >= 2 and parts[0] in ("api", "rest", "v1", "v2"):
            key = "/" + "/".join(parts[:2]) + "/*"
        elif parts:
            key = "/" + parts[0] + ("/*" if len(parts) > 1 else "")
        else:
            key = "/"
        groups.setdefault(key, []).append(ep)

    # Sort groups by size, biggest first
    ordered = sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True)

    lines: list[str] = []
    for prefix, eps in ordered[:max_lines]:
        methods: set[str] = set()
        params: set[str] = set()
        suffixes: list[str] = []
        for ep in eps:
            methods.update(ep.methods)
            params.update(ep.params)
            parts = [p for p in ep.path.split("/") if p]
            if len(parts) > 2:
                suffixes.append("/".join(parts[2:]) or "(root)")
            else:
                suffixes.append("(root)")
        m = ",".join(sorted(methods)) or "ANY"
        p = f"  params={sorted(params)}" if params else ""
        s = ", ".join(sorted(set(suffixes))[:6])
        lines.append(f"{prefix:28s} [{m:12s}] {s}{p}")

    return lines


def summarize_trace(t: HttpTrace) -> dict[str, Any]:
    """
    Compress a single HTTP trace to what the LLM actually needs.
    No bodies. Top-level JSON keys only. Headings for HTML.
    """
    out: dict[str, Any] = {
        "method": t.method,
        "url": t.url,
        "status": t.status,
        "content_type": t.response_headers.get("content-type", "")[:60],
    }

    body = t.response_body or ""
    ctype = out["content_type"].lower()

    if "json" in ctype and body.strip().startswith(("{", "[")):
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                out["json_keys"] = list(parsed.keys())[:20]
            elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                out["json_array_len"] = len(parsed)
                out["json_item_keys"] = list(parsed[0].keys())[:20]
        except Exception:
            pass
    elif "html" in ctype:
        title_m = re.search(r"<title[^>]*>([^<]{0,120})</title>", body, re.IGNORECASE)
        if title_m:
            out["page_title"] = title_m.group(1).strip()
        # form inputs = semantic signal for what the app accepts
        inputs = re.findall(r"<input[^>]*\bname=[\"']([^\"']+)[\"']", body, re.IGNORECASE)
        if inputs:
            out["form_inputs"] = inputs[:15]

    return out


def build_prompt(
    recon: ReconResult,
    max_traces: int = 6,
    body_chars: int = 0,     # kept for API compat; no longer used
) -> str:
    """
    Build the compressed user prompt. Target: <800 tokens.
    """
    endpoint_lines = compress_endpoints(recon, max_lines=10)
    endpoints_block = "\n".join(endpoint_lines) or "(no endpoints discovered)"

    # Pick the most informative traces by score, then summarize without bodies
    def trace_score(t: HttpTrace) -> int:
        s = 0
        if t.status in (200, 201): s += 100
        ctype = t.response_headers.get("content-type", "").lower()
        if "json" in ctype: s += 30
        if "html" in ctype: s += 15
        return s

    top = sorted(recon.http_traces, key=trace_score, reverse=True)[:max_traces]
    traces_block = "\n".join(
        f"- {json.dumps(summarize_trace(t))}" for t in top
    ) or "(no HTTP traces)"

    tech = recon.tech
    auth = recon.auth

    return f"""TARGET: {recon.target}
BASE URLS: {", ".join(recon.base_urls) or "(none)"}

TECH: server={tech.server or "unknown"} framework={tech.framework or "unknown"} \
language={tech.language or "unknown"} powered_by={tech.powered_by or "unknown"}

AUTH HINTS:
  login paths: {auth.login_paths[:6] or "none observed"}
  cookie names: {auth.cookie_names[:8] or "none observed"}
  csrf params: {auth.csrf_param_names or "none"}

ENDPOINTS (grouped by prefix):
{endpoints_block}

SAMPLE RESPONSES (JSON keys only, no bodies):
{traces_block}

RECON COULD NOT DETERMINE:
{chr(10).join('  - ' + u for u in recon.unknowns[:6]) or '  (nothing flagged)'}
"""
