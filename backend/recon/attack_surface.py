"""
Attack-surface mapping — the "what did we find to attack" deliverable.

Recon already discovers the raw material (endpoints, parameters, technologies,
auth surface, JS bundles). This distills that ReconResult into a compact,
report-ready attack-surface summary: the inventory a pentester puts at the front
of an engagement so the reader sees the shape of the target before the findings.

Pure and deterministic — no I/O, no LLM. It reports only what recon actually
observed (same grounding discipline as everything else); it never guesses.
"""

from __future__ import annotations

from recon.types import ReconResult

# Path shapes that mark an endpoint as API / higher-interest surface.
_API_HINTS = ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/", "/.well-known/", "/oauth", "/auth/")
# Discovery sources that found live/dynamic surface (vs a statically linked page).
_DYNAMIC_SOURCES = {"deep-crawler", "openapi", "ai-fuzz", "js_bundle", "js-bundle", "headless"}


def _endpoint_promise(path: str, params, source: str, auth_required) -> int:
    score = 0
    if params:
        score += 3 + min(len(params) - 1, 3)
    if (source or "") in _DYNAMIC_SOURCES:
        score += 2
    if any(h in (path or "").lower() for h in _API_HINTS):
        score += 2
    if auth_required is True:
        score += 1
    return score


def build_attack_surface(recon: ReconResult, endpoint_cap: int = 60) -> dict:
    """Distill a ReconResult into a report-ready attack-surface summary dict."""
    eps = list(recon.endpoints or [])
    rows = []
    all_params: set[str] = set()
    for e in eps:
        params = list(e.params or [])
        all_params.update(params)
        rows.append({
            "path": e.path,
            "methods": list(e.methods or ["GET"]),
            "params": params,
            "source": e.discovered_from or "unknown",
            "auth_required": e.auth_required,
            "content_type": e.content_type or "",
            "_score": _endpoint_promise(e.path, params, e.discovered_from, e.auth_required),
        })
    rows.sort(key=lambda r: (-r["_score"], r["path"]))
    for r in rows:
        r.pop("_score", None)

    api_eps = [r["path"] for r in rows if any(h in r["path"].lower() for h in _API_HINTS)]
    param_eps = [r["path"] for r in rows if r["params"]]
    authed_eps = [r["path"] for r in rows if r["auth_required"] is True]

    tech = recon.tech
    technologies = {
        "server": tech.server, "powered_by": tech.powered_by,
        "framework": tech.framework, "language": tech.language, "cms": tech.cms,
        "detected_products": list(tech.detected_products or []),
    }
    auth = recon.auth

    return {
        "target": recon.target,
        "base_urls": list(recon.base_urls or []),
        "technologies": technologies,
        "counts": {
            "endpoints": len(eps),
            "parameters": len(all_params),
            "api_endpoints": len(api_eps),
            "parameterized_endpoints": len(param_eps),
            "auth_required_endpoints": len(authed_eps),
            "js_bundles": len(recon.js_bundles or []),
        },
        "has_openapi": recon.openapi_spec is not None,
        "has_robots": bool(recon.robots_txt),
        "auth_surface": {
            "login_paths": list(auth.login_paths or []),
            "cookie_names": list(auth.cookie_names or []),
            "auth_header_names": list(auth.auth_header_names or []),
            "token_endpoint": auth.token_endpoint,
        },
        # Ranked, capped — most-promising surface first (what a tester hits first).
        "endpoints": rows[:endpoint_cap],
        "endpoint_total": len(eps),
        "parameters": sorted(all_params)[:120],
        "highlights": {
            "api_endpoints": api_eps[:20],
            "parameterized_endpoints": param_eps[:20],
            "auth_required_endpoints": authed_eps[:20],
        },
        "unknowns": list(recon.unknowns or []),
    }
