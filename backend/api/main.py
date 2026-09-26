"""
Thin FastAPI layer wrapping the orchestrator.

In-memory assessment store only - swap for Postgres before this is
anything but a demo. This exists to let the dashboard fetch real
findings instead of hardcoded HTML rows; it doesn't add any new
scanning logic itself.

Also serves the frontend as static files, so the whole app is one
process on one port - no CORS, no separate dev server.

Route registration order matters: all /api/* routes MUST be registered
BEFORE the static-files mount at "/", because the mount swallows
everything it's mounted on, and FastAPI matches in registration order.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.orchestrator import Orchestrator
from core.rules_of_engagement import RulesOfEngagement
from core.schema import Asset, Finding
from core.scope_loader import Scope, ScopeError, build_roe, load_scope
from evidence.llm_client import OllamaClient
from evidence.validation_pipeline import default_pipeline
from modules.discovery_module import DiscoveryModule
from modules.misconfig_module import MisconfigModule
from modules.example_web_api_module import WebApiScannerModule
from modules.owasp_top10_module import OwaspTop10Module
from api.serializers import serialize_finding
from api.scope_proposals import ProposalStore, verify_token
from api.rate_limit import RateLimiter
from api.middleware import RateLimitMiddleware, TokenBucketLimiter
from store.db import Store
from reporting.report_builder import (
    build_report_data, build_report_html, build_report_json,
)

logger = logging.getLogger("h4ck-bot.api")

# ── Logging setup ───────────────────────────────────────────────────
# By default, Python's root logger is at WARNING, so all the
# orchestrator/module/layer logger.info(...) calls are silently
# dropped and you can't see what a scan is doing. Configure once at
# import so the whole app logs at INFO to stderr, in the same format
# uvicorn uses.
import sys as _sys
_root = logging.getLogger()
if not _root.handlers:
    _handler = logging.StreamHandler(_sys.stderr)
    _handler.setFormatter(logging.Formatter(
        "%(levelname)s:     %(name)s - %(message)s"
    ))
    _root.addHandler(_handler)
_root.setLevel(logging.INFO)

# Quiet down some noisy third-party loggers if they ever show up
for _noisy in ("httpx", "httpcore", "urllib3"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)


app = FastAPI(title="H4CK-B0T API")

# Dev-only - lock this down before anything but localhost testing.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Persistence ─────────────────────────────────────────────────────
# SQLite at <project_root>/data/h4ckbot.db. Findings and assessment
# metadata survive API restarts. The in-memory dicts are gone; every
# read/write goes through the Store.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_STORE = Store(_PROJECT_ROOT / "data" / "h4ckbot.db")

# Rate limiter: max 2 concurrent scans, 10 per 60s, per client IP.
_RATE_LIMITER = RateLimiter(max_concurrent=2, max_per_window=10, window_seconds=60.0)


# ── Authorized scope (loaded once at import) ────────────────────────
# The API refuses any assessment whose target is not in scope.yaml.
# There is deliberately no API or UI path to add a target.
_SCOPE_PATH = Path(__file__).resolve().parent.parent.parent / "scope.yaml"
try:
    _SCOPE: Scope = load_scope(_SCOPE_PATH)
    logger.info("scope loaded from %s: %d authorized target(s)",
                _SCOPE_PATH, len(_SCOPE.targets))
except ScopeError as exc:
    logger.error("scope load failed: %s", exc)
    _SCOPE = Scope(authorized_by="", authorization_ref="", targets=tuple())

# Proposal store - lets an authenticated operator suggest additions to
# scope. Nothing here becomes scannable; promotion into scope.yaml is
# a manual step requiring shell access. See api/scope_proposals.py.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_PROPOSALS = ProposalStore(_PROJECT_ROOT)

# Fail loudly at import time if the admin token isn't configured, since
# /api/assessments/run and all /api/scope/* write routes now require it.
# A silent per-request 401 is easy to misdiagnose as "wrong token" when
# the real problem is "no token was ever set."
from api.scope_proposals import _token as _check_admin_token_configured
try:
    _check_admin_token_configured()
    logger.info("admin token configured - /run and /scope write routes are gated")
except RuntimeError as exc:
    logger.error(str(exc))
    raise


# ── Request/response models ─────────────────────────────────────────
class RunAssessmentRequest(BaseModel):
    target: str
    modules: list[str] = ["discovery", "misconfig", "web_api", "owasp_top10"]
    llm_model: str = "llama3.1"


class RunAssessmentResponse(BaseModel):
    assessment_id: str


MODULE_REGISTRY = {
    "discovery": DiscoveryModule,
    "misconfig": MisconfigModule,
    "web_api": WebApiScannerModule,
    "owasp_top10": OwaspTop10Module,
}

# All modules operate on the same physical target. We register exactly
# ONE Asset per target, with asset_type="host" (the target is a host;
# whether it serves an API is a property of what's running on it, not a
# separate asset). Modules declare the asset types they accept, and
# they all accept "host" - see the modules/*.py capabilities.


# ── /api/* routes — MUST all come before the static mount ───────────
@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/scope")
async def get_scope():
    """The list of targets the operator has authorized. The frontend
    uses this to render a dropdown - it cannot add to the list."""
    return {
        "authorized_by": _SCOPE.authorized_by,
        "authorization_ref": _SCOPE.authorization_ref,
        "targets": [
            {
                "host": e.host,
                "note": e.note,
                "permitted_techniques": list(e.permitted_techniques),
                "active_testing_permitted": e.active_testing_permitted,
                "destructive_actions_allowed": e.destructive_actions_allowed,
            }
            for e in _SCOPE.targets
        ],
    }


@app.post("/api/assessments/run", response_model=RunAssessmentResponse)
async def run_assessment(
    req: RunAssessmentRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    # Authorization has two layers and they are independent:
    #   1. _require_admin checks the CALLER (bearer token).
    #   2. _SCOPE.is_authorized checks the TARGET (scope.yaml).
    # Missing either means the request is refused.
    _require_admin(authorization)

    unknown = [m for m in req.modules if m not in MODULE_REGISTRY]
    if unknown:
        raise HTTPException(400, f"unknown module(s): {unknown}")

    if not _SCOPE.is_authorized(req.target):
        raise HTTPException(
            403,
            f"target '{req.target}' is not in the authorized scope. "
            f"Authorized targets: {[e.host for e in _SCOPE.targets]}. "
            "Edit scope.yaml on the server to add one.",
        )

    # Per-client rate limiting: 2 concurrent scans, 10 per 60s.
    # Independent of the API-wide token bucket - that one limits all
    # requests, this one limits how many scans can actually be
    # running at once.
    client_ip = request.client.host if request.client else "unknown"
    try:
        _RATE_LIMITER.check_and_acquire(client_ip)
    except ValueError as e:
        raise HTTPException(429, str(e))

    assessment_id = str(uuid.uuid4())
    _STORE.create_assessment(
        assessment_id=assessment_id,
        target=req.target,
        modules=list(req.modules),
        llm_model=req.llm_model,
    )

    asyncio.create_task(_run_assessment_task(assessment_id, req, client_ip))
    return RunAssessmentResponse(assessment_id=assessment_id)


async def _run_assessment_task(
    assessment_id: str,
    req: RunAssessmentRequest,
    client_ip: str = "unknown",
):
    try:
        roe = build_roe(assessment_id, req.target, _SCOPE)

        # Exactly one Asset per target. Modules declare the asset types
        # they accept; a single physical target is a single asset.
        assets = [Asset(
            asset_id="a0",
            name=req.target,
            asset_type="host",
            scope_approved=True,
            metadata={"exposure": "internet"},
        )]

        modules = [MODULE_REGISTRY[m]() for m in req.modules]
        orchestrator = Orchestrator(
            validation_pipeline=default_pipeline(
                llm_client=OllamaClient(model=req.llm_model)
            )
        )

        async for finding in orchestrator.run(roe, assets, modules, automation_level="assisted"):
            _STORE.insert_finding(assessment_id, finding)

        _STORE.set_status(assessment_id, "complete")
    except Exception as exc:
        logger.exception("assessment %s failed", assessment_id)
        _STORE.set_status(assessment_id, f"error: {exc}", error=str(exc))
    finally:
        # Always release the rate-limit slot, even if the task errored
        # or was cancelled.
        _RATE_LIMITER.release(client_ip)

@app.get("/api/assessments/{assessment_id}/status")
async def get_status(assessment_id: str):
    meta = _STORE.get_assessment(assessment_id)
    if meta is None:
        raise HTTPException(404, "assessment not found")
    return {
        "status": meta["status"],
        "finding_count": _STORE.finding_count(assessment_id),
        "meta": {
            "target": meta["target"],
            "modules": meta["modules"],
            "started_at": meta["started_at"],
            "completed_at": meta.get("completed_at"),
        },
    }


@app.get("/api/assessments/{assessment_id}/findings")
async def get_findings(assessment_id: str):
    if _STORE.get_assessment(assessment_id) is None:
        raise HTTPException(404, "assessment not found")
    return [serialize_finding(f) for f in _STORE.list_findings(assessment_id)]


@app.get("/api/assessments/{assessment_id}/findings/{finding_id}")
async def get_finding(assessment_id: str, finding_id: str):
    f = _STORE.get_finding(assessment_id, finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    return serialize_finding(f)


@app.get("/api/assessments")
async def list_assessments(limit: int = 50):
    """List past assessments, newest first."""
    return _STORE.list_assessments(limit=limit)



# ── Scope proposals (require admin token) ───────────────────────────
class ProposeTargetRequest(BaseModel):
    host: str
    note: str = ""
    authorization_ref: str
    permitted_techniques: list[str] = ["passive_recon", "port_scan", "misconfig_check"]
    active_testing_permitted: bool = False
    destructive_actions_allowed: bool = False


def _require_admin(authorization: str | None) -> None:
    """Extract 'Bearer <token>' from Authorization header and verify it."""
    presented = None
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    if not verify_token(presented):
        raise HTTPException(
            401,
            "admin token required. Send 'Authorization: Bearer <H4CK_BOT_ADMIN_TOKEN>'.",
        )


@app.post("/api/scope/propose", status_code=201)
async def propose_target(
    req: ProposeTargetRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Propose adding a target to scope. Requires the admin token.
    Does NOT make the target scannable - an admin must promote it via
    scripts/scope_promote.sh on the server."""
    _require_admin(authorization)
    client_ip = request.client.host if request.client else "unknown"
    try:
        prop = _PROPOSALS.propose(
            host=req.host,
            note=req.note,
            authorization_ref=req.authorization_ref,
            ip=client_ip,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {
        "proposal_id": prop.proposal_id,
        "host": prop.host,
        "status": prop.status,
        "message": (
            "Proposal recorded. It is NOT scannable yet. An admin must "
            "review scope.proposed.yaml and run scripts/scope_promote.sh "
            f"{prop.proposal_id} on the server, then restart the API."
        ),
    }


@app.get("/api/scope/proposed")
async def list_proposed(authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    return [
        {
            "proposal_id": p.proposal_id,
            "host": p.host,
            "note": p.note,
            "authorization_ref": p.authorization_ref,
            "proposed_at": p.proposed_at,
            "proposed_from_ip": p.proposed_from_ip,
        }
        for p in _PROPOSALS.list_pending()
    ]


@app.delete("/api/scope/proposed/{proposal_id}")
async def reject_proposed(
    proposal_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
):
    _require_admin(authorization)
    client_ip = request.client.host if request.client else "unknown"
    ok = _PROPOSALS.reject(proposal_id, client_ip)
    if not ok:
        raise HTTPException(404, "no pending proposal with that id")
    return {"status": "rejected", "proposal_id": proposal_id}




# ── Reports ─────────────────────────────────────────────────────────
@app.get("/api/assessments/{assessment_id}/report.json")
async def get_report_json(assessment_id: str):
    meta = _STORE.get_assessment(assessment_id)
    if meta is None:
        raise HTTPException(404, "assessment not found")
    findings = _STORE.list_findings(assessment_id)
    data = build_report_data(meta, findings, scope_note=_SCOPE.authorization_ref)
    return build_report_json(data)


@app.get("/api/assessments/{assessment_id}/report.html")
async def get_report_html(assessment_id: str):
    from fastapi.responses import HTMLResponse
    meta = _STORE.get_assessment(assessment_id)
    if meta is None:
        raise HTTPException(404, "assessment not found")
    findings = _STORE.list_findings(assessment_id)
    data = build_report_data(meta, findings, scope_note=_SCOPE.authorization_ref)
    return HTMLResponse(build_report_html(data))

# ── Static frontend mount — MUST be last ────────────────────────────
_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

if _FRONTEND_DIR.is_dir():
    @app.get("/")
    async def serve_index():
        return FileResponse(_FRONTEND_DIR / "index.html")

    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
    logger.info("serving frontend from %s", _FRONTEND_DIR)
else:
    logger.warning("frontend directory not found at %s - static serving disabled",
                   _FRONTEND_DIR)
