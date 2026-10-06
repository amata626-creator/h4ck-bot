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
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from api import auth
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
from modules.advanced_checks_module import AdvancedChecksModule
from modules.advanced_checks2_module import AdvancedChecks2Module
from api.serializers import serialize_finding
from api.scope_proposals import ProposalStore, verify_token
from api.rate_limit import RateLimiter
from api.middleware import RateLimitMiddleware, TokenBucketLimiter
from store.db import Store
from reporting.report_builder import (
    build_report_data, build_report_html, build_report_json,
)

# Red-team (hypothesis-driven) assessment pipeline.
import httpx
from core.module_interface import ModuleRunContext
from recon.module import ReconModule
from semantic.model import SemanticModelBuilder
from redteam.orchestrator import RedTeamOrchestrator
from redteam.executors import ExecutorRegistry, ExecContext, FetchResult

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


# Paths reachable without a session (the login page itself, its API, and
# liveness). Everything else is gated once login is configured.
_AUTH_PUBLIC_PATHS = {"/login", "/api/login", "/api/logout", "/api/health", "/favicon.ico"}


@app.middleware("http")
async def auth_gate(request: Request, call_next):
    """Single gate for the whole app. A request passes if it carries a valid
    session cookie OR a valid admin bearer token. For a session user we inject
    the admin bearer so the existing per-route token checks (writes) succeed
    without the user pasting a token. Unauthenticated browsers are redirected
    to /login; API clients get 401. The gate is a no-op until login is
    configured, so a fresh deploy is never locked out before a password is set."""
    path = request.url.path
    if path in _AUTH_PUBLIC_PATHS or not _login_enabled():
        return await call_next(request)

    # 1. valid session cookie?
    if auth.verify_session(request.cookies.get(auth.SESSION_COOKIE)):
        if not request.headers.get("authorization"):
            admin_tok = os.environ.get("H4CK_BOT_ADMIN_TOKEN", "")
            if admin_tok:
                hdrs = [(k, v) for (k, v) in request.scope["headers"] if k != b"authorization"]
                hdrs.append((b"authorization", f"Bearer {admin_tok}".encode()))
                request.scope["headers"] = hdrs
        return await call_next(request)

    # 2. valid admin bearer token? (programmatic API clients)
    authz = request.headers.get("authorization", "")
    if authz.startswith("Bearer ") and verify_token(authz.split(" ", 1)[1]):
        return await call_next(request)

    # 3. unauthenticated
    if "text/html" in request.headers.get("accept", ""):
        return RedirectResponse("/login", status_code=302)
    return JSONResponse({"detail": "authentication required"}, status_code=401)


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


# ── Dashboard accounts (multi-user) ─────────────────────────────────
# Users live in the `users` table. The .env admin (H4CK_BOT_ADMIN_USER /
# _PASSWORD_HASH) is a bootstrap account: on first start it is seeded into
# the table as an 'admin' so it is visible and manageable like any other.
try:
    if _STORE.count_users() == 0 and auth._password_hash():
        _STORE.add_user(auth.admin_user(), auth._password_hash(), role="admin")
        logger.info("seeded bootstrap admin '%s' into users table", auth.admin_user())
except Exception as exc:  # noqa: BLE001
    logger.warning("user bootstrap skipped: %s", exc)


def _login_enabled() -> bool:
    """The login gate is live once a session secret exists AND there is at
    least one credential (a DB user, or the .env bootstrap admin)."""
    if not auth._session_secret():
        return False
    if auth._password_hash():
        return True
    try:
        return _STORE.count_users() > 0
    except Exception:  # noqa: BLE001
        return False


def _authenticate(username: str, password: str) -> Optional[str]:
    """Return the caller's role if credentials are valid, else None.
    A username that exists in the DB is checked ONLY against the DB (no
    stale .env fallback); otherwise the .env bootstrap admin is tried."""
    u = _STORE.get_user(username)
    if u is not None:
        if u["active"] and auth.verify_password(password, u["password_hash"]):
            return u["role"]
        return None
    if auth.check_credentials(username, password):
        return "admin"
    return None


def _caller_is_admin(request: Request) -> bool:
    """Admin if the session role is admin, or a valid admin bearer token is
    presented (the bearer token is full-power by definition)."""
    sess = auth.verify_session(request.cookies.get(auth.SESSION_COOKIE))
    if sess and sess.get("r") == "admin":
        return True
    authz = request.headers.get("authorization", "")
    if authz.startswith("Bearer ") and verify_token(authz.split(" ", 1)[1]):
        return True
    return False


_VALID_ROLES = {"admin", "operator"}
import re as _re
_USERNAME_RE = _re.compile(r"^[A-Za-z0-9._-]{3,32}$")


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
    "advanced_checks": AdvancedChecksModule,
    "advanced_checks2": AdvancedChecks2Module,
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


@app.post("/api/login")
async def login(request: Request):
    """Authenticate and set a signed session cookie. JSON body:
    {"username": ..., "password": ...}. Rate-limited per client IP."""
    ip = request.client.host if request.client else "?"
    if auth.rate_limited(ip):
        raise HTTPException(429, "too many login attempts - wait a few minutes")
    try:
        body = await request.json()
    except Exception:
        body = {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    role = _authenticate(username, password)
    if role:
        auth.clear_attempts(ip)
        resp = JSONResponse({"ok": True, "role": role})
        resp.set_cookie(
            auth.SESSION_COOKIE, auth.make_session(username, role),
            max_age=auth.SESSION_TTL, httponly=True, secure=True,
            samesite="lax", path="/",
        )
        return resp
    auth.record_attempt(ip)
    raise HTTPException(401, "invalid username or password")


@app.post("/api/logout")
async def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.SESSION_COOKIE, path="/")
    return resp


@app.get("/api/me")
async def whoami(request: Request):
    """Who the current session belongs to (used by the dashboard header)."""
    sess = auth.verify_session(request.cookies.get(auth.SESSION_COOKIE))
    return {
        "user": sess["u"] if sess else None,
        "role": sess["r"] if sess else None,
        "login_enabled": _login_enabled(),
    }


# ── User management (admin only) ────────────────────────────────────
@app.get("/api/users")
async def list_users(request: Request):
    if not _caller_is_admin(request):
        raise HTTPException(403, "admin role required")
    return {"users": _STORE.list_users()}


@app.post("/api/users", status_code=201)
async def create_user(request: Request):
    if not _caller_is_admin(request):
        raise HTTPException(403, "admin role required")
    try:
        body = await request.json()
    except Exception:
        body = {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    role = str(body.get("role", "operator")).strip() or "operator"
    if not _USERNAME_RE.match(username):
        raise HTTPException(400, "username must be 3-32 chars: letters, digits, . _ -")
    if len(password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    if role not in _VALID_ROLES:
        raise HTTPException(400, f"role must be one of {sorted(_VALID_ROLES)}")
    if not _STORE.add_user(username, auth.hash_password(password), role):
        raise HTTPException(409, "a user with that username already exists")
    logger.info("user created: %s (role=%s)", username, role)
    return {"ok": True, "username": username, "role": role}


@app.delete("/api/users/{username}")
async def remove_user(username: str, request: Request):
    if not _caller_is_admin(request):
        raise HTTPException(403, "admin role required")
    u = _STORE.get_user(username)
    if u is None:
        raise HTTPException(404, "no such user")
    if u["role"] == "admin" and _STORE.count_admins() <= 1:
        raise HTTPException(409, "cannot delete the last admin account")
    _STORE.delete_user(username)
    logger.info("user deleted: %s", username)
    return {"ok": True}


@app.post("/api/users/{username}/password")
async def reset_user_password(username: str, request: Request):
    """Admins may reset anyone's password; a user may change their own."""
    sess = auth.verify_session(request.cookies.get(auth.SESSION_COOKIE))
    self_change = bool(sess and sess.get("u") == username)
    if not (_caller_is_admin(request) or self_change):
        raise HTTPException(403, "not permitted")
    try:
        body = await request.json()
    except Exception:
        body = {}
    password = str(body.get("password", ""))
    if len(password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    if not _STORE.get_user(username):
        raise HTTPException(404, "no such user")
    _STORE.set_user_password(username, auth.hash_password(password))
    logger.info("password reset for user: %s", username)
    return {"ok": True}


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

        findings: list[Finding] = []
        async for finding in orchestrator.run(assessment_id, roe, assets, modules, automation_level="assisted"):
            _STORE.insert_finding(assessment_id, finding)
            findings.append(finding)

        # Screenshot evidence is attached to these same Finding objects
        # in-place AFTER orchestrator.run() has finished yielding (see
        # Orchestrator._capture_and_attach_screenshots) - by design, it
        # runs once per unique asset rather than per finding, so it has
        # to happen after the module loop. That means the insert_finding
        # calls above ran before the screenshot evidence existed. Since
        # insert_finding is INSERT OR REPLACE, re-persisting every
        # finding now (the run is fully complete at this point) picks up
        # that evidence instead of silently losing it.
        # Re-run validation now that screenshot evidence exists. The
        # pipeline (including the ai_assisted_analysis and
        # evidence_correlation layers) originally ran inside
        # orchestrator.run(), before screenshots were attached - so its
        # verdicts were computed against an incomplete evidence set
        # (e.g. evidence_correlation would see only 1 evidence type and
        # fail, even though a screenshot has since been added). Re-run
        # it per finding now that the evidence set is final, so the
        # stored validation result reflects everything the finding
        # actually has attached.
        for finding in findings:
            finding.validation = await orchestrator.validation_pipeline.validate(finding)
            finding.status = finding.validation.status
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


@app.get("/api/assessments/{assessment_id}/findings/{finding_id}/evidence/{evidence_id}")
async def get_evidence_bytes(assessment_id: str, finding_id: str, evidence_id: str):
    """
    Serve the raw bytes of one piece of evidence (a screenshot PNG, a
    captured HTTP transaction, etc.) so the dashboard can render it
    directly instead of only showing its text metadata. Read-only, same
    auth tier as /findings and /report.html (no admin token required -
    this is scan output, not a scan-triggering or scope-writing action).
    """
    from fastapi.responses import Response
    from core.schema import EvidenceType
    from evidence.evidence_store import read_evidence_bytes

    if _STORE.get_assessment(assessment_id) is None:
        raise HTTPException(404, "assessment not found")

    finding = _STORE.get_finding(assessment_id, finding_id)
    if finding is None:
        raise HTTPException(404, "finding not found")

    match = next((e for e in finding.evidence if e.evidence_id == evidence_id), None)
    if match is None:
        raise HTTPException(404, "evidence not found")

    try:
        raw = read_evidence_bytes(match.storage_ref)
    except FileNotFoundError:
        raise HTTPException(404, "evidence file not found on disk")

    content_type = "image/png" if match.evidence_type == EvidenceType.SCREENSHOT else "text/plain"
    return Response(content=raw, media_type=content_type)


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

# ── Red-team assessment (hypothesis-driven loop) ────────────────────
# recon -> semantic model -> hypotheses -> gated plan -> run AUTO/approved
# steps through executors -> validation -> store. Semi-autonomous by default:
# non-destructive passive steps auto-run; active steps wait for approval.
#
# In-memory red-team state (plan + pending steps + the recon/semantic/roe needed
# to run an approved step later). Findings persist via _STORE; this dict does
# not survive a restart — move to the DB when this grows past a demo.
_REDTEAM: dict[str, dict] = {}
_REDTEAM_REGISTRY = ExecutorRegistry()


class RunRedTeamRequest(BaseModel):
    target: str
    automation_level: str = "semi_autonomous"
    llm_model: str = "llama3.1"
    llm_timeout: float = 300.0


def _owner_field_for(semantic, endpoints: list[str]) -> str:
    for res in semantic.resources:
        if any(e in res.endpoints for e in endpoints):
            return res.owner_field or ""
    return ""


async def _live_fetch(url: str) -> FetchResult:
    # GET only — the executor never needs more, and this keeps it non-destructive.
    async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as c:
        r = await c.get(url)
        return FetchResult(url=url, status=r.status_code, text=r.text[:200000],
                           headers={k.lower(): v for k, v in r.headers.items()})


def _make_exec_factory(semantic, roe, base_url: str):
    host = roe.authorized_targets[0] if roe.authorized_targets else ""

    def factory(hyp):
        return ExecContext(
            target_host=host, roe=roe, fetch=_live_fetch,
            candidate_ids=["1", "2", "3"],
            owner_field=_owner_field_for(semantic, hyp.target_endpoints),
            base_url=base_url,
        )
    return factory


@app.post("/api/redteam/assess", response_model=RunAssessmentResponse)
async def redteam_assess(
    req: RunRedTeamRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    _require_admin(authorization)
    if not _SCOPE.is_authorized(req.target):
        raise HTTPException(
            403,
            f"target '{req.target}' is not in the authorized scope. "
            f"Authorized targets: {[e.host for e in _SCOPE.targets]}.",
        )
    assessment_id = str(uuid.uuid4())
    _STORE.create_assessment(assessment_id=assessment_id, target=req.target,
                             modules=["redteam"], llm_model=req.llm_model)
    asyncio.create_task(_run_redteam_task(assessment_id, req))
    return RunAssessmentResponse(assessment_id=assessment_id)


async def _run_redteam_task(assessment_id: str, req: RunRedTeamRequest) -> None:
    try:
        roe = build_roe(assessment_id, req.target, _SCOPE)
        asset = Asset(asset_id="a0", name=req.target, asset_type="host",
                      scope_approved=True, metadata={"exposure": "internet"})

        # 1. recon (ReconModule stashes the ReconResult on ctx.config)
        ctx = ModuleRunContext(assessment_id=assessment_id, assets=[asset], roe=roe,
                               automation_level=req.automation_level, config={})
        async for _ in ReconModule().run(ctx):
            pass
        recon = ctx.config.get("recon_results", {}).get("a0")
        if recon is None:
            _STORE.set_status(assessment_id, "error: recon produced no result", error="recon empty")
            return

        # 2. semantic model (local LLM). If it fails or times out, degrade
        # gracefully to recon-only hypotheses rather than failing the whole
        # assessment — the loop still produces injection/XSS/auth hypotheses;
        # only the semantic-dependent ones (BOLA/mass-assignment) are skipped.
        try:
            semantic = await SemanticModelBuilder(
                model=req.llm_model, timeout=req.llm_timeout,
            ).build(recon)
        except Exception as exc:  # noqa: BLE001 - LLM slow/down/invalid output
            from semantic.types import SemanticModel
            logger.warning(
                "redteam %s: semantic model unavailable (%s) - continuing "
                "recon-only (no BOLA/mass-assignment hypotheses this run)",
                assessment_id, exc,
            )
            semantic = SemanticModel(target=req.target,
                                     unknowns=[f"semantic model unavailable: {exc}"])

        # 3. reason + plan + run AUTO steps, validate, store
        base_url = (recon.base_urls or [f"https://{req.target}"])[0]
        orch = RedTeamOrchestrator(
            _REDTEAM_REGISTRY,
            default_pipeline(llm_client=OllamaClient(model=req.llm_model)),
        )
        factory = _make_exec_factory(semantic, roe, base_url)
        result = await orch.assess(
            assessment_id=assessment_id, target=req.target, roe=roe,
            automation_level=req.automation_level, recon=recon,
            semantic=semantic, exec_factory=factory,
        )
        for f in result.findings:
            _STORE.insert_finding(assessment_id, f)

        _REDTEAM[assessment_id] = {
            "plan": result.plan,
            "semantic": semantic,
            "roe": roe,
            "base_url": base_url,
            "llm_model": req.llm_model,
            "pending": {s.hypothesis.hypothesis_id: s for s in result.plan.pending},
        }
        _STORE.set_status(assessment_id, "complete")
    except Exception as exc:  # noqa: BLE001
        logger.exception("redteam assessment %s failed", assessment_id)
        _STORE.set_status(assessment_id, f"error: {exc}", error=str(exc))


@app.get("/api/redteam/assessments/{assessment_id}")
async def redteam_get(assessment_id: str):
    meta = _STORE.get_assessment(assessment_id)
    if meta is None:
        raise HTTPException(404, "assessment not found")
    out = {
        "status": meta["status"],
        "target": meta["target"],
        "findings": [serialize_finding(f) for f in _STORE.list_findings(assessment_id)],
    }
    rt = _REDTEAM.get(assessment_id)
    if rt:
        out["plan"] = rt["plan"].summary()
        out["pending_step_ids"] = list(rt["pending"].keys())
    return out


@app.post("/api/redteam/assessments/{assessment_id}/steps/{hypothesis_id}/approve")
async def redteam_approve(
    assessment_id: str,
    hypothesis_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
):
    _require_admin(authorization)
    rt = _REDTEAM.get(assessment_id)
    if rt is None:
        raise HTTPException(404, "assessment not found, or its plan is no longer in memory")
    step = rt["pending"].get(hypothesis_id)
    if step is None:
        raise HTTPException(404, "no pending step with that hypothesis id")
    orch = RedTeamOrchestrator(
        _REDTEAM_REGISTRY,
        default_pipeline(llm_client=OllamaClient(model=rt.get("llm_model", "llama3.1"))),
    )
    factory = _make_exec_factory(rt["semantic"], rt["roe"], rt["base_url"])
    findings = await orch.approve_step(step, factory)
    for f in findings:
        _STORE.insert_finding(assessment_id, f)
    rt["pending"].pop(hypothesis_id, None)
    return {"approved": hypothesis_id,
            "findings": [serialize_finding(f) for f in findings]}


# ── Static frontend mount — MUST be last ────────────────────────────
_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

if _FRONTEND_DIR.is_dir():
    @app.get("/login")
    async def login_page():
        lp = _FRONTEND_DIR / "login.html"
        return FileResponse(lp if lp.is_file() else _FRONTEND_DIR / "index.html")

    @app.get("/")
    async def serve_index():
        return FileResponse(_FRONTEND_DIR / "index.html")

    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
    logger.info("serving frontend from %s", _FRONTEND_DIR)
else:
    logger.warning("frontend directory not found at %s - static serving disabled",
                   _FRONTEND_DIR)
