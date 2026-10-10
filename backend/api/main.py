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

from fastapi import FastAPI, HTTPException, Header, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from api import auth
from pydantic import BaseModel

from core.orchestrator import Orchestrator
from core.rules_of_engagement import RulesOfEngagement
from core.schema import Asset, Finding, Evidence, EvidenceType, FindingStatus
from core.scope_loader import Scope, ScopeError, build_roe, load_scope
from evidence.llm_client import OllamaClient
from evidence.validation_pipeline import default_pipeline
from evidence.screenshot_capture import screenshot_findings
from modules.discovery_module import DiscoveryModule
from modules.misconfig_module import MisconfigModule
from modules.example_web_api_module import WebApiScannerModule
from modules.owasp_top10_module import OwaspTop10Module
from modules.advanced_checks_module import AdvancedChecksModule
from modules.advanced_checks2_module import AdvancedChecks2Module
from modules.mobile_android_module import AndroidStaticModule
from modules.nuclei_module import NucleiModule
from modules.nmap_module import NmapModule
from modules.credentialed_module import run_audit, audit_to_findings
from modules.cloud_aws_module import collect as aws_collect, cloud_findings
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
    # /oob/<token> is the out-of-band listener: external back ends must be able
    # to hit it unauthenticated, otherwise we could never detect blind SSRF.
    if path in _AUTH_PUBLIC_PATHS or path.startswith("/oob/") or not _login_enabled():
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


def _caller_username(request: Request, authorization: str | None = None) -> str:
    """Best-effort identity of the caller for audit: the session username, or
    'admin-token' when authenticated by the bearer token."""
    sess = auth.verify_session(request.cookies.get(auth.SESSION_COOKIE))
    if sess and sess.get("u"):
        return str(sess["u"])
    return "admin-token"


_VALID_ROLES = {"admin", "operator"}
import re as _re
_USERNAME_RE = _re.compile(r"^[A-Za-z0-9._-]{3,32}$")


# ── Request/response models ─────────────────────────────────────────
class RunAssessmentRequest(BaseModel):
    target: str
    modules: list[str] = ["discovery", "misconfig", "nuclei", "nmap"]
    llm_model: str = "llama3.1:latest"
    # Run the AI red-team engine (deep recon -> grounded hypotheses ->
    # non-destructive executors -> validation) after the classic modules,
    # under the same assessment. This is what makes "Start scan" actually
    # exercise the engine instead of just the legacy modules.
    full_engine: bool = True
    automation_level: str = "autonomous"
    llm_timeout: float = 120.0
    # Authenticated assessment: a Cookie string copied from a logged-in
    # browser session (e.g. "sid=abc; csrf=def"), and/or extra request
    # headers (e.g. {"Authorization": "Bearer ..."}). When supplied, recon
    # and the executors carry the session so the scan sees the app behind
    # the login, not just the public surface.
    auth_cookie: str = ""
    auth_headers: dict = {}
    # Universal scope: the operator may scan ANY target without pre-registering
    # it in scope.yaml, but every scan of a not-yet-authorized target must carry
    # an authorization attestation, which is recorded to the audit trail. This
    # is the single guardrail that keeps the platform an *authorized* VAPT tool
    # rather than an unauthenticated scanner. `authorized` is the operator's
    # one-click "I am authorized to assess this target"; `authorization_ref` is
    # the free-text engagement reference that attestation is logged under.
    authorized: bool = False
    authorization_ref: str = ""


class RunAssessmentResponse(BaseModel):
    assessment_id: str


MODULE_REGISTRY = {
    "discovery": DiscoveryModule,
    "misconfig": MisconfigModule,
    "nuclei": NucleiModule,
    "nmap": NmapModule,
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


# ── Dynamic scope resolution (file scope ∪ DB-authorized targets) ───
# This is what makes the platform universal: any target an operator attests
# they are authorized to test is scannable at runtime, without editing
# scope.yaml. The authorization gate is preserved — a target is authorized
# only if it is in the file scope OR has a DB record with an authorization_ref.

def _resolve_scope(target: str) -> dict | None:
    entry = _SCOPE.find(target)
    if entry is not None:
        return {
            "host": entry.host, "authorized_by": _SCOPE.authorized_by or "scope.yaml",
            "permitted_techniques": list(entry.permitted_techniques),
            "active_testing_permitted": entry.active_testing_permitted,
            "destructive_actions_allowed": entry.destructive_actions_allowed,
            "source": "scope.yaml",
        }
    host = (target or "").strip().lower()
    db = _STORE.get_authorized_target(host)
    if db is not None:
        return {
            "host": db["host"], "authorized_by": db.get("added_by") or "operator-attested",
            "permitted_techniques": db["permitted_techniques"],
            "active_testing_permitted": db["active_testing_permitted"],
            "destructive_actions_allowed": db["destructive_actions_allowed"],
            "source": "runtime", "authorization_ref": db.get("authorization_ref", ""),
        }
    return None


def _is_authorized(target: str) -> bool:
    return _resolve_scope(target) is not None


def _normalize_host(target: str) -> str:
    """Strip scheme/path/port from a pasted target, leaving the bare host."""
    host = (target or "").strip().lower()
    host = host.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if not host or " " in host:
        return ""
    return host


def _build_roe_for(assessment_id: str, target: str):
    s = _resolve_scope(target)
    if s is None:
        raise ScopeError(
            f"target '{target}' is not authorized. Add it with an authorization "
            "reference (POST /api/scope/targets) or in scope.yaml first."
        )
    now = datetime.now(timezone.utc)
    return RulesOfEngagement(
        assessment_id=assessment_id, authorized_by=s["authorized_by"],
        authorized_targets=[s["host"]],
        testing_window_start=now - timedelta(minutes=1),
        testing_window_end=now + timedelta(hours=4),
        permitted_techniques=s["permitted_techniques"],
        active_testing_permitted=s["active_testing_permitted"],
        destructive_actions_allowed=s["destructive_actions_allowed"],
    )


@app.get("/api/scope")
async def get_scope():
    """All authorized targets: the static scope.yaml entries plus any the
    operator has authorized at runtime (with an authorization reference)."""
    targets = [
        {
            "host": e.host, "note": e.note,
            "permitted_techniques": list(e.permitted_techniques),
            "active_testing_permitted": e.active_testing_permitted,
            "destructive_actions_allowed": e.destructive_actions_allowed,
            "source": "scope.yaml",
        }
        for e in _SCOPE.targets
    ]
    for t in _STORE.list_authorized_targets():
        targets.append({
            "host": t["host"], "note": t.get("note", ""),
            "permitted_techniques": t["permitted_techniques"],
            "active_testing_permitted": t["active_testing_permitted"],
            "destructive_actions_allowed": t["destructive_actions_allowed"],
            "source": "runtime", "authorization_ref": t.get("authorization_ref", ""),
            "added_by": t.get("added_by", ""), "added_at": t.get("added_at", ""),
        })
    return {
        "authorized_by": _SCOPE.authorized_by,
        "authorization_ref": _SCOPE.authorization_ref,
        "targets": targets,
    }


class AddTargetRequest(BaseModel):
    host: str
    authorization_ref: str
    note: str = ""
    active_testing_permitted: bool = True


@app.post("/api/scope/targets", status_code=201)
async def add_authorized_target(
    req: AddTargetRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Authorize ANY target at runtime (universal scope). Requires an
    authorization reference — this is still authorized-testing-only, just not
    confined to scope.yaml. Admin/session gated and audited."""
    _require_admin(authorization)
    host = _normalize_host(req.host)
    if not host:
        raise HTTPException(400, "invalid host")
    if not (req.authorization_ref or "").strip():
        raise HTTPException(400, "authorization_ref is required — you must attest authorization to test this target")
    caller = _caller_username(request, authorization)
    _STORE.add_authorized_target(
        host=host, authorization_ref=req.authorization_ref.strip(), note=req.note.strip(),
        active_testing_permitted=bool(req.active_testing_permitted), added_by=caller,
    )
    client_ip = request.client.host if request.client else "unknown"
    logger.info("scope: %s authorized target '%s' (ref=%r, ip=%s)",
                caller, host, req.authorization_ref.strip()[:80], client_ip)
    return {"host": host, "authorized": True, "source": "runtime"}


@app.delete("/api/scope/targets/{host}")
async def remove_authorized_target(
    host: str, request: Request, authorization: str | None = Header(default=None),
):
    """Remove a runtime-authorized target. scope.yaml entries are not
    affected (edit the file for those)."""
    _require_admin(authorization)
    removed = _STORE.remove_authorized_target(host)
    if not removed:
        raise HTTPException(404, "no runtime-authorized target with that host")
    logger.info("scope: removed runtime target '%s'", host.strip().lower())
    return {"host": host.strip().lower(), "removed": True}


_DEFAULT_LLM_MODEL = "llama3.1:latest"


@app.get("/api/models")
async def list_models():
    """Local LLMs available via Ollama, for the model dropdown. Graceful: if
    Ollama is unreachable, returns a small fallback so the UI still works."""
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    models: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get(f"{base}/api/tags")
            r.raise_for_status()
            data = r.json()
        models = [m.get("name") for m in data.get("models", []) if m.get("name")]
    except Exception:  # noqa: BLE001 - Ollama down / not installed
        models = []
    if not models:
        models = [_DEFAULT_LLM_MODEL, "qwen2.5:3b"]
    default = _DEFAULT_LLM_MODEL if _DEFAULT_LLM_MODEL in models else models[0]
    return {"models": models, "default": default}


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

    # Universal scope with launch-time authorization. Any target is scannable,
    # but a target not already on record (scope.yaml or a prior runtime
    # attestation) must carry an authorization attestation IN THIS request. We
    # record that attestation to the audit trail and proceed - no separate
    # pre-registration step. The attestation (not an allowlist) is what keeps
    # every scan an authorized one.
    if not _is_authorized(req.target):
        if not (req.authorized and (req.authorization_ref or "").strip()):
            raise HTTPException(
                403,
                f"target '{req.target}' has no authorization on record. Re-submit with "
                "authorized=true and an authorization_ref attesting you are permitted to "
                "test it (the dashboard's authorization checkbox does this for you).",
            )
        host = _normalize_host(req.target)
        if not host:
            raise HTTPException(400, f"invalid target host: {req.target!r}")
        caller = _caller_username(request, authorization)
        _STORE.add_authorized_target(
            host=host, authorization_ref=req.authorization_ref.strip(),
            note="operator-attested at scan launch",
            active_testing_permitted=True, added_by=caller,
        )
        _ip = request.client.host if request.client else "unknown"
        logger.info("scope: %s attested authorization for '%s' at scan launch "
                    "(ref=%r, ip=%s)", caller, host,
                    req.authorization_ref.strip()[:80], _ip)

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


# ── Mobile app static analysis (APK upload) ──────────────────────────
_MOBILE_UPLOAD_DIR = Path(__file__).resolve().parents[2] / "data" / "mobile_uploads"
_MAX_MOBILE_BYTES = 200 * 1024 * 1024   # 200 MB cap on an uploaded app


def _build_mobile_roe(assessment_id: str, name: str):
    """RoE for an uploaded mobile app. Authorization is the act of an
    authenticated operator uploading an app they are entitled to test;
    static analysis is passive (no live target), so active testing is not
    requested. Window is open now for a short processing period."""
    now = datetime.now(timezone.utc)
    return RulesOfEngagement(
        assessment_id=assessment_id,
        authorized_by="operator-upload",
        authorized_targets=[name],
        testing_window_start=now - timedelta(minutes=1),
        testing_window_end=now + timedelta(hours=1),
        permitted_techniques=["static_analysis"],
        active_testing_permitted=False,
        destructive_actions_allowed=False,
    )


async def _run_mobile_task(assessment_id: str, file_path: str, display_name: str) -> None:
    try:
        asset = Asset(
            asset_id="a0", name=display_name, asset_type="mobile_app",
            scope_approved=True, metadata={"file_path": file_path},
        )
        roe = _build_mobile_roe(assessment_id, display_name)
        orchestrator = Orchestrator(
            validation_pipeline=default_pipeline(
                llm_client=OllamaClient(model=req.llm_model, timeout=25.0)
            )
        )
        modules = [AndroidStaticModule()]  # iOS module slots in here next
        count = 0
        async for finding in orchestrator.run(
            assessment_id, roe, [asset], modules, automation_level="autonomous"
        ):
            _STORE.insert_finding(assessment_id, finding)
            count += 1
        logger.info("mobile assessment %s: %d findings on %s", assessment_id, count, display_name)
        _STORE.set_status(assessment_id, "complete")
    except Exception as exc:  # noqa: BLE001
        logger.exception("mobile assessment %s failed", assessment_id)
        _STORE.set_status(assessment_id, f"error: {exc}", error=str(exc))


# ── Cloud posture scanning (AWS CSPM) ───────────────────────────────
class CloudScanRequest(BaseModel):
    access_key: str
    secret_key: str
    session_token: str = ""
    region: str = "us-east-1"
    authorization_ref: str


async def _run_cloud_task(assessment_id: str, access_key: str, secret_key: str,
                          session_token: str, region: str) -> None:
    try:
        data = await asyncio.to_thread(aws_collect, access_key, secret_key, session_token, region)
        account = data.get("account", "unknown")
        findings = cloud_findings(account, data)
        pipeline = default_pipeline(llm_client=OllamaClient(model="llama3.1:latest", timeout=25.0))
        for f in findings:
            if f.finding_kind != FindingKind.INFORMATIONAL:
                f.validation = await pipeline.validate(f)
                f.status = f.validation.status
            _STORE.insert_finding(assessment_id, f)
        logger.info("cloud assessment %s: %d finding(s) on account %s", assessment_id, len(findings), account)
        _STORE.set_status(assessment_id, "complete")
    except Exception as exc:  # noqa: BLE001
        logger.warning("cloud assessment %s failed: %s", assessment_id, exc)
        _STORE.set_status(assessment_id, f"error: {exc}", error=str(exc))


@app.post("/api/cloud/assess", response_model=RunAssessmentResponse)
async def cloud_assess(
    req: CloudScanRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """AWS cloud posture scan (read-only CSPM). Admin-gated; the operator
    attests authorization and supplies AWS credentials for an account they are
    entitled to audit. Credentials are used for the session and never logged or
    stored; only the authorization reference is kept."""
    _require_admin(authorization)
    if not (req.access_key or "").strip() or not (req.secret_key or "").strip():
        raise HTTPException(400, "AWS access key and secret key are required")
    if not (req.authorization_ref or "").strip():
        raise HTTPException(400, "authorization_ref is required — attest authorization to audit this account")
    caller = _caller_username(request, authorization)
    assessment_id = str(uuid.uuid4())
    _STORE.create_assessment(assessment_id=assessment_id, target=f"aws:{req.region}",
                             modules=["cloud_aws_scan"], llm_model="n/a")
    asyncio.create_task(_run_cloud_task(
        assessment_id, req.access_key, req.secret_key, req.session_token, req.region))
    logger.info("cloud scan started (region=%s, ref=%r, by=%s)",
                req.region, req.authorization_ref.strip()[:60], caller)
    return RunAssessmentResponse(assessment_id=assessment_id)


# ── Credentialed (authenticated) host scanning ──────────────────────
class CredentialedScanRequest(BaseModel):
    host: str
    username: str
    password: str = ""
    private_key: str = ""
    port: int = 22
    authorization_ref: str


async def _run_credentialed_task(assessment_id: str, host: str, username: str,
                                 password: str, key_text: str, port: int) -> None:
    try:
        # SSH + command execution is blocking (paramiko) — run off the loop.
        data = await asyncio.to_thread(run_audit, host, username, password, key_text, port)
        findings = audit_to_findings(host, data)
        pipeline = default_pipeline(llm_client=OllamaClient(model="llama3.1:latest", timeout=25.0))
        for f in findings:
            if f.finding_kind != FindingKind.INFORMATIONAL:
                f.validation = await pipeline.validate(f)
                f.status = f.validation.status
            _STORE.insert_finding(assessment_id, f)
        logger.info("credentialed assessment %s: %d finding(s) on %s", assessment_id, len(findings), host)
        _STORE.set_status(assessment_id, "complete")
    except Exception as exc:  # noqa: BLE001
        logger.warning("credentialed assessment %s failed: %s", assessment_id, exc)
        _STORE.set_status(assessment_id, f"error: {exc}", error=str(exc))


@app.post("/api/credentialed/assess", response_model=RunAssessmentResponse)
async def credentialed_assess(
    req: CredentialedScanRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Authenticated (credentialed) host scan over SSH — missing security
    updates + hardening checks. Read-only. Admin-gated; the operator attests
    authorization and supplies credentials for a host they are entitled to
    test. Credentials are used for the connection and never logged or stored;
    only the authorization reference is persisted."""
    _require_admin(authorization)
    host = (req.host or "").strip().lower().split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if not host:
        raise HTTPException(400, "invalid host")
    if not (req.authorization_ref or "").strip():
        raise HTTPException(400, "authorization_ref is required — attest authorization to test this host")
    if not (req.username or "").strip():
        raise HTTPException(400, "username is required")
    if not (req.password or req.private_key):
        raise HTTPException(400, "a password or private_key is required")

    # Authorize the host at runtime (the attestation), like the universal-scope flow.
    caller = _caller_username(request, authorization)
    _STORE.add_authorized_target(host=host, authorization_ref=req.authorization_ref.strip(),
                                 note="credentialed scan", added_by=caller)

    assessment_id = str(uuid.uuid4())
    _STORE.create_assessment(assessment_id=assessment_id, target=host,
                             modules=["credentialed_scan"], llm_model="n/a")
    asyncio.create_task(_run_credentialed_task(
        assessment_id, host, req.username, req.password, req.private_key, req.port))
    logger.info("credentialed scan started for %s (ref=%r, by=%s)",
                host, req.authorization_ref.strip()[:60], caller)
    return RunAssessmentResponse(assessment_id=assessment_id)


@app.post("/api/mobile/assess", response_model=RunAssessmentResponse)
async def mobile_assess(
    request: Request,
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
):
    """Upload an APK/IPA and run the mobile static-analysis stage on it.
    Admin-gated (same as a scan); the uploaded binary is the authorization."""
    _require_admin(authorization)

    raw = await file.read()
    if not raw:
        raise HTTPException(400, "empty upload")
    if len(raw) > _MAX_MOBILE_BYTES:
        raise HTTPException(413, f"file exceeds {_MAX_MOBILE_BYTES // (1024*1024)} MB limit")

    assessment_id = str(uuid.uuid4())
    orig = os.path.basename(file.filename or "app")
    suffix = ".apk" if orig.lower().endswith(".apk") else (".ipa" if orig.lower().endswith(".ipa") else ".bin")
    _MOBILE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = _MOBILE_UPLOAD_DIR / f"{assessment_id}{suffix}"
    dest.write_bytes(raw)

    display_name = orig or f"mobile-app{suffix}"
    _STORE.create_assessment(
        assessment_id=assessment_id, target=display_name,
        modules=["mobile_android_static"], llm_model="llama3.1:latest",
    )
    asyncio.create_task(_run_mobile_task(assessment_id, str(dest), display_name))
    return RunAssessmentResponse(assessment_id=assessment_id)


def _finding_cves(f: Finding) -> set[str]:
    cves = {c.cve_id.upper() for c in (f.cve_refs or []) if c.cve_id}
    # Nuclei also records the CVE in evidence metadata.
    for e in f.evidence:
        for c in (e.metadata or {}).get("cve", []) or []:
            if c:
                cves.add(str(c).upper())
    return cves


async def _confirm_nmap_with_nuclei(findings: list[Finding], pipeline) -> list[Finding]:
    """Promote version-inferred nmap CVE findings to VALIDATED when Nuclei
    independently confirmed the same CVE on the same asset. Returns the
    findings whose status changed (for re-persisting)."""
    # CVEs that Nuclei actively confirmed, per asset.
    confirmed: dict[str, dict[str, Finding]] = {}
    for f in findings:
        if f.module_source.startswith("nuclei") and f.status == FindingStatus.VALIDATED:
            for cve in _finding_cves(f):
                confirmed.setdefault(f.asset.name, {})[cve] = f
    if not confirmed:
        return []

    promoted: list[Finding] = []
    for f in findings:
        if f.module_source != "nmap_cve":
            continue
        asset_confirmed = confirmed.get(f.asset.name, {})
        for cve in _finding_cves(f):
            nf = asset_confirmed.get(cve)
            if not nf:
                continue
            # Add the Nuclei confirmation as a second, independent evidence
            # type (HTTP_TRANSACTION) so corroboration is real, not asserted.
            note = (f"Independently confirmed by the Nuclei engine: template matched {cve} "
                    f"on {f.asset.name}. Version inference corroborated by an active check.")
            f.add_evidence(Evidence.new(
                evidence_type=EvidenceType.HTTP_TRANSACTION, raw_bytes=note.encode(),
                storage_ref=f"mem://confirm/{f.finding_id}",
                description=f"Nuclei confirmation of {cve}",
                metadata={"preview": note, "source": "nuclei_confirmation", "cve": [cve],
                          "confirmed_by": nf.finding_id},
            ))
            f.title = f.title.replace("(version-inferred)", "(confirmed by Nuclei)")
            f.validation = await pipeline.validate(f)
            f.status = f.validation.status
            promoted.append(f)
            break
    return promoted


async def _run_assessment_task(
    assessment_id: str,
    req: RunAssessmentRequest,
    client_ip: str = "unknown",
):
    try:
        roe = _build_roe_for(assessment_id, req.target)

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
                llm_client=OllamaClient(model=req.llm_model, timeout=25.0)
            )
        )

        findings: list[Finding] = []
        async for finding in orchestrator.run(
            assessment_id, roe, assets, modules,
            automation_level="assisted", auth=_auth_from_request(req),
        ):
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

        # Confirmation loop: where nmap inferred a CVE from a version AND Nuclei
        # independently confirmed the same CVE on the same target, promote the
        # version-inferred finding to VALIDATED with the Nuclei match as
        # corroborating evidence. Two independent engines agreeing turns
        # inference into proof.
        promoted = await _confirm_nmap_with_nuclei(
            findings, orchestrator.validation_pipeline
        )
        for finding in promoted:
            _STORE.insert_finding(assessment_id, finding)
        if promoted:
            logger.info("assessment %s: Nuclei confirmed %d version-inferred CVE(s)",
                        assessment_id, len(promoted))

        # Full engine: run the AI red-team loop on the same target/assessment,
        # so one "Start scan" produces recon-grounded, executor-confirmed,
        # validated findings - not just the legacy modules' output. Isolated
        # in its own try so an engine hiccup never discards the classic
        # findings already stored.
        if getattr(req, "full_engine", False):
            try:
                rt_findings = await _run_redteam_pipeline(
                    assessment_id, req.target, roe,
                    getattr(req, "automation_level", "autonomous"),
                    req.llm_model, getattr(req, "llm_timeout", 300.0),
                    auth=_auth_from_request(req),
                )
                logger.info("assessment %s: red-team engine added %d findings",
                            assessment_id, len(rt_findings))
            except Exception as exc:  # noqa: BLE001
                logger.exception("assessment %s: red-team engine failed (classic "
                                 "findings kept): %s", assessment_id, exc)

        # AI attack-path chaining: reason over everything confirmed and compose
        # the findings into exploit chains (the pentester's narrative). Grounded
        # to real finding_ids, best-effort, and isolated so a failure never
        # affects the findings already stored.
        try:
            await _compose_attack_paths(assessment_id, req.llm_model,
                                        getattr(req, "llm_timeout", 120.0))
        except Exception as exc:  # noqa: BLE001
            logger.info("assessment %s: attack-path chaining skipped: %s", assessment_id, exc)

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
    data = build_report_data(meta, findings, scope_note=_SCOPE.authorization_ref,
                             attack_paths=_STORE.list_attack_paths(assessment_id))
    return build_report_json(data)


@app.get("/api/assessments/{assessment_id}/report.html")
async def get_report_html(assessment_id: str):
    from fastapi.responses import HTMLResponse
    meta = _STORE.get_assessment(assessment_id)
    if meta is None:
        raise HTTPException(404, "assessment not found")
    findings = _STORE.list_findings(assessment_id)
    data = build_report_data(meta, findings, scope_note=_SCOPE.authorization_ref,
                             attack_paths=_STORE.list_attack_paths(assessment_id))
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
    llm_model: str = "llama3.1:latest"
    llm_timeout: float = 120.0
    # Authenticated assessment (see RunAssessmentRequest).
    auth_cookie: str = ""
    auth_headers: dict = {}


def _owner_field_for(semantic, endpoints: list[str]) -> str:
    for res in semantic.resources:
        if any(e in res.endpoints for e in endpoints):
            return res.owner_field or ""
    return ""


def _make_live_fetch(auth: dict | None = None):
    """Build the GET-only fetch the executors use. If an authenticated session
    was supplied (Cookie string and/or extra headers), carry it on every
    probe so the executors exercise the app behind the login — the same
    session recon crawled with."""
    auth = auth or {}
    extra: dict[str, str] = {}
    for _k, _v in (auth.get("headers") or {}).items():
        extra[str(_k)] = str(_v)
    if auth.get("cookie"):
        extra["Cookie"] = str(auth["cookie"])

    async def _live_fetch(url: str) -> FetchResult:
        # GET only — the executor never needs more, and this keeps it non-destructive.
        async with httpx.AsyncClient(
            verify=False, timeout=10.0, follow_redirects=True, headers=extra or None,
        ) as c:
            r = await c.get(url)
            return FetchResult(url=url, status=r.status_code, text=r.text[:200000],
                               headers={k.lower(): v for k, v in r.headers.items()})
    return _live_fetch


def _make_live_post(auth: dict | None = None):
    """Build the body-POST used only by the XXE executor for its inert,
    detection-only XML payload. Carries the auth session like the GET fetch."""
    auth = auth or {}
    extra: dict[str, str] = {}
    for _k, _v in (auth.get("headers") or {}).items():
        extra[str(_k)] = str(_v)
    if auth.get("cookie"):
        extra["Cookie"] = str(auth["cookie"])

    async def _live_post(url: str, body: bytes, content_type: str) -> FetchResult:
        headers = dict(extra)
        headers["Content-Type"] = content_type
        async with httpx.AsyncClient(
            verify=False, timeout=10.0, follow_redirects=True, headers=headers,
        ) as c:
            r = await c.post(url, content=body)
            return FetchResult(url=url, status=r.status_code, text=r.text[:200000],
                               headers={k.lower(): v for k, v in r.headers.items()})
    return _live_post


def _make_exec_factory(semantic, roe, base_url: str, auth: dict | None = None):
    host = roe.authorized_targets[0] if roe.authorized_targets else ""
    fetch = _make_live_fetch(auth)
    poster = _make_live_post(auth)
    from oob.listener import oob_base_url
    oob_base = oob_base_url()

    def factory(hyp):
        return ExecContext(
            target_host=host, roe=roe, fetch=fetch,
            candidate_ids=["1", "2", "3"],
            owner_field=_owner_field_for(semantic, hyp.target_endpoints),
            base_url=base_url, oob_base_url=oob_base, post=poster,
        )
    return factory


@app.api_route("/oob/{token}", methods=["GET", "POST", "HEAD", "PUT"])
async def oob_callback(token: str, request: Request):
    """Out-of-band listener endpoint. Records any inbound hit carrying a token,
    so a blind SSRF (the target's back end fetching our injected callback URL)
    is detected. Unauthenticated by design — external back ends must reach it."""
    from fastapi.responses import Response
    from oob.listener import store
    ip = request.client.host if request.client else "unknown"
    store().record(
        token=token, source_ip=ip, method=request.method,
        path=str(request.url.path),
        user_agent=request.headers.get("user-agent", ""),
        host=request.headers.get("host", ""),
    )
    logger.info("oob: interaction recorded for token %s from %s", token[:10], ip)
    return Response(content=b"ok", media_type="text/plain")


@app.post("/api/redteam/assess", response_model=RunAssessmentResponse)
async def redteam_assess(
    req: RunRedTeamRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    _require_admin(authorization)
    if not _is_authorized(req.target):
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


async def _compose_attack_paths(assessment_id: str, llm_model: str, llm_timeout: float) -> None:
    """Chain the assessment's confirmed findings into AI-composed attack paths,
    persist them, and tag member findings (so the UI 'Has attack path' filter
    lights up). Grounded + best-effort; no-op when nothing chains."""
    from redteam.attack_paths import AttackPathChainer, attack_path_to_dict
    findings = _STORE.list_findings(assessment_id)
    chainer = AttackPathChainer(model=llm_model, timeout=min(llm_timeout, 60.0))
    paths = await chainer(findings)
    if not paths:
        return
    by_id = {f.finding_id: f for f in findings}
    tagged: set[str] = set()
    for ap in paths:
        _STORE.insert_attack_path(assessment_id, attack_path_to_dict(ap))
        for fid in ap.finding_ids:
            f = by_id.get(fid)
            if f is not None and not f.attack_path_id:   # first chain to claim it wins
                f.attack_path_id = ap.attack_path_id
                tagged.add(fid)
    for fid in tagged:
        _STORE.insert_finding(assessment_id, by_id[fid])
    logger.info("assessment %s: composed %d attack path(s), tagged %d finding(s)",
                assessment_id, len(paths), len(tagged))


async def _run_redteam_pipeline(
    assessment_id: str, target: str, roe, automation_level: str,
    llm_model: str, llm_timeout: float = 120.0, auth: dict | None = None,
) -> list[Finding]:
    """Run the full red-team engine (recon -> semantic -> hypotheses -> gated
    plan -> executors -> validation), persist its findings, and record the
    plan. Returns the findings. Raises on hard failure (e.g. recon empty);
    the caller decides how to surface that. Reused by the standalone red-team
    endpoint AND the dashboard's full-engine scan."""
    asset = Asset(asset_id="a0", name=target, asset_type="host",
                  scope_approved=True, metadata={"exposure": "internet"})
    auth = auth or {}

    # 1. recon (ReconModule stashes the ReconResult on ctx.config). The auth
    # session (if any) rides along on ctx.config so the crawler authenticates.
    ctx = ModuleRunContext(assessment_id=assessment_id, assets=[asset], roe=roe,
                           automation_level=automation_level, config={"auth": auth})
    async for _ in ReconModule().run(ctx):
        pass
    recon = ctx.config.get("recon_results", {}).get("a0")
    if recon is None:
        raise RuntimeError("recon produced no result")

    # 2. semantic model (local LLM). Degrade gracefully on timeout/failure to
    # recon-only hypotheses (injection/XSS/auth still generated).
    try:
        semantic = await SemanticModelBuilder(model=llm_model, timeout=llm_timeout).build(recon)
    except Exception as exc:  # noqa: BLE001
        from semantic.types import SemanticModel
        logger.warning("redteam %s: semantic model unavailable (%s) - recon-only",
                       assessment_id, exc)
        semantic = SemanticModel(target=target, unknowns=[f"semantic model unavailable: {exc}"])

    # 3. reason + plan + run AUTO steps, validate, store
    base_url = (recon.base_urls or [f"https://{target}"])[0]
    orch = RedTeamOrchestrator(
        _REDTEAM_REGISTRY, default_pipeline(llm_client=OllamaClient(model=llm_model, timeout=25.0)),
    )
    factory = _make_exec_factory(semantic, roe, base_url, auth=auth)
    # The AI strategist drives the adaptive loop (observe -> reason -> pivot). It
    # only acts where auto steps execute, so it's wired for autonomous runs; it's
    # best-effort (Ollama down -> loop just ends with the seed findings) and the
    # orchestrator re-grounds everything it proposes, so it can't invent targets.
    strategist = None
    if automation_level == "autonomous":
        from redteam.strategist import LlmStrategist
        strategist = LlmStrategist(model=llm_model, timeout=min(llm_timeout, 60.0))
    result = await orch.assess(
        assessment_id=assessment_id, target=target, roe=roe,
        automation_level=automation_level, recon=recon,
        semantic=semantic, exec_factory=factory, strategist=strategist,
    )
    # Screenshot each finding at its OWN url (the reflected-XSS page, the
    # probed endpoint), carrying the session so authenticated pages render —
    # then persist, so the screenshot evidence is saved with the finding.
    try:
        await screenshot_findings(result.findings, assessment_id, auth=auth)
    except Exception as exc:  # noqa: BLE001 - evidence capture is best-effort
        logger.warning("redteam %s: screenshot capture failed: %s", assessment_id, exc)
    for f in result.findings:
        _STORE.insert_finding(assessment_id, f)
    _REDTEAM[assessment_id] = {
        "plan": result.plan, "semantic": semantic, "roe": roe,
        "base_url": base_url, "llm_model": llm_model, "auth": auth,
        "pending": {s.hypothesis.hypothesis_id: s for s in result.plan.pending},
    }
    logger.info("redteam pipeline %s: %d findings, plan=%s",
                assessment_id, len(result.findings), result.plan.summary().get("counts"))
    return result.findings


def _auth_from_request(req) -> dict:
    """Build the auth session dict ({"cookie": str, "headers": dict}) from a
    scan request. Empty when no session was supplied — recon/executors then
    run unauthenticated, exactly as before."""
    cookie = (getattr(req, "auth_cookie", "") or "").strip()
    headers = getattr(req, "auth_headers", None) or {}
    out: dict = {}
    if cookie:
        out["cookie"] = cookie
    if headers:
        out["headers"] = headers
    return out


async def _run_redteam_task(assessment_id: str, req: RunRedTeamRequest) -> None:
    try:
        roe = _build_roe_for(assessment_id, req.target)
        await _run_redteam_pipeline(
            assessment_id, req.target, roe, req.automation_level,
            req.llm_model, req.llm_timeout, auth=_auth_from_request(req),
        )
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
        default_pipeline(llm_client=OllamaClient(model=rt.get("llm_model", "llama3.1:latest"), timeout=25.0)),
    )
    factory = _make_exec_factory(rt["semantic"], rt["roe"], rt["base_url"], auth=rt.get("auth"))
    findings = await orch.approve_step(step, factory)
    for f in findings:
        _STORE.insert_finding(assessment_id, f)
    rt["pending"].pop(hypothesis_id, None)
    return {"approved": hypothesis_id,
            "findings": [serialize_finding(f) for f in findings]}


# ── Static frontend mount — MUST be last ────────────────────────────
_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

if _FRONTEND_DIR.is_dir():
    # Always revalidate the HTML entry pages so a redeploy is picked up on a
    # normal refresh. The HTML is tiny and references versioned assets
    # (app.js?v=N), so this is cheap and prevents stale-page confusion.
    _NO_CACHE = {"Cache-Control": "no-cache, must-revalidate"}

    @app.get("/login")
    async def login_page():
        lp = _FRONTEND_DIR / "login.html"
        return FileResponse(lp if lp.is_file() else _FRONTEND_DIR / "index.html",
                            headers=_NO_CACHE)

    @app.get("/")
    async def serve_index():
        return FileResponse(_FRONTEND_DIR / "index.html", headers=_NO_CACHE)

    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
    logger.info("serving frontend from %s", _FRONTEND_DIR)
else:
    logger.warning("frontend directory not found at %s - static serving disabled",
                   _FRONTEND_DIR)
