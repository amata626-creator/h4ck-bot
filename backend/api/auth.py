"""
Session login for the H4CK-B0T dashboard.

Design, on purpose, dependency-free (stdlib only):
  - Passwords are stored ONLY as a pbkdf2_sha256 hash in the environment
    (H4CK_BOT_ADMIN_PASSWORD_HASH) - never plaintext, never in git.
  - The session cookie is a compact HMAC-signed token (secret:
    H4CK_BOT_SESSION_SECRET) carrying the username + an expiry. No server
    session store needed; tampering or expiry invalidates it.
  - Login is rate-limited per client IP (in-memory) to blunt guessing.

The gate ACTIVATES only when both a password hash and a session secret are
configured (`login_configured()`), so a fresh deploy is never accidentally
locked out before the operator sets a password.

Set the admin password with:
    python backend/api/auth.py set-password [username]
which writes H4CK_BOT_ADMIN_USER / _PASSWORD_HASH (and a _SESSION_SECRET if
missing) into the repo-root .env.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

SESSION_COOKIE = "h4ck_session"
SESSION_TTL = 8 * 3600  # 8 hours

_PBKDF2_ITERATIONS = 200_000

# login rate-limit (per IP, in-memory)
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 300
_ATTEMPTS: dict[str, list[float]] = {}


# ── base64url helpers ───────────────────────────────────────────────
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ── password hashing ────────────────────────────────────────────────
def hash_password(plain: str, iterations: int = _PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(plain: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# ── config from environment ─────────────────────────────────────────
def admin_user() -> str:
    return os.environ.get("H4CK_BOT_ADMIN_USER", "admin")


def _password_hash() -> str:
    return os.environ.get("H4CK_BOT_ADMIN_PASSWORD_HASH", "")


def _session_secret() -> str:
    return os.environ.get("H4CK_BOT_SESSION_SECRET", "")


def login_configured() -> bool:
    """The gate is live only once a password hash AND a session secret exist."""
    return bool(_password_hash() and _session_secret())


def check_credentials(username: str, password: str) -> bool:
    if username != admin_user():
        return False
    h = _password_hash()
    return bool(h) and verify_password(password, h)


# ── signed session token ────────────────────────────────────────────
def make_session(username: str, role: str = "operator", ttl: int = SESSION_TTL) -> str:
    secret = _session_secret().encode()
    payload = {"u": username, "r": role, "exp": int(time.time()) + ttl}
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_session(token: Optional[str]) -> Optional[dict]:
    """Return the session payload {"u": username, "r": role} if the token is
    valid and unexpired, else None."""
    secret = _session_secret().encode()
    if not token or not secret:
        return None
    try:
        body, sig = token.split(".", 1)
        expected = _b64e(hmac.new(secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64d(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return {"u": payload.get("u"), "r": payload.get("r", "operator")}
    except Exception:
        return None


# ── login rate-limit ────────────────────────────────────────────────
def rate_limited(ip: str) -> bool:
    now = time.time()
    arr = [t for t in _ATTEMPTS.get(ip, []) if now - t < _WINDOW_SECONDS]
    _ATTEMPTS[ip] = arr
    return len(arr) >= _MAX_ATTEMPTS


def record_attempt(ip: str) -> None:
    _ATTEMPTS.setdefault(ip, []).append(time.time())


def clear_attempts(ip: str) -> None:
    _ATTEMPTS.pop(ip, None)


# ── CLI: set the admin password (writes the hash into .env) ──────────
def _env_path() -> str:
    # backend/api/auth.py -> repo root
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env")


def _set_env_line(lines: list[str], key: str, value: str) -> list[str]:
    out = [ln for ln in lines if not ln.startswith(key + "=")]
    out.append(f"{key}={value}")
    return out


def _cli_set_password(username: str) -> None:
    import getpass

    pw = getpass.getpass(f"New password for '{username}': ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw != pw2 or not pw:
        raise SystemExit("passwords did not match (or empty) - aborted")

    pw_hash = hash_password(pw)
    path = _env_path()
    lines = []
    if os.path.exists(path):
        with open(path) as f:
            lines = [ln.rstrip("\n") for ln in f if ln.strip()]

    lines = _set_env_line(lines, "H4CK_BOT_ADMIN_USER", username)
    lines = _set_env_line(lines, "H4CK_BOT_ADMIN_PASSWORD_HASH", pw_hash)
    if not any(ln.startswith("H4CK_BOT_SESSION_SECRET=") for ln in lines):
        lines = _set_env_line(lines, "H4CK_BOT_SESSION_SECRET", secrets.token_urlsafe(48))

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
    print(f"Set login for user '{username}' in {path}")

    # Once a user exists in the DB, login checks the DB (not .env). So keep
    # them in sync: if this username is already a DB account, update its hash
    # too, otherwise the new password would silently not take effect.
    try:
        import sqlite3
        root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        db = os.path.join(root, "data", "h4ckbot.db")
        if os.path.exists(db):
            con = sqlite3.connect(db)
            cur = con.execute(
                "UPDATE users SET password_hash=? WHERE username=?", (pw_hash, username)
            )
            con.commit(); con.close()
            if cur.rowcount:
                print(f"Also updated the existing DB account '{username}'.")
    except Exception as exc:  # noqa: BLE001
        print(f"note: could not update DB account ({exc}); it will use its existing password")

    print("Restart the service for it to take effect:  sudo systemctl restart h4ckbot")


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 2 and sys.argv[1] == "set-password":
        _cli_set_password(sys.argv[2] if len(sys.argv) > 2 else "admin")
    else:
        print("usage: python backend/api/auth.py set-password [username]")
