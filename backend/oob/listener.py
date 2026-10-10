"""
Out-of-band (OOB) interaction listener — the capability that turns blind
vulnerabilities into confirmed ones.

Many of the highest-impact bugs are *blind*: the server does something on the
back end (fetches a URL, resolves a hostname) with no change in the HTTP
response you can see. The only reliable signal is the target reaching back out
to a server you control. This module is that server's memory: it mints unique
tokens, and records any inbound hit carrying a token.

Design:
  - A single in-process store, shared by the /oob/<token> route (which records
    hits) and the executors (which mint tokens and poll for hits). The platform
    runs as one uvicorn process, so in-memory is correct and simple.
  - The callback base URL (what the target must be able to reach) is configured
    via H4CK_BOT_OOB_BASE, e.g. "http://scan.vaptix.com". If it is unset, OOB
    detection is skipped with an honest log — there is no public host to call
    back to.

Non-destructive: a token is just an inert, unique URL. Observing whether a
target fetches it is passive detection; no exploit payload is involved.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass, field


@dataclass
class Interaction:
    token: str
    at: float
    source_ip: str
    method: str
    path: str
    user_agent: str = ""
    host: str = ""

    def summary(self) -> str:
        from datetime import datetime, timezone
        ts = datetime.fromtimestamp(self.at, timezone.utc).isoformat()
        return (f"OOB interaction at {ts}\n"
                f"  from: {self.source_ip}\n"
                f"  {self.method} {self.path}\n"
                f"  host: {self.host}\n"
                f"  user-agent: {self.user_agent}")


class OobStore:
    def __init__(self, cap_tokens: int = 5000):
        self._lock = threading.Lock()
        self._known: set[str] = set()
        self._hits: dict[str, list[Interaction]] = {}
        self._cap = cap_tokens

    def new_token(self) -> str:
        t = "oob" + uuid.uuid4().hex[:18]
        with self._lock:
            if len(self._known) >= self._cap:
                # drop the oldest-known token's hits to stay bounded
                old = next(iter(self._known))
                self._known.discard(old)
                self._hits.pop(old, None)
            self._known.add(t)
        return t

    def record(self, token: str, source_ip: str, method: str, path: str,
               user_agent: str = "", host: str = "") -> bool:
        """Record an inbound hit for a token. Returns True if the token was one
        we minted (a real correlated interaction)."""
        with self._lock:
            known = token in self._known
            self._hits.setdefault(token, []).append(Interaction(
                token=token, at=time.time(), source_ip=source_ip, method=method,
                path=path, user_agent=user_agent, host=host,
            ))
            return known

    def poll(self, token: str) -> list[Interaction]:
        with self._lock:
            return list(self._hits.get(token, []))


_STORE = OobStore()


def store() -> OobStore:
    return _STORE


def oob_base_url() -> str:
    """Public callback base the target must be able to reach, e.g.
    'http://scan.vaptix.com'. Empty when unset — OOB detection then no-ops."""
    return os.environ.get("H4CK_BOT_OOB_BASE", "").rstrip("/")


def callback_url(token: str, base: str | None = None) -> str:
    base = (base if base is not None else oob_base_url()).rstrip("/")
    return f"{base}/oob/{token}"
