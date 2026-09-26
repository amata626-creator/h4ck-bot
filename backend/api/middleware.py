"""
API-wide per-IP rate limiting middleware.

Token bucket: each IP starts with `capacity` tokens, refills at
`refill_rate` per second. Each /api/* request consumes one token.
If empty, 429.

The UI's polling loop makes about 2 requests per 1.5s per tab
(status + findings), so ~1.3 req/s. With capacity 30 and refill 10/s,
the UI never trips it. A runaway loop or a scripted attack will.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


@dataclass
class TokenBucketLimiter:
    capacity: float = 30.0
    refill_rate: float = 10.0
    _buckets: dict = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=self.capacity, last_refill=now)
                self._buckets[key] = b

            elapsed = now - b.last_refill
            b.tokens = min(self.capacity, b.tokens + elapsed * self.refill_rate)
            b.last_refill = now

            if b.tokens < 1.0:
                return False
            b.tokens -= 1.0
            return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: TokenBucketLimiter):
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api/"):
            return await call_next(request)
        if path == "/api/health":
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        if not self.limiter.allow(client_ip):
            return JSONResponse(
                {"detail": f"rate limit exceeded for {client_ip}"},
                status_code=429,
            )

        return await call_next(request)
