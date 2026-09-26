"""
In-memory rate limiter for assessments.

Two limits, per client (identified by request source IP):
  - MAX_CONCURRENT: how many assessments can run at once
  - MAX_PER_WINDOW: how many can start within a rolling window

For a single-user tool this is generous. It exists to prevent:
  - accidental DoS from a buggy client (a loop that fires POSTs)
  - a leaked admin token being used to spin up hundreds of scans
  - runaway scans against a slow target accumulating

State is in-process and resets on restart. Fine for the threat model
(abuse by a client, not a persistent attacker).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class RateLimiter:
    max_concurrent: int = 2
    max_per_window: int = 10
    window_seconds: float = 60.0

    _active: dict = field(default_factory=lambda: defaultdict(int))
    _history: dict = field(default_factory=lambda: defaultdict(deque))
    _lock: Lock = field(default_factory=Lock)

    def _prune(self, key: str, now: float) -> None:
        dq = self._history[key]
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    def check_and_acquire(self, key: str) -> None:
        now = time.time()
        with self._lock:
            self._prune(key, now)

            if self._active[key] >= self.max_concurrent:
                raise ValueError(
                    f"too many concurrent assessments for {key} "
                    f"(max {self.max_concurrent})"
                )
            if len(self._history[key]) >= self.max_per_window:
                raise ValueError(
                    f"too many assessments started in the last "
                    f"{int(self.window_seconds)}s for {key} "
                    f"(max {self.max_per_window})"
                )

            self._active[key] += 1
            self._history[key].append(now)

    def release(self, key: str) -> None:
        with self._lock:
            if self._active[key] > 0:
                self._active[key] -= 1
