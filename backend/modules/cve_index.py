"""
Local CVE correlation — authoritative, offline, reproducible.

Given a product + version (from an nmap -sV CPE), return the CVEs whose NVD
CPE match criteria cover that version. The data comes from a LOCAL NVD mirror
(data/cve/index.json, built by tools/sync_nvd.py), so:
  - no client service banners are sent to a third party at scan time,
  - results are reproducible (same index -> same CVEs),
  - it works air-gapped.

Index shape (built from NVD feeds, keyed by "vendor:product"):
  {
    "apache:http_server": [
      {"cve": "CVE-2021-41773", "score": 7.5, "severity": "high",
       "vector": "CVSS:3.1/AV:N/...", "description": "...",
       "ranges": [{"start_incl": "2.4.49", "end_incl": "2.4.49"}]},
      ...
    ],
    ...
  }
Each range may use start_incl/start_excl/end_incl/end_excl and/or "exact".

IMPORTANT (honesty): a version match is INFERENCE, not proof — distros
backport fixes without bumping the version — so the caller reports these as
POTENTIAL / needs-confirmation, never auto-"validated".
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass

logger = logging.getLogger("h4ck-bot.cve")


@dataclass
class CveMatch:
    cve: str
    score: float
    severity: str
    vector: str
    description: str


def default_index_path() -> str:
    root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))  # repo root
    return os.path.join(root, "data", "cve", "index.json")


def load_index(path: str | None = None) -> dict:
    path = path or default_index_path()
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


# ── version comparison ──────────────────────────────────────────────
_VER_SPLIT = re.compile(r"[._\-+~]")


def _ver_key(v: str) -> tuple:
    """A comparable key for a version string. Numeric parts compare
    numerically; non-numeric parts compare lexically but rank BELOW a numeric
    part at the same position (so 2.4.49 > 2.4.49rc1 is not assumed — we keep
    it simple and conservative)."""
    parts = []
    for p in _VER_SPLIT.split(v.strip()):
        if p.isdigit():
            parts.append((1, int(p), ""))
        elif p:
            # split trailing digits from alpha, e.g. "49rc1"
            m = re.match(r"^(\d+)?(.*)$", p)
            num = int(m.group(1)) if m.group(1) else -1
            parts.append((1 if m.group(1) else 0, num, m.group(2)))
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    ka, kb = _ver_key(a), _ver_key(b)
    # pad to equal length
    n = max(len(ka), len(kb))
    ka = ka + ((0, 0, ""),) * (n - len(ka))
    kb = kb + ((0, 0, ""),) * (n - len(kb))
    return (ka > kb) - (ka < kb)


def _in_range(version: str, r: dict) -> bool:
    exact = r.get("exact")
    if exact:
        return _cmp(version, exact) == 0
    ok = True
    if r.get("start_incl") is not None:
        ok = ok and _cmp(version, r["start_incl"]) >= 0
    if r.get("start_excl") is not None:
        ok = ok and _cmp(version, r["start_excl"]) > 0
    if r.get("end_incl") is not None:
        ok = ok and _cmp(version, r["end_incl"]) <= 0
    if r.get("end_excl") is not None:
        ok = ok and _cmp(version, r["end_excl"]) < 0
    # a range with no bounds at all is not a usable match
    has_bound = any(r.get(k) is not None for k in
                    ("start_incl", "start_excl", "end_incl", "end_excl"))
    return ok and has_bound


def correlate(vendor: str, product: str, version: str, index: dict) -> list[CveMatch]:
    """Return CVEs from the index whose ranges cover (vendor, product, version).
    Requires a concrete version; a missing version yields nothing (we do not
    guess)."""
    if not product or not version:
        return []
    key = f"{vendor}:{product}".lower()
    entries = index.get(key) or index.get(product.lower()) or []
    out: list[CveMatch] = []
    for e in entries:
        ranges = e.get("ranges") or []
        if any(_in_range(version, r) for r in ranges):
            out.append(CveMatch(
                cve=e.get("cve", ""),
                score=float(e.get("score", 0.0) or 0.0),
                severity=(e.get("severity") or "").lower(),
                vector=e.get("vector", "") or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                description=e.get("description", "") or "",
            ))
    # highest score first, dedup by CVE id
    seen = set()
    out.sort(key=lambda m: m.score, reverse=True)
    deduped = []
    for m in out:
        if m.cve in seen:
            continue
        seen.add(m.cve)
        deduped.append(m)
    return deduped
