"""
Converts Finding/Evidence/AttackPath dataclasses to plain JSON-safe
dicts for the API layer. Kept separate from core/schema.py so the core
data model has no web-framework dependency - modules and the
orchestrator never need to know an API exists.

Dataclass @property attributes (like Finding.severity and
CvssScore.severity) are NOT included by asdict(), so we add them
explicitly here. The UI relies on them for coloring and grouping.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum

from core.schema import Finding


def _json_safe(obj):
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _json_safe(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


def serialize_finding(finding: Finding) -> dict:
    d = _json_safe(finding)

    # Properties that asdict() drops:
    #   - Finding.severity (derived from cvss.severity)
    #   - CvssScore.severity (not needed separately, but included for symmetry)
    d["severity"] = finding.severity.value
    if isinstance(d.get("cvss"), dict):
        d["cvss"]["severity"] = finding.cvss.severity.value

    # Convenience: expose the module's declared kind as a plain string
    # if it's an enum (it already is after _json_safe, so this is a
    # no-op, kept for clarity).
    return d
