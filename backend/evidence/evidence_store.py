"""
Real evidence file storage.

Until now, storage_ref was just a naming convention baked into strings
at each call site (e.g. "evidence/<assessment_id>/<finding_id>/headers.txt")
- nothing actually wrote bytes to disk at that path. This module is the
actual writer/reader, rooted at <project_root>/data/evidence/.

subject_id is deliberately not called "finding_id": some evidence (like
an asset-level screenshot) is shared across multiple findings on the
same asset rather than owned by one finding, so the caller picks the
subject_id that makes sense (a finding_id, or "asset__<asset_name>").
"""

from __future__ import annotations

from pathlib import Path

_DATA_ROOT = Path(__file__).resolve().parent.parent.parent / "data"
EVIDENCE_ROOT = _DATA_ROOT / "evidence"


def save_evidence_bytes(assessment_id: str, subject_id: str, filename: str, raw_bytes: bytes) -> str:
    """
    Write raw_bytes to data/evidence/<assessment_id>/<subject_id>/<filename>,
    creating directories as needed, and return the storage_ref (a path
    relative to data/) to store on the Evidence record.
    """
    rel_dir = Path("evidence") / assessment_id / subject_id
    abs_dir = _DATA_ROOT / rel_dir
    abs_dir.mkdir(parents=True, exist_ok=True)
    abs_path = abs_dir / filename
    abs_path.write_bytes(raw_bytes)
    return str(rel_dir / filename)


def resolve_evidence_path(storage_ref: str) -> Path:
    """Resolve a storage_ref (relative path under data/) to an absolute Path."""
    return _DATA_ROOT / storage_ref


def read_evidence_bytes(storage_ref: str) -> bytes:
    return resolve_evidence_path(storage_ref).read_bytes()
