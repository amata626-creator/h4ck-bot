"""
SQLite persistence for assessments and findings.

Design:
  - One connection per request, opened lazily, closed on exit. SQLite
    is fast enough for single-user local operation; if this ever gets
    concurrent users, swap for Postgres.
  - Findings are stored as JSON blobs. The schema is deliberately thin:
    id, assessment_id, finding_id, module_source, status, severity,
    title, discovered_at, and a full JSON document. Query the blob for
    anything else. This keeps the store from needing schema changes
    every time the Finding dataclass evolves.
  - Evidence is embedded in the finding JSON - no separate table. It's
    always read together with the finding, so a join buys nothing.
  - The DB file lives at <project_root>/data/h4ckbot.db. The directory
    is created on first use.

Thread safety: sqlite3 objects aren't thread-safe by default. FastAPI
runs async handlers on an event loop with a threadpool for sync work,
so we open a fresh connection per call. Cheap, correct, good enough.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding, FindingKind,
    FindingStatus, KillChainPhase, MitreTechnique, Severity,
    ValidationLayerResult, ValidationResult, VulnerabilityRef, WeaknessRef,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    modules       TEXT NOT NULL,   -- JSON list
    llm_model     TEXT NOT NULL,
    status        TEXT NOT NULL,   -- "running" | "complete" | "error: ..."
    started_at    TEXT NOT NULL,
    completed_at  TEXT,
    error         TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id    TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    module_source TEXT NOT NULL,
    title         TEXT NOT NULL,
    status        TEXT NOT NULL,
    severity      TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    document      TEXT NOT NULL,   -- full Finding as JSON
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_assessment
    ON findings(assessment_id, discovered_at);

CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'operator',  -- 'admin' | 'operator'
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL
);

-- Dynamic, operator-authorized scope. Lets the platform target ANY host the
-- operator attests they are authorized to test, at runtime, without editing
-- scope.yaml or restarting. The authorization_ref is REQUIRED and audited —
-- this is still authorized-testing-only, just not confined to a static file.
CREATE TABLE IF NOT EXISTS authorized_targets (
    host                       TEXT PRIMARY KEY,
    authorization_ref          TEXT NOT NULL,
    note                       TEXT NOT NULL DEFAULT '',
    permitted_techniques       TEXT NOT NULL DEFAULT '[]',  -- JSON list
    active_testing_permitted   INTEGER NOT NULL DEFAULT 1,
    destructive_actions_allowed INTEGER NOT NULL DEFAULT 0,
    added_by                   TEXT NOT NULL DEFAULT '',
    added_at                   TEXT NOT NULL
);

-- AI-composed attack paths: chains of confirmed findings the strategist reasons
-- into a higher-impact exploit path. Each references real finding_ids (grounded
-- at creation), so a chain can never cite a finding that does not exist.
CREATE TABLE IF NOT EXISTS attack_paths (
    attack_path_id TEXT PRIMARY KEY,
    assessment_id  TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    document       TEXT NOT NULL,   -- full AttackPath as JSON
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_paths_assessment
    ON attack_paths(assessment_id, created_at);
"""


class Store:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as con:
            con.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.db_path, timeout=10.0)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    # ── assessments ──────────────────────────────────────────────

    def create_assessment(self, assessment_id: str, target: str,
                          modules: list[str], llm_model: str) -> None:
        with self._connect() as con:
            con.execute(
                "INSERT INTO assessments "
                "(assessment_id, target, modules, llm_model, status, started_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (assessment_id, target, json.dumps(modules), llm_model,
                 "running", datetime.now(timezone.utc).isoformat()),
            )

    def set_status(self, assessment_id: str, status: str, error: str | None = None) -> None:
        completed = None
        if status != "running":
            completed = datetime.now(timezone.utc).isoformat()
        with self._connect() as con:
            con.execute(
                "UPDATE assessments SET status=?, completed_at=?, error=? "
                "WHERE assessment_id=?",
                (status, completed, error, assessment_id),
            )

    def get_assessment(self, assessment_id: str) -> dict | None:
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM assessments WHERE assessment_id=?",
                (assessment_id,),
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["modules"] = json.loads(d["modules"])
        return d

    def list_assessments(self, limit: int = 50) -> list[dict]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM assessments ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["modules"] = json.loads(d["modules"])
            out.append(d)
        return out

    # ── users (dashboard accounts) ───────────────────────────────

    def add_user(self, username: str, password_hash: str, role: str = "operator") -> bool:
        """Create a user. Returns False if the username already exists."""
        try:
            with self._lock, self._connect() as con:
                con.execute(
                    "INSERT INTO users (username, password_hash, role, active, created_at) "
                    "VALUES (?, ?, ?, 1, ?)",
                    (username, password_hash, role, datetime.now(timezone.utc).isoformat()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username: str) -> dict | None:
        with self._connect() as con:
            row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT username, role, active, created_at FROM users ORDER BY created_at"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_user(self, username: str) -> bool:
        with self._lock, self._connect() as con:
            cur = con.execute("DELETE FROM users WHERE username=?", (username,))
        return cur.rowcount > 0

    def set_user_password(self, username: str, password_hash: str) -> bool:
        with self._lock, self._connect() as con:
            cur = con.execute(
                "UPDATE users SET password_hash=? WHERE username=?", (password_hash, username)
            )
        return cur.rowcount > 0

    def set_user_active(self, username: str, active: bool) -> bool:
        with self._lock, self._connect() as con:
            cur = con.execute(
                "UPDATE users SET active=? WHERE username=?", (1 if active else 0, username)
            )
        return cur.rowcount > 0

    def count_users(self) -> int:
        with self._connect() as con:
            return con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]

    def count_admins(self) -> int:
        with self._connect() as con:
            return con.execute(
                "SELECT COUNT(*) AS c FROM users WHERE role='admin' AND active=1"
            ).fetchone()["c"]

    # ── dynamic authorized scope ─────────────────────────────────

    def add_authorized_target(
        self, host: str, authorization_ref: str, note: str = "",
        permitted_techniques: list[str] | None = None,
        active_testing_permitted: bool = True,
        destructive_actions_allowed: bool = False,
        added_by: str = "",
    ) -> None:
        """Add (or update) a runtime-authorized target. authorization_ref is
        required by the caller — this method persists the attestation."""
        techs = json.dumps(permitted_techniques or
                           ["passive_recon", "port_scan", "misconfig_check", "active_testing"])
        with self._lock, self._connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO authorized_targets "
                "(host, authorization_ref, note, permitted_techniques, "
                " active_testing_permitted, destructive_actions_allowed, added_by, added_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (host.strip().lower(), authorization_ref, note, techs,
                 1 if active_testing_permitted else 0,
                 1 if destructive_actions_allowed else 0,
                 added_by, datetime.now(timezone.utc).isoformat()),
            )

    def get_authorized_target(self, host: str) -> dict | None:
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM authorized_targets WHERE host=?", (host.strip().lower(),)
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["permitted_techniques"] = json.loads(d["permitted_techniques"] or "[]")
        d["active_testing_permitted"] = bool(d["active_testing_permitted"])
        d["destructive_actions_allowed"] = bool(d["destructive_actions_allowed"])
        return d

    def list_authorized_targets(self) -> list[dict]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM authorized_targets ORDER BY added_at DESC"
            ).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["permitted_techniques"] = json.loads(d["permitted_techniques"] or "[]")
            d["active_testing_permitted"] = bool(d["active_testing_permitted"])
            d["destructive_actions_allowed"] = bool(d["destructive_actions_allowed"])
            out.append(d)
        return out

    def remove_authorized_target(self, host: str) -> bool:
        with self._lock, self._connect() as con:
            cur = con.execute(
                "DELETE FROM authorized_targets WHERE host=?", (host.strip().lower(),)
            )
        return cur.rowcount > 0

    # ── findings ─────────────────────────────────────────────────

    def insert_finding(self, assessment_id: str, finding: Finding) -> None:
        doc = _finding_to_json(finding)
        with self._lock, self._connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO findings "
                "(finding_id, assessment_id, module_source, title, status, "
                " severity, discovered_at, document) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding.finding_id,
                    assessment_id,
                    finding.module_source,
                    finding.title,
                    finding.status.value,
                    finding.severity.value,
                    finding.discovered_at.isoformat(),
                    json.dumps(doc),
                ),
            )

    def list_findings(self, assessment_id: str) -> list[Finding]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT document FROM findings WHERE assessment_id=? "
                "ORDER BY discovered_at ASC",
                (assessment_id,),
            ).fetchall()
        return [_finding_from_json(json.loads(r["document"])) for r in rows]

    def insert_attack_path(self, assessment_id: str, path: dict) -> None:
        """Persist one AI-composed attack path (a plain dict). Keyed by its id,
        so re-running an assessment's chaining replaces its paths."""
        from datetime import datetime, timezone
        with self._lock, self._connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO attack_paths "
                "(attack_path_id, assessment_id, created_at, document) VALUES (?, ?, ?, ?)",
                (path.get("attack_path_id", ""), assessment_id,
                 datetime.now(timezone.utc).isoformat(), json.dumps(path)),
            )

    def list_attack_paths(self, assessment_id: str) -> list[dict]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT document FROM attack_paths WHERE assessment_id=? ORDER BY created_at ASC",
                (assessment_id,),
            ).fetchall()
        return [json.loads(r["document"]) for r in rows]

    def get_finding(self, assessment_id: str, finding_id: str) -> Finding | None:
        with self._connect() as con:
            row = con.execute(
                "SELECT document FROM findings "
                "WHERE assessment_id=? AND finding_id=?",
                (assessment_id, finding_id),
            ).fetchone()
        if row is None:
            return None
        return _finding_from_json(json.loads(row["document"]))

    def finding_count(self, assessment_id: str) -> int:
        with self._connect() as con:
            row = con.execute(
                "SELECT COUNT(*) AS n FROM findings WHERE assessment_id=?",
                (assessment_id,),
            ).fetchone()
        return int(row["n"])


# ── Finding <-> JSON ────────────────────────────────────────────────
# We serialize the Finding to a plain dict and back. This is a
# deliberate choice: it keeps the DB resilient to schema changes in
# core/schema.py (new fields just appear in the JSON), and it matches
# exactly what the API serializes, so what's stored is what the UI saw.

def _finding_to_json(f: Finding) -> dict:
    return {
        "finding_id": f.finding_id,
        "title": f.title,
        "description": f.description,
        "module_source": f.module_source,
        "finding_kind": f.finding_kind.value,
        "kill_chain_phase": f.kill_chain_phase.value if f.kill_chain_phase else None,
        "status": f.status.value,
        "remediation": f.remediation,
        "business_impact": f.business_impact,
        "discovered_at": f.discovered_at.isoformat(),
        "attack_path_id": f.attack_path_id,
        "owasp_category": f.owasp_category,
        "requires_corroboration": f.requires_corroboration,
        "asset": {
            "asset_id": f.asset.asset_id,
            "name": f.asset.name,
            "asset_type": f.asset.asset_type,
            "scope_approved": f.asset.scope_approved,
            "metadata": f.asset.metadata,
        },
        "cvss": {
            "base_score": f.cvss.base_score,
            "vector": f.cvss.vector,
            "version": f.cvss.version,
        },
        "cwe": {"cwe_id": f.cwe.cwe_id, "name": f.cwe.name},
        "cve_refs": [
            {"cve_id": c.cve_id, "description": c.description}
            for c in f.cve_refs
        ],
        "mitre_techniques": [
            {"technique_id": m.technique_id, "tactic": m.tactic, "name": m.name}
            for m in f.mitre_techniques
        ],
        "evidence": [
            {
                "evidence_id": e.evidence_id,
                "evidence_type": e.evidence_type.value,
                "captured_at": e.captured_at.isoformat(),
                "content_hash": e.content_hash,
                "storage_ref": e.storage_ref,
                "description": e.description,
                "metadata": e.metadata,
            }
            for e in f.evidence
        ],
        "validation": {
            "layers": [
                {
                    "layer_name": l.layer_name,
                    "passed": l.passed,
                    "confidence": l.confidence,
                    "notes": l.notes,
                    "applicable": l.applicable,
                    "advisory": l.advisory,
                }
                for l in f.validation.layers
            ],
        },
    }


def _finding_from_json(d: dict) -> Finding:
    asset = Asset(
        asset_id=d["asset"]["asset_id"],
        name=d["asset"]["name"],
        asset_type=d["asset"]["asset_type"],
        scope_approved=d["asset"]["scope_approved"],
        metadata=d["asset"].get("metadata", {}),
    )
    f = Finding(
        finding_id=d["finding_id"],
        title=d["title"],
        description=d["description"],
        asset=asset,
        module_source=d["module_source"],
        finding_kind=FindingKind(d.get("finding_kind", "vulnerability")),
        cvss=CvssScore(
            base_score=d["cvss"]["base_score"],
            vector=d["cvss"]["vector"],
            version=d["cvss"].get("version", "3.1"),
        ),
        cwe=WeaknessRef(cwe_id=d["cwe"]["cwe_id"], name=d["cwe"]["name"]),
        cve_refs=[
            VulnerabilityRef(cve_id=c["cve_id"], description=c.get("description"))
            for c in d.get("cve_refs", [])
        ],
        mitre_techniques=[
            MitreTechnique(technique_id=m["technique_id"], tactic=m["tactic"], name=m["name"])
            for m in d.get("mitre_techniques", [])
        ],
        kill_chain_phase=(
            KillChainPhase(d["kill_chain_phase"]) if d.get("kill_chain_phase") else None
        ),
        status=FindingStatus(d.get("status", "potential")),
        remediation=d.get("remediation", ""),
        business_impact=d.get("business_impact", ""),
        owasp_category=d.get("owasp_category", ""),
        requires_corroboration=d.get("requires_corroboration", True),
    )
    f.discovered_at = datetime.fromisoformat(d["discovered_at"])
    f.attack_path_id = d.get("attack_path_id")

    for e in d.get("evidence", []):
        f.add_evidence(Evidence(
            evidence_id=e["evidence_id"],
            evidence_type=EvidenceType(e["evidence_type"]),
            captured_at=datetime.fromisoformat(e["captured_at"]),
            content_hash=e["content_hash"],
            storage_ref=e["storage_ref"],
            description=e.get("description", ""),
            metadata=e.get("metadata", {}),
        ))

    f.validation = ValidationResult(layers=[
        ValidationLayerResult(
            layer_name=l["layer_name"],
            passed=l["passed"],
            confidence=l["confidence"],
            notes=l.get("notes", ""),
            applicable=l.get("applicable", True),
            advisory=l.get("advisory", False),
        )
        for l in d.get("validation", {}).get("layers", [])
    ])

    return f
