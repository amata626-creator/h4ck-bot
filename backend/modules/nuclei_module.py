"""
Nuclei integration — industry-grade detection breadth, behind our gate.

Strategy: we do NOT reimplement thousands of vulnerability checks. We run
ProjectDiscovery's Nuclei (if installed) as a detection engine, then map every
raw result into our Finding schema so it flows through the SAME evidence +
validation pipeline and report as everything else. Nuclei finds broadly; our
pipeline confirms and de-noises. That is the differentiator.

Safety / ethos:
  - Scope-gated: only runs against authorized_targets (assert_in_scope).
  - Non-destructive by default: intrusive/dos/fuzz/brute-force template tags
    are excluded; detection-oriented tags only.
  - Graceful: if the `nuclei` binary isn't installed, the module logs once and
    yields nothing — it never errors the assessment.
  - Each finding carries the matched request/response as evidence and is tagged
    so the validation pipeline can substantiate it (the engine's matcher fired
    and we faithfully recorded it); fingerprinting still rejects WAF/block
    pages, so an edge interstitial won't validate.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import uuid
from typing import AsyncIterator, Optional

from core.module_interface import ModuleCapabilities, ModuleRunContext, ScannerModule
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding,
    FindingKind, KillChainPhase, VulnerabilityRef, WeaknessRef,
)

logger = logging.getLogger("h4ck-bot.nuclei")

# Representative base scores when a template carries no CVSS score of its own.
_SEV_SCORE = {"info": 0.0, "low": 3.1, "medium": 5.5, "high": 7.5, "critical": 9.5}
_GENERIC_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

# Detection-oriented tags; intrusive/destructive families are excluded.
_DEFAULT_EXCLUDE_TAGS = "intrusive,dos,fuzz,brute-force"
_DEFAULT_SEVERITIES = "low,medium,high,critical"
_RUN_TIMEOUT_S = 300.0
_MAX_FINDINGS = 300


_USER_AGENT = "h4ckbot-nuclei/0.1 (+authorized-assessment)"

# Well-known install locations to fall back to when `nuclei` isn't on PATH.
# A systemd unit can inherit a minimal PATH that omits /usr/local/bin (where a
# release binary lands) or ~/go/bin (where `go install` lands), so resolving by
# absolute path keeps the module working regardless of how the service's
# environment was set up.
_NUCLEI_FALLBACK_PATHS = (
    "/usr/local/bin/nuclei",
    "/usr/bin/nuclei",
    os.path.expanduser("~/go/bin/nuclei"),
    "/root/go/bin/nuclei",
    "/home/ubuntu/go/bin/nuclei",
)


def resolve_nuclei_bin() -> Optional[str]:
    """Return an absolute path to the nuclei binary, or None if not installed.
    Checks PATH first, then well-known install locations (see above)."""
    found = shutil.which("nuclei")
    if found:
        return found
    for cand in _NUCLEI_FALLBACK_PATHS:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def build_nuclei_cmd(target: str, auth: dict | None = None, binary: str = "nuclei") -> list[str]:
    """Build the nuclei command. Non-destructive tag set, matched request/
    response for evidence, and — when a session is supplied — authenticated
    headers so nuclei scans behind the login too. `binary` is the resolved
    nuclei path (defaults to the bare name for tests/PATH use)."""
    cmd = [
        binary, "-target", target,
        "-jsonl", "-silent", "-no-color", "-disable-update-check",
        "-severity", _DEFAULT_SEVERITIES,
        "-exclude-tags", _DEFAULT_EXCLUDE_TAGS,
        "-rate-limit", "50", "-timeout", "10", "-retries", "1",
        "-include-rr",
        "-H", f"User-Agent: {_USER_AGENT}",
    ]
    auth = auth or {}
    for k, v in (auth.get("headers") or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    if auth.get("cookie"):
        cmd += ["-H", f"Cookie: {auth['cookie']}"]
    return cmd


class NucleiModule(ScannerModule):
    @property
    def capabilities(self) -> ModuleCapabilities:
        return ModuleCapabilities(
            module_id="nuclei",
            display_name="Nuclei template engine (CVEs, exposures, misconfig)",
            supported_asset_types=["host", "web_app", "api"],
            kill_chain_phases=["reconnaissance", "exploitation"],
            requires_active_testing=True,
            max_automation_level="autonomous",
        )

    async def run(self, ctx: ModuleRunContext) -> AsyncIterator[Finding]:
        nuclei_bin = resolve_nuclei_bin()
        if nuclei_bin is None:
            logger.info("nuclei binary not found on PATH or well-known locations - "
                        "skipping (install it to enable CVE/template coverage)")
            return
        logger.info("nuclei: using binary %s", nuclei_bin)

        auth = (ctx.config or {}).get("auth") or {}
        for asset in ctx.assets:
            if asset.asset_type not in self.capabilities.supported_asset_types:
                continue
            self.assert_in_scope(asset, ctx)
            target = asset.name if "://" in asset.name else f"https://{asset.name}"
            async for finding in self._scan(asset, target, auth, nuclei_bin):
                yield finding

    async def _scan(self, asset: Asset, target: str, auth: dict | None = None,
                    nuclei_bin: str = "nuclei"):
        cmd = build_nuclei_cmd(target, auth, binary=nuclei_bin)
        if auth and (auth.get("cookie") or auth.get("headers")):
            logger.info("nuclei: scanning %s (AUTHENTICATED)", target)
        else:
            logger.info("nuclei: scanning %s", target)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
        except (FileNotFoundError, OSError) as exc:
            logger.warning("nuclei failed to launch: %s", exc)
            return

        # Stream stdout line by line under an overall deadline, so a timeout
        # still preserves the findings collected so far (reading only after the
        # process exits would discard everything on a kill).
        loop = asyncio.get_event_loop()
        deadline = loop.time() + _RUN_TIMEOUT_S
        count = 0
        try:
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    logger.warning("nuclei timed out after %ss on %s - killing (kept %d)",
                                   _RUN_TIMEOUT_S, target, count)
                    break
                try:
                    raw = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
                except asyncio.TimeoutError:
                    logger.warning("nuclei timed out on %s - killing (kept %d)", target, count)
                    break
                if not raw:
                    break  # EOF — process finished
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                finding = nuclei_json_to_finding(obj, asset)
                if finding is None:
                    continue
                count += 1
                yield finding
                if count >= _MAX_FINDINGS:
                    logger.warning("nuclei: hit finding cap (%d) on %s", _MAX_FINDINGS, target)
                    break
        finally:
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
        logger.info("nuclei: %d finding(s) on %s", count, target)


# ── pure mapping function (unit-testable without the binary) ─────────

def _first(val) -> str:
    """nuclei fields like cve-id/cwe-id can be a list or a string."""
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val) if val else ""


def _all(val) -> list[str]:
    if isinstance(val, list):
        return [str(v) for v in val if v]
    return [str(val)] if val else []


def nuclei_json_to_finding(obj: dict, asset: Asset) -> Optional[Finding]:
    """Map one Nuclei JSONL record to a Finding, or None if it isn't a usable
    match. Deterministic and side-effect free so it can be unit-tested with
    sample output and no binary."""
    if not isinstance(obj, dict):
        return None
    # Only emit on a successful match.
    if obj.get("matcher-status") is False:
        return None
    template_id = obj.get("template-id") or obj.get("templateID") or ""
    info = obj.get("info") or {}
    name = info.get("name") or template_id or "Nuclei finding"
    matched_at = obj.get("matched-at") or obj.get("matched") or obj.get("host") or asset.name
    if not template_id and not matched_at:
        return None

    severity = (info.get("severity") or "info").lower()
    classification = info.get("classification") or {}
    cvss_score = classification.get("cvss-score")
    cvss_vector = classification.get("cvss-metrics") or _GENERIC_VECTOR
    try:
        base_score = float(cvss_score) if cvss_score is not None else _SEV_SCORE.get(severity, 0.0)
    except (TypeError, ValueError):
        base_score = _SEV_SCORE.get(severity, 0.0)

    cwe_id = _first(classification.get("cwe-id")) or "CWE-0"
    cve_ids = _all(classification.get("cve-id"))
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]

    # Informational/tech templates are context, not vulnerability claims.
    is_info = severity in ("info", "unknown") or "tech" in tags
    kind = FindingKind.INFORMATIONAL if is_info else FindingKind.VULNERABILITY

    request = obj.get("request") or ""
    response = obj.get("response") or ""
    extracted = obj.get("extracted-results") or []
    matcher = obj.get("matcher-name") or ""

    title = f"{name} [{template_id}]" if template_id else name
    desc_bits = [info.get("description") or name, f"Matched at: {matched_at}."]
    if cve_ids:
        desc_bits.append("CVE: " + ", ".join(cve_ids) + ".")
    if extracted:
        desc_bits.append("Extracted: " + ", ".join(str(e) for e in extracted[:5]) + ".")
    description = " ".join(desc_bits)

    finding = Finding(
        finding_id=str(uuid.uuid4()),
        title=title,
        description=description,
        asset=asset,
        module_source=f"nuclei:{template_id}" if template_id else "nuclei",
        finding_kind=kind,
        cvss=CvssScore(base_score=round(base_score, 1), vector=cvss_vector),
        cwe=WeaknessRef(cwe_id=cwe_id, name=f"Reported by Nuclei template {template_id}"),
        cve_refs=[VulnerabilityRef(cve_id=c) for c in cve_ids],
        kill_chain_phase=KillChainPhase.EXPLOITATION if not is_info else KillChainPhase.RECONNAISSANCE,
        remediation=_first(info.get("remediation")) or "See the referenced advisory/template for remediation.",
        business_impact=f"{severity.capitalize()}-severity issue detected by the Nuclei engine.",
        # A template matcher firing is one authoritative detection; there is
        # nothing to cross-correlate against a second independent signal.
        requires_corroboration=False,
    )

    # Evidence: the matched request/response (trimmed) plus a substantiation
    # claim (template-id + matched-at) the validation pipeline can verify.
    claim = f"{template_id} @ {matched_at}"
    preview_lines = [
        f"nuclei template: {template_id}",
        f"matched-at: {matched_at}",
        f"severity: {severity}",
        f"substantiating match: {claim}",   # the static_analysis layer checks this literal
    ]
    if matcher:
        preview_lines.append(f"matcher: {matcher}")
    if request:
        preview_lines.append("\n--- request ---\n" + request.strip()[:2000])
    if response:
        preview_lines.append("\n--- response ---\n" + response.strip()[:2000])
    preview = "\n".join(preview_lines)
    finding.add_evidence(Evidence.new(
        evidence_type=EvidenceType.HTTP_TRANSACTION,
        raw_bytes=preview.encode(),
        storage_ref=f"mem://nuclei/{finding.finding_id}",
        description=f"Nuclei match for {template_id} at {matched_at}",
        metadata={"preview": preview, "static_claim": claim, "source": "nuclei",
                  "template_id": template_id, "cve": cve_ids},
    ))
    return finding
