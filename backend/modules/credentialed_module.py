"""
Credentialed (authenticated) host scanning — the Nessus-style capability.

With operator-supplied SSH credentials for a host they are authorized to test,
we log in and audit from the inside. This is far more accurate than remote
banner guessing, and it reports the signals credentialed scanning is actually
good at:

  1. MISSING SECURITY UPDATES — the distro's own view of which packages have
     security updates available (apt). This is a FACT, not an inference: the
     package manager says an update exists. (We deliberately do NOT naively
     match installed versions against NVD — distros backport fixes without
     bumping versions, so that over-reports. The patch-status signal is the
     honest one.)
  2. HOST HARDENING — real sshd_config directives (PermitRootLogin,
     PasswordAuthentication, …), read directly. Also a fact.
  3. SERVICE INVENTORY — listening ports, recorded as context.

Strictly READ-ONLY: every command only reads state; nothing is changed.
Credentials are used for the connection and never logged or persisted.
"""

from __future__ import annotations

import logging
import re
import uuid

from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding,
    FindingKind, KillChainPhase, WeaknessRef,
)

logger = logging.getLogger("h4ck-bot.credentialed")

# Read-only audit commands. Keyed by a short name; outputs parsed below.
AUDIT_COMMANDS = {
    "os_release": "cat /etc/os-release 2>/dev/null",
    "kernel": "uname -r 2>/dev/null",
    "pkg_mgr": "command -v apt-get >/dev/null 2>&1 && echo apt || (command -v dnf >/dev/null 2>&1 && echo dnf || echo unknown)",
    "apt_upgradable": "apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep ^Inst || true",
    "sshd_config": "cat /etc/ssh/sshd_config 2>/dev/null",
    "listening": "ss -tlnH 2>/dev/null || netstat -tlnp 2>/dev/null || true",
}

# sshd_config directives we flag, with (bad_value_predicate, title, cwe, score).
_RISKY_DIRECTIVE_SCORE = 5.3


# ── parsers (pure, unit-testable) ───────────────────────────────────

def parse_os_release(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"')
    return out


def parse_apt_upgradable(text: str) -> list[dict]:
    """Parse `apt-get -s upgrade` 'Inst' lines:
        Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-security [amd64])
    Returns [{"pkg","current","candidate","security"}]."""
    out = []
    rx = re.compile(r"^Inst\s+(\S+)\s+\[([^\]]+)\]\s+\(([^\s]+)\s+([^)]*)\)")
    for line in text.splitlines():
        m = rx.match(line.strip())
        if not m:
            continue
        pkg, current, candidate, origin = m.group(1), m.group(2), m.group(3), m.group(4)
        security = "security" in origin.lower()
        out.append({"pkg": pkg, "current": current, "candidate": candidate, "security": security})
    return out


def parse_sshd_config(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        if len(parts) == 2:
            out[parts[0].lower()] = parts[1].strip()
    return out


def parse_listening(text: str) -> list[str]:
    ports = []
    for line in text.splitlines():
        m = re.search(r"[:.](\d+)\s", line) or re.search(r":(\d+)\s", line)
        if m:
            ports.append(m.group(1))
    # dedup, keep order
    seen, out = set(), []
    for p in ports:
        if p not in seen:
            seen.add(p); out.append(p)
    return out


# ── findings ────────────────────────────────────────────────────────

def _asset(host: str) -> Asset:
    return Asset(asset_id="a0", name=host, asset_type="host",
                 scope_approved=True, metadata={"exposure": "credentialed"})


def _mk(host, title, desc, score, vector, cwe_id, cwe_name, remediation, impact,
        kind=FindingKind.VULNERABILITY, preview="", source="credentialed",
        requires_corroboration=False) -> Finding:
    f = Finding(
        finding_id=str(uuid.uuid4()), title=title, description=desc,
        asset=_asset(host), module_source="credentialed_scan",
        finding_kind=kind,
        cvss=CvssScore(base_score=score, vector=vector),
        cwe=WeaknessRef(cwe_id=cwe_id, name=cwe_name),
        kill_chain_phase=KillChainPhase.RECONNAISSANCE,
        remediation=remediation, business_impact=impact,
        requires_corroboration=requires_corroboration,
    )
    # Title is always in the body so the static-analysis layer can substantiate
    # the claim; tag as a static artifact (an at-rest fact read over SSH), so
    # the HTTP-oriented layers abstain and static_analysis is the gate.
    body = f"{title}\n" + (preview or desc)
    f.add_evidence(Evidence.new(
        evidence_type=EvidenceType.RAW_OUTPUT, raw_bytes=body.encode(),
        storage_ref=f"mem://cred/{f.finding_id}", description=title,
        metadata={"preview": body, "source": source, "static_claim": title,
                  "static_artifact": True},
    ))
    return f


def audit_to_findings(host: str, data: dict):
    """Turn collected command output into Findings. `data` maps the keys in
    AUDIT_COMMANDS to raw stdout strings."""
    findings = []
    osr = parse_os_release(data.get("os_release", ""))
    os_name = f"{osr.get('PRETTY_NAME') or osr.get('NAME','')} {osr.get('VERSION_ID','')}".strip()

    # 1. Missing security updates (the headline credentialed finding).
    upg = parse_apt_upgradable(data.get("apt_upgradable", ""))
    sec = [u for u in upg if u["security"]]
    if sec:
        names = ", ".join(u["pkg"] for u in sec[:20])
        more = f" (+{len(sec)-20} more)" if len(sec) > 20 else ""
        score = min(4.0 + 0.3 * len(sec), 8.1)
        findings.append(_mk(
            host,
            f"{len(sec)} missing security update(s) on {host}",
            (f"The package manager reports {len(sec)} package(s) with security updates available on "
             f"{os_name or host}: {names}{more}. These are published fixes not yet applied — a factual, "
             "credentialed confirmation of unpatched vulnerabilities."),
            round(score, 1), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CWE-1104", "Use of Unmaintained/Unpatched Components",
            "Apply the pending security updates (e.g. `apt-get upgrade`); schedule regular patching.",
            "Unpatched packages with known fixes are a primary exploitation vector.",
            preview=("missing security updates (from the package manager):\n"
                     + "\n".join(f"  {u['pkg']}: {u['current']} -> {u['candidate']}" for u in sec[:50])),
            source="apt_security",
        ))
    # non-security pending updates -> low/informational note
    nonsec = [u for u in upg if not u["security"]]
    if nonsec:
        findings.append(_mk(
            host, f"{len(nonsec)} pending (non-security) update(s) on {host}",
            f"{len(nonsec)} non-security package update(s) are pending on {os_name or host}. "
            "Recorded as maintenance context.",
            0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "CWE-1104", "Outdated components (maintenance)",
            "Apply pending updates during maintenance.",
            "Keeping components current reduces future risk.",
            kind=FindingKind.INFORMATIONAL,
            preview="pending non-security updates: " + ", ".join(u["pkg"] for u in nonsec[:50]),
            source="apt_nonsecurity",
        ))

    # 2. SSH hardening (facts read from sshd_config).
    sshd = parse_sshd_config(data.get("sshd_config", ""))
    prl = (sshd.get("permitrootlogin") or "").lower()
    if prl in ("yes", "prohibit-password", "without-password"):
        sev = 7.8 if prl == "yes" else 5.3
        findings.append(_mk(
            host, f"SSH permits root login (PermitRootLogin {sshd.get('permitrootlogin')}) on {host}",
            (f"sshd_config sets PermitRootLogin {sshd.get('permitrootlogin')}. Direct root login over "
             "SSH widens the attack surface and removes per-user accountability."),
            sev, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CWE-1188", "Insecure Default/Config (root SSH login)",
            "Set `PermitRootLogin no`; use per-user accounts with sudo.",
            "Root SSH login enables direct, high-impact compromise and brute-force targeting.",
            preview=f"sshd_config: PermitRootLogin {sshd.get('permitrootlogin')}",
            source="sshd_config",
        ))
    if (sshd.get("passwordauthentication") or "").lower() == "yes":
        findings.append(_mk(
            host, f"SSH password authentication enabled on {host}",
            "sshd_config sets PasswordAuthentication yes — SSH accepts passwords, exposing the host to "
            "credential brute-forcing.",
            5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "CWE-262", "Weak Authentication (SSH passwords)",
            "Set `PasswordAuthentication no`; use key-based authentication.",
            "Password SSH is a common brute-force and credential-stuffing entry point.",
            preview="sshd_config: PasswordAuthentication yes",
            source="sshd_config",
        ))

    # 3. OS/kernel context + listening ports (informational).
    kernel = (data.get("kernel") or "").strip()
    ports = parse_listening(data.get("listening", ""))
    if os_name or kernel or ports:
        findings.append(_mk(
            host, f"Host inventory for {host}",
            f"OS: {os_name or 'unknown'}; kernel: {kernel or 'unknown'}; "
            f"listening TCP port(s): {', '.join(ports) if ports else 'none observed'}.",
            0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "CWE-0", "Host inventory (informational)",
            "Review exposed services and reduce the listening surface where possible.",
            "Inventory context for the assessment.",
            kind=FindingKind.INFORMATIONAL,
            preview=f"os={os_name}\nkernel={kernel}\nlistening_ports={ports}",
            source="inventory",
        ))
    return findings


# ── SSH runner (paramiko; graceful) ─────────────────────────────────

def run_audit(host: str, username: str, password: str = "", key_text: str = "",
              port: int = 22, timeout: float = 15.0) -> dict:
    """Connect over SSH and run the read-only audit commands. Returns a dict of
    {name: stdout}. Raises RuntimeError with a clear message on failure (incl.
    paramiko not installed). Credentials are not logged."""
    try:
        import paramiko  # noqa
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("paramiko is not installed (pip install paramiko) - credentialed scan unavailable") from exc

    import io
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = None
    if key_text.strip():
        for loader in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                pkey = loader.from_private_key(io.StringIO(key_text))
                break
            except Exception:
                continue
    try:
        client.connect(
            hostname=host, port=port, username=username,
            password=(password or None), pkey=pkey,
            timeout=timeout, allow_agent=False, look_for_keys=False,
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"SSH connection failed: {exc}") from exc

    out = {}
    try:
        for name, cmd in AUDIT_COMMANDS.items():
            try:
                _in, _o, _e = client.exec_command(cmd, timeout=timeout)
                out[name] = _o.read().decode("utf-8", "replace")
            except Exception as exc:  # noqa: BLE001
                logger.info("credentialed: command %s failed: %s", name, exc)
                out[name] = ""
    finally:
        client.close()
    return out
