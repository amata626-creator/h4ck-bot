"""
AWS cloud posture scanning (CSPM) — the cloud half of infrastructure scanning.

Instead of SSH-ing into a host, this uses read-only AWS APIs (the operator's
credentials) to audit for the classic high-impact misconfigurations:

  - S3 buckets public (ACL/policy) or unencrypted
  - Security groups open to the world (0.0.0.0/0) on sensitive ports
  - IAM users without MFA; stale active access keys
  - Root account without MFA; no password policy
  - RDS instances publicly accessible
  - CloudTrail not enabled

Every finding is a FACT read from the AWS API, so they validate as VALIDATED
via the static-fact gate. Strictly READ-ONLY (Describe/List/Get only).
Credentials are used for the session and never logged or persisted.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding,
    FindingKind, KillChainPhase, WeaknessRef,
)

logger = logging.getLogger("h4ck-bot.cloud.aws")

# Ports that should essentially never be open to 0.0.0.0/0.
SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP", 3306: "MySQL",
    5432: "PostgreSQL", 1433: "MSSQL", 6379: "Redis", 27017: "MongoDB",
    9200: "Elasticsearch", 5984: "CouchDB", 11211: "Memcached", 2379: "etcd",
}
_WORLD = ("0.0.0.0/0", "::/0")
_STALE_KEY_DAYS = 90


def _asset(account: str) -> Asset:
    return Asset(asset_id="a0", name=f"aws:{account}", asset_type="host",
                 scope_approved=True, metadata={"exposure": "cloud"})


def _mk(account, title, desc, score, vector, cwe_id, cwe_name, remediation, impact,
        kind=FindingKind.VULNERABILITY, preview="", source="cloud_aws") -> Finding:
    f = Finding(
        finding_id=str(uuid.uuid4()), title=title, description=desc,
        asset=_asset(account), module_source="cloud_aws_scan",
        finding_kind=kind,
        cvss=CvssScore(base_score=score, vector=vector),
        cwe=WeaknessRef(cwe_id=cwe_id, name=cwe_name),
        kill_chain_phase=KillChainPhase.RECONNAISSANCE,
        remediation=remediation, business_impact=impact,
        requires_corroboration=False,
    )
    body = f"{title}\n" + (preview or desc)
    f.add_evidence(Evidence.new(
        evidence_type=EvidenceType.RAW_OUTPUT, raw_bytes=body.encode(),
        storage_ref=f"mem://cloud/{f.finding_id}", description=title,
        metadata={"preview": body, "source": source, "static_claim": title,
                  "static_artifact": True},
    ))
    return f


# ── pure checks (unit-testable with boto3-shaped fixtures) ──────────

def check_security_groups(account: str, describe_sg_response: dict):
    """World-open ingress on sensitive ports, from a describe_security_groups
    response."""
    findings = []
    for sg in describe_sg_response.get("SecurityGroups", []):
        gid = sg.get("GroupId", "?")
        gname = sg.get("GroupName", "")
        open_hits = []
        for perm in sg.get("IpPermissions", []):
            proto = perm.get("IpProtocol", "")
            frm, to = perm.get("FromPort"), perm.get("ToPort")
            world = any(r.get("CidrIp") in _WORLD for r in perm.get("IpRanges", [])) \
                or any(r.get("CidrIpv6") in _WORLD for r in perm.get("Ipv6Ranges", []))
            if not world:
                continue
            if proto == "-1" or frm is None:
                open_hits.append("ALL ports/protocols")
                continue
            for p, name in SENSITIVE_PORTS.items():
                if frm <= p <= (to if to is not None else frm):
                    open_hits.append(f"{p}/{name}")
        if open_hits:
            findings.append(_mk(
                account, f"Security group {gid} open to the world on {', '.join(open_hits)}",
                (f"Security group {gid} ({gname}) allows inbound from 0.0.0.0/0 on: "
                 f"{', '.join(open_hits)}. These should be restricted to known source ranges."),
                7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                "CWE-284", "Improper Access Control (security group)",
                "Restrict the ingress rule to specific trusted CIDRs; never expose admin/DB ports to 0.0.0.0/0.",
                "World-exposed sensitive ports invite brute-force, exploitation, and lateral movement.",
                preview=f"security group: {gid} ({gname})\nworld-open: {', '.join(open_hits)}",
                source="aws_sg",
            ))
    return findings


def check_s3(account: str, buckets: list[dict]):
    """buckets: [{name, public, reason, encrypted}] normalized by the collector."""
    findings = []
    for b in buckets:
        if b.get("public"):
            findings.append(_mk(
                account, f"S3 bucket '{b['name']}' is publicly accessible",
                f"S3 bucket '{b['name']}' is public ({b.get('reason','public')}). "
                "Public buckets expose their contents to anyone on the internet.",
                8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "CWE-284", "Improper Access Control (public S3 bucket)",
                "Enable S3 Block Public Access; remove public ACLs/policy grants.",
                "Public buckets are a leading cause of large-scale data exposure.",
                preview=f"bucket: {b['name']}\npublic: True ({b.get('reason','')})",
                source="aws_s3",
            ))
        if b.get("encrypted") is False:
            findings.append(_mk(
                account, f"S3 bucket '{b['name']}' has no default encryption",
                f"S3 bucket '{b['name']}' does not enforce default encryption at rest.",
                3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "CWE-311", "Missing Encryption of Sensitive Data",
                "Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.",
                "Unencrypted data at rest increases exposure if storage is compromised.",
                preview=f"bucket: {b['name']}\ndefault_encryption: disabled",
                source="aws_s3",
            ))
    return findings


def check_iam(account: str, users: list[dict]):
    """users: [{user, mfa(bool), access_keys:[{id, age_days, active}]}]."""
    findings = []
    no_mfa = [u["user"] for u in users if not u.get("mfa")]
    if no_mfa:
        findings.append(_mk(
            account, f"{len(no_mfa)} IAM user(s) without MFA",
            f"IAM user(s) without an MFA device: {', '.join(no_mfa[:20])}. "
            "Accounts without MFA are vulnerable to credential theft.",
            6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "CWE-308", "Use of Single-factor Authentication",
            "Require MFA for all IAM users (enforce via IAM policy / SCP).",
            "A phished or leaked password alone grants access without MFA.",
            preview="users without MFA: " + ", ".join(no_mfa[:50]),
            source="aws_iam",
        ))
    stale = []
    for u in users:
        for k in u.get("access_keys", []):
            if k.get("active") and (k.get("age_days") or 0) > _STALE_KEY_DAYS:
                stale.append(f"{u['user']} (key {k.get('id','?')[:8]}…, {k['age_days']}d)")
    if stale:
        findings.append(_mk(
            account, f"{len(stale)} stale active IAM access key(s) (> {_STALE_KEY_DAYS} days)",
            "Long-lived active access keys: " + ", ".join(stale[:20]) +
            ". Old keys increase the window for leaked-credential abuse.",
            4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "CWE-798", "Use of Hard-coded/Long-lived Credentials",
            "Rotate access keys regularly (<90 days); prefer short-lived roles.",
            "Stale keys are more likely to have leaked and remain usable.",
            preview="stale active keys:\n  " + "\n  ".join(stale[:50]),
            source="aws_iam",
        ))
    return findings


def check_account(account: str, root_mfa: bool, has_password_policy: bool):
    findings = []
    if root_mfa is False:
        findings.append(_mk(
            account, "Root account has no MFA enabled",
            "The AWS account root user does not have MFA enabled. Root is all-powerful; "
            "compromise of an MFA-less root is catastrophic.",
            9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CWE-308", "Single-factor Authentication (root)",
            "Enable a hardware or virtual MFA device on the root user immediately.",
            "Root compromise without MFA means total account takeover.",
            preview="account_mfa_enabled (root): False",
            source="aws_account",
        ))
    if has_password_policy is False:
        findings.append(_mk(
            account, "No IAM account password policy configured",
            "The account has no IAM password policy — weak passwords are permitted.",
            4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "CWE-521", "Weak Password Requirements",
            "Set a strong IAM password policy (length, complexity, rotation, reuse).",
            "No policy allows weak, guessable passwords on IAM users.",
            preview="iam_password_policy: absent",
            source="aws_account",
        ))
    return findings


def check_rds(account: str, instances: list[dict]):
    findings = []
    pub = [i["id"] for i in instances if i.get("public")]
    if pub:
        findings.append(_mk(
            account, f"{len(pub)} RDS instance(s) publicly accessible",
            "Publicly accessible RDS instance(s): " + ", ".join(pub[:20]) +
            ". Databases should not be reachable from the internet.",
            7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "CWE-284", "Improper Access Control (public RDS)",
            "Set PubliclyAccessible=false; place the DB in private subnets behind a bastion/VPN.",
            "Internet-exposed databases are a direct path to data compromise.",
            preview="public RDS instances: " + ", ".join(pub[:50]),
            source="aws_rds",
        ))
    return findings


def check_cloudtrail(account: str, enabled: bool):
    if enabled is False:
        return [_mk(
            account, "CloudTrail is not enabled",
            "No CloudTrail trail is configured — API activity is not being logged, "
            "hampering detection and incident response.",
            4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "CWE-778", "Insufficient Logging",
            "Enable a multi-region CloudTrail trail with log file validation.",
            "Without audit logging, attacker activity goes unrecorded.",
            preview="cloudtrail_enabled: False",
            source="aws_cloudtrail",
        )]
    return []


def cloud_findings(account: str, data: dict):
    """Aggregate all checks over the normalized collected data."""
    out = []
    out += check_security_groups(account, data.get("security_groups_raw") or {})
    out += check_s3(account, data.get("s3_buckets") or [])
    out += check_iam(account, data.get("iam_users") or [])
    out += check_account(account, data.get("root_mfa"), data.get("password_policy"))
    out += check_rds(account, data.get("rds_instances") or [])
    out += check_cloudtrail(account, data.get("cloudtrail_enabled"))
    # inventory note
    out.append(_mk(
        account, f"AWS account {account} posture scan",
        f"Scanned account {account}: {len((data.get('s3_buckets') or []))} bucket(s), "
        f"{len((data.get('iam_users') or []))} IAM user(s), "
        f"{len((data.get('rds_instances') or []))} RDS instance(s).",
        0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "CWE-0", "Cloud posture inventory",
        "Review the findings above.", "Inventory context.",
        kind=FindingKind.INFORMATIONAL, source="inventory",
    ))
    return out


# ── boto3 collector (read-only; graceful) ───────────────────────────

def _s3_is_public(acl: dict, policy_status: dict | None, pab: dict | None) -> tuple[bool, str]:
    """Decide if a bucket is public from its ACL, policy status, and public
    access block. Pure, so it's unit-testable."""
    # Block Public Access fully on -> treat as not public.
    if pab:
        cfg = pab.get("PublicAccessBlockConfiguration", {})
        if all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                    "BlockPublicPolicy", "RestrictPublicBuckets")):
            return False, ""
    for g in (acl or {}).get("Grants", []):
        uri = (g.get("Grantee", {}) or {}).get("URI", "")
        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
            return True, "public ACL grant"
    if policy_status and policy_status.get("PolicyStatus", {}).get("IsPublic"):
        return True, "public bucket policy"
    return False, ""


def collect(access_key: str, secret_key: str, session_token: str = "",
            region: str = "us-east-1") -> dict:
    """Read-only AWS collection via boto3. Raises RuntimeError with a clear
    message when boto3 is missing or credentials fail."""
    try:
        import boto3  # noqa
        from botocore.config import Config
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("boto3 is not installed (pip install boto3) - cloud scan unavailable") from exc

    cfg = Config(retries={"max_attempts": 3}, read_timeout=20, connect_timeout=10)
    kw = dict(aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    if session_token:
        kw["aws_session_token"] = session_token
    session = boto3.session.Session(**kw)

    data: dict = {}
    try:
        account = session.client("sts", config=cfg).get_caller_identity()["Account"]
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"AWS authentication failed: {exc}") from exc
    data["account"] = account

    # Security groups
    try:
        data["security_groups_raw"] = session.client("ec2", config=cfg).describe_security_groups()
    except Exception as exc:  # noqa: BLE001
        logger.info("cloud: describe_security_groups failed: %s", exc)
        data["security_groups_raw"] = {}

    # S3
    buckets = []
    try:
        s3 = session.client("s3", config=cfg)
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            acl = policy_status = pab = None
            enc = None
            try: acl = s3.get_bucket_acl(Bucket=name)
            except Exception: pass
            try: policy_status = s3.get_bucket_policy_status(Bucket=name)
            except Exception: pass
            try: pab = s3.get_public_access_block(Bucket=name)
            except Exception: pab = None
            try:
                s3.get_bucket_encryption(Bucket=name); enc = True
            except Exception:
                enc = False
            public, reason = _s3_is_public(acl or {}, policy_status, pab)
            buckets.append({"name": name, "public": public, "reason": reason, "encrypted": enc})
    except Exception as exc:  # noqa: BLE001
        logger.info("cloud: s3 collection failed: %s", exc)
    data["s3_buckets"] = buckets

    # IAM users + MFA + access keys
    users = []
    try:
        iam = session.client("iam", config=cfg)
        for u in iam.list_users().get("Users", []):
            un = u["UserName"]
            mfa = bool(iam.list_mfa_devices(UserName=un).get("MFADevices"))
            keys = []
            for k in iam.list_access_keys(UserName=un).get("AccessKeyMetadata", []):
                created = k.get("CreateDate")
                age = (datetime.now(timezone.utc) - created).days if created else 0
                keys.append({"id": k.get("AccessKeyId", ""), "age_days": age,
                             "active": k.get("Status") == "Active"})
            users.append({"user": un, "mfa": mfa, "access_keys": keys})
        # account-level
        summary = iam.get_account_summary().get("SummaryMap", {})
        data["root_mfa"] = bool(summary.get("AccountMFAEnabled"))
        try:
            iam.get_account_password_policy(); data["password_policy"] = True
        except Exception:
            data["password_policy"] = False
    except Exception as exc:  # noqa: BLE001
        logger.info("cloud: iam collection failed: %s", exc)
    data["iam_users"] = users

    # RDS
    rds = []
    try:
        for i in session.client("rds", config=cfg).describe_db_instances().get("DBInstances", []):
            rds.append({"id": i.get("DBInstanceIdentifier", "?"),
                        "public": bool(i.get("PubliclyAccessible"))})
    except Exception as exc:  # noqa: BLE001
        logger.info("cloud: rds collection failed: %s", exc)
    data["rds_instances"] = rds

    # CloudTrail
    try:
        trails = session.client("cloudtrail", config=cfg).describe_trails().get("trailList", [])
        data["cloudtrail_enabled"] = len(trails) > 0
    except Exception as exc:  # noqa: BLE001
        logger.info("cloud: cloudtrail check failed: %s", exc)
        data["cloudtrail_enabled"] = None

    return data
