"""
Android static analysis — inspect an uploaded APK at rest.

Non-destructive by construction: this reads a file, it never touches a live
target. It decodes the (binary) AndroidManifest.xml with the dependency-free
decoder in modules.axml and flags the classic Android hygiene issues, plus a
precise, low-false-positive scan for hardcoded secrets in packaged files.

Every check is a single authoritative observation (requires_corroboration
False): the manifest literally declares the flag, or a secret literally
appears in a packaged file. Each substantiating evidence item is tagged with
metadata['static_claim'] so the static-analysis validation layer can confirm
the evidence contains exactly what the finding asserts.

The APK is identified by the presence of AndroidManifest.xml in the zip; a
non-APK upload (e.g. an IPA) is left for the iOS module.
"""

from __future__ import annotations

import logging
import re
import uuid
import zipfile
from typing import AsyncIterator

from core.module_interface import ModuleCapabilities, ModuleRunContext, ScannerModule
from core.schema import (
    Asset, CvssScore, Evidence, EvidenceType, Finding,
    FindingKind, KillChainPhase, WeaknessRef,
)

logger = logging.getLogger("h4ck-bot.mobile.android")

# Dangerous Android permissions worth surfacing as context (not a flaw by
# itself — reported INFORMATIONAL/Recorded, like an open port).
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
}

# High-precision secret patterns: known prefixes only, so a match is almost
# certainly a real credential rather than random base64.
_SECRET_PATTERNS = [
    ("Google API key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("AWS access key id", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("Slack token", re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("Private key block", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Firebase database URL", re.compile(rb"https://[a-z0-9.-]+\.firebaseio\.com")),
]

# Which packaged files to scan for secrets (bounded; skip giant assets).
_SECRET_SCAN_SUFFIXES = (".dex", ".xml", ".json", ".properties", ".js", ".arsc", ".txt", ".cfg")
_MAX_ENTRY_BYTES = 8 * 1024 * 1024
_COMPONENT_TAGS = ("activity", "service", "receiver", "provider")


class AndroidStaticModule(ScannerModule):
    @property
    def capabilities(self) -> ModuleCapabilities:
        return ModuleCapabilities(
            module_id="mobile_android_static",
            display_name="Android static analysis (APK, manifest + secrets)",
            supported_asset_types=["mobile_app"],
            kill_chain_phases=["reconnaissance"],
            # Reading a file is not active testing against a live target.
            requires_active_testing=False,
            max_automation_level="autonomous",
        )

    async def run(self, ctx: ModuleRunContext) -> AsyncIterator[Finding]:
        for asset in ctx.assets:
            if asset.asset_type != "mobile_app":
                continue
            self.assert_in_scope(asset, ctx)
            path = (asset.metadata or {}).get("file_path")
            if not path:
                logger.warning("mobile asset %s has no file_path", asset.name)
                continue
            try:
                zf = zipfile.ZipFile(path)
            except (zipfile.BadZipFile, FileNotFoundError, OSError) as exc:
                logger.warning("cannot open APK %s: %s", path, exc)
                continue
            with zf:
                names = set(zf.namelist())
                if "AndroidManifest.xml" not in names:
                    # Not an APK (likely an IPA) — the iOS module handles it.
                    continue
                for f in self._analyze(asset, zf):
                    yield f

    # ------------------------------------------------------------------
    def _analyze(self, asset: Asset, zf: zipfile.ZipFile):
        from modules.axml import parse_axml
        try:
            elements = parse_axml(zf.read("AndroidManifest.xml"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("manifest decode failed for %s: %s", asset.name, exc)
            elements = []

        manifest = next((e for e in elements if e.tag == "manifest"), None)
        package = manifest.attrs.get("package", "") if manifest else ""
        app = next((e for e in elements if e.tag == "application"), None)

        # 1. debuggable
        if app and app.attrs.get("debuggable") == "true":
            yield self._mk(
                asset, "Android app is debuggable (android:debuggable=\"true\")",
                f'The application manifest sets android:debuggable="true"{self._pkg(package)}. '
                "A debuggable release build lets anyone with local/ADB access attach a debugger, "
                "read memory, and run code in the app context.",
                6.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "CWE-489", "Active Debug Code",
                claim='android:debuggable="true"',
                remediation='Set android:debuggable="false" (or remove it) in release builds.',
                impact="Local attacker can debug the app, extract data, and execute code in its context.",
            )

        # 2. allowBackup
        if app and app.attrs.get("allowBackup") == "true":
            yield self._mk(
                asset, "Android app allows backup (android:allowBackup=\"true\")",
                f'The manifest sets android:allowBackup="true"{self._pkg(package)}, so app private '
                "data can be extracted via adb backup on a device without root.",
                4.0, "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "CWE-312", "Cleartext Storage of Sensitive Information",
                claim='android:allowBackup="true"',
                remediation='Set android:allowBackup="false" unless backup is required and data is non-sensitive.',
                impact="App-private data can be copied off the device via adb backup.",
            )

        # 3. cleartext traffic
        if app and app.attrs.get("usesCleartextTraffic") == "true":
            yield self._mk(
                asset, "Android app permits cleartext (HTTP) traffic",
                f'The manifest sets android:usesCleartextTraffic="true"{self._pkg(package)}, allowing '
                "unencrypted HTTP, which exposes traffic to interception and tampering.",
                6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "CWE-319", "Cleartext Transmission of Sensitive Information",
                claim='android:usesCleartextTraffic="true"',
                remediation="Set it false and use HTTPS; pin a Network Security Config that forbids cleartext.",
                impact="Network attacker can read or modify the app's unencrypted traffic.",
            )

        # 4. explicitly exported components without a permission guard
        exported = []
        for e in elements:
            if e.tag in _COMPONENT_TAGS and e.attrs.get("exported") == "true" and not e.attrs.get("permission"):
                exported.append(f"{e.tag} {e.attrs.get('name', '(unnamed)')}")
        if exported:
            listing = "; ".join(exported)
            yield self._mk(
                asset, "Exported Android components without permission guard",
                f'{len(exported)} component(s) are explicitly android:exported="true" with no '
                f"android:permission{self._pkg(package)}: {listing}. Any app on the device can invoke them.",
                6.1, "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "CWE-926", "Improper Export of Android Application Components",
                claim=listing,
                remediation="Set exported=\"false\" for components not meant to be external, or guard them with a signature-level permission.",
                impact="A malicious app on the same device can invoke these components directly.",
            )

        # 5. low minSdkVersion
        uses_sdk = next((e for e in elements if e.tag == "uses-sdk"), None)
        min_sdk_raw = uses_sdk.attrs.get("minSdkVersion") if uses_sdk else None
        if min_sdk_raw and min_sdk_raw.lstrip("-").isdigit() and int(min_sdk_raw) < 24:
            yield self._mk(
                asset, f"Low minSdkVersion ({min_sdk_raw}) widens attack surface",
                f"The app supports Android API level {min_sdk_raw}{self._pkg(package)}, below API 24. "
                "Old platform versions lack modern protections (Network Security Config enforcement, "
                "scoped storage, hardened runtime defaults).",
                3.1, "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "CWE-693", "Protection Mechanism Failure",
                claim=min_sdk_raw,
                remediation="Raise minSdkVersion to a currently supported API level where feasible.",
                impact="App can run on old Android versions missing current security controls.",
            )

        # 6. dangerous permissions — INFORMATIONAL context (Recorded), not a flaw
        perms = sorted({
            e.attrs.get("name", "") for e in elements
            if e.tag == "uses-permission" and e.attrs.get("name", "") in DANGEROUS_PERMISSIONS
        })
        if perms:
            listing = ", ".join(perms)
            yield self._mk_info(
                asset, "Dangerous permissions requested",
                f"The app requests {len(perms)} dangerous permission(s){self._pkg(package)}: {listing}. "
                "Recorded as context for review — requesting a permission is not itself a vulnerability.",
                claim=listing,
            )

        # 7. hardcoded secrets in packaged files
        yield from self._scan_secrets(asset, zf, package)

    # ------------------------------------------------------------------
    def _scan_secrets(self, asset: Asset, zf: zipfile.ZipFile, package: str):
        seen: set[tuple[str, bytes]] = set()
        for info in zf.infolist():
            name = info.filename
            if not name.lower().endswith(_SECRET_SCAN_SUFFIXES):
                continue
            if info.file_size > _MAX_ENTRY_BYTES:
                continue
            try:
                blob = zf.read(name)
            except Exception:
                continue
            for label, pat in _SECRET_PATTERNS:
                for m in pat.finditer(blob):
                    token = m.group(0)
                    key = (label, token)
                    if key in seen:
                        continue
                    seen.add(key)
                    shown = self._redact(token)
                    yield self._mk(
                        asset, f"Hardcoded {label} in {name}",
                        f"A {label} appears hardcoded in the packaged file '{name}'{self._pkg(package)} "
                        f"(value shown partially): {shown}. Secrets embedded in the app binary can be "
                        "extracted by anyone with the APK.",
                        7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "CWE-798", "Use of Hard-coded Credentials",
                        claim=shown,
                        remediation="Remove the secret from the app; rotate it; fetch short-lived credentials server-side.",
                        impact="Anyone with the APK can recover the credential and abuse the backing service.",
                    )

    # ------------------------------------------------------------------
    @staticmethod
    def _pkg(package: str) -> str:
        return f" (package {package})" if package else ""

    @staticmethod
    def _redact(token: bytes) -> str:
        s = token.decode("latin-1", "replace")
        if s.startswith("-----BEGIN"):
            return s.splitlines()[0] + " …(redacted)"
        head = s[:10]
        return f"{head}…(+{max(0, len(s) - 10)} chars redacted)"

    def _mk(self, asset, title, desc, score, vector, cwe_id, cwe_name,
            claim, remediation, impact) -> Finding:
        f = Finding(
            finding_id=str(uuid.uuid4()), title=title, description=desc,
            asset=asset, module_source=self.capabilities.module_id,
            finding_kind=FindingKind.VULNERABILITY,
            cvss=CvssScore(base_score=score, vector=vector),
            cwe=WeaknessRef(cwe_id=cwe_id, name=cwe_name),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            remediation=remediation, business_impact=impact,
            requires_corroboration=False,
        )
        preview = f"{title}\nstatic finding (APK)\nsubstantiating fact: {claim}\n{desc}"
        f.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RAW_OUTPUT, raw_bytes=preview.encode(),
            storage_ref=f"mem://android/{f.finding_id}",
            description=title,
            metadata={"preview": preview, "static_claim": claim, "source": "android_manifest"},
        ))
        return f

    def _mk_info(self, asset, title, desc, claim) -> Finding:
        f = Finding(
            finding_id=str(uuid.uuid4()), title=title, description=desc,
            asset=asset, module_source=self.capabilities.module_id,
            finding_kind=FindingKind.INFORMATIONAL,
            cvss=CvssScore(base_score=0.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            cwe=WeaknessRef(cwe_id="CWE-250", name="Execution with Unnecessary Privileges"),
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            requires_corroboration=False,
        )
        preview = f"{title}\nstatic finding (APK)\nsubstantiating fact: {claim}\n{desc}"
        f.add_evidence(Evidence.new(
            evidence_type=EvidenceType.RAW_OUTPUT, raw_bytes=preview.encode(),
            storage_ref=f"mem://android/{f.finding_id}",
            description=title,
            metadata={"preview": preview, "static_claim": claim, "source": "android_manifest"},
        ))
        return f
