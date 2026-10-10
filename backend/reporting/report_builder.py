"""
Report generation.

Produces two formats from a set of findings:
  - JSON: a structured document for programmatic consumption
  - HTML: a self-contained page (inline CSS, no external assets) that
    renders in any browser and prints cleanly to PDF

Screenshot evidence is base64-embedded directly into the HTML (not
linked as a separate file), so the report stays a single portable
document even when it's the screenshot evidence carrying the proof.
"""

from __future__ import annotations

import base64
import html
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.schema import EvidenceType, Finding, Severity
from evidence.evidence_store import read_evidence_bytes


SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]

SEVERITY_COLOR = {
    "critical": "#E5484D",
    "high":     "#F0883E",
    "medium":   "#D4A72C",
    "low":      "#6E7681",
    "info":     "#5E6B7D",
}

SEVERITY_BG = {
    "critical": "#2A1518",
    "high":     "#291B0E",
    "medium":   "#251F0E",
    "low":      "#1B1F26",
    "info":     "#1B1F26",
}

STATUS_LABEL = {
    "validated":      "Validated",
    "potential":      "Potential",
    "needs_review":   "Needs review",
    "false_positive": "False positive",
}


@dataclass
class ReportData:
    assessment_id: str
    target: str
    modules: list[str]
    status: str
    started_at: str
    completed_at: str | None
    generated_at: str
    findings: list[Finding]
    scope_note: str = ""
    attack_paths: list[dict] = field(default_factory=list)
    methodology_note: str = (
        "Findings were produced by automated scanner modules and passed "
        "through a multi-layer validation pipeline. Informational findings "
        "(e.g. open ports) are recorded without validation, as they are "
        "observations rather than vulnerability claims. Non-informational "
        "findings carry a per-layer validation breakdown; only findings "
        "with a 'Validated' status have passed every deterministic "
        "(non-advisory) layer at >= 0.85 aggregate confidence. The "
        "AI-assisted layer is advisory: it informs the review but does not "
        "gate the verdict."
    )


def build_report_data(
    assessment_meta: dict,
    findings: list[Finding],
    scope_note: str = "",
    attack_paths: list[dict] | None = None,
) -> ReportData:
    return ReportData(
        assessment_id=assessment_meta.get("assessment_id", ""),
        target=assessment_meta.get("target", ""),
        modules=assessment_meta.get("modules", []),
        status=assessment_meta.get("status", ""),
        started_at=assessment_meta.get("started_at", ""),
        completed_at=assessment_meta.get("completed_at"),
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        scope_note=scope_note,
        attack_paths=attack_paths or [],
    )


def build_report_json(data: ReportData) -> dict[str, Any]:
    counts = {s.value: 0 for s in SEVERITY_ORDER}
    validated = 0
    informational = 0
    for f in data.findings:
        counts[f.severity.value] += 1
        if f.status.value == "validated":
            validated += 1
        if f.finding_kind.value == "informational":
            informational += 1

    return {
        "assessment_id": data.assessment_id,
        "target": data.target,
        "modules": data.modules,
        "status": data.status,
        "started_at": data.started_at,
        "completed_at": data.completed_at,
        "generated_at": data.generated_at,
        "scope_note": data.scope_note,
        "attack_paths": data.attack_paths,
        "methodology_note": data.methodology_note,
        "summary": {
            "total": len(data.findings),
            "validated": validated,
            "informational": informational,
            "by_severity": counts,
        },
        "findings": [_finding_to_report_dict(f) for f in data.findings],
    }


def _finding_to_report_dict(f: Finding) -> dict[str, Any]:
    applicable = [l for l in f.validation.layers if l.applicable]
    gating = [l for l in applicable if not l.advisory]   # deterministic layers decide status
    basis = gating or applicable
    passed = [l for l in gating if l.passed]
    return {
        "finding_id": f.finding_id,
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value,
        "cvss": {
            "base_score": f.cvss.base_score,
            "vector": f.cvss.vector,
            "version": f.cvss.version,
        },
        "cwe": {"id": f.cwe.cwe_id, "name": f.cwe.name},
        "status": f.status.value,
        "finding_kind": f.finding_kind.value,
        "module_source": f.module_source,
        "asset": {"name": f.asset.name, "asset_type": f.asset.asset_type},
        "kill_chain_phase": f.kill_chain_phase.value if f.kill_chain_phase else None,
        "discovered_at": f.discovered_at.isoformat(),
        "remediation": f.remediation,
        "business_impact": f.business_impact,
        "evidence_count": len(f.evidence),
        "has_screenshot": any(e.evidence_type == EvidenceType.SCREENSHOT for e in f.evidence),
        "validation": {
            "applicable_layers": len(applicable),
            "gating_layers": len(gating),
            "passed_layers": len(passed),
            "confidence": (
                sum(l.confidence for l in basis) / len(basis) if basis else 0.0
            ),
            "layers": [
                {
                    "name": l.layer_name,
                    "applicable": l.applicable,
                    "advisory": l.advisory,
                    "passed": l.passed,
                    "confidence": l.confidence,
                    "notes": l.notes,
                }
                for l in f.validation.layers
            ],
        },
    }


# ── HTML rendering ──────────────────────────────────────────────────

def build_report_html(data: ReportData) -> str:
    counts = {s.value: 0 for s in SEVERITY_ORDER}
    validated = 0
    for f in data.findings:
        counts[f.severity.value] += 1
        if f.status.value == "validated":
            validated += 1

    def esc(s: Any) -> str:
        return html.escape(str(s) if s is not None else "")

    findings_html = "\n".join(_render_finding(f) for f in _sort_findings(data.findings))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>H4CK-B0T report - {esc(data.target)}</title>
<style>
  :root {{
    --bg: #ffffff; --fg: #1a1a1a; --muted: #666; --border: #ddd;
    --crit: #c41e22; --high: #c26200; --med: #8a6d00; --low: #555; --info: #666;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: var(--fg); background: var(--bg); margin: 0; padding: 40px 20px;
    font-size: 14px; line-height: 1.55;
  }}
  .wrap {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 24px; margin: 0 0 4px; }}
  h2 {{ font-size: 16px; margin: 32px 0 12px; border-bottom: 2px solid var(--fg); padding-bottom: 6px; }}
  h3 {{ font-size: 14px; margin: 0 0 8px; }}
  .meta {{ color: var(--muted); font-size: 13px; margin-bottom: 24px; }}
  .meta span {{ margin-right: 16px; }}
  .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 20px 0 24px; }}
  .stat {{ border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }}
  .stat .n {{ font-size: 22px; font-weight: 600; }}
  .stat .l {{ font-size: 12px; color: var(--muted); }}
  .stat.crit .n {{ color: var(--crit); }}
  .stat.high .n {{ color: var(--high); }}
  .stat.med .n {{ color: var(--med); }}
  .finding {{ border: 1px solid var(--border); border-radius: 8px; padding: 16px 18px; margin-bottom: 14px; page-break-inside: avoid; }}
  .finding-head {{ display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 8px; }}
  .finding-title {{ font-weight: 600; font-size: 15px; }}
  .pill {{ display: inline-block; padding: 2px 9px; border-radius: 5px; font-size: 11px; font-weight: 600; color: #fff; }}
  .pill.critical {{ background: var(--crit); }}
  .pill.high {{ background: var(--high); }}
  .pill.medium {{ background: var(--med); }}
  .pill.low {{ background: var(--low); }}
  .pill.info {{ background: var(--info); }}
  .kv {{ display: grid; grid-template-columns: 130px 1fr; gap: 4px 12px; font-size: 13px; margin: 10px 0; }}
  .kv .k {{ color: var(--muted); }}
  .kv .v {{ font-family: 'SF Mono', Consolas, monospace; font-size: 12.5px; }}
  .body {{ margin: 10px 0; font-size: 13.5px; }}
  .layers {{ font-size: 12.5px; margin-top: 10px; }}
  .layers .layer {{ display: flex; gap: 10px; padding: 3px 0; border-bottom: 1px dashed var(--border); }}
  .layers .layer:last-child {{ border-bottom: none; }}
  .layers .name {{ width: 200px; color: var(--muted); }}
  .layers .status {{ color: var(--muted); }}
  .evidence {{ margin: 12px 0; }}
  .evidence-head {{ font-weight: 600; font-size: 13px; margin-bottom: 8px; }}
  .evidence-note {{ font-weight: 400; color: var(--muted); font-size: 11.5px; }}
  .evidence-item {{ margin-bottom: 10px; }}
  .evidence-label {{ font-size: 12px; color: var(--muted); margin-bottom: 3px; }}
  .evidence-hash {{ font-family: 'SF Mono', Consolas, monospace; font-size: 10.5px; color: #999; }}
  .evidence-pre {{
    font-family: 'SF Mono', Consolas, monospace; font-size: 11.5px; line-height: 1.45;
    background: #f6f8fa; border: 1px solid var(--border); border-radius: 6px;
    padding: 10px 12px; margin: 0; white-space: pre-wrap; word-break: break-word;
    overflow-x: auto; page-break-inside: avoid;
  }}
  .screenshot {{ margin: 12px 0; }}
  .screenshot img {{ display: block; max-width: 100%; border: 1px solid var(--border); border-radius: 6px; }}
  .screenshot-caption {{ font-size: 11.5px; color: var(--muted); margin-top: 4px; }}
  .note {{ background: #f6f6f6; border-left: 3px solid var(--muted); padding: 10px 14px; font-size: 13px; color: #444; margin: 12px 0 20px; }}
  .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); font-size: 12px; color: var(--muted); }}
  @media print {{
    body {{ padding: 0; }}
    .finding {{ break-inside: avoid; }}
    .finding-title {{ font-size: 13px; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Security assessment report</h1>
  <div class="meta">
    <span><strong>Target:</strong> {esc(data.target)}</span>
    <span><strong>Assessment:</strong> {esc(data.assessment_id)}</span>
  </div>
  <div class="meta">
    <span><strong>Started:</strong> {esc(data.started_at)}</span>
    <span><strong>Completed:</strong> {esc(data.completed_at or "(in progress)")}</span>
    <span><strong>Modules:</strong> {esc(", ".join(data.modules))}</span>
  </div>

  <h2>Summary</h2>
  <div class="summary">
    <div class="stat crit"><div class="n">{counts['critical']}</div><div class="l">Critical</div></div>
    <div class="stat high"><div class="n">{counts['high']}</div><div class="l">High</div></div>
    <div class="stat med"><div class="n">{counts['medium']}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n">{counts['low']}</div><div class="l">Low</div></div>
    <div class="stat"><div class="n">{counts['info']}</div><div class="l">Informational</div></div>
  </div>
  <div class="meta">
    <span><strong>Total findings:</strong> {len(data.findings)}</span>
    <span><strong>Validated:</strong> {validated}</span>
  </div>

  {_render_attack_paths(data)}

  <h2>Methodology</h2>
  <div class="note">{esc(data.methodology_note)}</div>
  {f'<div class="note"><strong>Scope:</strong> {esc(data.scope_note)}</div>' if data.scope_note else ''}

  <h2>Findings</h2>
  {findings_html or '<p>No findings.</p>'}

  <div class="footer">
    Generated by H4CK-B0T at {esc(data.generated_at)}.
    This report reflects the state of the assessment at that time and is
    not a guarantee of absence of vulnerabilities.
  </div>
</div>
</body>
</html>
"""


def _render_attack_paths(data: "ReportData") -> str:
    """Render the AI-composed attack paths (the pentester narrative). Each chain
    lists its member findings by title, so the reader sees the story, grounded in
    findings that appear in the Findings section below."""
    if not data.attack_paths:
        return ""
    title_by_id = {f.finding_id: f.title for f in data.findings}
    blocks = []
    for ap in data.attack_paths:
        sev = str(ap.get("overall_severity", "info")).lower()
        steps = "".join(
            f"<li>{html.escape(title_by_id.get(fid, fid))}</li>"
            for fid in ap.get("finding_ids", [])
        )
        phases = ", ".join(ap.get("kill_chain_phases", []))
        blocks.append(
            f'<div class="apath">'
            f'<div class="finding-head"><span class="finding-title">{html.escape(ap.get("title",""))}</span>'
            f'<span class="pill {html.escape(sev)}">{html.escape(sev.upper())}</span></div>'
            f'<div class="body">{html.escape(ap.get("narrative",""))}</div>'
            f'<div class="apath-steps"><strong>Chained findings:</strong><ol>{steps}</ol></div>'
            + (f'<div class="kv"><span class="k">kill chain</span><span class="v">{html.escape(phases)}</span></div>' if phases else "")
            + '</div>'
        )
    return ('<h2>Attack paths <span style="font-weight:400;font-size:12px;color:var(--muted)">'
            '&middot; AI-composed, grounded in the findings below</span></h2>'
            '<style>.apath{border:1px solid var(--border);border-left:4px solid var(--crit);'
            'border-radius:8px;padding:14px 16px;margin-bottom:12px;page-break-inside:avoid}'
            '.apath-steps{font-size:13px;margin-top:8px}.apath-steps ol{margin:4px 0 0 18px}</style>'
            + "\n".join(blocks))


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(
        findings,
        key=lambda f: (order.get(f.severity, 99), f.title),
    )


def _render_screenshots(f: Finding) -> str:
    def esc(s: Any) -> str:
        return html.escape(str(s) if s is not None else "")

    shots = [e for e in f.evidence if e.evidence_type == EvidenceType.SCREENSHOT]
    if not shots:
        return ""

    parts = []
    seen_refs = set()
    for e in shots:
        if e.storage_ref in seen_refs:
            continue
        seen_refs.add(e.storage_ref)
        try:
            raw = read_evidence_bytes(e.storage_ref)
        except FileNotFoundError:
            continue
        b64 = base64.b64encode(raw).decode("ascii")
        caption = esc(e.description or "Screenshot evidence")
        parts.append(
            f'<div class="screenshot">'
            f'<img src="data:image/png;base64,{b64}" alt="{caption}">'
            f'<div class="screenshot-caption">{caption}</div>'
            f'</div>'
        )
    return "\n".join(parts)


_EVIDENCE_LABEL = {
    EvidenceType.HTTP_TRANSACTION: "HTTP transaction",
    EvidenceType.BEHAVIORAL_DIFF:  "Behavioral difference (baseline vs probe)",
    EvidenceType.RESPONSE_HEADERS: "Response headers",
    EvidenceType.RAW_OUTPUT:       "Raw output",
    EvidenceType.POC_REFERENCE:    "PoC reference",
}


def _evidence_text(e) -> str:
    """The human-readable proof for a non-screenshot evidence item. The
    executors stash it in metadata['preview']; fall back to the stored bytes
    when a preview isn't present and the content is text (mem:// refs have no
    file, so a missing preview just yields no body)."""
    preview = (e.metadata or {}).get("preview")
    if preview:
        return str(preview)
    try:
        return read_evidence_bytes(e.storage_ref).decode("utf-8", "replace")[:4000]
    except (FileNotFoundError, OSError, ValueError):
        return ""


def _render_evidence_text(f: Finding) -> str:
    """Render the reproducible proof — the exact request made, the reflected
    inert marker, the baseline-vs-probe differential — as monospace blocks.
    This is what turns a 'Validated' label into something a reader can check
    and reproduce, so it belongs in the report, not just a count."""
    def esc(s: Any) -> str:
        return html.escape(str(s) if s is not None else "")

    items = [e for e in f.evidence if e.evidence_type != EvidenceType.SCREENSHOT]
    if not items:
        return ""

    blocks = []
    for e in items:
        text = _evidence_text(e)
        if not text:
            continue
        label = _EVIDENCE_LABEL.get(e.evidence_type, e.evidence_type.value)
        caption = esc(e.description) if e.description else ""
        short_hash = esc((e.content_hash or "")[:12])
        blocks.append(
            f'<div class="evidence-item">'
            f'<div class="evidence-label">{esc(label)}'
            f'{f" &mdash; {caption}" if caption else ""}'
            f'{f" <span class=\"evidence-hash\">sha256:{short_hash}</span>" if short_hash else ""}'
            f'</div>'
            f'<pre class="evidence-pre">{esc(text)}</pre>'
            f'</div>'
        )
    if not blocks:
        return ""
    return (
        '<div class="evidence"><div class="evidence-head">Evidence '
        '<span class="evidence-note">(verbatim, GET-only, inert markers)</span>'
        '</div>' + "\n".join(blocks) + "</div>"
    )


def _render_finding(f: Finding) -> str:
    def esc(s: Any) -> str:
        return html.escape(str(s) if s is not None else "")

    sev = f.severity.value
    applicable = [l for l in f.validation.layers if l.applicable]
    gating = [l for l in applicable if not l.advisory]
    basis = gating or applicable
    passed = [l for l in gating if l.passed]
    conf = (sum(l.confidence for l in basis) / len(basis)) if basis else 0.0

    def _layer_label(l) -> str:
        if not l.applicable:
            return "not applicable"
        verdict = "pass" if l.passed else "fail"
        return f"{verdict} &middot; advisory" if l.advisory else verdict

    layers_html = "\n".join(
        f'<div class="layer">'
        f'<span class="name">{esc(l.layer_name)}</span>'
        f'<span class="status">'
        f'{_layer_label(l)}'
        f' ({round(l.confidence * 100)}%)'
        f'</span>'
        f'</div>'
        for l in f.validation.layers
    )

    cvss_cell = str(f.cvss.base_score) if f.cvss.base_score > 0 else "&mdash;"
    screenshots_html = _render_screenshots(f)
    evidence_html = _render_evidence_text(f)

    return f"""
<div class="finding">
  <div class="finding-head">
    <div class="finding-title">{esc(f.title)}</div>
    <span class="pill {esc(sev)}">{esc(sev.upper())}</span>
  </div>

  <div class="kv">
    <div class="k">Asset</div><div class="v">{esc(f.asset.name)}</div>
    <div class="k">CVSS</div><div class="v">{cvss_cell}{f' / {esc(f.cvss.vector)}' if f.cvss.base_score > 0 else ''}</div>
    <div class="k">CWE</div><div class="v">{esc(f.cwe.cwe_id)} &mdash; {esc(f.cwe.name)}</div>
    <div class="k">Status</div><div class="v">{esc(STATUS_LABEL.get(f.status.value, f.status.value))}</div>
    <div class="k">Source module</div><div class="v">{esc(f.module_source)}</div>
    <div class="k">Discovered</div><div class="v">{esc(f.discovered_at.isoformat())}</div>
    {f'<div class="k">Kill chain</div><div class="v">{esc(f.kill_chain_phase.value)}</div>' if f.kill_chain_phase else ''}
  </div>

  <div class="body">{esc(f.description)}</div>
  {f'<div class="body"><strong>Remediation:</strong> {esc(f.remediation)}</div>' if f.remediation else ''}
  {f'<div class="body"><strong>Business impact:</strong> {esc(f.business_impact)}</div>' if f.business_impact else ''}

  {evidence_html}
  {screenshots_html}

  <div class="layers">
    <div style="margin-bottom:4px"><strong>Validation:</strong>
      {len(passed)} of {len(gating)} deciding layers passed &mdash;
      aggregate confidence {round(conf * 100)}%
      &middot; {len(f.evidence)} evidence item(s)
    </div>
    {layers_html}
  </div>
</div>
"""
