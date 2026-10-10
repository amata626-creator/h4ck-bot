#!/usr/bin/env python3
"""
Benchmark the engine against a known target with curated ground truth, and print
a detection + precision scorecard. This is how you objectively answer "are we
finding the vulnerabilities we should, without crying wolf?" — numbers, not a vibe.

Usage:
    # run a scan via the live API and score it
    python backend/tools/benchmark.py benchmarks/testfire.yaml \
        --api http://127.0.0.1:8090 --token "$H4CK_BOT_ADMIN_TOKEN"

    # score findings already saved to a JSON file (list of finding dicts)
    python backend/tools/benchmark.py benchmarks/testfire.yaml --findings findings.json

    # write an HTML and/or JSON scorecard too
    python backend/tools/benchmark.py benchmarks/testfire.yaml --api ... --html out.html --json out.json

Ground-truth items (benchmarks/*.yaml):
  - expected: true  -> the tool SHOULD surface this. Counts toward RECALL.
  - expected: false with `out_of_scope: true` -> the tool is not designed to find
    this (e.g. a POST-only login bypass vs GET-only executors). Finding it anyway
    is a bonus; NOT finding it is not a miss; it never counts as a false positive.
  - expected: false with `fp_trap: true` -> a known NON-issue the tool must NOT
    report. If a VALIDATED finding matches it, that's a hard false positive.

An item is "detected" if any finding matches its CWE or any match_any keyword
(case-insensitive, over title + description). Scoring is STATUS-AWARE:
  - RECALL counts an expected-true item detected by a finding of any status.
  - PRECISION is measured on the confident set only: of all VALIDATED findings,
    the fraction that map to a ground-truth expected-true item. VALIDATED
    findings that map to nothing in ground truth are flagged for audit (precision
    suspects). NEEDS_REVIEW findings never count against precision — they are, by
    design, "confirm these", not asserted vulnerabilities.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field

import yaml


# ── scoring (pure, unit-testable) ───────────────────────────────────

@dataclass
class ItemResult:
    id: str
    name: str
    category: str
    expected: bool               # True = should be found (recall); False = negative control
    detected: bool               # matched by a finding of ANY status
    detected_validated: bool     # matched by a VALIDATED finding
    matched_by: list[str] = field(default_factory=list)   # finding titles that matched
    fp_trap: bool = False        # negative that MUST NOT be reported (counts as FP if hit)
    out_of_scope: bool = False   # negative the tool isn't designed to find (informational)


@dataclass
class ExtraFinding:
    title: str
    status: str


@dataclass
class ScoreCard:
    target: str
    items: list[ItemResult]
    total_findings: int
    validated_total: int
    validated_true: int              # VALIDATED findings matching an expected-true item
    validated_extra: list[ExtraFinding]   # VALIDATED findings matching NO ground-truth item (audit)
    extra_findings: int              # findings (any status) mapping to no ground-truth item

    # recall ---------------------------------------------------------
    @property
    def expected_items(self) -> list[ItemResult]:
        return [i for i in self.items if i.expected]

    @property
    def detected_expected(self) -> int:
        return sum(1 for i in self.expected_items if i.detected)

    @property
    def recall(self) -> float:
        exp = self.expected_items
        return (self.detected_expected / len(exp)) if exp else 0.0

    # false-positive traps -------------------------------------------
    @property
    def fp_traps(self) -> list[ItemResult]:
        return [i for i in self.items if i.fp_trap]

    @property
    def fp_trap_hits(self) -> list[ItemResult]:
        # a trap is a hard FP when a VALIDATED finding matched it
        return [i for i in self.fp_traps if i.detected_validated]

    # precision on the confident set ---------------------------------
    @property
    def precision(self) -> float:
        # VALIDATED true / (VALIDATED true + VALIDATED-extra + hard FP traps)
        hard_fp = len(self.validated_extra) + len(self.fp_trap_hits)
        denom = self.validated_true + hard_fp
        return (self.validated_true / denom) if denom else 1.0


def _finding_text(f: dict) -> str:
    return " ".join(str(b) for b in (f.get("title", ""), f.get("description", ""))).lower()


def _finding_cwe(f: dict) -> str:
    cwe = f.get("cwe") or {}
    if isinstance(cwe, dict):
        return str(cwe.get("cwe_id", "")).upper()
    return str(cwe).upper()


def _finding_status(f: dict) -> str:
    return str(f.get("status", "")).lower()


def _matches(f: dict, cwe: str, kws: list[str]) -> bool:
    # Keywords identify an item precisely: when a ground-truth item provides
    # match_any, require a keyword hit (CWE alone must not match, or two items
    # sharing a CWE - e.g. two different XSS - would both be marked detected from
    # a single finding, inflating recall). CWE is the fallback only for items
    # that give no keywords.
    if kws:
        text = _finding_text(f)
        return any(k in text for k in kws)
    return bool(cwe) and _finding_cwe(f) == cwe


def score(findings: list[dict], ground_truth: dict) -> ScoreCard:
    items: list[ItemResult] = []
    # Track, per finding index, whether it matched any ground-truth item and
    # whether it matched an expected-true one (for precision bookkeeping).
    matched_any: set[int] = set()
    matched_true: set[int] = set()

    for gi in ground_truth.get("items", []):
        cwe = str(gi.get("cwe", "")).upper()
        kws = [k.lower() for k in gi.get("match_any", [])]
        expected = gi.get("expected", True)
        matched_by: list[str] = []
        det_validated = False
        for idx, f in enumerate(findings):
            if not _matches(f, cwe, kws):
                continue
            matched_by.append(f.get("title", "(untitled)"))
            matched_any.add(idx)
            if expected:
                matched_true.add(idx)
            if _finding_status(f) == "validated":
                det_validated = True
        items.append(ItemResult(
            id=gi.get("id", ""), name=gi.get("name", ""), category=gi.get("category", ""),
            expected=expected, detected=bool(matched_by), detected_validated=det_validated,
            matched_by=matched_by,
            fp_trap=bool(gi.get("fp_trap", False)),
            out_of_scope=bool(gi.get("out_of_scope", False)),
        ))

    validated_idx = [i for i, f in enumerate(findings) if _finding_status(f) == "validated"]
    validated_true = sum(1 for i in validated_idx if i in matched_true)
    validated_extra = [
        ExtraFinding(title=findings[i].get("title", "(untitled)"), status="validated")
        for i in validated_idx if i not in matched_any
    ]
    extra_findings = sum(1 for i in range(len(findings)) if i not in matched_any)

    return ScoreCard(
        target=ground_truth.get("target", ""),
        items=items,
        total_findings=len(findings),
        validated_total=len(validated_idx),
        validated_true=validated_true,
        validated_extra=validated_extra,
        extra_findings=extra_findings,
    )


# ── scorecard rendering ─────────────────────────────────────────────

def print_scorecard(card: ScoreCard) -> None:
    print(f"\n=== Benchmark: {card.target} ===")
    print(f"Recall    : {card.detected_expected}/{len(card.expected_items)} "
          f"= {card.recall*100:.0f}%   (expected vulnerabilities detected)")
    print(f"Precision : {card.precision*100:.0f}%   "
          f"({card.validated_true} VALIDATED match ground truth, "
          f"{len(card.validated_extra)} VALIDATED unmatched, "
          f"{len(card.fp_trap_hits)} FP-trap hit)")
    print(f"Findings  : {card.total_findings} total, {card.validated_total} VALIDATED, "
          f"{card.extra_findings} not in ground truth\n")
    for i in card.items:
        if i.expected:
            mark = "DETECTED" if i.detected else "MISSED"
        elif i.fp_trap:
            mark = "FALSE POSITIVE" if i.detected_validated else ("flagged (review)" if i.detected else "clean")
        else:  # out of scope
            mark = "found (bonus)" if i.detected else "out of scope"
        print(f"  [{mark:>16}] {i.id:<20} {i.name}")
    if card.validated_extra:
        print("\n  VALIDATED findings not in ground truth (audit these — precision suspects):")
        for e in card.validated_extra:
            print(f"    - {e.title}")
    print()


def html_scorecard(card: ScoreCard) -> str:
    import html as _h
    rows = []
    for i in card.items:
        if i.expected:
            status = ("<b style='color:#1a7f37'>DETECTED</b>" if i.detected
                      else "<b style='color:#c41e22'>MISSED</b>")
        elif i.fp_trap:
            status = ("<b style='color:#c41e22'>FALSE POSITIVE</b>" if i.detected_validated
                      else ("flagged (review)" if i.detected else "<span style='color:#1a7f37'>clean</span>"))
        else:
            status = ("found (bonus)" if i.detected else "<span style='color:#888'>out of scope</span>")
        rows.append(f"<tr><td>{_h.escape(i.id)}</td><td>{_h.escape(i.name)}</td>"
                    f"<td>{_h.escape(i.category)}</td><td>{status}</td></tr>")
    extra = ""
    if card.validated_extra:
        lis = "".join(f"<li>{_h.escape(e.title)}</li>" for e in card.validated_extra)
        extra = ("<h3>VALIDATED findings not in ground truth (audit — precision suspects)</h3>"
                 f"<ul>{lis}</ul>")
    return f"""<!doctype html><meta charset="utf-8"><title>Benchmark {_h.escape(card.target)}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:860px;margin:40px auto;padding:0 16px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;text-align:left;font-size:14px}}
th{{background:#f6f8fa}}.big{{font-size:24px;font-weight:700}}</style>
<h1>Benchmark — {_h.escape(card.target)}</h1>
<p class="big">Recall {card.detected_expected}/{len(card.expected_items)} = {card.recall*100:.0f}%
&middot; Precision {card.precision*100:.0f}%</p>
<p>{card.total_findings} findings &middot; {card.validated_total} VALIDATED &middot;
{len(card.fp_trap_hits)} false-positive trap(s) hit</p>
<table><tr><th>ID</th><th>Item</th><th>Category</th><th>Result</th></tr>
{''.join(rows)}</table>{extra}"""


# ── running a scan via the live API ─────────────────────────────────

def run_via_api(api: str, token: str, target: str, timeout_s: int = 1800) -> list[dict]:
    import httpx  # local import so scoring works without httpx installed
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    api = api.rstrip("/")
    with httpx.Client(timeout=30.0, verify=False) as c:
        # Universal-scope: attest authorization for the benchmark target at launch.
        r = c.post(f"{api}/api/assessments/run", headers=headers, json={
            "target": target,
            "authorized": True,
            "authorization_ref": "benchmark corpus (authorized test target)",
        })
        r.raise_for_status()
        aid = r.json()["assessment_id"]
        print(f"assessment {aid} started; polling (up to {timeout_s}s)...", file=sys.stderr)
        deadline = time.time() + timeout_s
        status = "running"
        while time.time() < deadline:
            time.sleep(5)
            s = c.get(f"{api}/api/assessments/{aid}", headers=headers)
            if s.status_code != 200:
                continue
            status = s.json().get("status", "running")
            if status != "running":
                break
        if status == "running":
            print(f"WARNING: poll timed out after {timeout_s}s — scoring findings so far "
                  f"(may UNDERCOUNT). Re-run with --timeout to wait longer.", file=sys.stderr)
        else:
            print(f"assessment finished: {status}", file=sys.stderr)
        fr = c.get(f"{api}/api/assessments/{aid}/report.json", headers=headers)
        if fr.status_code == 200:
            return fr.json().get("findings", [])
        fl = c.get(f"{api}/api/assessments/{aid}/findings", headers=headers)
        fl.raise_for_status()
        return fl.json()


def main():
    ap = argparse.ArgumentParser(description="Benchmark the engine against ground truth")
    ap.add_argument("ground_truth", help="path to a ground-truth YAML (e.g. benchmarks/testfire.yaml)")
    ap.add_argument("--api", help="base URL of the running API (e.g. http://127.0.0.1:8090)")
    ap.add_argument("--token", default="", help="admin bearer token")
    ap.add_argument("--findings", help="score a saved findings JSON instead of running a scan")
    ap.add_argument("--html", help="also write an HTML scorecard to this path")
    ap.add_argument("--json", help="also write the scorecard as JSON to this path")
    ap.add_argument("--timeout", type=int, default=1800,
                    help="seconds to wait for the scan to finish (default 1800)")
    args = ap.parse_args()

    with open(args.ground_truth) as f:
        gt = yaml.safe_load(f)

    if args.findings:
        with open(args.findings) as f:
            findings = json.load(f)
            if isinstance(findings, dict):
                findings = findings.get("findings", [])
    elif args.api:
        findings = run_via_api(args.api, args.token, gt["target"], timeout_s=args.timeout)
    else:
        ap.error("provide --api to run a scan, or --findings to score saved output")

    card = score(findings, gt)
    print_scorecard(card)

    if args.html:
        with open(args.html, "w") as f:
            f.write(html_scorecard(card))
        print(f"wrote HTML scorecard: {args.html}", file=sys.stderr)
    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "target": card.target, "recall": card.recall, "precision": card.precision,
                "detected": card.detected_expected, "expected": len(card.expected_items),
                "validated_total": card.validated_total, "validated_true": card.validated_true,
                "validated_extra": [vars(e) for e in card.validated_extra],
                "fp_trap_hits": [i.id for i in card.fp_trap_hits],
                "total_findings": card.total_findings, "extra_findings": card.extra_findings,
                "items": [vars(i) for i in card.items],
            }, f, indent=2)
        print(f"wrote JSON scorecard: {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
