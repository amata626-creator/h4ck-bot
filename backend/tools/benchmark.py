#!/usr/bin/env python3
"""
Benchmark the engine against a known-vulnerable target with curated ground
truth, and print a detection-rate scorecard. This is how you objectively
answer "are we finding the vulnerabilities we should?" — a number, not a vibe.

Usage:
    # run a scan via the live API and score it
    python backend/tools/benchmark.py benchmarks/testfire.yaml \
        --api http://127.0.0.1:8090 --token "$H4CK_BOT_ADMIN_TOKEN"

    # score findings already saved to a JSON file (list of finding dicts)
    python backend/tools/benchmark.py benchmarks/testfire.yaml --findings findings.json

    # write an HTML scorecard too
    python backend/tools/benchmark.py benchmarks/testfire.yaml --api ... --html out.html

A ground-truth item counts as DETECTED if any finding matches its CWE or any
of its match_any keywords (case-insensitive, against title + description).
Items with `expected: false` are out-of-scope-by-design: they don't count
against recall, and the scorecard shows whether we found them anyway.
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
    expected: bool
    detected: bool
    matched_by: list[str] = field(default_factory=list)   # finding titles that matched


@dataclass
class ScoreCard:
    target: str
    items: list[ItemResult]
    total_findings: int
    extra_findings: int           # findings not mapping to any ground-truth item

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


def _finding_text(f: dict) -> str:
    bits = [f.get("title", ""), f.get("description", "")]
    cvss = f.get("cvss") or {}
    return " ".join(str(b) for b in bits).lower()


def _finding_cwe(f: dict) -> str:
    cwe = f.get("cwe") or {}
    if isinstance(cwe, dict):
        return str(cwe.get("cwe_id", "")).upper()
    return str(cwe).upper()


def score(findings: list[dict], ground_truth: dict) -> ScoreCard:
    items: list[ItemResult] = []
    matched_finding_ids: set[int] = set()

    for gi in ground_truth.get("items", []):
        cwe = str(gi.get("cwe", "")).upper()
        kws = [k.lower() for k in gi.get("match_any", [])]
        matched_by: list[str] = []
        for idx, f in enumerate(findings):
            text = _finding_text(f)
            hit = (cwe and _finding_cwe(f) == cwe) or any(k in text for k in kws)
            if hit:
                matched_by.append(f.get("title", "(untitled)"))
                matched_finding_ids.add(idx)
        items.append(ItemResult(
            id=gi.get("id", ""), name=gi.get("name", ""),
            category=gi.get("category", ""),
            expected=gi.get("expected", True),
            detected=bool(matched_by), matched_by=matched_by,
        ))

    extra = len(findings) - len(matched_finding_ids)
    return ScoreCard(
        target=ground_truth.get("target", ""),
        items=items, total_findings=len(findings), extra_findings=extra,
    )


# ── scorecard rendering ─────────────────────────────────────────────

def print_scorecard(card: ScoreCard) -> None:
    print(f"\n=== Benchmark: {card.target} ===")
    print(f"Detection rate (recall): {card.detected_expected}/{len(card.expected_items)} "
          f"= {card.recall*100:.0f}%   | total findings: {card.total_findings} "
          f"| extra (not in ground truth): {card.extra_findings}\n")
    for i in card.items:
        if i.expected:
            mark = "PASS" if i.detected else "MISS"
        else:
            mark = "n/a (found!)" if i.detected else "n/a (out of scope)"
        print(f"  [{mark:>14}] {i.id:<18} {i.name}")
    print()


def html_scorecard(card: ScoreCard) -> str:
    import html as _h
    rows = []
    for i in card.items:
        if i.expected:
            status = ("<b style='color:#1a7f37'>DETECTED</b>" if i.detected
                      else "<b style='color:#c41e22'>MISSED</b>")
        else:
            status = ("found (out-of-scope)" if i.detected else "<span style='color:#888'>out of scope</span>")
        rows.append(f"<tr><td>{_h.escape(i.id)}</td><td>{_h.escape(i.name)}</td>"
                    f"<td>{_h.escape(i.category)}</td><td>{status}</td></tr>")
    return f"""<!doctype html><meta charset="utf-8"><title>Benchmark {_h.escape(card.target)}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:860px;margin:40px auto;padding:0 16px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;text-align:left;font-size:14px}}
th{{background:#f6f8fa}}.big{{font-size:28px;font-weight:700}}</style>
<h1>Benchmark — {_h.escape(card.target)}</h1>
<p class="big">Recall: {card.detected_expected}/{len(card.expected_items)} = {card.recall*100:.0f}%</p>
<p>Total findings: {card.total_findings} &middot; extra (not in ground truth): {card.extra_findings}</p>
<table><tr><th>ID</th><th>Vulnerability</th><th>Category</th><th>Result</th></tr>
{''.join(rows)}</table>"""


# ── running a scan via the live API ─────────────────────────────────

def run_via_api(api: str, token: str, target: str, timeout_s: int = 1800) -> list[dict]:
    import httpx  # local import so scoring works without httpx installed
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    api = api.rstrip("/")
    with httpx.Client(timeout=30.0, verify=False) as c:
        r = c.post(f"{api}/api/assessments/run", headers=headers, json={"target": target})
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
            meta = s.json()
            status = meta.get("status", "running")
            if status != "running":
                break
        if status == "running":
            print(f"WARNING: poll timed out after {timeout_s}s — the scan is still "
                  f"running; scoring the findings stored so far (this may UNDERCOUNT). "
                  f"Re-run with --timeout to wait longer, or pick a faster model.",
                  file=sys.stderr)
        else:
            print(f"assessment finished: {status}", file=sys.stderr)
        fr = c.get(f"{api}/api/assessments/{aid}/report.json", headers=headers)
        if fr.status_code == 200:
            return fr.json().get("findings", [])
        # fallback: findings listing
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
                "target": card.target, "recall": card.recall,
                "detected": card.detected_expected, "expected": len(card.expected_items),
                "total_findings": card.total_findings, "extra_findings": card.extra_findings,
                "items": [vars(i) for i in card.items],
            }, f, indent=2)
        print(f"wrote JSON scorecard: {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
