#!/usr/bin/env python3
"""
Build the local CVE index (data/cve/index.json) from the NVD 2.0 CVE API.

This is the OFFLINE data source for modules.cve_index: we mirror NVD once (and
refresh periodically), so scans never send target service banners to a third
party, results are reproducible, and correlation works air-gapped afterwards.

Usage:
    python backend/tools/sync_nvd.py                 # full sync (long; 250k+ CVEs)
    python backend/tools/sync_nvd.py --days 120      # only CVEs modified in last N days (incremental)
    NVD_API_KEY=xxxx python backend/tools/sync_nvd.py  # higher rate limit

Notes:
  - Without an API key NVD allows ~5 requests / 30s; with a free key, ~50.
    Get one at https://nvd.nist.gov/developers/request-an-api-key.
  - A full first sync takes a while; schedule --days refreshes thereafter.
  - Index shape is documented in modules/cve_index.py.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000


def _index_path() -> str:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "data", "cve", "index.json")


def _cpe_vendor_product(criteria: str) -> tuple[str, str]:
    # cpe:2.3:a:vendor:product:version:...
    f = criteria.split(":")
    if len(f) > 4 and f[0] == "cpe" and f[1] == "2.3":
        return f[3].lower(), f[4].lower()
    return "", ""


def _best_metric(cve: dict) -> tuple[float, str, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0) or 0.0)
            vector = data.get("vectorString", "")
            severity = (arr[0].get("baseSeverity") or data.get("baseSeverity") or "").lower()
            if not severity:
                severity = ("critical" if score >= 9 else "high" if score >= 7
                            else "medium" if score >= 4 else "low" if score > 0 else "none")
            return score, vector, severity
    return 0.0, "", "none"


def _english_desc(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _ranges_from_match(match: dict) -> dict | None:
    if not match.get("vulnerable", False):
        return None
    r: dict = {}
    if match.get("versionStartIncluding"):
        r["start_incl"] = match["versionStartIncluding"]
    if match.get("versionStartExcluding"):
        r["start_excl"] = match["versionStartExcluding"]
    if match.get("versionEndIncluding"):
        r["end_incl"] = match["versionEndIncluding"]
    if match.get("versionEndExcluding"):
        r["end_excl"] = match["versionEndExcluding"]
    if not r:
        # exact-version CPE (criteria carries a concrete version field)
        f = match.get("criteria", "").split(":")
        if len(f) > 5 and f[5] not in ("*", "-", ""):
            r["exact"] = f[5]
    return r or None


def _iter_cpe_matches(node: dict):
    for m in node.get("cpeMatch", []):
        yield m
    for child in node.get("children", []):
        yield from _iter_cpe_matches(child)


def fetch_page(start: int, days: int | None, api_key: str | None) -> dict:
    params = [f"resultsPerPage={PAGE}", f"startIndex={start}"]
    if days:
        end = datetime.now(timezone.utc)
        begin = end - timedelta(days=days)
        params.append("lastModStartDate=" + begin.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
        params.append("lastModEndDate=" + end.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
    url = API + "?" + "&".join(params)
    headers = {"User-Agent": "h4ckbot-nvd-sync/0.1"}
    if api_key:
        headers["apiKey"] = api_key
    for attempt in range(5):
        try:
            with urlopen(Request(url, headers=headers), timeout=60) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            if e.code in (403, 429, 503):
                wait = 20 * (attempt + 1)
                print(f"  rate-limited ({e.code}); waiting {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            raise
        except URLError as e:
            wait = 10 * (attempt + 1)
            print(f"  network error ({e}); retrying in {wait}s", file=sys.stderr)
            time.sleep(wait)
    raise SystemExit("repeated NVD API failures - aborting")


def build(days: int | None, api_key: str | None) -> dict:
    index: dict[str, list] = {}
    start = 0
    total = None
    while True:
        data = fetch_page(start, days, api_key)
        if total is None:
            total = data.get("totalResults", 0)
            print(f"NVD: {total} CVE record(s) to process", file=sys.stderr)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            score, vector, severity = _best_metric(cve)
            desc = _english_desc(cve)
            # vendor:product -> merged ranges
            pp: dict[str, list] = {}
            for conf in cve.get("configurations", []):
                for node in conf.get("nodes", []):
                    for match in _iter_cpe_matches(node):
                        vendor, product = _cpe_vendor_product(match.get("criteria", ""))
                        if not product:
                            continue
                        rng = _ranges_from_match(match)
                        if rng:
                            pp.setdefault(f"{vendor}:{product}", []).append(rng)
            for key, ranges in pp.items():
                index.setdefault(key, []).append({
                    "cve": cve_id, "score": score, "severity": severity,
                    "vector": vector, "description": desc, "ranges": ranges,
                })
        start += PAGE
        print(f"  processed {min(start, total)}/{total}", file=sys.stderr)
        if start >= (total or 0):
            break
        time.sleep(0.6 if api_key else 6.5)  # respect NVD rate limits
    return index


def main():
    ap = argparse.ArgumentParser(description="Build local CVE index from NVD")
    ap.add_argument("--days", type=int, default=None,
                    help="only CVEs modified in the last N days (incremental refresh)")
    ap.add_argument("--out", default=None, help="output path (default data/cve/index.json)")
    args = ap.parse_args()
    api_key = os.environ.get("NVD_API_KEY")

    index = build(args.days, api_key)

    out = args.out or _index_path()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # Incremental refresh: merge onto an existing index.
    if args.days and os.path.exists(out):
        try:
            with open(out) as f:
                existing = json.load(f)
            for k, v in index.items():
                existing[k] = v  # replace this product's entries with the fresh set
            index = existing
        except (json.JSONDecodeError, OSError):
            pass
    with open(out, "w") as f:
        json.dump(index, f)
    print(f"wrote {out}: {len(index)} product key(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
