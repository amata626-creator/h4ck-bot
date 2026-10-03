"""
Run recon against a single target and print the result.

Usage:
    python3 -m tools.run_recon --target crapi.local --port 8888
    python3 -m tools.run_recon --target crapi.local --port 8888 --json out.json

This exercises the same ReconModule the orchestrator uses, so anything
that works here will work in the pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

# Ensure the backend root is on sys.path so `recon`, `core` import cleanly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.module_interface import ModuleRunContext
from core.rules_of_engagement import RulesOfEngagement
from core.schema import Asset
from recon.module import ReconModule


async def _main(args) -> int:
    target = args.target
    port = args.port
    host_for_url = f"{target}:{port}" if port not in (80, 443) else target

    roe = RulesOfEngagement(
        assessment_id="recon-cli",
        authorized_by="operator (local test)",
        authorized_targets=[target, host_for_url],
        testing_window_start=_now_minus(),
        testing_window_end=_now_plus(),
        permitted_techniques=["passive_recon", "port_scan", "api_testing"],
        active_testing_permitted=True,
    )

    asset = Asset(
        asset_id="a0",
        name=host_for_url,
        asset_type="host",
        scope_approved=True,
        metadata={"exposure": "internet"},
    )

    ctx = ModuleRunContext(
        assessment_id="recon-cli",
        assets=[asset],
        roe=roe,
        automation_level="assisted",
        config={},
    )

    module = ReconModule()
    async for _ in module.run(ctx):
        pass  # recon yields no findings

    result = ctx.config.get("recon_results", {}).get("a0")
    if result is None:
        print("ERROR: recon produced no result", file=sys.stderr)
        return 1

    if args.json:
        out = Path(args.json)
        out.write_text(json.dumps(asdict(result), indent=2, default=str))
        print(f"wrote {out}")

    # Human-readable summary
    print()
    print("═" * 60)
    print(f"  Recon result: {result.target}")
    print("═" * 60)
    print()
    print(f"  Reachable base URLs ({len(result.base_urls)}):")
    for u in result.base_urls:
        print(f"    {u}")
    print()
    tech = result.tech
    print(f"  Tech stack:")
    print(f"    server:     {tech.server or '-'}")
    print(f"    powered-by: {tech.powered_by or '-'}")
    print(f"    framework:  {tech.framework or '-'}")
    print(f"    language:   {tech.language or '-'}")
    print(f"    cms:        {tech.cms or '-'}")
    print()
    print(f"  Auth hints:")
    print(f"    login paths:  {', '.join(result.auth.login_paths) or '-'}")
    print(f"    cookies:      {', '.join(result.auth.cookie_names) or '-'}")
    print(f"    auth headers: {', '.join(result.auth.auth_header_names) or '-'}")
    print(f"    csrf params:  {', '.join(result.auth.csrf_param_names) or '-'}")
    print()
    print(f"  Endpoints ({len(result.endpoints)}):")
    for ep in result.endpoints[:args.max_endpoints]:
        methods = ",".join(ep.methods) or "ANY"
        src = ep.discovered_from
        params = f"  params={ep.params}" if ep.params else ""
        print(f"    [{methods:12s}] {ep.path:50s} ({src}){params}")
    if len(result.endpoints) > args.max_endpoints:
        print(f"    ... and {len(result.endpoints) - args.max_endpoints} more")
    print()
    print(f"  JS bundles ({len(result.js_bundles)}):")
    for j in result.js_bundles[:5]:
        print(f"    {j}")
    print()
    if result.openapi_spec is not None:
        print(f"  OpenAPI spec: found (version={result.openapi_spec.get('openapi') or result.openapi_spec.get('swagger')})")
    print()
    if result.unknowns:
        print(f"  Unknowns:")
        for u in result.unknowns:
            print(f"    - {u}")
    print()
    return 0


def _now_minus():
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) - timedelta(minutes=1)


def _now_plus():
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) + timedelta(hours=1)


def main():
    p = argparse.ArgumentParser(description="Run H4CK-B0T recon against one target.")
    p.add_argument("--target", required=True, help="hostname or IP")
    p.add_argument("--port", type=int, default=8888, help="port for the primary base URL")
    p.add_argument("--json", help="write full result as JSON to this path")
    p.add_argument("--max-endpoints", type=int, default=80, help="cap on printed endpoints")
    args = p.parse_args()
    sys.exit(asyncio.run(_main(args)))


if __name__ == "__main__":
    main()
