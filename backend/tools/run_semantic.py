"""
Run recon + semantic model against a single target and print both.

Usage:
    python3 -m tools.run_semantic --target dev.cokpit.ai --port 443
    python3 -m tools.run_semantic --target 127.0.0.1 --port 8888 --model llama3.1
    python3 -m tools.run_semantic --target dev.cokpit.ai --port 443 \
        --json-recon /tmp/recon.json --json-semantic /tmp/semantic.json

Requires Ollama running locally with the target model pulled:
    ollama pull llama3.1
    ollama serve       (usually already running as a service)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.module_interface import ModuleRunContext
from core.rules_of_engagement import RulesOfEngagement
from core.schema import Asset
from recon.module import ReconModule
from recon.types import ReconResult
from semantic.model import SemanticModelBuilder

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(name)s - %(message)s",
)


async def _main(args) -> int:
    target = args.target
    port = args.port
    host_for_url = f"{target}:{port}" if port not in (80, 443) else target

    # ── 1. Recon ────────────────────────────────────────────────
    print(f"[1/2] running recon against {host_for_url} ...")
    roe = RulesOfEngagement(
        assessment_id="semantic-cli",
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
        assessment_id="semantic-cli",
        assets=[asset],
        roe=roe,
        automation_level="assisted",
        config={},
    )

    recon_module = ReconModule()
    async for _ in recon_module.run(ctx):
        pass
    recon: ReconResult = ctx.config["recon_results"]["a0"]

    if args.json_recon:
        Path(args.json_recon).write_text(json.dumps(asdict(recon), indent=2, default=str))
        print(f"      recon written to {args.json_recon}")

    print(f"      {len(recon.endpoints)} endpoints, {len(recon.http_traces)} traces, "
          f"framework={recon.tech.framework or 'unknown'}")

    # ── 2. Semantic model ───────────────────────────────────────
    print(f"[2/2] building semantic model via {args.model} ...")
    builder = SemanticModelBuilder(
        model=args.model,
        ollama_base_url=args.ollama_url,
        timeout=args.timeout,
        allow_cloud=args.allow_cloud,
    )
    try:
        model = await builder.build(recon)
    except Exception as e:
        import traceback
        print(f"ERROR: semantic model failed: {type(e).__name__}", file=sys.stderr)
        print(f"       message: {e!r}", file=sys.stderr)
        print("       full traceback:", file=sys.stderr)
        traceback.print_exc()
        return 2

    if args.json_semantic:
        Path(args.json_semantic).write_text(json.dumps(asdict(model), indent=2, default=str))
        print(f"      semantic model written to {args.json_semantic}")

    # ── Human-readable output ───────────────────────────────────
    print()
    print("═" * 66)
    print(f"  Semantic model: {model.target}")
    print("═" * 66)
    print()
    print(f"  Category: {model.product_category or '(unspecified)'}")
    print()
    print(f"  Purpose:")
    for line in _wrap(model.app_purpose or "(empty)", 62):
        print(f"    {line}")
    print()

    if model.roles:
        print(f"  Roles ({len(model.roles)}):")
        for r in model.roles:
            print(f"    - {r.name}")
            if r.evidence:
                for line in _wrap(r.evidence, 58):
                    print(f"        {line}")
        print()

    if model.resources:
        print(f"  Resources ({len(model.resources)}):")
        for r in model.resources:
            marker = " *OWNERSHIP*" if r.has_ownership_signal() else ""
            print(f"    - {r.name}  [sensitivity={r.sensitivity}]{marker}")
            if r.identifier_field:
                print(f"        id field:    {r.identifier_field}")
            if r.owner_field:
                print(f"        owner field: {r.owner_field}")
            if r.endpoints:
                print(f"        endpoints:   {', '.join(r.endpoints[:4])}"
                      + (f" (+{len(r.endpoints)-4} more)" if len(r.endpoints) > 4 else ""))
            if r.notes:
                for line in _wrap(r.notes, 58):
                    print(f"        {line}")
        print()

    if model.workflows:
        print(f"  Workflows ({len(model.workflows)}):")
        for w in model.workflows:
            pay = " [PAYMENT]" if w.involves_payment else ""
            print(f"    - {w.name}{pay}")
            if w.steps:
                print(f"        {' -> '.join(w.steps[:5])}"
                      + (f" (+{len(w.steps)-5} more)" if len(w.steps) > 5 else ""))
        print()

    if model.trust_boundaries:
        print(f"  Trust boundaries:")
        for t in model.trust_boundaries:
            for line in _wrap(t, 62):
                print(f"    {line}")
        print()

    if model.auth_flow_notes:
        print(f"  Auth flow:")
        for line in _wrap(model.auth_flow_notes, 62):
            print(f"    {line}")
        print()

    if model.unknowns:
        print(f"  Unknowns ({len(model.unknowns)}):")
        for u in model.unknowns:
            for line in _wrap(u, 62):
                print(f"    - {line}")
        print()

    print(f"  Model: {model.model_name}")
    print()

    return 0


def _wrap(text: str, width: int) -> list[str]:
    import textwrap
    return textwrap.wrap(text, width=width) or [""]


def _now_minus():
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) - timedelta(minutes=1)


def _now_plus():
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) + timedelta(hours=1)


def main():
    p = argparse.ArgumentParser(description="Run recon + semantic model.")
    p.add_argument("--target", required=True)
    p.add_argument("--port", type=int, default=8888)
    p.add_argument("--model", default="llama3.1",
                   help="Ollama model name. Local models are preferred; "
                        "a :cloud model requires --allow-cloud.")
    p.add_argument("--timeout", type=float, default=300.0,
                   help="Seconds to wait for the LLM. Default 300s.")
    p.add_argument("--allow-cloud", action="store_true",
                   help="Permit use of a :cloud model. Without this, cloud "
                        "models are refused because recon data leaves the host.")
    p.add_argument("--ollama-url", default="http://localhost:11434")
    p.add_argument("--json-recon", help="write recon result to this path")
    p.add_argument("--json-semantic", help="write semantic model to this path")
    args = p.parse_args()
    sys.exit(asyncio.run(_main(args)))


if __name__ == "__main__":
    main()
