"""
ReconModule — a ScannerModule that performs discovery only.

Recon does not produce Findings. It builds a ReconResult, which is the
input to the semantic model and hypothesis generator. The Finding
type is intentionally not used here - recon is not a finding, it's
context for hypotheses that will become findings.

To keep the ScannerModule contract (which yields Finding), this module
yields *nothing*. The orchestrator runs it and the ReconResult is
stashed on the context, to be picked up by the semantic and hypothesis
components. If you're running recon standalone, use tools/run_recon.py
which calls this module directly.
"""

from __future__ import annotations

import logging
from typing import AsyncIterator, Optional

import httpx

from core.module_interface import (
    ModuleCapabilities, ModuleRunContext, ScannerModule,
)
from core.schema import Finding
from recon.crawler import Crawler
from recon.fingerprint import fingerprint, infer_auth_hints
from recon.openapi import find_and_parse
from recon.types import Endpoint, ReconResult

logger = logging.getLogger("h4ck-bot.recon")

DEFAULT_HTTP_PORTS = [80, 443, 8080, 8000, 8888]
MAX_PAGES = 120
MAX_DEPTH = 3


class ReconModule(ScannerModule):
    @property
    def capabilities(self) -> ModuleCapabilities:
        return ModuleCapabilities(
            module_id="recon",
            display_name="Reconnaissance (crawl, enumerate, fingerprint)",
            supported_asset_types=["host", "web_app", "api"],
            kill_chain_phases=["reconnaissance"],
            requires_active_testing=True,
            max_automation_level="assisted",
        )

    async def run(self, ctx: ModuleRunContext) -> AsyncIterator[Finding]:
        """
        Yield nothing. Recon produces a ReconResult; the orchestrator
        stashes it on ctx.config["recon_results"][asset.asset_id] for
        downstream components. This is a ScannerModule so it fits the
        existing plugin contract, but recon isn't a finding-generator.
        """
        recon_cache: dict = ctx.config.setdefault("recon_results", {})
        for asset in ctx.assets:
            self.assert_in_scope(asset, ctx)
            result = await self.recon_asset(asset.name, ctx)
            recon_cache[asset.asset_id] = result
            logger.info(
                "recon complete for %s: %d endpoints, %d js bundles, tech=%s",
                asset.name, len(result.endpoints), len(result.js_bundles),
                result.tech.framework or result.tech.server or "unknown",
            )
        # A generator that yields nothing still satisfies the contract
        return
        yield  # unreachable; makes this a valid async generator

    async def recon_asset(self, target: str, ctx: ModuleRunContext) -> ReconResult:
        """
        Recon a single target. Not on the ScannerModule ABC - exposed
        separately so tools/run_recon.py can call it directly without
        going through the orchestrator.
        """
        result = ReconResult(target=target)

        # Authenticated assessment: if the caller supplied a session (a Cookie
        # string copied from a logged-in browser, and/or extra headers like a
        # bearer token), carry it on every recon request so the crawl sees the
        # app behind the login, not just the public pages.
        auth = (ctx.config or {}).get("auth") or {}
        _headers = {"User-Agent": "h4ckbot-recon/0.1 (+authorized-assessment)"}
        for _k, _v in (auth.get("headers") or {}).items():
            _headers[str(_k)] = str(_v)
        if auth.get("cookie"):
            _headers["Cookie"] = str(auth["cookie"])
        if auth.get("cookie") or auth.get("headers"):
            logger.info("recon %s: running AUTHENTICATED (session supplied)", target)

        async with httpx.AsyncClient(
            timeout=8.0, follow_redirects=True, verify=False, headers=_headers,
        ) as client:
            # 1. Which base URLs are reachable?
            for port in DEFAULT_HTTP_PORTS:
                for scheme in ("https", "http"):
                    # Skip http on 443 and https on 80 - never right in practice
                    if port == 443 and scheme == "http":
                        continue
                    if port == 80 and scheme == "https":
                        continue
                    url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"
                    if await self._is_alive(client, url):
                        result.base_urls.append(url)
                        logger.info("reachable base: %s", url)

            if not result.base_urls:
                result.unknowns.append("no reachable HTTP(S) base URL found on common ports")
                result.completed_at = _now()
                return result

            # 2. Per base URL: openapi, then crawl
            for base in result.base_urls:
                spec, spec_endpoints = await find_and_parse(client, base)
                if spec is not None:
                    result.openapi_spec = spec
                    for ep in spec_endpoints:
                        result.add_endpoint(ep)
                    logger.info("openapi found at %s: %d endpoints", base, len(spec_endpoints))
                    break   # one spec per target is enough

            # Crawl the first reachable base (HTTPS preferred if present)
            primary = next((b for b in result.base_urls if b.startswith("https")), result.base_urls[0])
            crawler = Crawler(
                base_url=primary,
                max_depth=MAX_DEPTH,
                max_pages=MAX_PAGES,
                respect_robots=True,
                client=client,
            )
            crawl = await crawler.crawl()
            result.robots_txt = crawl.robots_txt
            result.js_bundles = crawl.js_bundles
            for ep in crawl.endpoints:
                result.add_endpoint(ep)
            # Cap stored traces: keep the most informative ones
            result.http_traces = _select_traces(crawl.traces, limit=30)

            # If we found JS bundles, fetch a couple to extract more paths
            for js_url in result.js_bundles[:17]:
                try:
                    resp = await client.get(js_url)
                    if resp.status_code == 200:
                        from recon.crawler import Crawler as _C
                        c = _C(base_url=primary, client=client)
                        c._extract_js_paths(resp.text[:200_000])
                        for ep in c._endpoints:
                            result.add_endpoint(ep)
                except Exception:
                    continue

            # 3. Fingerprint and auth hints from the traces we have
            result.tech = fingerprint(result.http_traces)
            result.auth = infer_auth_hints(result.http_traces)

            # 4. Note what we couldn't determine
            if not result.endpoints:
                result.unknowns.append("no endpoints discovered; site may be JS-rendered or require auth")
            if not result.tech.framework and not result.tech.server:
                result.unknowns.append("could not fingerprint server framework")
            if not result.auth.login_paths:
                result.unknowns.append("no login path identified")

        result.completed_at = _now()
        return result

    async def _is_alive(self, client: httpx.AsyncClient, url: str) -> bool:
        try:
            resp = await client.get(url, timeout=5.0)
            return resp.status_code < 600
        except Exception:
            return False


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _select_traces(traces: list, limit: int) -> list:
    """
    Keep a bounded set of traces: prefer 200s with content, one per
    unique path, newest-first. This is what the semantic-model LLM
    reads, so quality matters more than volume.
    """
    seen_paths: set[str] = set()
    out = []
    # Score: prefer 200/201, then non-HTML, then smaller bodies (less noise)
    def score(t):
        s = 0
        if t.status in (200, 201): s += 100
        elif 200 <= t.status < 300: s += 50
        if "json" in t.response_headers.get("content-type", ""): s += 30
        if t.error: s -= 200
        return s
    for t in sorted(traces, key=score, reverse=True):
        from urllib.parse import urlparse
        p = urlparse(t.url).path
        if p in seen_paths:
            continue
        seen_paths.add(p)
        out.append(t)
        if len(out) >= limit:
            break
    return out
