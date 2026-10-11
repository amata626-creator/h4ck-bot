"""
Playwright-based deep endpoint discovery.

The static HTML parser used elsewhere in this codebase only sees
links present in the server-rendered HTML. Modern SPA/hydrated apps
often add links via client-side JS after the initial render, and the
interesting attack surface is frequently an API endpoint the page
calls via fetch()/XHR rather than a link a user clicks - neither of
those show up to a plain HTML parser at all.

This module renders each page with a real (headless) browser and:
  - reads the fully hydrated DOM's <a href> links, not just the raw HTML
  - observes every XHR/fetch request the page makes during normal load
  - parses robots.txt (Sitemap: and Disallow: directives) and
    sitemap.xml for additional same-origin URLs
  - checks a handful of common OpenAPI/Swagger spec paths and, if one
    is found, extracts every path it declares

This is still pure reconnaissance: pages are only ever *visited*
(normal GET-equivalent navigation), never has a form submitted or a
button clicked, and any link whose path looks like a logout/destructive
action is explicitly skipped so a crawl never accidentally changes
server-side state.

Kept as a separate module from modules/owasp_top10_module.py's own
crawler (which also does auth-form-aware discovery for its own checks)
so that already-verified crawler is not touched or put at risk by this.
"""

from __future__ import annotations

import logging
import os
import re
from urllib.parse import urljoin, urlparse

import httpx

from modules.owasp_top10_module import _normalize_netloc, STATIC_EXTENSIONS
from evidence.llm_client import OllamaClient

logger = logging.getLogger("h4ck-bot.deep_crawler")


def _resolve_model(model: str | None) -> str:
    """The model for AI-assisted JS endpoint extraction. Honors the engine's
    reasoning-model override (H4CK_BOT_REASONING_MODEL) so a CPU host can run a
    fast model here instead of timing out on an 8B one — the same decoupling the
    rest of the AI layers use. Never defaults to OllamaClient's own 'mistral:7b'
    (not installed on this server, silently 404s)."""
    return (model
            or os.environ.get("H4CK_BOT_REASONING_MODEL", "").strip()
            or os.environ.get("H4CK_BOT_LLM_MODEL", "").strip()
            or "qwen2.5:3b")

JS_ENDPOINT_REGEX = re.compile(r"""["'`](/(?:api|graphql|v[0-9]+)/[a-zA-Z0-9_\-/{}:.]+)["'`]""")
MAX_JS_FILES_FOR_AI = 6  # cap AI-assisted extraction calls per crawl to keep scan time reasonable

EXCLUDED_PATH_SUBSTRINGS = ["/logout", "/signout", "/sign-out", "/log-out", "/delete"]
NAV_TIMEOUT_MS = 15000
FETCH_TIMEOUT = 6.0

OPENAPI_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs",
    "/api/openapi.json", "/.well-known/openapi.json", "/api/swagger.json",
]


async def discover_endpoints(base_url: str, max_pages: int = 40,
                             extra_headers: dict | None = None,
                             model: str | None = None) -> list[str]:
    """Deep (rendered) endpoint discovery. `extra_headers`, when supplied,
    carries an authenticated session (a Cookie header and/or a bearer token) on
    BOTH the httpx fetches and the browser navigations, so an authenticated
    assessment crawls behind the login. GET-equivalent navigation only; never
    submits a form or clicks a destructive action."""
    from playwright.async_api import async_playwright

    extra_headers = {str(k): str(v) for k, v in (extra_headers or {}).items()}
    base_host = _normalize_netloc(urlparse(base_url).netloc)
    visited: set[str] = set()
    endpoints: set[str] = set()
    to_visit: list[str] = [base_url]

    # -- robots.txt / sitemap.xml / OpenAPI specs: cheap, no browser needed --
    async with httpx.AsyncClient(verify=False, timeout=FETCH_TIMEOUT, follow_redirects=True,
                                 headers=(extra_headers or None)) as client:
        try:
            robots = await client.get(urljoin(base_url, "/robots.txt"))
            if robots.status_code == 200:
                disallow_count = 0
                for line in robots.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("sitemap:"):
                        to_visit.append(line.split(":", 1)[1].strip())
                    elif line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            endpoints.add(urljoin(base_url, path))
                            disallow_count += 1
                logger.info(f"deep_crawler: {base_url} - robots.txt parsed, {disallow_count} Disallow path(s) added as candidates")
            else:
                logger.info(f"deep_crawler: {base_url} - robots.txt -> status {robots.status_code}")
        except Exception as e:
            logger.info(f"deep_crawler: {base_url} - robots.txt fetch failed - {type(e).__name__}: {e}")

        try:
            sitemap = await client.get(urljoin(base_url, "/sitemap.xml"))
            if sitemap.status_code == 200:
                locs = re.findall(r"<loc>(.*?)</loc>", sitemap.text)
                added = 0
                for loc in locs:
                    if _normalize_netloc(urlparse(loc).netloc) == base_host:
                        to_visit.append(loc)
                        added += 1
                logger.info(f"deep_crawler: {base_url} - sitemap.xml parsed, {added} same-origin URL(s) found")
            else:
                logger.info(f"deep_crawler: {base_url} - sitemap.xml -> status {sitemap.status_code}")
        except Exception as e:
            logger.info(f"deep_crawler: {base_url} - sitemap.xml fetch failed - {type(e).__name__}: {e}")

        for spec_path in OPENAPI_SPEC_PATHS:
            try:
                resp = await client.get(urljoin(base_url, spec_path))
            except Exception:
                continue
            if resp.status_code != 200 or "json" not in resp.headers.get("content-type", ""):
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            paths = data.get("paths") if isinstance(data, dict) else None
            if not paths:
                continue
            endpoints.add(urljoin(base_url, spec_path))
            for p in paths.keys():
                endpoints.add(urljoin(base_url, p))
            logger.info(f"deep_crawler: {base_url} - API spec found at {spec_path}, {len(paths)} endpoint(s) extracted")

    # -- Playwright-based rendered crawl + network capture --
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            context = await browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=(extra_headers or None),   # carry the auth session into the browser
            )

            async def on_request(request):
                url = request.url
                parsed = urlparse(url)
                if _normalize_netloc(parsed.netloc) != base_host:
                    return
                if request.resource_type in ("xhr", "fetch"):
                    if url not in endpoints:
                        endpoints.add(url)

            js_bundles: dict[str, str] = {}
            js_urls_with_regex_hits: list[str] = []

            async def on_response(response):
                try:
                    if response.request.resource_type != "script":
                        return
                    url = response.url
                    if url in js_bundles:
                        return
                    parsed = urlparse(url)
                    if _normalize_netloc(parsed.netloc) != base_host:
                        return
                    try:
                        body = await response.text()
                    except Exception:
                        return
                    js_bundles[url] = body
                    regex_hits = set(JS_ENDPOINT_REGEX.findall(body))
                    if regex_hits:
                        for hit in regex_hits:
                            endpoints.add(urljoin(base_url, hit))
                        js_urls_with_regex_hits.append(url)
                        logger.info(f"deep_crawler: {url} - regex found {len(regex_hits)} endpoint-like string(s) in JS bundle")
                except Exception as e:
                    logger.info(f"deep_crawler: JS response handling failed for {getattr(response, 'url', '?')} - {type(e).__name__}: {e}")

            page = await context.new_page()
            page.on("request", on_request)
            page.on("response", on_response)

            while to_visit and len(visited) < max_pages:
                url = to_visit.pop(0)
                if url in visited:
                    continue
                if any(sub in url.lower() for sub in EXCLUDED_PATH_SUBSTRINGS):
                    logger.info(f"deep_crawler: skipping {url} - excluded path (logout/destructive-looking)")
                    continue
                visited.add(url)

                try:
                    await page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="networkidle")
                except Exception as e:
                    logger.info(f"deep_crawler: failed to load {url} - {type(e).__name__}: {e}")
                    continue

                try:
                    hrefs = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                except Exception:
                    hrefs = []

                new_count = 0
                for link in hrefs:
                    parsed = urlparse(link)
                    if _normalize_netloc(parsed.netloc) != base_host:
                        continue
                    if parsed.scheme not in ("http", "https"):
                        continue
                    if link.lower().split("?")[0].endswith(STATIC_EXTENSIONS):
                        continue
                    if any(sub in link.lower() for sub in EXCLUDED_PATH_SUBSTRINGS):
                        continue
                    if link not in visited and link not in to_visit:
                        to_visit.append(link)
                        new_count += 1

                logger.info(f"deep_crawler: visited {url} -> {new_count} new link(s) queued "
                           f"({len(visited)}/{max_pages} pages, {len(endpoints)} endpoint(s) observed so far)")

            if js_bundles:
                logger.info(f"deep_crawler: {base_url} - {len(js_bundles)} JS bundle(s) captured, "
                           f"running AI-assisted endpoint extraction on up to {MAX_JS_FILES_FOR_AI}")
                # Uses the engine's reasoning model (H4CK_BOT_REASONING_MODEL,
                # e.g. qwen2.5:3b) via _resolve_model, not a hardcoded 8B model
                # that times out on CPU hosts and not OllamaClient's own
                # 'mistral:7b' default (never installed here, silently 404s and
                # was swallowed as "0 endpoints").
                ollama = OllamaClient(model=_resolve_model(model))
                ai_endpoint_total = 0
                # Prioritize bundles the regex pass already proved contain
                # endpoint-like strings - a webpack runtime/manifest bundle
                # (loaded first, purely by navigation order) never contains
                # application API paths, so processing by discovery order
                # wastes the AI budget on files guaranteed to return nothing.
                prioritized_urls = sorted(
                    js_bundles.keys(),
                    key=lambda u: 0 if u in js_urls_with_regex_hits else 1,
                )
                for i, js_url in enumerate(prioritized_urls):
                    if i >= MAX_JS_FILES_FOR_AI:
                        logger.info(f"deep_crawler: {base_url} - reached MAX_JS_FILES_FOR_AI cap, "
                                   f"skipping remaining {len(prioritized_urls) - i} bundle(s)")
                        break
                    js_body = js_bundles[js_url]
                    ai_endpoints = await ollama.extract_endpoints_from_js(js_body, js_url)
                    new_from_ai = 0
                    for ep in ai_endpoints:
                        full = urljoin(base_url, ep)
                        if full not in endpoints:
                            endpoints.add(full)
                            new_from_ai += 1
                    ai_endpoint_total += new_from_ai
                    logger.info(f"deep_crawler: AI extraction on {js_url} -> "
                               f"{len(ai_endpoints)} endpoint(s) returned, {new_from_ai} new")
                logger.info(f"deep_crawler: {base_url} - AI-assisted pass added {ai_endpoint_total} new endpoint(s) total")
            else:
                logger.info(f"deep_crawler: {base_url} - no same-origin JS bundles captured, skipping AI pass")

            await browser.close()
    except Exception as e:
        logger.info(f"deep_crawler: {base_url} - Playwright crawl phase failed - {type(e).__name__}: {e} "
                   f"(keeping whatever pages/endpoints were found before the failure)")

    all_urls = sorted(visited | endpoints)
    logger.info(f"deep_crawler: {base_url} - DONE: {len(visited)} page(s) rendered, "
               f"{len(endpoints)} distinct endpoint(s)/API call(s)/spec path(s) observed, "
               f"{len(all_urls)} total unique URL(s)")
    return all_urls
