"""
Headless-browser discovery — see what a regex crawler can't.

Modern apps render client-side: the initial HTML is an empty shell and the
real content, links, and — crucially — the API calls appear only after the
JavaScript runs. The regex crawler therefore finds almost nothing on a SPA
(we saw this: a hardened Next.js target returned ~nothing).

This renders a page in real Chromium (Playwright), waits for the network to
settle, and harvests two things the static crawler misses:
  1. the links/forms present in the *rendered* DOM, and
  2. the XHR/fetch requests the app actually made — i.e. the API endpoints,
     which are the real attack surface for a JS app.

It is read-only navigation (no clicking of destructive controls, no form
submission) and best-effort: any failure returns an empty list and the
caller falls back to the regex crawl. An auth session (extra_headers) is
carried so an authenticated SPA renders its real pages.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse, parse_qs

from recon.types import Endpoint

logger = logging.getLogger("h4ck-bot.recon.headless")

_NAV_TIMEOUT_MS = 15000
_SETTLE_MS = 1500          # grace for late XHR after networkidle
_MAX_ENDPOINTS = 200
# Asset/resource requests that are not interesting as endpoints.
_SKIP_RESOURCE = {"image", "media", "font", "stylesheet"}
_SKIP_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
                ".css", ".woff", ".woff2", ".ttf", ".map")


def _same_origin(url: str, base_netloc: str) -> bool:
    try:
        return urlparse(url).netloc == base_netloc
    except ValueError:
        return False


def _path_and_params(url: str) -> tuple[str, list[str]]:
    p = urlparse(url)
    return (p.path or "/"), sorted(parse_qs(p.query).keys())


async def render_and_discover(base_url: str, extra_headers: dict | None = None) -> list[Endpoint]:
    """Render base_url in headless Chromium and return the endpoints found in
    the rendered DOM and in the app's XHR/fetch traffic. Best-effort: returns
    [] on any failure."""
    try:
        from playwright.async_api import async_playwright, TimeoutError as PWTimeout
    except Exception as exc:  # noqa: BLE001
        logger.info("playwright unavailable, skipping headless discovery: %s", exc)
        return []

    base_netloc = urlparse(base_url).netloc
    xhr: dict[str, set[str]] = {}   # url -> methods (from fetch/xhr)

    def _on_request(req):
        try:
            if req.resource_type in ("xhr", "fetch") and _same_origin(req.url, base_netloc):
                xhr.setdefault(req.url, set()).add(req.method.upper())
        except Exception:
            pass

    endpoints: list[Endpoint] = []
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=extra_headers or {},
                )
                page = await context.new_page()
                page.on("request", _on_request)
                try:
                    await page.goto(base_url, timeout=_NAV_TIMEOUT_MS, wait_until="networkidle")
                except PWTimeout:
                    # networkidle may never fire on a chatty app; a load is enough
                    try:
                        await page.goto(base_url, timeout=_NAV_TIMEOUT_MS, wait_until="load")
                    except Exception:
                        return []
                await page.wait_for_timeout(_SETTLE_MS)

                # rendered links
                try:
                    hrefs = await page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)"
                    )
                except Exception:
                    hrefs = []
                # rendered forms (method-aware)
                try:
                    forms = await page.eval_on_selector_all(
                        "form",
                        "els => els.map(f => ({action: f.action, method: (f.method||'GET'), "
                        "inputs: Array.from(f.querySelectorAll('[name]')).map(i => i.name)}))",
                    )
                except Exception:
                    forms = []
            finally:
                await browser.close()
    except Exception as exc:  # noqa: BLE001
        logger.info("headless discovery failed for %s: %s", base_url, exc)
        return []

    seen: set[str] = set()

    def _add(path: str, methods: list[str], src: str, params: list[str], content_type: str = ""):
        key = f"{','.join(sorted(methods))} {path}"
        if key in seen or len(endpoints) >= _MAX_ENDPOINTS:
            return
        seen.add(key)
        endpoints.append(Endpoint(
            path=path, methods=methods, discovered_from=src,
            params=params, content_type=content_type,
        ))

    # XHR/fetch -> API endpoints (the real surface)
    for url, methods in xhr.items():
        if url.lower().endswith(_SKIP_SUFFIX):
            continue
        path, params = _path_and_params(url)
        _add(path, sorted(methods) or ["GET"], "xhr", params, content_type="application/json")

    # rendered links (same-origin, non-asset)
    for href in hrefs:
        if not _same_origin(href, base_netloc):
            continue
        if href.lower().split("?", 1)[0].endswith(_SKIP_SUFFIX):
            continue
        path, params = _path_and_params(href)
        _add(path, ["GET"], "headless", params)

    # rendered forms
    for f in forms:
        action = f.get("action") or base_url
        if not _same_origin(action, base_netloc):
            continue
        method = (f.get("method") or "GET").upper()
        path, qparams = _path_and_params(action)
        params = sorted(set(qparams) | set(f.get("inputs") or []))
        _add(path, [method], "form", params)

    logger.info("headless discovery on %s: %d endpoint(s) (%d from XHR/fetch)",
                base_url, len(endpoints), len(xhr))
    return endpoints
