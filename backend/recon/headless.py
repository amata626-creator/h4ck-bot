"""
Headless-browser discovery — a state-aware, authenticated SPA crawl.

Modern apps render client-side: the initial HTML is an empty shell and the real
content, links, and — crucially — the API calls appear only after JavaScript
runs, and only on the pages you actually navigate to. A single landing-page
render therefore misses almost the whole app.

This renders in real Chromium (Playwright) and performs a BOUNDED breadth-first
crawl over same-origin routes, reusing ONE browser context so the authenticated
session (and any cookies the app sets) persists from page to page — the fix for
"the scanner only ever sees the login screen". On every page it harvests:
  1. the links/forms present in the *rendered* DOM, and
  2. the XHR/fetch requests the app makes — i.e. the real API surface —
accumulated across the whole crawl.

Hard safety rules (this drives a browser against a live target):
  - Read-only navigation ONLY: page.goto (GET). Never submits a form, never
    clicks arbitrary controls, never issues a write.
  - Never follows logout/sign-out or delete/remove/destroy links — those would
    drop the authenticated session or change state.
  - Bounded: capped pages, depth, per-path visits, and an overall wall-clock
    budget, so it can never turn into an unbounded spider.
  - Best-effort: any failure returns what was found so far (or []), and the
    caller falls back to the regex crawl.
An auth session (extra_headers) is carried on the context so an authenticated
SPA renders — and keeps rendering — its real pages.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlparse, parse_qs

from recon.types import Endpoint

logger = logging.getLogger("h4ck-bot.recon.headless")

_NAV_TIMEOUT_MS = 12000
_SETTLE_MS = 1000          # grace for late XHR after networkidle
_MAX_ENDPOINTS = 300
_MAX_PAGES = 15            # how many distinct pages to render in one crawl
_MAX_DEPTH = 2             # link depth from the entry page
_PER_PATH_CAP = 1          # visits per normalized path (avoid 1000 product pages)
_CRAWL_BUDGET_S = 90.0     # overall wall-clock ceiling for the whole crawl

# Asset/resource requests that are not interesting as endpoints.
_SKIP_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
                ".css", ".woff", ".woff2", ".ttf", ".map")
# Links we must NOT navigate: they end the session or change state. Navigating
# a logout link mid-crawl would deauthenticate every subsequent page.
_SKIP_NAV_SUBSTR = ("logout", "log-out", "signout", "sign-out", "sign_out",
                    "logoff", "log-off", "/delete", "/remove", "/destroy",
                    "delete=", "remove=", "action=delete", "action=logout")


def _same_origin(url: str, base_netloc: str) -> bool:
    try:
        return urlparse(url).netloc == base_netloc
    except ValueError:
        return False


def _path_and_params(url: str) -> tuple[str, list[str]]:
    p = urlparse(url)
    return (p.path or "/"), sorted(parse_qs(p.query).keys())


def _norm_path(url: str) -> str:
    p = urlparse(url).path or "/"
    return p.rstrip("/") or "/"


def _is_skippable_nav(url: str) -> bool:
    low = url.lower()
    if low.split("?", 1)[0].endswith(_SKIP_SUFFIX):
        return True
    return any(s in low for s in _SKIP_NAV_SUBSTR)


async def _harvest(page):
    """Return (hrefs, forms) from the rendered DOM. Never raises."""
    try:
        hrefs = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
    except Exception:
        hrefs = []
    try:
        forms = await page.eval_on_selector_all(
            "form",
            "els => els.map(f => ({action: f.action, method: (f.method||'GET'), "
            "inputs: Array.from(f.querySelectorAll('[name]')).map(i => i.name)}))",
        )
    except Exception:
        forms = []
    return hrefs or [], forms or []


async def render_and_discover(
    base_url: str,
    extra_headers: dict | None = None,
    max_pages: int = _MAX_PAGES,
    max_depth: int = _MAX_DEPTH,
) -> list[Endpoint]:
    """Crawl base_url in headless Chromium (bounded BFS, one shared session) and
    return the endpoints found in the rendered DOM and the app's XHR/fetch
    traffic across all visited pages. Best-effort: returns what it has (or [])
    on failure."""
    try:
        from playwright.async_api import async_playwright, TimeoutError as PWTimeout
    except Exception as exc:  # noqa: BLE001
        logger.info("playwright unavailable, skipping headless discovery: %s", exc)
        return []

    base_netloc = urlparse(base_url).netloc
    xhr: dict[str, set[str]] = {}          # url -> methods (accumulated across all pages)
    hrefs_all: set[str] = set()
    forms_all: list[dict] = []

    def _on_request(req):
        try:
            if req.resource_type in ("xhr", "fetch") and _same_origin(req.url, base_netloc):
                xhr.setdefault(req.url, set()).add(req.method.upper())
        except Exception:
            pass

    visited: set[str] = set()
    path_counts: dict[str, int] = {}
    pages_rendered = 0
    deadline = time.monotonic() + _CRAWL_BUDGET_S

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                # ONE context + page for the whole crawl -> the session (auth
                # headers, cookies the app sets) persists across navigations.
                context = await browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=extra_headers or {},
                )
                page = await context.new_page()
                page.on("request", _on_request)

                queue: list[tuple[str, int]] = [(base_url, 0)]
                while queue and pages_rendered < max_pages:
                    if time.monotonic() > deadline:
                        logger.info("headless crawl hit time budget (%.0fs) on %s", _CRAWL_BUDGET_S, base_url)
                        break
                    url, depth = queue.pop(0)
                    url = url.split("#", 1)[0]
                    if url in visited:
                        continue
                    npath = _norm_path(url)
                    if path_counts.get(npath, 0) >= _PER_PATH_CAP:
                        continue
                    visited.add(url)
                    path_counts[npath] = path_counts.get(npath, 0) + 1

                    try:
                        await page.goto(url, timeout=_NAV_TIMEOUT_MS, wait_until="networkidle")
                    except PWTimeout:
                        try:
                            await page.goto(url, timeout=_NAV_TIMEOUT_MS, wait_until="load")
                        except Exception:
                            continue
                    except Exception:
                        continue
                    await page.wait_for_timeout(_SETTLE_MS)
                    pages_rendered += 1

                    hrefs, forms = await _harvest(page)
                    forms_all.extend(forms)
                    for href in hrefs:
                        if not _same_origin(href, base_netloc):
                            continue
                        hrefs_all.add(href)
                        nav = href.split("#", 1)[0]
                        # enqueue for deeper crawl unless it would end the session,
                        # change state, or we've gone deep enough
                        if (depth < max_depth and nav not in visited
                                and not _is_skippable_nav(nav)
                                and path_counts.get(_norm_path(nav), 0) < _PER_PATH_CAP):
                            queue.append((nav, depth + 1))
            finally:
                await browser.close()
    except Exception as exc:  # noqa: BLE001
        logger.info("headless discovery failed for %s: %s", base_url, exc)
        # fall through: we may still have harvested some endpoints before failure

    endpoints: list[Endpoint] = []
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

    # XHR/fetch -> API endpoints (the real surface), from every page crawled
    for url, methods in xhr.items():
        if url.lower().endswith(_SKIP_SUFFIX):
            continue
        path, params = _path_and_params(url)
        _add(path, sorted(methods) or ["GET"], "xhr", params, content_type="application/json")

    # rendered links (same-origin, non-asset)
    for href in hrefs_all:
        if href.lower().split("?", 1)[0].endswith(_SKIP_SUFFIX):
            continue
        path, params = _path_and_params(href)
        _add(path, ["GET"], "headless", params)

    # rendered forms
    for f in forms_all:
        action = f.get("action") or base_url
        if not _same_origin(action, base_netloc):
            continue
        method = (f.get("method") or "GET").upper()
        path, qparams = _path_and_params(action)
        params = sorted(set(qparams) | set(f.get("inputs") or []))
        _add(path, [method], "form", params)

    logger.info("headless crawl on %s: %d page(s) rendered, %d endpoint(s) (%d from XHR/fetch)",
                base_url, pages_rendered, len(endpoints), len(xhr))
    return endpoints
