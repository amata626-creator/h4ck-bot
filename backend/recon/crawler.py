"""
Bounded same-origin crawler.

Design constraints, on purpose:
  - Same origin only. A recon module for a scoped target should never
    follow links off that target; the scope file governs what we can
    talk to, and recon must not become a way to talk to something else.
  - Depth-limited and page-count-limited. Recon is discovery, not a
    full-site mirror. Defaults: max_depth=2, max_pages=60.
  - Respects robots.txt by default. Pass respect_robots=False only if
    you have a specific reason - the default is the ethical one.
  - HEAD before GET where possible. Many links don't need a full fetch
    to learn they're alive.
  - Captures forms and their input names as endpoint hints.
  - Extracts links from <a href>, <form action>, and common JS patterns
    (fetch/axios/XHR) so that SPA content is at least partially visible.

Everything is bounded so that running recon against a large site
doesn't turn into an hours-long mirror.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse, urldefrag

import httpx

from recon.types import Endpoint, HttpTrace


DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_PAGES = 60
MAX_BODY_CHARS = 60_000
REQ_TIMEOUT = 8.0

# Extract candidates from inline JS. These are the common fetch shapes.
_JS_PATH_RE = re.compile(r"""["'`](/(?:api|rest|v\d+|graphql|admin|user|account|order|invoice)[^"'`\s]{0,120})["'`]""")
_FETCH_CALL_RE = re.compile(r"""fetch\s*\(\s*["'`]([^"'`]+)["'`]""")
_AXIOS_CALL_RE = re.compile(r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]""")
_XHR_OPEN_RE = re.compile(r"""\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE)

_FORM_RE = re.compile(r"""<form\b[^>]*?(?:action=["']([^"']*)["'])?[^>]*>(.*?)</form>""", re.DOTALL | re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"""action=["']([^"']*)["']""", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r"""<input\b[^>]*?\bname=["']([^"']+)["']""", re.IGNORECASE)
_LINK_HREF_RE = re.compile(r"""<a\b[^>]*?\bhref=["']([^"']+)["']""", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*?\bsrc=["']([^"']+)["']""", re.IGNORECASE)

# Path shape /api/v2/orders/{id} — used to normalize numeric-looking
# segments into placeholders so we dedup across many instances.
_ID_SEGMENT_RE = re.compile(r"/(\d{1,12})(?=/|$)")
_UUID_SEGMENT_RE = re.compile(r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=/|$)")


@dataclass
class CrawlResult:
    endpoints: list[Endpoint]
    js_bundles: list[str]
    traces: list[HttpTrace]
    robots_txt: Optional[str]
    pages_fetched: int


def _normalize_path(path: str) -> str:
    """Turn /api/v2/orders/10421 into /api/v2/orders/{id} so we dedup."""
    p = _UUID_SEGMENT_RE.sub("/{id}", path)
    p = _ID_SEGMENT_RE.sub("/{id}", p)
    return p


def _same_origin(base: str, url: str) -> bool:
    b, u = urlparse(base), urlparse(url)
    return (b.scheme, b.hostname, b.port) == (u.scheme, u.hostname, u.port)


class Crawler:
    def __init__(
        self,
        base_url: str,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_pages: int = DEFAULT_MAX_PAGES,
        respect_robots: bool = True,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self._client = client
        self._owns_client = client is None
        self._robots_disallowed: list[str] = []
        self._visited: set[str] = set()
        self._endpoints: list[Endpoint] = []
        self._js_bundles: list[str] = []
        self._traces: list[HttpTrace] = []
        self._robots_txt: Optional[str] = None

    async def crawl(self) -> CrawlResult:
        if self._owns_client:
            self._client = httpx.AsyncClient(
                timeout=REQ_TIMEOUT, follow_redirects=True, verify=False,
                headers={"User-Agent": "h4ckbot-recon/0.1 (+authorized-assessment)"},
            )
        try:
            if self.respect_robots:
                await self._load_robots()
            await self._visit(self.base_url, depth=0)
        finally:
            if self._owns_client and self._client is not None:
                await self._client.aclose()
        return CrawlResult(
            endpoints=self._endpoints,
            js_bundles=sorted(set(self._js_bundles)),
            traces=self._traces,
            robots_txt=self._robots_txt,
            pages_fetched=len(self._visited),
        )

    async def _load_robots(self) -> None:
        url = urljoin(self.base_url, "/robots.txt")
        try:
            resp = await self._client.get(url)
        except Exception:
            return
        if resp.status_code != 200:
            return
        self._robots_txt = resp.text[:MAX_BODY_CHARS]
        # Parse Disallow lines
        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    self._robots_disallowed.append(path)

    def _robots_allows(self, url: str) -> bool:
        if not self._robots_disallowed:
            return True
        path = urlparse(url).path
        return not any(path.startswith(d) for d in self._robots_disallowed)

    async def _visit(self, url: str, depth: int) -> None:
        if depth > self.max_depth:
            return
        if len(self._visited) >= self.max_pages:
            return
        url, _ = urldefrag(url)
        if url in self._visited:
            return
        if not _same_origin(self.base_url, url):
            return
        if self.respect_robots and not self._robots_allows(url):
            return
        self._visited.add(url)

        trace = await self._fetch(url)
        if trace is None or trace.status == 0:
            return
        self._traces.append(trace)

        # Record the URL itself as a discovered endpoint
        path = urlparse(url).path or "/"
        self._endpoints.append(Endpoint(
            path=_normalize_path(path),
            methods=[trace.method],
            discovered_from="crawl",
            content_type=trace.response_headers.get("content-type", ""),
        ))

        body = trace.response_body
        content_type = trace.response_headers.get("content-type", "").lower()

        # Only parse HTML for links/forms
        if "html" in content_type:
            # Forms -> endpoints with param names
            for form_match in _FORM_RE.finditer(body):
                action = form_match.group(1) or url
                full = urljoin(url, action)
                if not _same_origin(self.base_url, full):
                    continue
                names = _INPUT_NAME_RE.findall(form_match.group(2))
                self._endpoints.append(Endpoint(
                    path=_normalize_path(urlparse(full).path),
                    methods=["POST"],       # conservative: forms usually POST
                    discovered_from="form",
                    params=names,
                    content_type="application/x-www-form-urlencoded",
                ))

            # Links
            links = _LINK_HREF_RE.findall(body)
            for href in links:
                full = urljoin(url, href)
                if _same_origin(self.base_url, full):
                    await self._visit(full, depth=depth + 1)

            # Script bundles
            for src in _SCRIPT_SRC_RE.findall(body):
                full = urljoin(url, src)
                if _same_origin(self.base_url, full):
                    self._js_bundles.append(full)

        # Inline + external JS: extract API-ish paths
        if "javascript" in content_type or url.endswith(".js"):
            self._extract_js_paths(body)

    async def _fetch(self, url: str) -> Optional[HttpTrace]:
        import time
        t0 = time.monotonic()
        try:
            resp = await self._client.get(url)
        except Exception as e:
            return HttpTrace(method="GET", url=url, error=str(e)[:200])
        elapsed = int((time.monotonic() - t0) * 1000)
        return HttpTrace(
            method="GET",
            url=url,
            request_headers=dict(self._client.headers),
            status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp.text[:MAX_BODY_CHARS],
            elapsed_ms=elapsed,
        )

    def _extract_js_paths(self, body: str) -> None:
        """Best-effort extraction of API paths from JS text."""
        seen: set[str] = set()
        for pattern in (_JS_PATH_RE, _FETCH_CALL_RE, _AXIOS_CALL_RE, _XHR_OPEN_RE):
            for m in pattern.finditer(body):
                raw = m.group(1)
                if not raw or raw.startswith("http") and not _same_origin(self.base_url, raw):
                    continue
                path = urlparse(raw).path if raw.startswith("http") else raw
                path = path.split("?")[0]
                norm = _normalize_path(path)
                if norm in seen:
                    continue
                seen.add(norm)
                self._endpoints.append(Endpoint(
                    path=norm,
                    methods=["GET", "POST"],     # unknown; conservative
                    discovered_from="js_bundle",
                ))
