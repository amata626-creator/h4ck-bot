"""
Real screenshot evidence capture via headless Chromium (Playwright).

This navigates to the target the way a browser would and records what
actually rendered at scan time - it does not perform exploitation,
injection, or credential use, and it does not fabricate an image when
the target can't be reached: callers get None and treat that as "no
screenshot evidence available for this asset".
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger("h4ck-bot.screenshot")

NAV_TIMEOUT_MS = 15000
SCHEMES_TO_TRY = ("https://", "http://")

# The URL a finding is about is recorded in its evidence as "GET <url>"
# (web/red-team) or "matched-at: <url>" (Nuclei).
_URL_RES = (
    re.compile(r"GET\s+(https?://\S+)"),
    re.compile(r"matched-at:\s*(https?://\S+)"),
)
_MAX_SCREENSHOT_URLS = 25   # bound per assessment


@dataclass
class ScreenshotResult:
    url_captured: str
    png_bytes: bytes
    page_title: str
    http_status: Optional[int]


async def capture_screenshot(
    hostname_or_url: str,
    extra_headers: Optional[dict] = None,
) -> Optional[ScreenshotResult]:
    """
    Navigate to hostname_or_url with headless Chromium and return a
    full-page PNG. If hostname_or_url has no scheme, tries https then
    http. Returns None if neither scheme was reachable within the
    timeout - this is an expected, non-exceptional outcome for
    non-web assets (e.g. a bare TCP host) and is handled as such by
    callers, never raised up as an error.

    `extra_headers` (e.g. {"Cookie": "JSESSIONID=…"}) are sent on every
    request, so an authenticated assessment captures the page behind the
    login rather than the login screen. This records what the session the
    operator supplied already sees; it performs no login of its own.
    """
    candidates = (
        [hostname_or_url]
        if "://" in hostname_or_url
        else [f"{scheme}{hostname_or_url}" for scheme in SCHEMES_TO_TRY]
    )

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context = await browser.new_context(
                viewport={"width": 1440, "height": 900},
                ignore_https_errors=True,  # recording evidence, not validating the cert chain
                extra_http_headers=extra_headers or {},
            )
            page = await context.new_page()

            for url in candidates:
                try:
                    response = await page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="load")
                    png_bytes = await page.screenshot(full_page=True)
                    title = await page.title()
                    logger.info(f"screenshot captured: {url} -> {len(png_bytes)} bytes")
                    return ScreenshotResult(
                        url_captured=url,
                        png_bytes=png_bytes,
                        page_title=title,
                        http_status=response.status if response else None,
                    )
                except PlaywrightTimeoutError:
                    logger.warning(f"screenshot navigation timed out: {url}")
                    continue
                except Exception as e:
                    logger.warning(f"screenshot navigation failed: {url} - {e}")
                    continue

            return None
        finally:
            await browser.close()


def _auth_headers(auth: Optional[dict]) -> dict:
    """Turn an auth session ({"cookie": str, "headers": dict}) into request
    headers for the screenshot browser, so authenticated pages render instead
    of redirecting to a login screen."""
    auth = auth or {}
    headers: dict = {}
    for k, v in (auth.get("headers") or {}).items():
        headers[str(k)] = str(v)
    if auth.get("cookie"):
        headers["Cookie"] = str(auth["cookie"])
    return headers


def _finding_url(finding) -> Optional[str]:
    """The specific URL a finding is about, read from its evidence. Falls back
    to the asset host (so capture_screenshot can try schemes) only when no
    evidence records a URL."""
    for e in finding.evidence:
        preview = (e.metadata or {}).get("preview") or e.description or ""
        for rx in _URL_RES:
            m = rx.search(preview)
            if m:
                return m.group(1)
    name = getattr(finding.asset, "name", "")
    # A bare host is fine (schemes are tried); a non-URL asset (mobile) is not.
    if name and "://" not in name and getattr(finding.asset, "asset_type", "") in ("host", "web_app", "api"):
        return name
    return None


async def screenshot_findings(findings, assessment_id, auth=None, log=None) -> None:
    """Capture a screenshot of each finding's OWN url (deduped), carrying the
    session when one was supplied, and attach it to the finding(s) at that url.

    This is the fix for 'the screenshot only shows the login screen': instead
    of one host-root capture stapled onto everything, each finding gets the
    page where it was actually observed — a reflected-XSS finding shows the
    reflected inert marker, an authenticated finding shows the page behind the
    login. Best-effort and non-destructive: navigation only, no exploitation;
    an unreachable url simply yields no screenshot.
    """
    from core.schema import Evidence, EvidenceType
    from evidence.evidence_store import save_evidence_bytes

    def _log(msg):
        (log or logger.info)(msg)

    headers = _auth_headers(auth)

    # group findings by their target url (dedupe captures)
    by_url: dict[str, list] = {}
    for f in findings:
        url = _finding_url(f)
        if not url:
            continue
        by_url.setdefault(url, []).append(f)

    for url in list(by_url)[:_MAX_SCREENSHOT_URLS]:
        result = await capture_screenshot(url, extra_headers=headers or None)
        if result is None:
            _log(f"screenshot skipped for {url} - not reachable")
            continue
        storage_ref = save_evidence_bytes(
            assessment_id=assessment_id,
            subject_id=f"url__{abs(hash(url))}",
            filename="screenshot.png",
            raw_bytes=result.png_bytes,
        )
        authed = " (authenticated session)" if headers else ""
        for f in by_url[url]:
            f.evidence.append(Evidence.new(
                evidence_type=EvidenceType.SCREENSHOT,
                raw_bytes=result.png_bytes,
                storage_ref=storage_ref,
                description=(
                    f'Full-page screenshot of {result.url_captured} '
                    f'(HTTP {result.http_status}, title: "{result.page_title}"){authed}, '
                    "captured at assessment time."
                ),
                metadata={
                    "url_captured": result.url_captured,
                    "http_status": result.http_status,
                    "page_title": result.page_title,
                    "authenticated": bool(headers),
                },
            ))
        _log(f"screenshot captured for {url} -> {storage_ref} "
             f"(attached to {len(by_url[url])} finding(s)){authed}")
