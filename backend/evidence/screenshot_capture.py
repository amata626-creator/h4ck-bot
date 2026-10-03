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
from dataclasses import dataclass
from typing import Optional

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger("h4ck-bot.screenshot")

NAV_TIMEOUT_MS = 15000
SCHEMES_TO_TRY = ("https://", "http://")


@dataclass
class ScreenshotResult:
    url_captured: str
    png_bytes: bytes
    page_title: str
    http_status: Optional[int]


async def capture_screenshot(hostname_or_url: str) -> Optional[ScreenshotResult]:
    """
    Navigate to hostname_or_url with headless Chromium and return a
    full-page PNG. If hostname_or_url has no scheme, tries https then
    http. Returns None if neither scheme was reachable within the
    timeout - this is an expected, non-exceptional outcome for
    non-web assets (e.g. a bare TCP host) and is handled as such by
    callers, never raised up as an error.
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
