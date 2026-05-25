"""Screenshot capture module.

Uses Playwright to take screenshots of web services for visual reconnaissance.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from reconprobe.http_probe import HttpProbeResult


@dataclass
class ScreenshotResult:
    """Result of a screenshot capture."""
    url: str
    file_path: Optional[str] = None
    success: bool = False
    error: Optional[str] = None


@dataclass
class ScreenshotReport:
    """Aggregated screenshot report."""
    hostname: str
    screenshots: list[ScreenshotResult] = field(default_factory=list)
    total_taken: int = 0
    total_failed: int = 0

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "total_taken": self.total_taken,
            "total_failed": self.total_failed,
            "screenshots": [
                {
                    "url": s.url,
                    "file_path": s.file_path,
                    "success": s.success,
                    "error": s.error,
                }
                for s in self.screenshots
            ],
        }


def _take_screenshot_sync(
    url: str,
    file_path: Path,
    timeout: float = 30.0,
    full_page: bool = False,
    width: int = 1280,
    height: int = 720,
) -> ScreenshotResult:
    """Take a screenshot using Playwright's sync API (runs in a thread)."""
    result = ScreenshotResult(url=url)
    try:
        import playwright.sync_api

        with playwright.sync_api.sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            context = browser.new_context(
                viewport={"width": width, "height": height},
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )
            page = context.new_page()
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
                # Brief wait for async content to render
                page.wait_for_timeout(2000)
                page.screenshot(
                    path=str(file_path),
                    full_page=full_page,
                    type="png",
                )
                result.success = True
                result.file_path = str(file_path)
            except BaseException as e:
                result.error = f"screenshot failed: {e}"
                if file_path.exists():
                    result.file_path = str(file_path)
            finally:
                context.close()
                browser.close()
    except ImportError:
        result.error = "playwright not installed (pip install playwright)"
    except Exception as e:
        result.error = f"playwright error: {e}"
    return result


async def capture_screenshot(
    url: str,
    output_dir: Path,
    filename: str,
    timeout: float = 30.0,
    full_page: bool = False,
    width: int = 1280,
    height: int = 720,
) -> ScreenshotResult:
    """Capture a screenshot of a URL using Playwright.

    Runs Playwright's sync API in a thread executor to avoid blocking the event loop.
    """
    file_path = output_dir / filename
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        _take_screenshot_sync,
        url,
        file_path,
        timeout,
        full_page,
        width,
        height,
    )


async def capture_host_screenshots(
    hostname: str,
    probe_results: list[HttpProbeResult],
    output_dir: Path,
    timeout: float = 30.0,
    max_concurrent: int = 3,
) -> ScreenshotReport:
    """Capture screenshots for all alive HTTP services on a host."""
    report = ScreenshotReport(hostname=hostname)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Only screenshot alive services
    alive_urls = [r.url for r in probe_results if r.is_alive and not r.error]

    # Limit concurrent screenshots
    semaphore = asyncio.Semaphore(max_concurrent)

    async def capture_with_limit(url: str, idx: int) -> ScreenshotResult:
        async with semaphore:
            domain_safe = hostname.replace(".", "_").replace(":", "_")
            filename = f"screenshot_{domain_safe}_{idx}.png"
            return await capture_screenshot(url, output_dir, filename, timeout)

    tasks = [
        capture_with_limit(url, i) for i, url in enumerate(alive_urls)
    ]

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, ScreenshotResult):
                report.screenshots.append(r)
                if r.success:
                    report.total_taken += 1
                else:
                    report.total_failed += 1

    return report


async def capture_all_screenshots(
    host_reports: list[tuple[str, list[HttpProbeResult]]],
    output_dir: Path,
    timeout: float = 30.0,
) -> list[ScreenshotReport]:
    """Capture screenshots for multiple hosts."""
    screenshot_reports: list[ScreenshotReport] = []
    for hostname, probe_results in host_reports:
        sr = await capture_host_screenshots(
            hostname, probe_results, output_dir / "screenshots", timeout,
        )
        screenshot_reports.append(sr)
    return screenshot_reports
