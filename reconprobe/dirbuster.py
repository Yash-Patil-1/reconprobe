"""Directory and file brute-force module.

Multi-threaded discovery of web paths, directories, and files using wordlists.
Includes smart 404 detection to filter out false positives from custom error pages.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx


PATHS_WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "paths.txt"


@dataclass
class DirBusterResult:
    """Result from brute-forcing a single path."""
    url: str
    status_code: int = 0
    content_length: int = 0
    redirect_url: str = ""
    content_type: str = ""
    title: str = ""
    error: Optional[str] = None

    @property
    def is_interesting(self) -> bool:
        """Determine if the result is interesting (not a true 404/error)."""
        return (200 <= self.status_code < 400 and self.status_code not in (304,))

    @property
    def status_category(self) -> str:
        if 200 <= self.status_code < 300:
            return "success"
        elif 300 <= self.status_code < 400:
            return "redirect"
        elif 400 <= self.status_code < 500:
            if self.status_code == 403:
                return "forbidden"
            elif self.status_code == 401:
                return "unauthorized"
            return "client_error"
        elif 500 <= self.status_code < 600:
            return "server_error"
        return "unknown"


@dataclass
class DirBusterReport:
    """Aggregated directory brute-force report."""
    base_url: str
    hostname: str
    results: list[DirBusterResult] = field(default_factory=list)
    total_scanned: int = 0
    total_found: int = 0
    findings_by_type: dict[str, int] = field(default_factory=lambda: {
        "success": 0, "redirect": 0, "forbidden": 0, "unauthorized": 0, "server_error": 0,
    })

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "base_url": self.base_url,
            "total_scanned": self.total_scanned,
            "total_found": self.total_found,
            "findings_by_type": self.findings_by_type,
            "results": [
                {
                    "url": r.url,
                    "status_code": r.status_code,
                    "content_length": r.content_length,
                    "content_type": r.content_type,
                    "title": r.title,
                    "redirect_url": r.redirect_url,
                }
                for r in self.results
                if r.is_interesting
            ],
        }


# Built-in paths wordlist as fallback
BUILTIN_PATHS = [
    "admin", "login", "api", "config", "backup", ".git", ".env",
    "wp-admin", "wp-content", "wp-includes", "administrator",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "favicon.ico",
    "index.php", "index.html", "index.htm", "default.aspx",
    "phpinfo.php", "info.php", "test.php", "shell.php",
    "uploads", "downloads", "assets", "static", "public",
    "css", "js", "images", "img", "fonts",
    "dashboard", "panel", "cpanel", "whm",
    "search", "contact", "about", "blog", "news",
    "register", "signup", "signin", "forgot",
    "status", "health", "metrics", "monitor",
    "docs", "documentation", "swagger", "api-docs",
    "graphql", "rest", "soap", "xmlrpc.php",
    "server-status", "server-info",
    "database", "db", "sql", "mysql",
    "logs", "error_log", "access_log", "tmp", "temp",
    "vendor", "node_modules", "composer.json",
    "package.json", "Dockerfile", "Makefile",
    "README.md", "CHANGELOG.md", "LICENSE",
    ".htaccess", ".htpasswd",
    "sites/default/settings.php",
    "wp-config.php", "configuration.php",
    "web.config", "app.config",
]


def load_paths_wordlist(wordlist_path: Optional[str] = None) -> list[str]:
    """Load a wordlist file, falling back to bundled file then built-in list."""
    words: list[str] = []
    if wordlist_path and os.path.isfile(wordlist_path):
        with open(wordlist_path) as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    elif os.path.isfile(PATHS_WORDLIST_PATH):
        with open(PATHS_WORDLIST_PATH) as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not words:
        words = BUILTIN_PATHS
    return words


def get_baseline_404(
    base_url: str,
    client: httpx.Client,
    timeout: float = 5.0,
) -> tuple[int, Optional[str]]:
    """Get baseline 404 content length and a snippet for comparison."""
    import random
    import string
    random_path = "".join(random.choices(string.ascii_lowercase, k=16))
    test_url = base_url.rstrip("/") + "/" + random_path
    try:
        resp = client.get(
            test_url,
            timeout=timeout,
            follow_redirects=False,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
                ),
            },
        )
        return len(resp.text), resp.text[:500]  # Content length + first 500 chars snippet
    except Exception:
        return 0, None


def is_probably_404(
    resp: httpx.Response,
    baseline_length: int,
    baseline_snippet: Optional[str] = None,
    tolerance: float = 0.1,
) -> bool:
    """Determine if a response is probably a custom 404 page."""
    # Explicit 404 status
    if resp.status_code == 404:
        return True

    # Content length matches 404 baseline (within tolerance)
    content_length = len(resp.text)
    if baseline_length > 0:
        ratio = abs(content_length - baseline_length) / max(baseline_length, 1)
        if ratio < tolerance:
            return True

    # Page title indicates not found
    if "<title>404" in resp.text or "<title>Not Found" in resp.text:
        return True

    # Body content indicates not found
    body_lower = resp.text.lower()
    not_found_indicators = [
        "page not found", "file not found", "path not found",
        "resource not found", "nothing found", "does not exist",
        "no such file", "could not be located", "could not be found",
    ]
    for indicator in not_found_indicators:
        if indicator in body_lower:
            # But only if the content is short (custom 404 pages can be verbose)
            if content_length < 2000:
                return True

    return False


def scan_path_sync(
    base_url: str,
    path: str,
    timeout: float = 5.0,
    baseline_length: int = 0,
    baseline_snippet: Optional[str] = None,
    proxy_url: Optional[str] = None,
) -> Optional[DirBusterResult]:
    """Scan a single path against the base URL.

    Each call creates its own httpx.Client for thread safety.
    """
    # Normalize path
    path = path.strip()
    if path.startswith("/"):
        path = path[1:]

    url = base_url.rstrip("/") + "/" + path
    result = DirBusterResult(url=url)

    try:
        client_kwargs: dict = {
            "verify": False,
            "timeout": httpx.Timeout(timeout),
        }
        if proxy_url:
            client_kwargs["proxies"] = proxy_url

        with httpx.Client(**client_kwargs) as client:
            resp = client.get(
                url,
                timeout=timeout,
                follow_redirects=False,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )

            result.status_code = resp.status_code
            result.content_length = len(resp.text)
            result.content_type = resp.headers.get("content-type", "")

            # Check for redirect
            if 300 <= resp.status_code < 400:
                location = resp.headers.get("location", "")
                if location:
                    result.redirect_url = location

            # Extract title if HTML
            content_type = resp.headers.get("content-type", "").lower()
            if "text/html" in content_type or "application/xhtml" in content_type:
                import re
                match = re.search(rb"<title[^>]*>(.*?)</title>", resp.content, re.I | re.DOTALL)
                if match:
                    result.title = match.group(1).decode("utf-8", errors="replace").strip()[:200]

            # Filter out probable 404s
            if is_probably_404(resp, baseline_length, baseline_snippet):
                return None

            return result

    except (httpx.TimeoutException, httpx.ConnectError):
        return None
    except Exception:
        return None


def brute_force_paths(
    base_url: str,
    hostname: str,
    wordlist_path: Optional[str] = None,
    max_workers: int = 20,
    timeout: float = 5.0,
    extensions: Optional[list[str]] = None,
    delay: float = 0.0,
    proxy_url: Optional[str] = None,
) -> DirBusterReport:
    """Brute-force paths on a base URL using a wordlist.

    Uses smart 404 detection to filter false positives from custom error pages.
    """
    report = DirBusterReport(base_url=base_url, hostname=hostname)

    # Load wordlist
    paths = load_paths_wordlist(wordlist_path)

    # Add extension variants if specified
    if extensions:
        extended_paths = list(paths)
        for path in paths:
            for ext in extensions:
                if not path.endswith(ext):
                    extended_paths.append(path + ext)
        paths = extended_paths

    # Deduplicate
    paths = list(dict.fromkeys(paths))

    # Get baseline 404 for smart detection
    baseline_length = 0
    baseline_snippet: Optional[str] = None
    client_kwargs: dict = {
        "verify": False,
        "timeout": httpx.Timeout(timeout),
    }
    if proxy_url:
        client_kwargs["proxies"] = proxy_url
    with httpx.Client(**client_kwargs) as baseliner:
        baseline_length, baseline_snippet = get_baseline_404(base_url, baseliner, timeout)

    # Multi-threaded scanning
    # Each thread handles its own httpx.Client for thread safety
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                scan_path_sync, base_url, path, timeout,
                baseline_length, baseline_snippet, proxy_url,
            ): path
            for i, path in enumerate(paths)
        }

        for i, future in enumerate(as_completed(futures)):
            result = future.result()
            if result is not None:
                report.results.append(result)
                report.total_found += 1
                cat = result.status_category
                if cat in report.findings_by_type:
                    report.findings_by_type[cat] += 1
            # Rate limiting between batches (every 10 paths)
            if delay > 0 and i > 0 and i % 10 == 0:
                import time
                time.sleep(delay)

    report.total_scanned = len(paths)

    # Sort results by status code then URL
    report.results.sort(key=lambda r: (r.status_code, r.url))

    return report


def brute_force_hosts(
    host_urls: list[tuple[str, str]],
    wordlist_path: Optional[str] = None,
    max_workers: int = 20,
    timeout: float = 5.0,
    extensions: Optional[list[str]] = None,
    delay: float = 0.0,
    proxy_url: Optional[str] = None,
) -> dict[str, DirBusterReport]:
    """Brute-force paths on multiple hosts."""
    reports: dict[str, DirBusterReport] = {}
    for hostname, base_url in host_urls:
        try:
            report = brute_force_paths(
                base_url=base_url,
                hostname=hostname,
                wordlist_path=wordlist_path,
                max_workers=max_workers,
                timeout=timeout,
                extensions=extensions,
                delay=delay,
                proxy_url=proxy_url,
            )
            if report.total_found > 0:
                reports[hostname] = report
        except Exception:
            pass
    return reports
