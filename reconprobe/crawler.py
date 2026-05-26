"""Web crawling module.

Discovers URLs, endpoints, JavaScript files, forms, and other resources
by crawling discovered HTTP services. Respects scope, depth limits, and rate limiting.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup



@dataclass
class CrawledPage:
    """Result from crawling a single page."""
    url: str
    status_code: int = 0
    content_type: str = ""
    title: str = ""
    depth: int = 0
    links: list[str] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    hidden_endpoints: list[str] = field(default_factory=list)
    interesting_findings: list[dict] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 400 and self.status_code != 0


@dataclass
class CrawlReport:
    """Aggregated crawl report for a host."""
    hostname: str
    base_url: str
    pages: list[CrawledPage] = field(default_factory=list)
    total_pages: int = 0
    total_links: int = 0
    total_scripts: int = 0
    total_forms: int = 0
    unique_urls: list[str] = field(default_factory=list)
    interesting_findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "base_url": self.base_url,
            "total_pages": self.total_pages,
            "total_links": self.total_links,
            "total_scripts": self.total_scripts,
            "total_forms": self.total_forms,
            "unique_urls": self.unique_urls[:200],  # Cap at 200
            "pages": [
                {
                    "url": p.url,
                    "status_code": p.status_code,
                    "content_type": p.content_type,
                    "title": p.title,
                    "depth": p.depth,
                    "links_found": len(p.links),
                    "scripts_found": len(p.scripts),
                    "forms_found": len(p.forms),
                    "error": p.error,
                }
                for p in self.pages
            ],
            "interesting_findings": self.interesting_findings[:50],
        }


# Patterns for detecting API endpoints, admin panels, and sensitive paths
API_PATTERNS = [
    re.compile(r"/api/", re.I),
    re.compile(r"/v\d+/", re.I),
    re.compile(r"/rest/", re.I),
    re.compile(r"/graphql", re.I),
    re.compile(r"/swagger", re.I),
    re.compile(r"/\.json", re.I),
    re.compile(r"/xmlrpc", re.I),
]

SENSITIVE_PATTERNS = [
    re.compile(r"/admin", re.I),
    re.compile(r"/login", re.I),
    re.compile(r"/register", re.I),
    re.compile(r"/reset", re.I),
    re.compile(r"/config", re.I),
    re.compile(r"/backup", re.I),
    re.compile(r"/dump", re.I),
    re.compile(r"/\.git", re.I),
    re.compile(r"/\.env", re.I),
    re.compile(r"/dashboard", re.I),
    re.compile(r"/cpanel", re.I),
    re.compile(r"/phpmyadmin", re.I),
    re.compile(r"/debug", re.I),
    re.compile(r"/test", re.I),
    re.compile(r"/shell", re.I),
    re.compile(r"/cmd", re.I),
    re.compile(r"/exec", re.I),
]

NON_HTML_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
    ".mp4", ".mp3", ".avi", ".mov",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".woff", ".woff2", ".ttf", ".eot",
}


def normalize_url(base: str, href: str) -> Optional[str]:
    """Normalize a potentially relative URL to an absolute URL."""
    if not href or href.startswith("#") or href.startswith("javascript:"):
        return None
    try:
        absolute = urljoin(base, href)
        parsed = urlparse(absolute)
        # Only http/https
        if parsed.scheme not in ("http", "https"):
            return None
        # Remove fragments
        clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))
        # Remove trailing slash for consistency (except for root)
        if len(clean) > 1 and clean.endswith("/"):
            clean = clean.rstrip("/")
        return clean
    except (ValueError, Exception):
        return None


def get_domain(url: str) -> str:
    """Extract the domain (hostname) from a URL."""
    return urlparse(url).hostname or ""


def is_same_domain(url: str, domain: str) -> bool:
    """Check if a URL belongs to the same domain."""
    url_domain = get_domain(url)
    return url_domain == domain or url_domain.endswith("." + domain)


def extract_interesting_findings(url: str, body: str, depth: int) -> list[dict]:
    """Extract interesting findings from a page (API endpoints, admin panels, etc.)."""
    findings: list[dict] = []

    # Check URL against sensitive patterns
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(url):
            findings.append({
                "type": "sensitive_url",
                "url": url,
                "detail": f"Matched pattern: {pattern.pattern}",
                "depth": depth,
            })
            break

    # Check URL against API patterns
    for pattern in API_PATTERNS:
        if pattern.search(url):
            findings.append({
                "type": "api_endpoint",
                "url": url,
                "detail": f"Matched pattern: {pattern.pattern}",
                "depth": depth,
            })
            break

    # Look for email addresses in the page
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body)
    for email in set(emails):
        if not email.endswith(".png") and not email.endswith(".jpg") and not email.endswith(".gif"):
            findings.append({
                "type": "email_address",
                "url": url,
                "detail": email,
                "depth": depth,
            })

    # Look for comments with TODO/FIXME/HACK
    comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
    for comment in comments:
        for keyword in ["TODO", "FIXME", "HACK", "XXX", "BUG", "NOTE"]:
            if keyword in comment.upper():
                findings.append({
                    "type": "code_comment",
                    "url": url,
                    "detail": f"{keyword}: {comment.strip()[:200]}",
                    "depth": depth,
                })
                break

    # Limit findings per page
    return findings[:20]


async def crawl_page(
    url: str,
    client: httpx.AsyncClient,
    target_domain: str,
    depth: int,
    max_depth: int,
    seen_urls: set[str],
    timeout: float = 10.0,
    max_pages: int = 100,
) -> tuple[CrawledPage, list[str]]:
    """Crawl a single page and return the result plus discovered URLs to visit."""
    page = CrawledPage(url=url, depth=depth)
    discovered: list[str] = []

    if len(seen_urls) >= max_pages:
        page.error = "max pages reached"
        return page, discovered

    if url in seen_urls:
        page.error = "duplicate"
        return page, discovered

    seen_urls.add(url)

    try:
        resp = await client.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )

        page.status_code = resp.status_code
        page.content_type = resp.headers.get("content-type", "")

        # Only parse HTML responses
        content_type = resp.headers.get("content-type", "").lower()
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            page.error = "not html"
            return page, discovered

        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract title
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            page.title = title_tag.string.strip()[:200]

        # Extract all links
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            href_str = str(href)
            normalized = normalize_url(url, href_str)
            if normalized:
                if is_same_domain(normalized, target_domain):
                    if normalized not in seen_urls:
                        # Check if the path has a non-HTML extension
                        parsed = urlparse(normalized)
                        ext = parsed.path.split(".")[-1] if "." in parsed.path else ""
                        if ext.lower() not in {e.lstrip(".") for e in NON_HTML_EXTENSIONS}:
                            page.links.append(normalized)
                            if depth < max_depth:
                                discovered.append(normalized)
                else:
                    page.external_links.append(normalized)

        # Extract scripts
        for script_tag in soup.find_all("script", src=True):
            src_str = str(script_tag["src"])
            normalized = normalize_url(url, src_str)
            if normalized:
                page.scripts.append(normalized)

        # Extract forms
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            method = str(form_tag.get("method", "GET")).upper()
            form_url = normalize_url(url, str(action)) or url
            inputs = []
            for input_tag in form_tag.find_all("input"):
                input_name = input_tag.get("name", "")
                input_type = input_tag.get("type", "text")
                if input_name:
                    inputs.append({"name": input_name, "type": input_type})
            page.forms.append({
                "action": form_url,
                "method": method,
                "inputs": inputs,
            })

        # Extract inline JS content for endpoint discovery
        for script_tag in soup.find_all("script"):
            if script_tag.string:
                # Look for URL patterns in inline JS
                js_urls = re.findall(r'["\'](/[^\s"\'<>?]+)["\']', script_tag.string)
                for js_url in js_urls:
                    if js_url.startswith("/") and len(js_url) > 1:
                        full_url = normalize_url(url, js_url)
                        if full_url and full_url not in seen_urls:
                            page.api_endpoints.append(full_url)

        # Extract hidden inputs
        for hidden in soup.find_all("input", type="hidden"):
            name = hidden.get("name", "")
            value = hidden.get("value", "")
            if name and value:
                page.hidden_endpoints.append(f"{name}={value}")

        # Extract interesting findings
        page.interesting_findings = extract_interesting_findings(url, resp.text, depth)

    except httpx.TimeoutException:
        page.error = "timeout"
    except httpx.ConnectError:
        page.error = "connection refused"
    except httpx.HTTPError as e:
        page.error = f"http error: {e}"
    except Exception as e:
        page.error = f"error: {e}"

    # Limit discovered URLs to prevent explosion
    if len(discovered) > 50:
        discovered = discovered[:50]

    return page, discovered


async def crawl_host(
    base_url: str,
    hostname: str,
    max_depth: int = 2,
    max_pages: int = 50,
    delay: float = 0.1,
    timeout: float = 10.0,
    proxy_url: Optional[str] = None,
) -> CrawlReport:
    """Crawl a host starting from a base URL.

    Args:
        base_url: Starting URL to crawl.
        hostname: Hostname for reporting.
        max_depth: Maximum crawl depth.
        max_pages: Maximum pages to crawl.
        delay: Seconds to wait between requests.
        timeout: Request timeout in seconds.
        proxy_url: Optional proxy URL for routing traffic.
    """
    report = CrawlReport(hostname=hostname, base_url=base_url)
    seen_urls: set[str] = set()
    all_pages: list[CrawledPage] = []
    url_queue: list[tuple[str, int]] = [(base_url, 0)]

    # Deduplicate queue
    seen_queue: set[str] = {base_url}
    target_domain = get_domain(base_url)

    client_kwargs: dict = {
        "verify": False,
        "timeout": httpx.Timeout(timeout),
        "limits": httpx.Limits(max_connections=10, max_keepalive_connections=5),
    }
    if proxy_url:
        client_kwargs["proxies"] = proxy_url

    async with httpx.AsyncClient(**client_kwargs) as client:
        while url_queue and len(all_pages) < max_pages:
            current_url, current_depth = url_queue.pop(0)

            page, discovered = await crawl_page(
                current_url,
                client,
                target_domain,
                current_depth,
                max_depth,
                seen_urls,
                timeout=timeout,
                max_pages=max_pages,
            )

            all_pages.append(page)

            # Add discovered URLs to queue (BFS)
            for url in discovered:
                if url not in seen_queue and len(all_pages) + len(url_queue) < max_pages:
                    url_queue.append((url, current_depth + 1))
                    seen_queue.add(url)

            # Rate limiting delay
            if delay > 0 and url_queue:
                await asyncio.sleep(delay)

    # Build report
    report.pages = all_pages
    report.total_pages = len(all_pages)
    report.unique_urls = sorted(seen_urls)

    # Aggregate statistics
    for page in all_pages:
        if page.is_success:
            report.total_links += len(page.links)
            report.total_scripts += len(page.scripts)
            report.total_forms += len(page.forms)

    # Collect all interesting findings
    all_findings: list[dict] = []
    seen_findings: set[str] = set()
    for page in all_pages:
        for finding in page.interesting_findings:
            key = f"{finding['type']}:{finding['detail']}"
            if key not in seen_findings:
                seen_findings.add(key)
                all_findings.append(finding)
    report.interesting_findings = all_findings

    return report


async def crawl_hosts(
    host_urls: list[tuple[str, str, list[int]]],
    max_depth: int = 2,
    max_pages_per_host: int = 50,
    delay: float = 0.1,
    timeout: float = 10.0,
    proxy_url: Optional[str] = None,
) -> dict[str, CrawlReport]:
    """Crawl multiple hosts, returning a dict of hostname -> CrawlReport."""
    reports: dict[str, CrawlReport] = {}
    for hostname, base_url, _ports in host_urls:
        try:
            report = await crawl_host(
                base_url=base_url,
                hostname=hostname,
                max_depth=max_depth,
                max_pages=max_pages_per_host,
                delay=delay,
                timeout=timeout,
                proxy_url=proxy_url,
            )
            if report.total_pages > 0:
                reports[hostname] = report
        except Exception:
            pass  # Skip hosts that fail to crawl
    return reports
