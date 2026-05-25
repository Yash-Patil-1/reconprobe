"""HTTP probing module.

Probes discovered web services for:
- HTTP status codes
- Page titles
- Technology fingerprinting (server, CMS, frameworks, CDN, analytics)
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional

import httpx


@dataclass
class TechSignature:
    """A technology fingerprint pattern."""
    name: str
    category: str
    header_patterns: Optional[dict[str, re.Pattern]] = None
    body_patterns: Optional[list[re.Pattern]] = None
    url_patterns: Optional[list[re.Pattern]] = None
    meta_patterns: Optional[dict[str, re.Pattern]] = None
    script_patterns: Optional[list[re.Pattern]] = None
    confidence: int = 100  # 0-100


@dataclass
class HttpProbeResult:
    """Result from probing a single HTTP service."""
    url: str
    status_code: int = 0
    title: str = ""
    server_header: str = ""
    content_type: str = ""
    technologies: list[dict] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def is_alive(self) -> bool:
        return 200 <= self.status_code < 500 and self.status_code != 0


@dataclass
class HttpProbeReport:
    """Aggregated HTTP probing report."""
    hostname: str
    results: list[HttpProbeResult] = field(default_factory=list)
    alive_count: int = 0

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "alive_count": self.alive_count,
            "results": [
                {
                    "url": r.url,
                    "status_code": r.status_code,
                    "title": r.title,
                    "server": r.server_header,
                    "content_type": r.content_type,
                    "technologies": r.technologies,
                    "error": r.error,
                }
                for r in self.results
            ],
        }


# Technology fingerprint database
# Patterns matched against response headers, HTML body, meta tags, and scripts
TECH_SIGNATURES: list[TechSignature] = [
    # === Web Servers ===
    TechSignature("nginx", "Web Server", header_patterns={"server": re.compile(r"nginx", re.I)}),
    TechSignature("Apache HTTP Server", "Web Server", header_patterns={"server": re.compile(r"Apache", re.I)}),
    TechSignature("IIS", "Web Server", header_patterns={"server": re.compile(r"IIS", re.I)}, confidence=90),
    TechSignature("Cloudflare", "CDN", header_patterns={"server": re.compile(r"cloudflare", re.I)}),
    TechSignature("Cloudflare", "CDN", header_patterns={"cf-ray": re.compile(r".+")}),
    TechSignature("Akamai", "CDN", header_patterns={"server": re.compile(r"Akamai", re.I)}),
    TechSignature("Fastly", "CDN", header_patterns={"server": re.compile(r"fastly", re.I)}),
    TechSignature("Amazon S3", "Cloud Storage", header_patterns={"server": re.compile(r"AmazonS3", re.I)}),
    TechSignature("Caddy", "Web Server", header_patterns={"server": re.compile(r"Caddy", re.I)}),
    TechSignature("Tomcat", "Application Server", header_patterns={"server": re.compile(r"Tomcat", re.I)}),

    # === CMS ===
    TechSignature("WordPress", "CMS",
        meta_patterns={"generator": re.compile(r"WordPress", re.I)},
        body_patterns=[re.compile(r"/wp-content/", re.I), re.compile(r"/wp-includes/", re.I)],
        script_patterns=[re.compile(r"wp-embed")],
    ),
    TechSignature("Drupal", "CMS",
        meta_patterns={"generator": re.compile(r"Drupal", re.I)},
        body_patterns=[re.compile(r"drupal\.js", re.I), re.compile(r"/sites/default/", re.I)],
    ),
    TechSignature("Joomla", "CMS",
        meta_patterns={"generator": re.compile(r"Joomla", re.I)},
        body_patterns=[re.compile(r"/components/", re.I), re.compile(r"/modules/", re.I)],
    ),
    TechSignature("Shopify", "Ecommerce",
        header_patterns={"x-shopid": re.compile(r".+")},
        body_patterns=[re.compile(r"Shopify\.sdk", re.I), re.compile(r"cdn\.shopify\.com", re.I)],
    ),
    TechSignature("Squarespace", "CMS",
        body_patterns=[re.compile(r"\.squarespace\.com/", re.I),
                       re.compile(r"<!-- This is Squarespace -->", re.I)],
    ),
    TechSignature("Wix", "CMS",
        body_patterns=[re.compile(r"Wix\.com", re.I), re.compile(r"wix\.com", re.I)],
    ),

    # === JavaScript Frameworks ===
    TechSignature("React", "JavaScript Framework",
        body_patterns=[re.compile(r"react\.js", re.I), re.compile(r"react-dom", re.I),
                       re.compile(r"data-reactroot", re.I), re.compile(r"data-reactid", re.I)],
    ),
    TechSignature("Vue.js", "JavaScript Framework",
        body_patterns=[re.compile(r"vue\.js", re.I), re.compile(r"vue\.min\.js", re.I),
                       re.compile(r"__VUE_", re.I), re.compile(r"data-v-", re.I)],
    ),
    TechSignature("Angular", "JavaScript Framework",
        body_patterns=[re.compile(r"angular\.js", re.I), re.compile(r"angular\.min\.js", re.I),
                       re.compile(r"ng-app", re.I), re.compile(r"ng-version", re.I)],
    ),
    TechSignature("jQuery", "JavaScript Library",
        body_patterns=[re.compile(r"jquery", re.I)],
        confidence=80,
    ),
    TechSignature("Next.js", "JavaScript Framework",
        body_patterns=[re.compile(r"__NEXT_DATA__", re.I), re.compile(r"next\.js", re.I)],
    ),
    TechSignature("Nuxt.js", "JavaScript Framework",
        body_patterns=[re.compile(r"__NUXT__", re.I)],
    ),
    TechSignature("Gatsby", "JavaScript Framework",
        body_patterns=[re.compile(r"gatsby\.js", re.I), re.compile(r"data-gatsby", re.I)],
    ),

    # === Analytics ===
    TechSignature("Google Analytics", "Analytics",
        body_patterns=[re.compile(r"google-analytics\.com", re.I),
                       re.compile(r"gtag\(", re.I), re.compile(r"ga\('create'", re.I)],
        script_patterns=[re.compile(r"www\.googletagmanager\.com", re.I)],
    ),
    TechSignature("Hotjar", "Analytics",
        body_patterns=[re.compile(r"hotjar", re.I)],
    ),
    TechSignature("Meta Pixel", "Analytics",
        body_patterns=[re.compile(r"fbq\(", re.I), re.compile(r"connect\.facebook\.net", re.I)],
    ),

    # === Programming Languages / Runtimes ===
    TechSignature("PHP", "Programming Language",
        header_patterns={"x-powered-by": re.compile(r"PHP", re.I),
                         "set-cookie": re.compile(r"PHPSESSID", re.I)},
    ),
    TechSignature("Python", "Programming Language",
        header_patterns={"server": re.compile(r"(gunicorn|uwsgi)", re.I),
                         "x-powered-by": re.compile(r"Python", re.I)},
    ),
    TechSignature("Ruby on Rails", "Framework",
        header_patterns={"x-powered-by": re.compile(r"Phusion", re.I),
                         "server": re.compile(r"(thin|puma|unicorn)", re.I)},
        body_patterns=[re.compile(r"csrf-param", re.I)],
    ),
    TechSignature("Express", "Framework",
        header_patterns={"x-powered-by": re.compile(r"Express", re.I)},
    ),
    TechSignature("ASP.NET", "Framework",
        header_patterns={"x-powered-by": re.compile(r"ASP\.NET", re.I),
                         "set-cookie": re.compile(r"ASPSESSION|ASP\.NET_SessionId", re.I)},
    ),

    # === Security Headers ===
    TechSignature("HSTS Enabled", "Security",
        header_patterns={"strict-transport-security": re.compile(r".+")},
        confidence=95,
    ),
    TechSignature("CSP Enabled", "Security",
        header_patterns={"content-security-policy": re.compile(r".+")},
        confidence=90,
    ),
    TechSignature("X-Frame-Options", "Security",
        header_patterns={"x-frame-options": re.compile(r"(DENY|SAMEORIGIN)", re.I)},
        confidence=85,
    ),
]


TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.DOTALL)


def detect_technologies(
    headers: dict[str, str],
    body: str,
    url: str,
) -> list[dict]:
    """Detect web technologies from response headers, body, and URL."""
    detected: list[dict] = []
    seen: set[str] = set()

    # Normalize headers to lowercase keys
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for sig in TECH_SIGNATURES:
        matched = False

        # Check header patterns
        if sig.header_patterns:
            for key, pattern in sig.header_patterns.items():
                if key in headers_lower and pattern.search(headers_lower[key]):
                    matched = True
                    break

        # Check body patterns
        if not matched and sig.body_patterns:
            for pattern in sig.body_patterns:
                if pattern.search(body):
                    matched = True
                    break

        # Check URL patterns
        if not matched and sig.url_patterns:
            for pattern in sig.url_patterns:
                if pattern.search(url):
                    matched = True
                    break

        # Check meta patterns (from body)
        if not matched and sig.meta_patterns:
            for attr, pattern in sig.meta_patterns.items():
                meta_match = re.search(
                    rb'<meta\s+[^>]*' + re.escape(attr).encode() + rb'[^>]*content=["\']([^"\']+)["\']',
                    body.encode() if isinstance(body, str) else body,
                    re.I,
                )
                if meta_match and pattern.search(meta_match.group(1).decode()):
                    matched = True
                    break

        # Check script patterns
        if not matched and sig.script_patterns:
            for pattern in sig.script_patterns:
                if pattern.search(body):
                    matched = True
                    break

        if matched and sig.name not in seen:
            seen.add(sig.name)
            detected.append({
                "name": sig.name,
                "category": sig.category,
                "confidence": sig.confidence,
            })

    return detected


def extract_title(body: bytes) -> str:
    """Extract the page title from HTML body."""
    match = TITLE_RE.search(body)
    if not match:
        return ""
    title = match.group(1).decode("utf-8", errors="replace").strip()
    # Clean up whitespace
    title = re.sub(r"\s+", " ", title)
    return title[:200]  # Cap title length


async def probe_url(
    url: str,
    client: httpx.AsyncClient,
    timeout: float = 10.0,
) -> HttpProbeResult:
    """Probe a single URL for HTTP info and tech fingerprinting."""
    result = HttpProbeResult(url=url)
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
        result.status_code = resp.status_code
        result.server_header = resp.headers.get("server", "")
        result.content_type = resp.headers.get("content-type", "")

        # Extract title
        result.title = extract_title(resp.content)

        # Detect technologies
        result.technologies = detect_technologies(
            dict(resp.headers),
            resp.text,
            url,
        )

    except httpx.TimeoutException:
        result.error = "timeout"
    except httpx.ConnectError:
        result.error = "connection refused"
    except httpx.HTTPError as e:
        result.error = f"http error: {e}"
    except Exception as e:
        result.error = f"error: {e}"

    return result


async def probe_host(
    hostname: str,
    ports: list[int],
    ssl_ports: Optional[set[int]] = None,
    timeout: float = 10.0,
    delay: float = 0.0,
    proxy_url: Optional[str] = None,
) -> HttpProbeReport:
    """Probe all HTTP/HTTPS services on a host.

    Args:
        hostname: Target hostname to probe.
        ports: List of ports to probe.
        ssl_ports: Set of ports that use SSL/TLS.
        timeout: Timeout per request in seconds.
        delay: Seconds to wait between probes (rate limiting).
        proxy_url: Optional proxy URL for routing traffic.
    """
    if ssl_ports is None:
        ssl_ports = {443, 8443, 9443}

    report = HttpProbeReport(hostname=hostname)

    # Build client with optional proxy
    client_kwargs: dict = {
        "verify": False,
        "timeout": httpx.Timeout(timeout),
        "limits": httpx.Limits(max_connections=20),
    }
    if proxy_url:
        client_kwargs["proxies"] = proxy_url

    # Build URLs from ports (explicit port form only to avoid duplicates)
    urls: list[str] = []
    seen: set[str] = set()
    for port in ports:
        scheme = "https" if port in ssl_ports else "http"
        url = f"{scheme}://{hostname}:{port}"
        if url not in seen:
            urls.append(url)
            seen.add(url)

    async with httpx.AsyncClient(**client_kwargs) as client:
        for i, url in enumerate(urls):
            if i > 0 and delay > 0:
                await asyncio.sleep(delay)
            result = await probe_url(url, client, timeout)
            report.results.append(result)
            if result.is_alive:
                report.alive_count += 1

    return report


async def probe_hosts(
    hosts: list[tuple[str, list[int]]],
    timeout: float = 10.0,
) -> list[HttpProbeReport]:
    """Probe multiple hosts in sequence."""
    reports: list[HttpProbeReport] = []
    for hostname, ports in hosts:
        report = await probe_host(hostname, ports, timeout=timeout)
        reports.append(report)
    return reports
