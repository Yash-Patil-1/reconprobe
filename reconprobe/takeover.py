"""Subdomain takeover detection module.

Detects dangling DNS records that point to deprovisioned cloud services.
Uses a two-phase approach:
1. DNS resolution check — identify dangling CNAME/A records
2. HTTP probe — match response bodies against known service fingerprints

Supports detection for 25+ cloud providers and services.
"""

from __future__ import annotations

import asyncio
import warnings
import dns.resolver
import dns.exception
import socket
from dataclasses import dataclass, field
from typing import Optional

import httpx


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class TakeoverFingerprint:
    """Fingerprint for detecting a vulnerable cloud service."""
    service: str
    cname_patterns: list[str]  # CNAME targets that indicate this service
    nxdomain: bool = False      # Check if CNAME target resolves
    http_signatures: list[str] = field(default_factory=list)  # Strings in response body
    http_status: Optional[int] = None  # Expected HTTP status code
    http_canonical_url: Optional[str] = None  # Expected redirect URL pattern


@dataclass
class TakeoverResult:
    """Result of a takeover check for a single subdomain."""
    hostname: str
    service: str = ""
    cname_target: str = ""
    is_vulnerable: bool = False
    confidence: str = ""  # "high", "medium", "low"
    dns_status: str = ""  # "dangling", "resolved", "nxdomain"
    http_status: Optional[int] = None
    http_body_snippet: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "service": self.service,
            "cname_target": self.cname_target,
            "is_vulnerable": self.is_vulnerable,
            "confidence": self.confidence,
            "dns_status": self.dns_status,
            "http_status": self.http_status,
            "http_body_snippet": self.http_body_snippet[:200] if self.http_body_snippet else "",
            "error": self.error,
        }


@dataclass
class TakeoverReport:
    """Aggregated subdomain takeover report."""
    results: list[TakeoverResult] = field(default_factory=list)
    total_checked: int = 0
    total_vulnerable: int = 0

    def to_dict(self) -> dict:
        return {
            "total_checked": self.total_checked,
            "total_vulnerable": self.total_vulnerable,
            "results": [r.to_dict() for r in self.results if r.is_vulnerable],
        }


# ── Takeover Fingerprint Database ───────────────────────────────────────────

# Based on community-maintained reference: https://github.com/EdOverflow/can-i-take-over-xyz
# and OWASP Subdomain Takeover Prevention Cheat Sheet.

TAKEOVER_FINGERPRINTS: list[TakeoverFingerprint] = [
    # AWS Services
    TakeoverFingerprint(
        "AWS S3 Bucket", ["s3.amazonaws.com", "s3-website", ".s3."],
        nxdomain=True,
        http_signatures=["NoSuchBucket", "The specified bucket does not exist"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "AWS CloudFront", ["cloudfront.net"],
        nxdomain=True,
        http_signatures=["ERROR: The request could not be satisfied", "Bad request"],
        http_status=403,
    ),
    TakeoverFingerprint(
        "AWS Elastic Beanstalk", ["elasticbeanstalk.com", "elasticbeanstalk."],
        nxdomain=True,
        http_signatures=["NXDOMAIN", "404 Not Found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "AWS API Gateway", ["execute-api.", ".amazonaws.com"],
        nxdomain=True,
        http_signatures=["{\"message\":\"Not Found\"", "{\"message\":\"Forbidden\""],
    ),
    TakeoverFingerprint(
        "AWS Lightsail", ["lightsail"],
        nxdomain=True,
        http_signatures=["404 Not Found"],
    ),

    # Azure Services
    TakeoverFingerprint(
        "Azure App Service", ["azurewebsites.net", ".azurewebsites."],
        nxdomain=True,
        http_signatures=["404 Not Found", "There is no site deployed"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Azure Cloud Service", ["cloudapp.net", ".cloudapp."],
        nxdomain=True,
        http_signatures=["404 Not Found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Azure Traffic Manager", ["trafficmanager.net", ".trafficmanager."],
        nxdomain=True,
        http_signatures=["404 Not Found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Azure CDN", ["azureedge.net", ".azureedge."],
        nxdomain=True,
        http_signatures=["The resource you are looking for has been removed"],
        http_status=404,
    ),

    # Google Cloud
    TakeoverFingerprint(
        "Google Cloud Storage", ["storage.googleapis.com"],
        nxdomain=True,
        http_signatures=["NoSuchBucket", "The specified bucket does not exist"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Google App Engine", ["appspot.com", ".appspot."],
        nxdomain=True,
        http_signatures=["404 Not Found", "There is no App Engine application"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Firebase", ["firebaseapp.com", ".firebaseapp.", "firebaseio.com"],
        nxdomain=True,
        http_signatures=["404 Not Found", "Firebase Hosting"],
        http_status=404,
    ),

    # CDN & Hosting
    TakeoverFingerprint(
        "Cloudflare", ["cloudflare"],
        nxdomain=True,
        http_signatures=[
            "The requested URL was not found on this server",
            "There is nothing here yet",
        ],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Fastly", ["fastly.net", ".fastly.", "global.ssl.fastly.net"],
        nxdomain=True,
        http_signatures=["Fastly error: unknown domain"],
        http_status=503,
    ),
    TakeoverFingerprint(
        "Heroku", ["herokuapp.com", ".herokuapp."],
        nxdomain=True,
        http_signatures=["No such app"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Netlify", ["netlify.app", ".netlify."],
        nxdomain=True,
        http_signatures=["Not Found - Netlify"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "GitHub Pages", ["github.io"],
        nxdomain=True,
        http_signatures=["There isn't a GitHub Pages site here"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "GitLab Pages", ["gitlab.io"],
        nxdomain=True,
        http_signatures=["The page you're looking for could not be found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Surge.sh", ["surge.sh"],
        nxdomain=True,
        http_signatures=["project not found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Vercel", ["vercel.app", ".vercel.app"],
        nxdomain=True,
        http_signatures=["The page could not be found", "404: NOT_FOUND"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Render", ["onrender.com", ".render.com"],
        nxdomain=True,
        http_signatures=["Render 404"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Fly.io", ["fly.dev", ".fly.dev"],
        nxdomain=True,
        http_signatures=["404 Not Found", "Not Found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Pantheon", ["pantheon.io", ".pantheonsite.io"],
        nxdomain=True,
        http_signatures=["The site you are looking for could not be found"],
        http_status=404,
    ),

    # Other SaaS
    TakeoverFingerprint(
        "Shopify", ["myshopify.com", ".myshopify."],
        nxdomain=True,
        http_signatures=["Sorry, this shop is currently unavailable"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Squarespace", ["squarespace.com"],
        nxdomain=True,
        http_signatures=["No site found for"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Tumblr", ["tumblr.com"],
        nxdomain=True,
        http_signatures=["There's nothing here"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "WordPress.com", ["wordpress.com"],
        nxdomain=True,
        http_signatures=["Doesn't look like anything here", "Don't have a WordPress.com site"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Strikingly", ["strikingly.com", ".strikingly.com"],
        nxdomain=True,
        http_signatures=["The page could not be found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Teamwork", ["teamwork.com"],
        nxdomain=True,
        http_signatures=["Oops - We didn't find that site"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Helpjuice", ["helpjuice.com"],
        nxdomain=True,
        http_signatures=["There is no site here"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Zendesk", ["zendesk.com", ".zendesk."],
        nxdomain=True,
        http_signatures=["Help Center Closed"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Freshdesk", ["freshdesk.com", ".freshdesk."],
        nxdomain=True,
        http_signatures=["Domain doesn't exist"],
        http_status=404,
    ),

    # Messaging & Collaboration
    TakeoverFingerprint(
        "Slack", ["slack.com"],
        nxdomain=True,
        http_signatures=["It looks like this workspace doesn't exist"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Atlassian", ["atlassian.net", ".atlassian.net"],
        nxdomain=True,
        http_signatures=["This site can't be reached", "The page you were looking for doesn't exist"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Cargo Collective", ["cargocollective.com"],
        nxdomain=True,
        http_signatures=["The site you were looking for doesn't exist"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Uptime Robot", ["uptimerobot.com"],
        nxdomain=True,
        http_signatures=["page not found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Statuspage.io", ["statuspage.io"],
        nxdomain=True,
        http_signatures=["The page you are looking for doesn't exist"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Smartling", ["smartling.com"],
        nxdomain=True,
        http_signatures=["Domain is not configured"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Campaign Monitor", ["createsend.com"],
        nxdomain=True,
        http_signatures=["Trying to access a page"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Acquia", ["acquia.com", ".acquia.com"],
        nxdomain=True,
        http_signatures=["The site you are looking for could not be found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "ReadMe.io", ["readme.io"],
        nxdomain=True,
        http_signatures=["Project not found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Kinsta", ["kinsta.com", ".kinsta."],
        nxdomain=True,
        http_signatures=["Site Not Found"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Ghost.org", ["ghost.io", ".ghost.io"],
        nxdomain=True,
        http_signatures=["The Ghost site you're looking for does not exist"],
        http_status=404,
    ),
    TakeoverFingerprint(
        "Tilda", ["tilda.ws", ".tilda."],
        nxdomain=True,
        http_signatures=["The page could not be found"],
        http_status=404,
    ),
]


# ── DNS Resolution ──────────────────────────────────────────────────────────


async def resolve_cname(hostname: str) -> Optional[str]:
    """Resolve the CNAME record for a hostname.

    Returns the CNAME target if one exists, None otherwise.
    """
    try:
        answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: dns.resolver.resolve(hostname, "CNAME")
        )
        if answers:
            return str(answers[0].target).rstrip(".")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None


async def resolve_a(hostname: str) -> Optional[str]:
    """Resolve the A record for a hostname.

    Returns the IP address if it resolves, None otherwise.
    """
    try:
        answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: dns.resolver.resolve(hostname, "A")
        )
        if answers:
            return str(answers[0])
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None


async def check_dns_dangling(hostname: str) -> tuple[Optional[str], str]:
    """Check if a subdomain's DNS record is dangling.

    Returns (cname_target, status) where status is one of:
    - "dangling": CNAME target does not resolve
    - "resolved": Both hostname and CNAME resolve normally
    - "nxdomain": Hostname itself does not resolve
    - "no_cname": Hostname resolves but has no CNAME
    """
    # First check if hostname resolves at all
    a_record = await resolve_a(hostname)
    if not a_record:
        return None, "nxdomain"

    # Check for CNAME
    cname = await resolve_cname(hostname)
    if not cname:
        return None, "no_cname"

    # CNAME found — check if it resolves
    cname_a = await resolve_a(cname)
    if not cname_a:
        return cname, "dangling"

    return cname, "resolved"


# ── HTTP Probing for Takeover Signatures ────────────────────────────────────


async def check_http_signatures(
    hostname: str,
    fingerprints: list[TakeoverFingerprint],
    timeout: float = 10.0,
) -> tuple[Optional[str], Optional[str], Optional[int], str]:
    """Probe the hostname and check for takeover signatures in the response.

    Returns (service_name, body_snippet, http_status, signature_type).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                async with httpx.AsyncClient(
                    verify=False,
                    timeout=httpx.Timeout(timeout),
                    follow_redirects=True,
                ) as client:
                    resp = await client.get(url, headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                      "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    })

                    body = resp.text.lower()

                    for fp in fingerprints:
                        # Check HTTP status if specified
                        if fp.http_status and resp.status_code != fp.http_status:
                            continue

                        # Check for HTTP signature strings in body
                        for sig in fp.http_signatures:
                            if sig.lower() in body:
                                # Found a match!
                                snippet = body[
                                    max(0, body.index(sig.lower()) - 20):
                                    body.index(sig.lower()) + len(sig) + 20
                                ]
                                return fp.service, snippet, resp.status_code, "http_body_match"

                    # No signature match found
                    return None, None, resp.status_code, "no_match"

        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError):
            continue
        except Exception:
            continue

    return None, None, None, "connection_failed"


# ── Main Detection Logic ────────────────────────────────────────────────────


async def check_takeover(
    hostname: str,
    fingerprints: Optional[list[TakeoverFingerprint]] = None,
) -> TakeoverResult:
    """Check a single subdomain for potential takeover.

    Two-phase approach:
    1. DNS check: Resolve CNAME and check if target is dangling
    2. HTTP check: Probe the hostname and match against service fingerprints

    Args:
        hostname: Subdomain to check.
        fingerprints: Optional custom fingerprint list (defaults to full database).

    Returns:
        TakeoverResult with findings.
    """
    result = TakeoverResult(hostname=hostname)
    fp_list = fingerprints or TAKEOVER_FINGERPRINTS

    # Phase 1: DNS Check
    cname, dns_status = await check_dns_dangling(hostname)
    result.cname_target = cname or ""
    result.dns_status = dns_status

    # Phase 2: HTTP Probe (always check, even if DNS looks normal)
    service_name, body_snippet, http_status, sig_type = await check_http_signatures(
        hostname, fp_list
    )
    result.http_status = http_status
    result.http_body_snippet = body_snippet or ""

    # Determine vulnerability status
    if dns_status == "dangling" and sig_type == "http_body_match":
        # Both DNS and HTTP indicate takeover
        result.is_vulnerable = True
        result.service = service_name or ""
        result.confidence = "high"
    elif dns_status == "dangling" and sig_type != "no_match":
        # DNS is dangling, HTTP didn't match but didn't return normal content
        result.is_vulnerable = True
        result.service = service_name or "Unknown cloud service"
        result.confidence = "medium"
    elif sig_type == "http_body_match":
        # HTTP matched a fingerprint even though DNS seemed normal
        # Could be a different type of takeover
        result.is_vulnerable = True
        result.service = service_name or ""
        result.confidence = "medium"
    elif dns_status == "nxdomain":
        # Hostname doesn't resolve at all — potential takeover
        result.is_vulnerable = True
        result.service = "Unknown (NXDOMAIN)"
        result.confidence = "low"
    else:
        result.is_vulnerable = False
        result.confidence = "none"

    return result


async def scan_takeovers(
    subdomains: list[str],
    max_concurrent: int = 20,
) -> TakeoverReport:
    """Scan a list of subdomains for potential takeover vulnerabilities.

    Args:
        subdomains: List of subdomain hostnames to check.
        max_concurrent: Maximum concurrent checks.

    Returns:
        TakeoverReport with all findings.
    """
    report = TakeoverReport()
    report.total_checked = len(subdomains)

    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_one(hostname: str) -> TakeoverResult:
        async with semaphore:
            return await check_takeover(hostname)

    tasks = [check_one(sub) for sub in subdomains]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, TakeoverResult):
            report.results.append(result)
            if result.is_vulnerable:
                report.total_vulnerable += 1

    return report
