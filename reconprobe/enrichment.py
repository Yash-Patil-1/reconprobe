"""Enrichment module — API-based data augmentation.

Integrates with external APIs to enrich scan results with:
- Shodan: open ports, banners, organization, hostnames, CVEs for discovered IPs
- NVD (National Vulnerability Database): CVE lookup for detected services/technologies
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


# Environment variable names for API keys
SHODAN_API_KEY_ENV = "SHODAN_API_KEY"
NVD_API_KEY_ENV = "NVD_API_KEY"


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class ShodanHostResult:
    """Result from querying Shodan for a single IP address."""
    ip: str
    org: str = ""
    isp: str = ""
    hostnames: list[str] = field(default_factory=list)
    country: str = ""
    city: str = ""
    open_ports: list[int] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)  # port + transport + banner info
    vulns: list[str] = field(default_factory=list)       # CVE IDs if Shodan lists them
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "org": self.org,
            "isp": self.isp,
            "hostnames": self.hostnames,
            "country": self.country,
            "city": self.city,
            "open_ports": self.open_ports,
            "services": self.services,
            "vulns": self.vulns,
            "error": self.error,
        }


@dataclass
class CVEResult:
    """Result from querying NVD for a specific CVE or product search."""
    cve_id: str
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_severity: str = ""
    published_date: str = ""
    last_modified: str = ""
    attack_vector: str = ""
    affected_products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description[:500] if self.description else "",
            "cvss_score": self.cvss_score,
            "cvss_severity": self.cvss_severity,
            "published_date": self.published_date,
            "attack_vector": self.attack_vector,
            "affected_products": self.affected_products[:10],
            "references": self.references[:5],
            "error": self.error,
        }


@dataclass
class EnrichmentReport:
    """Aggregated enrichment report for a scan."""
    shodan_results: dict[str, ShodanHostResult] = field(default_factory=dict)
    cve_results: list[CVEResult] = field(default_factory=list)
    total_ips_checked: int = 0
    total_vulns_found: int = 0

    def to_dict(self) -> dict:
        return {
            "shodan": {
                "total_ips_checked": len(self.shodan_results),
                "results": {ip: r.to_dict() for ip, r in self.shodan_results.items()},
            },
            "cve_lookup": {
                "total_found": len(self.cve_results),
                "results": [c.to_dict() for c in self.cve_results],
            },
        }


# ── Shodan Integration ───────────────────────────────────────────────────────


SHODAN_API_BASE = "https://api.shodan.io"


async def query_shodan_host(
    ip: str,
    api_key: str,
    client: httpx.AsyncClient,
    timeout: float = 15.0,
) -> ShodanHostResult:
    """Query Shodan for information about a specific IP address."""
    result = ShodanHostResult(ip=ip)
    url = f"{SHODAN_API_BASE}/shodan/host/{ip}?key={api_key}"
    try:
        resp = await client.get(url, timeout=timeout)
        if resp.status_code == 401:
            result.error = "invalid API key"
            return result
        if resp.status_code == 403:
            result.error = "API credit limit exceeded or access denied"
            return result
        if resp.status_code == 404:
            result.error = "IP not found in Shodan database"
            return result
        if resp.status_code != 200:
            result.error = f"HTTP {resp.status_code}"
            return result

        data = resp.json()
        result.org = data.get("org", "")
        result.isp = data.get("isp", "")
        result.hostnames = data.get("hostnames", [])
        result.country = data.get("country_code", "")
        result.city = data.get("city", "")
        result.open_ports = data.get("ports", [])

        # Parse service banners (the 'data' array)
        services: list[dict] = []
        for entry in data.get("data", []):
            service_info = {
                "port": entry.get("port"),
                "transport": entry.get("transport", "tcp"),
                "product": entry.get("product", ""),
                "version": entry.get("version", ""),
                "banner": (entry.get("data", "") or "")[:300],
                "timestamp": entry.get("timestamp", ""),
            }
            services.append(service_info)

            # Extract CVEs from the service data
            vulns = entry.get("vulns", {})
            if isinstance(vulns, dict):
                for cve_id, vuln_info in vulns.items():
                    if cve_id.startswith("CVE-"):
                        result.vulns.append(cve_id)
            elif isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, str) and v.startswith("CVE-"):
                        result.vulns.append(v)

        result.services = services

    except httpx.TimeoutException:
        result.error = "timeout"
    except httpx.ConnectError:
        result.error = "connection failed"
    except Exception as e:
        result.error = f"error: {e}"

    return result


async def enrich_with_shodan(
    ip_addresses: list[str],
    api_key: Optional[str] = None,
    max_concurrent: int = 5,
    proxy_url: Optional[str] = None,
    delay: float = 0.0,
) -> dict[str, ShodanHostResult]:
    """Query Shodan for all discovered IPs in parallel.

    Returns a dict of IP -> ShodanHostResult.
    Gracefully handles missing/invalid API keys and API errors per IP.
    """
    results: dict[str, ShodanHostResult] = {}
    key = api_key or os.environ.get(SHODAN_API_KEY_ENV)
    if not key:
        return results

    semaphore = asyncio.Semaphore(max_concurrent)

    async def query_with_throttle(ip: str) -> ShodanHostResult:
        async with semaphore:
            client_kwargs: dict = {"verify": False}
            if proxy_url:
                client_kwargs["proxies"] = proxy_url
            async with httpx.AsyncClient(**client_kwargs) as client:
                return await query_shodan_host(ip, key, client)

    tasks = [query_with_throttle(ip) for ip in ip_addresses]
    host_results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, host_result in enumerate(host_results):
        if isinstance(host_result, ShodanHostResult):
            results[host_result.ip] = host_result
        # Rate limiting between queries
        if delay > 0 and i < len(ip_addresses) - 1:
            await asyncio.sleep(delay)

    return results


# ── NVD (National Vulnerability Database) Integration ────────────────────────


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def query_nvd_cves(
    keywords: list[str],
    api_key: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    max_results: int = 20,
    timeout: float = 15.0,
    proxy_url: Optional[str] = None,
    delay: float = 0.0,
) -> list[CVEResult]:
    """Query NVD API for CVEs matching given keywords.

    Each keyword string is searched independently; results are merged and deduplicated.
    Returns up to `max_results` CVEResult objects.
    """
    results: dict[str, CVEResult] = {}
    key = api_key or os.environ.get(NVD_API_KEY_ENV)

    close_client = False
    if client is None:
        client_kwargs: dict = {"verify": False, "timeout": httpx.Timeout(timeout)}
        if proxy_url:
            client_kwargs["proxies"] = proxy_url
        client = httpx.AsyncClient(**client_kwargs)
        close_client = True

    try:
        for i, keyword in enumerate(keywords):
            if len(results) >= max_results:
                break

            # Rate limiting between keyword searches
            if i > 0 and delay > 0:
                await asyncio.sleep(delay)

            # Sanitize keyword for NVD search
            keyword = keyword.strip()
            if not keyword or len(keyword) < 2:
                continue

            params: dict[str, str | int] = {
                "keywordSearch": keyword,
                "resultsPerPage": min(50, max_results),
            }
            if key:
                params["apiKey"] = key

            try:
                resp = await client.get(
                    NVD_API_BASE,
                    params=params,
                    timeout=timeout,
                    headers={
                        "User-Agent": "ReconProbe/0.2.0 (Security Research)",
                        "Accept": "application/json",
                    },
                )

                if resp.status_code == 403 and not key:
                    # Rate limited without API key — skip remaining queries
                    break
                if resp.status_code != 200:
                    continue

                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    if not cve_id or cve_id in results:
                        continue

                    descriptions = cve_data.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break

                    metrics = cve_data.get("metrics", {})
                    cvss_score: Optional[float] = None
                    cvss_severity = ""
                    attack_vector = ""

                    # Try CVSS v3.1 first, then v3.0, then v2
                    for cvss_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        cvss_list = metrics.get(cvss_key, [])
                        if cvss_list:
                            cvss_data = cvss_list[0]
                            if cvss_key == "cvssMetricV2":
                                cvss_obj = cvss_data.get("cvssData", {})
                            else:
                                cvss_obj = cvss_data.get("cvssData", {})
                            cvss_score = cvss_obj.get("baseScore")
                            cvss_severity = cvss_obj.get("baseSeverity", "")
                            attack_vector = cvss_obj.get("attackVector", "")
                            break

                    published = cve_data.get("published", "")
                    last_modified = cve_data.get("lastModified", "")

                    # Extract affected products
                    affected: list[str] = []
                    for product in cve_data.get("configurations", []):
                        for node in product.get("nodes", []):
                            for match in node.get("cpeMatch", []):
                                criteria = match.get("criteria", "")
                                if criteria:
                                    affected.append(criteria)

                    # Extract references
                    refs: list[str] = []
                    for ref in cve_data.get("references", []):
                        url = ref.get("url", "")
                        if url:
                            refs.append(url)

                    results[cve_id] = CVEResult(
                        cve_id=cve_id,
                        description=description,
                        cvss_score=cvss_score,
                        cvss_severity=cvss_severity,
                        published_date=published,
                        last_modified=last_modified,
                        attack_vector=attack_vector,
                        affected_products=affected,
                        references=refs,
                    )

            except (httpx.TimeoutException, httpx.HTTPError):
                continue

    finally:
        if close_client:
            await client.aclose()

    return list(results.values())[:max_results]


def extract_nvd_keywords_from_http_probe(
    http_probe_reports: dict,
) -> list[str]:
    """Extract technology names suitable for NVD keyword search from HTTP probe results.

    Filters out non-product categories (e.g., "Security" for HSTS/CSP headers)
    that would waste NVD API calls without returning useful results.
    """
    # Categories that represent config attributes, not software products
    NON_PRODUCT_CATEGORIES = {"Security"}

    keywords: list[str] = []
    seen: set[str] = set()

    for hostname, probe_report in http_probe_reports.items():
        for result in probe_report.results:
            for tech in result.technologies:
                name = tech.get("name", "")
                category = tech.get("category", "")
                # Skip non-product categories (HSTS, CSP, X-Frame-Options, etc.)
                if category in NON_PRODUCT_CATEGORIES:
                    continue
                key = f"{name} {category}"
                if key not in seen:
                    seen.add(key)
                    keywords.append(name)

            # Also check server header
            server = getattr(result, "server_header", "") or ""
            if server and server.lower() not in ("", "-"):
                server_clean = server.split("/")[0]  # "nginx/1.24.0" -> "nginx"
                if server_clean not in seen:
                    seen.add(server_clean)
                    keywords.append(server_clean)

    return keywords


async def enrich_with_nvd(
    http_probe_reports: dict,
    api_key: Optional[str] = None,
    max_results: int = 30,
    proxy_url: Optional[str] = None,
    delay: float = 0.0,
) -> list[CVEResult]:
    """Query NVD for CVEs related to detected technologies from HTTP probing.

    Deduplicates results across keyword searches and sorts by CVSS score descending.
    """
    keywords = extract_nvd_keywords_from_http_probe(http_probe_reports)
    if not keywords:
        return []

    cves = await query_nvd_cves(keywords, api_key=api_key, max_results=max_results, proxy_url=proxy_url, delay=delay)

    # Final dedup across all keywords (in case different keywords returned same CVE)
    seen: set[str] = set()
    deduped: list[CVEResult] = []
    for cve in cves:
        if cve.cve_id not in seen:
            seen.add(cve.cve_id)
            deduped.append(cve)

    # Sort by CVSS score descending (highest severity first)
    deduped.sort(key=lambda c: c.cvss_score or 0, reverse=True)

    return deduped[:max_results]


# ── Combined enrichment helper ────────────────────────────────────────────────


async def run_enrichment(
    ip_addresses: list[str],
    http_probe_reports: dict,
    enable_shodan: bool = True,
    enable_nvd: bool = True,
    shodan_api_key: Optional[str] = None,
    nvd_api_key: Optional[str] = None,
    proxy_url: Optional[str] = None,
    delay: float = 0.0,
) -> EnrichmentReport:
    """Run all enabled enrichment sources in parallel.

    Returns an EnrichmentReport summarising all findings.
    """
    report = EnrichmentReport()

    tasks: list[Any] = []

    # Shodan
    if enable_shodan:
        tasks.append(
            enrich_with_shodan(ip_addresses, api_key=shodan_api_key, proxy_url=proxy_url, delay=delay)
        )
    else:
        tasks.append(asyncio.sleep(0, result={}))

    # NVD
    if enable_nvd and http_probe_reports:
        tasks.append(
            enrich_with_nvd(http_probe_reports, api_key=nvd_api_key, proxy_url=proxy_url, delay=delay)
        )
    else:
        tasks.append(asyncio.sleep(0, result=[]))

    # Collect results
    shodan_results, cve_results = await asyncio.gather(*tasks)

    if isinstance(shodan_results, dict):
        report.shodan_results = shodan_results
    if isinstance(cve_results, list):
        report.cve_results = cve_results

    report.total_ips_checked = len(report.shodan_results)
    report.total_vulns_found = len(report.cve_results)

    return report
