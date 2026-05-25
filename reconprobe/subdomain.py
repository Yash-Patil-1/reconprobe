"""Subdomain enumeration module.

Supports passive sources (crt.sh, CertSpotter, VirusTotal, SecurityTrails)
and active brute-force.
"""

from __future__ import annotations

import json
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from reconprobe.utils import is_valid_domain, resolve_hostname

WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "subdomains.txt"

# Environment variable names for API keys
VT_API_KEY_ENV = "VT_API_KEY"
ST_API_KEY_ENV = "ST_API_KEY"

# Default wordlist built into the source as a fallback
BUILTIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "admin", "ftp", "api", "dev", "test",
    "portal", "support", "pop", "web", "cloud", "cdn", "mx", "img",
    "static", "app", "stage", "beta", "docs", "help", "shop", "m",
    "mobile", "store", "news", "media", "download", "video", "live",
    "status", "host", "email", "autodiscover", "cpanel", "whm", "git",
    "jenkins", "jira", "confluence", "wiki", "grafana", "prometheus",
    "kibana", "elastic", "dashboard", "monitor", "backup", "proxy",
    "redirect", "origin", "direct", "auth", "login", "register",
    "signup", "report", "analytics", "tracker", "pixel", "ads",
    "partners", "affiliates", "reseller", "corp", "info", "intranet",
]


@dataclass
class SubdomainResult:
    """Result from subdomain enumeration."""
    hostname: str
    ip_address: Optional[str] = None
    source: str = ""
    resolved: bool = False


@dataclass
class SubdomainReport:
    """Aggregated subdomain enumeration report."""
    domain: str
    results: list[SubdomainResult] = field(default_factory=list)
    total_found: int = 0
    total_resolved: int = 0

    @property
    def resolved_hostnames(self) -> list[str]:
        return [r.hostname for r in self.results if r.resolved]

    @property
    def unresolved_hostnames(self) -> list[str]:
        return [r.hostname for r in self.results if not r.resolved]


async def enumerate_crtsh(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Query crt.sh Certificate Transparency log for subdomains."""
    subdomains: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = await client.get(url, timeout=30.0, headers={
            "User-Agent": "ReconProbe/0.1.0 (Security Research)",
            "Accept": "application/json",
        })
        if resp.status_code != 200:
            return subdomains
        entries = resp.json()
        for entry in entries:
            name_value: str = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name.endswith(f".{domain}") and is_valid_domain(name):
                    subdomains.add(name)
    except (httpx.HTTPError, json.JSONDecodeError, KeyError):
        pass
    return subdomains


async def enumerate_certspotter(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Query CertSpotter API for subdomains (no API key needed for basic usage)."""
    subdomains: set[str] = set()
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        resp = await client.get(url, timeout=30.0, headers={
            "User-Agent": "ReconProbe/0.1.0 (Security Research)",
        })
        if resp.status_code != 200:
            return subdomains
        entries = resp.json()
        for entry in entries:
            dns_names: list[str] = entry.get("dns_names", [])
            for name in dns_names:
                name = name.strip().lower()
                # CertSpotter returns names like *.example.com and example.com
                if name.startswith("*."):
                    name = name[2:]
                if name.endswith(f".{domain}") and is_valid_domain(name):
                    subdomains.add(name)
    except (httpx.HTTPError, json.JSONDecodeError, KeyError):
        pass
    return subdomains


async def enumerate_virustotal(
    domain: str,
    client: httpx.AsyncClient,
    api_key: Optional[str] = None,
) -> set[str]:
    """Query VirusTotal API v3 for subdomains (requires API key in VT_API_KEY env var)."""
    subdomains: set[str] = set()
    key = api_key or os.environ.get(VT_API_KEY_ENV)
    if not key:
        return subdomains
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    try:
        resp = await client.get(
            url,
            timeout=30.0,
            headers={
                "x-apikey": key,
                "Accept": "application/json",
            },
        )
        if resp.status_code != 200:
            return subdomains
        data = resp.json()
        for entry in data.get("data", []):
            subdomain_id: str = entry.get("id", "")
            if subdomain_id.endswith(f".{domain}") and is_valid_domain(subdomain_id):
                subdomains.add(subdomain_id.lower())
    except (httpx.HTTPError, json.JSONDecodeError, KeyError):
        pass
    return subdomains


async def enumerate_securitytrails(
    domain: str,
    client: httpx.AsyncClient,
    api_key: Optional[str] = None,
) -> set[str]:
    """Query SecurityTrails API for subdomains (requires API key in ST_API_KEY env var)."""
    subdomains: set[str] = set()
    key = api_key or os.environ.get(ST_API_KEY_ENV)
    if not key:
        return subdomains
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    try:
        resp = await client.get(
            url,
            timeout=30.0,
            headers={
                "APIKEY": key,
                "Accept": "application/json",
            },
        )
        if resp.status_code != 200:
            return subdomains
        data = resp.json()
        subdomain_list: list[str] = data.get("subdomains", [])
        for sub in subdomain_list:
            full = f"{sub}.{domain}".lower()
            if is_valid_domain(full):
                subdomains.add(full)
    except (httpx.HTTPError, json.JSONDecodeError, KeyError):
        pass
    return subdomains


async def enumerate_passive(
    domain: str,
    vt_api_key: Optional[str] = None,
    st_api_key: Optional[str] = None,
) -> set[str]:
    """Run all passive enumeration sources in parallel.

    Supports: crt.sh, CertSpotter, VirusTotal (VT_API_KEY), SecurityTrails (ST_API_KEY).
    """
    all_subdomains: set[str] = set()
    # verify=False: intentional for security tooling — CT log APIs sometimes
    # use non-standard CAs or misconfigured certs. No sensitive data is sent.
    async with httpx.AsyncClient(verify=False) as client:
        tasks = [
            enumerate_crtsh(domain, client),
            enumerate_certspotter(domain, client),
            enumerate_virustotal(domain, client, vt_api_key),
            enumerate_securitytrails(domain, client, st_api_key),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, set):
                all_subdomains.update(result)
    return all_subdomains


def brute_force_subdomains(
    domain: str,
    wordlist_path: Optional[str] = None,
    max_workers: int = 50,
    timeout: float = 5.0,
) -> set[str]:
    """Brute-force subdomains using a wordlist and DNS resolution."""
    found: set[str] = set()

    # Load wordlist — try bundled file first, then fall back to built-in list
    words: list[str] = []
    if wordlist_path and os.path.isfile(wordlist_path):
        with open(wordlist_path) as f:
            words = [line.strip().lower() for line in f if line.strip()]
    elif os.path.isfile(WORDLIST_PATH):
        with open(WORDLIST_PATH) as f:
            words = [line.strip().lower() for line in f if line.strip()]
    if not words:
        words = BUILTIN_WORDLIST

    def try_subdomain(word: str) -> Optional[str]:
        hostname = f"{word}.{domain}"
        ip = resolve_hostname(hostname, timeout=timeout)
        if ip:
            return hostname
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(try_subdomain, w): w for w in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.add(result)

    return found


async def enumerate_subdomains(
    domain: str,
    brute_force: bool = True,
    wordlist_path: Optional[str] = None,
    max_workers: int = 50,
    vt_api_key: Optional[str] = None,
    st_api_key: Optional[str] = None,
    # Advanced techniques
    enable_advanced: bool = False,
    enable_zone_transfer: bool = True,
    enable_permutations: bool = True,
    enable_recursive: bool = True,
    recursive_max_depth: int = 2,
    max_permutation_candidates: int = 5000,
) -> tuple[SubdomainReport, Optional[dict]]:
    """Full subdomain enumeration pipeline.

    Returns a tuple of (SubdomainReport, advanced_report_dict or None).
    """
    if not is_valid_domain(domain):
        raise ValueError(f"Invalid domain: {domain}")

    report = SubdomainReport(domain=domain)

    # Passive enumeration
    passive_results = await enumerate_passive(domain, vt_api_key, st_api_key)

    # Brute-force
    brute_results: set[str] = set()
    if brute_force:
        brute_results = brute_force_subdomains(domain, wordlist_path, max_workers)

    all_hostnames = passive_results | brute_results

    # Resolve found hostnames
    for hostname in sorted(all_hostnames):
        ip = resolve_hostname(hostname)
        report.results.append(
            SubdomainResult(
                hostname=hostname,
                ip_address=ip,
                source="passive" if hostname in passive_results else "brute-force",
                resolved=ip is not None,
            )
        )

    report.total_found = len(report.results)
    report.total_resolved = sum(1 for r in report.results if r.resolved)

    # Advanced techniques
    advanced_report = None
    if enable_advanced:
        from reconprobe.subdomain_advanced import run_advanced_techniques

        known_hostnames = [r.hostname for r in report.results if r.resolved]
        adv = await run_advanced_techniques(
            domain=domain,
            known_subdomains=known_hostnames,
            enable_zone_transfer=enable_zone_transfer,
            enable_permutations=enable_permutations,
            enable_recursive=enable_recursive,
            recursive_max_depth=recursive_max_depth,
            max_permutation_candidates=max_permutation_candidates,
            vt_api_key=vt_api_key,
            st_api_key=st_api_key,
        )

        # Add newly discovered subdomains to the main report
        new_subdomains: set[str] = set()

        # From permutations
        if adv.permutation_report:
            new_subdomains.update(adv.permutation_report.new_subdomains)

        # From recursive discovery
        for depth_results in adv.recursive_results.values():
            new_subdomains.update(depth_results)

        # Resolve and add new subdomains
        for hostname in sorted(new_subdomains):
            if hostname in all_hostnames:
                continue
            ip = resolve_hostname(hostname)
            report.results.append(
                SubdomainResult(
                    hostname=hostname,
                    ip_address=ip,
                    source="advanced-permutation" if hostname in (adv.permutation_report.new_subdomains if adv.permutation_report else []) else "advanced-recursive",
                    resolved=ip is not None,
                )
            )

        report.total_found = len(report.results)
        report.total_resolved = sum(1 for r in report.results if r.resolved)

        # Build advanced report dict for display
        advanced_report = {
            "zone_transfer": [
                {
                    "nameserver": zt.nameserver,
                    "success": zt.success,
                    "records": zt.records[:20],
                    "error": zt.error,
                }
                for zt in adv.zone_transfer_results
            ],
            "permutations": {
                "total_generated": adv.permutation_report.total_generated if adv.permutation_report else 0,
                "total_resolved": adv.permutation_report.total_resolved if adv.permutation_report else 0,
                "new_subdomains": adv.permutation_report.new_subdomains if adv.permutation_report else [],
            } if adv.permutation_report else None,
            "recursive": {
                depth: subs
                for depth, subs in adv.recursive_results.items()
            } if adv.recursive_results else None,
            "total_new_subdomains": adv.total_new_subdomains,
        }

    return report, advanced_report
