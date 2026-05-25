"""Multi-target batch processing.

Supports scanning multiple domains from a targets file and running
through each domain sequentially, collecting per-domain reports.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console

from reconprobe.runner import run_scan

console = Console()


def load_targets(targets_file: str) -> list[str]:
    """Load targets from a file (one domain per line, # comments ignored)."""
    path = Path(targets_file)
    if not path.exists():
        console.print(f"[red]Error:[/red] Targets file not found: {targets_file}")
        return []

    domains: list[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)

    if not domains:
        console.print(f"[yellow]Warning:[/yellow] No valid targets found in {targets_file}")
        return []

    console.print(f"Loaded [green]{len(domains)}[/green] targets from [cyan]{targets_file}[/cyan]")
    return domains


async def run_batch_scan(
    domains: list[str],
    output_dir: Optional[Path] = None,
    max_concurrency: int = 1,
    # Pass-through params for run_scan
    ports: Optional[list[int]] = None,
    brute_force: bool = True,
    wordlist_path: Optional[str] = None,
    max_workers_subdomain: int = 50,
    max_workers_port: int = 100,
    port_timeout: float = 2.0,
    json_output: bool = True,
    markdown_output: bool = True,
    enable_http_probe: bool = True,
    enable_screenshots: bool = False,
    use_masscan: bool = False,
    masscan_rate: int = 1000,
    vt_api_key: Optional[str] = None,
    st_api_key: Optional[str] = None,
    enable_crawling: bool = False,
    crawl_max_depth: int = 2,
    crawl_max_pages: int = 50,
    enable_dirbuster: bool = False,
    dirbuster_wordlist: Optional[str] = None,
    dirbuster_extensions: Optional[str] = None,
    enable_enrichment: bool = True,
    shodan_api_key: Optional[str] = None,
    nvd_api_key: Optional[str] = None,
    enable_html: bool = False,
    enable_advanced_subdomains: bool = False,
    enable_zone_transfer: bool = True,
    enable_permutations: bool = True,
    enable_recursive: bool = True,
    recursive_max_depth: int = 2,
    max_permutation_candidates: int = 5000,
    enable_version_detection: bool = False,
    enable_os_fingerprinting: bool = False,
    top_1000: bool = False,
    # Phase 2 Feature 6: Quality of Life
    delay: float = 0.0,
    rate_limit: Optional[int] = None,
    proxy_url: Optional[str] = None,
    tor: bool = False,
    resume: bool = False,
    # Phase 3: Vulnerability Assessment
    enable_vuln_scan: bool = False,
    check_default_creds: bool = True,
    # Phase 3: SSL/TLS Audit
    enable_ssl_audit: bool = False,
    ssl_ports: Optional[list[int]] = None,
    # Phase 3: Subdomain Takeover Detection
    enable_takeover: bool = False,
    # Phase 3: WAF Detection
    enable_waf_detect: bool = False,
    enable_active_waf: bool = True,
    # Phase 4: Exploitation Integration
    enable_exploit_suggest: bool = False,
    enable_payload_gen: bool = False,
    payload_type: str = "auto",
    payload_encode: bool = False,
    enable_loot: bool = False,
    enable_msf_gen: bool = False,
    lhost: str = "127.0.0.1",
    lport: int = 4444,
) -> dict[str, dict]:
    """Run scans for multiple domains sequentially or with limited concurrency.

    Returns a dict mapping each domain to its report dict.
    """
    # Use a semaphore to limit concurrency
    sem = asyncio.Semaphore(max_concurrency)

    async def scan_domain(domain: str) -> tuple[str, dict]:
        async with sem:
            console.print(f"\n[bold cyan]═══ Target {domains.index(domain) + 1}/{len(domains)}: {domain} ═══[/bold cyan]\n")
            start_time = datetime.now()
            try:
                report = await run_scan(
                    domain=domain,
                    ports=ports,
                    brute_force=brute_force,
                    wordlist_path=wordlist_path,
                    max_workers_subdomain=max_workers_subdomain,
                    max_workers_port=max_workers_port,
                    port_timeout=port_timeout,
                    output_dir=output_dir / domain.replace(".", "_") if output_dir else None,
                    json_output=json_output,
                    markdown_output=markdown_output,
                    enable_http_probe=enable_http_probe,
                    enable_screenshots=enable_screenshots,
                    use_masscan=use_masscan,
                    masscan_rate=masscan_rate,
                    vt_api_key=vt_api_key,
                    st_api_key=st_api_key,
                    enable_crawling=enable_crawling,
                    crawl_max_depth=crawl_max_depth,
                    crawl_max_pages=crawl_max_pages,
                    enable_dirbuster=enable_dirbuster,
                    dirbuster_wordlist=dirbuster_wordlist,
                    dirbuster_extensions=dirbuster_extensions,
                    enable_enrichment=enable_enrichment,
                    shodan_api_key=shodan_api_key,
                    nvd_api_key=nvd_api_key,
                    enable_html=enable_html,
                    enable_advanced_subdomains=enable_advanced_subdomains,
                    enable_zone_transfer=enable_zone_transfer,
                    enable_permutations=enable_permutations,
                    enable_recursive=enable_recursive,
                    recursive_max_depth=recursive_max_depth,
                    max_permutation_candidates=max_permutation_candidates,
                    enable_version_detection=enable_version_detection,
                    enable_os_fingerprinting=enable_os_fingerprinting,
                    top_1000=top_1000,
                    delay=delay,
                    rate_limit=rate_limit,
                    proxy_url=proxy_url,
                    tor=tor,
                    resume=resume,
                    enable_vuln_scan=enable_vuln_scan,
                    check_default_creds=check_default_creds,
                    enable_ssl_audit=enable_ssl_audit,
                    ssl_ports=ssl_ports,
                    enable_takeover=enable_takeover,
                    enable_waf_detect=enable_waf_detect,
                    enable_active_waf=enable_active_waf,
                    enable_exploit_suggest=enable_exploit_suggest,
                    enable_payload_gen=enable_payload_gen,
                    payload_type=payload_type,
                    payload_encode=payload_encode,
                    enable_loot=enable_loot,
                    enable_msf_gen=enable_msf_gen,
                    lhost=lhost,
                    lport=lport,
                )
                elapsed = (datetime.now() - start_time).total_seconds()
                console.print(f"[bold green]✓[/bold green] {domain} completed in {elapsed:.1f}s\n")
                return domain, report or {}
            except Exception as e:
                console.print(f"[red]✗[/red] {domain} failed: {e}\n")
                return domain, {"error": str(e)}

    tasks = [scan_domain(d) for d in domains]
    results: dict[str, dict] = {}

    for completed in asyncio.as_completed(tasks):
        domain, report = await completed
        results[domain] = report

    return results
