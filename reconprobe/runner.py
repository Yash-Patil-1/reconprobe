"""Main scan orchestrator.

Ties together subdomain enumeration, port scanning, HTTP probing,
enrichment (Shodan/NVD), crawling, directory brute-force, screenshot capture,
and reporting into a single pipeline. Supports checkpointing for resume,
rate limiting, and proxy/Tor routing.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from reconprobe.http_probe import probe_host
from reconprobe.html_reporter import generate_html_report
from reconprobe.reporter import build_full_report, output_json, output_markdown
from reconprobe.reporting import run_reporting_enhancements
from reconprobe.scanner import scan_host, scan_host_masscan, scan_host_advanced, get_scan_ports
from reconprobe.screenshot import capture_host_screenshots
from reconprobe.subdomain import enumerate_subdomains, SubdomainReport, SubdomainResult
from reconprobe.checkpoint import ScanCheckpoint
from reconprobe.utils import is_valid_domain
from reconprobe.webhook import WebhookConfig, dispatch_webhooks, build_summary_from_report

import os

console = Console()

# Standard HTTP/HTTPS ports to probe
HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 9090, 9443]

# Phase definitions (1-indexed)
PHASE_NAMES = {
    1: "Subdomain Enumeration",
    2: "Port Scanning",
    3: "HTTP Probing",
    4: "Enrichment (Shodan/NVD)",
    5: "Crawling",
    6: "Directory Brute-Force",
    7: "Screenshots",
    8: "Reporting",
    # Phase 3: Vulnerability Assessment
    9: "Vulnerability Scan (CVE mapping + default creds)",
    10: "SSL/TLS Audit",
    11: "Subdomain Takeover Detection",
    12: "WAF Detection & Fingerprinting",
    # Phase 4: Exploitation Integration
    13: "Exploit Suggestion",
    14: "Payload Generation",
    15: "Loot Collection",
    16: "MSF Resource Script Generation",
    # Phase 5: Advanced OSINT
    17: "Advanced OSINT",
    # Phase 6: Reporting Automation
    18: "Reporting Automation (PDF/CSV/XLSX/Summary)",
}

TOTAL_PHASES = 18


def _resolve_proxy(proxy_url: Optional[str] = None, tor: bool = False) -> Optional[str]:
    """Resolve the proxy URL from explicit proxy or Tor flag."""
    if tor:
        return "socks5://127.0.0.1:9050"
    return proxy_url


def _compute_delay(delay: float = 0.0, rate_limit: Optional[int] = None) -> float:
    """Compute effective delay in seconds from delay or rate_limit param."""
    if rate_limit and rate_limit > 0:
        return 1.0 / rate_limit
    return delay


async def run_scan(
    domain: str,
    ports: Optional[list[int]] = None,
    brute_force: bool = True,
    wordlist_path: Optional[str] = None,
    max_workers_subdomain: int = 50,
    max_workers_port: int = 100,
    port_timeout: float = 2.0,
    output_dir: Optional[Path] = None,
    json_output: bool = True,
    markdown_output: bool = True,
    enable_http_probe: bool = True,
    enable_screenshots: bool = False,
    use_masscan: bool = False,
    masscan_rate: int = 1000,
    vt_api_key: Optional[str] = None,
    st_api_key: Optional[str] = None,
    # Phase 2 features
    enable_crawling: bool = False,
    crawl_max_depth: int = 2,
    crawl_max_pages: int = 50,
    enable_dirbuster: bool = False,
    dirbuster_wordlist: Optional[str] = None,
    dirbuster_extensions: Optional[str] = None,
    # Phase 2 Feature 2: API Integrations
    enable_enrichment: bool = True,
    shodan_api_key: Optional[str] = None,
    nvd_api_key: Optional[str] = None,
    # Phase 2 Feature 3: Enhanced Reporting
    enable_html: bool = False,
    # Phase 2 Feature 4: Advanced Subdomain Techniques
    enable_advanced_subdomains: bool = False,
    enable_zone_transfer: bool = True,
    enable_permutations: bool = True,
    enable_recursive: bool = True,
    recursive_max_depth: int = 2,
    max_permutation_candidates: int = 5000,
    # Phase 2 Feature 5: Smarter Port Scanning
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
    # Phase 5: Advanced OSINT
    enable_osint: bool = False,
    github_token: Optional[str] = None,
    enable_github_dork: bool = True,
    enable_google_dorks: bool = True,
    enable_email_harvest: bool = True,
    enable_whois: bool = True,
    enable_social_footprint: bool = True,
    enable_breach_check: bool = True,
    enable_tech_osint: bool = True,
    # Phase 6: Reporting Automation
    enable_pdf_report: bool = False,
    enable_csv_export: bool = False,
    enable_xlsx_export: bool = False,
    enable_executive_summary: bool = False,
    # Phase 7: CI/CD & Automation
    webhook_config: Optional[WebhookConfig] = None,
) -> dict:
    """Run a full reconnaissance scan against the given domain.

    Steps:
     1. Validate domain
     2. Enumerate subdomains (passive + optional brute-force)
     3. Port scan resolved subdomains
     4. HTTP probe discovered web services
     5. Enrich with Shodan + NVD (optional)
     6. Crawl discovered HTTP services (optional)
     7. Directory brute-force on discovered web roots (optional)
     8. Screenshot capture (optional)
     9. Generate reports
    10. Vulnerability scan (CVE mapping + default creds) — Phase 3
    11. SSL/TLS audit (cert, protocols, ciphers, headers) — Phase 3
    12. Subdomain takeover detection (dangling DNS + HTTP) — Phase 3
    13. WAF detection & fingerprinting — Phase 3
    """
    if not is_valid_domain(domain):
        console.print(f"[bold red]Error:[/bold red] Invalid domain: {domain}")
        return {}

    start_time = datetime.now()
    console.print(f"[bold cyan]ReconProbe[/bold cyan] — Scanning [bold]{domain}[/bold]")
    console.print("")

    # Resolve proxy and delay settings
    effective_proxy = _resolve_proxy(proxy_url, tor)
    effective_delay = _compute_delay(delay, rate_limit)

    if effective_proxy:
        console.print(f"  [dim]Proxy: {effective_proxy}[/dim]")
    if effective_delay > 0:
        console.print(f"  [dim]Delay: {effective_delay}s between requests[/dim]")

    # Initialize checkpoint (requires output_dir for writing)
    checkpoint = None
    if output_dir:
        checkpoint = ScanCheckpoint(domain, output_dir)
        if resume and checkpoint.exists:
            console.print(f"  [yellow]Resuming from checkpoint: {checkpoint}[/yellow]")
        elif resume and not checkpoint.exists:
            console.print("  [yellow]No checkpoint found, starting fresh scan[/yellow]")

    # ─────────────────────────────────────────────────────────────────
    # Phase 1: Subdomain Enumeration
    # ─────────────────────────────────────────────────────────────────
    subdomain_report = SubdomainReport(domain=domain)
    advanced_report: Optional[dict] = None

    if checkpoint and checkpoint.is_phase_completed(1):
        console.print("[dim]Phase 1/8: Subdomain Enumeration — [green]✓ already completed[/green][/dim]")
        # Restore phase data
        phase_data = checkpoint.get_phase_data(1)
        if phase_data:
            subdomain_report_data = phase_data.get("subdomain_report")
            if subdomain_report_data:
                subdomain_report = SubdomainReport(
                    domain=subdomain_report_data.get("domain", domain),
                    results=[
                        SubdomainResult(**r) for r in subdomain_report_data.get("results", [])
                    ] if subdomain_report_data.get("results") else [],
                    total_found=subdomain_report_data.get("total_found", 0),
                    total_resolved=subdomain_report_data.get("total_resolved", 0),
                )
            advanced_report = phase_data.get("advanced_report")
    else:
        console.print("[yellow]Phase 1/8:[/yellow] Enumerating subdomains...")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Querying passive sources + brute-force...", total=None)

            subdomain_report, advanced_report = await enumerate_subdomains(
                domain=domain,
                brute_force=brute_force,
                wordlist_path=wordlist_path,
                max_workers=max_workers_subdomain,
                vt_api_key=vt_api_key,
                st_api_key=st_api_key,
                enable_advanced=enable_advanced_subdomains,
                enable_zone_transfer=enable_zone_transfer,
                enable_permutations=enable_permutations,
                enable_recursive=enable_recursive,
                recursive_max_depth=recursive_max_depth,
                max_permutation_candidates=max_permutation_candidates,
            )

            progress.update(task, completed=True)

        console.print(f"  Found [green]{subdomain_report.total_found}[/green] subdomains "
                      f"([green]{subdomain_report.total_resolved}[/green] resolved)")

        if advanced_report:
            if advanced_report.get("zone_transfer"):
                successful_zts = [zt for zt in advanced_report["zone_transfer"] if zt["success"]]
                if successful_zts:
                    console.print(f"  Zone Transfer: [green]{len(successful_zts)}[/green] nameservers allowed AXFR")
                else:
                    console.print("  Zone Transfer: [dim]no servers allowed transfer[/dim]")

            perms = advanced_report.get("permutations")
            if perms and perms["total_generated"] > 0:
                console.print(f"  Permutations: [green]{perms['total_generated']}[/green] candidates, "
                              f"[green]{perms['total_resolved']}[/green] resolved")

            rec = advanced_report.get("recursive")
            if rec:
                total_rec = sum(len(v) for v in rec.values())
                console.print(f"  Recursive: [green]{total_rec}[/green] subdomains found across {len(rec)} depth level(s)")

            total_new = advanced_report.get("total_new_subdomains", 0)
            if total_new > 0:
                console.print(f"  [yellow]Advanced techniques found {total_new} new subdomains[/yellow]")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=1,
                total_phases=TOTAL_PHASES,
                phase_name=PHASE_NAMES[1],
                data={
                    "phase_1": {
                        "subdomain_report": {
                            "domain": subdomain_report.domain,
                            "total_found": subdomain_report.total_found,
                            "total_resolved": subdomain_report.total_resolved,
                            "results": [
                                {"hostname": r.hostname, "ip_address": r.ip_address,
                                 "source": r.source, "resolved": r.resolved}
                                for r in subdomain_report.results
                            ],
                        },
                        "advanced_report": advanced_report,
                    }
                },
            )

    console.print("")

    resolved_hosts = [
        (r.hostname, r.ip_address)
        for r in subdomain_report.results
        if r.resolved and r.ip_address
    ]

    # ─────────────────────────────────────────────────────────────────
    # Phase 2: Port Scanning
    # ─────────────────────────────────────────────────────────────────
    scan_reports = []

    if checkpoint and checkpoint.is_phase_completed(2):
        console.print("[dim]Phase 2/8: Port Scanning — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(2)
        if phase_data:
            from reconprobe.scanner import HostScanReport, PortResult
            scan_reports_data = phase_data.get("scan_reports", [])
            for sr_data in scan_reports_data:
                hostname = sr_data.get("hostname", "")
                ip = sr_data.get("ip_address", "")
                hsr = HostScanReport(hostname=hostname, ip_address=ip)
                for p_data in sr_data.get("ports", []):
                    port_res = PortResult(
                        port=p_data.get("port", 0),
                        state=p_data.get("state", "closed"),
                        service=p_data.get("service", ""),
                        banner=p_data.get("banner"),
                        service_version=p_data.get("service_version"),
                        os_fingerprint=p_data.get("os_fingerprint"),
                    )
                    hsr.ports.append(port_res)
                    if port_res.is_open:
                        hsr.open_ports += 1
                hsr.ports.sort(key=lambda p: p.port)
                scan_reports.append(hsr)
    else:
        scan_label_extra = ""
        if enable_version_detection:
            scan_label_extra += " + version detection"
        if enable_os_fingerprinting:
            scan_label_extra += " + OS fingerprinting"
        if top_1000:
            scan_label_extra += " (top-1000)"
        console.print(f"[yellow]Phase 2/8:[/yellow] Scanning ports on resolved hosts{scan_label_extra}...")

        if resolved_hosts:
            if use_masscan:
                scan_fn: Callable[..., Any] = scan_host_masscan
                scan_label = "masscan"
            elif enable_version_detection or enable_os_fingerprinting:
                scan_fn = scan_host_advanced
                scan_label = "advanced"
            else:
                scan_fn = scan_host
                scan_label = "socket"

            scan_ports = get_scan_ports(ports, top_1000)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    f"Scanning {len(resolved_hosts)} hosts ({scan_label})...",
                    total=len(resolved_hosts),
                )

                for hostname, ip in resolved_hosts:
                    progress.update(task, description=f"Scanning [cyan]{hostname}[/cyan] ({ip})...")
                    try:
                        if use_masscan:
                            report = scan_fn(hostname=hostname, ip_address=ip, ports=scan_ports, rate=masscan_rate)
                        elif enable_version_detection or enable_os_fingerprinting:
                            report = scan_fn(
                                hostname=hostname, ip_address=ip, ports=scan_ports,
                                max_workers=max_workers_port, timeout=port_timeout,
                                enable_version_detection=enable_version_detection,
                                enable_os_fingerprinting=enable_os_fingerprinting,
                            )
                        else:
                            report = scan_fn(
                                hostname=hostname, ip_address=ip, ports=scan_ports,
                                max_workers=max_workers_port, timeout=port_timeout,
                            )
                        scan_reports.append(report)
                    except Exception as e:
                        console.print(f"  [red]Error scanning {hostname}: {e}[/red]")
                    progress.advance(task)

            total_open = sum(r.open_ports for r in scan_reports)
            console.print(f"  Found [green]{total_open}[/green] open ports across "
                          f"[green]{len(scan_reports)}[/green] hosts")
        else:
            console.print("  [yellow]No resolved hosts to scan.[/yellow]")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=2, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[2],
                data={"phase_2": {"scan_reports": [r.to_dict() for r in scan_reports]}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 3: HTTP Probing
    # ─────────────────────────────────────────────────────────────────
    http_probe_reports = {}

    if checkpoint and checkpoint.is_phase_completed(3):
        console.print("[dim]Phase 3/8: HTTP Probing — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(3)
        if phase_data:
            http_data = phase_data.get("http_probe_reports", {})
            for hostname, report_data in http_data.items():
                from reconprobe.http_probe import HttpProbeReport, HttpProbeResult
                hpr = HttpProbeReport(hostname=hostname)
                for r_data in report_data.get("results", []):
                    http_result = HttpProbeResult(
                        url=r_data.get("url", ""),
                        status_code=r_data.get("status_code", 0),
                        title=r_data.get("title", ""),
                        server_header=r_data.get("server", ""),
                        content_type=r_data.get("content_type", ""),
                        technologies=r_data.get("technologies", []),
                        error=r_data.get("error"),
                    )
                    hpr.results.append(http_result)
                    if http_result.is_alive:
                        hpr.alive_count += 1
                http_probe_reports[hostname] = hpr
    elif enable_http_probe and scan_reports:
        console.print("[yellow]Phase 3/8:[/yellow] Probing HTTP services...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Probing HTTP on {len(scan_reports)} hosts...", total=len(scan_reports))

            for scan_report in scan_reports:
                hostname = scan_report.hostname
                progress.update(task, description=f"Probing [cyan]{hostname}[/cyan]...")

                probe_ports = HTTP_PORTS
                if ports is not None:
                    probe_ports = list(set(HTTP_PORTS) | set(ports))
                http_ports = [p.port for p in scan_report.ports if p.is_open and p.port in probe_ports]

                if http_ports:
                    try:
                        probe_report = await probe_host(
                            hostname=hostname,
                            ports=http_ports,
                            timeout=10.0,
                            delay=effective_delay,
                            proxy_url=effective_proxy,
                        )
                        http_probe_reports[hostname] = probe_report
                        for r in probe_report.results:
                            if r.is_alive:
                                tech_str = ", ".join(t["name"] for t in r.technologies[:5])
                                console.print(
                                    f"    {r.url} → [{r.status_code}] [white]{r.title}[/white]"
                                    f"{' | ' + tech_str if tech_str else ''}"
                                )
                    except Exception as e:
                        console.print(f"  [red]Error probing {hostname}: {e}[/red]")

                progress.advance(task)

        # Save checkpoint
        if checkpoint:
            http_checkpoint_data = {}
            for hostname, hpr in http_probe_reports.items():
                http_checkpoint_data[hostname] = hpr.to_dict()
            checkpoint.save(
                phase=3, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[3],
                data={"phase_3": {"http_probe_reports": http_checkpoint_data}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 4: Enrichment (Shodan + NVD)
    # ─────────────────────────────────────────────────────────────────
    enrichment_report_data = {}

    if checkpoint and checkpoint.is_phase_completed(4):
        console.print("[dim]Phase 4/8: Enrichment — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(4)
        if phase_data:
            enrichment_report_data = phase_data.get("enrichment_report", {})
    elif enable_enrichment:
        console.print("[yellow]Phase 4/8:[/yellow] Enriching with external API sources...")

        all_ips: list[str] = []
        seen_ips: set[str] = set()
        for scan_report in scan_reports:
            ip = scan_report.ip_address
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                all_ips.append(ip)

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task("Running enrichment...", total=None)
            from reconprobe.enrichment import run_enrichment

            enrichment_obj = await run_enrichment(
                ip_addresses=all_ips,
                http_probe_reports=http_probe_reports,
                enable_shodan=True,
                enable_nvd=True,
                shodan_api_key=shodan_api_key,
                nvd_api_key=nvd_api_key,
                proxy_url=effective_proxy,
                delay=effective_delay,
            )
            enrichment_report_data = enrichment_obj.to_dict() if hasattr(enrichment_obj, "to_dict") else {}
            progress.update(task, completed=True)

        # Display Shodan summary
        shodan_results_data = enrichment_report_data.get("shodan", {}).get("results", {})
        if shodan_results_data:
            total_vulns = sum(len(r.get("vulns", [])) for r in shodan_results_data.values())
            console.print(f"  Shodan: [green]{len(shodan_results_data)}[/green] IPs enriched, "
                          f"[yellow]{total_vulns}[/yellow] CVEs found")
            for ip, sr_data in shodan_results_data.items():
                org = sr_data.get("org", "") or sr_data.get("isp", "")
                if org:
                    port_count = len(sr_data.get("open_ports", []))
                    vuln_count = len(sr_data.get("vulns", []))
                    parts = [f"    {ip} → [white]{org}[/white]"]
                    if port_count:
                        parts.append(f" ({port_count} ports)")
                    if vuln_count:
                        parts.append(f" | {vuln_count} CVEs")
                    console.print("".join(parts))
        else:
            key_present = bool(shodan_api_key or os.environ.get("SHODAN_API_KEY"))
            if not key_present:
                console.print("  [dim]Shodan: no API key provided (set SHODAN_API_KEY)[/dim]")
            else:
                console.print("  [yellow]Shodan: no results returned[/yellow]")

        # Display NVD summary
        cve_results_list = enrichment_report_data.get("cve_lookup", {}).get("results", [])
        if cve_results_list:
            high_critical = sum(1 for c in cve_results_list if c.get("cvss_severity", "").upper() in ("HIGH", "CRITICAL"))
            console.print(f"  NVD: [red]{len(cve_results_list)}[/red] CVEs found "
                          f"([bold red]{high_critical}[/bold red] high/critical)")
            for cve in cve_results_list[:10]:
                sev = cve.get("cvss_severity", "")
                sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "dim"
                console.print(f"    [{sev_color}]{cve.get('cve_id', '')}[/{sev_color}] "
                              f"(CVSS {cve.get('cvss_score', '')}) — "
                              f"{cve.get('description', '')[:120]}")
            if len(cve_results_list) > 10:
                console.print(f"    ... and {len(cve_results_list) - 10} more")
        else:
            key_present = bool(nvd_api_key or os.environ.get("NVD_API_KEY"))
            if not key_present:
                console.print("  [dim]NVD: no API key provided (set NVD_API_KEY for higher rate limits)[/dim]")
            console.print("  [dim]NVD: no CVEs found for detected technologies[/dim]")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=4, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[4],
                data={"phase_4": {"enrichment_report": enrichment_report_data}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 5: Crawling
    # ─────────────────────────────────────────────────────────────────
    crawl_reports = {}

    if checkpoint and checkpoint.is_phase_completed(5):
        console.print("[dim]Phase 5/8: Crawling — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(5)
        if phase_data:
            crawl_data = phase_data.get("crawl_reports", {})
            for hostname, cr_data in crawl_data.items():
                from reconprobe.crawler import CrawlReport, CrawledPage
                cr = CrawlReport(hostname=hostname, base_url=cr_data.get("base_url", ""))
                for p_data in cr_data.get("pages", []):
                    page = CrawledPage(
                        url=p_data.get("url", ""),
                        status_code=p_data.get("status_code", 0),
                        content_type=p_data.get("content_type", ""),
                        title=p_data.get("title", ""),
                        depth=p_data.get("depth", 0),
                        error=p_data.get("error"),
                    )
                    cr.pages.append(page)
                cr.total_pages = cr_data.get("total_pages", 0)
                cr.total_links = cr_data.get("total_links", 0)
                cr.total_scripts = cr_data.get("total_scripts", 0)
                cr.total_forms = cr_data.get("total_forms", 0)
                cr.unique_urls = cr_data.get("unique_urls", [])
                cr.interesting_findings = cr_data.get("interesting_findings", [])
                crawl_reports[hostname] = cr
    elif enable_crawling and http_probe_reports:
        console.print("[yellow]Phase 5/8:[/yellow] Crawling discovered web services...")

        crawl_targets: list[tuple[str, str, list[int]]] = []
        for hostname, probe_report in http_probe_reports.items():
            for result in probe_report.results:
                if result.is_alive:
                    crawl_targets.append((hostname, result.url, []))
                    break

        if crawl_targets:
            from reconprobe.crawler import crawl_hosts as run_crawls

            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(), console=console,
            ) as progress:
                task = progress.add_task(
                    f"Crawling {len(crawl_targets)} host(s) (depth={crawl_max_depth})...",
                    total=len(crawl_targets),
                )

                crawl_reports = await run_crawls(
                    host_urls=crawl_targets,
                    max_depth=crawl_max_depth,
                    max_pages_per_host=crawl_max_pages,
                    delay=effective_delay or 0.1,
                    timeout=10.0,
                    proxy_url=effective_proxy,
                )

                progress.update(task, completed=True)

            total_crawled = sum(r.total_pages for r in crawl_reports.values())
            total_findings = sum(len(r.interesting_findings) for r in crawl_reports.values())
            console.print(f"  Crawled [green]{total_crawled}[/green] pages across "
                          f"[green]{len(crawl_reports)}[/green] hosts")
            if total_findings:
                sensitive_count = sum(
                    1 for item in [f for r in crawl_reports.values() for f in r.interesting_findings]
                    if item['type'] == 'sensitive_url'
                )
                email_count = sum(
                    1 for item in [f for r in crawl_reports.values() for f in r.interesting_findings]
                    if item['type'] == 'email_address'
                )
                console.print(f"  Found [yellow]{total_findings}[/yellow] interesting findings "
                              f"({sensitive_count} sensitive, {email_count} emails)")
        else:
            console.print("  [yellow]No live HTTP services to crawl.[/yellow]")

        # Save checkpoint
        if checkpoint:
            crawl_checkpoint_data = {}
            for hostname, cr in crawl_reports.items():
                crawl_checkpoint_data[hostname] = cr.to_dict()
            checkpoint.save(
                phase=5, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[5],
                data={"phase_5": {"crawl_reports": crawl_checkpoint_data}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 6: Directory Brute-Force
    # ─────────────────────────────────────────────────────────────────
    dirbuster_reports: dict[str, Any] = {}

    if checkpoint and checkpoint.is_phase_completed(6):
        console.print("[dim]Phase 6/8: Directory Brute-Force — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(6)
        if phase_data:
            dirb_data = phase_data.get("dirbuster_reports", {})
            for hostname, dbr_data in dirb_data.items():
                from reconprobe.dirbuster import DirBusterReport, DirBusterResult
                dbr = DirBusterReport(
                    base_url=dbr_data.get("base_url", ""),
                    hostname=hostname,
                )
                for r_data in dbr_data.get("results", []):
                    dirb_result = DirBusterResult(
                        url=r_data.get("url", ""),
                        status_code=r_data.get("status_code", 0),
                        content_length=r_data.get("content_length", 0),
                        redirect_url=r_data.get("redirect_url", ""),
                        content_type=r_data.get("content_type", ""),
                        title=r_data.get("title", ""),
                        error=r_data.get("error"),
                    )
                    dbr.results.append(dirb_result)
                    if dirb_result.is_interesting:
                        dbr.total_found += 1
                        cat = dirb_result.status_category
                        if cat in dbr.findings_by_type:
                            dbr.findings_by_type[cat] += 1
                dbr.total_scanned = dbr_data.get("total_scanned", 0)
                dirbuster_reports[hostname] = dbr
    elif enable_dirbuster and http_probe_reports:
        console.print("[yellow]Phase 6/8:[/yellow] Brute-forcing directories...")

        host_base_urls: list[tuple[str, str]] = []
        for hostname, probe_report in http_probe_reports.items():
            for result in probe_report.results:
                if result.is_alive:
                    from urllib.parse import urlparse
                    parsed = urlparse(result.url)
                    base = f"{parsed.scheme}://{parsed.hostname}"
                    host_base_urls.append((hostname, base))
                    break

        if host_base_urls:
            from reconprobe.dirbuster import brute_force_hosts as run_dirbuster

            parsed_extensions: Optional[list[str]] = None
            if dirbuster_extensions:
                parsed_extensions = [f".{e.strip().lstrip('.')}" for e in dirbuster_extensions.split(",")]

            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(), console=console,
            ) as progress:
                task = progress.add_task(f"Spraying paths on {len(host_base_urls)} host(s)...", total=len(host_base_urls))
                loop = asyncio.get_running_loop()
                dirbuster_reports = await loop.run_in_executor(
                    None, run_dirbuster,
                    host_base_urls, dirbuster_wordlist, 20, 5.0, parsed_extensions, effective_delay, effective_proxy,
                )
                progress.update(task, completed=True)

            total_found = sum(r.total_found for r in dirbuster_reports.values())
            console.print(f"  Scanned [green]{sum(r.total_scanned for r in dirbuster_reports.values())}[/green] paths, "
                          f"found [green]{total_found}[/green] interesting")
            status_totals: dict[str, int] = {}
            for r in dirbuster_reports.values():
                for cat, count in r.findings_by_type.items():
                    status_totals[cat] = status_totals.get(cat, 0) + count
            parts = [f"[green]{count} {cat}[/green]" for cat, count in status_totals.items() if count > 0]
            if parts:
                console.print(f"  ({', '.join(parts)})")
        else:
            console.print("  [yellow]No live HTTP services to scan.[/yellow]")

        # Save checkpoint
        if checkpoint:
            dirb_checkpoint_data = {}
            for hostname, dbr in dirbuster_reports.items():
                dirb_checkpoint_data[hostname] = dbr.to_dict()
            checkpoint.save(
                phase=6, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[6],
                data={"phase_6": {"dirbuster_reports": dirb_checkpoint_data}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 7: Screenshots
    # ─────────────────────────────────────────────────────────────────
    screenshot_reports: dict[str, Any] = {}

    if checkpoint and checkpoint.is_phase_completed(7):
        console.print("[dim]Phase 7/8: Screenshots — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(7)
        if phase_data:
            ss_data = phase_data.get("screenshot_reports", {})
            for hostname, sr_data in ss_data.items():
                from reconprobe.screenshot import ScreenshotReport, ScreenshotResult
                ss_report = ScreenshotReport(hostname=hostname)
                for s_data in sr_data.get("screenshots", []):
                    s_result = ScreenshotResult(
                        url=s_data.get("url", ""),
                        file_path=s_data.get("file_path"),
                        success=s_data.get("success", False),
                        error=s_data.get("error"),
                    )
                    ss_report.screenshots.append(s_result)
                    if s_result.success:
                        ss_report.total_taken += 1
                    else:
                        ss_report.total_failed += 1
                screenshot_reports[hostname] = ss_report
    elif enable_screenshots and http_probe_reports and output_dir:
        console.print("[yellow]Phase 7/8:[/yellow] Capturing screenshots...")

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task(f"Taking screenshots of {len(http_probe_reports)} hosts...", total=len(http_probe_reports))

            for hostname, probe_report in http_probe_reports.items():
                progress.update(task, description=f"Screenshotting [cyan]{hostname}[/cyan]...")
                try:
                    ss_report = await capture_host_screenshots(
                        hostname=hostname,
                        probe_results=probe_report.results,
                        output_dir=output_dir / "screenshots",
                        timeout=30.0,
                    )
                    screenshot_reports[hostname] = ss_report
                    console.print(
                        f"    [green]{ss_report.total_taken}[/green] screenshots taken "
                        f"{'([red]' + str(ss_report.total_failed) + ' failed[/red])' if ss_report.total_failed else ''}"
                    )
                except Exception as e:
                    console.print(f"  [red]Error screenshotting {hostname}: {e}[/red]")
                progress.advance(task)

        # Save checkpoint
        if checkpoint:
            ss_checkpoint_data = {}
            for hostname, sr in screenshot_reports.items():
                ss_checkpoint_data[hostname] = sr.to_dict()
            checkpoint.save(
                phase=7, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[7],
                data={"phase_7": {"screenshot_reports": ss_checkpoint_data}},
            )

    console.print("")

    # ═════════════════════════════════════════════════════════════════
    # Phase 3 — Vulnerability Assessment (Phases 9-12)
    # ═════════════════════════════════════════════════════════════════

    # ─────────────────────────────────────────────────────────────────
    # Phase 9: Vulnerability Scan (CVE mapping + default creds)
    # ─────────────────────────────────────────────────────────────────
    vuln_scan_report_data = {}

    if checkpoint and checkpoint.is_phase_completed(9):
        console.print("[dim]Phase 9/12: Vulnerability Scan — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(9)
        if phase_data:
            vuln_scan_report_data = phase_data.get("vuln_scan_report", {})
    elif enable_vuln_scan:
        console.print("[yellow]Phase 9/12:[/yellow] Running vulnerability scan...")

        console.print("  Mapping detected services to known CVEs...")
        from reconprobe.vuln_scan import run_vuln_scan

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task("Scanning for vulnerabilities...", total=None)

            vuln_report = await run_vuln_scan(
                scan_reports=scan_reports,
                http_probe_reports=http_probe_reports,
                check_credentials=check_default_creds,
            )
            vuln_scan_report_data = vuln_report.to_dict()
            progress.update(task, completed=True)

        # Summary output
        if vuln_scan_report_data.get("total_cves", 0) > 0:
            cves = vuln_scan_report_data.get("cve_matches", [])
            high_crit = sum(1 for c in cves if c.get("cvss_severity", "").upper() in ("HIGH", "CRITICAL"))
            console.print(f"  CVE Matches: [red]{len(cves)}[/red] total "
                          f"([bold red]{high_crit}[/bold red] high/critical)")
            for cve in cves[:8]:
                sev = cve.get("cvss_severity", "")
                sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "dim"
                console.print(f"    [{sev_color}]{cve['cve_id']}[/{sev_color}] "
                              f"(CVSS {cve.get('cvss_score', '')}) — "
                              f"{cve.get('description', '')[:100]}")
            if len(cves) > 8:
                console.print(f"    ... and {len(cves) - 8} more")
        else:
            console.print("  [dim]No CVE matches found for detected services[/dim]")

        cred_count = vuln_scan_report_data.get("total_creds", 0)
        if cred_count > 0:
            console.print(f"  [yellow]{cred_count} default/weak credential(s) found![/yellow]")
            for cred in vuln_scan_report_data.get("default_credentials", []):
                console.print(f"    {cred['service']}:{cred['port']} — "
                              f"{cred['username']} / {cred['password']}")
        else:
            console.print("  [dim]No default credentials detected[/dim]")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=9, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[9],
                data={"phase_9": {"vuln_scan_report": vuln_scan_report_data}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 10: SSL/TLS Audit
    # ─────────────────────────────────────────────────────────────────
    ssl_audit_report_data = {}

    if checkpoint and checkpoint.is_phase_completed(10):
        console.print("[dim]Phase 10/12: SSL/TLS Audit — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(10)
        if phase_data:
            ssl_audit_report_data = phase_data.get("ssl_audit_report", {})
    elif enable_ssl_audit:
        console.print("[yellow]Phase 10/12:[/yellow] Auditing SSL/TLS services...")

        # Collect HTTPS services from HTTP probe results
        ssl_targets: list[tuple[str, int]] = []
        default_ssl_ports = ssl_ports or [443, 8443, 9443]

        # Add from port scan results
        for scan_report in scan_reports:
            hostname = scan_report.hostname
            for p in scan_report.ports:
                if p.is_open and p.port in default_ssl_ports:
                    ssl_targets.append((hostname, p.port))

        # Also add from HTTP probe results (URLs that use HTTPS)
        for hostname, probe_report in http_probe_reports.items():
            for result in probe_report.results:
                if result.is_alive and result.url.startswith("https://"):
                    from urllib.parse import urlparse
                    parsed = urlparse(result.url)
                    port = parsed.port or 443
                    if (hostname, port) not in ssl_targets:
                        ssl_targets.append((hostname, port))

        if ssl_targets:
            from reconprobe.ssl_audit import audit_ssl_hosts

            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TimeElapsedColumn(), console=console,
            ) as progress:
                task = progress.add_task(f"Auditing SSL on {len(ssl_targets)} host:port(s)...", total=None)

                ssl_results = await audit_ssl_hosts(
                    hosts=ssl_targets,
                    check_protos=True,
                    check_ciphers=True,
                    check_headers=True,
                    proxy_url=effective_proxy,
                    max_concurrent=5,
                )
                ssl_audit_report_data = {
                    "total_audited": len(ssl_results),
                    "results": {
                        key: r.to_dict() for key, r in ssl_results.items()
                    },
                }
                progress.update(task, completed=True)

            # Summary
            grades: dict[str, int] = {}
            total_issues = 0
            for key, ssl_report in ssl_results.items():
                grades[ssl_report.grade] = grades.get(ssl_report.grade, 0) + 1
                total_issues += ssl_report.total_issues

            grade_str = ", ".join(f"{g}: {c}" for g, c in sorted(grades.items()))
            console.print(f"  Audited [green]{len(ssl_results)}[/green] TLS endpoints")
            console.print(f"  Grades: {grade_str}")
            console.print(f"  Total issues: [yellow]{total_issues}[/yellow]")

            # Show expired/self-signed certs
            for key, ssl_report in ssl_results.items():
                if ssl_report.certificate:
                    cert = ssl_report.certificate
                    if cert.is_expired:
                        console.print(f"    [red]Expired certificate[/red] on {key}")
                    if cert.is_self_signed:
                        console.print(f"    [yellow]Self-signed certificate[/yellow] on {key}")
                    if cert.will_expire_soon:
                        console.print(f"    [yellow]Certificate expiring soon ({cert.days_remaining}d)[/yellow] on {key}")

            # Show supported outdated protocols
            for key, ssl_report in ssl_results.items():
                for proto in ssl_report.protocols:
                    if proto.protocol in ("TLS 1.0", "TLS 1.1") and proto.supported:
                        console.print(f"    [red]{proto.protocol} supported[/red] on {key} — should be disabled")
        else:
            console.print("  [yellow]No HTTPS services found to audit.[/yellow]")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=10, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[10],
                data={"phase_10": {"ssl_audit_report": ssl_audit_report_data}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 11: Subdomain Takeover Detection
    # ─────────────────────────────────────────────────────────────────
    takeover_report_data = {}

    if checkpoint and checkpoint.is_phase_completed(11):
        console.print("[dim]Phase 11/12: Subdomain Takeover — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(11)
        if phase_data:
            takeover_report_data = phase_data.get("takeover_report", {})
    elif enable_takeover:
        console.print("[yellow]Phase 11/12:[/yellow] Checking for subdomain takeovers...")

        # Collect all resolved hostnames from subdomain enumeration
        subdomain_hostnames = [
            r.hostname for r in subdomain_report.results
            if r.resolved and r.ip_address
        ]

        if subdomain_hostnames:
            from reconprobe.takeover import scan_takeovers

            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TimeElapsedColumn(), console=console,
            ) as progress:
                task = progress.add_task(
                    f"Scanning {len(subdomain_hostnames)} subdomains for takeovers...", total=None
                )

                takeover_report = await scan_takeovers(
                    subdomains=subdomain_hostnames,
                    max_concurrent=20,
                )
                takeover_report_data = takeover_report.to_dict()
                progress.update(task, completed=True)

            vulnerable_count = takeover_report_data.get("total_vulnerable", 0)
            if vulnerable_count > 0:
                console.print(f"  [red]{vulnerable_count}[/red] potential takeover(s) detected!")
                for takeover_res in takeover_report.results:
                    if takeover_res.is_vulnerable:
                        console.print(
                            f"    [bold yellow]{takeover_res.hostname}[/bold yellow] — "
                            f"{takeover_res.service} ({takeover_res.confidence} confidence)"
                        )
            else:
                console.print(f"  [green]{len(subdomain_hostnames)}[/green] subdomains checked, "
                              "no takeovers detected")
        else:
            console.print("  [yellow]No resolved subdomains to check for takeovers.[/yellow]")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=11, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[11],
                data={"phase_11": {"takeover_report": takeover_report_data}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 12: WAF Detection & Fingerprinting
    # ─────────────────────────────────────────────────────────────────
    waf_report_data = {}

    if checkpoint and checkpoint.is_phase_completed(12):
        console.print("[dim]Phase 12/12: WAF Detection — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(12)
        if phase_data:
            waf_report_data = phase_data.get("waf_report", {})
    elif enable_waf_detect:
        console.print("[yellow]Phase 12/12:[/yellow] Detecting WAFs...")

        # Collect URLs from HTTP probe results
        waf_targets: list[str] = []
        for hostname, probe_report in http_probe_reports.items():
            for result in probe_report.results:
                if result.is_alive and result.url not in waf_targets:
                    waf_targets.append(result.url)

        if waf_targets:
            from reconprobe.waf_detect import detect_waf

            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TimeElapsedColumn(), console=console,
            ) as progress:
                task = progress.add_task(
                    f"Testing {len(waf_targets)} URL(s) for WAF presence...", total=None
                )

                waf_report = await detect_waf(
                    urls=waf_targets,
                    enable_active=enable_active_waf,
                    proxy_url=effective_proxy,
                    max_concurrent=5,
                )
                waf_report_data = waf_report.to_dict()
                progress.update(task, completed=True)

            # Summary
            protected_count = waf_report_data.get("total_protected", 0)
            if protected_count > 0:
                console.print(f"  [yellow]{protected_count}[/yellow] URL(s) behind WAF(s)")
                for url_str, waf_res in waf_report.results.items():
                    if waf_res.is_protected:
                        waf_names = [w["name"] for w in waf_res.detected_wafs]
                        console.print(f"    {url_str} → [cyan]{', '.join(waf_names)}[/cyan]")
            else:
                console.print(f"  [green]{len(waf_targets)}[/green] URL(s) checked, no WAF detected")
        else:
            console.print("  [yellow]No live HTTP services to check for WAFs.[/yellow]")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=12, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[12],
                data={"phase_12": {"waf_report": waf_report_data}},
            )

    console.print("")

    # ═════════════════════════════════════════════════════════════════
    # Phase 4 — Exploitation Integration (Phases 13-16)
    # ═════════════════════════════════════════════════════════════════

    # ─────────────────────────────────────────────────────────────────
    # Phase 13: Exploit Suggestion
    # ─────────────────────────────────────────────────────────────────
    exploit_report = None

    if checkpoint and checkpoint.is_phase_completed(13):
        console.print("[dim]Phase 13/16: Exploit Suggestion — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(13)
        if phase_data:
            exploit_report = phase_data.get("exploit_report")
    elif enable_exploit_suggest:
        console.print("[yellow]Phase 13/16:[/yellow] Generating exploit suggestions...")

        from reconprobe.exploit_suggest import suggest_exploits_from_scan

        # Build scan results dict from current data
        scan_results_dict = {
            "scanner_data": {},
            "http_probe_data": {},
            "enriched_data": enrichment_report_data,
        }

        for sr in scan_reports:
            scan_results_dict["scanner_data"][sr.hostname] = sr.to_dict()

        for hostname, hpr in http_probe_reports.items():
            scan_results_dict["http_probe_data"][hostname] = hpr.to_dict()

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task("Matching services to known exploits...", total=None)
            expl_report = await suggest_exploits_from_scan(
                scan_results=scan_results_dict,
                try_searchsploit=False,
            )
            exploit_report = {
                "total_suggestions": expl_report.total_count,
                "searchsploit_available": expl_report.searchsploit_available,
                "suggestions": [
                    {
                        "edb_id": s.edb_id,
                        "title": s.title,
                        "service": s.service,
                        "version_range": s.version_range,
                        "reliability": s.reliability,
                        "exploit_type": s.exploit_type,
                        "cve_id": s.cve_id,
                        "url": s.url,
                        "port": s.port,
                        "rank": s.rank,
                    }
                    for s in expl_report.suggestions
                ],
            }
            progress.update(task, completed=True)

        total_suggestions = exploit_report["total_suggestions"]
        high_reliability = sum(1 for s in exploit_report["suggestions"] if s["reliability"] == "high")
        if total_suggestions > 0:
            console.print(f"  Found [green]{total_suggestions}[/green] exploit suggestions "
                          f"([yellow]{high_reliability}[/yellow] high reliability)")
            for s in exploit_report["suggestions"][:8]:
                rel_color = "green" if s["reliability"] == "high" else "yellow" if s["reliability"] == "medium" else "dim"
                console.print(f"    [{rel_color}]{s['edb_id']}[/{rel_color}] — {s['title'][:80]}")
            if total_suggestions > 8:
                console.print(f"    ... and {total_suggestions - 8} more")
        else:
            console.print("  [dim]No exploit suggestions generated[/dim]")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=13, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[13],
                data={"phase_13": {"exploit_report": exploit_report}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 14: Payload Generation
    # ─────────────────────────────────────────────────────────────────
    payload_report = None

    if checkpoint and checkpoint.is_phase_completed(14):
        console.print("[dim]Phase 14/16: Payload Generation — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(14)
        if phase_data:
            payload_report = phase_data.get("payload_report")
    elif enable_payload_gen:
        console.print("[yellow]Phase 14/16:[/yellow] Generating payloads...")

        from reconprobe.payload_gen import generate_all_payloads

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task("Generating reverse shell payloads...", total=None)

            pay_report = await generate_all_payloads(
                lhost=lhost,
                lport=lport,
                encode=payload_encode,
                try_msfvenom=False,
            )

            payload_report = {
                "lhost": pay_report.lhost,
                "lport": pay_report.lport,
                "encode_available": pay_report.encode_available,
                "total_payloads": len(pay_report.payloads),
                "payloads": [
                    {
                        "type": p.type,
                        "command": p.command,
                        "listener_command": p.listener_command,
                        "encoded": p.encoded,
                        "encoded_command": p.encoded_command,
                        "description": p.description,
                    }
                    for p in pay_report.payloads
                ],
            }
            progress.update(task, completed=True)

        console.print(f"  Generated [green]{len(payload_report['payloads'])}[/green] payload types")
        for p in payload_report["payloads"]:
            console.print(f"    {p['type']}: {p['description']}")
            console.print(f"      Command: [dim]{p['command'][:80]}...[/dim]")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=14, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[14],
                data={"phase_14": {"payload_report": payload_report}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 15: Loot Collection
    # ─────────────────────────────────────────────────────────────────
    loot_report = None

    if checkpoint and checkpoint.is_phase_completed(15):
        console.print("[dim]Phase 15/16: Loot Collection — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(15)
        if phase_data:
            loot_report = phase_data.get("loot_report")
    elif enable_loot:
        console.print("[yellow]Phase 15/16:[/yellow] Collecting loot from scan results...")

        from reconprobe.loot import collect_loot

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task("Extracting valuable artifacts...", total=None)

            # Build vuln_scan_data from check results
            vuln_scan_data = vuln_scan_report_data if vuln_scan_report_data else None
            http_data = http_probe_reports if http_probe_reports else None
            crawl_data_obj = crawl_reports if crawl_reports else None
            takeover_data = takeover_report_data if takeover_report_data else None

            loot_obj = collect_loot(
                target=domain,
                vuln_scan_data=vuln_scan_data,
                http_probe_data=http_data,
                crawl_data=crawl_data_obj,
                enrichment_data=enrichment_report_data if enrichment_report_data else None,
                takeover_data=takeover_data,
            )
            loot_report = loot_obj.to_dict()
            progress.update(task, completed=True)

        console.print(f"  Collected [green]{loot_report['total_count']}[/green] loot items")
        if loot_report['critical_count'] > 0:
            console.print(f"    Critical: [red]{loot_report['critical_count']}[/red]")
        if loot_report['high_count'] > 0:
            console.print(f"    High: [yellow]{loot_report['high_count']}[/yellow]")
        if loot_report['medium_count'] > 0:
            console.print(f"    Medium: [dim]{loot_report['medium_count']}[/dim]")

        # Show a sample of critical items
        critical_items = [i for i in loot_report.get("items", []) if i["severity"] == "critical"][:5]
        for item in critical_items:
            console.print(f"    [red]{item['type']}[/red] — {item.get('description', '')}")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=15, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[15],
                data={"phase_15": {"loot_report": loot_report}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 16: MSF Resource Script Generation
    # ─────────────────────────────────────────────────────────────────
    msf_report = None

    if checkpoint and checkpoint.is_phase_completed(16):
        console.print("[dim]Phase 16/16: MSF Script — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(16)
        if phase_data:
            msf_report = phase_data.get("msf_report")
    elif enable_msf_gen:
        console.print("[yellow]Phase 16/16:[/yellow] Generating Metasploit resource script...")

        from reconprobe.msf_gen import generate_msf_script_full

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task("Building MSF .rc script...", total=None)

            # Prepare scan results dict
            all_scan_results: dict[str, Any] = {
                "scanner_data": {},
                "exploit_data": exploit_report,
            }
            for sr in scan_reports:
                all_scan_results["scanner_data"][sr.hostname] = sr.to_dict()

            msf_script = generate_msf_script_full(
                target=domain,
                scan_results=all_scan_results,
                lhost=lhost,
                lport=lport,
            )

            msf_report = {
                "module_count": msf_script.module_count,
                "auxiliary_count": msf_script.auxiliary_count,
                "exploit_count": msf_script.exploit_count,
                "content": msf_script.content,
            }

            # Write script to output dir if available
            if output_dir:
                msf_path = output_dir / f"{domain.replace('.', '_')}_msf.rc"
                msf_path.write_text(msf_script.content)
                console.print(f"  MSF script written: [green]{msf_path}[/green]")

            progress.update(task, completed=True)

        console.print(f"  Generated MSF script with [green]{msf_report['module_count']}[/green] modules "
                      f"({msf_report['auxiliary_count']} auxiliary, {msf_report['exploit_count']} exploit)")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=16, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[16],
                data={"phase_16": {"msf_report": msf_report}},
            )

    console.print("")

    # ═════════════════════════════════════════════════════════════════
    # Phase 5 — Advanced OSINT
    # ═════════════════════════════════════════════════════════════════

    # ─────────────────────────────────────────────────────────────────
    # Phase 17: Advanced OSINT
    # ─────────────────────────────────────────────────────────────────
    osint_report_data = None

    if checkpoint and checkpoint.is_phase_completed(17):
        console.print("[dim]Phase 17/17: Advanced OSINT — [green]✓ already completed[/green][/dim]")
        phase_data = checkpoint.get_phase_data(17)
        if phase_data:
            osint_report_data = phase_data.get("osint_report")
    elif enable_osint:
        console.print("[yellow]Phase 17/17:[/yellow] Running advanced OSINT gathering...")

        from reconprobe.osint import run_osint

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task("Gathering OSINT from multiple sources...", total=None)

            osint_report = await run_osint(
                domain=domain,
                http_probe_data=http_probe_reports if http_probe_reports else None,
                crawl_data=crawl_reports if crawl_reports else None,
                github_token=github_token,
                enable_github=enable_github_dork,
                enable_google_dorks=enable_google_dorks,
                enable_email=enable_email_harvest,
                enable_whois=enable_whois,
                enable_social=enable_social_footprint,
                enable_breach=enable_breach_check,
                enable_tech_stack=enable_tech_osint,
            )
            osint_report_data = osint_report.to_dict()
            progress.update(task, completed=True)

        # Summary output
        total = osint_report_data["total_findings"]
        severity_counts = osint_report_data.get("severity_counts", {})
        source_counts = osint_report_data.get("source_counts", {})
        console.print(f"  OSINT complete: [green]{total}[/green] total findings")
        if severity_counts.get("critical", 0) > 0:
            console.print(f"    Critical: [red]{severity_counts['critical']}[/red]")
        if severity_counts.get("high", 0) > 0:
            console.print(f"    High: [yellow]{severity_counts['high']}[/yellow]")

        # Show source breakdown
        source_labels = {
            "github": "GitHub dorks", "google_dork": "Google dorks",
            "email": "Email addresses", "whois": "WHOIS data",
            "social": "Social profiles", "breach": "Breach checks",
            "tech_stack": "Tech stack OSINT",
        }
        src_parts = []
        for key, label in source_labels.items():
            count = source_counts.get(key, 0)
            if count > 0:
                src_parts.append(f"[green]{count}[/green] {label}")
        if src_parts:
            console.print(f"  Sources: {', '.join(src_parts)}")

        # Show critical/high findings summary
        for finding in osint_report_data.get("findings", [])[:5]:
            sev = finding.get("severity", "")
            if sev in ("critical", "high"):
                sev_color = "red" if sev == "critical" else "yellow"
                console.print(f"    [{sev_color}]{finding.get('type', '')}[/{sev_color}] — "
                              f"{finding.get('value', '')[:80]}")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=17, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[17],
                data={"phase_17": {"osint_report": osint_report_data}},
            )

    console.print("")

    # ─────────────────────────────────────────────────────────────────
    # Phase 8: Reporting (now includes Phase 3 + Phase 4 + Phase 5 data)
    # ─────────────────────────────────────────────────────────────────
    console.print(f"[yellow]Phase 8/{TOTAL_PHASES}:[/yellow] Generating reports...")
    end_time = datetime.now()

    report = build_full_report(
        domain=domain,
        subdomain_report=subdomain_report,
        scan_reports=scan_reports,
        http_probe_reports=http_probe_reports,
        screenshot_reports=screenshot_reports,
        crawl_reports=crawl_reports,
        dirbuster_reports=dirbuster_reports,
        enrichment_report=enrichment_report_data,
        start_time=start_time,
        end_time=end_time,
        advanced_subdomain_report=advanced_report,
        # Phase 3 data
        vuln_scan_report=vuln_scan_report_data,
        ssl_audit_report=ssl_audit_report_data,
        takeover_report=takeover_report_data,
        waf_report=waf_report_data,
        # Phase 4 data
        exploit_report=exploit_report,
        payload_report=payload_report,
        loot_report=loot_report,
        msf_report=msf_report,
        lhost=lhost,
        lport=lport,
        # Phase 5 data
        osint_report=osint_report_data,
    )

    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        domain_safe = domain.replace(".", "_")

        if json_output:
            json_path = output_dir / f"{domain_safe}_report.json"
            output_json(report, json_path)
            console.print(f"  JSON report: [green]{json_path}[/green]")

        if markdown_output:
            md_path = output_dir / f"{domain_safe}_report.md"
            output_markdown(report, md_path)
            console.print(f"  Markdown report: [green]{md_path}[/green]")

        if enable_html:
            html_path = output_dir / f"{domain_safe}_report.html"
            html_content = generate_html_report(report)
            html_path.write_text(html_content)
            console.print(f"  HTML dashboard: [green]{html_path}[/green]")

        # Save final checkpoint and clear on success
        if checkpoint:
            checkpoint.save(
                phase=8, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[8],
                data={"phase_8": {"report_generated": True}},
            )
            checkpoint.clear()

    # ═════════════════════════════════════════════════════════════════
    # Phase 6 — Reporting Automation (Phase 18)
    # ═════════════════════════════════════════════════════════════════

    generated: dict[str, Path] = {}
    if output_dir and (enable_pdf_report or enable_csv_export or enable_xlsx_export or enable_executive_summary):
        console.print(f"[yellow]Phase 18/{TOTAL_PHASES}:[/yellow] Running reporting automation...")

        gen_pdf = enable_pdf_report
        gen_csv = enable_csv_export
        gen_xlsx = enable_xlsx_export
        gen_summary = enable_executive_summary

        try:
            generated = run_reporting_enhancements(
                report=report,
                output_dir=output_dir,
                generate_pdf=gen_pdf,
                generate_csv=gen_csv,
                generate_xlsx=gen_xlsx,
                generate_exec_summary=gen_summary,
            )
            if generated.get("pdf"):
                console.print(f"  PDF report: [green]{generated['pdf']}[/green]")
            if generated.get("csv"):
                console.print(f"  CSV export: [green]{generated['csv']}[/green]")
            if generated.get("xlsx"):
                console.print(f"  XLSX export: [green]{generated['xlsx']}[/green]")
            if generated.get("exec_summary"):
                console.print(f"  Executive summary: [green]{generated['exec_summary']}[/green]")
        except Exception as e:
            console.print(f"  [red]Error during reporting automation: {e}[/red]")

        # Save checkpoint
        if checkpoint:
            checkpoint.save(
                phase=18, total_phases=TOTAL_PHASES, phase_name=PHASE_NAMES[18],
                data={"phase_18": {"reporting_generated": generated}},
            )

    # ═════════════════════════════════════════════════════════════════
    # Phase 7 — Webhook Notifications
    # ═════════════════════════════════════════════════════════════════

    if webhook_config and (webhook_config.slack or webhook_config.discord or webhook_config.email):
        console.print("[yellow]Phase —:[/yellow] Dispatching webhook notifications...")
        try:
            summary = build_summary_from_report(report)
            results = await dispatch_webhooks(summary, webhook_config)
            for target, success in results.items():
                status = "[green]✓[/green]" if success else "[red]✗[/red]"
                console.print(f"  {status} {target}")
        except Exception as e:
            console.print(f"  [red]Error dispatching webhooks: {e}[/red]")

    console.print("")
    console.print("[bold green]✓ Scan complete![/bold green]")

    return report
