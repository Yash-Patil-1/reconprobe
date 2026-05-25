"""CLI entry point for ReconProbe."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Optional

from reconprobe import __version__
from reconprobe.runner import run_scan
from reconprobe.utils import COMMON_PORTS
from reconprobe.webhook import WebhookConfig, SlackConfig, DiscordConfig, EmailConfig
from rich.console import Console
from rich.table import Table

console = Console()


BANNER = r"""
[bold cyan]
    _______________
   /              /|
  /   RECONPROBE / |
 /               /  |
/_______________/  |
|               |  |
|  probe active |  /
|               | /
|_______________|/
[/bold cyan]
[bold cyan]  ReconProbe[/bold cyan] [dim]v""" + __version__ + """[/dim]
"""


def print_banner():
    """Print the ReconProbe banner."""
    console.print(BANNER)


def parse_ports(port_str: Optional[str]) -> Optional[list[int]]:
    """Parse port specification string into a list of ports.

    Accepts: '80,443,8080' or '1-1000' or '80,443,8000-8080'
    """
    if not port_str:
        return None

    ports: list[int] = []
    parts = port_str.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.extend(range(int(start.strip()), int(end.strip()) + 1))
            except ValueError:
                console.print(f"[red]Invalid port range: {part}[/red]")
                sys.exit(1)
        else:
            try:
                ports.append(int(part))
            except ValueError:
                console.print(f"[red]Invalid port: {part}[/red]")
                sys.exit(1)
    return sorted(set(ports))


def list_common_ports():
    """Display a table of common ports."""
    table = Table(title="Common Ports Reference")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="green")

    for port in sorted(COMMON_PORTS.keys()):
        table.add_row(str(port), COMMON_PORTS[port])

    console.print(table)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="reconprobe",
        description="Automated reconnaissance tool for penetration testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reconprobe example.com
  reconprobe example.com -p 22,80,443,8080 -o ./reports
  reconprobe example.com --masscan --masscan-rate 5000
  reconprobe example.com --screenshots -o ./reports
  reconprobe example.com --crawl                        # Web crawling
  reconprobe example.com --dirbuster                    # Directory brute-force
  reconprobe example.com --crawl --dirbuster -o ./reports
  reconprobe example.com --no-enrichment                # Skip Shodan/NVD lookup
  reconprobe example.com --shodan-api-key KEY           # Shodan enrichment
  reconprobe example.com --nvd-api-key KEY              # NVD CVE lookup
  reconprobe example.com --no-http-probe
  reconprobe example.com --vt-api-key KEY --st-api-key KEY
  reconprobe --list-ports
  reconprobe example.com --html -o ./reports          # Generate HTML dashboard
  reconprobe example.com --advanced-subdomains       # Zone transfer, permutations, recursive
  reconprobe example.com --advanced-subdomains --recursive-depth 3
  reconprobe example.com --advanced-subdomains --no-zone-transfer --no-permutations
  reconprobe example.com --version-detection            # Service version detection
  reconprobe example.com --os-fingerprint               # OS fingerprinting via TTL
  reconprobe example.com --top-1000                     # Scan top 1000 TCP ports
  reconprobe example.com --version-detection --os-fingerprint --top-1000
        """,
    )

    parser.add_argument(
        "domain",
        nargs="?",
        help="Target domain to scan (e.g., example.com)",
    )

    parser.add_argument(
        "-p", "--ports",
        help="Ports to scan (e.g., '80,443,8080' or '1-1000')",
        default=None,
    )

    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output directory for reports (default: stdout only)",
        default=None,
    )

    parser.add_argument(
        "--no-brute-force",
        action="store_true",
        help="Skip subdomain brute-force (passive sources only)",
    )

    parser.add_argument(
        "--wordlist",
        type=Path,
        help="Path to subdomain wordlist for brute-force",
        default=None,
    )

    parser.add_argument(
        "--max-subdomain-workers",
        type=int,
        default=50,
        help="Max threads for subdomain brute-force (default: 50)",
    )

    parser.add_argument(
        "--max-port-workers",
        type=int,
        default=100,
        help="Max threads for port scanning (default: 100)",
    )

    parser.add_argument(
        "--port-timeout",
        type=float,
        default=2.0,
        help="Port scan timeout in seconds (default: 2.0)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON report to stdout (default: only to file if -o is set)",
    )

    parser.add_argument(
        "--list-ports",
        action="store_true",
        help="Display a table of common ports and exit",
    )

    # === HTTP Probing ===
    parser.add_argument(
        "--no-http-probe",
        action="store_true",
        help="Skip HTTP service probing and technology fingerprinting",
    )

    # === Enhanced Reporting ===
    reporting_group = parser.add_argument_group("Reporting")
    reporting_group.add_argument(
        "--html",
        action="store_true",
        help="Generate interactive HTML dashboard with charts (requires -o)",
    )

    # === Screenshots ===
    parser.add_argument(
        "--screenshots",
        action="store_true",
        help="Enable Playwright-based screenshot capture of web services (requires -o, needs playwright)",
    )

    # === Masscan ===
    parser.add_argument(
        "--masscan",
        action="store_true",
        help="Use masscan for high-speed port scanning (requires root/sudo)",
    )

    parser.add_argument(
        "--masscan-rate",
        type=int,
        default=1000,
        help="Packets per second for masscan (default: 1000)",
    )

    # === Phase 2: Web Crawling ===
    crawler_group = parser.add_argument_group("Web Crawling")
    crawler_group.add_argument(
        "--crawl",
        action="store_true",
        help="Enable web crawling of discovered HTTP services",
    )
    crawler_group.add_argument(
        "--crawl-depth",
        type=int,
        default=2,
        help="Maximum crawl depth (default: 2)",
    )
    crawler_group.add_argument(
        "--crawl-pages",
        type=int,
        default=50,
        help="Maximum pages to crawl per host (default: 50)",
    )

    # === Phase 2: Directory Brute-Force ===
    dirbuster_group = parser.add_argument_group("Directory Brute-Force")
    dirbuster_group.add_argument(
        "--dirbuster",
        action="store_true",
        help="Enable directory/file brute-force on discovered web services",
    )
    dirbuster_group.add_argument(
        "--dirbuster-wordlist",
        type=Path,
        help="Custom path wordlist for directory brute-force",
        default=None,
    )
    dirbuster_group.add_argument(
        "--dirbuster-extensions",
        help="File extensions to try (comma-separated, e.g., 'php,asp,html,jsp')",
        default=None,
    )

    # === Phase 2 Feature 2: API Integrations (Shodan + NVD) ===
    enrichment_group = parser.add_argument_group("API Enrichment (Shodan & NVD)")
    enrichment_group.add_argument(
        "--no-enrichment",
        action="store_true",
        help="Skip Shodan IP enrichment and NVD CVE lookup",
    )
    enrichment_group.add_argument(
        "--shodan-api-key",
        help="Shodan API key for IP enrichment (also via SHODAN_API_KEY env var)",
        default=None,
    )
    enrichment_group.add_argument(
        "--nvd-api-key",
        help="NVD API key for CVE lookup (also via NVD_API_KEY env var; without key: 5 req/30s)",
        default=None,
    )

    # === Phase 2 Feature 4: Advanced Subdomain Techniques ===
    advanced_subdomain_group = parser.add_argument_group("Advanced Subdomain Techniques")
    advanced_subdomain_group.add_argument(
        "--advanced-subdomains",
        action="store_true",
        help="Enable advanced subdomain techniques: zone transfer, permutations, recursive discovery",
    )
    advanced_subdomain_group.add_argument(
        "--no-zone-transfer",
        action="store_true",
        help="Skip DNS zone transfer attempts",
    )
    advanced_subdomain_group.add_argument(
        "--no-permutations",
        action="store_true",
        help="Skip subdomain permutation/alteration engine",
    )
    advanced_subdomain_group.add_argument(
        "--no-recursive",
        action="store_true",
        help="Skip recursive subdomain discovery",
    )
    advanced_subdomain_group.add_argument(
        "--recursive-depth",
        type=int,
        default=2,
        help="Maximum depth for recursive subdomain discovery (default: 2)",
    )
    advanced_subdomain_group.add_argument(
        "--max-permutations",
        type=int,
        default=5000,
        help="Maximum permutation candidates to test (default: 5000)",
    )

    # === Phase 2 Feature 5: Smarter Port Scanning ===
    scanning_group = parser.add_argument_group("Advanced Port Scanning")
    scanning_group.add_argument(
        "--version-detection",
        action="store_true",
        help="Enable service version detection via service-specific probes (SSH, HTTP, MySQL, etc.)",
    )
    scanning_group.add_argument(
        "--os-fingerprint",
        action="store_true",
        help="Enable OS fingerprinting via TTL/TCP window heuristics",
    )
    scanning_group.add_argument(
        "--top-1000",
        action="store_true",
        help="Scan top 1000 most common TCP ports instead of the default ~50",
    )

    # === Quality of Life ===
    qol_group = parser.add_argument_group("Batch & Performance")
    qol_group.add_argument(
        "--targets-file",
        type=Path,
        help="File containing target domains (one per line, # comments ignored)",
        default=None,
    )
    qol_group.add_argument(
        "--max-concurrency",
        type=int,
        default=1,
        help="Max concurrent batch scans (default: 1, sequential)",
    )
    qol_group.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Seconds to wait between requests (polite scanning, default: 0)",
    )
    qol_group.add_argument(
        "--rate-limit",
        type=int,
        default=None,
        help="Max requests per second (alternative to --delay)",
    )
    qol_group.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="Proxy URL for routing traffic (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050)",
    )
    qol_group.add_argument(
        "--tor",
        action="store_true",
        help="Route traffic through Tor (SOCKS5 127.0.0.1:9050)",
    )
    qol_group.add_argument(
        "--resume",
        action="store_true",
        help="Resume a previously interrupted scan from its checkpoint",
    )

    # === Phase 3: Vulnerability Assessment ===
    vuln_group = parser.add_argument_group("Vulnerability Assessment")
    vuln_group.add_argument(
        "--vuln-scan",
        action="store_true",
        help="Enable vulnerability scanning: CVE mapping for detected services + default credential checking",
    )
    vuln_group.add_argument(
        "--no-credential-check",
        action="store_true",
        help="Skip default credential checking during vulnerability scan",
    )

    # === Phase 3: SSL/TLS Audit ===
    ssl_group = parser.add_argument_group("SSL/TLS Security Audit")
    ssl_group.add_argument(
        "--ssl-audit",
        action="store_true",
        help="Enable SSL/TLS deep audit: certificate analysis, protocol/cipher checks, security headers",
    )
    ssl_group.add_argument(
        "--ssl-ports",
        help="SSL/TLS ports to audit (comma-separated, default: 443,8443,9443)",
        default=None,
    )

    # === Phase 3: Subdomain Takeover Detection ===
    takeover_group = parser.add_argument_group("Subdomain Takeover Detection")
    takeover_group.add_argument(
        "--takeover",
        action="store_true",
        help="Enable subdomain takeover detection (dangling DNS + HTTP signature matching)",
    )

    # === Phase 3: WAF Detection ===
    waf_group = parser.add_argument_group("WAF Detection & Fingerprinting")
    waf_group.add_argument(
        "--waf-detect",
        action="store_true",
        help="Enable WAF detection and fingerprinting (passive + active probing)",
    )
    waf_group.add_argument(
        "--no-active-waf",
        action="store_true",
        help="Skip active WAF probing (malicious payloads), passive detection only",
    )

    # === Phase 4: Exploitation Integration ===
    exploit_group = parser.add_argument_group("Exploitation Integration")
    exploit_group.add_argument(
        "--exploit-suggest",
        action="store_true",
        help="Enable exploit suggestion engine (maps services/versions to known exploits)",
    )
    exploit_group.add_argument(
        "--payload-gen",
        action="store_true",
        help="Generate reverse shell payloads (Python, Bash, PowerShell, Netcat, PHP, Perl, Ruby)",
    )
    exploit_group.add_argument(
        "--payload-type",
        help="Payload type for generation (auto, python, bash, powershell, netcat, php, perl, ruby, msfvenom)",
        default="auto",
    )
    exploit_group.add_argument(
        "--payload-encode",
        action="store_true",
        help="Enable base64 encoding/obfuscation for generated payloads",
    )
    exploit_group.add_argument(
        "--loot",
        action="store_true",
        help="Enable loot collection from scan results (credentials, API keys, tokens, emails)",
    )
    exploit_group.add_argument(
        "--msf-gen",
        action="store_true",
        help="Generate Metasploit resource (.rc) script from scan results",
    )
    exploit_group.add_argument(
        "--lhost",
        help="Local host IP for reverse shells and Metasploit listeners (default: 127.0.0.1)",
        default="127.0.0.1",
    )
    exploit_group.add_argument(
        "--lport",
        type=int,
        default=4444,
        help="Local port for reverse shells and Metasploit listeners (default: 4444)",
    )

    # === Phase 6: Reporting Automation ===
    reporting_auto_group = parser.add_argument_group("Reporting Automation")
    reporting_auto_group.add_argument(
        "--pdf",
        action="store_true",
        help="Generate professional PDF report from scan results (requires -o, needs fpdf2)",
    )
    reporting_auto_group.add_argument(
        "--csv",
        action="store_true",
        help="Export all findings to CSV file (requires -o)",
    )
    reporting_auto_group.add_argument(
        "--xlsx",
        action="store_true",
        help="Export findings to XLSX workbook with multiple sheets (requires -o, needs openpyxl)",
    )
    reporting_auto_group.add_argument(
        "--exec-summary",
        action="store_true",
        help="Generate executive summary text file with risk assessment and recommendations (requires -o)",
    )

    # === Phase 5: Advanced OSINT ===
    osint_group = parser.add_argument_group("Advanced OSINT")
    osint_group.add_argument(
        "--osint",
        action="store_true",
        help="Enable advanced OSINT gathering: GitHub dorking, WHOIS, email harvest, social footprint, breach checks, tech stack",
    )
    osint_group.add_argument(
        "--github-token",
        help="GitHub personal access token for authenticated API searches (also via GITHUB_TOKEN env var)",
        default=None,
    )
    osint_group.add_argument(
        "--no-github-dork",
        action="store_true",
        help="Skip GitHub dorking during OSINT phase",
    )
    osint_group.add_argument(
        "--no-google-dorks",
        action="store_true",
        help="Skip Google dork generation during OSINT phase",
    )
    osint_group.add_argument(
        "--no-email-harvest",
        action="store_true",
        help="Skip email harvesting during OSINT phase",
    )
    osint_group.add_argument(
        "--no-whois",
        action="store_true",
        help="Skip WHOIS lookup during OSINT phase",
    )
    osint_group.add_argument(
        "--no-social",
        action="store_true",
        help="Skip social footprinting during OSINT phase",
    )
    osint_group.add_argument(
        "--no-breach-check",
        action="store_true",
        help="Skip breach database check during OSINT phase",
    )
    osint_group.add_argument(
        "--no-tech-osint",
        action="store_true",
        help="Skip tech stack OSINT during OSINT phase",
    )

    # === Phase 7: CI/CD & Automation ===
    automation_group = parser.add_argument_group("Automation (Phase 7)")
    automation_group.add_argument(
        "--serve",
        action="store_true",
        help="Start ReconProbe as a FastAPI REST server for remote scanning",
    )
    automation_group.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind the REST API server (default: 0.0.0.0)",
    )
    automation_group.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for the REST API server (default: 8000)",
    )
    automation_group.add_argument(
        "--schedule",
        type=Path,
        help="Path to schedule YAML file for recurring scans",
        default=None,
    )
    automation_group.add_argument(
        "--schedule-once",
        action="store_true",
        help="Run all due scheduled scans once and exit (instead of looping)",
    )

    # Webhook configuration
    webhook_group = parser.add_argument_group("Webhook Notifications")
    webhook_group.add_argument(
        "--webhook-slack",
        help="Slack webhook URL for scan notifications",
        default=None,
    )
    webhook_group.add_argument(
        "--webhook-discord",
        help="Discord webhook URL for scan notifications",
        default=None,
    )
    webhook_group.add_argument(
        "--webhook-email",
        help="SMTP connection string for email notifications "
             "(e.g., 'smtp.example.com:587:user:pass' or 'smtp.example.com' with env vars)",
        default=None,
    )
    webhook_group.add_argument(
        "--webhook-to",
        help="Recipient email address(es) for email notifications (comma-separated)",
        default=None,
    )
    webhook_group.add_argument(
        "--webhook-from",
        help="From address for email notifications",
        default="reconprobe@localhost",
    )

    # === API Keys ===
    parser.add_argument(
        "--vt-api-key",
        help="VirusTotal API key for subdomain enumeration (also via VT_API_KEY env var)",
        default=None,
    )

    parser.add_argument(
        "--st-api-key",
        help="SecurityTrails API key for subdomain enumeration (also via ST_API_KEY env var)",
        default=None,
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"ReconProbe v{__version__}",
    )

    return parser


def main():
    """Main entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    # ── Phase 7: Serve mode (REST API) ──
    if args.serve:
        try:
            from reconprobe.api import run_server as run_api_server
        except ImportError:
            console.print("[red]Error:[/red] FastAPI + uvicorn are required for server mode.")
            console.print("  Install with: [bold]pip install reconprobe[api][/bold]")
            sys.exit(1)
        console.print(f"[bold cyan]REST API server[/bold cyan] — starting on [green]{args.host}:{args.port}[/green]")
        console.print("  Endpoints: POST /scan, GET /scan/{id}, GET /health\n")
        # Signal to Pyyaml that it's used (imported via scheduler)
        run_api_server(run_scan, host=args.host, port=args.port, version=__version__)
        return

    # ── Phase 7: Scheduled mode ──
    if args.schedule:
        from reconprobe.scheduler import load_schedule, run_scheduler_loop
        console.print(f"[bold cyan]Scheduler[/bold cyan] — loading schedule from [green]{args.schedule}[/green]")
        config = load_schedule(args.schedule)
        asyncio.run(run_scheduler_loop(
            config, args.schedule, run_scan,
            run_once=args.schedule_once,
        ))
        return

    # Handle --list-ports
    if args.list_ports:
        list_common_ports()
        return

    # Require domain or targets-file
    if not args.domain and not args.targets_file:
        parser.print_help()
        console.print("\n[yellow]Error:[/yellow] Domain argument or --targets-file is required.")
        sys.exit(1)

    # ── Build webhook config from CLI args ──
    webhook_config: Optional[WebhookConfig] = None
    if args.webhook_slack or args.webhook_discord or args.webhook_email:
        slack_cfg = SlackConfig(webhook_url=args.webhook_slack) if args.webhook_slack else None
        discord_cfg = DiscordConfig(webhook_url=args.webhook_discord) if args.webhook_discord else None
        email_cfg = None
        if args.webhook_email:
            parts = args.webhook_email.split(":")
            smtp_host = parts[0]
            smtp_port = int(parts[1]) if len(parts) > 1 else 587
            smtp_user = parts[2] if len(parts) > 2 else ""
            smtp_pass = parts[3] if len(parts) > 3 else ""
            to_addrs = [a.strip() for a in args.webhook_to.split(",")] if args.webhook_to else []
            email_cfg = EmailConfig(
                smtp_host=smtp_host,
                smtp_port=smtp_port,
                smtp_user=smtp_user,
                smtp_password=smtp_pass,
                from_addr=args.webhook_from,
                to_addrs=to_addrs,
            )
        webhook_config = WebhookConfig(slack=slack_cfg, discord=discord_cfg, email=email_cfg)

    # Validate output directory requirements
    if args.screenshots and not args.output:
        console.print("[red]Error:[/red] --screenshots requires -o/--output directory")
        sys.exit(1)
    if args.html and not args.output:
        console.print("[red]Error:[/red] --html requires -o/--output directory")
        sys.exit(1)

    # Parse ports
    ports = parse_ports(args.ports)

    # Determine if JSON output should go to stdout
    json_stdout = args.json or not args.output

    # ── Batch mode: scan multiple targets from file ──
    if args.targets_file:
        from reconprobe.batch import load_targets, run_batch_scan
        targets = load_targets(str(args.targets_file))
        if not targets:
            sys.exit(1)

        console.print(f"\n[bold]Batch mode:[/bold] scanning [cyan]{len(targets)}[/cyan] targets "
                      f"(max {args.max_concurrency} concurrent)\n")

        try:
            results = asyncio.run(
                run_batch_scan(
                    domains=targets,
                    output_dir=args.output,
                    max_concurrency=args.max_concurrency,
                    # Pass through all scan params
                    ports=ports,
                    brute_force=not args.no_brute_force,
                    wordlist_path=str(args.wordlist) if args.wordlist else None,
                    max_workers_subdomain=args.max_subdomain_workers,
                    max_workers_port=args.max_port_workers,
                    port_timeout=args.port_timeout,
                    json_output=json_stdout,
                    markdown_output=True,
                    enable_http_probe=not args.no_http_probe,
                    enable_screenshots=args.screenshots,
                    enable_crawling=args.crawl,
                    crawl_max_depth=args.crawl_depth,
                    crawl_max_pages=args.crawl_pages,
                    enable_dirbuster=args.dirbuster,
                    dirbuster_wordlist=str(args.dirbuster_wordlist) if args.dirbuster_wordlist else None,
                    dirbuster_extensions=args.dirbuster_extensions,
                    enable_enrichment=not args.no_enrichment,
                    shodan_api_key=args.shodan_api_key,
                    nvd_api_key=args.nvd_api_key,
                    enable_html=args.html,
                    enable_advanced_subdomains=args.advanced_subdomains,
                    enable_zone_transfer=not args.no_zone_transfer,
                    enable_permutations=not args.no_permutations,
                    enable_recursive=not args.no_recursive,
                    recursive_max_depth=args.recursive_depth,
                    max_permutation_candidates=args.max_permutations,
                    enable_version_detection=args.version_detection,
                    enable_os_fingerprinting=args.os_fingerprint,
                    top_1000=args.top_1000,
                    # Phase 2 Feature 6: Quality of Life
                    delay=args.delay,
                    rate_limit=args.rate_limit,
                    proxy_url=args.proxy,
                    tor=args.tor,
                    resume=args.resume,
                    # Phase 3: Vulnerability Assessment
                    enable_vuln_scan=args.vuln_scan,
                    check_default_creds=not args.no_credential_check,
                    # Phase 3: SSL/TLS Audit
                    enable_ssl_audit=args.ssl_audit,
                    ssl_ports=parse_ports(args.ssl_ports),
                    # Phase 3: Subdomain Takeover Detection
                    enable_takeover=args.takeover,
                    # Phase 3: WAF Detection
                    enable_waf_detect=args.waf_detect,
                    enable_active_waf=not args.no_active_waf,
                    # Phase 4: Exploitation Integration
                    enable_exploit_suggest=args.exploit_suggest,
                    enable_payload_gen=args.payload_gen,
                    payload_type=args.payload_type,
                    payload_encode=args.payload_encode,
                    enable_loot=args.loot,
                    enable_msf_gen=args.msf_gen,
                    lhost=args.lhost,
                    lport=args.lport,
                    # Phase 5: Advanced OSINT
                    enable_osint=args.osint,
                    github_token=args.github_token,
                    enable_github_dork=not args.no_github_dork,
                    enable_google_dorks=not args.no_google_dorks,
                    enable_email_harvest=not args.no_email_harvest,
                    enable_whois=not args.no_whois,
                    enable_social_footprint=not args.no_social,
                    enable_breach_check=not args.no_breach_check,
                    enable_tech_osint=not args.no_tech_osint,
                    # Phase 6: Reporting Automation
                    enable_pdf_report=args.pdf,
                    enable_csv_export=args.csv,
                    enable_xlsx_export=args.xlsx,
                    enable_executive_summary=args.exec_summary,
                    # Phase 7: Automation
                    webhook_config=webhook_config,
                )
            )
            total_domains = len(targets)
            succeeded = sum(1 for r in results.values() if "error" not in r)
            console.print(f"\n[bold green]Batch complete:[/bold green] {succeeded}/{total_domains} targets succeeded\n")
        except KeyboardInterrupt:
            console.print("\n[yellow]Batch scan interrupted by user.[/yellow]")
            sys.exit(130)
        except Exception as e:
            console.print(f"\n[bold red]Error:[/bold red] {e}")
            sys.exit(1)

        return

    # ── Single domain mode ──
    try:
        report = asyncio.run(
            run_scan(
                domain=args.domain,
                ports=ports,
                brute_force=not args.no_brute_force,
                wordlist_path=str(args.wordlist) if args.wordlist else None,
                max_workers_subdomain=args.max_subdomain_workers,
                max_workers_port=args.max_port_workers,
                port_timeout=args.port_timeout,
                output_dir=args.output,
                json_output=json_stdout,
                markdown_output=True,
                enable_http_probe=not args.no_http_probe,
                enable_screenshots=args.screenshots,
                use_masscan=args.masscan,
                masscan_rate=args.masscan_rate,
                vt_api_key=args.vt_api_key,
                st_api_key=args.st_api_key,
                # Phase 2 features
                enable_crawling=args.crawl,
                crawl_max_depth=args.crawl_depth,
                crawl_max_pages=args.crawl_pages,
                enable_dirbuster=args.dirbuster,
                dirbuster_wordlist=str(args.dirbuster_wordlist) if args.dirbuster_wordlist else None,
                dirbuster_extensions=args.dirbuster_extensions,
                # Phase 2 Feature 2: API Integrations
                enable_enrichment=not args.no_enrichment,
                shodan_api_key=args.shodan_api_key,
                nvd_api_key=args.nvd_api_key,
                # Phase 2 Feature 3: Enhanced Reporting
                enable_html=args.html,
                # Phase 2 Feature 4: Advanced Subdomain Techniques
                enable_advanced_subdomains=args.advanced_subdomains,
                enable_zone_transfer=not args.no_zone_transfer,
                enable_permutations=not args.no_permutations,
                enable_recursive=not args.no_recursive,
                recursive_max_depth=args.recursive_depth,
                max_permutation_candidates=args.max_permutations,
                # Phase 2 Feature 5: Smarter Port Scanning
                enable_version_detection=args.version_detection,
                enable_os_fingerprinting=args.os_fingerprint,
                top_1000=args.top_1000,
                # Phase 2 Feature 6: Quality of Life
                delay=args.delay,
                rate_limit=args.rate_limit,
                proxy_url=args.proxy,
                tor=args.tor,
                resume=args.resume,
                # Phase 3: Vulnerability Assessment
                enable_vuln_scan=args.vuln_scan,
                check_default_creds=not args.no_credential_check,
                # Phase 3: SSL/TLS Audit
                enable_ssl_audit=args.ssl_audit,
                ssl_ports=parse_ports(args.ssl_ports),
                # Phase 3: Subdomain Takeover Detection
                enable_takeover=args.takeover,
                # Phase 3: WAF Detection
                enable_waf_detect=args.waf_detect,
                enable_active_waf=not args.no_active_waf,
                # Phase 4: Exploitation Integration
                enable_exploit_suggest=args.exploit_suggest,
                enable_payload_gen=args.payload_gen,
                payload_type=args.payload_type,
                payload_encode=args.payload_encode,
                enable_loot=args.loot,
                enable_msf_gen=args.msf_gen,
                lhost=args.lhost,
                lport=args.lport,
                # Phase 5: Advanced OSINT
                enable_osint=args.osint,
                github_token=args.github_token,
                enable_github_dork=not args.no_github_dork,
                enable_google_dorks=not args.no_google_dorks,
                enable_email_harvest=not args.no_email_harvest,
                enable_whois=not args.no_whois,
                enable_social_footprint=not args.no_social,
                enable_breach_check=not args.no_breach_check,
                enable_tech_osint=not args.no_tech_osint,
                # Phase 6: Reporting Automation
                enable_pdf_report=args.pdf,
                enable_csv_export=args.csv,
                enable_xlsx_export=args.xlsx,                    enable_executive_summary=args.exec_summary,
                    # Phase 7: Automation
                    webhook_config=webhook_config,
                )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
