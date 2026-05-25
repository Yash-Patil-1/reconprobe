"""Reporting module for ReconProbe.

Outputs scan results as structured JSON and human-readable Markdown.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from reconprobe.subdomain import SubdomainReport
from reconprobe.scanner import HostScanReport


def build_full_report(
    domain: str,
    subdomain_report: SubdomainReport,
    scan_reports: list[HostScanReport],
    http_probe_reports: Optional[dict] = None,
    screenshot_reports: Optional[dict] = None,
    crawl_reports: Optional[dict] = None,
    dirbuster_reports: Optional[dict] = None,
    enrichment_report: Optional[object] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    advanced_subdomain_report: Optional[dict] = None,
    # Phase 3: Vulnerability Assessment
    vuln_scan_report: Optional[dict] = None,
    ssl_audit_report: Optional[dict] = None,
    takeover_report: Optional[dict] = None,
    waf_report: Optional[dict] = None,
    # Phase 4: Exploitation Integration
    exploit_report: Optional[dict] = None,
    payload_report: Optional[dict] = None,
    loot_report: Optional[dict] = None,
    msf_report: Optional[dict] = None,
    lhost: str = "127.0.0.1",
    lport: int = 4444,
    # Phase 5: Advanced OSINT
    osint_report: Optional[dict] = None,
) -> dict:
    """Build the complete scan report as a dictionary."""
    report: dict = {
        "tool": "ReconProbe",
        "version": "0.7.0",
        "target": {
            "domain": domain,
        },
        "scan_info": {},
        "subdomain_enumeration": {
            "total_found": subdomain_report.total_found if subdomain_report else 0,
            "total_resolved": subdomain_report.total_resolved if subdomain_report else 0,
            "results": [
                {
                    "hostname": r.hostname,
                    "ip_address": r.ip_address,
                    "source": r.source,
                    "resolved": r.resolved,
                }
                for r in (subdomain_report.results if subdomain_report else [])
            ],
        },
        "advanced_subdomain_techniques": {},
        "port_scanning": {
            "total_hosts_scanned": len(scan_reports),
            "hosts": [r.to_dict() for r in scan_reports],
        },
        "http_probing": {},
        "enrichment": {},
        "crawling": {},
        "dirbuster": {},
        "screenshots": {},
        # Phase 3: Vulnerability Assessment
        "vulnerability_scan": {},
        "ssl_tls_audit": {},
        "subdomain_takeover": {},
        "waf_detection": {},
        # Phase 4: Exploitation Integration
        "exploit_suggestions": {},
        "payloads": {},
        "loot": {},
        "msf_script": {},
        # Phase 5: Advanced OSINT
        "osint": {},
    }

    # Advanced subdomain techniques
    if advanced_subdomain_report:
        report["advanced_subdomain_techniques"] = advanced_subdomain_report

    if start_time and end_time:
        report["scan_info"] = {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
        }

    # HTTP probing results
    if http_probe_reports:
        http_data = {}
        total_alive = 0
        for hostname, probe_report in http_probe_reports.items():
            d = probe_report.to_dict()
            http_data[hostname] = d
            total_alive += d["alive_count"]
        report["http_probing"] = {
            "total_hosts_probed": len(http_probe_reports),
            "total_alive_services": total_alive,
            "hosts": http_data,
        }

    # Enrichment results (Shodan + NVD)
    if enrichment_report and hasattr(enrichment_report, "to_dict"):
        report["enrichment"] = enrichment_report.to_dict()
    elif enrichment_report and isinstance(enrichment_report, dict):
        # Fallback: check if it has common keys
        report["enrichment"] = {
            "shodan": {
                "total_ips_checked": len(enrichment_report.get("shodan_results", {})),
                "results": {
                    ip: r.to_dict() if hasattr(r, "to_dict") else r
                    for ip, r in enrichment_report.get("shodan_results", {}).items()
                },
            },
            "cve_lookup": {
                "total_found": len(enrichment_report.get("cve_results", [])),
                "results": [
                    c.to_dict() if hasattr(c, "to_dict") else c
                    for c in enrichment_report.get("cve_results", [])
                ],
            },
        }

    # Crawling results
    if crawl_reports:
        crawl_data = {}
        total_pages = 0
        total_findings = 0
        for hostname, cr in crawl_reports.items():
            d = cr.to_dict()
            crawl_data[hostname] = d
            total_pages += d["total_pages"]
            total_findings += len(d["interesting_findings"])
        report["crawling"] = {
            "total_hosts_crawled": len(crawl_reports),
            "total_pages_crawled": total_pages,
            "total_findings": total_findings,
            "hosts": crawl_data,
        }

    # Directory brute-force results
    if dirbuster_reports:
        dirbuster_data = {}
        total_scanned = 0
        total_found = 0
        for hostname, dbr in dirbuster_reports.items():
            d = dbr.to_dict()
            dirbuster_data[hostname] = d
            total_scanned += d["total_scanned"]
            total_found += d["total_found"]
        report["dirbuster"] = {
            "total_hosts_scanned": len(dirbuster_reports),
            "total_paths_scanned": total_scanned,
            "total_paths_found": total_found,
            "hosts": dirbuster_data,
        }

    # Screenshot results
    if screenshot_reports:
        screenshot_data = {}
        total_taken = 0
        total_failed = 0
        for hostname, sr in screenshot_reports.items():
            d = sr.to_dict()
            screenshot_data[hostname] = d
            total_taken += d["total_taken"]
            total_failed += d["total_failed"]
        report["screenshots"] = {
            "total_taken": total_taken,
            "total_failed": total_failed,
            "hosts": screenshot_data,
        }

    # Phase 3: Vulnerability Scan Results
    if vuln_scan_report:
        report["vulnerability_scan"] = vuln_scan_report

    # Phase 3: SSL/TLS Audit Results
    if ssl_audit_report:
        report["ssl_tls_audit"] = ssl_audit_report

    # Phase 3: Subdomain Takeover Results
    if takeover_report:
        report["subdomain_takeover"] = takeover_report

    # Phase 3: WAF Detection Results
    if waf_report:
        report["waf_detection"] = waf_report

    # Phase 4: Exploit Suggestions
    if exploit_report:
        report["exploit_suggestions"] = exploit_report

    # Phase 4: Payload Generation
    if payload_report:
        report["payloads"] = payload_report

    # Phase 4: Loot Collection
    if loot_report:
        report["loot"] = loot_report

    # Phase 4: MSF Script Generation
    if msf_report:
        report["msf_script"] = msf_report

    # Phase 5: Advanced OSINT
    if osint_report:
        report["osint"] = osint_report

    # Add lhost/lport to scan info
    report["scan_info"]["lhost"] = lhost
    report["scan_info"]["lport"] = lport

    return report


def output_json(report: dict, output_path: Optional[Path] = None) -> str:
    """Output the report as formatted JSON."""
    json_str = json.dumps(report, indent=2, default=str)
    if output_path:
        output_path.write_text(json_str)
    return json_str


def output_markdown(report: dict, output_path: Optional[Path] = None) -> str:
    """Output the report as a human-readable Markdown document."""
    lines: list[str] = []
    target = report["target"]
    scan_info = report.get("scan_info", {})
    sub_info = report["subdomain_enumeration"]
    port_info = report["port_scanning"]
    http_info = report.get("http_probing", {})
    enrichment_info = report.get("enrichment", {})
    crawl_info = report.get("crawling", {})
    dirbuster_info = report.get("dirbuster", {})
    screenshot_info = report.get("screenshots", {})

    # Header
    lines.append(f"# ReconProbe Report — {target['domain']}")
    lines.append("")
    lines.append(f"- **Tool:** ReconProbe v{report['version']}")
    lines.append(f"- **Target:** {target['domain']}")
    if scan_info:
        lines.append(f"- **Started:** {scan_info.get('start_time', '')}")
        lines.append(f"- **Duration:** {scan_info.get('duration_seconds', 0):.1f}s")
    lines.append("")

    # Advanced subdomain techniques
    advanced_info = report.get("advanced_subdomain_techniques", {})
    if advanced_info and (advanced_info.get("zone_transfer") or advanced_info.get("permutations") or advanced_info.get("recursive")):
        lines.append("## Advanced Subdomain Techniques")
        lines.append("")

        # Zone Transfer
        zt_results = advanced_info.get("zone_transfer", [])
        if zt_results:
            lines.append("### DNS Zone Transfer (AXFR)")
            lines.append("")
            lines.append("| Nameserver | Success | Records Found | Error |")
            lines.append("|------------|---------|---------------|-------|")
            for zt in zt_results:
                success_icon = "✅" if zt["success"] else "❌"
                records_count = len(zt.get("records", []))
                error = zt.get("error", "") or "-"
                lines.append(f"| {zt['nameserver']} | {success_icon} | {records_count} | {error} |")
            lines.append("")

            # Show some records from successful transfers
            for zt in zt_results:
                if zt["success"] and zt.get("records"):
                    lines.append("#### Zone Records")
                    lines.append("")
                    lines.append("```")
                    for record in zt["records"][:50]:
                        lines.append(record)
                    if len(zt["records"]) > 50:
                        lines.append(f"... and {len(zt['records']) - 50} more")
                    lines.append("```")
                    lines.append("")

        # Permutations
        perms = advanced_info.get("permutations")
        if perms and perms.get("total_generated", 0) > 0:
            lines.append("### Subdomain Permutations")
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            lines.append(f"| Candidates Generated | {perms.get('total_generated', 0)} |")
            lines.append(f"| Resolved | {perms.get('total_resolved', 0)} |")
            lines.append("")
            if perms.get("new_subdomains"):
                lines.append("#### Discovered via Permutations")
                lines.append("")
                for sub in perms["new_subdomains"][:50]:
                    lines.append(f"- `{sub}`")
                if len(perms["new_subdomains"]) > 50:
                    lines.append(f"- ... and {len(perms['new_subdomains']) - 50} more")
                lines.append("")

        # Recursive Discovery
        rec = advanced_info.get("recursive")
        if rec:
            lines.append("### Recursive Subdomain Discovery")
            lines.append("")
            for depth in sorted(rec.keys()):
                subs = rec[depth]
                lines.append(f"**Depth {depth}:** {len(subs)} subdomains")
                for sub in subs[:25]:
                    lines.append(f"- `{sub}`")
                if len(subs) > 25:
                    lines.append(f"- ... and {len(subs) - 25} more")
                lines.append("")

        lines.append("---")
        lines.append("")

    # Subdomain summary
    lines.append("## Subdomain Enumeration")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Found | {sub_info['total_found']} |")
    lines.append(f"| Resolved | {sub_info['total_resolved']} |")
    lines.append("")
    if sub_info["results"]:
        lines.append("### Discovered Subdomains")
        lines.append("")
        lines.append("| Hostname | IP Address | Source | Resolved |")
        lines.append("|----------|------------|--------|----------|")
        for r in sub_info["results"]:
            resolved = "✅" if r["resolved"] else "❌"
            ip = r["ip_address"] or "-"
            lines.append(f"| {r['hostname']} | {ip} | {r['source']} | {resolved} |")
        lines.append("")

    # Port scan results
    lines.append("## Port Scanning")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Hosts Scanned | {port_info['total_hosts_scanned']} |")
    lines.append("")
    for host in port_info["hosts"]:
        hostname = host["hostname"]
        ip = host["ip_address"]
        lines.append(f"### {hostname} ({ip})")
        lines.append("")
        if host["open_ports"] == 0:
            lines.append("*No open ports found.*")
            lines.append("")
            continue
        lines.append(f"**Open Ports:** {host['open_ports']}")
        lines.append("")
        lines.append("| Port | Service | Version | OS | Banner |")
        lines.append("|------|---------|---------|----|--------|")
        for p in host["ports"]:
            if p["state"] == "open":
                banner = (p["banner"][:60] + "...") if p["banner"] and len(p["banner"]) > 60 else (p["banner"] or "-")
                version = ""
                if p.get("service_version"):
                    v = p["service_version"]
                    parts = []
                    if v.get("product"):
                        parts.append(v["product"])
                    if v.get("version"):
                        parts.append(v["version"])
                    version = " ".join(parts)
                os_info = ""
                if p.get("os_fingerprint"):
                    os_info = p["os_fingerprint"].get("guessed_os", "") or ""
                lines.append(f"| {p['port']} | {p['service']} | {version or '-'} | {os_info or '-'} | `{banner}` |")
        lines.append("")

    # HTTP Probing results
    if http_info and http_info.get("hosts"):
        lines.append("## HTTP Probing & Technology Fingerprinting")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Hosts Probed | {http_info.get('total_hosts_probed', 0)} |")
        lines.append(f"| Alive Services | {http_info.get('total_alive_services', 0)} |")
        lines.append("")
        for hostname, host_data in http_info.get("hosts", {}).items():
            if not host_data.get("results"):
                continue
            lines.append(f"### {hostname}")
            lines.append("")
            for result in host_data["results"]:
                url = result["url"]
                status = result["status_code"]
                title = result.get("title", "")
                server = result.get("server", "")
                techs = result.get("technologies", [])
                tech_str = ", ".join(f"{t['name']} ({t['category']})" for t in techs)
                lines.append(f"#### [{status}] {url}")
                if title:
                    lines.append(f"- **Title:** {title}")
                if server:
                    lines.append(f"- **Server:** {server}")
                if tech_str:
                    lines.append(f"- **Technologies:** {tech_str}")
                lines.append("")

    # Enrichment results (Shodan + NVD)
    if enrichment_info:
        shodan_data = enrichment_info.get("shodan", {})
        cve_data = enrichment_info.get("cve_lookup", {})

        if shodan_data.get("results"):
            lines.append("## Shodan Enrichment")
            lines.append("")
            lines.append(f"| Metric | Value |")
            lines.append("|--------|-------|")
            lines.append(f"| IPs Queried | {shodan_data.get('total_ips_checked', len(shodan_data.get('results', {})))} |")
            lines.append("")

            for ip, shodan_result in shodan_data.get("results", {}).items():
                if shodan_result.get("error"):
                    lines.append(f"### {ip} — Error: {shodan_result['error']}")
                    lines.append("")
                    continue

                org = shodan_result.get("org", "") or shodan_result.get("isp", "")
                if org:
                    lines.append(f"### {ip} — {org}")
                else:
                    lines.append(f"### {ip}")
                lines.append("")

                if shodan_result.get("hostnames"):
                    lines.append(f"- **Hostnames:** {', '.join(shodan_result['hostnames'])}")
                if shodan_result.get("country"):
                    lines.append(f"- **Country:** {shodan_result['country']}")
                if shodan_result.get("open_ports"):
                    lines.append(f"- **Open Ports:** {', '.join(map(str, shodan_result['open_ports']))}")
                if shodan_result.get("vulns"):
                    lines.append(f"- **CVEs:** {', '.join(shodan_result['vulns'][:20])}"
                                 f"{' (+ more)' if len(shodan_result['vulns']) > 20 else ''}")
                lines.append("")

                if shodan_result.get("services"):
                    lines.append("| Port | Transport | Product | Version |")
                    lines.append("|------|-----------|---------|---------|")
                    for svc in shodan_result["services"][:15]:
                        lines.append(f"| {svc['port']} | {svc.get('transport', 'tcp')} | "
                                     f"{svc.get('product', '')} | {svc.get('version', '')} |")
                    if len(shodan_result["services"]) > 15:
                        lines.append(f"| ... and {len(shodan_result['services']) - 15} more |")
                    lines.append("")

        if cve_data.get("results"):
            lines.append("## CVE Lookup (NVD)")
            lines.append("")
            lines.append(f"| Metric | Value |")
            lines.append("|--------|-------|")
            lines.append(f"| CVEs Found | {cve_data.get('total_found', 0)} |")
            lines.append("")

            # Group by severity
            high_cves = [c for c in cve_data.get("results", []) if c.get("cvss_severity") in ("CRITICAL", "HIGH")]
            medium_cves = [c for c in cve_data.get("results", []) if c.get("cvss_severity") == "MEDIUM"]
            low_cves = [c for c in cve_data.get("results", []) if c.get("cvss_severity") in ("LOW", "NONE", "")]

            def write_cve_table(cve_list: list[dict], severity_label: str):
                if not cve_list:
                    return
                lines.append(f"### {severity_label} ({len(cve_list)})")
                lines.append("")
                lines.append("| CVE ID | CVSS | Description |")
                lines.append("|--------|------|-------------|")
                for cve in cve_list[:25]:
                    desc = (cve.get("description", "") or "")[:100]
                    score = cve.get("cvss_score", "")
                    score_str = f"{score:.1f}" if score is not None else "-"
                    lines.append(f"| `{cve['cve_id']}` | {score_str} | {desc} |")
                if len(cve_list) > 25:
                    lines.append(f"| ... and {len(cve_list) - 25} more |")
                lines.append("")

            if high_cves:
                write_cve_table(high_cves, "High & Critical Severity")
            if medium_cves:
                write_cve_table(medium_cves, "Medium Severity")
            if low_cves:
                write_cve_table(low_cves, "Low Severity")

    # Crawling results
    if crawl_info and crawl_info.get("hosts"):
        lines.append("## Web Crawling")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Hosts Crawled | {crawl_info.get('total_hosts_crawled', 0)} |")
        lines.append(f"| Pages Crawled | {crawl_info.get('total_pages_crawled', 0)} |")
        lines.append(f"| Interesting Findings | {crawl_info.get('total_findings', 0)} |")
        lines.append("")
        for hostname, host_data in crawl_info.get("hosts", {}).items():
            lines.append(f"### {hostname}")
            lines.append("")
            lines.append(f"- **Base URL:** {host_data.get('base_url', '')}")
            lines.append(f"- **Pages crawled:** {host_data.get('total_pages', 0)}")
            lines.append(f"- **Total links discovered:** {host_data.get('total_links', 0)}")
            lines.append(f"- **Total scripts discovered:** {host_data.get('total_scripts', 0)}")
            lines.append(f"- **Total forms discovered:** {host_data.get('total_forms', 0)}")
            lines.append("")

            if host_data.get("interesting_findings"):
                lines.append("#### Interesting Findings")
                lines.append("")
                lines.append("| Type | URL / Detail |")
                lines.append("|------|--------------|")
                for finding in host_data["interesting_findings"][:30]:
                    lines.append(f"| {finding['type']} | {finding['detail']} |")
                lines.append("")

            if host_data.get("unique_urls"):
                lines.append("#### Discovered URLs (first 50)")
                lines.append("")
                for url in host_data["unique_urls"][:50]:
                    lines.append(f"- `{url}`")
                lines.append("")
            lines.append("")

    # Directory brute-force results
    if dirbuster_info and dirbuster_info.get("hosts"):
        lines.append("## Directory Brute-Force")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Hosts Scanned | {dirbuster_info.get('total_hosts_scanned', 0)} |")
        lines.append(f"| Paths Scanned | {dirbuster_info.get('total_paths_scanned', 0)} |")
        lines.append(f"| Paths Found | {dirbuster_info.get('total_paths_found', 0)} |")
        lines.append("")
        for hostname, host_data in dirbuster_info.get("hosts", {}).items():
            lines.append(f"### {hostname}")
            lines.append("")
            lines.append(f"- **Base URL:** {host_data.get('base_url', '')}")
            lines.append(f"- **Scanned:** {host_data.get('total_scanned', 0)} paths")
            lines.append(f"- **Found:** {host_data.get('total_found', 0)} paths")
            findings_types = host_data.get("findings_by_type", {})
            if any(findings_types.values()):
                parts = [f"{k}: {v}" for k, v in findings_types.items() if v > 0]
                lines.append(f"- **Breakdown:** {', '.join(parts)}")
            lines.append("")

            if host_data.get("results"):
                lines.append("| URL | Status | Length | Content-Type | Title/Redirect |")
                lines.append("|-----|--------|--------|--------------|----------------|")
                for r in host_data["results"][:70]:
                    title = r.get("title") or r.get("redirect_url", "") or "-"
                    if len(title) > 60:
                        title = title[:60] + "..."
                    content_type = r.get("content_type", "-")[:30]
                    lines.append(f"| `{r['url']}` | {r['status_code']} | {r.get('content_length', 0)} | {content_type} | {title} |")
                if len(host_data["results"]) > 70:
                    lines.append(f"| ... and {len(host_data['results']) - 70} more |")
                lines.append("")
            lines.append("")

    # Screenshot results
    if screenshot_info and screenshot_info.get("hosts"):
        lines.append("## Screenshots")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Taken | {screenshot_info.get('total_taken', 0)} |")
        lines.append(f"| Failed | {screenshot_info.get('total_failed', 0)} |")
        lines.append("")
        for hostname, host_data in screenshot_info.get("hosts", {}).items():
            if not host_data.get("screenshots"):
                continue
            lines.append(f"### {hostname}")
            lines.append("")
            for s in host_data["screenshots"]:
                icon = "✅" if s["success"] else "❌"
                lines.append(f"- {icon} `{s['url']}` → {s.get('file_path', '-')}")
                if s.get("error"):
                    lines.append(f"  - Error: {s['error']}")
            lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # Phase 3: Vulnerability Scan Results
    # ══════════════════════════════════════════════════════════════════
    vuln_info = report.get("vulnerability_scan", {})
    if vuln_info and (vuln_info.get("cve_matches") or vuln_info.get("default_credentials")):
        lines.append("")
        lines.append("## Vulnerability Scan")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total CVEs | {vuln_info.get('total_cves', 0)} |")
        lines.append(f"| High/Critical | {vuln_info.get('total_high_severity', 0)} |")
        lines.append(f"| Default Credentials | {vuln_info.get('total_creds', 0)} |")
        lines.append("")

        cves = vuln_info.get("cve_matches", [])
        if cves:
            lines.append("### CVE Matches")
            lines.append("")
            lines.append("| CVE ID | CVSS | Severity | Service | Description |")
            lines.append("|--------|------|----------|---------|-------------|")
            for cve in cves[:30]:
                desc = (cve.get("description", "") or "")[:80]
                score = cve.get("cvss_score", "")
                score_str = f"{score:.1f}" if score is not None else "-"
                sev = cve.get("cvss_severity", "")
                lines.append(f"| `{cve['cve_id']}` | {score_str} | {sev} | {cve.get('affected_service', '')} | {desc} |")
            if len(cves) > 30:
                lines.append(f"| ... and {len(cves) - 30} more |")
            lines.append("")

        creds = vuln_info.get("default_credentials", [])
        if creds:
            lines.append("### Default Credentials Found")
            lines.append("")
            lines.append("| Service | Hostname | Port | Username | Password |")
            lines.append("|---------|----------|------|----------|----------|")
            for cred in creds:
                lines.append(f"| {cred['service']} | {cred['hostname']} | {cred['port']} | `{cred['username']}` | `{cred['password']}` |")
            lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # Phase 3: SSL/TLS Audit Results
    # ══════════════════════════════════════════════════════════════════
    ssl_info = report.get("ssl_tls_audit", {})
    if ssl_info and ssl_info.get("results"):
        lines.append("## SSL/TLS Audit")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Endpoints Audited | {ssl_info.get('total_audited', 0)} |")
        lines.append("")

        for endpoint_key, endpoint_data in ssl_info.get("results", {}).items():
            lines.append(f"### {endpoint_key}")
            lines.append("")
            lines.append(f"- **Grade:** {endpoint_data.get('grade', '?')}")
            lines.append(f"- **Total Issues:** {endpoint_data.get('total_issues', 0)}")
            lines.append("")

            cert = endpoint_data.get("certificate", {})
            if cert:
                lines.append("#### Certificate")
                lines.append("")
                lines.append(f"- **Subject:** {cert.get('subject', '')}")
                lines.append(f"- **Issuer:** {cert.get('issuer', '')}")
                lines.append(f"- **Valid To:** {cert.get('valid_to', '')}")
                if cert.get('is_expired'):
                    lines.append("- **Status:** ❌ **EXPIRED**")
                elif cert.get('will_expire_soon'):
                    lines.append(f"- **Status:** ⚠️ Expiring soon ({cert.get('days_remaining', 0)} days)")
                else:
                    lines.append(f"- **Status:** ✅ Valid ({cert.get('days_remaining', 0)} days remaining)")
                if cert.get('is_self_signed'):
                    lines.append("- **Self-Signed:** Yes ⚠️")
                if cert.get('is_wildcard'):
                    lines.append("- **Wildcard:** Yes")
                lines.append("")

            protos = endpoint_data.get("protocols", [])
            supported_protos = [p for p in protos if p.get("supported")]
            if supported_protos:
                lines.append("#### Supported TLS Protocols")
                lines.append("")
                lines.append("| Protocol | Status |")
                lines.append("|----------|--------|")
                for p in protos:
                    icon = "✅" if p["supported"] else "❌"
                    lines.append(f"| {p['protocol']} | {icon} |")
                lines.append("")

            weak_ciphers = endpoint_data.get("weak_ciphers", [])
            if weak_ciphers:
                lines.append("#### Weak Ciphers")
                lines.append("")
                lines.append("| Cipher | Reason |")
                lines.append("|--------|--------|")
                for c in weak_ciphers:
                    lines.append(f"| `{c['cipher']}` | {c.get('reason', '')} |")
                lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # Phase 3: Subdomain Takeover Results
    # ══════════════════════════════════════════════════════════════════
    takeover_info = report.get("subdomain_takeover", {})
    if takeover_info and takeover_info.get("total_vulnerable", 0) > 0:
        lines.append("## Subdomain Takeover Detection")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Subdomains Checked | {takeover_info.get('total_checked', 0)} |")
        lines.append(f"| Vulnerable | {takeover_info.get('total_vulnerable', 0)} |")
        lines.append("")
        lines.append("### Vulnerable Subdomains")
        lines.append("")
        lines.append("| Subdomain | Service | Confidence | DNS Status |")
        lines.append("|-----------|---------|------------|------------|")
        for r in takeover_info.get("results", []):
            lines.append(f"| `{r['hostname']}` | {r.get('service', '')} | {r.get('confidence', '')} | {r.get('dns_status', '')} |")
        lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # Phase 3: WAF Detection Results
    # ══════════════════════════════════════════════════════════════════
    waf_info = report.get("waf_detection", {})
    if waf_info and waf_info.get("total_protected", 0) > 0:
        lines.append("## WAF Detection & Fingerprinting")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| URLs Checked | {waf_info.get('total_urls_checked', 0)} |")
        lines.append(f"| Behind WAF | {waf_info.get('total_protected', 0)} |")
        lines.append("")
        for url_str, result in waf_info.get("results", {}).items():
            if result.get("is_protected"):
                waf_names = [w["name"] for w in result.get("detected_wafs", [])]
                lines.append(f"- **{url_str}** → {', '.join(waf_names)}")
        lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # Phase 4: Exploit Suggestions
    # ══════════════════════════════════════════════════════════════════
    exploit_info = report.get("exploit_suggestions", {})
    if exploit_info and exploit_info.get("suggestions"):
        lines.append("## Exploit Suggestions")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Suggestions | {exploit_info.get('total_suggestions', 0)} |")
        lines.append("")

        suggestions = exploit_info.get("suggestions", [])
        if suggestions:
            lines.append("### Ranked Exploit Targets")
            lines.append("")
            lines.append("| EDB ID | CVE ID | Service | Reliability | Type | Port | Title |")
            lines.append("|--------|--------|---------|-------------|------|------|-------|")
            for s in suggestions:
                lines.append(f"| {s.get('edb_id', '')} | {s.get('cve_id', '') or '-'} | {s.get('service', '')} | "
                             f"{s.get('reliability', '')} | {s.get('exploit_type', '')} | "
                             f"{s.get('port', '') or '-'} | {s.get('title', '')[:80]} |")
            lines.append("")

            # High reliability exploits
            high_exploits = [s for s in suggestions if s.get('reliability') == 'high']
            if high_exploits:
                lines.append("### High-Reliability Exploits")
                lines.append("")
                for s in high_exploits:
                    edb = s.get('edb_id', '')
                    url = s.get('url', f'https://www.exploit-db.com/exploits/{edb.replace("EDB-", "")}')
                    lines.append(f"- **`{edb}`** — {s.get('title', '')} — [Exploit-DB]({url})")
                lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # Phase 4: Payload Generation
    # ══════════════════════════════════════════════════════════════════
    payload_info = report.get("payloads", {})
    if payload_info and payload_info.get("payloads"):
        lh = payload_info.get("lhost", "127.0.0.1")
        lp = payload_info.get("lport", 4444)
        lines.append("## Reverse Shell Payloads")
        lines.append("")
        lines.append(f"- **LHOST:** {lh}")
        lines.append(f"- **LPORT:** {lp}")
        lines.append("")

        for p in payload_info.get("payloads", []):
            lines.append(f"### {p.get('description', p.get('type', ''))}")
            lines.append("")
            lines.append("```bash")
            lines.append(p.get('command', ''))
            lines.append("```")
            lines.append("")
            lines.append(f"**Listener:** `{p.get('listener_command', '')}`")
            lines.append("")
            if p.get('encoded_command'):
                lines.append("**Encoded variant:**")
                lines.append("")
                lines.append("```bash")
                lines.append(p['encoded_command'])
                lines.append("```")
                lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # Phase 4: Loot Collection
    # ══════════════════════════════════════════════════════════════════
    loot_info = report.get("loot", {})
    if loot_info and loot_info.get("items"):
        lines.append("## Loot Collection")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Items | {loot_info.get('total_count', 0)} |")
        lines.append(f"| Critical | {loot_info.get('critical_count', 0)} |")
        lines.append(f"| High | {loot_info.get('high_count', 0)} |")
        lines.append(f"| Medium | {loot_info.get('medium_count', 0)} |")
        lines.append("")

        critical_items = [i for i in loot_info.get("items", []) if i.get("severity") == "critical"]
        high_items = [i for i in loot_info.get("items", []) if i.get("severity") == "high"]

        if critical_items:
            lines.append("### Critical Items")
            lines.append("")
            lines.append("| Type | Source | Target | Data | Description |")
            lines.append("|------|--------|--------|------|-------------|")
            for item in critical_items[:15]:
                data_str = str(item.get('data', ''))[:50]
                lines.append(f"| {item.get('type', '')} | {item.get('source', '')} | "
                             f"{item.get('target', '')} | `{data_str}` | {item.get('description', '')} |")
            if len(critical_items) > 15:
                lines.append(f"| ... and {len(critical_items) - 15} more |")
            lines.append("")

        if high_items:
            lines.append("### High Severity Items")
            lines.append("")
            lines.append("| Type | Source | Target | Description |")
            lines.append("|------|--------|--------|-------------|")
            for item in high_items[:10]:
                lines.append(f"| {item.get('type', '')} | {item.get('source', '')} | "
                             f"{item.get('target', '')} | {item.get('description', '')} |")
            if len(high_items) > 10:
                lines.append(f"| ... and {len(high_items) - 10} more |")
            lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # Phase 4: MSF Resource Script
    # ══════════════════════════════════════════════════════════════════
    msf_info = report.get("msf_script", {})
    if msf_info and msf_info.get("content"):
        lines.append("## Metasploit Resource Script")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Modules | {msf_info.get('module_count', 0)} |")
        lines.append(f"| Auxiliary | {msf_info.get('auxiliary_count', 0)} |")
        lines.append(f"| Exploit | {msf_info.get('exploit_count', 0)} |")
        lines.append("")
        lines.append("```bash")
        lines.append(f"# Save and run: msfconsole -r script.rc")
        lines.append("")
        # Show first 30 lines of the script
        content_lines = msf_info.get("content", "").split("\n")
        for cl in content_lines[:30]:
            lines.append(cl)
        if len(content_lines) > 30:
            lines.append(f"# ... ({len(content_lines) - 30} more lines)")
        lines.append("```")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Generated by ReconProbe v{report['version']}*")
    lines.append("")

    md = "\n".join(lines)
    if output_path:
        output_path.write_text(md)
    return md
